"""Request-local gateway controls: masks, classifier toggles and safe blocks.

Synthetic in-process tests only.  They drive the real ``Gateway.handle`` path
with explicit ``GatewayControl`` values and never contact a network service.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from nasi_lemak.controls import (
    BLOCK_REASONS,
    MASK_TYPES,
    GatewayControl,
    block_detail,
)
from nasi_lemak.gateway import Gateway, MemoryAdapters, Policy, make_demo_gateway


PROMPT = "mail user@example.com phone 0123456789 ic 900101123456"
OUTPUT = "reply user@example.com 0123456789 900101123456"
PROMPT_CANARY = "CANARY-INPUT-PROMPT-7f3c"
OUTPUT_CANARY = "CANARY-WITHHELD-OUTPUT-91ab"


class EchoAdapters(MemoryAdapters):
    """Deterministic adapter that echoes the last sanitized turn."""

    def generate(self, messages, model, max_tokens):
        self.generation_inputs.append([dict(message) for message in messages])
        self.generate_options.append((model, max_tokens))
        return "reply " + messages[-1]["content"]


class GatewayControlValueTests(unittest.TestCase):
    def test_default_is_all_protections_on_and_digest_is_stable(self):
        first = GatewayControl()
        second = GatewayControl()
        self.assertTrue(first.input_check_enabled and first.output_check_enabled)
        self.assertEqual(first.input_masks, MASK_TYPES)
        self.assertEqual(first.output_masks, MASK_TYPES)
        self.assertEqual(first.revision, "default")
        self.assertEqual(len(first.digest), 64)
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.metadata()["sources"], [])

    def test_masks_are_canonical_and_invalid_values_are_rejected(self):
        control = GatewayControl(input_masks=("MYKAD", "EMAIL"), output_masks=())
        self.assertEqual(control.input_masks, ("EMAIL", "MYKAD"))
        self.assertEqual(control.output_masks, ())
        for kwargs in (
            {"input_masks": ("UNKNOWN",)},
            {"input_masks": ("EMAIL", "EMAIL")},
            {"output_masks": "EMAIL"},
            {"input_check_enabled": 1},
            {"output_check_enabled": None},
            {"revision": ""},
            {"revision": "x" * 129},
            {"sources": (("workspace", "workspace", "id", 0),)},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    GatewayControl(**kwargs)

    def test_block_details_are_fixed_for_known_reasons_only(self):
        self.assertEqual(
            set(BLOCK_REASONS),
            {
                "INPUT_GUARD_BLOCK",
                "INPUT_POLICY_BLOCK",
                "OUTPUT_GUARD_BLOCK",
                "OUTPUT_POLICY_BLOCK",
            },
        )
        detail = block_detail("OUTPUT_GUARD_BLOCK")
        self.assertEqual(
            detail,
            {
                "stage": "output",
                "reason_code": "OUTPUT_GUARD_BLOCK",
                "title": "Response withheld",
                "reason": "The response did not pass the output safety check.",
            },
        )
        with self.assertRaises(ValueError):
            block_detail("UNKNOWN")


class GatewayControlEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _gateway(self, name="audit.sqlite3", policy=None, adapters=None):
        gateway, defaults, key = make_demo_gateway(Path(self.tmp.name) / name)
        if policy is not None:
            gateway = Gateway(
                key,
                Path(self.tmp.name) / ("policy-" + name),
                adapters if adapters is not None else defaults,
                policy,
            )
            defaults = gateway.adapters
        elif adapters is not None:
            gateway = Gateway(key, Path(self.tmp.name) / ("custom-" + name), adapters)
            defaults = adapters
        return gateway, defaults, key

    @staticmethod
    def _body(content=PROMPT):
        return {
            "model": "pilot-local",
            "messages": [{"role": "user", "content": content}],
        }

    def test_default_control_masks_every_recognizer(self):
        gateway, adapters, key = self._gateway()
        adapters.generated = OUTPUT
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
        )
        self.assertEqual(status, 200)
        generated = json.dumps(adapters.generation_inputs[0])
        for raw in ("user@example.com", "0123456789", "900101123456"):
            self.assertNotIn(raw, generated)
            self.assertNotIn(raw, body["choices"][0]["message"]["content"])
        self.assertIn("[EMAIL]", body["choices"][0]["message"]["content"])

    def test_selected_and_empty_mask_sets(self):
        cases = {
            ("EMAIL",): {
                "input": ("[EMAIL]", "0123456789", "900101123456"),
                "output": ("[EMAIL]", "0123456789", "900101123456"),
            },
            ("MY_PHONE",): {
                "input": ("user@example.com", "[MY_PHONE]", "900101123456"),
                "output": ("user@example.com", "[MY_PHONE]", "900101123456"),
            },
            (): {
                "input": ("user@example.com", "0123456789", "900101123456"),
                "output": ("user@example.com", "0123456789", "900101123456"),
            },
        }
        for index, (masks, expected) in enumerate(cases.items()):
            with self.subTest(masks=masks):
                gateway, adapters, key = self._gateway(f"mask-{index}.sqlite3")
                adapters.generated = OUTPUT
                control = GatewayControl(input_masks=masks, output_masks=masks)
                status, body = gateway.handle(
                    "POST",
                    "/v1/chat/completions",
                    {"Authorization": "Bearer " + key},
                    self._body(),
                    control=control,
                )
                self.assertEqual(status, 200)
                safe_input = adapters.generation_inputs[0][0]["content"]
                for item in expected["input"]:
                    self.assertIn(item, safe_input)
                response = body["choices"][0]["message"]["content"]
                for item in expected["output"]:
                    self.assertIn(item, response)

    def test_input_classifier_can_be_disabled_but_unavailable_still_fails_closed(self):
        gateway, adapters, key = self._gateway("input-toggle.sqlite3")
        adapters.attack_result = {"decision": "block"}
        disabled = GatewayControl(input_check_enabled=False)
        status, _body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
            control=disabled,
        )
        self.assertEqual(status, 200)
        self.assertEqual(adapters.attack_inputs, [])

        adapters.attack_error = RuntimeError("guard unavailable")
        enabled = GatewayControl()
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
            control=enabled,
        )
        self.assertEqual((status, body["error"]["code"]), (503, "UNAVAILABLE"))
        self.assertNotIn("choices", body)

    def test_output_classifier_can_be_disabled_but_unavailable_still_fails_closed(self):
        gateway, adapters, key = self._gateway("output-toggle.sqlite3")
        adapters.output_result = {"safe": False}
        disabled = GatewayControl(output_check_enabled=False)
        status, _body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
            control=disabled,
        )
        self.assertEqual(status, 200)

        adapters.output_error = RuntimeError("guard unavailable")
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
            control=GatewayControl(),
        )
        self.assertEqual((status, body["error"]["code"]), (503, "UNAVAILABLE"))
        self.assertNotIn("choices", body)

    def test_input_and_output_blocks_use_fixed_safe_details(self):
        gateway, adapters, key = self._gateway("blocks.sqlite3")
        adapters.attack_result = {"decision": "block"}
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(PROMPT_CANARY),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(body["error"]["block"]["stage"], "input")
        self.assertEqual(body["error"]["block"]["reason_code"], "INPUT_GUARD_BLOCK")
        self.assertNotIn(PROMPT_CANARY, json.dumps(body))

        adapters.attack_result = {"decision": "allow"}
        adapters.generated = OUTPUT_CANARY
        adapters.output_result = {"safe": False}
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["block"]["stage"], "output")
        self.assertEqual(body["error"]["block"]["reason_code"], "OUTPUT_GUARD_BLOCK")
        self.assertNotIn(OUTPUT_CANARY, json.dumps(body))
        self.assertNotIn("choices", body)

    def test_disabled_classifiers_never_bypass_literal_policy_denies(self):
        gateway, adapters, key = self._gateway(
            "deny.sqlite3", policy=Policy(deny_phrases=("forbidden",))
        )
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body("forbidden prompt"),
            control=GatewayControl(input_check_enabled=False),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["block"]["reason_code"], "INPUT_POLICY_BLOCK")
        self.assertEqual(adapters.generation_inputs, [])

        adapters.generated = "forbidden response"
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
            control=GatewayControl(output_check_enabled=False),
        )
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["block"]["reason_code"], "OUTPUT_POLICY_BLOCK")
        self.assertNotIn("forbidden", json.dumps(body))

    def test_invalid_control_value_fails_closed_before_generation(self):
        gateway, adapters, key = self._gateway("invalid-control.sqlite3")
        status, body = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + key},
            self._body(),
            control={"input_masks": []},
        )
        self.assertEqual((status, body["error"]["code"]), (503, "UNAVAILABLE"))
        self.assertEqual(adapters.generation_inputs, [])
        self.assertEqual(adapters.attack_inputs, [])

    def test_shared_gateway_alternates_controls_without_leakage(self):
        gateway, adapters, key = self._gateway("alternating.sqlite3")
        adapters.generated = OUTPUT
        controls = (
            (GatewayControl(), ("[EMAIL]", "[MY_PHONE]", "[MYKAD]")),
            (
                GatewayControl(input_masks=(), output_masks=()),
                ("user@example.com", "0123456789", "900101123456"),
            ),
            (
                GatewayControl(input_masks=("EMAIL",), output_masks=("EMAIL",)),
                ("[EMAIL]", "0123456789", "900101123456"),
            ),
        )
        for index in range(6):
            control, expected = controls[index % len(controls)]
            status, body = gateway.handle(
                "POST",
                "/v1/chat/completions",
                {"Authorization": "Bearer " + key},
                self._body(),
                control=control,
            )
            self.assertEqual(status, 200)
            response = body["choices"][0]["message"]["content"]
            for item in expected:
                self.assertIn(item, response)
        # Every call saw only its own mask selection; the default never changed.
        self.assertEqual(len(adapters.generation_inputs), 6)

    def test_concurrent_controls_are_request_local(self):
        gateway, adapters, key = self._gateway(
            "concurrent.sqlite3", adapters=EchoAdapters()
        )

        def call(index: int):
            choice = index % 3
            if choice == 0:
                control = GatewayControl()
                expected = ("[EMAIL]", "[MY_PHONE]")
            elif choice == 1:
                control = GatewayControl(input_masks=(), output_masks=())
                expected = ("user%d@example.com" % index, "0123456789")
            else:
                control = GatewayControl(
                    input_masks=("EMAIL",), output_masks=("EMAIL",)
                )
                expected = ("[EMAIL]", "0123456789")
            prompt = "mail user%d@example.com phone 0123456789" % index
            status, body = gateway.handle(
                "POST",
                "/v1/chat/completions",
                {"Authorization": "Bearer " + key},
                self._body(prompt),
                control=control,
            )
            return index, status, body, expected

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(call, range(30)))
        for index, status, body, expected in results:
            self.assertEqual(status, 200)
            response = body["choices"][0]["message"]["content"]
            for item in expected:
                self.assertIn(item, response)
            if index % 3 != 1:
                self.assertNotIn("user%d@example.com" % index, response)
        self.assertEqual(len(adapters.generation_inputs), 30)


if __name__ == "__main__":
    unittest.main()
