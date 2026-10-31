import json
import tempfile
import unittest
from pathlib import Path

from nasi_lemak.diagnostics import GENERATION_TRUNCATED, SafeDiagnostics
from nasi_lemak.gateway import (
    Gateway,
    MemoryAdapters,
    Policy,
    log_rejection,
    make_demo_gateway,
)
from nasi_lemak.generation import GenerationError, RealGatewayAdapters
from nasi_lemak.scan_context import ScanContext


def request(messages=None, **extra):
    body = {"model": "pilot-local", "messages": messages or [{"role": "user", "content": "Hello"}]}
    body.update(extra)
    return body


class RaisingGenerationAdapters(MemoryAdapters):
    """Synthetic adapters whose generation raises a fixed error."""

    def __init__(self, error):
        super().__init__()
        self.generation_error = error

    def generate(self, messages, model, max_tokens):
        self.generation_inputs.append([dict(message) for message in messages])
        self.generate_options.append((model, max_tokens))
        raise self.generation_error


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.gateway, self.adapters, self.key = make_demo_gateway(Path(self.tmp.name) / "audit.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, body):
        return self.gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + self.key}, body)

    def test_success_scans_each_original_turn_and_returns_masked_output(self):
        turns = [{"role": "user", "content": "mail test@example.com"}, {"role": "assistant", "content": "I saw test@example.com"}]
        self.adapters.generated = "echo 0123456789 test@example.com +60123456789"
        response = self.call(request(turns))
        self.assertEqual(response[0], 200)
        self.assertEqual(len(self.adapters.attack_inputs), 1)
        for turn in turns:
            self.assertIn(turn["content"], self.adapters.attack_inputs[0])
        self.assertNotIn("test@example.com", self.adapters.generation_inputs[0][0]["content"])
        self.assertNotIn("test@example.com", response[1]["choices"][0]["message"]["content"])
        self.assertNotIn("0123456789", response[1]["choices"][0]["message"]["content"])

    def test_postal_address_masks_both_generation_input_and_output(self):
        address = "No. 12, Jalan Melati 3, Taman Sri Indah, 43000 Kajang, Selangor"
        self.adapters.generated = f"Alamat: {address}"
        response = self.call(
            request([{"role": "user", "content": f"Rumah saya di {address}"}])
        )
        self.assertEqual(response[0], 200)
        generated_input = self.adapters.generation_inputs[0][0]["content"]
        self.assertNotIn(address, generated_input)
        self.assertIn("[POSTAL_ADDRESS]", generated_input)
        content = response[1]["choices"][0]["message"]["content"]
        self.assertNotIn(address, content)
        self.assertIn("Alamat: [POSTAL_ADDRESS]", content)

    def test_labelled_address_without_postcode_masks_input_and_output(self):
        address = "Alamat: Unit 12-3, Jalan Ampang"
        self.adapters.generated = f"Rumah: {address}"
        response = self.call(
            request([{"role": "user", "content": f"Rumah saya {address}"}])
        )
        self.assertEqual(response[0], 200)
        generated_input = self.adapters.generation_inputs[0][0]["content"]
        self.assertNotIn(address, generated_input)
        self.assertIn("Alamat: [POSTAL_ADDRESS]", generated_input)
        content = response[1]["choices"][0]["message"]["content"]
        self.assertNotIn(address, content)
        self.assertIn("Rumah: Alamat: [POSTAL_ADDRESS]", content)

    def test_common_mykad_and_phone_formats_mask_gateway_output(self):
        self.adapters.generated = (
            "IC 900101 14 5678, mobile 012.345.6789, office +60 3-1234 5678."
        )
        response = self.call(request())
        self.assertEqual(response[0], 200)
        content = response[1]["choices"][0]["message"]["content"]
        self.assertNotIn("900101 14 5678", content)
        self.assertNotIn("012.345.6789", content)
        self.assertNotIn("+60 3-1234 5678", content)
        self.assertEqual(content.count("[MY_PHONE]"), 2)
        self.assertEqual(content.count("[MYKAD]"), 1)

    def test_rejects_unknown_fields_and_client_policy_override_before_upstream(self):
        for body in (request(tools=[]), request(policy="unsafe"), request(extra_field=1)):
            with self.subTest(body=body):
                status, result = self.call(body)
                self.assertEqual(status, 400)
                self.assertEqual(result["error"]["code"], "INVALID_REQUEST")
        self.assertEqual(self.adapters.attack_inputs, [])
        self.assertEqual(self.adapters.generation_inputs, [])

    def test_rejects_invalid_roles_parts_limits_and_bool_tokens(self):
        invalid = [
            request([{"role": "tool", "content": "x"}]),
            request([{"role": "user", "content": [{"type": "text", "text": "x"}]}]),
            request([{"role": "user", "content": "x", "name": "n"}]),
            request([{"role": "user", "content": "x"}], stream=True),
            request(max_tokens=True),
            request(max_tokens=0),
            request([{"role": "user", "content": ""}]),
            request([{"role": "user", "content": "x"}] * 33),
        ]
        for body in invalid:
            with self.subTest(body=str(body)[:80]):
                self.assertEqual(self.call(body)[0], 400)

    def test_oversized_character_budget_returns_input_limit(self):
        status, body = self.call(request([{"role": "user", "content": "x" * 8193}]))
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "INPUT_LIMIT")

    def test_exact_token_coverage_is_required(self):
        self.adapters.token_count = lambda _messages: 99
        gateway = Gateway(self.key, Path(self.tmp.name) / "coverage.sqlite", self.adapters, Policy(token_budget=98))
        status, result = gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + self.key}, request())
        self.assertEqual(status, 413)
        self.assertEqual(result["error"]["code"], "INPUT_LIMIT")
        self.assertEqual([e["event_type"] for e in gateway.audit_events()], ["request_started", "request_blocked"])

    def test_bad_token_counter_results_fail_closed(self):
        for invalid_count in (True, -1, "unknown", None):
            with self.subTest(invalid_count=invalid_count):
                self.adapters.token_count = lambda _serialized, value=invalid_count: value
                status, body = self.call(request())
                self.assertEqual(status, 503)
                self.assertEqual(body["error"]["code"], "UNAVAILABLE")
                self.assertNotIn("choices", body)
        self.assertEqual(self.adapters.generation_inputs, [])

    def test_missing_guards_fail_closed(self):
        gateway = Gateway(app_key=self.key, audit_path=Path(self.tmp.name) / "missing.sqlite", adapters=None)
        status, result = gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + self.key}, request())
        self.assertEqual(status, 503)
        self.assertEqual(result["error"]["code"], "UNAVAILABLE")

    def test_invalid_guard_result_fails_closed_without_leaking_content(self):
        self.adapters.attack_result = "allow"
        status, result = self.call(request([{"role": "user", "content": "secret PII test@example.com"}]))
        self.assertEqual(status, 503)
        self.assertEqual(result["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("secret", json.dumps(result))

    def test_generation_receives_only_sanitized_messages(self):
        self.call(request([{"role": "user", "content": "email test@example.com"}]))
        self.assertNotIn("test@example.com", json.dumps(self.adapters.generation_inputs))

    def test_input_pii_and_output_pii_are_not_in_response_or_audit(self):
        self.adapters.generated = "answer to 900101123456 test@example.com +60123456789"
        response = self.call(request([{"role": "user", "content": "0123456789 +60123456789 test@example.com 900101123456"}]))
        content_text = response[1]["choices"][0]["message"]["content"]
        self.assertIn("[MYKAD]", content_text)
        self.assertNotIn("900101123456", content_text)
        content = Path(self.tmp.name, "audit.sqlite3").read_bytes()
        for raw in (b"0123456789", b"+60123456789", b"test@example.com", b"900101123456"):
            self.assertNotIn(raw, content)

    def test_failures_are_generic_and_have_request_ids(self):
        self.adapters.attack_error = RuntimeError("prompt test@example.com secret")
        status, body = self.call(request([{"role": "user", "content": "test@example.com"}]))
        self.assertEqual(status, 503)
        self.assertTrue(body["error"]["request_id"])
        self.assertNotIn("test@example.com", json.dumps(body))
        self.assertNotIn("secret", json.dumps(body))

    def test_audit_writes_initial_and_terminal_events_and_recovers_orphans(self):
        self.call(request())
        events = self.gateway.audit_events()
        self.assertEqual([e["event_type"] for e in events], ["request_started", "request_completed"])
        self.assertNotIn("content", json.dumps(events))

    def test_initial_or_terminal_audit_write_failure_withholds_output(self):
        for stage in ("initial", "terminal"):
            g, a, key = make_demo_gateway(Path(self.tmp.name) / (stage + ".sqlite"))
            g.fail_audit_stage = stage
            status, body = g.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + key}, request())
            self.assertNotEqual(status, 200)
            self.assertNotIn("choices", body)
            self.assertEqual(len(a.generation_inputs), 0 if stage == "initial" else 1)
            if stage == "terminal":
                self.assertEqual(g.audit_events()[-1]["event_type"], "request_started")
                g.fail_audit_stage = None
                self.assertEqual(g.reconcile_incomplete(offline=True), 1)
                self.assertEqual(g.audit_events()[-1]["event_type"], "request_recovered")

    def test_authentication_is_constant_time_and_demo_key_is_nonempty(self):
        self.assertTrue(self.key)
        self.assertFalse(hasattr(self.gateway, "demo_key"))
        status, body = self.gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer wrong"}, request())
        self.assertEqual(status, 401)
        self.assertNotIn("wrong", json.dumps(body))

    def test_policy_digest_is_derived_and_output_cap_is_passed_to_adapter(self):
        policy = self.gateway.policy
        self.assertEqual(len(policy.digest), 64)
        self.assertEqual(self.call(request())[0], 200)
        self.assertEqual(self.adapters.generate_options, [("pilot-local", 1024)])
        response = self.call(request(max_tokens=17))
        self.assertEqual(response[0], 200)
        self.assertEqual(self.adapters.generate_options[-1], ("pilot-local", 17))
        self.assertNotIn("usage", response[1])

    def test_policy_block_has_403_and_untrusted_headers_fail_stably(self):
        self.adapters.attack_result = {"decision": "block"}
        status, body = self.call(request())
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        status, body = self.gateway.handle("POST", "/v1/chat/completions", None, request())
        self.assertEqual(status, 401)

    def _allow(self, **categories):
        self.gateway.policy = Policy(**categories)

    def test_input_block_passes_when_the_policy_allows_every_category(self):
        self._allow(input_allow_categories=("Copyright Violation",))
        self.adapters.attack_result = {
            "decision": "block",
            "categories": ["Copyright Violation"],
        }
        self.assertEqual(self.call(request())[0], 200)

    def test_input_block_holds_for_a_mixed_or_empty_category_list(self):
        self._allow(input_allow_categories=("Copyright Violation",))
        for categories in (["Copyright Violation", "Violent"], [], None):
            with self.subTest(categories=categories):
                self.adapters.attack_result = {
                    "decision": "block",
                    "categories": categories,
                }
                self.assertEqual(self.call(request())[0], 403)

    def test_each_lane_uses_its_own_allow_list(self):
        self._allow(input_allow_categories=("Violent",))
        self.adapters.output_result = {"safe": False, "categories": ["Violent"]}
        self.assertEqual(self.call(request())[0], 403)

        self._allow(output_allow_categories=("Violent",))
        self.assertEqual(self.call(request())[0], 200)
        self.adapters.attack_result = {"decision": "block", "categories": ["Violent"]}
        self.assertEqual(self.call(request())[0], 403)

    def test_policy_digest_cannot_be_overridden(self):
        with self.assertRaises((TypeError, ValueError)):
            Policy(version="v", digest="client-controlled")

    def test_explicit_offline_recovery_marks_incomplete_owned_events(self):
        with self.assertRaises(ValueError):
            self.gateway.reconcile_incomplete()
        self.gateway._audit("req_abandoned", "request_started", "pending")
        self.assertEqual(self.gateway.reconcile_incomplete(offline=True), 1)
        events = self.gateway.audit_events()
        self.assertEqual(events[-1]["event_type"], "request_recovered")

    def test_offline_recovery_preserves_original_policy_metadata(self):
        path = Path(self.tmp.name) / "policy-recovery.sqlite"
        original = Gateway(self.key, path, self.adapters, Policy(version="policy-a", token_budget=123))
        original._audit("req_policy_a", "request_started", "pending")
        restarted = Gateway(self.key, path, self.adapters, Policy(version="policy-b", token_budget=321))
        self.assertEqual(restarted.reconcile_incomplete(offline=True), 1)
        recovered = next(e for e in restarted.audit_events() if e["event_type"] == "request_recovered")
        self.assertEqual(recovered["policy_version"], "policy-a")
        self.assertEqual(recovered["model"], "pilot-local")
        self.assertEqual(recovered["policy_digest"], Policy(version="policy-a", token_budget=123).digest)

    def test_output_guard_block_and_malformed_results_release_nothing(self):
        self.adapters.output_result = {"safe": False}
        status, body = self.call(request())
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        self.adapters.output_result = {"missing": "safe"}
        status, body = self.call(request())
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "UNAVAILABLE")
        self.adapters.output_result = {"safe": True}
        self.adapters.output_error = RuntimeError("output guard failed")
        status, body = self.call(request())
        self.assertEqual(status, 503)
        self.assertNotIn("choices", body)

    def test_audit_start_precedes_generation_and_terminal_precedes_release(self):
        order = []
        original_audit = self.gateway._audit
        def audit(*args, **kwargs):
            order.append(args[1])
            return original_audit(*args, **kwargs)
        self.gateway._audit = audit
        original_generate = self.adapters.generate
        def generate(*args, **kwargs):
            order.append("generation")
            return original_generate(*args, **kwargs)
        self.adapters.generate = generate
        response = self.call(request())
        self.assertEqual(response[0], 200)
        self.assertLess(order.index("request_started"), order.index("generation"))
        self.assertLess(order.index("generation"), order.index("request_completed"))

    def _gateway(self, adapters, *, diagnostics=None, name="failure.sqlite3"):
        return Gateway(
            self.key,
            Path(self.tmp.name) / name,
            adapters,
            diagnostics=diagnostics,
        )

    def _call(self, gateway, body=None):
        return gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + self.key},
            request() if body is None else body,
        )

    def test_generation_diagnostic_is_counted_once_without_scan_context(self):
        sink = SafeDiagnostics()
        adapters = RaisingGenerationAdapters(
            GenerationError("truncated", diagnostic_code=GENERATION_TRUNCATED)
        )
        gateway = self._gateway(adapters, diagnostics=sink)
        status, body = self._call(gateway)
        self.assertEqual(status, 503)
        # The response body is exactly the pre-existing generic error shape.
        self.assertEqual(
            body,
            Gateway._error(503, "UNAVAILABLE", body["error"]["request_id"])[1],
        )
        self.assertEqual(sink.snapshot()[GENERATION_TRUNCATED], 1)
        self.assertEqual(
            [event["event_type"] for event in gateway.audit_events()],
            ["request_started", "request_failed"],
        )

    def test_shared_scan_context_and_gateway_sink_count_the_failure_once(self):
        sink = SafeDiagnostics()
        adapters = RaisingGenerationAdapters(
            GenerationError("truncated", diagnostic_code=GENERATION_TRUNCATED)
        )
        gateway = self._gateway(adapters, diagnostics=sink, name="shared.sqlite3")
        status, _ = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + self.key},
            request(),
            scan_context=ScanContext(diagnostic=sink),
        )
        self.assertEqual(status, 503)
        self.assertEqual(sink.snapshot()[GENERATION_TRUNCATED], 1)

    def test_each_failed_request_logs_one_content_free_stage_line(self):
        prompt = "PROMPT-CONTENT-MUST-NOT-BE-LOGGED"
        reply = "REPLY-CONTENT-MUST-NOT-BE-LOGGED"

        input_adapters = MemoryAdapters()
        input_adapters.attack_error = RuntimeError("guard failed: " + prompt)

        truncation = RaisingGenerationAdapters(
            GenerationError(prompt, diagnostic_code=GENERATION_TRUNCATED)
        )

        non_string = MemoryAdapters()
        non_string.generated = 42

        output_adapters = MemoryAdapters()
        output_adapters.generated = reply
        output_adapters.output_error = RuntimeError("output failed: " + reply)

        cases = (
            ("input_guard", input_adapters, None),
            ("generation", truncation, "diagnostic=generation_truncated"),
            ("generation", non_string, None),
            ("output_guard", output_adapters, None),
        )
        for index, (stage, adapters, diagnostic) in enumerate(cases):
            with self.subTest(stage=stage, index=index):
                gateway = self._gateway(adapters, name=f"log-{index}.sqlite3")
                with self.assertLogs(
                    "nasi_lemak.gateway", level="WARNING"
                ) as captured:
                    status, _ = self._call(
                        gateway, request([{"role": "user", "content": prompt}])
                    )
                self.assertEqual(status, 503)
                self.assertEqual(len(captured.output), 1, captured.output)
                line = captured.output[0]
                self.assertIn("request_failed request_id=req_", line)
                self.assertIn(f"stage={stage}", line)
                if diagnostic is None:
                    self.assertNotIn("diagnostic=", line)
                else:
                    self.assertIn(diagnostic, line)
                self.assertNotIn(prompt, line)
                self.assertNotIn(reply, line)

    def test_each_pre_validation_rejection_logs_one_content_free_reason(self):
        prompt = "REJECTION-PROMPT-MUST-NOT-BE-LOGGED"
        authenticated = {"Authorization": "Bearer " + self.key}
        unready = Gateway(
            self.key, Path(self.tmp.name) / "unready.sqlite3", adapters=None
        )
        cases = (
            (
                "unauthorized",
                self.gateway,
                {"Authorization": "Bearer wrong-key"},
                request([{"role": "user", "content": prompt}]),
                401,
            ),
            (
                "not_ready",
                unready,
                authenticated,
                request([{"role": "user", "content": prompt}]),
                503,
            ),
            (
                "model_mismatch",
                self.gateway,
                authenticated,
                request([{"role": "user", "content": prompt}], model="other-model"),
                400,
            ),
            (
                "unknown_field",
                self.gateway,
                authenticated,
                request([{"role": "user", "content": prompt}], tools=[]),
                400,
            ),
            (
                "invalid_request",
                self.gateway,
                authenticated,
                {"model": "pilot-local", "messages": []},
                400,
            ),
            (
                "input_limit",
                self.gateway,
                authenticated,
                request([{"role": "user", "content": "x" * 8193}]),
                413,
            ),
        )
        for reason, gateway, headers, body, status in cases:
            with self.subTest(reason=reason):
                with self.assertLogs(
                    "nasi_lemak.gateway", level="WARNING"
                ) as captured:
                    result_status, _ = gateway.handle(
                        "POST", "/v1/chat/completions", headers, body
                    )
                self.assertEqual(result_status, status)
                self.assertEqual(len(captured.output), 1, captured.output)
                line = captured.output[0]
                self.assertIn("request_rejected request_id=req_", line)
                self.assertIn(f"status={status}", line)
                self.assertIn(f"reason={reason}", line)
                self.assertNotIn(prompt, line)
                self.assertNotIn("other-model", line)
                self.assertNotIn("tools", line)

    def test_unknown_rejection_reason_collapses_to_invalid_request(self):
        with self.assertLogs("nasi_lemak.gateway", level="WARNING") as captured:
            log_rejection("req_test", 400, "not-a-reason")
        self.assertEqual(len(captured.output), 1, captured.output)
        self.assertIn("reason=invalid_request", captured.output[0])

    def test_configured_system_prompt_never_reaches_guards_or_audit(self):
        prompt = "SYSTEM-PROMPT-MUST-STAY-INSIDE-GENERATION"

        class Client:
            def generate(self, messages, max_tokens):
                # Stands in for GenerationClient: the prompt is added to the
                # upstream payload only.
                upstream.append([{"role": "system", "content": prompt}, *messages])
                return "safe reply"

        class Tokenizer:
            def count_tokens(self, serialized):
                return 1

        class AttackGuard:
            def __init__(self):
                self.inputs = []

            def scan_attack(self, text):
                self.inputs.append(text)
                return {"decision": "allow"}

        class OutputGuard:
            def __init__(self):
                self.messages = []
                self.outputs = []

            def scan_response(self, messages, output):
                self.messages.append([dict(message) for message in messages])
                self.outputs.append(output)
                return {"safe": True}

        upstream = []
        attack = AttackGuard()
        output = OutputGuard()
        adapters = RealGatewayAdapters(
            Client(),
            tokenizer=Tokenizer(),
            attack_guard=attack,
            output_guard=output,
        )
        gateway = self._gateway(adapters, name="prompt.sqlite3")
        status, _ = self._call(
            gateway, request([{"role": "user", "content": "hello"}])
        )
        self.assertEqual(status, 200)
        self.assertEqual(upstream[0][0], {"role": "system", "content": prompt})
        for label, value in (
            ("attack", attack.inputs),
            ("scan_context", output.messages),
            ("scan_output", output.outputs),
            ("audit", gateway.audit_events()),
        ):
            with self.subTest(label=label):
                self.assertNotIn(prompt, json.dumps(value))


if __name__ == "__main__":
    unittest.main()

