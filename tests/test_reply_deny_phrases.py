"""Reply-only deny phrases: end-to-end behaviour through the gateway.

All adapters are deterministic local doubles; no network, no real model and no
pretrained checkpoint is contacted.  The policy file's ``reply_deny_phrases``
list is checked only against the model's buffered reply, never against an
input turn, and a matching reply is withheld exactly like today's
``deny_phrases`` output block.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, Policy

TEST_KEY = "reply-deny-test-key"


class _Adapters:
    """Deterministic local generation/guard double; no network or ML."""

    def __init__(self) -> None:
        self.generate_inputs: list[list[dict[str, str]]] = []
        self.generated = "A clean synthetic answer."
        self.attack_result: Any = {"decision": "allow"}
        self.output_result: Any = {"safe": True}

    def count_tokens(self, serialized: str) -> int:
        return max(1, len(serialized.split()))

    def scan_attack(self, text: str) -> Any:
        return self.attack_result

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        self.generate_inputs.append([dict(message) for message in messages])
        return self.generated

    def scan_output(self, text: str) -> Any:
        return self.output_result


class ReplyDenyPhraseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._store_count = 0

    def _next_audit_path(self) -> Path:
        self._store_count += 1
        return Path(self.tmp.name) / f"reply-deny-{self._store_count}.sqlite3"

    def _gateway(
        self,
        adapters: _Adapters | None = None,
        **policy_kwargs: Any,
    ) -> tuple[Gateway, _Adapters]:
        policy = Policy(deny_phrases=("forbidden input phrase",), **policy_kwargs)
        adapters = adapters or _Adapters()
        gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(self._next_audit_path()),
            adapters=adapters,
            policy=policy,
        )
        return gateway, adapters

    def _call(self, gateway: Gateway, content: str):
        body = {
            "model": "pilot-local",
            "messages": [{"role": "user", "content": content}],
        }
        return gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer " + TEST_KEY},
            body,
        )

    def _assert_withheld(self, gateway: Gateway, result: tuple[int, dict[str, Any]]) -> None:
        status, payload = result
        self.assertEqual(status, 403)
        # The public body keeps one generic code; the bounded detail carries
        # the actual reason code.
        self.assertEqual(payload["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(payload["error"]["block"]["reason_code"], "OUTPUT_POLICY_BLOCK")
        self.assertEqual(payload["error"]["block"]["stage"], "output")
        self.assertNotIn("choices", payload)
        sample = gateway.metrics.snapshot()["recent"][0]
        self.assertEqual(sample["block_source"], "deny_phrase_output")
        events = gateway.audit_events()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_blocked"],
        )
        self.assertEqual(events[-1]["error_code"], "POLICY_BLOCK")

    def test_a_prompt_nameing_a_reply_phrase_is_answered(self) -> None:
        answers = [
            "how many words? exactly 200 words",
            "which model are you? maybe Qwen",
            "200 字",
            "通义",
        ]
        for content in answers:
            with self.subTest(prompt=content):
                gateway, adapters = self._gateway(
                    reply_deny_phrases=("200 words", "Qwen", "200 字", "通义")
                )
                status, payload = self._call(gateway, content)
                self.assertEqual(status, 200, payload)
                self.assertEqual(payload["choices"][0]["message"]["content"], adapters.generated)
                self.assertEqual(adapters.generate_inputs[0][0]["content"], content)

    def test_a_reply_containing_a_reply_phrase_is_withheld(self) -> None:
        adapters = _Adapters()
        adapters.generated = "Here is the answer: you get 200 words exactly."
        gateway, _ = self._gateway(adapters, reply_deny_phrases=("200 words",))

        result = self._call(gateway, "plain ordinary input")

        self._assert_withheld(gateway, result)

    def test_variant_reply_spellings_are_witheld_too(self) -> None:
        cases = {
            "fullwidth": "ＱＷＥＮ",
            "cjk-spaced": "通 义",
        }
        for name, needle in cases.items():
            with self.subTest(name=name):
                adapters = _Adapters()
                adapters.generated = f"The engine {needle} made this."
                gateway, _ = self._gateway(adapters, reply_deny_phrases=("Qwen", "通义"))
                self._assert_withheld(gateway, self._call(gateway, "ordinary input"))

    def test_a_clean_reply_still_passes_with_reply_phrases_configured(self) -> None:
        adapters = _Adapters()
        adapters.generated = "A completely clean answer about nothing."
        gateway, adapters = self._gateway(
            adapters, reply_deny_phrases=("200 words", "Qwen")
        )

        status, payload = self._call(gateway, "ordinary input")

        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["choices"][0]["message"]["content"], adapters.generated)
        events = gateway.audit_events()
        self.assertEqual(events[-1]["event_type"], "request_completed")

    def test_input_deny_phrases_keep_blocking_inputs_and_replies(self) -> None:
        gateway, adapters = self._gateway(
            reply_deny_phrases=("200 words",),
        )

        status, payload = self._call(
            gateway, "please include forbidden INPUT PHRASE today"
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(adapters.generate_inputs, [])

        adapters.generated = "mentions the forbidden input phrase again"
        status, payload = self._call(gateway, "ordinary input")
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload["error"]["code"], "POLICY_BLOCK")
        sample = gateway.metrics.snapshot()["recent"][0]
        self.assertEqual(sample["block_source"], "deny_phrase_output")


if __name__ == "__main__":
    unittest.main()
