"""Deny-phrase normalisation tests.

Every request goes through the real FastAPI ASGI application, the real
``Gateway`` and a real SQLite audit store.  Guard and generation behaviour
comes from deterministic local doubles: no network, no model and no PostgreSQL
server is contacted.  The OWASP benign controls are read from the frozen
corpus and never modified.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unicodedata
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from nasi_lemak import gateway as gateway_module
from nasi_lemak import server as server_module
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Policy, _normalize_deny_text
from nasi_lemak.server import make_app

TEST_KEY = "deny-normalisation-test-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
AUDIT_DSN = "postgresql://unused.invalid/nasi_lemak"
DENY = "synthetic denied phrase"
CORPUS = (
    Path(__file__).resolve().parent.parent
    / "evals"
    / "owasp"
    / "llm-top10-2026"
    / "payloads"
    / "controls_benign.jsonl"
)
# Legacy digest: SHA-256 over the canonical JSON of the raw fields below,
# including the raw deny phrase (no normalisation).  Captured before the
# normaliser was added; it must not change.
LEGACY_DIGEST = "3462e6a641342c014873593533d9bb76beb828585a975c1625fa1f0266dad662"


class _Adapters:
    """Deterministic local generation/guard double; no network or ML."""

    def __init__(self) -> None:
        self.attack_inputs: list[str] = []
        self.generate_inputs: list[list[dict[str, str]]] = []
        self.output_inputs: list[str] = []
        self.generated = "Safe synthetic answer."
        self.attack_result: Any = {"decision": "allow"}
        self.output_result: Any = {"safe": True}

    def count_tokens(self, serialized: str) -> int:
        return max(1, len(serialized.split()))

    def scan_attack(self, text: str) -> Any:
        self.attack_inputs.append(text)
        return self.attack_result

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        self.generate_inputs.append([dict(message) for message in messages])
        return self.generated

    def scan_output(self, text: str) -> Any:
        self.output_inputs.append(text)
        return self.output_result


def _legacy_digest(policy: Policy) -> str:
    canonical = json.dumps(
        {
            "app_id": policy.app_id,
            "deny_phrases": list(policy.deny_phrases),
            "model": policy.model,
            "token_budget": policy.token_budget,
            "version": policy.version,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DenyNormalisationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.adapters = _Adapters()

    def _app(self, policy: Policy):
        with mock.patch.object(
            server_module,
            "PostgresAuditStore",
            lambda _dsn: SqliteAuditStore(self.root / "audit.sqlite3"),
        ):
            app = make_app(
                environ={
                    "NASI_LEMAK_APP_KEY_DIGEST": hashlib.sha256(
                        TEST_KEY.encode("utf-8")
                    ).hexdigest(),
                    "NASI_LEMAK_AUDIT_DSN": AUDIT_DSN,
                },
                adapters=self.adapters,
                policy=policy,
            )
        self.assertTrue(app.state.config_ready)
        client = TestClient(app)
        self.addCleanup(client.close)
        return app, client

    def _post(self, client: TestClient, messages: list[dict[str, str]]):
        return client.post(
            "/v1/chat/completions",
            json={"model": "pilot-local", "messages": messages},
            headers=AUTH,
        )

    def _assert_blocked(self, response: Any) -> None:
        self.assertEqual(response.status_code, 403, response.text)
        body = response.json()
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(body["error"]["block"]["stage"], "input")
        self.assertEqual(
            body["error"]["block"]["reason_code"], "INPUT_POLICY_BLOCK"
        )
        self.assertNotIn("choices", body)
        self.assertEqual(self.adapters.generate_inputs, [])

    def test_exact_and_uppercase_phrases_remain_blocked(self) -> None:
        _, client = self._app(Policy(deny_phrases=(DENY,)))
        for content in (DENY, "SYNTHETIC DENIED PHRASE"):
            with self.subTest(content=content):
                self._assert_blocked(
                    self._post(client, [{"role": "user", "content": content}])
                )

    def test_whitespace_compatibility_and_format_bypasses_are_blocked(self) -> None:
        _, client = self._app(Policy(deny_phrases=(DENY,)))
        fullwidth = "".join(
            "\u3000" if char == " " else chr(ord(char) + 0xFEE0) for char in DENY
        )
        self.assertIn("\uff53", fullwidth)
        variants = {
            "double-space": "synthetic  denied phrase",
            "newline": "synthetic\ndenied phrase",
            "fullwidth": fullwidth,
            "zero-width-space": "synthetic\u200b denied phrase",
            "non-ascii-whitespace": "synthetic\u00a0denied\u2003phrase",
        }
        for name, content in variants.items():
            with self.subTest(name=name):
                self._assert_blocked(
                    self._post(client, [{"role": "user", "content": content}])
                )

    def test_every_unicode_format_character_is_removed(self) -> None:
        format_characters = [
            chr(code)
            for code in range(0x110000)
            if unicodedata.category(chr(code)) == "Cf"
        ]
        self.assertIn("\u200b", format_characters)
        self.assertIn("\ufeff", format_characters)
        for character in format_characters:
            with self.subTest(character=hex(ord(character))):
                self.assertEqual(
                    _normalize_deny_text("a" + character + "b"), "ab"
                )

        _, client = self._app(Policy(deny_phrases=(DENY,)))
        hidden = "synthetic" + "".join(format_characters) + " denied phrase"
        self._assert_blocked(
            self._post(client, [{"role": "user", "content": hidden}])
        )

    def test_policy_phrase_and_candidate_use_the_same_normalisation(self) -> None:
        fullwidth = "".join(
            "\u3000" if char == " " else chr(ord(char) + 0xFEE0) for char in DENY
        )
        variants = (
            "Synthetic Denied Phrase",
            "synthetic  denied phrase",
            "synthetic\ndenied phrase",
            "synthetic\u200b denied phrase",
            "synthetic\u00a0denied\u3000phrase",
            fullwidth,
        )
        candidate = "SYNTHETIC\u00a0 DENIED  PHRASE"
        for phrase in variants:
            with self.subTest(phrase=phrase):
                policy = Policy(deny_phrases=(phrase,))
                self.assertTrue(policy.denies(candidate))
                self.assertTrue(policy.denies(DENY))

    def test_phrase_normalisation_is_cached_once_at_construction(self) -> None:
        original = gateway_module._normalize_deny_text
        with mock.patch.object(
            gateway_module, "_normalize_deny_text", wraps=original
        ) as normalizer:
            policy = Policy(deny_phrases=("One Phrase", "Two  Phrase"))
            self.assertEqual(normalizer.call_count, 2)
            for _ in range(5):
                self.assertTrue(policy.denies("one phrase"))
                self.assertFalse(policy.denies("unrelated"))
            # Only constructions normalise phrases; matching normalises text.
            self.assertEqual(normalizer.call_count, 2 + (5 * 2))

    def test_empty_normalisation_phrase_is_rejected_not_match_all(self) -> None:
        for phrase in ("\u200b", " \t\n", "\ufeff", "\u200d\u2060"):
            with self.subTest(phrase=phrase):
                with self.assertRaises(ValueError):
                    Policy(deny_phrases=(phrase,))
        policy = Policy(deny_phrases=(DENY,))
        self.assertFalse(policy.denies(""))
        self.assertFalse(policy.denies("\u200b \ufeff"))
        self.assertFalse(Policy(deny_phrases=()).denies("anything"))

    def test_accents_are_preserved_not_stripped(self) -> None:
        policy = Policy(deny_phrases=("naïve café",))
        self.assertTrue(policy.denies("NAÏVE CAFÉ"))
        self.assertTrue(policy.denies("NAI\u0308VE CAFE\u0301"))
        self.assertFalse(policy.denies("naive cafe"))

        _, client = self._app(policy)
        response = self._post(
            client, [{"role": "user", "content": "a naive cafe story"}]
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.adapters.generate_inputs.clear()
        self._assert_blocked(
            self._post(client, [{"role": "user", "content": "NAÏVE CAFÉ"}])
        )

    def test_normalised_output_phrase_is_blocked_before_release(self) -> None:
        _, client = self._app(Policy(deny_phrases=(DENY,)))
        self.adapters.generated = "prefix synthetic\u200b  denied\nphrase suffix"
        response = self._post(
            client, [{"role": "user", "content": "ordinary input"}]
        )
        self.assertEqual(response.status_code, 403, response.text)
        body = response.json()
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(body["error"]["block"]["stage"], "output")
        self.assertEqual(
            body["error"]["block"]["reason_code"], "OUTPUT_POLICY_BLOCK"
        )
        self.assertNotIn("choices", body)
        self.assertEqual(len(self.adapters.generate_inputs), 1)

    def test_phrase_split_across_turns_is_not_joined(self) -> None:
        _, client = self._app(Policy(deny_phrases=(DENY,)))
        response = self._post(
            client,
            [
                {"role": "user", "content": "synthetic denied"},
                {"role": "assistant", "content": "phrase"},
            ],
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.adapters.generate_inputs), 1)

    def test_all_eighteen_benign_controls_remain_allowed(self) -> None:
        records = [
            json.loads(line)
            for line in CORPUS.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual([record["id"] for record in records], [
            "CTRL-%03d" % number for number in range(1, 19)
        ])
        _, client = self._app(
            Policy(deny_phrases=(DENY, "forbidden phrase", "system prompt"))
        )
        for record in records:
            with self.subTest(control=record["id"]):
                response = self._post(client, record["messages"])
                self.assertEqual(response.status_code, 200, response.text)
                body = response.json()
                self.assertNotIn("error", body)
                self.assertIn("choices", body)
        self.assertEqual(len(self.adapters.generate_inputs), 18)

    def test_digest_still_covers_raw_phrases_and_audit_matches_legacy(self) -> None:
        policy = Policy(
            app_id="nasi-lemak",
            version="2026-10-20.1",
            model="pilot-local",
            token_budget=128,
            deny_phrases=("Forbidden Phrase",),
        )
        self.assertEqual(policy.digest, LEGACY_DIGEST)
        self.assertEqual(_legacy_digest(policy), LEGACY_DIGEST)
        # A phrase that only differs after normalisation keeps a distinct raw
        # digest, so activation and audit identity are not collapsed.
        self.assertNotEqual(
            Policy(
                app_id="nasi-lemak",
                version="2026-10-20.1",
                model="pilot-local",
                token_budget=128,
                deny_phrases=("forbidden  phrase",),
            ).digest,
            LEGACY_DIGEST,
        )

        app, client = self._app(policy)
        response = self._post(
            client, [{"role": "user", "content": "ordinary benign request"}]
        )
        self.assertEqual(response.status_code, 200, response.text)
        events = app.state.gateway.audit_events()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_completed"],
        )
        for event in events:
            self.assertEqual(event["policy_digest"], LEGACY_DIGEST)
        self.assertEqual(app.state.policy_digest, LEGACY_DIGEST)


if __name__ == "__main__":
    unittest.main()
