"""Deny-phrase normalisation tests.

Every request goes through the real FastAPI ASGI application, the real
``Gateway`` and a real SQLite audit store.  Guard and generation behaviour
comes from deterministic local doubles: no network, no model and no PostgreSQL
server is contacted.  The OWASP benign controls and the every-expect-200-row
replay are read from the frozen corpus and never modified.
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
from nasi_lemak.gateway import (
    Policy,
    _normalize_deny_text,
    _normalize_deny_text_spaced,
    serialize_messages,
)
from nasi_lemak.generation import conservative_byte_budget
from nasi_lemak.server import make_app

TEST_KEY = "deny-normalisation-test-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
AUDIT_DSN = "postgresql://unused.invalid/nasi_lemak"
DENY = "synthetic denied phrase"
EVALS = Path(__file__).resolve().parent.parent / "evals" / "owasp"
CORPUS = EVALS / "llm-top10-2026" / "payloads" / "controls_benign.jsonl"
PAYLOADS = EVALS / "llm-top10-2026" / "payloads"
REBASELINE = EVALS / "rebaseline-llm-top10-2026.json"


def _payload_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(PAYLOADS.glob("*.jsonl")):
        records.extend(
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    return records
# Legacy digest: SHA-256 over the canonical JSON of the raw fields below,
# including the raw deny phrase (no normalisation).  Captured before the
# normaliser was added; it must not change.
LEGACY_DIGEST = "3462e6a641342c014873593533d9bb76beb828585a975c1625fa1f0266dad662"


class _Adapters:
    """Deterministic local generation/guard double; no network or ML."""

    def __init__(self, counter: Any = None) -> None:
        self.attack_inputs: list[str] = []
        self.generate_inputs: list[list[dict[str, str]]] = []
        self.output_inputs: list[str] = []
        self.generated = "Safe synthetic answer."
        self.attack_result: Any = {"decision": "allow"}
        self.output_result: Any = {"safe": True}
        self.counter = counter

    def count_tokens(self, serialized: str) -> int:
        if self.counter is not None:
            return self.counter(serialized)
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

    def test_every_unicode_format_character_is_removed_or_replaced(self) -> None:
        format_characters = [
            chr(code)
            for code in range(0x110000)
            if unicodedata.category(chr(code)) == "Cf"
        ]
        self.assertIn("\u200b", format_characters)
        self.assertIn("\ufeff", format_characters)
        for character in format_characters:
            with self.subTest(character=hex(ord(character))):
                # Form (a): deleted, so an intra-word insertion stays joined.
                self.assertEqual(
                    _normalize_deny_text("a" + character + "b"), "ab"
                )
                # Form (b): replaced by one separator, so it cannot join words.
                self.assertEqual(
                    _normalize_deny_text_spaced("a" + character + "b"), "a b"
                )

        _, client = self._app(Policy(deny_phrases=(DENY,)))
        hidden = "synthetic" + "".join(format_characters) + " denied phrase"
        self._assert_blocked(
            self._post(client, [{"role": "user", "content": hidden}])
        )

    def test_format_character_standing_in_for_the_word_separator_is_blocked(
        self,
    ) -> None:
        _, client = self._app(Policy(deny_phrases=(DENY,)))
        variants = {
            "zero-width-space": "synthetic\u200bdenied phrase",
            "soft-hyphen": "synthetic\u00addenied phrase",
            "byte-order-mark": "synthetic\ufeffdenied phrase",
        }
        for name, content in variants.items():
            with self.subTest(name=name):
                self.assertTrue(Policy(deny_phrases=(DENY,)).denies(content))
                self._assert_blocked(
                    self._post(client, [{"role": "user", "content": content}])
                )

    def test_intra_word_format_character_variants_stay_blocked(self) -> None:
        _, client = self._app(Policy(deny_phrases=(DENY,)))
        variants = {
            "zero-width-space": "synthetic deni\u200bed phrase",
            "soft-hyphen": "synthetic deni\u00aded phrase",
            "byte-order-mark": "synthetic deni\ufeffed phrase",
        }
        for name, content in variants.items():
            with self.subTest(name=name):
                self.assertTrue(Policy(deny_phrases=(DENY,)).denies(content))
                self._assert_blocked(
                    self._post(client, [{"role": "user", "content": content}])
                )

    def test_phrase_still_requires_its_own_word_boundaries(self) -> None:
        policy = Policy(deny_phrases=("not allowed",))
        # Form (b) separates words instead of squashing them, so a phrase is
        # never matched inside a longer word.
        for content in ("notallowed", "notallowedhere", "cannotallowed"):
            with self.subTest(content=content):
                self.assertFalse(policy.denies(content))
        self.assertTrue(policy.denies("not  allowed"))
        self.assertTrue(policy.denies("not\u200ballowed"))

        _, client = self._app(policy)
        response = self._post(
            client, [{"role": "user", "content": "the word notallowed is benign"}]
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.adapters.generate_inputs), 1)

    def test_policy_phrase_and_candidate_use_the_same_normalisation(self) -> None:
        fullwidth = "".join(
            "\u3000" if char == " " else chr(ord(char) + 0xFEE0) for char in DENY
        )
        variants = (
            "Synthetic Denied Phrase",
            "synthetic  denied phrase",
            "synthetic\ndenied phrase",
            "synthetic\u200b denied phrase",
            "synthetic\u200bdenied phrase",
            "synthetic\u00addenied phrase",
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

        # Known residual limitation, recorded in docs/owasp-corpus.md:
        # accents are deliberately preserved, so a diacritic substitution for
        # an ASCII letter is not folded to the configured phrase.
        denial = Policy(deny_phrases=(DENY,))
        self.assertFalse(denial.denies("synthetic den\u0131ed phrase"))
        self.assertFalse(denial.denies("synthetic denie\u0301d phrase"))

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

    def test_benign_controls_use_the_real_counter_and_assert_per_row_truth(
        self,
    ) -> None:
        """Counter: nasi_lemak.generation.conservative_byte_budget (the product's).

        The deployed guard-API, hosted-guard and test-mode adapters use this
        counter and the Policy default token_budget of 512.  Counting words
        would wrongly turn CTRL-007 into an allowed row.
        """
        records = [
            json.loads(line)
            for line in CORPUS.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual([record["id"] for record in records], [
            "CTRL-%03d" % number for number in range(1, 19)
        ])
        self.adapters = _Adapters(counter=conservative_byte_budget)
        _, client = self._app(
            Policy(deny_phrases=(DENY, "forbidden phrase", "system prompt"))
        )
        rejected: list[str] = []
        for record in records:
            units = conservative_byte_budget(serialize_messages(record["messages"]))
            with self.subTest(control=record["id"], units=units):
                response = self._post(client, record["messages"])
                if units > 512:
                    rejected.append(record["id"])
                    # A token-budget rejection, not a guard false positive.
                    self.assertEqual(response.status_code, 413, response.text)
                    body = response.json()
                    self.assertEqual(body["error"]["code"], "INPUT_LIMIT")
                    self.assertNotIn("choices", body)
                else:
                    self.assertEqual(response.status_code, 200, response.text)
                    body = response.json()
                    self.assertNotIn("error", body)
                    self.assertIn("choices", body)
        self.assertEqual(rejected, ["CTRL-007"])
        # CTRL-007 is 1439 content characters and 1449 conservative units;
        # 17 benign controls reach generation and only CTRL-007 does not.
        ctrl_007 = records[6]
        self.assertEqual(ctrl_007["id"], "CTRL-007")
        self.assertEqual(len(ctrl_007["messages"][0]["content"]), 1439)
        self.assertEqual(
            conservative_byte_budget(serialize_messages(ctrl_007["messages"])),
            1449,
        )
        self.assertEqual(len(self.adapters.generate_inputs), 17)

    def test_inverse_class_map_matches_every_expect_200_row(self) -> None:
        """Replay every expect-200 row over the real app and real counter."""
        rebaseline = json.loads(REBASELINE.read_text(encoding="utf-8"))
        inverse = rebaseline["inverse_class"]["rows"]
        self.adapters = _Adapters(counter=conservative_byte_budget)
        _, client = self._app(Policy())
        observed: list[tuple[str, int, str]] = []
        for record in _payload_records():
            if record["expect_status"] != 200:
                continue
            response = self._post(client, record["messages"])
            if response.status_code != 200:
                observed.append(
                    (
                        record["id"],
                        response.status_code,
                        response.json()["error"]["code"],
                    )
                )
        self.assertEqual(observed, [("CTRL-007", 413, "INPUT_LIMIT")])
        self.assertEqual(
            [(row["id"], row["observed_status"], row["observed_code"]) for row in inverse],
            observed,
        )
        # The inverse class is exactly the limit class, not any guard block.
        for row in inverse:
            self.assertEqual(row["expect_status"], 200)
            self.assertIsNone(row["expect_code"])
            self.assertEqual(row["observed_status"], 413)
            self.assertEqual(row["observed_code"], "INPUT_LIMIT")

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
