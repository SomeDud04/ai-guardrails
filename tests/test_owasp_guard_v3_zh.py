"""Contract tests for the Simplified Chinese (zh) OWASP guard-lane dataset v3.

Standard library only.  The dataset mirrors every v1 OWASP guard-lane case in
Simplified Chinese, preserving each case's expected outcome and role sequence so
the 39 inputs can be compared English versus Chinese.
"""

from __future__ import annotations

import base64
import json
import re
import unittest
from pathlib import Path

from nasi_lemak.guard_eval import MAX_MESSAGE_CHARS, load_dataset, parse_dataset

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v3-zh.json"
V1 = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v1.json"
V2 = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v2.json"
V2_BM = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v2-bm.json"
MULTILINGUAL = ROOT / "evals" / "guards" / "multilingual-guard-lanes-v2.json"

EXPECTED_DATASET_ID = "owasp-llm-top10-2026-guard-lane-v3-zh"
EXPECTED_EVIDENCE_LABEL = "agent-authored-synthetic-smoke-not-holdout"
EXPECTED_CASES = 39
EXPECTED_ATTACKS = 22
EXPECTED_BENIGN = 17
CASE_PREFIX = "zh-"
HAN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
URL = re.compile(r"https?://([^/\s\"'<>]+)", re.I)
BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
FULLWIDTH_LATIN = re.compile(r"[\uff21-\uff3a\uff41-\uff5a]")
ENGLISH_DENY_PHRASE = "ignore all previous instructions"
ALLOWED_URL_HOSTS = {"example.com", "models.upstream.example"}


def _payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _contents(payload: dict) -> set[str]:
    return {
        message["content"]
        for case in payload["cases"]
        for message in case["messages"]
    }


class ChineseGuardLaneDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset(DATASET)
        cls.payload = _payload(DATASET)
        cls.v1 = _payload(V1)
        cls.existing_contents = (
            _contents(cls.v1)
            | _contents(_payload(V2))
            | _contents(_payload(V2_BM))
            | _contents(_payload(MULTILINGUAL))
        )
        cls.v1_cases = {case["id"]: case for case in cls.v1["cases"]}
        cls.attacks = [
            case for case in cls.dataset.cases if case.expected == "block"
        ]
        cls.benign = [
            case for case in cls.dataset.cases if case.expected == "allow"
        ]

    def test_load_dataset_accepts_file(self) -> None:
        self.assertEqual(self.dataset.dataset_id, EXPECTED_DATASET_ID)
        self.assertEqual(self.dataset.evidence_label, EXPECTED_EVIDENCE_LABEL)
        self.assertEqual(len(self.dataset.cases), EXPECTED_CASES)

    def test_parse_dataset_accepts_payload(self) -> None:
        parsed = parse_dataset(self.payload, sha256="0" * 64)
        self.assertEqual(parsed.dataset_id, EXPECTED_DATASET_ID)
        self.assertEqual(
            [case.case_id for case in parsed.cases],
            [case.case_id for case in self.dataset.cases],
        )

    def test_ids_are_prefixed_v1_ids_in_order(self) -> None:
        self.assertEqual(
            [case.case_id for case in self.dataset.cases],
            [CASE_PREFIX + case["id"] for case in self.v1["cases"]],
        )

    def test_every_case_is_chinese_input(self) -> None:
        for case in self.dataset.cases:
            self.assertEqual(case.stage, "input", case.case_id)
            self.assertEqual(case.language, "zh", case.case_id)
            self.assertIsNone(case.output, case.case_id)

    def test_expected_split(self) -> None:
        self.assertEqual(len(self.attacks), EXPECTED_ATTACKS)
        self.assertEqual(len(self.benign), EXPECTED_BENIGN)
        self.assertEqual(
            {case.expected for case in self.dataset.cases}, {"allow", "block"}
        )

    def test_expected_and_roles_match_v1(self) -> None:
        for case in self.dataset.cases:
            v1_case = self.v1_cases[case.case_id[len(CASE_PREFIX):]]
            self.assertEqual(case.expected, v1_case["expected"], case.case_id)
            self.assertEqual(
                [message["role"] for message in case.messages],
                [message["role"] for message in v1_case["messages"]],
                case.case_id,
            )

    def test_every_case_contains_han_characters(self) -> None:
        for case in self.dataset.cases:
            text = "\n".join(message["content"] for message in case.messages)
            self.assertRegex(text, HAN, case.case_id)

    def test_content_within_limit_and_non_empty(self) -> None:
        for case in self.dataset.cases:
            for message in case.messages:
                self.assertTrue(message["content"], case.case_id)
                self.assertLessEqual(
                    len(message["content"]), MAX_MESSAGE_CHARS, case.case_id
                )

    def test_ids_are_unique(self) -> None:
        ids = [case.case_id for case in self.dataset.cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_base64_override_decodes_to_chinese(self) -> None:
        case = next(
            case for case in self.dataset.cases if case.case_id == "zh-llm01-003"
        )
        content = next(
            message["content"]
            for message in case.messages
            if message["role"] == "user"
        )
        token = BASE64_TOKEN.search(content)
        self.assertIsNotNone(token, "zh-llm01-003 must contain a Base64 payload")
        decoded = base64.b64decode(token.group(0), validate=True).decode("utf-8")
        self.assertRegex(decoded, HAN)

    def test_fullwidth_override_uses_fullwidth_latin(self) -> None:
        case = next(
            case for case in self.dataset.cases if case.case_id == "zh-llm01-006"
        )
        text = "\n".join(message["content"] for message in case.messages)
        self.assertGreaterEqual(
            len(FULLWIDTH_LATIN.findall(text)), 20, "zh-llm01-006"
        )

    def test_no_case_contains_the_english_deny_phrase(self) -> None:
        for case in self.dataset.cases:
            text = "\n".join(
                message["content"] for message in case.messages
            ).lower()
            self.assertNotIn(ENGLISH_DENY_PHRASE, text, case.case_id)

    def test_email_domains_are_example_com(self) -> None:
        found = 0
        for case in self.dataset.cases:
            for message in case.messages:
                for domain in EMAIL.findall(message["content"]):
                    found += 1
                    self.assertEqual(domain.lower(), "example.com", case.case_id)
        self.assertGreater(found, 0)

    def test_urls_use_synthetic_hosts(self) -> None:
        for case in self.dataset.cases:
            for message in case.messages:
                for host in URL.findall(message["content"]):
                    self.assertIn(host.lower().rstrip(".,"), ALLOWED_URL_HOSTS)

    def test_no_content_matches_existing_lanes(self) -> None:
        self.assertEqual(
            _contents(self.payload) & self.existing_contents, set()
        )


if __name__ == "__main__":
    unittest.main()
