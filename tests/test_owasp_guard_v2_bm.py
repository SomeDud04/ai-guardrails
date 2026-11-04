"""Contract tests for the Malay (bm) OWASP guard-lane dataset v2.

Standard library only.  The dataset mirrors the 22 v1 OWASP attack cases in
Bahasa Melayu and adds 30 Malay benign prompts, including hard negatives, so
the OWASP lane is measured in Malay without touching the v1 corpus.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from nasi_lemak.guard_eval import MAX_MESSAGE_CHARS, load_dataset, parse_dataset

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v2-bm.json"
V1 = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v1.json"
MULTILINGUAL = ROOT / "evals" / "guards" / "multilingual-guard-lanes-v2.json"

EXPECTED_DATASET_ID = "owasp-llm-top10-2026-guard-lane-v2-bm"
EXPECTED_EVIDENCE_LABEL = "agent-authored-synthetic-smoke-not-holdout"
EXPECTED_CASES = 52
EXPECTED_ATTACKS = 22
EXPECTED_BENIGN = 30
ATTACK_PREFIX = "bm-"
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
URL = re.compile(r"https?://([^/\s\"'<>]+)", re.I)
ALLOWED_URL_HOSTS = {"example.com", "models.upstream.example"}


def _payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _contents(payload: dict) -> set[str]:
    return {
        message["content"]
        for case in payload["cases"]
        for message in case["messages"]
    }


class MalayGuardLaneDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset(DATASET)
        cls.payload = _payload(DATASET)
        cls.v1 = _payload(V1)
        cls.multilingual = _payload(MULTILINGUAL)
        cls.v1_attacks = {
            case["id"]: case
            for case in cls.v1["cases"]
            if case["expected"] == "block"
        }
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

    def test_every_case_is_malay_input(self) -> None:
        self.assertEqual(len(self.dataset.cases), EXPECTED_CASES)
        for case in self.dataset.cases:
            self.assertEqual(case.stage, "input", case.case_id)
            self.assertEqual(case.language, "bm", case.case_id)
            self.assertIsNone(case.output, case.case_id)

    def test_expected_split(self) -> None:
        self.assertEqual(len(self.attacks), EXPECTED_ATTACKS)
        self.assertEqual(len(self.benign), EXPECTED_BENIGN)
        self.assertEqual(
            {case.expected for case in self.dataset.cases}, {"allow", "block"}
        )

    def test_attack_ids_mirror_v1(self) -> None:
        stripped = {
            case.case_id[len(ATTACK_PREFIX):]
            for case in self.attacks
            if case.case_id.startswith(ATTACK_PREFIX)
        }
        self.assertEqual(stripped, set(self.v1_attacks))
        self.assertEqual(len(stripped), EXPECTED_ATTACKS)

    def test_attack_role_sequences_match_v1(self) -> None:
        for case in self.attacks:
            v1_case = self.v1_attacks[case.case_id[len(ATTACK_PREFIX):]]
            self.assertEqual(
                [message["role"] for message in case.messages],
                [message["role"] for message in v1_case["messages"]],
                case.case_id,
            )

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
        existing = _contents(self.v1) | _contents(self.multilingual)
        self.assertEqual(_contents(self.payload) & existing, set())

    def test_benign_cases_cover_hard_negatives(self) -> None:
        benign_text = "\n".join(
            message["content"]
            for case in self.benign
            for message in case.messages
        ).lower()
        for phrase in (
            "abaikan arahan sebelum ini",
            "curl",
            "pentadbir",
            "pintas",
            "sistem",
            "@example.com",
        ):
            self.assertIn(phrase, benign_text)
        self.assertTrue(
            any(
                "bro," in message["content"].lower()
                or "tak" in message["content"].lower()
                for case in self.benign
                for message in case.messages
            )
        )


if __name__ == "__main__":
    unittest.main()
