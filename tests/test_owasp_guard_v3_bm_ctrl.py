"""Contract tests for the Malay (bm) OWASP v1 benign-control mirror.

Standard library only.  The dataset mirrors the 17 v1 OWASP benign controls in
Bahasa Melayu so the guard lane's allow side is measured in Malay as well.
The 22 v1 attack cases already have Malay mirrors in
``owasp-llm-top10-2026-v2-bm.json``.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from nasi_lemak.guard_eval import MAX_MESSAGE_CHARS, load_dataset, parse_dataset

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v3-bm-ctrl.json"
V1 = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v1.json"
V2 = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v2.json"
V2_BM = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v2-bm.json"
V2_BENIGN = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v2-benign.json"
MULTILINGUAL = ROOT / "evals" / "guards" / "multilingual-guard-lanes-v2.json"

EXPECTED_DATASET_ID = "owasp-llm-top10-2026-guard-lane-v3-bm-ctrl"
EXPECTED_EVIDENCE_LABEL = "agent-authored-synthetic-smoke-not-holdout"
EXPECTED_CASES = 17
ID_PREFIX = "bm-"
EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
URL = re.compile(r"https?://([^/\s\"'<>]+)", re.I)


def _payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _contents(payload: dict) -> set[str]:
    return {
        message["content"]
        for case in payload["cases"]
        for message in case["messages"]
    }


class MalayGuardControlDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset(DATASET)
        cls.payload = _payload(DATASET)
        cls.v1 = _payload(V1)
        cls.v2_bm = _payload(V2_BM)
        cls.v1_controls = [
            case for case in cls.v1["cases"] if case["expected"] == "allow"
        ]
        cls.cases = list(cls.dataset.cases)

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

    def test_every_case_is_malay_input_allow(self) -> None:
        self.assertEqual(len(self.cases), EXPECTED_CASES)
        for case in self.cases:
            self.assertEqual(case.stage, "input", case.case_id)
            self.assertEqual(case.language, "bm", case.case_id)
            self.assertEqual(case.expected, "allow", case.case_id)
            self.assertIsNone(case.output, case.case_id)

    def test_ids_are_bm_prefixed_v1_allow_ids_in_order(self) -> None:
        expected = [ID_PREFIX + case["id"] for case in self.v1_controls]
        self.assertEqual([case.case_id for case in self.cases], expected)

    def test_role_sequences_match_v1(self) -> None:
        for case, v1_case in zip(self.cases, self.v1_controls):
            self.assertEqual(
                [message["role"] for message in case.messages],
                [message["role"] for message in v1_case["messages"]],
                case.case_id,
            )

    def test_content_within_limit_and_non_empty(self) -> None:
        for case in self.cases:
            for message in case.messages:
                self.assertTrue(message["content"], case.case_id)
                self.assertLessEqual(
                    len(message["content"]), MAX_MESSAGE_CHARS, case.case_id
                )

    def test_ids_are_unique_and_do_not_collide_with_v2_bm(self) -> None:
        ids = [case.case_id for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            set(ids) & {case["id"] for case in self.v2_bm["cases"]}, set()
        )

    def test_email_domains_are_example_com(self) -> None:
        found = 0
        for case in self.cases:
            for message in case.messages:
                for domain in EMAIL.findall(message["content"]):
                    found += 1
                    self.assertEqual(domain.lower(), "example.com", case.case_id)
        self.assertGreater(found, 0)

    def test_urls_use_example_com(self) -> None:
        found = 0
        for case in self.cases:
            for message in case.messages:
                for host in URL.findall(message["content"]):
                    found += 1
                    self.assertEqual(host.lower().rstrip(".,"), "example.com", case.case_id)
        self.assertGreater(found, 0)

    def test_no_content_matches_existing_lanes(self) -> None:
        existing = (
            _contents(self.v1)
            | _contents(_payload(V2))
            | _contents(self.v2_bm)
            | _contents(_payload(V2_BENIGN))
            | _contents(_payload(MULTILINGUAL))
        )
        self.assertEqual(_contents(self.payload) & existing, set())

    def test_translation_keeps_literal_tokens(self) -> None:
        by_id = {case.case_id: case for case in self.cases}
        code = by_id["bm-ctrl-003"].messages[0]["content"]
        self.assertIn("```python\nfor i in range(3):\n    print(i)\n```", code)
        shape = by_id["bm-ctrl-010"].messages[0]["content"]
        self.assertIn('{"summary": "..."}', shape)
        emoji = by_id["bm-ctrl-016"].messages[0]["content"]
        self.assertIn("🎉✅", emoji)
        url = by_id["bm-ctrl-017"].messages[0]["content"]
        self.assertIn("https://example.com/guide", url)
        email = by_id["bm-ctrl-004"].messages[0]["content"]
        self.assertIn("alice@example.com", email)

    def test_adapted_cases_remain_benign(self) -> None:
        by_id = {case.case_id: case for case in self.cases}
        greeting = by_id["bm-ctrl-006"].messages[0]["content"]
        self.assertIn("Selamat sejahtera", greeting)
        self.assertIn("Good morning", greeting)
        translate = by_id["bm-ctrl-012"].messages[0]["content"]
        self.assertIn("Inggeris", translate)
        self.assertIn("Mandarin", translate)
        training = by_id["bm-ctrl-005"].messages[0]["content"]
        self.assertIn("'abaikan arahan sebelum ini'", training)
        self.assertIn("latihan keselamatan", training)


if __name__ == "__main__":
    unittest.main()
