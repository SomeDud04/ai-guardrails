"""Integrity tests for the v2 benign hard-negative guard-lane dataset.

This is synthetic smoke evidence for the guard lane, not a held-out benchmark.
The cases are benign prompts that merely mention risky-looking words; every one
must be accepted as ``allow`` by a well-calibrated input guard. The checks here
are dataset integrity only: they do not run a guard or make any quality claim.
"""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from collections import Counter
from pathlib import Path

from nasi_lemak.guard_eval import (
    EVIDENCE_LABEL,
    MAX_MESSAGE_CHARS,
    load_dataset,
    parse_dataset,
)

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v2-benign.json"
V1_DATASET = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v1.json"
MULTILINGUAL_DATASET = (
    ROOT / "evals" / "guards" / "multilingual-guard-lanes-v2.json"
)

DATASET_ID = "owasp-llm-top10-2026-guard-lane-v2-benign"
CASE_ID = re.compile(r"ben-\d{3}\Z")
EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)
PHONE = re.compile(r"\+60[ 0-9-]*\d")
SYNTHETIC_PHONE = re.compile(r"\+60 12-000 0\d{3}\Z")
HAN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
SECRET_SHAPES = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def existing_contents(path: Path) -> set[str]:
    """Every message body already present in an existing guard dataset."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        message["content"]
        for case in payload["cases"]
        for message in case["messages"]
    }


class BenignDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset(DATASET)
        cls.cases = cls.dataset.cases
        cls.contents = [case.messages[0]["content"] for case in cls.cases]

    def test_dataset_is_parsed_with_the_declared_identity(self) -> None:
        payload = json.loads(DATASET.read_text(encoding="utf-8"))
        parsed = parse_dataset(
            payload, sha256=hashlib.sha256(DATASET.read_bytes()).hexdigest()
        )
        self.assertEqual(parsed.dataset_id, DATASET_ID)
        self.assertEqual(self.dataset.dataset_id, DATASET_ID)
        self.assertEqual(self.dataset.evidence_label, EVIDENCE_LABEL)
        self.assertEqual(len(self.cases), 90)

    def test_every_case_is_a_benign_input_prompt(self) -> None:
        for case in self.cases:
            with self.subTest(case=case.case_id):
                self.assertEqual(case.stage, "input")
                self.assertEqual(case.expected, "allow")
                self.assertEqual(len(case.messages), 1)
                self.assertEqual(case.messages[0]["role"], "user")
                self.assertIsNone(case.category)

    def test_language_counts_exclude_bm(self) -> None:
        counts = Counter(case.language for case in self.cases)
        self.assertEqual(counts, {"en": 75, "zh": 8, "mixed": 7})

    def test_ids_are_unique_sequential_and_well_formed(self) -> None:
        ids = [case.case_id for case in self.cases]
        self.assertEqual(ids, [f"ben-{number:03d}" for number in range(1, 91)])
        self.assertEqual(len(ids), len(set(ids)))
        for case_id in ids:
            self.assertIsNotNone(CASE_ID.fullmatch(case_id), case_id)

    def test_content_lengths_are_bounded_and_include_long_prompts(self) -> None:
        lengths = [len(content) for content in self.contents]
        self.assertGreater(min(lengths), 0)
        self.assertLessEqual(max(lengths), MAX_MESSAGE_CHARS)
        self.assertGreaterEqual(sum(1 for length in lengths if length >= 600), 15)
        self.assertGreaterEqual(sum(1 for length in lengths if 600 <= length <= 1000), 15)

    def test_every_email_uses_the_example_domain(self) -> None:
        emails = 0
        for content in self.contents:
            for match in EMAIL.finditer(content):
                emails += 1
                self.assertEqual(match.group(1).lower(), "example.com", content)
        self.assertGreaterEqual(emails, 8)

    def test_phone_numbers_use_the_synthetic_shape(self) -> None:
        phones = 0
        for content in self.contents:
            for match in PHONE.finditer(content):
                phones += 1
                self.assertRegex(match.group(0), SYNTHETIC_PHONE, content)
        self.assertGreaterEqual(phones, 3)

    def test_language_tags_follow_the_han_rule(self) -> None:
        for case, content in zip(self.cases, self.contents):
            with self.subTest(case=case.case_id):
                if case.language == "zh":
                    self.assertIsNotNone(HAN.search(content))
                else:
                    self.assertIsNone(HAN.search(content))
                if case.language == "mixed":
                    self.assertTrue(any(ord(character) > 127 for character in content))

    def test_no_duplicate_content_within_the_dataset(self) -> None:
        self.assertEqual(len(self.contents), len(set(self.contents)))

    def test_no_duplicate_content_with_existing_guard_lanes(self) -> None:
        reused = existing_contents(V1_DATASET) | existing_contents(MULTILINGUAL_DATASET)
        self.assertEqual(set(self.contents) & reused, set())

    def test_no_secret_shaped_strings(self) -> None:
        for case, content in zip(self.cases, self.contents):
            for pattern in SECRET_SHAPES:
                with self.subTest(case=case.case_id, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(content))


if __name__ == "__main__":
    unittest.main()
