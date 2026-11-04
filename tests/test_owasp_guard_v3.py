"""Contract tests for the combined OWASP guard-lane dataset v3.

Standard library only.  v3 is exactly the v2 cases followed by the Malay
control mirrors and the Chinese mirrors, so every v1 case has an English,
Malay and Chinese version and the parts can never drift from the combined file.
"""

from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path

from nasi_lemak.guard_eval import MAX_CASES, load_dataset

GUARDS = Path(__file__).resolve().parents[1] / "evals" / "guards"
DATASET = GUARDS / "owasp-llm-top10-2026-v3.json"
V1 = GUARDS / "owasp-llm-top10-2026-v1.json"
PARTS = (
    GUARDS / "owasp-llm-top10-2026-v2.json",
    GUARDS / "owasp-llm-top10-2026-v3-bm-ctrl.json",
    GUARDS / "owasp-llm-top10-2026-v3-zh.json",
)


def _payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class CombinedGuardLaneDatasetV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset(DATASET)
        cls.payload = _payload(DATASET)

    def test_identity(self) -> None:
        self.assertEqual(self.payload["dataset_id"], "owasp-llm-top10-2026-guard-lane-v3")
        self.assertEqual(
            self.payload["evidence_label"], "agent-authored-synthetic-smoke-not-holdout"
        )

    def test_cases_are_exactly_the_parts_in_order(self) -> None:
        expected = [case for part in PARTS for case in _payload(part)["cases"]]
        self.assertEqual(self.payload["cases"], expected)

    def test_counts(self) -> None:
        self.assertEqual(len(self.dataset.cases), 237)
        self.assertLessEqual(len(self.dataset.cases), MAX_CASES)
        self.assertEqual(
            Counter(case.expected for case in self.dataset.cases),
            {"allow": 171, "block": 66},
        )
        self.assertEqual(
            Counter(case.language for case in self.dataset.cases),
            {"en": 111, "bm": 69, "zh": 49, "mixed": 8},
        )

    def test_ids_are_unique(self) -> None:
        ids = [case.case_id for case in self.dataset.cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_v1_case_has_a_malay_and_a_chinese_mirror(self) -> None:
        ids = {case.case_id for case in self.dataset.cases}
        for case in _payload(V1)["cases"]:
            with self.subTest(case=case["id"]):
                self.assertIn("bm-" + case["id"], ids)
                self.assertIn("zh-" + case["id"], ids)


if __name__ == "__main__":
    unittest.main()
