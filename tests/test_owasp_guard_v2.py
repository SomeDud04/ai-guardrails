"""Contract tests for the combined OWASP guard-lane dataset v2.

Standard library only.  v2 is exactly the v1 cases followed by the v2 benign
and v2 Malay parts, so one guard_eval run covers all three and the parts can
never drift from the combined file.
"""

from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path

from nasi_lemak.guard_eval import MAX_CASES, load_dataset

GUARDS = Path(__file__).resolve().parents[1] / "evals" / "guards"
DATASET = GUARDS / "owasp-llm-top10-2026-v2.json"
PARTS = (
    GUARDS / "owasp-llm-top10-2026-v1.json",
    GUARDS / "owasp-llm-top10-2026-v2-benign.json",
    GUARDS / "owasp-llm-top10-2026-v2-bm.json",
)


def _payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class CombinedGuardLaneDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset(DATASET)
        cls.payload = _payload(DATASET)

    def test_identity(self) -> None:
        self.assertEqual(self.payload["dataset_id"], "owasp-llm-top10-2026-guard-lane-v2")
        self.assertEqual(
            self.payload["evidence_label"], "agent-authored-synthetic-smoke-not-holdout"
        )

    def test_cases_are_exactly_the_parts_in_order(self) -> None:
        expected = [case for part in PARTS for case in _payload(part)["cases"]]
        self.assertEqual(self.payload["cases"], expected)

    def test_counts(self) -> None:
        self.assertEqual(len(self.dataset.cases), 181)
        self.assertLessEqual(len(self.dataset.cases), MAX_CASES)
        self.assertEqual(
            Counter(case.expected for case in self.dataset.cases),
            {"allow": 137, "block": 44},
        )
        self.assertEqual(
            Counter(case.language for case in self.dataset.cases),
            {"en": 111, "zh": 10, "mixed": 8, "bm": 52},
        )

    def test_ids_are_unique(self) -> None:
        ids = [case.case_id for case in self.dataset.cases]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
