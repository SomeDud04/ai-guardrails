"""Local-backend, category and dataset-v2 tests for the guard evaluation command.

A fake in-process guard stands in for the model.  These tests prove plumbing,
labels and dataset structure only, never model quality or latency.
"""

from __future__ import annotations

import collections
import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from nasi_lemak import guard_eval
from nasi_lemak.guard_errors import GuardError, GuardInputLimit
from nasi_lemak.guard_eval import (
    BACKEND_LOCAL,
    CATEGORIES,
    EVIDENCE_LABEL,
    ERROR_INPUT_API,
    ERROR_INPUT_WINDOW,
    ERROR_OUTPUT_API,
    MAX_CASES,
    DatasetError,
    execute_dataset,
    load_dataset,
    main,
    parse_dataset,
)

EVALS = Path(__file__).resolve().parent.parent / "evals" / "guards"
DATASET_V2 = EVALS / "multilingual-guard-lanes-v2.json"
SECRET_TEXT = "SYNTHETIC-TEXT-THAT-MUST-NOT-REACH-A-REPORT"


class FakeGuard:
    """Blocks text containing ``block``; raises for the other markers."""

    def scan_attack(self, serialized: str) -> dict[str, str]:
        if "toolong" in serialized:
            raise GuardInputLimit("guard input exceeds the configured limit")
        if "broken" in serialized:
            raise GuardError("guard inference failed")
        return {"decision": "block" if "block" in serialized else "allow"}

    def scan_response(self, messages: Any, output: str) -> dict[str, bool]:
        if "broken" in output:
            raise GuardError("guard inference failed")
        return {"safe": "block" not in output}


def case(
    case_id: str,
    text: str,
    *,
    stage: str = "input",
    expected: str = "allow",
    category: str | None = "benign",
    language: str = "en",
    output: str | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": case_id,
        "stage": stage,
        "language": language,
        "expected": expected,
        "messages": [{"role": "user", "content": text}],
    }
    if stage == "output":
        item["output"] = output or "fine"
    if category is not None:
        item["category"] = category
    return item


def dataset(cases: list[dict[str, Any]]) -> Any:
    return parse_dataset(
        {
            "schema_version": 1,
            "dataset_id": "local-test",
            "evidence_label": EVIDENCE_LABEL,
            "cases": cases,
        },
        sha256="0" * 64,
    )


class CategoryFieldTests(unittest.TestCase):
    def test_category_is_optional_and_validated(self) -> None:
        self.assertIsNone(dataset([case("a", "hi", category=None)]).cases[0].category)
        self.assertEqual(
            dataset([case("a", "hi", category="jailbreak")]).cases[0].category, "jailbreak"
        )
        with self.assertRaises(DatasetError):
            dataset([case("a", "hi", category="not-a-category")])
        with self.assertRaises(DatasetError):
            dataset([{**case("a", "hi", category=None), "category": 7}])

    def test_unknown_fields_are_still_rejected(self) -> None:
        with self.assertRaises(DatasetError):
            dataset([{**case("a", "hi"), "severity": "high"}])

    def test_uncategorized_report_keeps_its_previous_shape(self) -> None:
        data = dataset([case("a", "hi", category=None)])
        with mock.patch.object(
            guard_eval, "build_local_adapters",
            return_value=({"input": FakeGuard(), "output": FakeGuard()}, {}),
        ):
            outcomes, models = execute_dataset(data, environ={}, backend=BACKEND_LOCAL)
        report, _ = guard_eval.build_run_report(data, outcomes, models=models)
        self.assertNotIn("per_stage_category", report["aggregates"])
        self.assertNotIn("category", report["cases"][0])


class LocalBackendTests(unittest.TestCase):
    def run_local(self, cases: list[dict[str, Any]], **kwargs: Any) -> Any:
        data = dataset(cases)
        guard = FakeGuard()
        with mock.patch.object(
            guard_eval,
            "build_local_adapters",
            return_value=({"input": guard, "output": guard}, {"input": "m", "output": "m"}),
        ):
            outcomes, models = execute_dataset(
                data, environ={}, backend=BACKEND_LOCAL, **kwargs
            )
        return data, outcomes, models

    def test_both_stages_use_the_local_guard_and_never_the_api_builder(self) -> None:
        with mock.patch.object(guard_eval, "build_adapters") as api_builder:
            _, outcomes, _ = self.run_local(
                [
                    case("in-ok", "hello"),
                    case("in-no", "please block", expected="block", category="jailbreak"),
                    case("out-ok", "q", stage="output", output="fine"),
                    case("out-no", "q", stage="output", output="block me", expected="block",
                         category="violent"),
                ]
            )
        api_builder.assert_not_called()
        self.assertEqual(
            [outcome.observed for outcome in outcomes], ["allow", "block", "allow", "block"]
        )

    def test_legacy_window_does_not_apply_to_the_local_backend(self) -> None:
        # Over the API classifier's 512-unit window, inside the local budget.
        _, outcomes, _ = self.run_local([case("long", "word " * 200)])
        self.assertEqual(outcomes[0].observed, "allow")
        self.assertIsNone(outcomes[0].error_code)

    def test_guard_limit_and_failure_are_errors_not_decisions(self) -> None:
        _, outcomes, _ = self.run_local(
            [
                case("limit", "toolong"),
                case("fail", "broken"),
                case("out-fail", "q", stage="output", output="broken"),
            ]
        )
        self.assertEqual([outcome.observed for outcome in outcomes], ["error"] * 3)
        self.assertEqual(
            [outcome.error_code for outcome in outcomes],
            [ERROR_INPUT_WINDOW, ERROR_INPUT_API, ERROR_OUTPUT_API],
        )

    def test_progress_reports_counts_only(self) -> None:
        calls: list[tuple[int, int]] = []
        self.run_local(
            [case(f"c{i}", "hello") for i in range(25)],
            progress=lambda done, total: calls.append((done, total)),
        )
        self.assertEqual(calls, [(10, 25), (20, 25)])

    def test_report_has_category_rates_and_no_text(self) -> None:
        data, outcomes, models = self.run_local(
            [
                case("a", SECRET_TEXT + " block", expected="block", category="jailbreak"),
                case("b", SECRET_TEXT, expected="block", category="jailbreak"),
                case("c", SECRET_TEXT + " block", expected="allow"),
                case("d", "q", stage="output", output=SECRET_TEXT + " block",
                     expected="block", category="pii"),
            ]
        )
        report, code = guard_eval.build_run_report(
            data, outcomes, models=models, backend=BACKEND_LOCAL
        )
        self.assertEqual(code, 1)
        self.assertEqual(report["backend"], BACKEND_LOCAL)
        by_category = report["aggregates"]["per_stage_category"]
        self.assertEqual(by_category["input"]["jailbreak"]["correct_block"], 1)
        self.assertEqual(by_category["input"]["jailbreak"]["missed_unsafe"], 1)
        self.assertEqual(by_category["input"]["benign"]["false_blocks"], 1)
        self.assertEqual(by_category["output"]["pii"]["correct_block"], 1)
        self.assertEqual(report["cases"][0]["category"], "jailbreak")
        self.assertNotIn(SECRET_TEXT, json.dumps(report))

    def test_invalid_local_configuration_fails_before_any_case(self) -> None:
        data = dataset([case("a", "hello")])
        with self.assertRaises(guard_eval.EvaluationConfigError):
            execute_dataset(data, environ={}, backend=BACKEND_LOCAL)


class CommandLineTests(unittest.TestCase):
    def test_dataset_can_be_piped_on_standard_input(self) -> None:
        raw = DATASET_V2.read_bytes()
        stdin = mock.Mock()
        stdin.buffer = io.BytesIO(raw)
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), contextlib.redirect_stdout(out):
            self.assertEqual(main(["--dataset", "-"]), 0)
        self.assertIn("cases=186", out.getvalue())

    def test_execute_passes_the_backend_and_records_it(self) -> None:
        guard = FakeGuard()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "data.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "dataset_id": "cli-test",
                        "evidence_label": EVIDENCE_LABEL,
                        "cases": [case("a", "hello")],
                    }
                ),
                encoding="utf-8",
            )
            report_path = Path(tmp) / "report.json"
            with mock.patch.object(
                guard_eval,
                "build_local_adapters",
                return_value=({"input": guard, "output": guard}, {"input": "m", "output": "m"}),
            ), contextlib.redirect_stdout(io.StringIO()):
                code = main(
                    [
                        "--dataset", str(path), "--execute", "--backend", BACKEND_LOCAL,
                        "--report", str(report_path),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(
                json.loads(report_path.read_text(encoding="utf-8"))["backend"], BACKEND_LOCAL
            )


class DatasetV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = load_dataset(DATASET_V2)
        cls.cases = cls.dataset.cases

    def count(self, **fields: str) -> int:
        return sum(
            1
            for item in self.cases
            if all(getattr(item, name) == value for name, value in fields.items())
        )

    def test_size_and_balance(self) -> None:
        self.assertEqual(len(self.cases), 186)
        self.assertLessEqual(len(self.cases), MAX_CASES)
        self.assertEqual(self.dataset.evidence_label, EVIDENCE_LABEL)
        self.assertEqual(self.count(expected="allow"), 93)
        self.assertEqual(self.count(expected="block"), 93)

    def test_every_language_has_both_stages_and_both_outcomes(self) -> None:
        for language, per_input, per_output in (
            ("en", 19, 9),
            ("bm", 19, 9),
            ("zh", 19, 9),
            ("mixed", 6, 3),
        ):
            with self.subTest(language=language):
                for stage, expected_count in (("input", per_input), ("output", per_output)):
                    for expected in ("allow", "block"):
                        self.assertEqual(
                            self.count(language=language, stage=stage, expected=expected),
                            expected_count,
                        )

    def test_matched_rows_exist_in_every_main_language(self) -> None:
        groups: dict[str, set[str]] = collections.defaultdict(set)
        for item in self.cases:
            if item.language != "mixed":
                stem, language = item.case_id.rsplit("-", 1)
                groups[stem].add(language)
        self.assertTrue(groups)
        for stem, languages in groups.items():
            with self.subTest(stem=stem):
                self.assertEqual(languages, {"en", "bm", "zh"})

    def test_case_text_matches_its_language_label(self) -> None:
        han = re.compile(r"[一-鿿]")
        for item in self.cases:
            text = " ".join(
                [message["content"] for message in item.messages] + [item.output or ""]
            )
            with self.subTest(case=item.case_id):
                if item.language == "zh":
                    self.assertRegex(text, han)
                elif item.language in ("en", "bm"):
                    self.assertNotRegex(text, han)

    def test_every_case_is_labelled_and_consistent(self) -> None:
        for item in self.cases:
            with self.subTest(case=item.case_id):
                self.assertIn(item.category, CATEGORIES)
                self.assertEqual(item.category == "benign", item.expected == "allow")

    def test_no_duplicate_text_within_a_stage_and_language(self) -> None:
        seen: set[tuple[str, str, str, str | None, str]] = set()
        for item in self.cases:
            key = (
                item.stage,
                item.language,
                item.messages[-1]["content"],
                item.output,
                item.expected,
            )
            self.assertNotIn(key, seen, item.case_id)
            seen.add(key)

    def test_only_synthetic_contact_details_appear(self) -> None:
        email = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
        for item in self.cases:
            text = " ".join(
                [message["content"] for message in item.messages] + [item.output or ""]
            )
            for domain in email.findall(text):
                self.assertEqual(domain, "example.com", item.case_id)


if __name__ == "__main__":
    unittest.main()
