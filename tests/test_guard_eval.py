"""Tests for the guard-only synthetic evaluation command.

All execute tests use a fake in-process guard and synthetic text. They prove
plumbing and denominator arithmetic only; they are not model-quality, latency or
live-endpoint evidence.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from typing import Any

from nasi_lemak import guard_eval
from nasi_lemak.guards import GuardError, GuardInputLimit
from nasi_lemak.guard_eval import (
    EVIDENCE_LABEL,
    ERROR_INPUT_API,
    ERROR_INPUT_WINDOW,
    ERROR_OUTPUT_API,
    MAX_DATASET_BYTES,
    DatasetError,
    Outcome,
    aggregate_outcomes,
    execute_dataset,
    load_dataset,
    main,
)

MODEL = "qwen3guard-gen-fixture"
DATASET = Path(__file__).resolve().parent.parent / "evals" / "guards" / "synthetic-smoke-v1.json"
def input_case(
    case_id: str = "in-1",
    *,
    language: str = "en",
    expected: str = "allow",
    text: str = "hello",
) -> dict[str, Any]:
    return {
        "id": case_id,
        "stage": "input",
        "language": language,
        "expected": expected,
        "messages": [{"role": "user", "content": text}],
    }


def output_case(
    case_id: str = "out-1",
    *,
    language: str = "en",
    expected: str = "allow",
    text: str = "hello",
    output: str = "safe answer",
) -> dict[str, Any]:
    return {
        "id": case_id,
        "stage": "output",
        "language": language,
        "expected": expected,
        "messages": [{"role": "user", "content": text}],
        "output": output,
    }


def dataset_payload(cases: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "dataset_id": "test-smoke",
        "evidence_label": EVIDENCE_LABEL,
        "cases": cases,
    }
    payload.update(overrides)
    return payload


def write_dataset(root: Path, payload: Any, name: str = "dataset.json") -> Path:
    path = root / name
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class FixtureMixin(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_main(
        self, args: list[str], env: dict[str, str] | None
    ) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        # Preserve the host environment (Windows TLS needs SYSTEMROOT) while
        # removing every ambient NASI_LEMAK_* setting from the test.
        isolated = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("NASI_LEMAK_")
        }
        isolated.update(env or {})
        with mock.patch.dict(os.environ, isolated, clear=True):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

class DatasetValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def assert_invalid(self, payload: Any) -> None:
        with self.assertRaises(DatasetError):
            load_dataset(write_dataset(self.root, payload))

    def test_repository_smoke_dataset_shape_and_digest(self) -> None:
        dataset = load_dataset(DATASET)
        self.assertEqual(dataset.dataset_id, "guards-synthetic-smoke-v1")
        self.assertEqual(dataset.evidence_label, EVIDENCE_LABEL)
        self.assertEqual(len(dataset.cases), 16)
        self.assertEqual(len({case.case_id for case in dataset.cases}), 16)
        for stage in ("input", "output"):
            self.assertEqual(sum(1 for case in dataset.cases if case.stage == stage), 8)
        for language in ("en", "bm", "zh", "mixed"):
            self.assertEqual(
                sum(1 for case in dataset.cases if case.language == language), 4
            )
        self.assertEqual(
            sum(1 for case in dataset.cases if case.expected == "allow"), 8
        )
        self.assertEqual(
            sum(1 for case in dataset.cases if case.expected == "block"), 8
        )
        self.assertEqual(dataset.sha256, hashlib.sha256(DATASET.read_bytes()).hexdigest())

    def test_duplicate_keys_and_nonfinite_values_are_rejected(self) -> None:
        duplicate = (
            '{"schema_version":1,"schema_version":1,"dataset_id":"test-smoke",'
            f'"evidence_label":"{EVIDENCE_LABEL}","cases":[]}}'
        )
        with self.assertRaises(DatasetError):
            load_dataset(write_dataset(self.root, duplicate))
        nested = json.dumps(dataset_payload([input_case()]))
        nested = nested.replace(
            '"role": "user", "content": "hello"',
            '"role": "user", "content": "hello", "content": "again"',
        )
        with self.assertRaises(DatasetError):
            load_dataset(write_dataset(self.root, nested))
        nonfinite = json.dumps(dataset_payload([input_case()])).replace(
            '"expected": "allow"', '"expected": NaN'
        )
        with self.assertRaises(DatasetError):
            load_dataset(write_dataset(self.root, nonfinite))

    def test_schema_and_case_bounds_are_rejected(self) -> None:
        cases = [input_case()]
        invalid_payloads: list[Any] = [
            [],
            dataset_payload(cases, schema_version=2),
            dataset_payload(cases, schema_version=True),
            dataset_payload(cases, extra="field"),
            dataset_payload(cases, dataset_id="Bad ID"),
            dataset_payload([]),
            dataset_payload([input_case()] * 65),
            dataset_payload([input_case("dup"), input_case("dup")]),
        ]
        for case in (
            {**input_case(), "stage": "other"},
            {**input_case(), "language": "fr"},
            {**input_case(), "expected": "maybe"},
            {**input_case(), "output": "should not be here"},
            {key: value for key, value in output_case().items() if key != "output"},
            {**input_case(), "messages": []},
            {
                **input_case(),
                "messages": [{"role": "user", "content": "x"}] * 17,
            },
            {**input_case(), "messages": [{"role": "tool", "content": "x"}]},
            {**input_case(), "messages": [{"role": "user", "content": ""}]},
            {
                **input_case(),
                "messages": [{"role": "user", "content": "bad\x00content"}],
            },
            {
                **input_case(),
                "messages": [{"role": "user", "content": "x" * 1025}],
            },
            {
                **input_case(),
                "messages": [{"role": "user", "content": "x" * 1024}] * 16,
            },
            {**input_case(), "unexpected": "field"},
            {**output_case(), "output": ""},
        ):
            invalid_payloads.append(dataset_payload([case]))
        for payload in invalid_payloads:
            with self.subTest(payload=str(payload)[:80]):
                self.assert_invalid(payload)

    def test_file_size_bound_is_enforced(self) -> None:
        path = self.root / "huge.json"
        path.write_bytes(b"{" + b" " * MAX_DATASET_BYTES + b"}")
        with self.assertRaises(DatasetError):
            load_dataset(path)


class DryRunTests(FixtureMixin):
    def test_dry_run_needs_no_environment_client_or_network(self) -> None:
        report_path = self.root / "dry-run.json"
        with mock.patch.object(
            guard_eval, "build_local_adapters", side_effect=AssertionError("no guard")
        ):
            code, stdout, stderr = self.run_main(
                ["--dataset", str(DATASET), "--report", str(report_path)], {}
            )
        self.assertEqual(code, 0, stderr)
        self.assertIn("dry-run validation only", stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertTrue(report["dry_run"])
        self.assertNotIn("models", report)
        self.assertNotIn("aggregates", report)
        self.assertEqual(report["counts"]["cases"], 16)
        self.assertEqual(report["planned"]["total"]["cases"], 16)
        self.assertEqual(report["planned"]["total"]["expected_allowed"], 8)
        self.assertEqual(report["planned"]["total"]["expected_blocked"], 8)
        self.assertTrue(all(case["observed"] is None for case in report["cases"]))
        self.assertEqual(report["dataset_sha256"], hashlib.sha256(DATASET.read_bytes()).hexdigest())

    def test_dry_run_refuses_existing_report_and_the_dataset_path(self) -> None:
        existing = self.root / "exists.json"
        existing.write_text("keep", encoding="utf-8")
        code, _, _ = self.run_main(
            ["--dataset", str(DATASET), "--report", str(existing)], {}
        )
        self.assertEqual(code, 2)
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
        code, _, _ = self.run_main(
            ["--dataset", str(DATASET), "--report", str(DATASET)], {}
        )
        self.assertEqual(code, 2)
        self.assertEqual(
            hashlib.sha256(DATASET.read_bytes()).hexdigest(),
            load_dataset(DATASET).sha256,
        )

    def test_missing_dataset_argument_is_a_cli_error(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            main([])
        self.assertEqual(raised.exception.code, 2)


class AggregateTests(unittest.TestCase):
    def test_mixed_outcomes_exclude_errors_from_rates(self) -> None:
        outcomes = [
            Outcome("a", "input", "en", "allow", "allow", None, 1.0),
            Outcome("b", "input", "en", "block", "block", None, 2.0),
            Outcome("c", "input", "bm", "allow", "block", None, 3.0),
            Outcome("d", "input", "bm", "block", "allow", None, 4.0),
            Outcome("e", "output", "zh", "allow", "error", "INPUT_API", 5.0),
            Outcome("f", "output", "zh", "block", "error", ERROR_INPUT_WINDOW, 6.0),
        ]
        aggregate = aggregate_outcomes(outcomes)
        total = aggregate["total"]
        self.assertEqual(total["attempted"], 6)
        self.assertEqual(total["completed"], 4)
        self.assertEqual(total["errors"], 2)
        self.assertEqual(total["window_errors"], 1)
        self.assertEqual(total["correct_allow"], 1)
        self.assertEqual(total["correct_block"], 1)
        self.assertEqual(total["false_blocks"], 1)
        self.assertEqual(total["missed_unsafe"], 1)
        self.assertEqual(
            total["rates"]["denominators"]["accuracy"],
            {"name": "completed_cases_excluding_errors", "count": 4},
        )
        self.assertEqual(total["rates"]["accuracy"], 0.5)
        self.assertEqual(total["rates"]["false_block_rate"], 0.5)
        self.assertEqual(total["rates"]["missed_unsafe_rate"], 0.5)
        self.assertEqual(
            total["rates"]["denominators"]["false_block_rate"],
            {"name": "correct_allow_plus_false_blocks", "count": 2},
        )
        self.assertEqual(
            total["rates"]["denominators"]["missed_unsafe_rate"],
            {"name": "correct_block_plus_missed_unsafe", "count": 2},
        )
        self.assertEqual(total["latency_ms"]["population"], "all_attempted_cases_including_errors")
        self.assertEqual(total["latency_ms"]["method"], "nearest_rank")
        self.assertEqual(total["latency_ms"]["count"], 6)
        self.assertEqual(total["latency_ms"]["p50"], 3.0)

        output = aggregate["per_stage"]["output"]
        self.assertEqual(output["completed"], 0)
        self.assertIsNone(output["rates"]["accuracy"])
        self.assertIsNone(output["rates"]["false_block_rate"])
        self.assertIsNone(output["rates"]["missed_unsafe_rate"])
        self.assertEqual(
            output["rates"]["denominators"]["missed_unsafe_rate"]["count"], 0
        )

        chinese = aggregate["per_language"]["zh"]
        self.assertEqual(chinese["attempted"], 2)
        self.assertEqual(chinese["latency_ms"]["count"], 2)
        self.assertIsNone(chinese["rates"]["accuracy"])

        absent = aggregate["per_language"]["mixed"]
        self.assertEqual(absent["attempted"], 0)
        self.assertIsNone(absent["rates"]["accuracy"])
        self.assertIsNone(absent["latency_ms"]["p50"])
        self.assertIsNone(absent["latency_ms"]["p95"])

        self.assertEqual(
            aggregate["per_stage_language"]["input"]["en"]["completed"], 2
        )
        self.assertEqual(
            aggregate["per_stage_language"]["input"]["bm"]["rates"]["false_block_rate"], 1.0
        )
        self.assertEqual(
            aggregate["per_stage_language"]["output"]["zh"]["completed"], 0
        )
        self.assertIsNone(
            aggregate["per_stage_language"]["output"]["zh"]["rates"]["accuracy"]
        )

    def test_class_specific_denominators_and_stage_language_aggregates(self) -> None:
        outcomes = [
            Outcome("a", "input", "en", "allow", "allow", None, 1.0),
            Outcome("b", "input", "en", "allow", "allow", None, 1.0),
            Outcome("c", "input", "en", "allow", "block", None, 1.0),
            Outcome("d", "output", "en", "block", "allow", None, 1.0),
        ]
        aggregate = aggregate_outcomes(outcomes)
        total = aggregate["total"]
        self.assertEqual(total["rates"]["accuracy"], 0.5)
        self.assertEqual(total["rates"]["false_block_rate"], 1 / 3)
        self.assertEqual(total["rates"]["missed_unsafe_rate"], 1.0)
        self.assertEqual(
            total["rates"]["denominators"]["false_block_rate"]["count"], 3
        )
        self.assertEqual(
            total["rates"]["denominators"]["missed_unsafe_rate"]["count"], 1
        )
        self.assertEqual(
            aggregate["per_stage_language"]["input"]["en"]["rates"]["false_block_rate"],
            1 / 3,
        )
        self.assertEqual(
            aggregate["per_stage_language"]["output"]["en"]["rates"]["missed_unsafe_rate"],
            1.0,
        )

        zero_class = aggregate_outcomes(
            [
                Outcome("e", "input", "bm", "allow", "allow", None, 1.0),
                Outcome("f", "input", "bm", "allow", "block", None, 1.0),
            ]
        )["total"]
        self.assertIsNone(zero_class["rates"]["missed_unsafe_rate"])
        self.assertEqual(
            zero_class["rates"]["denominators"]["missed_unsafe_rate"]["count"], 0
        )
        self.assertEqual(zero_class["rates"]["false_block_rate"], 0.5)


class _FakeGuard:
    """Decides on markers in the text; counts every call it receives."""

    def __init__(self) -> None:
        self.calls = 0

    def scan_attack(self, serialized: str) -> dict[str, str]:
        self.calls += 1
        if "WINDOW-MARKER" in serialized:
            raise GuardInputLimit("over the window")
        if "BROKEN-MARKER" in serialized:
            raise GuardError("no verdict")
        return {"decision": "block" if "ATTACK-MARKER" in serialized else "allow"}

    def scan_response(self, messages: list[dict[str, str]], output: str) -> dict[str, bool]:
        self.calls += 1
        if "BROKEN-MARKER" in output:
            raise GuardError("no verdict")
        return {"safe": "UNSAFE-MARKER" not in output}


class ExecuteTests(FixtureMixin):
    def setUp(self) -> None:
        super().setUp()
        self.guard = _FakeGuard()
        patcher = mock.patch.object(
            guard_eval,
            "build_local_adapters",
            return_value=(
                {"input": self.guard, "output": self.guard},
                {"input": MODEL, "output": MODEL},
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _dataset(self, cases: list[dict[str, Any]]) -> Path:
        return write_dataset(self.root, dataset_payload(cases))

    def test_both_stages_run_through_the_local_guard(self) -> None:
        path = self._dataset(
            [
                input_case("in-safe", expected="allow", text="SAFE-MARKER"),
                input_case("in-attack", expected="block", text="ATTACK-MARKER"),
                output_case("out-unsafe", expected="block", output="UNSAFE-MARKER"),
            ]
        )
        outcomes, models = execute_dataset(load_dataset(path), environ={})
        self.assertEqual(models, {"input": MODEL, "output": MODEL})
        self.assertEqual(
            [(outcome.case_id, outcome.observed) for outcome in outcomes],
            [("in-safe", "allow"), ("in-attack", "block"), ("out-unsafe", "block")],
        )

    def test_execute_report_contains_no_payload(self) -> None:
        canary = "REPORT-CANARY-7c1d"
        report_path = self.root / "execute.json"
        path = self._dataset([input_case("in-safe", expected="allow", text=canary)])
        code, _stdout, stderr = self.run_main(
            ["--dataset", str(path), "--execute", "--report", str(report_path)], {}
        )
        self.assertEqual(code, 0, stderr)
        self.assertNotIn(canary, report_path.read_text(encoding="utf-8"))

    def test_invalid_verdict_is_an_error_not_a_block(self) -> None:
        path = self._dataset(
            [
                input_case("in-bad", expected="block", text="BROKEN-MARKER"),
                output_case("out-bad", expected="block", output="BROKEN-MARKER"),
            ]
        )
        outcomes, _models = execute_dataset(load_dataset(path), environ={})
        self.assertEqual(
            [(outcome.observed, outcome.error_code) for outcome in outcomes],
            [("error", ERROR_INPUT_API), ("error", ERROR_OUTPUT_API)],
        )
        self.assertEqual(self.guard.calls, 2)

    def test_input_over_the_window_is_a_separate_error(self) -> None:
        path = self._dataset([input_case("in-long", expected="block", text="WINDOW-MARKER")])
        outcomes, _models = execute_dataset(load_dataset(path), environ={})
        self.assertEqual(outcomes[0].observed, "error")
        self.assertEqual(outcomes[0].error_code, ERROR_INPUT_WINDOW)
        self.assertEqual(aggregate_outcomes(outcomes)["total"]["window_errors"], 1)

    def test_bad_late_case_causes_no_guard_call(self) -> None:
        path = self._dataset(
            [
                input_case("in-safe", expected="allow", text="SAFE-MARKER"),
                input_case("in-safe", expected="allow", text="duplicate id"),
            ]
        )
        code, _stdout, _stderr = self.run_main(["--dataset", str(path), "--execute"], {})
        self.assertEqual(code, 2)
        self.assertEqual(self.guard.calls, 0)

    def test_invalid_guard_config_exits_before_any_case(self) -> None:
        path = self._dataset([input_case("in-safe", expected="allow", text="SAFE-MARKER")])
        with mock.patch.object(
            guard_eval,
            "build_local_adapters",
            side_effect=guard_eval.EvaluationConfigError("invalid"),
        ):
            code, _stdout, _stderr = self.run_main(
                ["--dataset", str(path), "--execute"], {}
            )
        self.assertEqual(code, 2)
        self.assertEqual(self.guard.calls, 0)


if __name__ == "__main__":
    unittest.main()
