"""Guard-only evaluation over a strict synthetic JSON dataset.

The default command is a **dry run**: it validates the complete dataset and
reports the planned case counts. It constructs no guard client, reads no
credential and performs no network access. ``--execute`` additionally loads only
the guard configurations needed by the stages present in the dataset, through
the existing :func:`~nasi_lemak.guard_api.guard_client_config` helper, and runs
the real :class:`~nasi_lemak.guard_api.InputGuardApiAdapter` and
:class:`~nasi_lemak.guard_api.Qwen3GuardOutputAdapter`.

This is an agent-authored smoke harness, not a held-out benchmark. It reports
no model-quality acceptance and no live endpoint claim. Reports contain case
identifiers, labels, counts, generic error codes and timings only: never raw
messages, candidate output, URLs, keys, headers or exception text.

The dataset is fully validated before the first HTTP request, so a malformed
late case cannot cause a partial run. Input cases use the gateway's conservative
UTF-8 byte budget (512 bytes, including framing) before the classifier call; an
over-budget case is reported as a separate ``INPUT_WINDOW`` error and is never
sent. There is no retry, truncation or default-allow behaviour, and an invalid
or timed-out guard reply is an error rather than a successful block.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .gateway import MAX_TOKEN_BUDGET, serialize_messages
from .generation import (
    GenerationClient,
    GenerationConfigError,
    conservative_byte_budget,
)
from .guard_api import (
    INPUT_GUARD_CONTRACT_V1,
    MAX_ENCODED_INPUT_BYTES,
    InputGuardApiAdapter,
    Qwen3GuardOutputAdapter,
    guard_client_config,
)
from .guards import GuardError

SCHEMA_VERSION = 1
REPORT_KIND = "guard_evaluation"
EVIDENCE_LABEL = "agent-authored-synthetic-smoke-not-holdout"
STAGES = ("input", "output")
LANGUAGES = ("en", "bm", "zh", "mixed")
EXPECTED_VALUES = ("allow", "block")

MAX_DATASET_BYTES = 256 * 1024
MAX_CASES = 64
MAX_CASE_ID_LENGTH = 64
MAX_MESSAGES_PER_CASE = 16
MAX_MESSAGE_CHARS = 1024
MAX_OUTPUT_CHARS = 1024
_CASE_ID = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
_ACCEPTED_ROLES = frozenset({"system", "user", "assistant"})

# These literal prefixes mirror the server-side selection contract. Importing
# nasi_lemak.server here would pull FastAPI into a guard-only evaluation path.
INPUT_GUARD_ENV_PREFIX = "NASI_LEMAK_INPUT_GUARD"
OUTPUT_GUARD_ENV_PREFIX = "NASI_LEMAK_OUTPUT_GUARD"
ENV_INPUT_GUARD_THRESHOLD = f"{INPUT_GUARD_ENV_PREFIX}_THRESHOLD"
ENV_INPUT_GUARD_CONTRACT = f"{INPUT_GUARD_ENV_PREFIX}_CONTRACT"

ERROR_INPUT_WINDOW = "INPUT_WINDOW"
ERROR_INPUT_API = "INPUT_API"
ERROR_OUTPUT_API = "OUTPUT_API"


class DatasetError(ValueError):
    """The synthetic dataset failed validation. Messages carry no payload."""


class EvaluationConfigError(ValueError):
    """The guard API environment is incomplete or invalid."""


class ReportError(OSError):
    """The report path is unsafe or not writable."""


@dataclass(frozen=True)
class GuardCase:
    case_id: str
    stage: str
    language: str
    expected: str
    messages: tuple[dict[str, str], ...]
    output: str | None


@dataclass(frozen=True)
class GuardDataset:
    dataset_id: str
    evidence_label: str
    cases: tuple[GuardCase, ...]
    sha256: str


@dataclass(frozen=True)
class Outcome:
    case_id: str
    stage: str
    language: str
    expected: str
    observed: str
    error_code: str | None
    elapsed_ms: float


def _require_str(
    value: Any,
    field: str,
    *,
    case_id: str | None = None,
    max_length: int | None = None,
) -> str:
    where = f" in case {case_id}" if case_id else ""
    if not isinstance(value, str) or not value:
        raise DatasetError(f"invalid {field}{where}")
    if max_length is not None and len(value) > max_length:
        raise DatasetError(f"oversized {field}{where}")
    return value


def _has_forbidden_control(value: str) -> bool:
    return any(
        (ord(character) < 0x20 and character not in "\n\t") or ord(character) == 0x7F
        for character in value
    )


def _validate_text(value: Any, field: str, *, case_id: str, maximum: int) -> str:
    text = _require_str(value, field, case_id=case_id, max_length=maximum)
    if _has_forbidden_control(text):
        raise DatasetError(f"invalid {field} in case {case_id}")
    return text


def _validate_messages(value: Any, *, case_id: str) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_MESSAGES_PER_CASE:
        raise DatasetError(f"invalid messages in case {case_id}")
    messages: list[dict[str, str]] = []
    for message in value:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise DatasetError(f"invalid messages in case {case_id}")
        role = message["role"]
        if not isinstance(role, str) or role not in _ACCEPTED_ROLES:
            raise DatasetError(f"invalid messages in case {case_id}")
        content = _validate_text(
            message["content"],
            "message content",
            case_id=case_id,
            maximum=MAX_MESSAGE_CHARS,
        )
        messages.append({"role": role, "content": content})
    return tuple(messages)


def _case_conversation(case: GuardCase) -> list[dict[str, str]]:
    conversation = [dict(message) for message in case.messages]
    if case.stage == "output":
        conversation.append({"role": "assistant", "content": case.output or ""})
    return conversation


def _encoded_conversation_bytes(case: GuardCase) -> int:
    try:
        encoded = json.dumps(
            _case_conversation(case), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise DatasetError(f"invalid conversation in case {case.case_id}") from None
    return len(encoded)


def parse_dataset(payload: object, *, sha256: str) -> GuardDataset:
    """Validate an in-memory version-1 synthetic dataset."""
    if not isinstance(payload, dict):
        raise DatasetError("dataset top level must be an object")
    if set(payload) != {"schema_version", "dataset_id", "evidence_label", "cases"}:
        raise DatasetError("dataset fields are invalid")
    schema_version = payload.get("schema_version")
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise DatasetError("unsupported schema_version")
    dataset_id = _require_str(
        payload.get("dataset_id"), "dataset_id", max_length=MAX_CASE_ID_LENGTH
    )
    if not _CASE_ID.fullmatch(dataset_id):
        raise DatasetError("invalid dataset_id")
    if payload.get("evidence_label") != EVIDENCE_LABEL:
        raise DatasetError("dataset evidence_label must declare synthetic smoke data")

    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= MAX_CASES:
        raise DatasetError("cases must be a bounded non-empty list")

    seen_ids: set[str] = set()
    cases: list[GuardCase] = []
    for item in raw_cases:
        if not isinstance(item, dict):
            raise DatasetError("every case must be an object")
        stage = item.get("stage")
        if not isinstance(stage, str) or stage not in STAGES:
            raise DatasetError("invalid case stage")
        case_id = item.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise DatasetError("invalid case id")
        if len(case_id) > MAX_CASE_ID_LENGTH or not _CASE_ID.fullmatch(case_id):
            raise DatasetError(f"invalid case id {case_id}")
        if case_id in seen_ids:
            raise DatasetError(f"duplicate case id {case_id}")
        seen_ids.add(case_id)

        expected_fields = (
            {"id", "stage", "language", "expected", "messages"}
            if stage == "input"
            else {"id", "stage", "language", "expected", "messages", "output"}
        )
        if set(item) != expected_fields:
            raise DatasetError(f"invalid case fields in case {case_id}")
        language = item.get("language")
        if not isinstance(language, str) or language not in LANGUAGES:
            raise DatasetError(f"invalid language in case {case_id}")
        expected = item.get("expected")
        if not isinstance(expected, str) or expected not in EXPECTED_VALUES:
            raise DatasetError(f"invalid expected outcome in case {case_id}")
        messages = _validate_messages(item.get("messages"), case_id=case_id)
        output: str | None = None
        if stage == "output":
            output = _validate_text(
                item.get("output"),
                "output",
                case_id=case_id,
                maximum=MAX_OUTPUT_CHARS,
            )
        case = GuardCase(case_id, stage, language, expected, messages, output)
        if _encoded_conversation_bytes(case) > MAX_ENCODED_INPUT_BYTES:
            raise DatasetError(f"conversation exceeds the configured limit in case {case_id}")
        cases.append(case)
    return GuardDataset(dataset_id, EVIDENCE_LABEL, tuple(cases), sha256)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError("duplicate JSON key")
        mapping[key] = value
    return mapping


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON number")


def load_dataset(path: str | Path) -> GuardDataset:
    """Read, bound and fully validate the dataset; never touches the network."""
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_DATASET_BYTES + 1)
    except OSError:
        raise DatasetError("cannot read dataset") from None
    if len(raw) > MAX_DATASET_BYTES:
        raise DatasetError("dataset exceeds the size limit")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise DatasetError("invalid JSON in dataset") from None
    return parse_dataset(payload, sha256=hashlib.sha256(raw).hexdigest())


def input_serialized(case: GuardCase) -> str:
    """Canonical gateway serialization of an input-stage conversation."""
    return serialize_messages(
        [{"role": message["role"], "content": message["content"]} for message in case.messages]
    )


def input_window_exceeded(case: GuardCase) -> bool:
    """True when the conservative UTF-8 budget exceeds the gateway limit."""
    return conservative_byte_budget(input_serialized(case)) > MAX_TOKEN_BUDGET


def _guard_threshold(value: Any) -> float:
    try:
        threshold = float(value)
    except (TypeError, ValueError):
        raise EvaluationConfigError("guard input threshold is invalid") from None
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise EvaluationConfigError("guard input threshold is invalid")
    return threshold


def build_adapters(
    environ: Mapping[str, str], stages: Sequence[str]
) -> tuple[dict[str, Any], dict[str, str]]:
    """Build only the guard adapters required by the dataset stages.

    Configuration is validated and clients are constructed before the first
    case runs, so an invalid late setting cannot produce a partial request
    sequence. Construction itself performs no network access.
    """
    adapters: dict[str, Any] = {"input": None, "output": None}
    models: dict[str, str] = {}
    try:
        if "input" in stages:
            contract = environ.get(ENV_INPUT_GUARD_CONTRACT)
            if not isinstance(contract, str) or contract.strip() != INPUT_GUARD_CONTRACT_V1:
                raise EvaluationConfigError("input guard contract is not supported")
            threshold = _guard_threshold(environ.get(ENV_INPUT_GUARD_THRESHOLD))
            config = guard_client_config(environ, INPUT_GUARD_ENV_PREFIX)
            adapters["input"] = InputGuardApiAdapter(
                GenerationClient(config), threshold=threshold
            )
            models["input"] = config.model
        if "output" in stages:
            config = guard_client_config(environ, OUTPUT_GUARD_ENV_PREFIX)
            adapters["output"] = Qwen3GuardOutputAdapter(GenerationClient(config))
            models["output"] = config.model
    except EvaluationConfigError:
        raise
    except (GenerationConfigError, GuardError, ValueError, TypeError):
        raise EvaluationConfigError("guard API configuration is invalid") from None
    return adapters, models


def _observe(
    case: GuardCase,
    *,
    serialized: str | None,
    window_exceeded: bool,
    adapters: Mapping[str, Any],
) -> Outcome:
    start = time.perf_counter()
    observed = "error"
    error_code: str | None = None
    if window_exceeded:
        error_code = ERROR_INPUT_WINDOW
    elif case.stage == "input":
        try:
            result = adapters["input"].scan_attack(serialized)
            if not isinstance(result, dict) or result.get("decision") not in (
                "allow",
                "block",
            ):
                raise GuardError("guard input API response is invalid")
            observed = result["decision"]
        except (GuardError, OSError, ValueError, TypeError):
            observed, error_code = "error", ERROR_INPUT_API
    else:
        try:
            result = adapters["output"].scan_response(
                [dict(message) for message in case.messages], case.output
            )
            if not isinstance(result, dict) or not isinstance(result.get("safe"), bool):
                raise GuardError("guard output API response is invalid")
            observed = "allow" if result["safe"] else "block"
        except (GuardError, OSError, ValueError, TypeError):
            observed, error_code = "error", ERROR_OUTPUT_API
    elapsed = round((time.perf_counter() - start) * 1000.0, 3)
    return Outcome(
        case.case_id, case.stage, case.language, case.expected, observed, error_code, elapsed
    )


def execute_dataset(
    dataset: GuardDataset, *, environ: Mapping[str, str]
) -> tuple[tuple[Outcome, ...], dict[str, str]]:
    """Run every case against the real API adapters; no generator or database."""
    stages = tuple(stage for stage in STAGES if any(case.stage == stage for case in dataset.cases))
    adapters, models = build_adapters(environ, stages)
    serialized = {
        case.case_id: input_serialized(case) if case.stage == "input" else None
        for case in dataset.cases
    }
    windows = {
        case.case_id: input_window_exceeded(case) if case.stage == "input" else False
        for case in dataset.cases
    }
    outcomes = tuple(
        _observe(
            case,
            serialized=serialized[case.case_id],
            window_exceeded=windows[case.case_id],
            adapters=adapters,
        )
        for case in dataset.cases
    )
    return outcomes, models


def _empty_group() -> dict[str, int]:
    return {
        "attempted": 0,
        "completed": 0,
        "errors": 0,
        "window_errors": 0,
        "expected_allowed": 0,
        "expected_blocked": 0,
        "correct_allow": 0,
        "correct_block": 0,
        "false_blocks": 0,
        "missed_unsafe": 0,
    }


def _record(group: dict[str, int], outcome: Outcome) -> None:
    group["attempted"] += 1
    if outcome.expected == "allow":
        group["expected_allowed"] += 1
    else:
        group["expected_blocked"] += 1
    if outcome.observed == "error":
        group["errors"] += 1
        if outcome.error_code == ERROR_INPUT_WINDOW:
            group["window_errors"] += 1
        return
    group["completed"] += 1
    if outcome.expected == "allow" and outcome.observed == "allow":
        group["correct_allow"] += 1
    elif outcome.expected == "block" and outcome.observed == "block":
        group["correct_block"] += 1
    elif outcome.expected == "allow" and outcome.observed == "block":
        group["false_blocks"] += 1
    elif outcome.expected == "block" and outcome.observed == "allow":
        group["missed_unsafe"] += 1


def _rate(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _percentile(values: list[float], percent: int) -> float | None:
    """Nearest-rank percentile over an explicitly supplied population."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(percent / 100.0 * len(ordered)))
    return round(ordered[min(rank, len(ordered)) - 1], 3)


def _finalize(group: dict[str, int], latencies: list[float]) -> dict[str, Any]:
    completed = group["completed"]
    allowed_population = group["correct_allow"] + group["false_blocks"]
    blocked_population = group["correct_block"] + group["missed_unsafe"]
    result: dict[str, Any] = dict(group)
    result["rates"] = {
        "accuracy": _rate(
            group["correct_allow"] + group["correct_block"], completed
        ),
        "false_block_rate": _rate(group["false_blocks"], allowed_population),
        "missed_unsafe_rate": _rate(group["missed_unsafe"], blocked_population),
        "denominators": {
            "accuracy": {
                "name": "completed_cases_excluding_errors",
                "count": completed,
            },
            "false_block_rate": {
                "name": "correct_allow_plus_false_blocks",
                "count": allowed_population,
            },
            "missed_unsafe_rate": {
                "name": "correct_block_plus_missed_unsafe",
                "count": blocked_population,
            },
        },
    }
    result["latency_ms"] = {
        "population": "all_attempted_cases_including_errors",
        "method": "nearest_rank",
        "count": len(latencies),
        "p50": _percentile(latencies, 50),
        "p95": _percentile(latencies, 95),
    }
    return result


def aggregate_outcomes(outcomes: Sequence[Outcome]) -> dict[str, Any]:
    """Aggregate by total, stage, language and stage-language, excluding errors from rates."""
    total = _empty_group()
    per_stage = {stage: _empty_group() for stage in STAGES}
    per_language = {language: _empty_group() for language in LANGUAGES}
    per_stage_language = {
        stage: {language: _empty_group() for language in LANGUAGES} for stage in STAGES
    }
    total_latencies: list[float] = []
    stage_latencies = {stage: [] for stage in STAGES}
    language_latencies = {language: [] for language in LANGUAGES}
    stage_language_latencies = {
        stage: {language: [] for language in LANGUAGES} for stage in STAGES
    }
    for outcome in outcomes:
        _record(total, outcome)
        _record(per_stage[outcome.stage], outcome)
        _record(per_language[outcome.language], outcome)
        _record(per_stage_language[outcome.stage][outcome.language], outcome)
        total_latencies.append(outcome.elapsed_ms)
        stage_latencies[outcome.stage].append(outcome.elapsed_ms)
        language_latencies[outcome.language].append(outcome.elapsed_ms)
        stage_language_latencies[outcome.stage][outcome.language].append(
            outcome.elapsed_ms
        )
    return {
        "total": _finalize(total, total_latencies),
        "per_stage": {
            stage: _finalize(per_stage[stage], stage_latencies[stage]) for stage in STAGES
        },
        "per_language": {
            language: _finalize(per_language[language], language_latencies[language])
            for language in LANGUAGES
        },
        "per_stage_language": {
            stage: {
                language: _finalize(
                    per_stage_language[stage][language],
                    stage_language_latencies[stage][language],
                )
                for language in LANGUAGES
            }
            for stage in STAGES
        },
    }


def _expected_counts(cases: Sequence[GuardCase]) -> dict[str, Any]:
    def blank() -> dict[str, int]:
        return {
            "cases": 0,
            "expected_allowed": 0,
            "expected_blocked": 0,
            "window_exceeded": 0,
        }

    total = blank()
    per_stage = {stage: blank() for stage in STAGES}
    per_language = {language: blank() for language in LANGUAGES}
    for case in cases:
        for group in (total, per_stage[case.stage], per_language[case.language]):
            group["cases"] += 1
            if case.expected == "allow":
                group["expected_allowed"] += 1
            else:
                group["expected_blocked"] += 1
            if case.stage == "input" and input_window_exceeded(case):
                group["window_exceeded"] += 1
    return {"total": total, "per_stage": per_stage, "per_language": per_language}


def _outcome_entry(outcome: Outcome) -> dict[str, Any]:
    return {
        "id": outcome.case_id,
        "stage": outcome.stage,
        "language": outcome.language,
        "expected": outcome.expected,
        "observed": outcome.observed,
        "error_code": outcome.error_code,
        "elapsed_ms": outcome.elapsed_ms,
    }


def build_run_report(
    dataset: GuardDataset,
    outcomes: Sequence[Outcome],
    *,
    models: Mapping[str, str],
) -> tuple[dict[str, Any], int]:
    """Build a metadata-only execute report; never includes payload text."""
    return {
        "schema_version": SCHEMA_VERSION,
        "report_kind": REPORT_KIND,
        "dry_run": False,
        "dataset_id": dataset.dataset_id,
        "dataset_sha256": dataset.sha256,
        "evidence_label": dataset.evidence_label,
        "models": dict(models),
        "counts": {
            "cases": len(dataset.cases),
            "by_stage": {
                stage: sum(1 for case in dataset.cases if case.stage == stage)
                for stage in STAGES
            },
            "by_language": {
                language: sum(1 for case in dataset.cases if case.language == language)
                for language in LANGUAGES
            },
            "expected_allowed": sum(1 for case in dataset.cases if case.expected == "allow"),
            "expected_blocked": sum(1 for case in dataset.cases if case.expected == "block"),
        },
        "aggregates": aggregate_outcomes(outcomes),
        "cases": [_outcome_entry(outcome) for outcome in outcomes],
    }, 0 if all(outcome.observed == outcome.expected for outcome in outcomes) else 1


def build_dry_run_report(dataset: GuardDataset) -> dict[str, Any]:
    """Build the validation-only report; no outcome is invented or measured."""
    return {
        "schema_version": SCHEMA_VERSION,
        "report_kind": REPORT_KIND,
        "dry_run": True,
        "dataset_id": dataset.dataset_id,
        "dataset_sha256": dataset.sha256,
        "evidence_label": dataset.evidence_label,
        "counts": {
            "cases": len(dataset.cases),
            "by_stage": {
                stage: sum(1 for case in dataset.cases if case.stage == stage)
                for stage in STAGES
            },
            "by_language": {
                language: sum(1 for case in dataset.cases if case.language == language)
                for language in LANGUAGES
            },
            "expected_allowed": sum(1 for case in dataset.cases if case.expected == "allow"),
            "expected_blocked": sum(1 for case in dataset.cases if case.expected == "block"),
        },
        "planned": _expected_counts(dataset.cases),
        "cases": [
            {
                "id": case.case_id,
                "stage": case.stage,
                "language": case.language,
                "expected": case.expected,
                "observed": None,
                "error_code": None,
                "elapsed_ms": None,
            }
            for case in dataset.cases
        ],
    }


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve(strict=False) == right.resolve(strict=False)
    except (OSError, RuntimeError):
        return False


def _check_report_target(target: Path, *, dataset_path: str | Path) -> None:
    """Refuse an existing path or the dataset before any guard request runs."""
    if _same_path(target, Path(dataset_path)):
        raise ReportError("report path must differ from the dataset")
    if target.exists():
        raise ReportError("report path already exists")


def write_report(report: Mapping[str, Any], path: str | Path, *, dataset_path: str | Path) -> Path:
    """Create the report exclusively; refuse the dataset or an existing path."""
    target = Path(path)
    _check_report_target(target, dataset_path=dataset_path)
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ReportError("report path already exists") from None
    except OSError:
        raise ReportError("report path is not writable") from None
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
    except (OSError, TypeError, ValueError):
        raise ReportError("report could not be written") from None
    return target


def _print_summary(report: Mapping[str, Any], *, report_path: Path | None) -> None:
    counts = report["counts"]
    print(
        f"guard evaluation dataset={report['dataset_id']} cases={counts['cases']} "
        f"expected_allow={counts['expected_allowed']} "
        f"expected_block={counts['expected_blocked']}"
    )
    if report["dry_run"]:
        print("dry-run validation only: no guard client, credential or network access")
    else:
        aggregates = report["aggregates"]["total"]
        print(
            f"attempted={aggregates['attempted']} completed={aggregates['completed']} "
            f"errors={aggregates['errors']} window_errors={aggregates['window_errors']} "
            f"correct_allow={aggregates['correct_allow']} "
            f"correct_block={aggregates['correct_block']} "
            f"false_blocks={aggregates['false_blocks']} "
            f"missed_unsafe={aggregates['missed_unsafe']}"
        )
        passed = all(
            entry["observed"] == entry["expected"] for entry in report["cases"]
        )
        print("guard evaluation: PASS" if passed else "guard evaluation: FAIL")
    if report_path is not None:
        print(f"report: {report_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a synthetic guard dataset; execute only with --execute."
    )
    parser.add_argument("--dataset", required=True, help="version-1 synthetic JSON dataset")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="call the configured guard APIs (default: validate only)",
    )
    parser.add_argument("--report", help="create-exclusive JSON report path")
    args = parser.parse_args(argv)

    try:
        dataset = load_dataset(args.dataset)
    except DatasetError:
        print("error: invalid guard evaluation dataset", file=sys.stderr)
        return 2

    report_path = Path(args.report) if args.report else None
    try:
        if report_path is not None:
            _check_report_target(report_path, dataset_path=args.dataset)
        if args.execute:
            outcomes, models = execute_dataset(dataset, environ=os.environ)
            report, code = build_run_report(dataset, outcomes, models=models)
        else:
            report = build_dry_run_report(dataset)
            code = 0
        if report_path is not None:
            write_report(report, report_path, dataset_path=args.dataset)
    except EvaluationConfigError:
        print("error: guard API configuration is invalid", file=sys.stderr)
        return 2
    except ReportError:
        print("error: cannot write guard evaluation report", file=sys.stderr)
        return 2
    except (DatasetError, OSError, ValueError, TypeError):
        print("error: guard evaluation failed", file=sys.stderr)
        return 2

    _print_summary(report, report_path=report_path)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
