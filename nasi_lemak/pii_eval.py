"""Deterministic offline PII quality evaluation over frozen synthetic corpora.

The evaluator runs the actual production recognizers from
:mod:`nasi_lemak.pii` through their shared span function.  It is an engineering
quality gate over agent-authored synthetic fixtures, not independent human
annotation, population measurement or customer acceptance.

Default reports never contain raw fixture text: only case identifiers, labels,
entity types, offsets, counts and hashes are emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, NamedTuple

from .pii import ENTITY_TYPES, Redaction, find_redactions

PRECISION_GATE = 0.95
RECALL_GATE = 0.95
SCHEMA_VERSION = 1
DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "evals" / "pii"
MATCH_RULE = "exact_entity_type_and_offsets_one_to_one"
SCOPES = ("in_scope", "unsupported")
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
MAX_CASES = 5000
MAX_TEXT_LENGTH = 16384
MAX_SPANS_PER_CASE = 256


class FixtureError(Exception):
    """A frozen fixture or manifest failed validation."""


@dataclass(frozen=True)
class GoldSpan:
    entity_type: str
    start: int
    end: int


@dataclass(frozen=True)
class Case:
    case_id: str
    focus: str
    scope: str
    label: str
    notes: str
    text: str
    gold: tuple[GoldSpan, ...]


@dataclass(frozen=True)
class Corpus:
    split: str
    corpus_id: str
    cases: tuple[Case, ...]
    sha256: str


def _require_str(value: object, *, field: str, case_id: str | None = None) -> str:
    if not isinstance(value, str) or not value:
        where = f" in case {case_id}" if case_id else ""
        raise FixtureError(f"invalid {field}{where}")
    return value


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_corpus(payload: object, *, source_name: str = "corpus") -> Corpus:
    """Validate and parse an in-memory corpus object."""

    if not isinstance(payload, dict):
        raise FixtureError(f"{source_name}: top level must be an object")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise FixtureError(f"{source_name}: unsupported schema_version")
    split = _require_str(payload.get("split"), field="split")
    corpus_id = _require_str(payload.get("corpus_id"), field="corpus_id")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise FixtureError(f"{source_name}: cases must be a non-empty list")
    if len(raw_cases) > MAX_CASES:
        raise FixtureError(f"{source_name}: too many cases")

    seen_ids: set[str] = set()
    cases: list[Case] = []
    for item in raw_cases:
        if not isinstance(item, dict):
            raise FixtureError(f"{source_name}: every case must be an object")
        case_id = _require_str(item.get("id"), field="case id")
        if case_id in seen_ids:
            raise FixtureError(f"{source_name}: duplicate case id {case_id}")
        seen_ids.add(case_id)
        focus = _require_str(item.get("focus"), field="focus", case_id=case_id)
        if focus not in ENTITY_TYPES:
            raise FixtureError(f"{source_name}: invalid focus in case {case_id}")
        scope = item.get("scope", "in_scope")
        if scope not in SCOPES:
            raise FixtureError(f"{source_name}: invalid scope in case {case_id}")
        label = _require_str(item.get("label"), field="label", case_id=case_id)
        notes = item.get("notes", "")
        if not isinstance(notes, str):
            raise FixtureError(f"{source_name}: invalid notes in case {case_id}")
        text = _require_str(item.get("text"), field="text", case_id=case_id)
        if len(text) > MAX_TEXT_LENGTH:
            raise FixtureError(f"{source_name}: text too long in case {case_id}")
        raw_gold = item.get("gold")
        if not isinstance(raw_gold, list):
            raise FixtureError(f"{source_name}: gold must be a list in case {case_id}")
        if len(raw_gold) > MAX_SPANS_PER_CASE:
            raise FixtureError(f"{source_name}: too many gold spans in case {case_id}")

        gold: list[GoldSpan] = []
        seen_spans: set[tuple[str, int, int]] = set()
        for annotated in raw_gold:
            if not isinstance(annotated, dict) or set(annotated) != {"type", "start", "end", "text"}:
                raise FixtureError(f"{source_name}: invalid gold span in case {case_id}")
            entity_type = annotated.get("type")
            if entity_type not in ENTITY_TYPES:
                raise FixtureError(f"{source_name}: invalid gold type in case {case_id}")
            start, end = annotated.get("start"), annotated.get("end")
            if not _is_int(start) or not _is_int(end):
                raise FixtureError(f"{source_name}: non-integer offset in case {case_id}")
            if start < 0 or end > len(text) or start >= end:
                raise FixtureError(f"{source_name}: offset out of bounds in case {case_id}")
            if annotated.get("text") != text[start:end]:
                raise FixtureError(f"{source_name}: gold text mismatch in case {case_id}")
            key = (entity_type, start, end)
            if key in seen_spans:
                raise FixtureError(f"{source_name}: duplicate gold span in case {case_id}")
            seen_spans.add(key)
            gold.append(GoldSpan(entity_type, start, end))

        ordered = sorted(gold, key=lambda span: (span.start, span.end))
        for previous, current in zip(ordered, ordered[1:]):
            if current.start < previous.end:
                raise FixtureError(f"{source_name}: overlapping gold spans in case {case_id}")
        cases.append(Case(case_id, focus, scope, label, notes, text, tuple(ordered)))

    try:
        canonical = json.dumps(
            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except RecursionError:
        raise FixtureError(f"{source_name}: fixture nesting is too deep") from None
    return Corpus(split, corpus_id, tuple(cases), hashlib.sha256(canonical).hexdigest())


def _load_json(path: Path, label: str) -> tuple[bytes, object]:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FIXTURE_BYTES + 1)
    except OSError:
        raise FixtureError(f"cannot read {label}") from None
    if len(raw) > MAX_FIXTURE_BYTES:
        raise FixtureError(f"{label} exceeds the size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise FixtureError(f"invalid JSON in {label}") from None
    return raw, payload


def load_corpus(corpus_path: str | Path, manifest_path: str | Path) -> tuple[Corpus, str]:
    """Load one corpus only if its bytes match the frozen manifest."""

    corpus_path = Path(corpus_path)
    manifest_path = Path(manifest_path)
    manifest_raw, manifest = _load_json(manifest_path, "manifest")
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise FixtureError("invalid manifest")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise FixtureError("invalid manifest files")
    expected = files.get(corpus_path.name)
    if not isinstance(expected, str):
        raise FixtureError(f"manifest has no entry for {corpus_path.name}")
    raw, payload = _load_json(corpus_path, corpus_path.name)
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise FixtureError(f"frozen SHA256 mismatch for {corpus_path.name}")
    corpus = parse_corpus(payload, source_name=corpus_path.name)
    if corpus.split != corpus_path.stem:
        raise FixtureError(f"split mismatch in {corpus_path.name}")
    corpus = Corpus(corpus.split, corpus.corpus_id, corpus.cases, actual)
    return corpus, hashlib.sha256(manifest_raw).hexdigest()


def _runtime_digests() -> dict[str, str]:
    package = Path(__file__).resolve().parent
    digests: dict[str, str] = {}
    for name in ("pii.py", "pii_eval.py", "gateway.py"):
        path = package / name
        digests[f"nasi_lemak/{name}"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def _metric(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def _f1(tp: int, fp: int, fn: int) -> float | None:
    denominator = 2 * tp + fp + fn
    if denominator == 0:
        return None
    return 2 * tp / denominator


class _Counts(NamedTuple):
    gold: int = 0
    predicted: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    positive_cases: int = 0
    negative_cases: int = 0
    predicted_cases: int = 0


def evaluate_corpus(
    corpus: Corpus,
    recognizer: Callable[[str], Iterable[Redaction]] = find_redactions,
) -> dict:
    """Score a corpus against the shared production recognizer."""

    counters = {entity_type: {"gold": 0, "predicted": 0, "tp": 0, "fp": 0, "fn": 0,
                              "positive_cases": 0, "negative_cases": 0, "predicted_cases": 0}
                for entity_type in ENTITY_TYPES}
    errors: list[dict] = []
    excluded: list[dict] = []
    evaluated_cases = 0

    for case in corpus.cases:
        if case.scope != "in_scope":
            excluded.append({
                "case_id": case.case_id,
                "case_label": case.label,
                "scope": case.scope,
                "reason": "outside_declared_scope",
            })
            continue
        evaluated_cases += 1
        predictions = list(recognizer(case.text))
        for prediction in predictions:
            if prediction.entity_type not in ENTITY_TYPES:
                raise ValueError("recognizer returned an unsupported entity type")
            if not _is_int(prediction.start) or not _is_int(prediction.end):
                raise ValueError("recognizer returned a non-integer offset")
            if prediction.start < 0 or prediction.end > len(case.text) or prediction.start >= prediction.end:
                raise ValueError("recognizer returned an out-of-bounds span")

        gold_by_type = {entity_type: [] for entity_type in ENTITY_TYPES}
        for gold in case.gold:
            gold_by_type[gold.entity_type].append(gold)
        predicted_by_type = {entity_type: [] for entity_type in ENTITY_TYPES}
        for prediction in predictions:
            predicted_by_type[prediction.entity_type].append(prediction)

        for entity_type in ENTITY_TYPES:
            counter = counters[entity_type]
            if gold_by_type[entity_type]:
                counter["positive_cases"] += 1
            elif case.focus == entity_type:
                counter["negative_cases"] += 1
            if predicted_by_type[entity_type]:
                counter["predicted_cases"] += 1
            counter["gold"] += len(gold_by_type[entity_type])
            counter["predicted"] += len(predicted_by_type[entity_type])

        unmatched = list(predictions)
        for gold in case.gold:
            for index, prediction in enumerate(unmatched):
                if (prediction.entity_type, prediction.start, prediction.end) == (gold.entity_type, gold.start, gold.end):
                    counters[gold.entity_type]["tp"] += 1
                    unmatched.pop(index)
                    break
            else:
                counters[gold.entity_type]["fn"] += 1
                errors.append({
                    "case_id": case.case_id,
                    "case_label": case.label,
                    "kind": "false_negative",
                    "type": gold.entity_type,
                    "start": gold.start,
                    "end": gold.end,
                    "reason": "gold_span_without_exact_prediction",
                })
        for prediction in unmatched:
            counters[prediction.entity_type]["fp"] += 1
            errors.append({
                "case_id": case.case_id,
                "case_label": case.label,
                "kind": "false_positive",
                "type": prediction.entity_type,
                "start": prediction.start,
                "end": prediction.end,
                "reason": "predicted_span_without_exact_gold",
            })

    per_entity: dict[str, dict] = {}
    gates: dict[str, dict] = {}
    for entity_type in ENTITY_TYPES:
        counter = counters[entity_type]
        precision = _metric(counter["tp"], counter["tp"] + counter["fp"])
        recall = _metric(counter["tp"], counter["tp"] + counter["fn"])
        f1 = _f1(counter["tp"], counter["fp"], counter["fn"])
        applicable = counter["positive_cases"] > 0 and counter["negative_cases"] > 0
        if applicable:
            gate_pass = (
                precision is not None
                and recall is not None
                and precision >= PRECISION_GATE
                and recall >= RECALL_GATE
            )
            gate_status = "pass" if gate_pass else "fail"
        else:
            gate_pass = False
            gate_status = "not_applicable"
        per_entity[entity_type] = {
            "gold_count": counter["gold"],
            "predicted_count": counter["predicted"],
            "tp": counter["tp"],
            "fp": counter["fp"],
            "fn": counter["fn"],
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "positive_cases": counter["positive_cases"],
            "negative_cases": counter["negative_cases"],
            "predicted_cases": counter["predicted_cases"],
            "gate_applicable": applicable,
            "gate_status": gate_status,
        }
        gates[entity_type] = {
            "precision_min": PRECISION_GATE,
            "recall_min": RECALL_GATE,
            "applicable": applicable,
            "status": gate_status,
            "passed": gate_pass,
        }

    # A not_applicable gate means the frozen split has no labelled evidence for
    # that entity (for example POSTAL_ADDRESS before address gold exists).  Such
    # a gate must not fail the split by itself, but it also cannot make a split
    # pass: at least one applicable gate is still required, and every applicable
    # gate must pass.
    applicable_entities = [entity_type for entity_type in ENTITY_TYPES if gates[entity_type]["applicable"]]
    not_applicable_entities = [entity_type for entity_type in ENTITY_TYPES if not gates[entity_type]["applicable"]]
    overall_pass = bool(applicable_entities) and all(
        gates[entity_type]["status"] == "pass" for entity_type in applicable_entities
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "report_kind": "pii_quality_evaluation",
        "split": corpus.split,
        "corpus_id": corpus.corpus_id,
        "corpus_sha256": corpus.sha256,
        "match_rule": MATCH_RULE,
        "counts": {
            "total_cases": len(corpus.cases),
            "evaluated_cases": evaluated_cases,
            "excluded_cases": len(excluded),
            "gold_entities": sum(item["gold"] for item in counters.values()),
            "predicted_entities": sum(item["predicted"] for item in counters.values()),
        },
        "per_entity": per_entity,
        "gates": {
            "provisional_engineering_gate": True,
            "precision_min": PRECISION_GATE,
            "recall_min": RECALL_GATE,
            "requires_nonzero_positive_and_negative_cases": True,
            "customer_approved": False,
            "statistically_validated": False,
            "entities": gates,
            "applicable_entities": applicable_entities,
            "not_applicable_entities": not_applicable_entities,
            "requires_at_least_one_applicable_entity": True,
            "overall_status": "pass" if overall_pass else "fail",
            "overall_pass": overall_pass,
        },
        "errors": errors,
        "excluded_cases": excluded,
        "scope": {
            "entities": list(ENTITY_TYPES),
            "formats": "ASCII structured format recognizers only",
            "identity_validity": "not established",
            "semantic_context": "not evaluated",
            "fixture_provenance": "agent-authored synthetic; not independently labelled human hold-out data",
        },
    }


def _format_metric(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def render_markdown(report: dict, *, manifest_sha256: str) -> str:
    counts = report["counts"]
    lines = [
        "# PII quality evaluation summary",
        "",
        "**Synthetic, agent-authored evaluation split. Not independently labelled or customer accepted.**",
        "",
        f"- Split: `{report['split']}`",
        f"- Corpus ID: `{report['corpus_id']}`",
        f"- Corpus SHA256: `{report['corpus_sha256']}`",
        f"- Manifest SHA256: `{manifest_sha256}`",
        f"- Cases: {counts['evaluated_cases']} evaluated, {counts['excluded_cases']} excluded out of {counts['total_cases']}",
        f"- Match rule: `{report['match_rule']}`",
        "",
        "## Per-entity results",
        "",
        "| Entity | Gold | Predicted | TP | FP | FN | Precision | Recall | F1 | Gate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for entity_type, result in report["per_entity"].items():
        lines.append(
            f"| {entity_type} | {result['gold_count']} | {result['predicted_count']} | "
            f"{result['tp']} | {result['fp']} | {result['fn']} | "
            f"{_format_metric(result['precision'])} | {_format_metric(result['recall'])} | "
            f"{_format_metric(result['f1'])} | {result['gate_status']} |"
        )
    lines.extend([
        "",
        f"Provisional engineering gate: precision >= {PRECISION_GATE:.2f} and recall >= {RECALL_GATE:.2f} "
        "per entity, applicable only when the split has nonzero positive and negative cases for that entity. "
        "`not_applicable` entities are excluded from the overall verdict, but at least one applicable entity "
        "is required and every applicable entity must pass. "
        f"Overall: **{report['gates']['overall_status']}**.",
        "",
        "## Labelled errors",
        "",
    ])
    if report["errors"]:
        for error in report["errors"]:
            lines.append(
                f"- `{error['case_id']}` ({error['case_label']}): {error['kind']} "
                f"{error['type']} {error['start']}-{error['end']} — `{error['reason']}`"
            )
    else:
        lines.append("- None in this split.")
    lines.extend(["", "## Excluded cases", ""])
    if report["excluded_cases"]:
        for excluded in report["excluded_cases"]:
            lines.append(
                f"- `{excluded['case_id']}` ({excluded['case_label']}): "
                f"{excluded['scope']} — `{excluded['reason']}`"
            )
    else:
        lines.append("- None.")
    lines.extend([
        "",
        "## Limits",
        "",
        "- Gold spans are explicit synthetic annotations validated against each fixture text; they were not produced by the production regexes.",
        "- This split is agent-authored. It is not an independent human hold-out set, population estimate or customer acceptance evidence.",
        "- Format matching does not establish identity validity, phone reachability or email deliverability.",
        "- Full-width and obfuscated forms are outside the declared scope; excluded cases are listed above.",
        "- Native classifier/English semantic guard quality and BM/Chinese semantic protection are not evaluated here.",
        "- The thresholds are provisional engineering gates, not customer-approved release criteria.",
        "",
    ])
    return "\n".join(lines)


def write_report(report: dict, out_dir: str | Path, *, manifest_sha256: str) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{report['split']}-report.json"
    md_path = out_dir / f"{report['split']}-summary.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report, manifest_sha256=manifest_sha256), encoding="utf-8")
    return json_path, md_path


def _print_summary(report: dict, json_path: Path, md_path: Path) -> None:
    counts = report["counts"]
    print(f"PII evaluation split={report['split']} cases={counts['evaluated_cases']} "
          f"excluded={counts['excluded_cases']}")
    print("entity gold predicted tp fp fn precision recall f1 gate")
    for entity_type, result in report["per_entity"].items():
        print(
            f"{entity_type} {result['gold_count']} {result['predicted_count']} "
            f"{result['tp']} {result['fp']} {result['fn']} "
            f"{_format_metric(result['precision'])} {_format_metric(result['recall'])} "
            f"{_format_metric(result['f1'])} {result['gate_status']}"
        )
    print(f"report: {json_path}")
    print(f"summary: {md_path}")
    if report["gates"]["overall_pass"]:
        print("provisional quality gates: PASS")
    else:
        print("provisional quality gates: FAIL (honest synthetic evidence; no threshold or label changes)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the frozen synthetic PII quality evaluation.")
    parser.add_argument("--root", default=str(DEFAULT_ROOT), help="directory containing fixtures and manifest")
    parser.add_argument("--split", choices=("evaluation", "development"), default="evaluation")
    parser.add_argument("--manifest", default=None, help="manifest path (default: ROOT/manifest.json)")
    parser.add_argument("--out-dir", default=None, help="report directory (default: ROOT/results)")
    args = parser.parse_args(argv)

    root = Path(args.root)
    corpus_path = root / f"{args.split}.json"
    manifest_path = Path(args.manifest) if args.manifest else root / "manifest.json"
    out_dir = Path(args.out_dir) if args.out_dir else root / "results"

    try:
        corpus, manifest_sha256 = load_corpus(corpus_path, manifest_path)
        report = evaluate_corpus(corpus)
    except FixtureError as exc:
        print(f"error: malformed fixture: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError) as exc:
        print(f"error: evaluation failed: {exc}", file=sys.stderr)
        return 2

    report["runtime_sha256"] = _runtime_digests()
    report["manifest_sha256"] = manifest_sha256
    try:
        json_path, md_path = write_report(report, out_dir, manifest_sha256=manifest_sha256)
    except OSError:
        print("error: cannot write evaluation report", file=sys.stderr)
        return 2

    _print_summary(report, json_path, md_path)
    return 0 if report["gates"]["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
