"""Local CPU benchmark for the guard-model candidates on the guardrail VM.

This harness answers three questions with measurements instead of assumptions:

* which candidate can serve the **input** guard slot,
* which candidate can serve the **output** guard slot,
* how much added latency the local guard step costs per request, so the
  operator can record a budget for timeline item 8.

It reuses two patterns the product already ships:

* the **local loader discipline** of ``nasi_lemak/guards.py``: an existing
  local directory only, ``local_files_only=True``, ``trust_remote_code=False``,
  ``token=False``, safetensors only, ``device cpu`` explicit, an explicit
  thread count, and a fail-closed ``BenchmarkError``. There is no Hub
  resolution, no cache fallback, no download and no network access.
* the **one Qwen3Guard contract** of ``nasi_lemak/qwen3guard.py``: the safety
  taxonomy, the framing, the input-only ``Jailbreak`` category, the per-lane
  verdict shapes (the input slot: the artifact's official two-line
  ``Safety``/``Categories`` verdict; the output slot: the strict three-line
  ``Safety``/``Categories``/``Refusal`` verdict) and the parser are imported,
  never copied. ``--plan`` therefore imports only the standard library plus
  that dependency-free contract; ``torch``/``transformers`` stay optional and
  are imported only by an actual measurement. A verdict that cannot be parsed
  is counted as an error and the run fails closed; it is never reported as
  "safe" and no report is written.

Workload (``--plan``): three languages (en, bm, zh) times four synthetic input
lengths (200, 500, 1000, 2000 characters) times 20 measured calls per bucket,
at the VM's CPU count and again with the thread count capped, for each
applicable candidate/slot pair.

Measurement (``--measure``) runs **inside** the VM against an operator-supplied
model directory. It records, per candidate and per bucket, the character count,
the conservative-unit count of the serialized conversation, the resulting window
split count, the conservative-unit count of the **exact prompt sent** (which
includes the fixed framing) and its own split count, the prompt token count split
into fixed-template and payload parts, the p50/p95/p99 latency, the peak RSS, and
the verdict parse outcome for every call. ``--report`` writes a metadata-only
JSON: no raw inputs, no prompt text, no model output, no URLs and no credentials.
The report is written only when every call parsed; a fail-closed measurement
produces no output artifact.

Usage::

    python scripts/bench_guard_models.py --plan
    python scripts/bench_guard_models.py --measure --model-dir /models/Qwen3Guard-Gen-0.6B \\
        --model qwen3guard-gen --slot output --report /tmp/bench-output.json

Exit status: 0 for ``--plan`` and for a measurement where every call parsed;
1 when a call failed to parse or inference failed (**no report is written**);
2 for an invalid invocation, a missing model directory or a failed load.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

#: Running ``python scripts/bench_guard_models.py`` puts ``scripts/`` on
#: ``sys.path``; add the repository root as well so the shared contract below
#: resolves without an installed package, an editable install or a changed
#: working directory.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from nasi_lemak.guard_errors import GuardError  # noqa: E402
from nasi_lemak.qwen3guard import (  # noqa: E402
    CATEGORY_VALUES,
    FRAMING_VERSION,
    GUARD_FRAMING,
    INPUT_CATEGORY_VALUES,
    INPUT_ONLY_CATEGORY_VALUES,
    LANE_INPUT,
    LANE_RESPONSE,
    REFUSAL_VALUES,
    SAFETY_VALUES,
    VERDICT_MAX_TOKENS,
    parse_categories,
    parse_verdict_fields,
)

SCHEMA_VERSION = 1
BENCHMARK_ID = "guard-model-latency"
EVIDENCE_LABEL = "operator-measured-local-cpu"

#: Guard window in conservative units (UTF-8 bytes plus framing), mirroring
#: ``nasi_lemak.generation.conservative_byte_budget`` and the 512-unit input
#: budget in ``nasi_lemak/guard_eval.py``. This is a byte bound, never a
#: tokenizer count and never a model-context claim.
WINDOW_UNITS = 512

#: Meta Prompt Guard 2's fixed classifier window (special tokens included).
PROMPT_GUARD_MAX_TOKENS = 512

#: Synthetic filler lengths in characters, and the three measured languages.
LENGTHS = (200, 500, 1000, 2000)
LANGUAGES = ("en", "bm", "zh")
CALLS_PER_BUCKET = 20
WARMUP_CALLS = 1
DEFAULT_THREAD_CAP = 2
DEFAULT_PROMPT_GUARD_THRESHOLD = 0.5

#: Taxonomy, verdict vocabulary, framing and verdict bound are the shared
#: contract's objects (imported above); there is deliberately no benchmark copy
#: to drift.  The names are re-exported for the historical benchmark API.
#: ``PROMPT_FRAMING``/``PROMPT_FRAMING_VERSION`` are aliases, not restatements.

#: Benchmark slot -> shared verdict lane.  The product's output slot is the
#: strict three-line ``response`` lane; the input slot is the artifact's
#: official two-line ``input`` lane.  This mapping is applied before every
#: call, including the warm-up, so the benchmark never passes a slot name to
#: the parser as if it were a lane.
SLOT_LANES = {"input": LANE_INPUT, "output": LANE_RESPONSE}

#: Versioned fixed framing sent with every guard call. It is part of the
#: product contract (taxonomy plus verdict shape), so its token cost is paid on
#: every request and is reported separately from the payload.  Both names
#: resolve to the shared framing object, preserving its exact bytes.
PROMPT_FRAMING_VERSION = FRAMING_VERSION
PROMPT_FRAMING = GUARD_FRAMING

#: Fixed, short, PII-masked context for the output slot. The variable part of
#: an output-slot call is the buffered model output.
OUTPUT_CONTEXT = "user: My email is <EMAIL>. Please summarise the weekly plan."
OUTPUT_PREFIX = OUTPUT_CONTEXT + "\nassistant: "

CANDIDATES: dict[str, dict[str, Any]] = {
    "qwen3guard-gen": {
        "artifact": "Qwen/Qwen3Guard-Gen-0.6B",
        "kind": "causal",
        "slots": ("input", "output"),
        "context_window": 32768,
        "planning_seconds_per_call": 1.5,
        "note": "generative verdict; can serve either slot",
    },
    "qwen3guard-stream": {
        "artifact": "Qwen/Qwen3Guard-Stream-0.6B",
        "kind": "sequence-classification-3",
        "slots": ("input", "output"),
        "context_window": 32768,
        "planning_seconds_per_call": 0.15,
        "note": "classification head; low-latency sibling of the generative variant",
    },
    "promptguard2": {
        "artifact": "meta-llama/Llama-Prompt-Guard-2-86M",
        "kind": "sequence-classification-2",
        "slots": ("input",),
        "context_window": PROMPT_GUARD_MAX_TOKENS,
        "planning_seconds_per_call": 0.03,
        "note": "binary attack classifier; English-only; input slot only",
    },
}
MODELS = tuple(CANDIDATES)
SLOTS = ("input", "output")

FILLERS = {
    "en": (
        "The team reviewed the weekly report and updated the shared calendar "
        "before the next planning meeting. "
    ),
    "bm": (
        "Pasukan telah menyemak laporan mingguan dan mengemas kini kalendar "
        "bersama sebelum mesyuarat perancangan seterusnya. "
    ),
    "zh": "团队审阅了每周报告并更新了共享日历，为下一次规划会议做准备。",
}


class BenchmarkError(RuntimeError):
    """Fail-closed benchmark failure carrying no prompt text, path or token."""


# ---------------------------------------------------------------------------
# Workload definition (safe to run with no ML dependency installed)
# ---------------------------------------------------------------------------


def filler_text(language: str, characters: int) -> str:
    """Deterministic innocuous filler of an exact character count."""
    unit = FILLERS.get(language)
    if not isinstance(unit, str) or not unit:
        raise BenchmarkError("benchmark language is not supported")
    if isinstance(characters, bool) or not isinstance(characters, int) or characters < 1:
        raise BenchmarkError("benchmark length is invalid")
    text = (unit * (characters // len(unit) + 1))[:characters]
    if len(text) != characters:
        raise BenchmarkError("benchmark filler could not be built")
    return text


def conservative_units(serialized: str) -> int:
    """Conservative UTF-8 unit count, mirroring the gateway's byte budget.

    Identical to ``nasi_lemak.generation.conservative_byte_budget``: UTF-8 body
    bytes plus a small per-message framing allowance. It is a bound, not a
    tokenizer count.
    """
    if not isinstance(serialized, str):
        raise BenchmarkError("benchmark input is invalid")
    body = len(serialized.encode("utf-8"))
    messages = serialized.count("\n") + 1
    return body + messages * 2 + 2


def window_split_count(units: int) -> int:
    """Deterministic non-overlapping window count for a conservative budget."""
    if isinstance(units, bool) or not isinstance(units, int) or units < 0:
        raise BenchmarkError("benchmark window budget is invalid")
    if units == 0:
        return 1
    return (units + WINDOW_UNITS - 1) // WINDOW_UNITS


def case_payload(slot: str, language: str, characters: int) -> tuple[str, str]:
    """Return ``(serialized, prompt_text)`` for one synthetic bucket.

    The input slot classifies the serialized conversation; the output slot
    classifies the fixed masked context plus the buffered output, exactly the
    shape ``Qwen3GuardOutputAdapter.scan_response`` sends.
    """
    if slot not in SLOTS:
        raise BenchmarkError("benchmark slot is not supported")
    text = filler_text(language, characters)
    if slot == "input":
        serialized = f"user: {text}"
    else:
        serialized = OUTPUT_PREFIX + text
    if not serialized:
        raise BenchmarkError("benchmark input is invalid")
    return serialized, serialized


def plan_rows(settings: int | None = None) -> list[dict[str, Any]]:
    """Every applicable candidate/slot pair with its exact call counts.

    ``measured_calls`` covers every measured thread setting: each setting
    repeats the full language/length grid.
    """
    if settings is None:
        settings = len(thread_settings())
    if isinstance(settings, bool) or not isinstance(settings, int) or settings < 1:
        raise BenchmarkError("benchmark thread settings are invalid")
    rows: list[dict[str, Any]] = []
    for model in MODELS:
        candidate = CANDIDATES[model]
        for slot in SLOTS:
            applicable = slot in candidate["slots"]
            buckets = len(LANGUAGES) * len(LENGTHS) if applicable else 0
            rows.append(
                {
                    "model": model,
                    "artifact": candidate["artifact"],
                    "slot": slot,
                    "applicable": applicable,
                    "lengths": list(LENGTHS),
                    "languages": list(LANGUAGES),
                    "calls_per_bucket": CALLS_PER_BUCKET,
                    "buckets": buckets,
                    "thread_settings": settings if applicable else 0,
                    "measured_calls": buckets * CALLS_PER_BUCKET * settings if applicable else 0,
                    "warmup_calls": buckets * WARMUP_CALLS * settings if applicable else 0,
                    "note": candidate["note"],
                }
            )
    return rows


def thread_settings(cpu_count: int | None = None, cap: int = DEFAULT_THREAD_CAP) -> list[int]:
    """The measured thread settings: the VM's CPU count, then the cap."""
    total = cpu_count if isinstance(cpu_count, int) and cpu_count > 0 else (os.cpu_count() or 1)
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        raise BenchmarkError("benchmark thread cap is invalid")
    settings = [total]
    if cap < total:
        settings.append(cap)
    return settings


def estimated_wall_clock_seconds() -> float:
    """Planning estimate only; replaced by measurement on the VM."""
    total = 0.0
    for row in plan_rows():
        if not row["applicable"]:
            continue
        per_call = CANDIDATES[row["model"]]["planning_seconds_per_call"]
        total += (row["measured_calls"] + row["warmup_calls"]) * per_call
    return total


def plan_lines() -> list[str]:
    """Human-readable workload; no model, no network, no torch import."""
    settings = thread_settings()
    rows = plan_rows()
    measured = sum(row["measured_calls"] for row in rows)
    warmup = sum(row["warmup_calls"] for row in rows)
    framing_units = conservative_units(PROMPT_FRAMING)
    framing_share = 100.0 * framing_units / WINDOW_UNITS
    lines = [
        "Guard-model benchmark plan (no model is loaded; no network, no Hub resolution)",
        f"schema: {BENCHMARK_ID} v{SCHEMA_VERSION}; evidence label: {EVIDENCE_LABEL}",
        f"framing: {PROMPT_FRAMING_VERSION} ({len(PROMPT_FRAMING)} characters, "
        f"{framing_units} conservative units = {framing_share:.1f}% of one "
        f"{WINDOW_UNITS}-unit window, paid on every call)",
        f"guard window: {WINDOW_UNITS} conservative units; window split = ceil(units / {WINDOW_UNITS})",
        f"lengths (characters): {', '.join(str(value) for value in LENGTHS)}",
        f"languages: {', '.join(LANGUAGES)}; measured calls per bucket: {CALLS_PER_BUCKET}"
        f"; warm-up calls per bucket: {WARMUP_CALLS} (excluded from percentiles)",
        f"thread settings: {', '.join(str(value) for value in settings)}"
        f" (first is the VM CPU count, second is the cap)",
        "",
        f"{'candidate':<18}{'slot':<8}{'buckets':>8}{'measured':>10}{'warm-up':>9}  artifact",
        "(measured calls include every thread setting; buckets = languages x lengths)",
    ]
    for row in rows:
        if not row["applicable"]:
            lines.append(
                f"{row['model']:<18}{row['slot']:<8}{'-':>8}{'-':>10}{'-':>9}"
                f"  not applicable: {row['note']}"
            )
            continue
        lines.append(
            f"{row['model']:<18}{row['slot']:<8}{row['buckets']:>8}"
            f"{row['measured_calls']:>10}{row['warmup_calls']:>9}  {row['artifact']}"
        )
    lines.extend(
        [
            "",
            f"total measured calls: {measured}; total warm-up calls: {warmup}",
            "estimated cost: 0.00 USD (in-process CPU inference; no cloud, no network, no tokens)",
            f"estimated wall clock: {estimated_wall_clock_seconds():.0f} s "
            "(planning constants only, NOT a measurement)",
            "reports: metadata-only JSON (counts, percentiles, load seconds, peak RSS, parse outcomes)",
        ]
    )
    return lines


# ---------------------------------------------------------------------------
# Contract parsing (the shared contract; benchmark-local error mapping only)
# ---------------------------------------------------------------------------


def _slot_lane(slot: str) -> str:
    """Map a benchmark slot onto the shared parser's lane."""
    try:
        return SLOT_LANES[slot]
    except (KeyError, TypeError):
        raise BenchmarkError("benchmark slot is not supported") from None


def parse_verdict(text: Any, *, lane: str = LANE_RESPONSE) -> dict[str, Any]:
    """Convert the shared verdict to the report's dict, or fail closed.

    Parsing, text splitting, taxonomy membership and lane rules live only in
    :mod:`nasi_lemak.qwen3guard`.  The benchmark's sole local behaviour is the
    thin conversion below: a :class:`GuardVerdict` becomes this script's
    dictionary and a shared :class:`GuardError` becomes :class:`BenchmarkError`.
    """
    try:
        verdict = parse_verdict_fields(text, lane=lane)
    except GuardError as error:
        raise BenchmarkError(str(error)) from None
    return {
        "safety": verdict.safety,
        "categories": verdict.categories,
        "refusal": verdict.refusal,
        "allow": verdict.safe,
    }


def parse_safety_label(label: Any) -> str:
    """Map a classification-head label onto the product's safety vocabulary."""
    if not isinstance(label, str):
        raise BenchmarkError("guard label mapping is invalid")
    name = label.strip().lower()
    if "unsafe" in name:
        return "Unsafe"
    if "controversial" in name:
        return "Controversial"
    if "safe" in name:
        return "Safe"
    raise BenchmarkError("guard label mapping is invalid")


def parse_binary_label(label: Any) -> str:
    """Map a binary attack-classifier label onto ``benign``/``malicious``."""
    if not isinstance(label, str):
        raise BenchmarkError("guard label mapping is invalid")
    name = label.strip().lower()
    if name not in ("benign", "malicious"):
        raise BenchmarkError("guard label mapping is invalid")
    return name


# ---------------------------------------------------------------------------
# Report schema (metadata only)
# ---------------------------------------------------------------------------

_TOP_KEYS = frozenset(
    {
        "schema_version",
        "benchmark",
        "evidence_label",
        "generated_at",
        "environment",
        "candidate",
        "thread_settings",
        "totals",
    }
)
_ENVIRONMENT_KEYS = frozenset(
    {
        "cpu_count",
        "ram_bytes",
        "platform",
        "machine",
        "python",
        "torch",
        "transformers",
        "rss_source",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "name",
        "slot",
        "artifact",
        "artifact_bytes",
        "artifact_sha256",
        "context_window",
        "prompt_framing",
        "threshold",
    }
)
_RUN_KEYS = frozenset(
    {
        "threads",
        "load_seconds",
        "peak_rss_after_load_bytes",
        "peak_rss_after_run_bytes",
        "buckets",
    }
)
_BUCKET_KEYS = frozenset(
    {
        "language",
        "characters",
        "serialized_characters",
        "conservative_units",
        "window_split_count",
        "template_units",
        "prompt_units",
        "prompt_window_split_count",
        "template_tokens",
        "payload_tokens",
        "prompt_tokens",
        "calls",
        "warmup_calls",
        "errors",
        "over_window_calls",
        "parse_outcomes",
        "latency_ms",
    }
)
_PARSE_KEYS = frozenset({"parsed_allow", "parsed_block", "parse_error", "inference_error"})
_LATENCY_KEYS = frozenset({"p50", "p95", "p99"})
_SHA256_LENGTH = 64


def _is_int(value: Any, minimum: int = 0) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= minimum


def _is_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def validate_report(report: Any) -> list[str]:
    """Return schema violations; an empty list means the report is valid.

    The schema is a strict allowlist: a field that is not listed here cannot be
    written, so raw input, prompt text, model output, URLs and credentials have
    nowhere to go.
    """
    errors: list[str] = []
    if not isinstance(report, dict):
        return ["report is not an object"]
    if set(report) != _TOP_KEYS:
        errors.append("top-level keys are invalid")
        return errors
    if report["schema_version"] != SCHEMA_VERSION:
        errors.append("schema version is invalid")
    if report["benchmark"] != BENCHMARK_ID:
        errors.append("benchmark identifier is invalid")
    if report["evidence_label"] != EVIDENCE_LABEL:
        errors.append("evidence label is invalid")
    generated = report["generated_at"]
    if not isinstance(generated, str) or not generated.endswith("Z") or len(generated) != 20:
        errors.append("generated_at is invalid")
    environment = report["environment"]
    if not isinstance(environment, dict) or set(environment) != _ENVIRONMENT_KEYS:
        errors.append("environment is invalid")
    else:
        for key in ("cpu_count",):
            if not _is_int(environment[key], 1):
                errors.append(f"environment {key} is invalid")
        if environment["ram_bytes"] is not None and not _is_int(environment["ram_bytes"], 0):
            errors.append("environment ram_bytes is invalid")
        for key in ("torch", "transformers", "platform", "machine", "python", "rss_source"):
            if environment[key] is not None and not isinstance(environment[key], str):
                errors.append(f"environment {key} is invalid")
        if environment["rss_source"] not in ("vmhwm", "unavailable"):
            errors.append("environment rss_source is invalid")
    candidate = report["candidate"]
    if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_KEYS:
        errors.append("candidate is invalid")
    else:
        if candidate["name"] not in MODELS:
            errors.append("candidate name is invalid")
        if candidate["slot"] not in SLOTS:
            errors.append("candidate slot is invalid")
        if not isinstance(candidate["artifact"], str) or not candidate["artifact"]:
            errors.append("candidate artifact is invalid")
        if candidate["prompt_framing"] != PROMPT_FRAMING_VERSION:
            errors.append("candidate prompt framing is invalid")
        if not _is_int(candidate["artifact_bytes"], 0):
            errors.append("candidate artifact_bytes is invalid")
        if candidate["artifact_sha256"] is not None:
            digest = candidate["artifact_sha256"]
            if not isinstance(digest, str) or len(digest) != _SHA256_LENGTH:
                errors.append("candidate artifact_sha256 is invalid")
            elif any(character not in "0123456789abcdef" for character in digest):
                errors.append("candidate artifact_sha256 is invalid")
        if candidate["threshold"] is not None and not _is_number(candidate["threshold"]):
            errors.append("candidate threshold is invalid")
        if candidate["name"] == "promptguard2" and candidate["slot"] != "input":
            errors.append("promptguard2 has no output slot")
    runs = report["thread_settings"]
    if not isinstance(runs, list) or not runs:
        errors.append("thread settings are missing")
        runs = []
    seen_threads: list[int] = []
    for run in runs:
        if not isinstance(run, dict) or set(run) != _RUN_KEYS:
            errors.append("thread setting entry is invalid")
            continue
        threads = run["threads"]
        if not _is_int(threads, 1):
            errors.append("thread count is invalid")
        else:
            seen_threads.append(threads)
        if run["load_seconds"] is not None and not _is_number(run["load_seconds"]):
            errors.append("load seconds are invalid")
        for key in ("peak_rss_after_load_bytes", "peak_rss_after_run_bytes"):
            if run[key] is not None and not _is_int(run[key], 0):
                errors.append(f"{key} is invalid")
        buckets = run["buckets"]
        if not isinstance(buckets, list) or not buckets:
            errors.append("buckets are missing")
            continue
        expected = len(LANGUAGES) * len(LENGTHS)
        if len(buckets) != expected:
            errors.append("bucket count is invalid")
        for bucket in buckets:
            errors.extend(_validate_bucket(bucket))
    if len(set(seen_threads)) != len(seen_threads):
        errors.append("thread settings repeat")
    totals = report["totals"]
    if not isinstance(totals, dict) or set(totals) != {"calls", "errors"}:
        errors.append("totals are invalid")
    elif not _is_int(totals["calls"], 0) or not _is_int(totals["errors"], 0):
        errors.append("totals are invalid")
    else:
        counted_calls = 0
        counted_errors = 0
        for run in runs:
            if not isinstance(run, dict):
                continue
            for bucket in run.get("buckets") or ():
                if not isinstance(bucket, dict):
                    continue
                if _is_int(bucket.get("calls"), 0):
                    counted_calls += bucket["calls"]
                if _is_int(bucket.get("errors"), 0):
                    counted_errors += bucket["errors"]
        if totals["calls"] != counted_calls or totals["errors"] != counted_errors:
            errors.append("totals are inconsistent with the buckets")
    return errors


def _validate_bucket(bucket: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(bucket, dict) or set(bucket) != _BUCKET_KEYS:
        return ["bucket is invalid"]
    if bucket["language"] not in LANGUAGES:
        errors.append("bucket language is invalid")
    if bucket["characters"] not in LENGTHS:
        errors.append("bucket characters is invalid")
    if not _is_int(bucket["serialized_characters"], 1):
        errors.append("bucket serialized_characters is invalid")
    if not _is_int(bucket["conservative_units"], 1):
        errors.append("bucket conservative_units is invalid")
    if not _is_int(bucket["window_split_count"], 1):
        errors.append("bucket window_split_count is invalid")
    elif bucket["conservative_units"] > 0:
        expected = window_split_count(bucket["conservative_units"])
        if bucket["window_split_count"] != expected:
            errors.append("bucket window_split_count is inconsistent")
    if bucket["template_units"] is not None and not _is_int(bucket["template_units"], 1):
        errors.append("bucket template_units is invalid")
    if not _is_int(bucket["prompt_units"], 1):
        errors.append("bucket prompt_units is invalid")
    if not _is_int(bucket["prompt_window_split_count"], 1):
        errors.append("bucket prompt_window_split_count is invalid")
    elif bucket["prompt_units"] > 0:
        expected = window_split_count(bucket["prompt_units"])
        if bucket["prompt_window_split_count"] != expected:
            errors.append("bucket prompt_window_split_count is inconsistent")
    for key in ("template_tokens", "payload_tokens", "prompt_tokens"):
        if bucket[key] is not None and not _is_int(bucket[key], 0):
            errors.append(f"bucket {key} is invalid")
    if bucket["calls"] != CALLS_PER_BUCKET:
        errors.append("bucket call count is invalid")
    if bucket["warmup_calls"] != WARMUP_CALLS:
        errors.append("bucket warm-up count is invalid")
    outcomes = bucket["parse_outcomes"]
    if not isinstance(outcomes, dict) or set(outcomes) != _PARSE_KEYS:
        errors.append("bucket parse outcomes are invalid")
    else:
        if any(not _is_int(value, 0) for value in outcomes.values()):
            errors.append("bucket parse outcomes are invalid")
        elif sum(outcomes.values()) != bucket["calls"]:
            errors.append("bucket parse outcomes are inconsistent")
        elif outcomes["parse_error"] + outcomes["inference_error"] != bucket["errors"]:
            errors.append("bucket errors are inconsistent")
    if not _is_int(bucket["errors"], 0) or bucket["errors"] > bucket["calls"]:
        errors.append("bucket errors are invalid")
    if not _is_int(bucket["over_window_calls"], 0):
        errors.append("bucket over_window_calls is invalid")
    latency = bucket["latency_ms"]
    if not isinstance(latency, dict) or set(latency) != _LATENCY_KEYS:
        errors.append("bucket latency is invalid")
    else:
        values = [latency[key] for key in ("p50", "p95", "p99")]
        if any(not _is_number(value) for value in values):
            errors.append("bucket latency is invalid")
        elif not values[0] <= values[1] <= values[2]:
            errors.append("bucket latency percentiles are inconsistent")
    return errors


def write_report(report: dict[str, Any], path: str) -> None:
    """Write the metadata-only report create-exclusive; refuse an existing file."""
    errors = validate_report(report)
    if errors:
        raise BenchmarkError("benchmark report is invalid")
    target = _prepare_report_path(path)
    try:
        with open(target, "x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except BenchmarkError:
        raise
    except (OSError, ValueError):
        raise BenchmarkError("benchmark report could not be written") from None


def _prepare_report_path(path: Any) -> Path:
    """Fail before the measurement, not after it, on an unusable report path.

    The check is advisory only: :func:`write_report` still opens the file with
    ``x`` so an existing report is never overwritten.
    """
    if not isinstance(path, str) or not path or "\x00" in path:
        raise BenchmarkError("benchmark report path is invalid")
    try:
        target = Path(path).expanduser()
        if target.exists():
            raise BenchmarkError("benchmark report path already exists")
        if not target.parent.is_dir():
            raise BenchmarkError("benchmark report directory is missing")
    except BenchmarkError:
        raise
    except (OSError, ValueError):
        raise BenchmarkError("benchmark report path is invalid") from None
    return target


# ---------------------------------------------------------------------------
# Measurement helpers
# ---------------------------------------------------------------------------


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile over the measured population."""
    if not values:
        raise BenchmarkError("benchmark population is empty")
    if not 0.0 < fraction <= 1.0:
        raise BenchmarkError("benchmark percentile is invalid")
    ordered = sorted(float(value) for value in values)
    rank = min(max(math.ceil(fraction * len(ordered)), 1), len(ordered))
    return round(ordered[rank - 1], 3)


def peak_rss_bytes() -> int | None:
    """Peak resident set size from ``/proc/self/status`` ``VmHWM``."""
    try:
        with open("/proc/self/status", "r", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("VmHWM:"):
                    fields = line.split()
                    return int(fields[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def total_ram_bytes() -> int | None:
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _local_directory(model_dir: Any) -> str:
    """Existing local directory only; never a Hub ID, URL or cache fallback."""
    if isinstance(model_dir, bool) or not isinstance(model_dir, (str, Path)):
        raise BenchmarkError("model directory is not configured")
    text = str(model_dir)
    if not text or "\x00" in text or "://" in text:
        raise BenchmarkError("model directory is not configured")
    try:
        path = Path(text).expanduser()
        if not path.is_dir():
            raise BenchmarkError("model directory is not available")
    except BenchmarkError:
        raise
    except (OSError, ValueError):
        raise BenchmarkError("model directory is not available") from None
    return str(path)


def artifact_bytes(directory: str) -> int:
    """Sum of file sizes in the artifact directory (stat only, no read)."""
    total = 0
    try:
        for entry in Path(directory).rglob("*"):
            if entry.is_file():
                total += entry.stat().st_size
    except (OSError, ValueError):
        raise BenchmarkError("model directory could not be inspected") from None
    return total


def _import_torch() -> Any:
    try:
        import torch  # type: ignore[import-not-found]
    except Exception:
        raise BenchmarkError("benchmark dependencies are unavailable") from None
    return torch


def _import_transformers() -> Any:
    try:
        import transformers  # type: ignore[import-not-found]
    except Exception:
        raise BenchmarkError("benchmark dependencies are unavailable") from None
    return transformers


def _flat_ids(value: Any, message: str) -> list[int]:
    try:
        if hasattr(value, "detach"):
            value = value.detach()
        if hasattr(value, "cpu"):
            value = value.cpu()
        if hasattr(value, "tolist"):
            value = value.tolist()
    except Exception:
        raise BenchmarkError(message) from None
    if isinstance(value, dict):
        value = value.get("input_ids")
    if not isinstance(value, (list, tuple)):
        raise BenchmarkError(message)
    values = list(value)
    if values and isinstance(values[0], (list, tuple)):
        if len(values) != 1:
            raise BenchmarkError(message)
        values = list(values[0])
    for item in values:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise BenchmarkError(message)
    return values


def _safety_mapping(config: Any) -> dict[int, str]:
    mapping = getattr(config, "id2label", None)
    if not isinstance(mapping, dict) or len(mapping) != 3:
        raise BenchmarkError("guard label mapping is invalid")
    if {type(key) for key in mapping} != {int} or set(mapping) != {0, 1, 2}:
        raise BenchmarkError("guard label mapping is invalid")
    resolved = {key: parse_safety_label(label) for key, label in mapping.items()}
    if set(resolved.values()) != set(SAFETY_VALUES):
        raise BenchmarkError("guard label mapping is invalid")
    return resolved


def _binary_mapping(config: Any) -> dict[int, str]:
    mapping = getattr(config, "id2label", None)
    if not isinstance(mapping, dict) or len(mapping) != 2:
        raise BenchmarkError("guard label mapping is invalid")
    if {type(key) for key in mapping} != {int} or set(mapping) != {0, 1}:
        raise BenchmarkError("guard label mapping is invalid")
    resolved = {key: parse_binary_label(label) for key, label in mapping.items()}
    if set(resolved.values()) != {"benign", "malicious"}:
        raise BenchmarkError("guard label mapping is invalid")
    return resolved


def tokenizer_call_options(kind: str) -> dict[str, Any]:
    """Tokenizer settings per candidate shape, mirroring the product loaders.

    ``nasi_lemak.guards.PromptGuard2`` tokenizes with
    ``add_special_tokens=True`` and compares *that* count to
    :data:`PROMPT_GUARD_MAX_TOKENS`, so the benchmark must do the same or it
    would forward a prompt the product rejects. The chat-shaped candidates
    (generative and classification-head) get their special tokens from the
    artifact's own chat template, so they must not be double-counted.
    """
    if kind == "sequence-classification-2":
        return {"add_special_tokens": True, "truncation": False}
    if kind in ("causal", "sequence-classification-3"):
        return {"add_special_tokens": False, "truncation": False}
    raise BenchmarkError("benchmark model shape is not supported")


class Runner:
    """One loaded guard model, CPU-only, with an explicit thread count."""

    def __init__(self, model_name: str, directory: str, *, threads: int, threshold: float) -> None:
        candidate = CANDIDATES.get(model_name)
        if candidate is None:
            raise BenchmarkError("benchmark model is not supported")
        self.name = model_name
        self.kind = candidate["kind"]
        self.threshold = threshold
        self._torch = _import_torch()
        transformers = _import_transformers()
        self._set_threads(threads)
        common = {
            "token": False,
            "local_files_only": True,
            "trust_remote_code": False,
        }
        try:
            self.tokenizer = transformers.AutoTokenizer.from_pretrained(directory, **common)
        except Exception:
            raise BenchmarkError("guard tokenizer could not be loaded") from None
        if self.tokenizer is None:
            raise BenchmarkError("guard tokenizer could not be loaded")
        try:
            if self.kind == "causal":
                # Measure the deployed lane, not the checkpoint's storage dtype.
                # The Qwen3Guard artifact is bf16 and CPU bf16 matmul is
                # emulated (~330x slower than fp32); the product loads the
                # causal guard in float32, so the benchmark must do the same or
                # the latency it reports is not the deployed latency.
                model = transformers.AutoModelForCausalLM.from_pretrained(
                    directory,
                    use_safetensors=True,
                    dtype=self._torch.float32,
                    **common,
                )
            else:
                model = transformers.AutoModelForSequenceClassification.from_pretrained(
                    directory, use_safetensors=True, **common
                )
        except Exception:
            raise BenchmarkError("guard model could not be loaded") from None
        if model is None:
            raise BenchmarkError("guard model could not be loaded")
        try:
            model.eval()
            model.to("cpu")
        except Exception:
            raise BenchmarkError("guard model could not be prepared") from None
        self.model = model
        config = getattr(model, "config", None)
        self._context_window = getattr(config, "max_position_embeddings", None)
        if self.kind == "sequence-classification-3":
            self._mapping = _safety_mapping(config)
        elif self.kind == "sequence-classification-2":
            self._mapping = _binary_mapping(config)
        else:
            self._mapping = {}
        if self.kind == "causal":
            self._eos = self._generation_eos()
            pad = getattr(self.tokenizer, "pad_token_id", None)
            if isinstance(pad, bool) or not isinstance(pad, int) or pad < 0:
                pad = self._eos if isinstance(self._eos, int) else self._eos[0]
            self._pad = pad

    def _set_threads(self, threads: int) -> None:
        if isinstance(threads, bool) or not isinstance(threads, int) or threads < 1:
            raise BenchmarkError("benchmark thread count is invalid")
        try:
            self._torch.set_num_threads(threads)
        except Exception:
            raise BenchmarkError("benchmark thread count could not be set") from None

    def _generation_eos(self) -> int | list[int]:
        for source in (
            getattr(self.model, "generation_config", None),
            getattr(self.model, "config", None),
        ):
            value = getattr(source, "eos_token_id", None) if source is not None else None
            if value is not None:
                return self._validate_eos(value)
        value = getattr(self.tokenizer, "eos_token_id", None)
        if value is None:
            raise BenchmarkError("guard tokenizer has no end-of-sequence token")
        return self._validate_eos(value)

    @staticmethod
    def _validate_eos(value: Any) -> int | list[int]:
        if isinstance(value, bool):
            raise BenchmarkError("guard end-of-sequence configuration is invalid")
        if isinstance(value, int) and value >= 0:
            return value
        if isinstance(value, (list, tuple)) and value:
            identifiers = list(value)
            if all(
                not isinstance(item, bool) and isinstance(item, int) and item >= 0
                for item in identifiers
            ) and len(set(identifiers)) == len(identifiers):
                return identifiers
        raise BenchmarkError("guard end-of-sequence configuration is invalid")

    def context_window(self) -> int | None:
        value = self._context_window
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return None
        return value

    def encode(self, prompt: str) -> list[int]:
        """Tokenize one prompt; no truncation, so the count is the real cost."""
        if not isinstance(prompt, str) or not prompt:
            raise BenchmarkError("guard input is invalid")
        try:
            encoded = self.tokenizer(prompt, **tokenizer_call_options(self.kind))
        except Exception:
            raise BenchmarkError("guard tokenization failed") from None
        return _flat_ids(encoded, "guard tokenization failed")

    def chat_prompt(self, payload: str) -> str:
        """Apply the artifact's own chat template to the fixed framing + payload."""
        conversation = [
            {"role": "system", "content": PROMPT_FRAMING},
            {"role": "user", "content": payload},
        ]
        try:
            return self.tokenizer.apply_chat_template(
                conversation, tokenize=False, add_generation_prompt=True
            )
        except Exception:
            raise BenchmarkError("guard tokenization failed") from None

    def _tensors(self, ids: list[int]) -> dict[str, Any]:
        return {
            "input_ids": self._torch.tensor([ids]),
            "attention_mask": self._torch.tensor([[1] * len(ids)]),
        }

    def call(self, prompt: str, *, lane: str = LANE_RESPONSE) -> dict[str, Any]:
        """One real guard call; returns the parsed outcome or raises."""
        ids = self.encode(prompt)
        if self.kind == "causal":
            return self._call_causal(ids, lane=lane)
        if self.kind == "sequence-classification-3":
            return self._call_safety_head(ids)
        return self._call_binary(ids)

    def _call_causal(self, ids: list[int], *, lane: str) -> dict[str, Any]:
        try:
            with self._torch.inference_mode():
                generated = self.model.generate(
                    **self._tensors(ids),
                    max_new_tokens=VERDICT_MAX_TOKENS,
                    do_sample=False,
                    eos_token_id=self._eos,
                    pad_token_id=self._pad,
                )
        except Exception:
            raise BenchmarkError("guard inference failed") from None
        if hasattr(generated, "sequences"):
            generated = generated.sequences
        output = _flat_ids(generated, "guard model returned an invalid sequence")
        if len(output) <= len(ids) or output[: len(ids)] != list(ids):
            raise BenchmarkError("guard model returned an invalid sequence")
        new_ids = output[len(ids) :]
        if not new_ids or len(new_ids) > VERDICT_MAX_TOKENS:
            raise BenchmarkError("guard model returned an invalid sequence")
        try:
            text = self.tokenizer.decode(new_ids, skip_special_tokens=True)
        except Exception:
            raise BenchmarkError("guard output could not be decoded") from None
        return parse_verdict(text, lane=lane)

    def _call_safety_head(self, ids: list[int]) -> dict[str, Any]:
        try:
            with self._torch.inference_mode():
                outputs = self.model(**self._tensors(ids))
        except Exception:
            raise BenchmarkError("guard inference failed") from None
        logits = getattr(outputs, "logits", None)
        if logits is None:
            raise BenchmarkError("guard model returned invalid scores")
        try:
            values = logits.detach().cpu().tolist()
        except Exception:
            raise BenchmarkError("guard model returned invalid scores") from None
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], list):
            raise BenchmarkError("guard model returned invalid scores")
        rows = values[0]
        if not rows or not isinstance(rows[-1], list) or len(rows[-1]) != 3:
            raise BenchmarkError("guard model returned invalid scores")
        final = rows[-1]
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
            for value in final
        ):
            raise BenchmarkError("guard model returned invalid scores")
        index = max(range(3), key=lambda position: final[position])
        safety = self._mapping[index]
        return {
            "safety": safety,
            "categories": (),
            "refusal": None,
            "allow": safety == "Safe",
        }

    def _call_binary(self, ids: list[int]) -> dict[str, Any]:
        if len(ids) > PROMPT_GUARD_MAX_TOKENS:
            # The product's own behaviour: over-window input is blocked before
            # any forward pass, so the measured cost is tokenization only.
            return {"allow": False, "over_window": True}
        try:
            with self._torch.inference_mode():
                outputs = self.model(**self._tensors(ids))
        except Exception:
            raise BenchmarkError("guard inference failed") from None
        logits = getattr(outputs, "logits", None)
        if logits is None:
            raise BenchmarkError("guard model returned invalid scores")
        try:
            values = logits.detach().cpu().tolist()
        except Exception:
            raise BenchmarkError("guard model returned invalid scores") from None
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], list):
            raise BenchmarkError("guard model returned invalid scores")
        scores = values[0]
        if len(scores) != 2:
            raise BenchmarkError("guard model returned invalid scores")
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
            for value in scores
        ):
            raise BenchmarkError("guard model returned invalid scores")
        malicious = [index for index, name in self._mapping.items() if name == "malicious"]
        if len(malicious) != 1:
            raise BenchmarkError("guard label mapping is invalid")
        peak = max(float(value) for value in scores)
        exponentials = [math.exp(float(value) - peak) for value in scores]
        total = sum(exponentials)
        if not math.isfinite(total) or total <= 0.0:
            raise BenchmarkError("guard model returned invalid scores")
        probability = exponentials[malicious[0]] / total
        if not math.isfinite(probability):
            raise BenchmarkError("guard model returned invalid scores")
        return {
            "allow": probability < self.threshold,
            "over_window": False,
            "malicious_probability": probability,
        }


def _measure_bucket(
    runner: Runner,
    *,
    slot: str,
    language: str,
    characters: int,
) -> dict[str, Any]:
    serialized, payload = case_payload(slot, language, characters)
    lane = _slot_lane(slot)
    if runner.kind == "sequence-classification-2":
        prompt = payload
        template_tokens: int | None = None
        template_units: int | None = None
    else:
        template_prompt = runner.chat_prompt("")
        prompt = runner.chat_prompt(payload)
        template_tokens = len(runner.encode(template_prompt))
        template_units = conservative_units(template_prompt)
    prompt_ids = runner.encode(prompt)
    units = conservative_units(serialized)
    prompt_units = conservative_units(prompt)

    for _ in range(WARMUP_CALLS):
        try:
            runner.call(prompt, lane=lane)
        except BenchmarkError:
            # A warm-up failure is counted by the measured calls that follow;
            # the run still fails closed through its error count.
            pass

    outcomes = {"parsed_allow": 0, "parsed_block": 0, "parse_error": 0, "inference_error": 0}
    latencies: list[float] = []
    over_window = 0
    for _ in range(CALLS_PER_BUCKET):
        start = time.perf_counter()
        try:
            verdict = runner.call(prompt, lane=lane)
        except BenchmarkError:
            latencies.append((time.perf_counter() - start) * 1000.0)
            outcomes["inference_error"] += 1
            continue
        latencies.append((time.perf_counter() - start) * 1000.0)
        if not isinstance(verdict, dict) or not isinstance(verdict.get("allow"), bool):
            outcomes["parse_error"] += 1
        elif verdict.get("over_window"):
            over_window += 1
            outcomes["parsed_block"] += 1
        elif verdict["allow"]:
            outcomes["parsed_allow"] += 1
        else:
            outcomes["parsed_block"] += 1

    return {
        "language": language,
        "characters": characters,
        "serialized_characters": len(serialized),
        "conservative_units": units,
        "window_split_count": window_split_count(units),
        "template_units": template_units,
        "prompt_units": prompt_units,
        "prompt_window_split_count": window_split_count(prompt_units),
        "template_tokens": template_tokens,
        "payload_tokens": None if template_tokens is None else max(len(prompt_ids) - template_tokens, 0),
        "prompt_tokens": len(prompt_ids),
        "calls": CALLS_PER_BUCKET,
        "warmup_calls": WARMUP_CALLS,
        "errors": outcomes["parse_error"] + outcomes["inference_error"],
        "over_window_calls": over_window,
        "parse_outcomes": outcomes,
        "latency_ms": {
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
        },
    }


def _environment() -> dict[str, Any]:
    torch_version = None
    transformers_version = None
    try:
        import torch  # type: ignore[import-not-found]

        torch_version = str(torch.__version__)
    except Exception:
        torch_version = None
    try:
        import transformers  # type: ignore[import-not-found]

        transformers_version = str(transformers.__version__)
    except Exception:
        transformers_version = None
    return {
        "cpu_count": os.cpu_count() or 1,
        "ram_bytes": total_ram_bytes(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "torch": torch_version,
        "transformers": transformers_version,
        "rss_source": "vmhwm" if peak_rss_bytes() is not None else "unavailable",
    }


def build_report(
    *,
    model_name: str,
    slot: str,
    directory: str,
    digest: str | None,
    threshold: float | None,
    runs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assemble the metadata-only report object."""
    candidate = CANDIDATES[model_name]
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": BENCHMARK_ID,
        "evidence_label": EVIDENCE_LABEL,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": _environment(),
        "candidate": {
            "name": model_name,
            "slot": slot,
            "artifact": candidate["artifact"],
            "artifact_bytes": artifact_bytes(directory),
            "artifact_sha256": digest,
            "context_window": candidate["context_window"],
            "prompt_framing": PROMPT_FRAMING_VERSION,
            "threshold": threshold,
        },
        "thread_settings": runs,
        "totals": {
            "calls": sum(
                bucket["calls"] for run in runs for bucket in run["buckets"]
            ),
            "errors": sum(
                bucket["errors"] for run in runs for bucket in run["buckets"]
            ),
        },
    }


def _parse_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().lower()
    if len(text) != _SHA256_LENGTH or any(character not in "0123456789abcdef" for character in text):
        raise BenchmarkError("artifact digest is invalid")
    return text


def measure(
    *,
    model_name: str,
    slot: str,
    model_dir: str,
    report_path: str | None,
    digest: str | None,
    cap: int,
    threshold: float,
) -> int:
    """Load one local artifact and measure it; return the process exit status.

    The report is an evidence artifact for a *successful* measurement: if any
    call fails to parse or inference fails, the run returns 1 and writes no
    report at all.  The target path is still checked before loading so an
    unusable ``--report`` does not cost a multi-minute run.
    """
    candidate = CANDIDATES.get(model_name)
    if candidate is None:
        raise BenchmarkError("benchmark model is not supported")
    if slot not in SLOTS:
        raise BenchmarkError("benchmark slot is not supported")
    if slot not in candidate["slots"]:
        raise BenchmarkError("benchmark model has no such slot")
    directory = _local_directory(model_dir)
    if report_path is not None:
        # Refuse an unusable target now, not after a multi-minute run.
        _prepare_report_path(report_path)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise BenchmarkError("benchmark threshold is invalid")
    threshold_value = float(threshold)
    if not math.isfinite(threshold_value) or not 0.0 <= threshold_value <= 1.0:
        raise BenchmarkError("benchmark threshold is invalid")
    settings = thread_settings(cap=cap)

    started = time.perf_counter()
    runner = Runner(model_name, directory, threads=settings[0], threshold=threshold_value)
    load_seconds = round(time.perf_counter() - started, 3)
    peak_after_load = peak_rss_bytes()

    runs: list[dict[str, Any]] = []
    for index, threads in enumerate(settings):
        runner._set_threads(threads)
        buckets = [
            _measure_bucket(runner, slot=slot, language=language, characters=characters)
            for language in LANGUAGES
            for characters in LENGTHS
        ]
        runs.append(
            {
                "threads": threads,
                "load_seconds": load_seconds if index == 0 else None,
                "peak_rss_after_load_bytes": peak_after_load,
                "peak_rss_after_run_bytes": peak_rss_bytes(),
                "buckets": buckets,
            }
        )

    report = build_report(
        model_name=model_name,
        slot=slot,
        directory=directory,
        digest=_parse_sha256(digest),
        threshold=threshold_value if model_name == "promptguard2" else None,
        runs=runs,
    )
    failures = report["totals"]["errors"]
    print(
        f"{model_name}/{slot}: {report['totals']['calls']} measured calls, "
        f"{failures} errors, load {load_seconds:.3f} s, "
        f"threads {', '.join(str(value) for value in settings)}"
    )
    for run in runs:
        for bucket in run["buckets"]:
            latency = bucket["latency_ms"]
            print(
                f"  threads={run['threads']:<3} {bucket['language']:<2} "
                f"{bucket['characters']:>5} chars  units={bucket['conservative_units']:<6} "
                f"splits={bucket['window_split_count']:<3} "
                f"prompt_units={bucket['prompt_units']:<6} "
                f"prompt_splits={bucket['prompt_window_split_count']:<3} "
                f"p50={latency['p50']:>9.2f} p95={latency['p95']:>9.2f} "
                f"p99={latency['p99']:>9.2f} ms  "
                f"outcomes={bucket['parse_outcomes']}"
            )
    if failures:
        print(
            "measurement failed closed: at least one call failed; no report was written",
            file=sys.stderr,
        )
        return 1
    if report_path is not None:
        write_report(report, report_path)
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Local CPU guard-model benchmark (no network, no download).",
        allow_abbrev=False,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--plan",
        action="store_true",
        help="print the workload without loading a model or importing torch",
    )
    mode.add_argument(
        "--measure",
        action="store_true",
        help="measure one operator-supplied local artifact",
    )
    parser.add_argument("--model-dir", default="", help="existing local artifact directory")
    parser.add_argument("--model", default="", choices=("",) + MODELS, help="candidate name")
    parser.add_argument("--slot", default="", choices=("",) + SLOTS, help="guard slot")
    parser.add_argument("--report", default=None, help="metadata-only JSON report path")
    parser.add_argument("--artifact-sha256", default=None, help="operator-recorded digest")
    parser.add_argument(
        "--thread-cap",
        type=int,
        default=DEFAULT_THREAD_CAP,
        help="second thread setting to measure (default: 2)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_PROMPT_GUARD_THRESHOLD,
        help="binary attack-classifier threshold (Prompt Guard 2 only)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.plan:
        for line in plan_lines():
            print(line)
        return 0
    if not args.model or not args.slot or not args.model_dir:
        print(
            "--measure requires --model, --slot and --model-dir",
            file=sys.stderr,
        )
        return 2
    try:
        return measure(
            model_name=args.model,
            slot=args.slot,
            model_dir=args.model_dir,
            report_path=args.report,
            digest=args.artifact_sha256,
            cap=args.thread_cap,
            threshold=args.threshold,
        )
    except BenchmarkError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover - exercised as a script
    raise SystemExit(main())
