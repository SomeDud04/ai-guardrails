# Guard evaluation (synthetic smoke, dry-run by default)

`nasi_lemak/guard_eval.py` validates a strict version-1 synthetic JSON dataset
and, only with an explicit `--execute`, calls the existing input and output guard
API adapters. It is a plumbing check over agent-authored smoke text, **not** a
held-out benchmark, OWASP coverage, an accepted threshold or evidence of live
model quality, latency or availability.

## What and where

- Command: `python -m nasi_lemak.guard_eval --dataset PATH [--execute] [--report PATH]`
- Dataset: `evals/guards/synthetic-smoke-v1.json` — 16 cases: 8 input
  (safe/attack) and 8 output (safe/unsafe), with at least one pair per language
  (`en`, `bm`, `zh`, `mixed`).
- The dataset and report contain no real customer or production data.

Dataset shape (exact fields, duplicate JSON keys and non-finite numbers are
rejected; file, case, ID, message and conversation byte bounds apply):

```json
{
  "schema_version": 1,
  "dataset_id": "guards-synthetic-smoke-v1",
  "evidence_label": "agent-authored-synthetic-smoke-not-holdout",
  "cases": [
    {"id": "in-en-safe", "stage": "input", "language": "en", "expected": "allow",
     "messages": [{"role": "user", "content": "..."}]},
    {"id": "out-en-safe", "stage": "output", "language": "en", "expected": "allow",
     "messages": [{"role": "user", "content": "..."}], "output": "..."}
  ]
}
```

`stage` is `input` or `output`; `language` is `en`, `bm`, `zh` or `mixed`;
`expected` is `allow` or `block`. The `output` field is required for `output`
cases and forbidden for `input` cases. Roles are limited to `system`, `user` and
`assistant`.

## Dry run (default)

```bash
python -m nasi_lemak.guard_eval --dataset evals/guards/synthetic-smoke-v1.json
```

This validates the complete dataset and reports planned case counts only. It
constructs no guard client, reads no key or URL, and makes no network request.
Per-case `observed` and `elapsed_ms` are `null`; no outcome is fabricated.

## Execute (explicit opt-in)

`--execute` loads only the guard configurations required by the stages in the
dataset, using `guard_client_config` and the same environment contract as the
server (`NASI_LEMAK_INPUT_GUARD_*` / `NASI_LEMAK_OUTPUT_GUARD_*`). Before any
HTTP request it validates:

- every dataset case;
- the input contract identifier `nasi-lemak-input-classifier-v1`;
- the finite `[0, 1]` input threshold;
- each needed URL/model/auth/key or key-file setting.

It reuses `InputGuardApiAdapter`, `Qwen3GuardOutputAdapter` and
`gateway.serialize_messages`. It never loads a generator, database, deployment
configuration or model weights, and it does not retry, truncate or default to
allow. Invalid, timed-out or malformed replies become `error`, never a
successful block. The input path applies the gateway's conservative 512-byte
budget before the classifier call; an over-budget case is reported separately as
`INPUT_WINDOW` and is not sent.

```bash
python -m nasi_lemak.guard_eval --dataset evals/guards/synthetic-smoke-v1.json \
  --execute --report /tmp/guard-eval.json
```

Exit status: `0` for dry-run success or an execute run where every case matches;
`1` for any execute error or expected/observed mismatch; `2` for an invalid
dataset, invalid guard configuration or unsafe report path.

## Report

The JSON report contains the dry-run flag, dataset ID and SHA256, evidence label,
model IDs (execute only), per-case ID/stage/language/expected/observed
(`allow|block|error`), a fixed generic error code and elapsed milliseconds. It
never contains raw messages, candidate output, URLs, keys, headers or exception
text. Aggregates cover total, each stage, each language and each stage-language
pair with attempted/completed/errors counts, expected allowed/blocked, correct
allow/block, false blocks and missed unsafe cases. Each rate records its
denominator name and count and is `null` when that denominator is zero:
**accuracy** is correct/all completed non-error cases; **false-block rate** is
false blocks / (correct allows + false blocks); **missed-unsafe rate** is
missed unsafe / (correct blocks + missed unsafe). Stage-language aggregates let
language quality be inspected separately for input and output instead of
blending the two. Latency p50/p95 use the nearest-rank method over all attempted
cases, including errors, and state that population explicitly.

`--report` is create-exclusive and refuses an existing file or the dataset path.

## Contract compatibility and limits

The API adapters' contracts are documented in
[guard-api-integration.md](guard-api-integration.md). This harness does not
define a new serving wrapper and does not auto-select a runtime mode. The
following remain separate, unproven work: EN/BM/ZH/mixed hold-out evaluation,
concurrency and load testing, PII behaviour, real endpoint acceptance, threshold
calibration and OWASP verification. A passing smoke run is evidence that the
configured plumbing and contracts behave as implemented, not that the guard
models are accurate.
