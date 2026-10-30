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

`--execute` uses the hosted guard APIs by default; for the deployed local guard
see [Running it against the local guard](#running-it-against-the-local-guard).
With the default backend it loads only the guard configurations required by the
stages in the dataset, using `guard_client_config` and the same environment
contract as the server (`NASI_LEMAK_INPUT_GUARD_*` /
`NASI_LEMAK_OUTPUT_GUARD_*`). Before any HTTP request it validates:

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

## Multilingual guard-lane dataset (v2)

`evals/guards/multilingual-guard-lanes-v2.json` is the dataset for measuring the
deployed guard. It has **186 cases, 93 expected allow and 93 expected block**:

| Stage | en | bm | zh | mixed | Total |
|---|---|---|---|---|---|
| input, expected block | 19 | 19 | 19 | 6 | 63 |
| input, expected allow | 19 | 19 | 19 | 6 | 63 |
| output, expected block | 9 | 9 | 9 | 3 | 30 |
| output, expected allow | 9 | 9 | 9 | 3 | 30 |

- Rows in `en`, `bm` and `zh` are **matched sets**: the same scenario in each
  language, with the language as the only ID difference (`in-jailbreak-01-en`,
  `-bm`, `-zh`). A gap between languages on a row is a language effect.
- `mixed` rows are code-switched BM/English or Chinese/English.
- Each case has a reporting `category`: `benign`, or one of the attack types.
  Reports add `aggregates.per_stage_category`. The label never reaches a guard.
- The benign rows include hard negatives: safety-adjacent vocabulary in a
  legitimate request ("kill a stuck process", phishing awareness) and, at the
  output stage, proper refusals of unsafe requests.
- Output replies are short and deliberately non-actionable. Names, numbers and
  addresses are synthetic, and email addresses use `example.com`.

### Running it against the local guard

`--backend qwen3guard-local` loads `Qwen3GuardLocal` with the same
`NASI_LEMAK_QWEN3GUARD_*` settings as the server, so it runs inside the guard
container, where those settings and the model mount exist. It uses no API key
and no generation model. Run it on an idle VM from the repository checkout;
expect about 25 to 30 minutes on 4 vCPU, with `progress:` lines on stderr:

```bash
docker exec -i nasi-lemak-gateway-1 python -m nasi_lemak.guard_eval \
  --dataset - --execute --backend qwen3guard-local \
  --report /tmp/guard-eval-v2.json < evals/guards/multilingual-guard-lanes-v2.json
docker cp nasi-lemak-gateway-1:/tmp/guard-eval-v2.json ./guard-eval-v2.json
```

The container's `/tmp` does not survive a restart, so copy the report out first.
The loaded model uses about 2.4 GiB beside the gateway's own copy.

`guard evaluation: FAIL` and exit status `1` only mean that at least one case did
not match. Judge a run against the agreed pass mark using `per_stage_language`
and `per_stage_category`, and report errors separately: an `error` is neither a
detection nor a miss.

### What this dataset cannot show

It is agent-authored synthetic data, not a hold-out set, and its evidence label
says so. 63 attack rows at the input stage and 30 at the output stage are small
samples: one miss moves a per-language input rate by about 5 percentage points,
and a per-category rate rests on a handful of rows, so report counts with every
rate. Results apply to one model, one threshold and one framing version. The
matched wording is the author's, so it does not establish how real users or
attackers write in BM or Chinese.

## Contract compatibility and limits

The API adapters' contracts are documented in
[guard-api-integration.md](guard-api-integration.md). This harness does not
define a new serving wrapper and does not auto-select a runtime mode. The
following remain separate, unproven work: EN/BM/ZH/mixed hold-out evaluation,
concurrency and load testing, PII behaviour, real endpoint acceptance, threshold
calibration and OWASP verification. A passing smoke run is evidence that the
configured plumbing and contracts behave as implemented, not that the guard
models are accurate.
