# Guard-model benchmark and latency budget (28 October 2026)

Status: **harness complete, measurement pending.** This document defines the
benchmark, the decision rules and the honest limits. It deliberately records
**no latency, load-time, memory or parse-outcome numbers**, because no candidate
artifact has been executed yet: the operator obtains the artifacts, runs
`scripts/bench_guard_models.py --measure` inside the guardrail VM, and hands the
metadata-only JSON reports back. The tables below are the fill-in points for
that evidence. Nothing in this document is a measured result, and no
recommendation here may be quoted as one.

## Machine and scope

| Item | Value |
|---|---|
| Host | `ai-guardrail-demo`, Proxmox VM, 192.168.90.41 |
| CPU / RAM | 4 vCPU / 16 GiB, **CPU inference only** (no GPU) |
| Deployment shape | guard models and Presidio loaded **in-process** in the gateway, the way `nasi_lemak/guards.py` already loads Prompt Guard 2 and Llama Guard 3 |
| Out of scope | the generation model `qwen3.8-27b` (SGLang, `https://82haf69n.flexinfra.com.my/v1`) — never contacted |
| Network | none: no Hub resolution, no download, no cache fallback, `local_files_only=True` |

Candidates (operator-supplied local directories; the operator records each
SHA-256 and passes it with `--artifact-sha256`):

| Key | Artifact | Licence / access | Context | Shape |
|---|---|---|---|---|
| `qwen3guard-gen` | `Qwen/Qwen3Guard-Gen-0.6B` | Apache-2.0, ungated | 32768 | generative verdict (tokens to decode) |
| `qwen3guard-stream` | `Qwen/Qwen3Guard-Stream-0.6B` | Apache-2.0, ungated | 32768 | 3-class classification head, no decode |
| `promptguard2` | `meta-llama/Llama-Prompt-Guard-2-86M` | gated (licence accepted, token used to fetch) | 512 | binary attack classifier, English-only |

`promptguard2` is measured for the **input** slot only. It emits a
malicious-probability score, not a safety verdict, so it cannot serve the output
slot; the plan mode prints that row as "not applicable" rather than inventing a
number.

## Workload

`python scripts/bench_guard_models.py --plan` prints the workload and exits 0
without importing `torch`, without a model directory and without opening a
socket (both properties are asserted by tests). The workload is:

- languages `en`, `bm`, `zh`;
- synthetic innocuous filler of exactly 200, 500, 1000 and 2000 **characters**
  per language (not ASCII-only, not corpus payloads, not real data);
- 20 measured calls per language/length bucket, plus 1 warm-up call per bucket
  that is excluded from the percentiles;
- every applicable candidate/slot pair, measured twice: at the VM's CPU count
  and again with the thread count capped at 2.

That is 2400 measured calls and 120 warm-up calls across the five applicable
candidate/slot pairs (480 measured calls each) when the plan prints two thread
settings, as it does on the 4 vCPU VM. The input slot classifies the
serialized conversation (`user: <filler>`); the output slot classifies the fixed
PII-masked context plus the buffered output, which is the shape
`Qwen3GuardOutputAdapter.scan_response` sends. The fixed framing
(`nasi-lemak-guard-framing-v1`, the product taxonomy and the three-line verdict
shape) is prepended to every generative/head call and its token cost is recorded
separately from the payload's.

The exact, ordered command list is in **Operator commands** below. Every run is
sequential in one process; nothing is parallelised and nothing is downloaded.

## Operator commands (exact, in order)

Run these **inside** the guardrail VM, from the checkout root. Nothing here
downloads, resolves a Hub id or contacts the generation endpoint: `--model-dir`
must already be an existing local directory. The model directory names below are
examples — substitute the paths the artifacts were actually copied to.

One note on the interpreter: `.venv\Scripts\python.exe` is the path in the
Windows checkout. On the Ubuntu VM the same environment is `.venv/bin/python`
and the path separator is `/`, so substitute those for the interpreter and the
script path; the arguments are identical.

```bash
mkdir -p reports
.venv\Scripts\python.exe scripts\bench_guard_models.py --plan

# 1/5 generative, input slot
.venv\Scripts\python.exe scripts\bench_guard_models.py --measure \
    --model-dir /models/qwen3guard-gen-0.6b --model qwen3guard-gen --slot input \
    --report reports/gen-input.json

# 2/5 generative, output slot
.venv\Scripts\python.exe scripts\bench_guard_models.py --measure \
    --model-dir /models/qwen3guard-gen-0.6b --model qwen3guard-gen --slot output \
    --report reports/gen-output.json

# 3/5 classification head, input slot
.venv\Scripts\python.exe scripts\bench_guard_models.py --measure \
    --model-dir /models/qwen3guard-stream-0.6b --model qwen3guard-stream --slot input \
    --report reports/stream-input.json

# 4/5 classification head, output slot
.venv\Scripts\python.exe scripts\bench_guard_models.py --measure \
    --model-dir /models/qwen3guard-stream-0.6b --model qwen3guard-stream --slot output \
    --report reports/stream-output.json

# 5/5 86M baseline, input slot only (it has no output slot)
.venv\Scripts\python.exe scripts\bench_guard_models.py --measure \
    --model-dir /models/llama-prompt-guard-2-86m --model promptguard2 --slot input \
    --report reports/promptguard2-input.json
```

Add `--artifact-sha256 <sha256>` to each `--measure` run after recording the
digest; it is optional and the report records `null` when it is omitted.

A run that exits 1 still wrote its report — that is the point of the error
counts — so a rerun needs a new `--report` path (or the old file moved aside);
the writer never overwrites an existing report.

**Cold-load repeat.** Run each command a second time, changing only the report
path (for example `--report reports/gen-input-cold.json`). Compare the two
`load_seconds` values: the first run after the artifact is copied is the
cold-page-cache number, and the repeat shows how much of the first load was disk
cache rather than parsing. Record both, and use the cold number for the
container readiness start period, saying which one it is. The report writer is
create-exclusive, so the repeat cannot overwrite the first file.

**Thread settings are not copied from this document.** On the 4 vCPU guardrail
VM `--plan` prints thread settings `4, 2` — the CPU count, then the cap — and
each `--measure` run repeats the whole grid at both. `thread_settings` is derived
from `os.cpu_count()`, so on any other machine the printed values differ: use
the plan's own output, not these examples.

Exit status 0 means every call produced a parseable verdict. A single
unparseable verdict or inference failure makes the run exit 1 **after** writing
the report, so a broken template or taxonomy shows up as an error count rather
than as a suspiciously fast p50. A missing directory, a failed load, an
unusable `--report` path or an unsupported artifact fails closed with exit 2
*before* the measurement starts; there is no default allow and no fallback
model.

## What the report contains, and what each field decides

Metadata only: environment (CPU count, RAM, python, torch, transformers
versions), per candidate and per bucket the character count, the
**conservative-unit** count, the resulting **window split count**, the prompt
token count split into `template_tokens` and `payload_tokens`, the call count,
p50/p95/p99, the peak RSS from `/proc/self/status` `VmHWM` after load and after
the run, and the parse-outcome counts (`parsed_allow`, `parsed_block`,
`parse_error`, `inference_error`, `over_window_calls`). No input text, prompt
text, model output, URL or credential can be written: the schema is a strict
allowlist and the tests reject any extra key.

`load_seconds` is the local-disk load time and sets the container's readiness
start period after an HA restart. It is measured once per process; the second
thread setting reuses the loaded model and records `null` rather than a
meaningless second load.

Conservative units are the gateway's UTF-8 byte bound
(`conservative_byte_budget`), **not** a tokenizer count. `window_split_count`
is `ceil(units / 512)`, the deterministic non-overlapping window model. The
report also records the real tokenizer `prompt_tokens`, because the byte bound
cannot distinguish Malay from English (both ASCII) while the tokenizer can.

Two unit columns are reported per bucket, and they answer different questions.
`conservative_units` / `window_split_count` are the product's input-budget view
of the **serialized conversation only** — the number the gateway policy already
holds. `template_units` / `prompt_units` / `prompt_window_split_count` describe
the **exact prompt string sent** to the model, which includes the fixed framing
and the artifact's own chat markers. `template_units` is `null` for
`promptguard2`, which sends no framing.

## Per-language, per-length cost accounting

Two kinds of number appear in this document and they must not be confused.
**Arithmetic** is deterministic: it follows from the synthetic filler, the
gateway's `conservative_byte_budget` and the script's constants, so it needs no
model and is already exact. **Measurement** is produced by the operator's run on
the VM, and **none of it exists yet**. The table below pre-fills only arithmetic
columns. Every latency cell is deliberately empty.

Input slot, one row per language and length (the serialized conversation is
`user: <filler>`):

| Lang | Characters | Serialized chars | Conservative units | Window splits | Prompt units (≥) | Prompt splits (≥) | p50 ms | p95 ms | p99 ms |
|---|---|---|---|---|---|---|---|---|---|
| en | 200 | 206 | 210 | 1 | 638 | 2 | | | |
| en | 500 | 506 | 510 | 1 | 938 | 2 | | | |
| en | 1000 | 1006 | 1010 | 2 | 1438 | 3 | | | |
| en | 2000 | 2006 | 2010 | 4 | 2438 | 5 | | | |
| bm | 200 | 206 | 210 | 1 | 638 | 2 | | | |
| bm | 500 | 506 | 510 | 1 | 938 | 2 | | | |
| bm | 1000 | 1006 | 1010 | 2 | 1438 | 3 | | | |
| bm | 2000 | 2006 | 2010 | 4 | 2438 | 5 | | | |
| zh | 200 | 206 | 610 | 2 | 1038 | 3 | | | |
| zh | 500 | 506 | 1510 | 3 | 1938 | 4 | | | |
| zh | 1000 | 1006 | 3010 | 6 | 3438 | 7 | | | |
| zh | 2000 | 2006 | 6010 | 12 | 6438 | 13 | | | |

How to read it:

- **Characters** is the synthetic payload length. **Serialized chars** adds the
  `user: ` role prefix that `serialize_messages` writes.
- **Conservative units** and **window splits** are exact arithmetic, and the
  unit formula is asserted against `nasi_lemak.generation.conservative_byte_budget`
  by the tests. They are a UTF-8 byte bound, not tokens.
- **Prompt units (≥)** is a labelled **lower bound**, not a measurement. The
  432-unit framing is prepended to every generative/head call, but the product
  formula's 4-unit framing allowance is counted once rather than twice, so the
  prompt is at least `units + 428`. The exact figure needs the artifact's chat
  template (its markers add more) and is written by the run as `prompt_units`;
  `prompt_window_split_count` is the split count of that exact value. For
  `promptguard2`, which sends no framing, `prompt_units` equals the
  conservative-unit column exactly and `template_units` is `null`.
- **p50/p95/p99 are blank on purpose.** They are measurements, they have not been
  taken, and no estimate is substituted. Fill one copy of this table per
  candidate, per slot and per thread setting from that report's `buckets`.
- English and Malay are **identical** under the byte bound because both are
  ASCII. The byte bound cannot rank them; only the measured `prompt_tokens` can.
  Chinese costs about 2.9× the units of English at 200 characters and about 3.0×
  at 2000, which is why it is the planning case.

The output slot classifies the same filler after a fixed 72-character PII-masked
context prefix (`user: My email is <EMAIL>. Please summarise the weekly plan.` /
`assistant: `). So the same payload costs more: at 200 characters it is 278
units (1 split) for `en`/`bm` and 678 units (2 splits) for `zh`; at 2000
characters it is 2,078 units (5 splits) for `en`/`bm` and 6,078 units (12 splits)
for `zh`. The same framing lower bound applies on top, and the full per-bucket
grid is in each output-slot report.

## Decision rules

Fill the table from the reports, then apply these rules in order. Do not
average away a failing bucket.

| Candidate | Slot | Load s | p50/p95/p99 @2000 ZH | Peak RSS | Parse errors | Threads |
|---|---|---|---|---|---|---|
| `qwen3guard-gen` | input | | | | | |
| `qwen3guard-gen` | output | | | | | |
| `qwen3guard-stream` | input | | | | | |
| `qwen3guard-stream` | output | | | | | |
| `promptguard2` | input | | | | | |

1. **Hard gates (any failure disqualifies the candidate for that slot).**
   Any `parse_error` or `inference_error` > 0; a load failure; peak RSS that
   does not leave the gateway and Presidio room inside 16 GiB; a p95 at the
   2000-character ZH bucket that exceeds the latency budget below.
2. **Input slot.** Prefer the candidate with the lowest p95 in the worst bucket
   (2000 ZH, 2 threads) among those that pass the gates, with English not worse
   than the 86M baseline by more than the budget allows. `qwen3guard-stream` is
   the intended winner when it passes; `qwen3guard-gen` is acceptable only if its
   p95 fits the budget, because it also provides the output slot from one loaded
   artifact; `promptguard2` remains the English-only floor and the cheapest
   option, and must not be described as multilingual.
3. **Output slot.** `qwen3guard-stream` or `qwen3guard-gen` only. If neither
   passes the gates, the on-premise output guard is **not adopted** and the
   deployed output guard stays where it is. `promptguard2` is never an output
   guard.
4. **Thread setting.** The deployment number is the 2-thread run, not the
   CPU-count run: the gateway needs headroom for Presidio and the request path.
   Report both, decide on the capped one.

## Latency budget for timeline item 8

The budget is mechanical once the report exists:

```
budget_ms = ceil(p95_ms(2000 ZH, 2 threads, chosen candidate, chosen slot) x 1.2)
```

rounded up to the next 50 ms, and recorded in item 8 as:

> Added guard latency p95 ≤ **`budget_ms`** ms per call at a 2000-character
> Chinese input on the 4 vCPU guardrail VM with 2 inference threads, measured on
> 28 October 2026; input and output slots are separate calls, so the per-request
> total is their sum.

Two anchors make the budget falsifiable rather than arbitrary:

- the existing chat work deadline is 60 s (`DEFAULT_CHAT_WORK_TIMEOUT`); a guard
  step that consumes more than a quarter of it (15 s) fails gate 1 outright;
- the current input path already spends one classifier call per request, so the
  budget is **added** latency for the guard step, not total request latency.

If the measured p95 already exceeds 15 s, the honest entry for item 8 is "not
budgeted: local CPU guard does not fit the chat deadline", not a rounded number.

## Long-input decision (one call or deterministic windows)

This benchmark must settle it, and the report settles it with the
`window_split_count` and latency columns:

- **One call.** `qwen3guard-gen` and `qwen3guard-stream` accept 32768 context,
  so the whole serialized conversation fits for every measured length and for
  CTRL-007 (1439 characters, 1449 conservative units). If the 2000-character ZH
  p95 fits the budget, the decision is **one call per slot**, with an explicit
  conservative-unit ceiling below 32768 tokens and a fail-closed rejection above
  it. Consequences: CTRL-007 becomes screenable; the harness's single-call
  `INPUT_WINDOW` model becomes accurate; the dataset's 1024-character
  per-message bound no longer needs to be the screening bound.
- **Deterministic overlapping windows.** If one call at 2000 characters is too
  slow, the decision is windows of at most 480 conservative units with a 64-byte
  overlap, the model the product already uses for the Groq input path. Then the
  per-request cost is `window_split_count` classifier calls, **each paying the
  432-unit fixed framing again** (see the framing arithmetic below), CTRL-007 is
  screenable only as a windowed fixture, and both the harness's `INPUT_WINDOW`
  model and the 1024-character per-message bound must be revisited in a reviewed
  change.
- **Neither.** If both fail the budget, the local input guard is not adopted and
  item 8 records that outcome instead of a number.

Whichever branch wins, it must be written down as the contract; an implicit
"one call, truncated" or "block over the window" behaviour is not acceptable.

## Is the fixed guard template the dominant cost?

The template — the safety taxonomy and framing sent on every call — is paid on
every request regardless of the user's text. The report answers this directly
with `template_tokens` versus `payload_tokens`:

- if `template_tokens / prompt_tokens` is still above 50% at 2000 characters,
  the template dominates: per-request cost is roughly constant and the window
  split count matters more than the input length;
- if it falls below 25% at 2000 characters while being above 50% at 200, the
  input dominates: longer prompts get proportionally slower and the 2000-char
  bucket is the planning case;
- anything between the two is a mixed cost and both numbers must be quoted.

### The framing's own unit cost is arithmetic, not a measurement

What is already known without a model is the size of the fixed floor. The
versioned framing (`nasi-lemak-guard-framing-v1`: the taxonomy plus the
three-line verdict shape) is **416 characters / 432 conservative units**, which
is **84.4 % of one 512-unit window**, and it is paid on **every** call
regardless of the user's text. This is arithmetic over the script's own
constant — `--plan` prints it — not a timing.

That floor has a second consequence, and it matters more than any single call.
If the design screens a long input in deterministic overlapping windows, the
framing is **repeated inside every window**:

- at Chinese, 2000 characters, the payload alone already needs 12 windows
  (6,010 units); once the framing is included the bound is 13 windows
  (6,438 units, the lower-bound column above);
- 12 windows × 432 units = **5,184 units of pure template overhead** against
  6,010 units of payload — 5,616 if the 13-window bound is the one used;
- the same 2000 characters in English is 4 payload windows (2,010 units), so the
  windowed template overhead there is 4 × 432 = 1,728 units.

The design implication is plain: **a windowed design multiplies the dominant
fixed cost.** For non-English traffic the two levers that matter most are
whether long inputs are windowed at all, and how long the fixed taxonomy is —
not the per-call model choice alone. A shorter taxonomy would cut every window
of every request; a one-call design pays the framing once.

What this does **not** say: units are a UTF-8 byte bound, so these figures are a
**unit-bound view only**. The actual token cost of the framing, and therefore
whether the template or the payload dominates latency, is unmeasured; the run's
`template_tokens` and `payload_tokens` settle it by the rule above.

**No answer is claimed here**, because the token ratio is a measurement. The
framing is deliberately versioned (`nasi-lemak-guard-framing-v1`) so a template
change is a new measured workload, not a silent regression.

## Design consequences that are already decided

**Input guard contract change.** Adopting Qwen3Guard on the input side replaces
the numeric `malicious_probability` + `[0, 1]` threshold contract
(`nasi-lemak-input-classifier-v1`) with a categorical `Safety` verdict plus
`Categories`. The threshold then means something different: it is no longer a
calibrated probability cut but a policy choice over three labels (for example
"Unsafe blocks, Controversial blocks, Safe allows"). Every corpus input row's
expectation has to be restated in those terms, and the 0.5 default stops being
meaningful. The frozen corpus and `MANIFEST.sha256` are **not** edited by this
work; the restatement is a separate reviewed revision.

**Output-guard capability gap.** The deployed output guard is Llama Guard 3 8B
via Cloudflare. The product's local Llama Guard 3 is the 1B variant, and these
candidates are smaller again (0.6B generative or head, 86M for Prompt Guard 2).
Moving the output guard on-premise can therefore **weaken** it. The benchmark
measures latency, memory and template parseability only; it does not measure
detection quality, so it cannot show that a smaller local model is as good. A
decision to move the output slot on-premise requires a separate, labelled
quality comparison against the deployed 8B model.

## Honest limits

- **One machine, one CPU configuration.** 4 vCPU / 16 GiB, no GPU, no other
  tenant. Numbers do not transfer to a different VM size.
- **Synthetic inputs only.** Innocuous filler of a fixed length, not corpus
  payloads and not real data. The benchmark measures cost, not detection.
- **One threshold** (0.5 for Prompt Guard 2) and one taxonomy version. No
  calibration and no sweep.
- **No load test, no concurrency claim.** Calls are sequential in one process.
  Nothing here supports a throughput, queueing or multi-tenant statement.
- **20 samples per bucket.** With nearest-rank percentiles, p99 over 20 samples
  is the maximum observation: quote p50/p95, treat p99 as "worst of 20", not as
  a stable tail estimate.
- **The stream candidate is measured as a head over the last token.** The real
  streaming use classifies incrementally; the benchmark records the single
  forward pass cost, which is the right order of magnitude but not a
  token-by-token streaming latency claim.
- **`qwen3guard-stream` may not load at all under the mandated discipline.**
  Its published artifact may expect `trust_remote_code=True`. This benchmark
  requires `trust_remote_code=False` (the `guards.py` discipline), so such an
  artifact fails closed with **exit 2** instead of loading. That is a hard
  finding rather than a missing data point: the candidate cannot be deployed
  in-process under the product's loader, and the input-slot decision falls
  through to the generative candidate. The operator should expect that exit code
  and record it; it is not a broken command.
- **Load seconds are warm-cache after the first run.** The first `--measure` on
  a freshly copied artifact is the cold-page-cache number; the documented repeat
  shows the warm-cache floor. Record both before fixing the readiness start
  period.
- **The framing is this product's template.** If the deployed API adapter lets
  the served model apply its own instruction template, the measured
  `template_tokens` may under- or over-state the deployed prompt. The version
  string is the guard against comparing unlike prompts.

## What the numbers will NOT establish

They will not establish guard accuracy, precision, recall, multilingual
detection quality, adversarial robustness, availability, throughput, memory
safety under concurrency, or that a smaller local model can replace the deployed
Llama Guard 3 8B. They establish one thing: how long one local CPU guard call
takes, how much memory the artifact needs, and whether its verdict parses.
