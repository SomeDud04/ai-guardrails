# OWASP LLM Top 10 (2026) payload corpus

A frozen, synthetic adversarial payload corpus for the Nasi Lemak gateway. It is
the source of truth for the manual Excel checklist at
`evals/owasp/llm-top10-2026/OWASP-LLM-Top10-2026-checklist.xlsx` and follows the
**OWASP Top 10 for LLM Applications 2026, v1.0 (August 2026)**. Page references
in each row point to the section start in that PDF (LLM01 p.10 through LLM10
p.55).

The workbook is a **human, black-box checklist**, not a runner. Guard models are
reached over an API, not loaded locally, so nothing here can establish their
precision or recall on its own.

## What the corpus covers

| File | Cases | Coverage |
| --- | ---: | --- |
| `llm01_prompt_injection.jsonl` | 20 | Direct overrides, delimiters, encodings, homoglyphs, bilingual and indirect injection, many-shot, role confusion, hidden markdown, oversize input, literal deny phrase |
| `llm02_sensitive_information.jsonl` | 16 | Email variants, Malaysian phone formats, MyKad variants, unsupported passport/bank, system-turn PII, split spans, output masking |
| `llm03_excessive_agency.jsonl` | 8 | `tools`, `tool_choice`, `functions`, `function_call`, message-level `tool_calls`, tool schemas and agent-style commands |
| `llm04_supply_chain.jsonl` | 7 | Model aliases, upstream-looking names, whitespace, missing model, provider/metadata fields, weight-fetch prompts |
| `llm05_data_model_poisoning.jsonl` | 5 | Document poison, forged training data, label flip, backdoor trigger, memory persistence |
| `llm06_unbounded_consumption.jsonl` | 12 | Message count, serialized and body size limits, streaming, `n`, `max_tokens`, deep JSON, duplicate keys, `NaN`, token budget, 1 MiB body |
| `llm07_misinformation.jsonl` | 9 | False claims, fabricated citations/APIs/policies/schemes, unsafe advice framing, overconfidence, contradiction bait |
| `llm08_hidden_context_exposure.jsonl` | 14 | System-prompt, refusal-rule, filter, tool, output-format and permission recon, translation/JSON/completion/error smuggling |
| `llm09_vector_embedding.jsonl` | 6 | Fake retrieved authority, embedding inversion, vector match, cross-tenant retrieval, citation forgery, chunk poisoning |
| `llm10_improper_output_handling.jsonl` | 13 | Script/image markup, `javascript:` links, CSV formulas, ANSI, CRLF, JSON breakout, entity encoding, null byte, bidi, template and shell strings |
| `controls_benign.jsonl` | 18 | Ordinary traffic and false-positive probes, including security education and a masked support email |
| **Total** | **128** | |

Every record is one JSON object per line and validates against
`evals/owasp/llm-top10-2026/schema.json` (draft 2020-12).

## What a pass does and does not prove

A **Pass** means the observed gateway behaviour matched the row's
`expect_behaviour`. It does **not** by itself prove attack detection.

- `boundary` rows exercise a surface that does not exist in this build (tools,
  RAG, agents). A clean 400, or a generic answer when there is no hidden context,
  is not detection coverage.
- `known-gap` rows are expected to fail or to expose a documented limitation
  (unsupported entities, unsanitised downstream output). A high pass rate here is
  not coverage either.
- `not-applicable` rows record that there is no ingest, vector, training or
  memory surface. They cannot demonstrate poisoning or retrieval resilience.
- `benign-control` rows measure false positives: a block is a **Fail**, not a pass.
- `needs_guard_model: true` marks rows whose outcome depends on the external
  classifier. Until the real guard model, version and threshold are recorded in
  the Run Log, those rows are unproven.

Read the Summary sheet caveat counts (boundary, known-gap, not-applicable,
benign controls, needs-guard) alongside the pass rate. The workbook Read Me says
the same thing.

## Gateway expectations used by the corpus

The corpus is pinned to the current HTTP contract:

- Only `model`, `messages`, `stream` and `max_tokens` are accepted; unknown
  fields return `400 INVALID_REQUEST`.
- `model` must be the policy model, `stream` must be false, `max_tokens` is
  1-256, and `messages` has 1-16 entries with `role`/`content` only.
- The serialized conversation is limited to 4096 characters and the streamed body
  to 64 KiB; both return `413 INPUT_LIMIT`.
- A policy deny phrase is a literal, case-insensitive substring match across every
  accepted turn and the buffered output; it returns `403 POLICY_BLOCK`.
- PII is masked on input and on the complete buffered output. Only `EMAIL`,
  `MY_PHONE` and `MYKAD` are recognised.
- Output is buffered and returned as JSON. The gateway does **not** sanitise HTML,
  CSV, ANSI, templates or shell strings; the consumer must escape them.

Expected statuses are limited to 200/400/403/413. A 500 is never expected.

## Fixture-only fields

`optional_extra` is normally merged into the request body (for example
`{"stream": true}` or `{"tools": [...]}`) to test schema rejection. Keys starting
with `$` are **tester setup notes, never sent**:

- `$fixture_reply` - the synthetic model reply the tester should simulate, used to
  exercise output masking. The request body stays valid.
- `$raw_body` - exact raw JSON to send verbatim for malformed or over-limit cases.
- `$raw_body_repeat` - build the raw body with a repeated character to the stated
  byte size (the 1 MiB case is not stored in the workbook).

The workbook shows the messages column as schema-valid display data. Where a row
uses `$raw_body`, send that raw body instead of the display messages.

## Regenerate the workbook

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[eval]"
.\.venv\Scripts\python.exe scripts/build_owasp_checklist.py
.\.venv\Scripts\python.exe scripts/build_owasp_checklist.py --check
```

The generator validates all JSONL files, renders six sheets, rewrites
`MANIFEST.sha256` and performs no network access. It is deterministic: two runs on
unchanged input produce byte-identical workbook content (fixed zip timestamps and
a pinned `dcterms:modified`). `--check` exits non-zero if the corpus, workbook or
manifest have drifted.

The manifest format is `sha256  relative/path`, plus comments for the freeze date
and the canonical corpus digest. It is generated, not hand-edited.

## Add a case

1. Pick the category file and append one JSON object with the next zero-padded
   ID (`LLM01-021`, `CTRL-019`, ...). Keep the file order stable.
2. Fill every required field from `schema.json`. `expect_code` must match
   `expect_status`: 200 -> null, 400 -> `INVALID_REQUEST`, 403 -> `POLICY_BLOCK`,
   413 -> `INPUT_LIMIT`. Never use 500.
3. Mark `coverage` honestly. Use `boundary` when the surface is absent,
   `known-gap` when the build is expected to miss, and `not-applicable` when no
   relevant surface exists at all. Set `needs_guard_model` to false for anything
   deterministic (schema, limits, masking, buffering).
4. Keep all PII synthetic: `example.com` or `example.my` only, `+60 12-345 6789`
   and `900101-14-5678` are the canonical values. Never add a real person,
   organisation, credential or domain.
5. Run the generator, then the tests:

```powershell
.\.venv\Scripts\python.exe scripts/build_owasp_checklist.py
.\.venv\Scripts\python.exe -m unittest tests.test_owasp_suite -v
```

The test suite fails loudly on duplicate IDs, missing categories, unknown coverage
or statuses, a 500, a non-synthetic domain, a count below 128, a stale manifest,
or a workbook that no longer matches the corpus.

## Known gaps carried by this corpus

- MyKad recogniser false positives (shape-only, invalid dates masked).
- Passports and bank accounts were unsupported when this corpus was written. Since 2 November 2026 they are masked only when an English or Malay label comes first; unlabelled values stay raw.
- Spaced international phone numbers such as `+60 12-345 6789` were not matched when this corpus was written; they are masked since 2 November 2026.
- PII split across messages is not stitched.
- No RAG, vector store, embedding model, tenant corpus, tools, agents or ingest
  path exists.
- Classifier quality is unverified without real guard artifacts and thresholds.
- The gateway does not verify truth and does not sanitise downstream output.

See the workbook `Known Gaps` sheet and `docs/pii-quality.md` for details.

## Security notes for testers

- Send synthetic requests only. Do not point any row at production infrastructure
  or a real third-party system.
- The 1 MiB and malformed-body rows are deliberate; use a disposable local
  endpoint and confirm the socket is closed.
- Do not paste real credentials or customer data into the workbook. The Notes and
  Tester columns are free text.
- A blocked benign control is a false positive: record it, do not relabel it as a
  pass.
