# OWASP LLM Top 10 (2026) corpus: Malay and Chinese mirror

Malay (`bm`) and Simplified Chinese (`zh`) versions of rows in the frozen
English corpus at `../llm-top10-2026`. A mirror row tests the same control and
expects the same result as its English row, so the outcome can be compared row
for row by language. Plan: `docs/plans/2026-11-05-multilingual-checklist.md`.

Evidence label: agent-authored synthetic smoke, not a holdout. No row
establishes classifier quality or production behaviour.

## Row contract

- `id` is the language code plus the English id (`BM-LLM01-002`,
  `ZH-CTRL-017`); `mirror_of` names the English row; `language` is `bm` or `zh`.
- Every other field equals the English row except the message text. Message
  roles and turn count are unchanged.
- Payload rows are generated. Do not edit `payloads/*.jsonl`, `schema.json` or
  `MANIFEST.sha256` by hand; edit the sources and run the builder.

## Sources of message text

| Source | Rows |
|---|---|
| Guard lane v2 Malay (`evals/guards/owasp-llm-top10-2026-v2-bm.json`) | the 22 attack rows: LLM01-001..018, LLM03-006..008, LLM04-007 |
| Guard lane v3 Malay controls (`owasp-llm-top10-2026-v3-bm-ctrl.json`) | the 17 controls CTRL-001..018 except CTRL-007 |
| Guard lane v3 Chinese (`owasp-llm-top10-2026-v3-zh.json`) | the same 39 rows in Chinese |
| `translations.json` (authored here) | rows the guard lanes never covered; empty until step 2 of the plan |

Reused text is taken verbatim, so a case reads the same in the guard-lane
datasets and here.

## Build and check

```text
.\.venv\Scripts\python.exe scripts\build_owasp_ml_corpus.py
.\.venv\Scripts\python.exe scripts\build_owasp_ml_corpus.py --check
.\.venv\Scripts\python.exe -m unittest tests.test_owasp_ml_corpus -v
```

## Current coverage (step 1)

78 rows: 39 per language (17 CTRL, 18 LLM01, 3 LLM03, 1 LLM04). Step 2 adds the
authored rows for LLM01-020, LLM02, LLM03/04 schema samples, LLM06, LLM07,
LLM08 and LLM10.

## Left English-only on purpose

Language cannot change these outcomes, or the surface is absent:
LLM01-019 (oversize body), LLM02-014 and LLM02-016 (`$fixture_reply`),
LLM03-002..005 and LLM04-002..006 (request-field rejections), LLM06 except 011
(field and body limits), LLM05 and LLM09 (no surface, not applicable), LLM10
rows other than 001/004/012/013 (same known gap, wrapper text only), and
CTRL-007 (harness-bound long input).
