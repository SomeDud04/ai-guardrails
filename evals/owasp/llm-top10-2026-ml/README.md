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
| `translations.json` (authored here) | rows the guard lanes never covered |

Reused text is taken verbatim, so a case reads the same in the guard-lane
datasets and here.

## Build and check

```text
.\.venv\Scripts\python.exe scripts\build_owasp_ml_corpus.py
.\.venv\Scripts\python.exe scripts\build_owasp_ml_corpus.py --check
.\.venv\Scripts\python.exe -m unittest tests.test_owasp_ml_corpus -v
```

## Current coverage (step 2)

170 rows, 85 per language: CTRL 18, LLM01 19, LLM02 14, LLM03 4, LLM04 2,
LLM06 1, LLM07 9, LLM08 14, LLM10 4. 78 are reused from the guard lanes and 92
are authored in `translations.json`.

Authoring rules: identifiers, markup and code payloads, URLs and the English
deny phrase are kept verbatim (tests enforce this outside LLM01, whose reused
attacks re-encode their payload in the target language). Chinese places an
identifier directly after Chinese text where the sentence allows it
(`我的合成联系邮箱是alice@example.com。`), as people write it. The Malay
LLM08-009 asks for a translation into English, since the English row already
asks for Malay.

## Token-budget pair (LLM06-011 and CTRL-007)

The gateway refuses with 413 when either of two limits is exceeded: a byte
budget (`context_budget`, conservative UTF-8 units) checked first, then the
policy `token_budget` counted with the Qwen3Guard tokenizer (1024 on the pilot
VM since 3 Nov). Sizes measured on 5 Nov with the Qwen3Guard-Gen-0.6B
`tokenizer.json`, on the serialized `role: content` text:

| Row | Tokens | Byte units | Characters |
|---|---|---|---|
| LLM06-011 (English) | 842 | 3,509 | 3,505 |
| BM-LLM06-011 | 1,262 | 3,579 | 3,575 |
| ZH-LLM06-011 | 1,802 | 3,549 | 1,505 |
| CTRL-007 (English) | 302 | 1,449 | 1,445 |
| BM-CTRL-007 | 422 | 1,359 | 1,355 |
| ZH-CTRL-007 | 333 | 1,450 | 486 |

The English LLM06-011 is under a 1024-token budget (it was written for 512),
so its 413 on the VM must come from the byte budget. The mirrors exceed both
limits, and the CTRL-007 mirrors stay under both, so each mirror expects what
its English row expects whichever limit applies. If the VM's byte budget is
above about 3,600 units, English LLM06-011 answers while the mirrors are
refused, which would show the token budget acting on its own.
`test_token_budget_pair_sizes` guards the byte side; token counts need the
tokenizer and are recorded here only.

## Left English-only on purpose

Language cannot change these outcomes, or the surface is absent:
LLM01-019 (oversize body), LLM02-014 and LLM02-016 (`$fixture_reply`),
LLM03-002..005 and LLM04-002..006 (request-field rejections), LLM06 except 011
(field and body limits), LLM05 and LLM09 (no surface, not applicable), LLM10
rows other than 001/004/012/013 (same known gap, wrapper text only).
