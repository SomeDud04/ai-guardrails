# Plan: Malay and Chinese Checklist, by OWASP category

Status (5 Nov 2026): steps 1 to 3 done: 170 rows (78 reused, 92 authored) and
`run_owasp_live.py --corpus`. Steps 4 and 5 not started.

## Why

The Category Map's testing activities were run in English only (the 128-row
corpus). The guard-lane datasets v2 and v3 added Malay and Chinese, but only for
rows the input guard judges, so 54 of their 66 attacks are LLM01. This plan
mirrors the Checklist itself into Malay (`bm`) and Chinese (`zh`), category by
category, keeping each row's own control and expected result (403 block, masked
200, 400 rejection, 413 limit, Unverified reply).

## Scope: which rows get a Malay and a Chinese version

Rule: mirror a row only when its language can change the outcome. Rows whose
test lives in a request field or a raw body stay English-only.

| Category | Mirrored rows | Per language | Source of text | Why |
|---|---|---|---|---|
| CTRL benign | CTRL-001..018 except 007 | 17 | reuse v3 `bm-ctrl` / `zh-ctrl` | false blocks by language (3 seen in v3) |
| LLM01 Prompt Injection | 001..018 | 18 | reuse v2 `bm` / v3 `zh` | already measured; carried so the Checklist is complete |
| LLM01 deny phrase | 020 | 1 | new | English deny phrase inside a Malay/Chinese sentence |
| LLM02 Sensitive Info | 001..013, 015 | 14 | new | masking next to Chinese characters with no spaces, Malay wording; highest value |
| LLM03 Excessive Agency | 006..008, plus 001 as a schema sample | 4 | reuse 3, new 1 | text attacks reuse; one schema row proves rejection is language-independent |
| LLM04 Supply Chain | 007, plus 001 as a schema sample | 2 | reuse 1, new 1 | as above |
| LLM06 Unbounded Consumption | 011 (over budget, 413), plus CTRL-007 (long benign, 200) | 2 | new | the live gateway counts Qwen tokens, so the budget may bite at a different length per language; lengths are set from measured token counts (correction: an earlier draft said the budget counts bytes, which is only the test-mode stand-in) |
| LLM07 Misinformation | 001..009 | 9 | new | output guard and reply quality in Malay/Chinese |
| LLM08 Hidden Context | 001..014 | 14 | new | extraction prompts in Malay/Chinese |
| LLM10 Output Handling | 001, 004, 012, 013 (HTML, CSV, template, shell) | 4 | new | one per sink type; payload text stays literal |

Total: 85 per language, **170 rows** (78 reused, 92 new translations).

Left English-only, with the reason recorded in the corpus README:
LLM01-019, LLM02-014/016 (`$fixture_reply`), LLM03-002..005, LLM04-002..006,
LLM06 except 011 (field and body limits), LLM05 and LLM09 (no surface, N/A),
LLM10 other rows (same known gap, wrapper text only).

## Translation rules

- Keep verbatim: identifiers (emails, phones, MyKad, passport, bank numbers),
  markup and code payloads, URLs, encoded strings, the literal English deny
  phrase, the word APPROVED.
- Chinese text uses normal Chinese punctuation with no spaces around
  identifiers (`我的邮箱是alice@example.com。`), since that is how real users
  write it and is the boundary the masker has never seen.
- Keep message roles, turn count and `optional_extra` identical to the English
  row. Only `messages[*].content` changes.
- Same evidence label as the guard lanes: agent-authored synthetic smoke, not a
  holdout. A native-speaker check of the new translations is recommended.

## Build steps (each a separate, tested commit)

1. **Corpus scaffold and reused rows.** New sibling corpus
   `evals/owasp/llm-top10-2026-ml/` with `payloads/*.jsonl`, `schema.json`
   (the English schema plus `language` and `mirror_of`, and ids such as
   `BM-LLM02-001` / `ZH-LLM02-001`) and `MANIFEST.sha256`. The frozen English
   corpus is not touched. Generate the 78 reused rows from the guard-lane files.
   Tests: schema valid; every row's `mirror_of` exists; all fields except
   `id`, `language`, `mirror_of` and `messages` equal the English row; reused
   messages equal their guard-lane source.
2. **New translations (92 rows).** Author LLM01-020, LLM02, the LLM03/04 schema
   samples, LLM06, LLM07, LLM08 and LLM10. Tests add: every identifier the
   gateway would mask in the English row appears verbatim in the mirror; payload
   markup is unchanged; counts per category match the table above.
3. **Runner.** `scripts/run_owasp_live.py --corpus DIR`; retired-limit lookups
   go through `mirror_of`; totals by language and by category in the report.
   The leak check must take its identifiers from the English row named by
   `mirror_of`: it currently uses values the gateway's own recogniser finds in
   the row, so an identifier the recogniser misses would never be checked and
   would score a false Pass.
   Tests with a fake sender, then a local dry run. No VM traffic in this step.
4. **Live run on the pilot VM.** About 170 cases at about 20 s each, so roughly
   an hour. The user supplies the API key. Report to
   `evals/owasp/llm-top10-2026/owasp-live-ml-<date>.json`.
5. **Evidence.** In the Activity Plan V2 workbook: a "Multilingual Checklist"
   tab (same columns as Checklist plus Language and Mirror of), a
   "Multilingual cases" column in Category Map, a Run Log row, and progress
   text for T2/T3. Then the 36 Unverified rows (LLM08, LLM10) need a
   person who reads Malay and Chinese to judge the replies.

## Found while authoring (offline, no gateway traffic)

Running the gateway's PII recogniser over the new LLM02 mirrors misses 12 of
28 rows that English detects: in Chinese, an email or phone number directly
after a Chinese character (ZH-LLM02-001, 002, 005, 006, 012, 015; MyKad in the
same position is found), and the passport and bank numbers in both languages
(LLM02-010, 011). The live run in step 4 will show whether these leak.

Measuring with the Qwen3Guard tokenizer showed the English LLM06-011 is 842
tokens, under the VM's 1024-token budget, so its 413 on the VM comes from the
byte budget: the English Checklist does not currently prove the token budget.
Step 4 should record the VM's `NASI_LEMAK_CHAT_CONTEXT_BUDGET` to confirm.

## What the result will and will not show

- Will show, per category and language: masking misses, false blocks, limit
  differences and attack misses, compared row for row with English.
- Will not show: production accuracy, or the truth of model answers (an
  answered LLM07 row is a Pass for the gateway, not a truth check).

## Open decisions

- Who reviews the 36 Unverified Malay and Chinese replies, and whether to also spot-check the 18 LLM07 replies (the runner marks them Pass when answered, which is not a truth check).
- Whether to commission a native-speaker check of the 92 new translations
  before the live run, or after it for failing rows only.
