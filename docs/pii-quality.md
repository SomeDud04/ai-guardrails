# PII quality: frozen synthetic evaluation (tasks 13/14)

Status: local, offline engineering evidence only. The evaluation corpus is
**agent-authored synthetic data**. It is not an independently labelled human
hold-out set, a population estimate, a privacy audit or customer acceptance.

Caller review found a real privacy gap: an address followed by a sentence
period (`Contact a@example.invalid.`) stayed unmasked. A narrow, reviewed repair
to the EMAIL right boundary now accepts a terminal sentence period without
consuming it; the six known caller-review regression cases pass. This is a
regression repair, not an accuracy claim. The original v1 fixtures, labels,
thresholds and scope are unchanged.

Caller-agent label adjudication then created a separate reviewed corpus, v2,
that corrects exactly one disclosed v1 annotation error: `EV-EMAIL-014`
(`negative_trailing_dot`) had labelled a sentence-final address as non-PII,
encoding the old recognizer miss as a negative. The v2 gold treats
`nama@example.invalid` as one EMAIL span and excludes the period. The v1 raw
score (EMAIL 16 TP / 1 FP / 0 FN) remains available but is
**annotation-conflicted** and cannot be presented as a reliable current EMAIL
quality score. V2 scores EMAIL 17 TP / 0 FP / 0 FN, but MyKad still fails the
0.95 precision gate with four false positives, so the v2 CLI still exits `1`.
V2 is reviewed regression evidence, **not an unseen or independent hold-out
set**. The six-case caller-review corpus is likewise known-regression evidence
only.

## What was frozen

Fixtures live under [`evals/pii/`](../evals/pii/):

| File | Purpose | Cases |
|---|---|---:|
| [`development.json`](../evals/pii/development.json) | Distinct agent-authored examples for labelling/reproduction | 16 |
| [`evaluation.json`](../evals/pii/evaluation.json) | Frozen v1 scoring split (preserved, annotation-conflicted EMAIL label) | 61 |
| [`manifest.json`](../evals/pii/manifest.json) | SHA256 freeze for both v1 fixture files | — |
| [`reviewed-labels-v2/evaluation.json`](../evals/pii/reviewed-labels-v2/evaluation.json) | Reviewed regression corpus: v1 copy with only `EV-EMAIL-014` gold adjudicated | 61 |
| [`reviewed-labels-v2/manifest.json`](../evals/pii/reviewed-labels-v2/manifest.json) | SHA256 freeze for the v2 corpus | — |
| [`reviewed-labels-v2/label-adjudication.md`](../evals/pii/reviewed-labels-v2/label-adjudication.md) | Original/corrected gold, reason and agent provenance | — |
| [`caller-review-v1/evaluation.json`](../evals/pii/caller-review-v1/evaluation.json) | Separate caller-review edge evidence, explicitly annotated | 6 |
| [`caller-review-v1/manifest.json`](../evals/pii/caller-review-v1/manifest.json) | SHA256 freeze for the review corpus | — |

The evaluation split has 58 in-scope cases and 3 explicitly unsupported cases.
It contains 48 gold entities and no customer identifiers. Email addresses use
only `example.invalid` or `test.invalid` domains. Gold spans are explicit
`type`/`start`/`end`/`text` annotations validated against the fixture text; they
were not produced by the production regexes. Duplicate IDs/text across splits,
duplicate gold spans and overlapping gold spans are rejected by the evaluator.

The evaluation split includes BM and Chinese surrounding text, separated and
compact formats, punctuation boundaries, multiple entities, near-match length
and word-boundary cases, phone values one digit too short/long, malformed email
and TLD near-matches, and 12-digit order/SKU-like values. Full-width, obfuscated
and space-separated forms are marked `unsupported` and excluded from metrics;
they are not claimed as protected.

Frozen SHA256:

- evaluation corpus: `fa644f708df31e182a1e64ff1f9eb891dc3d99800c10ff81cea026e73ea55381`
- development corpus: `d950e445326fb94058847bd5b373947091ce57897035c979953ec580bf04c6b7`
- manifest: `309f65fbb979cc703a11b668322441c2a803786c9c9bedfcdb41fd6bcf6cf982`
- caller-review corpus: `6ec81452e320ac03517eed894f1cd416f73f54736335c04eca49153465aa7e14`
- caller-review manifest: `f5d24ecbb20fe60948f585b973f25c1428bd3b2f45dec87cec911dfa9bcc07ab`
- reviewed v2 corpus: `aa4879f2c7a678781498f514bdfd9d38213c15b6eb11c559f3df3824b5b7b4db`
- reviewed v2 manifest: `17820ffedcb531dcb4a5ebf25f6fb3f39252af4408726c179f2282df8802512b`

These frozen bytes were preserved. The caller-review and v2 manifests were
written before their corpora were first scored. Neither reviewed corpus is merged
into the v1 split, not counted as a retroactive hold-out pass and not used to
relabel or tune anything except the single disclosed v1 `EV-EMAIL-014` annotation.

The pre-fix failure evidence is also preserved as prefixed copies, never by
overwriting the frozen fixtures or current reports:

- [`evals/pii/caller-review-v1/results/before-email-fix-evaluation-report.json`](../evals/pii/caller-review-v1/results/before-email-fix-evaluation-report.json)
  and `before-email-fix-evaluation-summary.md` (copied from the caller baseline)
- [`evals/pii/results/before-email-fix-evaluation-report.json`](../evals/pii/results/before-email-fix-evaluation-report.json)
  and `before-email-fix-evaluation-summary.md` (pre-fix v1 copy)

The copied pre-fix caller-review report still records the original EMAIL false
negative (TP 0, FN 1, overall fail); tests assert that preserved artifact and the
current repaired TP separately. Fixture bytes did not change: the v1 manifest
remains `309f65fbb979cc703a11b668322441c2a803786c9c9bedfcdb41fd6bcf6cf982`
and the caller-review manifest remains
`f5d24ecbb20fe60948f585b973f25c1428bd3b2f45dec87cec911dfa9bcc07ab`.

## Deterministic evaluator

[`nasi_lemak/pii_eval.py`](../nasi_lemak/pii_eval.py) is a small offline CLI. It
loads only a corpus whose bytes match the frozen manifest, runs the actual
production recognizers through the shared
[`nasi_lemak/pii.py`](../nasi_lemak/pii.py) span function, and applies the same
masking path used by `mask_pii` in the gateway. There is no network access,
classifier stub, customer data or production clone.

Matching is strict and one-to-one: an entity type and both offsets must match
exactly. A wrong offset, wrong type or extra prediction is a false positive and
false negative; it is never rounded into a success. Precision is `null` only
when there are no predictions, recall only when there is no gold, and F1 is
computed directly from counts as `2*TP/(2*TP+FP+FN)`. F1 is `null` only when
that denominator is zero; a case with FP and FN but no TP therefore reports
`precision=0.0`, `recall=0.0` and `f1=0.0`, not a missing value.

The evaluator rejects malformed fixtures, manifest mismatches and
invalid/duplicate/overlapping spans. It also bounds fixture/manifest files at
2 MiB (read with a limit-plus-one read), cases at 5000, each text at 16384
characters and each case's gold list at 256 spans before scoring. JSON decode
or nesting `RecursionError` is reported as a generic fixture error. These are
malformed-input bounds, not a schema expansion or a scoring change.

Run it from the workspace virtualenv:

```powershell
.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --split evaluation
.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --root evals/pii/reviewed-labels-v2
.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --root evals/pii/caller-review-v1
```

The frozen v1 evaluation exits `1` with a MyKad gate failure and an
annotation-conflicted EMAIL false positive. The reviewed v2 root also exits `1`,
solely because MyKad still has four false positives; its EMAIL result is clean
under the corrected label. The six-case caller-review root exits `0` after the
narrow repair. A clean fixture/manifest error exits `2`. Reports are written
without wall-clock fields, so repeated runs are byte-reproducible; the current
reports embed runtime SHA256 values after the repair:

- [`evals/pii/results/evaluation-report.json`](../evals/pii/results/evaluation-report.json)
- [`evals/pii/results/evaluation-summary.md`](../evals/pii/results/evaluation-summary.md)
- [`evals/pii/reviewed-labels-v2/results/evaluation-report.json`](../evals/pii/reviewed-labels-v2/results/evaluation-report.json)
- [`evals/pii/reviewed-labels-v2/results/evaluation-summary.md`](../evals/pii/reviewed-labels-v2/results/evaluation-summary.md)
- [`evals/pii/caller-review-v1/results/evaluation-report.json`](../evals/pii/caller-review-v1/results/evaluation-report.json)
- [`evals/pii/caller-review-v1/results/evaluation-summary.md`](../evals/pii/caller-review-v1/results/evaluation-summary.md)

Default reports and terminal output contain case IDs, labels, entity types,
offsets and hashes, never raw fixture text.

## Results: v1 annotation conflict and corrected v2

The frozen v1 split is preserved byte-for-byte. Its raw current score is EMAIL
16 TP / 1 FP / 0 FN, MY_PHONE 17 TP, MYKAD 15 TP / 4 FP / 0 FN. The EMAIL FP is
`EV-EMAIL-014`, whose v1 gold is `[]` for an address followed by a sentence
period. That gold is a disclosed annotation defect, so the v1 EMAIL score is
**annotation-conflicted** and is not a reliable current EMAIL quality metric; it
is retained only as raw scoring under the preserved incorrect label.

Reviewed corpus v2 corrects that single label (all six-case text unchanged) and
scores:

| Entity | Gold | Predicted | TP | FP | FN | Precision | Recall | F1 | Provisional gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| EMAIL | 17 | 17 | 17 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |
| MY_PHONE | 17 | 17 | 17 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |
| MYKAD | 15 | 19 | 15 | 4 | 0 | 0.7895 | 1.0000 | 0.8824 | **fail** |

The v2 CLI exits `1` solely because MyKad precision is below the 0.95 gate. The
provisional engineering gate is precision >= 0.95 **and** recall >= 0.95 per
entity, applied only when the split has nonzero positive and negative cases for
that entity. It is not customer-approved and not statistically validated.

MyKad false positives (unchanged in v1 and v2):

- `EV-MYKAD-016` (`ambiguous_order_id`): field-labelled order number
- `EV-MYKAD-017` (`ambiguous_sku`): field-labelled SKU
- `EV-MYKAD-018` (`ambiguous_part_number`): field-labelled part number
- `EV-PHONE-017` (`negative_twelve_digit_phone_shape`): an overlong phone-like
  value also matches the 12-digit MyKad shape

The MyKad false positives are expected consequences of format-only recognition:
the production recognizer has no field context. Excluding them or changing
thresholds would manufacture a pass and is not permitted. The v1
`EV-EMAIL-014` annotation is documented in
[`label-adjudication.md`](../evals/pii/reviewed-labels-v2/label-adjudication.md);
it is a label defect, not a v2 false positive. Passport numbers and bank account
numbers are **not implemented and not evaluated** in this slice.

## Caller-review edge evidence (separate root)

The original evaluation's 16/16 EMAIL result was a narrow, agent-authored split
and is now known to include one incorrect negative label (v1 `EV-EMAIL-014`).
Caller review found an actual email punctuation miss:
`Contact a@example.invalid.` left the address unmasked because the terminal
period prevented the regex match. That miss was reproduced first in a red test,
then repaired only at the EMAIL right boundary. The period remains punctuation in
the output; a period that continues a domain or hyphenated suffix, or starts a
double-dot suffix, is still not accepted as a terminal boundary.

The separate review corpus freezes six simple cases with explicit annotations,
one positive and one negative per entity. Its provenance is caller-agent review,
**not independent human review**, customer data or a retroactive hold-out set.
After the repair its current results are:

| Entity | Gold | Predicted | TP | FP | FN | Precision | Recall | F1 | Provisional gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| EMAIL | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |
| MY_PHONE | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |
| MYKAD | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |

The pre-fix `CR-EMAIL-001` (`email_final_period_positive`) false negative
(gold offsets 8-25, TP 0, FN 1) remains visible in the preserved
`before-email-fix` report. The current report has no labelled errors and the
review CLI exits `0`. This corpus is now six **known regression cases**, not
unseen evidence and not an independent hold-out set.

## Scope and ambiguity rules

- EMAIL: ASCII mailbox-shaped text with a dotted domain and at least a
  two-character TLD; case-insensitive. One terminal sentence period is accepted
  as surrounding punctuation and retained, but a period followed by a domain-like
  word, hyphen or another dot is not accepted as a partial-address boundary. It
  does not establish deliverability or ownership.
- MY_PHONE: Malaysian mobile-shaped ASCII values beginning `0` or `60`, with
  compact, hyphen or space grouping within the current production literals. It
  does not establish reachability or ownership.
- MYKAD: any 12-digit ASCII value with optional hyphens in the current
  `6-2-4` grouping, regardless of field label. This intentionally over-matches
  order IDs and SKUs; that limitation is measured above rather than hidden.
  **User decision (22 October 2026): ambiguous 12-digit order/SKU values stay
  masked.** The gold labels and recognizers are unchanged; this is an accepted
  privacy-over-precision trade-off, not an accuracy pass.
- A match proves only that a structured format matched. It does not prove that
  a value is a real identity document or that surrounding text is semantically
  benign.
- Full-width, obfuscated, dotted-phone, space-separated MyKad and other
  non-listed forms are outside scope. Unsupported fixture cases are reported and
  excluded from the metric table.
- The measured supported-format boundary is ASCII structured tokens. That
  measurement statement is not a claim that the implementation rejects every
  non-ASCII character: the Python regexes use Unicode `\d` rather than `[0-9]`
  and Unicode `IGNORECASE`, so some non-ASCII digits/letters can match the same
  literals. A regression test preserves the existing Unicode `\d` MyKad
  behaviour; no non-ASCII protection is claimed. Full-width fixtures remain
  explicitly unsupported.
- Only the EMAIL right boundary changed in this repair. The MY_PHONE and MYKAD
  literals, recognition order, match rule, thresholds and scope are unchanged.
  Future recognizer changes require a new unseen hold-out split or clearly
  labelled development cases; they must not be tuned against this evaluation
  split.

## Limits

- Agent-authored synthetic fixtures can encode the same expectations as the
  implementation. They are not independent review.
- No native classifier, pretrained guard weights or English semantic quality
  was executed here. See [language-support.md](language-support.md).
- The evaluator measures the three structured recognizers only. It does not
  measure passport/bank coverage, free-text identity leakage, retrieval stores,
  logs, traces, backups or provider-side retention.
- This is an offline quality gate. An evaluation failure does not disable the
  runtime gateway and is not a production incident signal.

## Verification after the repair

- The new terminal-period mask/span regression and the assembled ASGI/HTTP
  regression were run red before the regex change (exit `1`), then green after.
- Focused PII span/evaluator tests: `34` tests OK. The ASGI enforcement suite:
  `7` tests OK, including a real loopback HTTP fixture capturing the upstream
  body and checking the full-context guard call and terminal audit.
- Current CLI exits: v1 evaluation `1` (annotation-conflicted EMAIL FP plus MyKad
  4 FP), reviewed v2 `1` (MyKad 4 FP only; EMAIL 17 TP / 0 FP), caller-review
  `0` (all six known cases pass). Full suite after the change: **284 tests run,
  282 passed, 2 skipped, exit 0**; the two skips are the existing
  `TEST_AUDIT_DSN`-gated PostgreSQL tests.
- Current runtime SHA256: `nasi_lemak/pii.py`
  `3b605e37821008308f7be11efb1f06463b561d4f5021d21f914f0b994a07b0ee`,
  `nasi_lemak/pii_eval.py`
  `e6e3b17e354b035c8627678596d0bfa4b299567c051a763a1b6d55eb8a55e8b0`,
  `nasi_lemak/gateway.py`
  `2a566f90ccfdfb83ccc23b8a231c161105d4ecc4c459f3c84e82e1bdbd00c7fd`.
  V1 fixture manifests remain unchanged; v2 has its own frozen manifest.
  This label-adjudication stage changed no production source and no runtime
  report hash.

Tasks 13/14 are therefore **not fully customer accepted**: the authored
evaluation, the narrow reviewed regression repair, the documented boundary and
the disclosed v1 annotation adjudication are delivered, while true independent
held-out labels/review, customer acceptance, native semantic-guard execution and
a real pilot remain open. Neither reviewed corpus is independent validation. The
MyKad four-false-positive gate still fails at 0.7895 precision in both v1 and
v2; the v1 EMAIL score remains annotation-conflicted, while v2 EMAIL passes
under the corrected label and the known terminal-period review case passes.
