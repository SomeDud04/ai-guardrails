# Label adjudication: reviewed corpus v2

Status: caller-agent label adjudication for local offline regression evidence.
It is **not** a human independent review, customer acceptance, an unseen
held-out set or a population estimate.

## Scope of the change

`evals/pii/reviewed-labels-v2/evaluation.json` is a copy of the frozen v1
evaluation corpus (61 cases). The corpus ID is changed to
`pii-synthetic-evaluation-v2-adjudicated`. Exactly one case annotation is
corrected: `EV-EMAIL-014`. All other case texts, labels, scopes, notes and gold
spans are copied unchanged. The v1 files, reports and labels are not modified.

## Original gold (v1, preserved)

- Case: `EV-EMAIL-014`
- Text: `Tulis kepada nama@example.invalid. untuk maklumat.`
- Label: `negative_trailing_dot`
- Gold: `[]`
- Original note: "Trailing sentence dot after the TLD is a word-boundary
  near-match."

## Corrected gold (v2)

- Label: `positive_trailing_dot`
- Gold: one `EMAIL` span, offsets `13-33`, text `nama@example.invalid`
- The sentence-final period at offset 33 is punctuation and is **not** part of
  the span.

## Reason and requirement

The frozen v1 annotation encoded the recognizer's old terminal-period miss as a
negative case. That conflicts with the accepted privacy requirement (also
exercised by the separate caller-review positive): an address followed by a
sentence period must be masked while the period is retained. Treating the old
miss as correct non-PII would bless an annotation error and hide a real gap.
The caller-agent therefore adjudicated this single label as positive. This is a
disclosed annotation correction, not a production false positive in v2.

## Provenance and freeze

- Provenance: caller-agent adjudication requested by the caller; no independent
  human reviewer was involved.
- V2 corpus SHA256:
  `aa4879f2c7a678781498f514bdfd9d38213c15b6eb11c559f3df3824b5b7b4db`
- V2 manifest SHA256:
  `17820ffedcb531dcb4a5ebf25f6fb3f39252af4408726c179f2282df8802512b`
- The manifest was written before the v2 corpus was scored.
- Frozen v1 corpus remains
  `fa644f708df31e182a1e64ff1f9eb891dc3d99800c10ff81cea026e73ea55381`.

## Interpretation

The v2 result is a corrected regression measurement over reviewed labels, not
unseen evidence. The original v1 raw score (EMAIL 16 TP / 1 FP / 0 FN) remains
available but is annotation-conflicted and must not be presented as a reliable
current EMAIL quality score. The six-case caller-review corpus remains
regression-only evidence. MyKad still fails the 0.95 precision gate with four
false positives in both v1 and v2.
