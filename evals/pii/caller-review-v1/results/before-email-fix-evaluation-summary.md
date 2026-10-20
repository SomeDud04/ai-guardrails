# PII quality evaluation summary

**Synthetic, agent-authored evaluation split. Not independently labelled or customer accepted.**

- Split: `evaluation`
- Corpus ID: `pii-caller-review-edge-v1`
- Corpus SHA256: `6ec81452e320ac03517eed894f1cd416f73f54736335c04eca49153465aa7e14`
- Manifest SHA256: `f5d24ecbb20fe60948f585b973f25c1428bd3b2f45dec87cec911dfa9bcc07ab`
- Cases: 6 evaluated, 0 excluded out of 6
- Match rule: `exact_entity_type_and_offsets_one_to_one`

## Per-entity results

| Entity | Gold | Predicted | TP | FP | FN | Precision | Recall | F1 | Gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| EMAIL | 1 | 0 | 0 | 0 | 1 | n/a | 0.0000 | 0.0000 | fail |
| MY_PHONE | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |
| MYKAD | 1 | 1 | 1 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |

Provisional engineering gate: precision >= 0.95 and recall >= 0.95 per entity, applicable only when the split has nonzero positive and negative cases for that entity. Overall: **fail**.

## Labelled errors

- `CR-EMAIL-001` (email_final_period_positive): false_negative EMAIL 8-25 — `gold_span_without_exact_prediction`

## Excluded cases

- None.

## Limits

- Gold spans are explicit synthetic annotations validated against each fixture text; they were not produced by the production regexes.
- This split is agent-authored. It is not an independent human hold-out set, population estimate or customer acceptance evidence.
- Format matching does not establish identity validity, phone reachability or email deliverability.
- Full-width and obfuscated forms are outside the declared scope; excluded cases are listed above.
- Native classifier/English semantic guard quality and BM/Chinese semantic protection are not evaluated here.
- The thresholds are provisional engineering gates, not customer-approved release criteria.
