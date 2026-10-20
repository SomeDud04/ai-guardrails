# PII quality evaluation summary

**Synthetic, agent-authored evaluation split. Not independently labelled or customer accepted.**

- Split: `evaluation`
- Corpus ID: `pii-synthetic-evaluation-v1`
- Corpus SHA256: `fa644f708df31e182a1e64ff1f9eb891dc3d99800c10ff81cea026e73ea55381`
- Manifest SHA256: `309f65fbb979cc703a11b668322441c2a803786c9c9bedfcdb41fd6bcf6cf982`
- Cases: 58 evaluated, 3 excluded out of 61
- Match rule: `exact_entity_type_and_offsets_one_to_one`

## Per-entity results

| Entity | Gold | Predicted | TP | FP | FN | Precision | Recall | F1 | Gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| EMAIL | 16 | 16 | 16 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |
| MY_PHONE | 17 | 17 | 17 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | pass |
| MYKAD | 15 | 19 | 15 | 4 | 0 | 0.7895 | 1.0000 | 0.8824 | fail |

Provisional engineering gate: precision >= 0.95 and recall >= 0.95 per entity, applicable only when the split has nonzero positive and negative cases for that entity. Overall: **fail**.

## Labelled errors

- `EV-PHONE-017` (negative_twelve_digit_phone_shape): false_positive MYKAD 7-19 — `predicted_span_without_exact_gold`
- `EV-MYKAD-016` (ambiguous_order_id): false_positive MYKAD 6-18 — `predicted_span_without_exact_gold`
- `EV-MYKAD-017` (ambiguous_sku): false_positive MYKAD 4-16 — `predicted_span_without_exact_gold`
- `EV-MYKAD-018` (ambiguous_part_number): false_positive MYKAD 9-21 — `predicted_span_without_exact_gold`

## Excluded cases

- `EV-EMAIL-019` (unsupported_obfuscated): unsupported — `outside_declared_scope`
- `EV-PHONE-021` (unsupported_fullwidth_digits): unsupported — `outside_declared_scope`
- `EV-MYKAD-020` (unsupported_space_separated): unsupported — `outside_declared_scope`

## Limits

- Gold spans are explicit synthetic annotations validated against each fixture text; they were not produced by the production regexes.
- This split is agent-authored. It is not an independent human hold-out set, population estimate or customer acceptance evidence.
- Format matching does not establish identity validity, phone reachability or email deliverability.
- Full-width and obfuscated forms are outside the declared scope; excluded cases are listed above.
- Native classifier/English semantic guard quality and BM/Chinese semantic protection are not evaluated here.
- The thresholds are provisional engineering gates, not customer-approved release criteria.
