# Postal address masking: bounded synthetic scope

Status: local synthetic implementation evidence only. No live deployment, live
evaluation, customer data or address-quality measurement is claimed here.

`POSTAL_ADDRESS` is an additional format recognizer in
[`nasi_lemak/pii.py`](../nasi_lemak/pii.py), exposed through the same
`find_redactions`/`mask_text` path as the other masks. It is a narrow
high-precision pattern for **numbered Malaysian single-line addresses written in
ASCII**, not semantic address detection.

## What the pattern recognizes

There are two bounded shapes. Both require a house/unit number and a recognized
street keyword followed by a title-cased ASCII street name:

- a house/unit number of one to four digits, optionally with a letter and a
  hyphenated second segment (`12`, `12A`, `12-3`), optionally prefixed by
  `No`, `Unit`, `Blok`, `Block`, `Lot`, `Level` or `Floor`;
- a recognized street keyword: `Jalan`, `Jln`, `Lorong`, `Lrg`, `Persiaran`,
  `Pesiaran`, `Lebuh`, `Lbh` or `Changkat` (keyword matching is
  case-insensitive);
- a title-cased/ASCII street name of up to four short tokens, e.g. `Ampang` or
  `Taman Sri Indah`.

The first shape then requires:

- up to three optional comma-separated locality words before the postcode;
- a comma followed by a five-digit postcode (`50450`);
- up to three optional trailing locality/state groups, comma- or
  space-separated (`Kuala Lumpur`, `Selangor`).

The second shape is the same number/street/name body with up to three optional
comma-separated locality groups, but **no postcode**, immediately after an
explicit `Address:` or `Alamat:` label. The label is case-insensitive and may
have spaces before the colon. Only the address body is masked: the label,
sentence punctuation and following prose stay outside the span. The bounded
street-name tokens and comma-separated locality groups also prevent the
recognizer from swallowing ordinary following words.

Examples that match today:

```text
12, Jalan Ampang, 50450 Kuala Lumpur
Unit 12-3, Lorong 3, 50450 KL
Address: 12, Jalan Ampang, 50450 Kuala Lumpur
Alamat: 12, Jalan Ampang, 50450 Kuala Lumpur
地址: 12, Jalan Ampang, 50450 Kuala Lumpur
Address: No. 12, Jalan Melati 3
Alamat: Unit 12-3, Jalan Ampang
Address: No. 12, Jalan Melati 3, Taman Sri Indah
Alamat: Unit 12-3, Jalan Ampang. Jumpa esok!
Address: No. 12, Jalan Melati 3 is nearby
```

The `Address:`, `Alamat:` and `地址:` labels may precede the postcode-bearing
ASCII form; the label remains outside the masked span. For the no-postcode form
only `Address:` and `Alamat:` are supported, and the label must directly precede
the ASCII body. A native-script or non-ASCII address body is **not** recognized
merely because one of those labels is present, and a label followed only by
prose stays raw.

## What it does not cover

- Street-first addresses without a leading house/unit number
  (`Jalan Ampang, 50450 Kuala Lumpur`).
- Postcode-less addresses without an `Address:`/`Alamat:` label
  (`No. 12, Jalan Melati 3`). This is a deliberate conservative limit; the
  labelled form above is the only no-postcode shape supported.
- Addresses that omit the comma before the postcode
  (`12, Jalan Ampang 50450 Kuala Lumpur`), with or without a label. The
  labelled recognizer refuses to mask a partial body in that shape.
- A label that is part of a longer word (`EmailAddress:`), or a label separated
  from the body by other text; the label must directly precede the address.
- All-lowercase street/place names; the street and place name tokens must start
  with an uppercase ASCII letter (or a short numeric token).
- Arbitrary prose, PO-box/descriptive addresses, multiple address blocks, and
  native-script (Chinese/Tamil/Arabic) address text.
- Comprehensive English, Bahasa Malaysia or Chinese semantic address coverage.
  This is one literal shape, not a language model and not an address database
  lookup.
- Identity validity, occupancy, ownership or deliverability. A match proves only
  that the ASCII shape matched.

Whitespace in the regex uses `\s`, so a line break can occur where the pattern
already allows whitespace. The recognizer still does not parse or reassemble
multi-line address blocks; treat multi-line addresses as outside the supported
scope.

## Administrative switches

Admin policy profiles expose **independent input and output `Postal address`
switches**, alongside the email, phone and MyKad switches. They are stored in
the profile's `input_masks` and `output_masks` lists.

- A brand-new profile defaults to selecting every mask, including postal
  address.
- A previously saved profile is rendered exactly as stored. If it was saved
  before `POSTAL_ADDRESS` existed, the postal switch is off for that saved
  profile; editing/re-saving the profile or assigning a newly pinned revision is
  required to activate it. Nothing silently rewrites saved settings.
- With no applicable workspace policy, gateway defaults follow `MASK_TYPES`,
  which now includes `POSTAL_ADDRESS`.
- Masking can be relaxed per profile only within the existing policy model;
  authentication, limits, audit ordering and the other unconditional controls
  are unchanged.

## Evaluation compatibility

The frozen evaluation corpora contain **no postal-address gold spans**. In the
v1, reviewed-v2 and caller-review splits, `POSTAL_ADDRESS` therefore reports
`not_applicable`, with `null` precision/recall/F1. No address quality metric,
score or threshold is claimed from those corpora, and their bytes, scores and
known MyKad false positives are unchanged.

The evaluator's overall gate now excludes `not_applicable` entities from the
verdict:

- at least one applicable entity gate is required, so an all-`not_applicable`
  report cannot pass;
- every applicable entity gate must pass, so a failing email, phone or MyKad
  gate still fails the split;
- a `not_applicable` new entity type no longer forces an otherwise clean split
  to fail.

This is evaluator aggregation compatibility, not evidence that the address
recognizer is accurate. A future address corpus must be separately authored,
frozen and disclosed before any address metric is reported.

The focused evaluator regression suite is:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_pii_eval
```

Synthetic unit tests prove only the documented local behavior. They are not a
live deployment test, a production outcome, independent human annotation or
customer acceptance.
