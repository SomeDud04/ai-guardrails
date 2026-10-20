# Language support and guard boundary

Status: local engineering baseline, 20 October 2026. This document records what
the repository actually demonstrates. It does not establish pilot acceptance.

## Current evidence

| Area | State | Evidence |
|---|---|---|
| Structured ASCII EMAIL / MY_PHONE / MYKAD masking | Implemented and locally tested; the reviewed EMAIL terminal-period repair was verified through ASGI and loopback HTTP; reviewed v2 measures EMAIL 17 TP / 0 FP / 0 FN and MY_PHONE 17 TP / 0 FP / 0 FN, while MyKad remains 15 TP / 4 FP / 0 FN, so the MyKad threshold gate still fails; the original frozen v1 EMAIL raw score is annotation-conflicted and is not a current EMAIL metric | Shared spans in `nasi_lemak/pii.py`; v1 synthetic evaluation plus separate caller-review edge corpus in [pii-quality.md](pii-quality.md) and [reviewed v2 summary](../evals/pii/reviewed-labels-v2/results/evaluation-summary.md) |
| ASCII structured IDs embedded in BM surrounding text | Format masking works in the sampled synthetic cases | Frozen evaluation cases with BM sentences for all three entities |
| ASCII structured IDs embedded in Chinese surrounding text | Format masking works in the sampled synthetic cases | Frozen evaluation cases with Chinese sentences for all three entities |
| English semantic guard quality | **UNVERIFIED** | No guard weights downloaded or executed; deterministic doubles only |
| BM semantic guard protection | **UNSUPPORTED for pilot acceptance** | No BM classifier evaluation or independent labels |
| Chinese semantic guard protection | **UNSUPPORTED for pilot acceptance** | No Chinese classifier evaluation or independent labels |
| Passport numbers, bank accounts, addresses, names and free-text identity | **Not implemented / deferred** | No recognizers or gold labels |

The structured recognizers operate on ASCII patterns. Matching an email, phone
or 12-digit value inside a BM or Chinese sentence demonstrates only that the
ASCII token was masked. It does **not** show that the surrounding BM or Chinese
text was semantically understood, that names/addresses were protected, or that a
prompt-injection attempt in those languages was detected.

The measured boundary is the synthetic ASCII fixture set. That statement does not
mean every non-ASCII character is rejected: the preserved Python regexes use
Unicode `\d` rather than `[0-9]` and Unicode `IGNORECASE`, so some non-ASCII
digits/letters can match the same literals. This is an implementation-behaviour
qualification, not native-language or non-ASCII protection evidence. Full-width
forms remain outside the evaluated scope. Only the EMAIL right boundary changed
for the terminal-period repair; the MY_PHONE and MYKAD literals are unchanged.

## English semantic guard pilot acceptance

English semantic guard acceptance remains **UNVERIFIED** pending:

- native execution of the approved local guard/tokenizer artifacts (not executed
  in this workspace);
- a frozen, independently labelled English evaluation set;
- independent review of labels, false positives/negatives and ambiguity rules;
- an agreed threshold and operating procedure approved by the customer.

Synthetic adapter tests prove orchestration and fail-closed handling only. They
are not classifier accuracy evidence.

## BM / Chinese boundary

BM and Chinese semantic protection is **UNSUPPORTED for pilot acceptance**.
There is no claim of multilingual classifier quality or semantic PII coverage.
The frozen PII evaluation includes BM/Chinese surrounding text solely to show
that structured ASCII masking is not limited to English sentences; its metrics
cover the three format recognizers, not language understanding.

The product/operator scope must therefore state that:

- English semantic protection is not yet accepted;
- BM/Chinese semantic protection is not accepted;
- only the three documented ASCII structured formats have synthetic quality
  evidence; the MyKad gate still fails on four false positives, the original
  frozen v1 EMAIL raw score is annotation-conflicted rather than a current EMAIL
  metric, and reviewed v2 corrects only that one label and passes EMAIL and
  MY_PHONE at 17 TP / 0 FP / 0 FN each;
- neither the caller-review corpus nor its post-fix pass is an unseen or
  independent hold-out set.

See [pii-quality.md](pii-quality.md) for exact per-entity counts, labelled
errors, reproduction commands and the provisional gate definition, and
[the reviewed v2 summary](../evals/pii/reviewed-labels-v2/results/evaluation-summary.md)
for the corrected-label run.
