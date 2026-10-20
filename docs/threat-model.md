# Initial threat model

Status: local design baseline, 19 October 2026; PII quality evidence updated 20 October 2026 (synthetic only, including a narrow reviewed EMAIL terminal-period repair); deployment controls and real-model effectiveness unverified.

## Assets and boundaries

Protect request/response text, application credentials, routing/policy integrity and decision evidence. Treat clients, all conversation roles, model output and future remote guard responses as untrusted. A client-supplied `system` role is accepted text for this restricted interface, not a privilege or a server instruction; it receives the same coverage and attack screening as all other roles. No tools or privileged actions are available in this slice.

The future application boundary is TLS ingress into authentication/schema checks. The in-process implementation currently exercises the following internal boundary:

`authenticate -> validate -> coverage/attack on original text -> mask -> initial audit before inference -> approved generator -> output safety -> mask -> durable terminal audit -> release`

The exact initial-event placement may precede screening, but must precede inference; a request admitted to inference must have a durable initial record. Output stays in memory until the terminal write commits. Required failures reject; there is no unguarded fallback.

## Threats and evidence

| Threat | Initial mitigation / test | Remaining pilot gate |
|---|---|---|
| Route/policy override or alternate payload surface | Fixed model alias; reject unknown top-level/message fields, tools, multimodal and streaming | HTTP route inventory, direct model access denial and network test |
| Prompt injection in any conversation turn | Mandatory full-conversation attack adapter on original input; exception and malformed-result tests | Actual classifier integration and frozen held-out quality suite |
| Guard input truncation | Character/turn bounds plus required coverage adapter; oversize rejection tests | Exact tokenizer, special tokens, separators, output guard and generator context checks |
| PII reaching generation or client | Three ASCII structured recognizers share production spans with a frozen agent-authored synthetic evaluator; a reviewed narrow EMAIL right-boundary repair (verified through ASGI and loopback HTTP) masks a sentence-final address without swallowing the period; captured sanitized input/output, full-context guard and no-raw-text audit/report tests | True independent human held-out metrics/review and customer acceptance; remaining MyKad gate failure; the original frozen v1 EMAIL raw score is annotation-conflicted and reviewed v2 passes EMAIL; passport/bank recognizers and semantic PII evaluation; privacy inspection across deployed services |
| Unsafe or malformed generation output | Buffer output, require safety guard, reject malformed adapter data | Real Llama Guard taxonomy/license/serving compatibility and timeout proof |
| Audit outage, crash or delivery ambiguity | Initial and terminal commit ordering; fault injection and incomplete-request reconciliation | PostgreSQL privileges, single-owner recovery protocol, backup/restore and crash/outage tests |
| Secret/text persistence | Fixed metadata fields, generic errors, no prompt logs; synthetic DB inspection | Ingress/LiteLLM/model/guard logs, traces, crash dumps, caches and backups inspected |
| Resource exhaustion | Bounded accepted text and generation budget | Pre-parse HTTP body limit, concurrency queue, deadlines, rate limits and OS/container resource controls |
| Credential theft and operator abuse | Configured hashed key and constant-time comparison | Secret distribution, rotation, TLS, isolated admin authentication and export auditing |
| Dependency/model compromise or egress | No downloads or external model calls in synthetic slice | Exact artifact pinning, license/security review, SBOM, egress denial and host isolation |

## Residual risk

Regex patterns miss PII and may over-redact. The frozen synthetic evaluation
measures the actual recognizers but is agent-authored, not an independent human
hold-out set. The reviewed terminal-period repair closes one reproduced miss and was
verified through ASGI and loopback HTTP; the MyKad precision gate still fails on
four false positives, and the original frozen v1 EMAIL score is annotation-conflicted
because a negative label encoded the old miss, so reviewed v2 corrects only that
label and measures EMAIL 17 TP / 0 FP / 0 FN. The six-case caller-review corpus is
known-regression evidence, not an
unseen or independent hold-out set. Deterministic test adapters offer no semantic
protection. Classifier success
does not establish authorization, retrieval isolation, comprehensive
prompt-injection resistance, multilingual quality or regulatory compliance. A
database is not tamper-proof: privileged local administrators can alter it.
SQLite is a development adapter, and no production durability/HA claim follows
from these tests.

No exactly-once inference or delivery guarantee is provided. A committed terminal event proves eligibility for release, not that a client received it. A crash can leave an initial record incomplete; reconciliation records uncertainty rather than replaying sensitive content. Recovery must run only when the process owns the audit store and no other worker has in-flight requests.
