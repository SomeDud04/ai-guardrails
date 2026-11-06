# Current limitations

Status: recorded 2 November 2026 from the repository docs, a spot check of the
code and pilot operations notes. Nothing was re-run to write this page. It
summarises existing evidence and is not an acceptance result.

Where this page disagrees with an older document, this page is newer. The README,
[guards.md](guards.md), [guardrails-comparison.md](guardrails-comparison.md),
[language-support.md](language-support.md) and `PROJECT_STATE.md` still say no
guard model has been run, or still describe older guards. The VM results are in
[guard-evaluation.md](guard-evaluation.md).

Each limitation has one of four types:

| Type | Meaning |
|---|---|
| Design | Follows from how the gateway works; removing it needs a different design |
| Decision | Chosen by the user; can be changed by a new decision |
| Hardware | Set by the current CPU-only VM |
| Not done | Work or evidence that does not exist yet |

## Detection

| Limitation | Why | Type | Relevant files |
|---|---|---|---|
| Guard accuracy is not independently proven. The last full run blocked 91 of 93 attacks and wrongly blocked 1 of 93 safe prompts. | The data is synthetic and agent-written. The input setup was chosen on these rows and the pass mark was set after they were seen, so this is a pilot acceptance check. | Not done | [guard-evaluation.md](guard-evaluation.md), `evals/guards/multilingual-guard-lanes-v2.json`, `nasi_lemak/guard_eval.py` |
| The result applies to one setup: Qwen3Guard-Gen-0.6B at threshold 0.5. | The threshold is a severity floor, not a calibrated probability, and no alternative was measured on a hold-out set. | Not done | [guards.md](guards.md), [guard-benchmark-20261028.md](guard-benchmark-20261028.md), `nasi_lemak/qwen3guard.py`, `nasi_lemak/qwen3_local.py` |
| BM and Chinese are the weak spot. The two missed attacks are `in-jailbreak-03-bm` and `in-jailbreak-04-zh`; the false block is `in-benign-13-bm`. | The cause of those misses is unknown. The rows are few and agent-written, so they do not show how real users or attackers write in those languages. | Not done | [guard-evaluation.md](guard-evaluation.md), [language-support.md](language-support.md) |
| Deny phrases only match literal text. Accented look-alikes and phrases split across turns are not blocked. | Literal matching is predictable and auditable. Accents are kept on purpose rather than folded to ASCII. | Design | [owasp-corpus.md](owasp-corpus.md), `nasi_lemak/gateway.py`, `tests/test_deny_normalisation.py` |
| A safe verdict does not mean an answer is true. | A safety model judges harm, not facts. Checking facts needs a trusted reference source. | Design | [owasp-verification-matrix.md](owasp-verification-matrix.md) |

## PII masking

| Limitation | Why | Type | Relevant files |
|---|---|---|---|
| Masked: email, Malaysian phone, MyKad, Luhn-valid card numbers, narrow postal address shapes, and passport and bank account numbers **only when an English or Malay label comes first** (`passport`/`pasport`; `account`, `acct`, `a/c`, `akaun`, `bank account`). An unlabelled or Chinese-labelled passport or bank number is not masked, except that any 12-digit number is caught as MyKad. Names and free-text identity are not masked. Only email, phone and MyKad have a measured accuracy. | Regex needs a fixed format. Identity in free text would need a language model, which is not part of the gateway. | Design | [pii-quality.md](pii-quality.md), [language-support.md](language-support.md), `nasi_lemak/pii.py` |
| Any 12-digit value that looks like a MyKad is masked, including order IDs and SKUs (15 correct, 4 false positives). The MyKad precision gate fails. | The user chose over-masking on 22 October 2026 rather than risk leaking a real MyKad. | Decision | [pii-quality.md](pii-quality.md), `evals/pii/reviewed-labels-v2/results/evaluation-summary.md` |
| Street-first, lowercase, multi-line and non-Latin-script addresses stay unmasked. Address masking has no quality score. | Loose patterns would mask ordinary text and could leave partial addresses, so uncertain shapes stay raw. The frozen corpora contain no address labels. | Design | [postal-address-mask.md](postal-address-mask.md), `nasi_lemak/pii.py` |
| Guards see unmasked data. The input guard reads the original text and the output guard reads the unmasked reply. | Masking first could hide an attack, and the output verdict must apply to what the model really said. This is safe only while guards run locally. | Design | [guardrails-comparison.md](guardrails-comparison.md), `nasi_lemak/gateway.py` |

## Unsupported features

| Limitation | Why | Type | Relevant files |
|---|---|---|---|
| Tool calls and multimodal input are rejected, so coding agents cannot use the gateway. | Tools let the model take actions and need their own permission and execution checks first. Rejecting them keeps the attack surface small. | Not done | [threat-model.md](threat-model.md), `docs/api-contract.yaml`, `nasi_lemak/server.py`, `nasi_lemak/workspace_page.py` |
| Streaming is not real streaming. `stream: true` sends the finished reply in one piece. | The guard must read the whole reply before release, so word-by-word output would send unchecked text. | Design | README (HTTP surface), `nasi_lemak/server.py` |
| No RAG, SSO or multi-customer support. | Left out of the agreed milestone. RAG needs access controls and customers need tenant isolation. | Not done | [workspace-setup.md](workspace-setup.md), [demo-tenancy-design.md](demo-tenancy-design.md) |
| The startup policy file changes only with a restart. | One approved file makes it easy to prove which policy was active, and rollback means selecting the earlier file. | Design | README (Startup policy), `nasi_lemak/policy.py`, `docs/policy.example.yaml` |
| Alerts are in-app only. | User decision: no email, Teams, webhooks or third-party delivery. | Decision | [admin-policies.md](admin-policies.md), `nasi_lemak/workspace_governance.py` |

## Speed and capacity

| Limitation | Why | Type | Relevant files |
|---|---|---|---|
| Scans are slow: about 6 s for input, and about 10 s to 31 s for output. | The guard generates a text verdict on CPU, and longer replies take longer to scan. | Hardware | [guard-evaluation.md](guard-evaluation.md), [chat-limits.md](chat-limits.md), `nasi_lemak/qwen3_local.py` |
| A 4-vCPU VM runs two guard scans at a time. | Each scan needs its own CPU threads. | Hardware | [guards.md](guards.md), `nasi_lemak/guard_pool.py` |
| Real multi-user capacity is unmeasured, and no target has been agreed. | No load test has been run against the real stack. Local concurrency tests use doubles. | Not done | [owasp-corpus.md](owasp-corpus.md) (Concurrency framing) |
| The chat deadline ends the HTTP response, not the work. The guard, model and audit can keep running after the user gets a `503`. | Native model code cannot be safely interrupted from a Python thread. A hard deadline needs process isolation. | Not done | README (HTTP surface), `nasi_lemak/server.py` |
| Long answers can stop at the reply limit. They are released after the output guard, with a notice and `finish_reason: length`. A reply with nothing visible is still a `503`. | The limit keeps the CPU output scan within the chat deadline. The user chose this on 2 November over refusing the reply. | Decision | [rca-2026-10-29-generation-truncation-503.md](rca-2026-10-29-generation-truncation-503.md), `nasi_lemak/generation.py` |
| The model sees only recent messages, so it can forget older details. Saved history is still decrypted in full on each turn. | Model and guard windows are limited, and every extra message adds scan time. | Design | [chat-limits.md](chat-limits.md), `nasi_lemak/workspace_store.py` |
| No durable token, daily or cost budgets. | Excluded from demo scope. A production deployment would still need them. | Not done | [owasp-verification-matrix.md](owasp-verification-matrix.md) (OWASP-LLM06-05), `nasi_lemak/limits.py` |

## Security and deployment

| Limitation | Why | Type | Relevant files |
|---|---|---|---|
| Workspace administrators can relax the model checks and masks for a scope. Authentication, limits, deny phrases and audit ordering stay on. | The user asked for full admin choice, including overrides in either direction. | Decision | [admin-policies.md](admin-policies.md), `nasi_lemak/workspace_governance.py`, `nasi_lemak/controls.py` |
| HTTPS has been rehearsed but not run with real browser sign-in. A whole `install.sh --workspace` has not been run either. | Each needs the real VM, and both are risky close to a live run. | Not done | `compose.demo-tls.yaml`, `deploy/nginx-demo-tls.conf`, `scripts/install.py`, [install-ubuntu.md](install-ubuntu.md) |
| No SBOM, vulnerability scanning, image signing or digest pinning. | The pilot put the core gateway first. These are production release gates. | Not done | `Dockerfile`, `compose.yaml`, [owasp-verification-matrix.md](owasp-verification-matrix.md) |
| The audit log is not tamper-proof. | Anyone with database administrator rights can change a normal database. | Design | [threat-model.md](threat-model.md), `nasi_lemak/audit.py` |
| Incomplete requests are reconciled only by a manual offline step. | Repairing records while requests run could mislabel work still in progress. | Design | README (Security and operational limits), `nasi_lemak/audit.py`, `nasi_lemak/gateway.py` |
| No customer acceptance, production approval or full OWASP acceptance. | Sign-off has to come from the customer and independent evidence, not from local tests. | Not done | [pilot-scope.md](pilot-scope.md), [owasp-verification-matrix.md](owasp-verification-matrix.md) |

## Changing on `feat/admin-build`

The branch has not been merged to `main` and is not confirmed on the VM. Its
changes do not count as live until they are merged and the VM has the schema 6
upgrade ([workspace-setup.md](workspace-setup.md)).

| Area | Change on the branch | What stays limited | Relevant files |
|---|---|---|---|
| Runtime settings | Administrators can save chat limits, allowed categories, deny phrases, retention, session and lockout settings with history. Some settings still need a restart. | Settings can only tighten the startup policy and environment. Guard mode, the guard, the model and audit ordering cannot be changed. | `nasi_lemak/system_settings.py`, `nasi_lemak/workspace_admin_http.py` |
| API key limits | Each key has an owner and a requests-per-minute limit. | Request rate is not a token, daily or cost budget. | `nasi_lemak/gateway.py`, `nasi_lemak/workspace_store.py` |
| Key audit | Keys follow the owner's policy and raise alerts, with per-key history. | Prompt and reply text is not stored by default. | [workspace-setup.md](workspace-setup.md) |
| Pause and shared key | Administrators can pause all chat and turn off the shared key. | Pausing returns `503` for everyone. | `nasi_lemak/gateway.py`, `nasi_lemak/system_settings.py` |

Update this page when the branch merges.
