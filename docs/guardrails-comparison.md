# Guardrail scope and reference comparison (26 October 2026)

This is a documentation-only assessment of the local synthetic foundation. It
compares what this repository implements with the capabilities described by
five public references. The references are vendor/framework documentation, not
evidence that this repository deployed or measured them.

The project remains a local FastAPI gateway with an optional employee workspace.
The default guarded mode is not ready without all of the operator policy, guard
artifacts or API endpoints, and audit configuration. Test mode deliberately
keeps model guards inactive. No pretrained guard checkpoint or live guard endpoint has been
executed here, and no production pilot is claimed.

Local verification for this assessment: the full local suite separately ran 713
tests with 7 skipped, and the local synthetic Chrome checks passed. Those runs
used synthetic data, SQLite and local fixtures, plus one disposable local
PostgreSQL instance for a single optional concurrency test. This document
contains no live guard-model, VM latest-release or production database evidence.

## Evidence labels used below

| Label | What it supports | What it does not prove |
|---|---|---|
| Code/test evidence | Request validation, auth, limits, deny phrases, PII masking, fail-closed ordering, guard adapter contracts, audit and workspace policy/alert behaviour. Tests use real SQLite, loopback HTTP fixtures and deterministic guard/tokenizer doubles; one optional workspace concurrency test was separately run against a disposable local PostgreSQL instance (1 passed). | Pretrained classifier quality, live endpoint availability, Docker/VM behaviour, production PostgreSQL privilege or durability behaviour, throughput or customer acceptance. |
| Synthetic Chrome evidence | The initiating Codex session ran Chrome against a local synthetic instance on 26 October 2026: a normal chat and saved reply worked; a blocked input showed one reason and a stable `ref` and incremented one alert; a disposable administrator grant/revoke flow worked; an employee did not see administrator controls; the page was readable at 390px. GPT-6.1 Sol then assessed the evidence supplied by that session; Sol did not operate the browser itself. | Live guard-model inference, production deployment, broad PostgreSQL or TLS ingress behaviour, load/latency, or broad accessibility. It exercises UI/API plumbing, not classifier efficacy. |
| Live unknowns | — | No live guard-model proof, no measured false-positive/false-negative or latency ranking, no live multilingual quality, no retrieval/tool rails, no production VM/Docker run and no production-database evidence beyond the single disposable local PostgreSQL check. |

## Implemented scope

| Control | Implemented behaviour | Enforcement point |
|---|---|---|
| Application auth and request limits | One configured bearer key for the direct API (workspace sessions are separate); strict content type, JSON shape, role/turn/byte/token bounds; no streaming, tools or multimodal input. | Before any generation or guard call. |
| Deterministic policy | Startup YAML supplies `app_id`, `version`, public alias, token budget and literal case-insensitive `deny_phrases`. The file is read once at construction; activation/rollback is a controlled restart. | Literal input and output checks. Not a classifier and not a semantic topic filter. |
| PII masking | ASCII structured recognizers for `EMAIL`, `MY_PHONE` and `MYKAD`; input masked before generation and output masked before client release. Workspace administrators may relax the mask set for their scope; the legacy API keeps all three. | Input before provider call; output after the output verdict and before release. |
| Input model guard | Prompt Guard 2 binary injection/jailbreak screening over the complete serialized conversation. Local artifacts or the gateway-owned `nasi-lemak-input-classifier-v1` API adapter. | Before PII masking and generation. |
| Output model guard | Contextual Llama Guard 3 locally, or Qwen3Guard output screening through the API backend. Complete current-request context plus the buffered raw output. | After generation, before PII masking and release. |
| Audit and operator view | Metadata-only audit events with request id, event type/decision and, for blocks, stage/reason plus policy version/digest; read-only operator events and bounded CSV export; in-app workspace block alerts. | Initial write before inference; terminal write before release. |
| Workspace admin policy | Immutable profile revisions, workspace/department/user assignments, effective-user preview, optimistic concurrency; only the two model-check toggles and PII mask subsets. | Per workspace turn, before provider call. Authentication, limits, deny phrases and audit ordering stay unconditional. |

Not implemented: harmful-topic input moderation as a separate rail, semantic PII
or secret detection, retrieval/RAG isolation, tool/execution rails, streaming
guardrails, multimodal coverage, a policy editor or hot reload, and per-request
custom validators. There is no LiteLLM routing layer in this gateway.

## Comparison by dimension

| Dimension | This repository | NVIDIA NeMo Guardrails | LiteLLM guardrails / Presidio | Guardrails AI validators | Groq content moderation |
|---|---|---|---|---|---|
| Coverage | Narrow chat path: auth, limits, deterministic phrases, three PII formats, injection input guard, contextual output guard, audit. No retrieval/tool rails. | Documented rail taxonomy spans input, output, dialog, retrieval, execution and configuration rails; broader orchestration library. | Proxy guardrails with pre/post request hooks and multiple provider integrations; Presidio adds PII detection/anonymization configuration. | Validator ecosystem for input/output checks, structured generation and remediation actions. | Hosted moderation model/API on GroqCloud; the caller integrates the result into its own gateway. |
| Input/output enforcement | In guarded mode both directions are mandatory and fail closed. Output is buffered; no streaming. A guard/audit error releases nothing. Workspace toggles can disable the model checks but not deterministic checks or audit ordering. | Can orchestrate input and output rails, plus retrieval/execution rails where configured. | Hook points can cover request and response paths depending on configuration and provider. | Validators can run on inputs/outputs and apply on-fail actions such as exception, fix, filter or reask according to the configured flow. | Moderation is a separate hosted call; enforcement, ordering and fail-closed behaviour remain the caller's responsibility. |
| False positives and quality evidence | Only synthetic PII known-regression numbers: reviewed v2 EMAIL and MY_PHONE are 17 TP / 0 FP / 0 FN each; MyKad is 15 TP / 4 FP / 0 FN (precision 0.7895), so its gate still fails. No classifier FP/FN rate, threshold calibration or independent hold-out. | Framework documentation describes configurable rails and policies, not a quality result for this data. Quality depends on the selected models, prompts and thresholds. | Same: integration capability is documented; no independent quality comparison was run here. Presidio entity coverage depends on recognizers and configuration. | Validator choice and configuration determine quality; the library itself is not an accuracy claim. | Provider-hosted models have their own terms, limits and unknown false-positive behaviour for this data; no vendor benchmark was reproduced. |
| Privacy and data flow | Raw serialized input reaches the input classifier **before** PII masking. The output guard sees the masked conversation plus the complete **raw** buffered output; client masking happens after the verdict. Local guards keep content on the host; API guards send it to the operator's endpoint. Audit is metadata-only; workspace originals are encrypted. | Can be deployed locally or configured with external model providers; the data boundary depends on that choice. | Guardrail providers may be local or remote; Presidio itself is a local PII library, but a proxy can call external services. | Validators may run locally or call hosted services depending on the chosen validator. | Content leaves the local boundary to Groq; data-flow approval is required before real content. |
| Latency and capacity | No measured latency, throughput or p95. The 500 ms p95 target remains unmeasured. Local inference is CPU, serialized per adapter and has no hard native deadline; the 60 s HTTP work deadline is a response deadline only and the worker may continue. API guards have bounded transport timeouts. | No comparative latency measurement was made here; deployment model, model size and hardware decide it. | No comparative measurement here; proxy/provider overhead depends on configuration and hosting. | No comparative measurement here; validator count and implementation decide it. | Hosted latency, quotas and rate limits are provider-dependent and were not measured. |
| Deployment | Local Python/FastAPI, optional PostgreSQL, SQLite for development, Docker Compose authored but not built/run here; one optional concurrency test ran against a disposable local PostgreSQL instance outside Docker/VM. Guarded mode needs local artifacts or internal guard APIs; TLS ingress is not included. Default/test mode is not guarded mode. | Self-hosted orchestration library/service with its own configuration and model/runtime dependencies. | Self-hosted proxy with configuration and provider credentials; Presidio is a library/service integration. | Self-hosted library with validator dependencies and optional hosted calls. | External hosted service; no local deployment of the moderation model. |
| Observability | Metadata-only audit, read-only operator event view, bounded CSV export and in-app per-administrator block alerts. When the workspace is enabled, `GET /health/ready` also returns a bounded set of fixed-code diagnostic counters: three signal codes with process-lifetime totals and no labels, timestamps, request ids or content. No metrics endpoint, tracing, time-series aggregation, dashboard or outbound notification. | Framework logging/callback options vary; not deployed or compared here. | Proxy logging/callback options depend on configuration; not compared here. | Validator outcomes can be logged by the host application; not compared here. | Provider dashboards/logs are external and were not inspected. |
| Policy configuration | One validated YAML file read at startup; restart-only activation/rollback. Workspace profiles add only two model-check toggles and PII mask subsets with immutable revisions and assignments. | Colang/config-based rails and flows, including retrieval and execution configuration. | Proxy configuration/YAML plus provider credentials; Presidio analyzer/anonymizer settings. | RAIL/spec or programmatic validators with per-validator on-fail behaviour. | Hosted model/request configuration; not an in-process policy engine. |
| Evaluation | `guard_eval` is a 16-case synthetic smoke harness, dry-run by default; execute mode calls the configured adapters. PII evaluation is a frozen agent-authored synthetic corpus. Neither is a held-out benchmark or OWASP acceptance. | Documentation and examples are not a substitute for a project-specific evaluation. | Documentation and examples are not a substitute for a project-specific evaluation. | Validator examples are not a substitute for a project-specific evaluation. | Provider documentation is not a substitute for a project-specific evaluation. |

Official references:

- NVIDIA NeMo Guardrails rail types:
  <https://docs.nvidia.com/nemo/guardrails/latest/about-nemo-guardrails-library/rail-types>
- LiteLLM guardrails quick start:
  <https://docs.litellm.ai/docs/proxy/guardrails/quick_start>
- LiteLLM Presidio PII masking:
  <https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2>
- Guardrails AI validators:
  <https://guardrailsai.com/guardrails/docs/concepts/validators>
- Groq content moderation:
  <https://console.groq.com/docs/content-moderation>

## Scope notes and common misreadings

- **Prompt Guard 2 is an injection/jailbreak classifier, not harmful-topic
  moderation.** It returns a binary benign/malicious signal over a 512-token
  window. It does not provide a violence, self-harm, sexual-content or illegal-
  acts taxonomy, and it must not be presented as a replacement for Llama Guard,
  Qwen3Guard or a hosted moderation model. In this design, topical output
  screening is the output guard's role; input harmful-topic coverage is not a
  separate implemented rail.
- **A literal deny phrase is deterministic policy, not a classifier verdict.**
  `deny_phrases` are case-insensitive substrings checked on accepted input turns
  and buffered output. They are not regexes, semantic similarity or a learned
  topic filter. A deny-phrase block is still a policy block with its own reason
  code; it is not evidence about model accuracy.
- **A failed turn is not a block.** Provider, guard, audit, policy-store,
  timeout, cancellation or overload failures return a generic `503` and are not
  recorded as a policy block or an alert. Only an exact, known input/output
  guard or policy block creates the blocked-turn record and alert. The synthetic
  Chrome check observed one alert increment for a blocked input; code/tests
  separately keep outages out of the alert path.
- **Privacy depends on the selected guard backend.** The input classifier sees
  raw content before masking, and the output classifier sees raw generated text
  before release masking. Local guards avoid sending that content to a guard
  service; API or hosted guards do not. Data-flow approval and endpoint
  contracts are therefore part of the deployment decision, not a documentation
  detail.
- **`NASI_LEMAK_GENERATION_ENABLE_THINKING=false` is provider-specific.** It is
  forwarded only as `chat_template_kwargs.enable_thinking`. Unset preserves the
  existing request body. It is not a general provider option and there is no
  live proof that it fixes empty or reasoning-only responses; the client still
  rejects blank `content`, never reads `reasoning_content`, and does not retry.
- **Synthetic Chrome success is not guarded-model evidence.** The initiating
  Codex session ran Chrome against the local synthetic instance; GPT-6.1 Sol then
  assessed the evidence that session supplied, rather than operating the browser
  itself. The normal chat, saved reply, blocked-input reason/ref, alert
  increment, disposable administrator grant/revoke, employee-hidden admin and
  390px checks show that the local UI and API paths behave as wired. They do not
  show that a pretrained classifier is accurate, that a Docker/VM deployment
  works, or that a production browser/accessibility review passed.
- **PostgreSQL evidence is narrow.** The only database-server evidence is one
  optional simultaneous-admin-demotion test, run by the initiating Codex session
  against a disposable local PostgreSQL instance outside Docker/VM (1 passed).
  SQLite and driver-double tests remain the main coverage. Privileges,
  durability, production-like migration behaviour, Compose and VM runs are still
  unverified here.
- **Diagnostic counters are not metrics.** When the workspace is enabled,
  `GET /health/ready` includes counters for exactly three fixed internal signal
  codes (`generation_truncated`, `generation_no_final_content`,
  `block_payload_rejected`) as process-lifetime totals. Unknown codes are
  ignored, the key set cannot grow, and no prompt, response, provider payload,
  credential, label or timestamp is retained. This is a bounded operational
  hint, not a metrics/tracing surface, history, per-user breakdown or alert
  delivery mechanism.
- **PII quality is a known synthetic regression result.** Reviewed v2 passes
  EMAIL and MY_PHONE at 17 TP / 0 FP / 0 FN and fails the MyKad precision gate
  with four false positives. The corpus is agent-authored, not an independent
  human hold-out, and does not cover semantic PII, names, addresses, passports
  or bank accounts. BM/Chinese semantic guard protection remains unaccepted.

## Future recommendations

1. Decide whether input-side harmful-topic moderation is required. If it is,
   add a separate topic/moderation rail; do not stretch Prompt Guard 2 beyond
   its injection/jailbreak role.
2. If retrieval or tools are introduced, add retrieval isolation, source
   provenance, tool allowlists and execution rails before enabling them. They
   are out of scope today.
3. Approve or avoid the raw classifier data flow. Prefer local or
   operator-controlled guards for sensitive content; otherwise add an approved
   pre-classifier redaction step or an explicit customer data-flow acceptance.
4. Calibrate thresholds on an approved held-out multilingual set (EN/BM/ZH/
   mixed, plus benign near-misses and adversarial cases). Report false blocks,
   missed unsafe cases and p50/p95 latency by stage and language rather than a
   single aggregate.
5. Treat the synthetic smoke run as plumbing evidence only. Require an
   independent hold-out and operator sign-off before claiming OWASP coverage,
   customer acceptance or a production false-positive rate.
6. Add metrics, tracing and alert delivery if operations need them; keep audit
   and alert payloads metadata-only. The only aggregate today is the bounded
   `/health/ready` diagnostic counter set. There is no dashboard, labelled time
   series, history, webhook or email notification.
7. Extend the deployment evidence separately: PostgreSQL privileges, durability
   and production-like migration behaviour beyond the single disposable local
   concurrency test, a Docker image/Compose run, TLS ingress, VM browser checks
   and native/API guard acceptance.
8. If a broader framework is proposed, evaluate NeMo Guardrails, LiteLLM,
   Presidio, Guardrails AI or Groq against the same held-out set and data-flow
   rules. Framework documentation describes capability, not this project's
   measured quality.

## Related internal documents

- [Guard adapters](guards.md) — local Prompt Guard 2 / Llama Guard 3 contracts.
- [Guard evaluation](guard-evaluation.md) — synthetic smoke harness.
- [PII quality](pii-quality.md) and [language support](language-support.md) —
  synthetic recognizer evidence and limits.
- [Control verification](control-verification.md) — assembled enforcement tests.
- [Administrator policies](admin-policies.md) — workspace profiles and alerts.
- [Workspace setup](workspace-setup.md) — deployment and privacy boundaries.
- [Pilot scope](pilot-scope.md) and [threat model](threat-model.md) — explicit
  open gates and residual risk.
