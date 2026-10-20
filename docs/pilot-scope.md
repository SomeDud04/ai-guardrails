# Project Nasi Lemak: initial local scope

Started 19 October 2026. This repository implements the first synthetic-data foundation of the supplied ten-working-day plan. It is not a deployed gateway or an approved live-data pilot.

## Source and authority

Inputs: `C:\Users\user\Desktop\ai-workspace\tasks\plan.md` and `todo.md`, read without changing them. Their historical planning-only status describes when they were written; the user's subsequent instruction authorizes starting reversible local work. The plan's proposed customer gates remain unaccepted until the customer accepts them.

## Working defaults

- One internal support chatbot, one application, one server-selected policy and local generation-model alias `pilot-local`.
- English semantic scope; experimental format recognizers for email, Malaysian phone patterns and MyKad-like identifiers. A match does not prove identity validity. Only synthetic provisional-gate measurements exist; no production precision or recall claim is made. A narrow reviewed repair masks an email before a terminal sentence period, verified through ASGI and loopback HTTP; the reviewed v2 run measures EMAIL 17 TP / 0 FP / 0 FN and MY_PHONE 17 TP / 0 FP / 0 FN, the MyKad gate still fails at 15 TP / 4 FP / 0 FN (overall quality gate FAIL), and the original frozen v1 EMAIL raw score is annotation-conflicted. The six known caller-review regression cases are not an independent hold-out set.
- Strict text-only chat-completions request, buffered output, no streaming, tools, files, images or arbitrary provider options.
- Original input is screened in memory; inference receives only masked text. Output must pass a mandatory safety adapter and PII masking before release. No restoration of PII.
- Metadata-only audit; required initial write before inference and terminal write before release. Audit failure withholds the response.
- No cloud fallback. Missing mandatory adapters fail closed.

## What this first slice proves

An in-process handler, synthetic adapters, local SQLite development audit and automated negative tests can prove orchestration, strict request validation and fail-closed release ordering without customer infrastructure. The command-line demonstration opens no listening port. Synthetic guards deliberately provide deterministic test outcomes; they do not detect real prompt attacks or prove model quality. PII quality evidence is limited to agent-authored synthetic fixtures: reviewed v2 passes EMAIL and MY_PHONE at 17 TP / 0 FP / 0 FN each, the MyKad gate has four false positives (15 TP / 4 FP / 0 FN, precision 0.7895), the original frozen v1 EMAIL score is annotation-conflicted, and the repaired six-case caller-review corpus is known regression evidence rather than an independent hold-out. The overall quality gate therefore remains FAIL. See [pii-quality.md](pii-quality.md) and the [reviewed v2 summary](../evals/pii/reviewed-labels-v2/results/evaluation-summary.md); this is not independent human held-out data or native semantic model evidence, English semantic guard quality is unverified, and BM/Chinese semantic protection is unsupported for pilot acceptance.

SQLite is a development/test audit adapter only. The pilot design still requires PostgreSQL, restricted writer privileges, validated backups, retention, recovery and operations controls. The scaffold's immutable internal policy object is not the planned validated YAML startup loader. The in-process handler is not an HTTP/SDK integration.

## Initial work sequence

1. Record the scope, API and trust boundaries; list external gates.
2. Implement strict request/authentication, mandatory adapter boundary and metadata audit lifecycle using test-first synthetic cases.
3. Demonstrate input/output masking, rejected surfaces, adapter outages and failed audit writes.
4. Review source and fresh verification evidence; record exact remaining work.
5. After environment details arrive, prove actual local generation, classifiers, complete tokenizer serialization and hardware feasibility before integrating the production serving path.

## Explicitly open gates

The user reports an existing local LLM with display name `Qwen3.8 27B FP8`. This is user-reported and unverified; the exact API model identifier, artifact revision and compatibility remain unknown. The user supplied an HTTP-only OpenAI-format root host `http://82haf69n.flexinfra.com.my` with no authentication required; `/v1` is an assumed prefix, not a live-verified fact. A caller attempt to list models timed out on port 80, and the user then requested configuration-only recording, so there is no successful serving evidence. Do not substitute another Qwen version or infer serving support from the display name. Any key must remain outside chat and repository files. Customer/application owner, two-engineer capacity, Linux host, serving availability, guard hardware and exact model revisions/licenses are unknown. Customer acceptance of language scope, data boundary, retention, capacity and latency is pending. No live data is authorized by these documents.

Ten weekdays from 19 October end on 30 October 2026 before holiday/leave adjustments. This is the supplied planning assumption, not a confirmed delivery commitment. No backlog item requiring real hardware, customer review, deployment or held-out quality evidence is complete merely because synthetic tests pass. In particular, the terminal-period repair is a reviewed regression fix, not evidence of general PII accuracy or pilot acceptance; true independent held-out data, native English/BM/Chinese classifier quality and customer acceptance remain open. Passport and bank-account recognition are deferred.
