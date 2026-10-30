# Project Nasi Lemak gateway

This repository contains a **real FastAPI HTTP gateway** plus the synthetic
in-process foundation it grew from. The HTTP surface is local and fail-closed.
Local guard/tokenizer wiring and one versioned YAML startup policy are
implemented, but **no pretrained guard checkpoint has been downloaded or
executed here** and the optional ML extra is not installed in this workspace.
An explicitly acknowledged test mode (`NASI_LEMAK_MODE=test` together with
`NASI_LEMAK_ALLOW_UNGUARDED_TEST=true`) and the prompt-testing page at `GET /`
exist; test mode keeps the model guards inactive and is not guarded mode. There
is no allow-all adapter or environment-selected bypass of guarded mode. The
upstream endpoint and model ID are operator configuration and were not
independently live-verified in this workspace. In the default guarded mode the
server therefore starts live and deliberately stays **not ready**, returning
generic `503` for chat until a valid operator-supplied policy file, locally
supplied guard artifacts, the configured model ID and PostgreSQL audit are
available. The acknowledged test mode can become ready without local guard
artifacts when policy, application auth, generation and audit configuration are
valid. Readiness checks configuration and audit structure only; it does not
prove model inference.

Docker Compose packaging is provided for a gateway + PostgreSQL audit stack,
including an optional guard-enabled pilot overlay (`compose.pilot.yaml`) that
selects a guard image target and mounts an approved policy plus local model
artifacts read-only. **No image has been built and no Compose stack has been
started in this workspace because Docker is not installed.** See
[Validation limits](#validation-limits).

## Status

| Area | State |
|---|---|
| `POST /v1/chat/completions` HTTP handling | Implemented locally, tested |
| Bounded body reading, strict JSON, auth, readiness | Implemented locally, tested |
| SQLite audit | Development/test only |
| PostgreSQL audit store | Implemented; optional integration tests skipped without `TEST_AUDIT_DSN` |
| Authenticated operator event view | Read-only `/admin` shell and `/admin/events` API implemented locally; optional separate reader config; PostgreSQL reader SQL checked with a driver double only |
| Bounded CSV export | `/admin/export.csv` implemented locally with a separate append-only export audit; contract in [docs/evidence-export.md](docs/evidence-export.md); PostgreSQL SQL checked with a driver double only |
| Versioned YAML startup policy | Strict loader, mandatory file activation, literal deny phrases and restart/rollback tests implemented locally |
| Real tokenizer / attack guard / output guard | Adapters and server wiring implemented locally; **pretrained weights not run** |
| API guard backend (input + output) | `NASI_LEMAK_GUARD_BACKEND=api` selects the API adapters in `nasi_lemak/guard_api.py`; the installer's `--guard-backend api` and the `compose.api.yaml` overlay expose the same explicit choice. Implemented and loopback-fixture-tested locally; **no live guard endpoint was contacted**, and real endpoint acceptance, model quality, latency and held-out capacity remain external work. See [docs/guard-api-integration.md](docs/guard-api-integration.md) |
| Guard evaluation harness | `nasi_lemak/guard_eval.py` validates a synthetic dataset by default and calls the configured adapters only with `--execute`; implemented and fixture-tested locally. This is plumbing evidence, **not** held-out model quality or OWASP coverage. See [docs/guard-evaluation.md](docs/guard-evaluation.md) |
| PII quality gate (synthetic) | Frozen agent-authored evaluation + deterministic evaluator; reviewed EMAIL terminal-period repair passes six known regression cases; v1 EMAIL fails on 1 frozen false positive and MyKad on 4; **not customer accepted**. See [docs/pii-quality.md](docs/pii-quality.md) |
| Postal address mask (synthetic) | Narrow ASCII single-line Malaysian shapes: numbered street + five-digit postcode, plus the same body without a postcode only when it directly follows `Address:`/`Alamat:`; unlabelled no-postcode forms stay raw. Admin input/output switches, new profiles default on; frozen corpora contain no address gold, so no address quality metric is claimed. See [docs/postal-address-mask.md](docs/postal-address-mask.md) |
| Generation transport | Implemented; not live-verified |
| Docker image / Compose runtime | Authored, **not built or run here**; default image/stack stays lightweight and safe-unavailable; optional `compose.pilot.yaml` adds the guard image target, policy and local model mounts as configuration scaffolding only |
| Employee workspace (`/workspace`) | Opt-in local subset for one organisation: username/password accounts, departments, encrypted saved conversations and explicit review grants. Store/HTTP/page tests pass locally; **real PostgreSQL, Docker, VM and guard acceptance remain pending**, and multi-customer/RAG/SSO/advanced department policy are deferred. Setup: [docs/workspace-setup.md](docs/workspace-setup.md) |
| Workspace admin policies and block alerts | Administrator-authored profiles with workspace → department → user full-profile override, immutable pinned revisions, effective-user preview and in-app per-administrator block alerts are implemented and store/HTTP tested locally. An existing schema 2 workspace requires the explicit schema 3 migration and grant reapplication. See [docs/admin-policies.md](docs/admin-policies.md) |
| LiteLLM routing | Deferred |
| TLS ingress | Not present; localhost HTTP by default; optional trusted-LAN demo proxy exists (`compose.demo.yaml`) |

This is not a completed day-2 milestone and not a production pilot. Dated
progress by timeline item, including code-versus-deployment evidence and the
latest test baseline, is in
[docs/development-progress.md](docs/development-progress.md).

Workspace administrator policies and in-app alerts are documented in
[docs/admin-policies.md](docs/admin-policies.md). The release changes only the
opt-in `/workspace` path: administrators may relax the two model-safety checks
or the `EMAIL`/`MY_PHONE`/`MYKAD`/`POSTAL_ADDRESS` masks for a scope, while authentication,
limits, literal deny phrases and audit ordering remain unconditional. The
legacy direct `/v1/chat/completions` path keeps its existing defaults. An
existing schema-2 workspace must complete the documented explicit schema-3
migration and reapply grants before the new gateway becomes ready; preserving
the database volume, key and mode overlays is mandatory.

## Local development

Use the workspace virtualenv:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m nasi_lemak.demo
.\.venv\Scripts\python.exe scripts/preflight.py
```

Ordinary test runs skip optional PostgreSQL cases when their DSNs are unset.
To run the explicit disposable PostgreSQL gate, provide the owner, administrator
and restricted runtime DSNs plus `TEST_WORKSPACE_DISPOSABLE=1` and
`TEST_AUDIT_DISPOSABLE=1`; the command fails clearly when any is missing rather
than reporting a skip as success. The workspace flag acknowledges that the
PostgreSQL privilege tests TRUNCATE every workspace row, so set it only for an
isolated disposable database; the owner DSN alone never authorises that action:

```powershell
$env:TEST_WORKSPACE_DISPOSABLE = "1"
$env:TEST_AUDIT_DISPOSABLE = "1"
.\.venv\Scripts\python.exe scripts/verify_postgres.py
```

See the script docstring for the exact variable names and synthetic example
values. Never point it at a shared database.

Run the server locally (it will be live but not ready without an explicitly
configured policy file, locally supplied guard artifacts and a configured
upstream model ID):

```powershell
.\.venv\Scripts\python.exe -m uvicorn nasi_lemak.server:app --host 127.0.0.1 --port 8000 --no-access-log
```

`pyproject.toml` is the canonical dependency definition. The `server` extra
pins the tested HTTP runtime (FastAPI 0.147.0, Uvicorn 0.54.0, psycopg 3.3.6
binary); the `test` extra adds HTTPX 0.28.1 and PyYAML 6.0.3.

## HTTP surface

Only these routes exist:

| Method | Path | Meaning |
|---|---|---|
| `GET` | `/` | Static prompt-testing page; served while the app is live and reports mode/readiness from `/health/ready` |
| `GET` | `/health/live` | Process liveness; `200 {"status":"ok"}` |
| `GET` | `/health/ready` | `200 {"status":"ready"}` only when configuration and audit readiness pass; otherwise `503 {"status":"not_ready"}` |
| `POST` | `/v1/chat/completions` | Bounded OpenAI-compatible chat request |
| `GET` | `/admin` | Static operator login/view shell only when optional operator config is valid; otherwise safe `404`/`503` |
| `GET` | `/admin/events` | Authenticated, read-only, filtered and paginated event metadata (operator key only) |
| `GET` | `/admin/export.csv` | Authenticated, bounded CSV snapshot of all rows matching the filters; append-only export audit before release |

There are no docs, OpenAPI, redoc, debug or trailing-slash routes.

Request rules:

- `Content-Type: application/json` exactly (parameters after `;` are ignored).
- Exactly one `Authorization: Bearer <application-key>` header.
- Body is streamed and bounded by actual bytes, independent of
  `Content-Length`; the default ceiling is 64 KiB (configured maximum 4 MiB).
- Invalid UTF-8, malformed JSON, duplicate keys, non-finite numbers, unknown
  fields, a non-`pilot-local` model, more than the configured context-message
  limit (default 32), or invalid roles/content all return a generic `400`.
- `POST /v1/chat/completions` accepts `stream: true` for OpenAI-compatible
  agent clients. One complete admission, guarded completion and terminal audit
  still run; only the already-masked released text is then sent as one-shot SSE
  (`text/event-stream`, `Cache-Control: no-cache`): an assistant-content chunk,
  a `finish_reason: stop` chunk and `[DONE]`. Nothing is emitted before the
  output guard passes. `stream_options` (object) and in-range numeric
  `temperature`/`top_p` are accepted and ignored, never forwarded upstream. Any
  non-200 outcome stays the unchanged JSON error envelope. The gateway itself
  remains strict: it still rejects `stream: true` when called directly.
- One complete body-read deadline applies; timeouts and overload return `503`.
- A separate, absolute server-owned chat work deadline starts when
  `Gateway.handle` is dispatched. `make_app(chat_work_timeout=...)` defaults to
  60 s (maximum 300 s); expiry returns the existing generic `503 UNAVAILABLE`
  with the HTTP `request_id`. The shielded worker keeps its chat admission slot
  until the real thread finishes, and any late result or error is consumed and
  never sent. Invalid values leave the app live but not ready, with chat
  unavailable and the safe 60 s default. This is an HTTP response deadline, not
  thread termination or a native model/guard/audit deadline.
- Missing/invalid auth returns `401`; attack/output guard blocks return `403`;
  oversized actual bytes, a serialized conversation over the configured context
  budget (default 8192 conservative units), or policy token budget returns `413`.
- Error bodies contain only a stable `code`, fixed generic `message` and
  `request_id`. Raw exception text, request content, credentials and DSNs are
  never returned or logged.
- Readiness performs cheap structural checks plus a bounded audit-store probe.
  It does not call the model or guard network endpoints.

The exact chat contract, including the unavailable-state semantics, is in
`docs/api-contract.yaml`.

### End-user CLI

`pip install .` also installs `nasi-chat`, a standard-library terminal client
for the `POST /chat` testing surface. It talks to exactly the endpoint you
give it (there is no localhost default) and never changes guard, audit or error
behaviour.

```powershell
$env:NASI_GATEWAY_URL = "https://guardrail.example"
$env:NASI_GATEWAY_TOKEN = "..."   # or leave unset to be prompted
nasi-chat                          # interactive; /quit or Ctrl-D exits
nasi-chat --prompt "What is the capital of Malaysia?"
nasi-chat --base-url https://guardrail.example --json --prompt "Hello"
```

`--base-url` (or `NASI_GATEWAY_URL`) is required and must be an absolute
`http`/`https` URL; `--timeout` defaults to 90 s. Each turn prints one status
line and then the released text:

- `ALLOW (200) · input: safe · output: safe · PII: masked|none · 21.4 s server · req_…`
- `BLOCK (403) · INPUT_GUARD_BLOCK · input: blocked · "…"`
- `ERROR (503) UNAVAILABLE: … · req_…`

`latency_ms` is served by `/chat` when the request's two audit rows both
exist and is taken from their own timestamps; otherwise the CLI labels the
measured client round trip. `--json` prints the raw reply JSON instead. ANSI
colour is used only on a TTY with `NO_COLOR` unset. One-shot exit codes are `0`
allowed, `1` blocked and `2` for a network, timeout, non-JSON or unexpected
status; the REPL reports the same errors and keeps running. The bearer token
is read from `NASI_GATEWAY_TOKEN` or prompted with `getpass` and is never
printed, logged, written or included in an error message. The PII column reads
`masked` when the returned sanitized prompt differs from the prompt sent.

Chat context and reply bounds use the four `NASI_LEMAK_CHAT_*` settings in
[docs/chat-limits.md](docs/chat-limits.md). The workspace keeps full saved
history but sends only a recent complete-pair window; the model may not remember
omitted older details.

## Operator event view

The optional operator view is a minimal, local, read-only HTML/JSON surface. It
is not a policy editor, approval workflow or chart dashboard. When
no operator configuration is present, both routes return the normal generic
`404` and chat is unaffected. Partial or invalid configuration returns a generic
`503`; an operator outage never makes chat unavailable.

| Variable | Meaning |
|---|---|
| `NASI_LEMAK_OPERATOR_KEY_DIGEST` | Lowercase 64-hex SHA-256 digest of one operator key. `_FILE` is supported. |
| `NASI_LEMAK_OPERATOR_AUDIT_DSN` | DSN for a separate SELECT-only reader role. `_FILE` is supported. |

The operator digest must differ from `NASI_LEMAK_APP_KEY_DIGEST`; configuring the
same digest disables the operator routes. `POST /v1/chat/completions` accepts only
the chat key, and `/admin/events` accepts only the operator key. There is no
default, sample or production key in source.

`/admin` returns static HTML/CSS/JS with no event, secret or runtime
configuration. The password-style token field is read by JavaScript; the token
stays in tab memory and is sent only as an `Authorization: Bearer` header to
same-origin `/admin/events`. It is never placed in a URL, cookie, local/session
storage or log. Disconnect and `pagehide` clear the token, rows and metadata
immediately and abort the in-flight request; a generation counter rejects late
success/error callbacks from an older connection. Event values are rendered with
`textContent`, never `innerHTML`. The shell includes decision/event-type/
request-ID filters, `Next`/`Previous` paging (cursor history stays in memory), the
active policy version/digest and a health status. A `request_started` row shows
the pending decision recorded by that start event; the table does not infer that
the request is still incomplete, because its final outcome may be in a later
event or another page. Both routes send `Cache-Control: no-store`, a hash-based
restrictive CSP (no `unsafe-inline`, `eval`, remote origin or framing), `nosniff`,
frame denial and same-origin resource policy, with no CORS.

`/admin/events` authenticates before any read and uses a separate reader
boundary, never `Gateway.audit_events()` or the runtime writer store/DSN. The
reader is SELECT-only, scopes every page to the trusted server-side `app_id`,
uses fixed SQL identifiers and parameterised values, a positive `seq` keyset
cursor, `LIMIT` at most 100 with a fetch of `limit + 1`, and bounded
decision/event-type/request-ID filters. PostgreSQL uses lazy `psycopg`, a bounded
connect timeout, `statement_timeout` and `default_transaction_read_only=on`, then
closes the connection. Responses contain only an allowlisted metadata shape plus
`has_more`, `next_cursor`, current policy version/digest and health; DSNs, raw
rows and driver errors are never returned. Reader failures return generic `503`
metadata only. The separate `/admin/export.csv` route reuses the operator key but
runs its own strict query parser, one bounded snapshot and an append-only export
audit; its caps, CSV format and failure modes are in
[docs/evidence-export.md](docs/evidence-export.md). Count aggregation is not
implemented.

For a local browser check, the synthetic fixture binds only `127.0.0.1` and
prints its explicit synthetic key at startup:

```powershell
.\.venv\Scripts\python.exe scripts/operator_demo.py --port 18789
```

It writes 127 synthetic rows (126 scoped demo events plus one unrelated-application
row), with `req_demo_01`–`req_demo_03` first and then filler requests, so the
default 50-row page has `Next`/`Previous` pages. It also includes one harmless
`<img ...>` metadata string to exercise escaping. Optional
`--reader-delay SECONDS` (bounded to 30) and `--reader-unavailable` switches
exist only in this synthetic script for caller race/outage checks; they are not
runtime environment configuration. The fixture passes `environ={}` explicitly,
so it never reads process environment or `*_FILE` secret paths. It is not
production evidence and must not be deployed.

Browser qualification includes a caller check in an IAB host on port 18789: the
synthetic fixture's 50-row page displayed 50 rows, and `Export matching events`
produced an actual `nasi-lemak-events-export.csv` download. The caller parsed
126 data rows and 13 columns, all scoped to `synthetic-operator-demo`, with
canonical filters `decision=*;event_type=*;request_id=*` and SHA-256
`38e37eeb5c1923d7ed97867ad073596616487f305a0095cd8ab2b9dd7c8ba84e`; this is
synthetic browser-download evidence only. Delayed-reply/stale-response race,
outage and escaping behaviour remain unexercised by the caller browser. Local
tests exercise the inline JavaScript with Node.js plus a deterministic DOM and
deferred fetch, not a browser engine or CSP execution. For a real setup, provision the
`nasi_lemak_audit_reader` NOLOGIN group from `audit_roles.sql`, then have an
administrator create a separate LOGIN reader outside this repository, for
example:

```sql
CREATE ROLE nasi_lemak_operator LOGIN IN ROLE nasi_lemak_audit_reader;
\password nasi_lemak_operator
```

Write that role's DSN only through `NASI_LEMAK_OPERATOR_AUDIT_DSN_FILE` or an
approved secret manager. Never reuse the runtime writer DSN, a chat key or a
default password. The default `compose.yaml` leaves the operator feature
disabled. The optional `compose.pilot.yaml` overlay supplies a distinct
operator-key digest secret and a separate reader DSN secret; it still does not
prove a live PostgreSQL reader deployment.

## Startup policy

The production server requires one operator-supplied policy file:

| Variable | Meaning |
|---|---|
| `NASI_LEMAK_POLICY_FILE` | Path to one UTF-8 YAML policy file, read once while the app is constructed |

`docs/policy.example.yaml` is a non-secret example of the exact canonical form.
The loader requires these five keys and accepts one optional `limits` mapping:

```yaml
app_id: nasi-lemak            # must equal the server-side app id
version: "2026-10-20.1"       # non-empty audit/version string
model: pilot-local            # the only accepted public alias
token_budget: 256             # integer 1..512
deny_phrases:                 # up to 64 non-empty strings, 256 chars each
  - "synthetic denied phrase"
limits:                       # optional; may only tighten env/default ceilings
  default_reply_tokens: 384
```

Each `limits` field (`context_messages`, `context_budget`,
`default_reply_tokens`, `max_reply_tokens`) must be a positive integer. The
effective value is the smaller of the environment/default ceiling and the policy
value, so a policy can never widen a limit; above-ceiling values are clamped.
When the key is omitted the policy digest is unchanged. See
[docs/chat-limits.md](docs/chat-limits.md) for precedence.

The file must contain exactly one YAML document, no anchors, aliases or custom
tags, no duplicate keys, at most 8 nested collections and at most 32 KiB. An
explicitly injected `Policy`/`Gateway` is a Python test seam only, not a runtime
mode.

Activation is construction-time only. To activate a new version, an operator
copies an approved file to a **preserved** path outside version control, points
`NASI_LEMAK_POLICY_FILE` at it and performs a controlled restart. The previously
approved file is never overwritten, so a rollback selects that preserved file
and restarts again. There is **no hot reload, in-process editor, database policy
management or approval mechanism**; approval is an operator procedure, and the
gateway only enforces the file it was started with.

A missing, unreadable, oversized, malformed or otherwise invalid file makes the
app live `200` but not ready `503`, and chat stays `503`; it never falls back to
built-in defaults and never loads guard artifacts. A valid file's `version` and
SHA-256 policy `digest` are recorded in `app.state` and on every audit event for
the active policy. The digest covers the app identity, version, alias, token
budget, deny phrases and, when present, the optional `limits` mapping.

`deny_phrases` are **literal, case-insensitive substrings** checked against every
accepted input turn before generation and against buffered output before
release. They are not a regex and not a semantic topic filter. No policy value
can disable the three mandatory PII masks (email, Malaysian phone, MyKad), the
attack guard, the contextual output guard or the audit-before-release ordering.

## Generation transport

The OpenAI-compatible client is configured only from server-side environment
variables; no URL, key, cloud fallback or proxy is inferred. Non-loopback plain
HTTP requires the explicit
`NASI_LEMAK_GENERATION_ALLOW_INSECURE_HTTP=true` opt-in, and TLS verification
is never disabled. See `docs/generation.env.example` for a non-secret example.

The supplied endpoint is:

```text
http://82haf69n.flexinfra.com.my/v1
```

Here `/v1` is an **assumed** OpenAI-compatible prefix, not a live-verified fact.
The supplied endpoint uses **no authentication** (`NASI_LEMAK_GENERATION_AUTH=none`),
requires the explicit insecure-HTTP opt-in, and the exact served model ID is
operator configuration. Set `NASI_LEMAK_GENERATION_MODEL` to the confirmed
upstream identifier before generation or probes can succeed; do not use the
display name `Qwen3.8 27B FP8` as an API model ID. No successful serving, model
listing or inference has been demonstrated in this workspace; operator-reported
VM generation was not independently verified here.

If a reasoning-style model returns empty or whitespace `content` because its
budget was spent on hidden reasoning, the client rejects it with the generic
`generation endpoint returned no text content`. It never reads or returns
`reasoning_content`, does not retry and does not increase the request budget.
Use an adequate `max_tokens` (the default maximum reply is 4096 tokens and the
configurable ceiling is 8192; see [docs/chat-limits.md](docs/chat-limits.md)) and a
provider model that returns ordinary assistant content. See
[docs/hosted-guard-setup.md](docs/hosted-guard-setup.md) for the deployment
troubleshooting note.

An earlier `GET .../v1/models` attempt timed out on port 80. No further live
network checks are made in this workspace.

The optional API guard backend in `nasi_lemak/guard_api.py` is selected only by
`NASI_LEMAK_GUARD_BACKEND=api` in guarded mode; the installer and the
`compose.api.yaml` overlay expose the same explicit choice. It is implemented and
loopback-fixture-tested locally, but no live guard endpoint or pretrained API
model was contacted here. Real endpoint acceptance, model quality, latency and
held-out capacity remain external work. See
[docs/guard-api-integration.md](docs/guard-api-integration.md) for the contract
and [docs/guard-evaluation.md](docs/guard-evaluation.md) for the synthetic
evaluation harness.

## Local guard wiring

`nasi_lemak/server.py:make_adapters_from_env` composes the local guard adapters
with the generation client. The default loaders are lazy: the module imports
`torch`/`transformers` only when a model is actually loaded, so the gateway and
the main test suite run without the optional ML extra. The interfaces and
limitations are documented in [`docs/guards.md`](docs/guards.md).

Required guard settings (all must be supplied; there is no default Hub ID,
download or demo adapter):

| Variable | Meaning |
|---|---|
| `NASI_LEMAK_PROMPT_GUARD_MODEL_DIR` | Existing local Prompt Guard 2 directory (tokenizer, config, safetensors). Also used as the input tokenizer. |
| `NASI_LEMAK_LLAMA_GUARD_MODEL_DIR` | Existing local Llama Guard 3 directory (tokenizer, config, safetensors). |
| `NASI_LEMAK_PROMPT_GUARD_THRESHOLD` | Finite malicious-probability threshold in `[0, 1]`; uncalibrated. |
| `NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT` | Integer context budget of at least 33; the guard reserves 32 verdict tokens inside it. |

The existing `NASI_LEMAK_GENERATION_*` settings are validated first. Every load
uses `local_files_only=True`, `trust_remote_code=False`, `token=False` and
safetensors weights; model files must already exist locally. No network access,
Hub resolution, cache fallback or customer path/secret is emitted. An invalid
or missing setting, unreadable directory, missing dependency or load failure
returns no adapters, so the app stays live `200` / ready `503` and chat `503`.

Behavior preserved by this wiring:

- Input coverage tokenizes the **complete original canonical conversation** with
  the actual Prompt Guard tokenizer (`add_special_tokens=True`,
  `truncation=False`). More than the 512-token budget returns `413` before
  generation.
- Output screening passes the **complete current-request sanitized conversation**
  plus the buffered model output to `scan_response(messages, output)`. The
  real adapter requires that contextual method; a context-free call fails
  closed. Synthetic test adapters may still use the legacy `scan_output(text)`
  fallback.
- The terminal audit write still precedes any response release; guard, audit or
  malformed-verdict failures release no output.

The user/operator must obtain license-approved weights independently and install
the optional extra when ready:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[guards]"
```

This workspace has **not** run that install. The exact pins in
`pyproject.toml` were only checked against PyPI metadata and their mutual
compatibility is untested. Real pretrained inference, quality, false-positive
rates and CPU memory/latency are unmeasured. The native model forward path has no
hard preemptive deadline, so process-isolated serving, outage behavior and
performance evidence remain required.

The bounded chat work deadline is likewise an HTTP response deadline only. Input
guard, generation, output guard and terminal audit can continue in the shielded
worker after the client receives `503`; the admission slot is released only when
that real call returns. Audit records therefore describe server-side processing
and are not proof that the client received a response. No process isolation,
thread termination, upstream-call cancellation or native hard deadline is added
or claimed.

**Compose guard profile:** the default `Dockerfile`/`compose.yaml` install only
the `server` extra and mount no guard weights, so the default stack remains
safely unavailable. The optional `compose.pilot.yaml` overlay selects the
`guards` Dockerfile target and mounts an operator-approved policy plus two local
model directories read-only. That is configuration scaffolding only: no guard
image, weight download, native inference, classifier accuracy or warmup has
been verified here.

## PII quality evaluation (synthetic)

`evals/pii/` freezes agent-authored, versioned synthetic fixtures with explicit
gold spans, plus a SHA256 manifest. `nasi_lemak/pii_eval.py` runs the actual
production recognizers through the shared span function used by `mask_pii` and
writes metadata-only reports under `evals/pii/results/`:

```powershell
.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --split evaluation
.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --root evals/pii/reviewed-labels-v2
```

The current v1 evaluation split has 61 cases (58 evaluated, 3 explicitly
unsupported), 16 EMAIL, 17 MY_PHONE and 15 MYKAD gold entities. Caller review
reproduced a privacy gap where an address followed by a sentence period stayed
unmasked. A narrow reviewed repair of only the EMAIL right boundary keeps the
period in the output while masking the address.

Caller-agent label adjudication produced a separate reviewed v2 corpus that
corrects exactly one disclosed annotation error: v1 `EV-EMAIL-014` labelled a
sentence-final address as non-PII. V2 scores EMAIL 17 TP / 0 FP / 0 FN
(1.0000/1.0000) and MY_PHONE 1.0000/1.0000, but MyKAD still has four labelled
false positives (order ID, SKU, part number and an overlong phone-like value
that also matches 12 digits), so precision is 0.7895/1.0000 and the v2 CLI
still exits `1`. The v1 raw score (EMAIL 16 TP / 1 FP / 0 FN) is retained but
is annotation-conflicted and is not a reliable current EMAIL quality score.

The separate six-case caller-review corpus exits `0`, but both reviewed
corpora are known-regression evidence, not unseen or independent hold-out sets.
Preserved `before-email-fix` reports retain the original failing evidence. This
is synthetic format-recognizer evidence only, not an independent human hold-out
set, population metric, privacy audit or customer acceptance.

The frozen corpora contain no `POSTAL_ADDRESS` gold, so that entity reports
`not_applicable` and contributes no address quality metric. The overall gate
excludes `not_applicable` entities but still requires at least one applicable
entity and still fails on any applicable failure; fixture bytes, thresholds and
known MyKad false positives are unchanged. Postal scope, admin switch behavior
and limitations: [docs/postal-address-mask.md](docs/postal-address-mask.md).

Full method, labels, hashes, adjudication and limits:
[docs/pii-quality.md](docs/pii-quality.md). Language boundary:
[docs/language-support.md](docs/language-support.md).

## Docker Compose packaging

`Dockerfile`, `compose.yaml`, `.dockerignore` and `docs/compose.env.example`
provide a two-service stack:

- `db`: PostgreSQL, no host-published port, named persistent volume
  `nasi_lemark_db`, container healthcheck.
- `gateway`: built from the minimal image, non-root UID 10001, read-only root
  filesystem with a small `/tmp` tmpfs, all capabilities dropped,
  `no-new-privileges`, memory/CPU/PID limits, and `127.0.0.1:8000` published by
  default. It waits for `db` to become healthy.
- PostgreSQL is attached only to an **internal** network. The gateway is also
  on the default bridge so it can reach the external model endpoint.

For the step-by-step installer procedure on an existing Ubuntu 24.04 amd64 VM,
including test-mode setup, admin access and guard activation, see
[docs/install-ubuntu.md](docs/install-ubuntu.md).

The image copies only `pyproject.toml` and `nasi_lemak/`; it installs the
`server` extra, packages the `.sql` bootstrap files, and runs:

```text
uvicorn nasi_lemak.server:app --host 0.0.0.0 --port 8000 --workers 1 --no-access-log
```

No reload, debug worker, Docker socket, privileged mode or access log.

The `Dockerfile` is multi-stage. `base` installs the tested `server` extra,
copies only `pyproject.toml` and `nasi_lemak/`, and then drops to UID/GID 10001.
`guards-deps` is the only stage that adds the existing pinned `guards` extra and
temporarily uses root for pip; both `guards` and the final `server` runtime
stages return to 10001. Because `server` is the last stage, a plain
`docker build .` and the default `compose.yaml` never install the optional ML
dependencies. No stage copies model weights; the image and pilot overlay set
`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1` and `HF_DATASETS_OFFLINE=1`.

`compose.pilot.yaml` is an opt-in overlay that must be applied together with
the base file, never alone. It:

- builds the `guards` target;
- mounts an operator-approved policy at `/run/pilot/policy/policy.yaml`, plus
  Prompt Guard 2 and Llama Guard 3 directories under `/models/`, all read-only
  using long bind syntax with `create_host_path: false`; a missing host path
  aborts instead of being auto-created;
- sets the matching `NASI_LEMAK_POLICY_FILE`, guard-directory, threshold and
  context variables. The initial threshold `0.5` and context limit `4096` are
  explicit provisional values (overridable in the pilot env file) and are not
  calibrated or benchmarked;
- adds distinct `operator_key_digest` and `operator_audit_dsn` file secrets for
  the admin/export reader. The runtime writer keeps the base `audit_dsn`;
- sets a provisional 8 GiB / 4 CPU / 512 PID budget, separate from the
  lightweight 512 MiB / 1 CPU default. These limits are not benchmarked, and
  native adapters are CPU-only in this repository (no GPU claim);
- adds a standard-library Python healthcheck against the real
  `/health/ready` endpoint with a finite request timeout and a model-loading
  start period. The probe uses a 7 s request timeout inside an 8 s Compose
  healthcheck timeout, so it outlasts the server's 5 s internal readiness
  deadline while every wait stays finite. It checks structural readiness, not
  classifier accuracy or native warmup.

`compose.demo.yaml` is a separate **optional** overlay for a trusted-LAN demo.
It adds an unprivileged `nginx:stable-alpine` proxy on port `8080` that forwards
the complete URI, query string and `Authorization` header to `gateway:8000`;
there is no static frontend, path prefix, CORS or new authentication. It
requires an explicit `DEMO_BIND_IP` (no `0.0.0.0` default) from a git-ignored
`.secrets/compose.demo.env`, joins only the default bridge network, mounts no
secrets and leaves the base `127.0.0.1:8000` publication and unpublished
database unchanged. It is plain HTTP for a trusted LAN/VPN only, uses a mutable
image tag, and is not TLS ingress. The synthetic tests parse configuration
only; VM acceptance is pending. See
[docs/demo-access.md](docs/demo-access.md) for the no-reinstall update
procedure, firewall checks and rollback.

### Guard-enabled pilot overlay runbook (Linux)

This procedure was authored but **not executed here**; Docker is absent from
this workspace. It is not deployment evidence. Use a reviewed commit and a
Linux host with Docker Engine plus Compose v2 supporting long bind syntax.

1. Clone the repository and enter it. Create two local env files from the
   samples; the pilot file is additional, not a replacement:

   ```bash
   git clone <reviewed-remote> ai-guardrails
   cd ai-guardrails
   mkdir -p .secrets
   cp docs/compose.env.example .secrets/compose.env
   cp docs/compose.pilot.env.example .secrets/compose.pilot.env
   chmod 600 .secrets/compose.env .secrets/compose.pilot.env
   ```

   Edit both files locally. Do not add the pilot file's paths to the base file
   or copy generation/model settings into the pilot file; later `--env-file`
   entries win and could unexpectedly override them.

2. Create the five secret **files** with an approved secret manager or secure
   editor: `db_admin_password`, `audit_dsn` (runtime writer), `app_key_digest`,
   `operator_key_digest` and `operator_audit_dsn`. The operator digest must
   differ from the application digest, and the reader DSN must differ from the
   writer DSN. Never put a secret value in a shell command, chat, Git or shell
   history. The container UID/GID 10001 must be able to read the host secret
   files; Compose local file secrets are host files, and this project makes no
   claim that Compose uid/gid/mode remapping works.

3. Start only PostgreSQL from the base stack first, before any heavy guard
   image build, and wait for its healthcheck:

   ```bash
   docker compose --env-file .secrets/compose.env up -d db
   docker compose --env-file .secrets/compose.env ps
   ```

   The mounted `audit_schema.sql` and `audit_roles.sql` run only on an empty
   data volume. They create the schema and NOLOGIN group roles, not LOGIN roles
   or passwords. Never delete a live volume to rerun bootstrap.

4. Provision separate writer and reader LOGIN roles with **interactive**
   `\password` (never a password on the command line or in history):

   ```bash
   docker compose --env-file .secrets/compose.env exec db \
     psql -U <admin-user> -d nasi_lemak
   ```

   ```sql
   CREATE ROLE nasi_lemak_gateway LOGIN IN ROLE nasi_lemak_audit_writer;
   \password nasi_lemak_gateway
   CREATE ROLE nasi_lemak_operator LOGIN IN ROLE nasi_lemak_audit_reader;
   \password nasi_lemak_operator
   ```

   The writer group may insert events and append export-audit metadata; the
   reader group may select events only and deliberately has no
   `export_audits` access. Write each role's DSN directly to its local secret
   file with the approved editor; do not echo it. The administrator DSN is not
   mounted into the gateway.

5. Prepare the policy and model mounts. Copy an operator-approved versioned
   policy to a preserved host path and point `PILOT_POLICY_FILE` at it. Obtain
   license-approved Prompt Guard 2 and Llama Guard 3 artifacts independently,
   point the two `PILOT_*_MODEL_DIR` variables at their complete directories,
   and ensure UID/GID 10001 can read and traverse them. Also set the **actual**
   provider model ID in `NASI_LEMAK_GENERATION_MODEL` in the base env file; it
   remains blank by default and fails closed. `/v1` is still an assumed
   OpenAI-compatible prefix. No model download, model license or software
   license approval is implied by this repository.

6. Render and inspect the overlay configuration. This does not start or build
   anything:

   ```bash
   docker compose \
     --env-file .secrets/compose.env \
     --env-file .secrets/compose.pilot.env \
     -f compose.yaml -f compose.pilot.yaml config
   ```

   Confirm the three read-only mounts, distinct secrets, localhost-only port,
   private database network and provisional resource limits.

7. Build and start the pilot profile:

   ```bash
   docker compose \
     --env-file .secrets/compose.env \
     --env-file .secrets/compose.pilot.env \
     -f compose.yaml -f compose.pilot.yaml up -d --build gateway
   ```

8. Check liveness, readiness and negative cases:

   ```bash
   curl -fsS http://127.0.0.1:8000/health/live
   curl -i http://127.0.0.1:8000/health/ready
   ```

   `200 {"status":"ready"}` means only that the configured structure and audit
   store passed readiness. It is **not** classifier accuracy, native model
   warmup or proof of guarded inference. A `503 {"status":"not_ready"}` while
   policy, model artifacts, audit or the model ID are pending is the expected
   safe state, not a deployment success. A missing policy/model host path
   should abort the mount because `create_host_path: false`; it must not be
   auto-created. When operator configuration is present, `GET /admin` is a
   public static login page and returns `200` without credentials.
   `GET /admin/events` and `GET /admin/export.csv` require an
   `Authorization: Bearer` operator key and return a generic `401` when it is
   missing or wrong.

9. To update, preserve the previous approved policy under its old path, write a
   new version to a new path, change `PILOT_POLICY_FILE` and restart the
   gateway. To roll back, restore the previous env value/path and restart. For
   an image rollback, rebuild the reviewed commit/tag; no database volume
   removal is needed for either policy or image rollback.

10. Stop without deleting data:

    ```bash
    docker compose \
      --env-file .secrets/compose.env \
      --env-file .secrets/compose.pilot.env \
      -f compose.yaml -f compose.pilot.yaml down
    ```

    Never use `down -v` on a live system. TLS ingress is still required before
    any remote access; this profile remains localhost-only HTTP. Do not send
    browser or vendor cloud traffic as part of this pilot setup.

### Operator runbook

Never place a password, DSN containing a password, application key or digest
value in chat, shell history, Git or the repository. Use `.secrets/` locally
(ignored by Git and Docker) and an approved secret manager for the real key.

1. Create a local env file from the sample and replace every
   `/ABSOLUTE/PATH/...` placeholder:

   ```powershell
   New-Item -ItemType Directory -Force .secrets | Out-Null
   Copy-Item docs/compose.env.example .secrets/compose.env
   ```

2. Create the three secret files with an approved password manager or secure
   prompt, **not** by echoing secrets into a command:

   - `db_admin_password`: PostgreSQL administrator password (no trailing
     newline).
   - `audit_dsn`: one runtime writer DSN, never the administrator DSN. Create
     the path as an empty placeholder before the first `config`/`up db` (the
     gateway is not started yet); fill in the real DSN after step 5.
   - `app_key_digest`: lowercase 64-hex SHA-256 digest of the application key.

   `POSTGRES_ADMIN_USER` is a non-secret name. The sample paths do not exist,
   so a copied-but-unedited env file fails instead of starting with a default
   credential.

3. Render and inspect the configuration (this does not start anything):

   ```powershell
   docker compose --env-file .secrets/compose.env config
   ```

4. Start PostgreSQL and wait for health:

   ```powershell
   docker compose --env-file .secrets/compose.env up -d db
   docker compose --env-file .secrets/compose.env ps
   ```

   The mounted `audit_schema.sql` and `audit_roles.sql` run **only when the data
   volume is empty**. They create the schema and NOLOGIN group roles, not a
   runtime LOGIN role and not any password. **Never delete a live database
   volume to rerun bootstrap.** For an existing volume, apply the SQL manually
   with administrator credentials.

5. Provision the runtime LOGIN role in the `nasi_lemak_audit_writer` group, then
   set its password interactively with `\password` (it is not echoed):

   ```powershell
   docker compose --env-file .secrets/compose.env exec db psql -U <admin-user> -d nasi_lemak
   ```

   ```sql
   CREATE ROLE nasi_lemak_gateway LOGIN IN ROLE nasi_lemak_audit_writer;
   \password nasi_lemak_gateway
   ```

   Write the corresponding DSN to the local `audit_dsn` file without printing
   it:

   ```text
   postgresql://nasi_lemak_gateway:<password>@db:5432/nasi_lemak
   ```

6. Start the gateway:

   ```powershell
   docker compose --env-file .secrets/compose.env up -d gateway
   ```

7. Check status and endpoints:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:8000/health/live
   Invoke-WebRequest http://127.0.0.1:8000/health/ready
   ```

   With the default Compose file, live is `200` and ready/chat are `503`. That
   is **intentional safe startup**, not successful guarded inference: the
   default image does not install the optional guard ML dependencies, does not
   mount local guard model directories, no policy file is mounted or configured,
   and the upstream model ID and local guard artifacts are not configured in
   that example. The PostgreSQL DSN and app digest
   alone do not make inference ready. The optional `compose.pilot.yaml` overlay
   and the pilot runbook above add the guard image target, read-only policy/model
   mounts and distinct operator secrets; that is authored configuration, not a
   verified deployment.

8. Stop without deleting data:

   ```powershell
   docker compose --env-file .secrets/compose.env down
   ```

   `down -v` deletes the database volume; never use it on a live system.

The DB administrator password is mounted as a Docker secret and read through
`POSTGRES_PASSWORD_FILE`; it is not plaintext in the environment. The runtime
audit DSN and application-key digest use the server's
`NASI_LEMAK_AUDIT_DSN_FILE` and `NASI_LEMAK_APP_KEY_DIGEST_FILE` file-backed
variables. The administrator DSN is not used by the gateway.

## Security and operational limits

The server's operational bounds can be set through optional environment
variables. An explicit `make_app` argument still wins (tests rely on it); the
environment applies when no argument is given, and the built-in default applies
otherwise. An explicitly configured invalid or out-of-range value makes the app
live but not ready, and the value is never echoed.

| Variable | Meaning | Range | Default |
| --- | --- | --- | --- |
| `NASI_LEMAK_CHAT_WORK_TIMEOUT` | Chat work deadline in seconds | 1–300 | 60 |
| `NASI_LEMAK_CHAT_MAX_CONCURRENCY` | Admitted chat requests | 1–256 | 5 |
| `NASI_LEMAK_CONTROL_CONCURRENCY` | Control-plane work slots | 1–64 | 2 |
| `NASI_LEMAK_MAX_BODY_BYTES` | Request body limit in bytes | 1024–4194304 | 65536 |
| `NASI_LEMAK_BODY_READ_TIMEOUT` | Body read timeout in seconds | 0.5–60 | 5.0 |

The resolved values are read-only in the authenticated `/admin/events` payload
under `operational`.

- The gateway is localhost-only HTTP by default. **TLS ingress is required before
  any remote pilot.** The separate optional demo proxy is plain HTTP on a
  trusted LAN/VPN only and does not satisfy that requirement.
- SQLite remains a local development/test store only. The production server
  requires PostgreSQL, and its runtime role is append-only.
- There is no background reconciler. Incomplete request records are reconciled
  only through an explicit offline call (`Gateway.reconcile_incomplete(offline=True)`)
  after stopping all gateway writers.
- PII masking uses experimental ASCII format recognizers. A frozen
  agent-authored synthetic evaluation appears in
  [docs/pii-quality.md](docs/pii-quality.md); a reviewed EMAIL terminal-period
  repair passes six known regression cases, but the v1 EMAIL gate fails on one
  frozen false positive and the MyKad gate on four. This is not independent
  held-out or customer evidence, and semantic PII plus BM/Chinese guard
  protection is not established ([docs/language-support.md](docs/language-support.md)).
  The measured ASCII fixtures do not mean every non-ASCII character is rejected:
  preserved Python regexes use Unicode `\d` and `IGNORECASE`.
- LiteLLM routing is deferred. No streaming, tools or multimodal input exists,
  and the startup YAML policy still has no editor, hot reload, database policy
  management or approval workflow. Its activation is one validated file
  selected server-side and read at construction; a controlled restart is the
  only activation/rollback mechanism. The separate workspace administrator
  policy profiles in [docs/admin-policies.md](docs/admin-policies.md) can
  change only per-user workspace model checks and PII masks, take effect on the
  next workspace turn and cannot modify the startup YAML policy or the legacy
  direct API. The optional `/admin` event view remains read-only and cannot
  change policy.
- No live-data approval or deployment exists.

## Validation limits

At packaging time Docker was absent from `PATH`. Therefore the Dockerfile was
not built, `compose.yaml` was not run, and `docker compose config` was not
executed. YAML and Dockerfile were reviewed statically; Python tests and a
local ASGI liveness check were run from the existing virtualenv. Image tags are
conservative version tags (`python:3.12-slim-bookworm`,
`postgres:16.4-bookworm`); immutable image digests, registry signature
verification and a full release security review remain pending. No digest was
invented. The optional `compose.pilot.yaml` overlay and the `guards` image
target it selects are authored but unverified: the overlay has not been resolved
by `docker compose config`, the guard image has not been built, and no Compose
stack has been started, so Docker configuration, build and startup remain
unverified.

The supplied test-host specification — Ubuntu 24.04, x86-64, 8 vCPU, 32 GiB
RAM, 100 GB SSD — is recorded as provisional sizing information for the
86M-parameter prompt guard plus 1B-parameter output guard running on CPU with
remote Qwen generation. It is not a benchmark or capacity claim; nothing was
executed on that host.

The prior-slice baseline was **414 tests: 412 passed and 2 skipped** (dated
prior slice; `TEST_AUDIT_DSN` unset). The final release suite is run before push
and its result is recorded in `docs/development-progress.md`; this README does
not claim a current total. The two skips
are the existing optional PostgreSQL
integration tests, skipped honestly because `TEST_AUDIT_DSN` is not set; no
PostgreSQL round-trip was run and no residual skip was added for the export or
PII work. Older `340`, `339`, `315`, `283`, `271`, `249` and `226` counts are
stale. A SQLite test-helper
close race that intermittently raised `WinError 32` on Windows was fixed in the
helper itself.

The focused PII span/evaluator suites contain 33 tests; the assembled ASGI
enforcement suite has 7. New regressions cover an email at EOF with a period,
period then whitespace, closing parenthesis, comma/question mark, a valid longer
domain, and invalid dotted/double-dot suffixes that must not be partially
masked. An ASGI/HTTP test proves the sent email is absent from the captured
upstream body while the period is retained, the full original context still
reaches the attack guard, the buffered reply is masked for the client and the
terminal audit remains metadata-only. The v1 evaluation CLI exits `1` for its
truthful EMAIL and MyKad gate failures; the review CLI exits `0`. Reports contain
no raw fixture text and are byte-reproducible. Only the narrow EMAIL right
boundary changed; no threshold, label, fixture or scope was altered to force a
pass.

Task 12's export path is locally verified: 23 ASGI export tests over the real
app with real SQLite audit rows, plus 10 Node.js behaviour cases for the
operator shell. PostgreSQL export-audit SQL is checked with a driver double
only; no PostgreSQL server, Docker runtime or native model was exercised. A
caller IAB run of the synthetic fixture produced a browser download; contract:
[docs/evidence-export.md](docs/evidence-export.md). Guard
tests use deterministic inference doubles, not pretrained weights; policy tests
use temporary files and local SQLite/model doubles. Operator tests use real
SQLite audit rows and the actual ASGI app; PostgreSQL reader SQL/parameter
construction is checked with a driver double only, not a live PostgreSQL server.
The operator-shell lifecycle tests extract the real inline script and run it
with the local Node.js runtime, a minimal deterministic DOM and deferred fetch
replies; that is JavaScript behaviour evidence, not browser/CSP execution.

`tests/test_enforcement_integration.py` adds assembled-path checks over the real
ASGI app, YAML policy, gateway, real generation client against a loopback HTTP
fixture and real SQLite audit. Captured upstream requests, audit rows, release
behaviour and fail-closed ordering are asserted; guard/tokenizer verdicts remain
deterministic doubles, so this is not native classifier or live-endpoint
evidence. See [docs/control-verification.md](docs/control-verification.md).

## References

Official documentation consulted for this packaging:

- FastAPI container deployment: <https://fastapi.tiangolo.com/deployment/docker/>
- psycopg 3 transaction management: <https://www.psycopg.org/psycopg3/docs/basic/transactions.html>
- Docker Compose startup order and healthchecks: <https://docs.docker.com/compose/how-tos/startup-order/>
