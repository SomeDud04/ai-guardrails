# Execution ledger

Date: 20 October 2026. Mode: local foundation with real generation transport,
local guard wiring, strict YAML policy activation and a bounded HTTP server;
live-data pilot: **disabled / not approved**. Docker packaging is authored but
**not built or run here**.

## Source provenance

External originals were read without editing:

| File | SHA256 at start |
|---|---|
| `C:\Users\user\Desktop\ai-workspace\tasks\plan.md` | `09E908AF3B748E8CDCA9A42A8359A9508164E67C3F2A36B7471764CD29254CA7` |
| `C:\Users\user\Desktop\ai-workspace\tasks\todo.md` | `8C859AC0309F94D4A2E1DC0899DADC9D9478D3E8F4136892D4277FAF348F0913` |

No ancestor `AGENTS.md` was found above the workspace at the time of the initial
slice; the current project-level `AGENTS.md` governs dual-harness routing. The
requested Sol/Luna workflow used one Sol planner/reviewer and one Luna
implementation worker. No secrets or customer text were used. No dependencies,
models or services were installed or deployed, and no external inference call
was made in this packaging stage.

## Current evidence

The deliverable now includes a real FastAPI ASGI application
(`nasi_lemak/server.py`), the in-process gateway/audit boundary, a synthetic
demonstration path, a generation transport client, SQLite development tests,
optional PostgreSQL integration tests, a strict versioned YAML startup policy,
and Docker Compose packaging.

The HTTP surface is local and fail-closed:

| Route | Behavior |
|---|---|
| `GET /health/live` | `200 {"status":"ok"}` while the process runs |
| `GET /health/ready` | `200` only when config, all four adapter callables, app-key digest, policy alias and bounded audit readiness pass; otherwise `503` |
| `POST /v1/chat/completions` | Strict bounded request; generic `400/401/403/413/503` envelopes |
| `GET /admin` | Static authenticated operator shell; optional config absent `404`, invalid `503` |
| `GET /admin/events` | Operator-key-only, read-only, filtered/paginated event metadata; generic errors |

There are no docs, OpenAPI, redoc, debug or trailing-slash routes. The request
body is read as a stream with one absolute deadline and a byte ceiling that does
not trust `Content-Length`. Duplicate JSON keys, non-finite numbers, invalid
UTF-8, wrong media type, multiple/absent authorization headers, unknown fields
and policy overrides fail before any adapter or audit call. Raw exception text,
request content, credentials and DSNs are not returned or logged.

### Complex timeout and cancellation repair

The complex HTTP stage combines body streaming, admission control, worker-thread
dispatch and client cancellation. The focused repair established:

- one complete body-read deadline across all chunks, not a fresh timeout per
  chunk, with `503` on timeout and `413` when actual bytes exceed the ceiling;
- concurrency admission **before** body reading, with immediate rejection rather
  than unbounded queueing;
- shielding of the synchronous worker task from repeated client cancellation;
  the concurrency slot is released exactly once, after the worker really
  finishes;
- bounded readiness work in a worker thread with a timeout, so `/health/live`
  stays responsive;
- middleware conversion of unexpected failures to a generic `503` envelope
  without a traceback; and
- `_FILE` secret support that fails closed when an explicitly configured file is
  unreadable and never falls back to an inline value.

### Bounded control-plane admission (task 15, partial local hardening)

- `_ControlPlaneAdmission` in `nasi_lemak/server.py` is one per-app,
  non-queuing bound (default 2) for synchronous readiness and authenticated
  operator calls: `/health/ready`, `/admin/events` and `/admin/export.csv`.
  Chat keeps its existing separate semaphore and bounded-admission behavior.
- `POST /v1/chat/completions` has one absolute, server-owned HTTP chat work
  deadline. `make_app(chat_work_timeout=...)` defaults to 60 s and accepts up to
  300 s. Invalid values (bool, zero, negative, NaN, infinity or out of range)
  leave the application live but not ready: readiness and chat return `503`, and
  the safe 60 s default is stored. The deadline starts when the gateway worker is
  dispatched, after the separate existing body-read limit. Expiry returns the
  existing generic `503 UNAVAILABLE` envelope with the HTTP `request_id`, never
  a late result. The route reuses the tested `_await_control_call` helper; chat
  and control-plane capacities remain separate. The running worker is shielded
  and keeps its chat admission slot until the real thread finishes; there is no
  queue or retry. Remembered repeated cancellation is re-raised at worker
  completion or the original deadline, whichever comes first. Each dispatched
  chat worker task is also retained in the per-app `app.state.chat_tasks` set
  until its done callback observes real completion, so a timed-out task cannot
  be garbage-collected while its thread is still running; the callback still
  consumes the result/exception and releases the slot exactly once.
- A slot is acquired only after operator authentication and query validation
  (or after readiness's cheap structural checks). Exhaustion returns the
  existing generic `503` immediately; readiness keeps its existing
  `{"status":"not_ready"}` body. No thread is dispatched when admission fails.
- The synchronous worker is shielded from the production 5-second HTTP deadline
  and client cancellation. The slot is released exactly once when the thread
  actually returns, and the thread result/exception is consumed. A timed-out or
  cancelled export read never continues to CSV assembly or an audit write. A
  failed or timed-out export audit releases no CSV, and the durable
  audit-before-response rule is unchanged. `/health/live` remains independent.
- Cancellation semantics: a remembered client cancellation is re-raised when the
  worker finishes or the original deadline expires, whichever comes first. It is
  never converted into `_CONTROL_TIMEOUT`/`503`, and a late worker success or
  error cannot replace it. The worker stays shielded and the slot stays held
  until the thread actually completes; the request never waits beyond its
  original deadline.
- This bounds concurrent queued background work only. It does not stop a running
  thread, does not add a native model/driver timeout, does not solve in-flight
  thread termination or upstream-call cancellation, and does not prevent an
  infrastructure-level bypass outside this process. No native hard deadline is
  verified. The chat deadline is an HTTP response deadline only: native input
  guard, generation, output guard and audit may continue after the `503`; audit
  records describe server processing, not proof of client delivery.
- Focused evidence: 10 deterministic event-gated ASGI tests in
  `tests/test_control_plane.py` cover readiness/events/export saturation, short
  test deadlines (0.05–0.1 s via patched constants, versus the 5-second
  production defaults), repeated cancellation retaining slots (including
  cancellation held past a shortened deadline), no excess reader/audit dispatch,
  authentication-before-admission, shared capacity across distinct routes at
  capacity 2, chat/control separation, liveness responsiveness, invalid
  `control_concurrency` bounds failing closed, recovery after late
  success/error, and no CSV or audit after a failed, timed-out or cancelled
  export. Every test gate is released in `finally`, and request tasks are
  settled during cleanup.
- Focused evidence: 9 deterministic event-gated ASGI tests in
  `tests/test_chat_deadline.py` cover a stalled input guard with no inference
  before release, a stalled output guard with no buffered output release,
  generation timeout late success and late error, repeated cancellation held past
  a shortened deadline with no response, overload rejection without excess
  dispatch while the thread runs, exact-once capacity recovery, liveness during
  a stalled worker, invalid `chat_work_timeout` values failing closed with the
  safe default, accepted 60/300 s bounds and unchanged normal chat. Test
  deadlines are 0.1 s; every gate is released in `finally` and tasks are settled.
  The late-error case keeps the injected error in place until the gate is opened
  and the worker really finishes, so it proves a late failure rather than a late
  success: the output guard never runs, the response body is unchanged, and
  capacity recovers only after the error is cleared. Both generation cases also
  assert the per-app `chat_tasks` strong reference still holds the timed-out task
  after the `503` and drops it once that task actually finishes.

### Focused audit repair

- PostgreSQL connections use `autocommit=True` and exactly one explicit
  transaction per append; `statement_timeout` is a libpq connect option.
- The runtime writer is append-only. Readiness verifies schema and append/sequence
  privilege without reading audit rows.
- Schema creation and role grants are bootstrap operations only; they are not run
  by the server.
- Terminal writes and offline recovery retain the original trusted request
  metadata instead of selecting the started row.
- DSNs are private and absent from representations and generic errors.

### Startup policy activation

- `nasi_lemak/policy.py` reads one UTF-8 YAML file exactly once, at app
  construction. A 32 KiB byte cap, a single-document rule, duplicate-key
  rejection, anchor/alias/custom-tag rejection and an explicit
  eight-collection depth bound are applied to the parse event stream before
  composition, so tiny but deeply nested YAML fails closed without
  `RecursionError`.
- Canonical keys are exactly `app_id`, `version`, `model` (only `pilot-local`),
  `token_budget` (1..512) and `deny_phrases` (up to 64 non-empty strings of at
  most 256 characters). `docs/policy.example.yaml` is the non-secret example and
  is loaded by a test.
- Missing, unreadable, oversized or invalid policy files leave the app live
  `200` / ready `503` / chat `503` without loading guard artifacts or activating
  built-in defaults. `NASI_LEMAK_POLICY_FILE` is required in the env path; an
  explicitly injected `Policy`/`Gateway` is only a Python test seam.
- Activation and rollback are controlled-restart operations over preserved
  operator-approved files. There is no hot reload, editor, database policy
  management or approval mechanism. Version and SHA-256 digest are exposed on
  `app.state` and audit events.
- Deny phrases are literal case-insensitive substrings across every accepted
  input turn (blocked before generation) and buffered output (blocked before
  release). They are not regexes or a semantic topic filter, and no policy value
  can disable the three PII masks or guard verdict handling.

### Assembled enforcement verification

- `tests/test_enforcement_integration.py` constructs the app through the YAML
  startup environment, replaces only `PostgresAuditStore` with real SQLite and
  injects the real composite adapters. `GenerationClient` sends actual HTTP to a
  loopback OpenAI-compatible fixture; guard/tokenizer verdicts are deterministic
  doubles.
- The success path asserts masked upstream messages, configured upstream model,
  no `Authorization` under `auth=none`, contextual sanitized output-guard input,
  masked output and metadata-only audit rows.
- The negative matrix covers auth, unknown fields/model/policy overrides,
  stream/tools, malformed and duplicate-key JSON, exact character/token
  boundaries, deny phrases in every role, attack verdict failures, tokenizer
  failures, output failures, generation malformed/HTTP/timeout failures and real
  SQLite initial/terminal write failures. Pre-generation cases assert zero
  upstream requests; post-generation failures assert no choices or raw output
  release and exactly one request (no retry).
- Success controls run alongside the matrix. Details and remaining gaps are in
  `docs/control-verification.md`.

### Authenticated operator event view (task 11)

- `nasi_lemak/operator.py` adds a separate read-only reader boundary. The
  operator API never calls `Gateway.audit_events()` or the runtime writer store,
  and it uses a distinct operator DSN. PostgreSQL uses lazy `psycopg`, bounded
  connect/statement timeouts and `default_transaction_read_only=on`. SQLite has a
  read-only `mode=ro` reader for local synthetic tests only.
- Queries use fixed identifiers and bound values, scope every page to the trusted
  server-side `app_id`, validate decision/event-type/request-ID filters and a
  positive keyset `seq` cursor, cap `limit` at 100 and fetch `limit + 1` to derive
  `has_more`/`next_cursor`. Results are reduced to a metadata allowlist; DSNs,
  raw rows, driver errors and other application data are not returned.
- `/admin` is static, same-origin HTML/CSS/JS with no event or secret content. The
  operator token stays in JavaScript memory and is sent only as a Bearer header.
  Rendering uses `textContent`; failures and denials clear the table. A
  request-generation counter plus `AbortController` aborts and invalidates every
  in-flight page on disconnect, `pagehide` or a new connection; late
  success/error/finally callbacks check the current generation before touching
  the UI. Disconnect and `pagehide` clear token, rows, metadata and paging
  immediately. Filters and navigation are disabled while a page is busy, and the
  filter/cursor values are captured per request so paging cannot race a later
  selection. The shell has filters, in-memory cursor history, policy
  version/digest and health metadata.
- A `request_started` row is displayed with its recorded `pending` decision only.
  It is not labelled incomplete: one paginated event does not prove that the
  request is still in flight, because its terminal event may be on a later page.
  Incomplete-request aggregation/narrowed global queries remain deferred.
- Both routes send `Cache-Control: no-store`, a hash-based CSP with no
  `unsafe-inline`/`eval`/remote origin/framing, `nosniff`, frame denial and
  same-origin policy, with no CORS. Auth is checked before reads; absent config is
  a safe `404`, partial/invalid config a safe `503`, and the operator feature
  never changes chat readiness. Same digest as the chat key, or the same DSN as
  the runtime writer, disables the routes.
- `scripts/operator_demo.py` is an explicit synthetic, loopback-only fixture for a
  caller browser check. It seeds 127 rows (126 scoped events plus one unrelated
  application row), preserves `req_demo_01`–`req_demo_03`, includes harmless
  `<img ...>` metadata and supports bounded `--reader-delay` and
  `--reader-unavailable` fixture-only switches. It passes `environ={}` explicitly
  so it reads no process environment or `*_FILE` secret path. The fixture also
  serves the task 12 export path; count aggregation is still not implemented.
- A caller browser check in an IAB host on port 18789 verified the initial login
  and that the default 50-row page displayed 50 rows. The same run clicked
  `Export matching events` and produced an actual
  `nasi-lemak-events-export.csv` download; the caller parsed 126 data rows and 13
  columns, all scoped to `synthetic-operator-demo`, with canonical filters
  `decision=*;event_type=*;request_id=*` and SHA-256
  `38e37eeb5c1923d7ed97867ad073596616487f305a0095cd8ab2b9dd7c8ba84e`. This is
  synthetic browser-download evidence only, not PostgreSQL/Docker/native-guard/
  live-model proof. The delayed-reply/stale-response race, outage and escaping
  checks remain pending in a browser; local Node.js DOM/fetch tests are not
  browser or CSP execution evidence.

### Bounded CSV export (task 12)

- `GET /admin/export.csv` is a separate operator-Bearer route. Auth is checked
  first; missing/invalid operator config, active policy, reader or export-audit
  writer returns a generic `503` before any snapshot. The expected
  `export_audits` schema is discovered on the required write after the snapshot
  is prepared, so a missing table or failed write releases no CSV but is not
  necessarily detected before the snapshot. There is no in-memory fallback.
- The strict parser accepts only `decision`, `event_type` and `request_id`
  (single occurrence, allowlisted enum values, bounded request ID) and rejects
  unknown, duplicate and `limit`/`after` parameters with a generic `400` before
  the reader or audit is touched.
- One app-scoped `SELECT` snapshot on the separate read-only reader, fixed
  identifiers, bound filters, `ORDER BY seq` and at most `LIMIT 1001`. More than
  1000 rows or 2 MiB returns a generic `413` with no CSV bytes and no export
  content in logs.
- The CSV is one complete byte string with a fixed 13-column header
  (`seq, request_id, event_type, timestamp, model, policy_version,
  policy_digest, decision, error_code, app_id, export_id, created_utc, filters`).
  Policy version/digest and export metadata are repeated per row. A leading `=`,
  `+`, `-`, `@`, tab/CR/LF or control character gets one apostrophe prefix in the
  rendered file; stored rows are unchanged.
- An empty match still returns a header-only file. Trusted response headers carry
  only the export ID, row count and SHA-256; canonical filters, active policy
  version/digest and creation metadata are in the audit row.
- Exactly one append-only `export_audits` row is written **before** release:
  export ID, app, creation time, canonical filters, row count, SHA-256 of the
  exact CSV, active policy version/digest and the maximum exported sequence bound.
  A failed write releases no CSV. The row proves preparation, not confirmed
  browser delivery.
- The UI exports the current filters as one snapshot, independent of its 50-row
  pagination, shows the trusted row count and `Download requested.`, maps
  `413`/`401`/`503` to fixed messages, revokes the blob URL and blocks stale or
  session-expired completions. A later caller IAB run confirmed an actual
  synthetic download; the source text itself still makes no browser-save claim.
- PostgreSQL bootstrap for an existing database: an administrator applies
  `audit_schema.sql` then `audit_roles.sql`; the volume is never deleted. The
  writer gets `INSERT` on `export_audits` and `USAGE` on its sequence only; the
  reader keeps `SELECT` on `events` and no `export_audits` privilege. Runtime does
  no DDL or role provisioning.
- Local evidence: 23 ASGI export tests with real SQLite audit rows and 10 Node.js
  behaviour cases. PostgreSQL SQL/privileges were checked with a driver double
  only; no PostgreSQL, Docker or native Qwen proof exists. A caller IAB run
  produced a synthetic browser download (126 rows, 13 columns, SHA-256
  `38e37eeb5c1923d7ed97867ad073596616487f305a0095cd8ab2b9dd7c8ba84e`). See
  [`evidence-export.md`](evidence-export.md).

### Frozen synthetic PII quality and language boundary (tasks 13/14)

- `evals/pii/` freezes `development.json` (16 cases) and `evaluation.json` (61
  cases; 58 evaluated, 3 explicitly unsupported) with explicit gold
  `type`/`start`/`end`/`text` annotations, distinct IDs/text, synthetic
  `example.invalid`/`test.invalid` email domains, BM/Chinese surrounding text,
  near-matches, multiple entities and ambiguous 12-digit order/SKU cases.
  `manifest.json` records SHA256 values; the evaluator refuses mismatched bytes.
- `nasi_lemak/pii.py` is the shared production span source. `mask_pii` and the
  offline evaluator both use those spans, so there is no shadow regex or
  production clone. MY_PHONE and MYKAD literals, recognition order, thresholds,
  labels and scope are unchanged. Caller review reproduced an EMAIL
  terminal-period miss; a narrow reviewed repair changed only the EMAIL right
  boundary so sentence-final punctuation is retained while the address is
  masked. A period that continues a domain/hyphenated suffix or starts a
  double-dot suffix is not accepted as a partial-address boundary.
- `nasi_lemak/pii_eval.py` validates/loads a frozen corpus, runs the actual
  production recognizers, applies exact one-to-one type/offset matching and
  reports per-entity gold/predicted/TP/FP/FN, precision/recall/F1 (`null` when
  undefined), case counts, labelled error IDs/reasons, corpus/runtime SHA256 and
  malformed-fixture failures. Default JSON/Markdown reports and terminal output
  contain no raw fixture text and no wall-clock fields; repeated runs are
  byte-identical.
- Provisional engineering gates are precision >= 0.95 and recall >= 0.95 per
  entity with nonzero positive and negative cases. The frozen v1 evaluation
  still exits `1` truthfully: its raw EMAIL score is 16 TP / 1 FP / 0 FN
  (precision 0.9412, recall 1.0000), MY_PHONE 17 TP (1.0000/1.0000), MYKAD 15 TP
  / 4 FP / 0 FN (0.7895/1.0000). The v1 EMAIL FP is the frozen
  `EV-EMAIL-014` (`negative_trailing_dot`) label, now disclosed as an
  **annotation defect**: it labelled a sentence-final address as non-PII. The
  raw score is annotation-conflicted and is not a reliable current EMAIL quality
  metric.
- `evals/pii/reviewed-labels-v2/` is a reviewed regression copy of the 61 v1
  cases with only that one gold label corrected (EMAIL span 13-33 excluding the
  period); all original texts are unchanged. Its manifest was frozen before
  scoring. V2 exits `1` only because MyKad still fails: EMAIL 17 TP / 0 FP / 0
  FN (1.0000/1.0000), MY_PHONE 17 TP (1.0000/1.0000), MYKAD 15 TP / 4 FP / 0 FN
  (0.7895/1.0000). The MyKad false positives are the ambiguous order ID, SKU and
  part number plus an overlong phone-like value that also matches the 12-digit
  shape. No threshold or error was removed to force a pass.
- The separate six-case caller-review corpus exits `0`: all three entities pass,
  and the pre-fix `CR-EMAIL-001` false negative is preserved in
  `evals/pii/caller-review-v1/results/before-email-fix-*`. Both reviewed corpora
  are known-regression evidence, not unseen or independent hold-out sets. The
  pre-fix v1 report is preserved as `evals/pii/results/before-email-fix-*`.
- Current runtime SHA256 after the repair: `nasi_lemak/pii.py`
  `3b605e37821008308f7be11efb1f06463b561d4f5021d21f914f0b994a07b0ee`;
  `nasi_lemak/pii_eval.py`
  `e6e3b17e354b035c8627678596d0bfa4b299567c051a763a1b6d55eb8a55e8b0`;
  `nasi_lemak/gateway.py`
  `2a566f90ccfdfb83ccc23b8a231c161105d4ecc4c459f3c84e82e1bdbd00c7fd`.
  Both fixture manifest hashes are unchanged.
- This is agent-authored synthetic format-recognizer evidence. It is not an
  independent human hold-out set, population estimate, privacy audit or
  customer acceptance. The measured ASCII fixtures do not mean every non-ASCII
  character is rejected: the preserved Python regexes use Unicode `\d` and
  `IGNORECASE`. English semantic guard acceptance remains unverified pending
  native execution and independent frozen labels/review; BM/Chinese semantic
  protection is unsupported for pilot acceptance. Passport and bank account
  recognizers are deferred. Structured ASCII masking inside BM/Chinese
  sentences does not establish semantic coverage.

## Docker Compose packaging (Step C)

Added `Dockerfile`, `compose.yaml`, `.dockerignore` and
`docs/compose.env.example`; updated packaging metadata in `pyproject.toml`.
`pyproject.toml` remains the canonical dependency definition, with exact tested
pins: FastAPI 0.147.0, Uvicorn 0.54.0, psycopg[binary] 3.3.6, plus HTTPX 0.28.1
and PyYAML 6.0.3 in the test extra. A minimal setuptools build system and
explicit package discovery were added for the flat repository, and the two `.sql`
files are declared package data.

The image copies only `pyproject.toml` and `nasi_lemak/`, installs the `server`
extra, runs as UID/GID 10001, and uses exec-form
`uvicorn nasi_lemak.server:app --host 0.0.0.0 --port 8000 --workers 1
--no-access-log` with no reload or debug mode. The default image therefore does
**not** include the optional `guards` ML extra or any guard/tokenizer weights,
and this slice does not add a Compose policy mount or `NASI_LEMAK_POLICY_FILE`
setting.

Compose defines only PostgreSQL and the gateway. PostgreSQL has a named volume,
a healthcheck and no host-published port; the gateway depends on
`service_healthy`, publishes `127.0.0.1:8000` by default, runs read-only with a
small `/tmp` tmpfs, drops all capabilities, sets `no-new-privileges`, and has
memory/CPU/PID limits. PostgreSQL is on an internal-only network; the gateway
also keeps the default bridge for outbound model-endpoint access. There is no
privileged mode or Docker socket mount.

Credentials are not hardcoded or defaulted. The administrator password is a
Docker secret read via `POSTGRES_PASSWORD_FILE`; the runtime writer DSN and the
application-key SHA-256 digest use `NASI_LEMAK_AUDIT_DSN_FILE` and
`NASI_LEMAK_APP_KEY_DIGEST_FILE`. Secret-file paths require mandatory
interpolation. `audit_schema.sql` and `audit_roles.sql` are mounted read-only as
PostgreSQL entrypoint init scripts; they create the schema and NOLOGIN group
roles only. The operator must create a LOGIN role in the writer group with an
interactive `\password` and write the corresponding local DSN file. Bootstrap
runs only on an empty volume; documentation explicitly forbids deleting a live
volume.

Image tags are conservative version tags: `python:3.12-slim-bookworm` and
`postgres:16.4-bookworm`. Immutable digest pinning, registry signature
verification and release security review are pending; no digest was invented and
no requirements lock file was produced. Packaging decisions were checked against
the official FastAPI Docker deployment guide
(<https://fastapi.tiangolo.com/deployment/docker/>), the psycopg 3 transaction
documentation
(<https://www.psycopg.org/psycopg3/docs/basic/transactions.html>) and the Docker
Compose startup-order/healthcheck documentation
(<https://docs.docker.com/compose/how-tos/startup-order/>).

## Verification

Commands run from the existing `.venv` (Python 3.12.14; FastAPI 0.147.0,
Uvicorn 0.54.0, psycopg 3.3.6, HTTPX 0.28.1, PyYAML 6.0.3):

| Command | Result |
|---|---|
| `.\.venv\Scripts\python.exe -m unittest discover -s tests` | **324 tests run, 322 passed, 2 skipped, exit 0, 21.847s** (22.843 s wall) — this worker's local run, not a final caller run; the two skips are the existing optional `TEST_AUDIT_DSN`-gated PostgreSQL tests; earlier 315/313, 312/310, 284/282, 283/281, 271/269, 249/247 and 226/224 figures are historical |
| `.\.venv\Scripts\python.exe -m unittest tests.test_control_plane -v` | **10 focused event-gated control-plane tests OK** (short-deadline readiness/events/export saturation, cancellation held past a shortened deadline with no late audit/CSV, shared capacity 2 across distinct routes, invalid `control_concurrency` bounds fail closed, no excess dispatch, auth-before-admission, chat separation, liveness, late success/error recovery, no CSV on failed/timed-out export audit) |
| `.\.venv\Scripts\python.exe -m unittest tests.test_chat_deadline -v` | **9 focused event-gated chat-deadline tests OK, exit 0, 1.453s** (stalled input/output guards, late success, retained late error with no output-guard call, repeated cancellation, overload, exact-once capacity, invalid bounds, normal chat; timed-out tasks remain strongly referenced until real completion) |
| `.\.venv\Scripts\python.exe -m unittest tests.test_pii tests.test_pii_eval -v` | **34 focused PII/span/evaluator tests OK** (metric math, strict spans, terminal-period and punctuation boundaries, invalid dotted suffixes, Unicode `\d` preservation, invalid fixtures, manifest freeze, v1 hash preservation, v2 single-label adjudication, CLI exit 0/1/2, reproducibility, no raw text) |
| `.\.venv\Scripts\python.exe -m unittest tests.test_operator -v` | **23 operator/API tests OK** (real SQLite audit rows + real ASGI; PostgreSQL SQL/params via driver double only) |
| `.\.venv\Scripts\python.exe -m unittest tests.test_export -v` | **23 export tests OK** (real ASGI app + real SQLite audit rows; PostgreSQL export-audit SQL via driver double only) |
| `.\.venv\Scripts\python.exe -m unittest tests.test_admin_js -v` | **1 test OK, 10 Node.js behaviour cases pass** (real inline script on local Node.js 24.19.0 with deterministic DOM/deferred fetch; not a browser) |
| `.\.venv\Scripts\python.exe -m unittest tests.test_enforcement_integration -v` | **7 assembled-path tests OK** (loopback HTTP fixture, real SQLite audit, deterministic guard doubles; includes the terminal-period email transport regression) |
| `.\.venv\Scripts\python.exe -m unittest tests.test_policy -v` | **19 focused tests OK** (loader bounds/nesting, example file, deny phrases, startup/restart/rollback) |
| `.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --split evaluation` | **Exit 1**: v1 raw score EMAIL 16 TP / 1 FP / 0 FN (annotation-conflicted `EV-EMAIL-014`), MY_PHONE 17/17/17, MYKAD 15 TP / 4 FP / 0 FN (0.7895/1.0000); reports under `evals/pii/results/` |
| `.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --root evals/pii/reviewed-labels-v2` | **Exit 1**: EMAIL 17 TP / 0 FP / 0 FN (1.0000/1.0000), MY_PHONE 17/17/17, MYKAD 15 TP / 4 FP / 0 FN (0.7895/1.0000, gate fail); reports under `evals/pii/reviewed-labels-v2/results/` |
| `.\.venv\Scripts\python.exe -m nasi_lemak.pii_eval --root evals/pii/caller-review-v1` | **Exit 0**: all six known regression cases pass; pre-fix failing report preserved as `before-email-fix-*` |
| Local ASGI check with empty environment | live `200 {"status":"ok"}`, ready `503 {"status":"not_ready"}`, chat `503 UNAVAILABLE`, adapters `None` |
| PyYAML parse of `compose.yaml` and `docs/api-contract.yaml` | Valid YAML; expected top-level keys |
| `tomllib` parse of `pyproject.toml` | Build backend, explicit `nasi_lemak` package and `*.sql` package data present |
| `docker --version` / `docker compose version` | **Unavailable**: Docker is not installed/on PATH |

The two skips are the existing optional PostgreSQL integration tests, skipped
because `TEST_AUDIT_DSN` is not set; no skip was added for task 12 or tasks
13/14. No real PostgreSQL round-trip was run, so the PostgreSQL reader and
export-audit SQL remain double-checked only. A SQLite test-helper close race that
intermittently raised `WinError 32` on Windows was fixed by closing
cursors/connections in the helper itself. The frozen PII evaluation is
agent-authored synthetic evidence: it measures the actual recognizers but is not
an independent human hold-out set, population estimate or customer acceptance.
No regex was changed to improve a score. The only recognizer change is the
reviewed narrow EMAIL right-boundary repair: an address immediately followed by a
sentence-final period is now masked without swallowing that period, while a period
that continues a domain or hyphenated suffix, including a double-dot suffix, is
still not accepted as a boundary. That repair was verified through the ASGI
application and loopback HTTP and leaves the MY_PHONE and MYKAD literals
unchanged; the nonzero MyKad result remains. Exact counts, labelled errors and
reproduction commands are in [`pii-quality.md`](pii-quality.md), and the reviewed
v2 run is in
[`evaluation-summary.md`](../evals/pii/reviewed-labels-v2/results/evaluation-summary.md).
A package
wheel was built with
`.\.venv\Scripts\python.exe -m pip wheel --no-deps --wheel-dir .orchestration/20261019T123913Z-8ace1189/wheels .`,
producing `nasi_lemak_gateway-0.1.0-py3-none-any.whl` (SHA256
`4afa863bf47a803636d526ab694c1170701066b83e733e8202c4bc95fbc70229`).
Build tools were fetched into the isolated temporary build environment only; no
global or bundled runtime installation was made. The wheel ZIP was verified to
contain `server.py` and both SQL files, with no tests, secrets or orchestration
files. Dockerfile and Compose were reviewed statically and their YAML parsed,
but this is **not** `docker compose config`, image-build or runtime validation.

## Not implemented or validated

- Native guard adapters and the contextual adapter factory are implemented and
  wired through `make_adapters_from_env`, but pretrained weights were not
  downloaded or executed and the optional ML extra is not installed here.
  Assembled-path tests use deterministic guard/tokenizer doubles; native
  classifiers, held-out metrics and hard inference timeouts remain open. Live
  `200` + ready/chat `503` until local weights, tokenizer and a confirmed model
  are configured is intentional safe startup, not successful guarded inference.
- Exact API model ID and successful connectivity to the supplied endpoint.
  `/v1` is assumed and unverified; the endpoint uses `auth=none` with explicit
  insecure-HTTP opt-in and a blank model.
- Production PostgreSQL runtime evidence, concurrency/failure drills and
  deployment-time log inspection.
- Docker image build, Compose startup, secret mounting and healthcheck behavior.
  The default image omits ML extra/weights and the Compose file has no policy
  mount; Docker/PostgreSQL/native-guard/Qwen integration is unverified.
- TLS ingress. The gateway is localhost HTTP only; TLS is required before a
  remote pilot.
- The operator event view is local-only and read-only. Its tests use real SQLite
  rows and a PostgreSQL driver double for SQL/parameters; no live PostgreSQL
  reader role, browser CSP execution or production routing was verified. The
  caller browser verified initial login, the 50-row page and a synthetic CSV
  download, but the delayed-reply race, outage and escaping checks remain
  pending. Local Node.js lifecycle tests are not browser evidence. The bounded
  CSV export is implemented and locally verified, but no PostgreSQL
  export-audit insert or Docker run was performed; charts and count aggregation
  are not implemented.
- LiteLLM routing. There is no policy editor, hot reload or approval mechanism.
  Versioned YAML policy activation/rollback is implemented and tested with
  temporary fixture files and doubles; operator approval remains a procedure.
  The optional `/admin` view only reads event metadata and cannot change policy.
- PII quality evidence is limited to the three ASCII structured recognizers and
  agent-authored synthetic splits. No independent human labels/review,
  population metrics or customer acceptance exist. Reviewed v2 measures EMAIL
  17 TP / 0 FP / 0 FN and MY_PHONE 17 TP / 0 FP / 0 FN, while the MyKad gate
  still fails on four labelled false positives (15 TP / 4 FP / 0 FN); the
  original frozen v1 EMAIL raw score is annotation-conflicted rather than a
  current metric. The six-case caller-review corpus passes after the narrow
  repair but is known-regression evidence, not an unseen hold-out. Overall
  quality gate: FAIL. The measured ASCII
  fixtures do not mean every non-ASCII character is rejected (preserved Python
  regexes use Unicode `\d` and `IGNORECASE`). Passport, bank-account, address,
  name and free-text semantic PII are not implemented. Structured masking inside
  BM/Chinese sentences is not semantic guard evidence; English semantic guard
  acceptance remains unverified and BM/Chinese semantic protection is
  unsupported for pilot acceptance.
- The bounded control-plane admission and HTTP chat work deadline are partial
  local hardening only: they cannot terminate a running thread, cancel an
  upstream call, impose a native model/driver hard deadline, or stop an
  infrastructure-level bypass outside this process. Retaining chat task
  references and releasing the slot after the thread returns is not thread
  termination or a native deadline. Cancellation is deferred until the worker
  finishes or the original deadline, whichever comes first. Tasks 16-20 remain
  pending.
- Any acceptance of the full day-2 milestone or live pilot.

## Backlog disposition

| Supplied work package | Current disposition |
|---|---|
| 1: pilot contract | Local draft documents; customer scope/resources/data-boundary approval open |
| 2: model/guard serving | Transport and packaging scaffolding; real serving/hardware/license evidence blocked |
| 3-5: auth, request surface, audit | HTTP/auth/audit foundation implemented locally; production PostgreSQL run pending |
| 6/13: PII | Three ASCII format recognizers share production spans with a frozen agent-authored synthetic evaluator (61 evaluation cases, 58 scored, 3 unsupported); reviewed v2 measures EMAIL and MY_PHONE at 17 TP / 0 FP / 0 FN each and MYKAD at 15 TP / 4 FP / 0 FN so that gate still fails, the original v1 EMAIL raw score is annotation-conflicted, and the narrow terminal-period repair was verified through ASGI and loopback HTTP; true independent held-out labels/review, passport/bank and semantic PII open |
| 7: full coverage | Adapter boundary and bounded tests; real tokenizer/window proof open |
| 8-10: attack, output, policy | Attack/output orchestration and versioned YAML policy activation tested with local doubles; native classifiers, approval workflow and hardware evidence open |
| 11: operator events | Read-only authenticated HTML/API, separate SQLite reader boundary and PostgreSQL SQL doubles implemented and locally tested; live PostgreSQL reader role pending |
| 12: bounded CSV export | Authenticated `/admin/export.csv`, append-only prepared-export audit and UI flow implemented and locally verified (23 ASGI export tests + 10 Node.js cases); PostgreSQL SQL via double, caller synthetic browser download confirmed, no Docker run |
| 13/14: PII quality and language boundary | Frozen synthetic fixtures/manifest, deterministic evaluator, focused tests and docs delivered; narrow reviewed EMAIL boundary regression fixed and verified through ASGI and loopback HTTP; reviewed v2 passes EMAIL and MY_PHONE but the MyKad gate still fails, so the overall quality gate remains FAIL; original v1 EMAIL score is annotation-conflicted; caller-review pass is known regression evidence, not unseen/independent; native English guard proof and BM/Chinese semantic support remain open |
| 15 | Bounded control-plane admission plus the bounded HTTP chat work deadline: partial local hardening delivered (non-queuing shared capacity for readiness/operator reads and export audit; one server-owned 60 s default/300 s max chat response deadline with exact-once slot release, retained worker task references, short test deadlines, cancellation deferred until worker completion or the original deadline); infrastructure bypass and native hard deadlines unverified |
| 16-20 | Not implemented or accepted |

Tasks 13/14 deliver an authored synthetic evaluation, a narrow reviewed
privacy regression repair and a documented language boundary, not customer
acceptance. The current full local suite figure from this worker's run is
`324 tests run, 322 passed, 2 skipped in 21.847s` (exit 0; final caller
confirmation pending), where both skips are the existing optional PostgreSQL
tests. The earlier 315/313, 312/310, 284/282, 283/281, 271/269, 249/247 and
226/224 figures are historical.
The caller-review corpus's post-fix pass is not an accuracy or independent
hold-out claim. Native inference, independent held-out PII labels, English
semantic-guard acceptance, BM/Chinese semantic protection, real PostgreSQL
reader/export-audit evidence and live pilots remain blocked pending approved
infrastructure, real guard/tokenizer/model revisions, the confirmed endpoint
model ID and the customer gates.
