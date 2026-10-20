# Assembled enforcement verification

Date: 20 October 2026. Scope: local, synthetic verification only.

## Method

`tests/test_enforcement_integration.py` assembles the real request path:
FastAPI ASGI (`make_app`), strict YAML startup policy, `Gateway`,
`RealGatewayAdapters`, a real `GenerationClient` talking to a loopback
`ThreadingHTTPServer` OpenAI-compatible fixture, and real SQLite audit writes.
Only the production `PostgresAuditStore` constructor is replaced with a SQLite
store. No live endpoint, model weight, PostgreSQL server or Docker runtime is
used.

Guard and tokenizer verdicts are explicit deterministic doubles. They prove
wiring, fail-closed ordering and observability; they are not native classifier
evidence.

Task 12 adds 23 ASGI export tests (`tests/test_export.py`) over the real app and
real SQLite audit rows, with PostgreSQL export-audit SQL checked through a
driver double, plus 10 Node.js behaviour cases for the operator shell.

## Controls and local evidence

| Control | Reproducible test | Observed local evidence |
|---|---|---|
| PII masking before generation | `EnforcementIntegrationTests.test_success_path_masks_pii_guards_and_audits_metadata_only` | Captured upstream body contains `[EMAIL]`, `[MY_PHONE]`, `[MYKAD]`; raw email, MY phone and MyKad absent |
| Configured upstream ID, public alias | same | Captured body uses `upstream-model-42` while request and response use `pilot-local` |
| `auth=none` sends no credential | same | Captured request has no `Authorization` header |
| Contextual output guard input | same | Guard receives all sanitized turns plus complete raw buffered output |
| Output PII masking | same | Response masks all three seeded entities |
| Metadata-only audit | same, plus all failure tests | Every event has immutable app ID, public model, policy version and 64-hex digest; no raw input/output/key/upstream sentinel |
| Authentication rejection | `test_pre_generation_rejections_never_contact_upstream` (wrong auth) | `401`, zero upstream requests |
| Unknown fields, model/policy overrides, stream/tools | same matrix | `400`, zero upstream requests |
| Malformed/duplicate-key JSON | same matrix | `400`, zero upstream requests |
| Character and token overflow | same matrix; `test_exact_token_boundary_allows_full_content_and_rejects_one_over` | `413`, zero upstream requests; exact budget allowed with full content, budget + 1 rejected, no truncation |
| Deny phrase in system/user/assistant | same matrix | `403`, zero upstream requests |
| Attack block, malformed verdict, exception | same matrix | `403`/`503`, zero upstream requests |
| Invalid/erroring tokenizer | same matrix | `503`, zero upstream requests |
| Unsafe or malformed output verdict, guard exception | `test_output_and_generation_failures_release_nothing` | `403`/`503`, one captured request, no choices or raw output sentinel |
| Literal output denial | same | `403` after one request, no output released |
| Malformed/HTTP-failing/truncated generation | same | `503`, one request, no retry |
| Bounded transport timeout | same (`generation_timeout`) | `503` well under 3 s with one request |
| Initial audit write failure | `test_initial_audit_write_failure_never_reaches_upstream` | Real read-only SQLite write failure; `503`, zero upstream requests, no events |
| Terminal audit write failure | `test_terminal_audit_write_failure_withholds_released_output` | Real read-only SQLite INSERT failure after generation (not a commit-time proof); `503`, no output released, only `request_started` stored |
| Operator key separation | `tests.test_operator.AuthenticationAndSeparationTests` | Missing/malformed/duplicate/wrong/chat keys return `401` before the reader is called; operator key cannot authorize chat; chat key cannot read events |
| Operator config states | `tests.test_operator.ConfigurationTests` | Absent config `404`; partial/malformed/same-digest/same-writer-DSN config `503`; chat remains ready; reader closes on shutdown |
| Bounded operator reads | `tests.test_operator.ReaderPagingAndIsolationTests`, `QueryBoundaryTests`, `ApiQueryBoundaryTests` | Real SQLite rows: app isolation, `limit<=100`, enum/length filters, positive keyset cursor, `has_more`/`next_cursor`; a `request_started` row keeps its recorded `pending` decision without an unsupported incomplete classification; malicious limits/filters `400` with zero reader calls |
| Operator reader SQL (double) | `tests.test_operator.PostgresReaderSqlTests` | Fixed `SELECT` allowlist, `app_id = %s`, bound filters/cursor, `LIMIT %s` with `limit + 1`, read-only session/statement timeout, connection closed; **not PostgreSQL proof** |
| Operator shell/CSP | `HeaderAndCspTests`, `AuthenticationAndSeparationTests.test_admin_shell_requires_no_token_and_contains_no_data` | No event/token/config in shell; password field; `textContent`; no `pending (incomplete)` label; corrected start-event caption; no storage/cookie token; no-store, hash CSP without `unsafe-inline`/remote/frame, nosniff, no CORS |
| Operator shell lifecycle (JS) | `tests.test_admin_js.AdminPageJavaScriptTests` | Real inline script under local Node.js 24.19.0 with a deterministic DOM and deferred fetch: disconnect aborts and clears data immediately; disconnect/`pagehide` stale success cannot repopulate; an older reply cannot overwrite a later connection; abort/failure reset busy; filters and navigation lock while busy and per-request filters are captured. **Not browser/CSP execution evidence.** |
| Synthetic operator fixture | `tests.test_operator.SyntheticFixtureTests` | Real SQLite: more than 100 seeded rows make the default page paged; one harmless `<img ...>` metadata value is present and escaped client-side; `environ={}` and fixture-only delay/unavailable flags are present |
| Operator reader failure | `ReaderPagingAndIsolationTests.test_reader_failure_and_missing_database_are_generic_503` | Generic `503` metadata only; no DSN, driver or secret text returned |
| Export auth and query boundary | `tests.test_export` | Separate operator key; unknown/duplicate/`limit`/`after`/invalid filters rejected with `400` before reader or audit; missing config/policy/reader/writer `503` before snapshot; expected schema discovered on the required write after snapshot preparation |
| Export snapshot and caps | `tests.test_export` | One app-scoped `SELECT`, `LIMIT 1001`; >1000 rows or >2 MiB returns `413` with no CSV bytes and no export content in logs; empty match is header-only with metadata |
| Export CSV rendering | `tests.test_export` | Fixed 13 columns, per-row policy version/digest and export metadata, apostrophe neutralization while stored rows stay unchanged |
| Export audit ordering | `tests.test_export` | Append-only row written before release with ID/app/time/filters/count/SHA-256 of exact CSV/policy version+digest/max exported seq; failed write releases no CSV; expected schema is found on that required write after the snapshot; preparation does not prove browser delivery |
| Export PostgreSQL writer (double) | `tests.test_export` | `INSERT`-only `export_audits` path, no DDL/role provisioning, bounded timeout and closed connection; **not PostgreSQL server proof** |
| Export UI (JS) | `tests.test_admin_js` + `tests/js/admin_page_harness.js` | 10 Node.js cases: export uses current filters without page cursor, locks controls, maps `401`/`413`/`503`, revokes the blob URL, and stale/session-expired completions never download; shows `Download requested.`; **the Node.js cases are not browser evidence**, but a separate caller IAB run of the synthetic fixture confirmed an actual download |

Success controls run in the same modules so a permanently blocked or
short-circuited system cannot pass the negative matrix.

The operator view has separate ASGI/SQLite tests (`tests/test_operator.py`). They
use real SQLite audit rows, the real reader boundary and the real ASGI app. The
PostgreSQL reader's SQL, parameters, timeout options and connection close are
checked with a driver double only; this is not PostgreSQL server evidence. The
inline shell script is also executed under the local Node.js runtime with a
deterministic DOM and deferred replies (`tests/test_admin_js.py`); this proves
JavaScript lifecycle branching, not browser engine, CSP/hash or layout behaviour.
The 10 shell cases include the export flow: filters without page cursor, control
locking, `401`/`413`/`503` messages, blob-URL revocation, and stale or
cross-session completions that must not download. The completion text is
`Export prepared: N rows. Download requested.` and makes no browser-save claim.
A caller IAB browser check on port 18789 verified the initial login, a 50-row
page and an actual `nasi-lemak-events-export.csv` download: 126 data rows, 13
columns, only `synthetic-operator-demo`, canonical filters
`decision=*;event_type=*;request_id=*`, SHA-256
`38e37eeb5c1923d7ed97867ad073596616487f305a0095cd8ab2b9dd7c8ba84e`. This is
synthetic browser-download evidence only. The delayed-reply race, outage and
escaping checks remain pending in a browser.

## Limits and OPEN items

These tests do **not** prove classification accuracy, privacy on arbitrary logs,
production safety or upstream compatibility. The following remain OPEN:

- native Prompt Guard 2 / Llama Guard 3 execution, revisions and held-out
  metrics; current guard verdicts are doubles;
- hard timeout isolation for native inference; local inference is still
  unbounded and must not be labelled timeout-tested;
- Qwen endpoint connectivity and exact upstream model ID/API path;
- real PostgreSQL privileges, durability and failure behaviour; this includes the
  operator reader role and reader DSN, which were not run against PostgreSQL;
- browser execution of the operator CSP hashes, the delayed-reply/race/outage
  and escaping checks and responsive layout; local tests inspect the static
  shell and headers and run the inline JavaScript under Node.js with a
  deterministic DOM, not a browser engine;
- Docker image build and Compose runtime; the Compose file leaves the optional
  operator view disabled;
- TLS ingress, network-bypass testing, retention policy and performance/load
  evidence.

The full suite reports **249 tests run, 247 passed and 2 skipped**; the only
skips remain the two optional PostgreSQL integration tests that require
`TEST_AUDIT_DSN`. Task 12 adds 23 ASGI export tests and 10 Node.js behaviour
cases; no skip was added, and a SQLite test-helper close race that intermittently
raised `WinError 32` on Windows was fixed in the helper. PostgreSQL export SQL
was exercised with a driver double only; no Docker or native Qwen run occurred.
A caller IAB run of the synthetic fixture confirmed an actual browser download;
prepared-export audit rows themselves still do not prove confirmed delivery. See
[evidence-export.md](evidence-export.md).
