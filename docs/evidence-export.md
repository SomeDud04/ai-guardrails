# Bounded CSV export contract

Date: 20 October 2026. Scope: local, synthetic verification only. This document
describes the implemented `/admin/export.csv` backend and operator-UI contract;
it is not a production, PostgreSQL-server or model-quality claim.

## Route, auth and configuration

- `GET /admin/export.csv` is a **separate route** from `/admin/events`. It uses the
  same optional operator configuration and accepts **only** the operator Bearer
  key. The chat key is rejected with `401`; auth is checked before any reader,
  snapshot or audit call.
- Missing, partial or invalid operator configuration returns a generic `503`
  (absent configuration keeps the normal safe `404`). A missing/invalid active
  policy, reader, export-audit writer or expected schema also makes the export
  `503` **before** a snapshot is taken. There is no in-memory fallback.
- Responses are `no-store`, same-origin and generic on error: no DSN, token, raw
  row, driver text or CSV content is returned or logged.

## Query grammar

`parse_export_query` is strict and independent of the UI page state:

- accepted parameters are exactly `decision`, `event_type` and `request_id`;
- every value must appear once (duplicates rejected), and unknown parameters,
  including `limit` and `after`, are rejected;
- `decision` and `event_type` must be allowlisted enum values; `request_id` is a
  bounded non-empty identifier;
- any parse failure is a generic `400` and no reader or audit call is made.

The export is always **all matching rows**, not the current 50-row page: the UI
deliberately omits `limit` and `after` when building the export query.

## Snapshot and caps

- One app-scoped `SELECT` snapshot on the separate read-only reader role, with
  fixed identifiers, bound filter values and `ORDER BY seq`.
- The query fetches at most `LIMIT 1001`, so a result that exceeds the 1000-row
  export cap is detectable instead of silently truncated.
- Hard caps: **1000 rows** and **2 MiB** of serialized CSV. Exceeding either
  returns a generic `413` with no CSV bytes, no download and no raw content in
  logs. The byte cap is enforced while rendering, not after an unbounded buffer.
- No count query, aggregation, join, cross-application read or streaming release.

## CSV format

Exactly one fixed 13-column header, in this order:

`seq, request_id, event_type, timestamp, model, policy_version, policy_digest,
decision, error_code, app_id, export_id, created_utc, filters`

- `app_id` is the trusted server-side scope, not a value read from a row.
- `policy_version` and `policy_digest` are repeated on every row, together with
  the export identity and creation time.
- `filters` is the canonical filter string, also repeated per row.
- Timestamps are serialized deterministically; UTF-8, CRLF line endings, standard
  CSV quoting.

### Formula neutralization

Every rendered cell that could start a spreadsheet formula receives one leading
apostrophe: leading `=`, `+`, `-` or `@` (including after any leading Unicode
whitespace, such as NBSP or em space), a leading tab/CR/LF, or a leading control
character. Only the CSV bytes are
neutralized; **stored audit rows are never modified** and no data is dropped.

### Empty result

An empty match still returns a valid **header-only** CSV file (not `404`/`400`).
The response headers carry the export ID, row count and SHA-256 only; canonical
filters, active policy version/digest and creation metadata are in the audit row.

## Audit before release

`export_audits` is append-only. Before any CSV bytes are released, the writer
persists exactly one row containing:

- `export_id` (public `exp_…` identifier), `app_id`, `created_at`;
- the canonical `filters`, `row_count` and `sha256` of the **exact** CSV bytes;
- the active `policy_version` and `policy_digest`;
- `upper_seq`, the maximum exported sequence bound of the snapshot.

Only after that write succeeds does the response carry the CSV plus trusted
metadata headers (`X-Export-Row-Count`, `X-Export-Id`, `X-Export-Sha256`). An audit
failure releases no CSV. The expected `export_audits` schema is discovered on the
required write, after the snapshot is prepared: a missing writer or invalid policy
is rejected before any read, but a missing table or failed write aborts before CSV
release without necessarily being detected before the snapshot. This row proves that a file was **prepared**; it does not
prove that a browser received or saved it.

## PostgreSQL bootstrap

For a new or existing database, an administrator applies `audit_schema.sql` and
then `audit_roles.sql`; the existing volume is preserved and never deleted to
re-run bootstrap. The runtime writer role receives `INSERT` on `export_audits`
and `USAGE` on its sequence **only**; the reader keeps `SELECT` on `events` and
has no `export_audits` privilege. Runtime performs no DDL and provisions no roles.

## Operator UI

- The `Export matching events` button sends the current decision/event-type/
  request-ID filters, never the page cursor.
- Pagination stays an independent 50-row view; an export covers all matching rows.
- The row count is read from the trusted response header and shown as
  `Export prepared: N rows. Download requested.` — completion of the browser save
  is not claimed.
- `413` maps to a fixed "narrow the filters" message; `401`/`503` map to fixed
  generic messages. The blob URL is revoked after the click.
- Disconnect, `pagehide` and a newer session invalidate stale export completions
  so they cannot download or repopulate the view. Cache/security headers are
  unchanged and the token remains header-only, in memory. A caller IAB check of
  the synthetic fixture confirmed the download described under Evidence limits.

## Evidence limits

Local evidence: 23 ASGI export tests over the real app with real SQLite audit
rows, plus 10 Node.js behaviour cases for the shell. The exact PostgreSQL
export-audit SQL/privilege path is checked with a driver double only. No
PostgreSQL server, Docker runtime or native Qwen model was exercised. A caller
browser run in an IAB host against the synthetic fixture displayed 50 rows,
downloaded `nasi-lemak-events-export.csv`, and parsed 126 data rows and 13
columns, all `synthetic-operator-demo`, with canonical filters
`decision=*;event_type=*;request_id=*` and SHA-256
`38e37eeb5c1923d7ed97867ad073596616487f305a0095cd8ab2b9dd7c8ba84e`. That is
synthetic browser-download evidence only; see
[execution-status.md](execution-status.md) and
[control-verification.md](control-verification.md).
