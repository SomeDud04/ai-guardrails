# Demo tenant isolation and per-user limits

**Status:** design for review only. Nothing here is implemented at source `ac6b5d1`. No tenancy registry, per-user quota, tenant-scoped operator key or new authentication mode exists; the legacy single-application gateway is the only runtime mode. This is a customer-demo design, not a production identity, billing or capacity platform.

**Implementation note (23 October 2026):** A separate opt-in employee workspace
implements a local, single-organisation subset only: username/password accounts,
departments, encrypted saved conversations and explicit reviewer grants. It does
not implement the multi-tenant registry, per-tenant policies/quotas or
tenant-scoped operator keys described below. Real PostgreSQL/Docker/VM
deployment and guard acceptance remain pending, and the multi-customer, RAG, SSO
and advanced department policy deferrals in this design are preserved.

**Date:** 22 October 2026. **Scope:** opt-in demo multi-user/multi-tenant authorization with bounded per-user chat admission. Guard wiring, supply-chain gates, live acceptance, factual verification and the reported MyKad/long-prompt issues remain separate subprojects.

## 1. Existing baseline

- One `Gateway` accepts one application-key digest and one `Policy` (`nasi_lemak/gateway.py`). The optional operator route has one digest and one read-only reader (`nasi_lemak/server.py`, `nasi_lemak/operator.py`).
- Audit uses the trusted `app_id` as its only tenant-like scope (`nasi_lemak/audit_schema.sql`); there is no `user_id` column.
- Bounded body, message, character, token, output, concurrency and deadline controls exist; per-user rate and per-user in-flight limits do not.
- Target runtime is one process and one Uvicorn worker (`Dockerfile`). Authentication recommendation: individual user API keys plus tenant-scoped operator keys; no browser passwords or SSO.
- The demo runs in test mode with native guards inactive; tenancy does not change that or make test-mode evidence a guard-efficacy claim.

Legacy mode is preserved exactly unless the operator supplies the registry setting in section 4.

## 2. Requirements

| ID | Requirement |
|---|---|
| R1 | Tenancy is opt-in; absent config leaves keys, policy, audit, installer secrets and data unchanged. |
| R2 | A server-owned immutable finite startup registry maps digest-only credentials to stable `user_id`/`tenant_id`. |
| R3 | Each tenant maps to one policy whose `app_id` is the canonical tenant ID; `app_id` stays the audit boundary. |
| R4 | Registry validation is complete at startup and fails closed; no default, sample, partial or legacy fallback. |
| R5 | Exactly one bearer header is authenticated before body read, provider call or expensive guard work. |
| R6 | Tenant comes only from the credential; no payload/query/header selector can change it. |
| R7 | User keys chat only; operator keys read/export only their tenant's audit. No global administrator. |
| R8 | Audit stays metadata-only; per-user attribution is not implied by the existing schema. |
| R9 | Existing `Gateway` validation/masking/ordering/audit and its authentication for direct callers are reused. |
| R10 | Per-user requests/minute and in-flight limits plus a shared global in-flight cap are enforced, with a 10-principal local capacity target. |
| R11 | Limits are bounded in-process demo controls, not durable budgets or production guarantees. |

## 3. Selected design

### 3.1 Topology

```text
FastAPI server: one-box auth gate -> registry digest lookup
  -> per-user quota -> shared global admission
     +--> user A Gateway --> tenant alpha Policy/audit
     +--> user B Gateway --> tenant alpha Policy/audit
     +--> user C Gateway --> tenant beta  Policy/audit
     +--> operator alpha key --> tenant-alpha audit/export reader
     +--> operator beta key  --> tenant-beta  audit/export reader
```

Registry and policies are read-only startup inputs. Router, quota state, tenant resources and Gateways are built once; there is no per-request Gateway, database tenant lookup or shared mutable "current tenant".

### 3.2 Registry schema and bounds

One UTF-8 JSON file, at most 64 KiB, with exactly these top-level keys: `schema_version` (`"1"`), `tenants` (array 1..16), `users` (1..100), `operators` (1..64), and `limits` (object with exactly the three keys below).

| Object | Fields and exact rules |
|---|---|
| `tenants[]` | Exactly `tenant_id`, `policy_file`. `tenant_id`: 1..128 chars, `[A-Za-z0-9][A-Za-z0-9._-]*`, equal to policy `app_id`. `policy_file`: absolute, 1..4096 chars, no NUL/scheme/`..`; existing regular file accepted by the strict loader with public model alias `pilot-local`. |
| `users[]` | Exactly `user_id`, `tenant_id`, `key_sha256`. `user_id`: 1..64 chars, `[a-z0-9][a-z0-9_-]*`. `tenant_id`: declared. `key_sha256`: exactly 64 lowercase hex chars. |
| `operators[]` | Exactly `operator_id`, `tenant_id`, `key_sha256`, with the same ID/digest rules as users. |
| `limits` | `per_user_requests_per_minute` integer 1..600; `per_user_in_flight` 1..8; `global_in_flight` 1..64 and at least `per_user_in_flight`. Booleans are rejected everywhere. |

Startup fails closed on: missing/unreadable/oversized/non-UTF-8/non-object file; duplicate JSON keys; unknown, missing or wrong-typed fields; trailing or unparseable JSON; empty arrays; a tenant without a user or operator; duplicate IDs; a digest reused by any user or operator (including across roles); unknown tenant; invalid ID/digest/path/limit; policy load failure, `app_id` mismatch or wrong model alias; and any empty or placeholder credential. `policy_file` is an operator startup input, never client-derived.

### 3.3 Conceptual example (invalid input)

```json
{"schema_version":"1",
 "tenants":[{"tenant_id":"tenant-alpha","policy_file":"/run/tenancy/policies/tenant-alpha.yaml"},
            {"tenant_id":"tenant-beta","policy_file":"/run/tenancy/policies/tenant-beta.yaml"}],
 "users":[{"user_id":"user-01","tenant_id":"tenant-alpha","key_sha256":"REPLACE_WITH_64_LOWERCASE_HEX"},
          {"user_id":"user-02","tenant_id":"tenant-beta","key_sha256":"REPLACE_WITH_64_LOWERCASE_HEX"}],
 "operators":[{"operator_id":"operator-alpha","tenant_id":"tenant-alpha","key_sha256":"REPLACE_WITH_64_LOWERCASE_HEX"},
              {"operator_id":"operator-beta","tenant_id":"tenant-beta","key_sha256":"REPLACE_WITH_64_LOWERCASE_HEX"}],
 "limits":{"per_user_requests_per_minute":10,"per_user_in_flight":2,"global_in_flight":10}}
```

The placeholders are rejected; this shows shape only and is not usable input.

### 3.4 Credentials

- Generate a fresh key per principal (target at least 32 random bytes, e.g. `secrets.token_urlsafe(32)`); only its SHA-256 digest enters the registry.
- Raw keys are distributed out-of-band and never committed, put in URLs, browser storage/cookies, issue trackers or logs. The demo page keeps a key in tab memory and sends it only as `Authorization`; JavaScript tests cover no-storage/no-console and plain-text rendering (`tests/test_demo_js.py`), but a real-browser check is pending.
- Rotation/revocation is a registry edit plus controlled restart; no hot reload. A key authenticates but does not prove a person or prevent sharing.

### 3.5 Authentication and routing seam

1. Reject anything except exactly one `Authorization` header starting with `Bearer ` with a non-empty candidate of at most 4096 characters.
2. SHA-256 hash and look up in the immutable startup index; unknown digests get generic `401` with no quota entry.
3. A frozen principal `{role, subject_id, tenant_id, gateway, operator_reader}` binds role and tenant to the credential; no fallback or shared tenant state.
4. Select that principal's prebuilt user `Gateway`, or the tenant reader. The body is read only after authentication and admission; tenant is never read from body, query or `X-Tenant`; unknown payload fields are rejected.

Construct one `Gateway` per user at startup (bounded by 100), sharing the tenant's immutable policy, audit store and adapters. The router calls the existing `Gateway.handle` with the same header, preserving `Gateway` authentication; the registry check is defense in depth, not a second header. No bypass flag or mutable tenant pointer exists. A future one-Gateway-per-tenant variant needs a separately designed authenticated server-side entry point.

### 3.6 Shared tenant resources and shutdown

- Users of one tenant share the tenant's single policy, audit store/writer, operator reader, and generation/guard adapters. Do not create a store, connection pool or adapter per user.
- Preserve the audit store's documented thread-safety. Do not assume a lock wrapped around one tenant Gateway serializes access through another: any necessary synchronization belongs to the shared store/adapter itself so every Gateway and shutdown path uses the same lock.
- On shutdown, stop admission, let outstanding workers finish (bounded grace period), then close each unique resource exactly once. Close must be idempotent and never run while a worker still uses the resource. Per-user Gateways are references, not owners.
- Startup constructs each unique resource once and deduplicates by identity; double-close or close-while-busy is an acceptance failure.

### 3.7 Tenant policy and audit

`policy.app_id` must equal `tenant_id`; each user Gateway writes only its tenant's `app_id`. Operator scope comes from the authenticated principal, never the query: `/admin/events` and `/admin/export.csv` are always tenant-bound, with no global view. A user key cannot reach admin routes; an operator key cannot chat (no mapping exists in either direction).

Tenant audit is in first scope using the existing metadata-only shape and `app_id`; no `user_id` column or attribution is added. That requires a migration, reader/export changes and retention decisions, so it is a separate follow-on. A tenant event proves tenant scope, not which user sent it. No prompt, response, key, digest or DSN enters an audit event.

## 4. Configuration, opt-in and collisions

### 4.1 Opt-in

```text
NASI_LEMAK_TENANCY_REGISTRY_FILE=/run/tenancy/tenancy.json
```

Non-empty presence enables registry mode. Absent = legacy mode. Empty or whitespace-only = configuration failure. Missing/unreadable/invalid file = configuration failure. There is no separate mode switch and no fallback. Registry and policies are mounted read-only (Compose secret or read-only bind mount) and readable by runtime UID 10001; fixtures may use a temp directory.

### 4.2 Reused and forbidden settings

Registry mode reuses `NASI_LEMAK_AUDIT_DSN[_FILE]`, `NASI_LEMAK_OPERATOR_AUDIT_DSN[_FILE]`, `NASI_LEMAK_MODE`, `NASI_LEMAK_ALLOW_UNGUARDED_TEST` and existing generation/guard settings. Writer and reader DSNs must be distinct and the reader SELECT-only; missing operator reader config leaves admin routes at the existing generic `503` and never widens chat scope.

These legacy identity settings are forbidden in registry mode:

```text
NASI_LEMAK_APP_KEY_DIGEST[_FILE]   NASI_LEMAK_OPERATOR_KEY_DIGEST[_FILE]
NASI_LEMAK_POLICY_FILE
```

Presence of the registry variable plus any of these is a startup identity failure: no router is built, readiness is not ready, chat and admin routes return the existing generic `503`, and there is no precedence rule, merge or fallback. With the registry variable absent the worker never reads a tenancy file and current installer, secrets, policy, data and Compose defaults are untouched.

### 4.3 Deployment artifact is future work

The current committed stack cannot be enabled by adding the registry variable:

- `compose.yaml` declares `NASI_LEMAK_APP_KEY_DIGEST_FILE` on the gateway unconditionally; the test/pilot overlays add `NASI_LEMAK_POLICY_FILE` and the operator digest secret.
- Compose merges service `environment` mappings. Deleting a value from an env file does not remove a key already declared by an included Compose file; an empty value is still present and forbidden.
- No command built only from today's overlays can satisfy the forbidden-setting rule. This document provides none and does not claim one works.

A future enablement must ship one separate, complete opt-in Compose file (working name `compose.tenancy.yaml`) with its own env file, not an overlay. It must preserve project `nasi-lemak`, the `db` service and `nasi_lemark_db` volume, the `db_internal` network, and gateway service name/ports; its gateway environment must omit every forbidden variable (not set them empty), add `NASI_LEMAK_TENANCY_REGISTRY_FILE`, and mount registry and tenant policies read-only. Whether Compose `!reset`/`!override` syntax or a minimum version can remove keys is unverified and not relied on. Authoring the file and proving the rendered service environment/mounts contain no forbidden variable is future implementation/acceptance work, pending. The current deployment remains unchanged.

## 5. Lifecycle and errors

### 5.1 Startup

1. Read environment and choose legacy or registry mode; in registry mode reject forbidden legacy settings.
2. Read the registry once under a hard byte cap; reject duplicate keys and any shape/type deviation.
3. Load every policy via the strict loader and require `app_id == tenant_id`; validate the full identity graph, including cross-role duplicate digests.
4. Resolve writer/reader, then build unique tenant resources, Gateways, quota state and digest index. Readiness requires all mandatory config and audit checks; one invalid tenant invalidates the whole registry. No hot reload or watcher.

### 5.2 Request

1. Authenticate exactly one bearer header before reading the body. Unknown identity or role confusion: `401`, with no body read, provider, guard or quota allocation.
2. Try global chat admission without queueing; exhaustion gives the existing `503` with no quota allocation.
3. Reserve the per-user rated slot (6.2). Exhaustion: release the global slot and return `429` with bounded `Retry-After`.
4. Reserve the per-user in-flight slot. Exhaustion: release the global slot and return `429`; the consumed rate count is not refunded.
5. Read the body. A body/shape failure releases in-flight and global exactly once, returns the existing 4xx, and leaves the rate count consumed.
6. Dispatch to the tenant Gateway for existing validation, token, attack guard, PII, generation, output guard, deny-phrase and audit ordering.
7. Release in-flight/global only when the real worker completes, never at HTTP timeout, response cancellation or on a late result.

### 5.3 Errors

| Situation | Response | Notes |
|---|---|---|
| Registry invalid, or registry plus legacy identity present | Chat/admin `503`; not ready | No fallback or precedence |
| Tenant policy invalid / `app_id` mismatch | Startup fail closed | No partial tenant |
| Missing/duplicate/invalid bearer, unknown key, wrong role | `401` | Before body, provider and quota |
| Forged tenant payload field | `400` | Strict schema rejects it |
| `X-Tenant`-style header | Ignored | Tenant unchanged |
| Per-user rate/in-flight cap | `429` + `Retry-After` | No identity or count leak |
| Global in-flight cap | Existing `503` | No queueing or `Retry-After` |
| Body/token/guard failure | Existing `400`/`413`/`403`/`503` | In-flight released; rate count stays |
| Audit write or reader failure | Existing generic `503` | Fail-closed ordering preserved |

## 6. Per-user and global limits

### 6.1 Controls

- `per_user_requests_per_minute`: fixed 60-second admission window per user.
- `per_user_in_flight`: concurrent accepted chat workers per user.
- `global_in_flight`: concurrent accepted chat workers across users.

Example values (10, 2, 10) are configuration examples, not throughput claims. The global cap follows the existing non-queuing chat admission; admin/readiness retain their control-plane bound. A restart resets state; multiple instances or workers are unsupported for quota correctness.

### 6.2 Counted request versus releasable in-flight reservation

- The **counted request** is consumed when the per-user rate slot is reserved. It is never decremented or refunded, including on malformed body, in-flight rejection, token/guard/generation failure, completion, timeout or cancel. Only real admission consumes it; auth/role failures, unknown identities, admin reads and readiness probes never do.
- The **in-flight reservation** is releasable capacity, released exactly once when the real worker completes or when setup/body handling fails after acquisition. It is retained across HTTP timeout and client cancellation until that worker returns.
- A malformed body therefore consumes the admitted rate count but releases in-flight/global; it does not decrement the rate counter. Normal completion releases in-flight, not the rate count.
- Unknown identities never create a quota dictionary entry; lookup is read-only until an authenticated user is known.

The clock is a monotonic float (`time.monotonic()`); a window resets when `now - window_start >= 60.0`. Reservations must be thread/event-loop safe (`threading.Lock` or equivalent explicitly justified primitive), with no double release and no unbounded state.

### 6.3 Retry-After

Per-user rejection uses the existing envelope with stable code `RATE_LIMITED` and a fixed generic message. `Retry-After` is an integer 1..60: for rate exhaustion, the ceiling of the remaining window (not truncated to an integer clock tick), clamped; for in-flight exhaustion, `1` as a bounded hint, not a completion promise. No user/tenant ID, digest or count is returned.

### 6.4 Not provided

This is not a durable daily/token/currency budget, billing, fair-share scheduler or production rate limit. It does not survive restart, coordinate processes, prevent key sharing or promise latency. Existing body/message/character/token/output/concurrency/deadline bounds remain in force.

## 7. Test acceptance (proposed)

Not implemented in this docs slice; synthetic capacity evidence only, with no VM, model, guard, PostgreSQL or provider throughput and no latency SLA.

| ID | Scenario | Expected |
|---|---|---|
| TEN-01 | Schema: unknown/missing/duplicate fields or JSON keys, empty arrays, bad IDs/digests/paths/limits, unknown tenant, cross-role duplicate digest, `app_id` mismatch, oversized/unreadable file | Startup fails closed; no tenant, no legacy fallback |
| TEN-02 | Registry plus each forbidden legacy identity setting | Fail closed; unambiguous readiness/chat/admin behaviour |
| TEN-03 | Missing/duplicate/wrong header, unknown key, operator-on-chat, user-on-admin | Generic `401`; no body read, provider/guard work or quota entry |
| TEN-04 | Ten principals across >=2 tenants admitted behind bounded barriers/counters | Genuine overlap; no identity, output or audit crossover |
| TEN-05 | Eleventh concurrent request at `global_in_flight=10` | Exactly ten admitted; eleventh gets `503`; no extra dispatch |
| TEN-06 | Per-user rate/in-flight caps with two users | Only offender gets bounded `429`; other user unaffected |
| TEN-07 | Worker gate held past HTTP deadline, then cancel | In-flight retained, same-user request rejected, capacity recovers exactly once |
| TEN-08 | Forged tenant in payload/query/header; unknown payload fields | `400` for fields; header/query cannot change tenant |
| TEN-09 | Operators A and B list/export their tenants | Every row/CSV scoped to authenticated tenant; no global view; no user admin access |
| TEN-10 | Audit after success, block, failure, timeout; shared-store shutdown | Metadata only; correct `app_id`; each unique resource closed once after workers finish |
| TEN-11 | Legacy regression with registry absent | Existing config and single-application tests unchanged |

Concurrency tests must use real threads/workers and explicit barriers, not merely serialized requests. Tests use synthetic/loopback fixtures and no real external service.

## 8. Rollout and reversal

Demo update only; no unattended production deployment, installer rerun or database migration. Stop the old process before starting tenancy because quota state is in-process and the target is one worker.

1. Preserve current env, policy, registry, `.secrets` and audit volume; do not overwrite them.
2. Generate fresh keys outside the repository; record only digests in a new registry. Never place raw keys in Git, commands, screenshots, chat or logs.
3. Keep one policy per tenant with `app_id` equal to the tenant ID, plus the untouched legacy policy; mount registry/policies read-only for UID 10001.
4. Validate with a read-only validator and render/inspect the tenancy Compose artifact before starting. Both are future implementation requirements; this document has not validated a real registry or deployment.
5. Confirm the rendered gateway environment omits every forbidden variable and writer/reader settings are valid and distinct. Do not print secrets.
6. Stop the old gateway (no `down -v`, no volume deletion), start the tenancy artifact, then check liveness, readiness and one negative case per role.
7. Rotate/revoke by registry edit plus restart. Roll back by stopping tenancy, restoring prior config/mounts and starting the previous stack; audit rows stay readable because `app_id` is reused. No reinstall or migration.

## 9. Alternatives and exclusions

Rejected: client-supplied tenant field (spoofable); browser passwords/SSO (large account surface); one global operator key (breaks isolation); one Gateway per tenant with a bypass entry point; Gateway per request (unbounded); token-bucket/sliding-window (more state than a demo needs); durable Redis/PostgreSQL quota store (adds dependency/consistency work); immediate `user_id` schema change (separate migration); per-user daily/token/currency budgets (billing-grade).

Not in this subproject: browser accounts/registration/profiles; global admin or cross-tenant audit/export; per-user audit attribution; durable quotas, budgets, billing or chargeback; TLS/nginx/topology changes; confirmed input-guard API, Qwen startup wiring or guard-efficacy claims; SBOM/scanner/signature/immutable digest gates; MyKad or long-prompt reproduction; live model/VM acceptance; factual/price verification; tools, function calling, retrieval, vector stores, training, fine-tuning or ingestion.

## 10. Validation status

Caller ran this turn on synthetic local fixtures: `python -m unittest tests.test_operator tests.test_policy tests.test_chat_deadline -q` -> **51 tests in 3.961s, OK**. That caller-run subset is distinct from the docs worker's checks. The docs worker ran only `git diff --check`, verified cited paths and test names exist, and confirmed only the two requested docs changed; it did not rerun the suite. Historical context (not fresh, not tenancy evidence): full release 428 tests, 426 passed, 2 real-PostgreSQL skips; focused checkpoint 68 passed in 9.143s. TEN-01..TEN-11 are proposed until implemented. In [owasp-verification-matrix.md](owasp-verification-matrix.md), only rows explicitly marked **Proposed (not implemented)** remain pending; existing matrix tests retain their dated, scoped synthetic evidence and are not downgraded here. No real endpoint, Docker daemon, PostgreSQL server or VM was used.
