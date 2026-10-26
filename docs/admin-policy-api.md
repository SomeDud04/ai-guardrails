# Admin policy and alert API contract

This is the implemented persistence and HTTP contract for workspace policy
profiles and block alerts. The store methods perform their own authenticated
actor and admin-role checks inside the transaction. The HTTP layer passes the
authenticated ``actor_id`` from the session and never accepts a client-supplied
role, scope owner or control object. Behavior and the upgrade runbook are in
[docs/admin-policies.md](admin-policies.md).

Synthetic local tests cover SQLite. The schema-2-to-3 migration and restricted
role operations were independently checked against local PostgreSQL outside
Docker/VM; live Docker/VM coverage remains a caller release gate. No production
database is contacted by these tests.

## Values

- Settings: ``input_check_enabled: bool``, ``output_check_enabled: bool``,
  ``input_masks: list[str]``, ``output_masks: list[str]``.
- Supported masks are exactly ``EMAIL``, ``MY_PHONE`` and ``MYKAD``. An empty
  list is the explicit no-masking relaxation. ``None`` on an input setter means
  all masks; stored/read values are always lists.
- Profile revisions are immutable and numbered from 1. Every update supplies
  ``expected_revision`` (the current profile version) and raises
  ``nasi_lemak.workspace_store.Conflict`` on a lost update.
- Assignment reads/writes use ``scope_type`` in ``workspace``, ``department`` or
  ``user``. ``scope_id`` is ``None`` for workspace, otherwise the real
  department/user id. Positively scoped rows override less specific rows:
  workspace, then department, then user.
- Generic validation errors are ``ValueError``; authorisation is
  ``AccessDenied``; missing rows are ``NotFound``; storage/corrupt stored policy
  data is ``WorkspaceStorageError``. Corrupt toggles, mask text or revision
  digests fail closed and never produce a permissive control.

## HTTP surface

Every route below is served only when the workspace is enabled and ready. It
requires an authenticated workspace principal; the admin routes require the
persisted ``admin`` role before any request body is read. Cookie-authenticated
mutations additionally require the existing strict same-origin and
``application/json`` checks. The cookie-session identity header rules are the
same as the rest of ``/workspace/api``. A successful response is the store result
as JSON; errors use the generic workspace error envelope and never include SQL,
DSN, key or exception text.

| Method | Path | Request |
|---|---|---|
| `GET` | `/workspace/api/policy` | Self-only effective policy; no query |
| `GET` | `/workspace/api/admin/policy/profiles?limit=&after=` | Bounded page |
| `POST` | `/workspace/api/admin/policy/profiles` | Profile body below; `201` |
| `GET` | `/workspace/api/admin/policy/profiles/{profile_id}` | Current profile |
| `GET` | `/workspace/api/admin/policy/profiles/{profile_id}/history?limit=&after=` | Revision page |
| `POST` | `/workspace/api/admin/policy/profiles/{profile_id}/revise` | Revision body below |
| `POST` | `/workspace/api/admin/policy/profiles/{profile_id}/rollback` | `{target_revision, expected_revision}` |
| `GET` | `/workspace/api/admin/policy/audit?limit=&after=` | Policy audit page |
| `GET` | `/workspace/api/admin/policy/assignments?limit=&after=&scope_type=` | Assignment page |
| `GET` | `/workspace/api/admin/policy/assignments/{scope_type}?scope_id=` | One assignment or `assignment: null` |
| `POST` | `/workspace/api/admin/policy/assignments` | Assignment body below |
| `POST` | `/workspace/api/admin/policy/assignments/{scope_type}/clear` | `{scope_id?, expected_version?}` |
| `GET` | `/workspace/api/admin/policy/effective?user_id=` | Active-user preview |
| `GET` | `/workspace/api/admin/alerts/summary` | Per-admin totals |
| `GET` | `/workspace/api/admin/alerts` | Alert page and filters below |
| `GET` | `/workspace/api/admin/alerts/{alert_id}` | One alert |
| `POST` | `/workspace/api/admin/alerts/{alert_id}/read` | Empty object `{}` |
| `POST` | `/workspace/api/admin/alerts/{alert_id}/ack` | Empty object `{}` |

Profile create body:

```json
{"name": "Restricted support", "input_check_enabled": true,
 "output_check_enabled": true, "input_masks": ["EMAIL", "MY_PHONE", "MYKAD"],
 "output_masks": ["EMAIL", "MY_PHONE", "MYKAD"]}
```

Only ``name`` is required. Omitted check booleans default to enabled and
omitted mask values default to all three masks; an explicit empty list means no
masking. Revise uses the same settings keys plus required
``expected_revision``. Settings are a full replacement: omitted keys take the
same defaults, so send the complete desired settings.

Assignment body:

```json
{"scope_type": "department", "scope_id": "<department-id>",
 "profile_id": "<profile-id>", "profile_revision": 2,
 "expected_version": 3}
```

``scope_type`` and ``profile_id`` are required. ``scope_id`` must be absent (or
``workspace``) for workspace scope and must identify a real department/user for
the other scopes. ``profile_revision`` defaults to the profile's current
revision; it pins that revision in the assignment. Omit ``expected_version``
only when creating a new assignment; updating an existing assignment requires
its current version. An assignment for a new profile is not created by
``create_policy_profile``.

Alert list filters are ``limit`` (1–100, default 50), ``after``, ``stage``
(``input``/``output``), ``user_id``, ``department_id``, ``reason_code``,
``unread`` and ``acknowledged`` (literal ``true``/``false``). ``unread=true``
with ``acknowledged=true`` is invalid. Read/acknowledgement is per
administrator; acknowledgement also marks the alert read and both operations
are idempotent.

Status mapping: ``400`` invalid input/filter/body, ``401`` missing or invalid
session, ``403`` non-admin, identity conflict or rejected cookie origin,
``404`` missing profile/assignment/alert/user, ``409`` stale expected revision or
assignment version, and ``503`` unavailable storage/admission. A malformed
gateway block is treated as ``503`` and is not persisted as an alert.

## Policy administration (``WorkspaceStore``)

```python
create_policy_profile(
    actor_id: str, name: str, *,
    input_check_enabled: bool = True,
    output_check_enabled: bool = True,
    input_masks=MASK_TYPES,
    output_masks=MASK_TYPES,
) -> dict
```

Returns ``{id, name, revision, settings, settings_digest, created_by,
created_at, updated_at}``.

```python
list_policy_profiles(actor_id: str, *, limit: int = 50, after: str | None = None)
    -> {"items": [policy...], "next": str | None}

get_policy_profile(actor_id: str, profile_id: str) -> dict
```

```python
revise_policy_profile(
    actor_id: str, profile_id: str, expected_revision: int, *,
    input_check_enabled: bool = True,
    output_check_enabled: bool = True,
    input_masks=MASK_TYPES,
    output_masks=MASK_TYPES,
) -> dict

rollback_policy_profile(
    actor_id: str, profile_id: str, target_revision: int,
    expected_revision: int,
) -> dict
```

Both return the same policy shape. Rollback appends a new revision copying the
target settings (``rollback_of`` records the target) and never mutates history.

```python
list_policy_profile_revisions(
    actor_id: str, profile_id: str, *,
    limit: int = 50, after: str | None = None,
) -> {"items": [
    {"revision", "settings", "settings_digest", "rollback_of",
     "created_by", "created_at"}
], "next": str | None}

list_policy_audit(
    actor_id: str, *, limit: int = 50, after: str | None = None,
) -> {"items": [
    {"id", "actor_id", "action", "profile_id", "revision", "scope_type",
     "scope_id", "detail", "created_at"}
], "next": str | None}
```

Audit detail is bounded JSON text and never contains prompt/response content.

## Assignments and effective policy

```python
assign_policy_profile(
    actor_id: str, scope_type: str, scope_id: str | None, profile_id: str, *,
    profile_revision: int | None = None,
    expected_version: int | None = None,
) -> dict
```

Returns ``{id, scope_type, scope_id, profile_id, profile_name,
profile_revision, version, settings, settings_digest, created_by, updated_by,
created_at, updated_at}``. Omit ``expected_version`` only when creating a new
assignment; an existing scope requires its current version. The pinned profile
revision defaults to the profile's current revision.

```python
clear_policy_assignment(
    actor_id: str, scope_type: str, scope_id: str | None, *,
    expected_version: int | None = None,
) -> {"cleared": bool, "scope_type": str, "scope_id": str}

get_policy_assignment(
    actor_id: str, scope_type: str, scope_id: str | None = None,
) -> assignment | None

list_policy_assignments(
    actor_id: str, *, scope_type: str | None = None,
    limit: int = 50, after: str | None = None,
) -> {"items": [assignment...], "next": str | None}
```

```python
resolve_effective_policy(actor_id: str, user_id: str | None = None) -> dict
```

A regular user may resolve only themselves; an admin may preview any active
user. Returns ``{user_id, department_id, input_check_enabled,
output_check_enabled, input_masks, output_masks, revision, digest,
settings_digest, source, sources, is_default}``. ``sources`` is the explicit
workspace/department/user lineage, least to most specific; ``source`` is the
winning entry. With no assignment the defaults are both checks enabled and all
masks (``is_default: True``).

```python
resolve_gateway_control(actor_id: str, user_id: str | None = None)
    -> nasi_lemak.controls.GatewayControl
```

This is the only supported bridge to enforcement. Pass the returned immutable
object explicitly as ``Gateway.handle(..., control=control)``. Do not cache it
across turns or derive it from the request body/headers.

## Block alerts

```python
record_failed_turn(
    owner_id: str, conversation_id: str, lease_token: str, *,
    user_prompt: str, outcome: str, request_id: str | None = None,
    error_code: str | None = None, alert: dict | None = None,
) -> {"conversation_id", "version", "alert_id", "message": {...}}
```

``alert`` is required to be exactly::

```python
{
  "stage": "input" | "output",
  "reason_code": "INPUT_GUARD_BLOCK" | "INPUT_POLICY_BLOCK"
                 | "OUTPUT_GUARD_BLOCK" | "OUTPUT_POLICY_BLOCK",
  "revision": str,          # GatewayControl.revision
  "digest": str,            # 64 lowercase hex chars, GatewayControl.digest
  "sources": [{"scope_type", "scope_id", "profile_id", "revision"}],
}
```

The reason code must agree with the stage. Alert insert and blocked-turn
metadata commit atomically; an invalid alert stores nothing. ``request_id`` is
unique, so retrying the same blocked turn returns the existing ``alert_id`` and
does not duplicate the alert. Alert rows contain metadata only: no prompt,
response, ciphertext or classifier verdict. Original text stays encrypted in
``ws_messages`` and is available only through existing review grants.

```python
list_block_alerts(
    actor_id: str, *, limit: int = 50, after: str | None = None,
    stage: str | None = None, user_id: str | None = None,
    department_id: str | None = None, reason_code: str | None = None,
    unread: bool | None = None, acknowledged: bool | None = None,
) -> {"items": [alert...], "next": str | None}

get_block_alert(actor_id: str, alert_id: str) -> alert
```

Alert shape: ``{id, request_id, user_id, username, full_name, department_id,
department_name, conversation_id, message_id, stage, reason_code, reason_text,
control_revision, control_digest, control_sources, created_at, read, read_at,
acknowledged, acknowledged_at}``. Read/ack state is per administrator.

```python
alert_summary(actor_id: str) -> {"total": int, "unread": int, "acknowledged": int}

mark_block_alert_read(actor_id: str, alert_id: str)
    -> {"alert_id", "read", "read_at", "acknowledged", "acknowledged_at"}

acknowledge_block_alert(actor_id: str, alert_id: str)
    -> {"alert_id", "read", "read_at", "acknowledged", "acknowledged_at"}
```

Read and acknowledge are idempotent. Acknowledging also marks the alert read.
One administrator's state never changes another administrator's unread count
or acknowledgement.
