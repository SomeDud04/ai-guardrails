# Workspace administrator policies and in-app block alerts

This document describes the implemented administrator policy and block-alert
release for the opt-in `/workspace` surface. It does not replace the startup
YAML policy in [docs/policy.example.yaml](policy.example.yaml), which remains a
single server-side file enforced for every request. Administrator policy
profiles apply only to workspace turns and can change only two model-safety
toggles, the selected PII masks, and an optional tightening of four chat limits.
They cannot edit the startup policy, the legacy direct OpenAI-compatible API,
authentication, or audit ordering, and they can never raise a chat limit above
the server ceiling.

## Before an existing deployment is upgraded

**Schema version 2 is no longer accepted by the new gateway. Migration to schema
3 is explicit and must be completed before the new image can serve workspace
traffic.** The new gateway stays live but reports not ready (`503`) until the
workspace database reports schema version 3.

An existing VM upgrade therefore requires all of the following:

- preserve the PostgreSQL data volume, existing accounts and saved
  conversations, the encryption key and every existing secret file;
- keep the currently deployed mode/API/guard/chat-limit/NGINX env files and
  overlays; do not rerun the installer, bootstrap another administrator,
  generate a new key or use `docker compose down -v`;
- run the packaged `workspace_cli init` against the **actual** workspace
  database with an operator-privileged migration DSN and the **same** Fernet
  key;
- reapply the packaged `nasi_lemak/workspace_roles.sql` grants to that same
  workspace database after the schema migration;
- keep the long-running gateway non-root with the restricted runtime DSN.

The detailed sequence, backup instructions and grant command are in
[Upgrading an existing schema-2 deployment](#upgrading-an-existing-schema-2-deployment).
Back up the database and key to private paths outside Git. The migration is
additive, but an older gateway image does not accept schema 3; rolling back the
code alone is not sufficient once the schema has been migrated.

## Acceptance checklist

- A new profile exists without being applied to anyone. Assignment is explicit.
- A revision is immutable. Editing a profile appends a revision and leaves old
  revisions and existing assignments unchanged.
- Each assignment pins one profile revision. Adopting a newer revision requires
  an explicit reapply; clearing an assignment requires an explicit clear.
- The effective policy for a user is shown before enforcement, and an
  administrator can preview any active user.
- Changes apply on that user's next workspace turn, not to a turn already in
  flight. The legacy direct API keeps its existing full-check/full-mask
  defaults.
- Block alerts appear in the workspace admin panel only. Read and
  acknowledgement state is per administrator.
- Alert metadata does not contain prompt or response text; original content
  still requires an explicit review grant.
- Readiness, an existing-user login, an existing conversation and the admin
  policy/alert panels work after the migration.
- No claim is made for live guard quality, load capacity, OWASP acceptance or a
  completed full-suite/VM/Docker run.

## Policy profiles, revisions and assignments

### Profiles are created unassigned

`create_policy_profile` creates a named profile at revision 1. It is not
assigned to the workspace, a department or a user. Creating a profile is
therefore a safe preparation step; enforcement does not change until an
administrator assigns it.

### Revisions are immutable

A profile revision stores:

- `input_check_enabled` and `output_check_enabled`;
- `input_masks` and `output_masks`, each a subset of `EMAIL`, `MY_PHONE` and
  `MYKAD` (the PII recognizer names; the UI may display MyKad);
- a settings digest, author and creation time.

`revise_policy_profile` appends a new revision and advances the profile's
optimistic-concurrency version. `rollback_policy_profile` also appends a new
revision that copies the selected old settings; it never rewrites history.
Every update supplies `expected_revision`, and a lost update returns a conflict
rather than silently overwriting another administrator.

### Assignments pin one revision

An assignment maps exactly one scope to one profile revision:

- `workspace` (`scope_id` is `None` or `workspace`);
- `department` (a real department id);
- `user` (a real user id).

The profile revision is pinned when the assignment is made. A later profile
revision does **not** change existing assignments. To adopt the newer revision,
reapply the assignment with its current assignment `expected_version` and the
desired `profile_revision` (or omit `profile_revision` to pin the current
profile revision). To fall back to a less specific scope or the defaults, clear
the assignment explicitly with its current `expected_version`.

Only one assignment exists per scope. The schema's composite foreign key
prevents an assignment from pointing at a missing or mismatched revision.

### Resolution is a full-profile override

For a workspace turn the store resolves the authenticated user's exact lineage,
least specific to most specific:

1. workspace assignment;
2. department assignment;
3. user assignment.

The most specific assignment supplies the complete settings object. This is a
full-profile override, not a field-by-field merge: a user profile with input
masking disabled does not inherit the department's input mask list, and its
`limits` mapping replaces the department's mapping rather than merging with it.
`sources` in the effective-policy result shows the explicit lineage, and
`source` shows the winning entry.

With no matching assignment, the defaults are: both model checks enabled and
all three masks (`EMAIL`, `MY_PHONE`, `MYKAD`). The preview reports
`is_default: true`.

### Effective user preview

- A regular user may resolve only their own policy at `GET
  /workspace/api/policy`.
- An authenticated administrator may preview any active user at `GET
  /workspace/api/admin/policy/effective?user_id=...`.
- Disabled or missing users are not previewed.
- The preview returns the settings, revision, digest, winning source and full
  source lineage. It is informational; enforcement still happens server-side
  on the turn.

## What an administrator may and may not relax

An authenticated user with the persisted `admin` role may create profiles that:

- disable the input model-safety classifier check;
- disable the output model-safety classifier check;
- select any subset of `EMAIL`, `MY_PHONE` and `MYKAD` for input masking;
- select any subset for output masking;
- select no masks (an empty list), which is the explicit no-masking
  relaxation;
- tighten any of the four chat limits (`context_messages`, `context_budget`,
  `default_reply_tokens`, `max_reply_tokens`) for that profile. An omitted
  field keeps the server value, and an empty `limits` mapping means no profile
  tightening.

In the `/workspace` admin policy form, the "Chat limits" fieldset exposes those
four fields as optional whole numbers (context messages, context budget, default
reply tokens, max reply tokens). Each field shows the server ceiling beside it,
and blank means the server value applies. The form rejects a non-positive value
and a default reply above the max reply, while a value above the ceiling is
allowed with a visible "will be clamped" warning because the server only
tightens. The profile list and history show the limits a profile sets (or
"Server limits"), and the effective-user preview lists each effective value and
marks any field tightened below the ceiling.

The server ceiling for those limits is resolved once at startup: the
environment values (or their built-in defaults), then the optional top-level
`limits` mapping in the startup policy. A profile value may only tighten that
ceiling; a value above it is clamped to the ceiling and is never an increase.
Administrators cannot change the environment, the startup policy or the
ceiling itself.

These toggles and limits are independent. Disabling the input classifier does
not disable input PII masking, the literal deny phrases, request validation or
limits. Disabling output masking does not disable the output classifier or the
output deny-phrase check. Disabling both classifiers does not disable any of the
following, which remain unconditional:

- application-key authentication and workspace session checks;
- request-shape, body-size, context and token-budget limits;
- startup YAML literal deny phrases (input and output);
- audit-before-release ordering;
- readiness and fail-closed unavailable handling;
- the server's TLS/transport requirements.

A corrupt stored toggle, mask list, digest or profile revision fails closed; it
never produces a more permissive effective policy. A policy-store failure
before a provider call returns `503 UNAVAILABLE`, not a permissive turn.

## Runtime application

For each workspace turn, after the session is revalidated and before context is
read or a provider is called, the gateway resolves one immutable
`GatewayControl` from committed policy rows. That snapshot is passed explicitly
to `Gateway.handle` for that turn. It is not cached across turns and is never
read from a request body, header or client-supplied role.

Committed changes are therefore visible on the **next workspace turn**. A turn
already in flight keeps its snapshot, even if a profile or assignment changes
concurrently. There is no websocket push or hot reload; refresh the admin page
to see new policy rows.

The legacy direct `POST /v1/chat/completions` path does not supply a workspace
control. It keeps the existing defaults: both model checks enabled and all
three masks. Administrator profiles cannot weaken that path. The startup YAML
policy continues to apply to both paths.

### Guardrail details for a turn

An allowed or blocked workspace turn returns a `guardrail` summary, shown under
the message: `input_check` and `output_check` (`safe`, `blocked`, `off` when the
policy disabled the check, or `not_run` when the turn never reached it),
`input_pii_masked`, `output_pii_masked` and the audit-derived `latency_ms`. It
holds only those fixed values, never classifier text, categories, prompts or
withheld output.

The summary is not stored. The page keeps it in memory for the session, so a
reloaded conversation shows the saved Blocked or Failed labels without it.

## In-app block alerts

When a workspace turn is blocked by an exact, known policy block from the
gateway, the blocked-turn record and one alert row commit atomically. Supported
reason codes are:

| Stage | Reason code | Safe client text |
|---|---|---|
| input | `INPUT_GUARD_BLOCK` | The prompt did not pass the input safety check. |
| input | `INPUT_POLICY_BLOCK` | The prompt contains content disallowed by policy. |
| output | `OUTPUT_GUARD_BLOCK` | The response did not pass the output safety check. |
| output | `OUTPUT_POLICY_BLOCK` | The response contains content disallowed by policy. |

The blocked response contains the fixed stage/reason text and a stable `ref`
(the gateway request id). It never contains classifier output, a prompt or
withheld model text. The same request id is used for the alert, so retrying the
same blocked turn does not duplicate it.

Outages are not blocks. Provider, guard, audit or policy-store failures, an
unknown/malformed block shape, cancellation, timeout or overload return a
generic `503` and are not recorded as a policy block or an alert.

### Metadata, not content

An alert row contains only bounded metadata:

- alert id, gateway request id, user and department display metadata;
- conversation and failed-message ids;
- stage, fixed reason code and fixed reason text;
- policy revision, digest and source lineage;
- creation time and per-administrator read/acknowledged state.

It contains no prompt, response, ciphertext, classifier verdict, rule text or
credential. The original user prompt remains encrypted in `ws_messages` like
any other saved workspace message. Only the existing explicit review-grant path
can decrypt it; an administrator has no implicit content access merely because
they can see the alert.

Deleting a chat removes its encrypted conversation content and messages. Alert
metadata is independent and can remain afterwards for the administrator audit
view; it does not retain the deleted text.

### In-app only, per administrator

There is no email, Microsoft Teams, webhook or other outbound notification.
Alerts live inside the authenticated `/workspace` admin panel and API.

Read and acknowledgement state is stored per administrator. Marking one alert
read or acknowledged does not change another administrator's unread count or
state; acknowledgement also marks the alert read and is idempotent.

The admin page refreshes its alert summary about every 30 seconds while an
administrator is signed in and the tab is visible. This is a UI convenience,
not a delivery guarantee; hidden tabs stop the timer. A failed summary refresh
leaves the last known state or shows an unavailable marker rather than making
chat unavailable.

## HTTP summary

The detailed persistence contract is in
[docs/admin-policy-api.md](admin-policy-api.md). Every route below requires an
authenticated workspace principal, and every admin route requires the persisted
`admin` role before the body is read. Cookie-authenticated mutations also
require the existing same-origin and JSON content-type checks.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/workspace/api/policy` | Self-only effective policy and source lineage |
| `GET` | `/workspace/api/admin/policy/profiles` | List profiles |
| `POST` | `/workspace/api/admin/policy/profiles` | Create an unassigned profile |
| `GET` | `/workspace/api/admin/policy/profiles/{id}` | Current profile and revision |
| `GET` | `/workspace/api/admin/policy/profiles/{id}/history` | Immutable revision history |
| `POST` | `/workspace/api/admin/policy/profiles/{id}/revise` | Append a revision |
| `POST` | `/workspace/api/admin/policy/profiles/{id}/rollback` | Append a copied revision |
| `GET` | `/workspace/api/admin/policy/audit` | Policy-administration audit |
| `GET` | `/workspace/api/admin/policy/assignments` | List assignments |
| `GET` | `/workspace/api/admin/policy/assignments/{scope_type}` | One assignment |
| `POST` | `/workspace/api/admin/policy/assignments` | Set or reapply an assignment |
| `POST` | `/workspace/api/admin/policy/assignments/{scope_type}/clear` | Clear an assignment |
| `GET` | `/workspace/api/admin/policy/effective?user_id=...` | Admin user preview |
| `GET` | `/workspace/api/admin/alerts/summary` | Per-admin totals |
| `GET` | `/workspace/api/admin/alerts` | Filtered, paginated alerts |
| `GET` | `/workspace/api/admin/alerts/{id}` | One alert |
| `POST` | `/workspace/api/admin/alerts/{id}/read` | Mark read (send `{}`) |
| `POST` | `/workspace/api/admin/alerts/{id}/ack` | Acknowledge (send `{}`) |

Invalid input returns a generic `400`; missing rows `404`; a non-admin or
cross-origin cookie write `403`; a stale optimistic-concurrency version `409`;
and storage/busy/unavailable conditions `503`. Error bodies never include SQL,
DSNs, keys or raw exception text.

Profile responses carry the profile's raw `limits` mapping (empty when the
profile tightens nothing) and `settings.ceiling`, the server effective limits
that a profile may only tighten. Create, revise and rollback accept an optional
`limits` object; invalid values are a generic `400`. The effective preview
additionally returns `ceiling` and `effective_limits`, i.e. the profile's
`limits` clamped to that ceiling.

## Upgrading an existing schema-2 deployment

This procedure is for the existing Docker Compose VM. It is an upgrade, not a
reinstall. Repeat **every** `--env-file` and `-f` argument that the running
stack already uses, in the same order. The example below shows test mode plus
the workspace overlay; keep a pilot/hosted API/demo/chat-limit file or overlay
instead when that is what is deployed. Do not use the base-only command.

```bash
# Example chain. Keep the real deployed env files and overlays, in order.
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  config
```

Confirm the rendered service uses the same workspace database, the same
read-only key/DSN secrets, the same network and the existing gateway UID
`10001`. Save the rendered output to a private file if the operator needs it;
do not add it to Git.

### 1. Preserve VM-only patches before `git pull`

The deployed checkout may contain VM-specific edits. Create a private root-only
backup directory first, then save tracked and untracked changes separately:

```bash
git status --short
sudo install -d -m 0700 -o root -g root /var/backups/ai-guardrails
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
git diff HEAD --binary \
  | sudo tee "/var/backups/ai-guardrails/vm-local-changes-$STAMP.patch" >/dev/null
mapfile -d '' untracked < <(git ls-files --others --exclude-standard -z)
if [ "${#untracked[@]}" -gt 0 ]; then
  sudo tar -czf "/var/backups/ai-guardrails/vm-untracked-$STAMP.tar.gz" \
    -- "${untracked[@]}"
fi
```

Review both backups before changing the checkout. If local changes exist,
reconcile them against the new release before pulling; do not discard them and
do not stage secrets. Do not use an automatic `git stash push`/`git stash pop`,
which could pop an unrelated older stash. Run `git pull --ff-only` only once the
working tree is safe to update, then reapply and review any deliberately kept
VM-specific edits. This upgrade keeps the existing mode and API/guard/chat-limit
env files, NGINX configuration and overlays unchanged. Never commit local
secrets or patches.

### 2. Stop only the gateway, then back up the database and key

Leave PostgreSQL running. Do not delete the volume and do not use `down -v`.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  stop gateway

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="/var/backups/ai-guardrails/workspace-$STAMP.dump"
sudo install -d -m 0700 -o root -g root /var/backups/ai-guardrails
set -o pipefail
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' \
  | sudo tee "$BACKUP" >/dev/null \
  || { echo "error: workspace database dump failed; stop before migrating" >&2; exit 1; }
sudo test -s "$BACKUP" \
  || { echo "error: workspace dump is empty; stop before migrating" >&2; exit 1; }
sudo cat "$BACKUP" \
  | sudo docker compose \
      --env-file .secrets/compose.env \
      --env-file .secrets/compose.test.env \
      --env-file .secrets/compose.workspace.env \
      -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
      exec -T db pg_restore --list >/dev/null \
  || { echo "error: workspace dump is not a valid archive; stop before migrating" >&2; exit 1; }
sudo chmod 0400 "$BACKUP"
sudo install -m 0400 -o root -g root .secrets/workspace/workspace_key \
  "/var/backups/ai-guardrails/workspace_key-$STAMP"
```

Run these commands in one bash shell so `pipefail` is active. If `pg_dump`,
the emptiness check or the archive check fails, stop before migration and fix
the backup; do not continue with an unverified dump.

**Confirm the actual workspace database before dumping or granting.** The
example dumps `$POSTGRES_DB` from the Compose `db` service. That is safe only
when the deployed workspace really uses that database. Verify the workspace
database from the preserved workspace DSN/env files. Do not assume the Compose
`db` service's `$POSTGRES_DB` is the workspace database, and never substitute the
audit database. If the workspace uses a separate or external PostgreSQL
database, use that database's own backup and migration procedure; never apply
these commands or grants silently to the audit database.

The key backup is as important as the database backup. Store both under a
private root-only path outside the checkout and outside Git. Do not print the
key. If the key is lost, existing conversation content cannot be recovered.

### 3. Build the new gateway image

Build with the same chain, before or while the old gateway is stopped. The
existing database and volumes are not touched.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  build gateway
```

Do not change the Dockerfile target, add ML dependencies or regenerate the key.

### 4. Run the explicit schema-3 migration

This is the only step that opens the workspace database with `migrate=True`.
Use the operator migration DSN file and the existing key. The same `init`
command upgrades a schema-2 database in place: it adds the policy/alert tables
and indexes, retains users/conversations and checks the key verifier. It does
not create or reset an administrator.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  run --rm --no-deps \
  -v "$PWD/.secrets/workspace:/secrets:ro" \
  --entrypoint python gateway \
  -m nasi_lemak.workspace_cli init \
  --dsn-file /secrets/migration_dsn \
  --key-file /secrets/workspace_key
```

The one-off container runs as the gateway's UID `10001`, not root: the service
drops every capability, so container root cannot enter the `0700` secrets
directory. `migration_dsn` must therefore be owned by `10001:10001`.
Never pass the DSN or password in argv or an environment variable, and
never point the runtime `NASI_LEMAK_WORKSPACE_DSN_FILE` at the migration DSN.

If the migration DSN was removed during the earlier setup, recreate it privately
as described in
[docs/workspace-setup.md](workspace-setup.md#2-generate-the-stable-encryption-key)
(section 2). Never overwrite or regenerate `workspace_key`; reuse the preserved
key.

If the migration reports a key mismatch or an unsupported schema, stop. Keep
the existing database and backups; do not recreate the volume, rerun
`bootstrap-admin` or generate a new key.

### 5. Reapply the packaged grants to the actual workspace database

The new policy and alert tables need the updated grants. Read the migration DSN
**inside** the one-off container from `/secrets/migration_dsn` and execute the
packaged `nasi_lemak/workspace_roles.sql` with psycopg. Do not put the DSN in
argv, an environment variable, a log or a traceback.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  run --rm --no-deps -T \
  -v "$PWD/.secrets/workspace:/secrets:ro" \
  --entrypoint python gateway - <<'PY'
import pathlib
import sys

import psycopg

try:
    dsn = pathlib.Path("/secrets/migration_dsn").read_text(encoding="utf-8").strip()
    sql = pathlib.Path("nasi_lemak/workspace_roles.sql").read_text(encoding="utf-8")
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
except Exception:
    print(
        "error: workspace grants failed; no changes were committed",
        file=sys.stderr,
    )
    raise SystemExit(1)

print("workspace grants applied")
PY
```

This is a transaction: a failed statement rolls back that grant run. The
generic message intentionally omits the exception, DSN, password and SQL
details. If it fails, leave the gateway stopped and retry after fixing the
database/DSN. Do not fall back to the interactive `db exec ... psql
"$POSTGRES_DB"` form unless the operator has confirmed that this is the
workspace database; applying grants to the audit database is not a valid
workaround.

### 6. Restart only the gateway and verify

Do not restart or recreate the database. A gateway that failed initialisation
while the schema was still version 2 does not recover automatically merely
because the database version changed. Restart it only after both the migration
and the grant reapplication have succeeded. Recreate the gateway with the new
image, then verify the real flows before removing the migration credential.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  up -d --no-deps --force-recreate gateway
```

Check, in this order:

1. `GET /health/ready` returns `200 {"status":"ready"}`. A `503` means the
   gateway or workspace schema/key/DSN is not ready; do not claim success.
2. An existing user signs in at `/workspace`; the session and department are
   correct.
3. An existing conversation opens and its saved messages decrypt with the
   preserved key.
4. An administrator opens the policy panel, loads profiles/assignments and
   previews an active user's effective policy.
5. The alert panel loads and its summary is consistent with the visible alerts
   (an empty list is valid).
6. A new workspace turn works for a normal user; the legacy direct API is
   unchanged.

Only after all checks pass, remove the temporary migration DSN as in the
existing setup procedure:

```bash
shred -u .secrets/workspace/migration_dsn
```

Keep the database dump and key backup. If verification fails, keep the DSN for
a safe retry. Because an old image does not accept schema 3, a code rollback
requires restoring the pre-migration database backup (and stopping the new
gateway); it is not enough to point Compose back at the old image.

## Upgrading an existing schema-3 deployment

Schema 4 adds four nullable columns (`context_messages`, `context_budget`,
`default_reply_tokens`, `max_reply_tokens`) to `ws_policy_profile_revisions`.
The change is additive: existing revisions keep their empty limits. An older
image does not accept schema 4, so migrate before starting the new gateway and
keep the same env-file/overlay chain throughout.

1. Preserve VM-only patches before `git pull`, exactly as in step 1 of the
   schema-2 procedure above.
2. Stop only the gateway and back up the workspace database and the Fernet key
   as in step 2. Leave PostgreSQL running and never use `down -v`.
3. Build the new gateway image.
4. Run the packaged `workspace_cli init` against the actual workspace database
   with the operator migration DSN and the same key. The same command upgrades
   schema 3 in place; it only adds the four nullable columns and does not reset
   users, conversations, profiles or the administrator account.
5. Reapply the packaged `nasi_lemak/workspace_roles.sql` grants to that same
   database.
6. Restart only the gateway and verify readiness, an existing login, an
   existing conversation, the policy/alert panels and one new workspace turn.

Keep the database dump and key backup; a code rollback alone is not sufficient
once the schema is migrated. Never point the runtime
`NASI_LEMAK_WORKSPACE_DSN_FILE` at the migration DSN.

## Verification status and limits

Local SQLite tests cover profiles, immutable revisions, assignment pinning,
full-profile resolution, optimistic conflicts, alerts and per-admin state.
The schema-2-to-3 migration and the restricted-role operations were also
independently verified against a local PostgreSQL instance, outside
Docker/VM. Consult the release report and its commit for the final test count;
this document does not repeat that count and makes no claim of a live Docker/VM
run.

This release is not evidence of guard-model quality, classifier accuracy,
latency/load capacity, OWASP coverage or production readiness. The model guards
remain independently configured; administrator toggles neither improve nor
validate their detection. Policy profiles are implemented; the employee
workspace remains one organisation with multi-customer separation and SSO
deferred.
