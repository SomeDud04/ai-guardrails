# Employee workspace setup (Ubuntu, Docker Compose)

This runbook adds the opt-in `/workspace` surface to an existing Nasi Lemak
deployment. It is one organisation with username/password accounts and
departments. It does not add SSO, multi-customer tenancy, RAG, retention
automation or production claims. The legacy installer, default console and
audit/database volume remain as they are; do not rerun the installer to update.

The workspace stores originals encrypted until the owner manually deletes a
conversation. Administrators do **not** receive an implicit review grant:
review access must be granted explicitly. Existing audit metadata cannot
reconstruct prompts or answers that were never saved by this workspace; only
conversations created after activation are available in `/workspace`.

## 0. Prerequisites

- Existing checkout and Ubuntu Docker Compose v2 deployment.
- The already-configured mode env files and secret files are in place, for
  example `.secrets/compose.env`, `.secrets/compose.test.env` (or
  `compose.pilot.env`) and, for the trusted-LAN demo, `.secrets/compose.demo.env`.
- A PostgreSQL administrator credential for the one-off migration step.
- No production traffic. The model guards remain inactive in the current demo;
  do not describe this as guarded-mode or production efficacy evidence.

Set these shell abbreviations for the existing mode. Replace `compose.test.yaml`
with `compose.pilot.yaml` only if that mode is already configured.

```bash
cd ~/ai-guardrails
BASE=(sudo docker compose
  --env-file .secrets/compose.env
  --env-file .secrets/compose.test.env
  -f compose.yaml -f compose.test.yaml)
```

For the trusted-LAN demo, use the existing demo files as well:

```bash
BASE=(sudo docker compose
  --env-file .secrets/compose.env
  --env-file .secrets/compose.test.env
  --env-file .secrets/compose.demo.env
  -f compose.yaml -f compose.test.yaml -f compose.demo.yaml)
```

## 1. Rebuild the existing gateway image first

Use the existing base and mode configuration; do not change targets or add ML
dependencies.

```bash
"${BASE[@]}" build gateway
```

## 2. Generate the stable encryption key

Create the directory as the current operator user, then run the CLI in a
one-off container under the host's current UID/GID with a directory bind. The
key file is created exclusively with mode `0600`; the command never overwrites
an existing key and never prints it.

```bash
mkdir -p -m 0700 .secrets/workspace

sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  -f compose.yaml -f compose.test.yaml \
  run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/.secrets/workspace:/secrets" \
  --entrypoint python gateway \
  -m nasi_lemak.workspace_cli generate-key \
  --key-file /secrets/workspace_key

sudo chown 10001:10001 .secrets/workspace/workspace_key
sudo chmod 0400 .secrets/workspace/workspace_key
```

Back this key up separately from the database. Never regenerate it on update.
Losing the key makes existing conversation content unreadable; there is no
automatic recovery.

The migration DSN file holds an operator-privileged PostgreSQL credential. It
is used only by the one-off `init` below. Create it with mode `0600` through an
editor, for example:

```bash
install -m 0600 /dev/null .secrets/workspace/migration_dsn
nano .secrets/workspace/migration_dsn
```

It must contain one absolute DSN such as:

```text
postgresql://nasi_lemak_admin:<administrator-password>@db:5432/nasi_lemak
```

Do not put this DSN in shell history, chat or the repository.

## 3. Initialise the schema with the migration credential

This is the only command that opens the database with `migrate=True`. The
privileged DSN is mounted only into this one-off container.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  -f compose.yaml -f compose.test.yaml \
  run --rm --no-deps \
  --user "0:0" \
  -v "$PWD/.secrets/workspace:/secrets:ro" \
  --entrypoint python gateway \
  -m nasi_lemak.workspace_cli init \
  --dsn-file /secrets/migration_dsn \
  --key-file /secrets/workspace_key
```

The one-off `init` container runs as `0:0` only because the mounted key is
mode `0400`, owned by `10001:10001`, inside a `0700` directory; the non-root
operator UID cannot read it. This applies only to this privileged migration
container. The gateway runtime still runs as UID `10001`.

Re-running `init` with the same key and schema is safe. A different key fails
before committing changes. Keep the privileged DSN until the one-time
`bootstrap-admin` step in section 7; it is needed because bootstrap writes a
`ws_meta` marker that the restricted runtime role cannot modify. Remove it
immediately after bootstrap (section 7).

## 4. Apply the fixed SQL privileges

Run the packaged role script as the PostgreSQL operator. It creates the fixed
`nasi_lemak_workspace` NOLOGIN group, checks that an existing group has no
elevated attributes or foreign membership, and grants only explicit privileges
on the fixed `ws_*` tables. It creates no LOGIN account and contains no password.

```bash
"${BASE[@]}" exec -T db \
  sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' \
  < nasi_lemak/workspace_roles.sql
```

## 5. Create the dedicated runtime LOGIN

Create a fresh unprivileged LOGIN and grant only workspace-group membership. Set
its password interactively with `\password`, which does not enter shell history.
Never pass the password as a command argument.

```bash
"${BASE[@]}" exec db \
  sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

At the `psql` prompt:

```sql
CREATE ROLE nasi_workspace_app LOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT nasi_lemak_workspace TO nasi_workspace_app;
\password nasi_workspace_app
\q
```

This credential is separate from the migration credential and from the legacy
audit writer/reader roles. Write its DSN to the dedicated runtime DSN file using
an editor; do not echo it:

```bash
install -m 0600 /dev/null .secrets/workspace/workspace_dsn
nano .secrets/workspace/workspace_dsn
```

The file contains one DSN (percent-encode special password characters):

```text
postgresql://nasi_workspace_app:<interactive-password>@db:5432/nasi_lemak
```

Then make it readable by the gateway UID:

```bash
sudo chown 10001:10001 .secrets/workspace/workspace_dsn
sudo chmod 0400 .secrets/workspace/workspace_dsn
```

## 6. Enable the overlay and recreate only the gateway

Copy the non-secret example, replace every absolute path, and keep the explicit
HTTP decision honest:

```bash
cp docs/compose.workspace.env.example .secrets/compose.workspace.env
nano .secrets/compose.workspace.env
```

The example sets `NASI_LEMAK_WORKSPACE_ALLOW_HTTP=true` for the current
trusted-LAN demo. The overlay defaults this to `false`; production or remote use
requires reviewed HTTPS ingress. Then recreate the gateway, preserving
`.secrets/`, the named PostgreSQL volume and the operator policy:

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  --env-file .secrets/compose.workspace.env \
  -f compose.yaml -f compose.test.yaml -f compose.workspace.yaml \
  up -d --no-deps --force-recreate gateway
```

For the existing demo ingress, include `.secrets/compose.demo.env` and
`-f compose.demo.yaml` in the same command. Do not use `docker compose down -v`;
it would remove the database volume and the saved workspace content. The
existing nginx proxy already forwards `/workspace`; no nginx change is needed.

## 7. Create the first administrator interactively

Use the operator-privileged migration DSN for this one-time bootstrap, in a
one-off container. The restricted runtime role has `SELECT`-only access to
`ws_meta`, so it cannot write the `bootstrap_admin` marker and must not be used
for this command. The password is prompted twice and is never accepted from
argv, an environment variable or a default. There is no default account.
Re-running this command after an administrator exists refuses instead of
resetting it.

```bash
sudo docker compose \
  --env-file .secrets/compose.env \
  --env-file .secrets/compose.test.env \
  -f compose.yaml -f compose.test.yaml \
  run --rm --no-deps \
  --user "0:0" \
  -v "$PWD/.secrets/workspace:/secrets:ro" \
  --entrypoint python gateway \
  -m nasi_lemak.workspace_cli bootstrap-admin \
  --dsn-file /secrets/migration_dsn \
  --key-file /secrets/workspace_key \
  --username admin.name \
  --full-name "Workspace Administrator" \
  --department "IT"
```

Then remove the privileged DSN; it is not needed by the gateway:

```bash
shred -u .secrets/workspace/migration_dsn
```

`bootstrap-admin` does not grant review access. Grant reviewer scope explicitly
from the admin panel only when approved; admins have no implicit content access.

## 8. Verify

- Loopback: `http://127.0.0.1:8000/workspace`
- Existing demo ingress: `http://<DEMO_BIND_IP>:<DEMO_PORT>/workspace`

Check `/health/ready` and the page through the same URL. A `503` means the
workspace configuration, schema, key or runtime credential is unavailable; the
error is deliberately generic and does not print the DSN or key.

Browser sessions use a host-only `HttpOnly`, `SameSite=Strict`,
`Path=/workspace` cookie issued only by a page login. It expires with the same
fixed eight-hour server session record and is `Secure` on HTTPS. The explicit
`NASI_LEMAK_WORKSPACE_ALLOW_HTTP=true` LAN acknowledgement also allows the
cookie over plain HTTP; that mode exposes the session to anyone who can observe
the LAN traffic and is only for local demonstration. Bearer API clients keep
their existing token behaviour. Sign-out revokes the server session and clears
the cookie; expired, disabled or password-reset sessions stop working
immediately. To use multiple accounts at once, use separate browser profiles or
browsers; tabs in one profile intentionally share the server cookie identity.

For a local disposable PostgreSQL verification run, set
`TEST_WORKSPACE_DISPOSABLE=1` as well as `TEST_AUDIT_DISPOSABLE=1`. The
workspace PostgreSQL privilege tests truncate every workspace row; never set the
flag for a shared database, and note that `TEST_WORKSPACE_DSN` alone never
authorises destructive setup.

## Updating and operating

Update the code with `git pull --ff-only`, then rebuild with the matching base
and mode configuration and recreate the gateway as in section 6. Do not rerun
the installer as an update and do not regenerate the key. The key, `.secrets/`
files, named database volume and policy are preserved.

Manual deletion by an owner removes that conversation from the workspace; it
does not remove PostgreSQL backups or any external backup copies. Backup
retention and verified key escrow are operator responsibilities. Production
HTTPS, multi-customer separation, SSO and advanced department policy remain
deferred. Model guard acceptance is still pending; this runbook does not claim
guard efficacy or production readiness.
