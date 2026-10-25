"""Explicit PostgreSQL verification gate for the workspace and audit stores.

This command is intentionally opt-in and fails when its disposable test
environment is incomplete; ordinary ``unittest`` runs may still skip the
optional integration cases.  It never prints a DSN.

Required environment:

* ``TEST_WORKSPACE_ADMIN_DSN`` -- PostgreSQL administrator for the disposable
  workspace database; used only to apply ``workspace_roles.sql`` and create the
  test runtime LOGIN.
* ``TEST_WORKSPACE_DSN`` -- owner of the disposable workspace database.
* ``TEST_WORKSPACE_RUNTIME_DSN`` -- restricted LOGIN that is only a member of
  ``nasi_lemak_workspace``.
* ``TEST_AUDIT_DSN`` -- owner of the disposable audit database.
* ``TEST_WORKSPACE_DISPOSABLE=1`` -- required before this command creates the
  workspace schema/roles or runs the destructive PostgreSQL workspace tests,
  which truncate every workspace row.  Never set it for a shared database.
* ``TEST_AUDIT_DISPOSABLE=1`` -- acknowledges the destructive offline
  reconciliation test.

Both disposable flags are mandatory.  ``TEST_WORKSPACE_DSN`` alone is not an
acknowledgement to truncate workspace data.

Example (local disposable PostgreSQL, never a shared database)::

    $env:TEST_WORKSPACE_ADMIN_DSN = "postgresql://postgres@127.0.0.1:55432/pgverify_ws"
    $env:TEST_WORKSPACE_DSN = "postgresql://pgverify_wsowner@127.0.0.1:55432/pgverify_ws"
    $env:TEST_WORKSPACE_RUNTIME_DSN = "postgresql://pgverify_wsapp@127.0.0.1:55432/pgverify_ws"
    $env:TEST_AUDIT_DSN = "postgresql://pgverify_auditowner@127.0.0.1:55432/pgverify_audit"
    $env:TEST_WORKSPACE_DISPOSABLE = "1"
    $env:TEST_AUDIT_DISPOSABLE = "1"
    python scripts/verify_postgres.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REQUIRED = (
    "TEST_WORKSPACE_ADMIN_DSN",
    "TEST_WORKSPACE_DSN",
    "TEST_WORKSPACE_RUNTIME_DSN",
    "TEST_AUDIT_DSN",
)
ROOT = Path(__file__).resolve().parents[1]
# Stable test-only key shared with PostgresWorkspaceStoreTest.  It is not a
# runtime default secret; the store still rejects a different key.
TEST_KEY = "SIuN9xihVB4_BtpG0So_WjfgQNiprJozOTk6YZMA_2o="


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def _prepare_workspace() -> int:
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict

    admin_dsn = os.environ["TEST_WORKSPACE_ADMIN_DSN"]
    owner_dsn = os.environ["TEST_WORKSPACE_DSN"]
    runtime_dsn = os.environ["TEST_WORKSPACE_RUNTIME_DSN"]
    try:
        owner_user = conninfo_to_dict(owner_dsn).get("user")
        admin_user = conninfo_to_dict(admin_dsn).get("user")
        runtime_user = conninfo_to_dict(runtime_dsn).get("user")
    except Exception:
        return _fail("a PostgreSQL DSN is malformed")
    if not runtime_user or runtime_user in (owner_user, admin_user):
        return _fail("runtime DSN must use a separate restricted LOGIN")

    roles_sql = (ROOT / "nasi_lemak" / "workspace_roles.sql").read_text(
        encoding="utf-8"
    )
    # The role script grants on fixed ws_* tables, so on a genuinely fresh
    # dedicated database the owner schema must exist first.  Initialising with
    # the stable test key also makes repeated verification runs usable.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from nasi_lemak.workspace_store import WorkspaceStore

        WorkspaceStore(owner_dsn, encryption_key=TEST_KEY).close()
    except Exception:
        return _fail(
            "workspace owner schema initialisation failed; "
            "check the disposable database"
        )
    try:
        with psycopg.connect(admin_dsn, connect_timeout=5, autocommit=True) as conn:
            # Applying twice proves the grant script is repeatable.
            conn.execute(roles_sql)
            conn.execute(roles_sql)
            conn.execute(
                sql.SQL(
                    "DO $$ BEGIN "
                    "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {name}) "
                    "THEN CREATE ROLE {ident} LOGIN; END IF; END $$;"
                ).format(
                    name=sql.Literal(runtime_user),
                    ident=sql.Identifier(runtime_user),
                )
            )
            conn.execute(
                sql.SQL("GRANT nasi_lemak_workspace TO {ident}").format(
                    ident=sql.Identifier(runtime_user)
                )
            )
    except Exception:
        return _fail("workspace role setup failed; check the disposable database")
    return 0


def _run(command: list[str]) -> int:
    print("running:", " ".join(command))
    return subprocess.run(command, cwd=ROOT, check=False).returncode


def main() -> int:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        return _fail(
            "explicit PostgreSQL verification requires: " + ", ".join(missing)
        )
    if os.environ.get("TEST_WORKSPACE_DISPOSABLE") != "1":
        return _fail(
            "set TEST_WORKSPACE_DISPOSABLE=1 only for an isolated disposable "
            "workspace database; the PostgreSQL tests truncate workspace rows"
        )
    if os.environ.get("TEST_AUDIT_DISPOSABLE") != "1":
        return _fail("set TEST_AUDIT_DISPOSABLE=1 for the disposable audit database")
    if _prepare_workspace() != 0:
        return 2

    for pattern in ("test_workspace_store.py", "test_audit.py"):
        code = _run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tests",
                "-p",
                pattern,
                "-k",
                "Postgres",
                "-v",
            ]
        )
        if code != 0:
            return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
