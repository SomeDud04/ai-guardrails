"""Protected employee-workspace store (accounts, sessions, conversations, review).

This module is the narrow persistence/business foundation for the opt-in
``/workspace`` routes. It is independent from the legacy audit store: the
workspace owns ``ws_*`` tables in a dedicated database (or SQLite file) with its
own credential and never reads or writes ``events``/``owners``/``export_audits``.

Design constraints enforced here:

* Explicit DSN/path and an explicit Fernet key. Missing/broken crypto fails
  closed; there is no default secret and the key is never stored or logged.
* Passwords use salted ``hashlib.scrypt`` with fixed reviewed parameters,
  constant-time comparison and a single generic authentication failure.
* Session tokens are opaque random values returned once; only their SHA-256
  hash is stored, with an 8 hour TTL, logout revocation and account-disable
  invalidation.
* Original prompts and delivered assistant text are encrypted with Fernet. The
  authenticated payload repeats the conversation id, message id and role, so a
  ciphertext swapped between rows fails closed instead of decrypting.
* Authorization uses the persisted user row and persisted review grants only.
  Admin accounts have no implicit content access; reviewer reads are audited in
  the same transaction as the read and the transaction commits before content is
  returned.
* All SQL is fixed and parameterised. Lists are bounded and keyset paginated.

A PostgreSQL DSN (``postgresql://...``) uses the existing psycopg dependency;
any other non-empty value is treated as a SQLite file path. PostgreSQL schema
provisioning/grant scripts for the dedicated workspace role are out of scope for
this slice.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from .controls import block_detail
from .workspace_governance import AlertAdminMixin, PolicyAdminMixin

SCHEMA_PATH = Path(__file__).with_name("workspace_schema.sql")
SCHEMA_VERSION = 3
# Version 2 adds outcome/request_id/error_code to ws_messages. Runtime stores
# open with ``migrate=False`` and therefore require an explicit provisioning
# step (CLI slice) rather than silently altering a live database.
_SCHEMA_V2_ALTERS = (
    "ALTER TABLE ws_messages ADD COLUMN outcome TEXT NOT NULL DEFAULT 'allowed' "
    "CHECK (outcome IN ('allowed', 'blocked', 'failed'))",
    "ALTER TABLE ws_messages ADD COLUMN request_id TEXT",
    "ALTER TABLE ws_messages ADD COLUMN error_code TEXT",
)

SESSION_TTL_SECONDS = 8 * 60 * 60
LEASE_TTL_SECONDS = 120.0
DEFAULT_LIMIT = 20
MAX_LIMIT = 100

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
# Finite storage/decryption envelope bound.  This matches the largest
# accepted prompt character limit so valid configured conversations cannot be
# accepted and then fail persistence with a 503.  Existing shorter history is
# fully compatible; content is never truncated.
TEXT_MAX_LENGTH = 65536
TITLE_MAX_LENGTH = 120
FULL_NAME_MAX_LENGTH = 120
DEPARTMENT_NAME_MAX_LENGTH = 80
USERNAME_MAX_LENGTH = 64

_SCRYPT_N = 1 << 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_SALT_BYTES = 16
_SCRYPT_MAXMEM = 64 * 1024 * 1024

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_DUMMY_SALT = b"workspace-dummy!"
_AUTH_FAILURE = "authentication failed"
_DEFAULT_TITLE = "Untitled conversation"
_KEY_VERIFIER_PREFIX = b"workspace-key-verifier:"


class WorkspaceError(RuntimeError):
    """Base class for workspace failures. Messages never contain content."""


class WorkspaceConfigError(WorkspaceError):
    """Invalid or incomplete workspace configuration; fail closed."""


class WorkspaceStorageError(WorkspaceError):
    """Database/crypto operation failed; no partial result is returned."""


class ContentError(WorkspaceError):
    """Stored content could not be authenticated/decrypted; fail closed."""


class AuthError(WorkspaceError):
    """Generic authentication/session failure."""


class AccessDenied(WorkspaceError):
    """The authenticated principal is not authorised for this operation."""


class NotFound(WorkspaceError):
    """The requested workspace record does not exist."""


class Conflict(WorkspaceError):
    """A reservation or uniqueness rule rejected the operation."""


# ---------------------------------------------------------------------------
# validation helpers (messages are deliberately generic and content-free)
# ---------------------------------------------------------------------------


def _require_text(value: Any, *, maximum: int, field: str, minimum: int = 1) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    candidate = value.strip()
    if len(candidate) < minimum or len(candidate) > maximum:
        raise ValueError(f"{field} is outside the allowed length")
    return candidate


def _require_content_text(value: Any, *, maximum: int, field: str) -> str:
    """Validate conversation text without altering it.

    Leading/trailing whitespace and newlines are part of the stored exchange,
    so only blankness and length are rejected here.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    if len(value) > maximum or not value.strip():
        raise ValueError(f"{field} is outside the allowed length")
    return value


def _require_password(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("password does not meet policy")
    if not (PASSWORD_MIN_LENGTH <= len(value) <= PASSWORD_MAX_LENGTH):
        raise ValueError("password does not meet policy")
    return value


def _normalise_username(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("username is invalid")
    candidate = value.strip().lower()
    if len(candidate) > USERNAME_MAX_LENGTH or not _USERNAME_RE.match(candidate):
        raise ValueError("username is invalid")
    return candidate


def _optional_metadata(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    candidate = value.strip()
    if not candidate or len(candidate) > 128:
        raise ValueError(f"{field} is invalid")
    return candidate


def _validate_limit(limit: Any) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if limit < 1 or limit > MAX_LIMIT:
        raise ValueError("limit is outside the allowed range")
    return limit


def _encode_cursor(created_at: float, record_id: str) -> str:
    return f"{float(created_at)!r}:{record_id}"


def _decode_cursor(value: Any) -> tuple[float, str]:
    if not isinstance(value, str) or len(value) > 160 or ":" not in value:
        raise ValueError("pagination cursor is invalid")
    raw_created, record_id = value.rsplit(":", 1)
    try:
        created_at = float(raw_created)
    except (TypeError, ValueError):
        raise ValueError("pagination cursor is invalid") from None
    if not math.isfinite(created_at) or not record_id or len(record_id) > 64:
        raise ValueError("pagination cursor is invalid")
    return created_at, record_id


def _schema_statements() -> list[str]:
    """Split the shared schema file into single statements.

    Line comments are removed first so a semicolon inside prose cannot create a
    bogus statement. The schema contains no string literals with ``--``.
    """
    text = SCHEMA_PATH.read_text(encoding="utf-8")
    without_comments = "\n".join(line.split("--", 1)[0] for line in text.splitlines())
    return [
        statement.strip()
        for statement in without_comments.split(";")
        if statement.strip()
    ]


def _schema_v3_statements() -> list[str]:
    """Additive version-3 DDL, filtered from the shared schema file.

    Keeping this derived from the same SQL file avoids a hand-maintained second
    copy drifting from a fresh install.  Every statement is ``IF NOT EXISTS``
    and safe to re-run after a partial deployment.
    """
    prefixes = (
        "CREATE TABLE IF NOT EXISTS WS_POLICY_",
        "CREATE TABLE IF NOT EXISTS WS_BLOCK_ALERTS",
        "CREATE TABLE IF NOT EXISTS WS_ALERT_STATE",
        "CREATE INDEX IF NOT EXISTS IDX_WS_POLICY_",
        "CREATE INDEX IF NOT EXISTS IDX_WS_BLOCK_ALERTS",
        "CREATE INDEX IF NOT EXISTS IDX_WS_ALERT_STATE",
    )
    return [
        statement
        for statement in _schema_statements()
        if statement.upper().startswith(prefixes)
    ]


# ---------------------------------------------------------------------------
# password, token and crypto primitives
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SCRYPT_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )
    return (
        f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}"
        f"${_b64(salt)}${_b64(digest)}"
    )


def _verify_password(stored: Any, password: str) -> bool:
    if not isinstance(stored, str):
        return False
    parts = stored.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = base64.b64decode(parts[4], validate=True)
        expected = base64.b64decode(parts[5], validate=True)
        if (n, r, p) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
            maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class _Cipher:
    """Authenticated envelope binding ciphertext to conversation/message/role."""

    def __init__(self, key: str | bytes | None):
        if not key:
            raise WorkspaceConfigError("workspace encryption key required")
        try:
            import cryptography.fernet  # noqa: F401
            from cryptography.fernet import Fernet
        except ImportError:
            raise WorkspaceConfigError("workspace encryption unavailable") from None
        if isinstance(key, bytes):
            key_bytes = key.strip()
        elif isinstance(key, str):
            try:
                key_bytes = key.strip().encode("ascii")
            except UnicodeEncodeError:
                raise WorkspaceConfigError("workspace encryption key invalid") from None
        else:
            raise WorkspaceConfigError("workspace encryption key invalid")
        if not key_bytes:
            raise WorkspaceConfigError("workspace encryption key required")
        try:
            self._fernet = Fernet(key_bytes)
        except Exception:
            raise WorkspaceConfigError("workspace encryption key invalid") from None

    def encrypt(self, conversation_id: str, message_id: str, role: str, text: str) -> str:
        payload = json.dumps(
            {"c": conversation_id, "m": message_id, "r": role, "t": text},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        try:
            token = self._fernet.encrypt(payload)
        except Exception:
            raise WorkspaceStorageError("workspace content could not be stored") from None
        return token.decode("ascii")

    def make_verifier(self) -> str:
        """Create an authenticated marker proving possession of this key."""
        payload = _KEY_VERIFIER_PREFIX + secrets.token_bytes(32)
        try:
            return self._fernet.encrypt(payload).decode("ascii")
        except Exception:
            raise WorkspaceStorageError(
                "workspace key verifier could not be created"
            ) from None

    def check_verifier(self, token: Any) -> bool:
        if not isinstance(token, str) or not token or len(token) > 512:
            return False
        try:
            raw = self._fernet.decrypt(token.encode("ascii"))
        except Exception:
            return False
        return len(raw) == len(_KEY_VERIFIER_PREFIX) + 32 and hmac.compare_digest(
            raw[: len(_KEY_VERIFIER_PREFIX)], _KEY_VERIFIER_PREFIX
        )

    def decrypt(self, conversation_id: str, message_id: str, role: str, ciphertext: str) -> str:
        try:
            raw = self._fernet.decrypt(str(ciphertext).encode("ascii"))
        except Exception:
            raise ContentError("stored workspace content is unavailable") from None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ContentError("stored workspace content is unavailable") from None
        if not isinstance(payload, dict):
            raise ContentError("stored workspace content is unavailable")
        if (
            payload.get("c") != conversation_id
            or payload.get("m") != message_id
            or payload.get("r") != role
        ):
            raise ContentError("stored workspace content failed integrity checks")
        text = payload.get("t")
        if not isinstance(text, str) or not text or len(text) > TEXT_MAX_LENGTH:
            raise ContentError("stored workspace content is unavailable")
        return text


# ---------------------------------------------------------------------------
# database adapters: fixed SQL with '?' placeholders, translated for psycopg
# ---------------------------------------------------------------------------


class _Db:
    def __init__(self, conn: Any, dialect: str):
        self.conn = conn
        self.dialect = dialect

    def _statement(self, sql: str, params: tuple) -> tuple[str, tuple]:
        if self.dialect == "postgres":
            return sql.replace("?", "%s"), params
        return sql, params

    def execute(self, sql: str, params: tuple = ()) -> int:
        statement, values = self._statement(sql, params)
        cursor = self.conn.execute(statement, values)
        return int(cursor.rowcount)

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        statement, values = self._statement(sql, params)
        cursor = self.conn.execute(statement, values)
        rows = cursor.fetchall()
        if not rows:
            return []
        if self.dialect == "sqlite":
            return [dict(row) for row in rows]
        columns = [column.name for column in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    def query_one(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None


class _SqliteBackend:
    dialect = "sqlite"

    def __init__(self, path: Path, connect_timeout: float):
        self.path = path
        self.connect_timeout = connect_timeout
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def transaction(self):
        with self._lock:
            try:
                conn = sqlite3.connect(
                    str(self.path),
                    timeout=self.connect_timeout,
                    isolation_level=None,
                )
            except sqlite3.Error:
                raise WorkspaceStorageError("workspace database unavailable") from None
            try:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute(f"PRAGMA busy_timeout={int(self.connect_timeout * 1000)}")
                conn.execute("BEGIN IMMEDIATE")
                try:
                    yield _Db(conn, self.dialect)
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
            finally:
                conn.close()


class _PostgresBackend:
    dialect = "postgres"

    def __init__(
        self,
        conninfo: str,
        connect_timeout: float,
        connect_factory: Callable[[str], Any] | None,
    ):
        self._conninfo = conninfo
        self.connect_timeout = connect_timeout
        self._connect_factory = connect_factory

    def _connect(self):
        if self._connect_factory is not None:
            return self._connect_factory(self._conninfo)
        try:
            import psycopg
        except ImportError:
            raise WorkspaceConfigError("workspace database driver unavailable") from None
        try:
            return psycopg.connect(
                self._conninfo,
                connect_timeout=max(1, int(self.connect_timeout)),
                autocommit=False,
                options="-c statement_timeout=5000",
            )
        except Exception:
            raise WorkspaceStorageError("workspace database unavailable") from None

    @contextmanager
    def transaction(self):
        conn = self._connect()
        try:
            with conn.transaction():
                yield _Db(conn, self.dialect)
        finally:
            try:
                conn.close()
            except Exception:
                pass


def _guard(operation):
    @wraps(operation)
    def wrapper(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except (WorkspaceError, ValueError):
            raise
        except Exception:
            raise WorkspaceStorageError("workspace storage operation failed") from None

    return wrapper


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------


class WorkspaceStore(PolicyAdminMixin, AlertAdminMixin):
    """Workspace persistence boundary with in-method authorization."""

    def __init__(
        self,
        dsn: str,
        *,
        encryption_key: str | bytes | None,
        clock: Callable[[], float] | None = None,
        connect_timeout: float = 5.0,
        connect_factory: Callable[[str], Any] | None = None,
        migrate: bool = True,
    ):
        if not isinstance(dsn, str) or not dsn.strip():
            raise WorkspaceConfigError("workspace dsn required")
        if not isinstance(migrate, bool):
            raise WorkspaceConfigError("workspace migration flag is invalid")
        if (
            isinstance(connect_timeout, bool)
            or not isinstance(connect_timeout, (int, float))
            or not math.isfinite(connect_timeout)
            or not 0.1 <= connect_timeout <= 30
        ):
            raise ValueError("connect_timeout must be finite between 0.1 and 30")
        if clock is not None and not callable(clock):
            raise WorkspaceConfigError("workspace clock is invalid")
        self._cipher = _Cipher(encryption_key)
        self._clock = clock or time.time
        self._dummy_hash: str | None = None

        value = dsn.strip()
        lowered = value.lower()
        if lowered.startswith(("postgresql://", "postgres://")):
            backend: Any = _PostgresBackend(
                value, float(connect_timeout), connect_factory
            )
        else:
            if connect_factory is not None:
                raise WorkspaceConfigError(
                    "connect_factory is only supported for PostgreSQL"
                )
            if lowered.startswith("sqlite://"):
                value = value[len("sqlite://") :]
                if not value:
                    raise WorkspaceConfigError("workspace dsn required")
            backend = _SqliteBackend(Path(value), float(connect_timeout))
        self._backend = backend
        with self._backend.transaction() as db:
            if migrate:
                self._ensure_schema(db)
            else:
                self._require_schema(db)
            self._ensure_key_verifier(db, create=migrate)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(backend={self._backend.dialect})"

    # -- schema ----------------------------------------------------------
    def _ensure_schema(self, db: _Db) -> None:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS ws_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at DOUBLE PRECISION NOT NULL
            )
            """
        )
        row = db.query_one("SELECT MAX(version) AS version FROM ws_schema_migrations")
        current = row["version"] if row else None
        if current is not None:
            version = int(current)
            if version == SCHEMA_VERSION:
                return
            if version not in (1, 2):
                raise WorkspaceConfigError("unsupported workspace schema version")
            if version == 1:
                # Preserve the original v1 -> v2 data migration, then add the
                # v3 governance tables.  Existing rows and the key verifier are
                # untouched.
                for statement in _SCHEMA_V2_ALTERS:
                    db.execute(statement)
            for statement in _schema_v3_statements():
                db.execute(statement)
            db.execute(
                "UPDATE ws_schema_migrations SET version = ? WHERE version = ?",
                (SCHEMA_VERSION, version),
            )
            return
        statements = _schema_statements()
        for statement in statements:
            db.execute(statement)
        db.execute(
            "INSERT INTO ws_schema_migrations(version, applied_at) VALUES (?, ?) "
            "ON CONFLICT DO NOTHING",
            (SCHEMA_VERSION, self._now()),
        )

    def _require_schema(self, db: _Db) -> None:
        """Runtime path: never create or alter schema; require explicit setup."""
        try:
            row = db.query_one(
                "SELECT MAX(version) AS version FROM ws_schema_migrations"
            )
        except Exception:
            raise WorkspaceConfigError(
                "workspace schema is not initialised"
            ) from None
        if row is None or int(row["version"] or 0) != SCHEMA_VERSION:
            raise WorkspaceConfigError("workspace schema version is unsupported")

    def _ensure_key_verifier(self, db: _Db, *, create: bool) -> None:
        """Bind this database to the configured key; fail closed on mismatch."""
        row = db.query_one("SELECT value FROM ws_meta WHERE key = 'key_verifier'")
        if row is None:
            if not create:
                raise WorkspaceConfigError(
                    "workspace encryption key verifier is missing"
                )
            db.execute(
                "INSERT INTO ws_meta(key, value) VALUES ('key_verifier', ?) "
                "ON CONFLICT DO NOTHING",
                (self._cipher.make_verifier(),),
            )
            row = db.query_one(
                "SELECT value FROM ws_meta WHERE key = 'key_verifier'"
            )
        if row is None or not self._cipher.check_verifier(row["value"]):
            raise WorkspaceConfigError(
                "workspace encryption key does not match this database"
            )

    def _now(self) -> float:
        return float(self._clock())

    def _dummy(self) -> str:
        if self._dummy_hash is None:
            self._dummy_hash = _hash_password("workspace-dummy-password")
        return self._dummy_hash

    # -- readiness -------------------------------------------------------
    @_guard
    def ready(self) -> bool:
        try:
            with self._backend.transaction() as db:
                row = db.query_one("SELECT MAX(version) AS version FROM ws_schema_migrations")
                return bool(row and row["version"] == SCHEMA_VERSION)
        except WorkspaceError:
            return False

    def close(self) -> None:
        """Connections are per-operation; kept for boundary symmetry."""

    # -- authorization helpers ------------------------------------------
    @staticmethod
    def _public_user(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"],
            "username": row["username"],
            "full_name": row["full_name"],
            "department_id": row["department_id"],
            "role": row["role"],
            "disabled": bool(row["disabled"]),
            "created_at": float(row["created_at"]),
        }

    def _require_admin(self, db: _Db, actor_id: str) -> dict[str, Any]:
        row = db.query_one(
            "SELECT id, role, disabled FROM ws_users WHERE id = ?", (actor_id,)
        )
        if not row or row["role"] != "admin" or int(row["disabled"]) != 0:
            raise AccessDenied("permission denied")
        return row

    def _require_active_user(self, db: _Db, user_id: str) -> dict[str, Any]:
        row = db.query_one("SELECT * FROM ws_users WHERE id = ?", (user_id,))
        if not row or int(row["disabled"]) != 0:
            raise AccessDenied("permission denied")
        return row

    def _review_scope(
        self, db: _Db, user_id: str
    ) -> tuple[str, list[str]] | None:
        rows = db.query(
            "SELECT scope, department_id FROM ws_review_grants WHERE user_id = ?",
            (user_id,),
        )
        if not rows:
            return None
        if any(row["scope"] == "global" for row in rows):
            return "global", []
        departments = sorted(
            {row["department_id"] for row in rows if row["department_id"]}
        )
        return ("department", departments) if departments else None

    @staticmethod
    def _log_access(
        db: _Db,
        actor_id: str,
        action: str,
        *,
        conversation_id: str | None,
        department_id: str | None,
        now: float,
    ) -> None:
        applied = db.execute(
            """
            INSERT INTO ws_access_log(
                id, actor_id, action, conversation_id, department_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), actor_id, action, conversation_id, department_id, now),
        )
        if applied != 1:
            raise WorkspaceStorageError("workspace access audit was not applied")

    @staticmethod
    def _conversation_metadata(
        row: dict[str, Any], message_count: int | None = None
    ) -> dict[str, Any]:
        metadata = {
            "id": row["id"],
            "owner_id": row["owner_id"],
            "department_id": row["department_id"],
            "title": row["title"],
            "status": row["status"],
            "version": int(row["version"]),
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }
        if message_count is not None:
            metadata["message_count"] = message_count
        # Reviewer-facing identity references are joined under the same
        # authorisation predicate as the conversation row; they are never a
        # separate user-directory lookup.
        for field in ("owner_full_name", "department_name"):
            if field in row:
                metadata[field] = row[field]
        return metadata

    # -- bootstrap and account administration ---------------------------
    @_guard
    def bootstrap_admin(
        self,
        *,
        username: str,
        password: str,
        full_name: str,
        department_name: str,
    ) -> dict[str, Any] | None:
        """Create the first admin exactly once. No default credentials exist."""
        normalised = _normalise_username(username)
        secret = _require_password(password)
        display_name = _require_text(
            full_name, maximum=FULL_NAME_MAX_LENGTH, field="full name"
        )
        dept_name = _require_text(
            department_name, maximum=DEPARTMENT_NAME_MAX_LENGTH, field="department name"
        )
        now = self._now()
        with self._backend.transaction() as db:
            existing = db.query_one(
                "SELECT id FROM ws_users WHERE role = 'admin' LIMIT 1"
            )
            if existing:
                return None
            marker = db.execute(
                "INSERT INTO ws_meta(key, value) VALUES ('bootstrap_admin', ?) "
                "ON CONFLICT DO NOTHING",
                (str(uuid.uuid4()),),
            )
            if marker != 1:
                return None
            department = db.query_one(
                "SELECT id FROM ws_departments WHERE name_key = ?",
                (dept_name.casefold(),),
            )
            if department:
                department_id = department["id"]
            else:
                department_id = str(uuid.uuid4())
                db.execute(
                    """
                    INSERT INTO ws_departments(id, name, name_key, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (department_id, dept_name, dept_name.casefold(), now),
                )
            user_id = str(uuid.uuid4())
            db.execute(
                """
                INSERT INTO ws_users(
                    id, username, full_name, department_id, role,
                    password_hash, disabled, created_at
                ) VALUES (?, ?, ?, ?, 'admin', ?, 0, ?)
                """,
                (
                    user_id,
                    normalised,
                    display_name,
                    department_id,
                    _hash_password(secret),
                    now,
                ),
            )
            row = db.query_one("SELECT * FROM ws_users WHERE id = ?", (user_id,))
            return self._public_user(row)

    @_guard
    def create_department(self, actor_id: str, name: str) -> dict[str, Any]:
        dept_name = _require_text(
            name, maximum=DEPARTMENT_NAME_MAX_LENGTH, field="department name"
        )
        name_key = dept_name.casefold()
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            if db.query_one(
                "SELECT id FROM ws_departments WHERE name_key = ?", (name_key,)
            ):
                raise Conflict("department already exists")
            department_id = str(uuid.uuid4())
            db.execute(
                """
                INSERT INTO ws_departments(id, name, name_key, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (department_id, dept_name, name_key, now),
            )
            return {"id": department_id, "name": dept_name, "created_at": now}

    @_guard
    def list_departments(
        self, actor_id: str, *, limit: int = MAX_LIMIT, after: str | None = None
    ) -> dict[str, Any]:
        limit = _validate_limit(limit)
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            params: list[Any] = []
            sql = "SELECT id, name, created_at FROM ws_departments WHERE 1 = 1"
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (created_at < ? OR (created_at = ? AND id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "created_at": float(row["created_at"]),
                }
                for row in rows[:limit]
            ]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    @_guard
    def create_user(
        self,
        actor_id: str,
        username: str,
        password: str,
        full_name: str,
        department_id: str,
        role: str = "employee",
    ) -> dict[str, Any]:
        normalised = _normalise_username(username)
        secret = _require_password(password)
        display_name = _require_text(
            full_name, maximum=FULL_NAME_MAX_LENGTH, field="full name"
        )
        if role not in ("employee", "admin"):
            raise ValueError("role is invalid")
        if not isinstance(department_id, str) or not department_id:
            raise ValueError("department is invalid")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            if not db.query_one(
                "SELECT id FROM ws_departments WHERE id = ?", (department_id,)
            ):
                raise NotFound("department not found")
            if db.query_one(
                "SELECT id FROM ws_users WHERE username = ?", (normalised,)
            ):
                raise Conflict("username already exists")
            user_id = str(uuid.uuid4())
            db.execute(
                """
                INSERT INTO ws_users(
                    id, username, full_name, department_id, role,
                    password_hash, disabled, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    user_id,
                    normalised,
                    display_name,
                    department_id,
                    role,
                    _hash_password(secret),
                    now,
                ),
            )
            row = db.query_one("SELECT * FROM ws_users WHERE id = ?", (user_id,))
            return self._public_user(row)

    @_guard
    def list_users(
        self, actor_id: str, *, limit: int = 50, after: str | None = None
    ) -> dict[str, Any]:
        limit = _validate_limit(limit)
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            params: list[Any] = []
            sql = (
                "SELECT id, username, full_name, department_id, role, disabled, "
                "created_at FROM ws_users WHERE 1 = 1"
            )
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (created_at < ? OR (created_at = ? AND id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [self._public_user(row) for row in rows[:limit]]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    @_guard
    def disable_user(self, actor_id: str, user_id: str) -> None:
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            row = db.query_one(
                "SELECT id, department_id FROM ws_users WHERE id = ?", (user_id,)
            )
            if not row:
                raise NotFound("user not found")
            db.execute(
                "UPDATE ws_users SET disabled = 1 WHERE id = ?", (user_id,)
            )
            db.execute(
                "UPDATE ws_sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0",
                (user_id,),
            )
            self._log_access(
                db,
                actor_id,
                "admin.disable_user",
                conversation_id=None,
                department_id=row["department_id"],
                now=now,
            )

    @_guard
    def grant_review(
        self,
        actor_id: str,
        user_id: str,
        scope: str,
        department_id: str | None = None,
    ) -> dict[str, Any]:
        if scope not in ("department", "global"):
            raise ValueError("review scope is invalid")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            if not db.query_one("SELECT id FROM ws_users WHERE id = ?", (user_id,)):
                raise NotFound("user not found")
            if scope == "department":
                if not isinstance(department_id, str) or not department_id:
                    raise ValueError("department is invalid")
                if not db.query_one(
                    "SELECT id FROM ws_departments WHERE id = ?", (department_id,)
                ):
                    raise NotFound("department not found")
                scope_key = f"department:{department_id}"
            else:
                department_id = None
                scope_key = "global"
            db.execute(
                """
                INSERT INTO ws_review_grants(
                    id, user_id, scope, scope_key, department_id, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (
                    str(uuid.uuid4()),
                    user_id,
                    scope,
                    scope_key,
                    department_id,
                    actor_id,
                    now,
                ),
            )
            self._log_access(
                db,
                actor_id,
                "admin.grant_review",
                conversation_id=None,
                department_id=department_id,
                now=now,
            )
            row = db.query_one(
                """
                SELECT id, user_id, scope, department_id, created_by, created_at
                FROM ws_review_grants WHERE user_id = ? AND scope_key = ?
                """,
                (user_id, scope_key),
            )
            return {
                "id": row["id"],
                "user_id": row["user_id"],
                "scope": row["scope"],
                "department_id": row["department_id"],
                "created_by": row["created_by"],
                "created_at": float(row["created_at"]),
            }

    @_guard
    def list_grants(
        self,
        actor_id: str,
        *,
        user_id: str | None = None,
        limit: int = 50,
        after: str | None = None,
    ) -> dict[str, Any]:
        """Admin list of persisted review grants (metadata only)."""
        limit = _validate_limit(limit)
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            params: list[Any] = []
            sql = (
                "SELECT g.id, g.user_id, g.scope, g.department_id, g.created_by, "
                "g.created_at, u.username, d.name AS department_name "
                "FROM ws_review_grants AS g "
                "JOIN ws_users AS u ON u.id = g.user_id "
                "LEFT JOIN ws_departments AS d ON d.id = g.department_id "
                "WHERE 1 = 1"
            )
            if user_id is not None:
                sql += " AND g.user_id = ?"
                params.append(user_id)
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (g.created_at < ? OR (g.created_at = ? AND g.id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY g.created_at DESC, g.id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [
                {
                    "id": row["id"],
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "scope": row["scope"],
                    "department_id": row["department_id"],
                    "department_name": row["department_name"],
                    "created_by": row["created_by"],
                    "created_at": float(row["created_at"]),
                }
                for row in rows[:limit]
            ]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    @_guard
    def revoke_grant(self, actor_id: str, grant_id: str) -> None:
        if not isinstance(grant_id, str) or not grant_id:
            raise NotFound("review grant not found")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            row = db.query_one(
                "SELECT id, department_id FROM ws_review_grants WHERE id = ?",
                (grant_id,),
            )
            if not row:
                raise NotFound("review grant not found")
            applied = db.execute(
                "DELETE FROM ws_review_grants WHERE id = ?", (grant_id,)
            )
            if applied != 1:
                raise NotFound("review grant not found")
            self._log_access(
                db,
                actor_id,
                "admin.revoke_review",
                conversation_id=None,
                department_id=row["department_id"],
                now=now,
            )

    @_guard
    def reset_password(self, actor_id: str, user_id: str, password: str) -> None:
        """Admin password reset: revoke every existing session atomically."""
        secret = _require_password(password)
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            row = db.query_one(
                "SELECT id, department_id FROM ws_users WHERE id = ?", (user_id,)
            )
            if not row:
                raise NotFound("user not found")
            db.execute(
                "UPDATE ws_users SET password_hash = ? WHERE id = ?",
                (_hash_password(secret), user_id),
            )
            db.execute(
                "UPDATE ws_sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0",
                (user_id,),
            )
            self._log_access(
                db,
                actor_id,
                "admin.reset_password",
                conversation_id=None,
                department_id=row["department_id"],
                now=now,
            )

    @_guard
    def get_profile(self, actor_id: str) -> dict[str, Any]:
        """Trusted profile plus persisted review-grant summary for /me."""
        with self._backend.transaction() as db:
            row = db.query_one(
                """
                SELECT u.*, d.name AS department_name
                FROM ws_users AS u
                JOIN ws_departments AS d ON d.id = u.department_id
                WHERE u.id = ?
                """,
                (actor_id,),
            )
            if not row or int(row["disabled"]) != 0:
                raise AuthError("session invalid")
            grants = db.query(
                """
                SELECT g.id, g.scope, g.department_id, d.name AS department_name
                FROM ws_review_grants AS g
                LEFT JOIN ws_departments AS d ON d.id = g.department_id
                WHERE g.user_id = ?
                ORDER BY g.scope, g.created_at
                """,
                (actor_id,),
            )
            scope = self._review_scope(db, actor_id)
            return {
                "user": self._public_user(row),
                "department": {
                    "id": row["department_id"],
                    "name": row["department_name"],
                },
                "review_scope": scope[0] if scope else None,
                "review_department_ids": scope[1] if scope else [],
                "review_grants": [
                    {
                        "id": grant["id"],
                        "scope": grant["scope"],
                        "department_id": grant["department_id"],
                        "department_name": grant["department_name"],
                    }
                    for grant in grants
                ],
            }

    # -- authentication and sessions -------------------------------------
    @_guard
    def authenticate(self, username: str, password: str) -> dict[str, Any]:
        candidate = ""
        if isinstance(username, str):
            try:
                candidate = _normalise_username(username)
            except ValueError:
                candidate = ""
        if (
            not candidate
            or not isinstance(password, str)
            or not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH)
        ):
            _verify_password(self._dummy(), password if isinstance(password, str) else "")
            raise AuthError(_AUTH_FAILURE)

        now = self._now()
        with self._backend.transaction() as db:
            row = db.query_one("SELECT * FROM ws_users WHERE username = ?", (candidate,))
            if not row:
                _verify_password(self._dummy(), password)
                raise AuthError(_AUTH_FAILURE)
            if int(row["disabled"]) != 0:
                _verify_password(self._dummy(), password)
                raise AuthError(_AUTH_FAILURE)
            if not _verify_password(row["password_hash"], password):
                raise AuthError(_AUTH_FAILURE)
            token = secrets.token_urlsafe(32)
            expires_at = now + SESSION_TTL_SECONDS
            applied = db.execute(
                """
                INSERT INTO ws_sessions(token_hash, user_id, created_at, expires_at, revoked)
                VALUES (?, ?, ?, ?, 0)
                """,
                (_token_hash(token), row["id"], now, expires_at),
            )
            if applied != 1:
                raise WorkspaceStorageError("session could not be created")
            return {
                "token": token,
                "expires_at": expires_at,
                "user": self._public_user(row),
            }

    @_guard
    def resolve_session(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not 1 <= len(token) <= 512:
            raise AuthError("session invalid")
        now = self._now()
        with self._backend.transaction() as db:
            row = db.query_one(
                """
                SELECT s.expires_at, s.revoked, u.id, u.username, u.full_name,
                       u.department_id, u.role, u.disabled, u.created_at
                FROM ws_sessions AS s
                JOIN ws_users AS u ON u.id = s.user_id
                WHERE s.token_hash = ?
                """,
                (_token_hash(token),),
            )
            if (
                not row
                or int(row["revoked"]) != 0
                or int(row["disabled"]) != 0
                or float(row["expires_at"]) <= now
            ):
                raise AuthError("session invalid")
            return self._public_user(row)

    @_guard
    def logout(self, token: str) -> None:
        if not isinstance(token, str) or not 1 <= len(token) <= 512:
            return
        with self._backend.transaction() as db:
            db.execute(
                "UPDATE ws_sessions SET revoked = 1 WHERE token_hash = ?",
                (_token_hash(token),),
            )

    # -- conversations ---------------------------------------------------
    @_guard
    def create_conversation(
        self, owner_id: str, title: str | None = None
    ) -> dict[str, Any]:
        if title is not None and title != _DEFAULT_TITLE:
            raise ValueError("custom conversation titles are not supported")
        clean_title = _DEFAULT_TITLE
        now = self._now()
        with self._backend.transaction() as db:
            owner = self._require_active_user(db, owner_id)
            conversation_id = str(uuid.uuid4())
            db.execute(
                """
                INSERT INTO ws_conversations(
                    id, owner_id, department_id, title, status, lease_hash,
                    lease_expires_at, version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'idle', NULL, NULL, 0, ?, ?)
                """,
                (
                    conversation_id,
                    owner["id"],
                    owner["department_id"],
                    clean_title,
                    now,
                    now,
                ),
            )
            return {
                "id": conversation_id,
                "owner_id": owner["id"],
                "department_id": owner["department_id"],
                "title": clean_title,
                "status": "idle",
                "version": 0,
                "created_at": now,
                "updated_at": now,
                "message_count": 0,
            }

    @_guard
    def reserve_turn(self, owner_id: str, conversation_id: str) -> dict[str, Any]:
        now = self._now()
        token = secrets.token_urlsafe(32)
        lease_expires_at = now + LEASE_TTL_SECONDS
        with self._backend.transaction() as db:
            self._require_active_user(db, owner_id)
            conversation = db.query_one(
                "SELECT id, owner_id FROM ws_conversations WHERE id = ?",
                (conversation_id,),
            )
            if not conversation:
                raise NotFound("conversation not found")
            if conversation["owner_id"] != owner_id:
                raise AccessDenied("permission denied")
            # The idle/expired predicate is evaluated at write time while this
            # statement holds the row lock. Under READ COMMITTED a concurrent
            # reserving transaction re-checks the predicate after the winner
            # commits, so exactly one reservation can succeed.
            applied = db.execute(
                """
                UPDATE ws_conversations
                SET status = 'pending', lease_hash = ?, lease_expires_at = ?,
                    updated_at = ?
                WHERE id = ? AND owner_id = ?
                  AND (
                      status = 'idle'
                      OR (
                          status = 'pending'
                          AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                      )
                  )
                """,
                (
                    _token_hash(token),
                    lease_expires_at,
                    now,
                    conversation_id,
                    owner_id,
                    now,
                ),
            )
            if applied != 1:
                raise Conflict("conversation busy")
            return {"token": token, "expires_at": lease_expires_at}

    @_guard
    def append_exchange(
        self,
        owner_id: str,
        conversation_id: str,
        lease_token: str,
        *,
        user_prompt: str,
        assistant_response: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        prompt = _require_content_text(
            user_prompt, maximum=TEXT_MAX_LENGTH, field="user prompt"
        )
        response = _require_content_text(
            assistant_response, maximum=TEXT_MAX_LENGTH, field="assistant response"
        )
        if not isinstance(lease_token, str) or not lease_token:
            raise ValueError("turn reservation is invalid")
        clean_request_id = _optional_metadata(request_id, "request_id")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_active_user(db, owner_id)
            conversation = db.query_one(
                "SELECT id, owner_id FROM ws_conversations WHERE id = ?",
                (conversation_id,),
            )
            if not conversation:
                raise NotFound("conversation not found")
            if conversation["owner_id"] != owner_id:
                raise AccessDenied("permission denied")
            claimed = db.execute(
                """
                UPDATE ws_conversations
                SET status = 'appending', version = version + 1, updated_at = ?
                WHERE id = ? AND owner_id = ? AND status = 'pending'
                  AND lease_hash = ? AND lease_expires_at IS NOT NULL
                  AND lease_expires_at > ?
                """,
                (now, conversation_id, owner_id, _token_hash(lease_token), now),
            )
            if claimed != 1:
                raise Conflict("turn reservation is invalid or expired")
            current = db.query_one(
                "SELECT version FROM ws_conversations WHERE id = ?",
                (conversation_id,),
            )
            if not current:
                raise WorkspaceStorageError("workspace conversation was not updated")
            version = int(current["version"])
            row = db.query_one(
                "SELECT COALESCE(MAX(position), 0) AS position FROM ws_messages "
                "WHERE conversation_id = ?",
                (conversation_id,),
            )
            base = int(row["position"]) if row else 0
            messages = []
            for offset, role, text in (
                (1, "user", prompt),
                (2, "assistant", response),
            ):
                message_id = str(uuid.uuid4())
                ciphertext = self._cipher.encrypt(
                    conversation_id, message_id, role, text
                )
                applied = db.execute(
                    """
                    INSERT INTO ws_messages(
                        id, conversation_id, role, position, ciphertext,
                        outcome, request_id, error_code, created_at
                    ) VALUES (?, ?, ?, ?, ?, 'allowed', ?, NULL, ?)
                    """,
                    (
                        message_id,
                        conversation_id,
                        role,
                        base + offset,
                        ciphertext,
                        clean_request_id,
                        now,
                    ),
                )
                if applied != 1:
                    raise WorkspaceStorageError("workspace message was not stored")
                messages.append(
                    {"id": message_id, "role": role, "created_at": now}
                )
            applied = db.execute(
                """
                UPDATE ws_conversations
                SET status = 'idle', lease_hash = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (now, conversation_id),
            )
            if applied != 1:
                raise WorkspaceStorageError("workspace conversation was not updated")
            return {
                "conversation_id": conversation_id,
                "version": version,
                "messages": messages,
            }

    @_guard
    def record_failed_turn(
        self,
        owner_id: str,
        conversation_id: str,
        lease_token: str,
        *,
        user_prompt: str,
        outcome: str,
        request_id: str | None = None,
        error_code: str | None = None,
        alert: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist a failed/blocked original prompt and close the lease.

        Only the user prompt is stored. No assistant content exists for this
        turn, so no pair can enter a later Gateway context.  When the turn was
        blocked, an optional bounded alert metadata payload is inserted in the
        same transaction (request-id idempotent); it never contains prompt or
        response text.
        """
        if outcome not in ("blocked", "failed"):
            raise ValueError("turn outcome is invalid")
        prompt = _require_content_text(
            user_prompt, maximum=TEXT_MAX_LENGTH, field="user prompt"
        )
        clean_request_id = _optional_metadata(request_id, "request_id")
        clean_error_code = _optional_metadata(error_code, "error_code")
        prepared_alert = self._prepare_block_alert(
            alert, outcome=outcome, request_id=clean_request_id
        )
        if not isinstance(lease_token, str) or not lease_token:
            raise ValueError("turn reservation is invalid")
        now = self._now()
        with self._backend.transaction() as db:
            owner = self._require_active_user(db, owner_id)
            conversation = db.query_one(
                "SELECT id, owner_id FROM ws_conversations WHERE id = ?",
                (conversation_id,),
            )
            if not conversation:
                raise NotFound("conversation not found")
            if conversation["owner_id"] != owner_id:
                raise AccessDenied("permission denied")
            claimed = db.execute(
                """
                UPDATE ws_conversations
                SET status = 'appending', version = version + 1, updated_at = ?
                WHERE id = ? AND owner_id = ? AND status = 'pending'
                  AND lease_hash = ? AND lease_expires_at IS NOT NULL
                  AND lease_expires_at > ?
                """,
                (now, conversation_id, owner_id, _token_hash(lease_token), now),
            )
            if claimed != 1:
                raise Conflict("turn reservation is invalid or expired")
            current = db.query_one(
                "SELECT version FROM ws_conversations WHERE id = ?",
                (conversation_id,),
            )
            if not current:
                raise WorkspaceStorageError("workspace conversation was not updated")
            version = int(current["version"])
            row = db.query_one(
                "SELECT COALESCE(MAX(position), 0) AS position FROM ws_messages "
                "WHERE conversation_id = ?",
                (conversation_id,),
            )
            position = (int(row["position"]) if row else 0) + 1
            message_id = str(uuid.uuid4())
            ciphertext = self._cipher.encrypt(
                conversation_id, message_id, "user", prompt
            )
            applied = db.execute(
                """
                INSERT INTO ws_messages(
                    id, conversation_id, role, position, ciphertext,
                    outcome, request_id, error_code, created_at
                ) VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    conversation_id,
                    position,
                    ciphertext,
                    outcome,
                    clean_request_id,
                    clean_error_code,
                    now,
                ),
            )
            if applied != 1:
                raise WorkspaceStorageError("workspace message was not stored")
            alert_id = None
            if prepared_alert is not None:
                alert_id = self._insert_block_alert(
                    db,
                    prepared_alert,
                    user_id=owner["id"],
                    department_id=owner["department_id"],
                    conversation_id=conversation_id,
                    message_id=message_id,
                    now=now,
                )
            applied = db.execute(
                """
                UPDATE ws_conversations
                SET status = 'idle', lease_hash = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE id = ?
                """,
                (now, conversation_id),
            )
            if applied != 1:
                raise WorkspaceStorageError("workspace conversation was not updated")
            return {
                "conversation_id": conversation_id,
                "version": version,
                "alert_id": alert_id,
                "message": {
                    "id": message_id,
                    "role": "user",
                    "outcome": outcome,
                    "request_id": clean_request_id,
                    "error_code": clean_error_code,
                    "created_at": now,
                },
            }

    @_guard
    def read_context(
        self, owner_id: str, conversation_id: str
    ) -> dict[str, Any]:
        """Return only allowed, paired messages for a new Gateway request.

        The complete stored sequence is validated before any filtering. A
        malformed role, an unknown outcome, an allowed message outside a
        user/assistant pair, or an assistant marked failed/blocked is stored
        corruption and raises ``ContentError``. Failed/blocked user-only turns
        between complete pairs remain in history but are omitted from context.
        """
        if not isinstance(conversation_id, str) or not conversation_id:
            raise NotFound("conversation not found")
        with self._backend.transaction() as db:
            self._require_active_user(db, owner_id)
            conversation = db.query_one(
                "SELECT id, owner_id FROM ws_conversations WHERE id = ?",
                (conversation_id,),
            )
            if not conversation:
                raise NotFound("conversation not found")
            if conversation["owner_id"] != owner_id:
                raise AccessDenied("permission denied")
            rows = db.query(
                """
                SELECT id, role, ciphertext, outcome
                FROM ws_messages WHERE conversation_id = ?
                ORDER BY position
                """,
                (conversation_id,),
            )
            paired: list[dict[str, str]] = []
            pending_user = None
            for row in rows:
                role, outcome = row["role"], row["outcome"]
                if role not in ("user", "assistant"):
                    raise ContentError("stored workspace history is invalid")
                if outcome not in ("allowed", "failed", "blocked"):
                    raise ContentError("stored workspace history is invalid")
                if outcome != "allowed":
                    if role != "user" or pending_user is not None:
                        raise ContentError("stored workspace history is invalid")
                    continue
                if role == "user":
                    if pending_user is not None:
                        raise ContentError("stored workspace history is invalid")
                    pending_user = row
                    continue
                if pending_user is None:
                    raise ContentError("stored workspace history is invalid")
                paired.append(
                    {
                        "role": "user",
                        "content": self._cipher.decrypt(
                            conversation_id,
                            pending_user["id"],
                            "user",
                            pending_user["ciphertext"],
                        ),
                    }
                )
                paired.append(
                    {
                        "role": "assistant",
                        "content": self._cipher.decrypt(
                            conversation_id,
                            row["id"],
                            "assistant",
                            row["ciphertext"],
                        ),
                    }
                )
                pending_user = None
            if pending_user is not None:
                raise ContentError("stored workspace history is invalid")
            return {"messages": paired}

    @_guard
    def cancel_turn(
        self, owner_id: str, conversation_id: str, lease_token: str
    ) -> None:
        if not isinstance(lease_token, str) or not lease_token:
            return
        now = self._now()
        with self._backend.transaction() as db:
            self._require_active_user(db, owner_id)
            db.execute(
                """
                UPDATE ws_conversations
                SET status = 'idle', lease_hash = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE id = ? AND owner_id = ? AND status = 'pending'
                  AND lease_hash = ?
                """,
                (now, conversation_id, owner_id, _token_hash(lease_token)),
            )

    @_guard
    def list_conversations(
        self,
        actor_id: str,
        *,
        limit: int = DEFAULT_LIMIT,
        after: str | None = None,
        scope: str = "own",
    ) -> dict[str, Any]:
        limit = _validate_limit(limit)
        if scope not in ("own", "review"):
            raise ValueError("conversation scope is invalid")
        with self._backend.transaction() as db:
            self._require_active_user(db, actor_id)
            params: list[Any] = []
            if scope == "own":
                where = "c.owner_id = ?"
                params.append(actor_id)
            else:
                grant = self._review_scope(db, actor_id)
                if grant is None:
                    raise AccessDenied("permission denied")
                self._log_access(
                    db,
                    actor_id,
                    "reviewer.list_conversations",
                    conversation_id=None,
                    department_id=None,
                    now=self._now(),
                )
                kind, departments = grant
                if kind == "global":
                    where = "1 = 1"
                else:
                    placeholders = ",".join("?" for _ in departments)
                    where = f"c.department_id IN ({placeholders})"
                    params.extend(departments)
            sql = (
                "SELECT c.*, u.full_name AS owner_full_name, "
                "d.name AS department_name, "
                "(SELECT COUNT(*) FROM ws_messages AS m "
                " WHERE m.conversation_id = c.id) AS message_count "
                "FROM ws_conversations AS c "
                "JOIN ws_users AS u ON u.id = c.owner_id "
                "JOIN ws_departments AS d ON d.id = c.department_id "
                f"WHERE {where}"
            )
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (c.created_at < ? OR (c.created_at = ? AND c.id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY c.created_at DESC, c.id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [
                self._conversation_metadata(row, int(row["message_count"]))
                for row in rows[:limit]
            ]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    @_guard
    def read_conversation(
        self, actor_id: str, conversation_id: str
    ) -> dict[str, Any]:
        if not isinstance(conversation_id, str) or not conversation_id:
            raise NotFound("conversation not found")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_active_user(db, actor_id)
            conversation = db.query_one(
                "SELECT c.*, u.full_name AS owner_full_name, "
                "d.name AS department_name "
                "FROM ws_conversations AS c "
                "JOIN ws_users AS u ON u.id = c.owner_id "
                "JOIN ws_departments AS d ON d.id = c.department_id "
                "WHERE c.id = ?",
                (conversation_id,),
            )
            if not conversation:
                raise NotFound("conversation not found")
            reviewer = conversation["owner_id"] != actor_id
            if reviewer:
                if not self._has_review_grant(
                    db, actor_id, conversation["department_id"]
                ):
                    raise AccessDenied("permission denied")
                self._log_access(
                    db,
                    actor_id,
                    "reviewer.read_conversation",
                    conversation_id=conversation_id,
                    department_id=conversation["department_id"],
                    now=now,
                )
            rows = db.query(
                """
                SELECT id, role, ciphertext, outcome, request_id, error_code,
                       created_at
                FROM ws_messages
                WHERE conversation_id = ? ORDER BY position
                """,
                (conversation_id,),
            )
            alert_rows = db.query(
                "SELECT message_id, request_id, stage, reason_code "
                "FROM ws_block_alerts WHERE conversation_id = ? AND user_id = ?",
                (conversation_id, conversation["owner_id"]),
            )
            blocks: dict[str, dict[str, str]] = {}
            for alert in alert_rows:
                message_id = alert.get("message_id")
                request_id = alert.get("request_id")
                reason_code = alert.get("reason_code")
                stage = alert.get("stage")
                if not isinstance(message_id, str) or not message_id:
                    continue
                if (
                    not isinstance(request_id, str)
                    or not 1 <= len(request_id) <= 128
                    or any(
                        ord(char) < 32 or ord(char) == 127
                        for char in request_id
                    )
                ):
                    continue
                try:
                    detail = block_detail(reason_code)
                except (KeyError, TypeError, ValueError):
                    continue
                if stage != detail["stage"]:
                    continue
                blocks[message_id] = {**detail, "ref": request_id}
            messages = [
                {
                    "id": row["id"],
                    "role": row["role"],
                    "outcome": row["outcome"],
                    "request_id": row["request_id"],
                    "error_code": row["error_code"],
                    "created_at": float(row["created_at"]),
                    "text": self._cipher.decrypt(
                        conversation_id, row["id"], row["role"], row["ciphertext"]
                    ),
                }
                for row in rows
            ]
            for message in messages:
                if message["outcome"] == "blocked":
                    block = blocks.get(message["id"])
                    if block is not None:
                        message["block"] = block
            metadata = self._conversation_metadata(conversation, len(messages))
        # The transaction above committed before the plaintext is returned.
        result = dict(metadata)
        result["messages"] = messages
        return result

    def _has_review_grant(
        self, db: _Db, user_id: str, department_id: str
    ) -> bool:
        grant = self._review_scope(db, user_id)
        if grant is None:
            return False
        kind, departments = grant
        return kind == "global" or department_id in departments

    @_guard
    def delete_conversation(self, actor_id: str, conversation_id: str) -> None:
        if not isinstance(conversation_id, str) or not conversation_id:
            raise NotFound("conversation not found")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_active_user(db, actor_id)
            conversation = db.query_one(
                "SELECT id, owner_id, department_id, status, lease_expires_at "
                "FROM ws_conversations WHERE id = ?",
                (conversation_id,),
            )
            if not conversation:
                raise NotFound("conversation not found")
            if conversation["owner_id"] != actor_id:
                raise AccessDenied("permission denied")
            status = conversation["status"]
            expires_at = conversation["lease_expires_at"]
            if status == "appending" or (
                status == "pending"
                and expires_at is not None
                and float(expires_at) > now
            ):
                raise Conflict("conversation busy")
            # The own-content deletion is recorded before the row is removed;
            # a failed audit aborts the transaction. Non-content audit rows are
            # retained after the content is gone.
            self._log_access(
                db,
                actor_id,
                "owner.delete_conversation",
                conversation_id=conversation_id,
                department_id=conversation["department_id"],
                now=now,
            )
            # The conditional delete is the authoritative row claim: a turn
            # that became active after the SELECT cannot be orphaned here.
            applied = db.execute(
                """
                DELETE FROM ws_conversations
                WHERE id = ? AND owner_id = ?
                  AND NOT (
                      status = 'appending'
                      OR (
                          status = 'pending'
                          AND lease_expires_at IS NOT NULL
                          AND lease_expires_at > ?
                      )
                  )
                """,
                (conversation_id, actor_id, now),
            )
            if applied != 1:
                raise Conflict("conversation busy")

    @_guard
    def list_access_log(
        self, actor_id: str, *, limit: int = 50, after: str | None = None
    ) -> dict[str, Any]:
        limit = _validate_limit(limit)
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            params: list[Any] = []
            sql = (
                "SELECT id, actor_id, action, conversation_id, department_id, "
                "created_at FROM ws_access_log WHERE 1 = 1"
            )
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (created_at < ? OR (created_at = ? AND id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [
                {
                    "id": row["id"],
                    "actor_id": row["actor_id"],
                    "action": row["action"],
                    "conversation_id": row["conversation_id"],
                    "department_id": row["department_id"],
                    "created_at": float(row["created_at"]),
                }
                for row in rows[:limit]
            ]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}
