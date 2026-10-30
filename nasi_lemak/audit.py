"""Audit store boundary with SQLite and PostgreSQL implementations.

Metadata-only event log: one initial event before inference and one terminal
event before a response is released.  ``AuditStore`` is the minimal boundary
used by ``Gateway``; concrete implementations own connection management,
parameterised SQL, timeouts and rollback/close behaviour.

Schema bootstrap and role grants are intentionally separate from runtime
writer credentials.  The PostgreSQL runtime writer is append-only: it may only
INSERT into ``events`` and cannot read, update or delete audit rows.  Reading and
explicit offline recovery use separate roles.  The runtime writer therefore
receives the trusted policy metadata for terminal events from ``Gateway``
instead of selecting the original row.
"""

from __future__ import annotations

import math
import sqlite3
import threading
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Any


SCHEMA_PATH = Path(__file__).with_name("audit_schema.sql")
ROLES_PATH = Path(__file__).with_name("audit_roles.sql")


class AuditError(RuntimeError):
    """Audit storage failed; the gateway must fail closed."""


class AuditStore(ABC):
    """Minimal audit boundary for the fail-closed gateway."""

    @abstractmethod
    def record_initial(
        self,
        request_id: str,
        app_id: str,
        model: str,
        policy_version: str,
        policy_digest: str,
    ) -> float:
        """Persist the initial event durably and return the timestamp written.

        The value is exactly the ``timestamp`` column stored in the audit row;
        callers may ignore it.  It is not a second, independent timer.
        """

    @abstractmethod
    def record_terminal(
        self,
        request_id: str,
        event_type: str,
        decision: str,
        error_code: str | None = None,
        *,
        app_id: str,
        model: str,
        policy_version: str,
        policy_digest: str,
    ) -> float:
        """Append a terminal event and return the timestamp written."""

    @abstractmethod
    def read_events(self) -> list[dict[str, Any]]:
        """Return all events ordered by sequence."""

    @abstractmethod
    def reconcile_incomplete(self, *, offline: bool = False) -> int:
        """Explicit offline recovery preserving original policy metadata."""

    @abstractmethod
    def ready(self) -> bool:
        """Lightweight connectivity check; must not perform heavy work."""

    @abstractmethod
    def close(self) -> None:
        """Release any long-lived resources."""


class _SqliteConnection:
    """Context manager: connect, commit on success, rollback/close on failure."""

    def __init__(self, path: Path, timeout: float):
        self.path = path
        self.timeout = timeout
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        try:
            self._conn = sqlite3.connect(str(self.path), timeout=self.timeout)
        except sqlite3.Error as exc:
            raise AuditError("audit database unavailable") from exc
        self._conn.execute("PRAGMA journal_mode=DELETE")
        self._conn.execute("PRAGMA busy_timeout=3000")
        return self._conn

    def __exit__(self, exc_type, exc, tb):
        conn = self._conn
        self._conn = None
        if conn is None:
            return False
        try:
            if exc_type is None:
                conn.commit()
            else:
                conn.rollback()
        finally:
            conn.close()
        return False


class SqliteAuditStore(AuditStore):
    """Development/test audit store backed by a local SQLite file.

    This is intentionally *not* the production audit target; it preserves the
    existing demo/test behaviour while the boundary is extracted.
    """

    def __init__(self, path: str | Path, *, connect_timeout: float = 3.0):
        self.path = Path(path)
        self.connect_timeout = connect_timeout
        self._lock = threading.Lock()
        self._owner_id = uuid.uuid4().hex
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._connection() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    app_id TEXT NOT NULL,
                    model TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    error_code TEXT
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS owners (
                    request_id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL
                )
                """
            )

    @contextmanager
    def _connection(self):
        with self._lock:
            with _SqliteConnection(self.path, self.connect_timeout) as db:
                yield db

    def record_initial(
        self,
        request_id: str,
        app_id: str,
        model: str,
        policy_version: str,
        policy_digest: str,
    ) -> float:
        timestamp = time.time()
        with self._connection() as db:
            cursor = db.execute(
                """
                INSERT INTO events(
                    request_id, event_type, timestamp, app_id, model,
                    policy_version, policy_digest, decision, error_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    "request_started",
                    timestamp,
                    app_id,
                    model,
                    policy_version,
                    policy_digest,
                    "pending",
                    None,
                ),
            )
            if cursor.rowcount != 1:
                raise AuditError("audit write was not applied")
            db.execute(
                "INSERT OR REPLACE INTO owners VALUES (?, ?)",
                (request_id, self._owner_id),
            )
        return timestamp

    def record_terminal(
        self,
        request_id: str,
        event_type: str,
        decision: str,
        error_code: str | None = None,
        *,
        app_id: str,
        model: str,
        policy_version: str,
        policy_digest: str,
    ) -> float:
        timestamp = time.time()
        with self._connection() as db:
            cursor = db.execute(
                """
                INSERT INTO events(
                    request_id, event_type, timestamp, app_id, model,
                    policy_version, policy_digest, decision, error_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    event_type,
                    timestamp,
                    app_id,
                    model,
                    policy_version,
                    policy_digest,
                    decision,
                    error_code,
                ),
            )
            if cursor.rowcount != 1:
                raise AuditError("audit write was not applied")
            db.execute("DELETE FROM owners WHERE request_id = ?", (request_id,))
        return timestamp

    def read_events(self) -> list[dict[str, Any]]:
        with self._connection() as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM events ORDER BY seq")]

    def reconcile_incomplete(self, *, offline: bool = False) -> int:
        if offline is not True:
            raise ValueError("offline confirmation required")
        terminal = ("request_completed", "request_failed", "request_blocked", "request_recovered")
        marks = ",".join("?" for _ in terminal)
        with self._connection() as db:
            rows = db.execute(
                f"""
                SELECT request_id, app_id, model, policy_version, policy_digest
                FROM events AS started
                WHERE event_type = 'request_started'
                  AND request_id NOT IN (
                      SELECT request_id FROM events WHERE event_type IN ({marks})
                  )
                """,
                terminal,
            ).fetchall()
            for request_id, app_id, model, policy_version, policy_digest in rows:
                cursor = db.execute(
                    """
                    INSERT INTO events(
                        request_id, event_type, timestamp, app_id, model,
                        policy_version, policy_digest, decision, error_code
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request_id,
                        "request_recovered",
                        time.time(),
                        app_id,
                        model,
                        policy_version,
                        policy_digest,
                        "interrupted",
                        "UNAVAILABLE",
                    ),
                )
                if cursor.rowcount != 1:
                    raise AuditError("audit recovery write was not applied")
                db.execute("DELETE FROM owners WHERE request_id = ?", (request_id,))
        return len(rows)

    def ready(self) -> bool:
        try:
            with self._connection() as db:
                db.execute("SELECT 1 FROM events LIMIT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        pass


class PostgresAuditStore(AuditStore):
    """Production audit store using psycopg 3.

    The runtime writer is append-only.  Connections use ``autocommit=True`` so
    no implicit transaction is opened before ``conn.transaction()``; each write
    runs in exactly one explicit transaction which psycopg commits before the
    context manager exits.  ``statement_timeout`` is applied as a libpq connect
    option, so it never depends on a session statement executed in an implicit
    transaction.  Schema creation and role grants are *not* performed at
    runtime; apply ``audit_schema.sql`` and ``audit_roles.sql`` during bootstrap
    with admin credentials.

    ``conninfo`` is deliberately private: reprs and raised errors never include
    the DSN or any credentials it may contain.
    """

    _INSERT_EVENT_SQL = """
        INSERT INTO events(
            request_id, event_type, timestamp, app_id, model,
            policy_version, policy_digest, decision, error_code
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    _READY_SQL = """
        SELECT
            to_regclass('public.events') IS NOT NULL
            AND has_schema_privilege(current_user, 'public', 'USAGE')
            AND COALESCE(
                has_table_privilege(current_user, 'public.events', 'INSERT'),
                false
            )
            AND COALESCE(
                has_sequence_privilege(
                    current_user,
                    pg_get_serial_sequence('public.events', 'seq'),
                    'USAGE'
                ),
                false
            )
    """

    def __init__(
        self,
        conninfo: str,
        *,
        connect_timeout: int = 5,
        statement_timeout_seconds: float = 5.0,
    ):
        if not isinstance(conninfo, str) or not conninfo.strip():
            raise ValueError("conninfo required")
        if (
            isinstance(connect_timeout, bool)
            or not isinstance(connect_timeout, int)
            or connect_timeout < 1
        ):
            raise ValueError("connect_timeout must be a positive integer")
        if (
            isinstance(statement_timeout_seconds, bool)
            or not isinstance(statement_timeout_seconds, (int, float))
            or not math.isfinite(statement_timeout_seconds)
            or statement_timeout_seconds <= 0
        ):
            raise ValueError("statement_timeout_seconds must be finite and positive")
        self._conninfo = conninfo
        self.connect_timeout = connect_timeout
        self.statement_timeout_ms = max(1, int(statement_timeout_seconds * 1000))
        self._psycopg: Any | None = None

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"connect_timeout={self.connect_timeout}, "
            f"statement_timeout_ms={self.statement_timeout_ms})"
        )

    def _load_psycopg(self):
        if self._psycopg is None:
            try:
                import psycopg
            except ImportError:
                raise AuditError("audit driver unavailable") from None
            self._psycopg = psycopg
        return self._psycopg

    def _connect(self):
        psycopg = self._load_psycopg()
        try:
            return psycopg.connect(
                self._conninfo,
                connect_timeout=self.connect_timeout,
                autocommit=True,
                options=f"-c statement_timeout={self.statement_timeout_ms}",
            )
        except Exception:
            raise AuditError("audit database unavailable") from None

    @staticmethod
    def _close_connection(conn) -> None:
        try:
            conn.close()
        except Exception:
            raise AuditError("audit connection close failed") from None

    def _write_event(
        self,
        request_id: str,
        event_type: str,
        timestamp: float,
        app_id: str,
        model: str,
        policy_version: str,
        policy_digest: str,
        decision: str,
        error_code: str | None,
    ) -> float:
        conn = self._connect()
        try:
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(
                            self._INSERT_EVENT_SQL,
                            (
                                request_id,
                                event_type,
                                timestamp,
                                app_id,
                                model,
                                policy_version,
                                policy_digest,
                                decision,
                                error_code,
                            ),
                        )
                        if cur.rowcount != 1:
                            raise AuditError("audit write was not applied")
            except AuditError:
                raise
            except Exception:
                raise AuditError("audit write failed") from None
        finally:
            self._close_connection(conn)
        return timestamp

    def record_initial(
        self,
        request_id: str,
        app_id: str,
        model: str,
        policy_version: str,
        policy_digest: str,
    ) -> float:
        timestamp = time.time()
        return self._write_event(
            request_id,
            "request_started",
            timestamp,
            app_id,
            model,
            policy_version,
            policy_digest,
            "pending",
            None,
        )

    def record_terminal(
        self,
        request_id: str,
        event_type: str,
        decision: str,
        error_code: str | None = None,
        *,
        app_id: str,
        model: str,
        policy_version: str,
        policy_digest: str,
    ) -> float:
        timestamp = time.time()
        return self._write_event(
            request_id,
            event_type,
            timestamp,
            app_id,
            model,
            policy_version,
            policy_digest,
            decision,
            error_code,
        )

    def read_events(self) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT seq, request_id, event_type, timestamp, app_id, model,
                               policy_version, policy_digest, decision, error_code
                        FROM events ORDER BY seq
                        """
                    )
                    rows = cur.fetchall()
                    columns = [desc[0] for desc in cur.description]
                    return [dict(zip(columns, row)) for row in rows]
            except Exception:
                raise AuditError("audit read failed") from None
        finally:
            self._close_connection(conn)

    def reconcile_incomplete(self, *, offline: bool = False) -> int:
        if offline is not True:
            raise ValueError("offline confirmation required")
        terminal = ("request_completed", "request_failed", "request_blocked", "request_recovered")
        conn = self._connect()
        try:
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT request_id, app_id, model, policy_version, policy_digest
                            FROM events
                            WHERE event_type = 'request_started'
                              AND request_id NOT IN (
                                  SELECT request_id FROM events
                                  WHERE event_type IN ({','.join('%s' for _ in terminal)})
                              )
                            """,
                            terminal,
                        )
                        rows = cur.fetchall()
                        for request_id, app_id, model, policy_version, policy_digest in rows:
                            cur.execute(
                                self._INSERT_EVENT_SQL,
                                (
                                    request_id,
                                    "request_recovered",
                                    time.time(),
                                    app_id,
                                    model,
                                    policy_version,
                                    policy_digest,
                                    "interrupted",
                                    "UNAVAILABLE",
                                ),
                            )
                            if cur.rowcount != 1:
                                raise AuditError("audit recovery write was not applied")
                return len(rows)
            except AuditError:
                raise
            except Exception:
                raise AuditError("audit recovery failed") from None
        finally:
            self._close_connection(conn)

    def ready(self) -> bool:
        """Verify schema presence and append privilege without reading events."""
        try:
            conn = self._connect()
            try:
                with conn.cursor() as cur:
                    cur.execute(self._READY_SQL)
                    row = cur.fetchone()
                    return bool(row and row[0])
            finally:
                self._close_connection(conn)
        except Exception:
            return False

    def close(self) -> None:
        pass


class UnreadyAuditStore(AuditStore):
    """Placeholder used when server configuration is incomplete.

    Keeps the gateway object valid for liveness, but forces readiness and chat
    to fail closed without claiming a working audit backend.
    """

    def record_initial(
        self, request_id, app_id, model, policy_version, policy_digest
    ) -> float:
        raise AuditError("audit not configured")

    def record_terminal(
        self,
        request_id,
        event_type,
        decision,
        error_code=None,
        *,
        app_id,
        model,
        policy_version,
        policy_digest,
    ) -> float:
        raise AuditError("audit not configured")

    def read_events(self):
        return []

    def reconcile_incomplete(self, *, offline=False):
        if offline is not True:
            raise ValueError("offline confirmation required")
        return 0

    def ready(self):
        return False

    def close(self):
        pass
