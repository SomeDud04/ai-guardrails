"""Bounded CSV export encoding and append-only export-audit writers.

The export path deliberately does not stream.  A bounded snapshot is rendered to
one complete byte string, checked against the row and byte caps, and only then is
its SHA-256 committed to an append-only audit row.  The HTTP response can be
released only after that write succeeds.

``PostgresExportAuditLog`` is the production writer boundary.  It reuses the
runtime writer DSN and only INSERTs into ``export_audits``; it never creates a
schema, selects a row or mutates existing audit data.  ``SqliteExportAuditLog``
is an explicit local test/demo implementation and is never selected by the
runtime environment automatically.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import sqlite3
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_EXPORT_ROWS = 1000
MAX_EXPORT_BYTES = 2 * 1024 * 1024
EXPORT_FILENAME = "nasi-lemak-events-export.csv"
MAX_DSN_LENGTH = 4096

# Metadata-only export columns.  ``app_id`` is the trusted server-side scope, not
# a value read from an untrusted row.  The export identity/creation/filter
# metadata is repeated on every row so a single line remains self-describing.
CSV_COLUMNS = (
    "seq",
    "request_id",
    "event_type",
    "timestamp",
    "model",
    "policy_version",
    "policy_digest",
    "decision",
    "error_code",
    "app_id",
    "export_id",
    "created_utc",
    "filters",
)

_FORBIDDEN_FORMULA_START = frozenset("=+-@")
# The formula probe strips Unicode whitespace; ASCII control prefixes are
# checked on the raw value below.


class ExportError(RuntimeError):
    """The export could not be prepared safely."""


class ExportTooLarge(ExportError):
    """The bounded snapshot or its serialized CSV exceeds the export cap."""


class ExportAuditError(RuntimeError):
    """The export audit write failed; no CSV may be released."""


@dataclass(frozen=True)
class ExportAuditEntry:
    """Metadata committed before an export is released.

    The complete CSV, credentials and raw request content are intentionally not
    fields.  The hash binds the metadata row to the exact bytes that are returned.
    """

    export_id: str
    app_id: str
    created_at: float
    filters: str
    row_count: int
    sha256: str
    policy_version: str
    policy_digest: str
    upper_seq: int

    def __post_init__(self) -> None:
        if not isinstance(self.export_id, str) or not self.export_id:
            raise ValueError("invalid export id")
        if not isinstance(self.app_id, str) or not self.app_id:
            raise ValueError("invalid app id")
        if (
            isinstance(self.created_at, bool)
            or not isinstance(self.created_at, (int, float))
            or not math.isfinite(self.created_at)
            or self.created_at <= 0
        ):
            raise ValueError("invalid export timestamp")
        if not isinstance(self.filters, str):
            raise ValueError("invalid filters")
        if (
            isinstance(self.row_count, bool)
            or not isinstance(self.row_count, int)
            or not 0 <= self.row_count <= MAX_EXPORT_ROWS
        ):
            raise ValueError("invalid export row count")
        if (
            not isinstance(self.sha256, str)
            or len(self.sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in self.sha256)
        ):
            raise ValueError("invalid export checksum")
        if not isinstance(self.policy_version, str) or not self.policy_version:
            raise ValueError("invalid policy version")
        if not _is_hex_digest(self.policy_digest):
            raise ValueError("invalid policy digest")
        if (
            isinstance(self.upper_seq, bool)
            or not isinstance(self.upper_seq, int)
            or self.upper_seq < 0
        ):
            raise ValueError("invalid export sequence")


def utc_iso(timestamp: float) -> str:
    """Format an epoch timestamp as a fixed UTC ISO-8601 string."""
    return (
        datetime.fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _is_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _format_timestamp(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, (int, float)):
        if not math.isfinite(float(value)):
            return str(value)
        return repr(float(value))
    return str(value)


def neutralize_cell(value: Any) -> str:
    """Return a CSV cell that cannot start a spreadsheet formula.

    Every value is stringified.  A leading ``=``, ``+``, ``-`` or ``@`` (also
    after any leading Unicode whitespace, including NBSP or em space), a
    leading tab/CR/LF or any leading control character receives one apostrophe.
    Stored rows are never changed; this is applied only to the rendered CSV.
    """
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""

    probe = text.lstrip()
    if probe:
        first = probe[0]
        if first in _FORBIDDEN_FORMULA_START:
            return "'" + text
        if ord(first) < 0x20 or ord(first) == 0x7F:
            return "'" + text

    first_raw = text[0]
    if first_raw in "\t\r\n":
        return "'" + text
    if ord(first_raw) < 0x20 or ord(first_raw) == 0x7F:
        return "'" + text
    return text


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_export_csv(
    rows: list[dict[str, Any]],
    *,
    app_id: str,
    export_id: str,
    created_utc: str,
    filters: str,
) -> bytes:
    """Render the complete bounded CSV and enforce the hard caps.

    ``rows`` must come from one app-scoped, sequence-ordered snapshot.  More than
    ``MAX_EXPORT_ROWS`` rows or more than ``MAX_EXPORT_BYTES`` serialized bytes is
    an error rather than a silently truncated export.
    """
    if len(rows) > MAX_EXPORT_ROWS:
        raise ExportTooLarge("export row cap exceeded")

    buffer = io.BytesIO()
    # ``write_through`` keeps the byte count current after every row so the cap
    # is enforced while rendering instead of after one unbounded whole buffer.
    text = io.TextIOWrapper(
        buffer, encoding="utf-8", newline="", write_through=True
    )
    writer = csv.writer(text, lineterminator="\r\n")
    writer.writerow([neutralize_cell(column) for column in CSV_COLUMNS])
    if buffer.tell() > MAX_EXPORT_BYTES:
        raise ExportTooLarge("export byte cap exceeded")
    for row in rows:
        writer.writerow(
            [
                neutralize_cell(row.get("seq")),
                neutralize_cell(row.get("request_id")),
                neutralize_cell(row.get("event_type")),
                neutralize_cell(_format_timestamp(row.get("timestamp"))),
                neutralize_cell(row.get("model")),
                neutralize_cell(row.get("policy_version")),
                neutralize_cell(row.get("policy_digest")),
                neutralize_cell(row.get("decision")),
                neutralize_cell(row.get("error_code")),
                neutralize_cell(app_id),
                neutralize_cell(export_id),
                neutralize_cell(created_utc),
                neutralize_cell(filters),
            ]
        )
        if buffer.tell() > MAX_EXPORT_BYTES:
            raise ExportTooLarge("export byte cap exceeded")
    text.flush()
    return buffer.getvalue()


class ExportAuditLog(ABC):
    """Minimal append-only boundary for prepared-export metadata."""

    @abstractmethod
    def record(self, entry: ExportAuditEntry) -> None:
        """Persist one audit row durably before the CSV is released."""

    @abstractmethod
    def close(self) -> None:
        """Release any long-lived resources."""


class SqliteExportAuditLog(ExportAuditLog):
    """Local test/demo export-audit writer.

    This is an explicit injected seam only.  It is not selected by the runtime
    environment and must not be presented as PostgreSQL evidence.
    """

    def __init__(self, path: str | Path, *, connect_timeout: float = 3.0):
        if (
            isinstance(connect_timeout, bool)
            or not isinstance(connect_timeout, (int, float))
            or not math.isfinite(connect_timeout)
            or connect_timeout <= 0
        ):
            raise ValueError("invalid connect timeout")
        self.path = Path(path)
        self.connect_timeout = float(connect_timeout)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connection(self):
        conn = sqlite3.connect(str(self.path), timeout=self.connect_timeout)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA busy_timeout=3000")
        return conn

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = None
            try:
                conn = self._connection()
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS export_audits (
                        id INTEGER PRIMARY KEY,
                        export_id TEXT NOT NULL UNIQUE,
                        app_id TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        filters TEXT NOT NULL,
                        row_count INTEGER NOT NULL,
                        sha256 TEXT NOT NULL,
                        policy_version TEXT NOT NULL,
                        policy_digest TEXT NOT NULL,
                        upper_seq INTEGER NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_export_audits_app_created
                    ON export_audits(app_id, created_at)
                    """
                )
                conn.commit()
            except sqlite3.Error as exc:
                raise ExportAuditError("export audit database unavailable") from exc
            finally:
                if conn is not None:
                    conn.close()

    def record(self, entry: ExportAuditEntry) -> None:
        if not isinstance(entry, ExportAuditEntry):
            raise ValueError("invalid export audit entry")
        with self._lock:
            conn = None
            try:
                conn = self._connection()
                cursor = conn.execute(
                    """
                    INSERT INTO export_audits(
                        export_id, app_id, created_at, filters, row_count,
                        sha256, policy_version, policy_digest, upper_seq
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.export_id,
                        entry.app_id,
                        entry.created_at,
                        entry.filters,
                        entry.row_count,
                        entry.sha256,
                        entry.policy_version,
                        entry.policy_digest,
                        entry.upper_seq,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ExportAuditError("export audit write was not applied")
                conn.commit()
            except ExportAuditError:
                raise
            except sqlite3.Error as exc:
                if conn is not None:
                    conn.rollback()
                raise ExportAuditError("export audit write failed") from exc
            finally:
                if conn is not None:
                    conn.close()

    def close(self) -> None:
        pass


class PostgresExportAuditLog(ExportAuditLog):
    """Production append-only export-audit writer using the runtime writer DSN.

    The restricted writer role has INSERT on ``export_audits`` and USAGE on its
    sequence only.  This class never creates schema or roles and never issues a
    SELECT/UPDATE/DELETE.  The DSN is private and never appears in reprs or
    raised errors.
    """

    _INSERT_SQL = """
        INSERT INTO export_audits(
            export_id, app_id, created_at, filters, row_count,
            sha256, policy_version, policy_digest, upper_seq
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
        if len(conninfo) > MAX_DSN_LENGTH or "\x00" in conninfo:
            raise ValueError("invalid conninfo")
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
                raise ExportAuditError("export audit driver unavailable") from None
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
            raise ExportAuditError("export audit database unavailable") from None

    @staticmethod
    def _close_connection(conn) -> None:
        try:
            conn.close()
        except Exception:
            raise ExportAuditError("export audit connection close failed") from None

    def record(self, entry: ExportAuditEntry) -> None:
        if not isinstance(entry, ExportAuditEntry):
            raise ValueError("invalid export audit entry")
        conn = self._connect()
        try:
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute(
                            self._INSERT_SQL,
                            (
                                entry.export_id,
                                entry.app_id,
                                entry.created_at,
                                entry.filters,
                                entry.row_count,
                                entry.sha256,
                                entry.policy_version,
                                entry.policy_digest,
                                entry.upper_seq,
                            ),
                        )
                        if cur.rowcount != 1:
                            raise ExportAuditError("export audit write was not applied")
            except ExportAuditError:
                raise
            except Exception:
                raise ExportAuditError("export audit write failed") from None
        finally:
            self._close_connection(conn)

    def close(self) -> None:
        pass
