"""Read-only operator event boundary.

The operator view is deliberately separate from ``Gateway``: it uses its own
SELECT-only connection (and, in production, its own reader DSN), never the
runtime writer store, and it pages forward with a bounded keyset cursor.  SQL
identifiers are fixed here; every value is a bound parameter.  Query results are
reduced to a small metadata allowlist, so a raw row, DSN or driver error is never
returned.
"""

from __future__ import annotations

import math
import re
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditError
from .export import MAX_EXPORT_ROWS


MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
MAX_REQUEST_ID_LENGTH = 128
MAX_CURSOR = 9_223_372_036_854_775_807
MAX_DSN_LENGTH = 4096

DECISIONS = frozenset({"pending", "allowed", "blocked", "failed", "interrupted"})
EVENT_TYPES = frozenset(
    {
        "request_started",
        "request_completed",
        "request_failed",
        "request_blocked",
        "request_recovered",
    }
)
QUERY_KEYS = frozenset({"limit", "decision", "event_type", "request_id", "after"})
# The export route deliberately has no page-size or cursor surface.  ``limit``
# and ``after`` are rejected as unknown rather than silently ignored, so a caller
# can never receive a page-shaped, truncated export.
EXPORT_QUERY_KEYS = frozenset({"decision", "event_type", "request_id"})

# Only these columns leave the reader.  ``app_id`` is an implicit query scope and
# is not returned; no other event column or record extra is exposed.
EVENT_COLUMNS = (
    "seq",
    "request_id",
    "event_type",
    "timestamp",
    "model",
    "policy_version",
    "policy_digest",
    "decision",
    "error_code",
)

_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_LIMIT = re.compile(r"[1-9][0-9]{0,2}\Z")
_CURSOR = re.compile(r"[1-9][0-9]{0,18}\Z")


class OperatorQueryError(ValueError):
    """A query parameter was outside the bounded operator filter contract."""


@dataclass(frozen=True)
class EventFilters:
    """Validated, bounded event query filters."""

    limit: int = DEFAULT_PAGE_SIZE
    decision: str | None = None
    event_type: str | None = None
    request_id: str | None = None
    after_seq: int | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.limit, bool)
            or not isinstance(self.limit, int)
            or not 1 <= self.limit <= MAX_PAGE_SIZE
        ):
            raise OperatorQueryError("invalid limit")
        if self.decision is not None and self.decision not in DECISIONS:
            raise OperatorQueryError("invalid decision")
        if self.event_type is not None and self.event_type not in EVENT_TYPES:
            raise OperatorQueryError("invalid event_type")
        if self.request_id is not None and _REQUEST_ID.fullmatch(self.request_id) is None:
            raise OperatorQueryError("invalid request_id")
        if self.after_seq is not None and (
            isinstance(self.after_seq, bool)
            or not isinstance(self.after_seq, int)
            or not 1 <= self.after_seq <= MAX_CURSOR
        ):
            raise OperatorQueryError("invalid cursor")


@dataclass(frozen=True)
class ExportFilters:
    """Validated filters for a bounded, unpaginated export snapshot.

    There is intentionally no public limit, cursor or upper-sequence field.  The
    reader applies its own fixed row bound and the server rejects an oversized
    snapshot rather than truncating it.
    """

    decision: str | None = None
    event_type: str | None = None
    request_id: str | None = None

    def __post_init__(self) -> None:
        if self.decision is not None and self.decision not in DECISIONS:
            raise OperatorQueryError("invalid decision")
        if self.event_type is not None and self.event_type not in EVENT_TYPES:
            raise OperatorQueryError("invalid event_type")
        if self.request_id is not None and _REQUEST_ID.fullmatch(self.request_id) is None:
            raise OperatorQueryError("invalid request_id")

    def canonical(self) -> str:
        """Return the canonical, non-secret filter representation for metadata."""
        parts = []
        for name in ("decision", "event_type", "request_id"):
            value = getattr(self, name)
            parts.append(f"{name}={value if value is not None else '*'}")
        return ";".join(parts)


@dataclass(frozen=True)
class EventPage:
    """One forward page of metadata-only events."""

    events: list[dict[str, Any]]
    has_more: bool
    next_cursor: int | None


@dataclass(frozen=True)
class ExportSnapshot:
    """One bounded, sequence-ordered export snapshot."""

    rows: list[dict[str, Any]]
    upper_seq: int


def parse_event_query(items: list[tuple[str, str]]) -> EventFilters:
    """Parse ``request.query_params.multi_items()`` strictly.

    Duplicate and unknown keys are rejected rather than silently collapsed, so a
    caller cannot smuggle a second filter or cursor.  Values are validated to a
    strict length/enum/int shape before any SQL is built.
    """
    values: dict[str, str] = {}
    for key, value in items:
        if key not in QUERY_KEYS or key in values:
            raise OperatorQueryError("invalid query")
        values[key] = value

    limit = DEFAULT_PAGE_SIZE
    if "limit" in values:
        raw_limit = values["limit"]
        if _LIMIT.fullmatch(raw_limit) is None:
            raise OperatorQueryError("invalid limit")
        limit = int(raw_limit, 10)

    decision = values.get("decision")
    if decision is not None and decision not in DECISIONS:
        raise OperatorQueryError("invalid decision")

    event_type = values.get("event_type")
    if event_type is not None and event_type not in EVENT_TYPES:
        raise OperatorQueryError("invalid event_type")

    request_id = values.get("request_id")
    if request_id is not None and _REQUEST_ID.fullmatch(request_id) is None:
        raise OperatorQueryError("invalid request_id")

    after_seq = None
    if "after" in values:
        raw_after = values["after"]
        if _CURSOR.fullmatch(raw_after) is None:
            raise OperatorQueryError("invalid cursor")
        after_seq = int(raw_after, 10)
        if after_seq > MAX_CURSOR:
            raise OperatorQueryError("invalid cursor")

    return EventFilters(
        limit=limit,
        decision=decision,
        event_type=event_type,
        request_id=request_id,
        after_seq=after_seq,
    )


def parse_export_query(items: list[tuple[str, str]]) -> ExportFilters:
    """Parse export query parameters strictly.

    Only the three bounded filter keys are accepted.  Duplicate, unknown,
    ``limit`` and ``after`` keys are all rejected so the export cannot be turned
    into a single-page view or a silently truncated result.
    """
    values: dict[str, str] = {}
    for key, value in items:
        if key not in EXPORT_QUERY_KEYS or key in values:
            raise OperatorQueryError("invalid query")
        values[key] = value

    decision = values.get("decision")
    if decision is not None and decision not in DECISIONS:
        raise OperatorQueryError("invalid decision")

    event_type = values.get("event_type")
    if event_type is not None and event_type not in EVENT_TYPES:
        raise OperatorQueryError("invalid event_type")

    request_id = values.get("request_id")
    if request_id is not None and _REQUEST_ID.fullmatch(request_id) is None:
        raise OperatorQueryError("invalid request_id")

    return ExportFilters(
        decision=decision,
        event_type=event_type,
        request_id=request_id,
    )


def _conditions(
    app_id: str,
    filters: EventFilters | ExportFilters,
    placeholder: str,
) -> tuple[str, list[Any]]:
    clauses = [f"app_id = {placeholder}"]
    params: list[Any] = [app_id]
    if filters.decision is not None:
        clauses.append(f"decision = {placeholder}")
        params.append(filters.decision)
    if filters.event_type is not None:
        clauses.append(f"event_type = {placeholder}")
        params.append(filters.event_type)
    if filters.request_id is not None:
        clauses.append(f"request_id = {placeholder}")
        params.append(filters.request_id)
    after_seq = getattr(filters, "after_seq", None)
    if after_seq is not None:
        clauses.append(f"seq > {placeholder}")
        params.append(after_seq)
    return " AND ".join(clauses), params


def _select_sql(placeholder: str, where: str) -> str:
    return (
        "SELECT seq, request_id, event_type, timestamp, model, "
        "policy_version, policy_digest, decision, error_code "
        f"FROM events WHERE {where} ORDER BY seq ASC LIMIT {placeholder}"
    )


def _page_from_rows(rows: list[dict[str, Any]], limit: int) -> EventPage:
    has_more = len(rows) > limit
    selected = rows[:limit]
    next_cursor = None
    if has_more and selected:
        cursor = selected[-1].get("seq")
        if isinstance(cursor, int) and not isinstance(cursor, bool) and cursor > 0:
            next_cursor = cursor
    return EventPage(events=selected, has_more=has_more, next_cursor=next_cursor)


def _snapshot_from_rows(rows: list[dict[str, Any]]) -> ExportSnapshot:
    upper_seq = 0
    for row in rows:
        seq = row.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool) and seq > upper_seq:
            upper_seq = seq
    return ExportSnapshot(rows=rows, upper_seq=upper_seq)


class AuditEventReader(ABC):
    """Minimal reader boundary used only by the authenticated operator API."""

    @abstractmethod
    def fetch_page(self, app_id: str, filters: EventFilters) -> EventPage:
        """Return at most ``filters.limit`` rows scoped to ``app_id``."""

    @abstractmethod
    def fetch_export(self, app_id: str, filters: ExportFilters) -> ExportSnapshot:
        """Return one bounded, unpaginated snapshot scoped to ``app_id``."""

    @abstractmethod
    def close(self) -> None:
        """Release any long-lived resources."""


class SqliteAuditReader(AuditEventReader):
    """Read-only SQLite reader for local synthetic tests only.

    It opens the existing database with ``mode=ro`` and never creates a schema,
    bootstraps a role, repairs rows or reuses a writer connection.
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

    def _connect(self) -> sqlite3.Connection:
        if not self.path.is_file():
            raise AuditError("audit database unavailable")
        try:
            uri = "file:" + self.path.resolve().as_posix() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=self.connect_timeout)
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA busy_timeout=3000")
            return conn
        except (sqlite3.Error, OSError, ValueError):
            raise AuditError("audit database unavailable") from None

    def fetch_page(self, app_id: str, filters: EventFilters) -> EventPage:
        if not isinstance(app_id, str) or not app_id:
            raise OperatorQueryError("invalid app identity")
        if not isinstance(filters, EventFilters):
            raise OperatorQueryError("invalid filters")
        where, params = _conditions(app_id, filters, "?")
        sql = _select_sql("?", where)
        params.append(filters.limit + 1)
        conn = None
        try:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
            return _page_from_rows(rows, filters.limit)
        except (AuditError, OperatorQueryError):
            raise
        except Exception:
            raise AuditError("audit read unavailable") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def fetch_export(self, app_id: str, filters: ExportFilters) -> ExportSnapshot:
        if not isinstance(app_id, str) or not app_id:
            raise OperatorQueryError("invalid app identity")
        if not isinstance(filters, ExportFilters):
            raise OperatorQueryError("invalid filters")
        where, params = _conditions(app_id, filters, "?")
        sql = _select_sql("?", where)
        params.append(MAX_EXPORT_ROWS + 1)
        conn = None
        try:
            conn = self._connect()
            conn.row_factory = sqlite3.Row
            rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
            return _snapshot_from_rows(rows)
        except (AuditError, OperatorQueryError):
            raise
        except Exception:
            raise AuditError("audit read unavailable") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self) -> None:
        pass


class PostgresAuditReader(AuditEventReader):
    """Production SELECT-only reader using a separate reader DSN.

    ``psycopg`` is imported lazily by the first read.  The connection is
    read-only at the session level, carries a bounded ``statement_timeout`` and
    is closed after every page.  The DSN is private and never appears in a repr or
    raised error.
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
                options=(
                    f"-c statement_timeout={self.statement_timeout_ms} "
                    "-c default_transaction_read_only=on"
                ),
            )
        except Exception:
            raise AuditError("audit database unavailable") from None

    def fetch_page(self, app_id: str, filters: EventFilters) -> EventPage:
        if not isinstance(app_id, str) or not app_id:
            raise OperatorQueryError("invalid app identity")
        if not isinstance(filters, EventFilters):
            raise OperatorQueryError("invalid filters")
        where, params = _conditions(app_id, filters, "%s")
        sql = _select_sql("%s", where)
        params.append(filters.limit + 1)
        conn = None
        try:
            conn = self._connect()
            with conn.cursor() as cur:
                cur.execute(sql, tuple(params))
                columns = [desc[0] for desc in cur.description]
                fetched = cur.fetchall()
                rows = [dict(zip(columns, row)) for row in fetched]
            return _page_from_rows(rows, filters.limit)
        except (AuditError, OperatorQueryError):
            raise
        except Exception:
            raise AuditError("audit read unavailable") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def fetch_export(self, app_id: str, filters: ExportFilters) -> ExportSnapshot:
        if not isinstance(app_id, str) or not app_id:
            raise OperatorQueryError("invalid app identity")
        if not isinstance(filters, ExportFilters):
            raise OperatorQueryError("invalid filters")
        where, params = _conditions(app_id, filters, "%s")
        sql = _select_sql("%s", where)
        params.append(MAX_EXPORT_ROWS + 1)
        conn = None
        try:
            conn = self._connect()
            with conn.cursor() as cur:
                cur.execute(sql, tuple(params))
                columns = [desc[0] for desc in cur.description]
                fetched = cur.fetchall()
                rows = [dict(zip(columns, row)) for row in fetched]
            return _snapshot_from_rows(rows)
        except (AuditError, OperatorQueryError):
            raise
        except Exception:
            raise AuditError("audit read unavailable") from None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self) -> None:
        pass
