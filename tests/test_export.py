"""Bounded CSV export backend tests.

Real SQLite audit rows and the actual ASGI application are used for the HTTP
contract.  PostgreSQL SQL, transaction shape and DSN handling are checked with a
driver double only; that is not PostgreSQL server evidence.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.export import (
    CSV_COLUMNS,
    MAX_EXPORT_BYTES,
    MAX_EXPORT_ROWS,
    ExportAuditEntry,
    ExportAuditError,
    PostgresExportAuditLog,
    SqliteExportAuditLog,
    build_export_csv,
    neutralize_cell,
)
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.operator import (
    ExportFilters,
    PostgresAuditReader,
    SqliteAuditReader,
)
from nasi_lemak.server import make_app

APP_KEY = "synthetic-chat-key"
OPERATOR_KEY = "synthetic-operator-key"
OPERATOR_DIGEST = hashlib.sha256(OPERATOR_KEY.encode()).hexdigest()
POLICY = Policy(
    app_id="synthetic-app",
    version="synthetic-2026-10-20.1",
    model="pilot-local",
    token_budget=256,
)
OTHER_APP = "other-app-sentinel"
EXPORT_PATH = "/admin/export.csv"

_EVENT_TYPES = (
    ("request_started", "pending", None),
    ("request_completed", "allowed", None),
    ("request_blocked", "blocked", "POLICY_BLOCK"),
    ("request_failed", "failed", "UNAVAILABLE"),
    ("request_recovered", "interrupted", "UNAVAILABLE"),
)

_INSERT_SQL = """
    INSERT INTO events(
        request_id, event_type, timestamp, app_id, model,
        policy_version, policy_digest, decision, error_code
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _record(
    request_id,
    event_type,
    decision,
    app_id=POLICY.app_id,
    model="pilot-local",
    version=POLICY.version,
    digest=None,
    error_code=None,
    timestamp=1.0,
):
    return (
        request_id,
        event_type,
        timestamp,
        app_id,
        model,
        version,
        digest if digest is not None else hashlib.sha256(version.encode()).hexdigest(),
        decision,
        error_code,
    )


def _insert_events(path, records):
    """Insert with one explicit transaction and a guaranteed close."""
    with closing(sqlite3.connect(str(path))) as db:
        try:
            db.execute("BEGIN")
            db.executemany(_INSERT_SQL, records)
            db.commit()
        except BaseException:
            db.rollback()
            raise


def _insert_event(path, **kwargs):
    _insert_events(path, [_record(**kwargs)])


def _export_rows(path):
    if not Path(path).is_file():
        return []
    with closing(sqlite3.connect(str(path))) as db:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM export_audits ORDER BY id")]


def _parse_csv(response):
    return list(csv.reader(io.StringIO(response.text)))


class _Adapters:
    def count_tokens(self, text):
        return max(1, len(text.split()))

    def scan_attack(self, text):
        return {"decision": "allow"}

    def generate(self, messages, model, max_tokens):
        return "Synthetic answer."

    def scan_output(self, text):
        return {"safe": True}


class _ObservingExportLog(SqliteExportAuditLog):
    """Persist through the real writer and prove the row exists on return."""

    def __init__(self, path):
        super().__init__(path)
        self.entries = []
        self.row_present_on_return = False

    def record(self, entry):
        super().record(entry)
        rows = _export_rows(self.path)
        self.row_present_on_return = any(
            row["export_id"] == entry.export_id for row in rows
        )
        self.entries.append(entry)


class _SpyReader:
    def __init__(self):
        self.page_calls = 0
        self.export_calls = 0

    def fetch_page(self, app_id, filters):
        self.page_calls += 1
        return None

    def fetch_export(self, app_id, filters):
        self.export_calls += 1
        return None

    def close(self):
        pass


class _SpyLog:
    def __init__(self):
        self.entries = []

    def record(self, entry):
        self.entries.append(entry)

    def close(self):
        pass


class _FailingExportReader:
    def __init__(self):
        self.export_calls = 0

    def fetch_page(self, app_id, filters):
        raise RuntimeError("SECRET_DSN postgresql://reader:password@db.internal/x")

    def fetch_export(self, app_id, filters):
        self.export_calls += 1
        raise RuntimeError("SECRET_DSN postgresql://reader:password@db.internal/x")

    def close(self):
        pass


class _PageOnlyReader:
    def fetch_page(self, app_id, filters):
        return None

    def close(self):
        pass


class ExportContentBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "audit.sqlite3"
        self.export_path = Path(self.tmp.name) / "export-audit.sqlite3"
        self.store = SqliteAuditStore(self.db_path)
        self.gateway = Gateway(
            app_key=APP_KEY,
            audit_store=self.store,
            adapters=_Adapters(),
            policy=POLICY,
            app_id=POLICY.app_id,
        )
        self.reader = SqliteAuditReader(self.db_path)
        self.log = _ObservingExportLog(self.export_path)
        self.app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=self.reader,
            export_log=self.log,
        )
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

    def auth(self):
        return {"Authorization": "Bearer " + OPERATOR_KEY}

    def export(self, query="", headers=None):
        url = EXPORT_PATH + (("?" + query) if query else "")
        return self.client.get(url, headers=self.auth() if headers is None else headers)

    def seed_cycles(self, cycles=11):
        records = []
        for cycle in range(cycles):
            version = f"historical-2026-10-{cycle % 3 + 1}.1"
            for index, (event_type, decision, error_code) in enumerate(_EVENT_TYPES):
                records.append(
                    _record(
                        f"req_{cycle:02d}_{index}",
                        event_type,
                        decision,
                        version=version,
                        error_code=error_code,
                        timestamp=float(cycle * 5 + index + 1),
                    )
                )
        records.append(_record("req_other_1", "request_started", "pending", app_id=OTHER_APP))
        records.append(_record("req_other_2", "request_completed", "allowed", app_id=OTHER_APP))
        _insert_events(self.db_path, records)
        return [record for record in records if record[3] == POLICY.app_id]


class ExportContentTests(ExportContentBase):
    def test_full_filtered_snapshot_reconciles_with_csv_and_audit(self):
        expected = self.seed_cycles()
        response = self.export()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["content-type"], "text/csv; charset=utf-8")
        self.assertEqual(
            response.headers["content-disposition"],
            'attachment; filename="nasi-lemak-events-export.csv"',
        )
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertLessEqual(len(response.content), MAX_EXPORT_BYTES)
        self.assertEqual(response.headers["x-export-row-count"], str(len(expected)))
        self.assertRegex(response.headers["x-export-id"], r"\Aexp_[0-9a-f]{32}\Z")
        self.assertEqual(
            response.headers["x-export-sha256"],
            hashlib.sha256(response.content).hexdigest(),
        )

        parsed = _parse_csv(response)
        self.assertEqual(parsed[0], list(CSV_COLUMNS))
        self.assertEqual(len(parsed) - 1, len(expected))
        self.assertGreater(len(expected), 50)
        body = parsed[1:]
        self.assertTrue(all(len(row) == 13 for row in body))

        expected_seqs = list(range(1, len(expected) + 1))  # sequence assigned by SQLite
        self.assertEqual([int(row[0]) for row in body], expected_seqs)
        self.assertEqual(
            {row[2] for row in body},
            {event_type for event_type, _, _ in _EVENT_TYPES},
        )
        self.assertEqual({row[4] for row in body}, {"pilot-local"})
        self.assertEqual(
            {row[5] for row in body},
            {record[5] for record in expected},
        )
        for csv_row, record in zip(body, expected):
            self.assertEqual(csv_row[5], record[5])
            self.assertEqual(csv_row[6], record[6])
            self.assertEqual(csv_row[9], POLICY.app_id)
        self.assertNotIn(OTHER_APP, response.text)
        self.assertNotIn("req_other_", response.text)
        self.assertNotIn(APP_KEY, response.text)
        self.assertNotIn(OPERATOR_KEY, response.text)

        self.assertTrue(self.log.row_present_on_return)
        self.assertEqual(len(self.log.entries), 1)
        audit = _export_rows(self.export_path)
        self.assertEqual(len(audit), 1)
        saved = audit[0]
        self.assertEqual(saved["sha256"], hashlib.sha256(response.content).hexdigest())
        self.assertEqual(saved["row_count"], len(body))
        self.assertEqual(saved["filters"], "decision=*;event_type=*;request_id=*")
        self.assertEqual(saved["policy_version"], POLICY.version)
        self.assertEqual(saved["policy_digest"], POLICY.digest)
        self.assertEqual(saved["app_id"], POLICY.app_id)
        self.assertEqual(saved["upper_seq"], max(expected_seqs))
        self.assertEqual(self.log.entries[0].sha256, saved["sha256"])

    def test_all_three_filters_are_canonical_and_audited(self):
        self.seed_cycles(cycles=3)
        response = self.export(
            "decision=blocked&event_type=request_blocked&request_id=req_01_2"
        )
        self.assertEqual(response.status_code, 200, response.text)
        parsed = _parse_csv(response)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[1][1], "req_01_2")
        self.assertEqual(parsed[1][2], "request_blocked")
        self.assertEqual(parsed[1][7], "blocked")

        audit = _export_rows(self.export_path)
        self.assertEqual(len(audit), 1)
        self.assertEqual(
            audit[0]["filters"],
            "decision=blocked;event_type=request_blocked;request_id=req_01_2",
        )

        only_decision = self.export("decision=blocked")
        self.assertEqual(only_decision.status_code, 200)
        self.assertEqual(len(_parse_csv(only_decision)) - 1, 3)
        only_type = self.export("event_type=request_completed")
        self.assertEqual(len(_parse_csv(only_type)) - 1, 3)
        only_request = self.export("request_id=req_02_3")
        self.assertEqual(len(_parse_csv(only_request)) - 1, 1)
        self.assertEqual(
            _export_rows(self.export_path)[-1]["filters"],
            "decision=*;event_type=*;request_id=req_02_3",
        )

    def test_empty_result_is_header_only_and_audited(self):
        self.seed_cycles(cycles=1)
        response = self.export("request_id=req_absent")
        self.assertEqual(response.status_code, 200, response.text)
        lines = response.text.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0], ",".join(CSV_COLUMNS))
        self.assertEqual(response.headers["content-type"], "text/csv; charset=utf-8")
        self.assertEqual(response.headers["x-export-row-count"], "0")
        self.assertRegex(response.headers["x-export-id"], r"\Aexp_[0-9a-f]{32}\Z")

        audit = _export_rows(self.export_path)
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["row_count"], 0)
        self.assertEqual(audit[0]["upper_seq"], 0)
        self.assertEqual(audit[0]["sha256"], hashlib.sha256(response.content).hexdigest())
        self.assertEqual(
            audit[0]["filters"], "decision=*;event_type=*;request_id=req_absent"
        )

    def test_formula_and_text_cells_are_neutralized_without_db_mutation(self):
        dangerous = [
            "=SUM(A1:A2)",
            "+1+2",
            "-1",
            "@SUM(A1)",
            "  =cmd",
            "\t=cmd",
            "\r=cmd",
            "\n=cmd",
            "\x01=cmd",
        ]
        safe_text = 'He said "hello",\r\nsecond line'
        dangerous_text = '=cmd,"quoted"\r\nnext'
        records = []
        for index, value in enumerate(dangerous):
            records.append(
                _record(f"req_formula_{index}", "request_started", "pending", version=value)
            )
        records.append(_record("req_text", "request_started", "pending", version=safe_text))
        records.append(
            _record("req_text_formula", "request_started", "pending", version=dangerous_text)
        )
        records.append(_record("req_apostrophe", "request_started", "pending", version="'=already"))
        _insert_events(self.db_path, records)

        response = self.export()
        self.assertEqual(response.status_code, 200, response.text)
        parsed = _parse_csv(response)[1:]
        self.assertEqual([row[5] for row in parsed[: len(dangerous)]], ["'" + v for v in dangerous])
        self.assertEqual(parsed[len(dangerous)][5], safe_text)
        self.assertEqual(parsed[len(dangerous) + 1][5], "'" + dangerous_text)
        self.assertEqual(parsed[len(dangerous) + 2][5], "'=already")

        stored = self.store.read_events()
        self.assertEqual([row["policy_version"] for row in stored], [record[5] for record in records])

    def test_exactly_1000_rows_is_allowed(self):
        _insert_events(
            self.db_path,
            [
                _record(f"req_bulk_{index:04d}", "request_started", "pending")
                for index in range(MAX_EXPORT_ROWS)
            ],
        )
        response = self.export()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(_parse_csv(response)) - 1, MAX_EXPORT_ROWS)
        self.assertEqual(_export_rows(self.export_path)[0]["row_count"], MAX_EXPORT_ROWS)

    def test_1001_rows_is_413_without_csv_or_audit(self):
        _insert_events(
            self.db_path,
            [
                _record(f"req_bulk_{index:04d}", "request_started", "pending")
                for index in range(MAX_EXPORT_ROWS + 1)
            ],
        )
        response = self.export()
        self.assertEqual(response.status_code, 413, response.text)
        self.assertEqual(response.headers["content-type"].split(";")[0], "application/json")
        self.assertNotIn("content-disposition", response.headers)
        self.assertNotIn("seq,request_id", response.text)
        self.assertEqual(_export_rows(self.export_path), [])

    def test_byte_cap_is_413_without_csv_or_audit(self):
        _insert_events(
            self.db_path,
            [
                _record(
                    f"req_bulk_{index:04d}",
                    "request_started",
                    "pending",
                    version="x" * 2200,
                )
                for index in range(MAX_EXPORT_ROWS)
            ],
        )
        response = self.export()
        self.assertEqual(response.status_code, 413, response.text)
        self.assertEqual(response.headers["content-type"].split(";")[0], "application/json")
        self.assertNotIn("content-disposition", response.headers)
        self.assertEqual(_export_rows(self.export_path), [])

    def test_success_control_still_works_after_boundary_failures(self):
        self.seed_cycles(cycles=1)
        self.assertEqual(self.export("limit=1").status_code, 400)
        self.assertEqual(self.export("request_id=" + "x" * 129).status_code, 400)
        response = self.export("decision=allowed")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(_parse_csv(response)) - 1, 1)


class ExportAuthorizationAndFailureTests(ExportContentBase):
    def test_auth_and_duplicate_headers_never_read_or_audit(self):
        reader = _SpyReader()
        log = _SpyLog()
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=reader,
            export_log=log,
        )
        cases = [
            {},
            {"Authorization": "Bearer wrong"},
            {"Authorization": "Bearer " + APP_KEY},
            {"Authorization": OPERATOR_KEY},
            [
                ("Authorization", "Bearer " + OPERATOR_KEY),
                ("Authorization", "Bearer " + OPERATOR_KEY),
            ],
        ]
        with TestClient(app) as client:
            for headers in cases:
                with self.subTest(headers=headers):
                    response = client.get(EXPORT_PATH, headers=headers)
                    self.assertEqual(response.status_code, 401)
                    self.assertEqual(response.json()["error"]["code"], "UNAUTHORIZED")
                    self.assertNotIn("content-disposition", response.headers)
        self.assertEqual(reader.page_calls, 0)
        self.assertEqual(reader.export_calls, 0)
        self.assertEqual(log.entries, [])

    def test_invalid_export_query_is_400_without_read_or_audit(self):
        reader = _SpyReader()
        log = _SpyLog()
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=reader,
            export_log=log,
        )
        cases = [
            "unknown=1",
            "decision=allowed&decision=blocked",
            "limit=1",
            "after=1",
            "decision=DROP%20TABLE",
            "event_type=%3Cscript%3E",
            "request_id=req%27%20OR%201%3D1",
            "request_id=" + "x" * 129,
        ]
        with TestClient(app) as client:
            for query in cases:
                with self.subTest(query=query):
                    response = client.get(EXPORT_PATH + "?" + query, headers=self.auth())
                    self.assertEqual(response.status_code, 400, query)
                    self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
                    self.assertNotIn("content-disposition", response.headers)
        self.assertEqual(reader.export_calls, 0)
        self.assertEqual(log.entries, [])

    def test_partial_disabled_and_missing_writer_states_are_safe(self):
        disabled = make_app(gateway=self.gateway, environ={})
        with TestClient(disabled) as client:
            response = client.get(EXPORT_PATH, headers=self.auth())
            self.assertEqual(response.status_code, 404)
            self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")

        partial = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
        )
        with TestClient(partial) as client:
            response = client.get(EXPORT_PATH, headers=self.auth())
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")

        no_writer = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=self.reader,
        )
        with TestClient(no_writer) as client:
            response = client.get(EXPORT_PATH, headers=self.auth())
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("content-disposition", response.headers)

        no_export_method = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=_PageOnlyReader(),
            export_log=self.log,
        )
        with TestClient(no_export_method) as client:
            response = client.get(EXPORT_PATH, headers=self.auth())
            self.assertEqual(response.status_code, 503)
        self.assertEqual(_export_rows(self.export_path), [])

    def test_reader_error_is_generic_503_without_csv_or_audit(self):
        reader = _FailingExportReader()
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=reader,
            export_log=self.log,
        )
        with TestClient(app) as client:
            response = client.get(EXPORT_PATH, headers=self.auth())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("content-disposition", response.headers)
        self.assertNotIn("SECRET", response.text)
        self.assertNotIn("postgresql", response.text)
        self.assertEqual(reader.export_calls, 1)
        self.assertEqual(_export_rows(self.export_path), [])

    def test_real_read_only_sqlite_insert_failure_is_503_without_csv(self):
        self.seed_cycles(cycles=1)
        self.log._connection = lambda: sqlite3.connect(
            "file:" + self.export_path.resolve().as_posix() + "?mode=ro",
            uri=True,
        )
        response = self.export()
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("content-disposition", response.headers)
        self.assertNotIn("readonly", response.text.lower())
        self.assertEqual(_export_rows(self.export_path), [])

    def test_real_sqlite_commit_failure_is_503_without_csv(self):
        self.seed_cycles(cycles=1)
        base = self.log._connection

        class _CommitFailureConnection:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, *args, **kwargs):
                return self._conn.execute(*args, **kwargs)

            def commit(self):
                raise sqlite3.OperationalError("synthetic commit failure")

            def rollback(self):
                return self._conn.rollback()

            def close(self):
                return self._conn.close()

        self.log._connection = lambda: _CommitFailureConnection(base())
        response = self.export()
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("content-disposition", response.headers)
        self.assertEqual(_export_rows(self.export_path), [])

    def test_invalid_startup_policy_does_not_write_blank_policy_audit(self):
        # No injected gateway/policy: the environment has no policy file, so the
        # app is intentionally not ready.  The operator/export seams still exist,
        # but export must fail closed instead of recording blank policy metadata.
        app = make_app(
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=self.reader,
            export_log=self.log,
            environ={},
        )
        with TestClient(app) as client:
            response = client.get(EXPORT_PATH, headers=self.auth())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("content-disposition", response.headers)
        self.assertEqual(_export_rows(self.export_path), [])


class ExportEntryValidationTests(unittest.TestCase):
    def _entry(self, **overrides):
        values = dict(
            export_id="exp_1",
            app_id="synthetic-app",
            created_at=1.0,
            filters="decision=*;event_type=*;request_id=*",
            row_count=0,
            sha256="a" * 64,
            policy_version="v1",
            policy_digest="b" * 64,
            upper_seq=0,
        )
        values.update(overrides)
        return ExportAuditEntry(**values)

    def test_policy_metadata_is_typed(self):
        self.assertEqual(self._entry().policy_version, "v1")
        for bad in ("", None, 1):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    self._entry(policy_version=bad)
        for bad in ("", "x" * 63, "x" * 64, "A" * 64, "g" * 64, None, 1):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    self._entry(policy_digest=bad)

    def test_formula_neutralization_is_strict_and_idempotent_after_apostrophe(self):
        for value in (
            "=1",
            "+1",
            "-1",
            "@x",
            " =1",
            "\t=1",
            "\r=1",
            "\n=1",
            "\x01=1",
            "\u00a0=1+1",
            "\u2003@SUM(1)",
        ):
            with self.subTest(value=value):
                self.assertEqual(neutralize_cell(value), "'" + value)
        self.assertEqual(neutralize_cell("'=1"), "'=1")
        self.assertEqual(neutralize_cell("plain"), "plain")
        self.assertEqual(neutralize_cell("plain \u00e9clair"), "plain \u00e9clair")
        self.assertEqual(neutralize_cell("'\u00a0=1"), "'\u00a0=1")
        self.assertEqual(neutralize_cell(None), "")

    def test_build_export_csv_rejects_oversize_before_completion(self):
        rows = [
            {
                "seq": index + 1,
                "request_id": f"req_{index}",
                "event_type": "request_started",
                "timestamp": 1.0,
                "model": "pilot-local",
                "policy_version": "x" * 2200,
                "policy_digest": "d" * 64,
                "decision": "pending",
                "error_code": None,
            }
            for index in range(MAX_EXPORT_ROWS)
        ]
        with self.assertRaises(Exception) as caught:
            build_export_csv(
                rows,
                app_id=POLICY.app_id,
                export_id="exp_1",
                created_utc="2026-10-20T00:00:00Z",
                filters="decision=*;event_type=*;request_id=*",
            )
        self.assertEqual(type(caught.exception).__name__, "ExportTooLarge")


class PostgresExportReaderSqlTests(unittest.TestCase):
    def test_export_read_is_one_bounded_app_scoped_select(self):
        rows = [
            (1, "req_a", "request_started", 1.0, "pilot-local", "v1", "d" * 64, "pending", None),
            (2, "req_a", "request_blocked", 2.0, "pilot-local", "v1", "d" * 64, "blocked", "POLICY_BLOCK"),
            (3, "req_b", "request_blocked", 3.0, "pilot-local", "v1", "d" * 64, "blocked", "POLICY_BLOCK"),
        ]
        description = [
            (name,)
            for name in (
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
        ]

        class FakeCursor:
            def __init__(self):
                self.executions = []
                self.description = description

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params):
                self.executions.append((sql, params))

            def fetchall(self):
                return rows

        class FakeConnection:
            def __init__(self, cursor):
                self._cursor = cursor
                self.closed = False

            def cursor(self):
                return self._cursor

            def close(self):
                self.closed = True

        class FakePsycopg:
            def __init__(self):
                self.cursor = FakeCursor()
                self.connection = FakeConnection(self.cursor)
                self.connect_kwargs = None

            def connect(self, conninfo, **kwargs):
                self.connect_kwargs = kwargs
                return self.connection

        fake = FakePsycopg()
        reader = PostgresAuditReader("postgresql://reader:secret@db/nasi_lemak")
        reader._psycopg = fake
        snapshot = reader.fetch_export(
            "synthetic-app",
            ExportFilters(
                decision="blocked",
                event_type="request_blocked",
                request_id="req_a",
            ),
        )

        self.assertEqual(len(snapshot.rows), 3)
        self.assertEqual(snapshot.upper_seq, 3)
        self.assertEqual(len(fake.cursor.executions), 1)
        sql, params = fake.cursor.executions[0]
        self.assertTrue(sql.strip().startswith("SELECT seq, request_id"))
        self.assertIn("FROM events WHERE app_id = %s", sql)
        self.assertIn("decision = %s", sql)
        self.assertIn("event_type = %s", sql)
        self.assertIn("request_id = %s", sql)
        self.assertIn("ORDER BY seq ASC LIMIT %s", sql)
        self.assertNotIn("LIMIT 1001", sql)
        self.assertNotIn("SELECT *", sql)
        self.assertNotIn("req_a", sql)
        self.assertEqual(
            params,
            ("synthetic-app", "blocked", "request_blocked", "req_a", MAX_EXPORT_ROWS + 1),
        )
        self.assertIs(fake.connect_kwargs["autocommit"], True)
        self.assertIn("statement_timeout", fake.connect_kwargs["options"])
        self.assertIn("default_transaction_read_only=on", fake.connect_kwargs["options"])
        self.assertTrue(fake.connection.closed)
        self.assertNotIn("secret", repr(reader))
        self.assertNotIn("postgresql://", repr(reader))


class _FakeWriteCursor:
    def __init__(self):
        self.executions = []
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params):
        self.executions.append((sql, params))


class _FakeTransaction:
    def __init__(self, connection, fail=False):
        self.connection = connection
        self.fail = fail

    def __enter__(self):
        self.connection.transactions += 1
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.connection.rollbacks += 1
            return False
        if self.fail:
            raise RuntimeError("SECRET_DSN postgresql://writer:password@db.internal/x")
        self.connection.commits += 1
        return False


class _FakeWriteConnection:
    def __init__(self, fail=False):
        self.cursor_obj = _FakeWriteCursor()
        self.fail = fail
        self.transactions = 0
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def transaction(self):
        return _FakeTransaction(self, fail=self.fail)

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


class _FakeWritePsycopg:
    def __init__(self, fail=False):
        self.connection = _FakeWriteConnection(fail=fail)
        self.connect_kwargs = None

    def connect(self, conninfo, **kwargs):
        self.connect_kwargs = kwargs
        return self.connection


def _valid_entry():
    return ExportAuditEntry(
        export_id="exp_1",
        app_id="synthetic-app",
        created_at=1.0,
        filters="decision=*;event_type=*;request_id=*",
        row_count=2,
        sha256="a" * 64,
        policy_version="v1",
        policy_digest="b" * 64,
        upper_seq=2,
    )


class PostgresExportWriterTests(unittest.TestCase):
    def test_writer_is_insert_only_in_one_transaction(self):
        fake = _FakeWritePsycopg()
        log = PostgresExportAuditLog("postgresql://writer:secret@db/nasi_lemak")
        log._psycopg = fake
        entry = _valid_entry()
        log.record(entry)

        executions = fake.connection.cursor_obj.executions
        self.assertEqual(len(executions), 1)
        sql, params = executions[0]
        self.assertTrue(sql.strip().upper().startswith("INSERT INTO EXPORT_AUDITS"))
        self.assertNotIn("SELECT", sql.upper())
        self.assertNotIn("UPDATE", sql.upper())
        self.assertNotIn("DELETE", sql.upper())
        self.assertEqual(
            params,
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
        self.assertEqual(fake.connection.transactions, 1)
        self.assertEqual(fake.connection.commits, 1)
        self.assertEqual(fake.connection.rollbacks, 0)
        self.assertTrue(fake.connection.closed)
        self.assertIs(fake.connect_kwargs["autocommit"], True)
        self.assertIn("statement_timeout", fake.connect_kwargs["options"])
        self.assertNotIn("secret", repr(log))
        self.assertNotIn("postgresql://", repr(log))

    def test_commit_failure_is_generic_and_closes(self):
        fake = _FakeWritePsycopg(fail=True)
        log = PostgresExportAuditLog("postgresql://writer:secret@db/nasi_lemak")
        log._psycopg = fake
        with self.assertRaises(ExportAuditError) as caught:
            log.record(_valid_entry())
        message = str(caught.exception)
        self.assertEqual(message, "export audit write failed")
        self.assertNotIn("SECRET", message)
        self.assertNotIn("postgresql", message)
        self.assertEqual(fake.connection.transactions, 1)
        self.assertEqual(fake.connection.commits, 0)
        self.assertTrue(fake.connection.closed)

    def test_constructor_rejects_bad_dsn_without_echo(self):
        with self.assertRaises(ValueError) as caught:
            PostgresExportAuditLog("")
        self.assertNotIn("secret", str(caught.exception))

    def test_static_sql_grants_keep_reader_out_of_export_audits(self):
        root = Path(__file__).resolve().parents[1]
        schema = (root / "nasi_lemak" / "audit_schema.sql").read_text(encoding="utf-8")
        roles = (root / "nasi_lemak" / "audit_roles.sql").read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS export_audits", schema)
        self.assertIn(
            "GRANT INSERT ON TABLE public.export_audits TO nasi_lemak_audit_writer",
            roles,
        )
        self.assertEqual(
            len(re.findall(r"GRANT\s+INSERT\s+ON\s+TABLE\s+public\.export_audits", roles, re.I)),
            1,
        )
        self.assertIsNone(
            re.search(
                r"GRANT\s+(SELECT|UPDATE|DELETE|ALL)[^;]*public\.export_audits",
                roles,
                re.I,
            )
        )
        self.assertIn(
            "GRANT SELECT ON TABLE public.events TO nasi_lemak_audit_reader", roles
        )


if __name__ == "__main__":
    unittest.main()
