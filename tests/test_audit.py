import os
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from nasi_lemak.audit import (
    AuditError,
    PostgresAuditStore,
    SqliteAuditStore,
)


class SqliteAuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def _terminal(self, request_id, event_type, decision, error_code=None):
        self.store.record_terminal(
            request_id,
            event_type,
            decision,
            error_code,
            app_id="app",
            model="pilot-local",
            policy_version="v1",
            policy_digest="digest1",
        )

    def test_records_initial_and_terminal_events(self):
        self.store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self._terminal("r1", "request_completed", "allowed")
        events = self.store.read_events()
        self.assertEqual(
            [e["event_type"] for e in events],
            ["request_started", "request_completed"],
        )
        self.assertEqual(events[0]["policy_digest"], "digest1")
        self.assertEqual(events[1]["policy_digest"], "digest1")
        self.assertEqual(events[1]["app_id"], "app")

    def test_terminal_event_inherits_original_policy_metadata(self):
        self.store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self._terminal("r1", "request_failed", "failed", "UNAVAILABLE")
        events = self.store.read_events()
        terminal = events[-1]
        self.assertEqual(terminal["policy_version"], "v1")
        self.assertEqual(terminal["policy_digest"], "digest1")
        self.assertEqual(terminal["error_code"], "UNAVAILABLE")

    def test_reconcile_preserves_original_policy_metadata(self):
        self.store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self.store.record_initial("r2", "app", "pilot-local", "v2", "digest2")
        self.store.record_terminal(
            "r2",
            "request_completed",
            "allowed",
            app_id="app",
            model="pilot-local",
            policy_version="v2",
            policy_digest="digest2",
        )
        count = self.store.reconcile_incomplete(offline=True)
        self.assertEqual(count, 1)
        events = self.store.read_events()
        recovered = [e for e in events if e["event_type"] == "request_recovered"][0]
        self.assertEqual(recovered["request_id"], "r1")
        self.assertEqual(recovered["policy_version"], "v1")
        self.assertEqual(recovered["policy_digest"], "digest1")
        self.assertEqual(recovered["decision"], "interrupted")

    def test_reconcile_requires_offline_confirmation(self):
        with self.assertRaises(ValueError):
            self.store.reconcile_incomplete()

    def test_ready(self):
        self.assertTrue(self.store.ready())


class FakeCursor:
    """Behavioral DB cursor double.  This is not real PostgreSQL proof."""

    def __init__(self, connection):
        self.connection = connection
        self.rowcount = -1
        self.description = []
        self._fetchall = []
        self._fetchone = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.closed = True
        return False

    def execute(self, sql, params=None):
        normalized = " ".join(sql.split())
        self.connection.statements.append((normalized, params))
        if (
            self.connection.execute_error is not None
            and self.connection.execute_error_match in normalized
        ):
            raise self.connection.execute_error
        if normalized.startswith("INSERT INTO events"):
            self.rowcount = self.connection.insert_rowcount
        elif normalized.startswith("SELECT"):
            self.rowcount = len(self.connection.query_rows)
            self.description = list(self.connection.query_description)
            self._fetchall = list(self.connection.query_rows)
            self._fetchone = self.connection.query_rows[0] if self.connection.query_rows else None

    def fetchall(self):
        return self._fetchall

    def fetchone(self):
        return self._fetchone


class FakeConnection:
    """Behavioral DB connection double.  This is not real PostgreSQL proof."""

    def __init__(
        self,
        *,
        insert_rowcount=1,
        query_rows=(),
        query_description=(),
        execute_error=None,
        execute_error_match="INSERT INTO events",
        fail_commit=False,
        fail_rollback=False,
        fail_close=False,
    ):
        self.insert_rowcount = insert_rowcount
        self.query_rows = list(query_rows)
        self.query_description = list(query_description)
        self.execute_error = execute_error
        self.execute_error_match = execute_error_match
        self.fail_commit = fail_commit
        self.fail_rollback = fail_rollback
        self.fail_close = fail_close
        self.autocommit = False
        self.in_transaction = False
        self.transactions = 0
        self.commits = 0
        self.rollbacks = 0
        self.close_calls = 0
        self.cursor_transaction_flags = []
        self.statements = []

    def cursor(self):
        self.cursor_transaction_flags.append(self.in_transaction)
        return FakeCursor(self)

    @contextmanager
    def transaction(self):
        self.transactions += 1
        self.in_transaction = True
        try:
            yield
        except BaseException:
            self.rollbacks += 1
            self.in_transaction = False
            if self.fail_rollback:
                raise RuntimeError("rollback failed")
            raise
        else:
            self.in_transaction = False
            self.commits += 1
            if self.fail_commit:
                raise RuntimeError("commit failed")

    def close(self):
        self.close_calls += 1
        if self.fail_close:
            raise RuntimeError("close failed")


class RecordingConnector:
    """Records psycopg.connect arguments and returns a supplied double."""

    def __init__(self, connection):
        self.connection = connection
        self.calls = []

    def __call__(self, conninfo, **kwargs):
        self.calls.append((conninfo, kwargs))
        self.connection.autocommit = kwargs.get("autocommit", False)
        return self.connection


class PostgresAuditStoreUnitTests(unittest.TestCase):
    """Unit tests with explicit doubles; they do not prove real PG durability."""

    def _store_and_connector(self, conn, **kwargs):
        connector = RecordingConnector(conn)
        store = PostgresAuditStore("dbname=audit host=db", **kwargs)
        return store, connector

    def test_initial_uses_autocommit_and_one_explicit_transaction_then_commits(self):
        conn = FakeConnection()
        store, connector = self._store_and_connector(
            conn, connect_timeout=7, statement_timeout_seconds=2
        )
        with patch("psycopg.connect", connector):
            store.record_initial("r1", "app", "pilot-local", "v1", "digest1")

        _, kwargs = connector.calls[0]
        self.assertIs(kwargs["autocommit"], True)
        self.assertEqual(kwargs["connect_timeout"], 7)
        self.assertIn("statement_timeout=2000", kwargs["options"])
        self.assertEqual(conn.transactions, 1)
        self.assertEqual(conn.commits, 1)
        self.assertEqual(conn.rollbacks, 0)
        self.assertEqual(conn.close_calls, 1)
        self.assertEqual(conn.cursor_transaction_flags, [True])
        self.assertEqual(len(conn.statements), 1)
        sql, params = conn.statements[0]
        self.assertTrue(sql.startswith("INSERT INTO events"))
        self.assertNotIn("SELECT", sql)
        self.assertNotIn("owners", sql)
        self.assertEqual(params[0], "r1")
        self.assertEqual(params[1], "request_started")
        self.assertEqual(params[7], "pending")

    def test_terminal_appends_trusted_metadata_without_select_or_owner_sql(self):
        conn = FakeConnection()
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            store.record_terminal(
                "r2",
                "request_completed",
                "allowed",
                None,
                app_id="app",
                model="pilot-local",
                policy_version="v1",
                policy_digest="digest1",
            )

        self.assertEqual(conn.commits, 1)
        self.assertEqual(conn.rollbacks, 0)
        self.assertEqual(len(conn.statements), 1)
        sql, params = conn.statements[0]
        self.assertTrue(sql.startswith("INSERT INTO events"))
        self.assertNotIn("SELECT", sql)
        self.assertNotIn("owners", sql)
        self.assertEqual(
            (params[0], params[1], params[3], params[4], params[5], params[6]),
            ("r2", "request_completed", "app", "pilot-local", "v1", "digest1"),
        )
        self.assertEqual(params[7], "allowed")
        self.assertIsNone(params[8])

    def test_terminal_zero_row_write_fails_and_rolls_back(self):
        conn = FakeConnection(insert_rowcount=0)
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            with self.assertRaises(AuditError):
                store.record_terminal(
                    "r2",
                    "request_completed",
                    "allowed",
                    app_id="app",
                    model="pilot-local",
                    policy_version="v1",
                    policy_digest="digest1",
                )
        self.assertEqual(conn.commits, 0)
        self.assertEqual(conn.rollbacks, 1)
        self.assertEqual(conn.close_calls, 1)

    def test_initial_write_failure_rolls_back_and_closes(self):
        conn = FakeConnection(execute_error=RuntimeError("db down"))
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            with self.assertRaises(AuditError) as caught:
                store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self.assertEqual(conn.commits, 0)
        self.assertEqual(conn.rollbacks, 1)
        self.assertEqual(conn.close_calls, 1)
        self.assertNotIn("db down", str(caught.exception))

    def test_commit_failure_fails_closed(self):
        conn = FakeConnection(fail_commit=True)
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            with self.assertRaises(AuditError):
                store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self.assertEqual(conn.commits, 1)
        self.assertEqual(conn.close_calls, 1)

    def test_rollback_failure_fails_closed(self):
        conn = FakeConnection(
            execute_error=RuntimeError("db down"),
            fail_rollback=True,
        )
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            with self.assertRaises(AuditError):
                store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self.assertEqual(conn.commits, 0)
        self.assertEqual(conn.rollbacks, 1)
        self.assertEqual(conn.close_calls, 1)

    def test_close_failure_after_successful_commit_fails_closed(self):
        conn = FakeConnection(fail_close=True)
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            with self.assertRaises(AuditError):
                store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self.assertEqual(conn.commits, 1)
        self.assertEqual(conn.close_calls, 1)

    def test_read_events_returns_column_dicts(self):
        conn = FakeConnection(
            query_rows=[(1, "r1", "request_started")],
            query_description=[("seq",), ("request_id",), ("event_type",)],
        )
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            events = store.read_events()
        self.assertEqual(
            events,
            [{"seq": 1, "request_id": "r1", "event_type": "request_started"}],
        )
        self.assertEqual(conn.transactions, 0)
        self.assertEqual(conn.close_calls, 1)

    def test_ready_verifies_schema_and_append_privilege_without_reading_events(self):
        conn = FakeConnection(query_rows=[(True,)])
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            self.assertTrue(store.ready())
        sql, _ = conn.statements[0]
        self.assertIn("to_regclass('public.events')", sql)
        self.assertIn("has_schema_privilege", sql)
        self.assertIn("has_table_privilege", sql)
        self.assertIn("has_sequence_privilege", sql)
        self.assertNotIn("FROM events", sql)
        self.assertNotIn("INSERT INTO", sql)
        self.assertEqual(conn.close_calls, 1)

    def test_ready_is_false_without_required_append_privilege(self):
        conn = FakeConnection(query_rows=[(False,)])
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            self.assertFalse(store.ready())

    def test_ready_returns_false_when_connect_fails(self):
        store = PostgresAuditStore("dbname=audit")
        with patch("psycopg.connect", side_effect=RuntimeError("unreachable")):
            self.assertFalse(store.ready())

    def test_reconcile_inserts_events_with_selected_source_metadata(self):
        conn = FakeConnection(
            query_rows=[("r1", "app", "pilot-local", "v1", "digest1")]
        )
        store, connector = self._store_and_connector(conn)
        with patch("psycopg.connect", connector):
            self.assertEqual(store.reconcile_incomplete(offline=True), 1)
        self.assertEqual(conn.commits, 1)
        self.assertEqual(conn.rollbacks, 0)
        inserts = [s for s in conn.statements if s[0].startswith("INSERT INTO events")]
        self.assertEqual(len(inserts), 1)
        self.assertNotIn("owners", " ".join(sql for sql, _ in conn.statements))
        params = inserts[0][1]
        self.assertEqual(
            (params[0], params[1], params[3], params[4], params[5], params[6]),
            ("r1", "request_recovered", "app", "pilot-local", "v1", "digest1"),
        )
        self.assertEqual(params[7], "interrupted")
        self.assertEqual(params[8], "UNAVAILABLE")

    def test_reconcile_requires_offline_confirmation(self):
        store = PostgresAuditStore("dbname=audit")
        with self.assertRaises(ValueError):
            store.reconcile_incomplete()

    def test_constructor_rejects_bad_timeouts(self):
        bad_connect = (0, -1, True, 1.5, "5")
        bad_statement = (0, -1, True, float("nan"), float("inf"), "5")
        for value in bad_connect:
            with self.subTest(connect_timeout=value):
                with self.assertRaises(ValueError):
                    PostgresAuditStore("dbname=audit", connect_timeout=value)
        for value in bad_statement:
            with self.subTest(statement_timeout_seconds=value):
                with self.assertRaises(ValueError):
                    PostgresAuditStore(
                        "dbname=audit", statement_timeout_seconds=value
                    )

    def test_dsn_does_not_appear_in_repr_or_errors(self):
        dsn = "postgresql://audit_user:supersecret@db.example/audit"
        store = PostgresAuditStore(dsn)
        self.assertNotIn("supersecret", repr(store))
        self.assertNotIn(dsn, repr(store))
        with patch(
            "psycopg.connect",
            side_effect=RuntimeError(f"connection failed for {dsn}"),
        ):
            with self.assertRaises(AuditError) as caught:
                store.record_initial("r1", "app", "pilot-local", "v1", "digest1")
        self.assertNotIn("supersecret", str(caught.exception))
        self.assertNotIn(dsn, str(caught.exception))
        self.assertNotIn("supersecret", repr(caught.exception))


@unittest.skipUnless(
    os.environ.get("TEST_AUDIT_DSN"),
    "optional PostgreSQL integration skipped: TEST_AUDIT_DSN not set",
)
class PostgresAuditIntegrationTests(unittest.TestCase):
    """Optional live checks; numbering/IDs are filtered to this test's requests."""

    def setUp(self):
        import psycopg

        self.dsn = os.environ["TEST_AUDIT_DSN"]
        conn = psycopg.connect(self.dsn)
        try:
            schema = Path("nasi_lemak/audit_schema.sql").read_text(encoding="utf-8")
            with conn.cursor() as cur:
                for statement in schema.split(";"):
                    if statement.strip():
                        cur.execute(statement)
            conn.commit()
        finally:
            conn.close()
        self.store = PostgresAuditStore(self.dsn)

    def test_round_trip_filters_own_request_ids(self):
        rid = "req_" + uuid.uuid4().hex
        self.store.record_initial(rid, "int-app", "pilot-local", "v1", "digest1")
        self.store.record_terminal(
            rid,
            "request_completed",
            "allowed",
            app_id="int-app",
            model="pilot-local",
            policy_version="v1",
            policy_digest="digest1",
        )
        events = [e for e in self.store.read_events() if e["request_id"] == rid]
        self.assertEqual(
            [e["event_type"] for e in events],
            ["request_started", "request_completed"],
        )
        self.assertEqual(events[1]["policy_version"], "v1")
        self.assertEqual(events[1]["policy_digest"], "digest1")

    def test_offline_reconcile_preserves_source_metadata_when_disposable(self):
        if os.environ.get("TEST_AUDIT_DISPOSABLE") != "1":
            self.skipTest(
                "destructive offline reconciliation requires a dedicated disposable "
                "local database and TEST_AUDIT_DISPOSABLE=1"
            )
        completed = "req_" + uuid.uuid4().hex
        self.store.record_initial(completed, "int-app", "pilot-local", "v1", "digest1")
        self.store.record_terminal(
            completed,
            "request_completed",
            "allowed",
            app_id="int-app",
            model="pilot-local",
            policy_version="v1",
            policy_digest="digest1",
        )
        orphan = "req_" + uuid.uuid4().hex
        self.store.record_initial(orphan, "int-app", "pilot-local", "v2", "digest2")

        count = self.store.reconcile_incomplete(offline=True)
        self.assertGreaterEqual(count, 1)

        own = {
            e["request_id"]: e
            for e in self.store.read_events()
            if e["request_id"] in (completed, orphan)
        }
        self.assertEqual(own[completed]["event_type"], "request_completed")
        self.assertEqual(own[orphan]["event_type"], "request_recovered")
        self.assertEqual(own[orphan]["policy_version"], "v2")
        self.assertEqual(own[orphan]["policy_digest"], "digest2")
        recovered_ids = [
            request_id
            for request_id, event in own.items()
            if event["event_type"] == "request_recovered"
        ]
        self.assertEqual(recovered_ids, [orphan])


if __name__ == "__main__":
    unittest.main()
