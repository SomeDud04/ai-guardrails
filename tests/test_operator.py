"""Operator event API and local HTML shell tests.

Real SQLite audit data and the actual ASGI app are used.  PostgreSQL SQL and
parameter construction is checked with a driver double only; that is not
PostgreSQL server evidence.
"""

from __future__ import annotations

import base64
import hashlib
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.operator import (
    EventFilters,
    EventPage,
    OperatorQueryError,
    PostgresAuditReader,
    SqliteAuditReader,
    parse_event_query,
)
from nasi_lemak.server import _resolve_operator, make_app

APP_KEY = "synthetic-chat-key"
OPERATOR_KEY = "synthetic-operator-key"
OPERATOR_DIGEST = hashlib.sha256(OPERATOR_KEY.encode()).hexdigest()
CHAT_DIGEST = hashlib.sha256(APP_KEY.encode()).hexdigest()
POLICY = Policy(
    app_id="synthetic-app",
    version="synthetic-2026-10-20.1",
    model="pilot-local",
    token_budget=256,
)
OTHER_SENTINEL = "other-app-sentinel"


class _Adapters:
    def count_tokens(self, text):
        return max(1, len(text.split()))

    def scan_attack(self, text):
        return {"decision": "allow"}

    def generate(self, messages, model, max_tokens):
        return "Synthetic answer."

    def scan_output(self, text):
        return {"safe": True}


class _SpyReader:
    def __init__(self):
        self.calls = []

    def fetch_page(self, app_id, filters):
        self.calls.append((app_id, filters))
        return EventPage(events=[], has_more=False, next_cursor=None)

    def close(self):
        pass


class _FailingReader:
    def fetch_page(self, app_id, filters):
        raise RuntimeError("SECRET_DSN postgresql://reader:password@db.internal/x")

    def close(self):
        pass


class _ClosingReader(_SpyReader):
    def __init__(self):
        super().__init__()
        self.closed = False

    def close(self):
        self.closed = True


def _insert_event(path, *, request_id, event_type, decision, app_id, model="pilot-local",
                  version="synthetic-2026-10-20.1", digest="d" * 64, error_code=None):
    # ``sqlite3.Connection`` used as a context manager commits/rolls back but
    # deliberately does not close the handle.  ``closing`` guarantees the close
    # so a Windows temporary-directory cleanup cannot hit a shared violation.
    with closing(sqlite3.connect(str(path))) as db:
        try:
            db.execute("BEGIN")
            db.execute(
                """
                INSERT INTO events(
                    request_id, event_type, timestamp, app_id, model,
                    policy_version, policy_digest, decision, error_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (request_id, event_type, 1.0, app_id, model, version, digest, decision, error_code),
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise


class OperatorTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "audit.sqlite3"
        self.store = SqliteAuditStore(self.db_path)
        self.gateway = Gateway(
            app_key=APP_KEY,
            audit_store=self.store,
            adapters=_Adapters(),
            policy=POLICY,
            app_id=POLICY.app_id,
        )
        self.reader = SqliteAuditReader(self.db_path)
        self.app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=self.reader,
        )
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

    def seed(self):
        for request_id, event_type, decision, code in (
            ("req_one", "request_started", "pending", None),
            ("req_one", "request_completed", "allowed", None),
            ("req_two", "request_started", "pending", None),
        ):
            if event_type == "request_started":
                self.store.record_initial(
                    request_id,
                    POLICY.app_id,
                    POLICY.model,
                    POLICY.version,
                    POLICY.digest,
                )
            else:
                self.store.record_terminal(
                    request_id,
                    event_type,
                    decision,
                    code,
                    app_id=POLICY.app_id,
                    model=POLICY.model,
                    policy_version=POLICY.version,
                    policy_digest=POLICY.digest,
                )
        _insert_event(
            self.db_path,
            request_id="req_other",
            event_type="request_started",
            decision="pending",
            app_id=OTHER_SENTINEL,
        )

    def events(self, **params):
        return self.client.get(
            "/admin/events",
            headers={"Authorization": "Bearer " + OPERATOR_KEY},
            params=params,
        )

    def auth(self):
        return {"Authorization": "Bearer " + OPERATOR_KEY}


class EffectiveLimitsAdminTests(OperatorTestBase):
    def test_admin_shows_effective_ceiling_and_source_read_only(self) -> None:
        policy = Policy(
            app_id=POLICY.app_id,
            version=POLICY.version,
            model=POLICY.model,
            token_budget=POLICY.token_budget,
            limits={"default_reply_tokens": 384, "max_reply_tokens": 512},
        )
        gateway = Gateway(
            app_key=APP_KEY,
            audit_store=SqliteAuditStore(self.db_path),
            adapters=_Adapters(),
            policy=policy,
            app_id=policy.app_id,
        )
        app = make_app(
            gateway=gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=self.reader,
        )
        with TestClient(app) as client:
            response = client.get("/admin/events", headers=self.auth())
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(
                response.json()["limits"]["default_reply_tokens"],
                {"effective": 384, "ceiling": 1024, "source": "policy"},
            )
            self.assertEqual(
                response.json()["limits"]["max_reply_tokens"],
                {"effective": 512, "ceiling": 4096, "source": "policy"},
            )
            self.assertEqual(
                response.json()["limits"]["context_budget"],
                {"effective": 8192, "ceiling": 8192, "source": "env"},
            )

            page = client.get("/admin")
            self.assertEqual(page.status_code, 200)
            self.assertIn("Effective limits", page.text)
            self.assertIn('id="limits-panel"', page.text)
            self.assertIn('id="effective-limits"', page.text)
            self.assertNotIn('id="limit-editor"', page.text)


class ConfigurationTests(OperatorTestBase):
    def test_absent_configuration_disables_admin_routes_with_404(self):
        app = make_app(gateway=self.gateway, environ={})
        with TestClient(app) as client:
            for path in ("/admin", "/admin/events"):
                response = client.get(path)
                self.assertEqual(response.status_code, 404, path)
                self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
                self.assertEqual(response.headers["cache-control"], "no-store")

    def test_partial_or_invalid_configuration_is_safe_503(self):
        cases = [
            {"operator_key_digest": OPERATOR_DIGEST},
            {"operator_reader": self.reader},
            {"operator_key_digest": "not-a-digest", "operator_reader": self.reader},
            {"operator_key_digest": CHAT_DIGEST, "operator_reader": self.reader},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                app = make_app(gateway=self.gateway, **kwargs)
                with TestClient(app) as client:
                    for path in ("/admin", "/admin/events"):
                        response = client.get(path, headers=self.auth())
                        self.assertEqual(response.status_code, 503, path)
                        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
                        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_env_partial_or_unreadable_secret_is_safe_503(self):
        cases = [
            {"NASI_LEMAK_OPERATOR_KEY_DIGEST": OPERATOR_DIGEST},
            {
                "NASI_LEMAK_OPERATOR_KEY_DIGEST_FILE": str(
                    Path(self.tmp.name) / "missing-operator-secret"
                ),
                "NASI_LEMAK_OPERATOR_AUDIT_DSN": "postgresql://reader@db/nasi_lemak",
            },
        ]
        for environ in cases:
            with self.subTest(environ=environ):
                app = make_app(gateway=self.gateway, environ=environ)
                with TestClient(app) as client:
                    self.assertEqual(client.get("/admin").status_code, 503)
                    self.assertEqual(
                        client.get("/admin/events", headers=self.auth()).status_code,
                        503,
                    )

    def test_operator_dsn_must_differ_from_runtime_writer_dsn(self):
        same = "postgresql://role@db/nasi_lemak"
        state = _resolve_operator(
            {
                "NASI_LEMAK_OPERATOR_KEY_DIGEST": OPERATOR_DIGEST,
                "NASI_LEMAK_OPERATOR_AUDIT_DSN": same,
            },
            self.gateway,
            None,
            None,
            same,
        )
        self.assertEqual(state.mode, "unavailable")

        state = _resolve_operator(
            {
                "NASI_LEMAK_OPERATOR_KEY_DIGEST": OPERATOR_DIGEST,
                "NASI_LEMAK_OPERATOR_AUDIT_DSN": "postgresql://reader@db/nasi_lemak",
            },
            self.gateway,
            None,
            None,
            same,
        )
        self.assertEqual(state.mode, "ready")

    def test_invalid_operator_configuration_does_not_break_chat(self):
        app = make_app(gateway=self.gateway, operator_key_digest=CHAT_DIGEST, operator_reader=self.reader)
        with TestClient(app) as client:
            response = client.post(
                "/v1/chat/completions",
                json={
                    "model": "pilot-local",
                    "messages": [{"role": "user", "content": "hello"}],
                },
                headers={"Authorization": "Bearer " + APP_KEY},
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(client.get("/admin").status_code, 503)

    def test_shutdown_closes_operator_reader(self):
        reader = _ClosingReader()
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=reader,
        )
        with TestClient(app):
            self.assertFalse(reader.closed)
        self.assertTrue(reader.closed)


class AuthenticationAndSeparationTests(OperatorTestBase):
    def test_absent_malformed_duplicate_wrong_and_chat_keys_are_401_before_reads(self):
        reader = _SpyReader()
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=reader,
        )
        cases = [
            [],
            [("Authorization", "Bearer wrong")],
            [("Authorization", "Bearer " + APP_KEY)],
            [("Authorization", "Basic " + OPERATOR_KEY)],
            [("Authorization", OPERATOR_KEY)],
            [("Authorization", "Bearer")],
            [("Authorization", "Bearer ")],
            [
                ("Authorization", "Bearer " + OPERATOR_KEY),
                ("Authorization", "Bearer " + OPERATOR_KEY),
            ],
        ]
        with TestClient(app) as client:
            for headers in cases:
                with self.subTest(headers=headers):
                    response = client.get("/admin/events", headers=headers)
                    self.assertEqual(response.status_code, 401, response.text)
                    self.assertEqual(response.json()["error"]["code"], "UNAUTHORIZED")
                    self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(reader.calls, [])

    def test_operator_key_does_not_authorize_chat(self):
        response = self.client.post(
            "/v1/chat/completions",
            json={
                "model": "pilot-local",
                "messages": [{"role": "user", "content": "hello"}],
            },
            headers={"Authorization": "Bearer " + OPERATOR_KEY},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], "UNAUTHORIZED")

    def test_chat_key_does_not_authorize_operator_events(self):
        response = self.client.get("/admin/events", headers={"Authorization": "Bearer " + APP_KEY})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["code"], "UNAUTHORIZED")

    def test_admin_shell_requires_no_token_and_contains_no_data(self):
        self.seed()
        _insert_event(
            self.db_path,
            request_id="<script>alert(1)</script>",
            event_type="request_started",
            decision="pending",
            app_id=POLICY.app_id,
            version="SECRET_VERSION_<b>",
        )
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        html = response.text
        self.assertNotIn("SECRET_VERSION", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn(OPERATOR_KEY, html)
        self.assertNotIn(APP_KEY, html)
        self.assertNotIn(POLICY.digest, html)
        self.assertIn('type="password"', html)
        self.assertIn("textContent", html)
        self.assertIn("AbortController", html)
        self.assertNotIn("pending (incomplete)", html)
        self.assertIn("final outcome may appear in a later event or on another page", html)
        # The default table is the five operational columns; technical metadata
        # stays in the same DOM and is revealed by an accessible toggle.
        self.assertIn('id="toggle-technical"', html)
        self.assertIn('aria-controls="events-table"', html)
        self.assertIn('aria-expanded="false"', html)
        self.assertIn('data-technical="off"', html)
        self.assertIn('id="events-table"', html)
        self.assertIn('tabindex="0"', html)
        self.assertIn('aria-label="Audit events table"', html)
        self.assertIn('class="col-technical">Seq', html)
        self.assertIn('class="col-technical">Policy version', html)
        self.assertIn('class="col-technical">Policy digest', html)
        self.assertIn('class="col-technical">Model', html)
        self.assertEqual(html.count('class="col-technical"'), 4)
        self.assertIn(
            '.table-wrap[data-technical="off"] .col-technical { display: none; }', html
        )
        self.assertRegex(html, r"table \{[^}]*min-width: 0;")
        self.assertIn("Show technical columns", html)
        for forbidden in ("innerHTML", "localStorage", "sessionStorage", "document.cookie"):
            self.assertNotIn(forbidden, html)
        self.assertNotIn("?token=", html)
        self.assertNotIn("token=", html)


class HeaderAndCspTests(OperatorTestBase):
    def test_security_headers_and_hash_csp_on_both_routes(self):
        self.seed()
        for response in (self.client.get("/admin"), self.events(limit=1)):
            with self.subTest(path=response.request.url.path):
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertEqual(response.headers["x-content-type-options"], "nosniff")
                self.assertEqual(response.headers["x-frame-options"], "DENY")
                self.assertNotIn("access-control-allow-origin", response.headers)
                csp = response.headers["content-security-policy"]
                self.assertIn("default-src 'none'", csp)
                self.assertIn("connect-src 'self'", csp)
                self.assertIn("frame-ancestors 'none'", csp)
                self.assertIn("base-uri 'none'", csp)
                self.assertNotIn("unsafe-inline", csp)
                self.assertNotIn("unsafe-eval", csp)
                self.assertNotIn("http://", csp)
                self.assertNotIn("https://", csp)

        html = self.client.get("/admin").text
        script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
        style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
        csp = self.client.get("/admin").headers["content-security-policy"]
        for text in (script, style):
            digest = base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
            self.assertIn("'sha256-" + digest + "'", csp)


class ReaderPagingAndIsolationTests(OperatorTestBase):
    def test_pages_filters_and_started_rows_are_deterministic(self):
        self.seed()
        first = self.events(limit=2)
        self.assertEqual(first.status_code, 200, first.text)
        payload = first.json()
        self.assertEqual([event["seq"] for event in payload["events"]], [1, 2])
        self.assertTrue(payload["has_more"])
        self.assertEqual(payload["next_cursor"], 2)
        self.assertEqual(
            set(payload["events"][0]),
            {
                "seq",
                "request_id",
                "event_type",
                "timestamp",
                "model",
                "policy_version",
                "policy_digest",
                "decision",
                "error_code",
            },
        )
        self.assertEqual(payload["events"][0]["event_type"], "request_started")
        self.assertEqual(payload["events"][0]["decision"], "pending")
        self.assertEqual(payload["policy"], {"version": POLICY.version, "digest": POLICY.digest})
        self.assertEqual(payload["health"], "ready")
        self.assertNotIn("app_id", payload["events"][0])

        second = self.events(limit=2, after=payload["next_cursor"])
        self.assertEqual([event["seq"] for event in second.json()["events"]], [3])
        self.assertFalse(second.json()["has_more"])
        self.assertIsNone(second.json()["next_cursor"])

        self.assertEqual(
            [event["seq"] for event in self.events(decision="pending").json()["events"]],
            [1, 3],
        )
        self.assertEqual(
            [event["seq"] for event in self.events(event_type="request_completed").json()["events"]],
            [2],
        )
        self.assertEqual(
            [event["seq"] for event in self.events(request_id="req_one").json()["events"]],
            [1, 2],
        )

    def test_app_isolation_hides_other_application_rows(self):
        self.seed()
        payload = self.events(limit=100).json()
        request_ids = {event["request_id"] for event in payload["events"]}
        self.assertEqual(request_ids, {"req_one", "req_two"})
        self.assertNotIn("req_other", request_ids)
        other = self.reader.fetch_page(OTHER_SENTINEL, EventFilters(limit=10))
        self.assertEqual([event["request_id"] for event in other.events], ["req_other"])

    def test_event_text_is_json_only_and_not_reflected_into_shell(self):
        self.seed()
        malicious = "<img src=x onerror=alert(1)>"
        _insert_event(
            self.db_path,
            request_id="req_bad",
            event_type="request_started",
            decision="pending",
            app_id=POLICY.app_id,
            version=malicious,
        )
        response = self.events(request_id="req_bad")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"].split(";")[0], "application/json")
        self.assertEqual(response.json()["events"][0]["policy_version"], malicious)
        self.assertNotIn(malicious, self.client.get("/admin").text)

    def test_reader_failure_and_missing_database_are_generic_503(self):
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=_FailingReader(),
        )
        with TestClient(app) as client:
            response = client.get("/admin/events", headers=self.auth())
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
            self.assertNotIn("SECRET", response.text)
            self.assertNotIn("postgresql", response.text)
            self.assertEqual(response.headers["cache-control"], "no-store")

        missing = SqliteAuditReader(Path(self.tmp.name) / "absent.sqlite3")
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=missing,
        )
        with TestClient(app) as client:
            response = client.get("/admin/events", headers=self.auth())
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")


class QueryBoundaryTests(unittest.TestCase):
    def test_query_parser_accepts_only_bounded_values(self):
        filters = parse_event_query(
            [
                ("limit", "100"),
                ("decision", "allowed"),
                ("event_type", "request_completed"),
                ("request_id", "req_abc-1.2"),
                ("after", "42"),
            ]
        )
        self.assertEqual(
            filters,
            EventFilters(
                limit=100,
                decision="allowed",
                event_type="request_completed",
                request_id="req_abc-1.2",
                after_seq=42,
            ),
        )
        self.assertEqual(parse_event_query([]), EventFilters())

    def test_query_parser_rejects_injection_and_unbounded_values(self):
        invalid = [
            [("limit", "0")],
            [("limit", "101")],
            [("limit", "001")],
            [("limit", "1e2")],
            [("limit", "1 OR 1=1")],
            [("after", "0")],
            [("after", "-1")],
            [("after", "abc")],
            [("after", "9999999999999999999")],
            [("decision", "DROP TABLE events")],
            [("event_type", "<script>")],
            [("request_id", "x" * 129)],
            [("request_id", "req' OR 1=1 --")],
            [("limit", "1"), ("limit", "2")],
            [("offset", "10")],
            [("decision", "")],
        ]
        for items in invalid:
            with self.subTest(items=items):
                with self.assertRaises(OperatorQueryError):
                    parse_event_query(items)


class ApiQueryBoundaryTests(OperatorTestBase):
    def test_malicious_query_is_400_without_reader_calls(self):
        reader = _SpyReader()
        app = make_app(
            gateway=self.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=reader,
        )
        cases = [
            "limit=0",
            "limit=101",
            "limit=1e2",
            "after=-1",
            "after=abc",
            "after=9999999999999999999",
            "decision=DROP%20TABLE",
            "event_type=%3Cscript%3E",
            "request_id=" + ("x" * 129),
            "request_id=req%27%20OR%201%3D1",
            "unknown=1",
            "limit=1&limit=2",
        ]
        with TestClient(app) as client:
            for query in cases:
                with self.subTest(query=query):
                    response = client.get(
                        "/admin/events?" + query,
                        headers=self.auth(),
                    )
                    self.assertEqual(response.status_code, 400, query)
                    self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
                    self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(reader.calls, [])


class PostgresReaderSqlTests(unittest.TestCase):
    def test_bounded_select_only_sql_and_parameters_with_driver_double(self):
        rows = [
            (1, "req_a", "request_started", 1.0, "pilot-local", "v1", "d" * 64, "pending", None),
            (2, "req_a", "request_completed", 2.0, "pilot-local", "v1", "d" * 64, "allowed", None),
            (3, "req_b", "request_started", 3.0, "pilot-local", "v1", "d" * 64, "pending", None),
        ]
        description = [(name,) for name in (
            "seq", "request_id", "event_type", "timestamp", "model",
            "policy_version", "policy_digest", "decision", "error_code",
        )]

        class FakeCursor:
            def __init__(self):
                self.sql = None
                self.params = None
                self.description = description

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params):
                self.sql = sql
                self.params = params

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
                self.connect_args = None
                self.connect_kwargs = None

            def connect(self, conninfo, **kwargs):
                self.connect_args = conninfo
                self.connect_kwargs = kwargs
                return self.connection

        fake = FakePsycopg()
        reader = PostgresAuditReader("postgresql://reader@db/nasi_lemak")
        reader._psycopg = fake
        page = reader.fetch_page(
            "synthetic-app",
            EventFilters(
                limit=2,
                decision="pending",
                event_type="request_started",
                request_id="req_a",
                after_seq=1,
            ),
        )

        self.assertTrue(page.has_more)
        self.assertEqual(page.next_cursor, 2)
        self.assertEqual(len(page.events), 2)
        self.assertEqual(set(page.events[0]), set(name for (name,) in description))
        sql = fake.cursor.sql
        self.assertIn("WHERE app_id = %s", sql)
        self.assertIn("decision = %s", sql)
        self.assertIn("event_type = %s", sql)
        self.assertIn("request_id = %s", sql)
        self.assertIn("seq > %s", sql)
        self.assertIn("ORDER BY seq ASC LIMIT %s", sql)
        self.assertNotIn("req_a", sql)
        self.assertEqual(
            fake.cursor.params,
            ("synthetic-app", "pending", "request_started", "req_a", 1, 3),
        )
        self.assertIs(fake.connect_kwargs["autocommit"], True)
        self.assertIn("statement_timeout", fake.connect_kwargs["options"])
        self.assertIn("default_transaction_read_only=on", fake.connect_kwargs["options"])
        self.assertTrue(fake.connection.closed)
        self.assertNotIn("password", repr(reader))
        self.assertNotIn("postgresql://", repr(reader))

    def test_reader_rejects_bad_app_and_filters(self):
        reader = PostgresAuditReader("postgresql://reader@db/nasi_lemak")
        with self.assertRaises(OperatorQueryError):
            reader.fetch_page("", EventFilters())
        with self.assertRaises(OperatorQueryError):
            reader.fetch_page("synthetic-app", {"limit": 5})


class SyntheticFixtureTests(unittest.TestCase):
    def test_fixture_seed_is_paged_and_includes_harmless_markup(self):
        import importlib.util

        fixture_path = Path(__file__).resolve().parents[1] / "scripts" / "operator_demo.py"
        spec = importlib.util.spec_from_file_location("operator_demo_fixture", fixture_path)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "synthetic.sqlite3"
            store = SqliteAuditStore(db_path)
            policy = Policy(
                app_id=fixture.SYNTHETIC_APP,
                version="synthetic-fixture-test.1",
                model="pilot-local",
                token_budget=256,
            )
            seeded = fixture._seed(store, policy, db_path)
            self.assertGreater(seeded, 50)
            self.assertGreater(seeded, 100)
            reader = SqliteAuditReader(db_path)
            first = reader.fetch_page(policy.app_id, EventFilters(limit=50))
            self.assertEqual(len(first.events), 50)
            self.assertTrue(first.has_more)
            versions = {
                event["policy_version"]
                for event in reader.fetch_page(policy.app_id, EventFilters(limit=100)).events
            }
            self.assertIn(fixture.SYNTHETIC_HOSTILE_METADATA, versions)
            self.assertNotIn("req_other_app", {event["request_id"] for event in first.events})
            source = fixture_path.read_text(encoding="utf-8")
            self.assertIn("environ={}", source)
            self.assertIn("--reader-delay", source)
            self.assertIn("--reader-unavailable", source)
            self.assertIn("--export-audit-unavailable", source)
            self.assertIn("SqliteExportAuditLog(export_path)", source)
            self.assertIn("export_log=export_log", source)
            self.assertIn('host="127.0.0.1"', source)


class ChatRegressionTests(OperatorTestBase):
    def test_chat_success_and_health_unchanged_with_operator_configured(self):
        response = self.client.post(
            "/v1/chat/completions",
            json={
                "model": "pilot-local",
                "messages": [{"role": "user", "content": "Email person@example.com"}],
            },
            headers={"Authorization": "Bearer " + APP_KEY},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.client.get("/health/live").status_code, 200)
        self.assertEqual(self.client.get("/health/ready").status_code, 200)

    def test_admin_methods_and_trailing_slashes_are_closed(self):
        self.assertEqual(self.client.post("/admin").status_code, 405)
        self.assertEqual(self.client.post("/admin/events").status_code, 405)
        self.assertEqual(self.client.get("/admin/").status_code, 404)
        self.assertEqual(self.client.get("/admin/events/").status_code, 404)


if __name__ == "__main__":
    unittest.main()
