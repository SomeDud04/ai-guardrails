"""Privacy regression tests through the real ASGI app and real SQLite stores.

Every test here uses the actual FastAPI application, ``Gateway`` and
``SqliteAuditStore``/``SqliteAuditReader``/``SqliteExportAuditLog`` with
temporary files.  Guard, tokenizer and generation verdicts are explicit
deterministic doubles.  ``environ={}`` is passed so no process environment,
``*_FILE`` secret path or real credential is read, and nothing contacts an
external host or loads a model.

The assertions distinguish what the code can actually promise:

* raw input remains in process memory for the mandatory attack screen, and raw
  output remains in memory for the output guard;
* the generation client and the HTTP client see masked values instead;
* the audit store, operator JSON, CSV export, export audit and captured
  logging/stdout/stderr contain metadata only.

This is local synthetic development evidence.  It says nothing about
PostgreSQL retention, production deletion, upstream-provider logs or universal
memory erasure.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import closing
from pathlib import Path

from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.export import SqliteExportAuditLog
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.operator import SqliteAuditReader
from nasi_lemak.server import make_app

APP_KEY = "privacy-synthetic-chat-key-not-real"
OPERATOR_KEY = "privacy-synthetic-operator-key-not-real"
APP_KEY_DIGEST = hashlib.sha256(APP_KEY.encode()).hexdigest()
OPERATOR_DIGEST = hashlib.sha256(OPERATOR_KEY.encode()).hexdigest()
POLICY = Policy(
    app_id="privacy-synthetic-app",
    version="privacy-2026-10-20.1",
    model="pilot-local",
    token_budget=256,
)

EMAIL = "privacy.user@example.invalid"
PHONE = "+60111222333"
MYKAD = "880101-14-5678"
INPUT_SENTINEL = "SYNTHETIC-RAW-INPUT-SENTINEL"
OUTPUT_SENTINEL = "SYNTHETIC-RAW-OUTPUT-SENTINEL"
EXC_SENTINEL = "SYNTHETIC-EXCEPTION-SENTINEL"
FAKE_DSN = (
    "postgresql://privacy_reader:fake-password-SENTINEL@db.invalid/privacy"
)
OTHER_APP = "privacy-other-app-sentinel"

MASK_TOKENS = ("[EMAIL]", "[MY_PHONE]", "[MYKAD]")
RAW_PII = (EMAIL, PHONE, MYKAD)
SECRETS = (
    APP_KEY,
    OPERATOR_KEY,
    EXC_SENTINEL,
    FAKE_DSN,
    "fake-password-SENTINEL",
    INPUT_SENTINEL,
    OUTPUT_SENTINEL,
)
# Persistent metadata surfaces must contain neither raw PII nor a mask token.
METADATA_FORBIDDEN = RAW_PII + SECRETS + MASK_TOKENS

USER_CONTENT = (
    f"{INPUT_SENTINEL}: contact {EMAIL}, phone {PHONE}, id {MYKAD}"
)
GENERATED_CONTENT = (
    f"{OUTPUT_SENTINEL}: reply to {EMAIL} / {PHONE} / {MYKAD}"
)
MASKED_OUTPUT = (
    f"{OUTPUT_SENTINEL}: reply to [EMAIL] / [MY_PHONE] / [MYKAD]"
)


class _Adapters:
    """Deterministic tokenizer, attack guard, generation and output guard."""

    def __init__(self):
        self.attack_result = {"decision": "allow"}
        self.attack_error = None
        self.generated = GENERATED_CONTENT
        self.generate_error = None
        self.output_result = {"safe": True}
        self.output_error = None
        self.attack_inputs = []
        self.generation_inputs = []
        self.output_inputs = []

    def count_tokens(self, serialized):
        return max(1, len(serialized.split()))

    def scan_attack(self, text):
        self.attack_inputs.append(text)
        if self.attack_error is not None:
            raise self.attack_error
        return self.attack_result

    def generate(self, messages, model, max_tokens):
        self.generation_inputs.append([dict(message) for message in messages])
        if self.generate_error is not None:
            raise self.generate_error
        return self.generated

    def scan_output(self, text):
        self.output_inputs.append(text)
        if self.output_error is not None:
            raise self.output_error
        return self.output_result


class _FailingReader:
    """Reader double that leaks markers in its exception text."""

    def fetch_page(self, app_id, filters):
        raise RuntimeError(f"{EXC_SENTINEL} {FAKE_DSN}")

    def fetch_export(self, app_id, filters):
        raise RuntimeError(f"{EXC_SENTINEL} {FAKE_DSN}")

    def close(self):
        pass


class _Runtime:
    __slots__ = ("client", "app", "gateway", "adapters", "db_path")

    def __init__(self, client, app, gateway, adapters, db_path):
        self.client = client
        self.app = app
        self.gateway = gateway
        self.adapters = adapters
        self.db_path = db_path


class _CapturedOutput:
    def __init__(self):
        self.log = io.StringIO()
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def text(self):
        return self.log.getvalue() + self.stdout.getvalue() + self.stderr.getvalue()


@contextlib.contextmanager
def _capture_process_output():
    """Capture Python logging plus stdout/stderr for the exercised operations."""
    captured = _CapturedOutput()
    handler = logging.StreamHandler(captured.log)
    handler.setLevel(logging.DEBUG)
    root = logging.getLogger()
    previous = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        with contextlib.redirect_stdout(
            captured.stdout
        ), contextlib.redirect_stderr(captured.stderr):
            yield captured
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def _make_runtime(db_path, adapters=None):
    adapters = adapters if adapters is not None else _Adapters()
    store = SqliteAuditStore(db_path)
    export_log = SqliteExportAuditLog(db_path)
    reader = SqliteAuditReader(db_path)
    gateway = Gateway(
        app_key=APP_KEY,
        audit_store=store,
        adapters=adapters,
        policy=POLICY,
        app_id=POLICY.app_id,
    )
    app = make_app(
        gateway=gateway,
        operator_key_digest=OPERATOR_DIGEST,
        operator_reader=reader,
        export_log=export_log,
        environ={},
    )
    return _Runtime(TestClient(app), app, gateway, adapters, Path(db_path))


def _rows(path, table):
    order = "seq" if table == "events" else "id"
    with closing(sqlite3.connect(str(path))) as db:
        db.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in db.execute(f"SELECT * FROM {table} ORDER BY {order}")
        ]


def _insert_event(path, **values):
    record = {
        "request_id": "req_direct",
        "event_type": "request_started",
        "timestamp": 1.0,
        "app_id": POLICY.app_id,
        "model": POLICY.model,
        "policy_version": POLICY.version,
        "policy_digest": POLICY.digest,
        "decision": "pending",
        "error_code": None,
    }
    record.update(values)
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
                tuple(
                    record[name]
                    for name in (
                        "request_id",
                        "event_type",
                        "timestamp",
                        "app_id",
                        "model",
                        "policy_version",
                        "policy_digest",
                        "decision",
                        "error_code",
                    )
                ),
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise


def _rows_hash(rows):
    payload = json.dumps(
        rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _sqlite_copy(source, destination):
    with closing(sqlite3.connect(str(source))) as src, closing(
        sqlite3.connect(str(destination))
    ) as dst:
        src.backup(dst)


def _integrity(path):
    with closing(sqlite3.connect(str(path))) as db:
        return db.execute("PRAGMA integrity_check").fetchone()[0]


class PrivacyTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def start(self, adapters=None):
        runtime = _make_runtime(
            self.root / f"audit-{uuid.uuid4().hex}.sqlite3", adapters
        )
        self.addCleanup(runtime.client.close)
        return runtime

    @staticmethod
    def auth():
        return {"Authorization": "Bearer " + APP_KEY}

    @staticmethod
    def operator_auth():
        return {"Authorization": "Bearer " + OPERATOR_KEY}

    def chat(self, runtime, content=USER_CONTENT):
        return runtime.client.post(
            "/v1/chat/completions",
            json={
                "model": "pilot-local",
                "messages": [{"role": "user", "content": content}],
            },
            headers=self.auth(),
        )

    def assert_metadata_only(self, text, label):
        for forbidden in METADATA_FORBIDDEN:
            self.assertNotIn(forbidden, text, f"{label} leaked {forbidden!r}")

    def assert_logs_clean(self, captured, label):
        text = captured.text()
        for forbidden in METADATA_FORBIDDEN:
            self.assertNotIn(forbidden, text, f"{label} log leaked {forbidden!r}")

    def verify_persistent_surfaces(self, runtime, expected_events):
        """Inspect audit rows, operator JSON, CSV and the export audit."""
        rows = _rows(runtime.db_path, "events")
        self.assertEqual(len(rows), expected_events, rows)
        self.assert_metadata_only(json.dumps(rows), "audit rows")
        for row in rows:
            self.assertEqual(row["app_id"], POLICY.app_id)
            self.assertEqual(row["model"], POLICY.model)
            self.assertEqual(row["policy_version"], POLICY.version)
            self.assertEqual(row["policy_digest"], POLICY.digest)

        operator = runtime.client.get(
            "/admin/events?limit=100", headers=self.operator_auth()
        )
        self.assertEqual(operator.status_code, 200, operator.text)
        self.assert_metadata_only(operator.text, "operator JSON")
        self.assertEqual(len(operator.json()["events"]), expected_events)

        export = runtime.client.get(
            "/admin/export.csv", headers=self.operator_auth()
        )
        self.assertEqual(export.status_code, 200, export.text)
        self.assert_metadata_only(export.text, "CSV")
        self.assert_metadata_only(
            json.dumps(dict(export.headers)), "CSV headers"
        )
        self.assertEqual(int(export.headers["x-export-row-count"]), expected_events)
        self.assertEqual(
            export.headers["x-export-sha256"],
            hashlib.sha256(export.content).hexdigest(),
        )

        exports = _rows(runtime.db_path, "export_audits")
        self.assertEqual(len(exports), 1, exports)
        self.assert_metadata_only(json.dumps(exports), "export audit rows")
        self.assertEqual(exports[0]["app_id"], POLICY.app_id)
        self.assertEqual(exports[0]["row_count"], expected_events)
        self.assertEqual(exports[0]["sha256"], hashlib.sha256(export.content).hexdigest())
        self.assertEqual(exports[0]["policy_version"], POLICY.version)
        self.assertEqual(exports[0]["policy_digest"], POLICY.digest)
        return rows, operator, export, exports


class PrivacySurfaceTests(PrivacyTestBase):
    def test_success_masks_client_and_upstream_but_audits_metadata_only(self):
        runtime = self.start()
        with _capture_process_output() as captured:
            response = self.chat(runtime)
            rows, _operator, export, exports = self.verify_persistent_surfaces(
                runtime, expected_events=2
            )
        self.assertEqual(response.status_code, 200, response.text)

        # Positive control: the non-PII answer survives, the seeded PII does not.
        body = response.json()
        content = body["choices"][0]["message"]["content"]
        self.assertEqual(content, MASKED_OUTPUT)
        self.assertEqual(body["object"], "chat.completion")
        for value in RAW_PII + (INPUT_SENTINEL,):
            self.assertNotIn(value, response.text)
        for value in (APP_KEY, OPERATOR_KEY, FAKE_DSN, EXC_SENTINEL):
            self.assertNotIn(value, response.text)

        # Raw input is legitimately in memory for the attack screen.
        self.assertEqual(runtime.adapters.attack_inputs, ["user: " + USER_CONTENT])
        self.assertIn(EMAIL, runtime.adapters.attack_inputs[0])

        # Generation receives the masked conversation, never the raw values.
        self.assertEqual(
            runtime.adapters.generation_inputs,
            [
                [
                    {
                        "role": "user",
                        "content": f"{INPUT_SENTINEL}: contact [EMAIL], phone [MY_PHONE], id [MYKAD]",
                    }
                ]
            ],
        )
        upstream = json.dumps(runtime.adapters.generation_inputs)
        for value in RAW_PII:
            self.assertNotIn(value, upstream)
        self.assertIn(INPUT_SENTINEL, upstream)

        # Raw output is legitimately in memory for the output guard.
        self.assertEqual(runtime.adapters.output_inputs, [GENERATED_CONTENT])
        self.assertIn(OUTPUT_SENTINEL, runtime.adapters.output_inputs[0])

        self.assertEqual(
            [(row["event_type"], row["decision"]) for row in rows],
            [("request_started", "pending"), ("request_completed", "allowed")],
        )
        self.assertEqual(exports[0]["row_count"], 2)
        self.assert_logs_clean(captured, "success path")

    def test_attack_block_rejects_before_generation_without_leaking_input(self):
        adapters = _Adapters()
        adapters.attack_result = {"decision": "block"}
        runtime = self.start(adapters)
        with _capture_process_output() as captured:
            response = self.chat(runtime)
            rows, _operator, _export, _exports = self.verify_persistent_surfaces(
                runtime, expected_events=2
            )
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json()["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(response.json()["error"]["message"], "Request did not pass safety checks.")
        for value in RAW_PII + (INPUT_SENTINEL, APP_KEY, FAKE_DSN):
            self.assertNotIn(value, response.text)
        self.assertEqual(adapters.generation_inputs, [])
        self.assertEqual(adapters.attack_inputs, ["user: " + USER_CONTENT])
        self.assertEqual(
            [(row["event_type"], row["decision"], row["error_code"]) for row in rows],
            [("request_started", "pending", None), ("request_blocked", "blocked", "POLICY_BLOCK")],
        )
        self.assert_logs_clean(captured, "attack block")

    def test_unsafe_output_is_blocked_and_never_released(self):
        adapters = _Adapters()
        adapters.output_result = {"safe": False}
        runtime = self.start(adapters)
        with _capture_process_output() as captured:
            response = self.chat(runtime)
            rows, _operator, _export, _exports = self.verify_persistent_surfaces(
                runtime, expected_events=2
            )
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json()["error"]["code"], "POLICY_BLOCK")
        for value in RAW_PII + (OUTPUT_SENTINEL, APP_KEY, FAKE_DSN):
            self.assertNotIn(value, response.text)
        self.assertEqual(adapters.output_inputs, [GENERATED_CONTENT])
        self.assertEqual(len(adapters.generation_inputs), 1)
        self.assertEqual(
            [(row["event_type"], row["decision"]) for row in rows],
            [("request_started", "pending"), ("request_blocked", "blocked")],
        )
        self.assert_logs_clean(captured, "unsafe output")

    def test_generation_and_guard_failures_are_generic_503(self):
        cases = {
            "generation": ("generate_error", RuntimeError(f"{EXC_SENTINEL} {FAKE_DSN}")),
            "attack_guard": ("attack_error", RuntimeError(f"{EXC_SENTINEL} {FAKE_DSN}")),
            "output_guard": ("output_error", RuntimeError(f"{EXC_SENTINEL} {FAKE_DSN}")),
        }
        for name, (attribute, error) in cases.items():
            with self.subTest(name=name):
                adapters = _Adapters()
                setattr(adapters, attribute, error)
                runtime = self.start(adapters)
                with _capture_process_output() as captured:
                    response = self.chat(runtime)
                    rows, _operator, _export, _exports = (
                        self.verify_persistent_surfaces(
                            runtime, expected_events=2
                        )
                    )
                self.assertEqual(response.status_code, 503, response.text)
                self.assertEqual(
                    response.json()["error"]["code"], "UNAVAILABLE"
                )
                self.assertEqual(
                    response.json()["error"]["message"],
                    "Required safety control is unavailable.",
                )
                for value in (EXC_SENTINEL, FAKE_DSN, INPUT_SENTINEL):
                    self.assertNotIn(value, response.text)
                if name == "attack_guard":
                    self.assertEqual(adapters.generation_inputs, [])
                self.assertEqual(
                    [(row["event_type"], row["decision"]) for row in rows],
                    [("request_started", "pending"), ("request_failed", "failed")],
                )
                self.assertEqual(rows[1]["error_code"], "UNAVAILABLE")
                self.assert_logs_clean(captured, name)

    def test_operator_reader_failure_is_generic_and_logs_no_secret(self):
        runtime = self.start()
        app = make_app(
            gateway=runtime.gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=_FailingReader(),
            export_log=SqliteExportAuditLog(runtime.db_path),
            environ={},
        )
        with _capture_process_output() as captured:
            with TestClient(app) as client:
                events = client.get(
                    "/admin/events", headers=self.operator_auth()
                )
                export = client.get(
                    "/admin/export.csv", headers=self.operator_auth()
                )
        for response in (events, export):
            self.assertEqual(response.status_code, 503, response.text)
            self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
            for value in (EXC_SENTINEL, FAKE_DSN, OPERATOR_KEY, APP_KEY):
                self.assertNotIn(value, response.text)
        self.assert_logs_clean(captured, "operator failure")


class AuditFailureTests(PrivacyTestBase):
    def test_initial_audit_failure_returns_503_without_events_or_generation(self):
        runtime = self.start()
        runtime.gateway.fail_audit_stage = "initial"
        with _capture_process_output() as captured:
            response = self.chat(runtime)
            self.assertEqual(_rows(runtime.db_path, "events"), [])
            _rows_found, _operator, _export, exports = (
                self.verify_persistent_surfaces(runtime, expected_events=0)
            )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertEqual(runtime.adapters.attack_inputs, [])
        self.assertEqual(runtime.adapters.generation_inputs, [])
        self.assertEqual(runtime.gateway.audit_events(), [])
        self.assertEqual(exports[0]["row_count"], 0)
        self.assert_logs_clean(captured, "initial audit failure")

    def test_terminal_audit_failure_releases_no_output_and_offline_recovery_preserves_identity(
        self,
    ):
        runtime = self.start()
        runtime.gateway.fail_audit_stage = "terminal"
        with _capture_process_output() as captured:
            response = self.chat(runtime)
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(runtime.adapters.attack_inputs, ["user: " + USER_CONTENT])
        for value in (OUTPUT_SENTINEL, EMAIL, PHONE, MYKAD, EXC_SENTINEL):
            self.assertNotIn(value, response.text)
        self.assertEqual(
            [(row["event_type"], row["decision"]) for row in _rows(runtime.db_path, "events")],
            [("request_started", "pending")],
        )

        runtime.gateway.fail_audit_stage = None
        with self.assertRaises(ValueError):
            runtime.gateway.reconcile_incomplete()
        self.assertEqual(runtime.gateway.reconcile_incomplete(offline=True), 1)
        rows = _rows(runtime.db_path, "events")
        recovered = [row for row in rows if row["event_type"] == "request_recovered"]
        self.assertEqual(len(recovered), 1, rows)
        self.assertEqual(recovered[0]["decision"], "interrupted")
        self.assertEqual(recovered[0]["error_code"], "UNAVAILABLE")
        for column, expected in (
            ("app_id", POLICY.app_id),
            ("model", POLICY.model),
            ("policy_version", POLICY.version),
            ("policy_digest", POLICY.digest),
        ):
            self.assertEqual(recovered[0][column], expected)

        self.verify_persistent_surfaces(runtime, expected_events=2)
        self.assert_logs_clean(captured, "terminal audit failure")


class SqliteBackupRestoreRehearsalTests(unittest.TestCase):
    """Local synthetic backup/restore rehearsal; not a production backup utility."""

    def test_backup_restore_integrity_operator_scoping_and_offline_reconciliation(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "source.sqlite3"
            backup_path = root / "backup.sqlite3"
            restored_path = root / "restored.sqlite3"

            adapters = _Adapters()
            runtime = _make_runtime(source_path, adapters)
            with _capture_process_output() as captured:
                with runtime.client as client:
                    success = client.post(
                        "/v1/chat/completions",
                        json={
                            "model": "pilot-local",
                            "messages": [{"role": "user", "content": USER_CONTENT}],
                        },
                        headers={"Authorization": "Bearer " + APP_KEY},
                    )
                    self.assertEqual(success.status_code, 200, success.text)
                    adapters.attack_result = {"decision": "block"}
                    blocked = client.post(
                        "/v1/chat/completions",
                        json={
                            "model": "pilot-local",
                            "messages": [{"role": "user", "content": USER_CONTENT}],
                        },
                        headers={"Authorization": "Bearer " + APP_KEY},
                    )
                    self.assertEqual(blocked.status_code, 403, blocked.text)
                    exported = client.get(
                        "/admin/export.csv",
                        headers={"Authorization": "Bearer " + OPERATOR_KEY},
                    )
                    self.assertEqual(exported.status_code, 200, exported.text)

            # Writers have stopped.  Add one interrupted request and one
            # unrelated-application row, both directly, then snapshot.
            runtime.gateway.audit_store.record_initial(
                "req_privacy_incomplete",
                POLICY.app_id,
                POLICY.model,
                POLICY.version,
                POLICY.digest,
            )
            _insert_event(source_path, request_id="req_other_app", app_id=OTHER_APP)
            source_events = _rows(source_path, "events")
            source_exports = _rows(source_path, "export_audits")
            source_hash = _file_hash(source_path)

            _sqlite_copy(source_path, backup_path)
            self.assertEqual(_file_hash(source_path), source_hash)
            self.assertEqual(_integrity(source_path), "ok")
            self.assertEqual(_integrity(backup_path), "ok")

            _sqlite_copy(backup_path, restored_path)
            self.assertEqual(_rows(restored_path, "events"), source_events)
            self.assertEqual(_rows(restored_path, "export_audits"), source_exports)
            self.assertEqual(
                _rows_hash(_rows(restored_path, "events")),
                _rows_hash(source_events),
            )
            self.assertEqual(
                _rows_hash(_rows(restored_path, "export_audits")),
                _rows_hash(source_exports),
            )
            self.assertEqual(_integrity(restored_path), "ok")

            # Offline reconciliation runs only against the restored copy.
            restored_store = SqliteAuditStore(restored_path)
            with self.assertRaises(ValueError):
                restored_store.reconcile_incomplete()
            # Two started rows have no terminal event: the interrupted request
            # and the unrelated-application row.  Recovery preserves each
            # row's own trusted identity.
            self.assertEqual(restored_store.reconcile_incomplete(offline=True), 2)
            recovered = [
                row
                for row in _rows(restored_path, "events")
                if row["request_id"] == "req_privacy_incomplete"
                and row["event_type"] == "request_recovered"
            ]
            self.assertEqual(len(recovered), 1)
            self.assertEqual(recovered[0]["decision"], "interrupted")
            self.assertEqual(recovered[0]["error_code"], "UNAVAILABLE")
            for column, expected in (
                ("app_id", POLICY.app_id),
                ("model", POLICY.model),
                ("policy_version", POLICY.version),
                ("policy_digest", POLICY.digest),
            ):
                self.assertEqual(recovered[0][column], expected)
            other_recovered = [
                row
                for row in _rows(restored_path, "events")
                if row["request_id"] == "req_other_app"
                and row["event_type"] == "request_recovered"
            ]
            self.assertEqual(len(other_recovered), 1)
            self.assertEqual(other_recovered[0]["app_id"], OTHER_APP)

            # The original database is bytes-identical and still incomplete.
            self.assertEqual(_file_hash(source_path), source_hash)
            self.assertEqual(_rows(source_path, "events"), source_events)
            self.assertFalse(
                any(
                    row["event_type"] == "request_recovered"
                    for row in _rows(source_path, "events")
                )
            )

            restored_runtime = _make_runtime(restored_path, _Adapters())
            with restored_runtime.client as client:
                page = client.get(
                    "/admin/events?limit=100",
                    headers={"Authorization": "Bearer " + OPERATOR_KEY},
                )
                self.assertEqual(page.status_code, 200, page.text)
                payload = page.json()
                request_ids = {event["request_id"] for event in payload["events"]}
                self.assertIn("req_privacy_incomplete", request_ids)
                self.assertNotIn("req_other_app", request_ids)
                for forbidden in METADATA_FORBIDDEN:
                    self.assertNotIn(forbidden, page.text)

                exported = client.get(
                    "/admin/export.csv",
                    headers={"Authorization": "Bearer " + OPERATOR_KEY},
                )
                self.assertEqual(exported.status_code, 200, exported.text)
                self.assertEqual(
                    int(exported.headers["x-export-row-count"]),
                    len(payload["events"]),
                )
                self.assertEqual(
                    exported.headers["x-export-sha256"],
                    hashlib.sha256(exported.content).hexdigest(),
                )
                for forbidden in METADATA_FORBIDDEN:
                    self.assertNotIn(forbidden, exported.text)

            restored_exports = _rows(restored_path, "export_audits")
            self.assertEqual(len(restored_exports), len(source_exports) + 1)
            self.assertEqual(restored_exports[-1]["app_id"], POLICY.app_id)
            self.assertEqual(restored_exports[-1]["policy_version"], POLICY.version)
            self.assertEqual(restored_exports[-1]["policy_digest"], POLICY.digest)
            self.assertEqual(_rows(source_path, "export_audits"), source_exports)
            self.assertEqual(_file_hash(source_path), source_hash)
            self.assertEqual(_integrity(restored_path), "ok")
            for forbidden in (EMAIL, PHONE, MYKAD, INPUT_SENTINEL, APP_KEY, FAKE_DSN):
                self.assertNotIn(forbidden, captured.text())


if __name__ == "__main__":
    unittest.main()
