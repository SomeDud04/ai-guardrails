"""Deterministic ASGI tests for bounded control-plane admission.

Every synchronous readiness/operator call runs in an event-gated local helper
thread.  No model, PostgreSQL server or external endpoint is contacted.  The
gates prove that a timed-out or cancelled HTTP request keeps its admission slot
until the real thread finishes, and that saturation rejects without dispatching
extra reader or audit work.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import nasi_lemak.server as server
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.operator import EventPage, ExportSnapshot
from nasi_lemak.server import make_app

APP_KEY = "synthetic-chat-key"
OPERATOR_KEY = "synthetic-operator-key"
OPERATOR_DIGEST = hashlib.sha256(OPERATOR_KEY.encode()).hexdigest()
AUTH = [("authorization", "Bearer " + OPERATOR_KEY)]
POLICY = Policy(
    app_id="synthetic-app",
    version="synthetic-2026-10-20.1",
    model="pilot-local",
    token_budget=256,
)
CHAT_BODY = json.dumps(
    {
        "model": "pilot-local",
        "messages": [{"role": "user", "content": "synthetic control-plane test"}],
    }
).encode()


class _Adapters:
    def count_tokens(self, text):
        return max(1, len(text.split()))

    def scan_attack(self, text):
        return {"decision": "allow"}

    def generate(self, messages, model, max_tokens):
        return "Synthetic answer."

    def scan_output(self, text):
        return {"safe": True}


class _GatedReadyStore(SqliteAuditStore):
    """Readiness blocks until the test releases it."""

    def __init__(self, path):
        super().__init__(path)
        self.ready_calls = 0
        self.ready_started = threading.Event()
        self.ready_release = threading.Event()
        self.ready_error: Exception | None = None

    def ready(self):
        self.ready_calls += 1
        self.ready_started.set()
        self.ready_release.wait(10)
        if self.ready_error is not None:
            raise self.ready_error
        return True


class _GatedReader:
    """Reader whose page/export calls are independently event-gated."""

    def __init__(self):
        self.page_calls = 0
        self.export_calls = 0
        self.page_gate = threading.Event()
        self.export_gate = threading.Event()
        self.fail_after_release = False
        self.page = EventPage(events=[], has_more=False, next_cursor=None)
        self.snapshot = ExportSnapshot(rows=[], upper_seq=0)

    def fetch_page(self, app_id, filters):
        self.page_calls += 1
        self.page_gate.wait(10)
        if self.fail_after_release:
            raise RuntimeError("SECRET reader failure")
        return self.page

    def fetch_export(self, app_id, filters):
        self.export_calls += 1
        self.export_gate.wait(10)
        if self.fail_after_release:
            raise RuntimeError("SECRET reader failure")
        return self.snapshot

    def close(self):
        pass


class _ImmediateReader:
    def __init__(self):
        self.export_calls = 0

    def fetch_page(self, app_id, filters):
        return EventPage(events=[], has_more=False, next_cursor=None)

    def fetch_export(self, app_id, filters):
        self.export_calls += 1
        return ExportSnapshot(rows=[], upper_seq=0)

    def close(self):
        pass


class _CountingLog:
    def __init__(self):
        self.calls = 0
        self.entries = []

    def record(self, entry):
        self.calls += 1
        self.entries.append(entry)

    def close(self):
        pass


class _GatedLog(_CountingLog):
    """Export audit blocks, then optionally fails after the response failed."""

    def __init__(self):
        super().__init__()
        self.release = threading.Event()
        self.fail = False

    def record(self, entry):
        self.calls += 1
        self.release.wait(10)
        if self.fail:
            raise RuntimeError("SECRET export audit failure")
        self.entries.append(entry)


async def _wait_until(predicate: Any, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("gated event was not observed")


async def _settle(task: Any, timeout: float = 3.0) -> None:
    """Finish a request task during cleanup without leaking its outcome."""
    if not task.done():
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        except BaseException:
            pass
    if not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=timeout)
        except BaseException:
            pass
    if task.done():
        try:
            task.result()
        except BaseException:
            pass


async def _asgi_request(
    app: Any,
    *,
    method: str = "GET",
    path: str = "/health/ready",
    query: bytes = b"",
    headers: list[tuple[str, str]] | None = None,
    body: bytes = b"",
    sent_sink: list[dict[str, Any]] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    raw_headers = [
        (key.lower().encode(), value.encode()) for key, value in (headers or [])
    ]
    sent: list[dict[str, Any]] = [] if sent_sink is None else sent_sink
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "root_path": "",
        "headers": raw_headers,
        "client": ("127.0.0.1", 45678),
        "server": ("testserver", 80),
        "state": {},
    }
    await app(scope, receive, send)
    status = next(
        item["status"] for item in sent if item["type"] == "http.response.start"
    )
    response_headers = {
        key.decode().lower(): value.decode()
        for item in sent
        if item["type"] == "http.response.start"
        for key, value in item.get("headers", [])
    }
    response_body = b"".join(
        item.get("body", b"")
        for item in sent
        if item["type"] == "http.response.body"
    )
    return status, response_headers, response_body


class ControlPlaneTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3")
        self.addCleanup(self.store.close)

    def build_app(
        self,
        *,
        store: Any = None,
        reader: Any = None,
        export_log: Any = None,
        control: int = 1,
        chat: int = 1,
    ):
        gateway = Gateway(
            app_key=APP_KEY,
            audit_store=self.store if store is None else store,
            adapters=_Adapters(),
            policy=POLICY,
            app_id=POLICY.app_id,
        )
        return make_app(
            gateway=gateway,
            operator_key_digest=OPERATOR_DIGEST,
            operator_reader=reader,
            export_log=export_log,
            control_concurrency=control,
            max_concurrency=chat,
        )


class ReadinessAdmissionTests(ControlPlaneTestBase):
    def test_timeout_retains_slot_blocks_redispatch_and_recovers(self):
        store = _GatedReadyStore(Path(self.tmp.name) / "gated-ready.sqlite3")
        self.addCleanup(store.close)
        app = self.build_app(store=store)

        async def scenario():
            first = asyncio.create_task(_asgi_request(app, path="/health/ready"))
            try:
                with patch.object(server, "READINESS_TIMEOUT", 0.1):
                    await _wait_until(lambda: store.ready_calls >= 1)
                    status, _, body = await asyncio.wait_for(first, timeout=2)
                    self.assertEqual(status, 503)
                    self.assertEqual(json.loads(body)["status"], "not_ready")

                    # The thread is still blocked, so the slot is still held.
                    self.assertEqual(app.state.control_admission.in_use, 1)
                    blocked = await asyncio.wait_for(
                        _asgi_request(app, path="/health/ready"), timeout=1
                    )
                    self.assertEqual(blocked[0], 503)
                    self.assertEqual(store.ready_calls, 1)

                    started = time.monotonic()
                    live = await asyncio.wait_for(
                        _asgi_request(app, path="/health/live"), timeout=1
                    )
                    self.assertEqual(live[0], 200)
                    self.assertLess(time.monotonic() - started, 1)
            finally:
                store.ready_release.set()
                await _settle(first)

            await _wait_until(
                lambda: app.state.control_admission.in_use == 0
            )
            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/health/ready"), timeout=2
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(json.loads(recovered[2])["status"], "ready")
            self.assertEqual(store.ready_calls, 2)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_repeated_cancellation_retains_slot_after_late_error(self):
        store = _GatedReadyStore(Path(self.tmp.name) / "cancel-ready.sqlite3")
        self.addCleanup(store.close)
        store.ready_error = RuntimeError("SECRET readiness failure")
        app = self.build_app(store=store)

        async def scenario():
            first = asyncio.create_task(_asgi_request(app, path="/health/ready"))
            try:
                await _wait_until(lambda: store.ready_calls >= 1)
                first.cancel()
                await asyncio.sleep(0)
                first.cancel()
                await asyncio.sleep(0)
                self.assertFalse(first.done())
                self.assertEqual(app.state.control_admission.in_use, 1)

                blocked = await asyncio.wait_for(
                    _asgi_request(app, path="/health/ready"), timeout=1
                )
                self.assertEqual(blocked[0], 503)
                self.assertEqual(store.ready_calls, 1)

                store.ready_release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await first
            finally:
                store.ready_release.set()
                await _settle(first)
                await _wait_until(
                    lambda: app.state.control_admission.in_use == 0
                )

            store.ready_error = None
            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/health/ready"), timeout=2
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(store.ready_calls, 2)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class EventAdmissionTests(ControlPlaneTestBase):
    def test_timeout_blocks_extra_reads_keeps_auth_and_chat_separate(self):
        reader = _GatedReader()
        app = self.build_app(reader=reader)

        async def scenario():
            first = asyncio.create_task(
                _asgi_request(app, path="/admin/events", headers=AUTH)
            )
            try:
                with patch.object(server, "ADMIN_READ_TIMEOUT", 0.1):
                    await _wait_until(lambda: reader.page_calls >= 1)
                    status, headers, body = await asyncio.wait_for(
                        first, timeout=2
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
                    self.assertEqual(headers["cache-control"], "no-store")
                    self.assertEqual(app.state.control_admission.in_use, 1)

                    # Auth and query validation precede admission: a saturated
                    # control plane still answers 401/400 without reader work.
                    missing_auth = await _asgi_request(
                        app, path="/admin/events"
                    )
                    self.assertEqual(missing_auth[0], 401)
                    bad_query = await _asgi_request(
                        app,
                        path="/admin/events",
                        query=b"limit=0",
                        headers=AUTH,
                    )
                    self.assertEqual(bad_query[0], 400)
                    self.assertEqual(reader.page_calls, 1)

                    # Chat admission is separate and remains available.
                    chat = await asyncio.wait_for(
                        _asgi_request(
                            app,
                            method="POST",
                            path="/v1/chat/completions",
                            headers=[
                                ("content-type", "application/json"),
                                ("authorization", "Bearer " + APP_KEY),
                            ],
                            body=CHAT_BODY,
                        ),
                        timeout=3,
                    )
                    self.assertEqual(chat[0], 200, chat[2])

                    second = await _asgi_request(
                        app, path="/admin/events", headers=AUTH
                    )
                    self.assertEqual(second[0], 503)
                    self.assertEqual(reader.page_calls, 1)
            finally:
                reader.page_gate.set()
                await _settle(first)

            await _wait_until(
                lambda: app.state.control_admission.in_use == 0
            )
            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/admin/events", headers=AUTH),
                timeout=3,
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(reader.page_calls, 2)

        asyncio.run(asyncio.wait_for(scenario(), timeout=15))

    def test_repeated_cancellation_survives_late_reader_error(self):
        reader = _GatedReader()
        reader.fail_after_release = True
        app = self.build_app(reader=reader)

        async def scenario():
            first = asyncio.create_task(
                _asgi_request(app, path="/admin/events", headers=AUTH)
            )
            try:
                await _wait_until(lambda: reader.page_calls >= 1)
                first.cancel()
                await asyncio.sleep(0)
                first.cancel()
                await asyncio.sleep(0)
                self.assertFalse(first.done())
                self.assertEqual(app.state.control_admission.in_use, 1)

                blocked = await _asgi_request(
                    app, path="/admin/events", headers=AUTH
                )
                self.assertEqual(blocked[0], 503)
                self.assertEqual(reader.page_calls, 1)

                reader.page_gate.set()
                with self.assertRaises(asyncio.CancelledError):
                    await first
            finally:
                reader.page_gate.set()
                await _settle(first)
                await _wait_until(
                    lambda: app.state.control_admission.in_use == 0
                )

            reader.fail_after_release = False
            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/admin/events", headers=AUTH),
                timeout=3,
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(reader.page_calls, 2)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class ExportAdmissionTests(ControlPlaneTestBase):
    def test_read_timeout_never_reaches_csv_or_audit_and_recovers(self):
        reader = _GatedReader()
        log = _CountingLog()
        app = self.build_app(reader=reader, export_log=log)

        async def scenario():
            first = asyncio.create_task(
                _asgi_request(
                    app, path="/admin/export.csv", headers=AUTH
                )
            )
            try:
                with patch.object(server, "ADMIN_READ_TIMEOUT", 0.1):
                    await _wait_until(lambda: reader.export_calls >= 1)
                    status, headers, body = await asyncio.wait_for(
                        first, timeout=2
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
                    self.assertNotIn("content-disposition", headers)
                    self.assertEqual(log.calls, 0)
                    self.assertEqual(reader.export_calls, 1)
                    self.assertEqual(app.state.control_admission.in_use, 1)

                    # Saturated export is rejected before auth-independent work;
                    # unauthenticated and malformed calls still fail earlier.
                    unauthenticated = await _asgi_request(
                        app, path="/admin/export.csv"
                    )
                    self.assertEqual(unauthenticated[0], 401)
                    bad_query = await _asgi_request(
                        app,
                        path="/admin/export.csv",
                        query=b"limit=1",
                        headers=AUTH,
                    )
                    self.assertEqual(bad_query[0], 400)

                    blocked = await _asgi_request(
                        app, path="/admin/export.csv", headers=AUTH
                    )
                    self.assertEqual(blocked[0], 503)
                    self.assertEqual(reader.export_calls, 1)
                    self.assertEqual(log.calls, 0)
            finally:
                reader.export_gate.set()
                await _settle(first)

            await _wait_until(
                lambda: app.state.control_admission.in_use == 0
            )
            # The late read may succeed, but there is no deferred continuation
            # that assembles CSV or writes an audit row.
            await asyncio.sleep(0.05)
            self.assertEqual(log.calls, 0)

            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/admin/export.csv", headers=AUTH),
                timeout=3,
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(log.calls, 1)
            self.assertEqual(reader.export_calls, 2)
            self.assertIn("content-disposition", recovered[1])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_audit_timeout_or_late_failure_never_releases_csv(self):
        reader = _ImmediateReader()
        log = _GatedLog()
        app = self.build_app(reader=reader, export_log=log)

        async def scenario():
            first = asyncio.create_task(
                _asgi_request(
                    app, path="/admin/export.csv", headers=AUTH
                )
            )
            try:
                with patch.object(server, "ADMIN_READ_TIMEOUT", 0.1):
                    await _wait_until(lambda: log.calls >= 1)
                    status, headers, body = await asyncio.wait_for(
                        first, timeout=2
                    )
                    self.assertEqual(status, 503)
                    self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
                    self.assertNotIn("content-disposition", headers)
                    self.assertEqual(log.entries, [])
                    self.assertEqual(app.state.control_admission.in_use, 1)

                    # The held audit slot blocks the next export before its read.
                    blocked = await _asgi_request(
                        app, path="/admin/export.csv", headers=AUTH
                    )
                    self.assertEqual(blocked[0], 503)
                    self.assertEqual(reader.export_calls, 1)
                    self.assertEqual(log.calls, 1)
            finally:
                log.fail = True
                log.release.set()
                await _settle(first)

            await _wait_until(
                lambda: app.state.control_admission.in_use == 0
            )
            self.assertEqual(log.entries, [])

            log.fail = False
            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/admin/export.csv", headers=AUTH),
                timeout=3,
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(log.calls, 2)
            self.assertEqual(len(log.entries), 1)
            self.assertIn("content-disposition", recovered[1])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_cancellation_past_short_deadline_never_reaches_csv_or_audit(self):
        reader = _GatedReader()
        log = _CountingLog()
        app = self.build_app(reader=reader, export_log=log)

        async def scenario():
            sent: list[dict[str, Any]] = []
            first = asyncio.create_task(
                _asgi_request(
                    app,
                    path="/admin/export.csv",
                    headers=AUTH,
                    sent_sink=sent,
                )
            )
            try:
                with patch.object(server, "ADMIN_READ_TIMEOUT", 0.1):
                    await _wait_until(lambda: reader.export_calls >= 1)
                    first.cancel()
                    await asyncio.sleep(0)
                    cancelled_at = time.monotonic()
                    self.assertFalse(first.done())
                    with self.assertRaises(asyncio.CancelledError):
                        await asyncio.wait_for(first, timeout=2)
                    # The remembered cancellation was not converted into a 503
                    # response when the shortened deadline expired; it was held
                    # past that deadline until the loop observed it.
                    self.assertGreaterEqual(
                        time.monotonic() - cancelled_at, 0.05
                    )
                    self.assertFalse(
                        [
                            m
                            for m in sent
                            if m["type"] == "http.response.start"
                        ]
                    )
                    self.assertEqual(app.state.control_admission.in_use, 1)
            finally:
                reader.export_gate.set()
                await _settle(first)

            await _wait_until(
                lambda: app.state.control_admission.in_use == 0
            )
            await asyncio.sleep(0.05)
            # The shielded read finished late, but there is no deferred
            # continuation: no audit row was written and no CSV was produced.
            self.assertEqual(reader.export_calls, 1)
            self.assertEqual(log.calls, 0)
            self.assertEqual(log.entries, [])
            self.assertFalse(
                [m for m in sent if m["type"] == "http.response.start"]
            )

            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/admin/export.csv", headers=AUTH),
                timeout=3,
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(log.calls, 1)
            self.assertEqual(reader.export_calls, 2)
            self.assertIn("content-disposition", recovered[1])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class SharedCapacityTests(ControlPlaneTestBase):
    def test_capacity_two_is_shared_across_readiness_events_and_export(self):
        store = _GatedReadyStore(Path(self.tmp.name) / "shared-ready.sqlite3")
        self.addCleanup(store.close)
        reader = _GatedReader()
        log = _CountingLog()
        app = self.build_app(
            store=store, reader=reader, export_log=log, control=2
        )

        async def scenario():
            ready_task = asyncio.create_task(
                _asgi_request(app, path="/health/ready")
            )
            events_task = asyncio.create_task(
                _asgi_request(app, path="/admin/events", headers=AUTH)
            )
            try:
                await _wait_until(
                    lambda: store.ready_calls >= 1 and reader.page_calls >= 1
                )
                # Readiness and events each hold one of the two shared slots.
                self.assertEqual(app.state.control_admission.in_use, 2)

                export = await asyncio.wait_for(
                    _asgi_request(app, path="/admin/export.csv", headers=AUTH),
                    timeout=1,
                )
                self.assertEqual(export[0], 503)
                self.assertEqual(
                    json.loads(export[2])["error"]["code"], "UNAVAILABLE"
                )
                # The saturated shared bound rejected the export before any
                # reader dispatch or audit work.
                self.assertEqual(reader.export_calls, 0)
                self.assertEqual(log.calls, 0)

                live = await asyncio.wait_for(
                    _asgi_request(app, path="/health/live"), timeout=1
                )
                self.assertEqual(live[0], 200)

                store.ready_release.set()
                reader.page_gate.set()
                ready = await asyncio.wait_for(ready_task, timeout=3)
                events = await asyncio.wait_for(events_task, timeout=3)
                self.assertEqual(ready[0], 200, ready[2])
                self.assertEqual(events[0], 200, events[2])
            finally:
                store.ready_release.set()
                reader.page_gate.set()
                reader.export_gate.set()
                await _settle(ready_task)
                await _settle(events_task)

            await _wait_until(
                lambda: app.state.control_admission.in_use == 0
            )
            recovered = await asyncio.wait_for(
                _asgi_request(app, path="/admin/export.csv", headers=AUTH),
                timeout=3,
            )
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertEqual(reader.export_calls, 1)
            self.assertEqual(log.calls, 1)
            self.assertIn("content-disposition", recovered[1])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class ConfigurationTests(ControlPlaneTestBase):
    def test_default_control_capacity_is_small_and_separate_from_chat(self):
        gateway = Gateway(
            app_key=APP_KEY,
            audit_store=self.store,
            adapters=_Adapters(),
            policy=POLICY,
            app_id=POLICY.app_id,
        )
        app = make_app(gateway=gateway, max_concurrency=5)
        self.assertEqual(app.state.control_concurrency, 2)
        self.assertEqual(app.state.control_admission.in_use, 0)
        self.assertEqual(app.state.max_concurrency, 5)

    def test_invalid_control_concurrency_bounds_fail_closed(self):
        def gateway():
            return Gateway(
                app_key=APP_KEY,
                audit_store=self.store,
                adapters=_Adapters(),
                policy=POLICY,
                app_id=POLICY.app_id,
            )

        for value in (
            0,
            -1,
            server.MAX_CONFIGURED_CONTROL_CONCURRENCY + 1,
            True,
            "2",
            2.0,
        ):
            with self.subTest(control=value):
                app = make_app(gateway=gateway(), control_concurrency=value)
                self.assertFalse(app.state.config_ready)
                self.assertEqual(
                    app.state.control_concurrency,
                    server.DEFAULT_CONTROL_CONCURRENCY,
                )

                async def scenario(app=app):
                    live = await _asgi_request(app, path="/health/live")
                    ready = await _asgi_request(app, path="/health/ready")
                    chat = await _asgi_request(
                        app,
                        method="POST",
                        path="/v1/chat/completions",
                        headers=[
                            ("content-type", "application/json"),
                            ("authorization", "Bearer " + APP_KEY),
                        ],
                        body=CHAT_BODY,
                    )
                    self.assertEqual(live[0], 200)
                    self.assertEqual(ready[0], 503)
                    self.assertEqual(
                        json.loads(ready[2])["status"], "not_ready"
                    )
                    self.assertEqual(chat[0], 503)
                    self.assertEqual(
                        json.loads(chat[2])["error"]["code"], "UNAVAILABLE"
                    )

                asyncio.run(asyncio.wait_for(scenario(), timeout=5))

        accepted = make_app(
            gateway=gateway(),
            control_concurrency=server.MAX_CONFIGURED_CONTROL_CONCURRENCY,
        )
        self.assertTrue(accepted.state.config_ready)
        self.assertEqual(
            accepted.state.control_concurrency,
            server.MAX_CONFIGURED_CONTROL_CONCURRENCY,
        )


if __name__ == "__main__":
    unittest.main()
