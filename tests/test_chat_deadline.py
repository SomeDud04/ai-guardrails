"""Deterministic ASGI tests for the bounded chat work deadline.

Every synchronous gateway call runs in a locally gated helper thread.  No model,
guard artifact or external endpoint is contacted.  The gates prove that the HTTP
deadline is independent of the running worker: a timed-out response never waits
for the thread, never releases a late result, and the chat admission slot stays
held until the real thread finishes.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

import nasi_lemak.server as server
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway
from nasi_lemak.server import make_app
from tests.test_server import JSON_BODY, RecordingAdapters, TEST_KEY

AUTH_HEADERS = [
    ("content-type", "application/json"),
    ("authorization", "Bearer " + TEST_KEY),
]
BODY = json.dumps(JSON_BODY).encode()


class GatedChatAdapters(RecordingAdapters):
    """Local adapters with independent input-guard and output-guard gates."""

    def __init__(self) -> None:
        super().__init__()
        self.attack_gate: threading.Event | None = None
        self.attack_started = threading.Event()
        self.output_gate: threading.Event | None = None
        self.output_started = threading.Event()

    def scan_attack(self, text: str) -> Any:
        self.attack_started.set()
        gate = self.attack_gate
        if gate is not None:
            gate.wait(10)
        return super().scan_attack(text)

    def scan_output(self, text: str) -> Any:
        self.output_started.set()
        gate = self.output_gate
        if gate is not None:
            gate.wait(10)
        return super().scan_output(text)


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
    method: str = "POST",
    path: str = "/v1/chat/completions",
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
        "query_string": b"",
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


def _response_starts(sent: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in sent if item["type"] == "http.response.start"]


def _body_bytes(sent: list[dict[str, Any]]) -> bytes:
    return b"".join(item.get("body", b"") for item in sent)


class ChatDeadlineTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapters = GatedChatAdapters()
        self.adapters.generated = "LATE_SYNTHETIC_OUTPUT"
        self.store = SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3")
        self.addCleanup(self.store.close)

    def build_app(self, *, timeout: float = 0.1, concurrency: int = 1):
        gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=self.store,
            adapters=self.adapters,
        )
        return make_app(
            gateway=gateway,
            max_concurrency=concurrency,
            chat_work_timeout=timeout,
        )

    async def chat(self, app: Any, *, sent_sink: list[dict[str, Any]] | None = None):
        return await _asgi_request(
            app, headers=AUTH_HEADERS, body=BODY, sent_sink=sent_sink
        )


class StalledGuardTests(ChatDeadlineTestBase):
    def test_stalled_input_guard_returns_503_without_inference_and_late_work_continues(
        self,
    ) -> None:
        gate = threading.Event()
        self.adapters.attack_gate = gate
        app = self.build_app(timeout=0.1)

        async def scenario():
            sent: list[dict[str, Any]] = []
            first = asyncio.create_task(self.chat(app, sent_sink=sent))
            try:
                await _wait_until(lambda: self.adapters.attack_started.is_set())
                status, _, body = await asyncio.wait_for(first, timeout=2)
                self.assertEqual(status, 503)
                error = json.loads(body)["error"]
                self.assertEqual(error["code"], "UNAVAILABLE")
                self.assertTrue(error["request_id"].startswith("req_"))
                self.assertNotIn("choices", json.loads(body))
                # No inference may start while the input guard is stalled.
                self.assertEqual(self.adapters.generate_calls, 0)
                self.assertTrue(app.state.sem.locked())
                live = await asyncio.wait_for(
                    _asgi_request(app, method="GET", path="/health/live"),
                    timeout=1,
                )
                self.assertEqual(live[0], 200)
            finally:
                gate.set()
                await _settle(first)

            await _wait_until(lambda: not app.state.sem.locked())
            # The native pipeline may still finish after the HTTP deadline, but
            # its late result is never released to this client.
            self.assertEqual(self.adapters.generate_calls, 1)
            self.assertEqual(len(_response_starts(sent)), 1)
            self.assertNotIn(b"LATE_SYNTHETIC_OUTPUT", _body_bytes(sent))

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_stalled_output_guard_never_releases_buffered_output(self) -> None:
        gate = threading.Event()
        self.adapters.output_gate = gate
        app = self.build_app(timeout=0.1)

        async def scenario():
            sent: list[dict[str, Any]] = []
            first = asyncio.create_task(self.chat(app, sent_sink=sent))
            try:
                await _wait_until(lambda: self.adapters.output_started.is_set())
                status, _, body = await asyncio.wait_for(first, timeout=2)
                self.assertEqual(status, 503)
                self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
                self.assertNotIn("choices", json.loads(body))
                self.assertEqual(self.adapters.output_inputs, [])
                self.assertTrue(app.state.sem.locked())
            finally:
                gate.set()
                await _settle(first)

            await _wait_until(lambda: not app.state.sem.locked())
            self.assertEqual(self.adapters.output_inputs, ["LATE_SYNTHETIC_OUTPUT"])
            self.assertEqual(len(_response_starts(sent)), 1)
            self.assertFalse(
                [
                    item
                    for item in sent
                    if b"LATE_SYNTHETIC_OUTPUT" in item.get("body", b"")
                ]
            )

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class GenerationDeadlineTests(ChatDeadlineTestBase):
    def test_generation_timeout_late_success_is_not_released_and_recovers(self) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        app = self.build_app(timeout=0.1)

        async def scenario():
            sent: list[dict[str, Any]] = []
            first = asyncio.create_task(self.chat(app, sent_sink=sent))
            try:
                await _wait_until(lambda: self.adapters.generate_started.is_set())
                status, _, body = await asyncio.wait_for(first, timeout=2)
                self.assertEqual(status, 503)
                self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
                self.assertEqual(self.adapters.generate_calls, 1)
                self.assertTrue(app.state.sem.locked())
                # The timed-out worker is still tracked by a strong reference.
                self.assertEqual(len(app.state.chat_tasks), 1)
                self.assertFalse(next(iter(app.state.chat_tasks)).done())
            finally:
                gate.set()
                self.adapters.generate_gate = None
                await _settle(first)

            await _wait_until(lambda: not app.state.sem.locked())
            self.assertEqual(app.state.chat_tasks, set())
            self.assertEqual(len(_response_starts(sent)), 1)
            self.assertNotIn(b"LATE_SYNTHETIC_OUTPUT", _body_bytes(sent))

            recovered = await asyncio.wait_for(self.chat(app), timeout=3)
            self.assertEqual(recovered[0], 200, recovered[2])
            self.assertIn(b"LATE_SYNTHETIC_OUTPUT", recovered[2])
            self.assertEqual(self.adapters.generate_calls, 2)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_generation_timeout_late_error_is_consumed_and_capacity_recovers_once(
        self,
    ) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        self.adapters.generate_error = RuntimeError("SECRET_LATE_MODEL_FAILURE")
        app = self.build_app(timeout=0.1, concurrency=1)

        async def scenario():
            sent: list[dict[str, Any]] = []
            first = asyncio.create_task(self.chat(app, sent_sink=sent))
            try:
                await _wait_until(lambda: self.adapters.generate_started.is_set())
                status, _, body = await asyncio.wait_for(first, timeout=2)
                self.assertEqual(status, 503)
                self.assertNotIn(b"SECRET", body)
                self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
                self.assertTrue(app.state.sem.locked())
                self.assertEqual(len(app.state.chat_tasks), 1)
            finally:
                # Release only the gate; the injected error must stay in place
                # until the worker has actually resumed and failed.  Otherwise
                # this test could silently exercise a late success instead.
                gate.set()
                self.adapters.generate_gate = None
                await _settle(first)
                # Even if an assertion above fails, wait for the real thread to
                # finish before the temporary store is closed.
                await _wait_until(lambda: not app.state.sem.locked(), timeout=8)

            # The late failure never reached the output guard or the response,
            # and the tracked task is dropped only after real completion.
            self.assertEqual(self.adapters.output_inputs, [])
            self.assertEqual(app.state.chat_tasks, set())
            # Exactly one release: the chat semaphore is fully restored, not
            # over-released by either the deadline path or the done callback.
            self.assertEqual(app.state.sem._value, 1)
            self.assertEqual(len(_response_starts(sent)), 1)

            # Normal recovery after the retained error is cleared.
            self.adapters.generate_error = None
            for _ in range(2):
                recovered = await asyncio.wait_for(self.chat(app), timeout=3)
                self.assertEqual(recovered[0], 200, recovered[2])
                self.assertEqual(app.state.sem._value, 1)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class CancellationAndOverloadTests(ChatDeadlineTestBase):
    def test_repeated_cancellation_past_shortened_deadline_sends_no_response(
        self,
    ) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        # Long enough that the cancellations land before the deadline even when
        # a loaded machine takes over a second to reach generation.
        deadline = 3.0
        app = self.build_app(timeout=deadline)

        async def scenario():
            sent: list[dict[str, Any]] = []
            started_at = time.monotonic()
            first = asyncio.create_task(self.chat(app, sent_sink=sent))
            try:
                await _wait_until(lambda: self.adapters.generate_started.is_set())
                first.cancel()
                await asyncio.sleep(0)
                first.cancel()
                await asyncio.sleep(0)
                self.assertFalse(first.done())
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(first, timeout=deadline + 5)
                # The remembered cancellation was held until the original
                # deadline instead of being converted into a 503 response.
                # Measured from the request start, because the time the worker
                # takes to reach generation depends on machine load.
                self.assertGreaterEqual(time.monotonic() - started_at, deadline * 0.9)
                self.assertEqual(_response_starts(sent), [])
                self.assertTrue(app.state.sem.locked())
            finally:
                gate.set()
                self.adapters.generate_gate = None
                await _settle(first)

            await _wait_until(lambda: not app.state.sem.locked())
            self.assertEqual(_response_starts(sent), [])
            recovered = await asyncio.wait_for(self.chat(app), timeout=3)
            self.assertEqual(recovered[0], 200, recovered[2])

        asyncio.run(asyncio.wait_for(scenario(), timeout=30))

    def test_overload_rejects_without_extra_dispatch_while_worker_runs(self) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        app = self.build_app(timeout=0.1)

        async def scenario():
            first = asyncio.create_task(self.chat(app))
            try:
                await _wait_until(lambda: self.adapters.generate_started.is_set())
                second = await asyncio.wait_for(self.chat(app), timeout=1)
                self.assertEqual(second[0], 503)
                self.assertEqual(
                    json.loads(second[2])["error"]["code"], "UNAVAILABLE"
                )
                self.assertEqual(self.adapters.generate_calls, 1)
                self.assertEqual(len(self.adapters.attack_inputs), 1)
                first_result = await asyncio.wait_for(first, timeout=2)
                self.assertEqual(first_result[0], 503)
            finally:
                gate.set()
                self.adapters.generate_gate = None
                await _settle(first)

            await _wait_until(lambda: not app.state.sem.locked())
            recovered = await asyncio.wait_for(self.chat(app), timeout=3)
            self.assertEqual(recovered[0], 200, recovered[2])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class ConfigurationTests(ChatDeadlineTestBase):
    def test_invalid_chat_work_timeout_fails_closed_with_safe_default(self) -> None:
        invalid = (
            True,
            0,
            -1,
            float("nan"),
            float("inf"),
            server.MAX_CONFIGURED_CHAT_WORK_TIMEOUT + 1,
            "60",
            None,
        )
        for value in invalid:
            with self.subTest(chat_work_timeout=value):
                app = self.build_app(timeout=value)
                self.assertFalse(app.state.config_ready)
                self.assertEqual(
                    app.state.chat_work_timeout,
                    server.DEFAULT_CHAT_WORK_TIMEOUT,
                )

                async def scenario(app=app):
                    live = await _asgi_request(app, method="GET", path="/health/live")
                    ready = await _asgi_request(app, method="GET", path="/health/ready")
                    chat = await self.chat(app)
                    self.assertEqual(live[0], 200)
                    self.assertEqual(ready[0], 503)
                    self.assertEqual(json.loads(ready[2])["status"], "not_ready")
                    self.assertEqual(chat[0], 503)
                    self.assertEqual(
                        json.loads(chat[2])["error"]["code"], "UNAVAILABLE"
                    )
                    self.assertEqual(self.adapters.generate_calls, 0)

                asyncio.run(asyncio.wait_for(scenario(), timeout=5))

    def test_default_and_maximum_chat_work_timeout_are_accepted(self) -> None:
        default_app = self.build_app(timeout=server.DEFAULT_CHAT_WORK_TIMEOUT)
        self.assertTrue(default_app.state.config_ready)
        self.assertEqual(default_app.state.chat_work_timeout, 60.0)
        self.assertEqual(server.DEFAULT_CHAT_WORK_TIMEOUT, 60.0)
        self.assertEqual(server.MAX_CONFIGURED_CHAT_WORK_TIMEOUT, 300.0)

        max_app = self.build_app(timeout=server.MAX_CONFIGURED_CHAT_WORK_TIMEOUT)
        self.assertTrue(max_app.state.config_ready)
        self.assertEqual(max_app.state.chat_work_timeout, 300.0)

        # The module-level production app is protected by the safe default.
        self.assertEqual(
            server.app.state.chat_work_timeout, server.DEFAULT_CHAT_WORK_TIMEOUT
        )

    def test_normal_chat_is_unchanged(self) -> None:
        app = self.build_app(timeout=server.DEFAULT_CHAT_WORK_TIMEOUT)

        async def scenario():
            status, _, body = await asyncio.wait_for(self.chat(app), timeout=3)
            self.assertEqual(status, 200, body)
            payload = json.loads(body)
            self.assertEqual(payload["object"], "chat.completion")
            self.assertEqual(payload["model"], "pilot-local")
            self.assertTrue(payload["id"].startswith("req_"))
            self.assertEqual(payload["choices"][0]["message"]["content"],
                             "LATE_SYNTHETIC_OUTPUT")

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


if __name__ == "__main__":
    unittest.main()
