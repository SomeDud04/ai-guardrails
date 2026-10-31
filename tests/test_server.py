"""Behavioral HTTP tests for the FastAPI gateway server.

These tests use the real ASGI application with a real SQLite audit store and
local recording adapters.  They do not contact an external model, guard or
infrastructure endpoint.
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

from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, MemoryAdapters
from nasi_lemak.server import _TlsTerminatedAtProxy, make_app

TEST_KEY = "test-app-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
JSON_BODY = {
    "model": "pilot-local",
    "messages": [{"role": "user", "content": "Email person@example.com"}],
}


class RecordingAdapters:
    """Test-only local adapters; no network or cloud access."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.token_inputs: list[str] = []
        self.attack_inputs: list[str] = []
        self.generate_inputs: list[list[dict[str, str]]] = []
        self.output_inputs: list[str] = []
        self.generate_calls = 0
        self.generated = "Safe synthetic answer."
        self.attack_result: Any = {"decision": "allow"}
        self.output_result: Any = {"safe": True}
        self.token_error: Exception | None = None
        self.attack_error: Exception | None = None
        self.generate_error: Exception | None = None
        self.output_error: Exception | None = None
        self.generate_gate: threading.Event | None = None
        self.generate_started = threading.Event()

    def count_tokens(self, serialized: str) -> int:
        with self._lock:
            self.token_inputs.append(serialized)
        if self.token_error:
            raise self.token_error
        return max(1, len(serialized.split()))

    def scan_attack(self, text: str) -> Any:
        with self._lock:
            self.attack_inputs.append(text)
        if self.attack_error:
            raise self.attack_error
        return self.attack_result

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        with self._lock:
            self.generate_inputs.append([dict(message) for message in messages])
            self.generate_calls += 1
        self.generate_started.set()
        gate = self.generate_gate
        if gate is not None:
            gate.wait(10)
        if self.generate_error:
            raise self.generate_error
        return self.generated

    def scan_output(self, text: str) -> Any:
        with self._lock:
            self.output_inputs.append(text)
        if self.output_error:
            raise self.output_error
        return self.output_result


class BlockingReadyAuditStore(SqliteAuditStore):
    def __init__(self, path: str | Path) -> None:
        super().__init__(path)
        self.ready_entered = threading.Event()
        self.ready_release = threading.Event()

    def ready(self) -> bool:
        self.ready_entered.set()
        self.ready_release.wait(5)
        return True


class ClosingAuditStore(SqliteAuditStore):
    def __init__(self, path: str | Path) -> None:
        super().__init__(path)
        self.closed = threading.Event()

    def close(self) -> None:
        self.closed.set()


class FalseReadyAuditStore(SqliteAuditStore):
    def ready(self) -> bool:
        return False


class ExplodingGateway(Gateway):
    def handle(self, method, path, headers, body):
        raise RuntimeError("SECRET_DSN_AND_CREDENTIALS")


async def asgi_request(
    app: Any,
    *,
    method: str = "POST",
    path: str = "/v1/chat/completions",
    headers: list[tuple[str, str]] | None = None,
    body_parts: list[bytes] | None = None,
    delay: float = 0.0,
) -> tuple[int, dict[str, str], bytes]:
    """Call the ASGI app directly to control chunking and timing."""
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or [])]
    parts = list(body_parts) if body_parts is not None else [b""]
    index = 0
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal index
        if index >= len(parts):
            return {"type": "http.disconnect"}
        chunk = parts[index]
        index += 1
        if delay:
            await asyncio.sleep(delay)
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": index < len(parts),
        }

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
    status = next(item["status"] for item in sent if item["type"] == "http.response.start")
    body = b"".join(item.get("body", b"") for item in sent if item["type"] == "http.response.body")
    response_headers = {
        key.decode().lower(): value.decode()
        for item in sent
        if item["type"] == "http.response.start"
        for key, value in item.get("headers", [])
    }
    return status, response_headers, body


class ServerTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapters = RecordingAdapters()
        self.gateway = self.make_gateway()
        self.app = make_app(gateway=self.gateway)
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

    def make_gateway(
        self,
        adapters: Any = None,
        *,
        app_key: str | None = TEST_KEY,
        store: Any = None,
        fail_audit_stage: str | None = None,
    ) -> Gateway:
        gateway = Gateway(
            app_key=app_key,
            audit_store=store or SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            adapters=self.adapters if adapters is None else adapters,
        )
        gateway.fail_audit_stage = fail_audit_stage
        return gateway

    def make_client(self, app: Any) -> TestClient:
        client = TestClient(app)
        self.addCleanup(client.close)
        return client

    def post(self, body: Any = None, *, headers: Any = None, client: TestClient | None = None):
        client = client or self.client
        return client.post(
            "/v1/chat/completions",
            json=JSON_BODY if body is None else body,
            headers=AUTH if headers is None else headers,
        )


class SuccessAndAuthenticationTests(ServerTestBase):
    def test_success_uses_core_request_id_and_masks_input_before_generation(self) -> None:
        response = self.post()

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["object"], "chat.completion")
        self.assertEqual(payload["model"], "pilot-local")
        self.assertTrue(payload["id"].startswith("req_"))

        # Only masked text reaches generation.
        self.assertEqual(
            self.adapters.generate_inputs[0][0]["content"],
            "Email [EMAIL]",
        )
        self.assertIn("person@example.com", self.adapters.attack_inputs[0])
        self.assertEqual(self.adapters.generate_calls, 1)

        events = self.gateway.audit_events()
        self.assertEqual([event["event_type"] for event in events], ["request_started", "request_completed"])
        self.assertEqual({event["request_id"] for event in events}, {payload["id"]})
        self.assertEqual(events[-1]["decision"], "allowed")

    def test_missing_wrong_and_duplicate_authorization_headers_are_rejected_without_calls(self) -> None:
        cases = [
            {},
            {"Authorization": "Bearer wrong"},
            {"Authorization": TEST_KEY},
            [(name, value) for name, value in AUTH.items()] + [(name, value) for name, value in AUTH.items()],
        ]
        for headers in cases:
            with self.subTest(headers=headers):
                response = self.post(headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["error"]["code"], "UNAUTHORIZED")
        self.assertEqual(self.adapters.generate_calls, 0)
        self.assertEqual(self.adapters.attack_inputs, [])
        self.assertEqual(self.gateway.audit_events(), [])

    def test_duplicate_authorization_headers_are_rejected_as_two_headers(self) -> None:
        status, _, body = asyncio.run(
            asgi_request(
                self.app,
                headers=[
                    ("content-type", "application/json"),
                    ("authorization", "Bearer " + TEST_KEY),
                    ("authorization", "Bearer " + TEST_KEY),
                ],
                body_parts=[json.dumps(JSON_BODY).encode()],
            )
        )
        self.assertEqual(status, 401)
        self.assertEqual(json.loads(body)["error"]["code"], "UNAUTHORIZED")


class StrictRequestTests(ServerTestBase):
    def test_content_type_invalid_utf8_invalid_json_duplicate_keys_and_nan_are_rejected(self) -> None:
        base_headers = {"Authorization": "Bearer " + TEST_KEY}
        cases = [
            ("text/plain", b"{}"),
            (None, b"{}"),
            ("application/json", b"\xff\xfe"),
            ("application/json", b"{not json"),
            (
                "application/json",
                b'{"model":"pilot-local","model":"pilot-local","messages":[{"role":"user","content":"hi"}]}',
            ),
            (
                "application/json",
                b'{"model":"pilot-local","max_tokens":NaN,"messages":[{"role":"user","content":"hi"}]}',
            ),
            ("application/json", b"[]"),
        ]
        for content_type, raw in cases:
            with self.subTest(content_type=content_type, raw=raw[:20]):
                headers = dict(base_headers)
                if content_type is not None:
                    headers["Content-Type"] = content_type
                response = self.client.post("/v1/chat/completions", content=raw, headers=headers)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
                self.assertNotIn("detail", response.json())
        self.assertEqual(self.adapters.generate_calls, 0)

    def test_unknown_fields_and_invalid_shapes_are_generic_400(self) -> None:
        cases = [
            {**JSON_BODY, "extra": True},
            {"model": "not-the-alias", "messages": JSON_BODY["messages"]},
            {"model": "pilot-local", "messages": []},
            {"model": "pilot-local", "messages": [{"role": "user", "content": 5}]},
            {"model": "pilot-local", "messages": [{"role": "user", "content": "hi"}], "stream_options": {}},
        ]
        for body in cases:
            with self.subTest(body=body):
                response = self.post(body)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
                self.assertNotIn("detail", response.json())
        self.assertEqual(self.adapters.generate_calls, 0)

    def test_unsupported_routes_paths_and_methods_return_generic_envelopes(self) -> None:
        cases = [
            ("get", "/v1/chat/completions", 405),
            ("post", "/health/live", 405),
            ("get", "/unknown", 404),
            ("post", "/v1/chat/completions/", 404),
        ]
        for method, path, expected in cases:
            with self.subTest(method=method, path=path):
                response = self.client.request(method, path)
                self.assertEqual(response.status_code, expected)
                payload = response.json()
                self.assertEqual(payload["error"]["code"], "INVALID_REQUEST")
                self.assertNotIn("detail", payload)

    def test_docs_openapi_and_debug_routes_are_absent(self) -> None:
        for path in ("/docs", "/redoc", "/openapi.json", "/v1/chat/completions/"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")


class StreamedBodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapters = RecordingAdapters()
        self.gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            adapters=self.adapters,
        )

    def _app(self, **kwargs):
        return make_app(gateway=self.gateway, **kwargs)

    def test_streamed_body_over_limit_with_missing_content_length(self) -> None:
        app = self._app(max_body_bytes=128, body_read_timeout=2)
        status, _, body = asyncio.run(
            asgi_request(
                app,
                headers=[
                    ("content-type", "application/json"),
                    ("authorization", "Bearer " + TEST_KEY),
                ],
                body_parts=[b"x" * 100, b"x" * 100],
            )
        )
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body)["error"]["code"], "INPUT_LIMIT")
        self.assertEqual(self.adapters.generate_calls, 0)

    def test_streamed_body_over_limit_with_false_content_length(self) -> None:
        app = self._app(max_body_bytes=128, body_read_timeout=2)
        status, _, body = asyncio.run(
            asgi_request(
                app,
                headers=[
                    ("content-type", "application/json"),
                    ("content-length", "5"),
                    ("authorization", "Bearer " + TEST_KEY),
                ],
                body_parts=[b"x" * 100, b"x" * 100],
            )
        )
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body)["error"]["code"], "INPUT_LIMIT")

    def test_body_read_deadline_returns_503_without_calling_work(self) -> None:
        app = self._app(max_body_bytes=4096, body_read_timeout=0.05)
        started = time.monotonic()
        status, _, body = asyncio.run(
            asyncio.wait_for(
                asgi_request(
                    app,
                    headers=[
                        ("content-type", "application/json"),
                        ("authorization", "Bearer " + TEST_KEY),
                    ],
                    body_parts=[b'{"model":', b'"pilot-local"}'],
                    delay=0.2,
                ),
                timeout=2,
            )
        )
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
        self.assertEqual(self.adapters.generate_calls, 0)


class OperationalEnvironmentTests(unittest.TestCase):
    """Operational bounds: explicit argument > env > built-in default."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            adapters=RecordingAdapters(),
        )

    def _app(self, environ, **kwargs):
        return make_app(gateway=self.gateway, environ=environ, **kwargs)

    def test_environment_sets_bounds_when_no_argument_is_passed(self) -> None:
        app = self._app(
            {
                "NASI_LEMAK_CHAT_WORK_TIMEOUT": "30",
                "NASI_LEMAK_CHAT_MAX_CONCURRENCY": "2",
                "NASI_LEMAK_CONTROL_CONCURRENCY": "3",
                "NASI_LEMAK_MAX_BODY_BYTES": "2048",
                "NASI_LEMAK_BODY_READ_TIMEOUT": "1.5",
            }
        )
        self.assertTrue(app.state.config_ready)
        self.assertEqual(app.state.chat_work_timeout, 30.0)
        self.assertEqual(app.state.max_concurrency, 2)
        self.assertEqual(app.state.control_concurrency, 3)
        self.assertEqual(app.state.max_body_bytes, 2048)
        self.assertEqual(app.state.body_read_timeout, 1.5)
        self.assertEqual(
            app.state.operational,
            {
                "chat_work_timeout": 30.0,
                "max_concurrency": 2,
                "control_concurrency": 3,
                "max_body_bytes": 2048,
                "body_read_timeout": 1.5,
            },
        )

    def test_explicit_arguments_win_over_environment(self) -> None:
        app = self._app(
            {
                "NASI_LEMAK_CHAT_WORK_TIMEOUT": "30",
                "NASI_LEMAK_CHAT_MAX_CONCURRENCY": "2",
                "NASI_LEMAK_CONTROL_CONCURRENCY": "3",
                "NASI_LEMAK_MAX_BODY_BYTES": "2048",
                "NASI_LEMAK_BODY_READ_TIMEOUT": "1.5",
            },
            chat_work_timeout=45.0,
            max_concurrency=4,
            control_concurrency=5,
            max_body_bytes=4096,
            body_read_timeout=2.5,
        )
        self.assertTrue(app.state.config_ready)
        self.assertEqual(app.state.chat_work_timeout, 45.0)
        self.assertEqual(app.state.max_concurrency, 4)
        self.assertEqual(app.state.control_concurrency, 5)
        self.assertEqual(app.state.max_body_bytes, 4096)
        self.assertEqual(app.state.body_read_timeout, 2.5)

    def test_explicit_arguments_ignore_invalid_environment_values(self) -> None:
        app = self._app(
            {
                "NASI_LEMAK_CHAT_WORK_TIMEOUT": "abc",
                "NASI_LEMAK_CHAT_MAX_CONCURRENCY": "0",
                "NASI_LEMAK_CONTROL_CONCURRENCY": "0",
                "NASI_LEMAK_MAX_BODY_BYTES": "0",
                "NASI_LEMAK_BODY_READ_TIMEOUT": "0",
            },
            chat_work_timeout=45.0,
            max_concurrency=4,
            control_concurrency=5,
            max_body_bytes=4096,
            body_read_timeout=2.5,
        )
        self.assertTrue(app.state.config_ready)
        self.assertEqual(app.state.chat_work_timeout, 45.0)
        self.assertEqual(app.state.max_concurrency, 4)
        self.assertEqual(app.state.control_concurrency, 5)
        self.assertEqual(app.state.max_body_bytes, 4096)
        self.assertEqual(app.state.body_read_timeout, 2.5)

    def test_unset_environment_keeps_built_in_defaults(self) -> None:
        app = self._app({})
        self.assertTrue(app.state.config_ready)
        self.assertEqual(app.state.chat_work_timeout, 60.0)
        self.assertEqual(app.state.max_concurrency, 5)
        self.assertEqual(app.state.control_concurrency, 2)
        self.assertEqual(app.state.max_body_bytes, 64 * 1024)
        self.assertEqual(app.state.body_read_timeout, 5.0)

    def test_invalid_environment_is_not_ready_and_never_echoed(self) -> None:
        cases = {
            "NASI_LEMAK_CHAT_WORK_TIMEOUT": ("0", "abc", "nan", "301"),
            "NASI_LEMAK_CHAT_MAX_CONCURRENCY": ("0", "abc", "257"),
            "NASI_LEMAK_CONTROL_CONCURRENCY": ("0", "abc", "65"),
            "NASI_LEMAK_MAX_BODY_BYTES": ("1023", "abc", "4194305"),
            "NASI_LEMAK_BODY_READ_TIMEOUT": ("0", "abc", "61"),
        }
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    app = self._app({name: value})
                    self.assertFalse(app.state.config_ready)
                    client = TestClient(app)
                    self.addCleanup(client.close)
                    self.assertEqual(client.get("/health/live").status_code, 200)
                    ready = client.get("/health/ready")
                    self.assertEqual(ready.status_code, 503)
                    self.assertEqual(ready.json()["status"], "not_ready")
                    self.assertNotIn("NASI_LEMAK", ready.text)
                    self.assertNotIn(value, ready.text)

    def test_defaults_apply_to_invalid_environment_values(self) -> None:
        app = self._app({"NASI_LEMAK_CHAT_WORK_TIMEOUT": "abc"})
        self.assertFalse(app.state.config_ready)
        self.assertEqual(app.state.chat_work_timeout, 60.0)
        self.assertEqual(app.state.max_concurrency, 5)
        self.assertEqual(app.state.control_concurrency, 2)
        self.assertEqual(app.state.max_body_bytes, 64 * 1024)
        self.assertEqual(app.state.body_read_timeout, 5.0)


class DefaultConfigurationTests(unittest.TestCase):
    def _client(self, app):
        client = TestClient(app)
        self.addCleanup(client.close)
        return client

    def test_missing_config_is_live_but_not_ready_and_chat_fails_closed(self) -> None:
        app = make_app(environ={})
        client = self._client(app)
        self.assertEqual(client.get("/health/live").status_code, 200)
        self.assertEqual(client.get("/health/ready").status_code, 503)
        self.assertEqual(
            client.post(
                "/v1/chat/completions",
                json=JSON_BODY,
                headers={"Authorization": "Bearer any"},
            ).status_code,
            503,
        )
        self.assertIsNone(app.state.gateway.adapters)
        self.assertNotIsInstance(app.state.gateway.adapters, MemoryAdapters)

    def test_configured_app_key_without_audit_or_adapters_still_fails_closed(self) -> None:
        app = make_app(environ={"NASI_LEMAK_APP_KEY_DIGEST": "a" * 64})
        client = self._client(app)
        self.assertEqual(client.get("/health/live").status_code, 200)
        self.assertEqual(client.get("/health/ready").status_code, 503)
        response = client.post(
            "/v1/chat/completions",
            json=JSON_BODY,
            headers={"Authorization": "Bearer any"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")

    def test_invalid_secret_file_and_numeric_config_do_not_crash_startup(self) -> None:
        cases = [
            {"NASI_LEMAK_APP_KEY_DIGEST_FILE": str(Path(tempfile.gettempdir()) / "missing-nasi-secret")},
            {"NASI_LEMAK_APP_KEY_DIGEST": "not-a-digest"},
        ]
        for environ in cases:
            with self.subTest(environ=environ):
                app = make_app(environ=environ)
                client = self._client(app)
                self.assertEqual(client.get("/health/live").status_code, 200)
                self.assertEqual(client.get("/health/ready").status_code, 503)

        for kwargs in (
            {"max_body_bytes": 0},
            {"max_body_bytes": 4 * 1024 * 1024 + 1},
            {"body_read_timeout": float("nan")},
            {"body_read_timeout": float("inf")},
            {"body_read_timeout": -1},
            {"max_concurrency": 0},
            {"max_concurrency": True},
            {"max_concurrency": 257},
        ):
            with self.subTest(kwargs=kwargs):
                app = make_app(environ={}, **kwargs)
                client = self._client(app)
                self.assertEqual(client.get("/health/live").status_code, 200)
                self.assertEqual(client.get("/health/ready").status_code, 503)

    def test_readiness_validates_all_adapter_callables_and_audit_ready(self) -> None:
        class IncompleteAdapters:
            def count_tokens(self, serialized):
                return 1

            def scan_attack(self, text):
                return {"decision": "allow"}

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(tmp.name) / "audit.sqlite3"),
            adapters=IncompleteAdapters(),
        )
        app = make_app(gateway=gateway)
        client = self._client(app)
        self.assertEqual(client.get("/health/ready").status_code, 503)
        response = client.post("/v1/chat/completions", json=JSON_BODY, headers=AUTH)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")

        false_ready = Gateway(
            app_key=TEST_KEY,
            audit_store=FalseReadyAuditStore(Path(tmp.name) / "audit2.sqlite3"),
            adapters=RecordingAdapters(),
        )
        client2 = self._client(make_app(gateway=false_ready))
        self.assertEqual(client2.get("/health/ready").status_code, 503)

    def test_invalid_app_key_configuration_is_not_ready(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gateway = Gateway(
            app_key=None,
            audit_store=SqliteAuditStore(Path(tmp.name) / "audit.sqlite3"),
            adapters=RecordingAdapters(),
        )
        client = self._client(make_app(gateway=gateway))
        self.assertEqual(client.get("/health/ready").status_code, 503)
        self.assertEqual(client.post("/v1/chat/completions", json=JSON_BODY, headers=AUTH).status_code, 503)


class GuardAuditAndFailureTests(ServerTestBase):
    def test_initial_audit_failure_returns_503_before_generation(self) -> None:
        gateway = self.make_gateway(fail_audit_stage="initial")
        client = self.make_client(make_app(gateway=gateway))
        response = self.post(client=client)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertEqual(self.adapters.generate_calls, 0)

    def test_terminal_audit_failure_withholds_generated_result(self) -> None:
        gateway = self.make_gateway(fail_audit_stage="terminal")
        client = self.make_client(make_app(gateway=gateway))
        response = self.post(client=client)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("choices", response.json())
        self.assertEqual(self.adapters.generate_calls, 1)
        events = gateway.audit_events()
        self.assertEqual(events[0]["event_type"], "request_started")
        self.assertEqual(events[-1]["event_type"], "request_started")

    def test_output_guard_block_returns_403_without_result(self) -> None:
        self.adapters.output_result = {"safe": False}
        response = self.post()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "POLICY_BLOCK")
        self.assertNotIn("choices", response.json())
        self.assertEqual(self.adapters.generate_calls, 1)

    def test_attack_block_returns_403_before_generation(self) -> None:
        self.adapters.attack_result = {"decision": "block"}
        response = self.post()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(self.adapters.generate_calls, 0)

    def test_adapter_exceptions_fail_closed_without_raw_details(self) -> None:
        cases = [
            ("token_error", RuntimeError("SECRET_TOKENIZER")),
            ("attack_error", RuntimeError("SECRET_ATTACK")),
            ("generate_error", RuntimeError("SECRET_MODEL")),
            ("output_error", RuntimeError("SECRET_OUTPUT")),
        ]
        for attribute, error in cases:
            with self.subTest(attribute=attribute):
                adapters = RecordingAdapters()
                setattr(adapters, attribute, error)
                gateway = self.make_gateway(adapters=adapters)
                client = self.make_client(make_app(gateway=gateway))
                response = self.post(client=client)
                self.assertEqual(response.status_code, 503)
                self.assertNotIn("SECRET", response.text)
                self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")

    def test_unexpected_gateway_exception_is_generic(self) -> None:
        gateway = ExplodingGateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "explode.sqlite3"),
            adapters=self.adapters,
        )
        client = self.make_client(make_app(gateway=gateway))
        response = self.post(client=client)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("SECRET", response.text)
        self.assertNotIn("Traceback", response.text)

    def test_shutdown_closes_audit_store(self) -> None:
        store = ClosingAuditStore(Path(self.tmp.name) / "closing.sqlite3")
        gateway = self.make_gateway(store=store)
        app = make_app(gateway=gateway)
        with TestClient(app):
            self.assertFalse(store.closed.is_set())
        self.assertTrue(store.closed.wait(2))


class ConcurrencyAndReadinessTests(ServerTestBase):
    def test_overload_rejects_without_queue_and_slot_waits_for_cancelled_worker(self) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        app = make_app(gateway=self.gateway, max_concurrency=1)
        headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer " + TEST_KEY),
        ]
        body = [json.dumps(JSON_BODY).encode()]

        async def scenario():
            first = asyncio.create_task(asgi_request(app, headers=headers, body_parts=body))
            for _ in range(100):
                if self.adapters.generate_started.is_set():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(self.adapters.generate_started.is_set())

            second = await asgi_request(app, headers=headers, body_parts=body)
            self.assertEqual(second[0], 503)
            self.assertEqual(json.loads(second[2])["error"]["code"], "UNAVAILABLE")

            # Repeated client cancellation must not release the slot while the
            # synchronous worker is still blocked.
            first.cancel()
            await asyncio.sleep(0)
            first.cancel()
            await asyncio.sleep(0)
            self.assertFalse(first.done())
            blocked = await asgi_request(app, headers=headers, body_parts=body)
            self.assertEqual(blocked[0], 503)

            gate.set()
            with self.assertRaises(asyncio.CancelledError):
                await first
            await asyncio.sleep(0.05)
            after = await asgi_request(app, headers=headers, body_parts=body)
            self.assertEqual(after[0], 200, after[2])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_body_reader_capacity_is_bounded_before_streaming(self) -> None:
        app = make_app(gateway=self.gateway, max_concurrency=1, body_read_timeout=2)
        headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer " + TEST_KEY),
        ]
        body = [json.dumps(JSON_BODY).encode()]

        async def scenario():
            slow_reader = asyncio.create_task(
                asgi_request(app, headers=headers, body_parts=[b"x", b"y"], delay=0.3)
            )
            await asyncio.sleep(0.05)
            second = await asgi_request(app, headers=headers, body_parts=body)
            self.assertEqual(second[0], 503)
            slow_reader.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await slow_reader
            await asyncio.sleep(0.05)
            after = await asgi_request(app, headers=headers, body_parts=body)
            self.assertEqual(after[0], 200, after[2])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_readiness_check_does_not_block_the_event_loop(self) -> None:
        store = BlockingReadyAuditStore(Path(self.tmp.name) / "blocking.sqlite3")
        gateway = self.make_gateway(store=store)
        app = make_app(gateway=gateway)

        async def scenario():
            readiness = asyncio.create_task(asgi_request(app, method="GET", path="/health/ready"))
            for _ in range(200):
                if store.ready_entered.is_set():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(store.ready_entered.is_set())

            started = time.monotonic()
            live = await asyncio.wait_for(asgi_request(app, method="GET", path="/health/live"), timeout=1)
            self.assertEqual(live[0], 200)
            self.assertLess(time.monotonic() - started, 1)

            store.ready_release.set()
            status, _, body = await asyncio.wait_for(readiness, timeout=2)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["status"], "ready")

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


class TlsTerminatedAtProxyTests(unittest.TestCase):
    def _seen_scheme(self, scope_type: str = "http") -> str:
        seen: dict[str, Any] = {}

        async def app(scope: Any, _receive: Any, _send: Any) -> None:
            seen.update(scope)

        wrapped = _TlsTerminatedAtProxy(app)
        asyncio.run(wrapped({"type": scope_type, "scheme": "http"}, None, None))
        return seen["scheme"]

    def test_http_requests_are_reported_as_https(self) -> None:
        self.assertEqual(self._seen_scheme(), "https")

    def test_lifespan_scope_is_left_alone(self) -> None:
        self.assertEqual(self._seen_scheme("lifespan"), "http")

    def test_middleware_is_installed_only_when_configured(self) -> None:
        for env, expected in (
            ({}, False),
            ({"NASI_LEMAK_TLS_TERMINATED_AT_PROXY": "false"}, False),
            ({"NASI_LEMAK_TLS_TERMINATED_AT_PROXY": "true"}, True),
        ):
            with self.subTest(env=env):
                app = make_app(environ=env)
                names = [item.cls for item in app.user_middleware]
                self.assertEqual(_TlsTerminatedAtProxy in names, expected)


if __name__ == "__main__":
    unittest.main()
