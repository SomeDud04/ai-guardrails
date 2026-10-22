"""Red-first tests for explicit API guard backends.

These tests use loopback HTTP fixtures only.  They prove transport, contract
parsing and environment composition; they are not evidence of real provider
behaviour, model quality or latency.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from typing import Any

from fastapi.testclient import TestClient

from nasi_lemak import server as server_module
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Policy
from nasi_lemak.generation import GenerationClient, GenerationConfig
from nasi_lemak.guard_api import (
    INPUT_GUARD_CONTRACT_V1,
    InputGuardApiAdapter,
    guard_client_config,
)
from nasi_lemak.guards import GuardError
from nasi_lemak.server import (
    ENV_ALLOW_INSECURE_HTTP,
    ENV_API_KEY,
    ENV_AUTH,
    ENV_GUARD_BACKEND,
    ENV_INPUT_GUARD_API_KEY,
    ENV_INPUT_GUARD_API_KEY_FILE,
    ENV_INPUT_GUARD_AUTH,
    ENV_INPUT_GUARD_CONTRACT,
    ENV_INPUT_GUARD_MODEL,
    ENV_INPUT_GUARD_THRESHOLD,
    ENV_INPUT_GUARD_URL,
    ENV_MODE,
    ENV_OUTPUT_GUARD_API_KEY_FILE,
    ENV_OUTPUT_GUARD_AUTH,
    ENV_OUTPUT_GUARD_MODEL,
    ENV_OUTPUT_GUARD_URL,
    ENV_URL,
    ENV_MODEL,
    GUARD_BACKEND_API,
    make_adapters_from_env,
    make_app,
)

GEN_MODEL = "generation-model-1"
INPUT_MODEL = "nasi-lemak/input-guard-api-1"
OUTPUT_MODEL = "Qwen/Qwen3Guard-Gen-4B"
GEN_KEY = "generation-key-not-a-real-secret"
INPUT_KEY = "input-guard-key-not-a-real-secret"
OUTPUT_KEY = "output-guard-key-not-a-real-secret"
APP_KEY = "app-key-not-a-real-secret"
SAFE_VERDICT = "Safety: Safe\nCategories: None\nRefusal: No"
UNSAFE_VERDICT = "Safety: Unsafe\nCategories: Violent\nRefusal: No"


def json_response(payload: Any, status: int = 200) -> tuple[int, bytes]:
    return status, json.dumps(payload).encode("utf-8")


def chat_payload(content: str, *, finish: str = "stop") -> tuple[int, bytes]:
    return json_response(
        {
            "id": "chatcmpl-fixture",
            "object": "chat.completion",
            "created": 0,
            "model": "upstream",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": finish,
                }
            ],
        }
    )


def input_payload(**overrides: Any) -> tuple[int, bytes]:
    payload = {
        "model": INPUT_MODEL,
        "malicious_probability": 0.05,
        "input_tokens": 12,
        "truncated": False,
    }
    payload.update(overrides)
    return json_response(payload)


def header(request: dict[str, Any], name: str) -> str | None:
    for key, value in request["headers"].items():
        if key.lower() == name.lower():
            return value
    return None


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _handle(self) -> None:
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length else 0
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = None
        request = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "raw": raw,
            "json": parsed,
        }
        self.server.requests.append(request)
        status, body = self.server.responder(request)
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except ConnectionError:
            pass

    do_GET = _handle
    do_POST = _handle


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def default_responder(request: dict[str, Any]) -> tuple[int, bytes]:
    if request["path"].endswith("/classify"):
        return input_payload()
    body = request["json"] if isinstance(request["json"], dict) else {}
    if body.get("model") == GEN_MODEL:
        return chat_payload("buffered answer")
    if body.get("model") == OUTPUT_MODEL:
        return chat_payload(SAFE_VERDICT)
    return json_response({"error": {"message": "unknown fixture request"}}, status=400)


class FixtureMixin(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def start_server(self, responder=default_responder) -> _FixtureServer:
        httpd = _FixtureServer(("127.0.0.1", 0), _Handler)
        httpd.requests = []
        httpd.responder = responder
        thread = threading.Thread(
            target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True
        )
        thread.start()

        def cleanup() -> None:
            httpd.shutdown()
            thread.join(timeout=2)
            httpd.server_close()

        self.addCleanup(cleanup)
        return httpd

    def base_url(self, httpd: _FixtureServer) -> str:
        return f"http://127.0.0.1:{httpd.server_address[1]}/v1"

    def input_adapter(
        self,
        httpd: _FixtureServer,
        *,
        threshold: float = 0.5,
        timeout: float = 2.0,
    ) -> InputGuardApiAdapter:
        client = GenerationClient(
            GenerationConfig(
                url=self.base_url(httpd),
                model=INPUT_MODEL,
                api_key=INPUT_KEY,
                timeout=timeout,
                max_response_bytes=8192,
            )
        )
        return InputGuardApiAdapter(client, threshold=threshold)

    def guard_env(self, httpd: _FixtureServer) -> dict[str, str]:
        output_key_file = self.root / "output-guard-key"
        output_key_file.write_text(OUTPUT_KEY + "\n", encoding="utf-8")
        return {
            "NASI_LEMAK_APP_KEY_DIGEST": hashlib.sha256(APP_KEY.encode()).hexdigest(),
            "NASI_LEMAK_AUDIT_DSN": "postgresql://synthetic/audit",
            ENV_MODE: "guarded",
            ENV_URL: self.base_url(httpd),
            ENV_MODEL: GEN_MODEL,
            ENV_AUTH: "bearer",
            ENV_API_KEY: GEN_KEY,
            ENV_GUARD_BACKEND: GUARD_BACKEND_API,
            ENV_INPUT_GUARD_URL: self.base_url(httpd),
            ENV_INPUT_GUARD_MODEL: INPUT_MODEL,
            "NASI_LEMAK_INPUT_GUARD_AUTH": "bearer",
            ENV_INPUT_GUARD_API_KEY: INPUT_KEY,
            ENV_INPUT_GUARD_THRESHOLD: "0.5",
            ENV_INPUT_GUARD_CONTRACT: INPUT_GUARD_CONTRACT_V1,
            ENV_OUTPUT_GUARD_URL: self.base_url(httpd),
            ENV_OUTPUT_GUARD_MODEL: OUTPUT_MODEL,
            ENV_OUTPUT_GUARD_AUTH: "bearer",
            ENV_OUTPUT_GUARD_API_KEY_FILE: str(output_key_file),
        }

    def make_api_app(self, httpd: _FixtureServer, env: dict[str, str]):
        counter = {"value": 0}

        def audit_factory(_dsn: str) -> SqliteAuditStore:
            counter["value"] += 1
            return SqliteAuditStore(self.root / f"audit-{counter['value']}.sqlite3")

        with mock.patch.object(server_module, "PostgresAuditStore", audit_factory):
            return make_app(environ=env, policy=Policy())

    def make_client(self, app: Any) -> TestClient:
        client = TestClient(app)
        self.addCleanup(client.close)
        return client

    def chat(self, client: TestClient, content: str):
        return client.post(
            "/v1/chat/completions",
            json={
                "model": "pilot-local",
                "messages": [{"role": "user", "content": content}],
                "max_tokens": 32,
            },
            headers={"Authorization": "Bearer " + APP_KEY},
        )

    @staticmethod
    def requests_for(httpd: _FixtureServer, path_suffix: str) -> list[dict[str, Any]]:
        return [request for request in httpd.requests if request["path"].endswith(path_suffix)]


class InputContractTests(FixtureMixin):
    def test_contract_request_shape_and_threshold_boundary(self) -> None:
        httpd = self.start_server()
        adapter = self.input_adapter(httpd, threshold=0.5)
        serialized = '[{"role":"user","content":"hello"}]'
        self.assertEqual(adapter.scan_attack(serialized), {"decision": "allow"})
        request = httpd.requests[0]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["path"], "/v1/classify")
        self.assertEqual(header(request, "Authorization"), "Bearer " + INPUT_KEY)
        self.assertEqual(
            request["json"],
            {
                "model": INPUT_MODEL,
                "input": serialized,
                "truncation": False,
                "max_input_tokens": 512,
            },
        )
        self.assertEqual(
            adapter.count_tokens(serialized),
            len(serialized.encode("utf-8")) + 2 * (serialized.count("\n") + 1) + 2,
        )

        httpd.responder = lambda request: input_payload(malicious_probability=0.5)
        self.assertEqual(adapter.scan_attack(serialized), {"decision": "block"})

    def test_strict_response_rejections_are_generic_and_single_shot(self) -> None:
        serialized = "input"
        cases: list[tuple[int, bytes]] = [
            input_payload(extra="unexpected"),
            json_response({"model": INPUT_MODEL, "malicious_probability": 0.1, "input_tokens": 1}),
            json_response(
                {
                    "model": INPUT_MODEL,
                    "malicious_probability": 0.1,
                    "input_tokens": 1,
                    "truncated": False,
                    "extra": None,
                }
            ),
            input_payload(malicious_probability=True),
            input_payload(malicious_probability=1.1),
            input_payload(malicious_probability=-0.1),
            input_payload(input_tokens=0),
            input_payload(input_tokens=513),
            input_payload(input_tokens=True),
            input_payload(input_tokens="12"),
            input_payload(truncated=True),
            input_payload(model=OUTPUT_MODEL),
        ]
        duplicates = (
            b'{"model":"' + INPUT_MODEL.encode() + b'","model":"' + INPUT_MODEL.encode()
            + b'","malicious_probability":0.1,"input_tokens":1,"truncated":false}'
        )
        nonfinite = (
            b'{"model":"' + INPUT_MODEL.encode()
            + b'","malicious_probability":NaN,"input_tokens":1,"truncated":false}'
        )
        cases.extend([(200, duplicates), (200, nonfinite)])
        for status, body in cases:
            with self.subTest(status=status, body=body):
                httpd = self.start_server(lambda request: (status, body))
                adapter = self.input_adapter(httpd)
                with self.assertRaises(GuardError) as raised:
                    adapter.scan_attack(serialized)
                message = str(raised.exception)
                self.assertNotIn("127.0.0.1", message)
                self.assertNotIn(INPUT_KEY, message)
                self.assertEqual(len(httpd.requests), 1)

    def test_http_failure_timeout_and_oversize_do_not_retry(self) -> None:
        cases = [
            lambda request: json_response({"error": {"message": "provider detail"}}, status=500),
            lambda request: json_response({"model": INPUT_MODEL}),
            lambda request: (200, b"{" + b'"padding":"' + b"x" * 9000 + b'"}'),
        ]
        for responder in cases:
            with self.subTest(responder=responder):
                httpd = self.start_server(responder)
                adapter = self.input_adapter(httpd)
                with self.assertRaises(GuardError):
                    adapter.scan_attack("input")
                self.assertEqual(len(httpd.requests), 1)

    def test_constructor_requires_explicit_model_and_threshold(self) -> None:
        httpd = self.start_server()
        with self.assertRaises(GuardError):
            self.input_adapter(httpd, threshold=float("nan"))
        with self.assertRaises(GuardError):
            self.input_adapter(httpd, threshold=True)
        with self.assertRaises(GuardError):
            self.input_adapter(httpd, threshold=1.5)
        unconfigured = GenerationClient(
            GenerationConfig(url=self.base_url(httpd), model="", api_key=INPUT_KEY)
        )
        with self.assertRaises(GuardError):
            InputGuardApiAdapter(unconfigured, threshold=0.5)
        self.assertEqual(httpd.requests, [])


class RuntimeConfigTests(unittest.TestCase):
    def test_guard_client_config_requires_explicit_fields_and_reads_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "key"
            key_file.write_text(INPUT_KEY + "\n", encoding="utf-8")
            env = {
                "NASI_LEMAK_INPUT_GUARD_URL": "http://127.0.0.1:9/v1",
                "NASI_LEMAK_INPUT_GUARD_MODEL": INPUT_MODEL,
                "NASI_LEMAK_INPUT_GUARD_AUTH": "bearer",
                "NASI_LEMAK_INPUT_GUARD_API_KEY_FILE": str(key_file),
            }
            config = guard_client_config(env, "NASI_LEMAK_INPUT_GUARD")
            self.assertEqual(config.model, INPUT_MODEL)
            self.assertEqual(config.auth_mode, "bearer")
            self.assertEqual(config.api_key, INPUT_KEY)
            self.assertNotIn(INPUT_KEY, repr(config))

            for missing in (
                "NASI_LEMAK_INPUT_GUARD_URL",
                "NASI_LEMAK_INPUT_GUARD_MODEL",
                "NASI_LEMAK_INPUT_GUARD_AUTH",
            ):
                broken = dict(env)
                broken.pop(missing)
                with self.subTest(missing=missing):
                    with self.assertRaises(Exception):
                        guard_client_config(broken, "NASI_LEMAK_INPUT_GUARD")

            both = dict(env)
            both["NASI_LEMAK_INPUT_GUARD_API_KEY"] = INPUT_KEY
            with self.assertRaises(Exception):
                guard_client_config(both, "NASI_LEMAK_INPUT_GUARD")

    def test_invalid_api_settings_never_run_local_ml_loaders(self) -> None:
        base = {
            "NASI_LEMAK_INPUT_GUARD_URL": "https://guard.example.invalid/v1",
            "NASI_LEMAK_INPUT_GUARD_MODEL": INPUT_MODEL,
            "NASI_LEMAK_INPUT_GUARD_AUTH": "none",
            "NASI_LEMAK_INPUT_GUARD_THRESHOLD": "0.5",
            "NASI_LEMAK_INPUT_GUARD_CONTRACT": INPUT_GUARD_CONTRACT_V1,
            "NASI_LEMAK_OUTPUT_GUARD_URL": "https://guard.example.invalid/v1",
            "NASI_LEMAK_OUTPUT_GUARD_MODEL": OUTPUT_MODEL,
            "NASI_LEMAK_OUTPUT_GUARD_AUTH": "none",
            ENV_URL: "https://generation.example.invalid/v1",
            ENV_MODEL: GEN_MODEL,
            ENV_AUTH: "none",
            ENV_GUARD_BACKEND: GUARD_BACKEND_API,
        }

        def must_not_load(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("local ML loader must not run in API mode")

        def must_not_build(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("client loader must not run for invalid settings")

        cases: list[dict[str, str]] = []
        for name in (
            ENV_INPUT_GUARD_URL,
            ENV_INPUT_GUARD_MODEL,
            "NASI_LEMAK_INPUT_GUARD_AUTH",
            ENV_INPUT_GUARD_THRESHOLD,
            ENV_INPUT_GUARD_CONTRACT,
            ENV_OUTPUT_GUARD_URL,
            ENV_OUTPUT_GUARD_MODEL,
            ENV_OUTPUT_GUARD_AUTH,
        ):
            env = dict(base)
            env.pop(name)
            cases.append(env)
        for name, value in (
            (ENV_GUARD_BACKEND, "hybrid"),
            (ENV_INPUT_GUARD_THRESHOLD, "nan"),
            (ENV_INPUT_GUARD_THRESHOLD, "1.1"),
            (ENV_INPUT_GUARD_CONTRACT, "prompt-guard-chat-v1"),
            (ENV_INPUT_GUARD_AUTH, "basic"),
        ):
            env = dict(base)
            env[name] = value
            cases.append(env)
        bearer_missing_key = dict(base)
        bearer_missing_key["NASI_LEMAK_INPUT_GUARD_AUTH"] = "bearer"
        cases.append(bearer_missing_key)
        unreadable = dict(base)
        unreadable["NASI_LEMAK_INPUT_GUARD_AUTH"] = "bearer"
        unreadable[ENV_INPUT_GUARD_API_KEY_FILE] = (
            Path(tempfile.gettempdir()) / "missing-nasi-guard-key"
        ).as_posix()
        cases.append(unreadable)

        for env in cases:
            with self.subTest(env={k: v for k, v in env.items() if k not in (ENV_URL, ENV_MODEL)}):
                self.assertIsNone(
                    make_adapters_from_env(
                        env,
                        prompt_guard_loader=must_not_load,
                        llama_guard_loader=must_not_load,
                        client_loader=must_not_build,
                    )
                )

    def test_api_mode_requires_no_local_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "key"
            key.write_text(INPUT_KEY + "\n", encoding="utf-8")
            env = {
                "NASI_LEMAK_INPUT_GUARD_URL": "http://127.0.0.1:9/v1",
                "NASI_LEMAK_INPUT_GUARD_MODEL": INPUT_MODEL,
                "NASI_LEMAK_INPUT_GUARD_AUTH": "bearer",
                ENV_INPUT_GUARD_API_KEY_FILE: str(key),
                "NASI_LEMAK_INPUT_GUARD_THRESHOLD": "0.5",
                "NASI_LEMAK_INPUT_GUARD_CONTRACT": INPUT_GUARD_CONTRACT_V1,
                "NASI_LEMAK_OUTPUT_GUARD_URL": "http://127.0.0.1:9/v1",
                "NASI_LEMAK_OUTPUT_GUARD_MODEL": OUTPUT_MODEL,
                "NASI_LEMAK_OUTPUT_GUARD_AUTH": "none",
                ENV_URL: "http://127.0.0.1:9/v1",
                ENV_MODEL: GEN_MODEL,
                ENV_AUTH: "none",
                ENV_GUARD_BACKEND: GUARD_BACKEND_API,
            }

            def must_not_load(*args: Any, **kwargs: Any) -> Any:
                raise AssertionError("local ML loader must not run in API mode")

            adapters = make_adapters_from_env(
                env,
                prompt_guard_loader=must_not_load,
                llama_guard_loader=must_not_load,
            )
            self.assertIsInstance(adapters, server_module.RealGatewayAdapters)
            self.assertIsInstance(adapters.attack_guard, InputGuardApiAdapter)
            self.assertIsInstance(adapters.tokenizer, InputGuardApiAdapter)
            self.assertIs(adapters.attack_guard, adapters.tokenizer)
            self.assertNotEqual(
                adapters.attack_guard._client.config.api_key,
                adapters.client.config.api_key,
            )


class EndToEndApiModeTests(FixtureMixin):
    def test_safe_path_uses_raw_input_masked_output_context_and_separate_keys(self) -> None:
        httpd = self.start_server()
        app = self.make_api_app(httpd, self.guard_env(httpd))
        client = self.make_client(app)
        self.assertEqual(client.get("/health/ready").status_code, 200)

        response = self.chat(client, "email me at test@example.com")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["choices"][0]["message"]["content"], "buffered answer")

        classify = self.requests_for(httpd, "/classify")
        generation = [
            request
            for request in httpd.requests
            if request["path"].endswith("/chat/completions")
            and request["json"]["model"] == GEN_MODEL
        ]
        output = [
            request
            for request in httpd.requests
            if request["path"].endswith("/chat/completions")
            and request["json"]["model"] == OUTPUT_MODEL
        ]
        self.assertEqual(len(classify), 1)
        self.assertEqual(len(generation), 1)
        self.assertEqual(len(output), 1)
        self.assertEqual(header(classify[0], "Authorization"), "Bearer " + INPUT_KEY)
        self.assertEqual(header(generation[0], "Authorization"), "Bearer " + GEN_KEY)
        self.assertEqual(header(output[0], "Authorization"), "Bearer " + OUTPUT_KEY)
        self.assertIn("test@example.com", classify[0]["json"]["input"])
        self.assertIn("[EMAIL]", generation[0]["json"]["messages"][0]["content"])
        self.assertIn("[EMAIL]", output[0]["json"]["messages"][0]["content"])
        self.assertNotIn("test@example.com", output[0]["json"]["messages"][0]["content"])
        self.assertEqual(
            output[0]["json"]["messages"][-1],
            {"role": "assistant", "content": "buffered answer"},
        )

    def test_input_block_never_calls_generation(self) -> None:
        def responder(request: dict[str, Any]) -> tuple[int, bytes]:
            if request["path"].endswith("/classify"):
                return input_payload(malicious_probability=0.9)
            return default_responder(request)

        httpd = self.start_server(responder)
        app = self.make_api_app(httpd, self.guard_env(httpd))
        response = self.chat(self.make_client(app), "blocked prompt")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(len(self.requests_for(httpd, "/classify")), 1)
        self.assertEqual(
            [
                request
                for request in httpd.requests
                if request["path"].endswith("/chat/completions")
            ],
            [],
        )

    def test_output_block_withholds_buffered_output(self) -> None:
        def responder(request: dict[str, Any]) -> tuple[int, bytes]:
            body = request["json"] if isinstance(request["json"], dict) else {}
            if request["path"].endswith("/classify"):
                return input_payload()
            if body.get("model") == GEN_MODEL:
                return chat_payload("buffered answer")
            return chat_payload(UNSAFE_VERDICT)

        httpd = self.start_server(responder)
        app = self.make_api_app(httpd, self.guard_env(httpd))
        response = self.chat(self.make_client(app), "hello")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("buffered answer", response.text)

    def test_malformed_input_and_output_fail_closed_without_retry(self) -> None:
        def bad_input(request: dict[str, Any]) -> tuple[int, bytes]:
            if request["path"].endswith("/classify"):
                return input_payload(input_tokens=513)
            return default_responder(request)

        def bad_output(request: dict[str, Any]) -> tuple[int, bytes]:
            body = request["json"] if isinstance(request["json"], dict) else {}
            if request["path"].endswith("/classify"):
                return input_payload()
            if body.get("model") == GEN_MODEL:
                return chat_payload("buffered answer")
            return chat_payload("Safety: Unsafe\nCategories: Violent")

        for responder, expected_paths in (
            (bad_input, ["/classify"]),
            (bad_output, ["/classify", "/chat/completions"]),
        ):
            with self.subTest(responder=responder):
                httpd = self.start_server(responder)
                app = self.make_api_app(httpd, self.guard_env(httpd))
                response = self.chat(self.make_client(app), "hello")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
                self.assertNotIn("buffered answer", response.text)
                classify = self.requests_for(httpd, "/classify")
                self.assertEqual(len(classify), 1)
                if expected_paths == ["/classify"]:
                    self.assertEqual(
                        [
                            request
                            for request in httpd.requests
                            if request["path"].endswith("/chat/completions")
                        ],
                        [],
                    )
                else:
                    output = [
                        request
                        for request in httpd.requests
                        if request["path"].endswith("/chat/completions")
                        and request["json"]["model"] == OUTPUT_MODEL
                    ]
                    self.assertEqual(len(output), 1)

    def test_delayed_input_api_timeout_fails_closed_without_retry_or_generation(self) -> None:
        """The fixture really delays past the configured timeout, then blocks."""

        def delayed(request: dict[str, Any]) -> tuple[int, bytes]:
            if request["path"].endswith("/classify"):
                time.sleep(1.0)
                return input_payload()
            return default_responder(request)

        httpd = self.start_server(delayed)
        env = self.guard_env(httpd)
        env["NASI_LEMAK_INPUT_GUARD_TIMEOUT"] = "0.2"
        app = self.make_api_app(httpd, env)
        response = self.chat(self.make_client(app), "timeout prompt")

        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("buffered answer", response.text)
        # Exactly one attempt: no retry, and no generation or output request.
        self.assertEqual(len(self.requests_for(httpd, "/classify")), 1)
        self.assertEqual(
            [
                request
                for request in httpd.requests
                if request["path"].endswith("/chat/completions")
            ],
            [],
        )

    def test_missing_api_settings_leave_app_unready_without_local_ml_loaders(self) -> None:
        httpd = self.start_server()
        env = self.guard_env(httpd)
        env.pop(ENV_OUTPUT_GUARD_URL)

        def must_not_load(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("local ML loader must not run in API mode")

        with mock.patch.object(server_module, "_load_prompt_guard", must_not_load), mock.patch.object(
            server_module, "_load_llama_guard", must_not_load
        ):
            app = self.make_api_app(httpd, env)
        client = self.make_client(app)
        self.assertEqual(client.get("/health/ready").status_code, 503)
        self.assertIsNone(app.state.gateway.adapters)
        self.assertEqual(httpd.requests, [])

    def test_parallel_requests_keep_input_context_isolated(self) -> None:
        barrier = threading.Barrier(2)

        def responder(request: dict[str, Any]) -> tuple[int, bytes]:
            if request["path"].endswith("/classify"):
                barrier.wait(timeout=10)
                text = request["json"]["input"]
                if "beta-marker" in text:
                    return input_payload(malicious_probability=0.9)
                return input_payload(malicious_probability=0.05)
            return default_responder(request)

        httpd = self.start_server(responder)
        app = self.make_api_app(httpd, self.guard_env(httpd))
        gateway = app.state.gateway

        def call(content: str) -> int:
            status, _ = gateway.handle(
                "POST",
                "/v1/chat/completions",
                {"Authorization": "Bearer " + APP_KEY},
                {
                    "model": "pilot-local",
                    "messages": [{"role": "user", "content": content}],
                    "max_tokens": 32,
                },
            )
            return status

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(call, ("alpha-marker", "beta-marker")))

        self.assertEqual(sorted(statuses), [200, 403])
        inputs = [request["json"]["input"] for request in self.requests_for(httpd, "/classify")]
        self.assertEqual(len(inputs), 2)
        self.assertTrue(any("alpha-marker" in text for text in inputs))
        self.assertTrue(any("beta-marker" in text for text in inputs))


if __name__ == "__main__":
    unittest.main()
