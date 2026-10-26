"""Synthetic tests for the opt-in hosted Prompt Guard / Llama Guard adapters.

Every HTTP request goes to a loopback ``ThreadingHTTPServer`` fixture.  No real
provider, credential or model is used.  Passing tests prove the wire adapter
contract and server wiring only; they are not live provider acceptance,
accuracy, quota or latency evidence.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from nasi_lemak import server as server_module
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Policy
from nasi_lemak.generation import APPLICATION_USER_AGENT, GenerationClient, GenerationConfig
from nasi_lemak.guard_api import (
    INPUT_GUARD_CONTRACT_V1,
    InputGuardApiAdapter,
    Qwen3GuardOutputAdapter,
)
from nasi_lemak.guards import GuardError
from nasi_lemak.hosted_guards import (
    CLOUDFLARE_LLAMA_GUARD_MODEL,
    GROQ_INPUT_MAX_SERIALIZED_BYTES,
    GROQ_PROMPT_GUARD_MODEL,
    CloudflareLlamaGuardOutputAdapter,
    GroqPromptGuardInputAdapter,
)
from nasi_lemak.server import (
    ENV_API_KEY,
    ENV_AUTH,
    ENV_GUARD_BACKEND,
    ENV_INPUT_GUARD_API_KEY,
    ENV_INPUT_GUARD_API_KEY_FILE,
    ENV_INPUT_GUARD_AUTH,
    ENV_INPUT_GUARD_CONTRACT,
    ENV_INPUT_GUARD_MODEL,
    ENV_INPUT_GUARD_PROVIDER,
    ENV_INPUT_GUARD_THRESHOLD,
    ENV_INPUT_GUARD_URL,
    ENV_MODE,
    ENV_MODEL,
    ENV_OUTPUT_GUARD_API_KEY,
    ENV_OUTPUT_GUARD_AUTH,
    ENV_OUTPUT_GUARD_MODEL,
    ENV_OUTPUT_GUARD_PROVIDER,
    ENV_OUTPUT_GUARD_URL,
    ENV_URL,
    GUARD_BACKEND_API,
    INPUT_GUARD_PROVIDER_GROQ,
    OUTPUT_GUARD_PROVIDER_CLOUDFLARE,
    make_adapters_from_env,
    make_app,
)

GEN_MODEL = "generation-model-hosted-1"
GEN_KEY = "generation-key-not-real"
INPUT_KEY = "groq-input-key-not-real"
OUTPUT_KEY = "cloudflare-output-key-not-real"
APP_KEY = "app-key-not-real"


def _json(payload: Any, status: int = 200) -> tuple[int, bytes]:
    return status, json.dumps(payload).encode("utf-8")


def chat_payload(
    content: str,
    *,
    model: str,
    finish: str = "stop",
    usage: dict[str, Any] | None = None,
    choices: int = 1,
    **message_overrides: Any,
) -> tuple[int, bytes]:
    message = {"role": "assistant", "content": content}
    message.update(message_overrides)
    payload: dict[str, Any] = {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": index,
                "message": dict(message),
                "finish_reason": finish,
            }
            for index in range(choices)
        ],
    }
    if usage is not None:
        payload["usage"] = usage
    return _json(payload)


def groq_payload(
    content: str = "0.05",
    *,
    model: str = GROQ_PROMPT_GUARD_MODEL,
    prompt_tokens: Any = 12,
    include_usage: bool = True,
    finish: str = "stop",
) -> tuple[int, bytes]:
    usage = {"prompt_tokens": prompt_tokens, "total_tokens": 15} if include_usage else None
    return chat_payload(content, model=model, finish=finish, usage=usage)


def strict_response_cases(
    model: str, content: str, *, usage: dict[str, Any] | None = None
) -> list[tuple[int, bytes]]:
    """Chat responses with an invalid index or optional-field shape."""

    def base() -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": "chatcmpl-fixture",
            "object": "chat.completion",
            "created": 0,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        }
        if usage is not None:
            payload["usage"] = dict(usage)
        return payload

    cases: list[tuple[int, bytes]] = []
    for index in (True, False, 0.0, None):
        payload = base()
        if index is None:
            payload["choices"][0].pop("index")
        else:
            payload["choices"][0]["index"] = index
        cases.append(_json(payload))
    for field, value in (
        ("tool_calls", {}),
        ("tool_calls", [{"id": "call-1"}]),
        ("function_call", {}),
        ("function_call", False),
        ("refusal", False),
        ("refusal", True),
        ("refusal", {"message": "no"}),
    ):
        payload = base()
        payload["choices"][0]["message"][field] = value
        cases.append(_json(payload))
    return cases


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


class FixtureMixin(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def start_server(self, responder=None) -> _FixtureServer:
        httpd = _FixtureServer(("127.0.0.1", 0), _Handler)
        httpd.requests = []
        httpd.responder = responder or (lambda request: groq_payload())
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

    def client(self, httpd: _FixtureServer, *, model: str, key: str, **overrides: Any) -> GenerationClient:
        values = {
            "url": self.base_url(httpd),
            "model": model,
            "api_key": key,
            "timeout": 2.0,
            "max_response_bytes": 8192,
        }
        values.update(overrides)
        return GenerationClient(GenerationConfig(**values))

    def input_adapter(
        self, httpd: _FixtureServer, *, threshold: float = 0.5, **overrides: Any
    ) -> GroqPromptGuardInputAdapter:
        return GroqPromptGuardInputAdapter(
            self.client(httpd, model=GROQ_PROMPT_GUARD_MODEL, key=INPUT_KEY, **overrides),
            threshold=threshold,
        )

    def output_adapter(
        self, httpd: _FixtureServer, **overrides: Any
    ) -> CloudflareLlamaGuardOutputAdapter:
        return CloudflareLlamaGuardOutputAdapter(
            self.client(
                httpd, model=CLOUDFLARE_LLAMA_GUARD_MODEL, key=OUTPUT_KEY, **overrides
            )
        )


class UserAgentTransportTests(FixtureMixin):
    def test_application_user_agent_is_sent_on_both_hosted_posts(self) -> None:
        # A missing or Python-default agent is rejected like the reported provider
        # front end; both hosted adapters share the fixed application agent.
        def responder(request):
            if header(request, "User-Agent") != APPLICATION_USER_AGENT:
                return 403, b"error code: 1010\n"
            if request["json"]["model"] == GROQ_PROMPT_GUARD_MODEL:
                return groq_payload()
            return chat_payload("safe", model=CLOUDFLARE_LLAMA_GUARD_MODEL)

        httpd = self.start_server(responder)
        self.assertEqual(
            self.input_adapter(httpd).scan_attack("user: hello"),
            {"decision": "allow"},
        )
        self.assertEqual(
            self.output_adapter(httpd).scan_response(
                [{"role": "user", "content": "hello"}], "hello"
            ),
            {"safe": True},
        )
        self.assertEqual(
            [header(request, "User-Agent") for request in httpd.requests],
            [APPLICATION_USER_AGENT, APPLICATION_USER_AGENT],
        )


class GroqInputAdapterTests(FixtureMixin):
    def test_request_shape_and_threshold_boundary(self) -> None:
        httpd = self.start_server(lambda request: groq_payload("0.05"))
        adapter = self.input_adapter(httpd, threshold=0.5)
        serialized = "user: hello\nassistant: earlier"
        self.assertEqual(adapter.scan_attack(serialized), {"decision": "allow"})
        request = httpd.requests[0]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["path"], "/v1/chat/completions")
        self.assertEqual(header(request, "Authorization"), "Bearer " + INPUT_KEY)
        self.assertEqual(header(request, "User-Agent"), APPLICATION_USER_AGENT)
        self.assertEqual(
            request["json"],
            {
                "model": GROQ_PROMPT_GUARD_MODEL,
                "messages": [{"role": "user", "content": serialized}],
                "max_tokens": 16,
                "temperature": 0,
                "stream": False,
            },
        )
        self.assertGreater(adapter.count_tokens(serialized), len(serialized))

        for probability, expected in (("0.5", "block"), ("0.49", "allow"), ("0", "allow"), ("1", "block")):
            httpd.responder = lambda request, value=probability: groq_payload(value)
            with self.subTest(probability=probability):
                self.assertEqual(
                    adapter.scan_attack(serialized), {"decision": expected}
                )

    def test_malformed_probability_and_usage_fail_closed(self) -> None:
        cases = [
            lambda request: groq_payload("NaN"),
            lambda request: groq_payload("inf"),
            lambda request: groq_payload("-0.1"),
            lambda request: groq_payload("1.1"),
            lambda request: groq_payload("0.1\n0.2"),
            lambda request: groq_payload("0.1 extra"),
            lambda request: groq_payload('"0.1"'),
            lambda request: groq_payload("benign"),
            lambda request: groq_payload("true"),
            lambda request: groq_payload("1e-3"),
            lambda request: groq_payload("{}"),
            lambda request: groq_payload(include_usage=False),
            lambda request: groq_payload(prompt_tokens=0),
            lambda request: groq_payload(prompt_tokens=512),
            lambda request: groq_payload(prompt_tokens=True),
            lambda request: groq_payload(prompt_tokens="12"),
        ]
        for responder in cases:
            with self.subTest(responder=responder):
                httpd = self.start_server(responder)
                adapter = self.input_adapter(httpd)
                with self.assertRaises(GuardError) as raised:
                    adapter.scan_attack("user: private prompt")
                message = str(raised.exception)
                for secret in ("private prompt", INPUT_KEY, "127.0.0.1", "NaN"):
                    self.assertNotIn(secret, message)
                self.assertEqual(len(httpd.requests), 1)

    def test_wrong_or_missing_model_and_truncated_completion_fail_closed(self) -> None:
        cases = [
            lambda request: groq_payload("0.05", model="another-model"),
            lambda request: _json(
                {
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "0.05"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 12},
                }
            ),
            lambda request: groq_payload("0.05", finish="length"),
            lambda request: chat_payload(
                "0.05", model=GROQ_PROMPT_GUARD_MODEL, usage={"prompt_tokens": 12}, choices=2
            ),
            lambda request: _json({"error": {"message": "provider detail"}}),
        ]
        for responder in cases:
            with self.subTest(responder=responder):
                httpd = self.start_server(responder)
                adapter = self.input_adapter(httpd)
                with self.assertRaises(GuardError) as raised:
                    adapter.scan_attack("user: hello")
                message = str(raised.exception)
                self.assertNotIn("provider detail", message)
                self.assertNotIn(INPUT_KEY, message)
                self.assertEqual(len(httpd.requests), 1)

    def test_strict_index_and_optional_field_shapes_fail_closed(self) -> None:
        httpd = self.start_server()
        adapter = self.input_adapter(httpd)
        cases = strict_response_cases(
            GROQ_PROMPT_GUARD_MODEL, "0.05", usage={"prompt_tokens": 12}
        )
        for status, body in cases:
            httpd.responder = lambda request, status=status, body=body: (status, body)
            with self.subTest(body=body):
                with self.assertRaises(GuardError):
                    adapter.scan_attack("user: hello")

    def test_none_or_empty_tool_calls_still_allow(self) -> None:
        httpd = self.start_server()
        adapter = self.input_adapter(httpd)
        for overrides in (
            {"tool_calls": None},
            {"tool_calls": []},
            {"function_call": None},
            {"refusal": None},
            {"refusal": ""},
        ):
            httpd.responder = lambda request, overrides=overrides: chat_payload(
                "0.05",
                model=GROQ_PROMPT_GUARD_MODEL,
                usage={"prompt_tokens": 12},
                **overrides,
            )
            with self.subTest(overrides=overrides):
                self.assertEqual(
                    adapter.scan_attack("user: hello"), {"decision": "allow"}
                )

    def test_long_input_is_rejected_before_http(self) -> None:
        httpd = self.start_server()
        adapter = self.input_adapter(httpd)
        with self.assertRaises(GuardError):
            adapter.scan_attack("user: " + "x" * (GROQ_INPUT_MAX_SERIALIZED_BYTES + 1))
        self.assertEqual(httpd.requests, [])
        # Just under the budget still calls exactly once.
        httpd.responder = lambda request: groq_payload("0.05")
        self.assertEqual(
            adapter.scan_attack("user: " + "x" * 400), {"decision": "allow"}
        )
        self.assertEqual(len(httpd.requests), 1)

    def test_http_errors_bad_json_and_timeout_do_not_retry_or_leak(self) -> None:
        cases = [
            lambda request: _json({"error": {"message": "provider detail"}}, status=401),
            lambda request: _json({"error": {"message": "provider detail"}}, status=403),
            lambda request: _json({"error": {"message": "provider detail"}}, status=429),
            lambda request: (200, b"{not-json"),
            lambda request: (200, b"{}"),
        ]
        for responder in cases:
            with self.subTest(responder=responder):
                httpd = self.start_server(responder)
                adapter = self.input_adapter(httpd)
                with self.assertRaises(GuardError) as raised:
                    adapter.scan_attack("user: private prompt")
                message = str(raised.exception)
                for secret in ("private prompt", INPUT_KEY, "127.0.0.1", "provider detail"):
                    self.assertNotIn(secret, message)
                self.assertEqual(len(httpd.requests), 1)

        release = threading.Event()
        entered = threading.Event()
        handler_threads: list[threading.Thread] = []

        def delayed(request: dict[str, Any]) -> tuple[int, bytes]:
            handler_threads.append(threading.current_thread())
            entered.set()
            release.wait(5)
            return groq_payload()

        httpd = self.start_server(delayed)
        adapter = self.input_adapter(httpd, timeout=0.05)
        try:
            with self.assertRaises(GuardError) as raised:
                adapter.scan_attack("user: private prompt")
            message = str(raised.exception)
            for secret in ("private prompt", INPUT_KEY, "127.0.0.1", "timed out"):
                self.assertNotIn(secret, message)
            self.assertTrue(entered.wait(1))
            self.assertEqual(len(httpd.requests), 1)
        finally:
            release.set()
            for thread in handler_threads:
                thread.join(timeout=5)

    def test_constructor_requires_exact_model_and_valid_threshold(self) -> None:
        httpd = self.start_server()
        with self.assertRaises(GuardError):
            self.input_adapter(httpd, threshold=float("nan"))
        with self.assertRaises(GuardError):
            self.input_adapter(httpd, threshold=True)
        with self.assertRaises(GuardError):
            self.input_adapter(httpd, threshold=1.5)
        with self.assertRaises(GuardError):
            GroqPromptGuardInputAdapter(None, threshold=0.5)
        for model in (CLOUDFLARE_LLAMA_GUARD_MODEL, "meta-llama/Llama-Prompt-Guard-2-22M", ""):
            with self.subTest(model=model):
                client = self.client(httpd, model=model, key=INPUT_KEY)
                with self.assertRaises(GuardError):
                    GroqPromptGuardInputAdapter(client, threshold=0.5)
        self.assertEqual(httpd.requests, [])


class CloudflareOutputAdapterTests(FixtureMixin):
    def test_request_uses_local_flattening_and_strict_shape(self) -> None:
        httpd = self.start_server(lambda request: chat_payload("safe", model=CLOUDFLARE_LLAMA_GUARD_MODEL))
        adapter = self.output_adapter(httpd)
        messages = [
            {"role": "system", "content": "policy"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "earlier answer"},
        ]
        self.assertEqual(adapter.scan_response(messages, "buffered answer"), {"safe": True})
        request = httpd.requests[0]
        self.assertEqual(request["path"], "/v1/chat/completions")
        self.assertEqual(header(request, "Authorization"), "Bearer " + OUTPUT_KEY)
        self.assertEqual(header(request, "User-Agent"), APPLICATION_USER_AGENT)
        self.assertEqual(
            request["json"],
            {
                "model": CLOUDFLARE_LLAMA_GUARD_MODEL,
                "messages": [
                    {
                        "role": "user",
                        "content": "system: policy\nuser: hello\nassistant: earlier answer",
                    },
                    {"role": "assistant", "content": "buffered answer"},
                ],
                "max_tokens": 32,
                "temperature": 0,
                "stream": False,
            },
        )
        self.assertEqual(messages[0]["content"], "policy")

    def test_canonical_verdicts_and_categories(self) -> None:
        cases = [
            ("safe", True),
            ("unsafe\nS1", False),
            ("unsafe\nS1,S14", False),
            ("unsafe\nS2\nS3", False),
            ("unsafe\nS1, S2", False),
        ]
        httpd = self.start_server()
        adapter = self.output_adapter(httpd)
        for verdict, expected in cases:
            httpd.responder = lambda request, value=verdict: chat_payload(
                value, model=CLOUDFLARE_LLAMA_GUARD_MODEL
            )
            with self.subTest(verdict=verdict):
                self.assertEqual(
                    adapter.scan_response([{"role": "user", "content": "hello"}], "answer"),
                    {"safe": expected},
                )

    def test_malformed_or_contradictory_verdicts_fail_closed(self) -> None:
        verdicts = [
            "Safe",
            "safe extra",
            "```safe```",
            '{"verdict":"safe"}',
            "unsafe",
            "unsafe\n",
            "unsafe\nS1,S1",
            "unsafe\nS15",
            "unsafe\nS0",
            "safe\nS1",
            "unsafe S1",
            "unsafe\nS1, prose",
            "here is the verdict: safe",
        ]
        httpd = self.start_server()
        adapter = self.output_adapter(httpd)
        for verdict in verdicts:
            httpd.responder = lambda request, value=verdict: chat_payload(
                value, model=CLOUDFLARE_LLAMA_GUARD_MODEL
            )
            with self.subTest(verdict=verdict):
                with self.assertRaises(GuardError):
                    adapter.scan_response([{"role": "user", "content": "hello"}], "answer")

    def test_missing_or_wrong_model_and_truncated_completion_fail_closed(self) -> None:
        def missing_model(request: dict[str, Any]) -> tuple[int, bytes]:
            status, body = chat_payload("safe", model=CLOUDFLARE_LLAMA_GUARD_MODEL)
            payload = json.loads(body)
            payload.pop("model")
            return status, json.dumps(payload).encode("utf-8")

        cases = [
            lambda request: chat_payload("safe", model="llama-guard-other"),
            missing_model,
            lambda request: chat_payload(
                "safe", model=CLOUDFLARE_LLAMA_GUARD_MODEL, finish="length"
            ),
            lambda request: chat_payload(
                "safe", model=CLOUDFLARE_LLAMA_GUARD_MODEL, choices=2
            ),
            lambda request: _json({"error": {"message": "provider detail"}}),
        ]
        for responder in cases:
            with self.subTest(responder=responder):
                httpd = self.start_server(responder)
                adapter = self.output_adapter(httpd)
                with self.assertRaises(GuardError) as raised:
                    adapter.scan_response([{"role": "user", "content": "hello"}], "answer")
                message = str(raised.exception)
                self.assertNotIn("provider detail", message)
                self.assertNotIn(OUTPUT_KEY, message)
                self.assertEqual(len(httpd.requests), 1)

    def test_strict_index_and_optional_field_shapes_fail_closed(self) -> None:
        httpd = self.start_server()
        adapter = self.output_adapter(httpd)
        cases = strict_response_cases(CLOUDFLARE_LLAMA_GUARD_MODEL, "safe")
        for status, body in cases:
            httpd.responder = lambda request, status=status, body=body: (status, body)
            with self.subTest(body=body):
                with self.assertRaises(GuardError):
                    adapter.scan_response(
                        [{"role": "user", "content": "hello"}], "answer"
                    )

    def test_none_or_empty_tool_calls_still_allow(self) -> None:
        httpd = self.start_server()
        adapter = self.output_adapter(httpd)
        for overrides in (
            {"tool_calls": None},
            {"tool_calls": []},
            {"function_call": None},
            {"refusal": None},
            {"refusal": ""},
        ):
            httpd.responder = lambda request, overrides=overrides: chat_payload(
                "safe", model=CLOUDFLARE_LLAMA_GUARD_MODEL, **overrides
            )
            with self.subTest(overrides=overrides):
                self.assertEqual(
                    adapter.scan_response(
                        [{"role": "user", "content": "hello"}], "answer"
                    ),
                    {"safe": True},
                )

    def test_http_errors_bad_json_and_timeout_do_not_allow_or_retry(self) -> None:
        cases = [
            lambda request: _json({"error": {"message": "provider detail"}}, status=401),
            lambda request: _json({"error": {"message": "provider detail"}}, status=403),
            lambda request: _json({"error": {"message": "provider detail"}}, status=429),
            lambda request: (200, b"{not-json"),
        ]
        for responder in cases:
            with self.subTest(responder=responder):
                httpd = self.start_server(responder)
                adapter = self.output_adapter(httpd)
                with self.assertRaises(GuardError) as raised:
                    adapter.scan_response([{"role": "user", "content": "hello"}], "private output")
                message = str(raised.exception)
                for secret in ("private output", OUTPUT_KEY, "127.0.0.1", "provider detail"):
                    self.assertNotIn(secret, message)
                self.assertEqual(len(httpd.requests), 1)

        release = threading.Event()
        entered = threading.Event()
        handler_threads: list[threading.Thread] = []

        def delayed(request: dict[str, Any]) -> tuple[int, bytes]:
            handler_threads.append(threading.current_thread())
            entered.set()
            release.wait(5)
            return chat_payload("safe", model=CLOUDFLARE_LLAMA_GUARD_MODEL)

        httpd = self.start_server(delayed)
        adapter = self.output_adapter(httpd, timeout=0.05)
        try:
            with self.assertRaises(GuardError) as raised:
                adapter.scan_response([{"role": "user", "content": "hello"}], "private output")
            message = str(raised.exception)
            for secret in ("private output", OUTPUT_KEY, "127.0.0.1", "timed out"):
                self.assertNotIn(secret, message)
            self.assertTrue(entered.wait(1))
            self.assertEqual(len(httpd.requests), 1)
        finally:
            release.set()
            for thread in handler_threads:
                thread.join(timeout=5)

    def test_invalid_context_or_oversize_is_rejected_before_http(self) -> None:
        httpd = self.start_server()
        adapter = self.output_adapter(httpd)
        base = [{"role": "user", "content": "hello"}]
        cases = [
            ([], "answer"),
            ([{"role": "user", "content": str(index)} for index in range(17)], "answer"),
            ([{"role": "tool", "content": "hello"}], "answer"),
            ([{"role": "user", "content": "hello", "extra": "field"}], "answer"),
            ([{"role": "user", "content": ""}], "answer"),
            (base, ""),
            (base, None),
            ("not-a-list", "answer"),
        ]
        for messages, output in cases:
            with self.subTest(messages=messages, output=output):
                with self.assertRaises(GuardError):
                    adapter.scan_response(messages, output)
        with self.assertRaises(GuardError):
            adapter.scan_response([{"role": "user", "content": "x" * 17000}], "answer")
        self.assertEqual(httpd.requests, [])

    def test_constructor_requires_exact_model(self) -> None:
        httpd = self.start_server()
        with self.assertRaises(GuardError):
            CloudflareLlamaGuardOutputAdapter(None)
        for model in (GROQ_PROMPT_GUARD_MODEL, "@cf/meta/llama-guard-3-1b", ""):
            with self.subTest(model=model):
                client = self.client(httpd, model=model, key=OUTPUT_KEY)
                with self.assertRaises(GuardError):
                    CloudflareLlamaGuardOutputAdapter(client)
        self.assertEqual(httpd.requests, [])


class HostedEnvMixin(FixtureMixin):
    def hosted_env(self, httpd: _FixtureServer, *, input_key_file: Path | None = None) -> dict[str, str]:
        env = {
            "NASI_LEMAK_APP_KEY_DIGEST": hashlib.sha256(APP_KEY.encode()).hexdigest(),
            "NASI_LEMAK_AUDIT_DSN": "postgresql://synthetic/audit",
            ENV_MODE: "guarded",
            ENV_URL: self.base_url(httpd),
            ENV_MODEL: GEN_MODEL,
            ENV_AUTH: "bearer",
            ENV_API_KEY: GEN_KEY,
            ENV_GUARD_BACKEND: GUARD_BACKEND_API,
            ENV_INPUT_GUARD_PROVIDER: INPUT_GUARD_PROVIDER_GROQ,
            ENV_INPUT_GUARD_URL: self.base_url(httpd),
            ENV_INPUT_GUARD_MODEL: GROQ_PROMPT_GUARD_MODEL,
            ENV_INPUT_GUARD_AUTH: "bearer",
            ENV_INPUT_GUARD_API_KEY: INPUT_KEY,
            ENV_INPUT_GUARD_THRESHOLD: "0.5",
            ENV_OUTPUT_GUARD_PROVIDER: OUTPUT_GUARD_PROVIDER_CLOUDFLARE,
            ENV_OUTPUT_GUARD_URL: self.base_url(httpd),
            ENV_OUTPUT_GUARD_MODEL: CLOUDFLARE_LLAMA_GUARD_MODEL,
            ENV_OUTPUT_GUARD_AUTH: "bearer",
            ENV_OUTPUT_GUARD_API_KEY: OUTPUT_KEY,
        }
        if input_key_file is not None:
            env.pop(ENV_INPUT_GUARD_API_KEY)
            env[ENV_INPUT_GUARD_API_KEY_FILE] = str(input_key_file)
        return env


class ServerWiringTests(HostedEnvMixin):
    def test_hosted_pair_is_wired_with_dedicated_clients_and_no_startup_http(self) -> None:
        httpd = self.start_server()
        adapters = make_adapters_from_env(self.hosted_env(httpd))
        self.assertIsInstance(adapters, server_module.RealGatewayAdapters)
        self.assertIsInstance(adapters.attack_guard, GroqPromptGuardInputAdapter)
        self.assertIs(adapters.attack_guard, adapters.tokenizer)
        self.assertIsInstance(adapters.output_guard, CloudflareLlamaGuardOutputAdapter)
        keys = {
            adapters.client.config.api_key,
            adapters.attack_guard._client.config.api_key,
            adapters.output_guard._client.config.api_key,
        }
        self.assertEqual(len(keys), 3)
        self.assertNotIn(GEN_KEY, {
            adapters.attack_guard._client.config.api_key,
            adapters.output_guard._client.config.api_key,
        })
        self.assertEqual(httpd.requests, [])

    def test_unknown_partial_or_invalid_hosted_selection_fails_before_loaders(self) -> None:
        httpd = self.start_server()
        base = self.hosted_env(httpd)
        cases = [
            {**base, ENV_INPUT_GUARD_PROVIDER: "other-provider"},
            {**base, ENV_OUTPUT_GUARD_PROVIDER: "other-provider"},
            {**base, ENV_INPUT_GUARD_PROVIDER: ""},
            {**base, ENV_OUTPUT_GUARD_PROVIDER: ""},
            {**base, ENV_INPUT_GUARD_MODEL: "meta-llama/Llama-Prompt-Guard-2-22M"},
            {**base, ENV_OUTPUT_GUARD_MODEL: "@cf/meta/llama-guard-3-1b"},
            {**base, ENV_INPUT_GUARD_AUTH: "none"},
            {**base, ENV_OUTPUT_GUARD_AUTH: "none"},
            {**base, ENV_INPUT_GUARD_API_KEY_FILE: str(self.root / "missing-key")},
        ]
        for env in cases:
            with self.subTest(env={k: v for k, v in env.items() if k in (ENV_INPUT_GUARD_PROVIDER, ENV_OUTPUT_GUARD_PROVIDER, ENV_INPUT_GUARD_MODEL, ENV_OUTPUT_GUARD_MODEL, ENV_INPUT_GUARD_AUTH, ENV_OUTPUT_GUARD_AUTH)}):
                self.assertIsNone(
                    make_adapters_from_env(env, client_loader=_must_not_build)
                )
        self.assertEqual(httpd.requests, [])

    def test_hosted_pair_does_not_require_or_use_the_old_contract(self) -> None:
        httpd = self.start_server()
        env = self.hosted_env(httpd)
        env[ENV_INPUT_GUARD_CONTRACT] = "not-the-old-contract"
        adapters = make_adapters_from_env(env)
        self.assertIsInstance(adapters.attack_guard, GroqPromptGuardInputAdapter)

    def test_default_pair_remains_custom_input_and_qwen_output(self) -> None:
        httpd = self.start_server()
        env = self.hosted_env(httpd)
        for name in (ENV_INPUT_GUARD_PROVIDER, ENV_OUTPUT_GUARD_PROVIDER):
            env.pop(name)
        env[ENV_INPUT_GUARD_MODEL] = "nasi-lemak/input-guard-api-1"
        env[ENV_OUTPUT_GUARD_MODEL] = "Qwen/Qwen3Guard-Gen-4B"
        env[ENV_INPUT_GUARD_CONTRACT] = INPUT_GUARD_CONTRACT_V1
        adapters = make_adapters_from_env(env)
        self.assertIsInstance(adapters.attack_guard, InputGuardApiAdapter)
        self.assertIsInstance(adapters.output_guard, Qwen3GuardOutputAdapter)

    def test_explicit_blank_whitespace_or_nonstring_selectors_fail_closed(self) -> None:
        httpd = self.start_server()
        env = self.hosted_env(httpd)
        for name in (ENV_INPUT_GUARD_PROVIDER, ENV_OUTPUT_GUARD_PROVIDER):
            env.pop(name)
        env[ENV_INPUT_GUARD_MODEL] = "nasi-lemak/input-guard-api-1"
        env[ENV_OUTPUT_GUARD_MODEL] = "Qwen/Qwen3Guard-Gen-4B"
        env[ENV_INPUT_GUARD_CONTRACT] = INPUT_GUARD_CONTRACT_V1
        cases = [
            {"": ""},
            {"   ": "  "},
            {"\t": "\n"},
            {
                ENV_INPUT_GUARD_PROVIDER: 1,
                ENV_OUTPUT_GUARD_PROVIDER: 2,
            },
            {
                ENV_INPUT_GUARD_PROVIDER: INPUT_GUARD_PROVIDER_GROQ,
                ENV_OUTPUT_GUARD_PROVIDER: 2,
            },
            {
                ENV_INPUT_GUARD_PROVIDER: None,
                ENV_OUTPUT_GUARD_PROVIDER: OUTPUT_GUARD_PROVIDER_CLOUDFLARE,
            },
        ]
        for selectors in cases:
            with self.subTest(selectors=selectors):
                explicit = {**env, **selectors}
                self.assertIsNone(
                    make_adapters_from_env(explicit, client_loader=_must_not_build)
                )

    def test_default_pair_still_requires_the_old_contract(self) -> None:
        httpd = self.start_server()
        env = self.hosted_env(httpd)
        for name in (ENV_INPUT_GUARD_PROVIDER, ENV_OUTPUT_GUARD_PROVIDER):
            env.pop(name)
        env[ENV_INPUT_GUARD_MODEL] = "nasi-lemak/input-guard-api-1"
        env[ENV_OUTPUT_GUARD_MODEL] = "Qwen/Qwen3Guard-Gen-4B"
        env.pop(ENV_INPUT_GUARD_CONTRACT, None)
        self.assertIsNone(make_adapters_from_env(env, client_loader=_must_not_build))


def _must_not_build(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("client loader must not run for invalid hosted settings")


class EndToEndHostedTests(HostedEnvMixin):
    def dispatcher(
        self,
        *,
        input_content: str = "0.05",
        input_prompt_tokens: Any = 12,
        input_status: int = 200,
        output_content: str = "safe",
        output_status: int = 200,
    ):
        def responder(request: dict[str, Any]) -> tuple[int, bytes]:
            body = request["json"] if isinstance(request["json"], dict) else {}
            model = body.get("model")
            if model == GEN_MODEL:
                return chat_payload("buffered answer", model=GEN_MODEL)
            if model == GROQ_PROMPT_GUARD_MODEL:
                if input_status != 200:
                    return _json({"error": {"message": "provider detail"}}, status=input_status)
                return groq_payload(input_content, prompt_tokens=input_prompt_tokens)
            if model == CLOUDFLARE_LLAMA_GUARD_MODEL:
                if output_status != 200:
                    return _json({"error": {"message": "provider detail"}}, status=output_status)
                return chat_payload(output_content, model=CLOUDFLARE_LLAMA_GUARD_MODEL)
            return _json({"error": {"message": "unknown fixture request"}}, status=400)

        return responder

    def make_hosted_app(self, httpd: _FixtureServer, responder) -> Any:
        httpd.responder = responder
        counter = {"value": 0}

        def audit_factory(_dsn: str) -> SqliteAuditStore:
            counter["value"] += 1
            return SqliteAuditStore(self.root / f"audit-{counter['value']}.sqlite3")

        with mock.patch.object(server_module, "PostgresAuditStore", audit_factory):
            return make_app(environ=self.hosted_env(httpd), policy=Policy())

    def chat(self, app: Any, content: str):
        client = TestClient(app)
        self.addCleanup(client.close)
        return client.post(
            "/v1/chat/completions",
            json={
                "model": "pilot-local",
                "messages": [{"role": "user", "content": content}],
                "max_tokens": 32,
            },
            headers={"Authorization": "Bearer " + APP_KEY},
        )

    def requests_for(self, httpd: _FixtureServer, model: str) -> list[dict[str, Any]]:
        return [
            request
            for request in httpd.requests
            if request["json"].get("model") == model
        ]

    def test_safe_path_uses_both_hosted_guards_and_separate_keys(self) -> None:
        httpd = self.start_server()
        app = self.make_hosted_app(httpd, self.dispatcher())
        response = self.chat(app, "email me at test@example.com")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["choices"][0]["message"]["content"], "buffered answer")
        inputs = self.requests_for(httpd, GROQ_PROMPT_GUARD_MODEL)
        generation = self.requests_for(httpd, GEN_MODEL)
        outputs = self.requests_for(httpd, CLOUDFLARE_LLAMA_GUARD_MODEL)
        self.assertEqual((len(inputs), len(generation), len(outputs)), (1, 1, 1))
        self.assertEqual(header(inputs[0], "Authorization"), "Bearer " + INPUT_KEY)
        self.assertEqual(header(generation[0], "Authorization"), "Bearer " + GEN_KEY)
        self.assertEqual(header(outputs[0], "Authorization"), "Bearer " + OUTPUT_KEY)
        # The input guard sees the raw accepted input; generation and output
        # receive the masked conversation, and the output guard sees the
        # buffered raw generation as the assistant turn.
        self.assertIn("test@example.com", inputs[0]["json"]["messages"][0]["content"])
        self.assertIn("[EMAIL]", generation[0]["json"]["messages"][0]["content"])
        self.assertIn("[EMAIL]", outputs[0]["json"]["messages"][0]["content"])
        self.assertEqual(
            outputs[0]["json"]["messages"][-1],
            {"role": "assistant", "content": "buffered answer"},
        )

    def test_input_block_or_error_never_calls_generation(self) -> None:
        cases = [
            (self.dispatcher(input_content="0.9"), 403),
            (self.dispatcher(input_status=401), 503),
            (self.dispatcher(input_prompt_tokens=512), 503),
        ]
        for responder, expected in cases:
            with self.subTest(expected=expected):
                httpd = self.start_server()
                app = self.make_hosted_app(httpd, responder)
                response = self.chat(app, "blocked prompt")
                self.assertEqual(response.status_code, expected, response.text)
                self.assertEqual(len(self.requests_for(httpd, GROQ_PROMPT_GUARD_MODEL)), 1)
                self.assertEqual(self.requests_for(httpd, GEN_MODEL), [])
                self.assertEqual(self.requests_for(httpd, CLOUDFLARE_LLAMA_GUARD_MODEL), [])

    def test_output_block_or_error_withholds_buffered_output(self) -> None:
        cases = [
            (self.dispatcher(output_content="unsafe\nS1"), 403),
            (self.dispatcher(output_status=429), 503),
            (self.dispatcher(output_content="safe extra"), 503),
        ]
        for responder, expected in cases:
            with self.subTest(expected=expected):
                httpd = self.start_server()
                app = self.make_hosted_app(httpd, responder)
                response = self.chat(app, "hello")
                self.assertEqual(response.status_code, expected, response.text)
                self.assertNotIn("buffered answer", response.text)
                self.assertEqual(len(self.requests_for(httpd, GEN_MODEL)), 1)
                self.assertEqual(len(self.requests_for(httpd, CLOUDFLARE_LLAMA_GUARD_MODEL)), 1)

    def test_missing_key_file_leaves_app_unready_without_http(self) -> None:
        httpd = self.start_server()
        env = self.hosted_env(httpd, input_key_file=self.root / "missing-key")
        counter = {"value": 0}

        def audit_factory(_dsn: str) -> SqliteAuditStore:
            counter["value"] += 1
            return SqliteAuditStore(self.root / f"audit-{counter['value']}.sqlite3")

        with mock.patch.object(server_module, "PostgresAuditStore", audit_factory):
            app = make_app(environ=env, policy=Policy())
        client = TestClient(app)
        self.addCleanup(client.close)
        self.assertEqual(client.get("/health/ready").status_code, 503)
        self.assertIsNone(app.state.gateway.adapters)
        self.assertEqual(httpd.requests, [])


class ComposePassthroughTests(unittest.TestCase):
    def test_compose_api_passes_optional_provider_selectors_unchanged(self) -> None:
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        root = Path(__file__).resolve().parents[1]
        document = yaml.safe_load((root / "compose.api.yaml").read_text(encoding="utf-8"))
        environment = document["services"]["gateway"]["environment"]
        rendered = {str(item) for item in environment}
        self.assertIn("NASI_LEMAK_INPUT_GUARD_PROVIDER", rendered)
        self.assertIn("NASI_LEMAK_OUTPUT_GUARD_PROVIDER", rendered)
        self.assertIn(
            "NASI_LEMAK_INPUT_GUARD_CONTRACT=nasi-lemak-input-classifier-v1", rendered
        )
        self.assertNotIn("groq-prompt-guard", "\n".join(rendered))
        self.assertNotIn("cloudflare-llama-guard", "\n".join(rendered))


if __name__ == "__main__":
    unittest.main()
