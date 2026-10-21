"""Explicit test-mode integration tests.

Test mode is the only supported unguarded posture: it uses a real
``GenerationClient`` against a mocked HTTP transport while the native guard
classifiers are deliberately inactive. Inputs are synthetic; no network or
pretrained checkpoint is used. These tests prove orchestration and transport
parsing only, not guard accuracy or deployment readiness.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from nasi_lemak import generation as generation_module
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.generation import (
    AUTH_NONE,
    ENV_API_KEY,
    ENV_AUTH,
    ENV_MODEL,
    ENV_URL,
    GenerationClient,
    TestGatewayAdapters,
)
from nasi_lemak.server import (
    ENV_ALLOW_UNGUARDED_TEST,
    ENV_LLAMA_GUARD_CONTEXT_LIMIT,
    ENV_LLAMA_GUARD_MODEL_DIR,
    ENV_MODE,
    ENV_PROMPT_GUARD_MODEL_DIR,
    ENV_PROMPT_GUARD_THRESHOLD,
    make_adapters_from_env,
    make_app,
)

TEST_KEY = "test-mode-chat-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
OPERATOR_KEY = "test-mode-operator-key"
UPSTREAM_MODEL = "exact-upstream-model-42"
JSON_BODY = {
    "model": "pilot-local",
    "messages": [{"role": "user", "content": "Email person@example.com"}],
}


class _FakeTransport:
    """Mocked urllib transport: records requests, returns one fixed response."""

    def __init__(self, payload: dict[str, Any]):
        self.payload = payload
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float | None = None) -> Any:
        self.requests.append(request)
        return _FakeResponse(self.payload)


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]):
        body = json.dumps(payload).encode("utf-8")
        self.status = 200
        self.headers = {"Content-Length": str(len(body))}
        self._body = body

    def read(self, amount: int = -1) -> bytes:
        return self._body if amount < 0 else self._body[:amount]

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


def _completion(content: str) -> dict[str, Any]:
    return {
        "id": "upstream-completion",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
    }


def _test_env() -> dict[str, str]:
    return {
        ENV_URL: "http://127.0.0.1:9/v1",
        ENV_MODEL: UPSTREAM_MODEL,
        ENV_AUTH: AUTH_NONE,
        # A stale key with auth=none must be discarded, not sent upstream.
        ENV_API_KEY: "stale-key-not-used",
        ENV_MODE: "test",
        ENV_ALLOW_UNGUARDED_TEST: "true",
    }


def _guarded_env(root: Path) -> dict[str, str]:
    prompt = root / "prompt-guard"
    llama = root / "llama-guard"
    prompt.mkdir(exist_ok=True)
    llama.mkdir(exist_ok=True)
    return {
        ENV_URL: "http://127.0.0.1:9/v1",
        ENV_MODEL: UPSTREAM_MODEL,
        ENV_AUTH: AUTH_NONE,
        ENV_PROMPT_GUARD_MODEL_DIR: str(prompt),
        ENV_LLAMA_GUARD_MODEL_DIR: str(llama),
        ENV_PROMPT_GUARD_THRESHOLD: "0.5",
        ENV_LLAMA_GUARD_CONTEXT_LIMIT: "2048",
    }


class _Reader:
    def fetch_page(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("admin shell must not read events")


class TestModeFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_default_guarded_without_checkpoints_is_unready(self) -> None:
        env = {
            ENV_URL: "http://127.0.0.1:9/v1",
            ENV_MODEL: UPSTREAM_MODEL,
            ENV_AUTH: AUTH_NONE,
        }
        self.assertIsNone(make_adapters_from_env(env))

        app = make_app(environ=env)
        client = TestClient(app)
        ready = client.get("/health/ready")
        self.assertEqual(ready.status_code, 503)
        self.assertEqual(ready.json()["mode"], "guarded")
        self.assertFalse(ready.json()["guards_active"])
        chat = client.post("/v1/chat/completions", json=JSON_BODY, headers=AUTH)
        self.assertEqual(chat.status_code, 503)
        self.assertEqual(chat.headers["X-Nasi-Lemak-Mode"], "guarded")
        self.assertEqual(chat.headers["X-Nasi-Lemak-Guards-Active"], "false")

    def test_test_mode_requires_explicit_acknowledgement_before_loading(self) -> None:
        calls: list[Any] = []

        def must_not_load(*args: Any, **kwargs: Any) -> Any:
            calls.append(args)
            raise AssertionError("loader must not run without acknowledgement")

        env = _test_env()
        env.pop(ENV_ALLOW_UNGUARDED_TEST)
        self.assertIsNone(make_adapters_from_env(env, client_loader=must_not_load))
        self.assertEqual(calls, [])

        app = make_app(environ=env)
        ready = TestClient(app).get("/health/ready")
        self.assertEqual(ready.status_code, 503)
        self.assertFalse(ready.json()["guards_active"])

    def test_unknown_mode_fails_closed(self) -> None:
        env = _test_env()
        env[ENV_MODE] = "demo"
        self.assertIsNone(make_adapters_from_env(env))

        app = make_app(environ=env)
        client = TestClient(app)
        ready = client.get("/health/ready")
        self.assertEqual(ready.status_code, 503)
        self.assertEqual(ready.json()["mode"], "invalid")
        self.assertFalse(ready.json()["guards_active"])
        chat = client.post("/v1/chat/completions", json=JSON_BODY, headers=AUTH)
        self.assertEqual(chat.status_code, 503)

    def test_guarded_loader_error_stays_unready_without_test_fallback(self) -> None:
        class _Client:
            def generate(self, messages: Any, max_tokens: int) -> str:
                return "unused"

        def explain(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("optional ML dependency unavailable")

        env = _guarded_env(self.root)
        self.assertIsNone(
            make_adapters_from_env(
                env,
                client_loader=lambda config: _Client(),
                prompt_guard_loader=explain,
                llama_guard_loader=explain,
            )
        )
        # The same environment without the test acknowledgement must never
        # silently produce unguarded adapters.
        self.assertIsNone(make_adapters_from_env(env))


class TestModeChatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.transport = _FakeTransport(_completion("Contact person@example.com"))
        patcher = mock.patch.object(
            generation_module.GenerationClient,
            "_opener",
            lambda _client: self.transport,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _app(
        self,
        *,
        deny: tuple[str, ...] = (),
        operator: bool = False,
    ) -> tuple[Any, Gateway]:
        adapters = make_adapters_from_env(_test_env())
        self.assertIsInstance(adapters, TestGatewayAdapters)
        self.assertIsInstance(adapters.client, GenerationClient)
        gateway = Gateway(
            key_digest=hashlib.sha256(TEST_KEY.encode()).hexdigest(),
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            adapters=adapters,
            policy=Policy(app_id="nasi-lemak", deny_phrases=deny),
        )
        kwargs: dict[str, Any] = {}
        if operator:
            kwargs["operator_key_digest"] = hashlib.sha256(
                OPERATOR_KEY.encode()
            ).hexdigest()
            kwargs["operator_reader"] = _Reader()
        app = make_app(
            gateway=gateway,
            environ={
                ENV_MODE: "test",
                ENV_ALLOW_UNGUARDED_TEST: "true",
            },
            **kwargs,
        )
        return app, gateway

    def _request_body(self, request: Any) -> dict[str, Any]:
        self.assertIsNotNone(request.data)
        return json.loads(request.data.decode("utf-8"))

    def test_real_client_reaches_mocked_upstream_with_exact_model_and_masks_pii(
        self,
    ) -> None:
        app, gateway = self._app()
        client = TestClient(app)
        response = client.post("/v1/chat/completions", json=JSON_BODY, headers=AUTH)

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["model"], "pilot-local")
        self.assertEqual(payload["choices"][0]["message"]["content"], "Contact [EMAIL]")

        self.assertEqual(len(self.transport.requests), 1)
        upstream = self.transport.requests[0]
        self.assertTrue(upstream.full_url.endswith("/chat/completions"))
        self.assertIsNone(upstream.get_header("Authorization"))
        sent = self._request_body(upstream)
        self.assertEqual(sent["model"], UPSTREAM_MODEL)
        self.assertEqual(sent["messages"][0]["content"], "Email [EMAIL]")
        self.assertIs(sent["stream"], False)

        events = gateway.audit_events()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_completed"],
        )

    def test_deny_phrase_blocks_before_upstream(self) -> None:
        app, _gateway = self._app(deny=("forbidden phrase",))
        client = TestClient(app)
        body = {
            "model": "pilot-local",
            "messages": [{"role": "user", "content": "say the forbidden phrase"}],
        }
        response = client.post("/v1/chat/completions", json=body, headers=AUTH)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(self.transport.requests, [])

    def test_invalid_and_unknown_fields_cannot_override_server_mode(self) -> None:
        app, _gateway = self._app()
        client = TestClient(app)
        for body in (
            {"model": "pilot-local", "messages": [{"role": "user", "content": "hi"}], "mode": "guarded"},
            {"model": "pilot-local", "messages": [{"role": "user", "content": "hi"}], "mode": "test"},
            {"model": "attacker-model", "messages": [{"role": "user", "content": "hi"}]},
            {"model": "pilot-local", "messages": []},
        ):
            with self.subTest(body=body):
                response = client.post(
                    "/v1/chat/completions", json=body, headers=AUTH
                )
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.transport.requests, [])

    def test_auth_and_audit_fail_closed_without_upstream_calls(self) -> None:
        app, gateway = self._app()
        client = TestClient(app)

        unauthorized = client.post(
            "/v1/chat/completions",
            json=JSON_BODY,
            headers={"Authorization": "Bearer wrong-key"},
        )
        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(self.transport.requests, [])

        gateway.fail_audit_stage = "initial"
        audit_failure = client.post(
            "/v1/chat/completions", json=JSON_BODY, headers=AUTH
        )
        self.assertEqual(audit_failure.status_code, 503)
        self.assertEqual(audit_failure.json()["error"]["code"], "UNAVAILABLE")
        self.assertEqual(self.transport.requests, [])

    def test_readiness_headers_and_admin_report_inactive_test_mode(self) -> None:
        app, _gateway = self._app(operator=True)
        client = TestClient(app)

        ready = client.get("/health/ready")
        self.assertEqual(ready.status_code, 200, ready.text)
        self.assertEqual(
            ready.json(),
            {"status": "ready", "mode": "test", "guards_active": False},
        )
        self.assertEqual(ready.headers["X-Nasi-Lemak-Mode"], "test")
        self.assertEqual(ready.headers["X-Nasi-Lemak-Guards-Active"], "false")

        admin = client.get("/admin")
        self.assertEqual(admin.status_code, 200, admin.text)
        self.assertIn("Test mode", admin.text)
        self.assertIn("LLM guards are inactive", admin.text)
        self.assertIn("not protected", admin.text)
        self.assertNotIn("guards are active", admin.text.lower())


if __name__ == "__main__":
    unittest.main()
