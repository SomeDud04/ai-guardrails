"""Wiring regressions for real guard composition, context and fail-closed paths.

Every guard/client here is an explicitly injected deterministic double. No
pretrained checkpoint, ML dependency, network endpoint or PostgreSQL instance is
used. These tests prove orchestration only, not guard accuracy, latency or
hardware behaviour.
"""

from __future__ import annotations

import contextlib
import json
import tempfile
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from nasi_lemak import server as server_module
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, MemoryAdapters, Policy, serialize_messages
from nasi_lemak.generation import (
    AUTH_NONE,
    ENV_API_KEY,
    ENV_AUTH,
    ENV_MODEL,
    ENV_URL,
    RealGatewayAdapters,
)
from nasi_lemak.guards import GuardError, PromptGuard2
from nasi_lemak.server import (
    ENV_LLAMA_GUARD_CONTEXT_LIMIT,
    ENV_LLAMA_GUARD_MODEL_DIR,
    ENV_POLICY_FILE,
    ENV_PROMPT_GUARD_MODEL_DIR,
    ENV_PROMPT_GUARD_THRESHOLD,
    POLICY_ACTIVATION_EXPLICIT,
    POLICY_ACTIVATION_UNAVAILABLE,
    make_adapters_from_env,
    make_app,
)

TEST_KEY = "wiring-test-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
UPSTREAM_MODEL = "upstream-model-1"


def request(messages: list[dict[str, str]]) -> dict[str, Any]:
    return {"model": "pilot-local", "messages": messages}


class _PromptGuard:
    def __init__(self, directory: str = "", threshold: float = 0.5) -> None:
        self.directory = directory
        self.threshold = threshold

    def count_tokens(self, serialized: str) -> int:
        return 1

    def scan_attack(self, text: str) -> dict[str, str]:
        return {"decision": "allow"}


class _LlamaGuard:
    def __init__(self, directory: str = "", context_limit: int = 2048) -> None:
        self.directory = directory
        self.context_limit = context_limit

    def scan_response(self, messages: list[dict[str, str]], output: str) -> dict[str, bool]:
        return {"safe": True}


class _OutputOnlyGuard:
    def scan_output(self, text: str) -> dict[str, bool]:
        return {"safe": True}


class _FakeClient:
    def __init__(self, config: Any = None) -> None:
        self.config = config
        self.calls: list[tuple[list[dict[str, str]], int]] = []

    def generate(self, messages: list[dict[str, str]], max_tokens: int) -> str:
        self.calls.append(([dict(message) for message in messages], max_tokens))
        return "generated answer"


class _Loader:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, directory: str, **kwargs: Any) -> Any:
        self.calls.append((directory, dict(kwargs)))
        return self.result


class _ClientLoader:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.configs: list[Any] = []

    def __call__(self, config: Any) -> Any:
        self.configs.append(config)
        return self.result


def _guard_env(root: Path, **overrides: str) -> dict[str, str]:
    prompt = root / "prompt-guard"
    llama = root / "llama-guard"
    prompt.mkdir(exist_ok=True)
    llama.mkdir(exist_ok=True)
    env = {
        ENV_URL: "http://127.0.0.1:9/v1",
        ENV_MODEL: UPSTREAM_MODEL,
        ENV_AUTH: AUTH_NONE,
        # A stale key with auth=none must be discarded, not sent.
        ENV_API_KEY: "stale-key-not-used",
        ENV_PROMPT_GUARD_MODEL_DIR: str(prompt),
        ENV_LLAMA_GUARD_MODEL_DIR: str(llama),
        ENV_PROMPT_GUARD_THRESHOLD: "0.5",
        ENV_LLAMA_GUARD_CONTEXT_LIMIT: "2048",
    }
    env.update(overrides)
    return env


class EnvFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_factory_composes_loaders_once_with_contextual_guard_and_no_auth(self) -> None:
        env = _guard_env(self.root)
        prompt = _PromptGuard()
        llama = _LlamaGuard()
        client = _FakeClient()
        prompt_loader = _Loader(prompt)
        llama_loader = _Loader(llama)
        client_loader = _ClientLoader(client)

        adapters = make_adapters_from_env(
            env,
            prompt_guard_loader=prompt_loader,
            llama_guard_loader=llama_loader,
            client_loader=client_loader,
        )

        self.assertIsInstance(adapters, RealGatewayAdapters)
        self.assertIs(adapters.tokenizer, prompt)
        self.assertIs(adapters.attack_guard, prompt)
        self.assertIs(adapters.output_guard, llama)
        self.assertIs(adapters.client, client)
        self.assertEqual(
            prompt_loader.calls,
            [(env[ENV_PROMPT_GUARD_MODEL_DIR], {"threshold": 0.5})],
        )
        self.assertEqual(
            llama_loader.calls,
            [(env[ENV_LLAMA_GUARD_MODEL_DIR], {"context_limit": 2048})],
        )
        self.assertEqual(len(client_loader.configs), 1)
        config = client_loader.configs[0]
        self.assertEqual(config.model, UPSTREAM_MODEL)
        self.assertEqual(config.auth_mode, AUTH_NONE)
        self.assertIsNone(config.api_key)
        self.assertEqual(client.calls, [])

    def test_invalid_or_missing_configuration_never_runs_a_loader(self) -> None:
        base = _guard_env(self.root)
        loader_calls: list[tuple[Any, ...]] = []

        def must_not_load(*args: Any, **kwargs: Any) -> Any:
            loader_calls.append(args)
            raise AssertionError("loader must not run for invalid configuration")

        file_path = self.root / "not-a-directory"
        file_path.write_text("x", encoding="utf-8")
        missing = str(self.root / "missing-directory")

        cases: list[dict[str, str]] = []
        for name in (
            ENV_URL,
            ENV_MODEL,
            ENV_PROMPT_GUARD_MODEL_DIR,
            ENV_LLAMA_GUARD_MODEL_DIR,
            ENV_PROMPT_GUARD_THRESHOLD,
            ENV_LLAMA_GUARD_CONTEXT_LIMIT,
        ):
            env = dict(base)
            env.pop(name)
            cases.append(env)
        for name, value in (
            (ENV_PROMPT_GUARD_MODEL_DIR, missing),
            (ENV_LLAMA_GUARD_MODEL_DIR, missing),
            (ENV_PROMPT_GUARD_MODEL_DIR, str(file_path)),
            (ENV_PROMPT_GUARD_THRESHOLD, "nan"),
            (ENV_PROMPT_GUARD_THRESHOLD, "inf"),
            (ENV_PROMPT_GUARD_THRESHOLD, "-0.1"),
            (ENV_PROMPT_GUARD_THRESHOLD, "1.5"),
            (ENV_PROMPT_GUARD_THRESHOLD, "not-a-number"),
            (ENV_LLAMA_GUARD_CONTEXT_LIMIT, "0"),
            (ENV_LLAMA_GUARD_CONTEXT_LIMIT, "32"),
            (ENV_LLAMA_GUARD_CONTEXT_LIMIT, "2048.5"),
            (ENV_LLAMA_GUARD_CONTEXT_LIMIT, "abc"),
        ):
            env = dict(base)
            env[name] = value
            cases.append(env)

        # Bearer auth without a key is also rejected before any loader.
        bearer = dict(base)
        bearer[ENV_AUTH] = "bearer"
        bearer.pop(ENV_API_KEY, None)
        cases.append(bearer)

        for env in cases:
            with self.subTest(env={k: v for k, v in env.items() if k.startswith("NASI_LEMAK_")}):
                self.assertIsNone(
                    make_adapters_from_env(
                        env,
                        prompt_guard_loader=must_not_load,
                        llama_guard_loader=must_not_load,
                        client_loader=must_not_load,
                    )
                )
        self.assertEqual(loader_calls, [])

    def test_default_loaders_fail_closed_without_local_artifacts_or_ml_deps(self) -> None:
        # The empty directories exist, but contain no tokenizer/config/weights
        # and the optional ML extra is not installed in this workspace.
        self.assertIsNone(make_adapters_from_env(_guard_env(self.root)))

    def test_real_adapter_requires_contextual_output_guard(self) -> None:
        client = _FakeClient()
        prompt = _PromptGuard()
        with self.assertRaises(ValueError):
            RealGatewayAdapters(
                client,
                tokenizer=prompt,
                attack_guard=prompt,
                output_guard=_OutputOnlyGuard(),
            )
        adapters = RealGatewayAdapters(
            client,
            tokenizer=prompt,
            attack_guard=prompt,
            output_guard=_LlamaGuard(),
        )
        self.assertEqual(
            adapters.scan_response([{"role": "user", "content": "x"}], "out"),
            {"safe": True},
        )
        # The structural method remains for readiness, but a context-free call
        # must never silently screen only the response text.
        with self.assertRaises(ValueError):
            adapters.scan_output("out")


class _ContextAdapters:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.attack_inputs: list[str] = []
        self.context_inputs: list[tuple[list[dict[str, str]], str]] = []
        self.generation_inputs: list[list[dict[str, str]]] = []
        self.output_only_calls = 0
        self.generated = "SECRET-BUFFERED-OUTPUT"
        self.result: Any = {"safe": True}
        self.error: Exception | None = None

    def count_tokens(self, serialized: str) -> int:
        return max(1, len(serialized.split()))

    def scan_attack(self, text: str) -> Any:
        with self._lock:
            self.attack_inputs.append(text)
        return {"decision": "allow"}

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        with self._lock:
            self.generation_inputs.append([dict(message) for message in messages])
        return self.generated

    def scan_response(self, messages: list[dict[str, str]], output: str) -> Any:
        with self._lock:
            self.context_inputs.append(([dict(message) for message in messages], output))
        if self.error is not None:
            raise self.error
        return self.result

    def scan_output(self, text: str) -> Any:
        with self._lock:
            self.output_only_calls += 1
        raise AssertionError("context-free output scan must not be used")


class ContextualGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "audit.sqlite3"

    def _gateway(self, adapters: Any) -> Gateway:
        return Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(self.path),
            adapters=adapters,
        )

    def _client(self, gateway: Gateway) -> TestClient:
        client = TestClient(make_app(gateway=gateway))
        self.addCleanup(client.close)
        return client

    def test_asgi_success_passes_all_sanitized_turns_and_buffered_output(self) -> None:
        adapters = _ContextAdapters()
        gateway = self._gateway(adapters)
        client = self._client(gateway)
        messages = [
            {"role": "system", "content": "system test@example.com"},
            {"role": "user", "content": "user +60123456789"},
            {"role": "assistant", "content": "prior answer"},
        ]

        response = client.post(
            "/v1/chat/completions", json=request(messages), headers=AUTH
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(adapters.context_inputs), 1)
        context, output = adapters.context_inputs[0]
        self.assertEqual(
            context,
            [
                {"role": "system", "content": "system [EMAIL]"},
                {"role": "user", "content": "user [MY_PHONE]"},
                {"role": "assistant", "content": "prior answer"},
            ],
        )
        self.assertEqual(output, adapters.generated)
        self.assertEqual(adapters.output_only_calls, 0)
        self.assertEqual(adapters.attack_inputs, [serialize_messages(messages)])
        self.assertEqual(
            [dict(message) for message in adapters.generation_inputs[0] if message["role"] != "system"],
            [
                {"role": "user", "content": "user [MY_PHONE]"},
                {"role": "assistant", "content": "prior answer"},
            ],
        )
        events = gateway.audit_events()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_completed"],
        )

    def test_guard_error_window_overflow_or_malformed_verdict_releases_nothing(self) -> None:
        for error in (
            GuardError("guard context exceeds the configured window"),
            GuardError("guard output was not a recognized verdict"),
        ):
            with self.subTest(error=str(error)):
                adapters = _ContextAdapters()
                adapters.error = error
                gateway = self._gateway(adapters)
                client = self._client(gateway)
                response = client.post(
                    "/v1/chat/completions",
                    json=request([{"role": "user", "content": "hello"}]),
                    headers=AUTH,
                )
                self.assertEqual(response.status_code, 503, response.text)
                self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
                self.assertNotIn("choices", response.json())
                self.assertNotIn(adapters.generated, response.text)
                self.assertNotIn("window", response.text)
                self.assertNotIn("verdict", response.text)
                self.assertEqual(gateway.audit_events()[-1]["event_type"], "request_failed")

        adapters = _ContextAdapters()
        adapters.result = {"safe": "yes"}
        client = self._client(self._gateway(adapters))
        response = client.post(
            "/v1/chat/completions",
            json=request([{"role": "user", "content": "hello"}]),
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn("choices", response.json())

    def test_unsafe_verdict_blocks_without_releasing_output(self) -> None:
        adapters = _ContextAdapters()
        adapters.result = {"safe": False}
        client = self._client(self._gateway(adapters))
        response = client.post(
            "/v1/chat/completions",
            json=request([{"role": "user", "content": "hello"}]),
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json()["error"]["code"], "POLICY_BLOCK")
        self.assertNotIn("choices", response.json())
        self.assertNotIn(adapters.generated, response.text)

    def test_terminal_audit_failure_withholds_guarded_output(self) -> None:
        adapters = _ContextAdapters()
        gateway = self._gateway(adapters)
        gateway.fail_audit_stage = "terminal"
        client = self._client(gateway)
        response = client.post(
            "/v1/chat/completions",
            json=request([{"role": "user", "content": "hello"}]),
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn("choices", response.json())
        self.assertNotIn(adapters.generated, response.text)
        self.assertEqual(len(adapters.context_inputs), 1)

    def test_concurrent_requests_do_not_share_context(self) -> None:
        workers = 8
        adapters = _ContextAdapters()
        barrier = threading.Barrier(workers)
        contexts: list[tuple[list[dict[str, str]], str]] = []
        lock = threading.Lock()
        generated = adapters.generated

        def scan_response(messages: list[dict[str, str]], output: str) -> Any:
            copy = ([dict(message) for message in messages], output)
            with lock:
                contexts.append(copy)
            barrier.wait(timeout=10)
            return {"safe": True}

        adapters.scan_response = scan_response

        def generate(messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
            return "reply " + messages[-1]["content"]

        adapters.generate = generate
        gateway = self._gateway(adapters)

        def call(index: int) -> int:
            status, _ = gateway.handle(
                "POST",
                "/v1/chat/completions",
                {"Authorization": "Bearer " + TEST_KEY},
                request([{"role": "user", "content": f"thread-{index}-marker"}]),
            )
            return status

        with ThreadPoolExecutor(max_workers=workers) as pool:
            statuses = list(pool.map(call, range(workers)))

        self.assertEqual(statuses, [200] * workers)
        self.assertEqual(len(contexts), workers)
        for index in range(workers):
            own = [
                (messages, output)
                for messages, output in contexts
                if messages[0]["content"] == f"thread-{index}-marker"
            ]
            self.assertEqual(len(own), 1)
            messages, output = own[0]
            self.assertEqual(len(messages), 1)
            self.assertEqual(output, f"reply thread-{index}-marker")
            self.assertEqual(generated, "SECRET-BUFFERED-OUTPUT")


class _ToyTokenizer:
    """One token per whitespace word plus two special tokens, like test_guards."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def __call__(self, text: str, add_special_tokens: bool = True, truncation: bool = False) -> Any:
        if add_special_tokens is not True or truncation is not False:
            raise AssertionError("tokenizer must not truncate")
        self.calls.append(text)
        return {"input_ids": [1] + [100 + (index % 50) for index, _ in enumerate(text.split())] + [2]}


class _ToyBackend:
    def tensor(self, values: Any) -> Any:
        return values

    def inference_mode(self) -> Any:
        return contextlib.nullcontext()


class _ToyClassifier:
    def __init__(self) -> None:
        self.config = types.SimpleNamespace(id2label={0: "BENIGN", 1: "MALICIOUS"})

    def eval(self) -> "_ToyClassifier":
        return self

    def to(self, device: str) -> "_ToyClassifier":
        return self

    def __call__(self, **inputs: Any) -> Any:
        return {"logits": [[0.0, -10.0]]}


class _ToyOutputGuard:
    def scan_response(self, messages: list[dict[str, str]], output: str) -> dict[str, bool]:
        return {"safe": True}


class InputCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_full_serialization_uses_real_prompt_guard_tokenizer_and_rejects_over_512(self) -> None:
        tokenizer = _ToyTokenizer()
        prompt_guard = PromptGuard2(
            self.tmp.name,
            threshold=0.5,
            tokenizer=tokenizer,
            model=_ToyClassifier(),
            backend=_ToyBackend(),
        )
        client = _FakeClient()
        adapters = RealGatewayAdapters(
            client,
            tokenizer=prompt_guard,
            attack_guard=prompt_guard,
            output_guard=_ToyOutputGuard(),
        )
        gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            adapters=adapters,
        )
        messages = [
            {"role": "system", "content": "system context"},
            {"role": "user", "content": "user question"},
            {"role": "assistant", "content": "assistant history"},
        ]

        status, _ = gateway.handle(
            "POST", "/v1/chat/completions", {"Authorization": "Bearer " + TEST_KEY}, request(messages)
        )
        self.assertEqual(status, 200)
        canonical = serialize_messages(messages)
        self.assertEqual(tokenizer.calls[0], canonical)
        self.assertEqual(tokenizer.calls[1], canonical)
        for message in messages:
            self.assertIn(message["content"], tokenizer.calls[0])
        self.assertEqual(len(client.calls), 1)

        too_long = [{"role": "user", "content": " ".join(["word"] * 511)}]
        status, body = gateway.handle(
            "POST", "/v1/chat/completions", {"Authorization": "Bearer " + TEST_KEY}, request(too_long)
        )
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "INPUT_LIMIT")
        self.assertEqual(tokenizer.calls[-1], serialize_messages(too_long))
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(gateway.audit_events()[-1]["event_type"], "request_blocked")


class StartupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _client(self, app: Any) -> TestClient:
        client = TestClient(app)
        self.addCleanup(client.close)
        return client

    def test_default_startup_is_unready_without_guard_artifacts(self) -> None:
        env = _guard_env(Path(self.tmp.name))
        # The guard directories exist but are empty. No model ID is fabricated.
        app = make_app(environ=env)
        client = self._client(app)
        self.assertEqual(client.get("/health/live").status_code, 200)
        self.assertEqual(client.get("/health/ready").status_code, 503)
        response = client.post(
            "/v1/chat/completions",
            json=request([{"role": "user", "content": "hello"}]),
            headers={"Authorization": "Bearer any"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertIsNone(app.state.gateway.adapters)
        self.assertNotIsInstance(app.state.gateway.adapters, MemoryAdapters)
        self.assertEqual(app.state.policy_activation, POLICY_ACTIVATION_UNAVAILABLE)

    def test_missing_policy_is_unavailable_but_explicit_policy_is_allowed(self) -> None:
        env = {
            "NASI_LEMAK_APP_KEY_DIGEST": "a" * 64,
            ENV_URL: "http://127.0.0.1:9/v1",
            ENV_MODEL: UPSTREAM_MODEL,
            ENV_AUTH: AUTH_NONE,
        }
        missing_app = make_app(environ=dict(env))
        self.assertFalse(missing_app.state.config_ready)
        self.assertEqual(
            missing_app.state.policy_activation, POLICY_ACTIVATION_UNAVAILABLE
        )
        self.assertEqual(missing_app.state.gateway.policy.model, "pilot-local")

        explicit_app = make_app(environ=dict(env), policy=Policy())
        self.assertEqual(
            explicit_app.state.policy_activation, POLICY_ACTIVATION_EXPLICIT
        )
        self.assertEqual(explicit_app.state.gateway.policy.model, "pilot-local")

        invalid_app = make_app(environ=dict(env), policy=object())
        self.assertFalse(invalid_app.state.config_ready)
        self.assertEqual(
            self._client(invalid_app).get("/health/ready").status_code, 503
        )
        self.assertEqual(
            invalid_app.state.policy_activation, POLICY_ACTIVATION_UNAVAILABLE
        )

    def test_adapter_factory_runs_once_per_app_not_per_request_or_readiness(self) -> None:
        class ReadyAdapters:
            def count_tokens(self, serialized: str) -> int:
                return 1

            def scan_attack(self, text: str) -> dict[str, str]:
                return {"decision": "allow"}

            def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
                return "answer"

            def scan_output(self, text: str) -> dict[str, bool]:
                return {"safe": True}

        policy_path = Path(self.tmp.name) / "policy.yaml"
        policy_path.write_text(
            json.dumps(
                {
                    "app_id": "nasi-lemak",
                    "version": "factory-test",
                    "model": "pilot-local",
                    "token_budget": 128,
                    "deny_phrases": [],
                }
            ),
            encoding="utf-8",
        )
        environ = {
            "NASI_LEMAK_APP_KEY_DIGEST": "a" * 64,
            ENV_POLICY_FILE: str(policy_path),
        }
        with mock.patch.object(
            server_module,
            "make_adapters_from_env",
            return_value=ReadyAdapters(),
        ) as factory:
            app = make_app(environ=environ)
            client = self._client(app)
            for _ in range(3):
                client.get("/health/live")
                client.get("/health/ready")
                client.post(
                    "/v1/chat/completions",
                    json=request([{"role": "user", "content": "hello"}]),
                    headers={"Authorization": "Bearer any"},
                )
        self.assertEqual(factory.call_count, 1)


if __name__ == "__main__":
    unittest.main()
