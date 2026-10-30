"""Tests for the ``POST /chat`` testing shim and the stdlib CLI script.

Everything here uses in-process fakes only: no model, guard or network endpoint
is contacted.  The shim must be a thin map over the same ``gateway.handle``
pipeline and the same admission lane as ``POST /v1/chat/completions``.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.server import make_app

TEST_KEY = "chat-test-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
V1_BODY = {
    "model": "pilot-local",
    "messages": [{"role": "user", "content": "Hello"}],
}
PII_PROMPT = "Email person@example.com"


class FakeAdapters:
    """Deterministic local adapters; no network, model or guard execution."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.token_inputs: list[str] = []
        self.attack_inputs: list[str] = []
        self.generate_inputs: list[list[dict[str, str]]] = []
        self.generate_calls = 0
        self.generated = "Synthetic local answer."
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
        if self.output_error:
            raise self.output_error
        return self.output_result


class ChatEndpointTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapters = FakeAdapters()
        self.gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            adapters=self.adapters,
        )
        self.app = make_app(gateway=self.gateway)
        self.client = TestClient(self.app)
        self.addCleanup(self.client.close)

    def post(self, body: Any = None, *, headers: Any = None):
        return self.client.post(
            "/chat",
            json={"prompt": "Hello"} if body is None else body,
            headers=AUTH if headers is None else headers,
        )


class ChatAllowPathTests(ChatEndpointTestBase):
    def test_allow_matches_audit_row_and_masked_generation_input(self) -> None:
        response = self.post({"prompt": PII_PROMPT})

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["decision"], "ALLOW")
        self.assertEqual(payload["sanitized_prompt"], "Email [EMAIL]")
        self.assertEqual(payload["input_safety_label"], "safe")
        self.assertEqual(payload["output_safety_label"], "safe")
        self.assertIsInstance(payload["latency_ms"], int)
        self.assertEqual(payload["response"], "Synthetic local answer.")

        # The exact sanitized text shown in the blueprint body is the text the
        # real pipeline passed to generation.
        self.assertEqual(
            self.adapters.generate_inputs,
            [[{"role": "user", "content": payload["sanitized_prompt"]}]],
        )

        # The terminal audit row is the ordinary /v1 row: same event types,
        # policy metadata and allowed decision.  Labels are derived from this
        # same request-scoped outcome.
        events = self.gateway.audit_events()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_completed"],
        )
        self.assertEqual({event["request_id"] for event in events}, {events[0]["request_id"]})
        self.assertEqual(events[-1]["decision"], "allowed")
        self.assertEqual(payload["decision"], "ALLOW")
        # The served latency is exactly the two audit rows this request wrote,
        # never a second timer.
        self.assertEqual(
            payload["latency_ms"],
            int(
                round(
                    (events[1]["timestamp"] - events[0]["timestamp"]) * 1000
                )
            ),
        )

    def test_chat_does_not_create_a_second_audit_row_shape(self) -> None:
        self.post()
        events = self.gateway.audit_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event_type"], "request_started")
        self.assertEqual(events[1]["event_type"], "request_completed")
        self.assertEqual(
            set(events[1]) - {"seq", "timestamp"},
            {
                "request_id",
                "event_type",
                "app_id",
                "model",
                "policy_version",
                "policy_digest",
                "decision",
                "error_code",
            },
        )

    def test_audit_rows_match_equivalent_v1_request_and_v1_schema_unchanged(
        self,
    ) -> None:
        chat_response = self.post({"prompt": "Hello"})
        v1_response = self.client.post(
            "/v1/chat/completions", json=V1_BODY, headers=AUTH
        )
        self.assertEqual(chat_response.status_code, 200, chat_response.text)
        self.assertEqual(v1_response.status_code, 200, v1_response.text)

        # /v1 keeps exactly its OpenAI-compatible schema; the extended /chat
        # view must not leak into it.
        self.assertEqual(
            set(v1_response.json()), {"id", "object", "model", "choices"}
        )
        self.assertNotIn("decision", v1_response.json())
        self.assertNotIn("sanitized_prompt", v1_response.json())
        self.assertNotIn("latency_ms", v1_response.json())

        events = self.gateway.audit_events()
        self.assertEqual(len(events), 4)

        def normalized(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
            # Only the nondeterministic identifiers/timestamps and the sequence
            # counter are changed; every audit column and value is compared.
            return [
                {
                    **{
                        key: value
                        for key, value in row.items()
                        if key not in ("seq", "timestamp", "request_id")
                    },
                    "seq": index,
                    "timestamp": 0,
                    "request_id": "<request>",
                }
                for index, row in enumerate(rows)
            ]

        self.assertEqual(normalized(events[:2]), normalized(events[2:]))


class ChatBlockPathTests(ChatEndpointTestBase):
    def test_input_guard_block_is_generic_and_categorised(self) -> None:
        self.adapters.attack_result = {"decision": "block"}

        response = self.post({"prompt": "synthetic attack text"})

        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertEqual(payload["decision"], "BLOCK")
        self.assertEqual(payload["category"], "INPUT_GUARD_BLOCK")
        self.assertEqual(payload["input_safety_label"], "blocked")
        self.assertEqual(
            set(payload),
            {
                "decision",
                "reason",
                "input_safety_label",
                "category",
                "latency_ms",
            },
        )
        # Masking never ran for an input-stage block, so no sanitized text is
        # exposed (and none is computed in the shim).
        self.assertNotIn("sanitized_prompt", payload)
        self.assertNotIn("output_safety_label", payload)
        self.assertEqual(
            payload["reason"], "The prompt did not pass the input safety check."
        )
        self.assertNotIn("response", payload)
        self.assertNotIn("Synthetic local answer", response.text)
        self.assertNotIn("synthetic attack text", response.text)
        self.assertEqual(self.adapters.generate_calls, 0)

        events = self.gateway.audit_events()
        self.assertEqual(events[-1]["event_type"], "request_blocked")
        self.assertEqual(events[-1]["decision"], "blocked")
        self.assertEqual(events[-1]["error_code"], "POLICY_BLOCK")
        self.assertEqual(
            payload["latency_ms"],
            int(
                round(
                    (events[-1]["timestamp"] - events[-2]["timestamp"]) * 1000
                )
            ),
        )

    def test_output_guard_block_does_not_leak_model_output(self) -> None:
        self.adapters.generated = "RAW MODEL OUTPUT MUST NOT LEAK"
        self.adapters.output_result = {"safe": False}

        response = self.post({"prompt": "Hello"})

        self.assertEqual(response.status_code, 403)
        payload = response.json()
        self.assertEqual(payload["decision"], "BLOCK")
        self.assertEqual(payload["category"], "OUTPUT_GUARD_BLOCK")
        self.assertEqual(payload["input_safety_label"], "safe")
        # Masking already ran before generation, so this request's masked input
        # is honestly exposed; the block body still omits output_safety_label.
        self.assertEqual(payload["sanitized_prompt"], "Hello")
        self.assertNotIn("output_safety_label", payload)
        self.assertEqual(
            set(payload),
            {
                "decision",
                "reason",
                "input_safety_label",
                "category",
                "sanitized_prompt",
                "latency_ms",
            },
        )
        self.assertEqual(
            self.adapters.generate_inputs,
            [[{"role": "user", "content": payload["sanitized_prompt"]}]],
        )
        self.assertNotIn("RAW MODEL OUTPUT", response.text)
        self.assertNotIn("response", payload)
        self.assertNotIn("stage", payload)
        self.assertNotIn("reason_code", payload)
        events = self.gateway.audit_events()
        self.assertEqual(events[-1]["event_type"], "request_blocked")
        self.assertEqual(
            payload["latency_ms"],
            int(
                round(
                    (events[-1]["timestamp"] - events[-2]["timestamp"]) * 1000
                )
            ),
        )


class ChatPolicyOnlyBlockTests(unittest.TestCase):
    """Blocks raised by the literal policy list, not by a guard adapter."""

    def _client(self, *, deny_phrases: tuple[str, ...], generated: str = "ok"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        adapters = FakeAdapters()
        adapters.generated = generated
        gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(tmp.name) / "audit.sqlite3"),
            adapters=adapters,
            policy=Policy(deny_phrases=deny_phrases),
        )
        client = TestClient(make_app(gateway=gateway))
        self.addCleanup(client.close)
        return client, adapters, gateway

    def test_input_policy_block_reports_actual_input_verdict_without_masking(
        self,
    ) -> None:
        client, adapters, gateway = self._client(
            deny_phrases=("blocked phrase",)
        )

        response = client.post(
            "/chat", json={"prompt": "a blocked phrase here"}, headers=AUTH
        )

        self.assertEqual(response.status_code, 403, response.text)
        payload = response.json()
        self.assertEqual(payload["decision"], "BLOCK")
        self.assertEqual(payload["category"], "INPUT_POLICY_BLOCK")
        # The input adapter allowed the text; the literal policy blocked it.
        self.assertEqual(payload["input_safety_label"], "safe")
        self.assertNotIn("sanitized_prompt", payload)
        self.assertNotIn("output_safety_label", payload)
        self.assertEqual(adapters.generate_calls, 0)
        self.assertEqual(gateway.audit_events()[-1]["error_code"], "POLICY_BLOCK")

    def test_output_policy_block_exposes_only_already_masked_input(self) -> None:
        client, adapters, gateway = self._client(
            deny_phrases=("forbidden answer",),
            generated="forbidden answer",
        )

        response = client.post(
            "/chat", json={"prompt": PII_PROMPT}, headers=AUTH
        )

        self.assertEqual(response.status_code, 403, response.text)
        payload = response.json()
        self.assertEqual(payload["decision"], "BLOCK")
        self.assertEqual(payload["category"], "OUTPUT_POLICY_BLOCK")
        self.assertEqual(payload["input_safety_label"], "safe")
        self.assertEqual(payload["sanitized_prompt"], "Email [EMAIL]")
        self.assertEqual(
            adapters.generate_inputs,
            [[{"role": "user", "content": payload["sanitized_prompt"]}]],
        )
        self.assertNotIn("output_safety_label", payload)
        self.assertNotIn("forbidden answer", response.text)
        self.assertEqual(gateway.audit_events()[-1]["error_code"], "POLICY_BLOCK")


class NoMetadataGateway(Gateway):
    """Mapping double: returns a pipeline result but fills no result sink."""

    def __init__(self, *args: Any, response: tuple[int, dict[str, Any]], **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.response = response

    def handle(
        self,
        method: str,
        path: str,
        headers: Any,
        body: Any,
        *,
        scan_context: Any = None,
        control: Any = None,
        result_sink: dict[str, Any] | None = None,
    ):
        return self.response


class ChatMissingStageDataTests(unittest.TestCase):
    """Honest handling when the pipeline produced no field for a stage."""

    def _client(self, response: tuple[int, dict[str, Any]]) -> TestClient:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gateway = NoMetadataGateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(tmp.name) / "audit.sqlite3"),
            adapters=FakeAdapters(),
            response=response,
        )
        client = TestClient(make_app(gateway=gateway))
        self.addCleanup(client.close)
        return client

    def test_allow_omits_absent_masked_text_and_reports_unknown_labels(
        self,
    ) -> None:
        client = self._client(
            (
                200,
                {
                    "id": "req_test",
                    "object": "chat.completion",
                    "model": "pilot-local",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                },
            )
        )

        response = client.post(
            "/chat", json={"prompt": "Email person@example.com"}, headers=AUTH
        )

        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        self.assertEqual(payload["decision"], "ALLOW")
        self.assertEqual(payload["input_safety_label"], "unknown")
        self.assertEqual(payload["output_safety_label"], "unknown")
        self.assertNotIn("sanitized_prompt", payload)
        self.assertNotIn("latency_ms", payload)

    def test_block_with_no_stage_metadata_reports_unknown_input_label(
        self,
    ) -> None:
        client = self._client(
            (
                403,
                {
                    "error": {
                        "code": "POLICY_BLOCK",
                        "message": "Request did not pass safety checks.",
                        "request_id": "req_test",
                        "block": {
                            "stage": "input",
                            "reason_code": "INPUT_GUARD_BLOCK",
                            "title": "Input guard block",
                            "reason": "The prompt did not pass the input safety check.",
                        },
                    }
                },
            )
        )

        response = client.post("/chat", json={"prompt": "Hello"}, headers=AUTH)

        self.assertEqual(response.status_code, 403, response.text)
        payload = response.json()
        self.assertEqual(payload["input_safety_label"], "unknown")
        self.assertEqual(payload["category"], "INPUT_GUARD_BLOCK")
        self.assertNotIn("sanitized_prompt", payload)
        self.assertNotIn("output_safety_label", payload)
        # No audit stamps reached the sink, so no latency is invented.
        self.assertNotIn("latency_ms", payload)


class LatencyDerivationTests(unittest.TestCase):
    """``latency_ms`` is audit-terminal minus audit-started, or absent."""

    def test_only_two_real_stamps_produce_an_integer(self) -> None:
        from nasi_lemak.server import _latency_ms

        self.assertEqual(
            _latency_ms({"audit_started_at": 10.0, "audit_terminal_at": 21.4}),
            11400,
        )
        self.assertEqual(
            _latency_ms({"audit_started_at": 5.0, "audit_terminal_at": 5.0}), 0
        )
        self.assertIsInstance(
            _latency_ms({"audit_started_at": 1.0, "audit_terminal_at": 1.0004}),
            int,
        )

    def test_missing_or_malformed_stamps_are_never_estimated(self) -> None:
        from nasi_lemak.server import _latency_ms

        cases = [
            {},
            {"audit_started_at": 1.0},
            {"audit_terminal_at": 2.0},
            {"audit_started_at": True, "audit_terminal_at": 2.0},
            {"audit_started_at": "1.0", "audit_terminal_at": 2.0},
            {"audit_started_at": 1.0, "audit_terminal_at": float("nan")},
            {"audit_started_at": float("inf"), "audit_terminal_at": 2.0},
        ]
        for sink in cases:
            with self.subTest(sink=sink):
                self.assertIsNone(_latency_ms(sink))


class ChatErrorMappingTests(ChatEndpointTestBase):
    def test_unavailable_pipeline_is_generic_503(self) -> None:
        gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "unready.sqlite3"),
            adapters=None,
        )
        client = TestClient(make_app(gateway=gateway))
        self.addCleanup(client.close)

        response = client.post("/chat", json={"prompt": "Hello"}, headers=AUTH)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("detail", response.json())
        self.assertEqual(gateway.audit_events(), [])

    def test_authentication_is_required_and_never_audited(self) -> None:
        cases = [
            {},
            {"Authorization": "Bearer wrong"},
            {"Authorization": TEST_KEY},
        ]
        for headers in cases:
            with self.subTest(headers=headers):
                response = self.post(headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.json()["error"]["code"], "UNAUTHORIZED")
        self.assertEqual(self.gateway.audit_events(), [])
        self.assertEqual(self.adapters.generate_calls, 0)

    def test_bad_json_and_wrong_shape_are_generic_400(self) -> None:
        raw_cases = [
            (b"{not json", "application/json"),
            (b"[]", "application/json"),
            (b'{"prompt":"x","prompt":"y"}', "application/json"),
            (b'{"prompt":"x"}', "text/plain"),
        ]
        for raw, content_type in raw_cases:
            with self.subTest(raw=raw[:20], content_type=content_type):
                response = self.client.post(
                    "/chat",
                    content=raw,
                    headers={**AUTH, "Content-Type": content_type},
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")

        shape_cases = [
            {},
            {"prompt": "x", "extra": True},
            {"prompt": 5},
            {"prompt": ""},
            {"messages": [{"role": "user", "content": "x"}]},
        ]
        for body in shape_cases:
            with self.subTest(body=body):
                response = self.post(body)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"]["code"], "INVALID_REQUEST")
                self.assertNotIn("detail", response.json())

        self.assertEqual(self.adapters.generate_calls, 0)
        self.assertEqual(self.gateway.audit_events(), [])

    def test_over_limit_prompt_is_413_with_the_v1_pre_audit_shape(self) -> None:
        limit = self.gateway.limits.context_budget
        response = self.post({"prompt": "x" * (limit + 16)})

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"]["code"], "INPUT_LIMIT")
        self.assertEqual(self.adapters.generate_calls, 0)
        # The finite prompt bound is enforced before the initial audit row, as
        # on /v1; /chat neither invents nor hides audit rows.
        self.assertEqual(self.gateway.audit_events(), [])

    def test_streamed_body_over_the_configured_limit_is_413(self) -> None:
        client = TestClient(make_app(gateway=self.gateway, max_body_bytes=64))
        self.addCleanup(client.close)

        response = client.post(
            "/chat",
            content=json.dumps({"prompt": "x" * 200}).encode(),
            headers={**AUTH, "Content-Type": "application/json"},
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"]["code"], "INPUT_LIMIT")
        self.assertEqual(self.adapters.generate_calls, 0)
        self.assertEqual(self.gateway.audit_events(), [])

    def test_body_read_deadline_is_generic_503(self) -> None:
        app = make_app(gateway=self.gateway, body_read_timeout=0.01)
        headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer " + TEST_KEY),
        ]

        status, _, body = asyncio.run(
            asgi_request(
                app,
                headers=headers,
                body_parts=[json.dumps({"prompt": "Hello"}).encode()],
                receive_delay=0.05,
            )
        )

        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"]["code"], "UNAVAILABLE")
        self.assertEqual(self.gateway.audit_events(), [])
        self.assertEqual(self.adapters.generate_calls, 0)


def _sse_data_frames(text: str) -> list[str]:
    frames = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        if not block.startswith("data: "):
            raise AssertionError(f"not an SSE data frame: {block!r}")
        frames.append(block[len("data: ") :])
    return frames


class StreamingRequestTests(ChatEndpointTestBase):
    def post_v1(self, body: Any, *, headers: Any = None):
        return self.client.post(
            "/v1/chat/completions",
            json=body,
            headers=AUTH if headers is None else headers,
        )

    def streamed(self, body: Any = None, **extra: Any):
        request_body = dict(V1_BODY if body is None else body)
        request_body["stream"] = True
        request_body.update(extra)
        return self.post_v1(request_body)

    def test_allowed_stream_emits_three_events_matching_plain_content(self) -> None:
        plain = self.post_v1(V1_BODY)
        self.assertEqual(plain.status_code, 200, plain.text)
        plain_content = plain.json()["choices"][0]["message"]["content"]

        response = self.streamed()

        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(
            response.headers["content-type"].startswith("text/event-stream")
        )
        self.assertEqual(response.headers["cache-control"], "no-cache")

        frames = _sse_data_frames(response.text)
        self.assertEqual(len(frames), 3)
        self.assertEqual(frames[2], "[DONE]")

        first = json.loads(frames[0])
        self.assertEqual(first["object"], "chat.completion.chunk")
        self.assertIsInstance(first["created"], int)
        self.assertEqual(first["model"], "pilot-local")
        self.assertEqual(first["choices"][0]["index"], 0)
        self.assertEqual(first["choices"][0]["finish_reason"], None)
        self.assertEqual(first["choices"][0]["delta"]["role"], "assistant")
        # The released content is exactly the plain response's content.
        self.assertEqual(
            first["choices"][0]["delta"]["content"], plain_content
        )

        second = json.loads(frames[1])
        self.assertEqual(second["id"], first["id"])
        self.assertEqual(second["model"], first["model"])
        self.assertEqual(second["created"], first["created"])
        self.assertEqual(second["choices"][0]["delta"], {})
        self.assertEqual(second["choices"][0]["finish_reason"], "stop")

        # Plain and streamed requests release the same masked reply text.
        self.assertEqual(
            self.adapters.generated, "Synthetic local answer."
        )
        self.assertEqual(plain_content, "Synthetic local answer.")

    def test_stream_content_matches_non_streaming_reply(self) -> None:
        self.adapters.generated = "Release: person@example.com"
        plain = self.post_v1(V1_BODY)
        streamed = self.streamed()

        self.assertEqual(plain.status_code, 200, plain.text)
        self.assertEqual(streamed.status_code, 200, streamed.text)
        frames = _sse_data_frames(streamed.text)
        streamed_content = json.loads(frames[0])["choices"][0]["delta"]["content"]
        self.assertEqual(
            streamed_content,
            plain.json()["choices"][0]["message"]["content"],
        )
        self.assertEqual(streamed_content, "Release: [EMAIL]")

    def test_streaming_uses_one_guarded_completion_and_audit_sequence(self) -> None:
        with mock.patch.object(
            self.gateway, "handle", wraps=self.gateway.handle
        ) as handle:
            response = self.streamed()

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(handle.call_count, 1)
        self.assertEqual(self.adapters.generate_calls, 1)
        self.assertEqual(
            [event["event_type"] for event in self.gateway.audit_events()],
            ["request_started", "request_completed"],
        )

    def test_stream_options_and_sampling_params_are_ignored(self) -> None:
        response = self.streamed(
            stream_options={"include_usage": True},
            temperature=0.7,
            top_p=0.9,
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(_sse_data_frames(response.text)), 3)
        self.assertEqual(self.adapters.generate_calls, 1)
        self.assertEqual(
            self.adapters.generate_inputs,
            [[{"role": "user", "content": "Hello"}]],
        )

    def test_invalid_stream_options_and_sampling_params_are_400(self) -> None:
        cases = [
            {"stream_options": "x"},
            {"stream_options": []},
            {"temperature": 3},
            {"temperature": -1},
            {"temperature": True},
            {"temperature": "0.5"},
            {"top_p": 1.5},
            {"top_p": -0.1},
            {"top_p": False},
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                response = self.streamed(**extra)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(
                    response.json()["error"]["code"], "INVALID_REQUEST"
                )
        self.assertEqual(self.adapters.generate_calls, 0)
        self.assertEqual(self.gateway.audit_events(), [])

    def test_unknown_keys_with_stream_are_still_400(self) -> None:
        for extra in ({"tools": []}, {"policy": "unsafe"}, {"extra": True}):
            with self.subTest(extra=extra):
                response = self.streamed(**extra)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(
                    response.json()["error"]["code"], "INVALID_REQUEST"
                )
        self.assertEqual(self.adapters.generate_calls, 0)

    def test_streaming_errors_match_non_streaming_json(self) -> None:
        cases = [
            (
                "input_block",
                {"attack_result": {"decision": "block"}},
                V1_BODY,
                None,
                403,
            ),
            (
                "output_block",
                {"output_result": {"safe": False}},
                V1_BODY,
                None,
                403,
            ),
            (
                "over_limit",
                {},
                {
                    "model": "pilot-local",
                    "messages": [
                        {"role": "user", "content": "x" * 9000}
                    ],
                },
                None,
                413,
            ),
            (
                "unauthorized",
                {},
                V1_BODY,
                {"Authorization": "Bearer wrong"},
                401,
            ),
            (
                "generation_failed",
                {"generate_error": RuntimeError("synthetic failure")},
                V1_BODY,
                None,
                503,
            ),
        ]
        for name, adapter_state, body, headers, expected in cases:
            with self.subTest(case=name):
                self.adapters.attack_result = {"decision": "allow"}
                self.adapters.output_result = {"safe": True}
                self.adapters.generate_error = None
                self.adapters.output_error = None
                for attribute, value in adapter_state.items():
                    setattr(self.adapters, attribute, value)
                plain = self.post_v1(body, headers=headers)
                streamed_body = {**body, "stream": True}
                streamed = self.post_v1(streamed_body, headers=headers)

                self.assertEqual(plain.status_code, expected, plain.text)
                self.assertEqual(streamed.status_code, expected, streamed.text)
                self.assertEqual(
                    streamed.headers["content-type"], "application/json"
                )
                self.assertEqual(
                    streamed.json()["error"]["code"],
                    plain.json()["error"]["code"],
                )
                self.assertEqual(
                    set(streamed.json()["error"]),
                    set(plain.json()["error"]),
                )


async def asgi_request(
    app: Any,
    *,
    method: str = "POST",
    path: str = "/chat",
    headers: list[tuple[str, str]] | None = None,
    body_parts: list[bytes] | None = None,
    receive_delay: float = 0.0,
) -> tuple[int, dict[str, str], bytes]:
    """Call the ASGI app directly to keep the concurrency scenario synchronous."""
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or [])]
    parts = list(body_parts) if body_parts is not None else [b""]
    index = 0
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        nonlocal index
        if receive_delay:
            await asyncio.sleep(receive_delay)
        if index >= len(parts):
            return {"type": "http.disconnect"}
        chunk = parts[index]
        index += 1
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
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    await app(scope, receive, send)
    start = next(message for message in sent if message["type"] == "http.response.start")
    body = b"".join(
        message.get("body", b"")
        for message in sent
        if message["type"] == "http.response.body"
    )
    response_headers = {
        key.decode(): value.decode() for key, value in start.get("headers", [])
    }
    return start["status"], response_headers, body


class SharedAdmissionTests(ChatEndpointTestBase):
    def _app(self) -> Any:
        return make_app(gateway=self.gateway, max_concurrency=1)

    def test_chat_occupies_the_single_v1_admission_slot(self) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        app = self._app()
        headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer " + TEST_KEY),
        ]

        async def scenario() -> None:
            first = asyncio.create_task(
                asgi_request(
                    app,
                    headers=headers,
                    body_parts=[json.dumps({"prompt": "first"}).encode()],
                )
            )
            for _ in range(100):
                if self.adapters.generate_started.is_set():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(self.adapters.generate_started.is_set())

            second = await asgi_request(
                app,
                path="/v1/chat/completions",
                headers=headers,
                body_parts=[json.dumps(V1_BODY).encode()],
            )
            self.assertEqual(second[0], 503)
            self.assertEqual(json.loads(second[2])["error"]["code"], "UNAVAILABLE")

            gate.set()
            first_status, _, first_body = await first
            self.assertEqual(first_status, 200, first_body)
            self.assertEqual(json.loads(first_body)["decision"], "ALLOW")

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_v1_request_also_blocks_a_second_chat_request(self) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        app = self._app()
        headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer " + TEST_KEY),
        ]

        async def scenario() -> None:
            first = asyncio.create_task(
                asgi_request(
                    app,
                    path="/v1/chat/completions",
                    headers=headers,
                    body_parts=[json.dumps(V1_BODY).encode()],
                )
            )
            for _ in range(100):
                if self.adapters.generate_started.is_set():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(self.adapters.generate_started.is_set())

            second = await asgi_request(
                app,
                headers=headers,
                body_parts=[json.dumps({"prompt": "second"}).encode()],
            )
            self.assertEqual(second[0], 503)
            self.assertEqual(json.loads(second[2])["error"]["code"], "UNAVAILABLE")

            gate.set()
            first_status, _, first_body = await first
            self.assertEqual(first_status, 200, first_body)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_work_deadline_returns_503_and_holds_the_shared_slot(self) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        app = make_app(
            gateway=self.gateway, max_concurrency=1, chat_work_timeout=0.05
        )
        headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer " + TEST_KEY),
        ]

        async def scenario() -> None:
            first = asyncio.create_task(
                asgi_request(
                    app,
                    headers=headers,
                    body_parts=[json.dumps({"prompt": "first"}).encode()],
                )
            )
            for _ in range(100):
                if self.adapters.generate_started.is_set():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(self.adapters.generate_started.is_set())

            first_status, _, first_body = await asyncio.wait_for(
                first, timeout=5
            )
            self.assertEqual(first_status, 503, first_body)
            self.assertEqual(
                json.loads(first_body)["error"]["code"], "UNAVAILABLE"
            )

            # The timed-out worker still holds the only admission slot.
            second = await asgi_request(
                app,
                headers=headers,
                body_parts=[json.dumps({"prompt": "second"}).encode()],
            )
            self.assertEqual(second[0], 503)
            self.assertEqual(json.loads(second[2])["error"]["code"], "UNAVAILABLE")

            gate.set()
            for _ in range(200):
                if not app.state.sem.locked():
                    break
                await asyncio.sleep(0.005)
            self.assertFalse(app.state.sem.locked())

            third = await asgi_request(
                app,
                headers=headers,
                body_parts=[json.dumps({"prompt": "third"}).encode()],
            )
            self.assertEqual(third[0], 200, third[2])

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))

    def test_cancellation_defers_release_until_the_worker_finishes(self) -> None:
        gate = threading.Event()
        self.adapters.generate_gate = gate
        app = make_app(
            gateway=self.gateway, max_concurrency=1, chat_work_timeout=30
        )
        headers = [
            ("content-type", "application/json"),
            ("authorization", "Bearer " + TEST_KEY),
        ]

        async def scenario() -> None:
            first = asyncio.create_task(
                asgi_request(
                    app,
                    headers=headers,
                    body_parts=[json.dumps({"prompt": "first"}).encode()],
                )
            )
            for _ in range(100):
                if self.adapters.generate_started.is_set():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(self.adapters.generate_started.is_set())

            first.cancel()
            await asyncio.sleep(0.05)
            # Cancellation is deferred while the synchronous worker runs.
            self.assertFalse(first.done())

            second = await asgi_request(
                app,
                headers=headers,
                body_parts=[json.dumps({"prompt": "second"}).encode()],
            )
            self.assertEqual(second[0], 503)
            self.assertEqual(json.loads(second[2])["error"]["code"], "UNAVAILABLE")

            gate.set()
            with self.assertRaises(asyncio.CancelledError):
                await first
            for _ in range(200):
                if not app.state.sem.locked():
                    break
                await asyncio.sleep(0.005)
            self.assertFalse(app.state.sem.locked())

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))


def load_cli() -> Any:
    path = Path(__file__).resolve().parents[1] / "scripts" / "test_gateway.py"
    spec = importlib.util.spec_from_file_location("test_gateway_cli", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, status: int, payload: dict[str, Any]) -> None:
        self.status = status
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self, size: int = -1) -> bytes:
        return self._raw if size < 0 else self._raw[:size]

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


class CliScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cli = load_cli()

    def _allow(self, sanitized: str) -> dict[str, Any]:
        return {
            "decision": "ALLOW",
            "sanitized_prompt": sanitized,
            "input_safety_label": "safe",
            "output_safety_label": "safe",
            "response": "ok",
        }

    def _fake_opener(self, *, status_for: Any = None) -> Any:
        def opener(request: Any, timeout: float | None = None) -> FakeResponse:
            prompt = json.loads(request.data.decode("utf-8"))["prompt"]
            if status_for is not None:
                return status_for(prompt)
            if "Ignore all previous instructions" in prompt:
                return FakeResponse(
                    403,
                    {
                        "decision": "BLOCK",
                        "reason": "The prompt did not pass the input safety check.",
                        "input_safety_label": "blocked",
                        "category": "INPUT_GUARD_BLOCK",
                    },
                )
            if "person@example.com" in prompt:
                return FakeResponse(200, self._allow("Email [EMAIL] and phone [MY_PHONE]"))
            return FakeResponse(200, self._allow(prompt))

        return opener

    def test_missing_base_url_fails_with_usage(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                self.cli.main([], environ={self.cli.TOKEN_ENV: "token"})
        self.assertEqual(raised.exception.code, 2)

    def test_missing_token_fails_with_usage(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                self.cli.main(
                    ["--base-url", "http://gateway.test:8080"], environ={}
                )
        self.assertEqual(raised.exception.code, 2)

    def test_default_three_cases_allow_and_block_exit_zero(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        code = self.cli.run(
            base_url="http://gateway.test:8080",
            token="secret-token",
            opener=self._fake_opener(),
            stdout=out,
            stderr=err,
        )
        self.assertEqual(code, 0, err.getvalue())
        lines = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(len(lines), 3)
        self.assertEqual([line["decision"] for line in lines], ["ALLOW", "ALLOW", "BLOCK"])
        self.assertEqual(lines[0]["sanitized_prompt"], "What is the capital of Malaysia?")
        self.assertNotIn("person@example.com", lines[1]["sanitized_prompt"])
        self.assertEqual(lines[2]["category"], "INPUT_GUARD_BLOCK")

    def test_block_without_category_is_not_a_cli_failure(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        code = self.cli.run(
            base_url="http://gateway.test:8080",
            token="secret-token",
            case="injection",
            opener=lambda request, timeout=None: FakeResponse(
                403,
                {
                    "decision": "BLOCK",
                    "reason": "The prompt did not pass the input safety check.",
                    "input_safety_label": "blocked",
                },
            ),
            stdout=out,
            stderr=err,
        )
        self.assertEqual(code, 0, err.getvalue())

    def test_unexpected_outcome_exits_two(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        code = self.cli.run(
            base_url="http://gateway.test:8080",
            token="secret-token",
            case="injection",
            opener=self._fake_opener(
                status_for=lambda prompt: FakeResponse(200, self._allow("unexpected"))
            ),
            stdout=out,
            stderr=err,
        )
        self.assertEqual(code, 2)
        self.assertIn("expected decision BLOCK", err.getvalue())

    def test_timeout_argument_is_passed_and_failures_exit_two(self) -> None:
        seen: list[float | None] = []

        def opener(request: Any, timeout: float | None = None) -> FakeResponse:
            seen.append(timeout)
            raise TimeoutError("simulated")

        out = io.StringIO()
        err = io.StringIO()
        code = self.cli.run(
            base_url="http://gateway.test:8080",
            token="secret-token",
            case="normal",
            timeout=0.25,
            opener=opener,
            stdout=out,
            stderr=err,
        )
        self.assertEqual(code, 2)
        self.assertEqual(seen, [0.25])
        self.assertIn("request failed", err.getvalue())

    def test_token_is_never_printed(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        token = "very-secret-bearer-token"
        code = self.cli.run(
            base_url="http://gateway.test:8080",
            token=token,
            case="normal",
            opener=self._fake_opener(),
            stdout=out,
            stderr=err,
        )
        self.assertEqual(code, 0, err.getvalue())
        self.assertNotIn(token, out.getvalue())
        self.assertNotIn(token, err.getvalue())

    def test_relative_base_url_is_rejected(self) -> None:
        with self.assertRaises(self.cli.UsageError):
            self.cli.chat_endpoint("gateway:8080")


if __name__ == "__main__":
    unittest.main()
