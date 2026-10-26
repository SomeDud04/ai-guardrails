"""Focused saved-chat rollover, limits and per-request scan-context tests."""

from __future__ import annotations

import asyncio
import threading
import time
import unittest
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.limits import (
    ENV_CONTEXT_BUDGET,
    ENV_CONTEXT_MESSAGES,
    ENV_DEFAULT_REPLY_TOKENS,
    ENV_MAX_REPLY_TOKENS,
    ChatLimits,
)
from nasi_lemak.scan_context import ScanContext
from nasi_lemak.server import make_app
from tests.test_server import RecordingAdapters
from tests.test_workspace_http import (
    GATEWAY_REPLY,
    PASSWORD,
    WorkspaceHTTPBase,
)


class ChatContextTests(WorkspaceHTTPBase):
    def seed_pairs(self, count: int, prefix: str = "turn") -> str:
        conversation = self.store.create_conversation(self.alice["id"])
        for index in range(count):
            lease = self.store.reserve_turn(self.alice["id"], conversation["id"])
            self.store.append_exchange(
                self.alice["id"],
                conversation["id"],
                lease["token"],
                user_prompt=f"{prefix}{index}u",
                assistant_response=f"{prefix}{index}a",
            )
        return conversation["id"]

    def send(self, client: TestClient, token: str, conversation_id: str, text: str, **extra: Any):
        body = {"text": text}
        body.update(extra)
        return client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json=body,
            headers=self.auth(token),
        )

    def test_saved_history_beyond_eight_exchanges_continues_unchanged(self) -> None:
        token = self.login()
        conversation_id = self.seed_pairs(12)
        response = self.send(
            self.client, token, conversation_id, "latest question"
        )
        self.assertEqual(response.status_code, 200, response.text)
        sent = [
            message["content"]
            for message in self.adapters.generate_inputs[-1]
        ]
        self.assertEqual(len(sent), 25)
        self.assertEqual(sent[0], "turn0u")
        self.assertEqual(sent[1], "turn0a")
        self.assertEqual(sent[-1], "latest question")
        context = response.json()["context"]
        self.assertEqual(context["selected_messages"], 25)
        self.assertEqual(context["omitted_messages"], 0)
        self.assertEqual(context["context_budget"], 8192)
        self.assertEqual(context["policy_token_budget"], 512)

        stored = self.store.read_conversation(
            self.alice["id"], conversation_id
        )["messages"]
        self.assertEqual(len(stored), 26)
        self.assertEqual(stored[0]["text"], "turn0u")
        self.assertEqual(stored[-2]["text"], "latest question")
        self.assertEqual(stored[-1]["text"], GATEWAY_REPLY)

    def test_oldest_complete_pairs_are_omitted_with_metadata(self) -> None:
        app = self.make_app(
            environ=self.env(**{ENV_CONTEXT_MESSAGES: "6"})
        )
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.seed_pairs(12)
        response = self.send(client, token, conversation_id, "latest question")
        self.assertEqual(response.status_code, 200, response.text)
        sent = [
            message["content"]
            for message in self.adapters.generate_inputs[-1]
        ]
        self.assertEqual(
            sent,
            ["turn10u", "turn10a", "turn11u", "turn11a", "latest question"],
        )
        context = response.json()["context"]
        self.assertEqual(context["selected_messages"], 5)
        self.assertEqual(context["omitted_messages"], 20)
        self.assertEqual(context["context_messages"], 6)
        stored = self.store.read_conversation(
            self.alice["id"], conversation_id
        )["messages"]
        self.assertEqual(len(stored), 26)

    def test_full_newest_prompt_is_never_trimmed(self) -> None:
        app = self.make_app(
            environ=self.env(**{ENV_CONTEXT_MESSAGES: "4"})
        )
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.seed_pairs(3)
        prompt = "p" * 3000
        response = self.send(client, token, conversation_id, prompt)
        self.assertEqual(response.status_code, 200, response.text)
        sent = self.adapters.generate_inputs[-1]
        self.assertEqual([item["content"] for item in sent], ["turn2u", "turn2a", prompt])
        self.assertEqual(response.json()["context"]["omitted_messages"], 4)

    def test_prompt_alone_over_budget_is_honest_413(self) -> None:
        app = self.make_app(environ=self.env(**{ENV_CONTEXT_BUDGET: "128"}))
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.seed_pairs(2)
        before = self.adapters.generate_calls
        response = self.send(client, token, conversation_id, "x" * 200)
        self.assert_error(response, 413, "INPUT_LIMIT")
        message = response.json()["error"]["message"]
        self.assertIn("configured input limit", message)
        self.assertIn("shorten", message)
        self.assertNotIn("start a new conversation", message)
        self.assertEqual(self.adapters.generate_calls, before)
        stored = self.store.read_conversation(
            self.alice["id"], conversation_id
        )["messages"]
        self.assertEqual(stored[-1]["outcome"], "failed")
        self.assertEqual(stored[-1]["error_code"], "INPUT_LIMIT")
        self.assertEqual(stored[-1]["text"], "x" * 200)

    def test_unpaired_or_malformed_selected_history_fails_closed(self) -> None:
        class UnpairedStore:
            def __init__(self, store: Any) -> None:
                self._store = store

            def __getattr__(self, name: str) -> Any:
                return getattr(self._store, name)

            def read_context(self, owner_id: str, conversation_id: str) -> dict:
                return {
                    "messages": [
                        {"role": "user", "content": "one"},
                        {"role": "user", "content": "two"},
                    ]
                }

        app = self.make_app(store=UnpairedStore(self.store))
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.new_conversation(token, client)
        before = self.adapters.generate_calls
        response = self.send(client, token, conversation_id, "hello")
        self.assert_error(response, 503, "UNAVAILABLE")
        self.assertEqual(self.adapters.generate_calls, before)

    def test_blocked_history_is_never_sent_to_generation(self) -> None:
        token = self.login()
        conversation_id = self.new_conversation(token)
        first = self.send(self.client, token, conversation_id, "allowed one")
        self.assertEqual(first.status_code, 200, first.text)
        self.adapters.output_result = {"safe": False}
        blocked = self.send(self.client, token, conversation_id, "blocked question")
        self.assert_error(blocked, 403, "FORBIDDEN")
        self.adapters.output_result = {"safe": True}
        after = self.send(self.client, token, conversation_id, "after block")
        self.assertEqual(after.status_code, 200, after.text)
        sent = [
            message["content"]
            for message in self.adapters.generate_inputs[-1]
        ]
        self.assertIn("allowed one", sent)
        self.assertNotIn("blocked question", sent)
        self.assertEqual(sent[-1], "after block")

    def test_operator_policy_budget_is_honoured(self) -> None:
        policy_gateway = Gateway(
            app_key="policy-limit-key",
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "policy-audit.sqlite3"),
            adapters=self.adapters,
            policy=Policy(token_budget=15),
        )
        app = make_app(
            gateway=policy_gateway,
            workspace_store=self.store,
            environ=self.env(),
        )
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.seed_pairs(4)
        response = self.send(client, token, conversation_id, "latest prompt")
        self.assertEqual(response.status_code, 200, response.text)
        context = response.json()["context"]
        self.assertEqual(context["policy_token_budget"], 15)
        self.assertEqual(context["omitted_messages"], 2)
        self.assertEqual(len(self.adapters.generate_inputs[-1]), 7)

    def test_byte_budget_and_policy_token_budget_stay_separate(self) -> None:
        policy_gateway = Gateway(
            app_key="unit-key",
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "unit-audit.sqlite3"),
            adapters=self.adapters,
            policy=Policy(token_budget=50),
        )
        app = make_app(
            gateway=policy_gateway,
            workspace_store=self.store,
            environ=self.env(**{ENV_CONTEXT_BUDGET: "4096"}),
        )
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.new_conversation(token, client)
        prompt = " ".join(["a"] * 40)
        response = self.send(client, token, conversation_id, prompt)
        self.assertEqual(response.status_code, 200, response.text)
        context = response.json()["context"]
        self.assertEqual(context["context_budget"], 4096)
        self.assertEqual(context["policy_token_budget"], 50)
        self.assertEqual(context["selected_messages"], 1)
        self.assertEqual(context["omitted_messages"], 0)
        self.assertNotIn("effective_budget", context)
        self.assertNotIn("effective_context_budget", context)
        self.assertEqual(self.adapters.generate_inputs[-1][-1]["content"], prompt)

    def test_workspace_reply_defaults_and_configured_ceiling(self) -> None:
        app = self.make_app(
            environ=self.env(
                **{
                    ENV_MAX_REPLY_TOKENS: "2048",
                    ENV_DEFAULT_REPLY_TOKENS: "512",
                }
            )
        )
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.new_conversation(token, client)
        calls: list[int] = []
        original = self.adapters.generate

        def generate(messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
            calls.append(max_tokens)
            return original(messages, model, max_tokens)

        self.adapters.generate = generate
        self.addCleanup(setattr, self.adapters, "generate", original)
        self.assertEqual(
            self.send(client, token, conversation_id, "first").status_code, 200
        )
        self.assertEqual(calls[-1], 512)
        self.assertEqual(
            self.send(client, token, conversation_id, "second", max_tokens=2048).status_code,
            200,
        )
        self.assertEqual(calls[-1], 2048)
        self.assert_error(
            self.send(client, token, conversation_id, "third", max_tokens=2049),
            400,
            "INVALID_REQUEST",
        )

    def test_invalid_chat_limits_leave_workspace_unready(self) -> None:
        app = self.make_app(
            environ=self.env(**{ENV_CONTEXT_MESSAGES: "0"})
        )
        client = self.make_client(app)
        self.assertFalse(app.state.config_ready)
        self.assertFalse(app.state.workspace.ready)
        self.assert_error(
            client.post(
                "/workspace/api/login",
                json={"username": "alice", "password": PASSWORD},
            ),
            503,
            "UNAVAILABLE",
        )
        self.assertEqual(self.gateway.limits, ChatLimits.defaults())

    def test_me_exposes_effective_nonsecret_limits_only(self) -> None:
        token = self.login()
        response = self.client.get(
            "/workspace/api/me", headers=self.auth(token)
        )
        self.assertEqual(response.status_code, 200, response.text)
        payload = response.json()
        profile = self.store.get_profile(self.alice["id"])
        for key, value in profile.items():
            self.assertEqual(payload[key], value)
        limits = payload["chat_limits"]
        self.assertEqual(limits["context_messages"], 32)
        self.assertEqual(limits["context_budget"], 8192)
        self.assertEqual(limits["default_reply_tokens"], 1024)
        self.assertEqual(limits["max_reply_tokens"], 4096)
        self.assertEqual(limits["max_prompt_chars"], 8192)
        self.assertEqual(limits["policy_token_budget"], 512)
        self.assertNotIn("effective_context_budget", limits)
        self.assertNotIn("token", limits)
        self.assertNotIn("key", limits)

    def test_long_prompt_and_reply_above_old_store_bound_persist(self) -> None:
        from nasi_lemak.workspace_store import WorkspaceStore

        app = self.make_app(
            environ=self.env(**{ENV_CONTEXT_BUDGET: "32768"})
        )
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.new_conversation(token, client)
        prompt = "p" * 12000
        reply = "r" * 12000
        self.adapters.generated = reply
        response = self.send(client, token, conversation_id, prompt)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["content"], reply)

        reopened = WorkspaceStore(
            self.db_path, encryption_key=self.key, connect_timeout=5.0
        )
        self.addCleanup(reopened.close)
        context = reopened.read_context(self.alice["id"], conversation_id)
        self.assertEqual(context["messages"][0]["content"], prompt)
        self.assertEqual(context["messages"][1]["content"], reply)

    def test_scan_context_is_propagated_and_isolated_per_request(self) -> None:
        app = self.make_app()
        runtime = app.state.workspace
        captured: list[ScanContext] = []
        barrier = threading.Barrier(2)

        def fake_handle(
            method: str,
            path: str,
            headers: Any,
            body: Any,
            *,
            scan_context: ScanContext | None = None,
        ):
            captured.append(scan_context)
            try:
                barrier.wait(timeout=5)
            except threading.BrokenBarrierError:
                pass
            return 503, {"error": {"code": "UNAVAILABLE"}}

        original_handle = runtime.internal_gateway.handle
        runtime.internal_gateway.handle = fake_handle
        self.addCleanup(
            setattr, runtime.internal_gateway, "handle", original_handle
        )

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver", timeout=10
            ) as client:
                login = await client.post(
                    "/workspace/api/login",
                    json={"username": "alice", "password": PASSWORD},
                )
                self.assertEqual(login.status_code, 200, login.text)
                headers = self.auth(login.json()["token"])
                conversations = [
                    self.store.create_conversation(self.alice["id"])["id"]
                    for _ in range(2)
                ]
                requests = [
                    asyncio.create_task(
                        client.post(
                            f"/workspace/api/conversations/{conversation}/messages",
                            json={"text": f"prompt {index}"},
                            headers=headers,
                        )
                    )
                    for index, conversation in enumerate(conversations)
                ]
                responses = await asyncio.gather(*requests)
                for response in responses:
                    self.assertEqual(response.status_code, 503, response.text)

        asyncio.run(asyncio.wait_for(scenario(), timeout=15))
        self.assertEqual(len(captured), 2)
        self.assertIsNot(captured[0], captured[1])
        for scan_context in captured:
            self.assertIsInstance(scan_context, ScanContext)
            self.assertIsNotNone(scan_context.deadline)
            self.assertGreater(scan_context.deadline, time.monotonic() - 10)
            self.assertIsNotNone(scan_context.cancel_event)
            self.assertFalse(scan_context.cancel_event.is_set())


if __name__ == "__main__":
    unittest.main()
