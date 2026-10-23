"""Behavioral HTTP tests for the opt-in employee workspace slice.

Every test uses the real FastAPI application, a temporary SQLite workspace
store and in-process synthetic adapters.  No external model, guard, VM or
database is contacted.  The HTTP opt-in is explicit and the app runs in the
acknowledged ``test`` mode so the fixture is honest about its safety posture.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

import httpx
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway
from nasi_lemak.server import make_app
from nasi_lemak.workspace_http import ENV_ALLOW_HTTP, ENV_ENABLED, _LoginLimiter
from nasi_lemak.workspace_http import load_workspace_runtime
from nasi_lemak.workspace_store import (
    AuthError,
    WorkspaceConfigError,
    WorkspaceStorageError,
    WorkspaceStore,
)
from tests.test_server import JSON_BODY, RecordingAdapters

LEGACY_KEY = "legacy-test-key"
PASSWORD = "correct-horse-battery-staple"
NEW_PASSWORD = "another-long-password-789"
GATEWAY_REPLY = "Safe synthetic answer."


class FakeClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class _ProxyStore:
    """Delegate to the real store while overriding one method for a test."""

    def __init__(self, store: WorkspaceStore) -> None:
        self._store = store

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)


class WorkspaceHTTPBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = Fernet.generate_key().decode("ascii")
        self.db_path = os.path.join(self.tmp.name, "workspace.db")
        self.adapters = RecordingAdapters()
        self.gateway = Gateway(
            app_key=LEGACY_KEY,
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            adapters=self.adapters,
        )
        self.store = WorkspaceStore(
            self.db_path, encryption_key=self.key, connect_timeout=5.0
        )
        self.addCleanup(self.store.close)
        self.admin = self.store.bootstrap_admin(
            username="root.admin",
            password=PASSWORD,
            full_name="Root Admin",
            department_name="IT",
        )
        self.accounting = self.store.create_department(self.admin["id"], "Accounting")
        self.hr = self.store.create_department(self.admin["id"], "Human Resources")
        self.alice = self._user("alice", "Alice Tan", self.accounting["id"])
        self.bob = self._user("bob", "Bob Lim", self.accounting["id"])
        self.carol = self._user("carol", "Carol Ng", self.hr["id"])
        self.app = self.make_app()
        self.client = self.make_client(self.app)

    def _user(self, username: str, full_name: str, department_id: str) -> dict:
        return self.store.create_user(
            self.admin["id"],
            username,
            PASSWORD,
            full_name,
            department_id,
            "employee",
        )

    def env(self, **overrides: str) -> dict[str, str]:
        env = {
            "NASI_LEMAK_MODE": "test",
            "NASI_LEMAK_ALLOW_UNGUARDED_TEST": "true",
            ENV_ENABLED: "true",
            ENV_ALLOW_HTTP: "true",
        }
        env.update(overrides)
        return env

    def make_app(self, *, store: Any = None, environ: dict[str, str] | None = None, **kwargs: Any):
        return make_app(
            gateway=self.gateway,
            workspace_store=self.store if store is None else store,
            environ=self.env() if environ is None else environ,
            **kwargs,
        )

    def make_client(self, app: Any) -> TestClient:
        client = TestClient(app)
        self.addCleanup(client.close)
        return client

    def login(self, username: str = "alice", password: str = PASSWORD, client: TestClient | None = None) -> str:
        response = (client or self.client).post(
            "/workspace/api/login", json={"username": username, "password": password}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["token"]

    @staticmethod
    def auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def new_conversation(self, token: str, client: TestClient | None = None) -> str:
        response = (client or self.client).post(
            "/workspace/api/conversations", json={}, headers=self.auth(token)
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["id"]

    def seeded_conversation(self, owner: dict, prompt: str, reply: str) -> str:
        conversation = self.store.create_conversation(owner["id"])
        lease = self.store.reserve_turn(owner["id"], conversation["id"])
        self.store.append_exchange(
            owner["id"],
            conversation["id"],
            lease["token"],
            user_prompt=prompt,
            assistant_response=reply,
        )
        return conversation["id"]

    # -- assertions ------------------------------------------------------
    def assert_error(self, response: Any, status: int, code: str) -> None:
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.json()["error"]["code"], code, response.text)


class ConfigurationTests(WorkspaceHTTPBase):
    def test_disabled_by_default_leaves_legacy_routes_and_db_closed(self) -> None:
        app = make_app(
            gateway=self.gateway,
            environ={
                "NASI_LEMAK_MODE": "test",
                "NASI_LEMAK_ALLOW_UNGUARDED_TEST": "true",
            },
        )
        client = self.make_client(app)
        self.assertFalse(app.state.workspace.enabled)
        self.assertIsNone(app.state.workspace.store)
        self.assertEqual(client.get("/health/live").status_code, 200)
        health = client.get("/health/ready")
        self.assertEqual(health.status_code, 200, health.text)
        self.assertNotIn("workspace", health.json())
        self.assertEqual(client.get("/workspace/api/me").status_code, 404)
        self.assertEqual(client.post("/workspace/api/login", json={}).status_code, 404)

    def test_missing_config_is_503_and_not_ready(self) -> None:
        runtime = load_workspace_runtime(
            {ENV_ENABLED: "true"},
            store=None,
            gateway=self.gateway,
            audit_writer_dsn=None,
            audit_reader_dsn=None,
            chat_work_timeout=10.0,
        )
        self.assertTrue(runtime.enabled)
        self.assertFalse(runtime.ready)
        self.assertIsNone(runtime.store)

        app = make_app(
            gateway=self.gateway,
            workspace_store=None,
            environ=self.env(),
        )
        client = self.make_client(app)
        self.assert_error(client.post("/workspace/api/login", json={}), 503, "UNAVAILABLE")
        health = client.get("/health/ready")
        self.assertEqual(health.status_code, 503, health.text)
        self.assertEqual(health.json()["workspace"], "not_ready")

    def test_plaintext_env_and_shared_dsn_are_rejected(self) -> None:
        plaintext = load_workspace_runtime(
            {
                ENV_ENABLED: "true",
                "NASI_LEMAK_WORKSPACE_DSN": "postgresql://user:secret@db/workspace",
            },
            store=None,
            gateway=self.gateway,
            audit_writer_dsn=None,
            audit_reader_dsn=None,
            chat_work_timeout=10.0,
        )
        self.assertFalse(plaintext.ready)
        self.assertIsNone(plaintext.store)

        dsn = "postgresql://user:secret@db/workspace"
        dsn_path = Path(self.tmp.name) / "workspace.dsn"
        key_path = Path(self.tmp.name) / "workspace.key"
        dsn_path.write_text(dsn, encoding="utf-8")
        key_path.write_text(self.key, encoding="utf-8")
        shared = load_workspace_runtime(
            {
                ENV_ENABLED: "true",
                "NASI_LEMAK_WORKSPACE_DSN_FILE": str(dsn_path),
                "NASI_LEMAK_WORKSPACE_KEY_FILE": str(key_path),
            },
            store=None,
            gateway=self.gateway,
            audit_writer_dsn=dsn,
            audit_reader_dsn=None,
            chat_work_timeout=10.0,
        )
        self.assertFalse(shared.ready)
        self.assertIsNone(shared.store)

    def test_runtime_migration_flag_refuses_unknown_schema_without_ddl(self) -> None:
        import sqlite3

        path = os.path.join(self.tmp.name, "runtime-unmigrated.db")
        with self.assertRaises(WorkspaceConfigError):
            WorkspaceStore(
                path,
                encryption_key=self.key,
                connect_timeout=5.0,
                migrate=False,
            )
        connection = sqlite3.connect(path)
        try:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(tables, [])

    def test_http_requires_opt_in_origin_and_single_json_auth_shape(self) -> None:
        app = make_app(
            gateway=self.gateway,
            workspace_store=self.store,
            environ=self.env(**{ENV_ALLOW_HTTP: "false"}),
        )
        client = self.make_client(app)
        response = client.post(
            "/workspace/api/login", json={"username": "alice", "password": PASSWORD}
        )
        self.assert_error(response, 403, "FORBIDDEN")

        response = self.client.post(
            "/workspace/api/login",
            json={"username": "alice", "password": PASSWORD},
            headers={"Origin": "https://evil.example"},
        )
        self.assert_error(response, 403, "FORBIDDEN")

        token = self.login()
        duplicate = self.client.get(
            "/workspace/api/me",
            headers=[("authorization", f"Bearer {token}"), ("authorization", f"Bearer {token}")],
        )
        self.assert_error(duplicate, 401, "UNAUTHORIZED")

        extra = self.client.post(
            "/workspace/api/login",
            json={"username": "alice", "password": PASSWORD, "extra": 1},
        )
        self.assert_error(extra, 400, "INVALID_REQUEST")

        duplicate_keys = self.client.post(
            "/workspace/api/login",
            content=b'{"username":"alice","username":"alice","password":"' + PASSWORD.encode() + b'"}',
            headers={"content-type": "application/json"},
        )
        self.assert_error(duplicate_keys, 400, "INVALID_REQUEST")


class LoginAndAdminTests(WorkspaceHTTPBase):
    def test_login_logout_revoke_disable_reset_and_rate_limit(self) -> None:
        self.assert_error(
            self.client.post(
                "/workspace/api/login",
                json={"username": "alice", "password": "wrong-password-123"},
            ),
            401,
            "UNAUTHORIZED",
        )

        token = self.login()
        self.assertEqual(self.client.get("/workspace/api/me", headers=self.auth(token)).status_code, 200)
        self.assertEqual(self.client.post("/workspace/api/logout", headers=self.auth(token)).status_code, 200)
        self.assert_error(self.client.get("/workspace/api/me", headers=self.auth(token)), 401, "UNAUTHORIZED")

        admin_token = self.login("root.admin")
        disabled = self.client.post(
            f"/workspace/api/admin/users/{self.bob['id']}/disable",
            json={},
            headers=self.auth(admin_token),
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assert_error(
            self.client.post(
                "/workspace/api/login", json={"username": "bob", "password": PASSWORD}
            ),
            401,
            "UNAUTHORIZED",
        )

        reset = self.client.post(
            f"/workspace/api/admin/users/{self.carol['id']}/reset-password",
            json={"password": NEW_PASSWORD},
            headers=self.auth(admin_token),
        )
        self.assertEqual(reset.status_code, 200, reset.text)
        self.assert_error(
            self.client.post(
                "/workspace/api/login", json={"username": "carol", "password": PASSWORD}
            ),
            401,
            "UNAUTHORIZED",
        )
        self.login("carol", NEW_PASSWORD)

    def test_rate_limit_runs_before_kdf_and_cache_is_bounded(self) -> None:
        clock = FakeClock(1000.0)
        limiter = _LoginLimiter(clock)
        for index in range(600):
            limiter.blocked(limiter.key(f"ip-{index}", "alice"))
        self.assertLessEqual(len(limiter._hits), 512)

        runtime = self.app.state.workspace
        runtime._login_limiter._clock = clock
        original = self.store.authenticate
        calls: list[str] = []

        def counting(username: str, password: str) -> dict:
            calls.append(username)
            return original(username, password)

        self.store.authenticate = counting
        self.addCleanup(setattr, self.store, "authenticate", original)
        for _ in range(5):
            response = self.client.post(
                "/workspace/api/login",
                json={"username": "alice", "password": "wrong-password-123"},
            )
            self.assertEqual(response.status_code, 401)
        calls.clear()
        response = self.client.post(
            "/workspace/api/login",
            json={"username": "alice", "password": PASSWORD},
        )
        self.assert_error(response, 429, "RATE_LIMIT")
        self.assertEqual(calls, [])

    def test_no_password_or_token_is_logged(self) -> None:
        messages: list[str] = []
        handler = logging.Handler()
        handler.emit = lambda record: messages.append(record.getMessage())  # type: ignore[method-assign]
        root = logging.getLogger()
        root.addHandler(handler)
        try:
            token = self.login()
            self.client.get("/workspace/api/me", headers=self.auth(token))
        finally:
            root.removeHandler(handler)
        joined = "\n".join(messages)
        self.assertNotIn(PASSWORD, joined)
        self.assertNotIn(token, joined)

    def test_admin_crud_and_non_admin_denied(self) -> None:
        admin_token = self.login("root.admin")
        created = self.client.post(
            "/workspace/api/admin/departments",
            json={"name": "Sales"},
            headers=self.auth(admin_token),
        )
        self.assertEqual(created.status_code, 201, created.text)
        department_id = created.json()["id"]

        created_user = self.client.post(
            "/workspace/api/admin/users",
            json={
                "username": "dave",
                "password": PASSWORD,
                "full_name": "Dave Lee",
                "department_id": department_id,
                "role": "employee",
            },
            headers=self.auth(admin_token),
        )
        self.assertEqual(created_user.status_code, 201, created_user.text)

        users = self.client.get(
            "/workspace/api/admin/users", headers=self.auth(admin_token)
        )
        self.assertEqual(users.status_code, 200, users.text)
        self.assertIn("dave", {item["username"] for item in users.json()["items"]})
        departments = self.client.get(
            "/workspace/api/admin/departments", headers=self.auth(admin_token)
        )
        self.assertEqual(departments.status_code, 200, departments.text)

        granted = self.client.post(
            "/workspace/api/admin/review-grants",
            json={"user_id": self.alice["id"], "scope": "department", "department_id": department_id},
            headers=self.auth(admin_token),
        )
        self.assertEqual(granted.status_code, 201, granted.text)
        listed = self.client.get(
            "/workspace/api/admin/review-grants", headers=self.auth(admin_token)
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(len(listed.json()["items"]), 1)
        revoked = self.client.delete(
            f"/workspace/api/admin/review-grants/{granted.json()['id']}",
            headers=self.auth(admin_token),
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)

        alice_token = self.login()
        self.assert_error(
            self.client.get("/workspace/api/admin/departments", headers=self.auth(alice_token)),
            403,
            "FORBIDDEN",
        )
        self.assert_error(
            self.client.get("/workspace/api/review/conversations", headers=self.auth(admin_token)),
            403,
            "FORBIDDEN",
        )


class ReviewScopeTests(WorkspaceHTTPBase):
    def test_review_grants_scopes_and_owner_rules(self) -> None:
        conversation_id = self.seeded_conversation(
            self.alice, "review original prompt", "review stored reply"
        )
        bob_token = self.login("bob")
        carol_token = self.login("carol")
        admin_token = self.login("root.admin")

        self.assert_error(
            self.client.get(
                f"/workspace/api/conversations/{conversation_id}", headers=self.auth(bob_token)
            ),
            403,
            "FORBIDDEN",
        )
        self.assert_error(
            self.client.delete(
                f"/workspace/api/conversations/{conversation_id}", headers=self.auth(bob_token)
            ),
            403,
            "FORBIDDEN",
        )

        department_grant = self.client.post(
            "/workspace/api/admin/review-grants",
            json={
                "user_id": self.carol["id"],
                "scope": "department",
                "department_id": self.accounting["id"],
            },
            headers=self.auth(admin_token),
        )
        self.assertEqual(department_grant.status_code, 201, department_grant.text)
        # An explicit review grant permits a read (and records the audit), but
        # the same route must not cross into another department.
        in_scope = self.client.get(
            f"/workspace/api/conversations/{conversation_id}", headers=self.auth(carol_token)
        )
        self.assertEqual(in_scope.status_code, 200, in_scope.text)
        admin_conversation = self.seeded_conversation(
            self.admin, "IT only prompt", "IT only reply"
        )
        self.assert_error(
            self.client.get(
                f"/workspace/api/conversations/{admin_conversation}",
                headers=self.auth(carol_token),
            ),
            403,
            "FORBIDDEN",
        )

        global_grant = self.client.post(
            "/workspace/api/admin/review-grants",
            json={"user_id": self.carol["id"], "scope": "global"},
            headers=self.auth(admin_token),
        )
        self.assertEqual(global_grant.status_code, 201, global_grant.text)
        reviewed = self.client.get(
            f"/workspace/api/review/conversations/{admin_conversation}",
            headers=self.auth(carol_token),
        )
        self.assertEqual(reviewed.status_code, 200, reviewed.text)
        self.assertEqual(reviewed.json()["messages"][0]["text"], "IT only prompt")

        log = self.store.list_access_log(self.admin["id"], limit=100)
        actions = [(item["actor_id"], item["action"]) for item in log["items"]]
        self.assertIn((self.carol["id"], "reviewer.read_conversation"), actions)
        self.assertNotIn((self.bob["id"], "reviewer.read_conversation"), actions)

        listed = self.client.get(
            "/workspace/api/review/conversations", headers=self.auth(carol_token)
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertTrue(listed.json()["items"])


class TurnFlowTests(WorkspaceHTTPBase):
    def test_masking_original_prompt_history_and_restart(self) -> None:
        token = self.login()
        conversation_id = self.new_conversation(token)
        original = "  Email person@example.com  \n"
        sent = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": original},
            headers=self.auth(token),
        )
        self.assertEqual(sent.status_code, 200, sent.text)
        delivered = sent.json()["content"]
        self.assertEqual(delivered, GATEWAY_REPLY)
        self.assertEqual(self.adapters.generate_inputs[0][-1]["content"], "  Email [EMAIL]  \n")

        second = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "second question"},
            headers=self.auth(token),
        )
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(
            self.adapters.generate_inputs[1],
            [
                # The Gateway masks PII before the model adapter sees the full
                # allowed history; the store keeps the exact original text.
                {"role": "user", "content": "  Email [EMAIL]  \n"},
                {"role": "assistant", "content": delivered},
                {"role": "user", "content": "second question"},
            ],
        )

        read = self.client.get(
            f"/workspace/api/conversations/{conversation_id}", headers=self.auth(token)
        )
        self.assertEqual(read.status_code, 200, read.text)
        messages = read.json()["messages"]
        self.assertEqual(messages[0]["text"], original)
        self.assertEqual(messages[0]["outcome"], "allowed")
        self.assertEqual(messages[1]["text"], delivered)

        bob_token = self.login("bob")
        bob_conversation = self.new_conversation(bob_token)
        bob_sent = self.client.post(
            f"/workspace/api/conversations/{bob_conversation}/messages",
            json={"text": "bob private prompt"},
            headers=self.auth(bob_token),
        )
        self.assertEqual(bob_sent.status_code, 200, bob_sent.text)
        self.assertEqual(
            [item["content"] for item in self.adapters.generate_inputs[-1]],
            ["bob private prompt"],
        )

        self.store.close()
        self.store = WorkspaceStore(
            self.db_path, encryption_key=self.key, connect_timeout=5.0
        )
        restarted = self.make_app()
        restart_client = self.make_client(restarted)
        read_again = restart_client.get(
            f"/workspace/api/conversations/{conversation_id}", headers=self.auth(token)
        )
        self.assertEqual(read_again.status_code, 200, read_again.text)
        self.assertEqual(read_again.json()["messages"][0]["text"], original)

    def test_input_and_output_block_store_failed_originals_only(self) -> None:
        alice_token = self.login()
        conversation_id = self.new_conversation(alice_token)
        self.adapters.attack_result = {"decision": "block"}
        blocked = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "blocked input prompt"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(blocked.status_code, 403, blocked.text)
        self.assertEqual(self.adapters.generate_calls, 0)

        self.adapters.attack_result = {"decision": "allow"}
        fresh = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "fresh question"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(fresh.status_code, 200, fresh.text)
        self.assertEqual(
            [item["content"] for item in self.adapters.generate_inputs[-1]],
            ["fresh question"],
        )

        self.adapters.generated = "RAW_BLOCKED_SECRET_OUTPUT"
        self.adapters.output_result = {"safe": False}
        raw_blocked = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "unsafe answer question"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(raw_blocked.status_code, 403, raw_blocked.text)
        self.assertNotIn("RAW_BLOCKED_SECRET_OUTPUT", raw_blocked.text)
        read = self.store.read_conversation(self.alice["id"], conversation_id)
        joined = "\n".join(item["text"] for item in read["messages"])
        self.assertNotIn("RAW_BLOCKED_SECRET_OUTPUT", joined)
        failed = [item for item in read["messages"] if item["outcome"] != "allowed"]
        self.assertTrue(failed)
        self.assertEqual(failed[-1]["error_code"], "POLICY_BLOCK")

        self.adapters.output_result = {"safe": True}
        after = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "after block"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(after.status_code, 200, after.text)
        self.assertEqual(
            [item["content"] for item in self.adapters.generate_inputs[-1]][-1],
            "after block",
        )
        self.assertNotIn(
            "unsafe answer question",
            [item["content"] for item in self.adapters.generate_inputs[-1]],
        )

    def test_persist_failure_returns_503_without_answer(self) -> None:
        class AppendFailureStore(_ProxyStore):
            def append_exchange(self, *args: Any, **kwargs: Any) -> Any:
                raise WorkspaceStorageError("synthetic append failure")

        app = self.make_app(store=AppendFailureStore(self.store))
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.new_conversation(token, client)
        response = client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "persist me"},
            headers=self.auth(token),
        )
        self.assert_error(response, 503, "UNAVAILABLE")
        self.assertNotIn(GATEWAY_REPLY, response.text)
        read = self.store.read_conversation(self.alice["id"], conversation_id)
        self.assertEqual(len(read["messages"]), 1)
        self.assertEqual(read["messages"][0]["outcome"], "failed")
        self.assertEqual(read["messages"][0]["text"], "persist me")

    def test_unavailable_generator_is_503_not_400(self) -> None:
        self.adapters.generate_error = RuntimeError("synthetic generation failure")
        token = self.login()
        conversation_id = self.new_conversation(token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "generate"},
            headers=self.auth(token),
        )
        self.assert_error(response, 503, "UNAVAILABLE")

    def test_malformed_history_fails_closed_without_generation(self) -> None:
        class MalformedContextStore(_ProxyStore):
            def read_context(self, owner_id: str, conversation_id: str) -> dict:
                return {"messages": [{"role": "system", "content": "injected"}]}

        app = self.make_app(store=MalformedContextStore(self.store))
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.new_conversation(token, client)
        before = self.adapters.generate_calls
        response = client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "hello"},
            headers=self.auth(token),
        )
        self.assert_error(response, 503, "UNAVAILABLE")
        self.assertEqual(self.adapters.generate_calls, before)
        read = self.store.read_conversation(self.alice["id"], conversation_id)
        self.assertEqual(read["messages"][-1]["outcome"], "failed")

    def test_corrupt_stored_history_is_503_without_inference(self) -> None:
        token = self.login()
        conversation_id = self.new_conversation(token)
        first = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "stored pair"},
            headers=self.auth(token),
        )
        self.assertEqual(first.status_code, 200, first.text)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA ignore_check_constraints = ON")
            conn.execute(
                "UPDATE ws_messages SET outcome = 'unknown' "
                "WHERE conversation_id = ? AND role = 'assistant'",
                (conversation_id,),
            )
            conn.commit()
        finally:
            conn.close()
        before = self.adapters.generate_calls
        response = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "must not reach provider"},
            headers=self.auth(token),
        )
        self.assert_error(response, 503, "UNAVAILABLE")
        self.assertEqual(self.adapters.generate_calls, before)

    def test_token_revalidated_inside_pipeline_denies_inference(self) -> None:
        token = self.login()
        conversation_id = self.new_conversation(token)
        original = self.store.resolve_session
        calls = {"count": 0}

        def flaky(inner: str) -> dict:
            calls["count"] += 1
            if calls["count"] >= 2:
                raise AuthError("session revoked")
            return original(inner)

        self.store.resolve_session = flaky
        self.addCleanup(setattr, self.store, "resolve_session", original)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "should not reach provider"},
            headers=self.auth(token),
        )
        self.assert_error(response, 401, "UNAUTHORIZED")
        self.assertEqual(self.adapters.generate_calls, 0)
        read = self.store.read_conversation(self.alice["id"], conversation_id)
        self.assertEqual(read["messages"][-1]["outcome"], "failed")


async def _wait_for(predicate: Any, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition was not observed within the bounded wait")


class HeldTurnTests(WorkspaceHTTPBase):
    def held_app(self) -> Any:
        app = self.make_app(chat_work_timeout=1.0, max_concurrency=1)
        self.gate = threading.Event()
        self.adapters.generate_gate = self.gate
        self.adapters.generate_started.clear()
        self.conversation_id = self.store.create_conversation(self.alice["id"])["id"]
        return app

    async def _login(self, client: httpx.AsyncClient) -> str:
        response = await client.post(
            "/workspace/api/login", json={"username": "alice", "password": PASSWORD}
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["token"]

    def _read(self) -> dict:
        return self.store.read_conversation(self.alice["id"], self.conversation_id)

    def test_timeout_holds_all_permits_until_real_thread_completion(self) -> None:
        app = self.held_app()
        runtime = app.state.workspace

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver", timeout=10
            ) as client:
                token = await self._login(client)
                headers = self.auth(token)
                request_task = asyncio.create_task(
                    client.post(
                        f"/workspace/api/conversations/{self.conversation_id}/messages",
                        json={"text": "held prompt"},
                        headers=headers,
                    )
                )
                await _wait_for(lambda: self.adapters.generate_started.is_set())
                self.assertTrue(app.state.sem.locked())
                self.assertEqual(runtime._principal_guard._inflight.get(self.alice["id"]), 1)
                self.assertIn(self.conversation_id, runtime._inflight_conversations)

                legacy = await client.post(
                    "/v1/chat/completions",
                    json=JSON_BODY,
                    headers={"Authorization": f"Bearer {LEGACY_KEY}"},
                )
                self.assertEqual(legacy.status_code, 503, legacy.text)

                response = await asyncio.wait_for(request_task, timeout=2.5)
                self.assertEqual(response.status_code, 503, response.text)
                # The HTTP deadline expired but the generation thread still runs.
                self.assertTrue(app.state.sem.locked())

                self.gate.set()
                await _wait_for(lambda: not app.state.sem.locked())
                await _wait_for(lambda: not app.state.workspace_tasks)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))
        self.assertEqual(runtime._principal_guard._inflight.get(self.alice["id"]), None)
        self.assertNotIn(self.conversation_id, runtime._inflight_conversations)
        messages = self._read()["messages"]
        self.assertEqual(len(messages), 1, messages)
        self.assertEqual(messages[0]["outcome"], "failed")
        self.assertEqual(messages[0]["error_code"], "DEADLINE")
        self.assertEqual(messages[0]["text"], "held prompt")

    def test_client_cancel_holds_permits_and_never_stores_late_assistant(self) -> None:
        app = self.held_app()
        runtime = app.state.workspace

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver", timeout=10
            ) as client:
                token = await self._login(client)
                headers = self.auth(token)
                request_task = asyncio.create_task(
                    client.post(
                        f"/workspace/api/conversations/{self.conversation_id}/messages",
                        json={"text": "cancelled prompt"},
                        headers=headers,
                    )
                )
                await _wait_for(lambda: self.adapters.generate_started.is_set())
                request_task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await request_task
                self.assertTrue(app.state.sem.locked())

                self.gate.set()
                await _wait_for(lambda: not app.state.sem.locked())
                await _wait_for(lambda: not app.state.workspace_tasks)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))
        self.assertIsNone(runtime._principal_guard._inflight.get(self.alice["id"]))
        self.assertNotIn(self.conversation_id, runtime._inflight_conversations)
        messages = self._read()["messages"]
        self.assertEqual(len(messages), 1, messages)
        self.assertEqual(messages[0]["outcome"], "failed")
        self.assertEqual(messages[0]["error_code"], "CANCELLED")
        self.assertTrue(all(item["role"] == "user" for item in messages))

    def test_same_conversation_is_rejected_while_a_turn_is_active(self) -> None:
        app = self.held_app()

        async def scenario() -> None:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://testserver", timeout=10
            ) as client:
                token = await self._login(client)
                headers = self.auth(token)
                request_task = asyncio.create_task(
                    client.post(
                        f"/workspace/api/conversations/{self.conversation_id}/messages",
                        json={"text": "first turn"},
                        headers=headers,
                    )
                )
                await _wait_for(lambda: self.adapters.generate_started.is_set())
                second = await asyncio.wait_for(
                    client.post(
                        f"/workspace/api/conversations/{self.conversation_id}/messages",
                        json={"text": "second turn"},
                        headers=headers,
                    ),
                    timeout=2.0,
                )
                self.assertEqual(second.status_code, 409, second.text)
                self.assertEqual(second.json()["error"]["code"], "CONFLICT")
                self.gate.set()
                first = await asyncio.wait_for(request_task, timeout=2.5)
                self.assertEqual(first.status_code, 200, first.text)

        asyncio.run(asyncio.wait_for(scenario(), timeout=10))
        messages = self._read()["messages"]
        self.assertEqual([item["role"] for item in messages], ["user", "assistant"])
        self.assertEqual(messages[0]["text"], "first turn")


if __name__ == "__main__":
    unittest.main()
