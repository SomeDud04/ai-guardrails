"""Focused tests for persisted admin role administration.

The SQLite/HTTP tests use the real application, a temporary workspace store and
in-process synthetic dependencies.  The optional PostgreSQL test contacts only
the dedicated disposable database named by ``TEST_WORKSPACE_DSN``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import unittest
import uuid

from nasi_lemak.workspace_store import (
    AccessDenied,
    AuthError,
    Conflict,
    NotFound,
    WorkspaceError,
    WorkspaceStore,
)
from tests.test_workspace_http import PASSWORD, WorkspaceHTTPBase

_ADMIN_TOKEN = "admin.set_user_role"
_PUBLIC_USER_FIELDS = {
    "id",
    "username",
    "full_name",
    "department_id",
    "role",
    "disabled",
    "created_at",
}


class AdminRoleStoreTests(WorkspaceHTTPBase):
    def test_valid_grant_and_revoke_return_safe_user_and_are_audited(self) -> None:
        promoted = self.store.set_user_role(
            self.admin["id"], self.alice["id"], "admin"
        )
        self.assertEqual(set(promoted), _PUBLIC_USER_FIELDS)
        self.assertEqual(promoted["role"], "admin")
        self.assertFalse(promoted["disabled"])
        self.assertNotIn("password_hash", promoted)

        demoted = self.store.set_user_role(
            self.admin["id"], self.alice["id"], "employee"
        )
        self.assertEqual(demoted["role"], "employee")

        actions = [
            row["action"]
            for row in self.store.list_access_log(self.admin["id"], limit=100)[
                "items"
            ]
        ]
        self.assertIn(f"{_ADMIN_TOKEN}:{self.alice['id']}:admin", actions)
        self.assertIn(f"{_ADMIN_TOKEN}:{self.alice['id']}:employee", actions)

        # Role changes do not grant transcript review on their own.
        self.assertEqual(
            self.store.list_grants(self.admin["id"], limit=100)["items"], []
        )
        conversation = self.seeded_conversation(
            self.bob, "role-test prompt", "role-test reply"
        )
        with self.assertRaises(AccessDenied):
            self.store.read_conversation(self.alice["id"], conversation)

    def test_last_active_admin_cannot_be_demoted_or_disabled(self) -> None:
        with self.assertRaises(Conflict):
            self.store.set_user_role(
                self.admin["id"], self.admin["id"], "employee"
            )
        with self.assertRaises(Conflict):
            self.store.disable_user(self.admin["id"], self.admin["id"])
        self.assertEqual(
            self.store.get_profile(self.admin["id"])["user"]["role"], "admin"
        )

        # A second active admin allows the original admin to step aside.
        self.store.set_user_role(self.admin["id"], self.alice["id"], "admin")
        stepped_down = self.store.set_user_role(
            self.admin["id"], self.admin["id"], "employee"
        )
        self.assertEqual(stepped_down["role"], "employee")

        # Alice is now the last active admin; neither operation may remove her.
        with self.assertRaises(Conflict):
            self.store.set_user_role(
                self.alice["id"], self.alice["id"], "employee"
            )
        with self.assertRaises(Conflict):
            self.store.disable_user(self.alice["id"], self.alice["id"])
        self.assertEqual(
            self.store.get_profile(self.alice["id"])["user"]["role"], "admin"
        )

        self.store.set_user_role(self.alice["id"], self.bob["id"], "admin")
        self.store.disable_user(self.bob["id"], self.alice["id"])
        users = {
            item["id"]: item
            for item in self.store.list_users(self.bob["id"], limit=100)["items"]
        }
        self.assertTrue(users[self.alice["id"]]["disabled"])
        with self.assertRaises(Conflict):
            self.store.disable_user(self.bob["id"], self.bob["id"])

    def test_disabled_unknown_and_invalid_role_targets(self) -> None:
        self.store.disable_user(self.admin["id"], self.alice["id"])
        with self.assertRaises(Conflict):
            self.store.set_user_role(
                self.admin["id"], self.alice["id"], "admin"
            )
        with self.assertRaises(NotFound):
            self.store.set_user_role(
                self.admin["id"], str(uuid.uuid4()), "admin"
            )
        for role in (None, True, 1, "owner", "", "ADMIN"):
            with self.assertRaises(ValueError):
                self.store.set_user_role(
                    self.admin["id"], self.bob["id"], role
                )
        with self.assertRaises(NotFound):
            self.store.set_user_role(
                self.admin["id"], "x" * 65, "admin"
            )

    def test_employee_cannot_change_own_or_other_role(self) -> None:
        for target in (self.alice["id"], self.bob["id"]):
            with self.assertRaises(AccessDenied):
                self.store.set_user_role(
                    self.alice["id"], target, "admin"
                )
        self.assertEqual(
            self.store.get_profile(self.alice["id"])["user"]["role"], "employee"
        )
        self.assertEqual(
            self.store.get_profile(self.bob["id"])["user"]["role"], "employee"
        )
        self.assertEqual(
            self.store.list_access_log(self.admin["id"], limit=100)["items"], []
        )

    def test_sessions_reread_role_without_being_revoked(self) -> None:
        session = self.store.authenticate("alice", PASSWORD)
        token = session["token"]
        self.assertEqual(
            self.store.resolve_session(token)["role"], "employee"
        )
        self.store.set_user_role(self.admin["id"], self.alice["id"], "admin")
        self.assertEqual(
            self.store.resolve_session(token)["role"], "admin"
        )
        self.store.list_users(self.alice["id"])
        self.store.set_user_role(
            self.admin["id"], self.alice["id"], "employee"
        )
        self.assertEqual(
            self.store.resolve_session(token)["role"], "employee"
        )
        with self.assertRaises(AccessDenied):
            self.store.list_users(self.alice["id"])


class AccountLifecycleStoreTests(WorkspaceHTTPBase):
    """Enable and delete behaviour, including the documented deletion rule."""

    def _rows(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(sql, params)]
        finally:
            conn.close()

    def _blocked_alert(self, owner: dict, request_id: str) -> tuple[str, str]:
        control = self.store.resolve_gateway_control(owner["id"])
        alert = {
            "stage": "input",
            "reason_code": "INPUT_GUARD_BLOCK",
            "revision": control.revision,
            "digest": control.digest,
            "sources": control.metadata()["sources"],
        }
        conversation = self.store.create_conversation(owner["id"])
        lease = self.store.reserve_turn(owner["id"], conversation["id"])
        result = self.store.record_failed_turn(
            owner["id"],
            conversation["id"],
            lease["token"],
            user_prompt="synthetic blocked prompt",
            outcome="blocked",
            request_id=request_id,
            error_code="POLICY_BLOCK",
            alert=alert,
        )
        return conversation["id"], result["alert_id"]

    def _actions(self, actor_id: str | None = None) -> list[str]:
        return [
            row["action"]
            for row in self.store.list_access_log(
                self.admin["id"] if actor_id is None else actor_id, limit=100
            )["items"]
        ]

    def test_enable_after_disable_preserves_account_and_history(self) -> None:
        promoted = self.store.set_user_role(
            self.admin["id"], self.bob["id"], "admin"
        )
        self.assertEqual(promoted["role"], "admin")
        conversation = self.seeded_conversation(
            self.bob, "enable history prompt", "enable history reply"
        )
        old_token = self.store.authenticate("bob", PASSWORD)["token"]

        self.store.disable_user(self.admin["id"], self.bob["id"])
        with self.assertRaises(AuthError):
            self.store.resolve_session(old_token)
        with self.assertRaises(AuthError):
            self.store.authenticate("bob", PASSWORD)

        enabled = self.store.enable_user(self.admin["id"], self.bob["id"])
        self.assertEqual(set(enabled), _PUBLIC_USER_FIELDS)
        self.assertFalse(enabled["disabled"])
        self.assertEqual(enabled["role"], "admin")
        self.assertEqual(enabled["username"], "bob")
        self.assertNotIn("password_hash", enabled)

        # The pre-disable session stays revoked; the same password signs in.
        with self.assertRaises(AuthError):
            self.store.resolve_session(old_token)
        fresh = self.store.authenticate("bob", PASSWORD)
        self.assertFalse(fresh["user"]["disabled"])
        self.assertEqual(fresh["user"]["role"], "admin")
        history = self.store.read_context(self.bob["id"], conversation)
        self.assertEqual(
            [message["role"] for message in history["messages"]],
            ["user", "assistant"],
        )
        self.assertEqual(
            history["messages"][0]["content"], "enable history prompt"
        )

        with self.assertRaises(Conflict):
            self.store.enable_user(self.admin["id"], self.bob["id"])
        self.assertIn("admin.enable_user", self._actions())

    def test_enable_denies_employee_unknown_and_active_targets(self) -> None:
        for actor in (self.alice["id"], self.bob["id"]):
            with self.assertRaises(AccessDenied):
                self.store.enable_user(actor, self.bob["id"])
        with self.assertRaises(NotFound):
            self.store.enable_user(self.admin["id"], str(uuid.uuid4()))
        with self.assertRaises(NotFound):
            self.store.enable_user(self.admin["id"], "x" * 65)
        with self.assertRaises(Conflict):
            self.store.enable_user(self.admin["id"], self.bob["id"])
        self.assertNotIn("admin.enable_user", self._actions())

    def test_delete_erases_content_and_owned_alerts_but_keeps_audit(self) -> None:
        seeded = self.seeded_conversation(
            self.bob, "delete transcript prompt", "delete transcript reply"
        )
        alert_conversation, alert_id = self._blocked_alert(
            self.bob, "req_delete_alert"
        )
        self.store.mark_block_alert_read(self.admin["id"], alert_id)
        # A completed own-conversation deletion leaves a metadata-only audit row
        # authored by the account that is about to be removed.
        removed_own = self.store.create_conversation(self.bob["id"])
        self.store.delete_conversation(self.bob["id"], removed_own["id"])

        result = self.store.delete_user(self.admin["id"], self.bob["id"], "bob")
        self.assertEqual(
            result,
            {
                "status": "deleted",
                "deleted_conversations": 2,
                "deleted_messages": 3,
            },
        )

        users = self.store.list_users(self.admin["id"], limit=100)["items"]
        self.assertNotIn(self.bob["id"], {user["id"] for user in users})
        with self.assertRaises(AuthError):
            self.store.authenticate("bob", PASSWORD)
        self.assertEqual(
            self._rows(
                "SELECT id FROM ws_conversations WHERE id IN (?, ?)",
                (seeded, alert_conversation),
            ),
            [],
        )
        self.assertEqual(
            self._rows(
                "SELECT id FROM ws_messages WHERE conversation_id IN (?, ?)",
                (seeded, alert_conversation),
            ),
            [],
        )
        self.assertEqual(
            self._rows("SELECT id FROM ws_block_alerts WHERE id = ?", (alert_id,)),
            [],
        )
        self.assertEqual(
            self._rows(
                "SELECT * FROM ws_alert_state WHERE alert_id = ?", (alert_id,)
            ),
            [],
        )

        events = self.store.list_access_log(self.admin["id"], limit=100)["items"]
        delete_event = next(
            event
            for event in events
            if event["action"] == f"admin.delete_user:{self.bob['id']}"
        )
        self.assertEqual(delete_event["actor_id"], self.admin["id"])
        self.assertIsNone(delete_event["conversation_id"])
        self.assertEqual(delete_event["department_id"], self.bob["department_id"])
        own_delete = next(
            event
            for event in events
            if event["actor_id"] == self.bob["id"]
            and event["action"] == "owner.delete_conversation"
        )
        self.assertEqual(own_delete["conversation_id"], removed_own["id"])
        self.assertNotIn(
            "delete transcript prompt", json.dumps(events, sort_keys=True)
        )

    def test_delete_requires_exact_username_and_denies_self_and_last_admin(self) -> None:
        with self.assertRaises(Conflict):
            self.store.delete_user(
                self.admin["id"], self.admin["id"], "root.admin"
            )
        with self.assertRaises(AccessDenied):
            self.store.delete_user(self.alice["id"], self.bob["id"], "bob")
        for wrong in ("bobby", "alice", "", "bob!", None):
            with self.assertRaises(ValueError):
                self.store.delete_user(self.admin["id"], self.bob["id"], wrong)

        # Promote Bob, then step the original admin down: Bob is now the only
        # active administrator and must not be able to remove that account.
        self.store.set_user_role(self.admin["id"], self.bob["id"], "admin")
        self.store.set_user_role(self.admin["id"], self.admin["id"], "employee")
        with self.assertRaises(Conflict):
            self.store.delete_user(self.bob["id"], self.bob["id"], "bob")

        bob_session = self.store.authenticate("bob", PASSWORD)
        users = self.store.list_users(bob_session["user"]["id"], limit=100)["items"]
        self.assertIn(self.bob["id"], {user["id"] for user in users})
        self.assertNotIn(
            f"admin.delete_user:{self.bob['id']}",
            self._actions(bob_session["user"]["id"]),
        )

        # The exact confirmation succeeds for an ordinary account.
        deleted = self.store.delete_user(self.bob["id"], self.alice["id"], "alice")
        self.assertEqual(deleted["status"], "deleted")

    def test_delete_conflicts_for_authored_policy_and_grant_history(self) -> None:
        self.store.set_user_role(self.admin["id"], self.bob["id"], "admin")
        self.store.set_user_role(self.admin["id"], self.carol["id"], "admin")
        self.store.create_policy_profile(self.bob["id"], "Retained profile")
        self.store.grant_review(self.carol["id"], self.alice["id"], "global")

        for target in (self.bob, self.carol):
            with self.subTest(target=target["username"]):
                with self.assertRaises(Conflict):
                    self.store.delete_user(
                        self.admin["id"], target["id"], target["username"]
                    )
        users = self.store.list_users(self.admin["id"], limit=100)["items"]
        self.assertTrue(
            {self.bob["id"], self.carol["id"]}.issubset(
                {user["id"] for user in users}
            )
        )

    def test_delete_conflicts_for_user_scoped_assignment_target(self) -> None:
        profile = self.store.create_policy_profile(
            self.admin["id"], "User scoped deletion"
        )
        self.store.assign_policy_profile(
            self.admin["id"], "user", self.bob["id"], profile["id"]
        )
        with self.assertRaises(Conflict):
            self.store.delete_user(self.admin["id"], self.bob["id"], "bob")

    def test_delete_conflicts_during_an_active_turn(self) -> None:
        conversation = self.store.create_conversation(self.alice["id"])
        lease = self.store.reserve_turn(self.alice["id"], conversation["id"])
        with self.assertRaises(Conflict):
            self.store.delete_user(self.admin["id"], self.alice["id"], "alice")
        # An appending turn is protected by the same guard.
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE ws_conversations SET status = 'appending' WHERE id = ?",
                (conversation["id"],),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(Conflict):
            self.store.delete_user(self.admin["id"], self.alice["id"], "alice")

        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE ws_conversations SET status = 'pending' WHERE id = ?",
                (conversation["id"],),
            )
            conn.commit()
        finally:
            conn.close()
        self.store.append_exchange(
            self.alice["id"],
            conversation["id"],
            lease["token"],
            user_prompt="active turn prompt",
            assistant_response="active turn reply",
        )
        deleted = self.store.delete_user(self.admin["id"], self.alice["id"], "alice")
        self.assertEqual(deleted["deleted_conversations"], 1)


class AdminRoleHTTPTests(WorkspaceHTTPBase):
    ORIGIN = "http://testserver"

    def _admin_token(self) -> str:
        return self.login("root.admin")

    def _cookie_login(self, username: str = "root.admin"):
        response = self.client.post(
            "/workspace/api/login",
            json={"username": username, "password": PASSWORD, "cookie": True},
            headers={"Origin": self.ORIGIN},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def _role_url(self, user_id: str) -> str:
        return f"/workspace/api/admin/users/{user_id}/role"

    def test_employee_escalation_is_denied_before_body_validation(self) -> None:
        token = self.login("alice")
        for target in (self.alice["id"], self.bob["id"]):
            response = self.client.post(
                self._role_url(target),
                json={"role": "admin", "extra": "ignored"},
                headers=self.auth(token),
            )
            self.assert_error(response, 403, "FORBIDDEN")
        self.assertEqual(
            self.store.get_profile(self.alice["id"])["user"]["role"], "employee"
        )
        self.assertEqual(
            self.store.get_profile(self.bob["id"])["user"]["role"], "employee"
        )

    def test_strict_body_fields_and_bounded_safe_errors(self) -> None:
        token = self._admin_token()
        for payload in (
            {"role": "admin", "extra": True},
            {"extra": "admin"},
            {"role": ["admin"]},
            {"role": "owner"},
            {"role": None},
        ):
            response = self.client.post(
                self._role_url(self.alice["id"]),
                json=payload,
                headers=self.auth(token),
            )
            self.assert_error(response, 400, "INVALID_REQUEST")
            self.assertNotIn("owner", response.text)
            self.assertNotIn("Traceback", response.text)
        unknown = self.client.post(
            self._role_url(str(uuid.uuid4())),
            json={"role": "admin"},
            headers=self.auth(token),
        )
        self.assert_error(unknown, 404, "INVALID_REQUEST")

    def test_cookie_origin_json_and_identity_are_enforced(self) -> None:
        self._cookie_login()
        payload = {"role": "admin"}
        for headers in (
            {"X-Workspace-User": self.admin["id"]},
            {
                "Origin": "https://evil.example",
                "X-Workspace-User": self.admin["id"],
            },
        ):
            response = self.client.post(
                self._role_url(self.alice["id"]), json=payload, headers=headers
            )
            self.assert_error(response, 403, "FORBIDDEN")

        not_json = self.client.post(
            self._role_url(self.alice["id"]),
            content=json.dumps(payload),
            headers={
                "Origin": self.ORIGIN,
                "X-Workspace-User": self.admin["id"],
                "Content-Type": "text/plain",
            },
        )
        self.assert_error(not_json, 403, "FORBIDDEN")

        success = self.client.post(
            self._role_url(self.alice["id"]),
            json=payload,
            headers={
                "Origin": self.ORIGIN,
                "X-Workspace-User": self.admin["id"],
            },
        )
        self.assertEqual(success.status_code, 200, success.text)
        self.assertEqual(success.json()["role"], "admin")
        self.assertEqual(set(success.json()), _PUBLIC_USER_FIELDS)

    def test_success_conflict_revoked_session_and_disabled_target(self) -> None:
        token = self._admin_token()
        promoted = self.client.post(
            self._role_url(self.alice["id"]),
            json={"role": "admin"},
            headers=self.auth(token),
        )
        self.assertEqual(promoted.status_code, 200, promoted.text)
        self.assertEqual(promoted.json()["role"], "admin")
        self.assertEqual(set(promoted.json()), _PUBLIC_USER_FIELDS)
        self.assertNotIn("password_hash", promoted.text)

        demoted = self.client.post(
            self._role_url(self.alice["id"]),
            json={"role": "employee"},
            headers=self.auth(token),
        )
        self.assertEqual(demoted.status_code, 200, demoted.text)
        self.assertEqual(demoted.json()["role"], "employee")

        last_admin = self.client.post(
            self._role_url(self.admin["id"]),
            json={"role": "employee"},
            headers=self.auth(token),
        )
        self.assert_error(last_admin, 409, "CONFLICT")

        self.assertEqual(
            self.client.post(
                "/workspace/api/logout", headers=self.auth(token)
            ).status_code,
            200,
        )
        revoked = self.client.post(
            self._role_url(self.alice["id"]),
            json={"role": "admin"},
            headers=self.auth(token),
        )
        self.assert_error(revoked, 401, "UNAUTHORIZED")

        fresh = self._admin_token()
        disabled = self.client.post(
            f"/workspace/api/admin/users/{self.bob['id']}/disable",
            json={},
            headers=self.auth(fresh),
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        disabled_target = self.client.post(
            self._role_url(self.bob["id"]),
            json={"role": "admin"},
            headers=self.auth(fresh),
        )
        self.assert_error(disabled_target, 409, "CONFLICT")


class AccountLifecycleHTTPTests(WorkspaceHTTPBase):
    ORIGIN = "http://testserver"

    def _admin_token(self) -> str:
        return self.login("root.admin")

    def _enable_url(self, user_id: str) -> str:
        return f"/workspace/api/admin/users/{user_id}/enable"

    def _delete_url(self, user_id: str) -> str:
        return f"/workspace/api/admin/users/{user_id}/delete"

    def _cookie_login(self, username: str = "root.admin"):
        response = self.client.post(
            "/workspace/api/login",
            json={"username": username, "password": PASSWORD, "cookie": True},
            headers={"Origin": self.ORIGIN},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def test_enable_and_delete_are_admin_only(self) -> None:
        alice_token = self.login("alice")
        delete_url = self._delete_url(self.bob["id"])
        for url, payload in (
            (self._enable_url(self.bob["id"]), {}),
            (delete_url, {"confirm_username": "bob"}),
        ):
            with self.subTest(url=url, caller="employee"):
                self.assert_error(
                    self.client.post(
                        url, json=payload, headers=self.auth(alice_token)
                    ),
                    403,
                    "FORBIDDEN",
                )
            with self.subTest(url=url, caller="anonymous"):
                self.assert_error(
                    self.client.post(url, json=payload), 401, "UNAUTHORIZED"
                )
        # The denials did not change the target.
        self.store.authenticate("bob", PASSWORD)
        self.assertFalse(
            self.store.get_profile(self.bob["id"])["user"]["disabled"]
        )

    def test_enable_after_disable_round_trip_over_http(self) -> None:
        admin_token = self._admin_token()
        bob_token = self.login("bob")
        seeded = self.seeded_conversation(
            self.bob, "http enable prompt", "http enable reply"
        )
        disabled = self.client.post(
            f"/workspace/api/admin/users/{self.bob['id']}/disable",
            json={},
            headers=self.auth(admin_token),
        )
        self.assertEqual(disabled.status_code, 200, disabled.text)
        self.assert_error(
            self.client.get("/workspace/api/me", headers=self.auth(bob_token)),
            401,
            "UNAUTHORIZED",
        )
        self.assert_error(
            self.client.post(
                "/workspace/api/login",
                json={"username": "bob", "password": PASSWORD},
            ),
            401,
            "UNAUTHORIZED",
        )

        enabled = self.client.post(
            self._enable_url(self.bob["id"]),
            json={},
            headers=self.auth(admin_token),
        )
        self.assertEqual(enabled.status_code, 200, enabled.text)
        self.assertFalse(enabled.json()["disabled"])
        self.assertEqual(enabled.json()["role"], "employee")
        self.assertEqual(set(enabled.json()), _PUBLIC_USER_FIELDS)

        self.assert_error(
            self.client.get("/workspace/api/me", headers=self.auth(bob_token)),
            401,
            "UNAUTHORIZED",
        )
        fresh = self.login("bob")
        listed = self.client.get(
            "/workspace/api/conversations", headers=self.auth(fresh)
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertIn(seeded, {item["id"] for item in listed.json()["items"]})
        self.assert_error(
            self.client.post(
                self._enable_url(self.bob["id"]),
                json={},
                headers=self.auth(admin_token),
            ),
            409,
            "CONFLICT",
        )

    def test_delete_over_http_removes_account_and_keeps_audit(self) -> None:
        admin_token = self._admin_token()
        seeded = self.seeded_conversation(
            self.bob, "http delete prompt", "http delete reply"
        )
        delete_url = self._delete_url(self.bob["id"])
        for payload in (
            {},
            {"confirm_username": "alice"},
            {"confirm_username": "bob", "extra": True},
        ):
            with self.subTest(payload=payload):
                self.assert_error(
                    self.client.post(
                        delete_url, json=payload, headers=self.auth(admin_token)
                    ),
                    400,
                    "INVALID_REQUEST",
                )
        self.store.authenticate("bob", PASSWORD)

        deleted = self.client.post(
            delete_url,
            json={"confirm_username": "bob"},
            headers=self.auth(admin_token),
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertEqual(deleted.json()["status"], "deleted")
        self.assertEqual(deleted.json()["deleted_conversations"], 1)
        self.assertEqual(deleted.json()["deleted_messages"], 2)

        self.assert_error(
            self.client.post(
                "/workspace/api/login",
                json={"username": "bob", "password": PASSWORD},
            ),
            401,
            "UNAUTHORIZED",
        )
        users = self.client.get(
            "/workspace/api/admin/users", headers=self.auth(admin_token)
        ).json()["items"]
        self.assertNotIn(self.bob["id"], {user["id"] for user in users})
        events = self.client.get(
            "/workspace/api/admin/access-log", headers=self.auth(admin_token)
        ).json()["items"]
        self.assertIn(
            f"admin.delete_user:{self.bob['id']}",
            {event["action"] for event in events},
        )
        self.assertNotIn("http delete prompt", json.dumps(events))

        self.assert_error(
            self.client.post(
                self._delete_url(self.admin["id"]),
                json={"confirm_username": "root.admin"},
                headers=self.auth(admin_token),
            ),
            409,
            "CONFLICT",
        )

    def test_cookie_csrf_and_json_body_validation(self) -> None:
        admin_token = self._admin_token()
        delete_url = self._delete_url(self.bob["id"])
        enable_url = self._enable_url(self.bob["id"])

        self.assert_error(
            self.client.post(
                enable_url, json={"extra": True}, headers=self.auth(admin_token)
            ),
            400,
            "INVALID_REQUEST",
        )
        duplicate = self.client.post(
            delete_url,
            content='{"confirm_username": "bob", "confirm_username": "bob"}',
            headers={
                **self.auth(admin_token),
                "Content-Type": "application/json",
            },
        )
        self.assert_error(duplicate, 400, "INVALID_REQUEST")

        self._cookie_login()
        identity = {"X-Workspace-User": self.admin["id"]}
        for url, payload in (
            (enable_url, {}),
            (delete_url, {"confirm_username": "bob"}),
        ):
            with self.subTest(url=url, check="missing origin"):
                self.assert_error(
                    self.client.post(url, json=payload, headers=identity),
                    403,
                    "FORBIDDEN",
                )
            with self.subTest(url=url, check="cross origin"):
                self.assert_error(
                    self.client.post(
                        url,
                        json=payload,
                        headers={**identity, "Origin": "https://evil.example"},
                    ),
                    403,
                    "FORBIDDEN",
                )
            with self.subTest(url=url, check="not json"):
                self.assert_error(
                    self.client.post(
                        url,
                        content=json.dumps(payload),
                        headers={
                            **identity,
                            "Origin": self.ORIGIN,
                            "Content-Type": "text/plain",
                        },
                    ),
                    403,
                    "FORBIDDEN",
                )
        self.assert_error(
            self.client.post(
                delete_url,
                json={"extra": "bob"},
                headers={**identity, "Origin": self.ORIGIN},
            ),
            400,
            "INVALID_REQUEST",
        )

        deleted = self.client.post(
            delete_url,
            json={"confirm_username": "bob"},
            headers={**identity, "Origin": self.ORIGIN},
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertEqual(deleted.json()["status"], "deleted")


@unittest.skipUnless(
    os.environ.get("TEST_WORKSPACE_DSN"),
    "TEST_WORKSPACE_DSN not set; no database contacted",
)
class PostgresAdminRoleConcurrencyTests(unittest.TestCase):
    """Optional simultaneous demotion test against a disposable database."""

    TEST_KEY = "SIuN9xihVB4_BtpG0So_WjfgQNiprJozOTk6YZMA_2o="

    def _open(self) -> WorkspaceStore:
        return WorkspaceStore(
            os.environ["TEST_WORKSPACE_DSN"], encryption_key=self.TEST_KEY
        )

    def test_simultaneous_self_demotion_has_one_winner(self) -> None:
        owner_store = self._open()
        admin = owner_store.bootstrap_admin(
            username="pg.admin.owner",
            password=PASSWORD,
            full_name="PG Admin",
            department_name="PG IT",
        )
        if admin is None:
            admin = owner_store.authenticate("pg.admin.owner", PASSWORD)["user"]
        suffix = uuid.uuid4().hex[:8]
        department = owner_store.create_department(
            admin["id"], f"PG Roles {suffix}"
        )
        target = owner_store.create_user(
            admin["id"],
            f"pg.roles.{suffix}",
            PASSWORD,
            "PG Role Target",
            department["id"],
            "employee",
        )
        owner_store.set_user_role(admin["id"], target["id"], "admin")

        workers = [self._open(), self._open()]
        barrier = threading.Barrier(2)
        results: list[str] = []

        def demote(worker: WorkspaceStore) -> None:
            barrier.wait()
            try:
                worker.set_user_role(target["id"], target["id"], "employee")
                results.append("ok")
            except WorkspaceError as exc:
                results.append(type(exc).__name__)

        threads = [
            threading.Thread(target=demote, args=(worker,)) for worker in workers
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(results), ["AccessDenied", "ok"])
        self.assertEqual(
            owner_store.get_profile(target["id"])["user"]["role"],
            "employee",
        )
        owner_store.disable_user(admin["id"], target["id"])
        for worker in workers:
            worker.close()
        owner_store.close()


if __name__ == "__main__":
    unittest.main()
