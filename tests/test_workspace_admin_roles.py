"""Focused tests for persisted admin role administration.

The SQLite/HTTP tests use the real application, a temporary workspace store and
in-process synthetic dependencies.  The optional PostgreSQL test contacts only
the dedicated disposable database named by ``TEST_WORKSPACE_DSN``.
"""

from __future__ import annotations

import json
import os
import threading
import unittest
import uuid

from nasi_lemak.workspace_store import (
    AccessDenied,
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
