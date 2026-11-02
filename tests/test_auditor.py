"""The read-only auditor role and the whole-workspace audit export."""

from __future__ import annotations

import csv
import io
import re
import unittest
from pathlib import Path

from nasi_lemak import workspace_store
from nasi_lemak.system_settings import DEFAULT_SETTINGS
from nasi_lemak.workspace_store import AccessDenied, Conflict
from tests.test_api_keys import ApiKeyBase
from tests.test_workspace_http import PASSWORD

ADMIN = "/workspace/api/admin"
EXPORT_PATH = f"{ADMIN}/audit-export.csv"
ROOT = Path(__file__).resolve().parents[1]


class AuditorBase(ApiKeyBase):
    def setUp(self) -> None:
        super().setUp()
        self.auditor = self.store.create_user(
            self.admin["id"],
            "audit.user",
            PASSWORD,
            "Audit User",
            self.accounting["id"],
            role="auditor",
        )

    def auditor_headers(self) -> dict[str, str]:
        return self.auth(self.login("audit.user"))


class AuditorRoleTests(AuditorBase):
    def test_the_role_is_reported_everywhere_an_account_is_read(self) -> None:
        self.assertEqual(self.auditor["role"], "auditor")
        headers = self.auditor_headers()
        me = self.client.get("/workspace/api/me", headers=headers)
        self.assertEqual(me.json()["user"]["role"], "auditor")
        listed = self.store.list_users(self.auditor["id"], limit=100)["items"]
        self.assertIn(
            "auditor", [user["role"] for user in listed if user["id"] == self.auditor["id"]]
        )

    def test_every_metadata_page_is_readable(self) -> None:
        item = self.generate()["item"]
        headers = self.auditor_headers()
        for path in (
            "/departments",
            "/users",
            "/review-grants",
            "/access-log",
            "/settings",
            "/live",
            "/monitor",
            "/api-keys",
            f"/api-keys/{item['id']}/requests",
            f"/api-keys/{item['id']}/requests.csv",
            "/system-settings",
            "/policy/profiles",
            "/policy/audit",
            "/policy/assignments",
            "/alerts",
            "/alerts/summary",
            "/audit-export.csv",
        ):
            with self.subTest(path=path):
                response = self.client.get(ADMIN + path, headers=headers)
                self.assertEqual(response.status_code, 200, response.text)

    def test_every_change_is_refused(self) -> None:
        item = self.generate()["item"]
        target = self.alice["id"]
        paths = (
            "/departments",
            "/users",
            f"/users/{target}/disable",
            f"/users/{target}/enable",
            f"/users/{target}/delete",
            f"/users/{target}/role",
            f"/users/{target}/reset-password",
            "/review-grants",
            "/api-keys",
            f"/api-keys/{item['id']}",
            f"/api-keys/{item['id']}/revoke",
            "/system-settings",
            "/system-settings/rollback",
            "/policy/profiles",
            "/policy/assignments",
            "/alerts/read-all",
        )
        headers = self.auditor_headers()
        for path in paths:
            with self.subTest(path=path):
                response = self.client.post(ADMIN + path, json={}, headers=headers)
                self.assert_error(response, 403, "FORBIDDEN")
        self.assertFalse(self.store.list_users(self.admin["id"], limit=100)["items"][0]["disabled"])
        self.assertEqual(self.store.current_system_settings()["revision"], 0)

    def test_every_admin_post_route_is_closed_to_auditors(self) -> None:
        # A route added later is covered by the method rule, not by this list.
        headers = self.auditor_headers()
        posts = [
            route
            for route in self.app.routes
            if route.path.startswith(ADMIN)
            and set(getattr(route, "methods", ())) & {"POST", "PUT", "PATCH", "DELETE"}
        ]
        self.assertGreater(len(posts), 20)
        for route in posts:
            path = re.sub(r"{[^}]+}", "x", route.path)
            method = sorted(set(route.methods) - {"HEAD", "OPTIONS"})[0]
            with self.subTest(path=path):
                response = self.client.request(method, path, json={}, headers=headers)
                self.assert_error(response, 403, "FORBIDDEN")

    def test_stored_text_stays_out_of_reach(self) -> None:
        created = self.store.create_api_key(
            self.admin["id"], "Text", self.alice["id"], store_text=True
        )
        response = self.chat(created["key"])
        self.assertEqual(response.status_code, 200, response.text)
        key_id = created["item"]["id"]
        request_id = self.store.list_api_key_requests(self.admin["id"], key_id)["items"][0][
            "request_id"
        ]
        refused = self.client.get(
            f"{ADMIN}/api-keys/{key_id}/requests/{request_id}/text",
            headers=self.auditor_headers(),
        )
        self.assert_error(refused, 403, "FORBIDDEN")
        with self.assertRaises(AccessDenied):
            self.store.read_api_key_text(self.auditor["id"], key_id, request_id)

    def test_an_auditor_can_still_chat_as_a_normal_user(self) -> None:
        token = self.login("audit.user")
        self.new_conversation(token)

    def test_changing_a_role_takes_effect_at_once(self) -> None:
        headers = self.auth(self.login("alice"))
        self.assert_error(self.client.get(f"{ADMIN}/users", headers=headers), 403, "FORBIDDEN")

        updated = self.store.set_user_role(self.admin["id"], self.alice["id"], "auditor")
        self.assertEqual(updated["role"], "auditor")
        self.assertEqual(
            self.client.get(f"{ADMIN}/users", headers=headers).status_code, 200
        )

        self.store.set_user_role(self.admin["id"], self.alice["id"], "admin")
        made_admin = self.store.get_profile(self.alice["id"])
        self.assertEqual(made_admin["user"]["role"], "admin")

        self.store.set_user_role(self.admin["id"], self.alice["id"], "employee")
        self.assert_error(self.client.get(f"{ADMIN}/users", headers=headers), 403, "FORBIDDEN")

    def test_a_disabled_auditor_is_refused(self) -> None:
        self.store.disable_user(self.admin["id"], self.auditor["id"])
        with self.assertRaises(AccessDenied):
            self.store.list_users(self.auditor["id"])

    def test_the_last_administrator_cannot_become_an_auditor(self) -> None:
        with self.assertRaises(Conflict):
            self.store.set_user_role(self.admin["id"], self.admin["id"], "auditor")

    def test_the_access_log_shows_the_auditor_role(self) -> None:
        self.store.set_user_role(self.admin["id"], self.alice["id"], "auditor")
        self.store.export_audit(self.alice["id"], 0.0)
        items = self.store.list_access_log(self.admin["id"])["items"]
        self.assertIn("auditor", [item["actor_role"] for item in items])

    def test_only_listed_reads_open_the_store_to_auditors(self) -> None:
        # Any other store method still calls _require_admin and refuses.
        with self.assertRaises(AccessDenied):
            self.store.create_department(self.auditor["id"], "Blocked")


class AuditExportTests(AuditorBase):
    def export(self, headers: dict[str, str], query: str = "") -> list[dict[str, str]]:
        response = self.client.get(EXPORT_PATH + query, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["content-type"].split(";")[0], "text/csv")
        return list(csv.DictReader(io.StringIO(response.text)))

    def test_the_export_joins_every_kind_of_record(self) -> None:
        created = self.generate("Export key")
        self.assertEqual(self.chat(created["key"]).status_code, 200)
        self.store.save_system_settings(
            self.admin["id"],
            dict(DEFAULT_SETTINGS),
            "Quarterly review",
            expected_revision=0,
        )
        self.store.disable_user(self.admin["id"], self.bob["id"])

        rows = self.export(self.auditor_headers())

        self.assertEqual(
            list(rows[0]),
            ["time", "source", "actor", "action", "target", "client_ip", "outcome", "detail"],
        )
        by_source = {row["source"] for row in rows}
        self.assertTrue({"access", "settings", "api_key"} <= by_source, by_source)
        self.assertIn("Quarterly review", [row["detail"] for row in rows])
        self.assertIn("Export key", [row["actor"] for row in rows])
        self.assertEqual(rows, sorted(rows, key=lambda row: row["time"]))

    def test_taking_an_export_is_itself_recorded(self) -> None:
        self.export(self.auditor_headers())
        actions = self.store.list_access_log(self.admin["id"])["items"]
        self.assertEqual(actions[0]["action"], "admin.export_audit")
        self.assertEqual(actions[0]["actor_id"], self.auditor["id"])

    def test_the_export_never_holds_message_text(self) -> None:
        token = self.login("alice")
        conversation = self.new_conversation(token)
        self.client.post(
            f"/workspace/api/conversations/{conversation}/messages",
            json={"text": "UNIQUE-SECRET-PROMPT"},
            headers=self.auth(token),
        )
        created = self.store.create_api_key(
            self.admin["id"], "Text", self.alice["id"], store_text=True
        )
        self.chat(created["key"])
        response = self.client.get(EXPORT_PATH, headers=self.auditor_headers())
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("UNIQUE-SECRET-PROMPT", response.text)
        self.assertNotIn("hello", response.text)

    def test_the_range_is_applied_and_bounded(self) -> None:
        headers = self.auditor_headers()
        self.assertGreater(len(self.export(headers, "?days=1")), 0)
        for query in ("?days=0", "?days=366", "?days=x", "?days=1&days=2", "?other=1"):
            with self.subTest(query=query):
                response = self.client.get(EXPORT_PATH + query, headers=headers)
                self.assert_error(response, 400, "INVALID_REQUEST")

    def test_old_records_are_left_out(self) -> None:
        self.store.disable_user(self.admin["id"], self.bob["id"])
        rows = self.store.export_audit(self.auditor["id"], self.store._now() + 3600)
        self.assertEqual(rows, [])

    def test_a_range_too_large_is_refused_not_cut_short(self) -> None:
        original = workspace_store.MAX_AUDIT_EXPORT_ROWS
        workspace_store.MAX_AUDIT_EXPORT_ROWS = 1
        self.addCleanup(setattr, workspace_store, "MAX_AUDIT_EXPORT_ROWS", original)
        self.store.disable_user(self.admin["id"], self.bob["id"])
        self.store.disable_user(self.admin["id"], self.carol["id"])
        response = self.client.get(EXPORT_PATH, headers=self.auditor_headers())
        self.assert_error(response, 409, "CONFLICT")

    def test_spreadsheet_formulas_are_neutralised(self) -> None:
        self.generate("=HYPERLINK(1)")
        created = self.store.create_api_key(self.admin["id"], "=SUM(1)", self.alice["id"])
        self.chat(created["key"])
        response = self.client.get(EXPORT_PATH, headers=self.auditor_headers())
        self.assertIn("'=SUM(1)", response.text)

    def test_employees_cannot_export(self) -> None:
        response = self.client.get(EXPORT_PATH, headers=self.auth(self.login("alice")))
        self.assert_error(response, 403, "FORBIDDEN")
        with self.assertRaises(AccessDenied):
            self.store.export_audit(self.alice["id"], 0.0)


class AuditorPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.page = (ROOT / "nasi_lemak/workspace_page.py").read_text(encoding="utf-8")

    def test_every_form_that_changes_something_is_hidden_from_auditors(self) -> None:
        for form in re.findall(r"<form id=\"([a-z-]+)\"([^>]*)>", self.page):
            with self.subTest(form=form[0]):
                if form[0] in ("login-form", "composer-form", "key-edit-form"):
                    continue
                self.assertIn("data-admin-write", form[1])

    def test_users_redraw_when_department_names_arrive(self) -> None:
        loaded = self.page.index("adminDepartmentsLoaded = true;")
        self.assertIn("renderUsers(adminUsers, true)", self.page[loaded:loaded + 300])

    def test_the_access_history_buttons_are_connected(self) -> None:
        self.assertIn('accessRefresh.addEventListener("click"', self.page)
        self.assertIn('auditExport.addEventListener("click"', self.page)


class AuditorMigrationTests(unittest.TestCase):
    def test_schema_files_agree_on_the_new_column(self) -> None:
        schema = (ROOT / "nasi_lemak/workspace_schema.sql").read_text(encoding="utf-8")
        self.assertIn("auditor INTEGER NOT NULL DEFAULT 0", schema)
        self.assertEqual(workspace_store.SCHEMA_VERSION, 7)


if __name__ == "__main__":
    unittest.main()
