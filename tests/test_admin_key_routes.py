"""Administrator routes for key ownership, key history and system settings."""

from __future__ import annotations

import csv
import hashlib
import io
import unittest

from nasi_lemak.system_settings import DEFAULT_SETTINGS
from tests.test_api_keys import ApiKeyBase
from tests.test_workspace_http import LEGACY_KEY

KEYS_PATH = "/workspace/api/admin/api-keys"
SETTINGS_PATH = "/workspace/api/admin/system-settings"


class AdminRouteTests(ApiKeyBase):
    def admin_headers(self):
        return self.auth(self.login("root.admin"))

    def values(self, **changes):
        return {**DEFAULT_SETTINGS, **changes}

    def test_every_route_is_administrator_only(self) -> None:
        item = self.generate()["item"]
        key_id = item["id"]
        routes = [
            ("get", KEYS_PATH),
            ("post", KEYS_PATH),
            ("post", f"{KEYS_PATH}/{key_id}"),
            ("post", f"{KEYS_PATH}/{key_id}/revoke"),
            ("get", f"{KEYS_PATH}/{key_id}/requests"),
            ("get", f"{KEYS_PATH}/{key_id}/requests.csv"),
            ("get", f"{KEYS_PATH}/{key_id}/requests/req/text"),
            ("get", SETTINGS_PATH),
            ("post", SETTINGS_PATH),
            ("post", f"{SETTINGS_PATH}/rollback"),
        ]
        for method, path in routes:
            with self.subTest(route=path, method=method):
                call = getattr(self.client, method)
                response = call(path) if method == "get" else call(path, json={})
                self.assert_error(response, 401, "UNAUTHORIZED")
        employee = self.auth(self.login())
        for method, path in routes:
            with self.subTest(route=path, method=method, role="employee"):
                call = getattr(self.client, method)
                headers = employee
                response = (
                    call(path, headers=headers)
                    if method == "get"
                    else call(path, json={}, headers=headers)
                )
                self.assert_error(response, 403, "FORBIDDEN")

    def test_a_cookie_session_cannot_post_from_another_origin(self) -> None:
        self.login("root.admin")
        response = self.client.post(
            SETTINGS_PATH,
            json={
                "values": self.values(),
                "reason": "forged",
                "expected_revision": 0,
            },
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(response.status_code, 403, response.text)

    def test_creating_and_updating_a_key_accepts_the_options(self) -> None:
        admin = self.admin_headers()
        created = self.client.post(
            KEYS_PATH,
            json={
                "name": "Owned",
                "owner_id": self.alice["id"],
                "store_text": True,
                "allowed_ips": ["10.0.0.0/8"],
                "requests_per_minute": 5,
            },
            headers=admin,
        )
        self.assertEqual(created.status_code, 201, created.text)
        item = created.json()["item"]
        self.assertEqual(item["owner_username"], "alice")
        self.assertTrue(item["store_text"])
        self.assertEqual(item["allowed_ips"], ["10.0.0.0/8"])
        self.assertEqual(item["requests_per_minute"], 5)

        updated = self.client.post(
            f"{KEYS_PATH}/{item['id']}",
            json={
                "owner_id": self.bob["id"],
                "expires_at": None,
                "store_text": False,
                "allowed_ips": [],
                "requests_per_minute": None,
            },
            headers=admin,
        )
        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["owner_username"], "bob")
        self.assertFalse(updated.json()["store_text"])

        missing = self.client.post(
            f"{KEYS_PATH}/{item['id']}",
            json={"owner_id": self.bob["id"]},
            headers=admin,
        )
        self.assert_error(missing, 400, "INVALID_REQUEST")

    def test_the_csv_has_a_header_and_neutralises_formulas(self) -> None:
        admin = self.admin_headers()
        secret = self.generate()["key"]
        key = self.store.resolve_api_key(hashlib.sha256(secret.encode()).hexdigest())
        self.store.record_api_key_use(key["id"], "=request", client_ip="+1")
        self.store.record_api_key_result(
            key,
            "=request",
            outcome="allowed",
            error_code="=err",
        )
        for index in range(104):
            self.store.record_api_key_use(key["id"], f"req_{index:03d}")

        first = self.client.get(
            f"{KEYS_PATH}/{key['id']}/requests?limit=1", headers=admin
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(len(first.json()["items"]), 1)
        self.assertIsNotNone(first.json()["next"])

        response = self.client.get(f"{KEYS_PATH}/{key['id']}/requests.csv", headers=admin)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["content-type"].split(";")[0], "text/csv")
        self.assertEqual(
            response.headers["content-disposition"],
            'attachment; filename="api-key-requests.csv"',
        )
        self.assertIn("no-store", response.headers.get("cache-control", ""))
        rows = list(csv.reader(io.StringIO(response.text)))
        self.assertEqual(
            rows[0],
            [
                "time", "request_id", "client_ip", "outcome", "error_code",
                "reply_tokens", "tokens_per_second", "total_ms", "stopped_by",
            ],
        )
        self.assertEqual(len(rows), 106)
        formula = next(row for row in rows[1:] if row[1] == "'=request")
        self.assertEqual(formula[2:5], ["'+1", "allowed", "'=err"])
        self.assertTrue(formula[0].endswith("+00:00"))
        self.assertEqual(len({row[1] for row in rows[1:]}), 105)

    def test_reading_stored_text_is_in_the_access_log(self) -> None:
        created = self.store.create_api_key(
            self.admin["id"], "Reviewed", self.alice["id"], store_text=True
        )
        self.assertEqual(self.chat(created["key"]).status_code, 200)
        key_id = created["item"]["id"]
        request_id = self.store.list_api_key_requests(
            self.admin["id"], key_id
        )["items"][0]["request_id"]

        response = self.client.get(
            f"{KEYS_PATH}/{key_id}/requests/{request_id}/text",
            headers=self.admin_headers(),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn("hello", response.json()["prompt"])
        actions = [
            item["action"]
            for item in self.store.list_access_log(self.admin["id"])["items"]
        ]
        self.assertIn(f"admin.read_api_key_text:{key_id}", actions)

    def test_settings_read_never_returns_a_key_or_digest(self) -> None:
        created = self.generate()
        response = self.client.get(SETTINGS_PATH, headers=self.admin_headers())
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(set(body), {"revision", "values", "ceilings", "history"})
        self.assertEqual(body["revision"], 0)
        self.assertEqual(body["values"], DEFAULT_SETTINGS)
        self.assertEqual(body["ceilings"], self.app.state.settings_ceilings)
        self.assertNotIn(created["key"], response.text)
        self.assertNotIn("key_digest", response.text)

    def test_saving_settings_takes_effect_immediately(self) -> None:
        admin = self.admin_headers()
        saved = self.client.post(
            SETTINGS_PATH,
            json={
                "values": self.values(paused=True),
                "reason": "maintenance",
                "expected_revision": 0,
            },
            headers=admin,
        )
        self.assertEqual(saved.status_code, 200, saved.text)
        self.assertEqual(saved.json()["revision"], 1)
        self.assertEqual(self.chat(LEGACY_KEY).status_code, 503)

        current = self.client.get(SETTINGS_PATH, headers=admin)
        self.assertEqual(current.json()["revision"], 1)
        self.assertTrue(current.json()["values"]["paused"])
        self.assertEqual(current.json()["history"][0]["reason"], "maintenance")

    def test_a_value_above_the_ceiling_is_refused_without_a_revision(self) -> None:
        ceilings = self.app.state.settings_ceilings
        response = self.client.post(
            SETTINGS_PATH,
            json={
                "values": self.values(
                    chat_timeout_seconds=ceilings["chat_timeout_seconds"] + 1
                ),
                "reason": "too loose",
                "expected_revision": 0,
            },
            headers=self.admin_headers(),
        )
        self.assert_error(response, 400, "INVALID_REQUEST")
        self.assertEqual(self.store.current_system_settings()["revision"], 0)

    def test_a_stale_expected_revision_is_a_conflict(self) -> None:
        admin = self.admin_headers()
        body = {
            "values": self.values(session_hours=4),
            "reason": "tighten",
            "expected_revision": 0,
        }
        self.assertEqual(
            self.client.post(SETTINGS_PATH, json=body, headers=admin).status_code, 200
        )
        self.assert_error(
            self.client.post(SETTINGS_PATH, json=body, headers=admin),
            409,
            "CONFLICT",
        )

    def test_rollback_appends_the_old_values_as_a_new_revision(self) -> None:
        admin = self.admin_headers()

        def save(values, expected):
            response = self.client.post(
                SETTINGS_PATH,
                json={
                    "values": values,
                    "reason": "change",
                    "expected_revision": expected,
                },
                headers=admin,
            )
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        save(self.values(session_hours=4), 0)
        save(self.values(session_hours=6), 1)
        rolled = self.client.post(
            f"{SETTINGS_PATH}/rollback",
            json={"revision": 1, "reason": "undo", "expected_revision": 2},
            headers=admin,
        )
        self.assertEqual(rolled.status_code, 200, rolled.text)
        self.assertEqual(rolled.json()["revision"], 3)
        self.assertEqual(rolled.json()["values"]["session_hours"], 4)
        self.assertEqual(
            self.app.state.workspace.settings.snapshot()[1]["session_hours"], 4
        )

        missing = self.client.post(
            f"{SETTINGS_PATH}/rollback",
            json={"revision": 99, "reason": "undo", "expected_revision": 3},
            headers=admin,
        )
        self.assert_error(missing, 404, "INVALID_REQUEST")


if __name__ == "__main__":
    unittest.main()
