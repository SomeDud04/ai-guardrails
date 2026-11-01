"""Named API keys: storage, the guarded pipeline and the admin routes."""

from __future__ import annotations

import hashlib
import sqlite3
import unittest

from nasi_lemak.controls import API_KEY_PREFIX
from nasi_lemak.workspace_store import AccessDenied, Conflict, NotFound
from tests.test_workspace_http import LEGACY_KEY, _ProxyStore, WorkspaceHTTPBase

CHAT_PATH = "/chat"


class ApiKeyBase(WorkspaceHTTPBase):
    def generate(self, name: str = "Ali, laptop") -> dict:
        return self.store.create_api_key(self.admin["id"], name)

    def chat(self, key: str, client=None):
        return (client or self.client).post(
            CHAT_PATH,
            json={"prompt": "hello"},
            headers={"Authorization": f"Bearer {key}"},
        )

    def rows(self, sql: str) -> list[tuple]:
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()


class ApiKeyStoreTests(ApiKeyBase):
    def test_the_key_is_returned_once_and_only_its_digest_is_stored(self) -> None:
        created = self.generate()
        secret = created["key"]
        self.assertTrue(secret.startswith(API_KEY_PREFIX))
        self.assertGreater(len(secret), 40)
        self.assertNotIn(secret, str(created["item"]))
        stored = self.rows("SELECT key_digest, key_hint FROM ws_api_keys")
        self.assertEqual(
            stored, [(hashlib.sha256(secret.encode()).hexdigest(), secret[:8])]
        )
        listed = self.store.list_api_keys(self.admin["id"])["items"][0]
        self.assertNotIn(secret, str(listed))
        self.assertNotIn("key_digest", listed)

    def test_a_name_stays_reserved_after_revoking(self) -> None:
        item = self.generate()["item"]
        with self.assertRaises(Conflict):
            self.generate("ali, LAPTOP")
        self.store.revoke_api_key(self.admin["id"], item["id"])
        with self.assertRaises(Conflict):
            self.generate()

    def test_a_blank_or_long_name_is_refused(self) -> None:
        for name in ("", "   ", "x" * 81, None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.generate(name)

    def test_only_an_administrator_can_manage_keys(self) -> None:
        item = self.generate()["item"]
        with self.assertRaises(AccessDenied):
            self.store.create_api_key(self.alice["id"], "Alice")
        with self.assertRaises(AccessDenied):
            self.store.list_api_keys(self.alice["id"])
        with self.assertRaises(AccessDenied):
            self.store.revoke_api_key(self.alice["id"], item["id"])

    def test_revoking_stops_the_key_and_records_who_did_it(self) -> None:
        created = self.generate()
        digest = hashlib.sha256(created["key"].encode()).hexdigest()
        self.assertEqual(self.store.resolve_api_key(digest)["name"], "Ali, laptop")
        revoked = self.store.revoke_api_key(self.admin["id"], created["item"]["id"])
        self.assertEqual(revoked["revoked_by"], "root.admin")
        self.assertIsNotNone(revoked["revoked_at"])
        self.assertIsNone(self.store.resolve_api_key(digest))

    def test_revoking_twice_or_an_unknown_key_is_refused(self) -> None:
        item = self.generate()["item"]
        self.store.revoke_api_key(self.admin["id"], item["id"])
        with self.assertRaises(Conflict):
            self.store.revoke_api_key(self.admin["id"], item["id"])
        with self.assertRaises(NotFound):
            self.store.revoke_api_key(self.admin["id"], "missing")

    def test_generating_and_revoking_are_in_the_access_log(self) -> None:
        item = self.generate()["item"]
        self.store.revoke_api_key(self.admin["id"], item["id"])
        actions = {
            row["action"]
            for row in self.store.list_access_log(self.admin["id"])["items"]
        }
        self.assertIn(f"admin.create_api_key:{item['id']}", actions)
        self.assertIn(f"admin.revoke_api_key:{item['id']}", actions)

    def test_the_list_counts_uses_and_pages(self) -> None:
        first = self.generate("First")["item"]
        self.generate("Second")
        self.store.record_api_key_use(first["id"], "req_a")
        self.store.record_api_key_use(first["id"], "req_b")
        page = self.store.list_api_keys(self.admin["id"], limit=1)
        self.assertEqual(len(page["items"]), 1)
        self.assertIsNotNone(page["next"])
        rest = self.store.list_api_keys(self.admin["id"], limit=1, after=page["next"])
        counted = {
            item["name"]: (item["requests"], item["last_used_at"] is not None)
            for item in page["items"] + rest["items"]
        }
        self.assertEqual(counted, {"First": (2, True), "Second": (0, False)})


class ApiKeyPipelineTests(ApiKeyBase):
    def test_a_named_key_runs_the_guarded_pipeline(self) -> None:
        secret = self.generate()["key"]
        response = self.chat(secret)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["decision"], "ALLOW")

    def test_the_usage_row_matches_the_audit_row(self) -> None:
        secret = self.generate()["key"]
        self.chat(secret)
        used = {row[0] for row in self.rows("SELECT request_id FROM ws_api_key_uses")}
        audited = {event["request_id"] for event in self.gateway.audit_events()}
        self.assertEqual(len(used), 1)
        self.assertTrue(used <= audited)

    def test_the_shared_key_still_works_and_records_no_use(self) -> None:
        self.generate()
        response = self.chat(LEGACY_KEY)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.rows("SELECT * FROM ws_api_key_uses"), [])

    def test_a_revoked_key_is_refused(self) -> None:
        created = self.generate()
        self.store.revoke_api_key(self.admin["id"], created["item"]["id"])
        self.assertEqual(self.chat(created["key"]).status_code, 401)

    def test_an_unknown_key_is_refused(self) -> None:
        self.assertEqual(self.chat(API_KEY_PREFIX + "unknown").status_code, 401)

    def test_a_value_without_the_prefix_never_reaches_the_store(self) -> None:
        store = _ProxyStore(self.store)

        def fail(_digest: str) -> None:
            raise AssertionError("the store must not be asked")

        store.resolve_api_key = fail
        self.app.state.gateway.api_keys = store
        self.assertEqual(self.chat("not-a-named-key").status_code, 401)

    def test_a_store_failure_stops_named_keys_but_not_the_shared_key(self) -> None:
        secret = self.generate()["key"]
        store = _ProxyStore(self.store)

        def fail(_digest: str) -> None:
            raise OSError("database down")

        store.resolve_api_key = fail
        self.app.state.gateway.api_keys = store
        self.assertEqual(self.chat(secret).status_code, 503)
        self.assertEqual(self.chat(LEGACY_KEY).status_code, 200)

    def test_no_request_reaches_the_model_unattributed(self) -> None:
        secret = self.generate()["key"]
        store = _ProxyStore(self.store)

        def fail(_key_id: str, _request_id: str) -> None:
            raise OSError("database down")

        store.record_api_key_use = fail
        self.app.state.gateway.api_keys = store
        before = self.adapters.generate_calls
        self.assertEqual(self.chat(secret).status_code, 503)
        self.assertEqual(self.adapters.generate_calls, before)

    def test_monitor_shows_the_key_beside_the_request(self) -> None:
        secret = self.generate()["key"]
        self.chat(secret)
        self.chat(LEGACY_KEY)
        recent = self.app.state.gateway.metrics.snapshot()["traffic"]["recent"]
        chats = [row for row in recent if row["route"] == CHAT_PATH]
        self.assertEqual([row["key"] for row in chats], [None, "Ali, laptop"])
        self.assertNotIn(secret, str(recent))


class ApiKeyRouteTests(ApiKeyBase):
    PATH = "/workspace/api/admin/api-keys"

    def test_every_route_is_for_administrators_only(self) -> None:
        item = self.generate()["item"]
        revoke = f"{self.PATH}/{item['id']}/revoke"
        self.assert_error(self.client.get(self.PATH), 401, "UNAUTHORIZED")
        alice = self.auth(self.login())
        self.assert_error(self.client.get(self.PATH, headers=alice), 403, "FORBIDDEN")
        self.assert_error(
            self.client.post(self.PATH, json={"name": "x"}, headers=alice),
            403,
            "FORBIDDEN",
        )
        self.assert_error(self.client.post(revoke, headers=alice), 403, "FORBIDDEN")

    def test_generate_list_and_revoke(self) -> None:
        admin = self.auth(self.login("root.admin"))
        created = self.client.post(self.PATH, json={"name": "Harness"}, headers=admin)
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        self.assertEqual(self.chat(body["key"]).status_code, 200)

        listed = self.client.get(self.PATH, headers=admin)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertNotIn(body["key"], listed.text)
        self.assertEqual(listed.json()["items"][0]["requests"], 1)

        revoked = self.client.post(
            f"{self.PATH}/{body['item']['id']}/revoke", headers=admin
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertEqual(self.chat(body["key"]).status_code, 401)

    def test_a_duplicate_name_or_extra_field_is_refused(self) -> None:
        admin = self.auth(self.login("root.admin"))
        self.generate("Taken")
        self.assert_error(
            self.client.post(self.PATH, json={"name": "Taken"}, headers=admin),
            409,
            "CONFLICT",
        )
        self.assert_error(
            self.client.post(self.PATH, json={"name": "x", "key": "y"}, headers=admin),
            400,
            "INVALID_REQUEST",
        )

    def test_a_cookie_session_cannot_be_used_from_another_origin(self) -> None:
        self.login("root.admin")
        response = self.client.post(
            self.PATH,
            json={"name": "Forged"},
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(response.status_code, 403, response.text)

    def test_a_new_key_is_not_cached(self) -> None:
        admin = self.auth(self.login("root.admin"))
        created = self.client.post(self.PATH, json={"name": "Harness"}, headers=admin)
        self.assertIn("no-store", created.headers.get("cache-control", ""))


if __name__ == "__main__":
    unittest.main()
