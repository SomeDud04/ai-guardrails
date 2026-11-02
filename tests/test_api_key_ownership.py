"""A key belongs to a user: their policy, status, alerts and history apply."""

from __future__ import annotations

import time
import unittest

from nasi_lemak.workspace_store import Conflict, NotFound
from tests.test_api_keys import ApiKeyBase
from tests.test_workspace_http import _ProxyStore


class OwnershipTests(ApiKeyBase):
    def owned(self, **options) -> dict:
        return self.store.create_api_key(
            self.admin["id"], "Alice laptop", self.alice["id"], **options
        )

    def test_a_key_names_its_owner_and_department(self) -> None:
        item = self.owned()["item"]
        self.assertEqual(item["owner_username"], "alice")
        self.assertEqual(item["owner_full_name"], "Alice Tan")
        self.assertEqual(item["owner_department"], "Accounting")
        self.assertEqual(item["status"], "active")

    def test_a_disabled_or_unknown_owner_is_refused(self) -> None:
        self.store.disable_user(self.admin["id"], self.alice["id"])
        with self.assertRaises(ValueError):
            self.owned()
        with self.assertRaises(ValueError):
            self.store.create_api_key(self.admin["id"], "Nobody", "missing")

    def test_disabling_the_owner_stops_the_key_until_re_enabled(self) -> None:
        created = self.owned()
        self.assertEqual(self.chat(created["key"]).status_code, 200)
        self.store.disable_user(self.admin["id"], self.alice["id"])
        self.assertEqual(self.chat(created["key"]).status_code, 401)
        listed = self.store.list_api_keys(self.admin["id"])["items"][0]
        self.assertEqual(listed["status"], "owner_disabled")
        self.store.enable_user(self.admin["id"], self.alice["id"])
        self.assertEqual(self.chat(created["key"]).status_code, 200)

    def test_deleting_the_owner_revokes_the_key_and_keeps_its_record(self) -> None:
        created = self.owned()
        self.chat(created["key"])
        self.store.delete_user(self.admin["id"], self.alice["id"], "alice")
        self.assertEqual(self.chat(created["key"]).status_code, 401)
        listed = self.store.list_api_keys(self.admin["id"])["items"][0]
        self.assertEqual(listed["status"], "revoked")
        self.assertEqual(listed["requests"], 1)

    def test_a_key_can_be_handed_to_another_owner(self) -> None:
        item = self.owned()["item"]
        updated = self.store.update_api_key(
            self.admin["id"],
            item["id"],
            owner_id=self.bob["id"],
            expires_at=None,
            store_text=False,
            allowed_ips=[],
            requests_per_minute=None,
        )
        self.assertEqual(updated["owner_username"], "bob")
        actions = [
            row["action"]
            for row in self.store.list_access_log(self.admin["id"])["items"]
        ]
        self.assertIn(f"admin.update_api_key:{item['id']}", actions)

    def test_a_revoked_key_cannot_be_changed(self) -> None:
        item = self.owned()["item"]
        self.store.revoke_api_key(self.admin["id"], item["id"])
        with self.assertRaises(Conflict):
            self.store.update_api_key(
                self.admin["id"],
                item["id"],
                owner_id=self.bob["id"],
                expires_at=None,
                store_text=False,
                allowed_ips=[],
                requests_per_minute=None,
            )


class KeyLimitTests(ApiKeyBase):
    def test_an_expired_key_is_refused(self) -> None:
        created = self.store.create_api_key(
            self.admin["id"], "Short", self.alice["id"], expires_at=time.time() + 3600
        )
        self.assertEqual(self.chat(created["key"]).status_code, 200)
        self.store._clock = lambda: time.time() + 7200
        self.assertEqual(self.chat(created["key"]).status_code, 401)
        listed = self.store.list_api_keys(self.admin["id"])["items"][0]
        self.assertEqual(listed["status"], "expired")

    def test_an_expiry_in_the_past_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.store.create_api_key(
                self.admin["id"], "Old", self.alice["id"], expires_at=1.0
            )

    def test_an_address_outside_the_allowlist_is_refused(self) -> None:
        outside = self.store.create_api_key(
            self.admin["id"], "Outside", self.alice["id"], allowed_ips=["10.1.2.0/24"]
        )
        self.assertEqual(self.chat(outside["key"]).status_code, 401)

    def test_an_address_inside_the_allowlist_is_accepted(self) -> None:
        created = self.store.create_api_key(
            self.admin["id"], "Lan", self.alice["id"], allowed_ips=["192.168.90.0/24"]
        )
        app = self.make_app(environ=self.env(NASI_LEMAK_TRUST_PROXY_CLIENT_IP="true"))
        client = self.make_client(app)
        response = client.post(
            "/chat",
            json={"prompt": "hello"},
            headers={
                "Authorization": f"Bearer {created['key']}",
                "X-Real-IP": "192.168.90.50",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_a_bad_allowlist_entry_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.store.create_api_key(
                self.admin["id"], "Bad", self.alice["id"], allowed_ips=["not-an-ip"]
            )

    def test_the_rate_limit_applies_per_key(self) -> None:
        limited = self.store.create_api_key(
            self.admin["id"], "Limited", self.alice["id"], requests_per_minute=1
        )
        other = self.store.create_api_key(self.admin["id"], "Other", self.alice["id"])
        self.assertEqual(self.chat(limited["key"]).status_code, 200)
        before = self.adapters.generate_calls
        response = self.chat(limited["key"])
        self.assert_error(response, 429, "RATE_LIMITED")
        self.assertEqual(self.adapters.generate_calls, before)
        self.assertEqual(self.chat(other["key"]).status_code, 200)


class PolicyAndAlertTests(ApiKeyBase):
    def assign(self, user_id: str, **settings) -> None:
        profile = self.store.create_policy_profile(self.admin["id"], "Key rules", **settings)
        self.store.assign_policy_profile(
            self.admin["id"], "user", user_id, profile["id"]
        )

    def test_a_key_follows_its_owners_policy(self) -> None:
        created = self.store.create_api_key(self.admin["id"], "Owned", self.alice["id"])
        self.chat(created["key"])
        scanned = len(self.adapters.attack_inputs)
        self.assign(self.alice["id"], input_check_enabled=False)
        self.chat(created["key"])
        self.assertEqual(len(self.adapters.attack_inputs), scanned)

    def test_the_owners_limits_tighten_the_key(self) -> None:
        created = self.store.create_api_key(self.admin["id"], "Owned", self.alice["id"])
        self.assign(self.alice["id"], limits={"context_budget": 8})
        self.assert_error(self.chat(created["key"]), 413, "INPUT_LIMIT")

    def test_a_policy_failure_is_never_permissive(self) -> None:
        created = self.store.create_api_key(self.admin["id"], "Owned", self.alice["id"])
        store = _ProxyStore(self.store)

        def fail(_owner: str) -> None:
            raise OSError("database down")

        store.resolve_gateway_control = fail
        self.app.state.gateway.api_keys = store
        before = self.adapters.generate_calls
        self.assertEqual(self.chat(created["key"]).status_code, 503)
        self.assertEqual(self.adapters.generate_calls, before)

    def test_a_block_raises_an_alert_naming_the_key_and_owner(self) -> None:
        created = self.store.create_api_key(self.admin["id"], "Owned", self.alice["id"])
        self.adapters.attack_result = {"decision": "block"}
        self.assertEqual(self.chat(created["key"]).status_code, 403)
        alert = self.store.list_block_alerts(self.admin["id"])["items"][0]
        self.assertEqual(alert["api_key_name"], "Owned")
        self.assertEqual(alert["username"], "alice")
        self.assertIsNone(alert["conversation_id"])
        fetched = self.store.get_block_alert(self.admin["id"], alert["id"])
        self.assertEqual(fetched["api_key_name"], "Owned")

    def test_each_request_shows_its_ip_and_outcome(self) -> None:
        created = self.store.create_api_key(self.admin["id"], "Owned", self.alice["id"])
        self.chat(created["key"])
        self.adapters.attack_result = {"decision": "block"}
        self.chat(created["key"])
        rows = self.store.list_api_key_requests(
            self.admin["id"], created["item"]["id"]
        )["items"]
        self.assertEqual(
            sorted(row["outcome"] for row in rows), ["allowed", "blocked"]
        )
        self.assertEqual({row["client_ip"] for row in rows}, {"testclient"})
        self.assertFalse(any(row["has_text"] for row in rows))


class StoredTextTests(ApiKeyBase):
    def test_no_text_is_stored_by_default(self) -> None:
        created = self.store.create_api_key(self.admin["id"], "Plain", self.alice["id"])
        self.chat(created["key"])
        self.assertEqual(self.rows("SELECT * FROM ws_api_key_text"), [])

    def test_a_key_can_keep_encrypted_text_and_each_read_is_logged(self) -> None:
        created = self.store.create_api_key(
            self.admin["id"], "Reviewed", self.alice["id"], store_text=True
        )
        self.chat(created["key"])
        key_id = created["item"]["id"]
        stored = self.rows("SELECT prompt_ciphertext, reply_ciphertext FROM ws_api_key_text")
        self.assertEqual(len(stored), 1)
        self.assertNotIn("hello", stored[0][0])
        row = self.store.list_api_key_requests(self.admin["id"], key_id)["items"][0]
        self.assertTrue(row["has_text"])
        text = self.store.read_api_key_text(self.admin["id"], key_id, row["request_id"])
        self.assertIn("hello", text["prompt"])
        self.assertEqual(text["reply"], self.adapters.generated)
        actions = [
            entry["action"]
            for entry in self.store.list_access_log(self.admin["id"])["items"]
        ]
        self.assertIn(f"admin.read_api_key_text:{key_id}", actions)

    def test_a_blocked_prompt_is_kept_with_no_reply(self) -> None:
        created = self.store.create_api_key(
            self.admin["id"], "Reviewed", self.alice["id"], store_text=True
        )
        self.adapters.attack_result = {"decision": "block"}
        self.chat(created["key"])
        key_id = created["item"]["id"]
        row = self.store.list_api_key_requests(self.admin["id"], key_id)["items"][0]
        text = self.store.read_api_key_text(self.admin["id"], key_id, row["request_id"])
        self.assertIn("hello", text["prompt"])
        self.assertIsNone(text["reply"])

    def test_a_reply_that_cannot_be_stored_is_withheld(self) -> None:
        created = self.store.create_api_key(
            self.admin["id"], "Reviewed", self.alice["id"], store_text=True
        )
        store = _ProxyStore(self.store)

        def fail(*_args, **_kwargs) -> None:
            raise OSError("database down")

        store.record_api_key_result = fail
        self.app.state.gateway.api_keys = store
        self.assertEqual(self.chat(created["key"]).status_code, 503)

    def test_a_result_that_cannot_be_recorded_does_not_stop_a_plain_key(self) -> None:
        created = self.store.create_api_key(self.admin["id"], "Plain", self.alice["id"])
        store = _ProxyStore(self.store)

        def fail(*_args, **_kwargs) -> None:
            raise OSError("database down")

        store.record_api_key_result = fail
        self.app.state.gateway.api_keys = store
        self.assertEqual(self.chat(created["key"]).status_code, 200)

    def test_reading_text_of_another_key_is_refused(self) -> None:
        first = self.store.create_api_key(
            self.admin["id"], "First", self.alice["id"], store_text=True
        )
        second = self.store.create_api_key(self.admin["id"], "Second", self.alice["id"])
        self.chat(first["key"])
        row = self.store.list_api_key_requests(
            self.admin["id"], first["item"]["id"]
        )["items"][0]
        with self.assertRaises(NotFound):
            self.store.read_api_key_text(
                self.admin["id"], second["item"]["id"], row["request_id"]
            )


if __name__ == "__main__":
    unittest.main()
