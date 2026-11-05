"""Block alerts keep the guard category names behind each block."""

from __future__ import annotations

import unittest

from nasi_lemak.system_settings import DEFAULT_SETTINGS
from tests.test_api_keys import ApiKeyBase


class AlertCategoryTests(ApiKeyBase):
    def latest_alert(self) -> dict:
        return self.store.list_block_alerts(self.admin["id"])["items"][0]

    def admin_headers(self):
        return self.auth(self.login("root.admin"))

    def test_alerts_can_be_found_by_full_or_short_request_id(self) -> None:
        created = self.generate()
        self.adapters.attack_result = {
            "decision": "block",
            "categories": ["Jailbreak"],
        }
        self.assertEqual(self.chat(created["key"]).status_code, 403)
        alert = self.latest_alert()
        request_id = alert["request_id"]
        self.assertRegex(request_id, r"^req_[0-9a-f]{32}$")
        headers = self.admin_headers()
        base = "/workspace/api/admin/alerts"
        for query in (request_id, request_id[4:16], request_id[:16], request_id.upper()):
            with self.subTest(query=query):
                response = self.client.get(
                    f"{base}?request_id={query}", headers=headers
                )
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(
                    [item["id"] for item in response.json()["items"]],
                    [alert["id"]],
                )
        missing = self.client.get(f"{base}?request_id=000000000000", headers=headers)
        self.assertEqual(missing.status_code, 200, missing.text)
        self.assertEqual(missing.json(), {"items": [], "next": None})
        with self.assertRaises(ValueError):
            self.store.list_block_alerts(self.admin["id"], request_id="abc")

    def test_a_request_id_filter_still_ands_with_unread(self) -> None:
        created = self.generate()
        self.adapters.attack_result = {"decision": "block", "categories": ["PII"]}
        self.assertEqual(self.chat(created["key"]).status_code, 403)
        alert = self.latest_alert()
        headers = self.admin_headers()
        marked = self.client.post(
            f"/workspace/api/admin/alerts/{alert['id']}/read",
            json={},
            headers=headers,
        )
        self.assertEqual(marked.status_code, 200, marked.text)
        filtered = self.client.get(
            f"/workspace/api/admin/alerts?request_id={alert['request_id']}&unread=true",
            headers=headers,
        )
        self.assertEqual(filtered.status_code, 200, filtered.text)
        self.assertEqual(filtered.json(), {"items": [], "next": None})

    def test_an_api_key_guard_block_records_its_categories(self) -> None:
        created = self.generate()
        self.adapters.attack_result = {
            "decision": "block",
            "categories": ["Jailbreak", "Violent"],
        }
        self.assertEqual(self.chat(created["key"]).status_code, 403)
        alert = self.latest_alert()
        self.assertEqual(alert["categories"], ["Jailbreak", "Violent"])
        self.assertEqual(alert["api_key_name"], created["item"]["name"])

    def test_a_workspace_chat_block_records_its_categories(self) -> None:
        self.adapters.attack_result = {"decision": "block", "categories": ["PII"]}
        token = self.login("alice")
        conversation = self.new_conversation(token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation}/messages",
            json={"text": "my number is private"},
            headers=self.auth(token),
        )
        self.assertEqual(response.status_code, 403, response.text)
        alert = self.latest_alert()
        self.assertEqual(alert["categories"], ["PII"])
        self.assertEqual(alert["username"], "alice")

    def test_a_deny_phrase_block_has_no_guard_category(self) -> None:
        saved = self.store.save_system_settings(
            self.admin["id"],
            {**DEFAULT_SETTINGS, "deny_phrases": ["hello"]},
            "Test deny phrase",
            expected_revision=0,
        )
        self.app.state.workspace.settings.load(saved["revision"], saved["values"])
        created = self.generate()
        self.assertEqual(self.chat(created["key"]).status_code, 403)
        alert = self.latest_alert()
        self.assertEqual(alert["reason_code"], "INPUT_POLICY_BLOCK")
        self.assertEqual(alert["categories"], [])

    def test_unknown_category_names_are_dropped(self) -> None:
        created = self.generate()
        self.adapters.attack_result = {
            "decision": "block",
            "categories": ["Jailbreak", "<script>", "Made Up"],
        }
        self.chat(created["key"])
        self.assertEqual(self.latest_alert()["categories"], ["Jailbreak"])


if __name__ == "__main__":
    unittest.main()
