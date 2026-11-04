"""Block alerts keep the guard category names behind each block."""

from __future__ import annotations

import unittest

from nasi_lemak.system_settings import DEFAULT_SETTINGS
from tests.test_api_keys import ApiKeyBase


class AlertCategoryTests(ApiKeyBase):
    def latest_alert(self) -> dict:
        return self.store.list_block_alerts(self.admin["id"])["items"][0]

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
