"""API key history keeps the figures Monitor shows for each request."""

from __future__ import annotations

import unittest

from nasi_lemak.system_settings import DEFAULT_SETTINGS
from tests.test_api_keys import ApiKeyBase


class KeyHistoryFigureTests(ApiKeyBase):
    def history(self, key_id: str) -> list[dict]:
        return self.store.list_api_key_requests(self.admin["id"], key_id)["items"]

    def test_an_allowed_request_records_its_total_time(self) -> None:
        created = self.generate()
        self.assertEqual(self.chat(created["key"]).status_code, 200)
        item = self.history(created["item"]["id"])[0]
        self.assertEqual(item["outcome"], "allowed")
        self.assertIsInstance(item["total_ms"], int)
        self.assertIsNone(item["block_source"])
        self.assertEqual(item["block_categories"], [])

    def test_a_guard_block_records_its_category(self) -> None:
        created = self.generate()
        self.adapters.attack_result = {"decision": "block", "categories": ["Jailbreak"]}
        self.assertEqual(self.chat(created["key"]).status_code, 403)
        item = self.history(created["item"]["id"])[0]
        self.assertEqual(item["block_source"], "guard")
        self.assertEqual(item["block_categories"], ["Jailbreak"])

    def test_a_deny_phrase_block_says_so(self) -> None:
        saved = self.store.save_system_settings(
            self.admin["id"],
            {**DEFAULT_SETTINGS, "deny_phrases": ["hello"]},
            "Test deny phrase",
            expected_revision=0,
        )
        self.app.state.workspace.settings.load(saved["revision"], saved["values"])
        created = self.generate()
        self.assertEqual(self.chat(created["key"]).status_code, 403)
        item = self.history(created["item"]["id"])[0]
        self.assertEqual(item["block_source"], "deny_phrase_input")
        self.assertEqual(item["block_categories"], [])

    def test_history_and_monitor_show_the_same_total(self) -> None:
        created = self.generate()
        self.chat(created["key"])
        item = self.history(created["item"]["id"])[0]
        recent = self.gateway.metrics.snapshot()["recent"][0]
        self.assertEqual(item["total_ms"], recent["total_ms"])

    def test_only_known_values_are_stored(self) -> None:
        created = self.generate()
        key = self.store.resolve_api_key(
            __import__("hashlib").sha256(created["key"].encode()).hexdigest()
        )
        self.store.record_api_key_use(key["id"], "req_figures", "10.0.0.1")
        self.store.record_api_key_result(
            key,
            "req_figures",
            outcome="blocked",
            figures={
                "reply_tokens": 100,
                "generation_ms": 2000,
                "total_ms": 3000,
                "block_source": "made-up source",
                "block_categories": ["Jailbreak", "<script>", 42],
                "allowed_categories": "PII",
            },
        )
        item = self.history(key["id"])[0]
        self.assertEqual(item["reply_tokens"], 100)
        self.assertEqual(item["tokens_per_second"], 50.0)
        self.assertEqual(item["total_ms"], 3000)
        self.assertIsNone(item["block_source"])
        self.assertEqual(item["block_categories"], ["Jailbreak"])
        self.assertEqual(item["allowed_categories"], [])

    def test_a_row_from_before_schema_8_reads_as_empty(self) -> None:
        created = self.generate()
        key = self.store.resolve_api_key(
            __import__("hashlib").sha256(created["key"].encode()).hexdigest()
        )
        self.store.record_api_key_use(key["id"], "req_old", "10.0.0.1")
        self.store.record_api_key_result(key, "req_old", outcome="allowed")
        item = self.history(key["id"])[0]
        self.assertIsNone(item["reply_tokens"])
        self.assertIsNone(item["tokens_per_second"])
        self.assertIsNone(item["total_ms"])

    def test_the_csv_export_carries_the_same_figures(self) -> None:
        import csv
        import io

        created = self.generate()
        self.adapters.attack_result = {"decision": "block", "categories": ["Jailbreak"]}
        self.chat(created["key"])
        headers = self.auth(self.login("root.admin"))
        response = self.client.get(
            f"/workspace/api/admin/api-keys/{created['item']['id']}/requests.csv",
            headers=headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        row = list(csv.DictReader(io.StringIO(response.text)))[0]
        self.assertEqual(row["stopped_by"], "Jailbreak")
        self.assertTrue(row["total_ms"].isdigit())


if __name__ == "__main__":
    unittest.main()
