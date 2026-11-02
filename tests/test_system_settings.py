"""Saved settings tighten the deployment and leave an audit trail."""

from __future__ import annotations

import unittest

from nasi_lemak.system_settings import (
    DEFAULT_SETTINGS,
    RuntimeSettings,
    SettingsError,
    validate_reason,
    validate_settings,
)
from nasi_lemak.workspace_store import Conflict
from tests.test_api_keys import ApiKeyBase
from tests.test_workspace_http import LEGACY_KEY

CEILINGS = {
    "context_messages": 32,
    "context_budget": 3000,
    "default_reply_tokens": 384,
    "max_reply_tokens": 512,
}


def check(**changes):
    return validate_settings(
        {**DEFAULT_SETTINGS, **changes},
        limit_ceilings=CEILINGS,
        input_allow=("privacy",),
        output_allow=(),
        concurrency_ceiling=2,
        chat_timeout_ceiling=60.0,
    )


class ValidationTests(unittest.TestCase):
    def test_defaults_are_valid(self) -> None:
        self.assertEqual(check(), DEFAULT_SETTINGS)

    def test_nothing_can_pass_the_deployment_limits(self) -> None:
        for changes in (
            {"chat_limits": {"context_budget": 3001}},
            {"chat_limits": {"default_reply_tokens": 500, "max_reply_tokens": 400}},
            {"chat_limits": {"unknown": 1}},
            {"input_allow_categories": ["jailbreak"]},
            {"output_allow_categories": ["privacy"]},
            {"max_concurrency": 3},
            {"chat_timeout_seconds": 61},
            {"session_hours": 25},
            {"login_max_attempts": 2},
            {"retention_days": 0},
            {"key_requests_per_minute": 601},
        ):
            with self.subTest(changes=changes), self.assertRaises(SettingsError):
                check(**changes)

    def test_a_setting_can_narrow_what_the_file_allows(self) -> None:
        self.assertEqual(check(input_allow_categories=[])["input_allow_categories"], [])

    def test_an_unknown_field_is_refused(self) -> None:
        with self.assertRaises(SettingsError):
            validate_settings(
                {**DEFAULT_SETTINGS, "guards_active": False},
                limit_ceilings=CEILINGS,
                input_allow=(),
                output_allow=(),
                concurrency_ceiling=1,
                chat_timeout_ceiling=60.0,
            )

    def test_guards_are_not_settings(self) -> None:
        for name in ("mode", "guards_active", "framing_version", "model"):
            self.assertNotIn(name, DEFAULT_SETTINGS)

    def test_deny_phrases_are_trimmed_and_deduplicated(self) -> None:
        self.assertEqual(
            check(deny_phrases=[" secret ", "secret"])["deny_phrases"], ["secret"]
        )
        with self.assertRaises(SettingsError):
            check(deny_phrases=["line\nbreak"])

    def test_a_reason_is_required(self) -> None:
        self.assertEqual(validate_reason("  tighten limits "), "tighten limits")
        for value in ("", "  ", None, "ab"):
            with self.subTest(value=value), self.assertRaises(SettingsError):
                validate_reason(value)

    def test_policy_identity_changes_with_each_revision(self) -> None:
        settings = RuntimeSettings()
        self.assertEqual(settings.effective_policy("v1", "d"), ("v1", "d"))
        settings.load(3, check(session_hours=4))
        version, digest = settings.effective_policy("v1", "d")
        self.assertEqual(version, "v1+settings.3")
        self.assertNotEqual(digest, "d")


class EnforcementTests(ApiKeyBase):
    def save(self, **changes) -> None:
        current = self.store.current_system_settings()
        values = check(**{**(current["values"] or {}), **changes})
        saved = self.store.save_system_settings(
            self.admin["id"], values, "test change", expected_revision=current["revision"]
        )
        self.app.state.workspace.settings.load(saved["revision"], saved["values"])

    def test_pausing_stops_every_route_without_reaching_the_model(self) -> None:
        created = self.generate()
        before = self.adapters.generate_calls
        self.save(paused=True)
        self.assertEqual(self.chat(LEGACY_KEY).status_code, 503)
        self.assertEqual(self.chat(created["key"]).status_code, 503)
        self.assertEqual(self.adapters.generate_calls, before)
        self.save(paused=False)
        self.assertEqual(self.chat(LEGACY_KEY).status_code, 200)

    def test_pausing_also_stops_workspace_chat_but_not_admin(self) -> None:
        token = self.login("root.admin")
        conversation = self.new_conversation(token)
        self.save(paused=True)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation}/messages",
            json={"text": "hello"},
            headers=self.auth(token),
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(self.adapters.generate_calls, 0)
        self.assertEqual(
            self.client.get("/workspace/api/admin/live", headers=self.auth(token)).status_code,
            200,
        )

    def test_turning_off_the_shared_key_leaves_named_keys_working(self) -> None:
        created = self.generate()
        self.save(shared_key_enabled=False)
        self.assertEqual(self.chat(LEGACY_KEY).status_code, 401)
        self.assertEqual(self.chat(created["key"]).status_code, 200)

    def test_turning_off_the_shared_key_leaves_workspace_chat_working(self) -> None:
        self.save(shared_key_enabled=False)
        token = self.login("root.admin")
        conversation = self.new_conversation(token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation}/messages",
            json={"text": "hello"},
            headers=self.auth(token),
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_added_deny_phrases_block_on_top_of_the_file(self) -> None:
        self.save(deny_phrases=["hello"])
        response = self.chat(LEGACY_KEY)
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(response.json()["decision"], "BLOCK")

    def test_saved_limits_tighten_requests(self) -> None:
        self.save(chat_limits={"context_budget": 8})
        self.assert_error(self.chat(LEGACY_KEY), 413, "INPUT_LIMIT")

    def test_the_default_rate_limit_applies_to_keys_without_their_own(self) -> None:
        created = self.generate()
        self.save(key_requests_per_minute=1)
        self.assertEqual(self.chat(created["key"]).status_code, 200)
        self.assert_error(self.chat(created["key"]), 429, "RATE_LIMITED")

    def test_audit_rows_name_the_settings_revision(self) -> None:
        self.save(session_hours=4)
        self.chat(LEGACY_KEY)
        versions = {event["policy_version"] for event in self.gateway.audit_events()}
        self.assertEqual(len(versions), 1)
        self.assertTrue(versions.pop().endswith("+settings.1"))

    def test_a_stale_form_is_refused(self) -> None:
        self.save(session_hours=4)
        with self.assertRaises(Conflict):
            self.store.save_system_settings(
                self.admin["id"], check(), "stale form", expected_revision=0
            )

    def test_history_records_who_and_why(self) -> None:
        self.save(session_hours=4)
        item = self.store.list_system_settings(self.admin["id"])["items"][0]
        self.assertEqual(item["actor_username"], "root.admin")
        self.assertEqual(item["reason"], "test change")
        self.assertEqual(item["values"]["session_hours"], 4)
        self.assertIn(
            "admin.save_settings:1",
            [row["action"] for row in self.store.list_access_log(self.admin["id"])["items"]],
        )

    def test_saved_settings_load_after_a_restart(self) -> None:
        self.save(paused=True)
        restarted = self.make_app()
        self.assertTrue(restarted.state.workspace.settings.snapshot()[1]["paused"])


if __name__ == "__main__":
    unittest.main()
