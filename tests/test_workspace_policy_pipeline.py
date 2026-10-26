"""Focused HTTP coverage for per-turn policy controls and block alerts.

These tests use the real FastAPI workspace application, a temporary SQLite
store and synthetic in-process adapters.  No external provider, guard, database
or network service is contacted.
"""

from __future__ import annotations

from typing import Any

from nasi_lemak.controls import block_detail
from nasi_lemak.workspace_store import WorkspaceStorageError
from tests.test_workspace_http import WorkspaceHTTPBase, _ProxyStore


class PolicyPipelineTests(WorkspaceHTTPBase):
    def _profile(self, admin_token: str, name: str, **fields: Any) -> dict:
        response = self.client.post(
            "/workspace/api/admin/policy/profiles",
            json={"name": name, **fields},
            headers=self.auth(admin_token),
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def _assign(self, admin_token: str, profile_id: str) -> dict:
        response = self.client.post(
            "/workspace/api/admin/policy/assignments",
            json={
                "scope_type": "user",
                "scope_id": self.alice["id"],
                "profile_id": profile_id,
            },
            headers=self.auth(admin_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def _alerts(self, admin_token: str) -> list[dict]:
        response = self.client.get(
            "/workspace/api/admin/alerts", headers=self.auth(admin_token)
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["items"]

    def test_assignment_changes_next_turn_masks_and_self_policy(self) -> None:
        alice_token = self.login()
        conversation_id = self.new_conversation(alice_token)
        prompt = "first@example.com 0123456789 900101123456"
        first = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": prompt},
            headers=self.auth(alice_token),
        )
        self.assertEqual(first.status_code, 200, first.text)
        first_input = self.adapters.generate_inputs[-1][-1]["content"]
        for masked in ("[EMAIL]", "[MY_PHONE]", "[MYKAD]"):
            self.assertIn(masked, first_input)

        admin_token = self.login("root.admin")
        profile = self._profile(
            admin_token,
            "Email only",
            input_masks=["EMAIL"],
            output_masks=["EMAIL"],
        )
        assignment = self._assign(admin_token, profile["id"])
        self.assertEqual(assignment["scope_type"], "user")
        self.assertEqual(assignment["settings"]["input_masks"], ["EMAIL"])

        policy = self.client.get(
            "/workspace/api/policy", headers=self.auth(alice_token)
        )
        self.assertEqual(policy.status_code, 200, policy.text)
        self.assertEqual(policy.json()["user_id"], self.alice["id"])
        self.assertEqual(policy.json()["input_masks"], ["EMAIL"])
        # The self-only endpoint never accepts a caller-selected principal.
        rejected = self.client.get(
            "/workspace/api/policy",
            params={"user_id": self.bob["id"]},
            headers=self.auth(alice_token),
        )
        self.assert_error(rejected, 400, "INVALID_REQUEST")

        self.adapters.generated = "reply second@example.com 0123456789 900101123456"
        second = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "mail second@example.com 0123456789 900101123456"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(second.status_code, 200, second.text)
        second_input = self.adapters.generate_inputs[-1][-1]["content"]
        self.assertIn("[EMAIL]", second_input)
        self.assertIn("0123456789", second_input)
        self.assertIn("900101123456", second_input)
        self.assertNotIn("second@example.com", second_input)
        reply = second.json()["content"]
        self.assertIn("[EMAIL]", reply)
        self.assertIn("0123456789", reply)
        self.assertNotIn("second@example.com", reply)

    def test_blocks_keep_fixed_feedback_and_never_store_raw_output(self) -> None:
        alice_token = self.login()
        conversation_id = self.new_conversation(alice_token)
        prompt_canary = "CANARY-INPUT-PROMPT-8a11"
        classifier_canary = "RAW-CLASSIFIER-TEXT-2b22"
        self.adapters.attack_result = {
            "decision": "block",
            "reason": classifier_canary,
        }
        blocked = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": prompt_canary},
            headers=self.auth(alice_token),
        )
        self.assertEqual(blocked.status_code, 403, blocked.text)
        error = blocked.json()["error"]
        reference = error["turn_request_id"]
        self.assertEqual(error["code"], "FORBIDDEN")
        self.assertTrue(reference.startswith("req_"))
        self.assertEqual(
            error["block"],
            {**block_detail("INPUT_GUARD_BLOCK"), "ref": reference},
        )
        self.assertEqual(error["block"]["title"], "Prompt blocked")
        self.assertNotIn(prompt_canary, blocked.text)
        self.assertNotIn(classifier_canary, blocked.text)

        admin_token = self.login("root.admin")
        alerts = self._alerts(admin_token)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["reason_code"], "INPUT_GUARD_BLOCK")
        self.assertEqual(alerts[0]["request_id"], reference)
        self.assertEqual(alerts[0]["user_id"], self.alice["id"])
        self.assertNotIn(prompt_canary, str(alerts))
        self.assertNotIn(classifier_canary, str(alerts))

        reopened = self.store.read_conversation(self.alice["id"], conversation_id)
        blocked_messages = [
            item for item in reopened["messages"] if item["outcome"] == "blocked"
        ]
        self.assertEqual(len(blocked_messages), 1)
        self.assertEqual(blocked_messages[0]["text"], prompt_canary)
        self.assertEqual(
            blocked_messages[0]["block"],
            {**block_detail("INPUT_GUARD_BLOCK"), "ref": reference},
        )

        output_canary = "RAW-WITHHELD-OUTPUT-9c33"
        self.adapters.attack_result = {"decision": "allow"}
        self.adapters.generated = output_canary
        self.adapters.output_result = {"safe": False}
        withheld = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "safe prompt with withheld answer"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(withheld.status_code, 403, withheld.text)
        output_error = withheld.json()["error"]
        self.assertEqual(output_error["block"]["stage"], "output")
        self.assertEqual(
            output_error["block"]["reason_code"], "OUTPUT_GUARD_BLOCK"
        )
        self.assertEqual(output_error["block"]["title"], "Response withheld")
        self.assertNotIn(output_canary, withheld.text)

        reopened = self.store.read_conversation(self.alice["id"], conversation_id)
        self.assertNotIn(
            output_canary, "\n".join(item["text"] for item in reopened["messages"])
        )
        self.assertFalse(
            any(item["role"] == "assistant" for item in reopened["messages"])
        )
        alerts = self._alerts(admin_token)
        self.assertEqual(len(alerts), 2)
        self.assertNotIn(output_canary, str(alerts))
        self.assertIn(
            "OUTPUT_GUARD_BLOCK", [item["reason_code"] for item in alerts]
        )

    def test_block_persistence_failure_is_503_and_leaves_no_alert(self) -> None:
        class AlertFailureStore(_ProxyStore):
            def record_failed_turn(self, *args: Any, **kwargs: Any) -> Any:
                raise WorkspaceStorageError("synthetic alert persistence failure")

        app = self.make_app(store=AlertFailureStore(self.store))
        client = self.make_client(app)
        token = self.login(client=client)
        conversation_id = self.new_conversation(token, client)
        self.adapters.attack_result = {"decision": "block"}
        response = client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "blocked but not persisted"},
            headers=self.auth(token),
        )
        self.assert_error(response, 503, "UNAVAILABLE")
        self.assertEqual(self.adapters.generate_calls, 0)
        self.assertEqual(self.store.alert_summary(self.admin["id"])["total"], 0)

    def test_profile_mask_selection_rejects_non_list_values(self) -> None:
        admin_token = self.login("root.admin")
        before = len(self.store.list_policy_profiles(self.admin["id"])["items"])
        for field in ("input_masks", "output_masks"):
            response = self.client.post(
                "/workspace/api/admin/policy/profiles",
                json={"name": f"Object {field}", field: {"EMAIL": False}},
                headers=self.auth(admin_token),
            )
            self.assert_error(response, 400, "INVALID_REQUEST")
        self.assertEqual(
            len(self.store.list_policy_profiles(self.admin["id"])["items"]), before
        )

        empty = self._profile(
            admin_token, "No masks", input_masks=[], output_masks=[]
        )
        self.assertEqual(empty["settings"]["input_masks"], [])
        self.assertEqual(empty["settings"]["output_masks"], [])

