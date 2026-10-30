"""Focused HTTP coverage for per-turn policy controls and block alerts.

These tests use the real FastAPI workspace application, a temporary SQLite
store and synthetic in-process adapters.  No external provider, guard, database
or network service is contacted.
"""

from __future__ import annotations

import json
from typing import Any

from nasi_lemak.controls import block_detail
from nasi_lemak.workspace_store import WorkspaceStorageError
from tests.test_workspace_http import PASSWORD, WorkspaceHTTPBase, _ProxyStore


class PolicyPipelineTests(WorkspaceHTTPBase):
    def _profile(self, admin_token: str, name: str, **fields: Any) -> dict:
        response = self.client.post(
            "/workspace/api/admin/policy/profiles",
            json={"name": name, **fields},
            headers=self.auth(admin_token),
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def _assign(
        self,
        admin_token: str,
        profile_id: str,
        *,
        expected_version: int | None = None,
        profile_revision: int | None = None,
    ) -> dict:
        body: dict[str, Any] = {
            "scope_type": "user",
            "scope_id": self.alice["id"],
            "profile_id": profile_id,
        }
        if expected_version is not None:
            body["expected_version"] = expected_version
        if profile_revision is not None:
            body["profile_revision"] = profile_revision
        response = self.client.post(
            "/workspace/api/admin/policy/assignments",
            json=body,
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

    def _blocked_alert(self, owner: dict, request_id: str) -> str:
        control = self.store.resolve_gateway_control(owner["id"])
        conversation = self.store.create_conversation(owner["id"])
        lease = self.store.reserve_turn(owner["id"], conversation["id"])
        result = self.store.record_failed_turn(
            owner["id"],
            conversation["id"],
            lease["token"],
            user_prompt="synthetic blocked prompt",
            outcome="blocked",
            request_id=request_id,
            error_code="POLICY_BLOCK",
            alert={
                "stage": "input",
                "reason_code": "INPUT_GUARD_BLOCK",
                "revision": control.revision,
                "digest": control.digest,
                "sources": control.metadata()["sources"],
            },
        )
        return result["alert_id"]

    def _cookie_login(self, client: Any = None, username: str = "root.admin") -> None:
        response = (client or self.client).post(
            "/workspace/api/login",
            json={"username": username, "password": PASSWORD, "cookie": True},
            headers={"Origin": "http://testserver"},
        )
        self.assertEqual(response.status_code, 200, response.text)

    def test_read_all_marks_twelve_alerts_for_one_admin_only(self) -> None:
        for index in range(12):
            self._blocked_alert(self.alice, f"req_read_all_{index}")
        second_admin = self.store.create_user(
            self.admin["id"],
            "second.admin",
            PASSWORD,
            "Second Admin",
            self.accounting["id"],
            "admin",
        )
        admin_token = self.login("root.admin")
        second_token = self.login("second.admin")

        first = self.client.post(
            "/workspace/api/admin/alerts/read-all",
            json={},
            headers=self.auth(admin_token),
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(
            first.json(), {"status": "ok", "marked_read": 12, "total": 12}
        )
        alerts = self._alerts(admin_token)
        self.assertEqual(len(alerts), 12)
        self.assertTrue(all(item["read"] for item in alerts))
        self.assertEqual(
            self.client.get(
                "/workspace/api/admin/alerts/summary",
                headers=self.auth(admin_token),
            ).json()["unread"],
            0,
        )

        # A second administrator's own read state is untouched.
        other = self._alerts(second_token)
        self.assertEqual(len(other), 12)
        self.assertFalse(any(item["read"] for item in other))
        self.assertEqual(
            self.client.get(
                "/workspace/api/admin/alerts/summary",
                headers=self.auth(second_token),
            ).json()["unread"],
            12,
        )
        self.assertEqual(second_admin["role"], "admin")

        # Repeating the bulk mark is a no-op, so the route is idempotent.
        repeated = self.client.post(
            "/workspace/api/admin/alerts/read-all",
            json={},
            headers=self.auth(admin_token),
        )
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(repeated.json()["marked_read"], 0)

        # The employee role is denied before the body is read or state written.
        alice_token = self.login()
        denied = self.client.post(
            "/workspace/api/admin/alerts/read-all",
            json={},
            headers=self.auth(alice_token),
        )
        self.assert_error(denied, 403, "FORBIDDEN")
        self.assertTrue(all(item["read"] for item in self._alerts(admin_token)))

    def test_read_all_requires_csrf_and_an_empty_json_body(self) -> None:
        for index in range(12):
            self._blocked_alert(self.alice, f"req_read_all_guard_{index}")
        admin_token = self.login("root.admin")
        unread = lambda: self.client.get(  # noqa: E731
            "/workspace/api/admin/alerts/summary", headers=self.auth(admin_token)
        ).json()["unread"]
        self.assertEqual(unread(), 12)

        for body in ({"unexpected": True}, {"read": False}):
            response = self.client.post(
                "/workspace/api/admin/alerts/read-all",
                json=body,
                headers=self.auth(admin_token),
            )
            self.assert_error(response, 400, "INVALID_REQUEST")
        self.assertEqual(unread(), 12)

        duplicate = self.client.post(
            "/workspace/api/admin/alerts/read-all",
            content=b'{"unexpected":true,"unexpected":false}',
            headers={**self.auth(admin_token), "content-type": "application/json"},
        )
        self.assert_error(duplicate, 400, "INVALID_REQUEST")
        missing_json = self.client.post(
            "/workspace/api/admin/alerts/read-all",
            content=b"",
            headers=self.auth(admin_token),
        )
        self.assert_error(missing_json, 400, "INVALID_REQUEST")
        self.assertEqual(unread(), 12)

        # Use a separate client so the cookie credential never mixes with the
        # bearer token used by the read-state assertions above.
        cookie_client = self.make_client(self.app)
        self._cookie_login(cookie_client)
        cookie_headers = {"X-Workspace-User": self.admin["id"]}
        for origin in (None, "https://evil.example", "null", "http://testserver/"):
            headers = dict(cookie_headers)
            if origin is not None:
                headers["Origin"] = origin
            denied = cookie_client.post(
                "/workspace/api/admin/alerts/read-all", json={}, headers=headers
            )
            self.assert_error(denied, 403, "FORBIDDEN")
        self.assertEqual(unread(), 12)

        marked = cookie_client.post(
            "/workspace/api/admin/alerts/read-all",
            json={},
            headers={
                **cookie_headers,
                "Origin": "http://testserver",
            },
        )
        self.assertEqual(marked.status_code, 200, marked.text)
        self.assertEqual(marked.json()["marked_read"], 12)
        self.assertEqual(unread(), 0)

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

    def test_allowed_turn_reports_guardrail_details(self) -> None:
        token = self.login()
        conversation_id = self.new_conversation(token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "My email is ali@example.com"},
            headers=self.auth(token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        details = response.json()["guardrail"]
        self.assertEqual(details["input_check"], "safe")
        self.assertEqual(details["output_check"], "safe")
        self.assertIs(details["input_pii_masked"], True)
        self.assertIsInstance(details["output_pii_masked"], bool)
        self.assertIsInstance(details["latency_ms"], int)
        self.assertNotIn("ali@example.com", json.dumps(details))

    def test_blocked_turn_reports_guardrail_details_without_text(self) -> None:
        token = self.login()
        conversation_id = self.new_conversation(token)
        prompt_canary = "CANARY-GUARDRAIL-PROMPT-71f"
        classifier_canary = "RAW-CLASSIFIER-GUARDRAIL-90c"
        self.adapters.attack_result = {"decision": "block", "reason": classifier_canary}
        blocked = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": prompt_canary},
            headers=self.auth(token),
        )
        self.assertEqual(blocked.status_code, 403, blocked.text)
        details = blocked.json()["error"]["guardrail"]
        self.assertEqual(details["input_check"], "blocked")
        self.assertEqual(details["output_check"], "not_run")
        self.assertIs(details["input_pii_masked"], False)
        self.assertIs(details["output_pii_masked"], False)
        self.assertNotIn(prompt_canary, blocked.text)
        self.assertNotIn(classifier_canary, blocked.text)

    def test_policy_disabled_check_reads_off_not_safe(self) -> None:
        admin_token = self.login("root.admin")
        profile = self._profile(
            admin_token, "input-check-off", input_check_enabled=False
        )
        self._assign(admin_token, profile["id"])
        token = self.login()
        conversation_id = self.new_conversation(token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation_id}/messages",
            json={"text": "hello"},
            headers=self.auth(token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["guardrail"]["input_check"], "off")
        self.assertEqual(response.json()["guardrail"]["output_check"], "safe")

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

    def test_postal_mask_policy_controls_trusted_gateway_input_and_output(self) -> None:
        address = "No. 12, Jalan Melati 3, 43000 Kajang"
        alice_token = self.login()
        admin_token = self.login("root.admin")

        # Input postal mask on, output off.
        profile = self._profile(
            admin_token,
            "Postal input only",
            input_masks=["EMAIL", "MY_PHONE", "MYKAD", "POSTAL_ADDRESS"],
            output_masks=[],
        )
        self._assign(admin_token, profile["id"])
        conversation = self.new_conversation(alice_token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation}/messages",
            json={"text": f"Alamat: {address}"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        sent = self.adapters.generate_inputs[-1][-1]["content"]
        self.assertIn("[POSTAL_ADDRESS]", sent)
        self.assertNotIn(address, sent)
        self.assertNotIn("[POSTAL_ADDRESS]", response.json()["content"])

        # Flip the independent channels: input postal off, output postal on.
        revised = self.client.post(
            f"/workspace/api/admin/policy/profiles/{profile['id']}/revise",
            json={
                "expected_revision": profile["revision"],
                "input_masks": ["EMAIL", "MY_PHONE", "MYKAD"],
                "output_masks": ["EMAIL", "MY_PHONE", "MYKAD", "POSTAL_ADDRESS"],
            },
            headers=self.auth(admin_token),
        )
        self.assertEqual(revised.status_code, 200, revised.text)
        self.assertEqual(
            revised.json()["settings"]["output_masks"],
            ["EMAIL", "MY_PHONE", "MYKAD", "POSTAL_ADDRESS"],
        )
        self.assertNotIn(
            "POSTAL_ADDRESS", revised.json()["settings"]["input_masks"]
        )
        # Assignments pin an immutable revision, so an administrator applying
        # the revised settings re-points the assignment explicitly.
        assignment = self._assign(
            admin_token,
            profile["id"],
            expected_version=1,
            profile_revision=revised.json()["revision"],
        )
        self.assertEqual(
            assignment["settings"]["output_masks"],
            ["EMAIL", "MY_PHONE", "MYKAD", "POSTAL_ADDRESS"],
        )
        policy = self.client.get(
            "/workspace/api/policy", headers=self.auth(alice_token)
        )
        self.assertEqual(policy.status_code, 200, policy.text)
        self.assertEqual(
            policy.json()["output_masks"],
            ["EMAIL", "MY_PHONE", "MYKAD", "POSTAL_ADDRESS"],
        )

        self.adapters.generated = f"Alamat: {address}"
        conversation = self.new_conversation(alice_token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation}/messages",
            json={"text": f"Alamat: {address}"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        sent = self.adapters.generate_inputs[-1][-1]["content"]
        self.assertIn(address, sent)
        self.assertNotIn("[POSTAL_ADDRESS]", sent)
        released = response.json()["content"]
        self.assertIn("[POSTAL_ADDRESS]", released)
        self.assertNotIn(address, released)

        # Input and output postal masks both off leaves the address raw.
        third = self.client.post(
            f"/workspace/api/admin/policy/profiles/{profile['id']}/revise",
            json={
                "expected_revision": revised.json()["revision"],
                "input_masks": ["EMAIL", "MY_PHONE", "MYKAD"],
                "output_masks": ["EMAIL", "MY_PHONE", "MYKAD"],
            },
            headers=self.auth(admin_token),
        )
        self.assertEqual(third.status_code, 200, third.text)
        self.assertNotIn(
            "POSTAL_ADDRESS", third.json()["settings"]["output_masks"]
        )
        self._assign(
            admin_token,
            profile["id"],
            expected_version=2,
            profile_revision=third.json()["revision"],
        )
        self.adapters.generated = f"Alamat: {address}"
        conversation = self.new_conversation(alice_token)
        response = self.client.post(
            f"/workspace/api/conversations/{conversation}/messages",
            json={"text": f"Alamat: {address}"},
            headers=self.auth(alice_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        sent = self.adapters.generate_inputs[-1][-1]["content"]
        self.assertIn(address, sent)
        self.assertNotIn("[POSTAL_ADDRESS]", sent)
        released = response.json()["content"]
        self.assertEqual(released, f"Alamat: {address}")
        self.assertNotIn("[POSTAL_ADDRESS]", released)

    def test_employee_cannot_create_or_revise_a_postal_mask_profile(self) -> None:
        alice_token = self.login()
        denied = self.client.post(
            "/workspace/api/admin/policy/profiles",
            json={"name": "Employee postal", "input_masks": ["POSTAL_ADDRESS"]},
            headers=self.auth(alice_token),
        )
        self.assert_error(denied, 403, "FORBIDDEN")

        admin_token = self.login("root.admin")
        profile = self._profile(
            admin_token, "Admin postal", input_masks=["POSTAL_ADDRESS"]
        )
        denied = self.client.post(
            f"/workspace/api/admin/policy/profiles/{profile['id']}/revise",
            json={"expected_revision": profile["revision"], "input_masks": []},
            headers=self.auth(alice_token),
        )
        self.assert_error(denied, 403, "FORBIDDEN")
        stored = self.store.get_policy_profile(self.admin["id"], profile["id"])
        self.assertEqual(stored["revision"], profile["revision"])
        self.assertEqual(stored["settings"]["input_masks"], ["POSTAL_ADDRESS"])

