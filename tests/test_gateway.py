import json
import tempfile
import unittest
from pathlib import Path

from nasi_lemak.gateway import Gateway, MemoryAdapters, Policy, make_demo_gateway


def request(messages=None, **extra):
    body = {"model": "pilot-local", "messages": messages or [{"role": "user", "content": "Hello"}]}
    body.update(extra)
    return body


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.gateway, self.adapters, self.key = make_demo_gateway(Path(self.tmp.name) / "audit.sqlite3")

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, body):
        return self.gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + self.key}, body)

    def test_success_scans_each_original_turn_and_returns_masked_output(self):
        turns = [{"role": "user", "content": "mail test@example.com"}, {"role": "assistant", "content": "I saw test@example.com"}]
        self.adapters.generated = "echo 0123456789 test@example.com +60123456789"
        response = self.call(request(turns))
        self.assertEqual(response[0], 200)
        self.assertEqual(len(self.adapters.attack_inputs), 1)
        for turn in turns:
            self.assertIn(turn["content"], self.adapters.attack_inputs[0])
        self.assertNotIn("test@example.com", self.adapters.generation_inputs[0][0]["content"])
        self.assertNotIn("test@example.com", response[1]["choices"][0]["message"]["content"])
        self.assertNotIn("0123456789", response[1]["choices"][0]["message"]["content"])

    def test_postal_address_masks_both_generation_input_and_output(self):
        address = "No. 12, Jalan Melati 3, Taman Sri Indah, 43000 Kajang, Selangor"
        self.adapters.generated = f"Alamat: {address}"
        response = self.call(
            request([{"role": "user", "content": f"Rumah saya di {address}"}])
        )
        self.assertEqual(response[0], 200)
        generated_input = self.adapters.generation_inputs[0][0]["content"]
        self.assertNotIn(address, generated_input)
        self.assertIn("[POSTAL_ADDRESS]", generated_input)
        content = response[1]["choices"][0]["message"]["content"]
        self.assertNotIn(address, content)
        self.assertIn("Alamat: [POSTAL_ADDRESS]", content)

    def test_labelled_address_without_postcode_masks_input_and_output(self):
        address = "Alamat: Unit 12-3, Jalan Ampang"
        self.adapters.generated = f"Rumah: {address}"
        response = self.call(
            request([{"role": "user", "content": f"Rumah saya {address}"}])
        )
        self.assertEqual(response[0], 200)
        generated_input = self.adapters.generation_inputs[0][0]["content"]
        self.assertNotIn(address, generated_input)
        self.assertIn("Alamat: [POSTAL_ADDRESS]", generated_input)
        content = response[1]["choices"][0]["message"]["content"]
        self.assertNotIn(address, content)
        self.assertIn("Rumah: Alamat: [POSTAL_ADDRESS]", content)

    def test_rejects_unknown_fields_and_client_policy_override_before_upstream(self):
        for body in (request(tools=[]), request(policy="unsafe"), request(extra_field=1)):
            with self.subTest(body=body):
                status, result = self.call(body)
                self.assertEqual(status, 400)
                self.assertEqual(result["error"]["code"], "INVALID_REQUEST")
        self.assertEqual(self.adapters.attack_inputs, [])
        self.assertEqual(self.adapters.generation_inputs, [])

    def test_rejects_invalid_roles_parts_limits_and_bool_tokens(self):
        invalid = [
            request([{"role": "tool", "content": "x"}]),
            request([{"role": "user", "content": [{"type": "text", "text": "x"}]}]),
            request([{"role": "user", "content": "x", "name": "n"}]),
            request([{"role": "user", "content": "x"}], stream=True),
            request(max_tokens=True),
            request(max_tokens=0),
            request([{"role": "user", "content": ""}]),
            request([{"role": "user", "content": "x"}] * 33),
        ]
        for body in invalid:
            with self.subTest(body=str(body)[:80]):
                self.assertEqual(self.call(body)[0], 400)

    def test_oversized_character_budget_returns_input_limit(self):
        status, body = self.call(request([{"role": "user", "content": "x" * 8193}]))
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "INPUT_LIMIT")

    def test_exact_token_coverage_is_required(self):
        self.adapters.token_count = lambda _messages: 99
        gateway = Gateway(self.key, Path(self.tmp.name) / "coverage.sqlite", self.adapters, Policy(token_budget=98))
        status, result = gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + self.key}, request())
        self.assertEqual(status, 413)
        self.assertEqual(result["error"]["code"], "INPUT_LIMIT")
        self.assertEqual([e["event_type"] for e in gateway.audit_events()], ["request_started", "request_blocked"])

    def test_bad_token_counter_results_fail_closed(self):
        for invalid_count in (True, -1, "unknown", None):
            with self.subTest(invalid_count=invalid_count):
                self.adapters.token_count = lambda _serialized, value=invalid_count: value
                status, body = self.call(request())
                self.assertEqual(status, 503)
                self.assertEqual(body["error"]["code"], "UNAVAILABLE")
                self.assertNotIn("choices", body)
        self.assertEqual(self.adapters.generation_inputs, [])

    def test_missing_guards_fail_closed(self):
        gateway = Gateway(app_key=self.key, audit_path=Path(self.tmp.name) / "missing.sqlite", adapters=None)
        status, result = gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + self.key}, request())
        self.assertEqual(status, 503)
        self.assertEqual(result["error"]["code"], "UNAVAILABLE")

    def test_invalid_guard_result_fails_closed_without_leaking_content(self):
        self.adapters.attack_result = "allow"
        status, result = self.call(request([{"role": "user", "content": "secret PII test@example.com"}]))
        self.assertEqual(status, 503)
        self.assertEqual(result["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("secret", json.dumps(result))

    def test_generation_receives_only_sanitized_messages(self):
        self.call(request([{"role": "user", "content": "email test@example.com"}]))
        self.assertNotIn("test@example.com", json.dumps(self.adapters.generation_inputs))

    def test_input_pii_and_output_pii_are_not_in_response_or_audit(self):
        self.adapters.generated = "answer to 900101123456 test@example.com +60123456789"
        response = self.call(request([{"role": "user", "content": "0123456789 +60123456789 test@example.com 900101123456"}]))
        content_text = response[1]["choices"][0]["message"]["content"]
        self.assertIn("[MYKAD]", content_text)
        self.assertNotIn("900101123456", content_text)
        content = Path(self.tmp.name, "audit.sqlite3").read_bytes()
        for raw in (b"0123456789", b"+60123456789", b"test@example.com", b"900101123456"):
            self.assertNotIn(raw, content)

    def test_failures_are_generic_and_have_request_ids(self):
        self.adapters.attack_error = RuntimeError("prompt test@example.com secret")
        status, body = self.call(request([{"role": "user", "content": "test@example.com"}]))
        self.assertEqual(status, 503)
        self.assertTrue(body["error"]["request_id"])
        self.assertNotIn("test@example.com", json.dumps(body))
        self.assertNotIn("secret", json.dumps(body))

    def test_audit_writes_initial_and_terminal_events_and_recovers_orphans(self):
        self.call(request())
        events = self.gateway.audit_events()
        self.assertEqual([e["event_type"] for e in events], ["request_started", "request_completed"])
        self.assertNotIn("content", json.dumps(events))

    def test_initial_or_terminal_audit_write_failure_withholds_output(self):
        for stage in ("initial", "terminal"):
            g, a, key = make_demo_gateway(Path(self.tmp.name) / (stage + ".sqlite"))
            g.fail_audit_stage = stage
            status, body = g.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer " + key}, request())
            self.assertNotEqual(status, 200)
            self.assertNotIn("choices", body)
            self.assertEqual(len(a.generation_inputs), 0 if stage == "initial" else 1)
            if stage == "terminal":
                self.assertEqual(g.audit_events()[-1]["event_type"], "request_started")
                g.fail_audit_stage = None
                self.assertEqual(g.reconcile_incomplete(offline=True), 1)
                self.assertEqual(g.audit_events()[-1]["event_type"], "request_recovered")

    def test_authentication_is_constant_time_and_demo_key_is_nonempty(self):
        self.assertTrue(self.key)
        self.assertFalse(hasattr(self.gateway, "demo_key"))
        status, body = self.gateway.handle("POST", "/v1/chat/completions", {"Authorization": "Bearer wrong"}, request())
        self.assertEqual(status, 401)
        self.assertNotIn("wrong", json.dumps(body))

    def test_policy_digest_is_derived_and_output_cap_is_passed_to_adapter(self):
        policy = self.gateway.policy
        self.assertEqual(len(policy.digest), 64)
        self.assertEqual(self.call(request())[0], 200)
        self.assertEqual(self.adapters.generate_options, [("pilot-local", 1024)])
        response = self.call(request(max_tokens=17))
        self.assertEqual(response[0], 200)
        self.assertEqual(self.adapters.generate_options[-1], ("pilot-local", 17))
        self.assertNotIn("usage", response[1])

    def test_policy_block_has_403_and_untrusted_headers_fail_stably(self):
        self.adapters.attack_result = {"decision": "block"}
        status, body = self.call(request())
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        status, body = self.gateway.handle("POST", "/v1/chat/completions", None, request())
        self.assertEqual(status, 401)

    def test_policy_digest_cannot_be_overridden(self):
        with self.assertRaises((TypeError, ValueError)):
            Policy(version="v", digest="client-controlled")

    def test_explicit_offline_recovery_marks_incomplete_owned_events(self):
        with self.assertRaises(ValueError):
            self.gateway.reconcile_incomplete()
        self.gateway._audit("req_abandoned", "request_started", "pending")
        self.assertEqual(self.gateway.reconcile_incomplete(offline=True), 1)
        events = self.gateway.audit_events()
        self.assertEqual(events[-1]["event_type"], "request_recovered")

    def test_offline_recovery_preserves_original_policy_metadata(self):
        path = Path(self.tmp.name) / "policy-recovery.sqlite"
        original = Gateway(self.key, path, self.adapters, Policy(version="policy-a", token_budget=123))
        original._audit("req_policy_a", "request_started", "pending")
        restarted = Gateway(self.key, path, self.adapters, Policy(version="policy-b", token_budget=321))
        self.assertEqual(restarted.reconcile_incomplete(offline=True), 1)
        recovered = next(e for e in restarted.audit_events() if e["event_type"] == "request_recovered")
        self.assertEqual(recovered["policy_version"], "policy-a")
        self.assertEqual(recovered["model"], "pilot-local")
        self.assertEqual(recovered["policy_digest"], Policy(version="policy-a", token_budget=123).digest)

    def test_output_guard_block_and_malformed_results_release_nothing(self):
        self.adapters.output_result = {"safe": False}
        status, body = self.call(request())
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        self.adapters.output_result = {"missing": "safe"}
        status, body = self.call(request())
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "UNAVAILABLE")
        self.adapters.output_result = {"safe": True}
        self.adapters.output_error = RuntimeError("output guard failed")
        status, body = self.call(request())
        self.assertEqual(status, 503)
        self.assertNotIn("choices", body)

    def test_audit_start_precedes_generation_and_terminal_precedes_release(self):
        order = []
        original_audit = self.gateway._audit
        def audit(*args, **kwargs):
            order.append(args[1])
            return original_audit(*args, **kwargs)
        self.gateway._audit = audit
        original_generate = self.adapters.generate
        def generate(*args, **kwargs):
            order.append("generation")
            return original_generate(*args, **kwargs)
        self.adapters.generate = generate
        response = self.call(request())
        self.assertEqual(response[0], 200)
        self.assertLess(order.index("request_started"), order.index("generation"))
        self.assertLess(order.index("generation"), order.index("request_completed"))


if __name__ == "__main__":
    unittest.main()

