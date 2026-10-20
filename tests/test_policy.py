"""Startup policy activation, deny-phrase and rollback tests.

All stores, guards and generators here are deterministic local SQLite/model
doubles.  No PostgreSQL instance, pretrained checkpoint, network endpoint or
real upstream model is contacted.  These tests prove orchestration only.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient

from nasi_lemak import server as server_module
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import MAX_DENY_PHRASE_LENGTH, Gateway, Policy
from nasi_lemak.policy import (
    MAX_POLICY_FILE_BYTES,
    PolicyError,
    load_policy,
)
from nasi_lemak.server import (
    ENV_POLICY_FILE,
    POLICY_ACTIVATION_EXPLICIT,
    POLICY_ACTIVATION_UNAVAILABLE,
    POLICY_ACTIVATION_YAML,
    make_app,
)

TEST_KEY = "policy-test-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
AUDIT_DSN = "postgresql://unused.invalid/nasi_lemak"


class _Adapters:
    """Deterministic local generation/guard double; no network or ML."""

    def __init__(self) -> None:
        self.attack_inputs: list[str] = []
        self.generate_inputs: list[list[dict[str, str]]] = []
        self.output_inputs: list[str] = []
        self.generated = "Safe synthetic answer."
        self.attack_result: Any = {"decision": "allow"}
        self.output_result: Any = {"safe": True}

    def count_tokens(self, serialized: str) -> int:
        return max(1, len(serialized.split()))

    def scan_attack(self, text: str) -> Any:
        self.attack_inputs.append(text)
        return self.attack_result

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        self.generate_inputs.append([dict(message) for message in messages])
        return self.generated

    def scan_output(self, text: str) -> Any:
        self.output_inputs.append(text)
        return self.output_result


def _policy_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "app_id": "nasi-lemak",
        "version": "2026-10-20.1",
        "model": "pilot-local",
        "token_budget": 128,
        "deny_phrases": ["Forbidden Phrase"],
    }
    data.update(overrides)
    return data


def _write_policy(path: Path, **overrides: Any) -> Path:
    path.write_text(json.dumps(_policy_data(**overrides), ensure_ascii=False), encoding="utf-8")
    return path


class PolicyLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _write_text(self, text: str, name: str = "policy.yaml") -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_valid_policy_loads_stably_and_digest_covers_actual_fields(self) -> None:
        path = _write_policy(self.root / "policy.yaml")
        first = load_policy(path)
        second = load_policy(path)

        self.assertEqual(first, second)
        self.assertEqual(first.app_id, "nasi-lemak")
        self.assertEqual(first.version, "2026-10-20.1")
        self.assertEqual(first.model, "pilot-local")
        self.assertEqual(first.token_budget, 128)
        self.assertEqual(first.deny_phrases, ("Forbidden Phrase",))
        self.assertEqual(len(first.digest), 64)
        self.assertEqual(first.digest, second.digest)

        variants = [
            load_policy(_write_policy(self.root / "identity.yaml", app_id="other-app")),
            load_policy(_write_policy(self.root / "version.yaml", version="v2")),
            load_policy(_write_policy(self.root / "budget.yaml", token_budget=129)),
            load_policy(_write_policy(self.root / "deny.yaml", deny_phrases=["Other Phrase"])),
        ]
        digests = {first.digest}
        for variant in variants:
            self.assertNotIn(variant.digest, digests)
            digests.add(variant.digest)

    def test_empty_deny_phrase_list_is_allowed(self) -> None:
        policy = load_policy(_write_policy(self.root / "empty.yaml", deny_phrases=[]))
        self.assertEqual(policy.deny_phrases, ())
        self.assertFalse(policy.denies("anything"))

    def test_missing_unreadable_and_oversized_files_fail_closed(self) -> None:
        with self.assertRaises(PolicyError):
            load_policy(None)
        with self.assertRaises(PolicyError):
            load_policy(self.root / "missing.yaml")
        with self.assertRaises(PolicyError):
            load_policy(self.root)
        oversized = self.root / "oversized.yaml"
        oversized.write_bytes(b"x" * (MAX_POLICY_FILE_BYTES + 1))
        with self.assertRaises(PolicyError):
            load_policy(oversized)
        invalid_utf8 = self.root / "invalid-utf8.yaml"
        invalid_utf8.write_bytes(b"\xff\xfe")
        with self.assertRaises(PolicyError):
            load_policy(invalid_utf8)

    def test_malformed_duplicate_unknown_and_missing_keys_are_rejected(self) -> None:
        cases = {
            "malformed": "app_id: [\n",
            "duplicate": "\n".join(
                [
                    "app_id: nasi-lemak",
                    "app_id: other-app",
                    "version: v1",
                    "model: pilot-local",
                    "token_budget: 10",
                    "deny_phrases: []",
                ]
            ),
            "unknown": "\n".join(
                [
                    "app_id: nasi-lemak",
                    "version: v1",
                    "model: pilot-local",
                    "token_budget: 10",
                    "deny_phrases: []",
                    "extra: true",
                ]
            ),
            "missing": "\n".join(
                [
                    "app_id: nasi-lemak",
                    "version: v1",
                    "model: pilot-local",
                    "token_budget: 10",
                ]
            ),
            "top-level-list": "- app_id\n- nasi-lemak\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(PolicyError):
                    load_policy(self._write_text(text, name + ".yaml"))

    def test_anchors_aliases_custom_tags_and_multiple_documents_are_rejected(self) -> None:
        cases = {
            "anchor-alias": "\n".join(
                [
                    "app_id: &identity nasi-lemak",
                    "version: *identity",
                    "model: pilot-local",
                    "token_budget: 10",
                    "deny_phrases: []",
                ]
            ),
            "custom-tag": "\n".join(
                [
                    "app_id: !identity nasi-lemak",
                    "version: v1",
                    "model: pilot-local",
                    "token_budget: 10",
                    "deny_phrases: []",
                ]
            ),
            "multiple-documents": "\n".join(
                [
                    "app_id: nasi-lemak",
                    "version: v1",
                    "model: pilot-local",
                    "token_budget: 10",
                    "deny_phrases: []",
                    "---",
                    "app_id: other-app",
                    "version: v2",
                    "model: pilot-local",
                    "token_budget: 10",
                    "deny_phrases: []",
                ]
            ),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(PolicyError):
                    load_policy(self._write_text(text, name + ".yaml"))

    def test_example_policy_file_loads(self) -> None:
        example = Path(__file__).resolve().parent.parent / "docs" / "policy.example.yaml"
        policy = load_policy(example)
        self.assertEqual(policy.app_id, "nasi-lemak")
        self.assertEqual(policy.model, "pilot-local")
        self.assertGreaterEqual(policy.token_budget, 1)
        self.assertLessEqual(policy.token_budget, 512)
        self.assertTrue(policy.deny_phrases)

    def test_deeply_nested_yaml_under_byte_cap_is_rejected(self) -> None:
        depth = 200
        text = "\n".join(
            [
                "app_id: nasi-lemak",
                "version: v1",
                "model: pilot-local",
                "token_budget: 10",
                "deny_phrases: " + "[" * depth + "]" * depth,
            ]
        )
        self.assertLess(len(text.encode("utf-8")), MAX_POLICY_FILE_BYTES)
        with self.assertRaises(PolicyError):
            load_policy(self._write_text(text, "nested.yaml"))

    def test_invalid_types_and_bounds_are_rejected(self) -> None:
        cases = {
            "budget-zero": _policy_data(token_budget=0),
            "budget-too-high": _policy_data(token_budget=513),
            "budget-bool": _policy_data(token_budget=True),
            "budget-string": _policy_data(token_budget="10"),
            "budget-float": _policy_data(token_budget=1.5),
            "model-other": _policy_data(model="other-model"),
            "app-id-empty": _policy_data(app_id=""),
            "app-id-int": _policy_data(app_id=5),
            "app-id-space": _policy_data(app_id="nasi lemak"),
            "version-empty": _policy_data(version=""),
            "version-int": _policy_data(version=3),
            "deny-string": _policy_data(deny_phrases="phrase"),
            "deny-int": _policy_data(deny_phrases=[1]),
            "deny-empty-string": _policy_data(deny_phrases=[""]),
            "deny-too-long": _policy_data(deny_phrases=["x" * (MAX_DENY_PHRASE_LENGTH + 1)]),
            "deny-too-many": _policy_data(deny_phrases=["p" + str(i) for i in range(65)]),
        }
        for name, data in cases.items():
            with self.subTest(name=name):
                path = self.root / (name + ".yaml")
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(PolicyError):
                    load_policy(path)


class DenyPhraseGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "audit.sqlite3"

    def _gateway(self, policy: Policy, adapters: _Adapters | None = None) -> tuple[Gateway, _Adapters]:
        adapters = adapters or _Adapters()
        gateway = Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(self.path),
            adapters=adapters,
            policy=policy,
        )
        return gateway, adapters

    def _request(self, messages: list[dict[str, str]], **extra: Any) -> dict[str, Any]:
        body = {"model": "pilot-local", "messages": messages}
        body.update(extra)
        return body

    def _call(self, gateway: Gateway, body: dict[str, Any]):
        return gateway.handle(
            "POST", "/v1/chat/completions", {"Authorization": "Bearer " + TEST_KEY}, body
        )

    def test_every_input_turn_is_checked_before_generation(self) -> None:
        policy = Policy(deny_phrases=("forbidden phrase",))
        gateway, adapters = self._gateway(policy)
        messages = [
            {"role": "system", "content": "ordinary system context"},
            {"role": "assistant", "content": "ordinary history"},
            {"role": "user", "content": "please include FORBIDDEN PHRASE now"},
        ]

        status, payload = self._call(gateway, self._request(messages))

        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(adapters.generate_inputs, [])
        # The mandatory attack guard still covers the complete conversation.
        self.assertEqual(len(adapters.attack_inputs), 1)
        for message in messages:
            self.assertIn(message["content"], adapters.attack_inputs[0])
        events = gateway.audit_events()
        self.assertEqual([event["event_type"] for event in events], ["request_started", "request_blocked"])
        self.assertEqual(events[-1]["error_code"], "POLICY_BLOCK")
        self.assertEqual(events[-1]["policy_digest"], policy.digest)

    def test_buffered_output_is_checked_before_release_after_output_guard(self) -> None:
        policy = Policy(deny_phrases=("forbidden phrase",))
        gateway, adapters = self._gateway(policy)
        adapters.generated = "prefix FORBIDDEN PHRASE suffix"

        status, payload = self._call(
            gateway, self._request([{"role": "user", "content": "ordinary input"}])
        )

        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "POLICY_BLOCK")
        self.assertNotIn("choices", payload)
        self.assertEqual(len(adapters.generate_inputs), 1)
        self.assertEqual(adapters.output_inputs, [adapters.generated])
        self.assertEqual(gateway.audit_events()[-1]["event_type"], "request_blocked")

    def test_unicode_casefold_is_literal_and_not_a_regex(self) -> None:
        gateway, _ = self._gateway(Policy(deny_phrases=("Straße", "a.b")))
        status, _ = self._call(
            gateway, self._request([{"role": "user", "content": "STRASSE"}])
        )
        self.assertEqual(status, 403)

        gateway, _ = self._gateway(
            Policy(deny_phrases=("a.b",)),
            _Adapters(),
        )
        status, _ = self._call(
            gateway, self._request([{"role": "user", "content": "axb"}])
        )
        self.assertEqual(status, 200)
        status, _ = self._call(
            gateway, self._request([{"role": "user", "content": "A.B"}])
        )
        self.assertEqual(status, 403)

    def test_client_cannot_override_identity_policy_or_model(self) -> None:
        policy = Policy(app_id="nasi-lemak", deny_phrases=("forbidden phrase",))
        gateway, adapters = self._gateway(policy)
        cases = [
            self._request([{"role": "user", "content": "hello"}], app_id="attacker-app"),
            self._request([{"role": "user", "content": "hello"}], policy={"token_budget": 1}),
            self._request([{"role": "user", "content": "hello"}], deny_phrases=[]),
            self._request([{"role": "user", "content": "hello"}], model="other-model"),
        ]
        for body in cases:
            with self.subTest(body=body):
                status, payload = self._call(gateway, body)
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"]["code"], "INVALID_REQUEST")
        self.assertEqual(adapters.generate_inputs, [])
        self.assertEqual(gateway.app_id, "nasi-lemak")
        self.assertEqual(gateway.policy, policy)

    def test_guard_block_still_wins_and_deny_cannot_relax_it(self) -> None:
        policy = Policy(deny_phrases=())
        gateway, adapters = self._gateway(policy)
        adapters.attack_result = {"decision": "block"}
        status, payload = self._call(
            gateway, self._request([{"role": "user", "content": "ordinary input"}])
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(adapters.generate_inputs, [])


class StartupActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.digest = hashlib.sha256(TEST_KEY.encode()).hexdigest()

    def _environment(self, policy_path: Path | None) -> dict[str, str]:
        env = {
            "NASI_LEMAK_APP_KEY_DIGEST": self.digest,
            "NASI_LEMAK_AUDIT_DSN": AUDIT_DSN,
        }
        if policy_path is not None:
            env[ENV_POLICY_FILE] = str(policy_path)
        return env

    def _activated_app(self, policy_path: Path, adapters: Any = None, *, app_id: str = "nasi-lemak"):
        def store(_dsn: str) -> SqliteAuditStore:
            return SqliteAuditStore(self.root / "audit.sqlite3")

        with mock.patch.object(server_module, "PostgresAuditStore", store):
            return make_app(
                environ=self._environment(policy_path),
                adapters=adapters or _Adapters(),
                app_id=app_id,
            )

    def _client(self, app: Any) -> TestClient:
        client = TestClient(app)
        self.addCleanup(client.close)
        return client

    def test_valid_yaml_activates_once_and_chat_uses_active_policy(self) -> None:
        path = _write_policy(self.root / "policy.yaml")
        app = self._activated_app(path)
        client = self._client(app)

        self.assertTrue(app.state.config_ready)
        self.assertEqual(app.state.policy_activation, POLICY_ACTIVATION_YAML)
        self.assertEqual(app.state.gateway.policy.version, "2026-10-20.1")
        self.assertEqual(app.state.gateway.app_id, "nasi-lemak")
        self.assertEqual(app.state.policy_digest, load_policy(path).digest)
        self.assertEqual(client.get("/health/ready").status_code, 200)

        response = client.post(
            "/v1/chat/completions",
            json={"model": "pilot-local", "messages": [{"role": "user", "content": "Email person@example.com"}]},
            headers=AUTH,
        )
        self.assertEqual(response.status_code, 200, response.text)
        events = app.state.gateway.audit_events()
        self.assertEqual(
            {event["policy_digest"] for event in events}, {app.state.policy_digest}
        )

    def test_missing_or_invalid_policy_never_loads_guards_or_defaults(self) -> None:
        invalid = self.root / "invalid.yaml"
        invalid.write_text("app_id: nasi-lemak\n", encoding="utf-8")
        nested = self.root / "nested.yaml"
        nested.write_text(
            "app_id: nasi-lemak\nversion: v1\nmodel: pilot-local\n"
            "token_budget: 10\ndeny_phrases: " + "[" * 200 + "]" * 200 + "\n",
            encoding="utf-8",
        )
        cases = [None, self.root / "missing.yaml", invalid, nested]
        with mock.patch.object(
            server_module,
            "make_adapters_from_env",
            side_effect=AssertionError("guards must not load for a bad policy"),
        ) as factory:
            for path in cases:
                with self.subTest(path=path):
                    app = make_app(environ=self._environment(path))
                    client = self._client(app)
                    self.assertFalse(app.state.config_ready)
                    self.assertEqual(
                        app.state.policy_activation, POLICY_ACTIVATION_UNAVAILABLE
                    )
                    self.assertIsNone(app.state.gateway.adapters)
                    self.assertEqual(client.get("/health/live").status_code, 200)
                    self.assertEqual(client.get("/health/ready").status_code, 503)
                    response = client.post(
                        "/v1/chat/completions",
                        json={"model": "pilot-local", "messages": [{"role": "user", "content": "hello"}]},
                        headers={"Authorization": "Bearer any"},
                    )
                    self.assertEqual(response.status_code, 503)
                    self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertEqual(factory.call_count, 0)

    def test_policy_identity_must_match_server_side_app_id(self) -> None:
        path = _write_policy(self.root / "policy.yaml", app_id="other-app")
        with mock.patch.object(
            server_module,
            "make_adapters_from_env",
            side_effect=AssertionError("guards must not load after identity mismatch"),
        ) as factory:
            app = make_app(environ=self._environment(path), adapters=None)
        self.assertFalse(app.state.config_ready)
        self.assertEqual(app.state.policy_activation, POLICY_ACTIVATION_UNAVAILABLE)
        self.assertEqual(factory.call_count, 0)

        matching = self._activated_app(path, app_id="other-app")
        self.assertTrue(matching.state.config_ready)
        self.assertEqual(matching.state.gateway.app_id, "other-app")

    def test_explicit_policy_seam_does_not_require_yaml(self) -> None:
        policy = Policy(version="explicit-v1", app_id="nasi-lemak")
        with mock.patch.object(
            server_module,
            "PostgresAuditStore",
            lambda _dsn: SqliteAuditStore(self.root / "explicit.sqlite3"),
        ):
            app = make_app(
                environ=self._environment(None),
                adapters=_Adapters(),
                policy=policy,
            )
        self.assertTrue(app.state.config_ready)
        self.assertEqual(app.state.policy_activation, POLICY_ACTIVATION_EXPLICIT)
        self.assertEqual(app.state.gateway.policy, policy)
        self.assertEqual(app.state.policy_digest, policy.digest)

    def test_restart_version_change_and_preserved_file_rollback(self) -> None:
        v1_path = _write_policy(self.root / "policy-v1.yaml", version="v1")
        v1_text = v1_path.read_text(encoding="utf-8")
        first = self._activated_app(v1_path)
        first_digest = first.state.policy_digest

        v2_path = _write_policy(self.root / "policy-v2.yaml", version="v2")
        second = self._activated_app(v2_path)
        self.assertEqual(first.state.gateway.policy.version, "v1")
        self.assertEqual(second.state.gateway.policy.version, "v2")
        self.assertNotEqual(first_digest, second.state.policy_digest)

        # A rollback selects a preserved prior file and restarts. The approved
        # v1 file is never overwritten by the v2 activation.
        self.assertEqual(v1_path.read_text(encoding="utf-8"), v1_text)
        rollback_path = self.root / "policy-rollback.yaml"
        shutil.copyfile(v1_path, rollback_path)
        rolled_back = self._activated_app(rollback_path)
        self.assertEqual(rolled_back.state.gateway.policy.version, "v1")
        self.assertEqual(rolled_back.state.policy_digest, first_digest)

    def test_invalid_restart_does_not_reuse_or_fallback_to_previous_policy(self) -> None:
        good = self._activated_app(_write_policy(self.root / "good.yaml"))
        self.assertTrue(good.state.config_ready)
        bad_path = self.root / "bad.yaml"
        bad_path.write_text("app_id: nasi-lemak\nversion: v2\n", encoding="utf-8")

        with mock.patch.object(
            server_module,
            "make_adapters_from_env",
            side_effect=AssertionError("guards must not load for an invalid restart"),
        ) as factory:
            bad = make_app(environ=self._environment(bad_path))
        self.assertFalse(bad.state.config_ready)
        self.assertEqual(bad.state.policy_activation, POLICY_ACTIVATION_UNAVAILABLE)
        self.assertIsNone(bad.state.gateway.adapters)
        self.assertEqual(factory.call_count, 0)
        self.assertTrue(good.state.config_ready)
        self.assertEqual(good.state.gateway.policy.version, "2026-10-20.1")


if __name__ == "__main__":
    unittest.main()
