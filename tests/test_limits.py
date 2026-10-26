"""Focused tests for immutable shared chat limits and Gateway wiring."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from nasi_lemak.gateway import Gateway, MemoryAdapters
from nasi_lemak.limits import (
    ENV_CONTEXT_BUDGET,
    ENV_CONTEXT_MESSAGES,
    ENV_DEFAULT_REPLY_TOKENS,
    ENV_MAX_REPLY_TOKENS,
    MAX_REPLY_TOKENS_CEILING,
    ChatLimits,
    ChatLimitsError,
    has_explicit_env,
)
from nasi_lemak.server import make_app


class ChatLimitsConfigTests(unittest.TestCase):
    def test_defaults_are_bounded_and_shareable(self) -> None:
        limits = ChatLimits.defaults()
        self.assertEqual(
            limits.public(),
            {
                "context_messages": 32,
                "context_budget": 8192,
                "default_reply_tokens": 1024,
                "max_reply_tokens": 4096,
            },
        )
        self.assertEqual(limits.max_prompt_chars(), 8192)

    def test_explicit_environment_is_parsed_once(self) -> None:
        limits = ChatLimits.from_env(
            {
                ENV_CONTEXT_MESSAGES: "8",
                ENV_CONTEXT_BUDGET: "4096",
                ENV_DEFAULT_REPLY_TOKENS: "600",
                ENV_MAX_REPLY_TOKENS: "2048",
            }
        )
        self.assertEqual(limits.context_messages, 8)
        self.assertEqual(limits.context_budget, 4096)
        self.assertEqual(limits.default_reply_tokens, 600)
        self.assertEqual(limits.max_reply_tokens, 2048)
        self.assertTrue(has_explicit_env({ENV_CONTEXT_BUDGET: "4096"}))
        self.assertFalse(has_explicit_env({ENV_CONTEXT_BUDGET: "  "}))

    def test_explicit_maximum_lowers_implicit_default(self) -> None:
        limits = ChatLimits.from_env({ENV_MAX_REPLY_TOKENS: "512"})
        self.assertEqual(limits.default_reply_tokens, 512)
        self.assertEqual(limits.max_reply_tokens, 512)

    def test_invalid_values_are_rejected(self) -> None:
        cases = [
            {ENV_CONTEXT_MESSAGES: "0"},
            {ENV_CONTEXT_MESSAGES: "33"},
            {ENV_CONTEXT_MESSAGES: "2.5"},
            {ENV_CONTEXT_BUDGET: "32769"},
            {ENV_DEFAULT_REPLY_TOKENS: "0"},
            {ENV_MAX_REPLY_TOKENS: str(MAX_REPLY_TOKENS_CEILING + 1)},
            {ENV_DEFAULT_REPLY_TOKENS: "700", ENV_MAX_REPLY_TOKENS: "600"},
        ]
        for env in cases:
            with self.subTest(env=env):
                with self.assertRaises(ChatLimitsError):
                    ChatLimits.from_env(env)

    def test_invalid_environment_leaves_app_live_but_not_ready(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        adapters = MemoryAdapters()
        gateway = Gateway(
            app_key="limits-key",
            audit_path=Path(tmp.name) / "audit.sqlite3",
            adapters=adapters,
        )
        app = make_app(
            gateway=gateway,
            environ={
                "NASI_LEMAK_MODE": "test",
                "NASI_LEMAK_ALLOW_UNGUARDED_TEST": "true",
                ENV_CONTEXT_MESSAGES: "0",
            },
        )
        client = TestClient(app)
        self.addCleanup(client.close)
        self.assertEqual(client.get("/health/live").status_code, 200)
        self.assertEqual(client.get("/health/ready").status_code, 503)
        self.assertFalse(app.state.config_ready)
        # Invalid env is never silently applied to the injected fixture.
        self.assertEqual(gateway.limits, ChatLimits.defaults())

    def test_explicit_environment_builds_app_owned_clone(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        gateway = Gateway(
            app_key="clone-key",
            audit_path=Path(tmp.name) / "audit.sqlite3",
            adapters=MemoryAdapters(),
        )
        original = gateway.limits
        app = make_app(
            gateway=gateway,
            environ={
                "NASI_LEMAK_MODE": "test",
                "NASI_LEMAK_ALLOW_UNGUARDED_TEST": "true",
                ENV_CONTEXT_MESSAGES: "8",
                ENV_CONTEXT_BUDGET: "4096",
            },
        )
        client = TestClient(app)
        self.addCleanup(client.close)
        self.assertIsNot(app.state.gateway, gateway)
        self.assertEqual(gateway.limits, original)
        self.assertEqual(app.state.gateway.limits.context_messages, 8)
        self.assertEqual(app.state.gateway.limits.context_budget, 4096)
        self.assertEqual(client.get("/health/ready").status_code, 200)


class GatewayLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.adapters = MemoryAdapters()

    def gateway(self, **limits: int) -> Gateway:
        return Gateway(
            app_key="reply-key",
            audit_path=Path(self.tmp.name) / "audit.sqlite3",
            adapters=self.adapters,
            limits=ChatLimits(**limits),
        )

    def call(self, gateway: Gateway, **extra: object):
        body = {
            "model": "pilot-local",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        body.update(extra)
        return gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer reply-key"},
            body,
        )

    def test_default_and_ceiling_match_shared_limits(self) -> None:
        gateway = self.gateway()
        self.assertEqual(self.call(gateway)[0], 200)
        self.assertEqual(self.adapters.generate_options[-1], ("pilot-local", 1024))
        self.assertEqual(self.call(gateway, max_tokens=4096)[0], 200)
        self.assertEqual(self.call(gateway, max_tokens=4097)[0], 400)

    def test_configured_max_and_explicit_lower_value(self) -> None:
        gateway = self.gateway(
            default_reply_tokens=256, max_reply_tokens=2048
        )
        self.assertEqual(self.call(gateway)[0], 200)
        self.assertEqual(self.adapters.generate_options[-1], ("pilot-local", 256))
        self.assertEqual(self.call(gateway, max_tokens=512)[0], 200)
        self.assertEqual(self.call(gateway, max_tokens=2049)[0], 400)

    def test_gateway_context_count_uses_configured_messages(self) -> None:
        gateway = self.gateway(context_messages=4)
        too_many = [{"role": "user", "content": "x"}] * 5
        response = gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer reply-key"},
            {"model": "pilot-local", "messages": too_many},
        )
        self.assertEqual(response[0], 400)


if __name__ == "__main__":
    unittest.main()
