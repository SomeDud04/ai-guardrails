"""Synthetic, read-only tests for the deployment preflight script.

The real Docker CLI, Compose runtime, deployment files and secret values are
never used.  A mocked runner returns synthetic rendered configuration so the
checks can be exercised without mutating a stack or contacting a provider.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.check_hosted_setup import (
    CommandResult,
    PreflightError,
    build_command,
    run_preflight,
)

MUTATION_COMMANDS = frozenset(
    {"build", "up", "down", "stop", "start", "restart", "create", "run", "kill", "rm"}
)


class RecordingRunner:
    def __init__(self, result=None, error=None):
        self.result = result if result is not None else CommandResult(0, "{}")
        self.error = error
        self.calls = []

    def __call__(self, command, timeout):
        self.calls.append((list(command), timeout))
        if self.error is not None:
            raise self.error
        return self.result


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def local_file(self, name, content="synthetic-not-a-real-secret"):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def good_config(self):
        policy = self.local_file("policy.yaml")
        digest = self.local_file("operator_key_digest")
        audit_dsn = self.local_file("operator_audit_dsn")
        input_key = self.local_file("input_guard_key")
        output_key = self.local_file("output_guard_key")
        return {
            "services": {
                "gateway": {
                    "environment": {
                        "NASI_LEMAK_OUTPUT_GUARD_URL": (
                            "https://api.example.invalid/client/v4/accounts/"
                            "0123456789abcdef0123456789abcdef/ai/v1"
                        )
                    },
                    "volumes": [
                        {
                            "type": "bind",
                            "source": str(policy),
                            "target": "/run/pilot/policy/policy.yaml",
                            "read_only": True,
                        }
                    ],
                }
            },
            "secrets": {
                "operator_key_digest": {"file": str(digest)},
                "operator_audit_dsn": {"file": str(audit_dsn)},
                "input_guard_key": {"file": str(input_key)},
                "output_guard_key": {"file": str(output_key)},
            },
        }

    def test_good_config_passes_in_supplied_order_without_mutation_or_reading(self):
        config = self.good_config()
        runner = RecordingRunner(CommandResult(0, json.dumps(config)))
        with mock.patch("builtins.open", side_effect=AssertionError("must not read files")):
            message = run_preflight(
                [".secrets/base.env", ".secrets/hosted.env"],
                ["compose.yaml", "compose.api.yaml"],
                runner=runner,
                timeout=12,
            )
        self.assertIn("Preflight OK", message)
        command, timeout = runner.calls[0]
        self.assertEqual(
            command,
            [
                "docker",
                "compose",
                "--env-file",
                ".secrets/base.env",
                "--env-file",
                ".secrets/hosted.env",
                "-f",
                "compose.yaml",
                "-f",
                "compose.api.yaml",
                "config",
                "--format",
                "json",
            ],
        )
        self.assertEqual(timeout, 12.0)
        self.assertTrue(MUTATION_COMMANDS.isdisjoint(command))
        self.assertNotIn("0123456789abcdef", message)

    def test_placeholders_fail_with_field_names_and_no_values(self):
        config = self.good_config()
        config["services"]["gateway"]["environment"][
            "NASI_LEMAK_OUTPUT_GUARD_URL"
        ] = (
            "https://api.cloudflare.com/client/v4/accounts/"
            "ACCOUNT_ID/ai/v1"
        )
        config["secrets"]["operator_key_digest"]["file"] = (
            "/ABSOLUTE/PATH/TO/.secrets/operator_key_digest"
        )
        runner = RecordingRunner(CommandResult(0, json.dumps(config)))
        with self.assertRaises(PreflightError) as caught:
            run_preflight([], ["compose.yaml", "compose.api.yaml"], runner=runner)
        message = str(caught.exception)
        self.assertIn(
            "services.gateway.environment.NASI_LEMAK_OUTPUT_GUARD_URL", message
        )
        self.assertIn("secrets.operator_key_digest.file", message)
        self.assertNotIn("cloudflare.com", message)
        self.assertNotIn("ACCOUNT_ID", message)
        self.assertNotIn("/ABSOLUTE", message)

    def test_missing_bind_source_and_secret_file_fail_without_leaking_paths(self):
        config = self.good_config()
        missing_bind = str(self.root / "missing-policy.yaml")
        missing_secret = str(self.root / "missing-key")
        config["services"]["gateway"]["volumes"][0]["source"] = missing_bind
        config["secrets"]["input_guard_key"]["file"] = missing_secret
        runner = RecordingRunner(CommandResult(0, json.dumps(config)))
        with self.assertRaises(PreflightError) as caught:
            run_preflight([], ["compose.yaml", "compose.api.yaml"], runner=runner)
        message = str(caught.exception)
        self.assertIn("services.gateway.volumes[0].source", message)
        self.assertIn("secrets.input_guard_key.file", message)
        self.assertNotIn(missing_bind, message)
        self.assertNotIn(missing_secret, message)

    def test_wrong_bind_kind_and_relative_source_are_rejected(self):
        config = self.good_config()
        config["services"]["gateway"]["volumes"][0]["source"] = str(self.root)
        runner = RecordingRunner(CommandResult(0, json.dumps(config)))
        with self.assertRaises(PreflightError) as caught:
            run_preflight([], ["compose.yaml", "compose.api.yaml"], runner=runner)
        self.assertIn("must be a regular file", str(caught.exception))

        config["services"]["gateway"]["volumes"][0]["source"] = "relative/policy.yaml"
        runner = RecordingRunner(CommandResult(0, json.dumps(config)))
        with self.assertRaises(PreflightError) as caught:
            run_preflight([], ["compose.yaml", "compose.api.yaml"], runner=runner)
        self.assertIn("must resolve to an absolute path", str(caught.exception))

    def test_config_failure_is_generic_and_does_not_echo_rendered_data(self):
        runner = RecordingRunner(
            CommandResult(
                7,
                '{"secret": "RENDERED-CANARY"}',
                "CHILD-STDERR-CANARY",
            )
        )
        with self.assertRaises(PreflightError) as caught:
            run_preflight([], ["compose.yaml"], runner=runner)
        message = str(caught.exception)
        self.assertIn("exit code 7", message)
        self.assertNotIn("RENDERED-CANARY", message)
        self.assertNotIn("CHILD-STDERR-CANARY", message)
        self.assertNotIn("secret", message)

    def test_timeout_and_invalid_json_are_generic(self):
        runner = RecordingRunner(error=subprocess.TimeoutExpired(["docker"], 1.0))
        with self.assertRaises(PreflightError) as caught:
            run_preflight([], ["compose.yaml"], runner=runner, timeout=1)
        self.assertIn("timed out", str(caught.exception))
        self.assertNotIn("docker", str(caught.exception))

        runner = RecordingRunner(CommandResult(0, "not-json RENDERED-CANARY"))
        with self.assertRaises(PreflightError) as caught:
            run_preflight([], ["compose.yaml"], runner=runner)
        message = str(caught.exception)
        self.assertIn("valid JSON", message)
        self.assertNotIn("RENDERED-CANARY", message)

    def test_requires_a_compose_file_and_bounded_timeout(self):
        with self.assertRaises(PreflightError):
            run_preflight([], [], runner=RecordingRunner())
        for timeout in (0, -1, float("inf"), 301, True):
            with self.subTest(timeout=timeout):
                with self.assertRaises(PreflightError):
                    run_preflight(
                        [],
                        ["compose.yaml"],
                        runner=RecordingRunner(),
                        timeout=timeout,
                    )

    def test_build_command_never_adds_a_mutating_verb(self):
        command = build_command(["a.env"], ["compose.yaml", "compose.api.yaml"])
        self.assertEqual(command[-3:], ["config", "--format", "json"])
        self.assertTrue(MUTATION_COMMANDS.isdisjoint(command))


if __name__ == "__main__":
    unittest.main()
