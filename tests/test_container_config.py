"""Structural invariants for the authored Docker/Compose pilot configuration.

These tests parse YAML and Dockerfile text only.  They are deliberately not a
Compose merge/interpolation engine, not ``docker compose config``, and not
image-build, startup, PostgreSQL, native-guard or live-model evidence.  Docker
is absent from this workspace.  The ASGI test uses existing injected fake
loaders; no pretrained weights are downloaded or executed.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    import yaml
except ImportError:  # pragma: no cover - the test extra pins PyYAML
    yaml = None

from fastapi.testclient import TestClient

from nasi_lemak import server as server_module
from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.server import make_adapters_from_env, make_app

ROOT = Path(__file__).resolve().parents[1]

BASE_ENV_KEYS = {
    "NASI_LEMAK_AUDIT_DSN_FILE",
    "NASI_LEMAK_APP_KEY_DIGEST_FILE",
    "NASI_LEMAK_GENERATION_URL",
    "NASI_LEMAK_GENERATION_MODEL",
    "NASI_LEMAK_GENERATION_AUTH",
    "NASI_LEMAK_GENERATION_ALLOW_INSECURE_HTTP",
    "NASI_LEMAK_GENERATION_API_KEY",
    "NASI_LEMAK_GENERATION_ENABLE_THINKING",
    "NASI_LEMAK_GENERATION_SYSTEM_PROMPT",
    "NASI_LEMAK_CHAT_CONTEXT_MESSAGES",
    "NASI_LEMAK_CHAT_CONTEXT_BUDGET",
    "NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS",
    "NASI_LEMAK_CHAT_MAX_REPLY_TOKENS",
}

CHAT_LIMIT_ENV_KEYS = {
    "NASI_LEMAK_CHAT_CONTEXT_MESSAGES",
    "NASI_LEMAK_CHAT_CONTEXT_BUDGET",
    "NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS",
    "NASI_LEMAK_CHAT_MAX_REPLY_TOKENS",
}

OVERLAY_ENV_KEYS = {
    "NASI_LEMAK_MODE",
    "NASI_LEMAK_ALLOW_UNGUARDED_TEST",
    "NASI_LEMAK_GUARD_BACKEND",
    "NASI_LEMAK_POLICY_FILE",
    # Restored Meta pilot settings: the overlay extends that pilot with Qwen.
    "NASI_LEMAK_PROMPT_GUARD_MODEL_DIR",
    "NASI_LEMAK_LLAMA_GUARD_MODEL_DIR",
    "NASI_LEMAK_PROMPT_GUARD_THRESHOLD",
    "NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT",
    "NASI_LEMAK_QWEN3GUARD_MODEL_DIR",
    "NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD",
    "NASI_LEMAK_QWEN3GUARD_OUTPUT_THRESHOLD",
    "NASI_LEMAK_QWEN3GUARD_WORKERS",
    "NASI_LEMAK_QWEN3GUARD_THREADS",
    "NASI_LEMAK_QWEN3GUARD_LONG_INPUT",
    "NASI_LEMAK_OPERATOR_KEY_DIGEST_FILE",
    "NASI_LEMAK_OPERATOR_AUDIT_DSN_FILE",
    "HF_HUB_OFFLINE",
    "TRANSFORMERS_OFFLINE",
    "HF_DATASETS_OFFLINE",
}

EXPECTED_TARGETS = {
    "/run/pilot/policy/policy.yaml": "NASI_LEMAK_POLICY_FILE",
    "/models/prompt-guard-2": "NASI_LEMAK_PROMPT_GUARD_MODEL_DIR",
    "/models/llama-guard-3": "NASI_LEMAK_LLAMA_GUARD_MODEL_DIR",
}

QWEN_ENV_NAME = "NASI_LEMAK_QWEN3GUARD_MODEL_DIR"
QWEN_CONTAINER_DIR_PREFIX = "${PILOT_QWEN_GUARD_MODEL_CONTAINER_DIR:?"

_STAGE_RE = re.compile(r"^\s*FROM\s+(\S+)\s+AS\s+(\S+)\s*$", re.IGNORECASE)
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _load(name: str):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


def _string_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _dockerfile_stages(text: str):
    order = []
    stages = {}
    current = None
    for line in text.splitlines():
        match = _STAGE_RE.match(line)
        if match:
            current = match.group(2).lower()
            order.append(current)
            stages[current] = []
        elif current is not None:
            stages[current].append(line)
    return order, stages


class _FakeHealthcheckResponse:
    """Context-manager response stand-in for the real embedded probe script."""

    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


def _run_embedded_healthcheck(script, urlopen):
    """Run the actual Compose healthcheck script against a mocked ``urlopen``.

    Only ``urllib.request.urlopen`` is replaced; the script text under test is
    the one embedded in ``compose.pilot.yaml``.  No socket is opened.
    """
    code = compile(script, "<compose.pilot.healthcheck>", "exec")
    with mock.patch("urllib.request.urlopen", urlopen):
        try:
            exec(code, {"__name__": "__main__"})
        except SystemExit as exc:
            return exc.code
    raise AssertionError("healthcheck script did not raise SystemExit")


class ComposeConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if yaml is None:
            raise unittest.SkipTest("PyYAML is not installed")
        cls.base = _load("compose.yaml")
        cls.pilot = _load("compose.pilot.yaml")
        cls.base_text = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        cls.pilot_text = (ROOT / "compose.pilot.yaml").read_text(encoding="utf-8")
        cls.pilot_example = (
            ROOT / "docs" / "compose.pilot.env.example"
        ).read_text(encoding="utf-8")
        cls.chat_limits_text = (
            ROOT / "docs" / "compose.chat-limits.env.example"
        ).read_text(encoding="utf-8")

    def test_base_stack_keeps_lightweight_safe_defaults(self):
        gateway = self.base["services"]["gateway"]
        self.assertNotIn("target", gateway.get("build", {}))
        self.assertEqual(gateway["read_only"], True)
        self.assertEqual(gateway["user"], "10001:10001")
        self.assertEqual(gateway["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", gateway["security_opt"])
        self.assertEqual(gateway["mem_limit"], "512m")
        self.assertEqual(gateway["cpus"], 1.0)
        self.assertEqual(gateway["ports"], ["127.0.0.1:${GATEWAY_PORT:-8000}:8000"])
        self.assertEqual(gateway["depends_on"]["db"]["condition"], "service_healthy")
        gateway_env = _environment_map(gateway["environment"])
        self.assertEqual(set(gateway_env), BASE_ENV_KEYS)
        self.assertEqual(
            gateway_env["NASI_LEMAK_AUDIT_DSN_FILE"], "/run/secrets/audit_dsn"
        )
        self.assertEqual(
            gateway_env["NASI_LEMAK_APP_KEY_DIGEST_FILE"],
            "/run/secrets/app_key_digest",
        )
        self.assertEqual(
            gateway_env["NASI_LEMAK_GENERATION_URL"],
            "${NASI_LEMAK_GENERATION_URL:-}",
        )
        # The bearer key is a bare pass-through: forwarded only when the
        # operator defines it in the git-ignored base env file.
        self.assertEqual(gateway_env["NASI_LEMAK_GENERATION_API_KEY"], "")
        self.assertIn("- NASI_LEMAK_GENERATION_API_KEY\n", self.base_text)
        self.assertNotIn("NASI_LEMAK_GENERATION_API_KEY=", self.base_text)

        db = self.base["services"]["db"]
        self.assertNotIn("ports", db)
        self.assertEqual(db["networks"], ["db_internal"])
        self.assertTrue(self.base["networks"]["db_internal"]["internal"])
        self.assertEqual(set(gateway["networks"]), {"default", "db_internal"})

    def test_base_forwards_the_bearer_key_as_a_bare_pass_through(self):
        gateway_env = _environment_map(
            self.base["services"]["gateway"]["environment"]
        )
        # The name is forwarded; the tracked file supplies no value.
        self.assertEqual(gateway_env["NASI_LEMAK_GENERATION_API_KEY"], "")
        # Exactly a bare list entry: no "=value", no ":value" and no default.
        self.assertRegex(
            self.base_text,
            r"(?m)^\s*-\s*NASI_LEMAK_GENERATION_API_KEY\s*$",
        )
        self.assertIsNone(
            re.search(r"NASI_LEMAK_GENERATION_API_KEY\s*[:=]", self.base_text)
        )
        # It is never set to a literal by interpolation in the tracked file;
        # only the operator's git-ignored base env can supply the value.
        self.assertNotIn("NASI_LEMAK_GENERATION_API_KEY=${", self.base_text)
        self.assertNotIn("NASI_LEMAK_GENERATION_API_KEY=", self.base_text)

    def test_chat_limits_are_bare_pass_through_with_a_documented_example(self):
        gateway = self.base["services"]["gateway"]
        gateway_env = _environment_map(gateway["environment"])
        for name in CHAT_LIMIT_ENV_KEYS:
            with self.subTest(name=name):
                self.assertEqual(gateway_env[name], "")
                self.assertIn(f"- {name}\n", self.base_text)
                self.assertNotIn(f"{name}=", self.base_text)
                self.assertNotIn(f"{name}=", self.pilot_text)
        # Compose resolves unset bare entries to the application defaults; no
        # secret or provider-capacity claim may be embedded in the example.
        self.assertIn("NASI_LEMAK_CHAT_CONTEXT_MESSAGES=32", self.chat_limits_text)
        self.assertIn("NASI_LEMAK_CHAT_CONTEXT_BUDGET=8192", self.chat_limits_text)
        self.assertIn(
            "NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS=1024", self.chat_limits_text
        )
        self.assertIn("NASI_LEMAK_CHAT_MAX_REPLY_TOKENS=4096", self.chat_limits_text)

    def test_base_secrets_require_absolute_file_interpolation(self):
        expected = {"db_admin_password", "audit_dsn", "app_key_digest"}
        self.assertEqual(set(self.base["secrets"]), expected)
        for name, secret in self.base["secrets"].items():
            with self.subTest(secret=name):
                self.assertIn(":?", secret["file"])
                self.assertIn("_FILE", secret["file"])

    def test_overlay_selects_guards_target_and_keeps_base_security(self):
        gateway = self.pilot["services"]["gateway"]
        self.assertEqual(gateway["build"]["target"], "guards")
        self.assertNotEqual(gateway["image"], self.base["services"]["gateway"]["image"])
        env = _environment_map(gateway["environment"])
        self.assertEqual(set(env), OVERLAY_ENV_KEYS)
        self.assertFalse(set(env) & BASE_ENV_KEYS)
        # The overlay must not reset the inherited non-root/read-only posture.
        for key in ("read_only", "user", "cap_drop", "security_opt", "ports", "networks"):
            with self.subTest(key=key):
                self.assertNotIn(key, gateway)

    def test_overlay_mount_targets_match_runtime_variables(self):
        gateway = self.pilot["services"]["gateway"]
        env = _environment_map(gateway["environment"])
        volumes = gateway["volumes"]
        self.assertEqual(len(volumes), len(EXPECTED_TARGETS) + 1)
        by_target = {volume["target"]: volume for volume in volumes}
        for target, env_name in EXPECTED_TARGETS.items():
            with self.subTest(target=target):
                self.assertIn(target, by_target)
                volume = by_target[target]
                self.assertEqual(volume["type"], "bind")
                self.assertEqual(volume["read_only"], True)
                self.assertIs(volume["bind"]["create_host_path"], False)
                self.assertIn(":?", volume["source"])
                self.assertTrue(volume["source"].startswith("${"))
                self.assertEqual(env[env_name], target)
        # The Qwen mount target and runtime directory are the SAME mandatory
        # container-dir interpolation, so the two cannot drift apart.
        qwen_targets = [
            target
            for target in by_target
            if target.startswith(QWEN_CONTAINER_DIR_PREFIX)
        ]
        self.assertEqual(len(qwen_targets), 1)
        qwen_target = qwen_targets[0]
        self.assertIn(":?", qwen_target)
        volume = by_target[qwen_target]
        self.assertEqual(volume["type"], "bind")
        self.assertIs(volume["read_only"], True)
        self.assertIs(volume["bind"]["create_host_path"], False)
        self.assertIn(":?", volume["source"])
        self.assertTrue(
            volume["source"].startswith("${PILOT_QWEN_GUARD_MODEL_DIR:?")
        )
        self.assertEqual(env[QWEN_ENV_NAME], qwen_target)
        # The documented container directory is the fixed pilot path.
        self.assertIn(
            "PILOT_QWEN_GUARD_MODEL_CONTAINER_DIR=/models/qwen3guard-gen-0.6b",
            self.pilot_example,
        )

    def test_overlay_guard_threshold_and_context_are_explicit(self):
        env = _environment_map(self.pilot["services"]["gateway"]["environment"])
        self.assertEqual(env["NASI_LEMAK_MODE"], "guarded")
        self.assertEqual(env["NASI_LEMAK_ALLOW_UNGUARDED_TEST"], "false")
        self.assertEqual(env["NASI_LEMAK_GUARD_BACKEND"], "qwen3guard-local")
        # Restored Meta pilot settings keep their baseline defaults.
        self.assertEqual(
            env["NASI_LEMAK_PROMPT_GUARD_THRESHOLD"],
            "${NASI_LEMAK_PROMPT_GUARD_THRESHOLD:-0.5}",
        )
        self.assertEqual(
            env["NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT"],
            "${NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT:-4096}",
        )
        self.assertEqual(
            env["NASI_LEMAK_PROMPT_GUARD_MODEL_DIR"], "/models/prompt-guard-2"
        )
        self.assertEqual(
            env["NASI_LEMAK_LLAMA_GUARD_MODEL_DIR"], "/models/llama-guard-3"
        )
        # Required Qwen model directory: a mandatory interpolation, not a
        # literal, and the same expression as the read-only mount target.
        self.assertTrue(env[QWEN_ENV_NAME].startswith(QWEN_CONTAINER_DIR_PREFIX))
        self.assertIn(":?", env[QWEN_ENV_NAME])
        # Optional local settings are bare pass-throughs; unset keeps the
        # validated application defaults.  None is defaulted or invented here.
        for name in (
            "NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD",
            "NASI_LEMAK_QWEN3GUARD_OUTPUT_THRESHOLD",
            "NASI_LEMAK_QWEN3GUARD_WORKERS",
            "NASI_LEMAK_QWEN3GUARD_THREADS",
            "NASI_LEMAK_QWEN3GUARD_LONG_INPUT",
        ):
            with self.subTest(name=name):
                self.assertEqual(env[name], "")
                self.assertIn(f"- {name}\n", self.pilot_text)
                self.assertNotIn(f"{name}=", self.pilot_text)
        self.assertNotIn("NASI_LEMAK_GENERATION_MODEL", env)
        for flag in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE"):
            self.assertEqual(env[flag], "1")

    def test_overlay_is_local_only_and_has_no_hosted_api_guard_entries(self):
        env = _environment_map(self.pilot["services"]["gateway"]["environment"])
        hosted_prefixes = (
            "NASI_LEMAK_INPUT_GUARD_",
            "NASI_LEMAK_OUTPUT_GUARD_",
        )
        for name in env:
            with self.subTest(name=name):
                self.assertFalse(name.startswith(hosted_prefixes))
        gateway = self.pilot["services"]["gateway"]
        self.assertFalse(
            {name for name in gateway["secrets"] if name.endswith("_guard_key")}
        )
        # The rule itself must be stated in the file, not only enforced by the
        # missing entries: the two verticals must never merge into one
        # half-configured container.
        self.assertIn("must be ABSENT", self.pilot_text)
        self.assertIn("compose.api.yaml", self.pilot_text)

    def test_overlay_operator_secrets_are_distinct_and_file_backed(self):
        gateway = self.pilot["services"]["gateway"]
        env = _environment_map(gateway["environment"])
        expected = {"operator_key_digest", "operator_audit_dsn"}
        self.assertEqual(set(gateway["secrets"]), expected)
        self.assertFalse(expected & set(self.base["secrets"]))
        self.assertEqual(
            env["NASI_LEMAK_OPERATOR_KEY_DIGEST_FILE"],
            "/run/secrets/operator_key_digest",
        )
        self.assertEqual(
            env["NASI_LEMAK_OPERATOR_AUDIT_DSN_FILE"],
            "/run/secrets/operator_audit_dsn",
        )
        self.assertEqual(set(self.pilot["secrets"]), expected)
        for name, secret in self.pilot["secrets"].items():
            with self.subTest(secret=name):
                self.assertIn(":?", secret["file"])

    def test_overlay_healthcheck_probes_real_readiness_with_finite_timeout(self):
        check = self.pilot["services"]["gateway"]["healthcheck"]
        self.assertEqual(check["test"][:3], ["CMD", "python", "-c"])
        script = check["test"][3]
        self.assertIn("/health/ready", script)
        self.assertIn("urlopen", script)
        self.assertIn("SystemExit", script)
        self.assertEqual(check["interval"], "30s")
        self.assertEqual(check["timeout"], "8s")
        self.assertEqual(check["retries"], 3)
        self.assertEqual(check["start_period"], "10m")

    def test_embedded_healthcheck_exit_codes_request_shape_and_finite_timeout(self):
        script = self.pilot["services"]["gateway"]["healthcheck"]["test"][3]
        observed = {}

        def urlopen(url, timeout=None):
            observed["url"] = url
            observed["timeout"] = timeout
            return _FakeHealthcheckResponse(200)

        self.assertEqual(_run_embedded_healthcheck(script, urlopen), 0)
        self.assertEqual(observed["url"], "http://127.0.0.1:8000/health/ready")
        request_timeout = observed["timeout"]
        self.assertIsInstance(request_timeout, (int, float))
        self.assertNotIsInstance(request_timeout, bool)
        self.assertEqual(float(request_timeout), 7.0)
        # The probe's own wait fits strictly inside Compose's outer timeout.
        self.assertLess(float(request_timeout), 8.0)

        def unavailable(url, timeout=None):
            return _FakeHealthcheckResponse(503)

        self.assertEqual(_run_embedded_healthcheck(script, unavailable), 1)

        def timed_out(url, timeout=None):
            raise TimeoutError("probe timed out")

        self.assertEqual(_run_embedded_healthcheck(script, timed_out), 1)

    def test_overlay_resource_budget_is_separate_and_configurable(self):
        gateway = self.pilot["services"]["gateway"]
        self.assertEqual(gateway["mem_limit"], "${GUARD_MEM_LIMIT:-8g}")
        self.assertEqual(gateway["cpus"], "${GUARD_CPUS:-4.0}")
        self.assertEqual(gateway["pids_limit"], "${GUARD_PIDS_LIMIT:-512}")
        self.assertNotEqual(gateway["mem_limit"], self.base["services"]["gateway"]["mem_limit"])

    def test_overlay_contains_no_embedded_secret_values(self):
        for name, document in (("compose.yaml", self.base), ("compose.pilot.yaml", self.pilot)):
            for value in _string_values(document):
                with self.subTest(file=name, value=value[:40]):
                    self.assertNotRegex(value, _HEX_DIGEST_RE)
                    self.assertNotIn("postgresql://", value)
                    self.assertNotIn("BEGIN PRIVATE KEY", value)
        # Generation credentials stay file/secret-manager owned.  The base file
        # carries only a bare pass-through name for the bearer key -- never a
        # default, a value or a file path -- and the local overlay carries no
        # generation credential at all.
        self.assertIn("- NASI_LEMAK_GENERATION_API_KEY\n", self.base_text)
        self.assertNotIn("NASI_LEMAK_GENERATION_API_KEY=", self.base_text)
        self.assertNotIn("NASI_LEMAK_GENERATION_API_KEY", self.pilot_text)


def _environment_map(value):
    if isinstance(value, dict):
        return dict(value)
    result = {}
    for item in value:
        name, _, setting = item.partition("=")
        result[name] = setting
    return result


class ApiComposeOverlayTests(unittest.TestCase):
    """Structural checks for the API guard backend packaging.

    These parse YAML only.  Docker is absent, so this is not a merged
    ``docker compose config`` result or a runtime claim.
    """

    @classmethod
    def setUpClass(cls):
        if yaml is None:
            raise unittest.SkipTest("PyYAML is not installed")
        cls.base = _load("compose.yaml")
        cls.api = _load("compose.api.yaml")
        cls.ca = _load("compose.api-ca.yaml")
        cls.api_text = (ROOT / "compose.api.yaml").read_text(encoding="utf-8")
        cls.example = (ROOT / "docs" / "compose.api.env.example").read_text(
            encoding="utf-8"
        )

    def test_overlay_selects_lightweight_server_and_keeps_base_security(self):
        gateway = self.api["services"]["gateway"]
        self.assertEqual(gateway["build"]["target"], "server")
        self.assertEqual(
            gateway["image"], self.base["services"]["gateway"]["image"]
        )
        # The overlay must not reset the inherited non-root/read-only posture.
        for key in (
            "read_only",
            "user",
            "cap_drop",
            "security_opt",
            "ports",
            "networks",
            "mem_limit",
            "cpus",
            "pids_limit",
        ):
            with self.subTest(key=key):
                self.assertNotIn(key, gateway)
        self.assertEqual(self.base["services"]["gateway"]["ports"], ["127.0.0.1:${GATEWAY_PORT:-8000}:8000"])
        self.assertNotIn("ports", self.base["services"]["db"])

    def test_overlay_is_guarded_api_with_test_ack_false(self):
        env = _environment_map(self.api["services"]["gateway"]["environment"])
        self.assertEqual(env["NASI_LEMAK_MODE"], "guarded")
        self.assertEqual(env["NASI_LEMAK_ALLOW_UNGUARDED_TEST"], "false")
        self.assertEqual(env["NASI_LEMAK_GUARD_BACKEND"], "api")
        self.assertEqual(
            env["NASI_LEMAK_INPUT_GUARD_CONTRACT"],
            "nasi-lemak-input-classifier-v1",
        )
        self.assertNotIn("NASI_LEMAK_GENERATION_MODEL", env)

    def test_overlay_mounts_only_approved_policy_not_model_artifacts(self):
        volumes = self.api["services"]["gateway"]["volumes"]
        self.assertEqual(len(volumes), 1)
        policy = volumes[0]
        self.assertEqual(policy["type"], "bind")
        self.assertEqual(policy["target"], "/run/pilot/policy/policy.yaml")
        self.assertIs(policy["read_only"], True)
        self.assertIs(policy["bind"]["create_host_path"], False)
        self.assertIn(":?", policy["source"])
        for volume in volumes:
            self.assertNotIn("/models", volume["target"])
        self.assertNotIn("PROMPT_GUARD_MODEL_DIR", self.api_text)
        self.assertNotIn("LLAMA_GUARD_MODEL_DIR", self.api_text)

    def test_overlay_operator_and_guard_secrets_are_file_backed(self):
        gateway = self.api["services"]["gateway"]
        self.assertEqual(
            set(gateway["secrets"]),
            {
                "operator_key_digest",
                "operator_audit_dsn",
                "input_guard_key",
                "output_guard_key",
            },
        )
        self.assertEqual(
            set(self.api["secrets"]),
            {
                "operator_key_digest",
                "operator_audit_dsn",
                "input_guard_key",
                "output_guard_key",
            },
        )
        for name, secret in self.api["secrets"].items():
            with self.subTest(secret=name):
                self.assertIn(":?", secret["file"])
                self.assertIn("_FILE", secret["file"])
        operator_files = {
            self.api["secrets"]["operator_key_digest"]["file"],
            self.api["secrets"]["operator_audit_dsn"]["file"],
        }
        self.assertEqual(len(operator_files), 2)
        self.assertFalse(
            operator_files
            & {secret["file"] for secret in self.base["secrets"].values()}
        )

    def test_bearer_key_variables_are_conditional_container_paths(self):
        env = _environment_map(self.api["services"]["gateway"]["environment"])
        # Bare list entries in the source are not materialized into key=value
        # pairs until interpolation; the static parser reports an empty value,
        # which is exactly the "not passed unless the operator sets it" shape.
        self.assertEqual(env["NASI_LEMAK_INPUT_GUARD_API_KEY_FILE"], "")
        self.assertEqual(env["NASI_LEMAK_OUTPUT_GUARD_API_KEY_FILE"], "")
        self.assertIn("- NASI_LEMAK_INPUT_GUARD_API_KEY_FILE", self.api_text)
        self.assertIn("- NASI_LEMAK_OUTPUT_GUARD_API_KEY_FILE", self.api_text)
        self.assertNotIn("NASI_LEMAK_INPUT_GUARD_API_KEY=", self.api_text)
        self.assertNotIn("NASI_LEMAK_OUTPUT_GUARD_API_KEY=", self.api_text)

    def test_private_ca_overlay_is_an_explicit_readonly_mount(self):
        gateway = self.ca["services"]["gateway"]
        env = _environment_map(gateway["environment"])
        volume = gateway["volumes"][0]
        self.assertEqual(volume["type"], "bind")
        self.assertEqual(volume["target"], "/run/pilot/guard-ca/ca.pem")
        self.assertIs(volume["read_only"], True)
        self.assertIs(volume["bind"]["create_host_path"], False)
        self.assertIn(":?", volume["source"])
        self.assertEqual(
            env["NASI_LEMAK_INPUT_GUARD_CA_FILE"], volume["target"]
        )
        self.assertEqual(
            env["NASI_LEMAK_OUTPUT_GUARD_CA_FILE"], volume["target"]
        )
        self.assertFalse(
            [key for key in env if key.endswith("_ALLOW_INSECURE_HTTP")]
        )

    def test_packaging_contains_no_embedded_secret_values(self):
        for name, document in (
            ("compose.yaml", self.base),
            ("compose.api.yaml", self.api),
            ("compose.api-ca.yaml", self.ca),
        ):
            for value in _string_values(document):
                with self.subTest(file=name, value=str(value)[:40]):
                    self.assertNotRegex(str(value), _HEX_DIGEST_RE)
                    self.assertNotIn("postgresql://", str(value))
                    self.assertNotIn("BEGIN PRIVATE KEY", str(value))
        self.assertNotIn("API_KEY=", self.example)
        for line in self.example.splitlines():
            if "API_KEY_FILE" in line and not line.lstrip().startswith("#"):
                self.assertIn("/run/secrets/", line)


class DockerfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        cls.order, cls.stages = _dockerfile_stages(cls.text)

    def test_stage_order_and_default_stage_are_lightweight(self):
        self.assertEqual(self.order, ["base", "guards-deps", "guards", "server"])
        # Last stage is the implicit default target; a plain build must not
        # install the optional ML extra.
        self.assertEqual(self.order[-1], "server")
        self.assertIn('".[server]"', "\n".join(self.stages["base"]))
        self.assertNotIn('".[guards]"', "\n".join(self.stages["server"]))

    def test_guards_target_adds_only_existing_guards_extra(self):
        deps = "\n".join(self.stages["guards-deps"])
        guard_runtime = "\n".join(self.stages["guards"])
        self.assertIn("USER root", deps)
        self.assertIn('".[guards]"', deps)
        self.assertNotIn("pip install", guard_runtime)
        self.assertIn("USER 10001:10001", guard_runtime)

    def test_final_runtime_images_drop_to_non_root(self):
        for stage in ("guards", "server"):
            with self.subTest(stage=stage):
                body = "\n".join(self.stages[stage])
                self.assertIn("USER 10001:10001", body)
                self.assertIn("ENTRYPOINT", body)
                self.assertIn('"--no-access-log"', body)

    def test_minimal_copy_allowlist_has_no_workspace_wildcard(self):
        copies = [
            line.strip()
            for line in self.stages["base"]
            if line.lstrip().upper().startswith("COPY ")
        ]
        self.assertEqual(
            copies,
            [
                "COPY --chown=10001:10001 pyproject.toml ./",
                "COPY --chown=10001:10001 nasi_lemak ./nasi_lemak",
            ],
        )
        self.assertNotIn("COPY . .", self.text)

    def test_offline_flags_are_embodied_in_the_image(self):
        body = "\n".join(self.stages["base"])
        for flag in ("HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1", "HF_DATASETS_OFFLINE=1"):
            self.assertIn(flag, body)


class _FakePromptGuard:
    def __init__(self, path, *, threshold):
        self.path = path
        self.threshold = threshold

    def count_tokens(self, serialized):
        return 1

    def scan_attack(self, text):
        return {"decision": "allow"}


class _FakeOutputGuard:
    def __init__(self, path, *, context_limit):
        self.path = path
        self.context_limit = context_limit

    def scan_response(self, messages, output):
        return {"safe": True}


class _FakeClient:
    def __init__(self, config):
        self.config = config

    def generate(self, messages, max_tokens):
        return "synthetic fake output"


class PilotSettingsAcceptanceTests(unittest.TestCase):
    """Proof that the pilot settings are accepted, not that models work."""

    def test_injected_loaders_receive_pilot_guard_settings_and_app_is_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prompt_dir = root / "prompt-guard-2"
            llama_dir = root / "llama-guard-3"
            prompt_dir.mkdir()
            llama_dir.mkdir()
            policy_path = root / "policy.yaml"
            policy_path.write_text(
                "app_id: nasi-lemak\n"
                'version: "2026-10-20.1"\n'
                "model: pilot-local\n"
                "token_budget: 256\n"
                "deny_phrases: []\n",
                encoding="utf-8",
            )

            created = {}

            def prompt_loader(path, *, threshold):
                created["prompt"] = (path, threshold)
                return _FakePromptGuard(path, threshold=threshold)

            def llama_loader(path, *, context_limit):
                created["llama"] = (path, context_limit)
                return _FakeOutputGuard(path, context_limit=context_limit)

            def client_loader(config):
                created["client"] = config
                return _FakeClient(config)

            environ = {
                "NASI_LEMAK_GENERATION_URL": "http://127.0.0.1:9/v1",
                "NASI_LEMAK_GENERATION_MODEL": "operator-confirmed-model",
                "NASI_LEMAK_GENERATION_AUTH": "none",
                "NASI_LEMAK_GENERATION_ALLOW_INSECURE_HTTP": "true",
                "NASI_LEMAK_PROMPT_GUARD_MODEL_DIR": str(prompt_dir),
                "NASI_LEMAK_LLAMA_GUARD_MODEL_DIR": str(llama_dir),
                "NASI_LEMAK_PROMPT_GUARD_THRESHOLD": "0.42",
                "NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT": "512",
                "NASI_LEMAK_POLICY_FILE": str(policy_path),
                "NASI_LEMAK_APP_KEY_DIGEST": "a" * 64,
                "NASI_LEMAK_AUDIT_DSN": "postgresql://unused-in-this-test",
            }

            adapters = make_adapters_from_env(
                environ,
                prompt_guard_loader=prompt_loader,
                llama_guard_loader=llama_loader,
                client_loader=client_loader,
            )
            self.assertIsNotNone(adapters)
            self.assertEqual(created["prompt"], (str(prompt_dir), 0.42))
            self.assertEqual(created["llama"], (str(llama_dir), 512))
            self.assertEqual(created["client"].model, "operator-confirmed-model")

            with mock.patch.object(
                server_module,
                "PostgresAuditStore",
                lambda _dsn: SqliteAuditStore(root / "audit.sqlite3"),
            ):
                app = make_app(environ=environ, adapters=adapters)

            client = TestClient(app)
            try:
                self.assertEqual(client.get("/health/ready").status_code, 200)
            finally:
                client.close()


class WorkspaceComposeTests(unittest.TestCase):
    """Structural checks for the optional workspace overlay and role SQL.

    These parse YAML/text only.  Docker and PostgreSQL are absent, so this is
    configuration-contract evidence, not a compose merge or database run.
    """

    @classmethod
    def setUpClass(cls):
        if yaml is None:
            raise unittest.SkipTest("PyYAML is not installed")
        cls.base = _load("compose.yaml")
        cls.workspace = _load("compose.workspace.yaml")
        cls.workspace_text = (ROOT / "compose.workspace.yaml").read_text(
            encoding="utf-8"
        )
        cls.example = (ROOT / "docs" / "compose.workspace.env.example").read_text(
            encoding="utf-8"
        )

    def test_overlay_adds_only_workspace_environment_and_secrets(self) -> None:
        self.assertEqual(set(self.workspace), {"services", "secrets"})
        self.assertEqual(set(self.workspace["services"]), {"gateway"})
        gateway = self.workspace["services"]["gateway"]
        self.assertEqual(set(gateway), {"environment", "secrets"})
        self.assertEqual(
            set(gateway["environment"]),
            {
                "NASI_LEMAK_WORKSPACE_ENABLED",
                "NASI_LEMAK_WORKSPACE_DSN_FILE",
                "NASI_LEMAK_WORKSPACE_KEY_FILE",
                "NASI_LEMAK_WORKSPACE_ALLOW_HTTP",
            },
        )
        self.assertEqual(gateway["environment"]["NASI_LEMAK_WORKSPACE_ENABLED"], "true")
        self.assertEqual(
            gateway["environment"]["NASI_LEMAK_WORKSPACE_DSN_FILE"],
            "/run/secrets/workspace_dsn",
        )
        self.assertEqual(
            gateway["environment"]["NASI_LEMAK_WORKSPACE_KEY_FILE"],
            "/run/secrets/workspace_key",
        )
        self.assertTrue(
            gateway["environment"]["NASI_LEMAK_WORKSPACE_ALLOW_HTTP"].endswith(
                ":-false}"
            )
        )
        self.assertEqual(gateway["secrets"], ["workspace_dsn", "workspace_key"])
        self.assertNotIn("build", gateway)
        self.assertNotIn("volumes", gateway)
        self.assertNotIn("ports", gateway)
        self.assertNotIn("networks", gateway)
        self.assertNotIn("read_only", gateway)
        self.assertNotIn("user", gateway)
        self.assertNotIn("db", self.workspace["services"])
        for key in self.base["services"]["gateway"]["environment"]:
            self.assertNotIn(key, gateway["environment"])

    def test_overlay_secret_files_are_mandatory_readonly_mounts(self) -> None:
        secrets = self.workspace["secrets"]
        self.assertEqual(set(secrets), {"workspace_dsn", "workspace_key"})
        for name, secret in secrets.items():
            with self.subTest(secret=name):
                self.assertIn(":?", secret["file"])
                self.assertTrue(secret["file"].startswith("${"))
                self.assertIn("_FILE", secret["file"])
        # Docker mounts service secrets read-only under /run/secrets; the
        # overlay declares no privileged container or writable bind.
        self.assertNotIn("privileged", self.workspace["services"]["gateway"])

    def test_example_uses_absolute_paths_and_explicit_http_decision(self) -> None:
        self.assertIn(
            "WORKSPACE_DSN_FILE=/ABSOLUTE/PATH/TO/.secrets/workspace/workspace_dsn",
            self.example,
        )
        self.assertIn(
            "WORKSPACE_KEY_FILE=/ABSOLUTE/PATH/TO/.secrets/workspace/workspace_key",
            self.example,
        )
        self.assertIn("NASI_LEMAK_WORKSPACE_ALLOW_HTTP=true", self.example)
        self.assertNotIn("postgresql://", self.example)
        for value in _string_values(self.workspace):
            with self.subTest(value=str(value)[:40]):
                self.assertNotIn("postgresql://", str(value))
                self.assertNotRegex(str(value), _HEX_DIGEST_RE)

    def test_role_sql_is_fixed_nologin_and_explicitly_scoped(self) -> None:
        text = (ROOT / "nasi_lemak" / "workspace_roles.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("CREATE ROLE nasi_lemak_workspace NOLOGIN", text)
        self.assertIn("RAISE EXCEPTION", text)
        self.assertIn("rolcanlogin", text)
        self.assertIn("rolsuper", text)
        self.assertIn("pg_auth_members", text)
        self.assertIn("GRANT USAGE ON SCHEMA public", text)
        self.assertIn("REVOKE CREATE ON SCHEMA public", text)
        self.assertNotIn("GRANT ALL", text)
        self.assertNotIn("ALL TABLES", text)
        self.assertNotIn("ALTER DEFAULT PRIVILEGES", text)
        self.assertNotIn("nasi_lemak_audit", text)
        self.assertNotIn("export_audits", text)
        self.assertNotRegex(text, r"(?i)\b(events|owners)\b")
        self.assertNotRegex(text, r"(?i)PASSWORD\s+'")
        for table in (
            "ws_schema_migrations",
            "ws_meta",
            "ws_departments",
            "ws_users",
            "ws_sessions",
            "ws_review_grants",
            "ws_conversations",
            "ws_messages",
            "ws_access_log",
        ):
            with self.subTest(table=table):
                self.assertIn(f"public.{table}", text)

        self.assertIn(
            "GRANT SELECT ON TABLE public.ws_schema_migrations", text
        )
        self.assertIn("GRANT SELECT ON TABLE public.ws_meta", text)
        self.assertIn(
            "GRANT SELECT, INSERT ON TABLE public.ws_access_log", text
        )
        self.assertNotRegex(
            text,
            r"GRANT[^;]*(UPDATE|DELETE)[^;]*public\.ws_access_log",
        )
        self.assertNotRegex(
            text,
            r"GRANT[^;]*(INSERT|UPDATE|DELETE)[^;]*public\.ws_schema_migrations",
        )
        self.assertNotRegex(
            text,
            r"GRANT[^;]*(INSERT|UPDATE|DELETE)[^;]*public\.ws_meta",
        )

    def test_sql_files_remain_part_of_the_package(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('nasi_lemak = ["*.sql"]', pyproject)


if __name__ == "__main__":
    unittest.main()
