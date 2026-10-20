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
}

OVERLAY_ENV_KEYS = {
    "NASI_LEMAK_POLICY_FILE",
    "NASI_LEMAK_PROMPT_GUARD_MODEL_DIR",
    "NASI_LEMAK_LLAMA_GUARD_MODEL_DIR",
    "NASI_LEMAK_PROMPT_GUARD_THRESHOLD",
    "NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT",
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
        self.assertEqual(set(gateway["environment"]), BASE_ENV_KEYS)

        db = self.base["services"]["db"]
        self.assertNotIn("ports", db)
        self.assertEqual(db["networks"], ["db_internal"])
        self.assertTrue(self.base["networks"]["db_internal"]["internal"])
        self.assertEqual(set(gateway["networks"]), {"default", "db_internal"})

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
        self.assertEqual(set(gateway["environment"]), OVERLAY_ENV_KEYS)
        self.assertFalse(set(gateway["environment"]) & BASE_ENV_KEYS)
        # The overlay must not reset the inherited non-root/read-only posture.
        for key in ("read_only", "user", "cap_drop", "security_opt", "ports", "networks"):
            with self.subTest(key=key):
                self.assertNotIn(key, gateway)

    def test_overlay_mount_targets_match_runtime_variables(self):
        gateway = self.pilot["services"]["gateway"]
        volumes = gateway["volumes"]
        self.assertEqual(len(volumes), len(EXPECTED_TARGETS))
        by_target = {volume["target"]: volume for volume in volumes}
        self.assertEqual(set(by_target), set(EXPECTED_TARGETS))
        for target, env_name in EXPECTED_TARGETS.items():
            volume = by_target[target]
            with self.subTest(target=target):
                self.assertEqual(volume["type"], "bind")
                self.assertEqual(volume["read_only"], True)
                self.assertIs(volume["bind"]["create_host_path"], False)
                self.assertIn(":?", volume["source"])
                self.assertTrue(volume["source"].startswith("${"))
                self.assertEqual(gateway["environment"][env_name], target)

    def test_overlay_guard_threshold_and_context_are_explicit(self):
        env = self.pilot["services"]["gateway"]["environment"]
        self.assertEqual(
            env["NASI_LEMAK_PROMPT_GUARD_THRESHOLD"],
            "${NASI_LEMAK_PROMPT_GUARD_THRESHOLD:-0.5}",
        )
        self.assertEqual(
            env["NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT"],
            "${NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT:-4096}",
        )
        self.assertNotIn("NASI_LEMAK_GENERATION_MODEL", env)
        for flag in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE", "HF_DATASETS_OFFLINE"):
            self.assertEqual(env[flag], "1")

    def test_overlay_operator_secrets_are_distinct_and_file_backed(self):
        gateway = self.pilot["services"]["gateway"]
        expected = {"operator_key_digest", "operator_audit_dsn"}
        self.assertEqual(set(gateway["secrets"]), expected)
        self.assertFalse(expected & set(self.base["secrets"]))
        self.assertEqual(
            gateway["environment"]["NASI_LEMAK_OPERATOR_KEY_DIGEST_FILE"],
            "/run/secrets/operator_key_digest",
        )
        self.assertEqual(
            gateway["environment"]["NASI_LEMAK_OPERATOR_AUDIT_DSN_FILE"],
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
        # Generation credentials stay file/secret-manager owned; only the
        # non-secret transport settings appear in the base environment.
        self.assertNotIn("NASI_LEMAK_GENERATION_API_KEY", self.base_text)
        self.assertNotIn("NASI_LEMAK_GENERATION_API_KEY", self.pilot_text)


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


if __name__ == "__main__":
    unittest.main()
