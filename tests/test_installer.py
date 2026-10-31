"""Hermetic tests for the Ubuntu installer.

These tests exercise the installer's pure-Python logic with injected command
runners, filesystem operators and a clock; they never call apt, Docker or write
outside a temporary directory.
"""

from __future__ import annotations

import io
import json
import os
import shlex
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from scripts import install
from scripts.install import (
    CommandError,
    CommandResult,
    Credentials,
    InstallError,
    Installer,
    InvalidPathError,
    RealCommandRunner,
    ValidationError,
    atomic_write,
    ensure_within_parent,
    install_docker,
    platform_ops,
    safe_realpath,
    set_platform_ops,
    validate_generation_url,
    validate_port,
)


# ---------------------------------------------------------------------------
# Test seams
# ---------------------------------------------------------------------------
class FakeClock:
    def __init__(self) -> None:
        self._t = 0.0

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += seconds


class FakeStat:
    def __init__(
        self,
        *,
        mode: int = 0o100644,
        uid: int = 0,
        gid: int = 0,
        nlink: int = 1,
        size: int = 0,
    ):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_nlink = nlink
        self.st_size = size


class FakePlatformOps:
    """Delegating filesystem seam that records ownership/chmod and fakes symlinks."""

    enforce_ownership = True

    def __init__(self, tmp: Path, clock: FakeClock):
        self.tmp = tmp
        self.clock = clock
        self.uid = 0
        self.gid = 0
        self.symlinks: set[str] = set()
        self.ownership: dict[str, tuple[int, int]] = {}
        self.modes: dict[str, int] = {}
        self.chown_calls: list[tuple[str, int, int]] = []
        self.chmod_calls: list[tuple[str, int]] = []
        self.mkdir_calls: list[str] = []
        self.sleeps: list[float] = []
        self.read_text_overrides: dict[str, str] = {}
        self.read_text_calls: list[str] = []
        self._lock_paths: dict[int, str] = {}
        self.held_locks: set[str] = set()
        self.env: dict[str, str] = {"PATH": os.environ.get("PATH", "")}
        self.chmod_failures: set[str] = set()
        self.opened_paths: list[str] = []

    def _abs(self, path: Path) -> Path:
        return Path(path).resolve()

    def getuid(self) -> int:
        return self.uid

    def getgid(self) -> int:
        return self.gid

    def lstat(self, path: Path) -> FakeStat:
        key = str(self._abs(path))
        if key in self.symlinks:
            return FakeStat(mode=0o120777, uid=self.uid, gid=self.gid)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            raise
        mode = self.modes.get(key, stat.S_IMODE(st.st_mode))
        uid, gid = self.ownership.get(key, (st.st_uid, st.st_gid))
        return FakeStat(
            mode=(stat.S_IFMT(st.st_mode) | mode),
            uid=uid,
            gid=gid,
            size=st.st_size,
        )

    def mkdir(
        self, path: Path, *, parents: bool = False, exist_ok: bool = False, mode: int = 0o777
    ) -> None:
        self.mkdir_calls.append(str(self._abs(path)))
        path.mkdir(parents=parents, exist_ok=exist_ok)
        self.modes[str(self._abs(path))] = mode

    def chmod(self, path: Path, mode: int) -> None:
        key = str(self._abs(path))
        if key in self.chmod_failures:
            raise PermissionError(1, "operation not permitted")
        self.chmod_calls.append((key, mode))
        self.modes[key] = mode
        os.chmod(path, mode)

    def chown(self, path: Path, uid: int, gid: int) -> None:
        key = str(self._abs(path))
        self.chown_calls.append((key, uid, gid))
        self.ownership[key] = (uid, gid)

    def unlink(self, path: Path) -> None:
        os.unlink(path)

    def rename(self, src: Path, dst: Path) -> None:
        src_key = str(self._abs(src))
        dst_key = str(self._abs(dst))
        if src_key in self.modes:
            self.modes[dst_key] = self.modes.pop(src_key)
        if src_key in self.ownership:
            self.ownership[dst_key] = self.ownership.pop(src_key)
        os.replace(src, dst)

    def fsync(self, fd: int) -> None:
        try:
            os.fsync(fd)
        except OSError:
            pass

    def close(self, fd: int) -> None:
        self.unlock_file(fd)
        os.close(fd)

    def write(self, fd: int, data: bytes) -> int:
        return os.write(fd, data)

    def open_exclusive(self, path: Path, mode: int) -> int:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        self.opened_paths.append(str(self._abs(path)))
        return os.open(path, flags, mode)

    def open_lock(self, path: Path, mode: int) -> int:
        # Persistent lock: create-or-open, never truncate, never unlink.
        flags = os.O_CREAT | os.O_RDWR
        fd = os.open(path, flags, mode)
        self._lock_paths[fd] = str(self._abs(path))
        return fd

    def lock_file(self, fd: int) -> None:
        key = self._lock_paths[fd]
        if key in self.held_locks:
            raise BlockingIOError(11, "resource temporarily unavailable")
        self.held_locks.add(key)

    def unlock_file(self, fd: int) -> None:
        key = self._lock_paths.get(fd)
        if key is not None:
            self.held_locks.discard(key)

    def now(self) -> float:
        return self.clock.now()

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.clock.advance(seconds)

    def is_symlink(self, path: Path) -> bool:
        return str(self._abs(path)) in self.symlinks or path.is_symlink()

    def read_text(self, path: Path) -> str:
        key = str(self._abs(path))
        self.read_text_calls.append(key)
        if key in self.read_text_overrides:
            return self.read_text_overrides[key]
        return path.read_text(encoding="utf-8")

    def write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def resolve(self, path: Path, *, strict: bool = False) -> Path:
        return path.resolve(strict=strict)

    def getenv(self) -> dict[str, str]:
        return dict(self.env)


class FakeRunner:
    """Command runner that matches predicates and returns configured responses."""

    def __init__(self, responses: list[tuple[list[str] | str, CommandResult]] | None = None):
        self.commands: list[tuple[list[str], dict[str, Any]]] = []
        self.responses = responses or []
        self._default = CommandResult(0, "", "")

    def add(self, predicate: list[str] | str, result: CommandResult) -> None:
        self.responses.append((predicate, result))

    def run(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> CommandResult:
        self.commands.append((cmd, {"cwd": cwd, "env": env, "input_text": input_text, "timeout": timeout}))
        result = None
        for predicate, candidate in self.responses:
            if isinstance(predicate, str):
                if predicate in " ".join(cmd):
                    result = candidate
                    break
            else:
                if list(predicate) == list(cmd[: len(predicate)]):
                    # Exact match wins over prefix match.
                    if len(predicate) == len(cmd):
                        result = candidate
                        break
        if result is None:
            result = self._default
        if check and result.returncode != 0:
            raise CommandError(
                f"command failed with exit code {result.returncode}: {shlex.join(cmd)}"
            )
        return result


def _cmd_contains(cmd: list[str], needle: str) -> bool:
    return any(needle in arg for arg in cmd)


class FakeProvisioner:
    """Injected Docker provisioner that records whether it was invoked."""

    def __init__(
        self,
        *,
        conflicts: list[str] | None = None,
        on_install=None,
    ):
        self.conflicts = list(conflicts or [])
        self.on_install = on_install
        self.installed = False

    def conflicting_packages(self, runner: FakeRunner) -> list[str]:
        return list(self.conflicts)

    def install(self, runner: FakeRunner) -> None:
        self.installed = True
        if self.on_install is not None:
            self.on_install(runner)


class ScriptedRunner:
    """Command runner that returns queued results in order."""

    def __init__(self, results: list[CommandResult]):
        self.results = list(results)
        self.commands: list[list[str]] = []

    def run(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> CommandResult:
        self.commands.append(list(cmd))
        if not self.results:
            raise AssertionError("scripted runner exhausted")
        result = self.results.pop(0)
        if check and result.returncode != 0:
            raise CommandError(
                f"command failed with exit code {result.returncode}: {shlex.join(cmd)}"
            )
        return result


DOCKER_KEY_ARMOR = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----\n"


def _gpg_fingerprint_output(fingerprint: str) -> CommandResult:
    return CommandResult(
        0,
        "pub:-:4096:1:ABCDEF0123456789:1700000000:::-:\n"
        f"fpr:::::::::{fingerprint}:\n"
        "uid:-::::1700000000::HASH::Docker Release (CE deb) <docker@docker.com>:\n",
        "",
    )


def _volume_create_cmd() -> list[str]:
    cmd = ["docker", "volume", "create"]
    for key, value in install.expected_volume_labels().items():
        cmd.extend(["--label", f"{key}={value}"])
    cmd.append(install.compose_volume_name())
    return cmd


# ---------------------------------------------------------------------------
# Path validation tests
# ---------------------------------------------------------------------------
class PathValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.base, self.clock)
        set_platform_ops(self.ops)

    def test_spaces_allowed_in_path(self) -> None:
        path = self.base / "my state"
        path.mkdir()
        resolved = safe_realpath(str(path), must_exist=True, allow_symlink=False)
        self.assertTrue(resolved.exists())

    def test_newline_and_metacharacters_rejected(self) -> None:
        for bad in "path;rm -rf\x00/n", "path\nother", "path|cmd", "path$(x)":
            with self.subTest(path=bad):
                with self.assertRaises(InvalidPathError):
                    safe_realpath(str(self.base / bad), allow_symlink=False)

    def test_symlink_rejected_for_state_path(self) -> None:
        real = self.base / "real"
        real.mkdir()
        link = self.base / "link"
        link.mkdir()
        self.ops.symlinks.add(str(link.resolve()))
        with self.assertRaises(InvalidPathError):
            safe_realpath(str(link), must_exist=True, allow_symlink=False)

    def test_traversal_outside_parent_rejected(self) -> None:
        child = safe_realpath(str(self.base / "child"), allow_symlink=False)
        ensure_within_parent(child, self.base)
        outside = Path("/tmp")
        with self.assertRaises(InvalidPathError):
            ensure_within_parent(outside, self.base)


# ---------------------------------------------------------------------------
# Atomic write tests
# ---------------------------------------------------------------------------
class AtomicWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.base, self.clock)
        set_platform_ops(self.ops)

    def test_atomic_write_creates_file_with_mode(self) -> None:
        path = self.base / "secret"
        atomic_write(path, "value\n", 0o600)
        self.assertEqual(path.read_text(encoding="utf-8"), "value\n")
        self.assertEqual(self.ops.modes[str(path.resolve())], 0o600)

    def test_atomic_write_preserves_existing_bytes(self) -> None:
        path = self.base / "secret"
        atomic_write(path, "first\n", 0o600)
        atomic_write(path, "second\n", 0o600)
        self.assertEqual(path.read_text(encoding="utf-8"), "first\n")

    def test_atomic_write_records_ownership(self) -> None:
        path = self.base / "secret"
        atomic_write(path, "value\n", 0o400, owner_uid=10001, owner_gid=10001)
        self.assertEqual(self.ops.ownership[str(path.resolve())], (10001, 10001))

    def test_atomic_overwrite_replaces_existing_bytes(self) -> None:
        path = self.base / "mode"
        atomic_write(path, "test\n", 0o600)
        atomic_write(path, "guarded\n", 0o600, overwrite=True)
        self.assertEqual(path.read_text(encoding="utf-8"), "guarded\n")
        self.assertEqual(self.ops.modes[str(path.resolve())], 0o600)

    def test_atomic_overwrite_refuses_symlink_target(self) -> None:
        path = self.base / "mode"
        path.write_text("test\n", encoding="utf-8")
        self.ops.symlinks.add(str(path.resolve()))
        with self.assertRaises(InstallError):
            atomic_write(path, "guarded\n", 0o600, overwrite=True)
        self.assertEqual(path.read_text(encoding="utf-8"), "test\n")


# ---------------------------------------------------------------------------
# Env writer tests
# ---------------------------------------------------------------------------
class EnvWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()
        self.state = self.project / ".secrets"
        self.state.mkdir()
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.project, self.clock)
        set_platform_ops(self.ops)

    def test_rewrite_updates_changed_url_model_and_port(self) -> None:
        install.write_base_compose_env(
            self.state, self.project, "8000", "https://old.example/v1", "old-model",
            "none", False,
        )
        path = install.write_base_compose_env(
            self.state, self.project, "9001", "https://new.example/v1", "new-model",
            "none", False,
        )
        text = path.read_text(encoding="utf-8")
        self.assertIn("GATEWAY_PORT='9001'", text)
        self.assertIn("NASI_LEMAK_GENERATION_URL='https://new.example/v1'", text)
        self.assertIn("NASI_LEMAK_GENERATION_MODEL='new-model'", text)
        self.assertNotIn("old.example", text)
        self.assertEqual(self.ops.modes[str(path.resolve())], 0o600)

    def test_rewrite_refuses_foreign_env_file(self) -> None:
        path = self.state / "compose.env"
        path.write_text("GATEWAY_PORT='1234'\n", encoding="utf-8")
        with self.assertRaises(InstallError):
            install.write_base_compose_env(
                self.state, self.project, "8000", "https://example/v1", "model",
                "none", False,
            )
        self.assertEqual(path.read_text(encoding="utf-8"), "GATEWAY_PORT='1234'\n")

    def test_guarded_env_rewrites_policy_and_model_paths(self) -> None:
        install.write_guarded_compose_env(
            self.state, self.project, "/old/policy.yaml", "/old/qg"
        )
        path = install.write_guarded_compose_env(
            self.state, self.project, "/new/policy.yaml", "/new/qg"
        )
        text = path.read_text(encoding="utf-8")
        self.assertIn("PILOT_POLICY_FILE='/new/policy.yaml'", text)
        self.assertIn("PILOT_QWEN_GUARD_MODEL_DIR='/new/qg'", text)
        self.assertNotIn("/old/", text)

    def test_guarded_env_carries_qwen_and_reply_pilot_values(self) -> None:
        path = install.write_guarded_compose_env(
            self.state, self.project, "/p.yaml", "/qg"
        )
        text = path.read_text(encoding="utf-8")
        for line in (
            "PILOT_QWEN_GUARD_MODEL_CONTAINER_DIR='/models/qwen3guard-gen-0.6b'",
            "NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD='0.5'",
            "NASI_LEMAK_QWEN3GUARD_OUTPUT_THRESHOLD='0.5'",
            "NASI_LEMAK_QWEN3GUARD_WORKERS='1'",
            "NASI_LEMAK_QWEN3GUARD_THREADS='4'",
            "NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS='384'",
            "NASI_LEMAK_CHAT_MAX_REPLY_TOKENS='512'",
            "NASI_LEMAK_CHAT_CONTEXT_BUDGET='3000'",
            "NASI_LEMAK_CHAT_MAX_CONCURRENCY='1'",
            "NASI_LEMAK_GENERATION_SYSTEM_PROMPT='Answer concisely, in at most about "
            "200 words, unless the user asks for more detail.'",
        ):
            self.assertIn(line, text)

    def test_generated_test_policy_tightens_reply_budget_and_loads(self) -> None:
        from nasi_lemak.policy import load_policy

        policy = install.write_test_policy(self.project)
        loaded = load_policy(policy)
        self.assertEqual(loaded.limits, {"default_reply_tokens": 384})
        self.assertEqual(loaded.model, "pilot-local")

    def test_fresh_test_policy_readable_by_runtime_but_credentials_protected(self) -> None:
        policy = install.write_test_policy(self.project)
        key = str(policy.resolve())
        self.assertEqual(self.ops.modes[key], 0o644)
        self.assertEqual(self.ops.ownership[key], (install.RUNTIME_UID, install.RUNTIME_GID))
        install.ensure_runtime_readable(policy, label="test policy file")

        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        self.assertEqual(
            self.ops.modes[str((self.state / "db_admin_password").resolve())], 0o400
        )
        self.assertEqual(
            self.ops.modes[str((self.state / "chat_key").resolve())], 0o600
        )



# ---------------------------------------------------------------------------
# Credentials tests
# ---------------------------------------------------------------------------
class CredentialsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / ".secrets"
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.state, self.clock)
        set_platform_ops(self.ops)

    def test_credentials_generate_and_preserve_on_reload(self) -> None:
        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        reloaded = Credentials.load_or_generate(self.state)
        self.assertEqual(creds.chat_key, reloaded.chat_key)
        self.assertEqual(creds.operator_key, reloaded.operator_key)
        self.assertEqual(creds.admin_password, reloaded.admin_password)

    def test_dsn_does_not_expose_plaintext_in_repr(self) -> None:
        creds = Credentials.load_or_generate(self.state)
        self.assertNotIn(creds.writer_password, repr(creds))

    def test_unmanaged_state_rejected(self) -> None:
        self.state.mkdir(parents=True)
        (self.state / "chat_key").write_text("leaked", encoding="utf-8")
        with self.assertRaises(InstallError):
            Credentials.load_or_generate(self.state)

    def test_partial_state_resumed_from_manifest(self) -> None:
        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        manifest = json.loads((self.state / install.MANIFEST_FILE).read_text(encoding="utf-8"))
        # Delete one credential file; manifest should recreate exact value.
        (self.state / "writer_password").unlink()
        reloaded = Credentials.load_or_generate(self.state)
        self.assertEqual(creds.writer_password, reloaded.writer_password)
        self.assertEqual(
            (self.state / "writer_password").read_text(encoding="utf-8"),
            creds.writer_password,
        )
        self.assertEqual(reloaded._manifest(), manifest)

    def test_interruption_after_first_secret_recovers_same_material(self) -> None:
        creds = Credentials.load_or_generate(self.state)

        class InterruptingOps(FakePlatformOps):
            def __init__(self, tmp: Path, clock: FakeClock):
                super().__init__(tmp, clock)
                self.renames = 0

            def rename(self, src: Path, dst: Path) -> None:
                self.renames += 1
                # manifest (1), first secret (2), then interrupt.
                if self.renames == 3:
                    raise OSError("simulated interruption")
                super().rename(src, dst)

        interrupting = InterruptingOps(self.state, self.clock)
        set_platform_ops(interrupting)
        try:
            with self.assertRaises(OSError):
                creds.write(self.state)
        finally:
            set_platform_ops(self.ops)

        # The manifest and exactly one secret survived, so the material is
        # recoverable without reading any unrelated state.
        self.assertTrue((self.state / install.MANIFEST_FILE).exists())
        self.assertTrue((self.state / "db_admin_password").exists())
        self.assertFalse((self.state / "writer_password").exists())
        manifest_bytes = (self.state / install.MANIFEST_FILE).read_bytes()

        reloaded = Credentials.load_or_generate(self.state)
        reloaded.write(self.state)
        self.assertEqual(reloaded._manifest()["values"], creds._manifest()["values"])
        for attr, (filename, *_rest) in install.CREDENTIAL_FILES.items():
            self.assertEqual(
                (self.state / filename).read_text(encoding="utf-8"),
                getattr(creds, attr),
                filename,
            )
        self.assertEqual(
            (self.state / install.MANIFEST_FILE).read_bytes(), manifest_bytes
        )

    def test_corrupt_existing_secret_rejected(self) -> None:
        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        (self.state / "chat_key").write_text("rotated-key", encoding="utf-8")
        with self.assertRaises(InstallError):
            Credentials.load_or_generate(self.state)

    def test_existing_derived_files_validated(self) -> None:
        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        creds.write_derived(self.state)
        corrupt = self.state / "audit_dsn"
        corrupt.chmod(0o600)
        corrupt.write_text("postgresql://wrong\n", encoding="utf-8")
        with self.assertRaises(InstallError):
            Credentials.load_or_generate(self.state)

    def test_wrongly_owned_derived_file_rejected(self) -> None:
        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        creds.write_derived(self.state)
        digest = str((self.state / "app_key_digest").resolve())
        self.ops.ownership[digest] = (1000, 1000)
        with self.assertRaises(InstallError):
            Credentials.load_or_generate(self.state)


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------
class ValidationTests(unittest.TestCase):
    def test_port_validation(self) -> None:
        self.assertEqual(validate_port("8000"), "8000")
        for bad in ("0", "65536", "abc", "1.5"):
            with self.subTest(port=bad):
                with self.assertRaises(ValidationError):
                    validate_port(bad)

    def test_url_rejects_userinfo_query_fragment(self) -> None:
        with self.assertRaises(ValidationError):
            validate_generation_url("http://user:pass@host/v1", allow_insecure=True)
        with self.assertRaises(ValidationError):
            validate_generation_url("http://host/v1?x=1", allow_insecure=True)
        with self.assertRaises(ValidationError):
            validate_generation_url("http://host/v1#frag", allow_insecure=True)

    def test_http_requires_explicit_opt_in(self) -> None:
        with self.assertRaises(ValidationError):
            validate_generation_url("http://host/v1", allow_insecure=False)
        self.assertEqual(
            validate_generation_url("http://host/v1", allow_insecure=True),
            "http://host/v1",
        )

    def test_url_rejects_injection(self) -> None:
        with self.assertRaises(ValidationError):
            validate_generation_url("http://host/v1$VAR", allow_insecure=True)


# ---------------------------------------------------------------------------
# Installer mode / dry-run tests
# ---------------------------------------------------------------------------
class ModeValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()
        self.state = self.project / ".secrets"
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.project, self.clock)
        set_platform_ops(self.ops)
        self.runner = FakeRunner()

    def _installer(self, *, mode: str, **kwargs: Any) -> Installer:
        defaults = {
            "project_dir": self.project,
            "state_dir": self.state,
            "mode": mode,
            "port": "8000",
            "generation_url": "https://example.com/v1",
            "generation_model": "model-1",
            "generation_auth": "none",
            "policy_file": None,
            "qwen_guard_dir": None,
            "interactive": False,
            "ack_test_unguarded": False,
            "allow_insecure_http": False,
            "runner": self.runner,
        }
        defaults.update(kwargs)
        return Installer(**defaults)

    def test_rerun_keeps_the_overlays_this_host_uses(self) -> None:
        inst = self._installer(mode="test")
        compose_files = ["compose.yaml", "compose.pilot.yaml"]
        env_files = [self.state / "compose.env"]
        (self.state / "compose.workspace.env").write_text("x=1\n", encoding="utf-8")
        (self.state / "compose.demo.env").write_text("x=1\n", encoding="utf-8")

        inst._add_configured_overlays(compose_files, env_files)

        self.assertEqual(
            compose_files[2:],
            [
                str(self.project / "compose.workspace.yaml"),
                str(self.project / "compose.demo.yaml"),
            ],
        )
        self.assertEqual(
            env_files[1:],
            [self.state / "compose.workspace.env", self.state / "compose.demo.env"],
        )

    def test_overlays_without_env_files_stay_off(self) -> None:
        inst = self._installer(mode="test")
        compose_files = ["compose.yaml"]
        env_files = [self.state / "compose.env"]

        inst._add_configured_overlays(compose_files, env_files)

        self.assertEqual(compose_files, ["compose.yaml"])
        self.assertEqual(env_files, [self.state / "compose.env"])

    def test_demo_bind_ip_is_written_and_refuses_a_wildcard(self) -> None:
        path = install.write_demo_compose_env(self.state, "192.168.90.41")
        self.assertIn("DEMO_BIND_IP='192.168.90.41'", path.read_text(encoding="utf-8"))
        for value in ("0.0.0.0", "::", "not-an-ip"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self._installer(mode="test", demo_bind_ip=value)

    def test_guarded_mode_requires_policy_and_model_dirs(self) -> None:
        # Construction validates all guarded-mode paths are supplied.
        with self.assertRaises(ValidationError):
            self._installer(mode="guarded")
        # If supplied, plan validates the paths point to real files/directories.
        with self.assertRaises(InstallError):
            self._installer(
                mode="guarded",
                policy_file=str(self.project / "missing.yaml"),
            ).plan()

    def test_guarded_local_mode_requires_qwen_guard_dir(self) -> None:
        policy = self._guarded_paths()
        with self.assertRaises(ValidationError) as ctx:
            self._installer(
                mode="guarded",
                policy_file=policy,
            )
        self.assertIn("--qwen-guard-dir", str(ctx.exception))
        with self.assertRaises(InstallError):
            self._installer(
                mode="guarded",
                policy_file=policy,
                qwen_guard_dir=str(self.project / "missing-qg"),
            ).plan()

    def test_guarded_plan_previews_qwen_and_reply_budget(self) -> None:
        policy = self._guarded_paths()
        inst = self._installer(
            mode="guarded",
            policy_file=policy,
            qwen_guard_dir=str(self.project / "qwen_guard"),
        )
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(inst.plan(), 0)
        self.assertIn("Qwen3Guard dir:", out.getvalue())
        self.assertIn("Reply budget:      384 tokens", out.getvalue())

    def test_parser_accepts_qwen_guard_dir(self) -> None:
        args = install.build_parser().parse_args(["--qwen-guard-dir", "/models/qg"])
        self.assertEqual(args.qwen_guard_dir, "/models/qg")

    def test_install_requires_ack_in_non_interactive_use(self) -> None:
        inst = self._installer(mode="test")
        with self.assertRaises(InstallError):
            inst.install()

    def test_read_only_plan_allows_missing_generation_settings(self) -> None:
        inst = self._installer(
            mode="test", generation_url="", generation_model="", ack_test_unguarded=False
        )
        self.assertEqual(inst.plan(), 0)

    def test_install_requires_generation_settings(self) -> None:
        inst = self._installer(
            mode="test",
            generation_url="",
            generation_model="",
            interactive=True,
            ack_test_unguarded=True,
            prompt_fn=lambda _: "yes",
        )
        with self.assertRaises(ValidationError):
            inst.install()

    def test_test_mode_accepted_with_flag(self) -> None:
        inst = self._installer(mode="test", ack_test_unguarded=True)
        self.assertEqual(inst.plan(), 0)

    def test_check_is_read_only(self) -> None:
        inst = self._installer(mode="test", ack_test_unguarded=True)
        self.assertEqual(inst.check(), 0)
        # Read-only checks may probe docker availability but never mutate.
        for cmd, _ in self.runner.commands:
            self.assertNotIn("apt-get", cmd)
            self.assertNotIn("volume create", " ".join(cmd))

    def test_plan_is_read_only(self) -> None:
        inst = self._installer(mode="test", ack_test_unguarded=True)
        self.assertEqual(inst.plan(), 0)
        for cmd, _ in self.runner.commands:
            self.assertNotIn("docker", cmd)

    def test_non_interactive_install_requires_confirmation(self) -> None:
        inst = self._installer(mode="test", ack_test_unguarded=True)
        with self.assertRaises(InstallError):
            inst.install()

    def test_install_requires_root(self) -> None:
        self.ops.uid = 1000
        inst = self._installer(
            mode="test",
            ack_test_unguarded=True,
            interactive=True,
            prompt_fn=lambda _: "yes",
        )
        with self.assertRaises(InstallError):
            inst.install()

    def test_state_dir_chmod_failure_is_reported(self) -> None:
        self.state.mkdir()
        self.ops.chmod_failures.add(str(self.state.resolve()))
        inst = self._installer(mode="test", ack_test_unguarded=True)
        with self.assertRaises(InstallError) as ctx:
            inst._ensure_state_dir_mode()
        self.assertIn("state directory permissions", str(ctx.exception))

    def _guarded_paths(self, *, policy_mode: int = 0o644) -> str:
        policy = self.project / "policy.yaml"
        policy.write_text("app_id: test\n", encoding="utf-8")
        self.ops.modes[str(policy.resolve())] = policy_mode
        (self.project / "qwen_guard").mkdir(exist_ok=True)
        return str(policy)

    def test_read_only_check_and_plan_do_not_repair_permissions(self) -> None:
        policy = self._guarded_paths(policy_mode=0o600)
        inst = self._installer(
            mode="guarded",
            policy_file=policy,
            qwen_guard_dir=str(self.project / "qwen_guard"),
        )
        before_chmod = list(self.ops.chmod_calls)
        before_chown = list(self.ops.chown_calls)
        with mock.patch.object(install, "_check_python3", return_value=None):
            with self.assertRaises(InstallError) as ctx:
                inst.check()
        self.assertIn("chmod a+r", str(ctx.exception))
        with self.assertRaises(InstallError):
            inst.plan()
        self.assertEqual(self.ops.chmod_calls, before_chmod)
        self.assertEqual(self.ops.chown_calls, before_chown)
        self.assertEqual(self.ops.modes[str(Path(policy).resolve())], 0o600)

    def test_readable_policy_check_and_plan_are_mutation_free(self) -> None:
        policy = self._guarded_paths()
        inst = self._installer(
            mode="guarded",
            policy_file=policy,
            qwen_guard_dir=str(self.project / "qwen_guard"),
        )
        before_chmod = list(self.ops.chmod_calls)
        before_chown = list(self.ops.chown_calls)
        with mock.patch.object(install, "_check_python3", return_value=None), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(inst.check(), 0)
            self.assertEqual(inst.plan(), 0)
        self.assertEqual(self.ops.chmod_calls, before_chmod)
        self.assertEqual(self.ops.chown_calls, before_chown)

    def test_cancelled_install_changes_no_permissions_or_marker(self) -> None:
        policy = self._guarded_paths()
        (self.project / "compose.yaml").write_text(
            "name: nasi-lemak\nservices:\n  db:\n  gateway:\n", encoding="utf-8"
        )
        self.ops.read_text_overrides[str(Path("/etc/os-release").resolve())] = (
            "ID=ubuntu\nVERSION_CODENAME=noble\n"
        )
        self.runner.add(["uname", "-m"], CommandResult(0, install.REQUIRED_ARCH, ""))
        inst = self._installer(
            mode="guarded",
            policy_file=policy,
            qwen_guard_dir=str(self.project / "qwen_guard"),
            interactive=True,
            prompt_fn=lambda _: "no",
        )
        before_chmod = list(self.ops.chmod_calls)
        before_chown = list(self.ops.chown_calls)
        with mock.patch.object(install, "_check_python3", return_value=None), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(inst.install(), 1)
        self.assertEqual(self.ops.chmod_calls, before_chmod)
        self.assertEqual(self.ops.chown_calls, before_chown)
        self.assertFalse(self.state.exists())
        self.assertFalse((self.state / ".active_mode").exists())



# ---------------------------------------------------------------------------
# Full install flow tests
# ---------------------------------------------------------------------------
class InstallFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()
        self.state = self.project / ".secrets"
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.project, self.clock)
        self.ops.uid = 0
        set_platform_ops(self.ops)

        # Provide a minimal compose.yaml so config validation can be faked.
        (self.project / "compose.yaml").write_text("name: nasi-lemak\nservices:\n  db:\n  gateway:\n", encoding="utf-8")
        (self.project / "compose.test.yaml").write_text("services:\n  gateway:\n", encoding="utf-8")
        (self.project / "policy.test.yaml").write_text("app_id: test\n", encoding="utf-8")
        # Pretend the host is Ubuntu 24.04 amd64.
        self.ops.read_text_overrides[str(Path("/etc/os-release").resolve())] = (
            "ID=ubuntu\nVERSION_CODENAME=noble\n"
        )

    def _make_runner(self) -> FakeRunner:
        runner = FakeRunner()
        # docker available
        runner.add(["docker", "version"], CommandResult(0, "", ""))
        runner.add(["docker", "compose", "version"], CommandResult(0, "", ""))
        runner.add(["uname", "-m"], CommandResult(0, "x86_64", ""))
        # volume inspect missing -> create the actual Compose-prefixed volume
        runner.add(
            ["docker", "volume", "inspect", install.compose_volume_name()],
            CommandResult(1, "", ""),
        )
        runner.add(_volume_create_cmd(), CommandResult(0, "", ""))
        # config --quiet
        runner.add("config --quiet", CommandResult(0, "", ""))
        # up db
        runner.add("up -d --wait --wait-timeout 120 db", CommandResult(0, "", ""))
        # ps db healthy
        runner.add("ps --format json db", CommandResult(0, '{"Health": "healthy"}', ""))
        # bootstrap roles
        runner.add("exec -T db psql", CommandResult(0, "", ""))
        # up gateway
        runner.add("up -d --build --wait --wait-timeout 300 gateway", CommandResult(0, "", ""))
        # readiness
        runner.add(
            "http://127.0.0.1:8000/health/ready",
            CommandResult(0, json.dumps({"status": "ready", "mode": "test", "guards_active": False}), ""),
        )
        return runner

    def _installer(self, runner: FakeRunner, **kwargs: Any) -> Installer:
        defaults = {
            "project_dir": self.project,
            "state_dir": self.state,
            "mode": "test",
            "port": "8000",
            "generation_url": "https://example.com/v1",
            "generation_model": "model-1",
            "generation_auth": "none",
            "policy_file": None,
            "qwen_guard_dir": str(self.project / "qwen_guard"),
            "interactive": True,
            "ack_test_unguarded": True,
            "allow_insecure_http": False,
            "runner": runner,
            "prompt_fn": lambda _: "yes",
        }
        defaults.update(kwargs)
        return Installer(**defaults)

    def test_fresh_install_all_stage_commands(self) -> None:
        runner = self._make_runner()
        inst = self._installer(runner)
        self.assertEqual(inst.install(), 0)

        commands = [cmd for cmd, _ in runner.commands]
        self.assertTrue(any(cmd[:2] == ["docker", "version"] for cmd in commands))
        self.assertTrue(any(cmd[:3] == ["docker", "compose", "version"] for cmd in commands))
        self.assertTrue(any(cmd[:3] == ["docker", "volume", "inspect"] for cmd in commands))
        self.assertTrue(any(cmd[:4] == ["docker", "volume", "create", "--label"] for cmd in commands))
        self.assertTrue(any("config --quiet" in " ".join(cmd) for cmd in commands))
        self.assertTrue(any("up -d --wait --wait-timeout 120 db" in " ".join(cmd) for cmd in commands))
        self.assertTrue(any("ps --format json db" in " ".join(cmd) for cmd in commands))
        self.assertTrue(any("exec -T db psql" in " ".join(cmd) for cmd in commands))
        self.assertTrue(any("up -d --build --wait --wait-timeout 300 gateway" in " ".join(cmd) for cmd in commands))
        self.assertTrue(any("/health/ready" in " ".join(cmd) for cmd in commands))

        # Active-mode marker persisted.
        self.assertTrue((self.state / ".active_mode").exists())
        self.assertEqual((self.state / ".active_mode").read_text(encoding="utf-8").strip(), "test")

    def test_second_run_stable_credentials(self) -> None:
        runner = self._make_runner()
        inst = self._installer(runner)
        self.assertEqual(inst.install(), 0)
        first_key = (self.state / "chat_key").read_text(encoding="utf-8")

        runner2 = self._make_runner()
        inst2 = self._installer(runner2)
        self.assertEqual(inst2.install(), 0)
        second_key = (self.state / "chat_key").read_text(encoding="utf-8")
        self.assertEqual(first_key, second_key)

    def test_dry_run_no_writes_or_secret_reads(self) -> None:
        runner = FakeRunner()
        inst = self._installer(runner, mode="test", interactive=False, ack_test_unguarded=True)
        self.assertEqual(inst.plan(), 0)
        self.assertFalse(self.state.exists())

    def test_rerun_applies_changed_settings_and_keeps_credentials(self) -> None:
        runner = self._make_runner()
        self.assertEqual(self._installer(runner).install(), 0)
        first_key = (self.state / "chat_key").read_text(encoding="utf-8")

        runner2 = self._make_runner()
        runner2.add(
            "http://127.0.0.1:9001/health/ready",
            CommandResult(
                0,
                json.dumps({"status": "ready", "mode": "test", "guards_active": False}),
                "",
            ),
        )
        inst2 = self._installer(
            runner2,
            port="9001",
            generation_url="https://new.example/v1",
            generation_model="new-model",
        )
        self.assertEqual(inst2.install(), 0)

        env_text = (self.state / "compose.env").read_text(encoding="utf-8")
        self.assertIn("GATEWAY_PORT='9001'", env_text)
        self.assertIn("NASI_LEMAK_GENERATION_URL='https://new.example/v1'", env_text)
        self.assertIn("NASI_LEMAK_GENERATION_MODEL='new-model'", env_text)
        self.assertNotIn("example.com/v1", env_text)
        self.assertEqual(
            (self.state / "chat_key").read_text(encoding="utf-8"), first_key
        )
        self.assertEqual(
            [cmd for cmd, _ in runner2.commands if cmd[:3] == ["docker", "volume", "inspect"]],
            [["docker", "volume", "inspect", install.compose_volume_name()]],
        )
        self.assertEqual(
            (self.state / ".active_mode").read_text(encoding="utf-8").strip(), "test"
        )

    def test_successful_test_to_guarded_transition_updates_marker(self) -> None:
        self.assertEqual(self._installer(self._make_runner()).install(), 0)
        self.assertEqual(
            (self.state / ".active_mode").read_text(encoding="utf-8").strip(), "test"
        )

        (self.project / "policy.yaml").write_text("app_id: test\n", encoding="utf-8")
        (self.project / "qwen_guard").mkdir()
        runner2 = FakeRunner()
        runner2.add(["docker", "version"], CommandResult(0, "", ""))
        runner2.add(["docker", "compose", "version"], CommandResult(0, "", ""))
        runner2.add(["uname", "-m"], CommandResult(0, install.REQUIRED_ARCH, ""))
        runner2.add(
            ["docker", "volume", "inspect", install.compose_volume_name()],
            CommandResult(0, json.dumps([{"Labels": install.expected_volume_labels()}]), ""),
        )
        runner2.add("config --quiet", CommandResult(0, "", ""))
        runner2.add("up -d --wait --wait-timeout 120 db", CommandResult(0, "", ""))
        runner2.add("ps --format json db", CommandResult(0, '{"Health": "healthy"}', ""))
        runner2.add("exec -T db psql", CommandResult(0, "", ""))
        runner2.add("up -d --build --wait --wait-timeout 300 gateway", CommandResult(0, "", ""))
        runner2.add(
            "/health/ready",
            CommandResult(
                0,
                json.dumps({"status": "ready", "mode": "guarded", "guards_active": True}),
                "",
            ),
        )
        inst2 = self._installer(
            runner2,
            mode="guarded",
            policy_file=str(self.project / "policy.yaml"),
        )
        self.assertEqual(inst2.install(), 0)
        self.assertEqual(
            (self.state / ".active_mode").read_text(encoding="utf-8").strip(), "guarded"
        )
        pilot_env = (self.state / "compose.pilot.env").read_text(encoding="utf-8")
        self.assertIn(f"PILOT_POLICY_FILE='{self.project / 'policy.yaml'}'", pilot_env)

    def test_readiness_failure_no_success(self) -> None:
        runner = self._make_runner()
        runner.add(
            "/health/ready",
            CommandResult(0, json.dumps({"status": "not_ready", "mode": "test", "guards_active": False}), ""),
        )
        # Override the default healthy readiness with not_ready by removing the success response
        # and adding a failing one. FakeRunner uses first prefix match, so we need the failing
        # response earlier or exact. Simpler: create runner with only failing readiness.
        runner2 = FakeRunner()
        runner2.add(["docker", "version"], CommandResult(0, "", ""))
        runner2.add(["docker", "compose", "version"], CommandResult(0, "", ""))
        runner2.add(
            ["docker", "volume", "inspect", install.compose_volume_name()],
            CommandResult(1, "", ""),
        )
        runner2.add(_volume_create_cmd(), CommandResult(0, "", ""))
        runner2.add("config --quiet", CommandResult(0, "", ""))
        runner2.add("up -d --wait --wait-timeout 120 db", CommandResult(0, "", ""))
        runner2.add("ps --format json db", CommandResult(0, '{"Health": "healthy"}', ""))
        runner2.add("exec -T db psql", CommandResult(0, "", ""))
        runner2.add("up -d --build --wait --wait-timeout 300 gateway", CommandResult(0, "", ""))
        runner2.add(
            "/health/ready",
            CommandResult(0, json.dumps({"status": "not_ready", "mode": "test", "guards_active": False}), ""),
        )

        inst = self._installer(runner2)
        with self.assertRaises(InstallError):
            inst.install()
        self.assertFalse((self.state / ".active_mode").exists())

    def test_rollback_preserves_previous_mode(self) -> None:
        # First install test mode.
        runner = self._make_runner()
        inst = self._installer(runner)
        self.assertEqual(inst.install(), 0)
        test_env = (self.state / "compose.test.env").read_text(encoding="utf-8")
        base_env = (self.state / "compose.env").read_text(encoding="utf-8")

        # Switch to guarded with a failing gateway start.
        (self.project / "policy.yaml").write_text("app_id: test\n", encoding="utf-8")
        (self.project / "qwen_guard").mkdir()
        runner2 = FakeRunner()
        runner2.add(["docker", "version"], CommandResult(0, "", ""))
        runner2.add(["docker", "compose", "version"], CommandResult(0, "", ""))
        runner2.add(["uname", "-m"], CommandResult(0, install.REQUIRED_ARCH, ""))
        runner2.add(
            ["docker", "volume", "inspect", install.compose_volume_name()],
            CommandResult(0, json.dumps([{"Labels": install.expected_volume_labels()}]), ""),
        )
        runner2.add("config --quiet", CommandResult(0, "", ""))
        runner2.add("up -d --wait --wait-timeout 120 db", CommandResult(0, "", ""))
        runner2.add("ps --format json db", CommandResult(0, '{"Health": "healthy"}', ""))
        runner2.add("exec -T db psql", CommandResult(0, "", ""))
        runner2.add("up -d --build --wait --wait-timeout 300 gateway", CommandResult(1, "", "fail"))

        inst2 = self._installer(
            runner2,
            mode="guarded",
            policy_file=str(self.project / "policy.yaml"),
        )
        stderr = io.StringIO()
        with self.assertRaises(CommandError), redirect_stderr(stderr):
            inst2.install()
        # The gateway startup failure was actually reached and attempted.
        self.assertTrue(
            any(
                "up -d --build --wait --wait-timeout 300 gateway" in " ".join(cmd)
                for cmd, _ in runner2.commands
            )
        )
        # Previous env should be restored.
        self.assertEqual((self.state / "compose.test.env").read_text(encoding="utf-8"), test_env)
        self.assertEqual((self.state / "compose.env").read_text(encoding="utf-8"), base_env)
        self.assertFalse((self.state / "compose.pilot.env").exists())
        # Active mode marker should not change.
        self.assertEqual((self.state / ".active_mode").read_text(encoding="utf-8").strip(), "test")
        message = stderr.getvalue()
        self.assertIn("Previous installer-owned configuration files were restored", message)
        self.assertIn("remains 'test'", message)
        self.assertIn("Running containers were not rolled back automatically", message)


class LockLifecycleTests(unittest.TestCase):
    """Proves lock reuse and mutual exclusion through the platform seam.

    The seam substitutes flock, so the lifecycle is exercised on Windows hosts
    that have no fcntl as well; production ownership/type/mode checks stay in
    RealPlatformOps.open_lock.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.base, self.clock)
        set_platform_ops(self.ops)

    def test_lock_reused_across_runs_and_file_persists(self) -> None:
        fd = install.acquire_lock(self.base)
        lock_path = self.base / ".install.lock"
        inode = os.stat(lock_path).st_ino
        install.release_lock(fd)
        self.assertTrue(lock_path.exists())
        # A rerun must open the same persistent inode and succeed.
        fd2 = install.acquire_lock(self.base)
        self.assertEqual(os.stat(lock_path).st_ino, inode)
        install.release_lock(fd2)
        self.assertTrue(lock_path.exists())

    def test_second_holder_rejected_without_unlinking(self) -> None:
        fd = install.acquire_lock(self.base)
        with self.assertRaises(InstallError):
            install.acquire_lock(self.base)
        self.assertTrue((self.base / ".install.lock").exists())
        install.release_lock(fd)
        fd2 = install.acquire_lock(self.base)
        install.release_lock(fd2)


# ---------------------------------------------------------------------------
# Secret handling tests
# ---------------------------------------------------------------------------
class SecretHandlingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()
        self.state = self.project / ".secrets"
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.project, self.clock)
        set_platform_ops(self.ops)

    def test_bootstrap_sql_hardens_logging_before_secrets(self) -> None:
        runner = FakeRunner()
        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        sql = install.bootstrap_roles_sql(creds.writer_password, creds.reader_password)
        for setting in (
            "SET log_statement = 'none';",
            "SET log_min_error_statement = 'panic';",
        ):
            self.assertIn(setting, sql)
            self.assertLess(
                sql.index(setting),
                sql.index("PASSWORD"),
                f"{setting} must precede secret-bearing DDL",
            )
        # Group roles come from audit_roles.sql; never fabricate them here.
        self.assertNotIn("CREATE ROLE nasi_lemak_audit_writer", sql)
        self.assertNotIn("CREATE ROLE nasi_lemak_audit_reader", sql)
        self.assertIn("required bootstrap role nasi_lemak_audit_writer is missing", sql)
        # Existing roles must not have cross-role or extra memberships.
        self.assertIn("must not be a member of nasi_lemak_audit_reader", sql)
        self.assertIn("must not be a member of nasi_lemak_audit_writer", sql)
        self.assertIn("unexpected extra role memberships", sql)

        install.bootstrap_roles(runner, self.project, ["compose.yaml"], [], creds)
        cmd, kwargs = runner.commands[-1]
        joined = " ".join(cmd)
        self.assertIn("ON_ERROR_STOP=1", cmd)
        self.assertNotIn("PGPASSWORD", joined)
        self.assertNotIn(creds.writer_password, joined)
        self.assertNotIn(creds.reader_password, joined)
        self.assertNotIn("PGPASSWORD", kwargs.get("env") or {})
        self.assertEqual(kwargs["input_text"], sql)
        self.assertIn(creds.writer_password, kwargs["input_text"])

    def test_env_file_values_quoted_no_interpolation(self) -> None:
        from scripts.install import _quote_env_value
        self.assertEqual(_quote_env_value("hello world"), "'hello world'")
        self.assertEqual(_quote_env_value("$VAR"), "'$VAR'")

    def test_digest_files_owned_by_runtime_user(self) -> None:
        creds = Credentials.load_or_generate(self.state)
        creds.write(self.state)
        creds.write_derived(self.state)
        digest_path = str((self.state / "app_key_digest").resolve())
        self.assertEqual(self.ops.ownership.get(digest_path), (10001, 10001))


# ---------------------------------------------------------------------------
# Docker helper tests
# ---------------------------------------------------------------------------
class DockerHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.base, self.clock)
        set_platform_ops(self.ops)

    def test_command_exists_uses_docker_version(self) -> None:
        runner = FakeRunner()
        runner.add(["docker", "version"], CommandResult(0, "", ""))
        runner.add(["docker", "compose", "version"], CommandResult(0, "", ""))
        install_docker(runner)
        self.assertTrue(any(cmd[:2] == ["docker", "version"] for cmd, _ in runner.commands))

    def test_volume_name_matches_base_compose_project(self) -> None:
        # compose.yaml: name: nasi-lemak + volume nasi_lemark_db.
        self.assertEqual(
            install.compose_volume_name(), "nasi-lemak_nasi_lemark_db"
        )
        runner = FakeRunner()
        runner.add(
            ["docker", "volume", "inspect", install.compose_volume_name()],
            CommandResult(1, "", ""),
        )
        install.ensure_installer_volume(runner)
        inspected = [
            cmd for cmd, _ in runner.commands
            if cmd[:3] == ["docker", "volume", "inspect"]
        ]
        self.assertEqual(inspected, [["docker", "volume", "inspect", install.compose_volume_name()]])
        creates = [
            cmd for cmd, _ in runner.commands
            if cmd[:3] == ["docker", "volume", "create"]
        ]
        self.assertEqual(creates, [_volume_create_cmd()])

    def test_unknown_actual_volume_rejected(self) -> None:
        runner = FakeRunner()
        runner.add(
            ["docker", "volume", "inspect", install.compose_volume_name()],
            CommandResult(0, json.dumps([{"Labels": {}}]), ""),
        )
        with self.assertRaises(InstallError):
            install.ensure_installer_volume(runner)
        self.assertFalse(any("up" in cmd for cmd, _ in runner.commands))

    def test_wrong_compose_project_label_rejected(self) -> None:
        labels = install.expected_volume_labels()
        labels[install.COMPOSE_PROJECT_LABEL] = "other-project"
        runner = FakeRunner()
        runner.add(
            ["docker", "volume", "inspect", install.compose_volume_name()],
            CommandResult(0, json.dumps([{"Labels": labels}]), ""),
        )
        with self.assertRaises(InstallError):
            install.ensure_installer_volume(runner)

    def test_nonzero_version_or_compose_probe_is_unavailable(self) -> None:
        broken_version = FakeRunner()
        broken_version.add(["docker", "version"], CommandResult(1, "", ""))
        broken_version.add(["docker", "compose", "version"], CommandResult(0, "", ""))
        self.assertFalse(install._docker_available(broken_version))

        broken_compose = FakeRunner()
        broken_compose.add(["docker", "version"], CommandResult(0, "", ""))
        broken_compose.add(["docker", "compose", "version"], CommandResult(1, "", ""))
        self.assertFalse(install._docker_available(broken_compose))

    def test_present_but_broken_docker_fails_without_apt_or_provisioner(self) -> None:
        runner = FakeRunner()
        runner.add(["docker", "version"], CommandResult(1, "", ""))
        runner.add(["docker", "compose", "version"], CommandResult(1, "", ""))
        runner.add("command -v docker", CommandResult(0, "", ""))
        provisioner = FakeProvisioner()
        with self.assertRaises(InstallError) as ctx:
            install_docker(runner, provisioner)
        self.assertIn("not usable", str(ctx.exception))
        self.assertFalse(provisioner.installed)
        self.assertFalse(
            any(
                cmd[:1] == ["apt-get"] or cmd[:1] == ["curl"]
                for cmd, _ in runner.commands
            )
        )

    def _absent_docker_runner(self) -> FakeRunner:
        runner = FakeRunner()
        runner.add(["docker", "version"], CommandResult(1, "", ""))
        runner.add(["docker", "compose", "version"], CommandResult(1, "", ""))
        runner.add("command -v docker", CommandResult(1, "", ""))
        return runner

    def test_absent_docker_uses_injected_provisioner_without_etc_writes(self) -> None:
        runner = self._absent_docker_runner()

        def make_available(fake: FakeRunner) -> None:
            fake.responses = []
            fake.add(["docker", "version"], CommandResult(0, "", ""))
            fake.add(["docker", "compose", "version"], CommandResult(0, "", ""))

        provisioner = FakeProvisioner(on_install=make_available)
        install_docker(runner, provisioner)
        self.assertTrue(provisioner.installed)
        self.assertFalse(
            any(
                cmd[:1] in (["apt-get"], ["curl"], ["gpg"])
                for cmd, _ in runner.commands
            )
        )
        touched = (
            self.ops.opened_paths
            + self.ops.mkdir_calls
            + [path for path, _ in self.ops.chmod_calls]
            + [path for path, _, _ in self.ops.chown_calls]
        )
        self.assertFalse(
            any("/etc" in path.lower() or "\\etc" in path.lower() for path in touched),
            touched,
        )

    def test_failing_postinstall_capability_probe_fails(self) -> None:
        runner = self._absent_docker_runner()
        provisioner = FakeProvisioner()
        with self.assertRaises(InstallError) as ctx:
            install_docker(runner, provisioner)
        self.assertIn("not responding", str(ctx.exception))
        self.assertTrue(provisioner.installed)
        self.assertFalse(
            any(cmd[:1] in (["apt-get"], ["curl"]) for cmd, _ in runner.commands)
        )

    def test_conflicting_packages_abort_before_provisioning(self) -> None:
        runner = self._absent_docker_runner()
        provisioner = FakeProvisioner(conflicts=["docker.io"])
        with self.assertRaises(InstallError) as ctx:
            install_docker(runner, provisioner)
        self.assertIn("conflicting packages", str(ctx.exception))
        self.assertFalse(provisioner.installed)

    def test_remote_docker_host_and_context_env_rejected(self) -> None:
        self.ops.env["DOCKER_HOST"] = "tcp://203.0.113.5:2376"
        runner = FakeRunner()
        with self.assertRaises(InstallError):
            install_docker(runner, FakeProvisioner())
        self.assertEqual(runner.commands, [])

        self.ops.env.pop("DOCKER_HOST")
        self.ops.env["DOCKER_CONTEXT"] = "remote-box"
        with self.assertRaises(InstallError):
            install_docker(runner, FakeProvisioner())
        self.assertEqual(runner.commands, [])

    def test_persisted_nondefault_context_rejected_before_compose(self) -> None:
        runner = FakeRunner()
        runner.add(["docker", "context", "show"], CommandResult(0, "remote-box\n", ""))
        with self.assertRaises(InstallError) as ctx:
            install_docker(runner, FakeProvisioner())
        self.assertIn("remote", str(ctx.exception))
        self.assertFalse(any(cmd[:2] == ["docker", "version"] for cmd, _ in runner.commands))
        self.assertFalse(any("compose" in cmd for cmd, _ in runner.commands))

    def test_default_context_remote_endpoint_rejected(self) -> None:
        runner = FakeRunner()
        runner.add(["docker", "context", "show"], CommandResult(0, "default\n", ""))
        runner.add(
            [
                "docker", "context", "inspect", "--format",
                "{{.Endpoints.docker.Host}}", "default",
            ],
            CommandResult(0, "tcp://203.0.113.5:2376\n", ""),
        )
        with self.assertRaises(InstallError) as ctx:
            install_docker(runner, FakeProvisioner())
        self.assertIn("remote endpoint", str(ctx.exception))

    def test_compose_env_forces_default_context(self) -> None:
        self.ops.env["DOCKER_CONTEXT"] = "remote-box"
        env = install._sanitized_env()
        self.assertEqual(env["DOCKER_CONTEXT"], "default")
        self.assertNotIn("remote-box", env.values())


class RealDockerProvisionerTests(unittest.TestCase):
    """Exercise the real apt/key handling against temporary directories only."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.base, self.clock)
        set_platform_ops(self.ops)
        self.keyring = self.base / "keyrings"
        self.sources = self.base / "sources"
        for directory in (self.keyring, self.sources):
            directory.mkdir()
            self.ops.modes[str(directory.resolve())] = 0o755
        self.key_path = self.keyring / "docker.asc"
        self.list_path = self.sources / "docker.list"
        self.provisioner = install.RealDockerProvisioner(
            keyring_dir=self.keyring, sources_dir=self.sources
        )

    def _runner(self, fingerprint: str) -> FakeRunner:
        runner = FakeRunner()
        runner.add(["apt-get", "--version"], CommandResult(0, "", ""))
        runner.add(
            ["gpg", "--show-keys", "--with-colons"],
            _gpg_fingerprint_output(fingerprint),
        )
        return runner

    def _write_managed_key(self, mode: int = 0o644) -> None:
        self.key_path.write_text(DOCKER_KEY_ARMOR, encoding="utf-8")
        self.ops.modes[str(self.key_path.resolve())] = mode

    def _write_managed_repo(self, content: str = install.DOCKER_SOURCE_LINE + "\n", mode: int = 0o644) -> None:
        self.list_path.write_text(content, encoding="utf-8")
        self.ops.modes[str(self.list_path.resolve())] = mode

    def test_foreign_existing_key_is_refused(self) -> None:
        self._write_managed_key()
        self._write_managed_repo()
        runner = self._runner("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
        with self.assertRaises(InstallError) as ctx:
            self.provisioner.install(runner)
        self.assertIn(install.DOCKER_SIGNING_FINGERPRINT, str(ctx.exception))
        self.assertEqual(self.key_path.read_text(encoding="utf-8"), DOCKER_KEY_ARMOR)

    def test_unsafe_or_foreign_repository_file_is_refused(self) -> None:
        self._write_managed_key()
        self._write_managed_repo(content="deb [trusted=yes] http://evil.example stable\n")
        runner = self._runner(install.DOCKER_SIGNING_FINGERPRINT)
        with self.assertRaises(InstallError) as ctx:
            self.provisioner.install(runner)
        self.assertIn("unexpected content", str(ctx.exception))

        self._write_managed_repo(content=install.DOCKER_SOURCE_LINE + "\n", mode=0o666)
        runner = self._runner(install.DOCKER_SIGNING_FINGERPRINT)
        with self.assertRaises(InstallError):
            self.provisioner.install(runner)

    def test_key_bundle_with_extra_primary_key_is_refused(self) -> None:
        self._write_managed_key()
        self._write_managed_repo()
        runner = FakeRunner()
        runner.add(["apt-get", "--version"], CommandResult(0, "", ""))
        runner.add(
            ["gpg", "--show-keys", "--with-colons"],
            CommandResult(
                0,
                "pub:-:4096:1:1111111111111111:0:::-:\n"
                f"fpr:::::::::{install.DOCKER_SIGNING_FINGERPRINT}:\n"
                "pub:-:4096:1:2222222222222222:0:::-:\n"
                "fpr:::::::::DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF:\n",
                "",
            ),
        )
        with self.assertRaises(InstallError) as ctx:
            self.provisioner.install(runner)
        self.assertIn("additional primary keys", str(ctx.exception))

    def test_official_fingerprint_allows_existing_files(self) -> None:
        self._write_managed_key()
        self._write_managed_repo()
        runner = self._runner(install.DOCKER_SIGNING_FINGERPRINT)
        self.provisioner.install(runner)
        self.assertFalse(any(cmd[:1] == ["curl"] for cmd, _ in runner.commands))
        self.assertEqual(self.key_path.read_text(encoding="utf-8"), DOCKER_KEY_ARMOR)
        self.assertEqual(
            self.list_path.read_text(encoding="utf-8"),
            install.DOCKER_SOURCE_LINE + "\n",
        )
        self.assertTrue(
            any(cmd[:3] == ["apt-get", "install", "-y"] for cmd, _ in runner.commands)
        )
        self.assertFalse(
            any("/etc" in path.lower() for path in self.ops.opened_paths),
            self.ops.opened_paths,
        )

    def test_downloaded_key_is_verified_before_install(self) -> None:
        runner = self._runner(install.DOCKER_SIGNING_FINGERPRINT)
        runner.add(
            ["curl", "-fsSL", install.DOCKER_KEY_URL],
            CommandResult(0, DOCKER_KEY_ARMOR, ""),
        )
        self.provisioner.install(runner)
        self.assertEqual(self.key_path.read_text(encoding="utf-8"), DOCKER_KEY_ARMOR)
        self.assertEqual(
            self.list_path.read_text(encoding="utf-8"),
            install.DOCKER_SOURCE_LINE + "\n",
        )

    def test_downloaded_key_with_wrong_fingerprint_is_not_installed(self) -> None:
        runner = self._runner("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
        runner.add(
            ["curl", "-fsSL", install.DOCKER_KEY_URL],
            CommandResult(0, DOCKER_KEY_ARMOR, ""),
        )
        with self.assertRaises(InstallError):
            self.provisioner.install(runner)
        self.assertFalse(self.key_path.exists())
        self.assertFalse(self.list_path.exists())


class PostgresHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.base, self.clock)
        set_platform_ops(self.ops)

    def test_only_explicit_healthy_status_is_accepted(self) -> None:
        for payload in (
            "",
            "not json",
            '{"Health": ""}',
            '{"Health": "starting"}',
            '{"Health": "unhealthy"}',
            '{"Health": "unknown"}',
            '{"State": "running"}',
        ):
            with self.subTest(payload=payload):
                self.assertFalse(install._postgres_is_healthy(payload))
        self.assertTrue(install._postgres_is_healthy('{"Health": "healthy"}'))
        self.assertTrue(install._postgres_is_healthy('{"Health": "HEALTHY"}'))

    def test_unhealthy_then_malformed_then_healthy_accepted_with_fake_clock(self) -> None:
        runner = ScriptedRunner([
            CommandResult(0, '{"Health": "unhealthy"}', ""),
            CommandResult(0, "not json", ""),
            CommandResult(0, '{"Health": "healthy"}', ""),
        ])
        install.wait_for_postgres_health(
            runner, self.base, ["compose.yaml"], [], timeout=10.0
        )
        self.assertEqual(len(runner.commands), 3)
        self.assertEqual(self.ops.sleeps, [2.0, 2.0])
        self.assertEqual(self.clock.now(), 4.0)

    def test_malformed_or_unhealthy_status_never_accepted_and_wait_is_finite(self) -> None:
        runner = ScriptedRunner([CommandResult(0, '{"Health": "unhealthy"}', "")] * 3)
        with self.assertRaises(InstallError) as ctx:
            install.wait_for_postgres_health(
                runner, self.base, ["compose.yaml"], [], timeout=5.0
            )
        self.assertIn("did not become healthy", str(ctx.exception))
        self.assertEqual(self.ops.sleeps, [2.0, 2.0, 1.0])
        self.assertEqual(self.clock.now(), 5.0)
        self.assertEqual(len(runner.commands), 3)


class ReadinessRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.clock = FakeClock()
        self.ops = FakePlatformOps(Path(self.tmp.name), self.clock)
        set_platform_ops(self.ops)

    def test_readiness_retries_use_injected_sleep(self) -> None:
        runner = FakeRunner()
        runner.add(
            "http://127.0.0.1:8000/health/ready",
            CommandResult(
                0,
                json.dumps({"status": "not_ready", "mode": "test", "guards_active": False}),
                "",
            ),
        )
        with self.assertRaises(InstallError):
            install.readiness_probe(runner, "8000", "test", False, timeout=5.0)
        # Fake sleep advanced the fake clock; no real time was consumed.
        self.assertEqual(self.ops.sleeps, [2.0, 2.0, 1.0])
        self.assertEqual(self.clock.now(), 5.0)
        probes = [cmd for cmd, _ in runner.commands if "/health/ready" in " ".join(cmd)]
        self.assertEqual(len(probes), 3)


class MainFlagsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()
        self.state = self.project / ".secrets"
        self.clock = FakeClock()
        self.ops = FakePlatformOps(self.project, self.clock)
        set_platform_ops(self.ops)

    def _run_main(self, argv: list[str]) -> tuple[int, FakeRunner]:
        runner = FakeRunner()
        stdin = mock.Mock()
        stdin.isatty.return_value = False
        with mock.patch.object(install, "RealCommandRunner", return_value=runner), \
                mock.patch.object(install, "_check_python3", return_value=None), \
                mock.patch.object(install.sys, "stdin", stdin), \
                mock.patch("builtins.input", side_effect=AssertionError("must not prompt")), \
                redirect_stdout(io.StringIO()):
            rc = install.main(
                argv + ["--project-dir", str(self.project), "--state-dir", ".secrets"]
            )
        return rc, runner

    def test_check_with_no_api_values_is_read_only(self) -> None:
        rc, runner = self._run_main(["--check"])
        self.assertEqual(rc, 0)
        self.assertFalse(self.state.exists())
        self.assertEqual(
            [cmd for cmd, _ in runner.commands],
            [
                ["docker", "context", "show"],
                [
                    "docker", "context", "inspect", "--format",
                    "{{.Endpoints.docker.Host}}", "default",
                ],
                ["docker", "version"],
                ["docker", "compose", "version"],
            ],
        )

    def test_plan_with_no_api_values_is_read_only(self) -> None:
        rc, runner = self._run_main(["--plan"])
        self.assertEqual(rc, 0)
        self.assertFalse(self.state.exists())
        self.assertEqual(runner.commands, [])

    def test_install_without_api_values_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self._run_main([])
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
