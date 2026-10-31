"""Nasi Lemak gateway installer.

A stdlib-only Python module invoked by ``install.sh`` on an existing Ubuntu
24.04 amd64 host.  It is designed to be testable with injected command runners,
filesystem/ownership operators and a clock so the bulk of the logic can be
exercised without touching apt, Docker or the real filesystem.

The installer never downloads model weights, accepts a license on behalf of the
operator, or disables TLS verification.  It generates credentials locally, writes
Compose env files containing paths only, and mutates the system only after
showing a preview and receiving explicit confirmation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows test hosts lack fcntl
    fcntl = None  # type: ignore[assignment]

DEFAULT_PROJECT = "."
DEFAULT_STATE = ".secrets"
DEFAULT_PORT = "8000"
DEFAULT_GENERATION_URL = ""
DEFAULT_GENERATION_MODEL = ""
PROJECT_NAME = "nasi-lemak"
DB_VOLUME = "nasi_lemark_db"
COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
COMPOSE_VOLUME_LABEL = "com.docker.compose.volume"
INSTALLER_LABEL = "managed-by"
INSTALLER_LABEL_VALUE = "nasi-lemak-installer"
RUNTIME_UID = 10001
RUNTIME_GID = 10001
VALID_MODES = ("test", "guarded")

UBUNTU_CODENAME = "noble"
REQUIRED_ARCH = "x86_64"


class InstallError(RuntimeError):
    """Actionable, generic installer failure with no secret content."""


class InvalidPathError(InstallError):
    pass


class CommandError(InstallError):
    pass


class ValidationError(InstallError):
    pass


class PlatformError(InstallError):
    pass


# ---------------------------------------------------------------------------
# Platform abstraction
# ---------------------------------------------------------------------------
class PlatformOps(Protocol):
    def getuid(self) -> int: ...
    def getgid(self) -> int: ...
    def lstat(self, path: Path) -> os.stat_result: ...
    def mkdir(
        self, path: Path, *, parents: bool = False, exist_ok: bool = False, mode: int = 0o777
    ) -> None: ...
    def chmod(self, path: Path, mode: int) -> None: ...
    def chown(self, path: Path, uid: int, gid: int) -> None: ...
    def unlink(self, path: Path) -> None: ...
    def rename(self, src: Path, dst: Path) -> None: ...
    def fsync(self, fd: int) -> None: ...
    def close(self, fd: int) -> None: ...
    def write(self, fd: int, data: bytes) -> int: ...
    def open_exclusive(self, path: Path, mode: int) -> int: ...
    def open_lock(self, path: Path, mode: int) -> int: ...
    def lock_file(self, fd: int) -> None: ...
    def unlock_file(self, fd: int) -> None: ...
    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
    def is_symlink(self, path: Path) -> bool: ...
    def read_text(self, path: Path) -> str: ...
    def write_text(self, path: Path, content: str) -> None: ...
    def resolve(self, path: Path, *, strict: bool = False) -> Path: ...
    def getenv(self) -> dict[str, str]: ...


class RealPlatformOps:
    """Real POSIX/Windows filesystem and process operations."""

    # UID/GID checks are meaningful on POSIX only.
    enforce_ownership = os.name == "posix"

    def getuid(self) -> int:
        return os.getuid()

    def getgid(self) -> int:
        return os.getgid()

    def lstat(self, path: Path) -> os.stat_result:
        return os.lstat(path)

    def mkdir(
        self, path: Path, *, parents: bool = False, exist_ok: bool = False, mode: int = 0o777
    ) -> None:
        path.mkdir(parents=parents, exist_ok=exist_ok)

    def chmod(self, path: Path, mode: int) -> None:
        os.chmod(path, mode)

    def chown(self, path: Path, uid: int, gid: int) -> None:
        shutil.chown(path, user=uid, group=gid)

    def unlink(self, path: Path) -> None:
        os.unlink(path)

    def rename(self, src: Path, dst: Path) -> None:
        os.replace(src, dst)

    def fsync(self, fd: int) -> None:
        os.fsync(fd)

    def close(self, fd: int) -> None:
        os.close(fd)

    def write(self, fd: int, data: bytes) -> int:
        return os.write(fd, data)

    def open_exclusive(self, path: Path, mode: int) -> int:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        return os.open(path, flags, mode)

    def open_lock(self, path: Path, mode: int) -> int:
        """Open (or create) the persistent lock file without truncating it.

        The file is never unlinked, so an active inode cannot be swapped out
        from under a holder.  Owner, type and mode are verified after opening
        so a pre-existing unsafe lock file is rejected rather than followed.
        """
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(path, flags, mode)
        except OSError as exc:
            raise InstallError(f"cannot open installer lock {path}: {exc}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise InstallError(f"installer lock {path} is not a regular file")
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise InstallError(f"installer lock {path} must not be group/world accessible")
            if self.enforce_ownership and (
                st.st_uid != os.geteuid() or st.st_gid != os.getegid()
            ):
                raise InstallError(f"installer lock {path} is not owned by the current user")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def lock_file(self, fd: int) -> None:
        if fcntl is None:  # pragma: no cover - Windows hosts cannot flock
            return
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def unlock_file(self, fd: int) -> None:
        if fcntl is None:  # pragma: no cover - Windows hosts cannot flock
            return
        fcntl.flock(fd, fcntl.LOCK_UN)

    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def is_symlink(self, path: Path) -> bool:
        return path.is_symlink()

    def read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def write_text(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")

    def resolve(self, path: Path, *, strict: bool = False) -> Path:
        return path.resolve(strict=strict)

    def getenv(self) -> dict[str, str]:
        return dict(os.environ)


_PLATFORM_OPS: PlatformOps = RealPlatformOps()


def set_platform_ops(ops: PlatformOps) -> None:
    global _PLATFORM_OPS
    _PLATFORM_OPS = ops


def platform_ops() -> PlatformOps:
    return _PLATFORM_OPS


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
_CONTROL_CHARS = set(map(chr, range(0x20)))
_CONTROL_CHARS.discard("\t")  # allow tab inside files, not in path components

# Forbidden shell metacharacters plus control chars (NUL, CR, LF) and `$`.
_FORBIDDEN_PATH_CHARS = set("|&;<>$`\\\"'(){}[]\x00\n\r") | _CONTROL_CHARS


def _is_allowed_path_char(c: str) -> bool:
    return c not in _FORBIDDEN_PATH_CHARS


def _validate_path_component(text: str) -> None:
    if not text:
        raise InvalidPathError("empty path component")
    if text in (".", ".."):
        raise InvalidPathError("path component is invalid")
    # Permit Windows drive letters at the start of an absolute path.
    if re.fullmatch(r"[A-Za-z]:[/\\]", text):
        return
    if not all(_is_allowed_path_char(c) for c in text):
        raise InvalidPathError("path contains forbidden characters")


def _validate_no_injection(text: str, *, name: str) -> str:
    """Reject CRLF, NUL, $ substitution and common injection characters."""
    if "\x00" in text or "\n" in text or "\r" in text:
        raise ValidationError(f"{name} contains newline or NUL")
    if "$" in text:
        raise ValidationError(f"{name} contains '$' which is not allowed")
    if "`" in text or "|" in text or "&" in text or ";" in text:
        raise ValidationError(f"{name} contains shell metacharacters")
    return text


def validate_port(port: str) -> str:
    if not re.fullmatch(r"[1-9][0-9]{0,4}", port):
        raise ValidationError(f"port must be an integer 1-65535: {port}")
    value = int(port)
    if value > 65535:
        raise ValidationError(f"port out of range: {port}")
    return port


def validate_generation_url(url: str, *, allow_insecure: bool) -> str:
    if not url:
        raise ValidationError("generation URL is required")
    _validate_no_injection(url, name="generation URL")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("generation URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValidationError("generation URL must not contain userinfo")
    if parsed.query:
        raise ValidationError("generation URL must not contain a query string")
    if parsed.fragment:
        raise ValidationError("generation URL must not contain a fragment")
    if parsed.scheme == "http" and not allow_insecure:
        raise ValidationError(
            "plain HTTP generation URL requires explicit acknowledgement "
            "(--allow-insecure-http or interactive confirmation)"
        )
    # Do not log URLs that may still hold sensitive query/fragment data;
    # validation has already stripped those, but keep the rule explicit.
    return url


def validate_model_id(model: str) -> str:
    if not model:
        raise ValidationError("generation model ID is required")
    if len(model) > 256:
        raise ValidationError("generation model ID too long")
    _validate_no_injection(model, name="generation model ID")
    return model


def validate_mode(mode: str) -> str:
    if mode not in VALID_MODES:
        raise ValidationError(f"mode must be one of {VALID_MODES}")
    return mode


def validate_generation_auth(auth: str) -> str:
    if auth not in ("none", "bearer"):
        raise ValidationError("generation-auth must be 'none' or 'bearer'")
    return auth


# ---------------------------------------------------------------------------
# Path utilities
# ---------------------------------------------------------------------------
def safe_realpath(
    path: str | Path, *, must_exist: bool = False, allow_symlink: bool = True
) -> Path:
    """Canonicalize a path and reject traversal, symlinks and unsafe state.

    Spaces in path components are allowed.  Newline, NUL, CR, shell
    metacharacters and ``$`` are rejected.

    When ``allow_symlink`` is ``False`` the original path and every existing
    ancestor is inspected with ``lstat`` before resolution; any symlink in the
    chain is rejected.
    """
    raw = Path(str(path))
    for part in raw.parts:
        _validate_path_component(part)

    if not allow_symlink:
        # Inspect the original path and each ancestor before resolution.
        current = Path(raw.root) if raw.is_absolute() else Path.cwd()
        for idx, part in enumerate(raw.parts):
            if idx == 0 and raw.is_absolute():
                if part.endswith(("/", "\\")):
                    continue
            current = current / part
            try:
                if platform_ops().lstat(current).st_nlink > 0:
                    if platform_ops().is_symlink(current):
                        raise InvalidPathError("symlink is not allowed in state path")
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise InvalidPathError(f"cannot inspect path: {exc}") from exc

    try:
        resolved = platform_ops().resolve(raw, strict=must_exist)
    except (OSError, ValueError) as exc:
        raise InvalidPathError(f"path could not be resolved: {exc}") from None

    if not allow_symlink:
        # A symlink could also be introduced by the resolution itself (for
        # example a symlink in the cwd).  Double-check the resolved path.
        try:
            if platform_ops().is_symlink(resolved):
                raise InvalidPathError("resolved path is a symlink")
        except FileNotFoundError:
            pass

    return resolved


def ensure_within_parent(child: Path, parent: Path) -> None:
    """Fail if child escapes parent after canonicalization."""
    try:
        child.relative_to(parent)
    except ValueError as exc:
        raise InvalidPathError("path escapes the allowed parent directory") from exc


def ensure_safe_state_dir(state_dir: Path) -> None:
    """Reject an existing state directory with unsafe ownership or mode."""
    try:
        st = platform_ops().lstat(state_dir)
    except FileNotFoundError:
        return
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise InvalidPathError(
            f"state directory has unsafe permissions {oct(mode)}; expected no group/other access"
        )
    # Accept root or the runtime owner.  On Windows the uid/gid fields are not
    # meaningful, so this is a no-op there and is validated via injected ops in
    # tests.
    try:
        uid = st.st_uid
    except AttributeError:  # pragma: no cover - Windows
        return
    if uid not in (0, RUNTIME_UID, platform_ops().getuid()):
        raise InvalidPathError(
            f"state directory is owned by uid {uid}; expected root, current user or {RUNTIME_UID}"
        )


# ---------------------------------------------------------------------------
# Command runner
# ---------------------------------------------------------------------------
class CommandRunner(Protocol):
    def run(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout: float | None = None,
        check: bool = True,
    ) -> "CommandResult": ...


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class RealCommandRunner:
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
        try:
            completed = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                input=input_text,
                timeout=timeout,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise CommandError(f"command not found: {cmd[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(f"command timed out: {shlex.join(cmd)}") from exc
        result = CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
        if check and result.returncode != 0:
            raise CommandError(
                f"command failed with exit code {result.returncode}: {shlex.join(cmd)}"
            )
        return result


# ---------------------------------------------------------------------------
# Atomic, durable file writes
# ---------------------------------------------------------------------------
def _secure_temp_name(path: Path) -> Path:
    return path.parent / f".tmp_{secrets.token_hex(8)}"


def atomic_write(
    path: Path,
    content: str,
    mode: int,
    *,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    overwrite: bool = False,
) -> None:
    """Write a file atomically.

    By default an existing file is preserved (credentials are never rotated).
    ``overwrite=True`` atomically replaces installer-owned configuration; a
    symlink at the target is refused rather than followed.  On POSIX
    ``O_NOFOLLOW`` blocks a symlink race on the temporary file.
    """
    if path.exists():
        if not overwrite:
            return
        if platform_ops().is_symlink(path):
            raise InstallError(f"refusing to replace symlink {path}")

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _secure_temp_name(path)
    fd: int | None = None
    try:
        fd = platform_ops().open_exclusive(tmp, 0o600)
        platform_ops().write(fd, content.encode("utf-8"))
        platform_ops().fsync(fd)
        platform_ops().close(fd)
        fd = None
        platform_ops().chmod(tmp, mode)
        if owner_uid is not None:
            platform_ops().chown(tmp, owner_uid, owner_gid if owner_gid is not None else owner_uid)
        platform_ops().rename(tmp, path)
    except Exception:
        if fd is not None:
            try:
                platform_ops().close(fd)
            except OSError:
                pass
        try:
            platform_ops().unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Credentials and manifest
# ---------------------------------------------------------------------------
def generate_password() -> str:
    return secrets.token_urlsafe(24)


def generate_key() -> str:
    return "nk_" + secrets.token_urlsafe(32)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


CREDENTIAL_FILES = {
    "admin_password": ("db_admin_password", 0o400, None, None),
    "writer_password": ("writer_password", 0o600, None, None),
    "reader_password": ("reader_password", 0o600, None, None),
    "chat_key": ("chat_key", 0o600, None, None),
    "operator_key": ("operator_key", 0o600, None, None),
}

MANIFEST_FILE = ".credentials.json"


class Credentials:
    """Holds generated or reused credential bytes.

    Credentials are anchored by a single root-owned manifest file.  A partial
    write can be resumed because the manifest stores the exact material; a
    missing or inconsistent manifest never silently regenerates the database
    password or signing key.
    """

    def __init__(
        self,
        admin_password: str,
        writer_password: str,
        reader_password: str,
        chat_key: str,
        operator_key: str,
    ):
        self.admin_password = admin_password
        self.writer_password = writer_password
        self.reader_password = reader_password
        self.chat_key = chat_key
        self.operator_key = operator_key
        self.chat_key_digest = sha256_hex(chat_key)
        self.operator_key_digest = sha256_hex(operator_key)

    @property
    def audit_dsn(self) -> str:
        return (
            f"postgresql://nasi_lemak_gateway:{self.writer_password}"
            f"@db:5432/nasi_lemak"
        )

    @property
    def operator_audit_dsn(self) -> str:
        return (
            f"postgresql://nasi_lemak_operator:{self.reader_password}"
            f"@db:5432/nasi_lemak"
        )

    def _manifest(self) -> dict[str, Any]:
        return {
            "version": 1,
            "files": {
                filename: sha256_hex(getattr(self, attr))
                for attr, (filename, *_rest) in CREDENTIAL_FILES.items()
            },
            "values": {
                "admin_password": self.admin_password,
                "writer_password": self.writer_password,
                "reader_password": self.reader_password,
                "chat_key": self.chat_key,
                "operator_key": self.operator_key,
            },
        }

    def _derived_contents(self) -> dict[str, str]:
        return {
            "app_key_digest": self.chat_key_digest + "\n",
            "operator_key_digest": self.operator_key_digest + "\n",
            "audit_dsn": self.audit_dsn + "\n",
            "operator_audit_dsn": self.operator_audit_dsn + "\n",
        }

    def _validate_derived(self, state_dir: Path) -> None:
        """Reject corrupt or wrongly-owned derived files; never regenerate them here."""
        enforce_ownership = getattr(platform_ops(), "enforce_ownership", False)
        for filename, expected in self._derived_contents().items():
            path = state_dir / filename
            if not path.exists():
                continue
            if platform_ops().is_symlink(path):
                raise InstallError(f"derived credential file {filename} is a symlink")
            try:
                actual = platform_ops().read_text(path)
            except OSError as exc:
                raise InstallError(
                    f"derived credential file {filename} is unreadable: {exc}"
                ) from exc
            if actual != expected:
                raise InstallError(
                    f"derived credential file {filename} does not match generated material"
                )
            if enforce_ownership:
                try:
                    st = platform_ops().lstat(path)
                except OSError as exc:
                    raise InstallError(
                        f"derived credential file {filename} cannot be inspected: {exc}"
                    ) from exc
                if (st.st_uid, st.st_gid) != (RUNTIME_UID, RUNTIME_GID):
                    raise InstallError(
                        f"derived credential file {filename} is not owned by "
                        f"{RUNTIME_UID}:{RUNTIME_GID}"
                    )

    @classmethod
    def load_or_generate(cls, state_dir: Path) -> "Credentials":
        manifest_path = state_dir / MANIFEST_FILE
        managed_files = {MANIFEST_FILE} | {
            filename for filename, *_rest in CREDENTIAL_FILES.values()
        }
        # Treat digest and DSN files as derived; their presence without a
        # manifest is also unmanaged state.
        derived = {
            "app_key_digest",
            "operator_key_digest",
            "audit_dsn",
            "operator_audit_dsn",
            "compose.env",
            "compose.test.env",
            "compose.pilot.env",
            ".active_mode",
        }
        existing = {p.name for p in state_dir.iterdir()} if state_dir.exists() else set()
        if (existing & (managed_files | derived)) and not manifest_path.exists():
            raise InstallError(
                "state directory contains credential/env files but no manifest; "
                "remove them or back up and start with an empty state directory"
            )

        if manifest_path.exists():
            if platform_ops().is_symlink(manifest_path):
                raise InstallError("credential manifest is a symlink; refusing to use it")
            try:
                manifest = json.loads(platform_ops().read_text(manifest_path))
            except (OSError, json.JSONDecodeError) as exc:
                raise InstallError(f"credential manifest is unreadable: {exc}") from exc
            if not isinstance(manifest, dict) or manifest.get("version") != 1:
                raise InstallError("credential manifest has an unsupported format")
            values = manifest.get("values", {})
            required = {
                "admin_password",
                "writer_password",
                "reader_password",
                "chat_key",
                "operator_key",
            }
            if not isinstance(values, dict) or any(
                not isinstance(values.get(key), str) or not values.get(key)
                for key in required
            ):
                raise InstallError(
                    "credential manifest is incomplete; restore from backup or "
                    "start with an empty state directory"
                )
            instance = cls(**{k: values[k] for k in required})
            expected = instance._manifest()
            if manifest.get("files") != expected["files"]:
                raise InstallError(
                    "credential manifest hashes do not match its stored material"
                )
            # Verify existing files and recreate missing ones from the manifest
            # without generating or rotating any secret.
            for attr, (filename, mode, uid, gid) in CREDENTIAL_FILES.items():
                path = state_dir / filename
                if path.exists():
                    if platform_ops().is_symlink(path):
                        raise InstallError(f"credential file {filename} is a symlink")
                    try:
                        actual = sha256_hex(platform_ops().read_text(path))
                    except OSError as exc:
                        raise InstallError(
                            f"credential file {filename} is unreadable: {exc}"
                        ) from exc
                    if actual != expected["files"][filename]:
                        raise InstallError(
                            f"credential file {filename} does not match manifest"
                        )
                else:
                    atomic_write(
                        path,
                        getattr(instance, attr),
                        mode,
                        owner_uid=uid,
                        owner_gid=gid,
                    )
            instance._validate_derived(state_dir)
            return instance

        return cls(
            admin_password=generate_password(),
            writer_password=generate_password(),
            reader_password=generate_password(),
            chat_key=generate_key(),
            operator_key=generate_key(),
        )

    def write(self, state_dir: Path) -> None:
        """Persist the root-only manifest first, then the individual secrets.

        The manifest is the durable anchor: an interruption after the first
        secret still allows a later run to recreate the exact same material.
        Existing values are never rotated.
        """
        manifest_path = state_dir / MANIFEST_FILE
        payload = self._manifest()
        if manifest_path.exists():
            if platform_ops().is_symlink(manifest_path):
                raise InstallError("credential manifest is a symlink; refusing to overwrite")
            try:
                existing = json.loads(platform_ops().read_text(manifest_path))
            except (OSError, json.JSONDecodeError) as exc:
                raise InstallError(f"credential manifest is unreadable: {exc}") from exc
            if (
                not isinstance(existing, dict)
                or existing.get("version") != 1
                or existing.get("files") != payload["files"]
                or existing.get("values") != payload["values"]
            ):
                raise InstallError(
                    "credential manifest already exists with different material; "
                    "refusing to overwrite or rotate credentials"
                )
        else:
            atomic_write(manifest_path, json.dumps(payload, indent=2) + "\n", 0o600)

        for attr, (filename, mode, uid, gid) in CREDENTIAL_FILES.items():
            atomic_write(
                state_dir / filename,
                getattr(self, attr),
                mode,
                owner_uid=uid,
                owner_gid=gid,
            )

    def write_derived(self, state_dir: Path) -> None:
        """Validate existing derived files, then write missing ones."""
        self._validate_derived(state_dir)
        atomic_write(
            state_dir / "app_key_digest",
            self.chat_key_digest + "\n",
            0o400,
            owner_uid=RUNTIME_UID,
            owner_gid=RUNTIME_GID,
        )
        atomic_write(
            state_dir / "operator_key_digest",
            self.operator_key_digest + "\n",
            0o400,
            owner_uid=RUNTIME_UID,
            owner_gid=RUNTIME_GID,
        )
        atomic_write(
            state_dir / "audit_dsn",
            self.audit_dsn + "\n",
            0o400,
            owner_uid=RUNTIME_UID,
            owner_gid=RUNTIME_GID,
        )
        atomic_write(
            state_dir / "operator_audit_dsn",
            self.operator_audit_dsn + "\n",
            0o400,
            owner_uid=RUNTIME_UID,
            owner_gid=RUNTIME_GID,
        )


# ---------------------------------------------------------------------------
# Env-file generation (safe quoting, no Compose interpolation)
# ---------------------------------------------------------------------------
def _quote_env_value(value: str) -> str:
    """Single-quote a value so Compose treats it literally."""
    if "'" in value:
        raise ValidationError("env value contains a single quote")
    if "\n" in value or "\r" in value or "\x00" in value:
        raise ValidationError("env value contains newline or NUL")
    return f"'{value}'"


def _env_line(name: str, value: str) -> str:
    _validate_no_injection(name, name="env variable name")
    return f"{name}={_quote_env_value(value)}"


BASE_ENV_HEADER = "# Generated by the Nasi Lemak installer. Do not commit."
TEST_ENV_HEADER = "# Generated by the Nasi Lemak installer for test mode. Do not commit."
PILOT_ENV_HEADER = "# Generated by the Nasi Lemak installer for guarded mode. Do not commit."
DEMO_ENV_HEADER = "# Generated by the Nasi Lemak installer for the demo ingress. Do not commit."
TEST_POLICY_HEADER = "# Generated by the Nasi Lemak installer for test mode."


def _write_installer_file(
    path: Path,
    content: str,
    mode: int,
    *,
    header: str,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
) -> None:
    """Atomically replace an installer-owned file, refusing foreign content.

    Existing files created by an operator are never overwritten.  Files whose
    first line carries the expected generated marker are replaced atomically so
    changed settings take effect on rerun.
    """
    if path.exists():
        if platform_ops().is_symlink(path):
            raise InstallError(f"refusing to replace symlink {path}")
        try:
            existing = platform_ops().read_text(path)
        except OSError as exc:
            raise InstallError(f"cannot inspect existing configuration {path}: {exc}") from exc
        if not existing.startswith(header):
            raise InstallError(
                f"{path} exists but was not generated by this installer; "
                "move it aside or pass a different path"
            )
    atomic_write(
        path,
        content,
        mode,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        overwrite=True,
    )


def write_base_compose_env(
    state_dir: Path,
    project_dir: Path,
    port: str,
    generation_url: str,
    generation_model: str,
    generation_auth: str,
    allow_insecure_http: bool,
) -> Path:
    """Write .secrets/compose.env, replacing installer-owned settings."""
    env_path = state_dir / "compose.env"
    lines = [
        BASE_ENV_HEADER,
        _env_line("DB_ADMIN_PASSWORD_FILE", str(state_dir / "db_admin_password")),
        _env_line("AUDIT_DSN_FILE", str(state_dir / "audit_dsn")),
        _env_line("APP_KEY_DIGEST_FILE", str(state_dir / "app_key_digest")),
        _env_line("POSTGRES_ADMIN_USER", "nasi_lemak_admin"),
        _env_line("GATEWAY_PORT", port),
        _env_line("NASI_LEMAK_GENERATION_URL", generation_url),
        _env_line("NASI_LEMAK_GENERATION_AUTH", generation_auth),
        _env_line(
            "NASI_LEMAK_GENERATION_ALLOW_INSECURE_HTTP",
            "true" if allow_insecure_http else "false",
        ),
        _env_line("NASI_LEMAK_GENERATION_MODEL", generation_model),
        "",
    ]
    _write_installer_file(env_path, "\n".join(lines), 0o600, header=BASE_ENV_HEADER)
    return env_path


def write_test_compose_env(state_dir: Path, project_dir: Path) -> Path:
    env_path = state_dir / "compose.test.env"
    policy_file = project_dir / "policy.test.yaml"
    lines = [
        TEST_ENV_HEADER,
        _env_line("TEST_POLICY_FILE", str(policy_file)),
        _env_line("OPERATOR_KEY_DIGEST_FILE", str(state_dir / "operator_key_digest")),
        _env_line("OPERATOR_AUDIT_DSN_FILE", str(state_dir / "operator_audit_dsn")),
        "",
    ]
    _write_installer_file(env_path, "\n".join(lines), 0o600, header=TEST_ENV_HEADER)
    return env_path


# compose.pilot.yaml mounts Qwen3Guard-Gen at this fixed container directory and
# runs it as the active guard; the Meta directories stay mounted alongside.
QWEN_GUARD_CONTAINER_DIR = "/models/qwen3guard-gen-0.6b"
# Pilot values measured on the 4-vCPU guard VM (docs/rca-2026-10-29-generation-
# truncation-503.md): one guard worker with four threads, and replies short
# enough for the CPU output scan to finish inside the work deadline.
PILOT_QWEN_THRESHOLD = "0.5"
PILOT_QWEN_WORKERS = "1"
PILOT_QWEN_THREADS = "4"
PILOT_DEFAULT_REPLY_TOKENS = "384"
PILOT_MAX_REPLY_TOKENS = "512"
# The guard scans the whole selected history, so the history is bounded too: on
# 4 vCPU a full 8192-unit context would pass the 60 s work deadline.
PILOT_CONTEXT_BUDGET = "3000"
# One guard worker serves one scan at a time.  Admitting more only queues them.
PILOT_MAX_CONCURRENCY = "1"
PILOT_GENERATION_SYSTEM_PROMPT = (
    "Answer concisely, in at most about 200 words, unless the user asks for more detail."
)


def write_guarded_compose_env(
    state_dir: Path,
    project_dir: Path,
    policy_file: str,
    qwen_guard_dir: str,
) -> Path:
    env_path = state_dir / "compose.pilot.env"
    lines = [
        PILOT_ENV_HEADER,
        _env_line("PILOT_POLICY_FILE", policy_file),
        _env_line("PILOT_QWEN_GUARD_MODEL_DIR", qwen_guard_dir),
        _env_line("PILOT_QWEN_GUARD_MODEL_CONTAINER_DIR", QWEN_GUARD_CONTAINER_DIR),
        _env_line("NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD", PILOT_QWEN_THRESHOLD),
        _env_line("NASI_LEMAK_QWEN3GUARD_OUTPUT_THRESHOLD", PILOT_QWEN_THRESHOLD),
        _env_line("NASI_LEMAK_QWEN3GUARD_WORKERS", PILOT_QWEN_WORKERS),
        _env_line("NASI_LEMAK_QWEN3GUARD_THREADS", PILOT_QWEN_THREADS),
        _env_line("NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS", PILOT_DEFAULT_REPLY_TOKENS),
        _env_line("NASI_LEMAK_CHAT_MAX_REPLY_TOKENS", PILOT_MAX_REPLY_TOKENS),
        _env_line("NASI_LEMAK_CHAT_CONTEXT_BUDGET", PILOT_CONTEXT_BUDGET),
        _env_line("NASI_LEMAK_CHAT_MAX_CONCURRENCY", PILOT_MAX_CONCURRENCY),
        _env_line("NASI_LEMAK_GENERATION_SYSTEM_PROMPT", PILOT_GENERATION_SYSTEM_PROMPT),
        _env_line("GUARD_MEM_LIMIT", "8g"),
        _env_line("GUARD_CPUS", "4.0"),
        _env_line("GUARD_PIDS_LIMIT", "512"),
        _env_line("OPERATOR_KEY_DIGEST_FILE", str(state_dir / "operator_key_digest")),
        _env_line("OPERATOR_AUDIT_DSN_FILE", str(state_dir / "operator_audit_dsn")),
        "",
    ]
    _write_installer_file(env_path, "\n".join(lines), 0o600, header=PILOT_ENV_HEADER)
    return env_path


def validate_demo_bind_ip(value: str) -> str:
    """Return a specific host address; a wildcard would expose the demo widely."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError("--demo-bind-ip must be an IP address") from None
    if address.is_unspecified:
        raise ValidationError("--demo-bind-ip must be this host's LAN or VPN address")
    return str(address)


def write_demo_compose_env(state_dir: Path, bind_ip: str) -> Path:
    env_path = state_dir / "compose.demo.env"
    lines = [DEMO_ENV_HEADER, _env_line("DEMO_BIND_IP", bind_ip), ""]
    _write_installer_file(env_path, "\n".join(lines), 0o600, header=DEMO_ENV_HEADER)
    return env_path


def _runtime_can_read(st: os.stat_result) -> bool:
    mode = stat.S_IMODE(st.st_mode)
    uid = getattr(st, "st_uid", 0)
    gid = getattr(st, "st_gid", 0)
    if uid == RUNTIME_UID:
        return bool(mode & 0o400)
    if gid == RUNTIME_GID:
        return bool(mode & 0o040)
    return bool(mode & 0o004)


def ensure_runtime_readable(path: Path, *, label: str) -> None:
    """Verify a bind-mounted non-secret config file is readable by UID 10001.

    This is deliberately read-only: ``--check``, ``--plan`` and the pre-flight
    confirmation must never change operator-owned permissions.  An unreadable
    artifact is refused with an actionable message instead of being repaired.
    """
    try:
        st = platform_ops().lstat(path)
    except OSError as exc:
        raise InstallError(f"{label} {path} cannot be inspected: {exc}") from exc
    if not stat.S_ISREG(st.st_mode):
        raise InstallError(f"{label} {path} is not a regular file")
    if not _runtime_can_read(st):
        raise InstallError(
            f"{label} {path} is not readable by runtime UID {RUNTIME_UID}; "
            f"run: chmod a+r {path}"
        )


def write_test_policy(project_dir: Path) -> Path:
    path = project_dir / "policy.test.yaml"
    content = TEST_POLICY_HEADER + """\napp_id: nasi-lemak
version: "test-1"
model: pilot-local
token_budget: 256
deny_phrases:
  - "synthetic denied phrase"
# Optional: may only tighten the env chat limits (docs/chat-limits.md).
limits:
  default_reply_tokens: """ + PILOT_DEFAULT_REPLY_TOKENS + """
"""
    if path.exists():
        if platform_ops().is_symlink(path):
            raise InstallError(f"refusing to use symlinked policy file {path}")
        try:
            existing = platform_ops().read_text(path)
        except OSError as exc:
            raise InstallError(f"cannot read policy file {path}: {exc}") from exc
        if existing.startswith(TEST_POLICY_HEADER):
            atomic_write(
                path,
                content,
                0o644,
                owner_uid=RUNTIME_UID,
                owner_gid=RUNTIME_GID,
                overwrite=True,
            )
        else:
            # Operator-supplied policy: preserve content, only verify access.
            ensure_runtime_readable(path, label="test policy file")
            return path
    else:
        atomic_write(
            path,
            content,
            0o644,
            owner_uid=RUNTIME_UID,
            owner_gid=RUNTIME_GID,
        )
    ensure_runtime_readable(path, label="test policy file")
    return path


def write_active_mode(state_dir: Path, mode: str) -> None:
    """Atomically replace the marker after the matching mode is ready."""
    atomic_write(state_dir / ".active_mode", mode + "\n", 0o600, overwrite=True)



def read_active_mode(state_dir: Path) -> str | None:
    path = state_dir / ".active_mode"
    if not path.exists():
        return None
    return platform_ops().read_text(path).strip()


# ---------------------------------------------------------------------------
# Docker / Compose helpers
# ---------------------------------------------------------------------------
def _check_python3() -> None:
    if shutil.which("python3") is None:
        raise InstallError(
            "python3 is required. Install it with your system package manager "
            "or an approved bootstrap before running the installer."
        )


CONFLICTING_DOCKER_PACKAGES = (
    "docker.io",
    "docker-compose",
    "docker-compose-v2",
    "podman-docker",
    "containerd",
    "runc",
)
DOCKER_KEY_URL = "https://download.docker.com/linux/ubuntu/gpg"
DOCKER_SIGNING_FINGERPRINT = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
DOCKER_SOURCE_LINE = (
    "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] "
    "https://download.docker.com/linux/ubuntu noble stable"
)


def _docker_probe(runner: CommandRunner) -> tuple[CommandResult | None, CommandResult | None]:
    """Run the two capability probes, distinguishing failure from absence."""
    results: list[CommandResult | None] = []
    for cmd in (["docker", "version"], ["docker", "compose", "version"]):
        try:
            results.append(runner.run(cmd, check=False, timeout=10.0))
        except CommandError:
            results.append(None)
    return results[0], results[1]


def _docker_available(runner: CommandRunner) -> bool:
    """True only when both Docker and the Compose plugin exit successfully."""
    version, compose = _docker_probe(runner)
    return (
        version is not None
        and compose is not None
        and version.returncode == 0
        and compose.returncode == 0
    )


def _command_present(runner: CommandRunner, name: str) -> bool:
    try:
        result = runner.run(
            ["sh", "-c", f"command -v {name} >/dev/null 2>&1"],
            check=False,
            timeout=10.0,
        )
    except CommandError:
        return False
    return result.returncode == 0


def _ensure_local_docker_daemon(runner: CommandRunner | None = None) -> None:
    """Reject remote Docker endpoints; every bind mount requires a local daemon.

    ``DOCKER_HOST``/``DOCKER_CONTEXT`` can be unset while a remote context is
    persisted in the Docker CLI configuration.  When a runner is supplied, ask
    the CLI which context is effective and reject anything that is not the
    local default.  The context is only inspected, never mutated.
    """
    env = platform_ops().getenv()
    host = env.get("DOCKER_HOST", "").strip()
    if host and not (host.startswith("unix://") or host.startswith("npipe://")):
        raise InstallError(
            "DOCKER_HOST points to a remote Docker daemon; local bind mounts "
            "require a local daemon. Unset DOCKER_HOST or use a local unix socket."
        )
    context = env.get("DOCKER_CONTEXT", "").strip()
    if context and context != "default":
        raise InstallError(
            f"DOCKER_CONTEXT={context} selects a non-default Docker context; "
            "remote contexts are not supported because bind mounts require a "
            "local daemon. Use DOCKER_CONTEXT=default."
        )
    if runner is None:
        return
    # Inspect the persisted CLI configuration without any DOCKER_CONTEXT
    # override, otherwise `DOCKER_CONTEXT=default` could mask a remote context
    # stored in ~/.docker/config.json.
    inspect_env = dict(env)
    inspect_env.pop("DOCKER_CONTEXT", None)
    try:
        shown = runner.run(
            ["docker", "context", "show"], check=False, timeout=10.0, env=inspect_env
        )
    except CommandError:
        # Docker may be absent; install_docker handles provisioning.
        return
    if shown.returncode != 0:
        return
    effective = shown.stdout.strip()
    if effective and effective != "default":
        raise InstallError(
            f"the effective Docker context is {effective!r}; remote or "
            "non-default contexts are not supported because bind mounts require "
            "the local default daemon. Select the default context explicitly."
        )
    try:
        endpoint = runner.run(
            [
                "docker", "context", "inspect", "--format",
                "{{.Endpoints.docker.Host}}", "default",
            ],
            check=False,
            timeout=10.0,
            env=inspect_env,
        )
    except CommandError:
        return
    docker_host = endpoint.stdout.strip()
    if (
        endpoint.returncode == 0
        and docker_host
        and not (docker_host.startswith("unix://") or docker_host.startswith("npipe://"))
    ):
        raise InstallError(
            "the Docker default context points to a remote endpoint "
            f"({docker_host}); local bind mounts require a local unix socket."
        )


def _docker_key_fingerprints(
    runner: CommandRunner, armored_key: str
) -> tuple[set[str], set[str]]:
    """Return (all, primary) OpenPGP fingerprints via bounded gpg.

    The key travels on stdin, so no path is interpolated into a shell and no
    key material is logged.  ``--show-keys`` only reads the key; it does not
    import or trust it.
    """
    try:
        result = runner.run(
            ["gpg", "--show-keys", "--with-colons"],
            input_text=armored_key,
            timeout=10.0,
            check=False,
        )
    except CommandError as exc:
        raise InstallError(
            "cannot verify the Docker signing key fingerprint because gpg is "
            "unavailable; install gnupg and re-run"
        ) from exc
    if result.returncode != 0:
        raise InstallError(
            "cannot verify the Docker signing key fingerprint; gpg rejected the key"
        )
    fingerprints: set[str] = set()
    primary: set[str] = set()
    current_record: str | None = None
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if not fields:
            continue
        record = fields[0]
        if record in ("pub", "sub"):
            current_record = record
            continue
        if record == "fpr" and len(fields) >= 10:
            fingerprint = fields[9].strip().upper()
            if fingerprint:
                fingerprints.add(fingerprint)
                if current_record == "pub":
                    primary.add(fingerprint)
            current_record = None
    return fingerprints, primary


def _verify_docker_signing_key(runner: CommandRunner, armored_key: str) -> None:
    """Refuse anything that is not the official Docker signing key."""
    if "BEGIN PGP PUBLIC KEY BLOCK" not in armored_key:
        raise InstallError(
            "Docker signing key is not an ASCII-armored PGP public key"
        )
    fingerprints, primary = _docker_key_fingerprints(runner, armored_key)
    if DOCKER_SIGNING_FINGERPRINT not in fingerprints:
        raise InstallError(
            "Docker signing key does not match the official fingerprint "
            f"{DOCKER_SIGNING_FINGERPRINT}; refusing to trust or overwrite it. "
            "Remove the file only after verifying it manually."
        )
    if primary and primary != {DOCKER_SIGNING_FINGERPRINT}:
        raise InstallError(
            "Docker signing key file contains additional primary keys; "
            "refusing to trust a bundle that is not exactly the official key"
        )


class DockerProvisioner(Protocol):
    def conflicting_packages(self, runner: CommandRunner) -> list[str]: ...

    def install(self, runner: CommandRunner) -> None: ...


class RealDockerProvisioner:
    """Real apt/repository operations for a genuinely absent Docker install.

    Tests inject a fake provisioner, so no test branch can write to /etc.
    Existing keyring/repository files are reused only after ownership and
    content verification; otherwise the installer refuses instead of replacing
    operator-managed files.
    """

    def __init__(
        self,
        *,
        keyring_dir: Path = Path("/etc/apt/keyrings"),
        sources_dir: Path = Path("/etc/apt/sources.list.d"),
    ):
        self.keyring_dir = keyring_dir
        self.sources_dir = sources_dir

    def conflicting_packages(self, runner: CommandRunner) -> list[str]:
        found: list[str] = []
        for package in CONFLICTING_DOCKER_PACKAGES:
            try:
                result = runner.run(
                    ["dpkg-query", "-W", "-f=${Status}", package],
                    check=False,
                    timeout=10.0,
                )
            except CommandError:
                continue
            if result.returncode == 0 and "install ok installed" in result.stdout:
                found.append(package)
        return found

    def _verify_managed_file(
        self, path: Path, *, exact: str | None = None, marker: str | None = None
    ) -> None:
        if platform_ops().is_symlink(path):
            raise InstallError(f"{path} is a symlink; refusing to use it")
        try:
            st = platform_ops().lstat(path)
            content = platform_ops().read_text(path)
        except OSError as exc:
            raise InstallError(f"cannot inspect existing {path}: {exc}") from exc
        if not stat.S_ISREG(st.st_mode):
            raise InstallError(f"{path} is not a regular file; refusing to use it")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o022:
            raise InstallError(
                f"{path} is group/world writable ({oct(mode)}); refusing to use it"
            )
        if getattr(platform_ops(), "enforce_ownership", False) and st.st_uid != 0:
            raise InstallError(f"{path} is not owned by root; refusing to use it")
        if exact is not None and content.strip() != exact:
            raise InstallError(
                f"{path} exists with unexpected content; refusing to overwrite it"
            )
        if marker is not None and marker not in content:
            raise InstallError(
                f"{path} does not contain the expected Docker signing key; "
                "refusing to overwrite it"
            )

    def _ensure_root_dir(self, path: Path) -> None:
        if path.exists():
            if platform_ops().is_symlink(path):
                raise InstallError(f"{path} is a symlink; refusing to use it")
            try:
                st = platform_ops().lstat(path)
            except OSError as exc:
                raise InstallError(f"cannot inspect {path}: {exc}") from exc
            if not stat.S_ISDIR(st.st_mode):
                raise InstallError(f"{path} is not a directory")
            if stat.S_IMODE(st.st_mode) & 0o022:
                raise InstallError(f"{path} is group/world writable; refusing to use it")
            if getattr(platform_ops(), "enforce_ownership", False) and st.st_uid != 0:
                raise InstallError(f"{path} is not owned by root; refusing to use it")
            return
        platform_ops().mkdir(path, parents=True, exist_ok=True, mode=0o755)
        platform_ops().chmod(path, 0o755)

    def install(self, runner: CommandRunner) -> None:
        try:
            apt = runner.run(["apt-get", "--version"], check=False, timeout=10.0)
        except CommandError as exc:
            raise InstallError(
                "Docker is not installed and apt-get is unavailable. "
                "Install Docker manually before re-running the installer."
            ) from exc
        if apt.returncode != 0:
            raise InstallError(
                "Docker is not installed and apt-get is not usable. "
                "Install Docker manually before re-running the installer."
            )

        runner.run(["apt-get", "update"], timeout=120.0)
        runner.run(
            ["apt-get", "install", "-y", "ca-certificates", "curl", "gnupg"],
            timeout=300.0,
        )

        self._ensure_root_dir(self.keyring_dir)
        key_path = self.keyring_dir / "docker.asc"
        if key_path.exists():
            self._verify_managed_file(
                key_path, marker="BEGIN PGP PUBLIC KEY BLOCK"
            )
            try:
                existing_key = platform_ops().read_text(key_path)
            except OSError as exc:
                raise InstallError(
                    f"cannot read existing Docker signing key {key_path}: {exc}"
                ) from exc
            _verify_docker_signing_key(runner, existing_key)
        else:
            result = runner.run(["curl", "-fsSL", DOCKER_KEY_URL], timeout=60.0)
            _verify_docker_signing_key(runner, result.stdout)
            atomic_write(key_path, result.stdout, 0o644)

        self._ensure_root_dir(self.sources_dir)
        list_path = self.sources_dir / "docker.list"
        if list_path.exists():
            self._verify_managed_file(list_path, exact=DOCKER_SOURCE_LINE)
        else:
            atomic_write(list_path, DOCKER_SOURCE_LINE + "\n", 0o644)

        runner.run(["apt-get", "update"], timeout=120.0)
        runner.run(
            [
                "apt-get", "install", "-y",
                "docker-ce", "docker-ce-cli", "containerd.io",
                "docker-buildx-plugin", "docker-compose-plugin",
            ],
            timeout=300.0,
        )


def install_docker(
    runner: CommandRunner, provisioner: DockerProvisioner | None = None
) -> None:
    """Install Docker only when it is genuinely absent.

    A present but unusable Docker/Compose installation fails actionably without
    apt replacement.  Conflicting packages are reported, never removed.
    """
    _ensure_local_docker_daemon(runner)
    if _docker_available(runner):
        return

    version, compose = _docker_probe(runner)
    if _command_present(runner, "docker"):
        version_rc = "not runnable" if version is None else str(version.returncode)
        compose_rc = "not runnable" if compose is None else str(compose.returncode)
        raise InstallError(
            "Docker is installed but not usable "
            f"(docker version rc={version_rc}, docker compose version rc={compose_rc}). "
            "Start the Docker daemon or repair the Compose plugin; the installer "
            "will not replace or reinstall existing packages."
        )

    active = provisioner or RealDockerProvisioner()
    conflicts = active.conflicting_packages(runner)
    if conflicts:
        raise InstallError(
            "Docker is absent but conflicting packages are installed: "
            f"{', '.join(conflicts)}. Remove or resolve them manually; the "
            "installer never removes packages."
        )
    active.install(runner)
    if not _docker_available(runner):
        raise InstallError(
            "Docker was installed but is not responding.  Check that the daemon "
            "is running and that your user can access it."
        )


def check_runtime_environment(runner: CommandRunner) -> None:
    """Validate that the host is Ubuntu 24.04 amd64 and can run Docker."""
    _check_python3()
    _ensure_local_docker_daemon(runner)
    try:
        os_release = platform_ops().read_text(Path("/etc/os-release"))
    except OSError as exc:
        raise InstallError(f"cannot read /etc/os-release: {exc}") from exc
    id_match = re.search(r'^ID=(.+)$', os_release, re.MULTILINE)
    version_match = re.search(r'^VERSION_CODENAME=(.+)$', os_release, re.MULTILINE)
    if not id_match or id_match.group(1).strip('"') != "ubuntu":
        raise InstallError("this installer supports Ubuntu only")
    if not version_match or version_match.group(1).strip('"') != UBUNTU_CODENAME:
        raise InstallError("this installer supports Ubuntu 24.04 (noble) only")
    try:
        uname_result = runner.run(["uname", "-m"], timeout=10.0, check=False)
    except CommandError as exc:
        raise InstallError(f"cannot detect machine architecture: {exc}") from exc
    arch = uname_result.stdout.strip()
    if arch != REQUIRED_ARCH:
        raise InstallError(f"this installer supports amd64 ({REQUIRED_ARCH}); found {arch}")



def _compose_args(project_dir: Path, files: list[str], env_files: list[Path]) -> list[str]:
    cmd = ["docker", "compose", "-p", PROJECT_NAME]
    for f in files:
        cmd.extend(["-f", f])
    for env_file in env_files:
        cmd.extend(["--env-file", str(env_file)])
    return cmd


def _sanitized_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return a clean subprocess environment without inherited secret overrides."""
    full = platform_ops().getenv()
    allowed = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "DOCKER_HOST"}
    env = {k: v for k, v in full.items() if k in allowed}
    # Bind mounts require the local daemon.  Select the default context
    # explicitly so a persisted remote context cannot be used by Compose.
    env["DOCKER_CONTEXT"] = "default"
    if extra:
        for key, value in extra.items():
            # Do not carry secrets or Compose overrides.
            if key.upper() in {
                "COMPOSE_FILE",
                "COMPOSE_PROJECT_NAME",
                "DOCKER_CONTEXT",
                "PGPASSWORD",
                "NASI_LEMAK_APP_KEY",
                "NASI_LEMAK_OPERATOR_KEY",
            }:
                continue
            env[key] = value
    return env


def validate_compose_config(
    runner: CommandRunner,
    project_dir: Path,
    files: list[str],
    env_files: list[Path],
) -> None:
    cmd = _compose_args(project_dir, files, env_files) + ["config", "--quiet"]
    runner.run(cmd, cwd=str(project_dir), env=_sanitized_env())


def compose_up_db(
    runner: CommandRunner,
    project_dir: Path,
    files: list[str],
    env_files: list[Path],
    *,
    wait_timeout: float = 120.0,
) -> None:
    cmd = (
        _compose_args(project_dir, files, env_files)
        + ["up", "-d", "--wait", "--wait-timeout", str(int(wait_timeout)), "db"]
    )
    runner.run(cmd, cwd=str(project_dir), env=_sanitized_env(), timeout=wait_timeout + 30.0)


def _postgres_is_healthy(stdout: str) -> bool:
    """Parse compose ps JSON and accept only an explicit ``healthy`` status."""
    text = stdout.strip()
    if not text:
        return False
    entries: list[Any] = []
    try:
        parsed = json.loads(text)
        entries = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            entries.extend(item if isinstance(item, list) else [item])
    for item in entries:
        if isinstance(item, dict):
            health = item.get("Health")
            if isinstance(health, str) and health.strip().lower() == "healthy":
                return True
    return False


def wait_for_postgres_health(
    runner: CommandRunner,
    project_dir: Path,
    files: list[str],
    env_files: list[Path],
    *,
    timeout: float = 120.0,
) -> None:
    """Wait until PostgreSQL reports healthy via compose ps."""
    deadline = platform_ops().now() + timeout
    while platform_ops().now() < deadline:
        result = runner.run(
            _compose_args(project_dir, files, env_files)
            + ["ps", "--format", "json", "db"],
            cwd=str(project_dir),
            env=_sanitized_env(),
            timeout=10.0,
            check=False,
        )
        if _postgres_is_healthy(result.stdout):
            return
        remaining = deadline - platform_ops().now()
        platform_ops().sleep(min(2.0, remaining))
    raise InstallError("PostgreSQL did not become healthy in time")



def compose_start_gateway(
    runner: CommandRunner,
    project_dir: Path,
    files: list[str],
    env_files: list[Path],
    *,
    wait_timeout: float = 300.0,
) -> None:
    cmd = (
        _compose_args(project_dir, files, env_files)
        + ["up", "-d", "--build", "--wait", "--wait-timeout", str(int(wait_timeout)), "gateway"]
    )
    runner.run(
        cmd,
        cwd=str(project_dir),
        env=_sanitized_env(),
        timeout=wait_timeout + 60.0,
    )


def inspect_volume(runner: CommandRunner, volume: str) -> dict[str, Any] | None:
    result = runner.run(
        ["docker", "volume", "inspect", volume],
        timeout=10.0,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError):
        return None


def expected_volume_labels() -> dict[str, str]:
    """Labels Compose and the installer must agree on for the DB volume."""
    return {
        COMPOSE_PROJECT_LABEL: PROJECT_NAME,
        COMPOSE_VOLUME_LABEL: DB_VOLUME,
        INSTALLER_LABEL: INSTALLER_LABEL_VALUE,
    }


def compose_volume_name(logical_volume: str = DB_VOLUME) -> str:
    """Actual Docker name for a Compose-managed named volume.

    ``compose.yaml`` declares ``name: nasi-lemak`` and the logical volume
    ``nasi_lemark_db``, so Docker uses ``nasi-lemak_nasi_lemark_db``.
    """
    return f"{PROJECT_NAME}_{logical_volume}"


def ensure_installer_volume(runner: CommandRunner, logical_volume: str = DB_VOLUME) -> None:
    volume = compose_volume_name(logical_volume)
    info = inspect_volume(runner, volume)
    expected = expected_volume_labels()
    if info is None:
        cmd = ["docker", "volume", "create"]
        for key, value in expected.items():
            cmd.extend(["--label", f"{key}={value}"])
        cmd.append(volume)
        runner.run(cmd, timeout=10.0)
        return
    labels = info.get("Labels") or {}
    if labels.get(INSTALLER_LABEL) != INSTALLER_LABEL_VALUE:
        raise InstallError(
            f"Docker volume {volume} already exists but is not managed by this installer. "
            "Remove it manually only after confirming it is unneeded."
        )
    for key, value in expected.items():
        if key == INSTALLER_LABEL:
            continue
        if labels.get(key) != value:
            raise InstallError(
                f"Docker volume {volume} has an unexpected {key} label "
                f"({labels.get(key)!r}, expected {value!r})"
            )


def _readiness_payload(port: int) -> str:
    return (
        "import json, urllib.request; "
        f"r = urllib.request.urlopen('http://127.0.0.1:{port}/health/ready', timeout=7); "
        "print(r.read().decode())"
    )


def readiness_probe(
    runner: CommandRunner,
    port: str,
    expected_mode: str,
    expected_guards_active: bool,
    *,
    timeout: float = 120.0,
) -> None:
    """Hit /health/ready until it reports the expected mode and guard state."""
    deadline = platform_ops().now() + timeout
    while platform_ops().now() < deadline:
        result = runner.run(
            ["python3", "-c", _readiness_payload(int(port))],
            timeout=10.0,
            check=False,
        )
        if result.returncode == 0:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                payload = {}
            if (
                payload.get("status") == "ready"
                and payload.get("mode") == expected_mode
                and payload.get("guards_active") is expected_guards_active
            ):
                return
        remaining = deadline - platform_ops().now()
        platform_ops().sleep(min(2.0, remaining))
    raise InstallError("gateway readiness check did not succeed in time")


# ---------------------------------------------------------------------------
# Role bootstrap (no PGPASSWORD in child env)
# ---------------------------------------------------------------------------
def _escape_sql_literal(value: str) -> str:
    return value.replace("'", "''")


def _role_properties_check(rolname: str) -> str:
    return f"""
    SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls
    INTO _login, _super, _createdb, _createrole, _replication, _bypassrls
    FROM pg_roles WHERE rolname = '{rolname}';
    IF NOT _login OR _super OR _createdb OR _createrole OR _replication OR _bypassrls THEN
        RAISE EXCEPTION '{rolname} has unexpected role properties';
    END IF;
"""


def _role_memberships_check(
    rolname: str, expected_group: str, forbidden_group: str
) -> str:
    """Reject missing, cross-role or extra memberships on a runtime LOGIN role."""
    return f"""
    IF NOT pg_has_role('{rolname}', '{expected_group}', 'MEMBER') THEN
        RAISE EXCEPTION '{rolname} is not a member of {expected_group}';
    END IF;
    IF pg_has_role('{rolname}', '{forbidden_group}', 'MEMBER') THEN
        RAISE EXCEPTION '{rolname} must not be a member of {forbidden_group}';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_auth_members m
        JOIN pg_roles granted ON granted.oid = m.roleid
        JOIN pg_roles member ON member.oid = m.member
        WHERE member.rolname = '{rolname}'
          AND granted.rolname <> '{expected_group}'
    ) THEN
        RAISE EXCEPTION '{rolname} has unexpected extra role memberships';
    END IF;
"""


def bootstrap_roles_sql(writer_password: str, reader_password: str) -> str:
    """Return the SQL bootstrap script sent to psql via stdin.

    Session logging is hardened before any statement containing a secret:
    ``log_statement = 'none'`` and ``log_min_error_statement = 'panic'`` stop
    PostgreSQL from echoing the generated password into server logs if role
    creation fails.  The NOLOGIN group roles must already exist because
    ``audit_roles.sql`` creates them and grants their privileges; this script
    never fabricates empty group roles.
    """
    writer = _escape_sql_literal(writer_password)
    reader = _escape_sql_literal(reader_password)
    return f"""
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
DO $$
DECLARE
    _login bool;
    _super bool;
    _createdb bool;
    _createrole bool;
    _replication bool;
    _bypassrls bool;
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nasi_lemak_audit_writer') THEN
    RAISE EXCEPTION 'required bootstrap role nasi_lemak_audit_writer is missing; apply nasi_lemak/audit_roles.sql first';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nasi_lemak_audit_reader') THEN
    RAISE EXCEPTION 'required bootstrap role nasi_lemak_audit_reader is missing; apply nasi_lemak/audit_roles.sql first';
  END IF;

  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nasi_lemak_gateway') THEN
    CREATE ROLE nasi_lemak_gateway LOGIN IN ROLE nasi_lemak_audit_writer PASSWORD '{writer}';
  ELSE
    {_role_properties_check('nasi_lemak_gateway')}
    {_role_memberships_check('nasi_lemak_gateway', 'nasi_lemak_audit_writer', 'nasi_lemak_audit_reader')}
  END IF;

  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nasi_lemak_operator') THEN
    CREATE ROLE nasi_lemak_operator LOGIN IN ROLE nasi_lemak_audit_reader PASSWORD '{reader}';
  ELSE
    {_role_properties_check('nasi_lemak_operator')}
    {_role_memberships_check('nasi_lemak_operator', 'nasi_lemak_audit_reader', 'nasi_lemak_audit_writer')}
  END IF;
END
$$;
"""


def bootstrap_roles(
    runner: CommandRunner,
    project_dir: Path,
    files: list[str],
    env_files: list[Path],
    credentials: Credentials,
) -> None:
    """Create or verify LOGIN writer/reader roles via psql stdin.

    The official Postgres image allows local trust access for the bootstrap
    admin user, so no PGPASSWORD is placed in the child environment.
    """
    sql = bootstrap_roles_sql(credentials.writer_password, credentials.reader_password)
    runner.run(
        _compose_args(project_dir, files, env_files)
        + [
            "exec", "-T", "db",
            "psql", "-U", "nasi_lemak_admin", "-d", "nasi_lemak", "-v", "ON_ERROR_STOP=1",
        ],
        cwd=str(project_dir),
        env=_sanitized_env(),
        input_text=sql,
        timeout=60.0,
    )


# ---------------------------------------------------------------------------
# Installer
# ---------------------------------------------------------------------------
def _absolute_project_path(project_dir: Path, value: str | None) -> str | None:
    """Resolve an operator-supplied path against the project checkout."""
    if not value:
        return value
    path = Path(value)
    if not path.is_absolute():
        path = project_dir / path
    return str(path)


class Installer:
    def __init__(
        self,
        *,
        project_dir: Path,
        state_dir: Path,
        mode: str,
        port: str,
        generation_url: str,
        generation_model: str,
        generation_auth: str,
        policy_file: str | None,
        interactive: bool,
        qwen_guard_dir: str | None = None,
        demo_bind_ip: str | None = None,
        ack_test_unguarded: bool,
        allow_insecure_http: bool,
        runner: CommandRunner,
        prompt_fn=None,
        provisioner: DockerProvisioner | None = None,
    ):
        self.project_dir = project_dir
        self.state_dir = state_dir
        self.mode = validate_mode(mode)
        self.port = validate_port(port)
        self.demo_bind_ip = validate_demo_bind_ip(demo_bind_ip) if demo_bind_ip else None
        # Read-only --check/--plan must not require API settings.  Empty values
        # are accepted at construction and enforced by install().
        self.generation_url = (
            validate_generation_url(generation_url, allow_insecure=allow_insecure_http)
            if generation_url
            else ""
        )
        self.generation_model = (
            validate_model_id(generation_model) if generation_model else ""
        )
        self.generation_auth = validate_generation_auth(generation_auth)
        self.policy_file = _absolute_project_path(project_dir, policy_file)
        self.qwen_guard_dir = _absolute_project_path(project_dir, qwen_guard_dir)
        self.interactive = interactive
        self.ack_test_unguarded = ack_test_unguarded
        self.allow_insecure_http = allow_insecure_http
        self.runner = runner
        self.provisioner = provisioner
        self._prompt_fn = prompt_fn if prompt_fn is not None else input
        if self.mode == "guarded":
            if not self.policy_file:
                raise ValidationError("guarded mode requires --policy-file")
            if not self.qwen_guard_dir:
                raise ValidationError("guarded mode requires --qwen-guard-dir")

    def _prompt(self, text: str) -> str:
        if not self.interactive:
            raise InstallError(f"interactive input required: {text}")
        return self._prompt_fn(text)

    def _confirm_mode(self, *, read_only: bool = False) -> None:
        if self.mode == "test":
            print("WARNING: test mode disables the native LLM guard classifiers.")
            print("The runtime will still enforce auth, PII masking, deny phrases and audit,")
            print("but it is NOT protected by attack/output guard models.")
            if read_only:
                # Dry runs must not prompt or require an install acknowledgement.
                return
            if self.interactive:
                answer = self._prompt("Type 'yes' to acknowledge and continue: ")
                if answer.strip().lower() != "yes":
                    raise InstallError("test mode not acknowledged")
            elif not self.ack_test_unguarded:
                raise InstallError("test mode requires --ack-test-unguarded in non-interactive use")
        elif self.mode == "guarded":
            self._require_guarded_inputs()

    def _require_guarded_inputs(self) -> None:
        """Read-only validation shared by check, plan and install.

        API mode never inspects a native model directory.  It revalidates the
        non-secret config and key/CA file metadata; secret contents are not read.
        """
        if not self.policy_file or not Path(self.policy_file).is_file():
            raise InstallError("guarded mode policy file is not readable")
        ensure_runtime_readable(Path(self.policy_file), label="guarded policy file")
        if not self.qwen_guard_dir or not Path(self.qwen_guard_dir).is_dir():
            raise InstallError("qwen3guard model directory is not available")

    def _require_generation_settings(self) -> None:
        """Mutating installs require explicit upstream URL and exact model ID.

        The installer does not infer these from an older environment file, so a
        rerun can never silently reuse a stale or mismatched endpoint.
        """
        if not self.generation_url:
            raise ValidationError(
                "generation URL is required for installation; pass --generation-url "
                "explicitly (saved values are never inferred)"
            )
        if not self.generation_model:
            raise ValidationError(
                "generation model ID is required for installation; pass "
                "--generation-model explicitly (saved values are never inferred)"
            )


    def _preview(self) -> str:
        lines = [
            "Planned actions:",
            f"  Project directory: {self.project_dir}",
            f"  State directory:   {self.state_dir}",
            f"  Mode:              {self.mode}",
            f"  Gateway port:      {self.port}",
            f"  Generation URL:    {self.generation_url}",
            f"  Generation model:  {self.generation_model}",
        ]
        if self.mode == "guarded":
            lines.append(f"  Policy file:       {self.policy_file}")
            lines.append(f"  Qwen3Guard dir:    {self.qwen_guard_dir} (active guard)")
            lines.append(
                f"  Qwen3Guard budget: {PILOT_QWEN_WORKERS} worker x "
                f"{PILOT_QWEN_THREADS} threads, threshold {PILOT_QWEN_THRESHOLD}"
            )
            lines.append(
                f"  Reply budget:      {PILOT_DEFAULT_REPLY_TOKENS} tokens "
                "with a concise-answer instruction"
            )
            lines.append(
                f"  Chat bounds:       max {PILOT_MAX_REPLY_TOKENS} reply tokens, "
                f"context {PILOT_CONTEXT_BUDGET}, "
                f"{PILOT_MAX_CONCURRENCY} request at a time"
            )
        lines.append("  Config is rewritten from the values above on every mutating run.")

        lines.extend([
            "  Credentials (files only, values never printed):",
            f"    - {self.state_dir / 'db_admin_password'}",
            f"    - {self.state_dir / 'writer_password'}",
            f"    - {self.state_dir / 'reader_password'}",
            f"    - {self.state_dir / 'chat_key'}",
            f"    - {self.state_dir / 'operator_key'}",
            f"    - {self.state_dir / 'app_key_digest'}",
            f"    - {self.state_dir / 'operator_key_digest'}",
            f"    - {self.state_dir / 'audit_dsn'}",
            f"    - {self.state_dir / 'operator_audit_dsn'}",
        ])
        lines.extend([
            "  Compose files:",
            f"    - {self.state_dir / 'compose.env'}",
        ])
        if self.mode == "test":
            lines.append(f"    - {self.state_dir / 'compose.test.env'}")
        else:
            lines.append(f"    - {self.state_dir / 'compose.pilot.env'}")
        return "\n".join(lines)

    def check(self) -> int:
        """Read-only prerequisite check."""
        print("Checking installer prerequisites...")
        _check_python3()
        _ensure_local_docker_daemon(self.runner)
        docker_ok = _docker_available(self.runner)
        print(f"  docker usable:          {docker_ok}")
        print(f"  docker compose usable:  {docker_ok}")
        print(f"  project directory:      {self.project_dir}")
        print(f"  state directory:        {self.state_dir}")
        if self.mode == "guarded":
            self._require_guarded_inputs()
        print("Check complete.")
        return 0


    def plan(self) -> int:
        """Show planned actions without mutations, prompts or secret reads."""
        self._confirm_mode(read_only=True)
        print(self._preview())
        print("\nThis was a dry run; no files were written and no services were started.")
        return 0

    def install(self) -> int:
        self._require_generation_settings()
        self._confirm_mode()

        if platform_ops().getuid() != 0:
            raise InstallError("mutating operations must run as root")
        check_runtime_environment(self.runner)

        ensure_safe_state_dir(self.state_dir)

        if self.interactive:
            print(self._preview())
            answer = self._prompt("Proceed? Type 'yes' to continue: ")
            if answer.strip().lower() != "yes":
                print("Installation cancelled.")
                return 1
        else:
            # Non-interactive mutation is never allowed to bypass confirmation.
            raise InstallError(
                "non-interactive installation requires interactive confirmation; "
                "run from a TTY or use --check/--plan for read-only inspection"
            )

        lock_fd = acquire_lock(self.state_dir)
        try:
            return self._install_locked()
        finally:
            release_lock(lock_fd)

    def _install_locked(self) -> int:
        # Load or generate credentials only after confirmation and lock.
        credentials = Credentials.load_or_generate(self.state_dir)

        # Snapshot installer-owned configuration so a failed run can restore it.
        snapshots = self._snapshot_config()

        install_docker(self.runner, self.provisioner)
        ensure_installer_volume(self.runner)

        try:
            # Write credentials and env files with the requested settings.
            credentials.write(self.state_dir)
            write_base_compose_env(
                self.state_dir,
                self.project_dir,
                self.port,
                self.generation_url,
                self.generation_model,
                self.generation_auth,
                self.allow_insecure_http,
            )
            if self.mode == "test":
                write_test_compose_env(self.state_dir, self.project_dir)
                write_test_policy(self.project_dir)
                compose_files = [
                    str(self.project_dir / "compose.yaml"),
                    str(self.project_dir / "compose.test.yaml"),
                ]
                env_files = [
                    self.state_dir / "compose.env",
                    self.state_dir / "compose.test.env",
                ]
            else:
                write_guarded_compose_env(
                    self.state_dir,
                    self.project_dir,
                    self.policy_file or "",
                    self.qwen_guard_dir or "",
                )
                compose_files = [
                    str(self.project_dir / "compose.yaml"),
                    str(self.project_dir / "compose.pilot.yaml"),
                ]
                env_files = [
                    self.state_dir / "compose.env",
                    self.state_dir / "compose.pilot.env",
                ]

            if self.demo_bind_ip:
                write_demo_compose_env(self.state_dir, self.demo_bind_ip)
            self._add_configured_overlays(compose_files, env_files)

            credentials.write_derived(self.state_dir)
            self._ensure_state_dir_mode()

            # Validate configuration before starting anything.
            validate_compose_config(self.runner, self.project_dir, compose_files, env_files)

            # Start PostgreSQL first and provision roles.
            compose_up_db(self.runner, self.project_dir, compose_files, env_files)
            wait_for_postgres_health(self.runner, self.project_dir, compose_files, env_files)
            bootstrap_roles(self.runner, self.project_dir, compose_files, env_files, credentials)

            # Start the gateway and wait for the requested mode to be ready.
            compose_start_gateway(self.runner, self.project_dir, compose_files, env_files)
            readiness_probe(
                self.runner,
                self.port,
                self.mode,
                expected_guards_active=(self.mode == "guarded"),
                timeout=120.0,
            )

            # Update the confirmed marker only after matching readiness.
            write_active_mode(self.state_dir, self.mode)
        except (InstallError, OSError):
            self._rollback(snapshots)
            raise

        print("\nInstallation complete.")
        print(f"Gateway: http://127.0.0.1:{self.port}")
        print("Credential files (values not shown) in:")
        print(f"  {self.state_dir}")
        return 0

    def _add_configured_overlays(
        self, compose_files: list[str], env_files: list[Path]
    ) -> None:
        """Keep every overlay this host is configured for.

        A rerun with only the mode overlay would recreate the gateway without
        /workspace and leave nginx behind, so each overlay's env file decides.
        """
        for env_name, overlay in (
            ("compose.workspace.env", "compose.workspace.yaml"),
            ("compose.demo.env", "compose.demo.yaml"),
            ("compose.demo-tls.env", "compose.demo-tls.yaml"),
        ):
            env_path = self.state_dir / env_name
            if env_path.is_file():
                compose_files.append(str(self.project_dir / overlay))
                env_files.append(env_path)

    def _config_paths(self) -> dict[str, Path]:
        return {
            "compose.env": self.state_dir / "compose.env",
            "compose.test.env": self.state_dir / "compose.test.env",
            "compose.pilot.env": self.state_dir / "compose.pilot.env",
            "compose.demo.env": self.state_dir / "compose.demo.env",
            "policy.test.yaml": self.project_dir / "policy.test.yaml",
        }

    def _snapshot_config(self) -> dict[str, tuple[str, int] | None]:
        snapshots: dict[str, tuple[str, int] | None] = {}
        for name, path in self._config_paths().items():
            if not path.exists():
                snapshots[name] = None
                continue
            try:
                content = platform_ops().read_text(path)
                st = platform_ops().lstat(path)
            except OSError as exc:
                raise InstallError(f"cannot snapshot existing configuration {path}: {exc}") from exc
            snapshots[name] = (content, stat.S_IMODE(st.st_mode))
        return snapshots

    def _rollback(self, snapshots: dict[str, tuple[str, int] | None]) -> None:
        """Restore installer-owned config files; never claim a live rollback.

        The confirmed mode marker is not touched here: it changes only after a
        successful readiness check.  Containers started by the failed attempt
        are not automatically reverted.
        """
        failures: list[str] = []
        for name, path in self._config_paths().items():
            previous = snapshots.get(name)
            try:
                if previous is None:
                    if path.exists():
                        if platform_ops().is_symlink(path):
                            raise InstallError(f"refusing to remove symlink {path}")
                        platform_ops().unlink(path)
                else:
                    atomic_write(
                        path, previous[0], previous[1], overwrite=True
                    )
            except (InstallError, OSError) as exc:
                failures.append(f"{path}: {exc}")
        marker = read_active_mode(self.state_dir) or "absent"
        print(
            "Installation failed before the requested mode passed readiness.",
            file=sys.stderr,
        )
        if failures:
            print(
                "Configuration restoration was incomplete: " + "; ".join(failures),
                file=sys.stderr,
            )
        else:
            print(
                "Previous installer-owned configuration files were restored; "
                f"the confirmed active-mode marker remains {marker!r}.",
                file=sys.stderr,
            )
        print(
            "Running containers were not rolled back automatically. Inspect "
            "`docker compose ps`; restart the previously confirmed mode explicitly "
            "if needed.",
            file=sys.stderr,
        )

    def _ensure_state_dir_mode(self) -> None:
        """Ensure the state directory itself is root-accessible only."""
        try:
            platform_ops().chmod(self.state_dir, 0o700)
        except OSError as exc:
            raise InstallError(
                f"cannot secure state directory permissions for {self.state_dir}: {exc}"
            ) from exc



# ---------------------------------------------------------------------------
# Locking
# ---------------------------------------------------------------------------
def acquire_lock(state_dir: Path) -> Any:
    """Take the persistent installer lock.

    The lock file is opened without truncation and never unlinked: unlinking a
    held inode would let a second installer create a fresh one and run
    concurrently.  Mutual exclusion comes from the non-blocking flock.
    """
    lock_path = state_dir / ".install.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = platform_ops().open_lock(lock_path, 0o600)
    try:
        platform_ops().lock_file(fd)
    except OSError as exc:
        platform_ops().close(fd)
        raise InstallError("another installer instance is running") from exc
    return fd


def release_lock(fd: int) -> None:
    try:
        platform_ops().unlock_file(fd)
    except OSError:
        pass
    try:
        platform_ops().close(fd)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install the Nasi Lemak gateway on Ubuntu 24.04.",
    )
    parser.add_argument("--check", action="store_true", help="check prerequisites without changes")
    parser.add_argument("--plan", action="store_true", help="show planned actions without changes")
    parser.add_argument("--project-dir", default=DEFAULT_PROJECT, help="project root directory")
    parser.add_argument("--state-dir", default=DEFAULT_STATE, help="directory for generated credentials")
    parser.add_argument("--mode", choices=VALID_MODES, help="runtime mode (guarded or test)")
    parser.add_argument("--port", default=DEFAULT_PORT, help="host loopback port")
    parser.add_argument("--generation-url", default=DEFAULT_GENERATION_URL, help="upstream API base URL")
    parser.add_argument("--generation-model", default=DEFAULT_GENERATION_MODEL, help="exact upstream model ID")
    parser.add_argument(
        "--generation-auth", default="none", choices=("none", "bearer"),
        help="upstream auth mode",
    )
    parser.add_argument("--allow-insecure-http", action="store_true", help="allow plain HTTP generation URL")
    parser.add_argument("--policy-file", help="approved YAML policy file (guarded mode)")
    parser.add_argument(
        "--qwen-guard-dir",
        help="local Qwen3Guard-Gen-0.6B directory, the active guard (guarded mode)",
    )
    parser.add_argument(
        "--demo-bind-ip",
        help="host LAN or VPN address for the nginx demo ingress on port 8080",
    )
    parser.add_argument(
        "--ack-test-unguarded", action="store_true",
        help="acknowledge inactive guards in test mode",
    )
    return parser


def _interactive_prompt(default_url: str, default_model: str) -> tuple[str, str]:
    print()
    url = input(f"Generation URL [{default_url or 'required'}]: ").strip()
    url = url or default_url
    if not url:
        raise InstallError("a generation URL is required")
    model = input(f"Exact generation model ID [{default_model or 'required'}]: ").strip()
    model = model or default_model
    if not model:
        raise InstallError("a generation model ID is required")
    return url, model


def _interactive_guarded_prompt(
    policy_file: str | None,
    qwen_guard_dir: str | None,
) -> tuple[str, str]:
    """Prompt for guarded paths before constructor validation."""
    print()
    policy = input(f"Approved policy file [{policy_file or 'required'}]: ").strip()
    policy = policy or (policy_file or "")
    qwen_dir = input(
        f"Qwen3Guard-Gen-0.6B directory [{qwen_guard_dir or 'required'}]: "
    ).strip()
    qwen_dir = qwen_dir or (qwen_guard_dir or "")
    missing = [
        label
        for label, value in (
            ("--policy-file", policy),
            ("--qwen-guard-dir", qwen_dir),
        )
        if not value
    ]
    if missing:
        raise InstallError("guarded mode requires " + ", ".join(missing))
    return policy, qwen_dir



def _resolve_state_dir(project_dir: Path, state_dir_arg: str) -> Path:
    raw = Path(state_dir_arg)
    if raw.is_absolute():
        return safe_realpath(raw, allow_symlink=False)
    return safe_realpath(project_dir / raw, allow_symlink=False)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    old_umask = os.umask(0o077)
    try:
        project_dir = safe_realpath(args.project_dir, must_exist=True, allow_symlink=True)
        state_dir = _resolve_state_dir(project_dir, args.state_dir)
        ensure_within_parent(state_dir, project_dir)

        read_only = args.check or args.plan
        interactive = sys.stdin.isatty() and not read_only
        mode = args.mode
        allow_insecure = bool(args.allow_insecure_http)
        generation_url = args.generation_url
        generation_model = args.generation_model

        if interactive and not read_only:
            if mode is None:
                print("Select installation mode:")
                print("  1) test   - real generation, inactive guards (default)")
                print("  2) guarded - native guard classifiers active")
                choice = input("Choice [1]: ").strip() or "1"
                if choice == "1":
                    mode = "test"
                elif choice == "2":
                    mode = "guarded"
                else:
                    raise InstallError("mode choice must be 1 (test) or 2 (guarded)")
            if mode == "guarded":
                args.policy_file, args.qwen_guard_dir = _interactive_guarded_prompt(
                    args.policy_file, args.qwen_guard_dir
                )
            generation_url, generation_model = _interactive_prompt(
                generation_url or "", generation_model or ""
            )
            if generation_url.startswith("http://") and not allow_insecure:
                answer = input("Plain HTTP is insecure. Allow it? Type 'yes': ").strip()
                allow_insecure = answer.lower() == "yes"
        elif mode is None:
            mode = "test"


        if not generation_url:
            generation_url = ""
        if not generation_model:
            generation_model = ""

        installer = Installer(
            project_dir=project_dir,
            state_dir=state_dir,
            mode=mode,
            port=args.port,
            generation_url=generation_url,
            generation_model=generation_model,
            generation_auth=args.generation_auth,
            policy_file=args.policy_file,
            qwen_guard_dir=args.qwen_guard_dir,
            demo_bind_ip=args.demo_bind_ip,
            interactive=interactive,
            ack_test_unguarded=args.ack_test_unguarded,
            allow_insecure_http=allow_insecure,
            runner=RealCommandRunner(),
        )

        if args.check:
            return installer.check()
        if args.plan:
            return installer.plan()
        return installer.install()
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    sys.exit(main())
