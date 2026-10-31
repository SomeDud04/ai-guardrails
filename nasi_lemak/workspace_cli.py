"""Operator CLI for the opt-in employee workspace.

This module is deliberately small. It provisions the dedicated PostgreSQL
schema, creates the first administrator and generates the encryption key. It
never prints a DSN, password, key, request content or traceback.

Commands::

    python -m nasi_lemak.workspace_cli generate-key --key-file PATH
    python -m nasi_lemak.workspace_cli init --dsn-file PATH --key-file PATH
    python -m nasi_lemak.workspace_cli bootstrap-admin \
        --dsn-file PATH --key-file PATH --username NAME \
        --full-name "Full Name" --department "Department"

``init`` is the only command that opens the database with ``migrate=True`` and
must use an operator-privileged migration DSN. ``bootstrap-admin`` also uses an
operator-privileged, one-time provisioning DSN with ``migrate=False``: the
one-time bootstrap writes the ``bootstrap_admin`` marker to ``ws_meta``, which
the restricted runtime role deliberately cannot modify. The runtime DSN is for
the gateway and must not be used for bootstrap. Passwords are read only from an
interactive terminal with confirmation and are never accepted from argv, the
environment or a default value.

Tests may inject a ``store_factory`` and ``password_reader``; SQLite is accepted
only through that explicit injection and is never a product fallback.
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Sequence, TextIO

from .workspace_store import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, WorkspaceStore

MAX_SECRET_BYTES = 8192

StoreFactory = Callable[..., Any]
PasswordReader = Callable[[str], str]


class CliError(RuntimeError):
    """A safe, operator-facing CLI failure (no secrets or paths)."""


def _safe_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _read_secret_file(path_value: str, *, label: str) -> str:
    """Read one bounded, non-empty regular UTF-8 secret file."""
    if not isinstance(path_value, str) or not path_value.strip():
        raise CliError(f"{label} file is required")
    path = Path(path_value)
    try:
        info = path.stat()
    except OSError:
        raise CliError(f"{label} file is unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise CliError(f"{label} file must be a regular file")
    if info.st_size == 0:
        raise CliError(f"{label} file is empty")
    if info.st_size < 0 or info.st_size > MAX_SECRET_BYTES:
        raise CliError(f"{label} file has an unsupported size")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_SECRET_BYTES + 1)
    except OSError:
        raise CliError(f"{label} file is unavailable") from None
    if len(data) > MAX_SECRET_BYTES:
        raise CliError(f"{label} file has an unsupported size")
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise CliError(f"{label} file is not valid UTF-8") from None
    if not text:
        raise CliError(f"{label} file is empty")
    return text


def _is_postgres_dsn(value: str) -> bool:
    return value.lower().startswith(("postgresql://", "postgres://"))


def _open_store(
    dsn: str,
    key: str,
    *,
    migrate: bool,
    store_factory: StoreFactory | None,
) -> Any:
    """Open the workspace store, refusing SQLite outside test injection."""
    if store_factory is None:
        if not _is_postgres_dsn(dsn):
            raise CliError("workspace DSN must be a PostgreSQL DSN")
        factory: StoreFactory = WorkspaceStore
    else:
        # Explicit test-only injection: the pinned production path above never
        # accepts a non-PostgreSQL DSN from the operator.
        factory = store_factory
    try:
        return factory(
            dsn,
            encryption_key=key,
            migrate=migrate,
            connect_timeout=5.0,
        )
    except Exception:
        raise CliError("workspace storage is unavailable") from None


def _close_store(store: Any) -> None:
    close = getattr(store, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def _generate_key(key_file: str) -> None:
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        raise CliError("key generation is unavailable") from None
    try:
        material = Fernet.generate_key()
    except Exception:
        raise CliError("key generation is unavailable") from None

    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(
            key_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        created = True
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(material + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError:
        raise CliError("key file already exists; it was not overwritten") from None
    except OSError:
        if created:
            try:
                os.unlink(key_file)
            except OSError:
                pass
        raise CliError("key file could not be created") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass


def _prompt_password(prompt: str) -> str:
    """Read one password interactively; refuse an echoing non-TTY fallback."""
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if not interactive:
        raise CliError("an interactive terminal is required for password entry")
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise CliError("password entry was cancelled") from None


def _read_confirmed_password(reader: PasswordReader | None) -> str:
    source = reader or _prompt_password
    first = source("Password: ")
    second = source("Confirm password: ")
    if not isinstance(first, str) or not isinstance(second, str):
        raise CliError("password is invalid")
    if not hmac.compare_digest(first.encode("utf-8"), second.encode("utf-8")):
        raise CliError("passwords do not match")
    if len(first) < PASSWORD_MIN_LENGTH or len(first) > PASSWORD_MAX_LENGTH:
        raise CliError("password does not meet policy")
    return first


def _command_generate_key(args: argparse.Namespace) -> None:
    _generate_key(args.key_file)


def _command_init(
    args: argparse.Namespace, store_factory: StoreFactory | None
) -> None:
    dsn = _read_secret_file(args.dsn_file, label="DSN")
    key = _read_secret_file(args.key_file, label="key")
    store = _open_store(dsn, key, migrate=True, store_factory=store_factory)
    _close_store(store)


def _command_bootstrap(
    args: argparse.Namespace,
    store_factory: StoreFactory | None,
    password_reader: PasswordReader | None,
) -> None:
    dsn = _read_secret_file(args.dsn_file, label="DSN")
    key = _read_secret_file(args.key_file, label="key")
    password = _read_confirmed_password(password_reader)
    store = _open_store(dsn, key, migrate=False, store_factory=store_factory)
    try:
        created = store.bootstrap_admin(
            username=args.username,
            password=password,
            full_name=args.full_name,
            department_name=args.department,
        )
    except Exception:
        raise CliError("administrator creation failed") from None
    finally:
        _close_store(store)
    if created is None:
        raise CliError("an administrator already exists; it was not reset")


def _command_purge(
    args: argparse.Namespace, store_factory: StoreFactory | None
) -> int:
    dsn = _read_secret_file(args.dsn_file, label="DSN")
    key = _read_secret_file(args.key_file, label="key")
    store = _open_store(dsn, key, migrate=False, store_factory=store_factory)
    try:
        return store.purge_expired_conversations(args.older_than_days)
    except ValueError:
        raise CliError("retention period is invalid") from None
    finally:
        _close_store(store)


class _SanitizedArgumentParser(argparse.ArgumentParser):
    """Reject parse errors without echoing raw argv values (possible secrets)."""

    def error(self, message: str) -> None:
        raise CliError("invalid command line arguments")


def _build_parser() -> argparse.ArgumentParser:
    parser = _SanitizedArgumentParser(
        prog="python -m nasi_lemak.workspace_cli",
        description=(
            "Provision the opt-in employee workspace without printing secrets."
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    generate = subcommands.add_parser(
        "generate-key", help="create a new Fernet key file (never overwrites)"
    )
    generate.add_argument("--key-file", required=True)

    init = subcommands.add_parser(
        "init",
        help="create or verify the workspace schema with the migration DSN",
    )
    init.add_argument("--dsn-file", required=True)
    init.add_argument("--key-file", required=True)

    bootstrap = subcommands.add_parser(
        "bootstrap-admin",
        help=(
            "create the first administrator with the one-time privileged "
            "provisioning DSN (not the restricted runtime DSN)"
        ),
    )
    bootstrap.add_argument("--dsn-file", required=True)
    bootstrap.add_argument("--key-file", required=True)
    bootstrap.add_argument("--username", required=True)
    bootstrap.add_argument("--full-name", required=True)
    bootstrap.add_argument("--department", required=True)

    purge = subcommands.add_parser(
        "purge-expired",
        help="delete conversations untouched for the given number of days",
    )
    purge.add_argument("--dsn-file", required=True)
    purge.add_argument("--key-file", required=True)
    purge.add_argument("--older-than-days", required=True, type=int)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    store_factory: StoreFactory | None = None,
    password_reader: PasswordReader | None = None,
    output: TextIO | None = None,
    error_output: TextIO | None = None,
) -> int:
    """Run one CLI command and return a process exit code.

    All failures are reported as one generic line. Exception text, DSNs, keys,
    passwords and tracebacks are never written by this function.
    """
    parser = _build_parser()
    out = output if output is not None else sys.stdout
    err = error_output if error_output is not None else sys.stderr
    try:
        args = parser.parse_args(argv)
    except CliError as exc:
        print(f"error: {exc}", file=err)
        return 2
    try:
        if args.command == "generate-key":
            _command_generate_key(args)
            print("encryption key file created", file=out)
        elif args.command == "init":
            _command_init(args, store_factory)
            print("workspace schema is initialised", file=out)
        elif args.command == "bootstrap-admin":
            _command_bootstrap(args, store_factory, password_reader)
            print("workspace administrator created", file=out)
        elif args.command == "purge-expired":
            deleted = _command_purge(args, store_factory)
            print(f"deleted {deleted} expired conversations", file=out)
        else:  # argparse prevents this, but keep a fail-closed default.
            raise CliError("unsupported command")
    except CliError as exc:
        print(f"error: {exc}", file=err)
        return 2
    except Exception:
        print("error: workspace operation failed", file=err)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
