"""Read-only Compose preflight for the opt-in hosted guard deployment.

The script runs exactly ``docker compose ... config --format json`` with the
env files and Compose overlays supplied on the command line, in the supplied
order.  It then checks the resolved configuration for unresolved placeholders,
missing local bind sources and missing file-based secrets.  It never runs
``build``, ``up``, ``down``, ``stop`` or any other mutating Compose command,
never reads secret-file contents, never contacts a model endpoint and never
prints or saves the rendered configuration, child stderr or configured values.

Exit status is 0 when the preflight passes and 2 for an invalid configuration,
a failed/timed-out Compose invocation or a local-path problem.  Errors name the
configuration field or secret, not its value, provider URL, credential or DSN.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Callable, Sequence

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 300.0
MAX_REPORTED_ERRORS = 8

# Unresolved example markers.  Only the rendered configuration is scanned and
# only the field path is reported, never the value.
PLACEHOLDER_MARKERS = ("/absolute", "account_id", "your_account_id")


class PreflightError(RuntimeError):
    """Safe, generic preflight failure; its message never includes values."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


def _default_runner(command: Sequence[str], timeout: float) -> CommandResult:
    completed = subprocess.run(
        list(command),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return CommandResult(completed.returncode, completed.stdout or "", completed.stderr or "")


def build_command(
    env_files: Sequence[str], compose_files: Sequence[str]
) -> list[str]:
    """Build the read-only command, preserving the supplied order of each set."""
    command = ["docker", "compose"]
    for env_file in env_files:
        command.extend(("--env-file", env_file))
    for compose_file in compose_files:
        command.extend(("-f", compose_file))
    command.extend(("config", "--format", "json"))
    return command


def _iter_environment(value: Any, path: str):
    if isinstance(value, dict):
        for name, item in value.items():
            yield f"{path}.{name}", "" if item is None else str(item)
        return
    for index, item in enumerate(value):
        if isinstance(item, str) and "=" in item:
            name, _, item_value = item.partition("=")
            yield f"{path}.{name}", item_value
        else:
            yield f"{path}[{index}]", "" if item is None else str(item)


def _iter_config_strings(value: Any, path: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            if key == "environment" and isinstance(item, (dict, list)):
                yield from _iter_environment(item, child)
            else:
                yield from _iter_config_strings(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_config_strings(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def _placeholder_errors(config: Any) -> list[str]:
    errors: list[str] = []
    for path, value in _iter_config_strings(config):
        lowered = value.lower()
        if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
            errors.append(f"{path or 'configuration'} contains an unresolved placeholder")
    return errors


def _expected_bind_kind(target: Any) -> str | None:
    """Infer a file/directory expectation only when the target is unambiguous."""
    if not isinstance(target, str) or not target:
        return None
    if target.endswith("/"):
        return "directory"
    name = target.rstrip("/").rsplit("/", 1)[-1]
    if "." in name and not name.startswith("."):
        return "file"
    return None


def _validate_bind(label: str, source: Any, target: Any, errors: list[str]) -> None:
    if not isinstance(source, str) or not source:
        errors.append(f"{label} is missing")
        return
    if not os.path.isabs(source):
        errors.append(f"{label} must resolve to an absolute path")
        return
    if not os.path.exists(source):
        errors.append(f"{label} does not exist")
        return
    expected = _expected_bind_kind(target)
    if expected == "file" and not os.path.isfile(source):
        errors.append(f"{label} must be a regular file")
    elif expected == "directory" and not os.path.isdir(source):
        errors.append(f"{label} must be a directory")
    elif not (os.path.isfile(source) or os.path.isdir(source)):
        errors.append(f"{label} must be a file or directory")


def _path_errors(config: Any) -> list[str]:
    errors: list[str] = []
    services = config.get("services")
    if not isinstance(services, dict):
        return ["configuration does not contain a services mapping"]
    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        volumes = service.get("volumes")
        if not isinstance(volumes, list):
            continue
        for index, volume in enumerate(volumes):
            if not isinstance(volume, dict) or volume.get("type") != "bind":
                continue
            _validate_bind(
                f"services.{service_name}.volumes[{index}].source",
                volume.get("source"),
                volume.get("target"),
                errors,
            )
    secrets = config.get("secrets")
    if isinstance(secrets, dict):
        for name, secret in secrets.items():
            label = f"secrets.{name}.file"
            if not isinstance(secret, dict):
                errors.append(f"{label} is missing")
                continue
            path = secret.get("file")
            if not isinstance(path, str) or not path:
                errors.append(f"{label} is missing")
            elif not os.path.isabs(path):
                errors.append(f"{label} must be an absolute path")
            elif not os.path.isfile(path):
                errors.append(f"{label} is missing or not a regular file")
    return errors


def _collect_errors(config: Any) -> list[str]:
    if not isinstance(config, dict):
        return ["compose config did not return a configuration object"]
    placeholders = _placeholder_errors(config)
    if placeholders:
        # Do not add misleading missing-path errors for an unresolved template.
        return placeholders
    return _path_errors(config)


def _limited(errors: Sequence[str]) -> str:
    shown = list(errors[:MAX_REPORTED_ERRORS])
    if len(errors) > MAX_REPORTED_ERRORS:
        shown.append(f"{len(errors) - MAX_REPORTED_ERRORS} more problem(s) omitted")
    return "; ".join(shown)


def run_preflight(
    env_files: Sequence[str],
    compose_files: Sequence[str],
    *,
    runner: Callable[[Sequence[str], float], CommandResult] = _default_runner,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Run the read-only check and return a short, value-free success message."""
    if not compose_files:
        raise PreflightError("at least one -f Compose file is required; no action was taken")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 0 < float(timeout) <= MAX_TIMEOUT_SECONDS
    ):
        raise PreflightError(
            f"compose config timeout must be a finite number of seconds up to {MAX_TIMEOUT_SECONDS:g}"
        )

    command = build_command(env_files, compose_files)
    try:
        result = runner(command, float(timeout))
    except subprocess.TimeoutExpired:
        raise PreflightError(
            f"compose config timed out after {float(timeout):g}s; no deployment action was taken"
        ) from None
    except OSError:
        raise PreflightError(
            "compose config could not start; no deployment action was taken"
        ) from None

    if result.returncode != 0:
        raise PreflightError(
            f"compose config failed with exit code {result.returncode}; "
            "no deployment action was taken"
        )
    try:
        config = json.loads(result.stdout)
    except (TypeError, ValueError):
        raise PreflightError(
            "compose config did not return valid JSON; no deployment action was taken"
        ) from None

    errors = _collect_errors(config)
    if errors:
        raise PreflightError(_limited(errors))
    return (
        f"Preflight OK: {len(compose_files)} Compose file(s), {len(env_files)} env file(s); "
        "local bind sources and file-based secrets are present."
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only hosted-guard deployment preflight. Runs docker compose config "
            "with the supplied env/overlay order; never builds, starts, stops or "
            "prints rendered values."
        )
    )
    parser.add_argument(
        "--env-file",
        action="append",
        default=[],
        metavar="PATH",
        help="Compose env file; repeat in deployment order",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="compose_files",
        action="append",
        default=[],
        metavar="COMPOSE_FILE",
        help="Compose file or overlay; repeat in deployment order",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"bounded compose config timeout (default {DEFAULT_TIMEOUT_SECONDS:g}s)",
    )
    args = parser.parse_args(argv)
    if not args.compose_files:
        parser.error("at least one -f Compose file is required")
    try:
        print(
            run_preflight(
                args.env_file,
                args.compose_files,
                timeout=args.timeout,
            )
        )
    except PreflightError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
