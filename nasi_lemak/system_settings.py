"""Administrator-editable runtime settings.

The startup policy file and environment remain the upper limit: a setting can
tighten them freely but never loosen past them.  Guard mode, the guard itself,
the model and the audit ordering are deliberately not settings, so a stolen
administrator login cannot switch protection off.

Saved values live in an append-only revision table.  This module validates a
complete set of values and holds the active revision in memory; the server runs
one worker process, so a save updates that holder directly.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Mapping

from .limits import LIMIT_FIELDS

MAX_DENY_PHRASES = 100
MAX_DENY_PHRASE_LENGTH = 200
MAX_RETENTION_DAYS = 36500
MIN_SESSION_HOURS = 1
MAX_SESSION_HOURS = 24
MIN_LOGIN_ATTEMPTS = 3
MAX_LOGIN_ATTEMPTS = 20
MAX_REQUESTS_PER_MINUTE = 600
MIN_REASON_LENGTH = 3
MAX_REASON_LENGTH = 500

DEFAULT_SETTINGS: dict[str, Any] = {
    "paused": False,
    "shared_key_enabled": True,
    "chat_limits": {},
    # ``None`` means everything the policy file allows.
    "input_allow_categories": None,
    "output_allow_categories": None,
    "deny_phrases": [],
    "retention_days": None,
    "session_hours": 8,
    "login_max_attempts": 5,
    "key_requests_per_minute": None,
    # Read once at startup, so a change needs a gateway restart.
    "max_concurrency": None,
    "chat_timeout_seconds": None,
}


class SettingsError(ValueError):
    """A proposed setting is outside what the deployment allows."""


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SettingsError(f"{name} is invalid")
    if not minimum <= value <= maximum:
        raise SettingsError(f"{name} is out of range")
    return value


def _optional_int(value: Any, name: str, minimum: int, maximum: int) -> int | None:
    return None if value is None else _bounded_int(value, name, minimum, maximum)


def _allow_subset(value: Any, name: str, allowed: tuple[str, ...]) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(set(map(str, value))) != len(value):
        raise SettingsError(f"{name} is invalid")
    for category in value:
        if category not in allowed:
            raise SettingsError(f"{name} goes beyond the policy file")
    return [category for category in allowed if category in value]


def _deny_phrases(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_DENY_PHRASES:
        raise SettingsError("deny_phrases is invalid")
    phrases: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise SettingsError("deny_phrases is invalid")
        phrase = item.strip()
        if not 1 <= len(phrase) <= MAX_DENY_PHRASE_LENGTH:
            raise SettingsError("deny_phrases is invalid")
        if any(ord(char) < 32 or ord(char) == 127 for char in phrase):
            raise SettingsError("deny_phrases is invalid")
        if phrase not in phrases:
            phrases.append(phrase)
    return phrases


def validate_settings(
    values: Mapping[str, Any],
    *,
    limit_ceilings: Mapping[str, int],
    input_allow: tuple[str, ...],
    output_allow: tuple[str, ...],
    concurrency_ceiling: int,
    chat_timeout_ceiling: float,
) -> dict[str, Any]:
    """Return canonical values, refusing anything past the deployment's limits."""
    if not isinstance(values, Mapping) or set(values) != set(DEFAULT_SETTINGS):
        raise SettingsError("settings fields are invalid")
    for name in ("paused", "shared_key_enabled"):
        if not isinstance(values[name], bool):
            raise SettingsError(f"{name} is invalid")
    limits = values["chat_limits"]
    if not isinstance(limits, Mapping) or set(limits) - set(LIMIT_FIELDS):
        raise SettingsError("chat_limits is invalid")
    canonical_limits = {
        name: _bounded_int(limits[name], name, 1, limit_ceilings[name])
        for name in LIMIT_FIELDS
        if name in limits
    }
    if canonical_limits.get("default_reply_tokens", 0) > canonical_limits.get(
        "max_reply_tokens", limit_ceilings["max_reply_tokens"]
    ):
        raise SettingsError("default_reply_tokens is above max_reply_tokens")
    timeout = values["chat_timeout_seconds"]
    if timeout is not None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise SettingsError("chat_timeout_seconds is invalid")
        if not 1 <= timeout <= chat_timeout_ceiling:
            raise SettingsError("chat_timeout_seconds is out of range")
        timeout = float(timeout)
    return {
        "paused": values["paused"],
        "shared_key_enabled": values["shared_key_enabled"],
        "chat_limits": canonical_limits,
        "input_allow_categories": _allow_subset(
            values["input_allow_categories"], "input_allow_categories", input_allow
        ),
        "output_allow_categories": _allow_subset(
            values["output_allow_categories"], "output_allow_categories", output_allow
        ),
        "deny_phrases": _deny_phrases(values["deny_phrases"]),
        "retention_days": _optional_int(
            values["retention_days"], "retention_days", 1, MAX_RETENTION_DAYS
        ),
        "session_hours": _bounded_int(
            values["session_hours"], "session_hours", MIN_SESSION_HOURS, MAX_SESSION_HOURS
        ),
        "login_max_attempts": _bounded_int(
            values["login_max_attempts"],
            "login_max_attempts",
            MIN_LOGIN_ATTEMPTS,
            MAX_LOGIN_ATTEMPTS,
        ),
        "key_requests_per_minute": _optional_int(
            values["key_requests_per_minute"],
            "key_requests_per_minute",
            1,
            MAX_REQUESTS_PER_MINUTE,
        ),
        "max_concurrency": _optional_int(
            values["max_concurrency"], "max_concurrency", 1, concurrency_ceiling
        ),
        "chat_timeout_seconds": timeout,
    }


def validate_reason(reason: Any) -> str:
    if not isinstance(reason, str):
        raise SettingsError("a reason is required")
    text = reason.strip()
    if not MIN_REASON_LENGTH <= len(text) <= MAX_REASON_LENGTH:
        raise SettingsError("a reason is required")
    return text


def settings_digest(values: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        values, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class RuntimeSettings:
    """The active revision, shared by the API gateway and the workspace gateway."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revision = 0
        self._values = {**DEFAULT_SETTINGS, "chat_limits": {}, "deny_phrases": []}

    def load(self, revision: int, values: Mapping[str, Any]) -> None:
        with self._lock:
            self._revision = revision
            self._values = {**DEFAULT_SETTINGS, **values}

    def snapshot(self) -> tuple[int, dict[str, Any]]:
        with self._lock:
            return self._revision, self._values

    def effective_policy(self, version: str, digest: str) -> tuple[str, str]:
        """The policy identity for an audit row, including saved settings."""
        revision, values = self.snapshot()
        if revision == 0:
            return version, digest
        combined = f"{digest}:{settings_digest(values)}".encode("utf-8")
        return f"{version}+settings.{revision}", hashlib.sha256(combined).hexdigest()
