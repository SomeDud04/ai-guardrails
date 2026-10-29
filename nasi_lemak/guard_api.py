"""Explicit input/output guard adapters over the existing generation transport.

This module is selected by the server only when ``NASI_LEMAK_MODE=guarded`` and
``NASI_LEMAK_GUARD_BACKEND=api`` are both explicit. The default local backend
and test mode are unchanged. The installer and the opt-in ``compose.api.yaml``
overlay can supply that environment, but this module never invents a client,
endpoint, model name or credential by itself. The caller must supply a
:class:`~nasi_lemak.generation.GenerationClient` that was configured with a
non-empty served model ID (for example ``Qwen/Qwen3Guard-Gen-4B`` or an
operator-confirmed alias).

The adapter sends the complete accepted conversation plus the buffered model
output to the OpenAI-compatible chat-completions endpoint and parses the
documented three-line Qwen3Guard verdict. Only a consistent
``Safety: Safe`` + ``Categories: None`` verdict returns ``{"safe": True}``.
Unsafe and Controversial verdicts return ``{"safe": False}``; the ``Refusal``
line is validated but never overrides the Safety line. Any malformed,
contradictory or ambiguous verdict, transport failure or truncated completion
raises :class:`~nasi_lemak.guards.GuardError` so the gateway fails closed.
"""

from __future__ import annotations

import math
from typing import Any

from .generation import (
    AUTH_MODES,
    ENV_ALLOW_INSECURE_HTTP,
    ENV_API_KEY,
    ENV_AUTH,
    ENV_CA_FILE,
    ENV_MAX_RESPONSE_BYTES,
    ENV_MODEL,
    ENV_TIMEOUT,
    ENV_URL,
    GenerationClient,
    GenerationConfig,
    GenerationConfigError,
    conservative_byte_budget,
)
from .guard_errors import GuardError
from .qwen3guard import (
    CATEGORY_VALUES,
    MAX_CONTEXT_MESSAGES,
    MAX_ENCODED_INPUT_BYTES,
    REFUSAL_VALUES,
    SAFETY_VALUES,
    VERDICT_MAX_TOKENS,
    parse_categories,
    parse_verdict,
    validate_conversation,
)

# The Qwen3Guard taxonomy and verdict parser live in ``qwen3guard`` and are
# re-exported here so every historical ``nasi_lemak.guard_api`` import path keeps
# resolving to the *same* definition.  There is deliberately no local copy: two
# parsers would drift, and a drifted verdict parser is an unreviewed detection
# change.
_CATEGORY_VALUES = frozenset(CATEGORY_VALUES)
_SAFETY_VALUES = SAFETY_VALUES
_REFUSAL_VALUES = REFUSAL_VALUES
_parse_categories = parse_categories
_validate_conversation = validate_conversation
_ACCEPTED_ROLES = frozenset({"system", "user", "assistant"})

# Versioned, gateway-owned input-classifier HTTP contract.  This is not a claim
# that a stock Prompt Guard endpoint exposes this shape: the serving wrapper
# must implement it explicitly and advertise this exact contract identifier.
INPUT_GUARD_CONTRACT_V1 = "nasi-lemak-input-classifier-v1"
INPUT_GUARD_PATH = "/classify"
INPUT_GUARD_MAX_TOKENS = 512
_INPUT_RESPONSE_FIELDS = frozenset(
    {"model", "malicious_probability", "input_tokens", "truncated"}
)

def _read_guard_key_file(path: str) -> str:
    """Read one explicitly configured guard key file; never fall back."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
    except (OSError, UnicodeError, ValueError, TypeError):
        raise GenerationConfigError("guard API key file is unreadable") from None
    if not value:
        raise GenerationConfigError("guard API key file is empty")
    return value


def guard_client_config(environ: Any, prefix: str) -> GenerationConfig:
    """Build a dedicated guard transport config from ``<prefix>_*`` settings.

    URL, model and auth mode are mandatory and have no defaults.  The API key is
    supplied by exactly one of ``<prefix>_API_KEY`` or ``<prefix>_API_KEY_FILE``;
    an explicitly configured but unreadable file is an error, never a fallback.
    Optional timeout, CA file, response-size and insecure-HTTP settings are
    mapped onto the same validated bounds as the generation transport.  This
    function performs no network access and never reads the generation key.
    """
    if not isinstance(prefix, str) or not prefix:
        raise GenerationConfigError("guard API prefix is invalid")

    def required(suffix: str) -> str:
        name = f"{prefix}_{suffix}"
        value = environ.get(name)
        if not isinstance(value, str) or not value.strip():
            raise GenerationConfigError(f"guard setting {name} is required")
        return value.strip()

    url = required("URL")
    model = required("MODEL")
    auth_mode = required("AUTH").lower()
    if auth_mode not in AUTH_MODES:
        raise GenerationConfigError("guard auth mode must be 'bearer' or 'none'")

    inline_key = environ.get(f"{prefix}_API_KEY")
    key_file = environ.get(f"{prefix}_API_KEY_FILE")
    if inline_key is not None and key_file is not None:
        raise GenerationConfigError(
            "guard API key and key file are mutually exclusive"
        )
    api_key: str | None = None
    if key_file is not None:
        if not isinstance(key_file, str) or not key_file.strip():
            raise GenerationConfigError("guard API key file path is invalid")
        api_key = _read_guard_key_file(key_file)
    elif inline_key is not None:
        if not isinstance(inline_key, str):
            raise GenerationConfigError("guard API key is invalid")
        api_key = inline_key
    if auth_mode == "bearer" and not api_key:
        raise GenerationConfigError("guard API key is not configured")

    mapped: dict[str, str] = {
        ENV_URL: url,
        ENV_MODEL: model,
        ENV_AUTH: auth_mode,
    }
    if api_key is not None:
        mapped[ENV_API_KEY] = api_key
    for suffix, generation_name in (
        ("TIMEOUT", ENV_TIMEOUT),
        ("CA_FILE", ENV_CA_FILE),
        ("MAX_RESPONSE_BYTES", ENV_MAX_RESPONSE_BYTES),
        ("ALLOW_INSECURE_HTTP", ENV_ALLOW_INSECURE_HTTP),
    ):
        value = environ.get(f"{prefix}_{suffix}")
        if value is not None:
            mapped[generation_name] = value
    return GenerationConfig.from_env(mapped)


def _valid_probability(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0.0 <= value <= 1.0
    )


def _valid_input_tokens(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and 1 <= value <= INPUT_GUARD_MAX_TOKENS
    )


class InputGuardApiAdapter:
    """Stateless input classifier over the versioned ``/classify`` contract.

    The adapter uses the shared bounded generation transport (TLS, no redirect,
    no proxy, single attempt, timeout and response-size limit) with a dedicated
    guard client.  It creates no client and performs no HTTP work in its
    constructor.  ``count_tokens`` returns :func:`conservative_byte_budget`,
    which is a UTF-8 byte bound, never a model tokenizer count.
    """

    def __init__(self, client: Any, *, threshold: Any) -> None:
        if not isinstance(client, GenerationClient):
            raise GuardError("guard input API client is not configured")
        model = client.config.model
        if not isinstance(model, str) or not model.strip():
            raise GuardError("guard input API model is not configured")
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(threshold)
            or not 0.0 <= threshold <= 1.0
        ):
            raise GuardError("guard input API threshold is invalid")
        self._client = client
        self._threshold = float(threshold)

    def count_tokens(self, serialized: str) -> int:
        """Conservative UTF-8 byte budget; not a model tokenizer."""
        if not isinstance(serialized, str):
            raise GuardError("guard input is invalid")
        try:
            return conservative_byte_budget(serialized)
        except ValueError:
            raise GuardError("guard input is invalid") from None

    def _parse_response(self, response: Any) -> dict[str, str]:
        if not isinstance(response, dict) or set(response) != _INPUT_RESPONSE_FIELDS:
            raise GuardError("guard input API response is invalid")
        if response["model"] != self._client.config.model:
            raise GuardError("guard input API response is invalid")
        probability = response["malicious_probability"]
        if not _valid_probability(probability):
            raise GuardError("guard input API response is invalid")
        if not _valid_input_tokens(response["input_tokens"]):
            raise GuardError("guard input API response is invalid")
        if response["truncated"] is not False:
            raise GuardError("guard input API response is invalid")
        decision = "block" if float(probability) >= self._threshold else "allow"
        return {"decision": decision}

    def scan_attack(self, serialized: str) -> dict[str, str]:
        """Classify one complete serialized input; fail closed on any error."""
        if not isinstance(serialized, str) or not serialized:
            raise GuardError("guard input is invalid")
        payload = {
            "model": self._client.config.model,
            "input": serialized,
            "truncation": False,
            "max_input_tokens": INPUT_GUARD_MAX_TOKENS,
        }
        try:
            response = self._client.post_json(
                INPUT_GUARD_PATH, payload, strict_json=True
            )
        except Exception:
            raise GuardError("guard input API request failed") from None
        try:
            return self._parse_response(response)
        except GuardError:
            raise
        except Exception:
            raise GuardError("guard input API response is invalid") from None


class Qwen3GuardOutputAdapter:
    """Qwen3Guard generative output guard using an explicit generation client."""

    def __init__(self, client: Any) -> None:
        if not isinstance(client, GenerationClient):
            raise GuardError("guard output API client is not configured")
        model = client.config.model
        if not isinstance(model, str) or not model.strip():
            raise GuardError("guard output API model is not configured")
        self._client = client

    def scan_response(self, messages: Any, output: Any) -> dict[str, bool]:
        """Return ``{"safe": bool}`` for the complete context plus output."""
        conversation = _validate_conversation(messages, output)
        try:
            verdict = self._client.generate(
                conversation, max_tokens=VERDICT_MAX_TOKENS
            )
        except Exception:
            raise GuardError("guard output API request failed") from None
        return {"safe": parse_verdict(verdict)}
