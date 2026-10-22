"""Explicit Qwen3Guard output adapter over the existing generation transport.

This module is an optional, explicitly constructed adapter. It is **not**
selected by the server environment, installer or Compose files, and it never
creates a client, endpoint, model name or credential by itself. The caller must
supply a :class:`~nasi_lemak.generation.GenerationClient` that was configured
with a non-empty served model ID (for example ``Qwen/Qwen3Guard-Gen-4B`` or an
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

import json
from typing import Any

from .generation import GenerationClient
from .guards import GuardError

VERDICT_MAX_TOKENS = 128
MAX_CONTEXT_MESSAGES = 16
# Conservative bound on the UTF-8 JSON-encoded conversation plus buffered
# output. This is a byte bound, not a token count and not a model window claim.
MAX_ENCODED_INPUT_BYTES = 16 * 1024

_ACCEPTED_ROLES = frozenset({"system", "user", "assistant"})
_SAFETY_VALUES = ("Safe", "Unsafe", "Controversial")
_REFUSAL_VALUES = ("Yes", "No")
_CATEGORY_VALUES = frozenset(
    {
        "Violent",
        "Non-violent Illegal Acts",
        "Sexual Content or Sexual Acts",
        "PII",
        "Suicide & Self-Harm",
        "Unethical Acts",
        "Politically Sensitive Topics",
        "Copyright Violation",
    }
)


def _validate_conversation(messages: Any, output: Any) -> list[dict[str, str]]:
    """Copy the full accepted context and append the buffered assistant output."""
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_CONTEXT_MESSAGES:
        raise GuardError("guard context is invalid")
    conversation: list[dict[str, str]] = []
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise GuardError("guard context is invalid")
        role, content = message["role"], message["content"]
        if not isinstance(role, str) or role not in _ACCEPTED_ROLES:
            raise GuardError("guard context is invalid")
        if not isinstance(content, str) or not content:
            raise GuardError("guard context is invalid")
        conversation.append({"role": role, "content": content})
    if not isinstance(output, str) or not output:
        raise GuardError("guard output is invalid")
    conversation.append({"role": "assistant", "content": output})
    try:
        encoded = json.dumps(
            conversation, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise GuardError("guard context is invalid") from None
    if len(encoded) > MAX_ENCODED_INPUT_BYTES:
        raise GuardError("guard context exceeds the configured limit")
    return conversation


def _field(line: str, label: str) -> str:
    prefix = label + ": "
    if not line.startswith(prefix):
        raise GuardError("guard output was not a recognized verdict")
    return line[len(prefix) :]


def _parse_categories(value: str) -> tuple[str, ...] | None:
    if value == "None":
        return None
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        raise GuardError("guard output was not a recognized verdict")
    if len(set(parts)) != len(parts):
        raise GuardError("guard output was not a recognized verdict")
    if any(part not in _CATEGORY_VALUES for part in parts):
        raise GuardError("guard output was not a recognized verdict")
    return tuple(parts)


def parse_verdict(text: Any) -> bool:
    """Parse the complete three-line verdict; only consistent Safe+None allows."""
    if not isinstance(text, str):
        raise GuardError("guard output was not a recognized verdict")
    lines = text.strip().splitlines()
    if len(lines) != 3:
        raise GuardError("guard output was not a recognized verdict")
    safety = _field(lines[0], "Safety")
    categories_text = _field(lines[1], "Categories")
    refusal = _field(lines[2], "Refusal")
    if safety not in _SAFETY_VALUES or refusal not in _REFUSAL_VALUES:
        raise GuardError("guard output was not a recognized verdict")
    categories = _parse_categories(categories_text)
    if safety == "Safe":
        if categories is not None:
            raise GuardError("guard output was not a recognized verdict")
        return True
    # Unsafe and Controversial are blocking verdicts. A refusal flag does not
    # change that, and neither verdict may omit its categories.
    if categories is None:
        raise GuardError("guard output was not a recognized verdict")
    return False


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
