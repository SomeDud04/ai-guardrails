"""Compact immutable chat context/reply limits shared by gateway and workspace.

All values are non-secret, validated once at startup and treated as read-only for
the life of the process.  The context budget is expressed in the same
conservative UTF-8 byte units used by :func:`nasi_lemak.generation.
conservative_byte_budget`; it is **not** a model tokenizer count and not a
provider model-window claim.

Invalid values raise :class:`ChatLimitsError`.  The server treats that as a
configuration failure (live but not ready) instead of silently substituting a
different limit, so an apparently configured window is either honoured or
refused before inference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

ENV_CONTEXT_MESSAGES = "NASI_LEMAK_CHAT_CONTEXT_MESSAGES"
ENV_CONTEXT_BUDGET = "NASI_LEMAK_CHAT_CONTEXT_BUDGET"
ENV_DEFAULT_REPLY_TOKENS = "NASI_LEMAK_CHAT_DEFAULT_REPLY_TOKENS"
ENV_MAX_REPLY_TOKENS = "NASI_LEMAK_CHAT_MAX_REPLY_TOKENS"

DEFAULT_CONTEXT_MESSAGES = 32
MAX_CONTEXT_MESSAGES = 32
DEFAULT_CONTEXT_BUDGET = 8192
MAX_CONTEXT_BUDGET = 32768
DEFAULT_REPLY_TOKENS = 1024
MAX_REPLY_TOKENS = 4096
MAX_REPLY_TOKENS_CEILING = 8192
# Finite memory bound for a single accepted prompt, independent of the
# configured conservative-unit budget.  The configured budget and the operator
# policy token budget remain the effective limits.
MAX_PROMPT_CHARS = 64 * 1024

_POSITIVE_INT = re.compile(r"[1-9][0-9]*\Z")


def has_explicit_env(environ: Mapping[str, str] | None) -> bool:
    """True when any chat-limit variable is explicitly non-empty."""
    env = {} if environ is None else environ
    return any(
        isinstance(env.get(name), str) and env[name].strip() != ""
        for name in (
            ENV_CONTEXT_MESSAGES,
            ENV_CONTEXT_BUDGET,
            ENV_DEFAULT_REPLY_TOKENS,
            ENV_MAX_REPLY_TOKENS,
        )
    )


class ChatLimitsError(ValueError):
    """An explicitly configured chat limit is invalid or out of range."""


def _bounded_env_int(
    env: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = env.get(name)
    if raw is None or (isinstance(raw, str) and raw.strip() == ""):
        return default
    if not isinstance(raw, str):
        raise ChatLimitsError(f"{name} must be a bounded integer")
    text = raw.strip()
    if _POSITIVE_INT.fullmatch(text) is None:
        raise ChatLimitsError(f"{name} must be a bounded integer")
    try:
        value = int(text, 10)
    except (TypeError, ValueError):
        raise ChatLimitsError(f"{name} must be a bounded integer") from None
    if not minimum <= value <= maximum:
        raise ChatLimitsError(f"{name} must be a bounded integer")
    return value


@dataclass(frozen=True)
class ChatLimits:
    """Validated non-secret chat limits.

    ``context_budget`` is a conservative UTF-8 unit budget for the complete
    serialized conversation sent to generation, including role/content framing.
    ``default_reply_tokens`` and ``max_reply_tokens`` bound the requested reply
    length; the provider's own model window and tokenizer remain unverified.
    """

    context_messages: int = DEFAULT_CONTEXT_MESSAGES
    context_budget: int = DEFAULT_CONTEXT_BUDGET
    default_reply_tokens: int = DEFAULT_REPLY_TOKENS
    max_reply_tokens: int = MAX_REPLY_TOKENS

    def __post_init__(self) -> None:
        for value, label in (
            (self.context_messages, "context messages"),
            (self.context_budget, "context budget"),
            (self.default_reply_tokens, "default reply tokens"),
            (self.max_reply_tokens, "maximum reply tokens"),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ChatLimitsError(f"chat {label} must be a bounded integer")
        if not 1 <= self.context_messages <= MAX_CONTEXT_MESSAGES:
            raise ChatLimitsError("chat context messages must be a bounded integer")
        if not 1 <= self.context_budget <= MAX_CONTEXT_BUDGET:
            raise ChatLimitsError("chat context budget must be a bounded integer")
        if not 1 <= self.max_reply_tokens <= MAX_REPLY_TOKENS_CEILING:
            raise ChatLimitsError("chat maximum reply tokens must be a bounded integer")
        if not 1 <= self.default_reply_tokens <= self.max_reply_tokens:
            raise ChatLimitsError(
                "chat default reply tokens must not exceed the maximum"
            )

    @classmethod
    def defaults(cls) -> "ChatLimits":
        return cls()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None) -> "ChatLimits":
        env = {} if environ is None else environ
        context_messages = _bounded_env_int(
            env,
            ENV_CONTEXT_MESSAGES,
            default=DEFAULT_CONTEXT_MESSAGES,
            minimum=1,
            maximum=MAX_CONTEXT_MESSAGES,
        )
        context_budget = _bounded_env_int(
            env,
            ENV_CONTEXT_BUDGET,
            default=DEFAULT_CONTEXT_BUDGET,
            minimum=1,
            maximum=MAX_CONTEXT_BUDGET,
        )
        max_reply_tokens = _bounded_env_int(
            env,
            ENV_MAX_REPLY_TOKENS,
            default=MAX_REPLY_TOKENS,
            minimum=1,
            maximum=MAX_REPLY_TOKENS_CEILING,
        )
        raw_default = env.get(ENV_DEFAULT_REPLY_TOKENS)
        if raw_default is None or (
            isinstance(raw_default, str) and raw_default.strip() == ""
        ):
            # An explicit maximum below the built-in default is valid; the
            # default then follows that smaller ceiling rather than failing.
            default_reply_tokens = min(DEFAULT_REPLY_TOKENS, max_reply_tokens)
        else:
            default_reply_tokens = _bounded_env_int(
                env,
                ENV_DEFAULT_REPLY_TOKENS,
                default=DEFAULT_REPLY_TOKENS,
                minimum=1,
                maximum=max_reply_tokens,
            )
        return cls(
            context_messages=context_messages,
            context_budget=context_budget,
            default_reply_tokens=default_reply_tokens,
            max_reply_tokens=max_reply_tokens,
        )

    def max_prompt_chars(self) -> int:
        """Finite single-prompt character ceiling derived from the budget."""
        return min(MAX_PROMPT_CHARS, max(4096, self.context_budget))

    def public(self) -> dict[str, int]:
        """Non-secret values safe for an authenticated workspace response."""
        return {
            "context_messages": self.context_messages,
            "context_budget": self.context_budget,
            "default_reply_tokens": self.default_reply_tokens,
            "max_reply_tokens": self.max_reply_tokens,
        }
