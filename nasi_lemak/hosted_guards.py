"""Opt-in hosted guard adapters over the existing bounded chat transport.

This module is selected by the server only when both explicit provider selectors
are set under ``NASI_LEMAK_MODE=guarded`` and
``NASI_LEMAK_GUARD_BACKEND=api``:

* ``NASI_LEMAK_INPUT_GUARD_PROVIDER=groq-prompt-guard`` selects
  :class:`GroqPromptGuardInputAdapter` (Prompt Guard 2 86M chat completion).
* ``NASI_LEMAK_OUTPUT_GUARD_PROVIDER=cloudflare-llama-guard`` selects
  :class:`CloudflareLlamaGuardOutputAdapter` (Llama Guard 3 8B chat
  completion).

No selector defaults to a hosted provider: the existing gateway-owned input
``/classify`` contract and Qwen3Guard output adapter remain the defaults.  The
adapters here create no client, endpoint, model or credential by themselves and
perform no network access at import or construction time.

Both adapters reuse :class:`~nasi_lemak.generation.GenerationClient` and its
``post_json`` transport, so TLS verification, the no-redirect policy, proxy
suppression, one-attempt timeout and the response-size bound are unchanged.
There is no retry, no silent fallback and no provider switch.  Errors are
generic and never include a URL, key, prompt, output or provider detail.

These are fixture-tested wire adapters, not evidence of live provider
compatibility, accuracy, quota or latency.  The numeric Prompt Guard response
shape and the Cloudflare model-echo requirement in particular remain pending
live contract acceptance; see ``docs/hosted-guard-setup.md``.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from .generation import GenerationClient, conservative_byte_budget
from .guards import GuardError

GROQ_PROMPT_GUARD_MODEL = "meta-llama/llama-prompt-guard-2-86m"
# The documented Prompt Guard 2 window is 512 tokens.  The adapter never claims
# to tokenize: it refuses input over a conservative UTF-8 byte budget that
# reserves framing/headroom inside that window and never truncates or chunks.
GROQ_PROMPT_GUARD_MAX_TOKENS = 512
GROQ_PROMPT_GUARD_RESERVED_TOKENS = 32
GROQ_INPUT_MAX_SERIALIZED_BYTES = 480
GROQ_INPUT_MAX_OUTPUT_TOKENS = 16

CLOUDFLARE_LLAMA_GUARD_MODEL = "@cf/meta/llama-guard-3-8b"
LLAMA_GUARD_VERDICT_MAX_TOKENS = 32

VERDICT_MAX_TOKENS = LLAMA_GUARD_VERDICT_MAX_TOKENS
MAX_CONTEXT_MESSAGES = 16
# Byte bound on the complete flattened conversation sent to the hosted output
# guard.  This is not a tokenizer count and not a model-window claim.
MAX_ENCODED_INPUT_BYTES = 16 * 1024

CHAT_COMPLETIONS_PATH = "/chat/completions"
_ACCEPTED_ROLES = frozenset({"system", "user", "assistant"})
_CATEGORY = re.compile(r"S(?:[1-9]|1[0-4])\Z")
# A bare decimal probability.  Exponents, labels, prose, JSON objects and
# leading signs are deliberately not accepted.
_PROBABILITY = re.compile(r"(?:0(?:\.\d+)?|1(?:\.0+)?|\.\d+)\Z")


def _require_client(client: Any, model: str, message: str) -> GenerationClient:
    if not isinstance(client, GenerationClient):
        raise GuardError(message)
    configured = client.config.model
    if not isinstance(configured, str) or configured != model:
        raise GuardError(message)
    return client


def _validate_threshold(value: Any) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise GuardError("guard input API threshold is invalid")
    return float(value)


def _strict_chat_content(response: Any, model: str) -> str:
    """Return the single completed assistant text from a strict chat response.

    The response must echo the exact configured model ID, contain exactly one
    choice with a mandatory integer ``index`` of ``0``, ``finish_reason ==
    "stop"`` and an assistant message, and carry no refusal or tool/function
    call.  Optional fields are rejected on bad shape even when falsey, while
    ``None`` and an empty tool-call list remain valid.  Any other shape fails
    closed.
    """
    if not isinstance(response, dict) or "error" in response:
        raise GuardError("hosted guard response is invalid")
    if response.get("model") != model:
        raise GuardError("hosted guard response is invalid")
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise GuardError("hosted guard response is invalid")
    choice = choices[0]
    if not isinstance(choice, dict):
        raise GuardError("hosted guard response is invalid")
    # ``index`` is mandatory and must be a real integer, not ``True``/``False``
    # or a float that happens to compare equal to zero.
    index = choice.get("index")
    if isinstance(index, bool) or not isinstance(index, int) or index != 0:
        raise GuardError("hosted guard response is invalid")
    if choice.get("finish_reason") != "stop":
        raise GuardError("hosted guard response is invalid")
    message = choice.get("message")
    if not isinstance(message, dict):
        raise GuardError("hosted guard response is invalid")
    if message.get("role") != "assistant":
        raise GuardError("hosted guard response is invalid")
    # Optional provider fields are checked by presence and shape rather than
    # truthiness: ``tool_calls: false`` or ``function_call: {}`` must not be
    # mistaken for an absent field.  ``None`` and an empty ``tool_calls`` list
    # are the legitimate no-call forms.
    if "tool_calls" in message:
        tool_calls = message["tool_calls"]
        if tool_calls is not None:
            if not isinstance(tool_calls, list):
                raise GuardError("hosted guard response is invalid")
            if tool_calls:
                raise GuardError("hosted guard response is invalid")
    if "function_call" in message:
        function_call = message["function_call"]
        if function_call is not None:
            # Any call object (including ``{}``) or malformed value is not a
            # verdict; only ``None`` means the field is absent.
            raise GuardError("hosted guard response is invalid")
    if "refusal" in message:
        refusal = message["refusal"]
        if refusal is not None:
            if not isinstance(refusal, str) or refusal.strip():
                raise GuardError("hosted guard response is invalid")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise GuardError("hosted guard response is invalid")
    return content


def _parse_probability(content: str) -> float:
    text = content.strip()
    if not _PROBABILITY.fullmatch(text):
        raise GuardError("hosted guard response is invalid")
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise GuardError("hosted guard response is invalid") from None
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise GuardError("hosted guard response is invalid")
    return value


def _usage_prompt_tokens(response: Any) -> int:
    usage = response.get("usage")
    if not isinstance(usage, dict):
        raise GuardError("hosted guard response is invalid")
    value = usage.get("prompt_tokens")
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value < GROQ_PROMPT_GUARD_MAX_TOKENS
    ):
        raise GuardError("hosted guard response is invalid")
    return value


class GroqPromptGuardInputAdapter:
    """Prompt Guard 2 86M input classifier over an explicit chat client.

    ``scan_attack`` sends the complete serialized accepted input as one user
    message.  The entire assistant content must be a single finite decimal
    probability in ``[0, 1]``; a probability at or above the explicit threshold
    blocks.  ``usage.prompt_tokens`` must be a strict integer in
    ``(0, 512)``.  The adapter does not tokenize, truncate or chunk: input over
    :data:`GROQ_INPUT_MAX_SERIALIZED_BYTES` (a conservative UTF-8 byte budget
    with headroom inside the documented 512-token window) is rejected before
    any HTTP request.  Long prompts therefore need a different approved design.
    """

    def __init__(self, client: Any, *, threshold: Any) -> None:
        self._client = _require_client(
            client,
            GROQ_PROMPT_GUARD_MODEL,
            "guard input API client is not configured for the approved model",
        )
        self._threshold = _validate_threshold(threshold)

    def count_tokens(self, serialized: str) -> int:
        """Conservative UTF-8 byte budget; never a model tokenizer count."""
        if not isinstance(serialized, str):
            raise GuardError("guard input is invalid")
        try:
            return conservative_byte_budget(serialized)
        except ValueError:
            raise GuardError("guard input is invalid") from None

    def scan_attack(self, serialized: str) -> dict[str, str]:
        """Classify one complete serialized input; fail closed on any error."""
        if not isinstance(serialized, str) or not serialized:
            raise GuardError("guard input is invalid")
        if self.count_tokens(serialized) > GROQ_INPUT_MAX_SERIALIZED_BYTES:
            raise GuardError("guard input exceeds the configured limit")
        payload = {
            "model": GROQ_PROMPT_GUARD_MODEL,
            "messages": [{"role": "user", "content": serialized}],
            "max_tokens": GROQ_INPUT_MAX_OUTPUT_TOKENS,
            "temperature": 0,
            "stream": False,
        }
        try:
            response = self._client.post_json(
                CHAT_COMPLETIONS_PATH, payload, strict_json=True
            )
        except Exception:
            raise GuardError("guard input API request failed") from None
        try:
            content = _strict_chat_content(response, GROQ_PROMPT_GUARD_MODEL)
            _usage_prompt_tokens(response)
            probability = _parse_probability(content)
        except GuardError:
            raise
        except Exception:
            raise GuardError("hosted guard response is invalid") from None
        decision = "block" if probability >= self._threshold else "allow"
        return {"decision": decision}


def _serialize_context(messages: list[dict[str, str]]) -> str:
    """Complete accepted context, one line per turn, roles preserved.

    This mirrors the local :class:`~nasi_lemak.guards.LlamaGuard3` flattening
    pattern rather than sending the turns as separate chat messages.
    """
    return "\n".join(f"{message['role']}: {message['content']}" for message in messages)


def _validate_llama_conversation(
    messages: Any, output: Any
) -> list[dict[str, str]]:
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_CONTEXT_MESSAGES:
        raise GuardError("guard context is invalid")
    clean: list[dict[str, str]] = []
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise GuardError("guard context is invalid")
        role, content = message["role"], message["content"]
        if not isinstance(role, str) or role not in _ACCEPTED_ROLES:
            raise GuardError("guard context is invalid")
        if not isinstance(content, str) or not content:
            raise GuardError("guard context is invalid")
        clean.append({"role": role, "content": content})
    if not isinstance(output, str) or not output:
        raise GuardError("guard output is invalid")
    conversation = [
        {"role": "user", "content": _serialize_context(clean)},
        {"role": "assistant", "content": output},
    ]
    try:
        encoded = json.dumps(
            conversation, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise GuardError("guard context is invalid") from None
    if len(encoded) > MAX_ENCODED_INPUT_BYTES:
        raise GuardError("guard context exceeds the configured limit")
    return conversation


def _parse_llama_verdict(content: str) -> bool:
    """Parse only canonical ``safe`` or ``unsafe`` plus S1..S14 categories."""
    if not isinstance(content, str):
        raise GuardError("hosted guard response is invalid")
    stripped = content.strip()
    if stripped == "safe":
        return True
    lines = [line.strip() for line in stripped.splitlines()]
    if not lines or lines[0] != "unsafe":
        raise GuardError("hosted guard response is invalid")
    rest = [line for line in lines[1:] if line]
    if not rest:
        raise GuardError("hosted guard response is invalid")
    categories = [part.strip() for part in ",".join(rest).split(",")]
    if any(not part for part in categories):
        raise GuardError("hosted guard response is invalid")
    if len(set(categories)) != len(categories):
        raise GuardError("hosted guard response is invalid")
    if any(_CATEGORY.fullmatch(part) is None for part in categories):
        raise GuardError("hosted guard response is invalid")
    return False


class CloudflareLlamaGuardOutputAdapter:
    """Llama Guard 3 8B output classifier over an explicit chat client.

    ``scan_response`` validates the same accepted context shape as the existing
    output adapter, flattens every message into one user message exactly like
    the local :class:`~nasi_lemak.guards.LlamaGuard3`, appends the buffered
    output as the assistant turn, and rejects a UTF-8 JSON encoding over 16 KiB
    before any HTTP request.  It sends a non-streaming, low-temperature request
    and requires a single completed chat response that echoes the exact
    Cloudflare model ID.  Only the canonical token ``safe`` allows; ``unsafe``
    with one or more unique comma-separated S1..S14 categories blocks.  Any
    other content, a missing/incorrect model echo, truncated completion or
    transport error raises a generic :class:`GuardError`.
    """

    def __init__(self, client: Any) -> None:
        self._client = _require_client(
            client,
            CLOUDFLARE_LLAMA_GUARD_MODEL,
            "guard output API client is not configured for the approved model",
        )

    def scan_response(self, messages: Any, output: Any) -> dict[str, bool]:
        """Return ``{"safe": bool}`` for the complete context plus output."""
        conversation = _validate_llama_conversation(messages, output)
        payload = {
            "model": CLOUDFLARE_LLAMA_GUARD_MODEL,
            "messages": conversation,
            "max_tokens": LLAMA_GUARD_VERDICT_MAX_TOKENS,
            "temperature": 0,
            "stream": False,
        }
        try:
            response = self._client.post_json(
                CHAT_COMPLETIONS_PATH, payload, strict_json=True
            )
        except Exception:
            raise GuardError("guard output API request failed") from None
        try:
            content = _strict_chat_content(response, CLOUDFLARE_LLAMA_GUARD_MODEL)
            verdict = _parse_llama_verdict(content)
        except GuardError:
            raise
        except Exception:
            raise GuardError("hosted guard response is invalid") from None
        return {"safe": verdict}
