"""Request-local gateway control values and safe block details.

These objects are created by the trusted workspace policy layer and passed
explicitly to :meth:`nasi_lemak.gateway.Gateway.handle`.  They are never read
from a request body, header or process-global adapter state.  A control can
relax the two model classifiers and select PII masks, but it cannot disable
authentication, request-shape validation, limits, deny phrases, audit ordering
or fail-closed unavailable handling.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Iterable

from .pii import ENTITY_TYPES

MASK_TYPES = tuple(ENTITY_TYPES)
DEFAULT_REVISION = "default"
MAX_REVISION_LENGTH = 128
MAX_SOURCES = 3

BLOCK_STAGES = ("input", "output")
BLOCK_REASONS: dict[str, tuple[str, str, str]] = {
    "INPUT_GUARD_BLOCK": (
        "input",
        "Prompt blocked",
        "The prompt did not pass the input safety check.",
    ),
    "INPUT_POLICY_BLOCK": (
        "input",
        "Prompt blocked",
        "The prompt contains content disallowed by policy.",
    ),
    "OUTPUT_GUARD_BLOCK": (
        "output",
        "Response withheld",
        "The response did not pass the output safety check.",
    ),
    "OUTPUT_POLICY_BLOCK": (
        "output",
        "Response withheld",
        "The response contains content disallowed by policy.",
    ),
}
BLOCK_REASON_CODES = tuple(BLOCK_REASONS)


def normalize_masks(value: Iterable[str] | None) -> tuple[str, ...]:
    """Return a canonical, duplicate-free tuple of supported mask names.

    ``None`` means the default (all masks).  An empty iterable deliberately
    means no masking, which is the explicit administrator relaxation path.
    """

    if value is None:
        return MASK_TYPES
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ValueError("mask selection is invalid")
    items = list(value)
    if len(items) > len(MASK_TYPES):
        raise ValueError("mask selection is invalid")
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, str) or item not in MASK_TYPES or item in seen:
            raise ValueError("mask selection is invalid")
        seen.add(item)
    return tuple(mask for mask in MASK_TYPES if mask in seen)


def masks_to_text(masks: Iterable[str]) -> str:
    return ",".join(normalize_masks(masks))


def masks_from_text(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise ValueError("stored mask selection is invalid")
    if not value:
        return ()
    return normalize_masks(value.split(","))


def _canonical_source(source: tuple[str, str, str, int]) -> tuple[str, str, str, int]:
    scope_type, scope_id, profile_id, revision = source
    if scope_type not in ("workspace", "department", "user"):
        raise ValueError("control source is invalid")
    for item in (scope_id, profile_id):
        if not isinstance(item, str) or not 1 <= len(item) <= 64:
            raise ValueError("control source is invalid")
        if any(ord(char) < 32 or ord(char) == 127 for char in item):
            raise ValueError("control source is invalid")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("control source is invalid")
    return source


def _settings_payload(
    input_check_enabled: bool,
    output_check_enabled: bool,
    input_masks: tuple[str, ...],
    output_masks: tuple[str, ...],
    limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    payload = {
        "input_check_enabled": input_check_enabled,
        "input_masks": list(input_masks),
        "output_check_enabled": output_check_enabled,
        "output_masks": list(output_masks),
    }
    if limits:
        payload["limits"] = dict(sorted(limits.items()))
    return payload


def settings_digest(
    input_check_enabled: bool,
    output_check_enabled: bool,
    input_masks: Iterable[str] | None,
    output_masks: Iterable[str] | None,
    limits: dict[str, int] | None = None,
) -> str:
    """Stable digest of one profile revision's settings only.

    The digest includes a ``limits`` entry only when at least one limit is set,
    so existing limits-free revisions keep their historical digest value.
    """

    payload = _settings_payload(
        bool(input_check_enabled),
        bool(output_check_enabled),
        normalize_masks(input_masks),
        normalize_masks(output_masks),
        limits,
    )
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def audit_latency_ms(result_sink: dict[str, Any]) -> int | None:
    """Server latency derived from the two audit timestamps this request wrote.

    Both values come from the same request's pipeline sink and are the audit
    store's own ``timestamp`` column values.  Nothing is timed or estimated
    here: when either stamp is absent (a stage that did not run) the field is
    omitted rather than invented.
    """
    started = result_sink.get("audit_started_at")
    terminal = result_sink.get("audit_terminal_at")
    for value in (started, terminal):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        if not math.isfinite(value):
            return None
    return int(round((terminal - started) * 1000))


def guardrail_details(
    result_sink: dict[str, Any], user_text: str, control: "GatewayControl"
) -> dict[str, Any]:
    """Fixed per-turn summary of what the guardrail did, for the person's own turn.

    Every value comes from a fixed vocabulary, a boolean or the audit latency.
    No classifier text, category, prompt or withheld output is included.  A
    check the policy switched off reads ``off`` and one the turn never reached
    reads ``not_run``, so neither can be mistaken for a passed check.
    """
    decision = result_sink.get("input_decision")
    if not control.input_check_enabled:
        input_check = "off"
    elif decision in ("allow", "block"):
        input_check = "safe" if decision == "allow" else "blocked"
    else:
        input_check = "not_run"
    output_safe = result_sink.get("output_safe")
    if not control.output_check_enabled:
        output_check = "off"
    elif isinstance(output_safe, bool):
        output_check = "safe" if output_safe else "blocked"
    else:
        output_check = "not_run"
    messages = result_sink.get("sanitized_messages")
    masked_prompt = (
        messages[-1].get("content") if isinstance(messages, list) and messages else None
    )
    details: dict[str, Any] = {
        "input_check": input_check,
        "output_check": output_check,
        "input_pii_masked": isinstance(masked_prompt, str) and masked_prompt != user_text,
        "output_pii_masked": result_sink.get("output_masked") is True,
    }
    latency = audit_latency_ms(result_sink)
    if latency is not None:
        details["latency_ms"] = latency
    return details


@dataclass(frozen=True)
class GatewayControl:
    """Immutable per-request enforcement preferences.

    ``revision`` and ``sources`` are audit/preview metadata only.  They are
    included in ``digest`` so an effective-policy snapshot cannot be confused
    with a different inheritance lineage that happens to have equal toggles.
    """

    input_check_enabled: bool = True
    output_check_enabled: bool = True
    input_masks: tuple[str, ...] = MASK_TYPES
    output_masks: tuple[str, ...] = MASK_TYPES
    revision: str = DEFAULT_REVISION
    sources: tuple[tuple[str, str, str, int], ...] = ()
    limits: tuple[tuple[str, int], ...] = ()
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        from .limits import LIMIT_FIELDS

        for name, value in (
            ("input_check_enabled", self.input_check_enabled),
            ("output_check_enabled", self.output_check_enabled),
        ):
            if not isinstance(value, bool):
                raise ValueError(f"{name} is invalid")
        object.__setattr__(self, "input_masks", normalize_masks(self.input_masks))
        object.__setattr__(self, "output_masks", normalize_masks(self.output_masks))
        if (
            not isinstance(self.revision, str)
            or not 1 <= len(self.revision) <= MAX_REVISION_LENGTH
            or any(ord(char) < 32 or ord(char) == 127 for char in self.revision)
        ):
            raise ValueError("control revision is invalid")
        if not isinstance(self.sources, tuple) or len(self.sources) > MAX_SOURCES:
            raise ValueError("control sources are invalid")
        object.__setattr__(
            self,
            "sources",
            tuple(_canonical_source(source) for source in self.sources),
        )
        limits_dict: dict[str, int] | None = None
        if self.limits:
            if not isinstance(self.limits, tuple):
                raise ValueError("control limits are invalid")
            parsed: dict[str, int] = {}
            for item in self.limits:
                if (
                    not isinstance(item, tuple)
                    or len(item) != 2
                    or not isinstance(item[0], str)
                    or isinstance(item[1], bool)
                    or not isinstance(item[1], int)
                    or item[1] <= 0
                ):
                    raise ValueError("control limits are invalid")
                if item[0] not in LIMIT_FIELDS:
                    raise ValueError("control limits are invalid")
                parsed[item[0]] = item[1]
            if len(parsed) != len(self.limits):
                raise ValueError("control limits are invalid")
            if (
                "default_reply_tokens" in parsed
                and "max_reply_tokens" in parsed
                and parsed["default_reply_tokens"] > parsed["max_reply_tokens"]
            ):
                raise ValueError("control limits are invalid")
            limits_dict = dict(sorted(parsed.items()))
            object.__setattr__(self, "limits", tuple(limits_dict.items()))
        payload = _settings_payload(
            self.input_check_enabled,
            self.output_check_enabled,
            self.input_masks,
            self.output_masks,
            limits_dict,
        )
        payload["revision"] = self.revision
        payload["sources"] = [list(source) for source in self.sources]
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        object.__setattr__(
            self,
            "digest",
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

    def masks_for(self, stage: str) -> tuple[str, ...]:
        if stage == "input":
            return self.input_masks
        if stage == "output":
            return self.output_masks
        raise ValueError("control stage is invalid")

    def check_enabled(self, stage: str) -> bool:
        if stage == "input":
            return self.input_check_enabled
        if stage == "output":
            return self.output_check_enabled
        raise ValueError("control stage is invalid")

    def metadata(self) -> dict[str, Any]:
        """Bounded, JSON-friendly audit metadata (never request content)."""

        return {
            "revision": self.revision,
            "digest": self.digest,
            "sources": [
                {
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "profile_id": profile_id,
                    "revision": revision,
                }
                for scope_type, scope_id, profile_id, revision in self.sources
            ],
        }


def block_detail(reason_code: str) -> dict[str, str]:
    """Fixed client-safe detail for one exact block reason.

    The returned dict contains no classifier verdict, rule text, prompt or
    withheld model output.
    """

    try:
        stage, title, reason = BLOCK_REASONS[reason_code]
    except (KeyError, TypeError):
        raise ValueError("block reason is invalid") from None
    return {
        "stage": stage,
        "reason_code": reason_code,
        "title": title,
        "reason": reason,
    }
