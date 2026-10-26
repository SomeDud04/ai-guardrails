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
) -> dict[str, Any]:
    return {
        "input_check_enabled": input_check_enabled,
        "input_masks": list(input_masks),
        "output_check_enabled": output_check_enabled,
        "output_masks": list(output_masks),
    }


def settings_digest(
    input_check_enabled: bool,
    output_check_enabled: bool,
    input_masks: Iterable[str] | None,
    output_masks: Iterable[str] | None,
) -> str:
    """Stable digest of one profile revision's settings only."""

    payload = _settings_payload(
        bool(input_check_enabled),
        bool(output_check_enabled),
        normalize_masks(input_masks),
        normalize_masks(output_masks),
    )
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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
    digest: str = field(init=False)

    def __post_init__(self) -> None:
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
        payload = _settings_payload(
            self.input_check_enabled,
            self.output_check_enabled,
            self.input_masks,
            self.output_masks,
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
