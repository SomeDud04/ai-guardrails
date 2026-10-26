"""Explicit per-request cancellation/deadline capability for bounded scans.

A scan context is created for one request and passed down the call chain.  It is
never stored on a shared adapter or client, so concurrent requests with
different deadlines or cancellation states cannot observe each other.  The
object holds only references supplied by the caller; nothing here mutates that
state.

This is cooperative cancellation: an in-flight HTTP call is bounded by the
remaining time passed to the transport, and a cancelled/deadlined context stops
the *next* window or generation call.  It does not interrupt a call already
inside the transport, and it is not a thread terminator.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ScanContext:
    """Immutable handles for one request's cancellation and deadline."""

    cancel_event: Any | None = None
    deadline: float | None = None

    def __post_init__(self) -> None:
        if self.deadline is not None:
            if isinstance(self.deadline, bool) or not isinstance(
                self.deadline, (int, float)
            ):
                raise ValueError("scan deadline is invalid")
            value = float(self.deadline)
            if value != value or value in (float("inf"), float("-inf")):
                raise ValueError("scan deadline is invalid")
            object.__setattr__(self, "deadline", value)

    def cancelled(self) -> bool:
        if self.cancel_event is not None:
            try:
                if self.cancel_event.is_set():
                    return True
            except Exception:
                # An unusable cancellation handle fails closed.
                return True
        if self.deadline is not None and time.monotonic() >= self.deadline:
            return True
        return False

    def remaining(self) -> float | None:
        """Seconds left, or ``None`` when no deadline is set."""
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.monotonic())
