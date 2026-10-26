"""Bounded internal diagnostic signals for fail-closed chat failures.

These signals are deliberately narrow and content-free.  They exist so an
operator can distinguish a generation that produced only hidden reasoning /
truncated output from a policy block whose payload did not match the fixed
reason table, without ever exposing a prompt, provider payload, raw exception,
reasoning text or credential through the HTTP response or a log line.

Only the fixed codes in :data:`SIGNAL_CODES` are accepted.  Unknown values are
ignored, and the number of distinct codes is bounded, so a caller cannot grow
this structure with attacker-controlled text.
"""

from __future__ import annotations

import threading
from typing import Any

GENERATION_TRUNCATED = "generation_truncated"
GENERATION_NO_FINAL_CONTENT = "generation_no_final_content"
BLOCK_PAYLOAD_REJECTED = "block_payload_rejected"

SIGNAL_CODES = frozenset(
    {
        GENERATION_TRUNCATED,
        GENERATION_NO_FINAL_CONTENT,
        BLOCK_PAYLOAD_REJECTED,
    }
)


class SafeDiagnostics:
    """Thread-safe counters for a small fixed set of internal signal codes.

    ``snapshot`` returns a copy of the current counts.  No timestamps, request
    ids, user ids, prompts, provider bodies or exception text are retained.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts = {code: 0 for code in sorted(SIGNAL_CODES)}

    def record(self, code: Any) -> None:
        if not isinstance(code, str) or code not in SIGNAL_CODES:
            return
        with self._lock:
            self._counts[code] += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)


def record_signal(sink: Any, code: Any) -> None:
    """Record one fixed signal on an optional sink; never raises.

    A missing or unusable sink must not turn a safe failure into a different
    failure.  The signal is best-effort and bounded by the sink implementation.
    """

    if sink is None or not callable(getattr(sink, "record", None)):
        return
    try:
        sink.record(code)
    except Exception:
        pass
