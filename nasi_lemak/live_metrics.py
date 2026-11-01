"""In-memory timing for the Monitor screen.  Holds numbers only, never text.

Samples live in this process and are lost on restart.  The audit log remains the
record; this adds what it does not hold: time spent in each stage and the token
counts the generation endpoint reports.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable

MAX_SAMPLES = 200
RECENT_ROWS = 10
STAGE_WINDOW = 20
LIVE_WINDOW_SECONDS = 60.0


def tokens_per_second(sample: dict[str, Any]) -> float | None:
    tokens = sample.get("reply_tokens")
    generation_ms = sample.get("generation_ms")
    if not tokens or not generation_ms:
        return None
    return round(tokens / (generation_ms / 1000.0), 1)


class LiveMetrics:
    """Thread-safe rolling samples of finished requests."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._samples: deque[dict[str, Any]] = deque(maxlen=MAX_SAMPLES)
        self._in_flight = 0

    def enter(self) -> None:
        with self._lock:
            self._in_flight += 1

    def leave(self, timing: dict[str, Any], status: int) -> None:
        """Close one request.  One that never reached the pipeline is not a sample."""
        started = timing.pop("started", None)
        finished = time.perf_counter()
        with self._lock:
            self._in_flight -= 1
            if started is None:
                return
            decision = (
                "allowed" if status == 200
                else "blocked" if status in (403, 413)
                else "failed"
            )
            self._samples.append(
                {
                    "at": self._clock(),
                    "decision": decision,
                    "total_ms": round((finished - started) * 1000.0),
                    "input_ms": timing.get("input_ms"),
                    "generation_ms": timing.get("generation_ms"),
                    "output_ms": timing.get("output_ms"),
                    "prompt_tokens": timing.get("prompt_tokens"),
                    "reply_tokens": timing.get("reply_tokens"),
                }
            )

    def snapshot(self) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            samples = list(self._samples)
            in_flight = self._in_flight
        recent = [
            {**sample, "tokens_per_second": tokens_per_second(sample)}
            for sample in samples[-RECENT_ROWS:][::-1]
        ]
        last_minute = [s for s in samples if now - s["at"] <= LIVE_WINDOW_SECONDS]
        rates = [
            rate
            for rate in (tokens_per_second(s) for s in samples[-STAGE_WINDOW:])
            if rate is not None
        ]
        allowed = [s for s in samples[-STAGE_WINDOW:] if s["decision"] == "allowed"]

        def average(key: str) -> int | None:
            values = [s[key] for s in allowed if s.get(key) is not None]
            return round(sum(values) / len(values)) if values else None

        return {
            "in_flight": in_flight,
            "samples": len(samples),
            "last_minute": {
                "requests": len(last_minute),
                "reply_tokens": sum(s.get("reply_tokens") or 0 for s in last_minute),
            },
            "tokens_per_second": {
                "latest": rates[-1] if rates else None,
                "average": round(sum(rates) / len(rates), 1) if rates else None,
            },
            "stages_ms": {
                "input": average("input_ms"),
                "generation": average("generation_ms"),
                "output": average("output_ms"),
            },
            "recent": recent,
        }
