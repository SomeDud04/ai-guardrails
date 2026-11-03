"""In-memory timing for the Monitor screen.  Never holds prompt or reply text.

Samples live in this process and are lost on restart.  The audit log remains the
record; this adds what it does not hold: time spent in each stage and the token
counts the generation endpoint reports.  HTTP rows add the caller's address and
the matched route: a fixed route template, never a raw path or query string.
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
MAX_HTTP_ROWS = 5000
HTTP_RECENT_ROWS = 20
HTTP_IP_ROWS = 50
HTTP_WINDOW_SECONDS = 3600.0
CHAT_ROUTES = frozenset(
    {
        "/chat",
        "/v1/chat/completions",
        "/workspace/api/conversations/{conversation_id}/messages",
    }
)
# Health checks and Monitor's own refreshes would bury the real traffic.
QUIET_ROUTES = frozenset(
    {
        "/health/live",
        "/health/ready",
        "/workspace/api/admin/live",
        "/workspace/api/admin/monitor",
        "/workspace/api/admin/alerts/summary",
    }
)


def tokens_per_second(sample: dict[str, Any]) -> float | None:
    tokens = sample.get("reply_tokens")
    generation_ms = sample.get("generation_ms")
    if not tokens or not generation_ms:
        return None
    return round(tokens / (generation_ms / 1000.0), 1)


def _scan_rate(scans: list[tuple[int, float]]) -> float | None:
    """Tokens read per second across guard passes, weighted by their length."""
    seconds = sum(elapsed_ms for _tokens, elapsed_ms in scans) / 1000.0
    if seconds <= 0:
        return None
    return round(sum(tokens for tokens, _elapsed_ms in scans) / seconds, 1)


def _traffic(rows: list[dict[str, Any]], now: float) -> dict[str, Any]:
    window = [row for row in rows if now - row["at"] <= HTTP_WINDOW_SECONDS]
    by_ip: dict[str, dict[str, Any]] = {}
    for row in window:
        entry = by_ip.setdefault(
            row["ip"],
            {"ip": row["ip"], "requests": 0, "chat": 0, "refused": 0, "failed": 0},
        )
        entry["requests"] += 1
        if row["method"] == "POST" and row["route"] in CHAT_ROUTES:
            entry["chat"] += 1
        if 400 <= row["status"] < 500:
            entry["refused"] += 1
        elif row["status"] >= 500:
            entry["failed"] += 1
        entry["last_seen"] = row["at"]
    busiest = sorted(by_ip.values(), key=lambda entry: entry["requests"], reverse=True)
    return {
        "by_ip": busiest[:HTTP_IP_ROWS],
        "recent": window[-HTTP_RECENT_ROWS:][::-1],
    }


class LiveMetrics:
    """Thread-safe rolling samples of finished requests."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._samples: deque[dict[str, Any]] = deque(maxlen=MAX_SAMPLES)
        self._guard_scans: deque[tuple[int, float]] = deque(maxlen=STAGE_WINDOW)
        self._http: deque[dict[str, Any]] = deque(maxlen=MAX_HTTP_ROWS)
        self._in_flight = 0

    def enter(self) -> None:
        with self._lock:
            self._in_flight += 1

    def leave(self, timing: dict[str, Any], status: int) -> None:
        """Close one request.  One that never reached the pipeline is not a sample."""
        started = timing.pop("started", None)
        # A named key's history row records the same finish time.
        finished = timing.pop("finished", None) or time.perf_counter()
        with self._lock:
            self._in_flight -= 1
            if started is None:
                return
            finished_at = self._clock()
            request_id = timing.get("request_id")
            block_source = timing.get("block_source")
            decision = (
                "allowed" if status == 200
                else "blocked" if status in (403, 413)
                else "failed"
            )
            self._samples.append(
                {
                    "at": finished_at,
                    "received_at": timing.get("received_at", finished_at),
                    "request_id": request_id if isinstance(request_id, str) else None,
                    "decision": decision,
                    "total_ms": round((finished - started) * 1000.0),
                    "input_ms": timing.get("input_ms"),
                    "generation_ms": timing.get("generation_ms"),
                    "output_ms": timing.get("output_ms"),
                    "prompt_tokens": timing.get("prompt_tokens"),
                    "reply_tokens": timing.get("reply_tokens"),
                    "block_categories": list(timing.get("block_categories") or []),
                    "allowed_categories": list(timing.get("allowed_categories") or []),
                    "block_source": block_source if isinstance(block_source, str) else None,
                }
            )

    def note_guard_scan(self, lane: str, tokens: int, elapsed_ms: float) -> None:
        """Record one guard model pass: the tokens it read and how long it took."""
        with self._lock:
            self._guard_scans.append((tokens, elapsed_ms))

    def note_http(
        self,
        ip: str,
        method: str,
        route: str,
        status: int,
        elapsed_ms: float,
        key: str | None = None,
    ) -> None:
        """Record one HTTP request: where it came from and how it ended."""
        if route in QUIET_ROUTES:
            return
        row = {
            "at": self._clock(),
            "ip": ip,
            "key": key,
            "method": method,
            "route": route,
            "status": status,
            "ms": round(elapsed_ms),
        }
        with self._lock:
            self._http.append(row)

    def snapshot(self) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            samples = list(self._samples)
            in_flight = self._in_flight
            scans = list(self._guard_scans)
            http_rows = list(self._http)
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
            "guard_tokens_per_second": {
                "latest": _scan_rate(scans[-1:]),
                "average": _scan_rate(scans),
            },
            "stages_ms": {
                "input": average("input_ms"),
                "generation": average("generation_ms"),
                "output": average("output_ms"),
            },
            "recent": recent,
            "traffic": _traffic(http_rows, now),
        }
