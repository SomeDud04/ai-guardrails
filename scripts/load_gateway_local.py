"""Local gateway-only capacity harness for the real ASGI application.

The harness drives ``nasi_lemak.server.make_app`` in-process with deterministic
guard/tokenizer/generation doubles at 1, 2, 4 and 8 concurrent in-flight chat
requests.  It measures **gateway admission**, not production throughput: the
product's non-queuing admission semaphore, its control-plane admission cap and
its chat work deadline are exercised exactly as configured, and nothing is
added, widened or reordered.

Only structural invariants are asserted:

* admitted work never exceeds the configured cap,
* every acquired admission slot is released exactly once,
* a timed-out response releases no output and keeps its slot until the worker
  really finishes,
* overload responses are bounded and carry no generated output,
* the control-plane cap never blocks chat and returns to zero.

Wall-clock timings are recorded as data and are never asserted.  No socket,
model, guard artifact, provider or PostgreSQL server is contacted.

Usage::

    .\\.venv\\Scripts\\python.exe scripts/load_gateway_local.py
    .\\.venv\\Scripts\\python.exe scripts/load_gateway_local.py --json result.json

Exit status: 0 when every structural invariant holds, 1 otherwise.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.generation import conservative_byte_budget
from nasi_lemak.limits import ChatLimits
from nasi_lemak.policy import load_policy
from nasi_lemak.server import (
    DEFAULT_CHAT_WORK_TIMEOUT,
    DEFAULT_CONTROL_CONCURRENCY,
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_MAX_CONCURRENCY,
    make_app,
)

POLICY_FIXTURE = Path(__file__).resolve().with_name("owasp_corpus_policy.yaml")
LOCAL_TEST_KEY = "gateway-capacity-local-key-not-for-any-real-use"
DEFAULT_LEVELS = (1, 2, 4, 8)
CAPACITY_OUTPUT = "CAPACITY_SENTINEL_OUTPUT_7c1f"
PROBE_CONTENT = "Synthetic gateway capacity probe."
TOKEN_COUNTER = "nasi_lemak.generation.conservative_byte_budget"
# Short configured deadline for the dedicated deadline probe.  This uses the
# existing ``chat_work_timeout`` setting; it is not a new knob or threshold.
DEADLINE_PROBE_SECONDS = 0.05
BARRIER_TIMEOUT_SECONDS = 10.0
DRAIN_TIMEOUT_SECONDS = 10.0


class CapacityAdapters:
    """Deterministic doubles; barrier synchronises in-flight generation only."""

    def __init__(self, parties: int, generated: str = CAPACITY_OUTPUT) -> None:
        self.generated = generated
        self.barrier = threading.Barrier(parties) if parties > 1 else None
        self._lock = threading.Lock()
        self.generate_calls = 0

    def count_tokens(self, serialized: str) -> int:
        return conservative_byte_budget(serialized)

    def scan_attack(self, text: str) -> Any:
        return {"decision": "allow"}

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        with self._lock:
            self.generate_calls += 1
        barrier = self.barrier
        if barrier is not None:
            try:
                barrier.wait(timeout=BARRIER_TIMEOUT_SECONDS)
            except threading.BrokenBarrierError:
                # A broken barrier means the harness did not see the expected
                # in-flight count.  The request still returns; the level's
                # admission invariant records the discrepancy.
                pass
        return self.generated

    def scan_output(self, text: str) -> Any:
        return {"safe": True}


class DeadlineAdapters(CapacityAdapters):
    """Generation blocks until the harness releases it; no timing assumption."""

    def __init__(self) -> None:
        super().__init__(parties=1)
        self.started = threading.Event()
        self.release = threading.Event()

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        self.started.set()
        self.release.wait(BARRIER_TIMEOUT_SECONDS)
        return self.generated


class ObservedSemaphore:
    """Transparent proxy that records acquire/release accounting.

    ``make_app`` creates the real semaphore; replacing ``app.state.sem`` with
    this proxy exercises the same product code path and lets the harness prove
    one release per acquire.  ``asyncio.Semaphore`` permits over-release, so
    value-above-cap is recorded as a double release.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._semaphore = asyncio.Semaphore(limit)
        self.acquires = 0
        self.releases = 0
        self.in_flight = 0
        self.in_flight_max = 0
        self.value_after_release = limit
        self.double_release = False
        self.max_waiters = 0

    def locked(self) -> bool:
        waiters = getattr(self._semaphore, "_waiters", None) or ()
        self.max_waiters = max(self.max_waiters, len(waiters))
        return self._semaphore.locked()

    async def acquire(self) -> bool:
        result = await self._semaphore.acquire()
        self.acquires += 1
        self.in_flight += 1
        self.in_flight_max = max(self.in_flight_max, self.in_flight)
        if self.in_flight > self.limit:
            self.double_release = True
        return result

    def release(self) -> None:
        self.releases += 1
        self.in_flight -= 1
        if self.in_flight < 0:
            self.double_release = True
            self.in_flight = 0
        self._semaphore.release()
        self.value_after_release = getattr(self._semaphore, "_value", None)
        if (
            isinstance(self.value_after_release, int)
            and self.value_after_release > self.limit
        ):
            self.double_release = True
        waiters = getattr(self._semaphore, "_waiters", None) or ()
        self.max_waiters = max(self.max_waiters, len(waiters))

    def accounting(self) -> dict[str, Any]:
        return {
            "limit": self.limit,
            "acquires": self.acquires,
            "releases": self.releases,
            "in_flight_after": self.in_flight,
            "in_flight_max": self.in_flight_max,
            "value_after": self.value_after_release,
            "max_waiters": self.max_waiters,
            "double_release": self.double_release,
        }


class GatedReadyStore(SqliteAuditStore):
    """SQLite audit store whose readiness call blocks until the harness releases it."""

    def __init__(self, path: str | Path) -> None:
        super().__init__(path)
        self._lock = threading.Lock()
        self.entered_count = 0
        self.entered = threading.Event()
        self.release = threading.Event()

    def ready(self) -> bool:
        with self._lock:
            self.entered_count += 1
            if self.entered_count >= DEFAULT_CONTROL_CONCURRENCY:
                self.entered.set()
        self.release.wait(BARRIER_TIMEOUT_SECONDS)
        return True


def _build_app(
    adapters: Any,
    *,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
    control_concurrency: int = DEFAULT_CONTROL_CONCURRENCY,
    chat_work_timeout: float = DEFAULT_CHAT_WORK_TIMEOUT,
    store: SqliteAuditStore | None = None,
) -> tuple[Any, Path, tempfile.TemporaryDirectory]:
    temporary = tempfile.TemporaryDirectory(prefix="nasi-lemak-capacity-")
    root = Path(temporary.name)
    policy = load_policy(POLICY_FIXTURE)
    if store is None:
        store = SqliteAuditStore(root / "audit.sqlite3")
    gateway = Gateway(
        key_digest=hashlib.sha256(LOCAL_TEST_KEY.encode("utf-8")).hexdigest(),
        audit_store=store,
        adapters=adapters,
        policy=policy,
        limits=ChatLimits.defaults(),
    )
    app = make_app(
        gateway=gateway,
        environ={},
        max_body_bytes=DEFAULT_MAX_BODY_BYTES,
        max_concurrency=max_concurrency,
        control_concurrency=control_concurrency,
        chat_work_timeout=chat_work_timeout,
    )
    return app, root, temporary


def _request_body() -> bytes:
    return json.dumps(
        {
            "model": "pilot-local",
            "messages": [{"role": "user", "content": PROBE_CONTENT}],
        },
        separators=(",", ":"),
    ).encode("utf-8")


async def _asgi_request(
    app: Any,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: list[tuple[str, str]] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    raw_headers = [
        (key.lower().encode(), value.encode()) for key, value in (headers or [])
    ]
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": raw_headers,
        "client": ("127.0.0.1", 45678),
        "server": ("testserver", 80),
        "state": {},
    }
    await app(scope, receive, send)
    status = next(
        item["status"] for item in sent if item["type"] == "http.response.start"
    )
    response_headers = {
        key.decode().lower(): value.decode()
        for item in sent
        if item["type"] == "http.response.start"
        for key, value in item.get("headers", [])
    }
    response_body = b"".join(
        item.get("body", b"") for item in sent if item["type"] == "http.response.body"
    )
    return status, response_headers, response_body


async def _timed_chat(app: Any) -> tuple[int, bytes, float]:
    started = time.perf_counter()
    status, _headers, body = await _asgi_request(
        app,
        "POST",
        "/v1/chat/completions",
        body=_request_body(),
        headers=[
            ("content-type", "application/json"),
            ("authorization", "Bearer " + LOCAL_TEST_KEY),
        ],
    )
    return status, body, (time.perf_counter() - started) * 1000.0


async def _drain_chat(app: Any) -> None:
    deadline = time.monotonic() + DRAIN_TIMEOUT_SECONDS
    while app.state.chat_tasks and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    pending = list(app.state.chat_tasks)
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def _run_level(level: int, max_concurrency: int) -> dict[str, Any]:
    parties = min(level, max_concurrency)
    adapters = CapacityAdapters(parties)
    app, _root, temporary = _build_app(adapters, max_concurrency=max_concurrency)
    observed = ObservedSemaphore(max_concurrency)
    app.state.sem = observed
    try:
        wall_started = time.perf_counter()
        outcomes = await asyncio.gather(
            *[_timed_chat(app) for _ in range(level)]
        )
        await _drain_chat(app)
        wall_ms = round((time.perf_counter() - wall_started) * 1000.0, 3)
    finally:
        temporary.cleanup()

    statuses = [status for status, _body, _latency in outcomes]
    status_counts: dict[str, int] = {}
    for status in statuses:
        status_counts[str(status)] = status_counts.get(str(status), 0) + 1
    output_leaked = any(
        CAPACITY_OUTPUT.encode("utf-8") in body
        for status, body, _latency in outcomes
        if status != 200
    )
    non_success_has_choices = any(
        b'"choices"' in body for status, body, _latency in outcomes if status != 200
    )
    admitted = status_counts.get("200", 0)
    rejected = level - admitted
    accounting = observed.accounting()
    failures: list[str] = []
    if admitted > max_concurrency:
        failures.append("admitted work exceeded the configured cap")
    if rejected < 0:
        failures.append("response accounting is impossible")
    if level <= max_concurrency and rejected != 0:
        failures.append("a request was rejected below the configured cap")
    if level > max_concurrency and rejected < level - max_concurrency:
        failures.append("fewer overload responses than the cap requires")
    if status_counts.get("503", 0) != rejected:
        failures.append("rejected requests did not all return the overload status")
    if any(status not in (200, 503) for status in statuses):
        failures.append("unexpected response status")
    if output_leaked:
        failures.append("generated output leaked on a non-success response")
    if non_success_has_choices:
        failures.append("a non-success response carried a completion envelope")
    if accounting["double_release"]:
        failures.append("an admission slot was released more than once")
    if accounting["releases"] != accounting["acquires"]:
        failures.append("acquire/release accounting does not balance")
    if accounting["in_flight_after"] != 0:
        failures.append("an admission slot was not released")
    if accounting["value_after"] != max_concurrency:
        failures.append("the admission semaphore did not return to its limit")

    return {
        "concurrency": level,
        "admission_cap": max_concurrency,
        "admitted": admitted,
        "rejected_before_admission": rejected,
        "overloaded": rejected,
        "overload_rate": round(rejected / level, 6),
        "queueing": "none: saturated admission is rejected immediately",
        "max_in_flight": accounting["in_flight_max"],
        "status_counts": status_counts,
        "latencies_ms": [round(latency, 3) for _status, _body, latency in outcomes],
        "wall_ms": wall_ms,
        "slot_accounting": accounting,
        "output_leaked": output_leaked,
        "invariants_ok": not failures,
        "invariant_failures": failures,
    }


async def _run_deadline_probe() -> dict[str, Any]:
    adapters = DeadlineAdapters()
    app, _root, temporary = _build_app(
        adapters,
        max_concurrency=DEFAULT_MAX_CONCURRENCY,
        control_concurrency=DEFAULT_CONTROL_CONCURRENCY,
        chat_work_timeout=DEADLINE_PROBE_SECONDS,
    )
    observed = ObservedSemaphore(DEFAULT_MAX_CONCURRENCY)
    app.state.sem = observed
    failures: list[str] = []
    slot_after_response = None
    tasks_after_response = None
    latency_ms = None
    status = None
    body = b""
    try:
        task = asyncio.create_task(_timed_chat(app))
        started = await asyncio.to_thread(
            adapters.started.wait, BARRIER_TIMEOUT_SECONDS
        )
        if not started:
            failures.append("the deadline probe never reached generation")
        status, body, latency_ms = await asyncio.wait_for(task, timeout=10.0)
        slot_after_response = observed.in_flight
        tasks_after_response = len(app.state.chat_tasks)
        # The worker is still blocked in generation, so the slot must still be
        # held and no output may have been released.
        if status != 503:
            failures.append("a request past the chat work deadline did not return 503")
        if CAPACITY_OUTPUT.encode("utf-8") in body:
            failures.append("a timed-out response released generated output")
        if b'"choices"' in body:
            failures.append("a timed-out response carried a completion envelope")
        if slot_after_response != 1:
            failures.append("the admission slot was released before the worker finished")
        if tasks_after_response != 1:
            failures.append("the timed-out worker task was dropped before it finished")
    finally:
        adapters.release.set()
        await _drain_chat(app)
        accounting = observed.accounting()
        temporary.cleanup()

    if accounting["double_release"]:
        failures.append("an admission slot was released more than once")
    if accounting["acquires"] != 1 or accounting["releases"] != 1:
        failures.append("the deadline probe did not acquire and release exactly once")
    if accounting["in_flight_after"] != 0:
        failures.append("the deadline probe left a slot held")
    if accounting["value_after"] != DEFAULT_MAX_CONCURRENCY:
        failures.append("the deadline probe did not restore the semaphore")

    return {
        "configured_chat_work_timeout_seconds": DEADLINE_PROBE_SECONDS,
        "response_status": status,
        "response_latency_ms": None if latency_ms is None else round(latency_ms, 3),
        "slot_held_after_response": slot_after_response,
        "worker_tasks_after_response": tasks_after_response,
        "output_leaked": CAPACITY_OUTPUT.encode("utf-8") in body,
        "slot_accounting": accounting,
        "invariants_ok": not failures,
        "invariant_failures": failures,
    }


async def _run_control_probe() -> dict[str, Any]:
    temporary = tempfile.TemporaryDirectory(prefix="nasi-lemak-control-")
    root = Path(temporary.name)
    store = GatedReadyStore(root / "audit.sqlite3")
    app, _root, app_temporary = _build_app(
        CapacityAdapters(parties=1),
        control_concurrency=DEFAULT_CONTROL_CONCURRENCY,
        store=store,
    )
    failures: list[str] = []
    in_use_at_cap = None
    in_use_after = None
    statuses: list[int] = []
    try:
        tasks = [
            asyncio.create_task(
                _asgi_request(app, "GET", "/health/ready")
            )
            for _ in range(DEFAULT_CONTROL_CONCURRENCY * 2)
        ]
        entered = await asyncio.to_thread(store.entered.wait, BARRIER_TIMEOUT_SECONDS)
        if not entered:
            failures.append("the control-plane probe never saturated its cap")
        in_use_at_cap = app.state.control_admission.in_use
        store.release.set()
        results = await asyncio.gather(*tasks)
        statuses = [status for status, _headers, _body in results]
        in_use_after = app.state.control_admission.in_use
        if in_use_at_cap != DEFAULT_CONTROL_CONCURRENCY:
            failures.append("the control-plane cap admitted more or fewer than configured")
        if in_use_at_cap is not None and in_use_at_cap > DEFAULT_CONTROL_CONCURRENCY:
            failures.append("the control-plane cap exceeded its configured limit")
        if in_use_after != 0:
            failures.append("control-plane admission did not return to zero")
        if statuses.count(503) != DEFAULT_CONTROL_CONCURRENCY:
            failures.append("excess control-plane work was not rejected immediately")
    finally:
        store.release.set()
        app_temporary.cleanup()
        temporary.cleanup()

    return {
        "configured_control_concurrency": DEFAULT_CONTROL_CONCURRENCY,
        "requests": DEFAULT_CONTROL_CONCURRENCY * 2,
        "admitted_at_cap": in_use_at_cap,
        "in_use_after": in_use_after,
        "status_counts": {
            str(status): statuses.count(status) for status in set(statuses)
        },
        "queueing": "none: exhausted control admission is rejected immediately",
        "invariants_ok": not failures,
        "invariant_failures": failures,
    }


def run_capacity(levels: tuple[int, ...] = DEFAULT_LEVELS) -> dict[str, Any]:
    """Run every level plus the deadline and control-plane probes."""
    for level in levels:
        if isinstance(level, bool) or not isinstance(level, int) or level <= 0:
            raise ValueError("concurrency levels must be positive integers")
    started = time.perf_counter()
    level_results = [asyncio.run(_run_level(level, DEFAULT_MAX_CONCURRENCY)) for level in levels]
    deadline = asyncio.run(_run_deadline_probe())
    control = asyncio.run(_run_control_probe())
    failures: list[str] = []
    for result in level_results:
        if not result["invariants_ok"]:
            failures.extend(
                f"level {result['concurrency']}: {failure}"
                for failure in result["invariant_failures"]
            )
    if not deadline["invariants_ok"]:
        failures.extend(
            f"deadline probe: {failure}" for failure in deadline["invariant_failures"]
        )
    if not control["invariants_ok"]:
        failures.extend(
            f"control probe: {failure}" for failure in control["invariant_failures"]
        )

    return {
        "schema_version": 1,
        "mode": "local",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "configuration": {
            "max_concurrency": DEFAULT_MAX_CONCURRENCY,
            "configured_admission_cap": DEFAULT_MAX_CONCURRENCY,
            "control_concurrency": DEFAULT_CONTROL_CONCURRENCY,
            "chat_work_timeout_seconds": DEFAULT_CHAT_WORK_TIMEOUT,
            "body_limit_bytes": DEFAULT_MAX_BODY_BYTES,
            "token_counter": TOKEN_COUNTER,
            "request_path": (
                "nasi_lemak.server.make_app + direct ASGI invocation over the "
                "real Gateway with deterministic local adapters; no network"
            ),
            "note": (
                "Gateway-only admission capacity, not production throughput or "
                "provider-quota behaviour. Timings are data, not thresholds."
            ),
        },
        "levels": level_results,
        "deadline_probe": deadline,
        "control_probe": control,
        "invariants": {"ok": not failures, "failures": failures},
        "timings": {"total_ms": round((time.perf_counter() - started) * 1000.0, 3)},
        "policy_fixture": "scripts/owasp_corpus_policy.yaml",
    }


def _parse_levels(raw: str) -> tuple[int, ...]:
    values = []
    for part in raw.split(","):
        text = part.strip()
        if not text:
            raise ValueError("empty concurrency level")
        value = int(text, 10)
        if value <= 0:
            raise ValueError("concurrency levels must be positive")
        values.append(value)
    if not values:
        raise ValueError("at least one concurrency level is required")
    return tuple(values)


def _default_json_path() -> Path:
    return Path(tempfile.gettempdir()) / "nasi-lemak-gateway-capacity.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Exercise the existing local gateway admission, control and chat "
            "deadline limits at 1/2/4/8 concurrent requests."
        )
    )
    parser.add_argument(
        "--concurrency",
        default=",".join(str(level) for level in DEFAULT_LEVELS),
        help="comma-separated positive concurrency levels (default: 1,2,4,8)",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        default=str(_default_json_path()),
        help="metadata-only JSON result path",
    )
    args = parser.parse_args(argv)
    try:
        levels = _parse_levels(args.concurrency)
    except ValueError as error:
        print(f"Invalid --concurrency: {error}", file=sys.stderr)
        return 2

    result = run_capacity(levels)
    print(
        "capacity configuration: "
        f"configured_admission_cap={result['configuration']['max_concurrency']}, "
        f"control_concurrency={result['configuration']['control_concurrency']}, "
        f"token_counter={result['configuration']['token_counter']}"
    )
    print(
        "admission cap is the configured non-queuing limit; admitted/overloaded "
        "counts below are structural outcomes, not throughput measurements"
    )
    print(
        f"{'level':>5} {'admission_cap':>13} {'admitted':>8} {'overloaded':>10} "
        f"{'overload_rate':>13} {'max_in_flight':>13} {'latency_ms_max':>14}"
    )
    for level in result["levels"]:
        latencies = level["latencies_ms"] or [0.0]
        print(
            f"{level['concurrency']:>5} {level['admission_cap']:>13} "
            f"{level['admitted']:>8} {level['overloaded']:>10} "
            f"{level['overload_rate']:>13.3f} {level['max_in_flight']:>13} "
            f"{max(latencies):>14.3f}"
        )
    print(
        "deadline probe: "
        f"status={result['deadline_probe']['response_status']}, "
        f"slot_held_after_response="
        f"{result['deadline_probe']['slot_held_after_response']}"
    )
    print(
        "control probe: "
        f"admitted_at_cap={result['control_probe']['admitted_at_cap']}, "
        f"in_use_after={result['control_probe']['in_use_after']}"
    )
    path = Path(args.json_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Result written to {path}")
    if result["invariants"]["ok"]:
        print("Structural invariants: OK")
        return 0
    print("Structural invariants: FAILED", file=sys.stderr)
    for failure in result["invariants"]["failures"]:
        print(f"  {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
