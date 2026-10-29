"""Bounded local-guard inference pool and the explicit CPU thread budget.

Every local guard adapter used to serialise inference on one process-wide
``threading.Lock`` held across a whole scan.  On a multi-vCPU guard box that is
strictly one guard inference at a time no matter how many requests the HTTP
layer admits.  This module replaces the lock with a bounded pool of ``workers``
slots and records the CPU budget an operator may spend:

    workers * intra-op threads <= cpu_count

The pool preserves the existing discipline exactly:

* one slot per scan (tokenise and generate are one critical section, as the
  lock was);
* a per-scan deadline and an optional :class:`~nasi_lemak.scan_context.
  ScanContext` are honoured while waiting for a slot and re-checked *after* the
  slot is acquired, so a request that only reaches the model after its deadline
  never runs;
* no retry: a slot hands one request to the model at most once, and a failed
  request is released, never re-run;
* fail closed: any slot, deadline or cancellation failure raises
  :class:`~nasi_lemak.guard_errors.GuardError`.  A pool can never turn an error
  into an allow.

The module top level imports the standard library only.  ``torch`` is never
imported here; the caller sets the intra-op thread count through an explicit
backend or the lazy torch import in :mod:`nasi_lemak.guards`.
"""

from __future__ import annotations

import contextlib
import os
import threading
import time
from typing import Any, Iterator

from .guard_errors import GuardError

#: Derived default bounds.  ``workers`` is bounded so a large host does not open
#: an unbounded number of simultaneous 0.6B forward passes, and the intra-op
#: thread count is bounded to what a CPU guard box actually benefits from.
DEFAULT_MAX_WORKERS = 4
MAX_WORKERS = 8
DEFAULT_MAX_INTRA_OP_THREADS = 2
MAX_INTRA_OP_THREADS = 8

#: Cooperative wait slice while no slot is free.  Small enough to observe a
#: cancellation or deadline promptly, large enough not to spin.
_ACQUIRE_SLICE_SECONDS = 0.05


def cpu_total(cpu_count: Any = None) -> int:
    """Return the CPU count used for the budget, never below one."""
    if cpu_count is None:
        total: Any = os.cpu_count()
    else:
        total = cpu_count
    if isinstance(total, bool) or not isinstance(total, int) or total < 1:
        if cpu_count is not None:
            raise GuardError("guard worker budget is invalid")
        # An unreadable CPU count is treated as one CPU, which is the most
        # conservative budget and never over-subscribes an unknown host.
        return 1
    return total


def _bounded_count(value: Any, maximum: int, message: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise GuardError(message)
    return value


def default_inference_budget(cpu_count: Any = None) -> tuple[int, int]:
    """Return the derived ``(workers, intra_op_threads)`` for this CPU count.

    ``workers = clamp(cpu_count // 2, 1, DEFAULT_MAX_WORKERS)`` and the intra-op
    thread count is the largest value in ``1..DEFAULT_MAX_INTRA_OP_THREADS`` that
    keeps ``workers * threads <= cpu_count``.  On the 4-vCPU guard box that is
    ``(2, 2)``: two concurrent guard inferences, two torch intra-op threads
    each, four threads in total.
    """
    total = cpu_total(cpu_count)
    workers = min(DEFAULT_MAX_WORKERS, max(1, total // 2))
    threads = max(1, min(DEFAULT_MAX_INTRA_OP_THREADS, total // workers))
    return workers, threads


def resolve_inference_budget(
    workers: Any = None,
    threads: Any = None,
    cpu_count: Any = None,
) -> tuple[int, int]:
    """Validate an explicit budget, or derive the default for the CPU count.

    An explicit value outside ``1..MAX_WORKERS`` / ``1..MAX_INTRA_OP_THREADS`` is
    rejected, and so is a pair whose product exceeds the CPU count.  Nothing is
    clamped silently: a nonsensical budget leaves the app unready instead of
    quietly running with a different one.
    """
    total = cpu_total(cpu_count)
    default_workers, default_threads = default_inference_budget(total)
    resolved_workers = (
        default_workers
        if workers is None
        else _bounded_count(workers, MAX_WORKERS, "guard worker count is invalid")
    )
    resolved_threads = (
        default_threads
        if threads is None
        else _bounded_count(
            threads, MAX_INTRA_OP_THREADS, "guard thread count is invalid"
        )
    )
    if resolved_workers * resolved_threads > total:
        raise GuardError("guard worker budget exceeds the available CPU count")
    return resolved_workers, resolved_threads


class GuardInferencePool:
    """A bounded pool of at most ``workers`` concurrent guard inference slots.

    The pool owns no threads: a slot is held by the calling thread for the
    duration of one scan, which is exactly the critical section the previous
    process-wide lock protected.  A :class:`threading.BoundedSemaphore` makes an
    unbalanced release a programming error instead of a silent extra slot.
    """

    def __init__(self, workers: Any) -> None:
        self._workers = _bounded_count(workers, MAX_WORKERS, "guard worker count is invalid")
        self._slots = threading.BoundedSemaphore(self._workers)

    @property
    def workers(self) -> int:
        return self._workers

    def _acquire(self, deadline: float | None, scan_context: Any) -> None:
        while True:
            if scan_context is not None and scan_context.cancelled():
                raise GuardError("guard inference was cancelled")
            if deadline is None:
                wait = _ACQUIRE_SLICE_SECONDS
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GuardError("guard inference deadline was exceeded")
                wait = min(_ACQUIRE_SLICE_SECONDS, remaining)
            if not self._slots.acquire(timeout=wait):
                continue
            # Re-check after acquiring.  A slot that is handed over at or after
            # the deadline, or to a cancelled request, must not reach a model.
            try:
                if scan_context is not None and scan_context.cancelled():
                    raise GuardError("guard inference was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    raise GuardError("guard inference deadline was exceeded")
            except GuardError:
                self._slots.release()
                raise
            return

    @contextlib.contextmanager
    def slot(
        self,
        *,
        deadline: float | None = None,
        scan_context: Any = None,
    ) -> Iterator["GuardInferencePool"]:
        """Hold one inference slot for the duration of the ``with`` block.

        The block runs at most once.  An exception inside it is released to the
        caller unchanged (the adapters raise ``GuardError``, which the gateway
        fails closed on); it is never retried and never converted to an allow.
        """
        self._acquire(deadline, scan_context)
        try:
            yield self
        finally:
            self._slots.release()
