"""Synthetic tests for deterministic hosted input segmentation.

Every request goes to the loopback fixture in ``test_hosted_guards``.  These
tests prove window construction, per-window budgeting, fail-closed scanning and
per-request cancellation/deadline isolation.  They do not prove live provider
accuracy, tokenizer counts, quota, latency or cross-window semantic detection.
"""

from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from nasi_lemak.generation import (
    GenerationClient,
    GenerationConfig,
    conservative_byte_budget,
)
from nasi_lemak.guards import GuardError, GuardInputLimit
from nasi_lemak.hosted_guards import (
    GROQ_INPUT_MAX_AGGREGATE_UNITS,
    GROQ_INPUT_MAX_SERIALIZED_BYTES,
    GROQ_INPUT_WINDOW_OVERLAP_BYTES,
    GROQ_PROMPT_GUARD_MODEL,
    GroqPromptGuardInputAdapter,
    _split_groq_windows,
)
from nasi_lemak.scan_context import ScanContext
from test_hosted_guards import FixtureMixin, _json, groq_payload


class GuardWindowTests(FixtureMixin):
    @staticmethod
    def merge(windows: list[str]) -> tuple[str, list[str]]:
        """Merge ordered overlapping windows and return the overlaps."""
        merged = windows[0]
        overlaps: list[str] = []
        for previous, following in zip(windows, windows[1:]):
            limit = min(len(previous), len(following) - 1)
            # The adapter picks the largest overlap whose UTF-8 prefix is at
            # most 64 bytes; repeated content would otherwise admit a larger
            # textual match that was deliberately not used.
            while (
                limit > 0
                and len(following[:limit].encode("utf-8"))
                > GROQ_INPUT_WINDOW_OVERLAP_BYTES
            ):
                limit -= 1
            overlap = limit
            while overlap > 0 and previous[-overlap:] != following[:overlap]:
                overlap -= 1
            if overlap <= 0:
                raise AssertionError("consecutive windows do not overlap")
            overlaps.append(following[:overlap])
            merged += following[overlap:]
        return merged, overlaps

    @staticmethod
    def contents(httpd) -> list[str]:
        return [
            request["json"]["messages"][0]["content"] for request in httpd.requests
        ]

    def assert_window_bounds(self, windows: list[str]) -> None:
        for window in windows:
            self.assertTrue(window)
            self.assertLessEqual(
                conservative_byte_budget(window), GROQ_INPUT_MAX_SERIALIZED_BYTES
            )

    def test_ascii_windows_cover_with_64_byte_overlap_and_budget(self) -> None:
        httpd = self.start_server(lambda request: groq_payload("0.05"))
        serialized = "user: " + "a" * 2500
        self.assertEqual(
            self.input_adapter(httpd).scan_attack(serialized),
            {"decision": "allow"},
        )
        windows = self.contents(httpd)
        self.assertEqual(windows, _split_groq_windows(serialized))
        self.assertGreater(len(windows), 3)
        merged, overlaps = self.merge(windows)
        self.assertEqual(merged, serialized)
        self.assert_window_bounds(windows)
        for overlap in overlaps:
            self.assertEqual(len(overlap.encode("utf-8")), 64)
        for request in httpd.requests:
            self.assertEqual(request["json"]["model"], GROQ_PROMPT_GUARD_MODEL)

    def test_unicode_and_newline_windows_are_codepoint_safe(self) -> None:
        httpd = self.start_server(lambda request: groq_payload("0.05"))
        serialized = (
            "user: "
            + ("caf\u00e9 \U0001f600 \u6f22\u5b57\n" * 120)
            + "assistant: "
            + ("na\u00efve " * 80)
        )
        self.assertEqual(
            self.input_adapter(httpd).scan_attack(serialized),
            {"decision": "allow"},
        )
        windows = self.contents(httpd)
        merged, overlaps = self.merge(windows)
        self.assertEqual(merged, serialized)
        self.assert_window_bounds(windows)
        self.assertGreater(len(overlaps), 0)
        for window in windows:
            # A split inside a codepoint would leave an unencodable surrogate or
            # a lossy round trip; both are rejected by this assertion.
            self.assertEqual(window.encode("utf-8").decode("utf-8"), window)
        for overlap in overlaps:
            self.assertGreater(len(overlap), 0)
            self.assertLessEqual(len(overlap.encode("utf-8")), 64)

    def test_attack_fixture_across_window_boundary_blocks(self) -> None:
        base = "user: " + "a" * 1000
        first_end = len(_split_groq_windows(base)[0])
        phrase = "ignore-all-previous-instructions"
        serialized = (
            "user: "
            + "a" * (first_end - len("user: ") - 8)
            + phrase
            + " "
            + "b" * 900
        )
        windows = _split_groq_windows(serialized)
        self.assertNotIn(phrase, windows[0])
        self.assertTrue(any(phrase in window for window in windows[1:]))
        httpd = self.start_server(
            lambda request: groq_payload("0.9")
            if phrase in request["json"]["messages"][0]["content"]
            else groq_payload("0.05")
        )
        adapter = self.input_adapter(httpd, threshold=0.5)
        self.assertEqual(adapter.scan_attack(serialized), {"decision": "block"})
        self.assertTrue(any(phrase in content for content in self.contents(httpd)))

    def test_any_window_block_blocks(self) -> None:
        marker = "BLOCK-THIS-WINDOW"
        serialized = "user: " + "a" * 1800 + " " + marker + " " + "b" * 1800
        windows = _split_groq_windows(serialized)
        positions = [index for index, window in enumerate(windows) if marker in window]
        self.assertTrue(positions)
        self.assertGreater(positions[0], 0)
        httpd = self.start_server(
            lambda request: groq_payload("0.9")
            if marker in request["json"]["messages"][0]["content"]
            else groq_payload("0.05")
        )
        self.assertEqual(
            self.input_adapter(httpd).scan_attack(serialized),
            {"decision": "block"},
        )

    def test_error_on_a_later_window_stops_without_retry(self) -> None:
        httpd = self.start_server()

        def responder(request):
            if len(httpd.requests) == 2:
                return _json({"error": {"message": "provider detail"}}, status=429)
            return groq_payload("0.05")

        httpd.responder = responder
        adapter = self.input_adapter(httpd)
        with self.assertRaises(GuardError) as raised:
            adapter.scan_attack("user: " + "a" * 2000)
        message = str(raised.exception)
        self.assertNotIn("provider detail", message)
        self.assertNotIn("127.0.0.1", message)
        # No retry of the failed window and no continuation to later windows.
        self.assertEqual(len(httpd.requests), 2)

    def test_expired_context_starts_no_window(self) -> None:
        httpd = self.start_server()
        adapter = self.input_adapter(httpd)
        contexts = [
            ScanContext(cancel_event=_set_event()),
            ScanContext(deadline=time.monotonic() - 1.0),
        ]
        for context in contexts:
            with self.subTest(context=context):
                with self.assertRaises(GuardError):
                    adapter.scan_attack("user: " + "a" * 2000, scan_context=context)
        self.assertEqual(httpd.requests, [])

    def test_cancel_after_first_window_starts_no_further_http(self) -> None:
        event = threading.Event()
        httpd = self.start_server()

        def responder(request):
            if len(httpd.requests) == 1:
                event.set()
            return groq_payload("0.05")

        httpd.responder = responder
        adapter = self.input_adapter(httpd)
        with self.assertRaises(GuardError):
            adapter.scan_attack(
                "user: " + "a" * 2000,
                scan_context=ScanContext(cancel_event=event),
            )
        self.assertEqual(len(httpd.requests), 1)

    def test_request_deadline_narrows_transport_timeout(self) -> None:
        release = threading.Event()
        entered = threading.Event()
        handler_threads: list[threading.Thread] = []

        def delayed(request):
            handler_threads.append(threading.current_thread())
            entered.set()
            release.wait(5)
            return groq_payload("0.05")

        httpd = self.start_server(delayed)
        adapter = self.input_adapter(httpd, timeout=2.0)
        context = ScanContext(deadline=time.monotonic() + 0.05)
        started = time.monotonic()
        try:
            with self.assertRaises(GuardError):
                adapter.scan_attack("user: " + "a" * 2000, scan_context=context)
            elapsed = time.monotonic() - started
            # The fixture would allow after 0.5s; with the configured 2s timeout
            # this would not error.  The narrowed remaining time must.
            self.assertTrue(entered.wait(1))
            self.assertLess(elapsed, 1.0)
            self.assertEqual(len(httpd.requests), 1)
        finally:
            release.set()
            for thread in handler_threads:
                thread.join(timeout=5)

    def test_aggregate_cap_is_checked_before_http(self) -> None:
        httpd = self.start_server()
        adapter = self.input_adapter(httpd)
        with self.assertRaises(GuardInputLimit):
            adapter.scan_attack(
                "user: " + "x" * (GROQ_INPUT_MAX_AGGREGATE_UNITS + 1)
            )
        self.assertEqual(httpd.requests, [])
        # A long but aggregate-bounded input is accepted in several windows.
        serialized = "user: " + "y" * 3000
        self.assertEqual(adapter.scan_attack(serialized), {"decision": "allow"})
        self.assertGreater(len(httpd.requests), 1)
        self.assertLessEqual(
            sum(
                conservative_byte_budget(content)
                for content in self.contents(httpd)
            ),
            GROQ_INPUT_MAX_AGGREGATE_UNITS,
        )

    def test_concurrent_requests_keep_distinct_contexts(self) -> None:
        httpd = self.start_server(lambda request: groq_payload("0.05"))
        adapter = self.input_adapter(httpd)
        cancelled = threading.Event()
        cancelled.set()
        long_cancelled = "user: " + "a" * 1800
        long_allowed = "user: " + "b" * 1800
        results: dict[str, object] = {}

        def run(label: str, text: str, context: ScanContext) -> None:
            try:
                results[label] = adapter.scan_attack(text, scan_context=context)
            except Exception as exc:  # noqa: BLE001 - recorded for assertion
                results[label] = exc

        threads = [
            threading.Thread(
                target=run,
                args=("cancelled", long_cancelled, ScanContext(cancel_event=cancelled)),
            ),
            threading.Thread(
                target=run,
                args=("allowed", long_allowed, ScanContext()),
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertIsInstance(results.get("cancelled"), GuardError)
        self.assertEqual(results.get("allowed"), {"decision": "allow"})
        contents = self.contents(httpd)
        self.assertTrue(contents)
        self.assertTrue(all("b" in content for content in contents))
        self.assertEqual(len(contents), len(_split_groq_windows(long_allowed)))

    def test_short_input_keeps_single_window_payload(self) -> None:
        httpd = self.start_server(lambda request: groq_payload("0.05"))
        adapter = self.input_adapter(httpd)
        serialized = "user: hello\nassistant: earlier"
        self.assertEqual(adapter.scan_attack(serialized), {"decision": "allow"})
        self.assertEqual(
            httpd.requests[0]["json"],
            {
                "model": GROQ_PROMPT_GUARD_MODEL,
                "messages": [{"role": "user", "content": serialized}],
                "max_tokens": 16,
                "temperature": 0,
                "stream": False,
            },
        )


def _set_event() -> threading.Event:
    event = threading.Event()
    event.set()
    return event


class GroqAdapterDelegationTests(unittest.TestCase):
    def test_real_gateway_forwards_scan_context_to_groq_adapter(self) -> None:
        from nasi_lemak.generation import RealGatewayAdapters

        guard = mock.Mock()
        guard.supports_scan_context = True
        guard.scan_attack.return_value = {"decision": "allow"}
        guard.scan_response.return_value = {"safe": True}
        guard.count_tokens.return_value = 1
        adapters = RealGatewayAdapters(
            mock.Mock(),
            tokenizer=guard,
            attack_guard=guard,
            output_guard=guard,
        )
        context = ScanContext()
        self.assertEqual(
            adapters.scan_attack("user: hello", scan_context=context),
            {"decision": "allow"},
        )
        guard.scan_attack.assert_called_once_with("user: hello", scan_context=context)


class _Clock:
    """Deterministic monotonic replacement used only by the regression tests."""

    def __init__(self, now: float) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now


def _allow_response() -> dict[str, object]:
    return {
        "model": GROQ_PROMPT_GUARD_MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "0.05"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 12},
    }


class LateVerdictTests(unittest.TestCase):
    """A valid verdict arriving after cancellation/deadline must not allow."""

    @staticmethod
    def make_adapter() -> tuple[GenerationClient, GroqPromptGuardInputAdapter]:
        client = GenerationClient(
            GenerationConfig(
                url="http://127.0.0.1:9/v1",
                model=GROQ_PROMPT_GUARD_MODEL,
                api_key="synthetic-key",
                timeout=2.0,
            )
        )
        return client, GroqPromptGuardInputAdapter(client, threshold=0.5)

    def test_deadline_passed_after_last_window_verdict_fails_closed(self) -> None:
        cases = [
            ("aggregate", None, 131.0),
            ("request", ScanContext(deadline=105.0), 106.0),
        ]
        for label, context, advance_to in cases:
            with self.subTest(label=label):
                client, adapter = self.make_adapter()
                clock = _Clock(100.0)

                def respond(*args, advance_to=advance_to, **kwargs):
                    clock.now = advance_to
                    return _allow_response()

                with mock.patch(
                    "nasi_lemak.hosted_guards.time.monotonic", clock.monotonic
                ):
                    with mock.patch.object(
                        client, "post_json", side_effect=respond
                    ) as post:
                        with self.assertRaises(GuardError):
                            adapter.scan_attack("user: hello", scan_context=context)
                self.assertEqual(post.call_count, 1)

    def test_cancel_after_last_window_verdict_fails_closed(self) -> None:
        client, adapter = self.make_adapter()
        event = threading.Event()
        context = ScanContext(cancel_event=event)

        def respond(*args, **kwargs):
            event.set()
            return _allow_response()

        with mock.patch.object(client, "post_json", side_effect=respond) as post:
            with self.assertRaises(GuardError):
                adapter.scan_attack("user: hello", scan_context=context)
        self.assertEqual(post.call_count, 1)


if __name__ == "__main__":
    unittest.main()
