"""Tests for the in-memory Monitor timing."""

from __future__ import annotations

import time
import unittest

from nasi_lemak.live_metrics import (
    HTTP_IP_ROWS,
    HTTP_RECENT_ROWS,
    HTTP_WINDOW_SECONDS,
    MAX_HTTP_ROWS,
    MAX_SAMPLES,
    LiveMetrics,
    tokens_per_second,
)


def timing(**values: float) -> dict:
    return {"started": time.perf_counter(), **values}


class LiveMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1000.0
        self.metrics = LiveMetrics(clock=lambda: self.now)

    def finish(self, status: int = 200, **values: float) -> None:
        self.metrics.enter()
        self.metrics.leave(timing(**values), status)

    def test_tokens_per_second_uses_generation_time_only(self) -> None:
        self.assertEqual(
            tokens_per_second({"reply_tokens": 300, "generation_ms": 6000, "input_ms": 9000}),
            50.0,
        )

    def test_missing_usage_gives_no_rate(self) -> None:
        self.assertIsNone(tokens_per_second({"generation_ms": 6000}))
        self.assertIsNone(tokens_per_second({"reply_tokens": 0, "generation_ms": 6000}))
        self.assertIsNone(tokens_per_second({"reply_tokens": 10, "generation_ms": 0}))

    def test_in_flight_rises_and_falls(self) -> None:
        self.metrics.enter()
        self.assertEqual(self.metrics.snapshot()["in_flight"], 1)
        self.metrics.leave({}, 401)
        self.assertEqual(self.metrics.snapshot()["in_flight"], 0)

    def test_a_request_that_never_reached_the_pipeline_is_not_a_sample(self) -> None:
        self.metrics.enter()
        self.metrics.leave({}, 401)
        self.assertEqual(self.metrics.snapshot()["samples"], 0)

    def test_results_follow_the_status(self) -> None:
        for status in (200, 403, 413, 503):
            self.finish(status)
        decisions = [row["decision"] for row in self.metrics.snapshot()["recent"]]
        self.assertEqual(decisions, ["failed", "blocked", "blocked", "allowed"])

    def test_last_minute_drops_older_samples(self) -> None:
        self.finish(reply_tokens=10, generation_ms=1000)
        self.now += 61.0
        self.finish(reply_tokens=20, generation_ms=1000)
        minute = self.metrics.snapshot()["last_minute"]
        self.assertEqual(minute, {"requests": 1, "reply_tokens": 20})

    def test_rates_and_stages_summarise_recent_requests(self) -> None:
        self.finish(reply_tokens=100, generation_ms=2000, input_ms=4000, output_ms=1000)
        self.finish(reply_tokens=300, generation_ms=2000, input_ms=6000, output_ms=3000)
        snapshot = self.metrics.snapshot()
        self.assertEqual(snapshot["tokens_per_second"], {"latest": 150.0, "average": 100.0})
        self.assertEqual(
            snapshot["stages_ms"], {"input": 5000, "generation": 2000, "output": 2000}
        )

    def test_guard_rate_is_weighted_by_tokens_read(self) -> None:
        self.metrics.note_guard_scan("input", 100, 1000.0)
        self.metrics.note_guard_scan("response", 300, 1000.0)
        self.assertEqual(
            self.metrics.snapshot()["guard_tokens_per_second"],
            {"latest": 300.0, "average": 200.0},
        )

    def test_no_guard_scan_gives_no_rate(self) -> None:
        self.assertEqual(
            self.metrics.snapshot()["guard_tokens_per_second"],
            {"latest": None, "average": None},
        )

    def test_traffic_is_counted_per_address_busiest_first(self) -> None:
        self.metrics.note_http("10.0.0.1", "POST", "/chat", 200, 15000.0)
        self.metrics.note_http("10.0.0.2", "POST", "/chat", 403, 900.0)
        self.metrics.note_http("10.0.0.2", "POST", "/chat", 401, 2.0)
        self.metrics.note_http("10.0.0.2", "GET", "/workspace", 503, 3.0)
        by_ip = self.metrics.snapshot()["traffic"]["by_ip"]
        self.assertEqual([row["ip"] for row in by_ip], ["10.0.0.2", "10.0.0.1"])
        busy = by_ip[0]
        self.assertEqual(
            (busy["requests"], busy["chat"], busy["refused"], busy["failed"]),
            (3, 2, 2, 1),
        )

    def test_only_a_post_counts_as_a_chat(self) -> None:
        route = "/workspace/api/conversations/{conversation_id}/messages"
        self.metrics.note_http("10.0.0.1", "GET", route, 200, 1.0)
        self.assertEqual(self.metrics.snapshot()["traffic"]["by_ip"][0]["chat"], 0)

    def test_health_and_monitor_refreshes_are_not_traffic(self) -> None:
        for route in ("/health/ready", "/workspace/api/admin/live"):
            self.metrics.note_http("10.0.0.1", "GET", route, 200, 1.0)
        self.assertEqual(
            self.metrics.snapshot()["traffic"], {"by_ip": [], "recent": []}
        )

    def test_traffic_older_than_the_window_is_dropped(self) -> None:
        self.metrics.note_http("10.0.0.1", "GET", "/workspace", 200, 1.0)
        self.now += HTTP_WINDOW_SECONDS + 1
        self.metrics.note_http("10.0.0.2", "GET", "/workspace", 200, 1.0)
        traffic = self.metrics.snapshot()["traffic"]
        self.assertEqual([row["ip"] for row in traffic["by_ip"]], ["10.0.0.2"])
        self.assertEqual([row["ip"] for row in traffic["recent"]], ["10.0.0.2"])

    def test_http_rows_are_bounded_and_newest_first(self) -> None:
        for number in range(MAX_HTTP_ROWS + 5):
            self.metrics.note_http(f"10.0.{number // 256}.{number % 256}", "GET", "/", 200, 1.0)
        traffic = self.metrics.snapshot()["traffic"]
        self.assertEqual(len(traffic["by_ip"]), HTTP_IP_ROWS)
        self.assertEqual(len(traffic["recent"]), HTTP_RECENT_ROWS)
        self.assertEqual(self.metrics._http.maxlen, MAX_HTTP_ROWS)
        self.assertEqual(traffic["recent"][0]["ip"], "10.0.19.140")

    def test_samples_are_bounded(self) -> None:
        for _ in range(MAX_SAMPLES + 5):
            self.finish()
        self.assertEqual(self.metrics.snapshot()["samples"], MAX_SAMPLES)


if __name__ == "__main__":
    unittest.main()
