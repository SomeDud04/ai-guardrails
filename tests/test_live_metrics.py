"""Tests for the in-memory Monitor timing."""

from __future__ import annotations

import time
import unittest

from nasi_lemak.live_metrics import MAX_SAMPLES, LiveMetrics, tokens_per_second


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

    def test_samples_are_bounded(self) -> None:
        for _ in range(MAX_SAMPLES + 5):
            self.finish()
        self.assertEqual(self.metrics.snapshot()["samples"], MAX_SAMPLES)


if __name__ == "__main__":
    unittest.main()
