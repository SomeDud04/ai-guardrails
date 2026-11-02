"""The live OWASP runner and the evidence workbook it feeds."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_owasp_checklist as checklist  # noqa: E402
import run_owasp_corpus as corpus  # noqa: E402
import run_owasp_live as live  # noqa: E402


def record(**changes):
    base = {
        "id": "LLM01-001",
        "expect_status": 403,
        "expect_code": "POLICY_BLOCK",
        "guard_expect": "should_block",
        "coverage": "direct",
        "messages": [{"role": "user", "content": "hello"}],
    }
    base.update(changes)
    return base


def local_sender():
    policy = corpus.load_fixture_policy()
    send, _audit, close = corpus.make_local_sender(
        policy, corpus.load_effective_configuration(policy)
    )

    def adapter(body: bytes):
        response = send({}, body)
        return response.status, response.body

    return adapter, close


class ClassifyTests(unittest.TestCase):
    def test_an_attack_that_is_blocked_passes(self) -> None:
        self.assertEqual(live.classify(record(), 403, "POLICY_BLOCK", None)[0], "Pass")

    def test_an_attack_that_gets_a_reply_fails(self) -> None:
        self.assertEqual(live.classify(record(), 200, None, "sure")[0], "Fail")

    def test_a_safe_prompt_that_is_blocked_is_a_false_positive(self) -> None:
        safe = record(expect_status=200, expect_code=None, guard_expect="should_allow")
        result, note = live.classify(safe, 403, "POLICY_BLOCK", None)
        self.assertEqual(result, "Fail")
        self.assertIn("false positive", note)

    def test_an_open_question_is_left_for_a_person(self) -> None:
        open_row = record(expect_status=200, expect_code=None, guard_expect="unverified")
        self.assertEqual(live.classify(open_row, 200, None, "text")[0], "Unverified")
        self.assertEqual(live.classify(open_row, 403, "POLICY_BLOCK", None)[0], "Unverified")

    def test_raw_pii_in_the_reply_fails(self) -> None:
        pii = record(
            expect_status=200,
            expect_code=None,
            guard_expect="should_allow",
            messages=[{"role": "user", "content": "Email ali@example.com about it"}],
        )
        self.assertEqual(live.raw_pii(pii), ["ali@example.com"])
        self.assertEqual(live.classify(pii, 200, None, "Wrote to ali@example.com")[0], "Fail")
        self.assertEqual(live.classify(pii, 200, None, "Wrote to [EMAIL]")[0], "Pass")

    def test_an_answered_known_gap_is_an_expected_fail_not_a_pass(self) -> None:
        passport = record(
            id="LLM02-010",
            expect_status=200,
            expect_code=None,
            guard_expect="should_allow",
            coverage="known-gap",
            expect_behaviour="Passport numbers are not a supported entity: it passes. More.",
            messages=[{"role": "user", "content": "My synthetic passport is A12345678."}],
        )
        result, note = live.classify(passport, 200, None, "I cannot repeat that.")
        self.assertEqual(result, "Fail")
        self.assertIn("known gap", note)
        self.assertEqual(live.classify(passport, 403, "POLICY_BLOCK", None)[0], "Fail")

    def test_deterministic_rows_need_the_exact_status_and_code(self) -> None:
        limit = record(expect_status=413, expect_code="INPUT_LIMIT", guard_expect="should_allow")
        self.assertEqual(live.classify(limit, 413, "INPUT_LIMIT", None)[0], "Pass")
        self.assertEqual(live.classify(limit, 400, "INVALID_REQUEST", None)[0], "Fail")

    def test_a_deployment_limit_does_not_count_as_a_fail(self) -> None:
        safe = record(expect_status=200, expect_code=None, guard_expect="should_allow")
        self.assertEqual(live.classify(safe, 413, "INPUT_LIMIT", None)[0], "Unverified")

    def test_no_answer_is_blocked_not_judged(self) -> None:
        for status in (401, 429, 503):
            with self.subTest(status=status):
                self.assertEqual(live.classify(record(), status, None, None)[0], "Blocked")

    def test_a_limit_removed_on_purpose_is_not_applicable(self) -> None:
        stream = record(id="LLM06-004", expect_status=400, expect_code="INVALID_REQUEST")
        retired = live.retired_limits()
        self.assertIn("LLM06-004", retired)
        self.assertEqual(live.classify(stream, 200, None, "x", retired)[0], "N/A")
        self.assertEqual(live.classify(stream, 400, "INVALID_REQUEST", None, retired)[0], "Pass")

    def test_absent_surfaces_are_not_applicable(self) -> None:
        absent = record(coverage="not-applicable")
        self.assertEqual(live.classify(absent, 200, None, "x")[0], "N/A")


class RunTests(unittest.TestCase):
    def test_every_case_runs_end_to_end_and_fills_the_workbook(self) -> None:
        send, close = local_sender()
        self.addCleanup(close)
        records = corpus.load_records()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            report = live.run(records, send, report_path=path, meta={"base_url": "local"})
            saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(report["rows"]), len(records))
        self.assertEqual(saved["totals"], report["totals"])
        self.assertEqual(sum(report["totals"].values()), len(records))
        by_id = {row["id"]: row for row in report["rows"]}
        for item in records:
            if item["expect_status"] in (400, 413) and item["coverage"] != "not-applicable":
                with self.subTest(case=item["id"]):
                    # Offline the guards are doubles, so only these rows have a
                    # fixed answer: each passes or is a limit removed on purpose.
                    self.assertIn(by_id[item["id"]]["result"], ("Pass", "N/A"))

        data = checklist.fill_results(
            checklist.build_workbook_bytes(checklist.load_corpus()),
            [report],
            tester="Tester",
            build_label="abc1234",
            guard_label="test doubles",
        )
        import openpyxl

        wb = openpyxl.load_workbook(io.BytesIO(data))
        results = [cell.value for cell in wb["Checklist"]["S"][1:]]
        self.assertNotIn("Not Run", results)
        self.assertEqual(wb["Run Log"]["C2"].value, "abc1234")
        self.assertEqual(wb["Run Log"]["F2"].value, len(records))

    def test_a_rerun_replaces_only_its_own_cases(self) -> None:
        first = {"rows": [{"id": "LLM01-001", "result": "Blocked", "note": "503"}]}
        rerun = {"rows": [{"id": "LLM01-001", "result": "Pass", "status": 403, "note": "ok"}]}
        data = checklist.fill_results(
            checklist.build_workbook_bytes(checklist.load_corpus()),
            [first, rerun],
            tester="",
            build_label="",
            guard_label="",
        )
        import openpyxl

        wb = openpyxl.load_workbook(io.BytesIO(data))
        self.assertEqual(wb["Checklist"]["S2"].value, "Pass")
        self.assertEqual(wb["Checklist"]["S3"].value, "Not Run")

    def test_a_transport_failure_marks_the_case_blocked(self) -> None:
        def send(body):
            raise live.TransportError("URLError")

        report = live.run([record()], send)
        self.assertEqual(report["rows"][0]["result"], "Blocked")

    def test_the_key_is_never_written_to_the_report(self) -> None:
        send, close = local_sender()
        self.addCleanup(close)
        secret = "nlk_THIS-KEY-MUST-NOT-BE-SAVED"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            with mock.patch.dict(os.environ, {live.KEY_ENV: secret}), mock.patch.object(
                live, "make_sender", lambda base, key, timeout: send
            ):
                status = live.main(
                    ["--base-url", "http://127.0.0.1:9", "--report", str(path),
                     "--only", "LLM01-001,CTRL-001", "--pause", "0"]
                )
            text = path.read_text(encoding="utf-8")
        self.assertEqual(status, 0)
        self.assertNotIn(secret, text)
        self.assertEqual(len(json.loads(text)["rows"]), 2)

    def test_unknown_case_ids_are_refused(self) -> None:
        self.assertEqual(
            live.main(["--base-url", "http://127.0.0.1:9", "--report", "x.json", "--only", "NOPE-1"]),
            2,
        )


if __name__ == "__main__":
    unittest.main()
