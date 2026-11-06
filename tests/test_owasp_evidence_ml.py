"""Tests for the Malay/Chinese evidence sheets, reviewer columns and gap sheet.

All report and review inputs are small inline fixtures written to a temporary
directory.  The committed report and review files are never read here.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_owasp_checklist as checklist  # noqa: E402

WORKBOOK = checklist.WORKBOOK


def base_workbook() -> bytes:
    return checklist.build_workbook_bytes(checklist.load_corpus())


def ml_row(case_id: str, *, language: str, mirror: str, guard: str, title: str) -> dict:
    return {
        "id": case_id,
        "language": language,
        "mirror_of": mirror,
        "category": "LLM08",
        "title": title,
        "guard_expect": guard,
    }


def write_ml_corpus(folder: Path, rows: list[dict]) -> Path:
    payloads = folder / "payloads"
    payloads.mkdir()
    (payloads / "llm08_hidden_context_exposure.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )
    return payloads


def write_review(folder: Path, rows: list[dict]) -> Path:
    path = folder / "review.csv"
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["Case", "Proposed verdict", "Your verdict", "Your note"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def load_workbook(data: bytes):
    import openpyxl

    return openpyxl.load_workbook(io.BytesIO(data))


def row_for(ws, case_id: str) -> int:
    for row in range(2, ws.max_row + 1):
        if ws.cell(row=row, column=1).value == case_id:
            return row
    raise AssertionError(f"{case_id} not found")


def report(*rows: dict) -> dict:
    return {
        "started_at": "2026-11-06T02:29:31+00:00",
        "base_url": "http://127.0.0.1:8080",
        "runner_commit": "abc1234",
        "rows": list(rows),
    }


class MLSheetTests(unittest.TestCase):
    def test_the_ml_sheet_joins_the_report_to_the_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = write_ml_corpus(root, [
                ml_row("BM-LLM08-001", language="bm", mirror="LLM08-001",
                       guard="unverified", title="Direct system-prompt extraction"),
                ml_row("ZH-LLM08-001", language="zh", mirror="LLM08-001",
                       guard="should_block", title="Direct system-prompt extraction"),
            ])
            ml = report(
                {
                    "id": "BM-LLM08-001", "result": "Pass", "status": 200,
                    "verdict": "allowed", "latency_ms": 12, "request_id": "req_bm",
                    "note": "Answered.", "reply_excerpt": "x" * 400, "reply_chars": 400,
                },
                {
                    "id": "ZH-LLM08-001", "result": "Fail", "status": 200,
                    "verdict": "allowed", "latency_ms": 34, "request_id": "req_zh",
                    "note": "Leaked.", "block_reason": None, "reply_excerpt": "",
                    "reply_chars": 0,
                },
            )
            data = checklist.fill_results(
                base_workbook(), [], tester="Tester", build_label="abc1234",
                guard_label="doubles", ml_report=ml, ml_payload_root=payloads,
            )
        wb = load_workbook(data)
        ws = wb["Malay and Chinese"]
        self.assertEqual([cell.value for cell in ws[1]], list(checklist.ML_SHEET_HEADERS))

        bm_row = row_for(ws, "BM-LLM08-001")
        self.assertEqual(ws.cell(row=bm_row, column=2).value, "Malay")
        self.assertEqual(ws.cell(row=bm_row, column=3).value, "LLM08-001")
        self.assertEqual(ws.cell(row=bm_row, column=6).value, "Open")
        self.assertEqual(ws.cell(row=bm_row, column=7).value, "Pass")
        notes = ws.cell(row=bm_row, column=13).value
        self.assertIn("Reply:", notes)
        self.assertIn("x" * checklist.REPLY_NOTE_CHARS + "…", notes)

        zh_row = row_for(ws, "ZH-LLM08-001")
        self.assertEqual(ws.cell(row=zh_row, column=2).value, "Chinese")
        self.assertEqual(ws.cell(row=zh_row, column=6).value, "Block")
        self.assertEqual(ws.cell(row=zh_row, column=7).value, "Fail")

        self.assertEqual(wb["Run Log"]["F2"].value, 2)
        self.assertIn("Malay/Chinese", wb["Run Log"]["H2"].value)

    def test_gaps_hold_every_fail_unverified_and_blocked_row_sorted(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = write_ml_corpus(root, [
                ml_row("BM-LLM08-001", language="bm", mirror="LLM08-001",
                       guard="unverified", title="BM title"),
                ml_row("ZH-LLM08-001", language="zh", mirror="LLM08-001",
                       guard="should_block", title="ZH title"),
            ])
            english = report(
                {"id": "LLM08-001", "result": "Unverified", "request_id": "req_en"},
                {"id": "LLM08-002", "result": "Pass", "request_id": "req_pass"},
            )
            ml = report(
                {"id": "BM-LLM08-001", "result": "Fail", "request_id": "req_bm"},
                {"id": "ZH-LLM08-001", "result": "Blocked", "request_id": "req_zh"},
            )
            data = checklist.fill_results(
                base_workbook(), [english], tester="", build_label="", guard_label="",
                ml_report=ml, ml_payload_root=payloads,
            )
        wb = load_workbook(data)
        ws = wb["Outstanding Gaps"]
        self.assertEqual([cell.value for cell in ws[1]], list(checklist.GAP_SHEET_HEADERS))
        ids = [ws.cell(row=row, column=1).value for row in range(2, ws.max_row + 1)]
        self.assertEqual(ids, ["BM-LLM08-001", "LLM08-001", "ZH-LLM08-001"])
        self.assertEqual([ws.cell(row=row, column=5).value for row in range(2, 5)],
                         ["Fail", "Unverified", "Blocked"])
        self.assertNotIn("LLM08-002", ids)

    def test_an_unknown_ml_report_id_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = write_ml_corpus(root, [
                ml_row("BM-LLM08-001", language="bm", mirror="LLM08-001",
                       guard="unverified", title="Title"),
            ])
            ml = report({"id": "BM-NOPE-1", "result": "Pass"})
            with self.assertRaises(checklist.CorpusError):
                checklist.fill_results(
                    base_workbook(), [], tester="", build_label="", guard_label="",
                    ml_report=ml, ml_payload_root=payloads,
                )

    def test_ml_results_alone_produce_an_evidence_copy(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = write_ml_corpus(root, [
                ml_row("BM-LLM08-001", language="bm", mirror="LLM08-001",
                       guard="unverified", title="Title"),
            ])
            ml = report({"id": "BM-LLM08-001", "result": "Fail", "request_id": "req_bm"})
            data = checklist.fill_results(
                base_workbook(), [], tester="", build_label="", guard_label="",
                ml_report=ml, ml_payload_root=payloads,
            )
        wb = load_workbook(data)
        self.assertIn("Malay and Chinese", wb.sheetnames)
        self.assertIn("Outstanding Gaps", wb.sheetnames)
        self.assertEqual(wb["Malay and Chinese"].cell(row=2, column=1).value, "BM-LLM08-001")
        self.assertEqual(wb["Checklist"].max_column, len(checklist.CHECKLIST_HEADERS))


class ReviewColumnTests(unittest.TestCase):
    def test_review_verdicts_fill_the_checklist_and_ml_sheets(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = write_ml_corpus(root, [
                ml_row("BM-LLM08-001", language="bm", mirror="LLM08-001",
                       guard="unverified", title="Title"),
            ])
            review = write_review(root, [
                {"Case": "LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "Accept: safe", "Your note": "English note"},
                {"Case": "BM-LLM08-001", "Proposed verdict": "Review",
                 "Your verdict": "", "Your note": "Needs a second read"},
            ])
            english = report({"id": "LLM08-001", "result": "Unverified",
                              "request_id": "req_en"})
            ml = report({"id": "BM-LLM08-001", "result": "Fail",
                         "request_id": "req_bm"})
            data = checklist.fill_results(
                base_workbook(), [english], tester="", build_label="", guard_label="",
                ml_report=ml, review=review, ml_payload_root=payloads,
            )
        wb = load_workbook(data)
        sheet = wb["Checklist"]
        self.assertEqual(sheet.cell(row=1, column=26).value, "Reviewer verdict")
        self.assertEqual(sheet.cell(row=1, column=27).value, "Reviewer note")
        english_row = row_for(sheet, "LLM08-001")
        self.assertEqual(sheet.cell(row=english_row, column=26).value, "Accept: safe")
        self.assertEqual(sheet.cell(row=english_row, column=27).value, "English note")

        ml_sheet = wb["Malay and Chinese"]
        bm_row = row_for(ml_sheet, "BM-LLM08-001")
        self.assertEqual(ml_sheet.cell(row=bm_row, column=14).value, "(proposed) Review")
        self.assertEqual(ml_sheet.cell(row=bm_row, column=15).value, "Needs a second read")

        gaps = wb["Outstanding Gaps"]
        self.assertEqual(gaps.cell(row=row_for(gaps, "BM-LLM08-001"), column=6).value,
                         "(proposed) Review")
        self.assertEqual(gaps.cell(row=row_for(gaps, "LLM08-001"), column=6).value,
                         "Accept: safe")

    def test_a_control_character_in_a_review_note_is_escaped(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = write_ml_corpus(root, [
                ml_row("BM-LLM08-001", language="bm", mirror="LLM08-001",
                       guard="unverified", title="Title"),
            ])
            review = write_review(root, [
                {"Case": "LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "Accept", "Your note": "bad\x07note"},
                {"Case": "BM-LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "Accept", "Your note": "bad\x07note"},
            ])
            english = report({"id": "LLM08-001", "result": "Unverified"})
            ml = report({"id": "BM-LLM08-001", "result": "Fail"})
            data = checklist.fill_results(
                base_workbook(), [english], tester="", build_label="", guard_label="",
                ml_report=ml, review=review, ml_payload_root=payloads,
            )
        wb = load_workbook(data)
        checklist_sheet = wb["Checklist"]
        note_cell = checklist_sheet.cell(
            row=row_for(checklist_sheet, "LLM08-001"), column=27
        )
        self.assertEqual(note_cell.value, r"bad\u0007note")
        self.assertEqual(note_cell.data_type, "s")

        ml_sheet = wb["Malay and Chinese"]
        ml_note = ml_sheet.cell(row=row_for(ml_sheet, "BM-LLM08-001"), column=15)
        self.assertEqual(ml_note.value, r"bad\u0007note")
        self.assertEqual(ml_note.data_type, "s")

    def test_a_formula_like_review_value_is_stored_as_plain_text(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payloads = write_ml_corpus(root, [
                ml_row("BM-LLM08-001", language="bm", mirror="LLM08-001",
                       guard="unverified", title="Title"),
            ])
            review = write_review(root, [
                {"Case": "LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "=1+1", "Your note": "=1+1"},
                {"Case": "BM-LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "=1+1", "Your note": "=1+1"},
            ])
            english = report({"id": "LLM08-001", "result": "Unverified"})
            ml = report({"id": "BM-LLM08-001", "result": "Fail"})
            data = checklist.fill_results(
                base_workbook(), [english], tester="", build_label="", guard_label="",
                ml_report=ml, review=review, ml_payload_root=payloads,
            )
        wb = load_workbook(data)

        checklist_sheet = wb["Checklist"]
        english_row = row_for(checklist_sheet, "LLM08-001")
        for column in (26, 27):
            cell = checklist_sheet.cell(row=english_row, column=column)
            self.assertEqual(cell.value, "=1+1")
            self.assertEqual(cell.data_type, "s")

        ml_sheet = wb["Malay and Chinese"]
        ml_row_index = row_for(ml_sheet, "BM-LLM08-001")
        for column in (14, 15):
            cell = ml_sheet.cell(row=ml_row_index, column=column)
            self.assertEqual(cell.value, "=1+1")
            self.assertEqual(cell.data_type, "s")

        gaps = wb["Outstanding Gaps"]
        for case_id in ("BM-LLM08-001", "LLM08-001"):
            cell = gaps.cell(row=row_for(gaps, case_id), column=6)
            self.assertEqual(cell.value, "=1+1")
            self.assertEqual(cell.data_type, "s")

    def test_a_review_case_in_neither_sheet_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            review = write_review(root, [
                {"Case": "NOPE-1", "Proposed verdict": "Accept",
                 "Your verdict": "", "Your note": ""},
            ])
            with self.assertRaises(checklist.CorpusError):
                checklist.fill_results(
                    base_workbook(), [], tester="", build_label="", guard_label="",
                    review=review,
                )

    def test_review_only_produces_an_evidence_copy(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            review = write_review(root, [
                {"Case": "LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "", "Your note": ""},
            ])
            data = checklist.fill_results(
                base_workbook(), [], tester="", build_label="", guard_label="",
                review=review,
            )
        wb = load_workbook(data)
        sheet = wb["Checklist"]
        self.assertEqual(sheet.cell(row=row_for(sheet, "LLM08-001"), column=26).value,
                         "(proposed) Accept")
        self.assertIn("Outstanding Gaps", wb.sheetnames)
        self.assertNotIn("Malay and Chinese", wb.sheetnames)


class BlankWorkbookTests(unittest.TestCase):
    def test_build_workbook_bytes_matches_the_committed_blank_workbook(self) -> None:
        self.assertEqual(base_workbook(), WORKBOOK.read_bytes())

    def test_a_review_copy_does_not_change_the_source_bytes(self) -> None:
        blank = base_workbook()
        with tempfile.TemporaryDirectory() as folder:
            review = write_review(Path(folder), [
                {"Case": "LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "", "Your note": ""},
            ])
            evidence = checklist.fill_results(
                blank, [], tester="", build_label="", guard_label="", review=review,
            )
        self.assertNotEqual(blank, evidence)
        self.assertEqual(base_workbook(), blank)


class CommandLineTests(unittest.TestCase):
    def test_all_three_options_write_one_evidence_workbook(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            english_path = root / "english.json"
            ml_path = root / "ml.json"
            review = write_review(root, [
                {"Case": "LLM08-001", "Proposed verdict": "Accept",
                 "Your verdict": "", "Your note": "checked"},
            ])
            output = root / "evidence.xlsx"
            english_path.write_text(json.dumps(report(
                {"id": "LLM08-001", "result": "Unverified", "request_id": "req_en"}
            )), encoding="utf-8")
            ml_path.write_text(json.dumps(report(
                {"id": "BM-LLM08-001", "result": "Fail", "request_id": "req_bm"}
            )), encoding="utf-8")
            status = checklist.main([
                "--results", str(english_path),
                "--ml-results", str(ml_path),
                "--review", str(review),
                "--output", str(output),
                "--tester", "Tester",
            ])
            self.assertEqual(status, 0)
            wb = load_workbook(output.read_bytes())
        self.assertIn("Malay and Chinese", wb.sheetnames)
        self.assertIn("Outstanding Gaps", wb.sheetnames)
        self.assertEqual([cell.value for cell in wb["Checklist"][1]][24:27],
                         ["Notes", "Reviewer verdict", "Reviewer note"])
        self.assertEqual(wb["Run Log"]["F2"].value, 1)
        self.assertEqual(wb["Run Log"]["F3"].value, 1)


if __name__ == "__main__":
    unittest.main()
