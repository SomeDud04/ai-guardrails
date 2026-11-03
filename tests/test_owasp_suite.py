"""Contract tests for the frozen OWASP LLM Top 10 (2026) payload corpus.

Standard library only.  openpyxl is imported behind ``skipUnless`` so the
default suite runs without the optional ``eval`` extra.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = ROOT / "evals" / "owasp" / "llm-top10-2026"
PAYLOAD_ROOT = CORPUS_ROOT / "payloads"
WORKBOOK = CORPUS_ROOT / "OWASP-LLM-Top10-2026-checklist.xlsx"
MANIFEST = CORPUS_ROOT / "MANIFEST.sha256"
SCHEMA_PATH = CORPUS_ROOT / "schema.json"
BUILDER_PATH = ROOT / "scripts" / "build_owasp_checklist.py"

EXPECTED_FILES = {
    "LLM01": "llm01_prompt_injection.jsonl",
    "LLM02": "llm02_sensitive_information.jsonl",
    "LLM03": "llm03_excessive_agency.jsonl",
    "LLM04": "llm04_supply_chain.jsonl",
    "LLM05": "llm05_data_model_poisoning.jsonl",
    "LLM06": "llm06_unbounded_consumption.jsonl",
    "LLM07": "llm07_misinformation.jsonl",
    "LLM08": "llm08_hidden_context_exposure.jsonl",
    "LLM09": "llm09_vector_embedding.jsonl",
    "LLM10": "llm10_improper_output_handling.jsonl",
    "CTRL": "controls_benign.jsonl",
}
EXPECTED_COUNTS = {
    "LLM01": 20, "LLM02": 16, "LLM03": 8, "LLM04": 7, "LLM05": 5,
    "LLM06": 12, "LLM07": 9, "LLM08": 14, "LLM09": 6, "LLM10": 13, "CTRL": 18,
}
EXPECTED_TOTAL = 128
EXPECTED_HEADERS = [
    "ID", "Category", "Category Name", "Coverage", "Technique", "Severity", "Title",
    "Payload (first user message)", "Messages (full JSON)", "Extra Request Fields",
    "Guard Expectation", "Expected HTTP Status", "Expected Error Code",
    "Expected Behaviour", "Control Exercised", "Evidence To Capture",
    "Needs Real Guard (Y/N)", "Reference", "Result", "Actual HTTP Status",
    "Actual Guard Verdict", "Latency (ms)", "Tester", "Date Tested", "Notes",
]
REFERENCE_PAGES = {
    "LLM01": 10, "LLM02": 18, "LLM03": 23, "LLM04": 27, "LLM05": 33,
    "LLM06": 38, "LLM07": 43, "LLM08": 46, "LLM09": 50, "LLM10": 55,
}
EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})", re.I)
URL = re.compile(r"https?://([^/\s\"'<>]+)", re.I)
PHONE_SHAPE = re.compile(r"(?<!\w)(?:\+?60|0)1\d(?:[ -]?\d){7,8}(?!\w)")
MYKAD_SHAPE = re.compile(r"(?<!\d)\d{6}-?\d{2}-?\d{4}(?!\d)")
SECRET_SHAPES = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)password\s*[:=]\s*\S+"),
)
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.my"}
ALLOWED_URL_HOSTS = {"example.com", "models.upstream.example", "127.0.0.1"}
ALLOWED_PHONES = {"60123456789", "0123456789", "+60123456789", "012-345 6789", "+60 12-345 6789"}
ALLOWED_MYKADS = {"900101-14-5678", "900101145678", "991332-14-5678"}


def load_builder():
    spec = importlib.util.spec_from_file_location("build_owasp_checklist", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_records():
    records = []
    for category, filename in EXPECTED_FILES.items():
        path = PAYLOAD_ROOT / filename
        if not path.is_file():
            continue
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    records.append(json.loads(line))
    return records


def _json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def validate_json_schema(instance, schema, path="$"):
    """Small draft 2020-12 subset validator used by these tests only."""
    errors = []
    expected = schema.get("type")
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        actual = _json_type(instance)
        if actual not in allowed and not (actual == "integer" and "number" in allowed):
            errors.append(f"{path}: expected {allowed}, got {actual}")
            return errors
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append(f"{path}: does not match pattern")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                errors.extend(validate_json_schema(item, item_schema, f"{path}[{index}]"))
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}: unexpected {key}")
        for key, subschema in properties.items():
            if key in instance and isinstance(subschema, dict):
                errors.extend(validate_json_schema(instance[key], subschema, f"{path}.{key}"))
    return errors


def iter_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)


def synthetic_data_problems(records):
    """Return human-readable problems for real-looking secrets or domains."""
    problems = []
    for record in records:
        for text in iter_strings(record):
            for match in EMAIL.finditer(text):
                if match.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
                    problems.append(f"{record.get('id')}: non-synthetic email domain {match.group(1)}")
            for match in URL.finditer(text):
                host = match.group(1).split(":", 1)[0].lower()
                if host not in ALLOWED_URL_HOSTS:
                    problems.append(f"{record.get('id')}: non-synthetic URL host {host}")
            for match in PHONE_SHAPE.finditer(text):
                if match.group(0) not in ALLOWED_PHONES:
                    problems.append(f"{record.get('id')}: unexpected phone value {match.group(0)!r}")
            for match in MYKAD_SHAPE.finditer(text):
                if match.group(0) not in ALLOWED_MYKADS:
                    problems.append(f"{record.get('id')}: unexpected MyKad-shaped value {match.group(0)!r}")
            for pattern in SECRET_SHAPES:
                if pattern.search(text):
                    problems.append(f"{record.get('id')}: secret-shaped string {pattern.pattern!r}")
    return problems


class CorpusTests(unittest.TestCase):
    def test_payload_files_and_counts(self):
        for category, filename in EXPECTED_FILES.items():
            path = PAYLOAD_ROOT / filename
            self.assertTrue(path.is_file(), f"missing {filename}")
            with path.open(encoding="utf-8") as handle:
                count = sum(1 for line in handle if line.strip())
            self.assertEqual(count, EXPECTED_COUNTS[category], filename)

    def test_total_threshold(self):
        records = load_records()
        self.assertEqual(len(records), EXPECTED_TOTAL)
        self.assertGreaterEqual(len(records), 128)

    def test_ids_unique_zero_padded_and_sequential(self):
        records = load_records()
        ids = [record["id"] for record in records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate id in corpus")
        for category, expected in EXPECTED_COUNTS.items():
            category_ids = [record["id"] for record in records if record["category"] == category]
            expected_ids = [f"{category}-{number:03d}" for number in range(1, expected + 1)]
            self.assertEqual(category_ids, expected_ids, category)

    def test_records_validate_against_schema(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        for record in load_records():
            errors = validate_json_schema(record, schema)
            self.assertEqual(errors, [], f"{record.get('id')}: {errors[:3]}")

    def test_required_text_and_codes(self):
        for record in load_records():
            with self.subTest(record=record["id"]):
                for key in ("expect_behaviour", "evidence", "reference", "control", "technique"):
                    self.assertTrue(record[key].strip(), f"{record['id']} has empty {key}")
                self.assertNotEqual(record["expect_status"], 500)
                expected_code = {200: None, 400: "INVALID_REQUEST", 403: "POLICY_BLOCK",
                                 413: "INPUT_LIMIT"}[record["expect_status"]]
                self.assertEqual(record["expect_code"], expected_code)
                if record["coverage"] in {"known-gap", "not-applicable", "benign-control"}:
                    self.assertEqual(record["expect_status"], 200, record["id"])
                if record["expect_status"] in {400, 413}:
                    self.assertFalse(record["needs_guard_model"],
                                     f"{record['id']} is deterministic and must not need the guard model")
                if record["category"] in REFERENCE_PAGES:
                    self.assertEqual(record["reference"],
                                     f"OWASP {record['category']}:2026 p.{REFERENCE_PAGES[record['category']]}")
                else:
                    self.assertIn("control baseline", record["reference"])

    def test_synthetic_data_only(self):
        problems = synthetic_data_problems(load_records())
        self.assertEqual(problems, [], "\n".join(problems[:10]))

    def test_synthetic_scan_catches_bad_domain_and_secret(self):
        bad_domain = [{"id": "CTRL-001", "messages": [{"role": "user", "content": "mail bob@gmail.com"}]}]
        self.assertTrue(synthetic_data_problems(bad_domain))
        bad_secret = [{"id": "CTRL-001", "messages": [{"role": "user", "content": "token AKIAABCDEFGHIJKLMNOP"}]}]
        self.assertTrue(synthetic_data_problems(bad_secret))

    def test_manifest_matches_files(self):
        builder = load_builder()
        text = MANIFEST.read_text(encoding="utf-8")
        entries = builder.manifest_entries(text)
        self.assertEqual(set(entries), {f"payloads/{name}" for name in EXPECTED_FILES.values()} | {WORKBOOK.name})
        for relative, digest in entries.items():
            path = CORPUS_ROOT / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(builder.file_sha256(path), digest, f"{relative} hash drift")
        records = load_records()
        self.assertEqual(builder.manifest_corpus_digest(text), builder.corpus_digest(records))

    def test_generator_check_is_clean(self):
        builder = load_builder()
        self.assertEqual(builder.check(), [])

    def test_loader_rejects_bad_corpora(self):
        builder = load_builder()
        records = load_records()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for category, filename in EXPECTED_FILES.items():
                shutil.copyfile(PAYLOAD_ROOT / filename, root / filename)

            def rewrite(filename, mutate):
                path = root / filename
                items = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
                mutate(items)
                path.write_text(
                    "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in items),
                    encoding="utf-8", newline="\n",
                )

            filename = EXPECTED_FILES["LLM01"]

            with self.subTest(case="duplicate id"):
                shutil.copyfile(PAYLOAD_ROOT / filename, root / filename)
                with (root / filename).open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(json.dumps(records[0], ensure_ascii=False) + "\n")
                with self.assertRaises(builder.CorpusError):
                    builder.load_corpus(root)

            with self.subTest(case="missing category"):
                shutil.copyfile(PAYLOAD_ROOT / filename, root / filename)

                def mutate(items):
                    items[0].pop("category")
                rewrite(filename, mutate)
                with self.assertRaises(builder.CorpusError):
                    builder.load_corpus(root)

            with self.subTest(case="unknown coverage"):
                shutil.copyfile(PAYLOAD_ROOT / filename, root / filename)

                def mutate(items):
                    items[0]["coverage"] = "totally-covered"
                rewrite(filename, mutate)
                with self.assertRaises(builder.CorpusError):
                    builder.load_corpus(root)

            with self.subTest(case="500 status"):
                shutil.copyfile(PAYLOAD_ROOT / filename, root / filename)

                def mutate(items):
                    items[0]["expect_status"] = 500
                    items[0]["expect_code"] = None
                rewrite(filename, mutate)
                with self.assertRaises(builder.CorpusError):
                    builder.load_corpus(root)

            with self.subTest(case="below threshold"):
                shutil.copyfile(PAYLOAD_ROOT / filename, root / filename)
                lines = (root / filename).read_text(encoding="utf-8").splitlines()
                (root / filename).write_text("\n".join(lines[:10]) + "\n", encoding="utf-8", newline="\n")
                with self.assertRaises(builder.CorpusError):
                    builder.load_corpus(root)


def _openpyxl_available():
    try:
        import openpyxl  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(_openpyxl_available(), "openpyxl is not installed (optional eval extra)")
class WorkbookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from openpyxl import load_workbook

        cls.workbook = load_workbook(WORKBOOK)
        cls.records = load_records()
        cls.builder = load_builder()

    def test_sheet_order_and_row_counts(self):
        self.assertEqual(
            self.workbook.sheetnames,
            ["Read Me", "Checklist", "Summary", "Category Map", "Known Gaps", "Run Log"],
        )
        checklist = self.workbook["Checklist"]
        self.assertEqual(checklist.max_row, len(self.records) + 1)
        self.assertEqual([cell.value for cell in checklist[1]], EXPECTED_HEADERS)
        self.assertEqual(
            [checklist.cell(row=row, column=1).value for row in range(2, checklist.max_row + 1)],
            [record["id"] for record in self.records],
        )

    def test_freeze_filter_validation_and_formatting(self):
        checklist = self.workbook["Checklist"]
        last = len(self.records) + 1
        self.assertEqual(checklist.freeze_panes, "C2")
        self.assertEqual(checklist.auto_filter.ref, f"A1:Y{last}")
        validations = {str(item.sqref): item.formula1 for item in checklist.data_validations.dataValidation}
        self.assertEqual(validations[f"S2:S{last}"], '"Not Run,Pass,Fail,Blocked,Unverified,N/A"')
        self.assertEqual(validations[f"U2:U{last}"], '"blocked,allowed,error,n/a"')
        rules = []
        for cells, entries in checklist.conditional_formatting._cf_rules.items():
            self.assertEqual(str(cells.sqref), f"S2:S{last}")
            for rule in entries:
                rules.extend(rule.formula)
        for value in ("Pass", "Fail", "Blocked", "Unverified", "N/A"):
            self.assertIn(f'"{value}"', rules)
        for coordinate in ("H2", "N2", "O2", "P2"):
            self.assertTrue(checklist[coordinate].alignment.wrap_text, coordinate)

    def test_print_and_bulk(self):
        checklist = self.workbook["Checklist"]
        self.assertEqual(checklist.page_setup.orientation, "landscape")
        self.assertEqual(checklist.page_setup.fitToWidth, 1)
        self.assertIn(checklist.print_title_rows, {"1:1", "$1:$1"})
        self.assertLess(WORKBOOK.stat().st_size, 2 * 1024 * 1024)
        self.assertFalse(self.workbook._external_links)
        for worksheet in self.workbook.worksheets:
            self.assertEqual(len(worksheet._images), 0)

    def test_summary_distinguishes_caveats(self):
        summary = self.workbook["Summary"]
        formulas = [str(cell.value) for row in summary.iter_rows() for cell in row if cell.value]
        joined = "\n".join(formulas)
        self.assertIn("COUNTIF(", joined)
        self.assertIn("COUNTIFS(", joined)
        self.assertIn('"boundary"', joined)
        self.assertIn('"known-gap"', joined)
        self.assertIn('"not-applicable"', joined)
        self.assertIn('"Y"', joined)
        self.assertIn("Pass rate", joined)

    def test_category_map_and_gaps_present(self):
        category_map = self.workbook["Category Map"]
        self.assertEqual(category_map.max_row, 11)
        self.assertEqual([category_map.cell(row=row, column=1).value for row in range(2, 12)],
                         [category for category in EXPECTED_FILES if category != "CTRL"])
        gaps = self.workbook["Known Gaps"]
        self.assertGreaterEqual(gaps.max_row, 10)
        gap_text = " ".join(str(cell.value) for row in gaps.iter_rows() for cell in row if cell.value).lower()
        for phrase in ("mykad", "passport", "bank account", "rag", "classifier", "truth", "sanitise"):
            self.assertIn(phrase, gap_text)
        run_log = self.workbook["Run Log"]
        self.assertEqual([cell.value for cell in run_log[1]],
                         ["Date", "Tester", "Build / commit", "Endpoint", "Guard model and threshold",
                          "Cases run", "Verdict", "Notes"])

    def test_read_me_states_limits_and_digest(self):
        read_me = self.workbook["Read Me"]
        text = " ".join(str(cell.value) for row in read_me.iter_rows() for cell in row if cell.value)
        self.assertIn(self.builder.corpus_digest(self.records), text)
        self.assertIn("unproven", text.lower())
        self.assertIn("not detection coverage", text.lower())
        self.assertIn("build_owasp_checklist.py", text)

    def test_workbook_is_deterministic_and_current(self):
        first = self.builder.build_workbook_bytes(self.records)
        second = self.builder.build_workbook_bytes(self.records)
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())
        self.assertEqual(first, WORKBOOK.read_bytes(), "workbook drifted from the corpus; regenerate it")


class DocsTests(unittest.TestCase):
    def test_operator_doc_exists_and_is_honest(self):
        path = ROOT / "docs" / "owasp-payloads.md"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8").lower()
        for phrase in ("not detection coverage", "regenerate", "add a case", "known gap", "boundary"):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
