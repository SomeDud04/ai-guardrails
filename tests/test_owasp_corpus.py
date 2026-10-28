"""Corpus integrity tests for the imported OWASP LLM Top 10 (2026) corpus.

Standard library only. ``openpyxl`` is never imported here: the workbook is
checked through ``zipfile`` as an OOXML package, so this module needs no
optional extra and adds no skip to the suite. Regenerating the workbook is the
only task that needs ``openpyxl``, and that is out of scope for this import.

The frozen artifacts must arrive byte-identical: the payload files, the
workbook and ``MANIFEST.sha256`` were copied verbatim from the authoring
checkout, and the manifest was not regenerated, edited or reordered. The
``FROZEN_*`` constants below are the hashes of that authoring checkout captured
at import time, so any byte change (including a line-ending conversion) fails.
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import re
import unittest
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = ROOT / "evals" / "owasp" / "llm-top10-2026"
PAYLOAD_ROOT = CORPUS_ROOT / "payloads"
SCHEMA_PATH = CORPUS_ROOT / "schema.json"
MANIFEST = CORPUS_ROOT / "MANIFEST.sha256"
WORKBOOK = CORPUS_ROOT / "OWASP-LLM-Top10-2026-checklist.xlsx"
BUILDER_PATH = ROOT / "scripts" / "build_owasp_checklist.py"
REBASELINE = ROOT / "evals" / "owasp" / "rebaseline-llm-top10-2026.json"

PAYLOAD_FILES = {
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
DETERMINISTIC_STATUSES = (400, 413)
STATUS_CODES = {
    200: None,
    400: "INVALID_REQUEST",
    403: "POLICY_BLOCK",
    413: "INPUT_LIMIT",
}
REFERENCE_PAGES = {
    "LLM01": 10, "LLM02": 18, "LLM03": 23, "LLM04": 27, "LLM05": 33,
    "LLM06": 38, "LLM07": 43, "LLM08": 46, "LLM09": 50, "LLM10": 55,
}
CONTROL_REFERENCE = "Nasi Lemak control baseline (internal)"

# Hashes of the frozen authoring checkout. The manifest and schema are not
# covered by the manifest's own hash list, so their bytes are pinned here.
FROZEN_CORPUS_DIGEST = "36ed7bcfe6aeb0d35de6dc7326eeb1c65390efdd6c45d88d28c8fcc846d3514e"
FROZEN_MANIFEST_SHA256 = "5002877e6416b5451b49fe8f012e820f6bd093eb8a829fcc186be8c515617db9"
FROZEN_SCHEMA_SHA256 = "233e8d1ec2af22150963f4fc81c442700ca73e715c61ae8d6f71dd14dbdf07c9"

EXPECTED_SHEETS = ["Read Me", "Checklist", "Summary", "Category Map", "Known Gaps", "Run Log"]
CHECKLIST_HEADER_ROWS = 1

REFERENCE_CONFIGURATION = {
    "context_messages": 32,
    "context_budget": 8192,
    "default_reply_tokens": 1024,
    "max_reply_tokens": 4096,
    "body_limit_bytes": 65536,
    "policy_token_budget": 512,
}
REQUIRED_ROW_KEYS = (
    "id",
    "expect_status",
    "expect_code",
    "product_limit",
    "holds_under_product_default",
    "counter_dependent",
    "budget_dependent",
    "requires_raw_body",
    "reason",
)

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
    """Load this repository's builder by path; it imports no third party module."""
    spec = importlib.util.spec_from_file_location("build_owasp_checklist", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_records():
    records = []
    for category, filename in PAYLOAD_FILES.items():
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
    """Draft 2020-12 subset validator for these fixtures only.

    The same approach as the authoring checkout's suite; copied here deliberately
    so this repository never imports test code from another checkout.
    """
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
    """Human-readable problems for real-looking domains, phones or secrets."""
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


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CorpusTests(unittest.TestCase):
    def test_payload_files_and_counts(self):
        for category, filename in PAYLOAD_FILES.items():
            path = PAYLOAD_ROOT / filename
            self.assertTrue(path.is_file(), f"missing {filename}")
            with path.open(encoding="utf-8") as handle:
                count = sum(1 for line in handle if line.strip())
            self.assertEqual(count, EXPECTED_COUNTS[category], filename)
        self.assertEqual(sum(EXPECTED_COUNTS.values()), EXPECTED_TOTAL)

    def test_total_and_ids_are_unique_and_sequential(self):
        records = load_records()
        self.assertEqual(len(records), EXPECTED_TOTAL)
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
            self.assertEqual(errors, [], f"{record['id']}: {errors[:3]}")

    def test_record_invariants(self):
        records = load_records()
        unknown_coverage = {"known-gap", "not-applicable", "benign-control"}
        for record in records:
            with self.subTest(record=record["id"]):
                for key in ("expect_behaviour", "evidence", "reference", "control", "technique"):
                    self.assertTrue(record[key].strip(), f"{record['id']} has empty {key}")
                self.assertIn(record["expect_status"], STATUS_CODES)
                self.assertEqual(record["expect_code"], STATUS_CODES[record["expect_status"]])
                if record["coverage"] in unknown_coverage:
                    self.assertEqual(record["expect_status"], 200, record["id"])
                if record["expect_status"] in DETERMINISTIC_STATUSES:
                    self.assertFalse(
                        record["needs_guard_model"],
                        f"{record['id']} is deterministic and must not need the guard model",
                    )
                category = record["category"]
                if category == "CTRL":
                    self.assertEqual(record["reference"], CONTROL_REFERENCE)
                else:
                    self.assertEqual(
                        record["reference"],
                        f"OWASP {category}:2026 p.{REFERENCE_PAGES[category]}",
                    )

    def test_synthetic_data_only(self):
        problems = synthetic_data_problems(load_records())
        self.assertEqual(problems, [], "\n".join(problems[:10]))

    def test_synthetic_scan_detects_bad_domain_and_secret(self):
        bad_domain = [{"id": "CTRL-001", "messages": [{"role": "user", "content": "mail bob@gmail.com"}]}]
        self.assertTrue(synthetic_data_problems(bad_domain))
        bad_phone = [{"id": "CTRL-001", "messages": [{"role": "user", "content": "call 0199999999"}]}]
        self.assertTrue(synthetic_data_problems(bad_phone))
        bad_secret = [{"id": "CTRL-001", "messages": [{"role": "user", "content": "token AKIAABCDEFGHIJKLMNOP"}]}]
        self.assertTrue(synthetic_data_problems(bad_secret))


class ManifestTests(unittest.TestCase):
    def test_manifest_entry_set_is_exact(self):
        builder = load_builder()
        entries = builder.manifest_entries(MANIFEST.read_text(encoding="utf-8"))
        expected = {f"payloads/{name}" for name in PAYLOAD_FILES.values()} | {WORKBOOK.name}
        self.assertEqual(set(entries), expected)

    def test_manifest_hashes_match_copied_bytes(self):
        builder = load_builder()
        entries = builder.manifest_entries(MANIFEST.read_text(encoding="utf-8"))
        for relative, digest in sorted(entries.items()):
            path = CORPUS_ROOT / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(builder.file_sha256(path), digest, f"{relative} hash drift")

    def test_corpus_digest_matches_manifest(self):
        builder = load_builder()
        text = MANIFEST.read_text(encoding="utf-8")
        records = load_records()
        self.assertEqual(builder.manifest_corpus_digest(text), FROZEN_CORPUS_DIGEST)
        self.assertEqual(builder.corpus_digest(records), FROZEN_CORPUS_DIGEST)

    def test_manifest_and_schema_bytes_are_frozen(self):
        self.assertEqual(file_sha256(MANIFEST), FROZEN_MANIFEST_SHA256)
        self.assertEqual(file_sha256(SCHEMA_PATH), FROZEN_SCHEMA_SHA256)

    def test_manifest_is_not_regenerated_by_this_import(self):
        text = MANIFEST.read_text(encoding="utf-8")
        header = [line for line in text.splitlines() if line.startswith("#")]
        self.assertIn("# OWASP LLM Top 10 (2026) synthetic adversarial payload corpus", header)
        self.assertIn("# frozen_on: 2026-10-27", header)
        self.assertIn(f"# corpus_sha256: {FROZEN_CORPUS_DIGEST}", header)
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn("\r", text)


class WorkbookTests(unittest.TestCase):
    def test_workbook_is_present_and_hashed(self):
        self.assertTrue(WORKBOOK.is_file(), "workbook is missing")
        builder = load_builder()
        entries = builder.manifest_entries(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(builder.file_sha256(WORKBOOK), entries[WORKBOOK.name])
        self.assertLess(WORKBOOK.stat().st_size, 2 * 1024 * 1024)

    def test_workbook_is_a_valid_ooxml_package(self):
        with zipfile.ZipFile(WORKBOOK) as package:
            self.assertIsNone(package.testzip(), "workbook zip is corrupt")
            members = set(package.namelist())
            for required in ("[Content_Types].xml", "xl/workbook.xml", "_rels/.rels"):
                self.assertIn(required, members)
            workbook_xml = package.read("xl/workbook.xml").decode("utf-8")
            self.assertEqual(re.findall(r'<sheet name="([^"]+)"', workbook_xml), EXPECTED_SHEETS)
            checklist = package.read("xl/worksheets/sheet2.xml").decode("utf-8")
            self.assertEqual(
                checklist.count("<row "),
                EXPECTED_TOTAL + CHECKLIST_HEADER_ROWS,
                "Checklist sheet row count drifted",
            )
            for name in ("xl/worksheets/sheet1.xml", "xl/styles.xml"):
                self.assertIn(name, members)


class RebaselineTests(unittest.TestCase):
    def setUp(self):
        self.map = json.loads(REBASELINE.read_text(encoding="utf-8"))
        records = load_records()
        self.records = {record["id"]: record for record in records}
        self.deterministic = {
            record["id"]: record
            for record in records
            if record["expect_status"] in DETERMINISTIC_STATUSES
        }

    def test_map_covers_every_deterministic_row_exactly_once(self):
        ids = [row["id"] for row in self.map["rows"]]
        duplicates = [key for key, count in Counter(ids).items() if count > 1]
        self.assertEqual(duplicates, [], "duplicate ids in the re-baselining map")
        self.assertEqual(set(ids), set(self.deterministic))
        self.assertEqual(len(ids), len(self.deterministic))
        self.assertEqual(ids, sorted(ids), "keep the map ordered by corpus id")

    def test_map_entries_agree_with_the_corpus(self):
        for row in self.map["rows"]:
            with self.subTest(row=row["id"]):
                for key in REQUIRED_ROW_KEYS:
                    self.assertIn(key, row)
                record = self.deterministic[row["id"]]
                self.assertEqual(row["expect_status"], record["expect_status"])
                self.assertEqual(row["expect_code"], record["expect_code"])
                for key in (
                    "holds_under_product_default",
                    "counter_dependent",
                    "budget_dependent",
                    "requires_raw_body",
                ):
                    self.assertIsInstance(row[key], bool, key)
                for key in ("product_limit", "reason"):
                    self.assertIsInstance(row[key], str)
                    self.assertTrue(row[key].strip(), f"{row['id']} has an empty {key}")
                self.assertNotEqual(row["product_limit"], "", row["id"])

    def test_map_declares_the_reference_configuration(self):
        configuration = self.map["reference_configuration"]
        for key, expected in REFERENCE_CONFIGURATION.items():
            self.assertEqual(configuration[key], expected, key)

    def test_map_reference_configuration_matches_the_product_defaults(self):
        from nasi_lemak.gateway import Policy
        from nasi_lemak.limits import ChatLimits
        from nasi_lemak.server import DEFAULT_MAX_BODY_BYTES

        limits = ChatLimits.defaults()
        configuration = self.map["reference_configuration"]
        self.assertEqual(configuration["context_messages"], limits.context_messages)
        self.assertEqual(configuration["context_budget"], limits.context_budget)
        self.assertEqual(configuration["default_reply_tokens"], limits.default_reply_tokens)
        self.assertEqual(configuration["max_reply_tokens"], limits.max_reply_tokens)
        self.assertEqual(configuration["policy_token_budget"], Policy().token_budget)
        self.assertEqual(configuration["body_limit_bytes"], DEFAULT_MAX_BODY_BYTES)

    def test_map_lives_outside_the_hashed_corpus_directory(self):
        self.assertNotIn(CORPUS_ROOT.resolve(), REBASELINE.resolve().parents)
        self.assertEqual(REBASELINE.resolve().parent, (ROOT / "evals" / "owasp").resolve())

    def test_only_llm06_002_is_recorded_as_not_holding(self):
        not_holding = [
            row["id"] for row in self.map["rows"] if not row["holds_under_product_default"]
        ]
        self.assertEqual(not_holding, ["LLM06-002"])

    def test_inverse_class_covers_every_expect_200_row_that_cannot_return_200(self):
        """The inverse class must be complete against the corpus, not just one row.

        The product counter and the declared reference configuration are used,
        because those are exactly what turn an expect-200 row into a 413. The
        real ASGI replay of all expect-200 rows lives in
        tests/test_deny_normalisation.py; this module keeps the map structurally
        complete without importing the HTTP stack.
        """
        from nasi_lemak.generation import conservative_byte_budget
        from nasi_lemak.gateway import serialize_messages

        inverse = self.map["inverse_class"]
        self.assertTrue(inverse["complete"])
        self.assertEqual(inverse["replayed_expect_200_rows"], 81)
        ids = [row["id"] for row in inverse["rows"]]
        self.assertEqual(ids, sorted(ids), "keep the inverse class ordered by corpus id")
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids in the inverse class")
        self.assertFalse(
            set(ids) & {row["id"] for row in self.map["rows"]},
            "inverse class must be disjoint from the deterministic rows",
        )

        expect_200 = {
            record_id: record
            for record_id, record in self.records.items()
            if record["expect_status"] == 200
        }
        self.assertEqual(len(expect_200), 81)
        predicted = []
        for record_id, record in expect_200.items():
            serialized = serialize_messages(record["messages"])
            units = conservative_byte_budget(serialized)
            body_bytes = len(
                json.dumps(
                    {"model": "pilot-local", "messages": record["messages"]},
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            if (
                len(record["messages"]) > REFERENCE_CONFIGURATION["context_messages"]
                or units > REFERENCE_CONFIGURATION["context_budget"]
                or units > REFERENCE_CONFIGURATION["policy_token_budget"]
                or body_bytes > REFERENCE_CONFIGURATION["body_limit_bytes"]
            ):
                predicted.append(record_id)
        self.assertEqual(predicted, ids)
        self.assertEqual(ids, ["CTRL-007"])

        row = inverse["rows"][0]
        self.assertEqual(row["expect_status"], expect_200["CTRL-007"]["expect_status"])
        self.assertIsNone(row["expect_code"])
        self.assertEqual(row["observed_status"], 413)
        self.assertEqual(row["observed_code"], "INPUT_LIMIT")
        self.assertEqual(row["observed_content_characters"], 1439)
        self.assertEqual(row["observed_conservative_units"], 1449)
        self.assertGreater(
            row["observed_conservative_units"],
            REFERENCE_CONFIGURATION["policy_token_budget"],
        )
        self.assertEqual(row["allowed_at"]["policy_token_budget_min"], 1449)
        self.assertGreaterEqual(
            row["allowed_at"]["verified_policy_token_budget"],
            row["allowed_at"]["policy_token_budget_min"],
        )


class BuilderImportTests(unittest.TestCase):
    def test_builder_imports_without_openpyxl_at_module_scope(self):
        tree = ast.parse(BUILDER_PATH.read_text(encoding="utf-8"))
        module_level = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                module_level.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                module_level.add(node.module.split(".")[0])
        self.assertNotIn("openpyxl", module_level)
        for required in ("hashlib", "json", "pathlib"):
            self.assertIn(required, module_level)

    def test_builder_keeps_openpyxl_behind_a_lazy_import(self):
        tree = ast.parse(BUILDER_PATH.read_text(encoding="utf-8"))
        lazy = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_openpyxl"
        ]
        self.assertEqual(len(lazy), 1, "expected exactly one _openpyxl helper")
        imported = [
            alias.name
            for node in ast.walk(lazy[0])
            if isinstance(node, ast.Import)
            for alias in node.names
        ]
        self.assertIn("openpyxl", imported)

    def test_this_module_does_not_import_openpyxl(self):
        source = Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertNotIn("openpyxl", imported)


if __name__ == "__main__":
    unittest.main()
