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
import io
import json
import re
import sys
import tempfile
import unittest
import zipfile
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

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


def load_script(module_name):
    """Load scripts/<module_name>.py without making scripts a package."""
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = ROOT / "scripts" / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class _NeverSend:
    def __call__(self, record, body):  # pragma: no cover - must not be reached
        raise AssertionError("the runner sent a request when it should not have")


class _ConstantTransport:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.calls = 0

    def __call__(self, record, body):
        self.calls += 1
        return self.calls_result()

    def calls_result(self):
        return load_script("run_owasp_corpus").HttpResponse(self.status, self.body)


class _RaisingTransport:
    def __init__(self, error):
        self.error = error
        self.calls = 0

    def __call__(self, record, body):
        self.calls += 1
        raise self.error


class ConformanceRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_script("run_owasp_corpus")
        cls.map = json.loads(REBASELINE.read_text(encoding="utf-8"))
        cls.records = load_records()
        cls.policy = cls.runner.load_fixture_policy()
        cls.configuration = cls.runner.load_effective_configuration(cls.policy)
        cls.report = cls.runner.run_local(
            records=cls.records,
            map_data=cls.map,
            policy=cls.policy,
            configuration=cls.configuration,
        )

    def test_every_deterministic_row_has_a_verdict_or_a_mapped_reason(self):
        self.assertEqual(self.report["row_count"], 23)
        self.assertEqual(len(self.report["rows"]), 23)
        self.assertEqual(self.report["tallies"]["FAIL"], 0)
        self.assertEqual(self.report["tallies"]["ERROR"], 0)
        self.assertEqual(self.report["tallies"]["PASS"], 22)
        self.assertEqual(self.report["tallies"]["NOT-APPLICABLE-CONFIG"], 1)
        self.assertEqual(self.report["pass_rate"]["denominator"], 22)
        self.assertEqual(self.report["pass_rate"]["value"], 1.0)

        map_rows = {row["id"]: row for row in self.map["rows"]}
        for row in self.report["rows"]:
            with self.subTest(row=row["id"]):
                self.assertIn(
                    row["outcome"], ("PASS", "NOT-APPLICABLE-CONFIG")
                )
                if row["outcome"] == "PASS":
                    self.assertEqual(row["observed_status"], row["expect_status"])
                    self.assertEqual(row["observed_code"], row["expect_code"])
                    self.assertIsNone(row["reason"])
                else:
                    map_row = map_rows[row["id"]]
                    self.assertTrue(map_row["reason"].strip())
                    self.assertIn(map_row["reason"], row["reason"])
                    self.assertEqual(
                        row["reason_source"],
                        "evals/owasp/rebaseline-llm-top10-2026.json#rows",
                    )
        outcome_by_id = {row["id"]: row["outcome"] for row in self.report["rows"]}
        self.assertEqual(outcome_by_id["LLM06-002"], "NOT-APPLICABLE-CONFIG")

    def test_marker_expansion_is_exact_and_raw_body_is_verbatim(self):
        records = {record["id"]: record for record in self.records}
        for record_id, size in (("LLM06-003", 64512), ("LLM06-012", 1048576)):
            payload = json.loads(self.runner.build_request_body(records[record_id]))
            self.assertEqual(payload["model"], "pilot-local")
            self.assertEqual(len(payload["messages"]), 1)
            self.assertEqual(len(payload["messages"][0]["content"].encode("utf-8")), size)
        raw = records["LLM06-010"]["optional_extra"]["$raw_body"]
        self.assertEqual(
            self.runner.build_request_body(records["LLM06-010"]),
            raw.encode("utf-8"),
        )

    def test_uninterpretable_marker_is_error_never_a_verdict(self):
        record = {
            "id": "TEST-001",
            "expect_status": 400,
            "expect_code": "INVALID_REQUEST",
            "messages": [{"role": "user", "content": "synthetic probe"}],
            "optional_extra": {
                "$raw_body_repeat": {
                    "char": "ab",
                    "bytes": 10,
                    "template": "chat_content",
                }
            },
        }
        report = self.runner.run_rows(
            [record],
            {"rows": [], "reference_configuration": {}},
            _NeverSend(),
            self.configuration,
        )
        self.assertEqual(report["rows"][0]["outcome"], "ERROR")
        self.assertIn("uninterpretable fixture marker", report["rows"][0]["reason"])
        self.assertEqual(report["tallies"]["FAIL"], 0)
        self.assertEqual(report["tallies"]["PASS"], 0)

    def test_rate_limit_and_transport_failure_are_error_and_excluded(self):
        base_kwargs = dict(
            records=self.records,
            map_data=self.map,
            policy=self.policy,
            configuration=self.configuration,
        )
        rate_limited = self.runner.run_local(
            transport=_ConstantTransport(
                429, b'{"error":{"code":"RATE_LIMITED"}}'
            ),
            **base_kwargs,
        )
        self.assertEqual(rate_limited["tallies"]["ERROR"], 23)
        self.assertEqual(rate_limited["tallies"]["PASS"], 0)
        self.assertEqual(rate_limited["tallies"]["FAIL"], 0)
        self.assertEqual(rate_limited["pass_rate"]["denominator"], 0)
        self.assertIsNone(rate_limited["pass_rate"]["value"])

        transport_failure = self.runner.run_local(
            transport=_RaisingTransport(
                self.runner.TransportError("synthetic transport failure")
            ),
            **base_kwargs,
        )
        self.assertEqual(transport_failure["tallies"]["ERROR"], 23)
        self.assertEqual(transport_failure["tallies"]["PASS"], 0)
        self.assertEqual(transport_failure["tallies"]["FAIL"], 0)
        self.assertEqual(transport_failure["pass_rate"]["denominator"], 0)

    def test_main_exits_non_zero_on_injected_mismatch_and_error(self):
        with tempfile.TemporaryDirectory() as directory:
            mismatch_path = str(Path(directory) / "mismatch.json")
            mismatch = _ConstantTransport(
                400, b'{"error":{"code":"INVALID_REQUEST"}}'
            )
            with redirect_stdout(io.StringIO()):
                mismatch_code = self.runner.main(
                    ["--json", mismatch_path], transport=mismatch
                )
            self.assertNotEqual(mismatch_code, 0)
            mismatch_report = json.loads(
                Path(mismatch_path).read_text(encoding="utf-8")
            )
            self.assertGreater(mismatch_report["tallies"]["FAIL"], 0)

            error_path = str(Path(directory) / "error.json")
            failing = _RaisingTransport(
                self.runner.TransportError("synthetic transport failure")
            )
            with redirect_stdout(io.StringIO()):
                error_code = self.runner.main(
                    ["--json", error_path], transport=failing
                )
            self.assertNotEqual(error_code, 0)
            error_report = json.loads(Path(error_path).read_text(encoding="utf-8"))
            self.assertEqual(error_report["tallies"]["ERROR"], 23)
            self.assertEqual(error_report["tallies"]["PASS"], 0)
            self.assertEqual(error_report["tallies"]["FAIL"], 0)

    def test_missing_map_reason_for_config_dependent_row_is_error(self):
        map_copy = json.loads(json.dumps(self.map))
        for row in map_copy["rows"]:
            if row["id"] == "LLM06-002":
                row["reason"] = ""
        record = next(
            record for record in self.records if record["id"] == "LLM06-002"
        )
        map_subset = {
            "rows": [row for row in map_copy["rows"] if row["id"] == "LLM06-002"],
            "reference_configuration": map_copy["reference_configuration"],
        }
        transport = _ConstantTransport(
            200, b'{"choices":[{"message":{"content":"ok"}}]}'
        )
        reports = {
            "local": self.runner.run_local(
                records=[record],
                map_data=map_subset,
                policy=self.policy,
                configuration=self.configuration,
                transport=transport,
            ),
            "operator": self.runner.run_operator(
                transport,
                records=[record],
                map_data=map_subset,
                configuration=self.configuration,
            ),
        }
        for mode, report in reports.items():
            with self.subTest(mode=mode):
                self.assertEqual(report["rows"][0]["outcome"], "ERROR")
                self.assertIn("no named reason", report["rows"][0]["reason"])
                self.assertEqual(report["tallies"]["FAIL"], 0)
                self.assertEqual(report["tallies"]["NOT-APPLICABLE-CONFIG"], 0)

    # ------------------------------------------------------------------
    # Shared classifier: identical verdicts through both entry paths

    def _one_row(self, record_id):
        return next(record for record in self.records if record["id"] == record_id)

    def _one_row_map(self, record_id):
        return {
            "rows": [row for row in self.map["rows"] if row["id"] == record_id],
            "reference_configuration": self.map["reference_configuration"],
        }

    def _both_modes(self, transport, records, map_data, audit_text=None):
        return {
            "local": self.runner.run_local(
                records=records,
                map_data=map_data,
                policy=self.policy,
                configuration=self.configuration,
                transport=transport,
                audit_text=audit_text,
            ),
            "operator": self.runner.run_operator(
                transport,
                records=records,
                map_data=map_data,
                configuration=self.configuration,
                audit_text=audit_text,
            ),
        }

    def test_injected_infrastructure_outcomes_are_error_in_both_modes(self):
        for status in (401, 404, 503, 429):
            transport = _ConstantTransport(
                status, b'{"error":{"code":"NOT_A_PRODUCT_OUTCOME"}}'
            )
            for mode, report in self._both_modes(
                transport, self.records, self.map
            ).items():
                with self.subTest(mode=mode, status=status):
                    self.assertEqual(report["row_count"], 23)
                    self.assertEqual(report["tallies"]["ERROR"], 23)
                    self.assertEqual(report["tallies"]["FAIL"], 0)
                    self.assertEqual(report["tallies"]["NOT-APPLICABLE-CONFIG"], 0)
                    self.assertEqual(report["tallies"]["PASS"], 0)
                    self.assertEqual(report["pass_rate"]["denominator"], 0)
                    self.assertIsNone(report["pass_rate"]["value"])

        for label, error in (
            ("transport failure", self.runner.TransportError("synthetic")),
            ("timeout", TimeoutError("synthetic timeout")),
        ):
            transport = _RaisingTransport(error)
            for mode, report in self._both_modes(
                transport, self.records, self.map
            ).items():
                with self.subTest(mode=mode, error=label):
                    self.assertEqual(report["tallies"]["ERROR"], 23)
                    self.assertEqual(report["tallies"]["FAIL"], 0)
                    self.assertEqual(report["tallies"]["NOT-APPLICABLE-CONFIG"], 0)
                    self.assertEqual(report["pass_rate"]["denominator"], 0)

    def test_unbuildable_request_is_error_in_both_modes(self):
        record = {
            "id": "TEST-BUILD",
            "expect_status": 400,
            "expect_code": "INVALID_REQUEST",
            "messages": [{"role": "user", "content": "synthetic probe"}],
            "optional_extra": {
                "$raw_body_repeat": {
                    "char": "ab",
                    "bytes": 10,
                    "template": "chat_content",
                }
            },
        }
        for mode, report in self._both_modes(
            _NeverSend(), [record], {"rows": [], "reference_configuration": {}}
        ).items():
            with self.subTest(mode=mode):
                self.assertEqual(report["rows"][0]["outcome"], "ERROR")
                self.assertIn("uninterpretable fixture marker", report["rows"][0]["reason"])
                self.assertEqual(report["tallies"]["FAIL"], 0)

    def test_policy_block_on_llm06_002_is_fail_not_na_in_both_modes(self):
        record = self._one_row("LLM06-002")
        transport = _ConstantTransport(
            403, b'{"error":{"code":"POLICY_BLOCK"}}'
        )
        for mode, report in self._both_modes(
            transport, [record], self._one_row_map("LLM06-002")
        ).items():
            with self.subTest(mode=mode):
                self.assertEqual(report["rows"][0]["outcome"], "FAIL")
                self.assertEqual(report["rows"][0]["observed_status"], 403)
                self.assertEqual(report["rows"][0]["observed_code"], "POLICY_BLOCK")
                self.assertEqual(report["tallies"]["NOT-APPLICABLE-CONFIG"], 0)

    def test_recorded_200_on_llm06_002_is_na_with_exact_map_reason(self):
        record = self._one_row("LLM06-002")
        map_row = self._one_row_map("LLM06-002")["rows"][0]
        expected_reason = f"{map_row['product_limit']}: {map_row['reason']}"
        transport = _ConstantTransport(
            200, b'{"choices":[{"message":{"content":"ok"}}]}'
        )
        for mode, report in self._both_modes(
            transport, [record], self._one_row_map("LLM06-002")
        ).items():
            with self.subTest(mode=mode):
                row = report["rows"][0]
                self.assertEqual(row["outcome"], "NOT-APPLICABLE-CONFIG")
                self.assertEqual(row["reason"], expected_reason)
                self.assertEqual(
                    row["reason_source"],
                    "evals/owasp/rebaseline-llm-top10-2026.json#rows",
                )

    def test_missing_map_entry_mismatch_is_fail_in_both_modes(self):
        record = self._one_row("LLM01-019")
        transport = _ConstantTransport(
            400, b'{"error":{"code":"INVALID_REQUEST"}}'
        )
        for mode, report in self._both_modes(
            transport, [record], {"rows": [], "reference_configuration": {}}
        ).items():
            with self.subTest(mode=mode):
                self.assertEqual(report["rows"][0]["outcome"], "FAIL")
                self.assertEqual(report["tallies"]["ERROR"], 0)

    # ------------------------------------------------------------------
    # Audit assertions

    def _synthetic_400_record(self):
        return {
            "id": "TEST-AUDIT",
            "expect_status": 400,
            "expect_code": "INVALID_REQUEST",
            "messages": [
                {"role": "user", "content": "synthetic audit sentinel 9f2c"}
            ],
        }

    def test_local_real_run_verifies_the_audit_assertion(self):
        self.assertEqual(self.report["audit_leak_check"], "verified")
        self.assertTrue(self.report["audit_reader_configured"])
        self.assertGreater(self.report["audit_rows_sent"], 0)
        self.assertEqual(
            self.report["audit_checks_run"], self.report["audit_rows_sent"]
        )
        self.assertEqual(self.report["audit_read_errors"], 0)
        self.assertEqual(self.report["audit_leaks_detected"], 0)
        self.assertIn(
            f"all {self.report['audit_rows_sent']} sent rows",
            self.report["audit_leak_check_reason"],
        )

    def test_reader_configured_but_never_run_is_unverified_in_both_modes(self):
        for label, transport in (
            ("transport failure", _RaisingTransport(self.runner.TransportError("synthetic"))),
            ("timeout", _RaisingTransport(TimeoutError("synthetic timeout"))),
        ):
            for mode, report in self._both_modes(
                transport, self.records, self.map, audit_text=lambda: "clean"
            ).items():
                with self.subTest(mode=mode, error=label):
                    self.assertEqual(report["tallies"]["ERROR"], 23)
                    self.assertEqual(report["audit_leak_check"], "unverified")
                    self.assertEqual(report["audit_rows_sent"], 0)
                    self.assertEqual(report["audit_checks_run"], 0)
                    self.assertIn(
                        "did NOT run", report["audit_leak_check_reason"]
                    )

    def test_partially_executed_audit_is_unverified(self):
        state, reason = self.runner._derive_audit_state(
            reader_configured=True,
            rows_sent=5,
            checks_run=3,
            read_errors=0,
            leaks_detected=0,
        )
        self.assertEqual(state, "unverified")
        self.assertIn("only 3 of 5", reason)

    def test_zero_sent_rows_is_unverified_even_with_a_reader(self):
        state, reason = self.runner._derive_audit_state(
            reader_configured=True,
            rows_sent=0,
            checks_run=0,
            read_errors=0,
            leaks_detected=0,
        )
        self.assertEqual(state, "unverified")
        self.assertIn("did NOT run", reason)

    def test_audit_without_reader_is_explicitly_unverified_in_both_modes(self):
        transport = _ConstantTransport(
            400, b'{"error":{"code":"INVALID_REQUEST"}}'
        )
        for mode, report in self._both_modes(
            transport, [self._synthetic_400_record()], {"rows": [], "reference_configuration": {}}
        ).items():
            with self.subTest(mode=mode):
                self.assertEqual(report["audit_leak_check"], "unverified")
                self.assertFalse(report["audit_reader_configured"])
                self.assertIn("no audit reader", report["audit_leak_check_reason"])
                self.assertTrue(report["audit_leak_check_how_to_verify"])

    def test_audit_reader_detects_a_leak_in_both_modes(self):
        record = self._synthetic_400_record()
        transport = _ConstantTransport(
            400, b'{"error":{"code":"INVALID_REQUEST"}}'
        )
        clean = self._both_modes(
            transport,
            [record],
            {"rows": [], "reference_configuration": {}},
            audit_text=lambda: "no sentinel here",
        )
        leaking = self._both_modes(
            transport,
            [record],
            {"rows": [], "reference_configuration": {}},
            audit_text=lambda: "audit row: " + record["messages"][0]["content"],
        )
        for mode in ("local", "operator"):
            with self.subTest(mode=mode, case="clean"):
                self.assertEqual(clean[mode]["rows"][0]["outcome"], "PASS")
                self.assertEqual(clean[mode]["audit_leak_check"], "verified")
                self.assertEqual(clean[mode]["audit_leaks_detected"], 0)
                self.assertEqual(
                    clean[mode]["audit_checks_run"],
                    clean[mode]["audit_rows_sent"],
                )
            with self.subTest(mode=mode, case="leaking"):
                self.assertEqual(leaking[mode]["rows"][0]["outcome"], "FAIL")
                self.assertIn(
                    "raw request sentinel", leaking[mode]["rows"][0]["reason"]
                )
                self.assertEqual(leaking[mode]["audit_leak_check"], "failed")
                self.assertGreater(leaking[mode]["audit_leaks_detected"], 0)
                self.assertIn(
                    "raw request sentinel", leaking[mode]["audit_leak_check_reason"]
                )

    def test_audit_reader_failure_is_never_a_pass_in_both_modes(self):
        record = self._synthetic_400_record()
        transport = _ConstantTransport(
            400, b'{"error":{"code":"INVALID_REQUEST"}}'
        )

        def broken_reader():
            raise RuntimeError("synthetic audit store unavailable")

        for mode, report in self._both_modes(
            transport,
            [record],
            {"rows": [], "reference_configuration": {}},
            audit_text=broken_reader,
        ).items():
            with self.subTest(mode=mode):
                self.assertEqual(report["rows"][0]["outcome"], "ERROR")
                self.assertIn("audit reader failed", report["rows"][0]["reason"])
                self.assertEqual(report["audit_leak_check"], "failed")
                self.assertGreater(report["audit_read_errors"], 0)
                self.assertEqual(
                    report["audit_checks_run"], report["audit_rows_sent"]
                )
                self.assertEqual(report["tallies"]["PASS"], 0)

    def test_audit_failure_makes_the_exit_non_zero_without_any_fail_row(self):
        report = dict(self.report)
        report["audit_leak_check"] = "failed"
        report["audit_read_errors"] = 1
        report["audit_leak_check_reason"] = (
            "the audit reader failed for 1 row(s); no-leak is not claimed"
        )
        self.assertEqual(report["tallies"]["FAIL"], 0)
        self.assertEqual(report["tallies"]["ERROR"], 0)

        output = io.StringIO()
        with mock.patch.object(self.runner, "run_local", return_value=report):
            with redirect_stdout(output):
                code = self.runner.main([], transport=_NeverSend())
        self.assertEqual(code, 1)
        printed = output.getvalue()
        self.assertIn("Audit no-raw-sentinel check: FAILED", printed)
        for counter in (
            "audit_rows_sent=",
            "audit_checks_run=",
            "audit_read_errors=",
            "audit_leaks_detected=",
        ):
            with self.subTest(counter=counter):
                self.assertIn(counter, printed)

    def test_main_operator_path_accepts_an_audit_reader_and_exits_non_zero(self):
        record = self._synthetic_400_record()
        transport = _ConstantTransport(
            403, b'{"error":{"code":"POLICY_BLOCK"}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "operator.json")
            with redirect_stdout(io.StringIO()):
                code = self.runner.main(
                    ["--operator", "--json", path],
                    transport=transport,
                    audit_text=lambda: record["messages"][0]["content"],
                )
            self.assertNotEqual(code, 0)
            report = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(report["mode"], "operator")
            self.assertEqual(report["audit_leak_check"], "verified")
            self.assertEqual(report["tallies"]["FAIL"], 23)
            self.assertEqual(report["tallies"]["NOT-APPLICABLE-CONFIG"], 0)

        with redirect_stdout(io.StringIO()):
            code = self.runner.main(
                ["--operator"], transport=transport, audit_text=None
            )
        self.assertNotEqual(code, 0)

    def test_main_operator_429_is_error_and_excluded(self):
        transport = _ConstantTransport(
            429, b'{"error":{"code":"RATE_LIMITED"}}'
        )
        with redirect_stdout(io.StringIO()):
            code = self.runner.main(["--operator"], transport=transport)
        self.assertNotEqual(code, 0)

    def test_dry_run_sends_nothing_and_reports_the_plan(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = self.runner.main(["--dry-run"], transport=_NeverSend())
        self.assertEqual(code, 0)
        plan = json.loads(output.getvalue())
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["row_count"], 23)
        self.assertEqual(len(plan["selected_rows"]), 23)
        self.assertEqual(plan["expected_http_requests"], 23)
        self.assertEqual(plan["expected_provider_calls"], 0)
        self.assertEqual(
            plan["effective_configuration"]["token_counter"],
            self.runner.TOKEN_COUNTER,
        )
        self.assertEqual(
            plan["effective_configuration"]["counter_basis"],
            self.runner.COUNTER_BASIS,
        )
        for key in (
            "context_messages",
            "context_budget",
            "default_reply_tokens",
            "max_reply_tokens",
            "body_limit_bytes",
            "policy_token_budget",
        ):
            self.assertIn(key, plan["effective_configuration"])
        self.assertEqual(plan["policy_fixture"], "scripts/owasp_corpus_policy.yaml")
        self.assertTrue(plan["policy_self_check"]["ok"])

    def test_report_contains_no_raw_payload_text_or_secret_material(self):
        text = json.dumps(self.report, ensure_ascii=False)
        for forbidden in (
            "run_shell",
            "Calling a tool.",
            "Hello, please summarise this synthetic note.",
            "alpha bravo charlie",
            "Synthetic 1 MiB body probe.",
            "pilot-local-2025",
            "synthetic denied phrase",
            "Bearer ",
            "https://",
            "http://",
            "postgresql",
            "AAAA",
            "xxxxxxxx",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        self.assertEqual(
            self.report["policy_fixture"], "scripts/owasp_corpus_policy.yaml"
        )
        self.assertEqual(
            self.report["reference_configuration"]["token_counter"],
            self.runner.TOKEN_COUNTER,
        )

    def test_policy_fixture_does_not_touch_any_allowed_row(self):
        self.assertEqual(self.policy.deny_phrases, ("synthetic denied phrase",))
        self.assertEqual(
            self.runner.policy_self_check(self.policy, self.records), []
        )
        allowed_rows = 0
        for record in self.records:
            if record["expect_status"] != 200:
                continue
            allowed_rows += 1
            for message in record["messages"]:
                with self.subTest(row=record["id"]):
                    self.assertFalse(self.policy.denies(message["content"]))
        self.assertEqual(allowed_rows, 81)

    def test_effective_configuration_comes_from_live_configuration(self):
        from nasi_lemak.gateway import Policy
        from nasi_lemak.limits import ChatLimits
        from nasi_lemak.server import DEFAULT_MAX_BODY_BYTES

        limits = ChatLimits.defaults()
        self.assertEqual(self.configuration.context_messages, limits.context_messages)
        self.assertEqual(self.configuration.context_budget, limits.context_budget)
        self.assertEqual(
            self.configuration.default_reply_tokens, limits.default_reply_tokens
        )
        self.assertEqual(self.configuration.max_reply_tokens, limits.max_reply_tokens)
        self.assertEqual(self.configuration.body_limit_bytes, DEFAULT_MAX_BODY_BYTES)
        self.assertEqual(self.configuration.policy_token_budget, self.policy.token_budget)
        self.assertEqual(
            self.configuration.policy_default_token_budget, Policy().token_budget
        )
        self.assertEqual(
            self.configuration.as_dict()["token_counter"], self.runner.TOKEN_COUNTER
        )


GUARD_DATASET = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v1.json"
GUARD_LEDGER = ROOT / "evals" / "guards" / "owasp-llm-top10-2026-v1.exclusions.json"
GUARD_DATASET_ID = "owasp-llm-top10-2026-guard-lane-v1"
GUARD_EVIDENCE_LABEL = "agent-authored-synthetic-smoke-not-holdout"
GUARD_CASE_FIELDS = {"id", "stage", "language", "expected", "messages"}
GUARD_LEDGER_COUNTS = {
    "output-stage": 23,
    "boundary": 19,
    "known-gap": 18,
    "not-guard-control": 15,
    "not-applicable": 11,
    "fixture-marker": 2,
    "harness-bound": 1,
}
HAN = re.compile(r"[\u4e00-\u9fff]")
FULLWIDTH = re.compile(r"[\uff01-\uff5e]")


def load_guard_dataset():
    return json.loads(GUARD_DATASET.read_text(encoding="utf-8"))


def load_guard_ledger():
    return json.loads(GUARD_LEDGER.read_text(encoding="utf-8"))


def guard_language(record):
    """The documented deterministic rule: Han -> zh, fullwidth -> mixed, else en."""
    text = "\n".join(message["content"] for message in record["messages"])
    if HAN.search(text):
        return "zh"
    if FULLWIDTH.search(text):
        return "mixed"
    return "en"


class GuardLaneDatasetTests(unittest.TestCase):
    """Fidelity and accounting for the guard-lane dataset and its sidecar.

    These tests deliberately never call ``nasi_lemak.guard_eval.load_dataset``:
    the dataset must be checked against the frozen corpus first, independently of
    loader acceptance. CTRL-007 is excluded: its one message is 1439 characters
    and 1449 conservative units, over both the dataset's 1024-character
    per-message bound and the guard's 512-unit single-call window. The exclusion
    is recorded in the sidecar with both reasons; it is a harness bound, not a
    guard decision or a detection result.
    """

    @classmethod
    def setUpClass(cls):
        cls.dataset = load_guard_dataset()
        cls.ledger = load_guard_ledger()
        cls.records = {record["id"]: record for record in load_records()}

    def test_dataset_has_the_strict_version_1_shape(self):
        self.assertEqual(
            set(self.dataset), {"schema_version", "dataset_id", "evidence_label", "cases"}
        )
        self.assertEqual(self.dataset["schema_version"], 1)
        self.assertIs(type(self.dataset["schema_version"]), int)
        self.assertEqual(self.dataset["dataset_id"], GUARD_DATASET_ID)
        self.assertEqual(self.dataset["evidence_label"], GUARD_EVIDENCE_LABEL)
        self.assertIn("synthetic", self.dataset["evidence_label"])
        self.assertIn("not-holdout", self.dataset["evidence_label"])

        cases = self.dataset["cases"]
        self.assertEqual(len(cases), 39)
        ids = [case["id"] for case in cases]
        self.assertEqual(len(ids), len(set(ids)), "duplicate case id")
        self.assertTrue(set(ids) <= {identifier.lower() for identifier in self.records})
        self.assertEqual(len(self.records), EXPECTED_TOTAL)
        for case in cases:
            with self.subTest(case=case.get("id")):
                self.assertEqual(set(case), GUARD_CASE_FIELDS)
                self.assertEqual(case["stage"], "input")
                self.assertIn(case["expected"], {"allow", "block"})
                self.assertIn(case["language"], {"en", "bm", "zh", "mixed"})
                self.assertIsInstance(case["messages"], list)
                self.assertTrue(case["messages"])
                for message in case["messages"]:
                    self.assertEqual(set(message), {"role", "content"})
                    self.assertIn(message["role"], {"system", "user", "assistant"})
                    self.assertIsInstance(message["content"], str)
                    self.assertTrue(message["content"])

    def test_every_case_messages_equal_the_frozen_corpus_row_exactly(self):
        """Regression: roles, content, boundaries, order and Unicode are verbatim."""
        for case in self.dataset["cases"]:
            record = self.records[case["id"].upper()]
            with self.subTest(case=case["id"]):
                self.assertEqual(case["messages"], record["messages"])
                self.assertEqual(len(case["messages"]), len(record["messages"]))
                for observed, expected in zip(case["messages"], record["messages"]):
                    self.assertEqual(observed["role"], expected["role"])
                    self.assertEqual(observed["content"], expected["content"])

    def test_composition_maps_attacks_and_benign_controls(self):
        blocks = [case for case in self.dataset["cases"] if case["expected"] == "block"]
        allows = [case for case in self.dataset["cases"] if case["expected"] == "allow"]
        self.assertEqual(len(blocks), 22)
        self.assertEqual(len(allows), 17)
        for case in blocks:
            record = self.records[case["id"].upper()]
            with self.subTest(case=case["id"]):
                self.assertEqual(record["guard_expect"], "should_block")
                self.assertEqual(record["control"], "input_attack_guard")
                self.assertEqual(record["coverage"], "direct")
                self.assertEqual(record["expect_status"], 403)
                self.assertEqual(record["expect_code"], "POLICY_BLOCK")
        for case in allows:
            record = self.records[case["id"].upper()]
            with self.subTest(case=case["id"]):
                self.assertEqual(record["guard_expect"], "should_allow")
                self.assertEqual(record["control"], "false-positive-control")
                self.assertEqual(record["coverage"], "benign-control")
                self.assertEqual(record["expect_status"], 200)
                self.assertIsNone(record["expect_code"])

    def test_no_output_case_or_output_control_is_relabelled_as_input(self):
        for case in self.dataset["cases"]:
            record = self.records[case["id"].upper()]
            with self.subTest(case=case["id"]):
                self.assertNotIn("output", case)
                self.assertFalse(record["control"].startswith("output_guard"))

    def test_language_assignment_follows_the_documented_rule(self):
        for case in self.dataset["cases"]:
            record = self.records[case["id"].upper()]
            with self.subTest(case=case["id"]):
                self.assertEqual(case["language"], guard_language(record))
        counts = Counter(case["language"] for case in self.dataset["cases"])
        self.assertEqual(counts, {"en": 36, "zh": 2, "mixed": 1})
        self.assertNotIn("bm", counts)
        self.assertEqual(
            {case["id"] for case in self.dataset["cases"] if case["language"] == "zh"},
            {"ctrl-006", "llm01-008"},
        )
        self.assertEqual(
            {case["id"] for case in self.dataset["cases"] if case["language"] == "mixed"},
            {"llm01-006"},
        )

    def test_ctrl_007_is_excluded_from_the_dataset_with_both_bounds_recorded(self):
        """Exclusion is a harness bound, not a guard decision or detection result.

        The one corpus message is 1439 characters and 1449 conservative units: it
        exceeds the dataset's 1024-character per-message bound *and* the guard's
        512-unit single-call window. It must be absent from the cases and present
        once in the ledger, in its own class, with both reasons.
        """
        record = self.records["CTRL-007"]
        self.assertEqual(len(record["messages"]), 1)
        self.assertEqual(len(record["messages"][0]["content"]), 1439)
        self.assertNotIn("ctrl-007", {case["id"] for case in self.dataset["cases"]})
        entries = [
            entry
            for entry in self.ledger["classes"]
            if "CTRL-007" in entry["corpus_ids"]
        ]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["class"], "harness-bound")
        self.assertEqual(entry["count"], 1)
        self.assertEqual(entry["corpus_ids"], ["CTRL-007"])
        reason = entry["reason"]
        self.assertIn("1024-character", reason)
        self.assertIn("512-unit", reason)
        self.assertIn("not a guard decision", reason)
        self.assertIn("not a detection result", reason)

    def test_exclusion_ledger_accounts_for_all_128_corpus_ids_once(self):
        ledger = self.ledger
        self.assertEqual(ledger["schema_version"], 1)
        self.assertEqual(ledger["dataset_id"], GUARD_DATASET_ID)
        self.assertEqual(ledger["corpus_rows"], 128)
        self.assertEqual(ledger["kept"], 39)
        self.assertEqual(ledger["excluded"], 89)
        self.assertEqual(len(ledger["kept_ids"]), 39)
        self.assertEqual(len(set(ledger["kept_ids"])), 39)

        classes = {entry["class"]: entry for entry in ledger["classes"]}
        self.assertEqual(set(classes), set(GUARD_LEDGER_COUNTS))
        self.assertEqual(len(ledger["classes"]), len(classes))
        seen = list(ledger["kept_ids"])
        for name, expected in GUARD_LEDGER_COUNTS.items():
            entry = classes[name]
            with self.subTest(exclusion=name):
                self.assertEqual(entry["count"], expected)
                self.assertEqual(len(entry["corpus_ids"]), expected)
                self.assertTrue(entry["label"].strip())
                self.assertTrue(entry["reason"].strip())
                seen.extend(entry["corpus_ids"])
        self.assertEqual(len(seen), 128)
        self.assertEqual(len(set(seen)), 128, "an id is accounted for twice")
        self.assertEqual(set(seen), set(self.records))
        self.assertEqual(sum(GUARD_LEDGER_COUNTS.values()), 89)
        self.assertEqual(39 + sum(GUARD_LEDGER_COUNTS.values()), EXPECTED_TOTAL)

    def test_dataset_ids_are_exactly_the_kept_ids_and_never_excluded(self):
        case_ids = [case["id"].upper() for case in self.dataset["cases"]]
        self.assertEqual(case_ids, self.ledger["kept_ids"])
        excluded = {
            identifier
            for entry in self.ledger["classes"]
            for identifier in entry["corpus_ids"]
        }
        self.assertFalse(set(case_ids) & excluded)
        self.assertEqual(set(case_ids) | excluded, set(self.records))

    def test_every_kept_row_is_an_input_guard_control_kept_for_a_reason(self):
        for case in self.dataset["cases"]:
            record = self.records[case["id"].upper()]
            with self.subTest(case=case["id"]):
                self.assertIn(
                    record["control"],
                    {"input_attack_guard", "false-positive-control"},
                )


class LocalCapacityHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = load_script("load_gateway_local")

    def test_capacity_at_two_and_four_has_structural_invariants(self):
        self.assertEqual(self.harness.DEFAULT_LEVELS, (1, 2, 4, 8))
        result = self.harness.run_capacity((2, 4))
        self.assertEqual([level["concurrency"] for level in result["levels"]], [2, 4])
        self.assertEqual(
            result["configuration"]["configured_admission_cap"],
            result["configuration"]["max_concurrency"],
        )
        for level in result["levels"]:
            with self.subTest(level=level["concurrency"]):
                self.assertEqual(
                    level["admission_cap"], result["configuration"]["max_concurrency"]
                )
                self.assertEqual(level["overloaded"], level["rejected_before_admission"])
                self.assertEqual(
                    level["admitted"] + level["overloaded"], level["concurrency"]
                )
                self.assertTrue(level["invariants_ok"], level["invariant_failures"])
                self.assertFalse(level["output_leaked"])
                self.assertEqual(
                    level["admitted"], level["concurrency"]
                )
                self.assertEqual(level["rejected_before_admission"], 0)
                accounting = level["slot_accounting"]
                self.assertFalse(accounting["double_release"])
                self.assertEqual(accounting["acquires"], accounting["releases"])
                self.assertEqual(accounting["in_flight_after"], 0)
                self.assertEqual(
                    accounting["value_after"],
                    result["configuration"]["max_concurrency"],
                )
        self.assertTrue(result["invariants"]["ok"], result["invariants"]["failures"])
        self.assertTrue(result["deadline_probe"]["invariants_ok"])
        self.assertTrue(result["control_probe"]["invariants_ok"])
        self.assertEqual(result["deadline_probe"]["response_status"], 503)
        self.assertFalse(result["deadline_probe"]["output_leaked"])
        self.assertGreater(result["deadline_probe"]["slot_held_after_response"], 0)
        self.assertEqual(result["control_probe"]["in_use_after"], 0)


if __name__ == "__main__":
    unittest.main()

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
