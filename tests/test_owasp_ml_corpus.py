"""Contract tests for the Malay and Chinese mirror of the OWASP corpus.

Standard library only.  The committed files are read directly and compared with
the frozen English corpus and the guard-lane datasets, so these checks do not
rely on the builder's own validation.  The builder is exercised separately for
drift and for the inputs it must refuse.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EN_PAYLOADS = ROOT / "evals" / "owasp" / "llm-top10-2026" / "payloads"
ML_ROOT = ROOT / "evals" / "owasp" / "llm-top10-2026-ml"
ML_PAYLOADS = ML_ROOT / "payloads"
GUARDS = ROOT / "evals" / "guards"
BUILDER_PATH = ROOT / "scripts" / "build_owasp_ml_corpus.py"

HAN = re.compile(r"[㐀-䶿一-鿿]")
EXPECTED_PER_LANGUAGE = {"CTRL": 17, "LLM01": 18, "LLM03": 3, "LLM04": 1}
REUSED_SOURCES = {
    "bm": ("owasp-llm-top10-2026-v2-bm.json", "owasp-llm-top10-2026-v3-bm-ctrl.json"),
    "zh": ("owasp-llm-top10-2026-v3-zh.json",),
}


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _load_builder():
    sys.path.insert(0, str(BUILDER_PATH.parent))
    spec = importlib.util.spec_from_file_location("build_owasp_ml_corpus", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _text(row: dict) -> str:
    return "\n".join(message["content"] for message in row["messages"])


class MlCorpusContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.english = {
            row["id"]: row for path in sorted(EN_PAYLOADS.glob("*.jsonl")) for row in _jsonl(path)
        }
        cls.english_file = {
            row["id"]: path.name for path in sorted(EN_PAYLOADS.glob("*.jsonl")) for row in _jsonl(path)
        }
        cls.files = {path.name: _jsonl(path) for path in sorted(ML_PAYLOADS.glob("*.jsonl"))}
        cls.rows = [row for rows in cls.files.values() for row in rows]
        cls.schema = json.loads((ML_ROOT / "schema.json").read_text(encoding="utf-8"))

    def test_row_counts_per_language_and_category(self) -> None:
        self.assertEqual(len(self.rows), 2 * sum(EXPECTED_PER_LANGUAGE.values()))
        counts = Counter((row["language"], row["category"]) for row in self.rows)
        for language in ("bm", "zh"):
            for category, expected in EXPECTED_PER_LANGUAGE.items():
                self.assertEqual(counts[(language, category)], expected, (language, category))

    def test_ids_are_unique_and_follow_language_and_mirror(self) -> None:
        ids = [row["id"] for row in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        pattern = re.compile(self.schema["properties"]["id"]["pattern"])
        for row in self.rows:
            self.assertRegex(row["id"], pattern)
            self.assertEqual(row["id"], f"{row['language'].upper()}-{row['mirror_of']}")

    def test_every_field_but_text_equals_the_english_row(self) -> None:
        for row in self.rows:
            with self.subTest(row=row["id"]):
                english = self.english[row["mirror_of"]]
                self.assertEqual(
                    set(row) - {"language", "mirror_of"}, set(english),
                )
                for key, value in english.items():
                    if key in ("id", "messages"):
                        continue
                    self.assertEqual(row[key], value, key)
                self.assertEqual(
                    [m["role"] for m in row["messages"]],
                    [m["role"] for m in english["messages"]],
                )
                for message in row["messages"]:
                    self.assertEqual(set(message), {"role", "content"})
                    self.assertTrue(message["content"].strip())

    def test_rows_sit_in_the_english_file_in_english_order(self) -> None:
        english_order = list(self.english)
        for name, rows in self.files.items():
            with self.subTest(file=name):
                for row in rows:
                    self.assertEqual(self.english_file[row["mirror_of"]], name)
                keys = [(english_order.index(r["mirror_of"]), r["language"]) for r in rows]
                self.assertEqual(keys, sorted(keys))

    def test_text_is_translated_and_in_the_right_script(self) -> None:
        for row in self.rows:
            with self.subTest(row=row["id"]):
                text = _text(row)
                english_text = _text(self.english[row["mirror_of"]])
                self.assertNotEqual(text, english_text)
                if row["language"] == "zh":
                    self.assertRegex(text, HAN)
                elif not HAN.search(english_text):
                    self.assertNotRegex(text, HAN)

    def test_reused_rows_match_the_guard_lane_text_verbatim(self) -> None:
        by_id = {row["id"]: row for row in self.rows}
        reused = 0
        for language, names in REUSED_SOURCES.items():
            for name in names:
                payload = json.loads((GUARDS / name).read_text(encoding="utf-8"))
                for case in payload["cases"]:
                    rest = case["id"][len(language) + 1:]
                    if not rest.startswith(("llm", "ctrl")):
                        continue
                    row = by_id[f"{language.upper()}-{rest.upper()}"]
                    self.assertEqual(row["messages"], case["messages"], case["id"])
                    reused += 1
        self.assertEqual(reused, len(self.rows))

    def test_schema_describes_every_row(self) -> None:
        required = self.schema["required"]
        self.assertIn("language", required)
        self.assertIn("mirror_of", required)
        self.assertEqual(self.schema["properties"]["language"]["enum"], ["bm", "zh"])
        mirror = re.compile(self.schema["properties"]["mirror_of"]["pattern"])
        allowed = set(self.schema["properties"])
        for row in self.rows:
            self.assertTrue(set(required) <= set(row), row["id"])
            self.assertTrue(set(row) <= allowed, row["id"])
            self.assertRegex(row["mirror_of"], mirror)

    def test_manifest_lists_every_generated_file(self) -> None:
        manifest = (ML_ROOT / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
        listed = {line.split("  ", 1)[1] for line in manifest}
        expected = {"schema.json", "translations.json"} | {f"payloads/{name}" for name in self.files}
        self.assertEqual(listed, expected)


class MlCorpusBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = _load_builder()

    def test_committed_files_equal_a_fresh_build(self) -> None:
        self.assertEqual(self.builder.check(), [])

    def test_guard_id_mapping(self) -> None:
        to_en = self.builder.guard_to_english_id
        self.assertEqual(to_en("bm-llm01-002", "bm"), "LLM01-002")
        self.assertEqual(to_en("zh-ctrl-017", "zh"), "CTRL-017")
        self.assertIsNone(to_en("bm-ben-014", "bm"))
        self.assertIsNone(to_en("zh-llm01-001", "bm"))

    def test_mirror_refuses_changed_roles(self) -> None:
        english = self.builder.english_records()[0]
        messages = [{"role": "assistant", "content": "x"}] + english["messages"]
        with self.assertRaises(self.builder.MlCorpusError):
            self.builder.mirror_row(english, "bm", messages, "test")

    def test_validate_refuses_a_changed_expectation(self) -> None:
        records = self.builder.english_records()
        by_id = {record["id"]: record for record in records}
        english = by_id["LLM01-001"]
        row = self.builder.mirror_row(english, "zh", english["messages"], "test")
        self.builder.validate_mirror(row, by_id)
        row["expect_status"] = 200
        row["expect_code"] = None
        with self.assertRaises(self.builder.MlCorpusError):
            self.builder.validate_mirror(row, by_id)

    def _translations(self, rows: dict) -> Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        with handle:
            json.dump({"schema_version": 1, "rows": rows}, handle)
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def test_translations_must_hold_both_languages(self) -> None:
        with self.assertRaises(self.builder.MlCorpusError):
            self.builder.authored_messages(self._translations({"bm": {}}))

    def test_build_refuses_a_translation_that_duplicates_a_reused_row(self) -> None:
        path = self._translations(
            {"bm": {"LLM01-001": [{"role": "user", "content": "x"}]}, "zh": {}}
        )
        original = self.builder.authored_messages
        self.builder.authored_messages = lambda: original(path)
        self.addCleanup(setattr, self.builder, "authored_messages", original)
        with self.assertRaises(self.builder.MlCorpusError):
            self.builder.build_rows()

    def test_build_refuses_an_unknown_english_row(self) -> None:
        path = self._translations(
            {"bm": {}, "zh": {"LLM99-001": [{"role": "user", "content": "x"}]}}
        )
        original = self.builder.authored_messages
        self.builder.authored_messages = lambda: original(path)
        self.addCleanup(setattr, self.builder, "authored_messages", original)
        with self.assertRaises(self.builder.MlCorpusError):
            self.builder.build_rows()


if __name__ == "__main__":
    unittest.main()
