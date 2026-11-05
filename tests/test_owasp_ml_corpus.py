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
EXPECTED_PER_LANGUAGE = {
    "CTRL": 18, "LLM01": 19, "LLM02": 14, "LLM03": 4, "LLM04": 2,
    "LLM06": 1, "LLM07": 9, "LLM08": 14, "LLM10": 4,
}
# The pilot example caps the byte budget at 3000; the default is 8192.
SMALLEST_BYTE_BUDGET = 3000
DEFAULT_BYTE_BUDGET = 8192
MAX_SERIALIZED_CHARS = 4096
ENGLISH_DENY_PHRASE = "synthetic denied phrase"
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
        authored = json.loads((ML_ROOT / "translations.json").read_text(encoding="utf-8"))["rows"]
        self.assertEqual(reused + sum(len(rows) for rows in authored.values()), len(self.rows))

    def test_identifiers_are_kept_verbatim(self) -> None:
        """Every value a leak check looks for in the English row is in the mirror."""
        sys.path.insert(0, str(ROOT / "scripts"))
        import run_owasp_live as live

        for row in self.rows:
            if row["category"] == "LLM01":
                # The reused LLM01 attacks re-encode their payload in the target
                # language (Malay Base64, pinyin leetspeak), so their tokens
                # differ from English on purpose.
                continue
            english = self.english[row["mirror_of"]]
            values = set(live.raw_pii(english)) | {
                value for value in live.raw_values(english) if not value.isdigit()
            }
            mirror_text = _text(row)
            mirror_digits = re.sub(r"[^0-9]", "", mirror_text)
            for value in values:
                with self.subTest(row=row["id"], value=value):
                    self.assertIn(value, mirror_text)
            for value in live.raw_values(english):
                if value.isdigit():
                    with self.subTest(row=row["id"], digits=value):
                        self.assertIn(value, mirror_digits)

    def test_output_handling_payloads_are_unchanged(self) -> None:
        for row in self.rows:
            if row["category"] != "LLM10":
                continue
            payload = _text(self.english[row["mirror_of"]]).split(": ", 1)[1]
            # Plain words such as "and" are translated; every token carrying
            # markup or symbols must survive exactly.
            for token in payload.split():
                if token.isalpha():
                    continue
                with self.subTest(row=row["id"], token=token):
                    self.assertIn(token, _text(row))

    def test_token_budget_pair_sizes(self) -> None:
        """Byte side of the sizing; token counts are recorded in the README.

        LLM06-011 mirrors must be at least as large as the English row in byte
        units (so a byte-budget stop applies to them too) while staying under the
        serialized-character cap and the default byte budget; CTRL-007 mirrors
        must stay under the smallest byte budget the pilot uses.
        """
        from nasi_lemak.generation import conservative_byte_budget
        from nasi_lemak.qwen3guard import serialize_messages

        def units(row: dict) -> int:
            return conservative_byte_budget(serialize_messages(row["messages"]))

        english_overflow = units(self.english["LLM06-011"])
        for row in self.rows:
            serialized = serialize_messages(row["messages"])
            with self.subTest(row=row["id"]):
                if row["mirror_of"] == "LLM06-011":
                    self.assertGreaterEqual(units(row), english_overflow)
                    self.assertLess(units(row), DEFAULT_BYTE_BUDGET)
                    self.assertLess(len(serialized), MAX_SERIALIZED_CHARS)
                elif row["mirror_of"] == "CTRL-007":
                    self.assertLess(units(row), SMALLEST_BYTE_BUDGET)

    def test_deny_phrase_rows_keep_the_english_phrase(self) -> None:
        for row in self.rows:
            english = " ".join(_text(self.english[row["mirror_of"]]).split()).casefold()
            if ENGLISH_DENY_PHRASE not in english:
                continue
            with self.subTest(row=row["id"]):
                self.assertIn(ENGLISH_DENY_PHRASE, " ".join(_text(row).split()).casefold())

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
