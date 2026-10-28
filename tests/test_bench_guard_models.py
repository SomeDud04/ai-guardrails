"""Synthetic tests for the guard-model benchmark's plan mode and report schema.

These tests never load a model, never import ``torch`` or ``transformers`` and
never need an operator artifact directory. The measurement path itself is
exercised by the operator on the guardrail VM; its JSON report is the evidence.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from scripts import bench_guard_models as bench
from nasi_lemak import generation, guard_api

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "bench_guard_models.py"


def run_plan() -> tuple[int, str]:
    stream = StringIO()
    with redirect_stdout(stream):
        status = bench.main(["--plan"])
    return status, stream.getvalue()


def synthetic_bucket(language: str, characters: int) -> dict:
    serialized, _ = bench.case_payload("input", language, characters)
    units = bench.conservative_units(serialized)
    template_units = bench.conservative_units(bench.PROMPT_FRAMING)
    prompt_units = units + template_units
    return {
        "language": language,
        "characters": characters,
        "serialized_characters": len(serialized),
        "conservative_units": units,
        "window_split_count": bench.window_split_count(units),
        "template_units": template_units,
        "prompt_units": prompt_units,
        "prompt_window_split_count": bench.window_split_count(prompt_units),
        "template_tokens": 120,
        "payload_tokens": 40,
        "prompt_tokens": 160,
        "calls": bench.CALLS_PER_BUCKET,
        "warmup_calls": bench.WARMUP_CALLS,
        "errors": 0,
        "over_window_calls": 0,
        "parse_outcomes": {
            "parsed_allow": bench.CALLS_PER_BUCKET,
            "parsed_block": 0,
            "parse_error": 0,
            "inference_error": 0,
        },
        "latency_ms": {"p50": 10.0, "p95": 12.0, "p99": 15.0},
    }


def synthetic_report(*, model: str = "qwen3guard-gen", slot: str = "output") -> dict:
    buckets = [
        synthetic_bucket(language, characters)
        for language in bench.LANGUAGES
        for characters in bench.LENGTHS
    ]
    run = {
        "threads": 4,
        "load_seconds": 12.5,
        "peak_rss_after_load_bytes": 2_000_000_000,
        "peak_rss_after_run_bytes": 2_100_000_000,
        "buckets": buckets,
    }
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "model.safetensors").write_bytes(b"\x00" * 16)
        return bench.build_report(
            model_name=model,
            slot=slot,
            directory=tmp,
            digest="a" * 64,
            threshold=0.5 if model == "promptguard2" else None,
            runs=[run],
        )


class PlanModeTests(unittest.TestCase):
    def test_plan_exits_zero_and_prints_the_full_workload(self) -> None:
        status, output = run_plan()
        self.assertEqual(status, 0)
        for model in bench.MODELS:
            self.assertIn(model, output)
        for slot in bench.SLOTS:
            self.assertIn(slot, output)
        for characters in bench.LENGTHS:
            self.assertIn(str(characters), output)
        for language in bench.LANGUAGES:
            self.assertIn(language, output)
        self.assertIn(f"measured calls per bucket: {bench.CALLS_PER_BUCKET}", output)
        self.assertIn("estimated cost: 0.00 USD", output)
        self.assertIn("NOT a measurement", output)
        self.assertIn("not applicable", output)

    def test_plan_call_counts_cover_every_candidate_and_slot(self) -> None:
        rows = bench.plan_rows()
        applicable = [row for row in rows if row["applicable"]]
        self.assertEqual(len(rows), len(bench.MODELS) * len(bench.SLOTS))
        self.assertEqual(len(applicable), 5)
        for row in applicable:
            self.assertEqual(row["buckets"], len(bench.LANGUAGES) * len(bench.LENGTHS))
            self.assertEqual(
                row["measured_calls"],
                row["buckets"] * bench.CALLS_PER_BUCKET * len(bench.thread_settings()),
            )
        by_key = {(row["model"], row["slot"]): row for row in rows}
        self.assertFalse(by_key[("promptguard2", "output")]["applicable"])
        self.assertEqual(by_key[("promptguard2", "output")]["measured_calls"], 0)
        self.assertEqual(sum(row["measured_calls"] for row in rows), 2400)

    def test_plan_thread_settings_are_cpu_count_then_cap(self) -> None:
        self.assertEqual(bench.thread_settings(cpu_count=4, cap=2), [4, 2])
        self.assertEqual(bench.thread_settings(cpu_count=2, cap=2), [2])
        self.assertEqual(bench.thread_settings(cpu_count=8, cap=2), [8, 2])
        with self.assertRaises(bench.BenchmarkError):
            bench.thread_settings(cpu_count=4, cap=0)

    def test_plan_does_not_import_torch_or_transformers(self) -> None:
        probe = (
            "import importlib.util, json, sys\n"
            f"spec = importlib.util.spec_from_file_location('bench_probe', r'{SCRIPT}')\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "status = module.main(['--plan'])\n"
            "print(json.dumps({\n"
            "    'status': status,\n"
            "    'torch': 'torch' in sys.modules,\n"
            "    'transformers': 'transformers' in sys.modules,\n"
            "}))\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["status"], 0)
        self.assertFalse(payload["torch"])
        self.assertFalse(payload["transformers"])

    def test_plan_opens_no_socket(self) -> None:
        probe = (
            "import importlib.util, socket, sys\n"
            "class Blocked(socket.socket):\n"
            "    def __init__(self, *args, **kwargs):\n"
            "        raise AssertionError('plan mode opened a socket')\n"
            "socket.socket = Blocked\n"
            "socket.create_connection = lambda *a, **k: (_ for _ in ()).throw("
            "AssertionError('plan mode opened a connection'))\n"
            f"spec = importlib.util.spec_from_file_location('bench_probe', r'{SCRIPT}')\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(module)\n"
            "raise SystemExit(module.main(['--plan']))\n"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_plan_writes_no_report_and_needs_no_model_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plan-report.json"
            stream = StringIO()
            with redirect_stdout(stream):
                status = bench.main(["--plan", "--report", str(target)])
            self.assertEqual(status, 0)
            self.assertFalse(target.exists())


class WorkloadDefinitionTests(unittest.TestCase):
    def test_filler_is_exact_length_innocuous_and_per_language(self) -> None:
        for language in bench.LANGUAGES:
            for characters in bench.LENGTHS:
                text = bench.filler_text(language, characters)
                self.assertEqual(len(text), characters)
                self.assertFalse(any(ord(character) < 0x20 for character in text))
        self.assertNotEqual(
            bench.filler_text("zh", 200), bench.filler_text("en", 200)
        )
        self.assertNotEqual(
            bench.filler_text("bm", 200), bench.filler_text("en", 200)
        )

    def test_conservative_units_match_the_gateway_budget(self) -> None:
        for language in bench.LANGUAGES:
            serialized, _ = bench.case_payload("input", language, 500)
            self.assertEqual(
                bench.conservative_units(serialized),
                generation.conservative_byte_budget(serialized),
            )
        self.assertEqual(bench.conservative_units("user: ab"), 12)

    def test_window_split_count_is_deterministic(self) -> None:
        self.assertEqual(bench.window_split_count(1), 1)
        self.assertEqual(bench.window_split_count(bench.WINDOW_UNITS), 1)
        self.assertEqual(bench.window_split_count(bench.WINDOW_UNITS + 1), 2)
        self.assertEqual(bench.window_split_count(1449), 3)

    def test_chinese_is_denser_per_character_under_the_byte_bound(self) -> None:
        # The conservative unit is a UTF-8 byte bound, so CJK filler costs more
        # units per character and splits into more windows at the same length.
        english = bench.case_payload("input", "en", 1000)[0]
        chinese = bench.case_payload("input", "zh", 1000)[0]
        malay = bench.case_payload("input", "bm", 1000)[0]
        self.assertGreater(bench.conservative_units(chinese), bench.conservative_units(english))
        self.assertGreater(
            bench.window_split_count(bench.conservative_units(chinese)),
            bench.window_split_count(bench.conservative_units(english)),
        )
        # Malay is ASCII, so the byte bound cannot separate it from English;
        # its token density is measured as prompt_tokens on the VM instead.
        self.assertEqual(
            bench.conservative_units(malay), bench.conservative_units(english)
        )

    def test_every_language_and_length_is_reported_with_units_and_splits(self) -> None:
        # Amendment requirement: per language AND per length the report carries
        # the character count, the conservative-unit count, the window split
        # count and the percentiles (the bucket keys are asserted in the schema
        # tests; this test pins the workload shape).
        for language in bench.LANGUAGES:
            for characters in bench.LENGTHS:
                bucket = synthetic_bucket(language, characters)
                self.assertEqual(bucket["language"], language)
                self.assertEqual(bucket["characters"], characters)
                self.assertGreaterEqual(bucket["conservative_units"], characters)
                self.assertGreaterEqual(bucket["window_split_count"], 1)
                self.assertEqual(
                    bucket["window_split_count"],
                    bench.window_split_count(bucket["conservative_units"]),
                )
                self.assertEqual(
                    bucket["prompt_window_split_count"],
                    bench.window_split_count(bucket["prompt_units"]),
                )
                self.assertIn("latency_ms", bucket)

    def test_fixed_framing_is_a_large_share_of_one_window(self) -> None:
        # Derived arithmetic, not a measurement: the fixed framing alone is most
        # of a 512-unit window, so a windowed design would repeat it per window.
        framing = bench.conservative_units(bench.PROMPT_FRAMING)
        self.assertGreater(framing, bench.WINDOW_UNITS // 2)
        self.assertLess(framing, bench.WINDOW_UNITS)
        self.assertEqual(framing, 432)

    def test_tokenizer_options_follow_the_product_loaders(self) -> None:
        # guards.PromptGuard2 tokenizes with add_special_tokens=True and compares
        # that count to the 512-token window, so the benchmark must match it.
        self.assertEqual(
            bench.tokenizer_call_options("sequence-classification-2"),
            {"add_special_tokens": True, "truncation": False},
        )
        for kind in ("causal", "sequence-classification-3"):
            self.assertEqual(
                bench.tokenizer_call_options(kind),
                {"add_special_tokens": False, "truncation": False},
            )
        with self.assertRaises(bench.BenchmarkError):
            bench.tokenizer_call_options("system")

    def test_output_slot_includes_the_masked_context(self) -> None:
        serialized, _ = bench.case_payload("output", "en", 200)
        self.assertTrue(serialized.startswith(bench.OUTPUT_CONTEXT))
        self.assertIn("<EMAIL>", serialized)
        with self.assertRaises(bench.BenchmarkError):
            bench.case_payload("system", "en", 200)


class ContractTests(unittest.TestCase):
    def test_taxonomy_matches_the_product_contract(self) -> None:
        self.assertEqual(set(bench.CATEGORY_VALUES), guard_api._CATEGORY_VALUES)
        self.assertEqual(len(bench.CATEGORY_VALUES), len(guard_api._CATEGORY_VALUES))
        self.assertEqual(bench.SAFETY_VALUES, guard_api._SAFETY_VALUES)
        self.assertEqual(bench.REFUSAL_VALUES, guard_api._REFUSAL_VALUES)

    def test_parse_verdict_matches_the_product_parser(self) -> None:
        samples = (
            "Safety: Safe\nCategories: None\nRefusal: No",
            "Safety: Unsafe\nCategories: Violent, PII\nRefusal: No",
            "Safety: Controversial\nCategories: Politically Sensitive Topics\nRefusal: Yes",
        )
        for sample in samples:
            self.assertEqual(
                bench.parse_verdict(sample)["allow"], guard_api.parse_verdict(sample)
            )
        for malformed in (
            "Safety: Safe\nCategories: Violent\nRefusal: No",
            "Safety: Unsafe\nCategories: None\nRefusal: No",
            "Safety: Safe\nCategories: None",
            "safe",
            "",
        ):
            with self.assertRaises(bench.BenchmarkError):
                bench.parse_verdict(malformed)
            with self.assertRaises(Exception):
                guard_api.parse_verdict(malformed)

    def test_parse_safety_label_is_strict(self) -> None:
        self.assertEqual(bench.parse_safety_label("Safe"), "Safe")
        self.assertEqual(bench.parse_safety_label("Unsafe"), "Unsafe")
        self.assertEqual(bench.parse_safety_label("Controversial"), "Controversial")
        self.assertEqual(bench.parse_safety_label("UNSAFE"), "Unsafe")
        for label in ("LABEL_0", "", None, "Other"):
            with self.assertRaises(bench.BenchmarkError):
                bench.parse_safety_label(label)


class ReportSchemaTests(unittest.TestCase):
    def test_valid_report_has_no_schema_errors(self) -> None:
        report = synthetic_report()
        self.assertEqual(bench.validate_report(report), [])

    def test_report_carries_no_input_text_prompt_or_output(self) -> None:
        report = synthetic_report()
        rendered = json.dumps(report)
        for filler in ("weekly report", "Pasukan", "团队", bench.PROMPT_FRAMING):
            self.assertNotIn(filler, rendered)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("https://", rendered)

    def test_environment_accepts_the_linux_ram_value(self) -> None:
        # /proc/meminfo MemTotal is an integer byte count on the guardrail VM;
        # a string-only check here would reject every report measured on Linux.
        report = synthetic_report()
        report["environment"]["ram_bytes"] = 16 * 1024**3
        self.assertEqual(bench.validate_report(report), [])
        report["environment"]["ram_bytes"] = "16 GiB"
        self.assertTrue(bench.validate_report(report))

    def test_extra_keys_are_rejected(self) -> None:
        report = synthetic_report()
        report["prompt_text"] = "synthetic"
        self.assertTrue(bench.validate_report(report))
        report = synthetic_report()
        report["candidate"]["input_text"] = "synthetic"
        self.assertTrue(bench.validate_report(report))
        report = synthetic_report()
        report["thread_settings"][0]["buckets"][0]["raw_input"] = "synthetic"
        self.assertTrue(bench.validate_report(report))

    def test_bucket_consistency_is_checked(self) -> None:
        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["calls"] = 19
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["parse_outcomes"]["parsed_allow"] = 1
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["latency_ms"] = {"p50": 20.0, "p95": 10.0, "p99": 30.0}
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["window_split_count"] = 99
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["prompt_units"] = bucket["prompt_units"] + bench.WINDOW_UNITS
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["template_units"] = 0
        self.assertTrue(bench.validate_report(report))

    def test_errors_must_be_counted_and_match_outcomes(self) -> None:
        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["parse_outcomes"]["parse_error"] = 2
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        bucket = report["thread_settings"][0]["buckets"][0]
        bucket["parse_outcomes"]["parse_error"] = 2
        bucket["parse_outcomes"]["parsed_allow"] = 18
        bucket["errors"] = 2
        report["totals"]["errors"] = 2
        self.assertEqual(bench.validate_report(report), [])

        report = synthetic_report()
        report["totals"]["errors"] = 3
        self.assertTrue(bench.validate_report(report))

    def test_candidate_and_thread_settings_are_checked(self) -> None:
        report = synthetic_report(model="promptguard2", slot="output")
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        report["candidate"]["artifact_sha256"] = "not-a-digest"
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        report["thread_settings"] = []
        self.assertTrue(bench.validate_report(report))

        report = synthetic_report()
        report["thread_settings"][0]["threads"] = 4
        report["thread_settings"].append(dict(report["thread_settings"][0]))
        self.assertTrue(bench.validate_report(report))

    def test_single_thread_setting_report_is_valid(self) -> None:
        # When the cap equals the CPU count only one setting is measured.
        report = synthetic_report()
        self.assertEqual(len(report["thread_settings"]), 1)
        self.assertEqual(bench.validate_report(report), [])


class ReportWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_write_report_is_create_exclusive(self) -> None:
        target = self.root / "report.json"
        bench.write_report(synthetic_report(), str(target))
        first = target.read_text(encoding="utf-8")
        with self.assertRaises(bench.BenchmarkError):
            bench.write_report(synthetic_report(), str(target))
        self.assertEqual(target.read_text(encoding="utf-8"), first)

    def test_invalid_report_is_never_written(self) -> None:
        target = self.root / "report.json"
        report = synthetic_report()
        report["candidate"]["input_text"] = "synthetic"
        with self.assertRaises(bench.BenchmarkError):
            bench.write_report(report, str(target))
        self.assertFalse(target.exists())

    def test_written_report_round_trips(self) -> None:
        target = self.root / "report.json"
        bench.write_report(synthetic_report(), str(target))
        payload = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(bench.validate_report(payload), [])
        self.assertEqual(payload["schema_version"], bench.SCHEMA_VERSION)


class MeasurementGuardTests(unittest.TestCase):
    def test_missing_model_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "absent-artifact"
            with self.assertRaises(bench.BenchmarkError):
                bench.measure(
                    model_name="qwen3guard-gen",
                    slot="input",
                    model_dir=str(missing),
                    report_path=None,
                    digest=None,
                    cap=2,
                    threshold=0.5,
                )

    def test_hub_id_and_url_are_not_accepted_as_directories(self) -> None:
        for value in ("Qwen/Qwen3Guard-Gen-0.6B", "https://example.invalid/model", ""):
            with self.assertRaises(bench.BenchmarkError):
                bench.measure(
                    model_name="qwen3guard-gen",
                    slot="input",
                    model_dir=value,
                    report_path=None,
                    digest=None,
                    cap=2,
                    threshold=0.5,
                )

    def test_promptguard2_has_no_output_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(bench.BenchmarkError):
                bench.measure(
                    model_name="promptguard2",
                    slot="output",
                    model_dir=tmp,
                    report_path=None,
                    digest=None,
                    cap=2,
                    threshold=0.5,
                )

    def test_invalid_digest_fails_closed(self) -> None:
        with self.assertRaises(bench.BenchmarkError):
            bench._parse_sha256("abc")
        self.assertEqual(bench._parse_sha256("A" * 64), "a" * 64)
        self.assertIsNone(bench._parse_sha256(None))

    def test_unusable_report_path_fails_before_the_model_load(self) -> None:
        # A typo in --report must not cost a multi-minute measurement, so the
        # target is checked before the artifact is loaded.
        with tempfile.TemporaryDirectory() as tmp:
            model_dir = Path(tmp) / "artifact"
            model_dir.mkdir()
            target = Path(tmp) / "missing-dir" / "report.json"
            with self.assertRaises(bench.BenchmarkError) as caught:
                bench.measure(
                    model_name="qwen3guard-gen",
                    slot="input",
                    model_dir=str(model_dir),
                    report_path=str(target),
                    digest=None,
                    cap=2,
                    threshold=0.5,
                )
            self.assertIn("report directory is missing", str(caught.exception))
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
