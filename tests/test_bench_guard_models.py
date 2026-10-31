"""Synthetic tests for the guard-model benchmark's plan mode and report schema.

These tests never load a model, never import ``torch`` or ``transformers`` and
never need an operator artifact directory. The measurement path itself is
exercised by the operator on the guardrail VM; its JSON report is the evidence.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from scripts import bench_guard_models as bench
from nasi_lemak import generation, guard_api, qwen3guard

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "bench_guard_models.py"
#: Keep the real class available even while ``measure`` is patched to use a
#: factory, so the causal double exercises the actual Runner methods.
REAL_RUNNER = bench.Runner


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
        self.assertEqual(
            bench.INPUT_ONLY_CATEGORY_VALUES,
            qwen3guard.INPUT_ONLY_CATEGORY_VALUES,
        )

    def test_benchmark_reuses_the_canonical_contract_objects(self) -> None:
        # Import/alias, not mirrored copies: identity is the strongest proof
        # that there is one taxonomy, one framing and one parser definition.
        self.assertIs(bench.CATEGORY_VALUES, qwen3guard.CATEGORY_VALUES)
        self.assertIs(bench.SAFETY_VALUES, qwen3guard.SAFETY_VALUES)
        self.assertIs(bench.REFUSAL_VALUES, qwen3guard.REFUSAL_VALUES)
        self.assertIs(
            bench.INPUT_ONLY_CATEGORY_VALUES,
            qwen3guard.INPUT_ONLY_CATEGORY_VALUES,
        )
        self.assertIs(
            bench.INPUT_CATEGORY_VALUES, qwen3guard.INPUT_CATEGORY_VALUES
        )
        self.assertIs(bench.LANE_INPUT, qwen3guard.LANE_INPUT)
        self.assertIs(bench.LANE_RESPONSE, qwen3guard.LANE_RESPONSE)
        self.assertIs(bench.VERDICT_MAX_TOKENS, qwen3guard.VERDICT_MAX_TOKENS)
        self.assertIs(bench.parse_categories, qwen3guard.parse_categories)
        self.assertIs(bench.parse_verdict_fields, qwen3guard.parse_verdict_fields)
        self.assertEqual(bench.PROMPT_FRAMING, qwen3guard.GUARD_FRAMING)
        self.assertEqual(bench.PROMPT_FRAMING_VERSION, qwen3guard.FRAMING_VERSION)

    def test_slot_lanes_map_output_to_response(self) -> None:
        self.assertEqual(bench.SLOT_LANES, {"input": "input", "output": "response"})
        self.assertEqual(bench._slot_lane("input"), qwen3guard.LANE_INPUT)
        self.assertEqual(bench._slot_lane("output"), qwen3guard.LANE_RESPONSE)
        with self.assertRaises(bench.BenchmarkError):
            bench._slot_lane("system")

    def test_input_lane_accepts_the_artifact_two_line_verdict(self) -> None:
        for sample in (
            "Safety: Safe\nCategories: None",
            "Safety: Unsafe\nCategories: Jailbreak",
            "Safety: Unsafe\nCategories: Violent, PII",
        ):
            with self.subTest(sample=sample):
                result = bench.parse_verdict(sample, lane="input")
                expected = qwen3guard.parse_verdict_fields(sample, lane="input")
                self.assertEqual(result["safety"], expected.safety)
                self.assertEqual(tuple(result["categories"]), expected.categories)
                self.assertEqual(result["refusal"], expected.refusal)
                self.assertEqual(result["allow"], expected.safe)

    def test_response_lane_rejects_the_input_shape_and_jailbreak(self) -> None:
        for sample in (
            "Safety: Safe\nCategories: None",
            "Safety: Unsafe\nCategories: Jailbreak\nRefusal: No",
        ):
            with self.subTest(sample=sample):
                with self.assertRaises(bench.BenchmarkError):
                    bench.parse_verdict(sample)
                with self.assertRaises(Exception):
                    guard_api.parse_verdict(sample, lane="response")

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


class _FakeCausalTokenizer:
    """Deterministic word tokenizer and chat template; no model files."""

    def __init__(self) -> None:
        self.eos_token_id = 7
        self.pad_token_id = 7
        self.template_calls: list[tuple[list[dict[str, str]], bool, bool]] = []
        self._vocab: dict[str, int] = {}
        self._reverse: dict[int, str] = {}
        self._outputs: dict[int, str] = {}
        self._next_token = 100
        self._next_output = 50_000

    def _word_id(self, word: str) -> int:
        if word not in self._vocab:
            self._vocab[word] = self._next_token
            self._reverse[self._next_token] = word
            self._next_token += 1
        return self._vocab[word]

    def __call__(
        self,
        text: str,
        add_special_tokens: bool = False,
        truncation: bool = False,
    ) -> dict[str, list[int]]:
        self.assert_contract(add_special_tokens, truncation)
        return {"input_ids": [self._word_id(word) for word in text.split()]}

    @staticmethod
    def assert_contract(add_special_tokens: bool, truncation: bool) -> None:
        if add_special_tokens is not False or truncation is not False:
            raise AssertionError(
                "causal benchmark tokenization must not add specials or truncate"
            )

    def apply_chat_template(
        self,
        conversation: list[dict[str, str]],
        tokenize: bool = False,
        add_generation_prompt: bool = True,
    ) -> str:
        self.template_calls.append(
            (
                [dict(message) for message in conversation],
                tokenize,
                add_generation_prompt,
            )
        )
        return "".join(
            f"{message['role']}: {message['content']}\n" for message in conversation
        )

    def output_ids(self, text: str) -> list[int]:
        identifier = self._next_output
        self._next_output += 1
        self._outputs[identifier] = text
        return [identifier]

    def decode(self, ids: list[int], skip_special_tokens: bool = True) -> str:
        parts: list[str] = []
        for identifier in ids:
            if skip_special_tokens and identifier == self.eos_token_id:
                continue
            if identifier in self._outputs:
                parts.append(self._outputs[identifier])
            else:
                parts.append(self._reverse.get(identifier, ""))
        return "".join(parts)


class _FakeTorch:
    """Minimal tensor/thread seam for the real Runner causal path."""

    def __init__(self) -> None:
        self.threads: list[int] = []

    def tensor(self, values):
        return values

    def inference_mode(self):
        return contextlib.nullcontext()

    def set_num_threads(self, value: int) -> None:
        self.threads.append(value)


class _FakeCausalModel:
    def __init__(self, tokenizer: _FakeCausalTokenizer, output: str) -> None:
        self.tokenizer = tokenizer
        self.output = output
        self.calls = 0
        self.config = types.SimpleNamespace(
            max_position_embeddings=32768,
            eos_token_id=7,
            architectures=["Qwen3ForCausalLM"],
            model_type="qwen3",
        )
        self.generation_config = None

    def generate(self, **inputs):
        self.calls += 1
        prompt = list(inputs["input_ids"][0])
        return types.SimpleNamespace(
            sequences=[
                prompt + self.tokenizer.output_ids(self.output) + [self.tokenizer.eos_token_id]
            ]
        )


def causal_runner(output: str) -> bench.Runner:
    """A real Runner with an inference double, so its causal parse path runs."""
    tokenizer = _FakeCausalTokenizer()
    model = _FakeCausalModel(tokenizer, output)
    runner = REAL_RUNNER.__new__(REAL_RUNNER)
    runner.name = "qwen3guard-gen"
    runner.kind = "causal"
    runner.threshold = 0.5
    runner._torch = _FakeTorch()
    runner.tokenizer = tokenizer
    runner.model = model
    runner._context_window = 32768
    runner._mapping = {}
    runner._eos = tokenizer.eos_token_id
    runner._pad = tokenizer.pad_token_id
    return runner


class _RunnerFactory:
    """Replace ``bench.Runner`` during ``measure`` with a causal double."""

    def __init__(self, output: str) -> None:
        self.output = output
        self.calls = 0

    def __call__(self, model_name, directory, *, threads, threshold):
        self.calls += 1
        return causal_runner(self.output)


class CausalRunnerLaneTests(unittest.TestCase):
    """Exercise the real Runner causal parsing, not parse_verdict in isolation."""

    TWO_LINE_INPUT = "Safety: Safe\nCategories: None"
    THREE_LINE_RESPONSE = "Safety: Safe\nCategories: None\nRefusal: No"
    JAILBREAK_RESPONSE = "Safety: Unsafe\nCategories: Jailbreak\nRefusal: No"

    def test_input_slot_parses_the_official_two_line_verdict(self) -> None:
        runner = causal_runner(self.TWO_LINE_INPUT)
        bucket = bench._measure_bucket(
            runner, slot="input", language="en", characters=200
        )
        self.assertEqual(bucket["errors"], 0)
        self.assertEqual(
            bucket["parse_outcomes"],
            {
                "parsed_allow": bench.CALLS_PER_BUCKET,
                "parsed_block": 0,
                "parse_error": 0,
                "inference_error": 0,
            },
        )
        self.assertEqual(
            runner.model.calls, bench.CALLS_PER_BUCKET + bench.WARMUP_CALLS
        )

    def test_benchmark_uses_the_same_template_helper_as_the_product(self) -> None:
        # One delivery, both consumers: the benchmark must not carry a private
        # copy that can drift from the deployed lane.
        self.assertIs(bench.render_guard_prompt, qwen3guard.render_guard_prompt)

    def test_input_bucket_builds_only_the_user_message(self) -> None:
        runner = causal_runner(self.TWO_LINE_INPUT)
        bench._measure_bucket(runner, slot="input", language="en", characters=200)
        serialized = bench.case_payload("input", "en", 200)[0]
        shaped = [
            call
            for call in runner.tokenizer.template_calls
            if call[0][-1]["content"] == serialized
        ]
        self.assertEqual(len(shaped), 1)
        messages, tokenize, add_generation_prompt = shaped[0]
        self.assertEqual(messages, [{"role": "user", "content": serialized}])
        self.assertFalse(tokenize)
        self.assertTrue(add_generation_prompt)

    def test_output_bucket_builds_system_user_and_assistant_messages(self) -> None:
        runner = causal_runner(self.THREE_LINE_RESPONSE)
        bench._measure_bucket(runner, slot="output", language="en", characters=200)
        serialized = bench.case_payload("output", "en", 200)[0]
        reply = serialized[len(bench.OUTPUT_PREFIX) :]
        shaped = [
            call
            for call in runner.tokenizer.template_calls
            if len(call[0]) == 3 and call[0][2]["content"] == reply
        ]
        self.assertEqual(len(shaped), 1)
        messages, tokenize, add_generation_prompt = shaped[0]
        self.assertEqual(
            messages,
            [
                {"role": "system", "content": bench.PROMPT_FRAMING},
                {"role": "user", "content": bench.OUTPUT_CONTEXT},
                {"role": "assistant", "content": reply},
            ],
        )
        self.assertFalse(tokenize)
        self.assertTrue(add_generation_prompt)

    def test_output_slot_parses_the_three_line_response_verdict(self) -> None:
        # The bug this catches: passing slot="output" as the parser lane.
        runner = causal_runner(self.THREE_LINE_RESPONSE)
        bucket = bench._measure_bucket(
            runner, slot="output", language="en", characters=200
        )
        self.assertEqual(bucket["errors"], 0)
        self.assertEqual(
            bucket["parse_outcomes"],
            {
                "parsed_allow": bench.CALLS_PER_BUCKET,
                "parsed_block": 0,
                "parse_error": 0,
                "inference_error": 0,
            },
        )
        self.assertEqual(
            runner.model.calls, bench.CALLS_PER_BUCKET + bench.WARMUP_CALLS
        )

    def test_output_slot_fails_closed_on_two_line_and_jailbreak(self) -> None:
        for output in (self.TWO_LINE_INPUT, self.JAILBREAK_RESPONSE):
            with self.subTest(output=output):
                runner = causal_runner(output)
                bucket = bench._measure_bucket(
                    runner, slot="output", language="en", characters=200
                )
                self.assertEqual(
                    bucket["parse_outcomes"]["parsed_allow"], 0
                )
                self.assertEqual(
                    bucket["parse_outcomes"]["parsed_block"], 0
                )
                self.assertEqual(
                    bucket["parse_outcomes"]["inference_error"],
                    bench.CALLS_PER_BUCKET,
                )
                self.assertEqual(bucket["errors"], bench.CALLS_PER_BUCKET)
                self.assertEqual(
                    runner.model.calls,
                    bench.CALLS_PER_BUCKET + bench.WARMUP_CALLS,
                )


class MeasurementReportTests(unittest.TestCase):
    """The report is evidence for a successful run; a failure writes none."""

    def _run_measurement(self, output: str, *, slot: str = "input"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        model_dir = root / "artifact"
        model_dir.mkdir()
        (model_dir / "model.safetensors").write_bytes(b"\x00" * 8)
        target = root / "report.json"
        factory = _RunnerFactory(output)
        with mock.patch.object(bench, "Runner", factory), mock.patch.object(
            bench, "thread_settings", return_value=[1]
        ), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            status = bench.measure(
                model_name="qwen3guard-gen",
                slot=slot,
                model_dir=str(model_dir),
                report_path=str(target),
                digest=None,
                cap=2,
                threshold=0.5,
            )
        return status, target, factory

    def test_two_line_input_measurement_writes_the_report(self) -> None:
        status, target, factory = self._run_measurement(
            "Safety: Safe\nCategories: None"
        )
        self.assertEqual(status, 0)
        self.assertTrue(target.exists())
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(bench.validate_report(report), [])
        self.assertEqual(report["totals"]["errors"], 0)
        self.assertEqual(report["candidate"]["slot"], "input")
        self.assertEqual(factory.calls, 1)

    def test_malformed_measurement_returns_failure_and_writes_no_report(self) -> None:
        status, target, factory = self._run_measurement(
            "Safety: Safe\nCategories: Violent"
        )
        self.assertEqual(status, 1)
        self.assertFalse(target.exists())
        self.assertEqual(factory.calls, 1)

    def test_output_slot_measurement_uses_the_response_lane(self) -> None:
        status, target, factory = self._run_measurement(
            "Safety: Safe\nCategories: None\nRefusal: No", slot="output"
        )
        self.assertEqual(status, 0)
        self.assertTrue(target.exists())
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(bench.validate_report(report), [])
        self.assertEqual(report["totals"]["errors"], 0)
        self.assertEqual(report["candidate"]["slot"], "output")
        self.assertEqual(factory.calls, 1)


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
