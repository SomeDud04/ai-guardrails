"""Deterministic tests for the local Qwen3Guard-Gen transport and its wiring.

No pretrained checkpoint, tokenizer or model is downloaded or executed here.
Every behavioural test drives explicit **inference doubles** (fake tokenizer,
model and backend) or a fake loader.  Those doubles prove control flow, token
accounting, structural validation, pooling, transport parity and fail-closed
handling only.  They are **not** evidence of real guard efficacy, latency or
hardware behaviour, and the benchmark measurement is a separate operator
activity.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from unittest import mock

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.gateway import Gateway, serialize_messages
from nasi_lemak.generation import (
    AUTH_NONE,
    ENV_AUTH,
    ENV_MODEL,
    ENV_URL,
    GenerationClient,
    GenerationConfig,
    RealGatewayAdapters,
)
from nasi_lemak.guard_api import Qwen3GuardOutputAdapter, parse_verdict as http_parse_verdict
from nasi_lemak.guard_errors import GuardError, GuardInputLimit
from nasi_lemak.guard_pool import (
    GuardInferencePool,
    default_inference_budget,
    resolve_inference_budget,
)
from nasi_lemak.qwen3_local import (
    DEFAULT_LONG_INPUT_TOKENS,
    MAX_LONG_INPUT_TOKENS,
    MIN_LONG_INPUT_TOKENS,
    Qwen3GuardLocal,
)
from nasi_lemak.qwen3guard import (
    GUARD_FRAMING,
    VERDICT_MAX_TOKENS,
    parse_verdict,
    parse_verdict_fields,
    verdict_blocks,
)
from nasi_lemak.scan_context import ScanContext
from nasi_lemak.server import (
    ENV_GUARD_BACKEND,
    ENV_QWEN3GUARD_INPUT_THRESHOLD,
    ENV_QWEN3GUARD_LONG_INPUT,
    ENV_QWEN3GUARD_MODEL_DIR,
    ENV_QWEN3GUARD_OUTPUT_THRESHOLD,
    ENV_QWEN3GUARD_THREADS,
    ENV_QWEN3GUARD_WORKERS,
    GUARD_BACKEND_LOCAL,
    GUARD_BACKEND_QWEN3GUARD,
    make_adapters_from_env,
)

EOS = 7
WINDOW = 32768
TEST_KEY = "qwen3-local-test-key"
AUTH = {"Authorization": "Bearer " + TEST_KEY}
UPSTREAM_MODEL = "upstream-model-1"

SAFE = "Safety: Safe\nCategories: None\nRefusal: No"
UNSAFE = "Safety: Unsafe\nCategories: PII\nRefusal: No"
CONTROVERSIAL = "Safety: Controversial\nCategories: Unethical Acts\nRefusal: Yes"
#: The artifact's official input-moderation shape: no Refusal line.
SAFE_INPUT = "Safety: Safe\nCategories: None"
UNSAFE_INPUT_JAILBREAK = "Safety: Unsafe\nCategories: Jailbreak"


class _ToyTokenizer:
    """One token per whitespace word; output tokens decode to exact verdict text.

    Input tokenisation deliberately rejects any special-token or truncation
    setting other than the shared contract's ``False``/``False``.  The chat
    template records every delivery so tests can assert the per-lane message
    shapes and ``add_generation_prompt=True``.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, bool, bool]] = []
        self.template_calls: list[
            tuple[list[dict[str, str]], bool, bool, str]
        ] = []
        self.template_failure: Exception | None = None
        self.eos_token_id: int | None = EOS
        self.pad_token_id: int | None = EOS
        self._next_id = 100
        self._vocab: dict[str, int] = {}
        self._reverse: dict[int, str] = {}
        self._outputs: dict[int, str] = {}
        self._next_output = 50000
        self.failure: Exception | None = None

    def _word_id(self, word: str) -> int:
        if word not in self._vocab:
            self._vocab[word] = self._next_id
            self._reverse[self._next_id] = word
            self._next_id += 1
        return self._vocab[word]

    def encode(self, text: str) -> list[int]:
        return [self._word_id(word) for word in text.split()]

    def output_ids(self, text: str) -> list[int]:
        identifier = self._next_output
        self._next_output += 1
        self._outputs[identifier] = text
        return [identifier]

    def apply_chat_template(
        self,
        conversation: list[dict[str, str]],
        tokenize: bool = False,
        add_generation_prompt: bool = True,
    ) -> str:
        rendered = "".join(
            f"<|im_start|>{message['role']}\n{message['content']}<|im_end|>\n"
            for message in conversation
        )
        if add_generation_prompt:
            rendered += "<|im_start|>assistant\n"
        self.template_calls.append(
            (
                [dict(message) for message in conversation],
                tokenize,
                add_generation_prompt,
                rendered,
            )
        )
        if self.template_failure is not None:
            raise self.template_failure
        return rendered

    def __call__(
        self, text: str, add_special_tokens: bool = True, truncation: bool = False
    ) -> Any:
        self.calls.append((text, add_special_tokens, truncation))
        if self.failure is not None:
            raise self.failure
        if add_special_tokens is not False or truncation is not False:
            raise AssertionError(
                "transport must tokenize with add_special_tokens=False/truncation=False"
            )
        return {"input_ids": self.encode(text)}

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


class _NoTemplateTokenizer:
    """A delegating tokenizer with no chat template: the fail-closed case."""

    def __init__(self, base: _ToyTokenizer) -> None:
        self._base = base
        self.eos_token_id = base.eos_token_id
        self.pad_token_id = base.pad_token_id

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._base(*args, **kwargs)

    def decode(self, *args: Any, **kwargs: Any) -> str:
        return self._base.decode(*args, **kwargs)


class _ToyBackend:
    def __init__(self) -> None:
        self.threads: list[int] = []
        self.tensor_calls = 0
        self.thread_failure: Exception | None = None

    def tensor(self, values: Any) -> Any:
        self.tensor_calls += 1
        return values

    def inference_mode(self) -> Any:
        return contextlib.nullcontext()

    def set_num_threads(self, value: int) -> None:
        if self.thread_failure is not None:
            raise self.thread_failure
        self.threads.append(value)


class _ToyModel:
    """Deterministic causal-generator double; it never reads real weights."""

    def __init__(
        self,
        tokenizer: _ToyTokenizer,
        *,
        output: str = SAFE,
        window: int = WINDOW,
        eos: int | None = EOS,
        terminate: bool = True,
        failure: Exception | None = None,
        delay: float = 0.0,
        architectures: Any = ("Qwen3ForCausalLM",),
        id2label: Any = None,
    ) -> None:
        self.tokenizer = tokenizer
        self.output = output
        self.terminate = terminate
        self.failure = failure
        self.delay = delay
        self.calls = 0
        self.active = 0
        self.max_active = 0
        self.device: str | None = None
        self._lock = threading.Lock()
        self.config = types.SimpleNamespace(
            max_position_embeddings=window,
            eos_token_id=eos,
            architectures=architectures,
            model_type="qwen3",
        )
        if id2label is not None:
            self.config.id2label = id2label

    def eval(self) -> "_ToyModel":
        return self

    def to(self, device: str) -> "_ToyModel":
        self.device = device
        return self

    def generate(self, **inputs: Any) -> Any:
        with self._lock:
            self.calls += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                time.sleep(self.delay)
            if self.failure is not None:
                raise self.failure
            prompt = list(inputs["input_ids"][0])
            new_ids = list(self.tokenizer.output_ids(self.output))
            if self.terminate:
                new_ids.append(EOS)
            return types.SimpleNamespace(sequences=[prompt + new_ids])
        finally:
            with self._lock:
                self.active -= 1


class _BrokenModel:
    """A loaded object that resembles a model but cannot generate."""

    def __init__(self) -> None:
        self.config = types.SimpleNamespace(
            max_position_embeddings=WINDOW,
            eos_token_id=EOS,
            architectures=["Qwen3ForCausalLM"],
        )

    def eval(self) -> "_BrokenModel":
        return self

    def to(self, device: str) -> "_BrokenModel":
        return self


class Qwen3ForCausalLM(_ToyModel):
    """Production-shaped causal double; it never reads real weights."""


class Qwen3ForSequenceClassification(_ToyModel):
    """Classifier-shaped runtime double that still exposes ``generate``."""


class LlamaForCausalLM(_ToyModel):
    """A causal class outside the supported Qwen3 runtime restriction."""


class LocalTransportTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self._artifact(self.root / "qwen3guard")

    def _artifact(
        self,
        path: Path,
        *,
        config: Any = None,
        extra_files: tuple[str, ...] = (),
        weights: bool = True,
    ) -> str:
        path.mkdir(parents=True, exist_ok=True)
        if config is None:
            config = {
                "model_type": "qwen3",
                "architectures": ["Qwen3ForCausalLM"],
                "max_position_embeddings": WINDOW,
            }
        (path / "config.json").write_text(json.dumps(config), encoding="utf-8")
        if weights:
            (path / "model.safetensors").write_bytes(b"")
        for name in extra_files:
            (path / name).write_text("x", encoding="utf-8")
        return str(path)

    def _guard(self, **kwargs: Any) -> Qwen3GuardLocal:
        tokenizer = kwargs.pop("tokenizer", None) or _ToyTokenizer()
        backend = kwargs.pop("backend", None) or _ToyBackend()
        model = kwargs.pop("model", None)
        if model is None:
            model = _ToyModel(tokenizer, **kwargs.pop("model_kwargs", {}))
        return Qwen3GuardLocal(
            self.directory,
            tokenizer=tokenizer,
            model=model,
            backend=backend,
            workers=kwargs.pop("workers", 1),
            threads=kwargs.pop("threads", 1),
            **kwargs,
        )

    def _http_guard(self, verdict: str) -> Qwen3GuardOutputAdapter:
        config = GenerationConfig(
            url="http://127.0.0.1:9/v1",
            model="qwen3guard-test",
            auth_mode=AUTH_NONE,
            allow_insecure_http=True,
        )
        client = GenerationClient(config)

        def generate(messages: list[dict[str, str]], max_tokens: int = 0) -> str:
            self.assertLessEqual(max_tokens, VERDICT_MAX_TOKENS)
            return verdict

        client.generate = generate  # type: ignore[method-assign]
        return Qwen3GuardOutputAdapter(client)


class VerdictLaneTests(LocalTransportTestCase):
    """One parser, two lanes: the artifact shapes and the input-only category."""

    def test_input_lane_accepts_two_line_and_three_line_verdicts(self) -> None:
        two_line = parse_verdict_fields(SAFE_INPUT, lane="input")
        self.assertEqual(two_line.safety, "Safe")
        self.assertEqual(two_line.categories, ())
        self.assertIsNone(two_line.refusal)
        self.assertTrue(parse_verdict(SAFE_INPUT, lane="input"))

        three_line = parse_verdict_fields(SAFE, lane="input")
        self.assertEqual(three_line.refusal, "No")
        self.assertEqual(
            parse_verdict_fields(UNSAFE, lane="input"),
            parse_verdict_fields(UNSAFE, lane="response"),
        )

    def test_response_lane_still_requires_all_three_lines(self) -> None:
        for call in (
            lambda: parse_verdict_fields(SAFE_INPUT, lane="response"),
            lambda: parse_verdict(SAFE_INPUT),
            lambda: http_parse_verdict(SAFE_INPUT),
            lambda: parse_verdict_fields(SAFE_INPUT, lane="system"),
        ):
            with self.subTest(call=call):
                with self.assertRaises(GuardError):
                    call()

    def test_jailbreak_is_input_only(self) -> None:
        verdict = parse_verdict_fields(UNSAFE_INPUT_JAILBREAK, lane="input")
        self.assertEqual(verdict.categories, ("Jailbreak",))
        self.assertTrue(verdict_blocks(verdict, 0.5))
        # The response lane must never refuse-scan the input-only label.
        strict = "Safety: Unsafe\nCategories: Jailbreak\nRefusal: No"
        with self.assertRaises(GuardError):
            parse_verdict_fields(strict, lane="response")
        with self.assertRaises(GuardError):
            http_parse_verdict(strict)

    def test_local_input_lane_uses_the_input_contract(self) -> None:
        allowing = self._guard(model_kwargs={"output": SAFE_INPUT})
        self.assertEqual(allowing.scan_attack("hello"), {"decision": "allow"})
        blocking = self._guard(model_kwargs={"output": UNSAFE_INPUT_JAILBREAK})
        self.assertEqual(blocking.scan_attack("hello"), {"decision": "block"})

    def test_local_output_lane_uses_the_response_contract(self) -> None:
        guard = self._guard(model_kwargs={"output": SAFE_INPUT})
        with self.assertRaises(GuardError):
            guard.scan_response([{"role": "user", "content": "hello"}], "reply")

    def test_historical_guard_api_names_resolve_to_the_shared_parser(self) -> None:
        self.assertIs(http_parse_verdict, parse_verdict)


class TransportParityTests(LocalTransportTestCase):
    def test_local_and_http_parse_the_same_verdict_to_the_same_decision(self) -> None:
        messages = [{"role": "user", "content": "hello"}]
        for verdict in (SAFE, UNSAFE, CONTROVERSIAL):
            with self.subTest(verdict=verdict.splitlines()[0]):
                local = self._guard(model_kwargs={"output": verdict})
                http = self._http_guard(verdict)
                self.assertEqual(
                    local.scan_response(messages, "reply"),
                    http.scan_response(messages, "reply"),
                )
                self.assertEqual(
                    local.scan_response(messages, "reply")["safe"],
                    parse_verdict(verdict),
                )
                self.assertEqual(
                    parse_verdict_fields(verdict).safe, parse_verdict(verdict)
                )

    def test_input_threshold_is_a_categorical_severity_floor(self) -> None:
        default = self._guard(model_kwargs={"output": SAFE})
        self.assertEqual(default.scan_attack("hello"), {"decision": "allow"})

        unsafe = self._guard(model_kwargs={"output": UNSAFE})
        self.assertEqual(unsafe.scan_attack("hello"), {"decision": "block"})

        controversial = self._guard(model_kwargs={"output": CONTROVERSIAL})
        self.assertEqual(controversial.scan_attack("hello"), {"decision": "block"})

        # At a zero floor even Safe blocks: the comparison is fail-closed.
        zero = self._guard(
            input_threshold=0.0, model_kwargs={"output": SAFE}
        )
        self.assertEqual(zero.scan_attack("hello"), {"decision": "block"})

    def test_a_threshold_above_the_categorical_ceiling_is_invalid(self) -> None:
        for value in (0.5001, 1.0, -0.1, float("nan"), True, "0.5"):
            with self.subTest(value=value):
                with self.assertRaises(GuardError):
                    Qwen3GuardLocal(
                        self.directory,
                        input_threshold=value,
                        tokenizer=_ToyTokenizer(),
                        model=_ToyModel(_ToyTokenizer()),
                        backend=_ToyBackend(),
                        workers=1,
                        threads=1,
                    )

    def test_output_threshold_controls_safe_verdict_independently(self) -> None:
        guard = self._guard(
            output_threshold=0.0, model_kwargs={"output": SAFE}
        )
        self.assertEqual(
            guard.scan_response([{"role": "user", "content": "hello"}], "reply"),
            {"safe": False},
        )


class TemplateDeliveryTests(LocalTransportTestCase):
    """The artifact's chat template is the one delivery for both lanes."""

    def test_input_lane_uses_system_and_user_with_generation_prompt(self) -> None:
        tokenizer = _ToyTokenizer()
        guard = self._guard(tokenizer=tokenizer)
        self.assertEqual(guard.scan_attack("user: hello"), {"decision": "allow"})
        self.assertEqual(len(tokenizer.template_calls), 1)
        messages, tokenize, add_generation_prompt, _ = tokenizer.template_calls[0]
        self.assertEqual(
            messages,
            [
                {"role": "system", "content": GUARD_FRAMING},
                {"role": "user", "content": "user: hello"},
            ],
        )
        self.assertFalse(tokenize)
        self.assertTrue(add_generation_prompt)

    def test_output_lane_appends_the_reply_as_an_assistant_turn(self) -> None:
        tokenizer = _ToyTokenizer()
        guard = self._guard(tokenizer=tokenizer)
        self.assertEqual(
            guard.scan_response([{"role": "user", "content": "hello"}], "reply"),
            {"safe": True},
        )
        self.assertEqual(len(tokenizer.template_calls), 1)
        messages, tokenize, add_generation_prompt, _ = tokenizer.template_calls[0]
        self.assertEqual(
            messages,
            [
                {"role": "system", "content": GUARD_FRAMING},
                {"role": "user", "content": "user: hello"},
                {"role": "assistant", "content": "reply"},
            ],
        )
        self.assertFalse(tokenize)
        self.assertTrue(add_generation_prompt)

    def test_payload_budget_is_checked_before_any_template_work(self) -> None:
        tokenizer = _ToyTokenizer()
        guard = self._guard(tokenizer=tokenizer)
        over = LongInputTests._payload(DEFAULT_LONG_INPUT_TOKENS)
        with self.assertRaises(GuardInputLimit):
            guard.scan_attack(over)
        self.assertEqual(tokenizer.template_calls, [])
        self.assertEqual(guard._model.calls, 0)

    def test_window_check_counts_the_template_delivered_text(self) -> None:
        tokenizer = _ToyTokenizer()
        guard = self._guard(tokenizer=tokenizer, model_kwargs={"window": 1024})
        payload = LongInputTests._payload(1000)
        payload_tokens = guard.count_tokens(payload)
        self.assertLessEqual(payload_tokens, guard._long_input)
        with self.assertRaises(GuardInputLimit):
            guard.scan_attack(payload)
        self.assertEqual(len(tokenizer.template_calls), 1)
        rendered = tokenizer.template_calls[0][3]
        self.assertGreater(
            len(tokenizer.encode(rendered)), guard._window_limit
        )
        self.assertEqual(guard._model.calls, 0)

    def test_missing_chat_template_fails_closed(self) -> None:
        base = _ToyTokenizer()
        guard = self._guard(
            tokenizer=_NoTemplateTokenizer(base), model=_ToyModel(base)
        )
        with self.assertRaises(GuardError):
            guard.scan_attack("hello")
        self.assertEqual(guard._model.calls, 0)

    def test_failing_chat_template_fails_closed(self) -> None:
        tokenizer = _ToyTokenizer()
        tokenizer.template_failure = RuntimeError("template boom")
        guard = self._guard(tokenizer=tokenizer)
        with self.assertRaises(GuardError):
            guard.scan_attack("hello")
        self.assertEqual(guard._model.calls, 0)


class FailClosedTests(LocalTransportTestCase):
    def test_missing_directory_fails_closed(self) -> None:
        with self.assertRaises(GuardError):
            Qwen3GuardLocal(
                str(self.root / "missing"),
                tokenizer=_ToyTokenizer(),
                model=_ToyModel(_ToyTokenizer()),
                backend=_ToyBackend(),
                workers=1,
                threads=1,
            )

    def test_unreadable_configuration_fails_closed(self) -> None:
        path = self.root / "unreadable"
        path.mkdir()
        (path / "config.json").mkdir()
        (path / "model.safetensors").write_bytes(b"")
        with self.assertRaises(GuardError):
            Qwen3GuardLocal(
                str(path),
                tokenizer=_ToyTokenizer(),
                model=_ToyModel(_ToyTokenizer()),
                backend=_ToyBackend(),
                workers=1,
                threads=1,
            )

    def test_load_failure_fails_closed(self) -> None:
        tokenizer = _ToyTokenizer()
        with mock.patch(
            "nasi_lemak.qwen3_local._load_causal_model",
            side_effect=GuardError("guard model could not be loaded"),
        ):
            with self.assertRaises(GuardError):
                Qwen3GuardLocal(
                    self.directory,
                    tokenizer=tokenizer,
                    backend=_ToyBackend(),
                    workers=1,
                    threads=1,
                )

    def test_artifact_with_remote_code_file_is_rejected_before_loading(self) -> None:
        path = self._artifact(
            self.root / "stream", extra_files=("modeling_qwen3_guard.py",)
        )
        with mock.patch(
            "nasi_lemak.qwen3_local._load_causal_model"
        ) as loader:
            with self.assertRaises(GuardError):
                Qwen3GuardLocal(
                    path,
                    tokenizer=_ToyTokenizer(),
                    model=_ToyModel(_ToyTokenizer()),
                    backend=_ToyBackend(),
                    workers=1,
                    threads=1,
                )
            loader.assert_not_called()

    def test_artifact_without_safetensors_is_rejected(self) -> None:
        path = Path(self._artifact(self.root / "pickle-only", weights=False))
        (path / "pytorch_model.bin").write_bytes(b"")
        with self.assertRaises(GuardError):
            Qwen3GuardLocal(
                str(path),
                tokenizer=_ToyTokenizer(),
                model=_ToyModel(_ToyTokenizer()),
                backend=_ToyBackend(),
                workers=1,
                threads=1,
            )

    def test_artifact_auto_map_and_classifier_architectures_are_rejected(self) -> None:
        cases = (
            {"model_type": "qwen3", "architectures": ["Qwen3ForCausalLM"], "auto_map": {}},
            {"model_type": "qwen3", "architectures": ["Qwen3ForSequenceClassification"]},
            {"model_type": "llama", "architectures": ["LlamaForCausalLM"]},
            {"model_type": "qwen3", "architectures": ["Qwen3ForCausalLM"], "weights": "bin"},
        )
        for index, config in enumerate(cases):
            with self.subTest(config=config):
                path = self.root / f"invalid-{index}"
                path.mkdir()
                if config.get("weights") == "bin":
                    config = dict(config)
                    config.pop("weights")
                    (path / "config.json").write_text(json.dumps(config), encoding="utf-8")
                    (path / "pytorch_model.bin").write_bytes(b"")
                else:
                    self._artifact(path, config=config)
                with self.assertRaises(GuardError):
                    Qwen3GuardLocal(
                        str(path),
                        tokenizer=_ToyTokenizer(),
                        model=_ToyModel(_ToyTokenizer()),
                        backend=_ToyBackend(),
                        workers=1,
                        threads=1,
                    )

    def test_structurally_invalid_loaded_models_fail_closed(self) -> None:
        tokenizer = _ToyTokenizer()

        broken = _BrokenModel()
        with self.assertRaises(GuardError):
            Qwen3GuardLocal(
                self.directory,
                tokenizer=tokenizer,
                model=broken,
                backend=_ToyBackend(),
                workers=1,
                threads=1,
            )

        classifier = _ToyModel(tokenizer, id2label={0: "LABEL_0", 1: "LABEL_1"})
        classifier.classifier = object()  # an actual head, not label metadata
        with self.assertRaises(GuardError):
            Qwen3GuardLocal(
                self.directory,
                tokenizer=tokenizer,
                model=classifier,
                backend=_ToyBackend(),
                workers=1,
                threads=1,
            )

        for window in (0, -1, True, None):
            with self.subTest(window=window):
                model = _ToyModel(tokenizer, window=window)  # type: ignore[arg-type]
                with self.assertRaises(GuardError):
                    Qwen3GuardLocal(
                        self.directory,
                        tokenizer=tokenizer,
                        model=model,
                        backend=_ToyBackend(),
                        workers=1,
                        threads=1,
                    )

    def test_missing_end_of_sequence_fails_closed(self) -> None:
        tokenizer = _ToyTokenizer()
        tokenizer.eos_token_id = None
        model = _ToyModel(tokenizer, eos=None)
        with self.assertRaises(GuardError):
            Qwen3GuardLocal(
                self.directory,
                tokenizer=tokenizer,
                model=model,
                backend=_ToyBackend(),
                workers=1,
                threads=1,
            )

    def test_unparseable_or_malformed_replies_never_allow(self) -> None:
        messages = [{"role": "user", "content": "hello"}]

        bad_verdict = self._guard(model_kwargs={"output": "looks fine to me"})
        with self.assertRaises(GuardError):
            bad_verdict.scan_attack("hello")
        with self.assertRaises(GuardError):
            bad_verdict.scan_response(messages, "reply")

        missing_eos = self._guard(model_kwargs={"output": SAFE, "terminate": False})
        with self.assertRaises(GuardError):
            missing_eos.scan_attack("hello")

        failed = self._guard(model_kwargs={"failure": RuntimeError("boom")})
        with self.assertRaises(GuardError):
            failed.scan_attack("hello")

    def test_invalid_tokenizer_or_scan_context_fails_closed(self) -> None:
        tokenizer = _ToyTokenizer()
        tokenizer.failure = RuntimeError("tokenizer boom")
        guard = self._guard(tokenizer=tokenizer)
        with self.assertRaises(GuardError):
            guard.scan_attack("hello")

        guard = self._guard()
        with self.assertRaises(GuardError):
            guard.scan_attack("hello", scan_context=object())

    def test_thread_budget_failure_fails_closed(self) -> None:
        backend = _ToyBackend()
        backend.thread_failure = RuntimeError("no threads")
        with self.assertRaises(GuardError):
            self._guard(backend=backend)

    def test_invalid_long_input_budget_fails_closed(self) -> None:
        for value in (0, 511, 32769, True, "8192", 8192.0):
            with self.subTest(value=value):
                with self.assertRaises(GuardError):
                    self._guard(long_input=value)


class ProductionLoaderTests(LocalTransportTestCase):
    """Exercise the production load path with a mocked causal loader.

    No pretrained weights, tokenizer files or network are used.  The mock
    returns a realistic model double, so the post-load runtime-structure checks
    run exactly as they do after a real ``_load_causal_model`` call.
    """

    def _production_guard(self, model: Any, tokenizer: Any) -> Qwen3GuardLocal:
        with mock.patch(
            "nasi_lemak.qwen3_local._load_causal_model",
            return_value=model,
        ):
            return Qwen3GuardLocal(
                self.directory,
                tokenizer=tokenizer,
                backend=_ToyBackend(),
                workers=1,
                threads=1,
            )

    def test_production_accepts_causal_class_with_generic_label_metadata(self) -> None:
        tokenizer = _ToyTokenizer()
        model = Qwen3ForCausalLM(
            tokenizer, id2label={0: "LABEL_0", 1: "LABEL_1"}
        )
        guard = self._production_guard(model, tokenizer)
        self.assertIs(guard._model, model)
        self.assertEqual(guard.scan_attack("hello"), {"decision": "allow"})

    def test_production_rejects_classifier_runtime_declaring_causal(self) -> None:
        tokenizer = _ToyTokenizer()
        model = Qwen3ForSequenceClassification(
            tokenizer,
            architectures=("Qwen3ForCausalLM",),
            id2label={0: "LABEL_0", 1: "LABEL_1"},
        )
        with mock.patch(
            "nasi_lemak.qwen3_local._load_causal_model",
            return_value=model,
        ) as loader:
            with self.assertRaises(GuardError):
                Qwen3GuardLocal(
                    self.directory,
                    tokenizer=tokenizer,
                    backend=_ToyBackend(),
                    workers=1,
                    threads=1,
                )
        loader.assert_called_once_with(self.directory)

    def test_production_rejects_an_unexpected_causal_runtime_class(self) -> None:
        tokenizer = _ToyTokenizer()
        model = LlamaForCausalLM(tokenizer)
        with mock.patch(
            "nasi_lemak.qwen3_local._load_causal_model",
            return_value=model,
        ):
            with self.assertRaises(GuardError):
                Qwen3GuardLocal(
                    self.directory,
                    tokenizer=tokenizer,
                    backend=_ToyBackend(),
                    workers=1,
                    threads=1,
                )

    def test_production_rejects_a_loaded_model_without_architecture(self) -> None:
        tokenizer = _ToyTokenizer()
        model = Qwen3ForCausalLM(tokenizer)
        model.config.architectures = None
        with mock.patch(
            "nasi_lemak.qwen3_local._load_causal_model",
            return_value=model,
        ):
            with self.assertRaises(GuardError):
                Qwen3GuardLocal(
                    self.directory,
                    tokenizer=tokenizer,
                    backend=_ToyBackend(),
                    workers=1,
                    threads=1,
                )

    def test_missing_or_malformed_artifact_architecture_fails_before_loading(
        self,
    ) -> None:
        cases = (
            {"model_type": "qwen3"},
            {"model_type": "qwen3", "architectures": None},
            {"model_type": "qwen3", "architectures": []},
            {"model_type": "qwen3", "architectures": "Qwen3ForCausalLM"},
            {"model_type": "qwen3", "architectures": [None]},
            {"model_type": "qwen3", "architectures": ["Qwen3ForSequenceClassification"]},
            {
                "model_type": "qwen3",
                "architectures": ["Qwen3ForCausalLM", "LlamaForSequenceClassification"],
            },
        )
        for index, config in enumerate(cases):
            with self.subTest(config=config):
                path = self._artifact(
                    self.root / f"bad-architecture-{index}", config=config
                )
                with mock.patch(
                    "nasi_lemak.qwen3_local._load_causal_model"
                ) as loader:
                    with self.assertRaises(GuardError):
                        Qwen3GuardLocal(
                            path,
                            tokenizer=_ToyTokenizer(),
                            backend=_ToyBackend(),
                            workers=1,
                            threads=1,
                        )
                    loader.assert_not_called()

    def test_both_remote_code_filenames_are_rejected_before_loading(self) -> None:
        for index, filename in enumerate(
            ("modeling_qwen3_guard.py", "configuration_qwen3.py")
        ):
            with self.subTest(filename=filename):
                path = self._artifact(
                    self.root / f"stream-{index}", extra_files=(filename,)
                )
                with mock.patch(
                    "nasi_lemak.qwen3_local._load_causal_model"
                ) as loader:
                    with self.assertRaises(GuardError):
                        Qwen3GuardLocal(
                            path,
                            tokenizer=_ToyTokenizer(),
                            backend=_ToyBackend(),
                            workers=1,
                            threads=1,
                        )
                    loader.assert_not_called()

    def test_injected_seam_accepts_generic_metadata_but_not_a_classifier(
        self,
    ) -> None:
        tokenizer = _ToyTokenizer()
        accepted = _ToyModel(tokenizer, id2label={0: "LABEL_0", 1: "LABEL_1"})
        guard = self._guard(model=accepted, tokenizer=tokenizer)
        self.assertIs(guard._model, accepted)

        rejected = _ToyModel(tokenizer, id2label={0: "LABEL_0", 1: "LABEL_1"})
        rejected.classifier = object()
        with self.assertRaises(GuardError):
            self._guard(model=rejected, tokenizer=tokenizer)


class PoolAndBudgetTests(LocalTransportTestCase):
    def test_derived_and_explicit_budgets(self) -> None:
        self.assertEqual(default_inference_budget(4), (2, 2))
        self.assertEqual(default_inference_budget(1), (1, 1))
        self.assertEqual(default_inference_budget(16), (4, 2))
        self.assertEqual(resolve_inference_budget(None, None, cpu_count=4), (2, 2))
        self.assertEqual(resolve_inference_budget(2, 2, cpu_count=4), (2, 2))
        for workers, threads in ((0, 1), (9, 1), (1, 0), (1, 9), (3, 2)):
            with self.subTest(workers=workers, threads=threads):
                with self.assertRaises(GuardError):
                    resolve_inference_budget(workers, threads, cpu_count=4)

    def test_pool_bounds_and_applies_the_thread_count(self) -> None:
        backend = _ToyBackend()
        guard = self._guard(workers=2, threads=1, backend=backend)
        self.assertEqual(guard.workers, 2)
        self.assertEqual(guard.threads, 1)
        self.assertEqual(backend.threads, [1])
        self.assertEqual(GuardInferencePool(2).workers, 2)

    def test_each_request_reaches_the_model_exactly_once(self) -> None:
        guard = self._guard()
        model = guard._model
        for _ in range(3):
            self.assertEqual(guard.scan_attack("hello"), {"decision": "allow"})
        self.assertEqual(model.calls, 3)

        failing = self._guard(model_kwargs={"failure": RuntimeError("boom")})
        with self.assertRaises(GuardError):
            failing.scan_attack("hello")
        self.assertEqual(failing._model.calls, 1)
        with self.assertRaises(GuardError):
            failing.scan_attack("hello")
        self.assertEqual(failing._model.calls, 2)

    def test_concurrent_scans_are_bounded_by_the_worker_count(self) -> None:
        cpu = os.cpu_count() or 1
        workers = 2 if cpu >= 2 else 1
        guard = self._guard(
            workers=workers,
            threads=1,
            model_kwargs={"delay": 0.05},
        )
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: guard.scan_attack("hello"), range(6)))
        self.assertEqual(results, [{"decision": "allow"}] * 6)
        self.assertEqual(guard._model.calls, 6)
        self.assertLessEqual(guard._model.max_active, workers)

    def test_expired_deadline_and_cancellation_never_run_the_model(self) -> None:
        guard = self._guard()
        expired = ScanContext(deadline=time.monotonic() - 1.0)
        with self.assertRaises(GuardError):
            guard.scan_attack("hello", scan_context=expired)
        self.assertEqual(guard._model.calls, 0)

        event = threading.Event()
        event.set()
        cancelled = ScanContext(cancel_event=event)
        with self.assertRaises(GuardError):
            guard.scan_attack("hello", scan_context=cancelled)
        self.assertEqual(guard._model.calls, 0)


class LongInputTests(LocalTransportTestCase):
    @staticmethod
    def _payload(words: int) -> str:
        return serialize_messages(
            [{"role": "user", "content": " ".join(["word"] * words)}]
        )

    def test_default_budget_is_a_payload_budget_and_is_deterministic(self) -> None:
        tokenizer = _ToyTokenizer()
        guard = self._guard(tokenizer=tokenizer)
        at_default = self._payload(DEFAULT_LONG_INPUT_TOKENS - 1)
        self.assertEqual(guard.count_tokens(at_default), DEFAULT_LONG_INPUT_TOKENS)
        self.assertEqual(guard.count_tokens(at_default), DEFAULT_LONG_INPUT_TOKENS)
        self.assertEqual(guard.scan_attack(at_default), {"decision": "allow"})
        self.assertEqual(guard.scan_attack(at_default), {"decision": "allow"})
        for _, specials, truncation in tokenizer.calls:
            self.assertFalse(specials)
            self.assertFalse(truncation)

    def test_over_budget_input_fails_closed_without_truncation(self) -> None:
        guard = self._guard()
        over = self._payload(DEFAULT_LONG_INPUT_TOKENS)
        with self.assertRaises(GuardInputLimit):
            guard.scan_attack(over)
        self.assertEqual(guard._model.calls, 0)
        for text, specials, truncation in guard._tokenizer.calls:
            self.assertIn(text, (over,))
            self.assertFalse(specials)
            self.assertFalse(truncation)

    def test_at_the_maximum_ceiling_the_longest_inputs_are_unscreenable(self) -> None:
        framing_words = len(GUARD_FRAMING.split())
        # Payload is under the MAX budget, but payload + framing + 128-token
        # verdict reserve exceeds the 32768-position window by one token.
        words = (WINDOW - VERDICT_MAX_TOKENS) - framing_words
        at_ceiling = self._payload(words)
        guard = self._guard(long_input=MAX_LONG_INPUT_TOKENS)
        self.assertLessEqual(guard.count_tokens(at_ceiling), MAX_LONG_INPUT_TOKENS)
        with self.assertRaises(GuardInputLimit):
            guard.scan_attack(at_ceiling)
        self.assertEqual(guard._model.calls, 0)

        short = self._payload(8)
        self.assertEqual(guard.scan_attack(short), {"decision": "allow"})

    def test_framed_prompt_beyond_a_smaller_window_fails_closed(self) -> None:
        guard = self._guard(model_kwargs={"window": 1024})
        with self.assertRaises(GuardInputLimit):
            guard.scan_attack(self._payload(1000))
        self.assertEqual(guard._model.calls, 0)

    def test_budget_bounds_are_the_shared_contract(self) -> None:
        self.assertEqual(MIN_LONG_INPUT_TOKENS, 512)
        self.assertEqual(DEFAULT_LONG_INPUT_TOKENS, 8192)
        self.assertEqual(MAX_LONG_INPUT_TOKENS, 32768)


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[list[dict[str, str]], int]] = []

    def generate(self, messages: list[dict[str, str]], max_tokens: int) -> str:
        self.calls.append(([dict(message) for message in messages], max_tokens))
        return "upstream answer"


class _FakeGuard:
    supports_scan_context = True

    def __init__(self) -> None:
        self.attack_calls = 0
        self.response_calls = 0
        self.block = False

    def count_tokens(self, serialized: str) -> int:
        return max(1, len(serialized.split()))

    def scan_attack(self, text: str, *, scan_context: Any = None) -> dict[str, str]:
        self.attack_calls += 1
        return {"decision": "block" if self.block else "allow"}

    def scan_response(
        self, messages: list[dict[str, str]], output: str
    ) -> dict[str, bool]:
        self.response_calls += 1
        return {"safe": True}


class _ClientLoader:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.configs: list[Any] = []

    def __call__(self, config: Any) -> Any:
        self.configs.append(config)
        return self.result


class _GuardLoader:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, directory: str, **kwargs: Any) -> Any:
        self.calls.append((directory, dict(kwargs)))
        return self.result


class _MustNotLoad:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self.calls += 1
        raise AssertionError("loader must not run for invalid configuration")


class WiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / "qwen3guard"
        self.directory.mkdir()

    def _env(self, **overrides: str) -> dict[str, str]:
        env = {
            ENV_URL: "http://127.0.0.1:9/v1",
            ENV_MODEL: UPSTREAM_MODEL,
            ENV_AUTH: AUTH_NONE,
            ENV_GUARD_BACKEND: GUARD_BACKEND_QWEN3GUARD,
            ENV_QWEN3GUARD_MODEL_DIR: str(self.directory),
        }
        env.update(overrides)
        return env

    def test_local_backend_is_chosen_only_when_explicitly_selected(self) -> None:
        guard = _FakeGuard()
        client = _FakeClient()
        loader = _GuardLoader(guard)
        client_loader = _ClientLoader(client)

        # Explicit selection wires one guard into all three adapter slots.
        adapters = make_adapters_from_env(
            self._env(),
            qwen3guard_loader=loader,
            client_loader=client_loader,
        )
        self.assertIsInstance(adapters, RealGatewayAdapters)
        self.assertIs(adapters.tokenizer, guard)
        self.assertIs(adapters.attack_guard, guard)
        self.assertIs(adapters.output_guard, guard)
        self.assertEqual(len(loader.calls), 1)
        self.assertEqual(loader.calls[0][0], str(self.directory))

        # Without the explicit selector no Qwen3Guard loader is even consulted.
        meta = self.root / "meta"
        meta.mkdir()
        env = self._env(
            **{
                ENV_GUARD_BACKEND: GUARD_BACKEND_LOCAL,
                "NASI_LEMAK_PROMPT_GUARD_MODEL_DIR": str(meta),
                "NASI_LEMAK_LLAMA_GUARD_MODEL_DIR": str(meta),
                "NASI_LEMAK_PROMPT_GUARD_THRESHOLD": "0.5",
                "NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT": "2048",
            }
        )
        prompt_loader = _GuardLoader(_FakeGuard())
        llama_loader = _GuardLoader(_FakeGuard())
        adapters = make_adapters_from_env(
            env,
            prompt_guard_loader=prompt_loader,
            llama_guard_loader=llama_loader,
            qwen3guard_loader=loader,
            client_loader=client_loader,
        )
        self.assertIsInstance(adapters, RealGatewayAdapters)
        self.assertEqual(len(loader.calls), 1)
        self.assertEqual(len(prompt_loader.calls), 1)
        self.assertEqual(len(llama_loader.calls), 1)

    def test_no_directory_url_threshold_or_budget_is_inferred_from_another_value(self) -> None:
        others = {
            "NASI_LEMAK_PROMPT_GUARD_MODEL_DIR": str(self.directory),
            "NASI_LEMAK_LLAMA_GUARD_MODEL_DIR": str(self.directory),
            ENV_QWEN3GUARD_MODEL_DIR: "",
        }
        loader = _MustNotLoad()
        client_loader = _ClientLoader(_FakeClient())
        env = self._env(**others)
        self.assertIsNone(
            make_adapters_from_env(
                env, qwen3guard_loader=loader, client_loader=client_loader
            )
        )
        self.assertEqual(loader.calls, 0)
        self.assertEqual(client_loader.configs, [])

        missing = dict(self._env())
        missing.pop(ENV_QWEN3GUARD_MODEL_DIR)
        self.assertIsNone(
            make_adapters_from_env(
                missing, qwen3guard_loader=loader, client_loader=client_loader
            )
        )
        self.assertEqual(loader.calls, 0)

        no_url = dict(self._env())
        no_url.pop(ENV_URL)
        self.assertIsNone(
            make_adapters_from_env(
                no_url, qwen3guard_loader=loader, client_loader=client_loader
            )
        )
        self.assertEqual(loader.calls, 0)

        no_model = dict(self._env())
        no_model.pop(ENV_MODEL)
        self.assertIsNone(
            make_adapters_from_env(
                no_model, qwen3guard_loader=loader, client_loader=client_loader
            )
        )
        self.assertEqual(loader.calls, 0)

    def test_every_invalid_setting_produces_no_adapter_and_no_loader_call(self) -> None:
        loader = _MustNotLoad()
        client_loader = _MustNotLoad()
        cases: list[dict[str, str]] = []
        for name, value in (
            (ENV_QWEN3GUARD_INPUT_THRESHOLD, "0.5001"),
            (ENV_QWEN3GUARD_INPUT_THRESHOLD, "1.0"),
            (ENV_QWEN3GUARD_INPUT_THRESHOLD, "nan"),
            (ENV_QWEN3GUARD_INPUT_THRESHOLD, "-0.1"),
            (ENV_QWEN3GUARD_INPUT_THRESHOLD, "abc"),
            (ENV_QWEN3GUARD_INPUT_THRESHOLD, ""),
            (ENV_QWEN3GUARD_OUTPUT_THRESHOLD, "0.6"),
            (ENV_QWEN3GUARD_WORKERS, "0"),
            (ENV_QWEN3GUARD_WORKERS, "9"),
            (ENV_QWEN3GUARD_WORKERS, "abc"),
            (ENV_QWEN3GUARD_THREADS, "0"),
            (ENV_QWEN3GUARD_THREADS, "9"),
            (ENV_QWEN3GUARD_THREADS, "abc"),
            (ENV_QWEN3GUARD_LONG_INPUT, "511"),
            (ENV_QWEN3GUARD_LONG_INPUT, "32769"),
            (ENV_QWEN3GUARD_LONG_INPUT, "abc"),
        ):
            cases.append(self._env(**{name: value}))
        missing = self._env()
        missing.pop(ENV_QWEN3GUARD_MODEL_DIR)
        cases.append(missing)

        for env in cases:
            with self.subTest(env={k: v for k, v in env.items() if k.startswith("NASI_LEMAK_")}):
                self.assertIsNone(
                    make_adapters_from_env(
                        env,
                        qwen3guard_loader=loader,
                        client_loader=client_loader,
                    )
                )
        self.assertEqual(loader.calls, 0)
        self.assertEqual(client_loader.calls, 0)

        with mock.patch("nasi_lemak.guard_pool.os.cpu_count", return_value=4):
            env = self._env(
                **{ENV_QWEN3GUARD_WORKERS: "4", ENV_QWEN3GUARD_THREADS: "2"}
            )
            self.assertIsNone(
                make_adapters_from_env(
                    env, qwen3guard_loader=loader, client_loader=client_loader
                )
            )
        self.assertEqual(loader.calls, 0)

    def test_explicit_values_and_derived_defaults_reach_the_loader(self) -> None:
        guard = _FakeGuard()
        loader = _GuardLoader(guard)
        client_loader = _ClientLoader(_FakeClient())
        with mock.patch("nasi_lemak.guard_pool.os.cpu_count", return_value=4):
            self.assertIsNotNone(
                make_adapters_from_env(
                    self._env(),
                    qwen3guard_loader=loader,
                    client_loader=client_loader,
                )
            )
        self.assertEqual(
            loader.calls[0][1],
            {
                "input_threshold": 0.5,
                "output_threshold": 0.5,
                "workers": 2,
                "threads": 2,
                "long_input": DEFAULT_LONG_INPUT_TOKENS,
            },
        )

        explicit = self._env(
            **{
                ENV_QWEN3GUARD_INPUT_THRESHOLD: "0.25",
                ENV_QWEN3GUARD_OUTPUT_THRESHOLD: "0.4",
                ENV_QWEN3GUARD_WORKERS: "1",
                ENV_QWEN3GUARD_THREADS: "1",
                ENV_QWEN3GUARD_LONG_INPUT: "512",
            }
        )
        self.assertIsNotNone(
            make_adapters_from_env(
                explicit,
                qwen3guard_loader=loader,
                client_loader=client_loader,
            )
        )
        self.assertEqual(
            loader.calls[1][1],
            {
                "input_threshold": 0.25,
                "output_threshold": 0.4,
                "workers": 1,
                "threads": 1,
                "long_input": 512,
            },
        )


class _PipelineClient:
    def __init__(self) -> None:
        self.calls = 0

    def generate(self, messages: list[dict[str, str]], max_tokens: int) -> str:
        self.calls += 1
        return "synthetic answer"


class PipelineIntegrationTests(LocalTransportTestCase):
    def _gateway(self, guard: Qwen3GuardLocal, client: Any) -> Gateway:
        return Gateway(
            app_key=TEST_KEY,
            audit_store=SqliteAuditStore(self.root / "audit.sqlite3"),
            adapters=RealGatewayAdapters(
                client,
                tokenizer=guard,
                attack_guard=guard,
                output_guard=guard,
            ),
        )

    def _request(self) -> dict[str, Any]:
        return {
            "model": "pilot-local",
            "messages": [{"role": "user", "content": "hello there"}],
        }

    def test_short_input_pipeline_allows_with_the_local_guard(self) -> None:
        guard = self._guard()
        client = _PipelineClient()
        gateway = self._gateway(guard, client)
        status, body = gateway.handle(
            "POST", "/v1/chat/completions", AUTH, self._request()
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(body["choices"][0]["message"]["content"], "synthetic answer")
        self.assertEqual(client.calls, 1)
        self.assertEqual(
            [event["event_type"] for event in gateway.audit_events()],
            ["request_started", "request_completed"],
        )

    def test_unsafe_local_verdict_blocks_before_generation(self) -> None:
        guard = self._guard(model_kwargs={"output": UNSAFE})
        client = _PipelineClient()
        gateway = self._gateway(guard, client)
        status, body = gateway.handle(
            "POST", "/v1/chat/completions", AUTH, self._request()
        )
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        self.assertEqual(client.calls, 0)
        self.assertNotIn("choices", body)


if __name__ == "__main__":
    unittest.main()
