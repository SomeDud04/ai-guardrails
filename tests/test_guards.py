"""Deterministic tests for the local guard adapters (``nasi_lemak.guards``).

No pretrained checkpoint is downloaded or executed in this workspace. Every
behavioural test drives the documented injection seam with explicit **inference
doubles** (fake tokenizer/model/backend). Those doubles prove control flow,
token-boundary accounting, verdict parsing, local-only loader flags and
fail-closed handling only. They are **not** evidence of real guard efficacy,
latency or hardware, and the real Transformers path has not been run here.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from nasi_lemak.guards import GuardError, LlamaGuard3, PromptGuard2, _load_causal_model

EOS = 3
_UNSET = object()


class _NullCtx:
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _TensorStats:
    """Call counters shared by every tensor-like double derived in one test."""

    def __init__(self):
        self.detach = 0
        self.cpu = 0
        self.tolist = 0


class FakeTensor:
    """Tensor-like double faithful to the real torch method chain.

    ``detach()`` and ``cpu()`` each return *another* tensor-like object that
    also has ``detach``/``cpu``/``tolist``, exactly like ``torch.Tensor``. This
    is what catches a conversion loop that keeps detaching and never reaches
    ``tolist()``.
    """

    def __init__(self, values, stats=None):
        self._values = values
        self._stats = stats if stats is not None else _TensorStats()

    @property
    def stats(self):
        return self._stats

    def detach(self):
        self._stats.detach += 1
        return FakeTensor(self._values, self._stats)

    def cpu(self):
        self._stats.cpu += 1
        return FakeTensor(self._values, self._stats)

    def tolist(self):
        self._stats.tolist += 1
        value = self._values
        return list(value) if isinstance(value, (list, tuple)) else value


class FakeBackend:

    """Minimal torch-like double: tensor conversion and an inference context."""

    def __init__(self):
        self.tensor_calls = []
        self.inference_entries = 0

    def tensor(self, values):
        self.tensor_calls.append(values)
        return values

    def inference_mode(self):
        self.inference_entries += 1
        return _NullCtx()


class FakePromptTokenizer:
    """One token per whitespace word plus two special tokens."""

    def __init__(self):
        self.calls = []

    def __call__(self, text, add_special_tokens=True, truncation=False):
        if add_special_tokens is not True or truncation is not False:
            raise AssertionError("tokenizer must use add_special_tokens=True/truncation=False")
        self.calls.append(text)
        return {"input_ids": [1] + [100 + index for index, _ in enumerate(text.split())] + [2]}


class SilentTokenizer:
    def __call__(self, text, add_special_tokens=True, truncation=False):
        return {"input_ids": [1, len(text) % 5 + 3, 2]}


class BadBatchTokenizer:
    def __call__(self, text, add_special_tokens=True, truncation=False):
        return {"input_ids": [[1, 2], [3, 4]]}


class FakeClassifier:
    """Sequence-classification double; records inputs and concurrency."""

    def __init__(self, *, labels=_UNSET, logits=_UNSET, logits_fn=None, error=None, delay=0.0):
        self.config = types.SimpleNamespace(
            id2label={0: "BENIGN", 1: "MALICIOUS"} if labels is _UNSET else labels
        )
        self.logits = [1.0, -1.0] if logits is _UNSET else logits
        self.logits_fn = logits_fn
        self.error = error
        self.delay = delay
        self.calls = []
        self.eval_called = False
        self.device = None
        self._lock = threading.Lock()
        self._active = 0
        self.max_active = 0

    def eval(self):
        self.eval_called = True
        return self

    def to(self, device):
        self.device = device
        return self

    def __call__(self, **kwargs):
        with self._lock:
            self._active += 1
            self.max_active = max(self.max_active, self._active)
        try:
            if self.delay:
                time.sleep(self.delay)
            self.calls.append(kwargs)
            if self.error is not None:
                raise self.error
            scores = self.logits_fn(kwargs) if self.logits_fn is not None else self.logits
            return types.SimpleNamespace(logits=scores)
        finally:
            with self._lock:
                self._active -= 1


class FakeGuardTokenizer:
    def __init__(self, *, template_len=None, verdict="safe", eos=EOS, verdict_fn=None, decode_error=None):
        self.eos_token_id = eos
        self.template_len = template_len
        self.verdict = verdict
        self.verdict_fn = verdict_fn
        self.decode_error = decode_error
        self.conversations = []
        self.decodes = []
        self.generation_prompts = []

    def apply_chat_template(self, conversation, tokenize=True, add_generation_prompt=False):
        if tokenize is not True:
            raise AssertionError("adapter must tokenize the chat template")
        if add_generation_prompt is not True:
            raise AssertionError("adapter must set add_generation_prompt=True")
        self.conversations.append(conversation)
        self.generation_prompts.append(add_generation_prompt)
        if self.template_len is not None:
            return [9] * self.template_len
        text = "".join(message["content"] for message in conversation)
        return [9] + [30 + (ord(char) % 40) for char in text] + [self.eos_token_id]

    def decode(self, ids, skip_special_tokens=True):
        self.decodes.append((list(ids), skip_special_tokens))
        if self.decode_error is not None:
            raise self.decode_error
        if self.verdict_fn is not None:
            return self.verdict_fn(list(ids))
        return self.verdict


class FakeCausalModel:
    def __init__(
        self,
        *,
        new_tokens=None,
        mpe=4096,
        eos=EOS,
        error=None,
        delay=0.0,
        generate_fn=None,
        generation_config=_UNSET,
        config_eos=_UNSET,
    ):
        self.config = types.SimpleNamespace(max_position_embeddings=mpe)
        if config_eos is not _UNSET:
            self.config.eos_token_id = config_eos
        if generation_config is not _UNSET:
            self.generation_config = generation_config
        self.new_tokens = [10, 11, eos] if new_tokens is None else new_tokens
        self.eos = eos
        self.error = error
        self.delay = delay
        self.generate_fn = generate_fn
        self.calls = []
        self.eval_called = False
        self.device = None
        self._lock = threading.Lock()
        self._active = 0
        self.max_active = 0

    def eval(self):
        self.eval_called = True
        return self

    def to(self, device):
        self.device = device
        return self

    def generate(self, input_ids=None, **kwargs):
        with self._lock:
            self._active += 1
            self.max_active = max(self.max_active, self._active)
        try:
            if self.delay:
                time.sleep(self.delay)
            self.calls.append({"input_ids": input_ids, **kwargs})
            if self.error is not None:
                raise self.error
            if self.generate_fn is not None:
                return self.generate_fn(input_ids, kwargs)
            prompt = input_ids[0] if input_ids and isinstance(input_ids[0], list) else input_ids
            return [list(prompt) + list(self.new_tokens)]
        finally:
            with self._lock:
                self._active -= 1


class GuardTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.model_dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def prompt_adapter(self, *, tokenizer=None, model=None, backend=None, threshold=None):
        tokenizer = tokenizer or FakePromptTokenizer()
        model = model or FakeClassifier()
        backend = backend or FakeBackend()
        kwargs = {} if threshold is None else {"threshold": threshold}
        adapter = PromptGuard2(self.model_dir, tokenizer=tokenizer, model=model, backend=backend, **kwargs)
        return adapter, tokenizer, model, backend

    def llama_adapter(self, *, context_limit=128, tokenizer=None, model=None, backend=None):
        tokenizer = tokenizer or FakeGuardTokenizer()
        model = model or FakeCausalModel()
        backend = backend or FakeBackend()
        adapter = LlamaGuard3(
            self.model_dir, context_limit=context_limit, tokenizer=tokenizer, model=model, backend=backend
        )
        return adapter, tokenizer, model, backend


class PromptGuard2Tests(GuardTestBase):
    def test_count_tokens_uses_same_tokenizer_and_keeps_special_tokens(self):
        adapter, tokenizer, _, _ = self.prompt_adapter()
        self.assertEqual(adapter.count_tokens("one two three"), 5)
        self.assertEqual(tokenizer.calls[-1], "one two three")
        result = adapter.scan_attack("one two three")
        self.assertEqual(set(result), {"decision"})
        self.assertEqual(len(tokenizer.calls), 2)
        with self.assertRaises(GuardError):
            adapter.count_tokens(123)

    def test_512_token_boundary_includes_specials_and_does_not_truncate(self):
        adapter, _, model, _ = self.prompt_adapter()
        self.assertEqual(adapter.count_tokens("w " * 510), 512)
        self.assertEqual(adapter.scan_attack("w " * 510)["decision"], "allow")
        self.assertEqual(len(model.calls), 1)
        self.assertEqual(adapter.count_tokens("w " * 511), 513)
        self.assertEqual(adapter.scan_attack("w " * 511)["decision"], "block")
        self.assertEqual(len(model.calls), 1, "over-limit input must not reach the model")

    def test_tensor_like_logits_are_converted_with_one_detach_cpu_tolist_pass(self):
        tensor = FakeTensor([-1.0, 1.0])
        model = FakeClassifier(logits=tensor)
        adapter, _, _, _ = self.prompt_adapter(model=model)
        self.assertEqual(adapter.scan_attack("x")["decision"], "block")
        self.assertEqual(tensor.stats.detach, 1)
        self.assertEqual(tensor.stats.cpu, 1)
        self.assertEqual(tensor.stats.tolist, 1)

    def test_tensor_like_token_ids_are_converted_with_one_detach_cpu_tolist_pass(self):
        class TensorTokenizer:
            def __init__(self, identifiers):
                self.identifiers = identifiers
                self.stats = _TensorStats()

            def __call__(self, text, add_special_tokens=True, truncation=False):
                return {"input_ids": FakeTensor(self.identifiers, self.stats)}

        tokenizer = TensorTokenizer([1, 103, 2])
        adapter, _, _, _ = self.prompt_adapter(tokenizer=tokenizer)
        self.assertEqual(adapter.count_tokens("x"), 3)
        self.assertEqual((tokenizer.stats.detach, tokenizer.stats.cpu, tokenizer.stats.tolist), (1, 1, 1))
        self.assertEqual(adapter.scan_attack("x")["decision"], "allow")
        self.assertEqual((tokenizer.stats.detach, tokenizer.stats.cpu, tokenizer.stats.tolist), (2, 2, 2))

    def test_decision_reflects_threshold_on_finite_softmax(self):
        model = FakeClassifier(logits=[0.0, 0.0])
        default, _, _, _ = self.prompt_adapter(model=model)
        self.assertEqual(default.scan_attack("x")["decision"], "block")  # 0.5 >= 0.5
        stricter, _, _, _ = self.prompt_adapter(model=model, threshold=0.5000001)
        self.assertEqual(stricter.scan_attack("x")["decision"], "allow")
        never, _, _, _ = self.prompt_adapter(model=model, threshold=1.0)
        self.assertEqual(never.scan_attack("x")["decision"], "allow")
        always, _, _, _ = self.prompt_adapter(model=model, threshold=0.0)
        self.assertEqual(always.scan_attack("x")["decision"], "block")

    def test_label_mapping_is_normalized_and_reversed(self):
        reversed_model = FakeClassifier(labels={0: "malicious", 1: "  BENIGN "}, logits=[1.0, -1.0])
        adapter, _, _, _ = self.prompt_adapter(model=reversed_model)
        self.assertEqual(adapter.scan_attack("x")["decision"], "block")
        benign_model = FakeClassifier(labels={0: "Benign", 1: "Malicious"}, logits=[1.0, -1.0])
        adapter, _, _, _ = self.prompt_adapter(model=benign_model)
        self.assertEqual(adapter.scan_attack("x")["decision"], "allow")

    def test_invalid_label_mappings_fail_closed(self):
        invalid = [
            {0: "LABEL_0", 1: "LABEL_1"},
            {0: "BENIGN", 1: "BENIGN"},
            {0: "MALICIOUS"},
            {0: "BENIGN", 1: "MALICIOUS", 2: "EXTRA"},
            {0: "benign", 2: "malicious"},
            {0: 1, 1: "malicious"},
            {},
            "not-a-mapping",
            None,
        ]
        for labels in invalid:
            with self.subTest(labels=labels):
                with self.assertRaises(GuardError):
                    PromptGuard2(
                        self.model_dir,
                        tokenizer=FakePromptTokenizer(),
                        model=FakeClassifier(labels=labels),
                        backend=FakeBackend(),
                    )
        model = FakeClassifier()
        model.config = types.SimpleNamespace()
        with self.assertRaises(GuardError):
            PromptGuard2(self.model_dir, tokenizer=FakePromptTokenizer(), model=model, backend=FakeBackend())

    def test_invalid_thresholds_fail_closed(self):
        for value in [float("nan"), float("inf"), float("-inf"), -0.1, 1.1, True, "0.5", None]:
            with self.subTest(value=value):
                with self.assertRaises(GuardError):
                    PromptGuard2(
                        self.model_dir,
                        threshold=value,
                        tokenizer=FakePromptTokenizer(),
                        model=FakeClassifier(),
                        backend=FakeBackend(),
                    )

    def test_malformed_or_nonfinite_scores_fail_closed(self):
        cases = [
            [float("nan"), 1.0],
            [float("inf"), 0.0],
            [0.0],
            [0.0, 1.0, 2.0],
            [[0.0, 1.0], [0.0, 1.0]],
            "not-logits",
            [None, 1.0],
            [True, False],
            None,
        ]
        for scores in cases:
            with self.subTest(scores=scores):
                model = FakeClassifier(logits=scores)
                adapter, _, _, _ = self.prompt_adapter(model=model)
                with self.assertRaises(GuardError):
                    adapter.scan_attack("hello")

    def test_inference_and_tokenization_failures_are_generic_without_leaks(self):
        secret = "SECRET-PROMPT-77"
        model = FakeClassifier(error=RuntimeError("leak " + secret))
        adapter, _, _, _ = self.prompt_adapter(model=model)
        with self.assertRaises(GuardError) as ctx:
            adapter.scan_attack(secret)
        message = str(ctx.exception)
        self.assertNotIn(secret, message)
        self.assertNotIn("RuntimeError", message)
        adapter, _, _, _ = self.prompt_adapter(tokenizer=BadBatchTokenizer())
        with self.assertRaises(GuardError) as ctx:
            adapter.scan_attack("hello")
        self.assertNotIn("hello", str(ctx.exception))

    def test_model_prepared_on_cpu_and_ran_under_inference_mode(self):
        adapter, _, model, backend = self.prompt_adapter()
        adapter.scan_attack("hello")
        self.assertTrue(model.eval_called)
        self.assertEqual(model.device, "cpu")
        self.assertGreaterEqual(backend.inference_entries, 1)
        inputs = model.calls[-1]
        self.assertEqual(inputs["attention_mask"], [[1, 1, 1]])

    def test_prompt_is_not_retained_on_the_adapter(self):
        secret = "SECRET-CONTEXT-abc"
        adapter, _, _, _ = self.prompt_adapter(tokenizer=SilentTokenizer())
        adapter.scan_attack(secret)
        self.assertNotIn(secret, repr(vars(adapter)))

    def test_model_inference_is_locked_across_threads(self):
        adapter, _, model, backend = self.prompt_adapter(model=FakeClassifier(delay=0.02))
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: adapter.scan_attack("a b c")["decision"], range(6)))
        self.assertEqual(results, ["allow"] * 6)
        self.assertEqual(model.max_active, 1)
        self.assertEqual(backend.inference_entries, 6)

    def test_thread_context_isolation_for_prompt_counts(self):
        def logits_fn(kwargs):
            identifiers = kwargs["input_ids"][0]
            return [-1.0, 1.0] if len(identifiers) % 2 else [1.0, -1.0]

        adapter, _, _, _ = self.prompt_adapter(model=FakeClassifier(logits_fn=logits_fn))
        inputs = ["w " * words for words in range(1, 9)]
        expected = ["block" if (words + 2) % 2 else "allow" for words in range(1, 9)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda text: adapter.scan_attack(text)["decision"], inputs))
        self.assertEqual(results, expected)


class LlamaGuard3Tests(GuardTestBase):
    def test_every_turn_and_role_reaches_the_template(self):
        messages = [
            {"role": "system", "content": "system rules"},
            {"role": "user", "content": "first user turn"},
            {"role": "assistant", "content": "prior assistant turn"},
        ]
        tokenizer = FakeGuardTokenizer(template_len=20, verdict="safe")
        adapter, _, model, _ = self.llama_adapter(tokenizer=tokenizer)
        result = adapter.scan_response(messages, "buffered model output")
        self.assertEqual(result, {"safe": True})
        conversation = tokenizer.conversations[-1]
        self.assertEqual(len(conversation), 2)
        self.assertEqual(conversation[0]["role"], "user")
        self.assertEqual(conversation[1], {"role": "assistant", "content": "buffered model output"})
        for message in messages:
            self.assertIn(message["content"], conversation[0]["content"])
            self.assertIn(f"{message['role']}: ", conversation[0]["content"])
        self.assertEqual(tokenizer.generation_prompts[-1], True)
        self.assertEqual(len(model.calls), 1)

    def test_malformed_context_fails_closed_without_generating(self):
        adapter, _, model, _ = self.llama_adapter()
        bad_messages = [
            [],
            "not-a-list",
            [{"role": "tool", "content": "x"}],
            [{"role": "user", "content": "x", "name": "n"}],
            [{"role": "user", "content": 5}],
            [{"role": "user"}],
            [None],
        ]
        for messages in bad_messages:
            with self.subTest(messages=messages):
                with self.assertRaises(GuardError):
                    adapter.scan_response(messages, "out")
        with self.assertRaises(GuardError):
            adapter.scan_response([{"role": "user", "content": "x"}], 7)
        self.assertEqual(model.calls, [])

    def test_context_window_bounds_prompt_and_reserves_verdict_tokens(self):
        # min(context_limit=64, mpe=128) - 32 = 32 tokens of prompt budget.
        allowed, _, _, _ = self.llama_adapter(
            context_limit=64, tokenizer=FakeGuardTokenizer(template_len=32), model=FakeCausalModel(mpe=128)
        )
        self.assertEqual(allowed.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        blocked, _, model, _ = self.llama_adapter(
            context_limit=64, tokenizer=FakeGuardTokenizer(template_len=33), model=FakeCausalModel(mpe=128)
        )
        with self.assertRaises(GuardError):
            blocked.scan_response([{"role": "user", "content": "x"}], "out")
        self.assertEqual(model.calls, [])

    def test_explicit_context_limit_reserves_verdict_tokens_within_the_limit(self):
        # The verdict reservation comes out of the *configured* total, not just
        # out of max_position_embeddings. 33 is the smallest valid total.
        smallest, _, _, _ = self.llama_adapter(
            context_limit=33, tokenizer=FakeGuardTokenizer(template_len=1), model=FakeCausalModel(mpe=4096)
        )
        self.assertEqual(smallest.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        for context_limit in (32, 1, 0):
            with self.subTest(context_limit=context_limit):
                with self.assertRaises(GuardError):
                    LlamaGuard3(
                        self.model_dir,
                        context_limit=context_limit,
                        tokenizer=FakeGuardTokenizer(),
                        model=FakeCausalModel(mpe=4096),
                        backend=FakeBackend(),
                    )
        blocked, _, model, _ = self.llama_adapter(
            context_limit=33, tokenizer=FakeGuardTokenizer(template_len=2), model=FakeCausalModel(mpe=4096)
        )
        with self.assertRaises(GuardError):
            blocked.scan_response([{"role": "user", "content": "x"}], "out")
        self.assertEqual(model.calls, [])

    def test_configured_limit_is_bounded_by_local_model_window(self):
        # context_limit 200 but max_position_embeddings 64 leaves only 64-32=32.
        tokenizer = FakeGuardTokenizer(template_len=32)
        adapter, _, _, _ = self.llama_adapter(context_limit=200, tokenizer=tokenizer, model=FakeCausalModel(mpe=64))
        self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        blocked, _, model, _ = self.llama_adapter(
            context_limit=200, tokenizer=FakeGuardTokenizer(template_len=33), model=FakeCausalModel(mpe=64)
        )
        with self.assertRaises(GuardError):
            blocked.scan_response([{"role": "user", "content": "x"}], "out")
        self.assertEqual(model.calls, [])

    def test_missing_or_invalid_context_window_fails_closed(self):
        for mpe in [None, 0, -1, 16, 32, True, "4096"]:
            with self.subTest(mpe=mpe):
                model = FakeCausalModel()
                model.config = types.SimpleNamespace(max_position_embeddings=mpe)
                with self.assertRaises(GuardError):
                    LlamaGuard3(
                        self.model_dir,
                        context_limit=128,
                        tokenizer=FakeGuardTokenizer(),
                        model=model,
                        backend=FakeBackend(),
                    )
        model = FakeCausalModel()
        model.config = types.SimpleNamespace()
        with self.assertRaises(GuardError):
            LlamaGuard3(
                self.model_dir,
                context_limit=128,
                tokenizer=FakeGuardTokenizer(),
                model=model,
                backend=FakeBackend(),
            )
        # 33 is the smallest model window that leaves one prompt token.
        smallest = LlamaGuard3(
            self.model_dir,
            context_limit=128,
            tokenizer=FakeGuardTokenizer(template_len=1),
            model=FakeCausalModel(mpe=33),
            backend=FakeBackend(),
        )
        self.assertEqual(smallest.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})

    def test_invalid_context_limits_and_missing_eos_fail_closed(self):
        for value in [0, -1, True, "128", None]:
            with self.subTest(value=value):
                with self.assertRaises(GuardError):
                    LlamaGuard3(
                        self.model_dir,
                        context_limit=value,
                        tokenizer=FakeGuardTokenizer(),
                        model=FakeCausalModel(),
                        backend=FakeBackend(),
                    )
        tokenizer = FakeGuardTokenizer()
        tokenizer.eos_token_id = None
        with self.assertRaises(GuardError):
            LlamaGuard3(
                self.model_dir,
                context_limit=128,
                tokenizer=tokenizer,
                model=FakeCausalModel(),
                backend=FakeBackend(),
            )

    def test_prefix_slicing_decodes_only_new_tokens_before_eos(self):
        tokenizer = FakeGuardTokenizer(template_len=5, verdict="safe")
        model = FakeCausalModel(new_tokens=[20, 21, EOS])
        adapter, _, _, _ = self.llama_adapter(tokenizer=tokenizer, model=model)
        self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        self.assertEqual(tokenizer.decodes[-1], ([20, 21], True))
        call = model.calls[-1]
        self.assertEqual(call["max_new_tokens"], 32)
        self.assertIs(call["do_sample"], False)
        self.assertEqual(call["eos_token_id"], EOS)
        self.assertEqual(call["pad_token_id"], EOS)

    def test_tensor_like_generated_ids_are_converted_with_one_detach_cpu_tolist_pass(self):
        stats = _TensorStats()
        prompt = [9] * 5

        def tensor_generate(input_ids, kwargs):
            return FakeTensor([list(prompt) + [20, 21, EOS]], stats)

        adapter, _, _, _ = self.llama_adapter(
            tokenizer=FakeGuardTokenizer(template_len=5),
            model=FakeCausalModel(generate_fn=tensor_generate),
        )
        self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        self.assertEqual((stats.detach, stats.cpu, stats.tolist), (1, 1, 1))

    def test_model_generation_config_eos_supplies_multiple_accepted_ids(self):
        tokenizer = FakeGuardTokenizer(template_len=5)
        model = FakeCausalModel(
            new_tokens=[20, 21, 7],
            generation_config=types.SimpleNamespace(eos_token_id=[EOS, 7]),
        )
        adapter, _, _, _ = self.llama_adapter(tokenizer=tokenizer, model=model)
        self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        call = model.calls[-1]
        self.assertEqual(call["eos_token_id"], [EOS, 7])
        self.assertEqual(call["pad_token_id"], EOS)
        self.assertEqual(tokenizer.decodes[-1], ([20, 21], True))

    def test_model_generation_config_single_alternate_eos_wins_over_tokenizer(self):
        tokenizer = FakeGuardTokenizer(template_len=5)
        model = FakeCausalModel(new_tokens=[20, 21, 7], generation_config=types.SimpleNamespace(eos_token_id=7))
        adapter, _, _, _ = self.llama_adapter(tokenizer=tokenizer, model=model)
        self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        self.assertEqual(model.calls[-1]["eos_token_id"], 7)
        self.assertEqual(tokenizer.decodes[-1], ([20, 21], True))

    def test_model_config_eos_falls_back_when_generation_config_is_absent(self):
        model = FakeCausalModel(new_tokens=[20, EOS], config_eos=EOS)
        adapter, _, _, _ = self.llama_adapter(tokenizer=FakeGuardTokenizer(template_len=5), model=model)
        self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        self.assertEqual(model.calls[-1]["eos_token_id"], EOS)

    def test_malformed_generation_config_eos_fails_closed_without_generating(self):
        malformed = [
            True,
            -1,
            "3",
            3.0,
            [],
            (),
            [True],
            [-1],
            [EOS, "4"],
            [EOS, EOS],
            {"eos_token_id": EOS},
        ]
        for eos in malformed:
            with self.subTest(eos=eos):
                tokenizer = FakeGuardTokenizer(template_len=5)
                model = FakeCausalModel(generation_config=types.SimpleNamespace(eos_token_id=eos))
                with self.assertRaises(GuardError):
                    LlamaGuard3(
                        self.model_dir,
                        context_limit=128,
                        tokenizer=tokenizer,
                        model=model,
                        backend=FakeBackend(),
                    )
                self.assertEqual(tokenizer.conversations, [])

    def test_empty_generation_config_eos_falls_back_to_tokenizer(self):
        tokenizer = FakeGuardTokenizer(template_len=5, eos=EOS)
        model = FakeCausalModel(new_tokens=[20, EOS], generation_config=types.SimpleNamespace(eos_token_id=None))
        adapter, _, _, _ = self.llama_adapter(tokenizer=tokenizer, model=model)
        self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": True})
        self.assertEqual(model.calls[-1]["eos_token_id"], EOS)

    def test_missing_eos_or_bad_sequence_fails_closed(self):

        tokenizer = FakeGuardTokenizer(template_len=5)
        missing_eos, _, _, _ = self.llama_adapter(
            tokenizer=tokenizer, model=FakeCausalModel(new_tokens=[20, 21])
        )
        with self.assertRaises(GuardError):
            missing_eos.scan_response([{"role": "user", "content": "x"}], "out")
        self.assertEqual(tokenizer.decodes, [])

        too_long, _, _, _ = self.llama_adapter(
            tokenizer=FakeGuardTokenizer(template_len=5), model=FakeCausalModel(new_tokens=[7] * 33)
        )
        with self.assertRaises(GuardError):
            too_long.scan_response([{"role": "user", "content": "x"}], "out")

        def bad_prefix(input_ids, kwargs):
            return [[1, 2, 3, 4, 5, 6, EOS]]

        mismatch, _, _, _ = self.llama_adapter(
            tokenizer=FakeGuardTokenizer(template_len=5),
            model=FakeCausalModel(generate_fn=bad_prefix),
        )
        with self.assertRaises(GuardError):
            mismatch.scan_response([{"role": "user", "content": "x"}], "out")

        truncated, _, _, _ = self.llama_adapter(
            tokenizer=FakeGuardTokenizer(template_len=5), model=FakeCausalModel(new_tokens=[])
        )
        with self.assertRaises(GuardError):
            truncated.scan_response([{"role": "user", "content": "x"}], "out")

        resumed, _, _, _ = self.llama_adapter(
            tokenizer=FakeGuardTokenizer(template_len=5), model=FakeCausalModel(new_tokens=[20, EOS, 21])
        )
        with self.assertRaises(GuardError):
            resumed.scan_response([{"role": "user", "content": "x"}], "out")

    def test_decode_failures_and_non_string_decode_fail_closed(self):
        for keyword in [{"decode_error": RuntimeError("leak SECRET")}, {"verdict": None}]:
            with self.subTest(keyword=keyword):
                tokenizer = FakeGuardTokenizer(template_len=5, **keyword)
                adapter, _, _, _ = self.llama_adapter(tokenizer=tokenizer, model=FakeCausalModel())
                with self.assertRaises(GuardError) as ctx:
                    adapter.scan_response([{"role": "user", "content": "x"}], "out")
                self.assertNotIn("SECRET", str(ctx.exception))

    def test_generate_failure_is_generic_without_leaking_output(self):
        secret = "SECRET-BUFFERED-OUTPUT"
        adapter, _, _, _ = self.llama_adapter(model=FakeCausalModel(error=RuntimeError("leak " + secret)))
        with self.assertRaises(GuardError) as ctx:
            adapter.scan_response([{"role": "user", "content": "x"}], secret)
        self.assertNotIn(secret, str(ctx.exception))

    def test_verdict_parsing_is_exact_and_not_substring_based(self):
        accepted = {
            "safe": True,
            "  safe  ": True,
            "unsafe": False,
            "unsafe\n": False,
            "unsafe\nS1": False,
            "unsafe\nS1,S2": False,
            "unsafe\nS1 S13": False,
            "unsafe\nS1, S2\nS13": False,
        }
        rejected = [
            "Safe",
            "SAFE",
            "safe\nS1",
            "unsafe S1",
            "unsafe\nS0",
            "unsafe\nS14",
            "unsafe\ns1",
            "unsafe\nS01",
            "unsafe\nS1 extra",
            "unsafe because it is bad",
            "not safe",
            "maybe",
            "",
            "  ",
        ]
        for verdict, expected in accepted.items():
            with self.subTest(verdict=verdict):
                adapter, _, _, _ = self.llama_adapter(
                    tokenizer=FakeGuardTokenizer(template_len=5, verdict=verdict), model=FakeCausalModel()
                )
                self.assertEqual(adapter.scan_response([{"role": "user", "content": "x"}], "out"), {"safe": expected})
        for verdict in rejected:
            with self.subTest(verdict=verdict):
                adapter, _, _, _ = self.llama_adapter(
                    tokenizer=FakeGuardTokenizer(template_len=5, verdict=verdict), model=FakeCausalModel()
                )
                with self.assertRaises(GuardError):
                    adapter.scan_response([{"role": "user", "content": "x"}], "out")

    def test_context_is_stateless_across_threads(self):
        def generate_fn(input_ids, kwargs):
            prompt = input_ids[0]
            return [list(prompt) + [sum(prompt) % 2, EOS]]

        tokenizer = FakeGuardTokenizer(verdict_fn=lambda ids: "safe" if sum(ids) % 2 == 0 else "unsafe")
        adapter, _, _, _ = self.llama_adapter(tokenizer=tokenizer, model=FakeCausalModel(generate_fn=generate_fn))

        def expected_safe(content, output):
            text = f"user: {content}" + output
            identifiers = [9] + [30 + (ord(char) % 40) for char in text] + [EOS]
            return sum(identifiers) % 2 == 0

        cases = [(f"case-{index}", f"out-{index}") for index in range(8)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(
                pool.map(
                    lambda pair: adapter.scan_response([{"role": "user", "content": pair[0]}], pair[1]),
                    cases,
                )
            )
        self.assertEqual(results, [{"safe": expected_safe(*pair)} for pair in cases])

    def test_output_is_not_retained_on_the_adapter(self):
        secret = "SECRET-BUFFERED-xyz"
        adapter, _, _, _ = self.llama_adapter(
            tokenizer=FakeGuardTokenizer(template_len=5, verdict="safe"), model=FakeCausalModel()
        )
        adapter.scan_response([{"role": "user", "content": "hello"}], secret)
        self.assertNotIn(secret, repr(vars(adapter)))


class LoaderTests(GuardTestBase):
    def test_prompt_loader_uses_local_only_flags_and_cpu(self):
        captured = {}
        fake = types.ModuleType("transformers")

        class AutoTokenizer:
            @staticmethod
            def from_pretrained(*args, **kwargs):
                captured["tokenizer"] = (args, kwargs)
                return FakePromptTokenizer()

        class AutoModelForSequenceClassification:
            @staticmethod
            def from_pretrained(*args, **kwargs):
                captured["model"] = (args, kwargs)
                return FakeClassifier()

        fake.AutoTokenizer = AutoTokenizer
        fake.AutoModelForSequenceClassification = AutoModelForSequenceClassification
        with mock.patch.dict(sys.modules, {"transformers": fake}):
            adapter = PromptGuard2(self.model_dir, backend=FakeBackend())
        self.assertEqual(captured["tokenizer"][0], (str(self.model_dir),))
        self.assertEqual(captured["model"][0], (str(self.model_dir),))
        for kwargs in (captured["tokenizer"][1], captured["model"][1]):
            self.assertIs(kwargs["token"], False)
            self.assertIs(kwargs["local_files_only"], True)
            self.assertIs(kwargs["trust_remote_code"], False)
        self.assertIs(captured["model"][1]["use_safetensors"], True)
        self.assertTrue(adapter._model.eval_called)
        self.assertEqual(adapter._model.device, "cpu")

    def test_llama_loader_uses_local_only_flags_and_cpu(self):
        captured = {}
        fake = types.ModuleType("transformers")
        fake_torch = types.ModuleType("torch")
        fake_torch.float32 = object()

        class AutoTokenizer:
            @staticmethod
            def from_pretrained(*args, **kwargs):
                captured["tokenizer"] = (args, kwargs)
                return FakeGuardTokenizer()

        class AutoModelForCausalLM:
            @staticmethod
            def from_pretrained(*args, **kwargs):
                captured["model"] = (args, kwargs)
                return FakeCausalModel()

        fake.AutoTokenizer = AutoTokenizer
        fake.AutoModelForCausalLM = AutoModelForCausalLM
        with mock.patch.dict(sys.modules, {"transformers": fake, "torch": fake_torch}):
            adapter = LlamaGuard3(self.model_dir, context_limit=128, backend=FakeBackend())
        for kwargs in (captured["tokenizer"][1], captured["model"][1]):
            self.assertIs(kwargs["token"], False)
            self.assertIs(kwargs["local_files_only"], True)
            self.assertIs(kwargs["trust_remote_code"], False)
        self.assertIs(captured["model"][1]["use_safetensors"], True)
        self.assertTrue(adapter._model.eval_called)
        self.assertEqual(adapter._model.device, "cpu")

    def test_causal_loader_loads_explicit_float32(self):
        """The CPU-only causal lane loads weights as float32 from the start."""
        captured = {}
        fake = types.ModuleType("transformers")
        fake_torch = types.ModuleType("torch")
        fake_torch.float32 = object()

        class AutoModelForCausalLM:
            @staticmethod
            def from_pretrained(*args, **kwargs):
                captured.update(kwargs)
                model = FakeCausalModel()
                model.dtype = kwargs.get("dtype")
                return model

        fake.AutoModelForCausalLM = AutoModelForCausalLM
        with mock.patch.dict(sys.modules, {"transformers": fake, "torch": fake_torch}):
            model = _load_causal_model(str(self.model_dir))
        self.assertIs(model.dtype, fake_torch.float32)
        self.assertEqual(model.device, "cpu")

    def test_missing_directory_or_hub_identifier_fails_without_leaks(self):
        missing = self.model_dir / "does-not-exist"
        for constructor, kwargs in ((PromptGuard2, {}), (LlamaGuard3, {"context_limit": 128})):
            with self.subTest(constructor=constructor.__name__):
                with self.assertRaises(GuardError) as ctx:
                    constructor(missing, **kwargs)
                self.assertNotIn("does-not-exist", str(ctx.exception))
                self.assertNotIn(str(self.model_dir), str(ctx.exception))
        with self.assertRaises(GuardError) as ctx:
            PromptGuard2("meta-llama/Llama-Prompt-Guard-2-86M")
        self.assertNotIn("meta-llama", str(ctx.exception))
        with self.assertRaises(GuardError):
            PromptGuard2("https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M")

    def test_unavailable_dependency_or_files_fail_generic(self):
        """With real transformers absent this exercises the lazy-import failure."""
        for constructor, kwargs in ((PromptGuard2, {}), (LlamaGuard3, {"context_limit": 128})):
            with self.subTest(constructor=constructor.__name__):
                with self.assertRaises(GuardError) as ctx:
                    constructor(self.model_dir, **kwargs)
                message = str(ctx.exception)
                self.assertNotIn(str(self.model_dir), message)
                self.assertNotIn("transformers", message.lower())

    def test_loader_error_is_sanitized(self):
        fake = types.ModuleType("transformers")

        class AutoTokenizer:
            @staticmethod
            def from_pretrained(*args, **kwargs):
                raise RuntimeError("hf token=hf_SECRET promotion path=" + str(self.model_dir))

        fake.AutoTokenizer = AutoTokenizer
        with mock.patch.dict(sys.modules, {"transformers": fake}):
            with self.assertRaises(GuardError) as ctx:
                PromptGuard2(self.model_dir)
        message = str(ctx.exception)
        self.assertNotIn("SECRET", message)
        self.assertNotIn(str(self.model_dir), message)
        self.assertNotIn("RuntimeError", message)


class DependencyIsolationTests(GuardTestBase):
    def test_default_import_does_not_require_ml_extras(self):
        root = Path(__file__).resolve().parent.parent
        code = (
            "import sys\n"
            "import nasi_lemak.guards as guards\n"
            "print('ml_extras_imported=', 'torch' in sys.modules or 'transformers' in sys.modules)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code], cwd=str(root), capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ml_extras_imported= False", result.stdout)

    def test_no_verdict_is_returned_when_models_are_absent(self):
        with self.assertRaises(GuardError):
            PromptGuard2(self.model_dir)
        with self.assertRaises(GuardError):
            LlamaGuard3(self.model_dir, context_limit=128)


if __name__ == "__main__":
    unittest.main()
