"""Local Qwen3Guard-Gen transport: one causal model for both guard slots.

``Qwen3Guard-Gen-0.6B`` is a **generative** guard: it emits the verdict text
that :mod:`nasi_lemak.qwen3guard` parses.  The artifact defines two shapes, so
the shared parser is used with a lane: the input slot's official moderation
verdict is Safety + Categories (Refusal optional), while the output slot keeps
the strict three-line product verdict.  It is loaded as a causal language model
(never as a sequence-classification head), from an existing local directory,
with the same discipline as the Meta adapters in :mod:`nasi_lemak.guards`:

* ``local_files_only=True``, ``trust_remote_code=False``, ``token=False`` and
  safetensors only -- no Hub resolution, no download, no cache fallback, no
  remote code;
* device CPU explicitly, weights loaded as ``float32`` (the checkpoint's bf16
  storage is emulated on CPU and ~330x slower per measured matmul), an explicit
  torch intra-op thread count and a bounded
  :class:`~nasi_lemak.guard_pool.GuardInferencePool` with one slot per scan;
* every failure -- a missing directory or file, a load failure, an artifact
  carrying remote-code modules, a structurally invalid model, an unparseable
  verdict, a malformed or truncated reply, an over-long input -- raises
  :class:`~nasi_lemak.guard_errors.GuardError` (oversize input uses its
  :class:`~nasi_lemak.guard_errors.GuardInputLimit` subclass).  There is no
  default allow, no fallback model and no retry.

Structural validation is deliberately repeated after loading.  The proven
lesson (D12) is that ``trust_remote_code=False`` alone does not stop
``transformers`` from mapping an artifact onto a built-in class and silently
creating a **randomly initialised** model.  So the transport refuses, before any
loader runs, an artifact that carries remote-code modules or an ``auto_map``,
requires local ``config.json`` and safetensors weights, and requires an explicit
causal architecture declaration.  After loading it independently checks the
runtime class itself -- not only the config's declared architecture -- against
the supported Qwen3 causal structure, and validates the context window and EOS
configuration.  A generic ``id2label`` map is normal ``PretrainedConfig``
metadata and is not treated as evidence of a classifier; the classifier shape is
rejected from the runtime class/head.  Any surprise is a ``GuardError``, never
an allow.

The prompt delivery is the shared contract: ``render_guard_prompt`` applies the
artifact's own chat template to ``guard_chat_messages`` (system framing plus the
serialized text, plus the assistant reply on the output lane).  A missing or
failing chat template is a ``GuardError``; there is no plain-text fallback.  The
rendered prompt is tokenized with ``add_special_tokens=False`` and
``truncation=False``, because the template's special tokens are literal text in
the rendered string.

Long input is one call, never a window split and never truncated.  The fixed
framing is paid on every call, so splitting multiplies the dominant fixed cost.
At the default 8192-token payload budget a full input costs 8192 + 432 framing
units in one forward pass, inside the 32768-position window minus the 128-token
verdict reserve (8192 + 432 + 128 = 8752).  The budget is a payload budget: the
framed prompt is checked separately against the physical window.  An input above
the configured budget, or a framed prompt that does not fit the window with the
verdict reserve, fails closed with ``INPUT_LIMIT`` and nothing is released.

``Qwen3Guard-Stream`` is deliberately **not** a candidate: it needs
``trust_remote_code=True``, which this product forbids, so an artifact that
carries its remote-code modules is rejected by filename.

The module top level imports the standard library plus the cycle-free guard
contract/pool and the helper functions in :mod:`nasi_lemak.guards`.  It never
imports ``torch`` or ``transformers`` at module scope.

No pretrained checkpoint has been executed in this workspace, and nothing here
is evidence of detection quality, latency or hardware behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .guard_errors import GuardError, GuardInputLimit
from .guard_pool import GuardInferencePool, resolve_inference_budget
from .guards import (
    _context_window,
    _generation_eos,
    _generated_verdict_text,
    _ids_from_encoding,
    _import_torch,
    _load_causal_model,
    _load_tokenizer,
    _local_directory,
    _pad_token_id,
    _prepare_model,
)
from .qwen3guard import (
    DEFAULT_LONG_INPUT_TOKENS,
    DEFAULT_THRESHOLD,
    LANE_INPUT,
    LANE_RESPONSE,
    MAX_LONG_INPUT_TOKENS,
    MIN_LONG_INPUT_TOKENS,
    VERDICT_MAX_TOKENS,
    parse_verdict_fields,
    render_guard_prompt,
    serialize_messages,
    validate_conversation,
    validate_threshold,
    verdict_blocks,
)

#: Re-exported for callers that configure the local transport directly.
__all__ = [
    "DEFAULT_LONG_INPUT_TOKENS",
    "MAX_LONG_INPUT_TOKENS",
    "MIN_LONG_INPUT_TOKENS",
    "Qwen3GuardLocal",
    "REMOTE_CODE_ARTIFACTS",
]

#: Artifacts that require ``trust_remote_code=True``.  Qwen3Guard-Stream ships
#: these; the disciplined loader must refuse them by filename, before loading.
REMOTE_CODE_ARTIFACTS = frozenset(
    {"modeling_qwen3_guard.py", "configuration_qwen3.py"}
)

#: The causal-LM architecture suffix required of the declared/loaded class.  A
#: sequence-classification head -- including one silently initialised by
#: ``transformers`` from an unexpected artifact -- does not satisfy it.
_CAUSAL_ARCHITECTURE_SUFFIX = "forcausallm"
#: The production loader is restricted to the supported Qwen3 causal class.  The
#: declared architecture alone is not trusted: a classifier object can carry a
#: copied causal declaration.
_SUPPORTED_RUNTIME_SUFFIX = "qwen3forcausallm"
_CLASSIFIER_MARKERS = ("sequenceclassification", "sequence-classification")
_CLASSIFIER_HEAD_ATTRIBUTES = ("classifier", "score")


def _validate_long_input(value: Any) -> int:
    """Validate the single-call payload budget, or derive the contract default."""
    if value is None:
        return DEFAULT_LONG_INPUT_TOKENS
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not MIN_LONG_INPUT_TOKENS <= value <= MAX_LONG_INPUT_TOKENS
    ):
        raise GuardError("guard input budget is invalid")
    return value


def _artifact_entries(directory: str) -> list[Path]:
    try:
        return list(Path(directory).iterdir())
    except (OSError, ValueError):
        raise GuardError("guard model directory is not available") from None


def _validate_architectures(value: Any) -> None:
    """Require an explicit causal-LM architecture, never a classifier head.

    A missing declaration is invalid: the loader must not infer the architecture
    from a filename, a directory name or the loaded class name alone.
    """
    if not isinstance(value, (list, tuple)) or not value:
        raise GuardError("guard model architecture is invalid")
    causal = False
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise GuardError("guard model architecture is invalid")
        lowered = item.strip().lower()
        if any(marker in lowered for marker in _CLASSIFIER_MARKERS):
            raise GuardError("guard model architecture is not a causal language model")
        if lowered.endswith(_CAUSAL_ARCHITECTURE_SUFFIX):
            causal = True
    if not causal:
        raise GuardError("guard model architecture is not a causal language model")


def _validate_artifact_layout(directory: str) -> None:
    """Reject an artifact that cannot be a disciplined local causal checkpoint.

    This runs before either loader.  It is a filename/config check only: no
    import, no model construction and no network access.
    """
    entries = _artifact_entries(directory)
    names = {entry.name.lower() for entry in entries}
    if names & REMOTE_CODE_ARTIFACTS:
        raise GuardError("guard model directory requires remote code")
    if "config.json" not in names:
        raise GuardError("guard model configuration is unavailable")
    if not any(
        entry.is_file() and entry.name.lower().endswith(".safetensors")
        for entry in entries
    ):
        # Loader discipline is safetensors-only; a pickle/bin-only directory
        # must fail here rather than after an attempted load.
        raise GuardError("guard model weights are not available as safetensors")
    try:
        raw = (Path(directory) / "config.json").read_text(encoding="utf-8")
    except (OSError, ValueError, UnicodeDecodeError):
        raise GuardError("guard model configuration is unavailable") from None
    try:
        config = json.loads(raw)
    except (TypeError, ValueError):
        raise GuardError("guard model configuration is invalid") from None
    if not isinstance(config, dict):
        raise GuardError("guard model configuration is invalid")
    if config.get("auto_map") is not None:
        # ``auto_map`` is the other way an artifact asks for remote code.
        raise GuardError("guard model directory requires remote code")
    model_type = config.get("model_type")
    if (
        not isinstance(model_type, str)
        or not model_type.strip().lower().startswith("qwen3")
    ):
        raise GuardError("guard model architecture is not supported")
    _validate_architectures(config.get("architectures"))


def _runtime_class_name(model: Any) -> str:
    return str(type(model).__name__).strip().lower()


def _has_classifier_runtime_shape(model: Any) -> bool:
    """Detect an actual classifier class or head, not config label metadata."""
    if any(marker in _runtime_class_name(model) for marker in _CLASSIFIER_MARKERS):
        return True
    for attribute in _CLASSIFIER_HEAD_ATTRIBUTES:
        if getattr(model, attribute, None) is not None:
            return True
    return False


def _validate_loaded_structure(model: Any, *, injected: bool) -> None:
    """Independently verify the loaded object is a causal generator.

    ``injected`` marks the explicit test seam.  A double must still expose a
    callable ``generate``, a usable ``config``, a valid causal architecture
    declaration and no classifier runtime shape.  The real-artifact check is
    stricter: the runtime class must be the supported Qwen3 causal class, so a
    sequence-classification object cannot pass merely by declaring
    ``Qwen3ForCausalLM`` in its config.  Generic ``id2label`` metadata is not
    inspected: ``PretrainedConfig`` supplies it even for causal models.
    """
    if model is None:
        raise GuardError("guard model could not be loaded")
    if not callable(getattr(model, "generate", None)):
        raise GuardError("guard model architecture is not a causal language model")
    if _has_classifier_runtime_shape(model):
        raise GuardError("guard model architecture is not a causal language model")
    config = getattr(model, "config", None)
    if config is None:
        raise GuardError("guard model configuration is unavailable")
    _validate_architectures(getattr(config, "architectures", None))
    if not injected:
        model_type = getattr(config, "model_type", None)
        if (
            not isinstance(model_type, str)
            or not model_type.strip().lower().startswith("qwen3")
        ):
            raise GuardError("guard model architecture is not supported")
        if not _runtime_class_name(model).endswith(_SUPPORTED_RUNTIME_SUFFIX):
            raise GuardError(
                "guard model architecture is not a causal language model"
            )


def _apply_thread_budget(backend: Any, threads: int) -> None:
    """Apply the explicit intra-op thread count, never more than the budget."""
    if backend is None:
        setter = getattr(_import_torch(), "set_num_threads", None)
        if not callable(setter):
            raise GuardError("guard inference backend is unavailable")
    else:
        # A deterministic test double may not model tensor threading; it is an
        # explicit seam, not a production engine.
        setter = getattr(backend, "set_num_threads", None)
        if not callable(setter):
            return
    try:
        setter(threads)
    except Exception:
        raise GuardError("guard thread budget could not be applied") from None


class Qwen3GuardLocal:
    """Local causal Qwen3Guard-Gen adapter for the input and output slots.

    One object serves both slots: ``scan_attack`` compares the categorical
    verdict with the **input** threshold, ``scan_response`` with the **output**
    threshold.  Each threshold is a severity floor over ``Safe=0.0``,
    ``Controversial=0.5``, ``Unsafe=1.0``; the contract refuses a value above
    ``0.5`` because that would let a blocking label through.
    """

    #: The gateway may pass its per-request scan context; the pool honours the
    #: deadline and cancellation cooperatively before a slot reaches the model.
    supports_scan_context = True

    def __init__(
        self,
        model_dir: Any,
        *,
        input_threshold: Any = DEFAULT_THRESHOLD,
        output_threshold: Any = DEFAULT_THRESHOLD,
        workers: Any = None,
        threads: Any = None,
        long_input: Any = None,
        tokenizer: Any = None,
        model: Any = None,
        backend: Any = None,
    ) -> None:
        self._input_threshold = validate_threshold(input_threshold)
        self._output_threshold = validate_threshold(output_threshold)
        budget = _validate_long_input(long_input)
        directory = _local_directory(model_dir)
        _validate_artifact_layout(directory)
        injected = model is not None
        self._workers, self._threads = resolve_inference_budget(workers, threads)
        _apply_thread_budget(backend, self._threads)
        self._long_input = budget
        self._pool = GuardInferencePool(self._workers)
        self._backend = backend
        if tokenizer is not None:
            if not callable(tokenizer):
                raise GuardError("guard tokenizer could not be loaded")
            self._tokenizer = tokenizer
        else:
            self._tokenizer = _load_tokenizer(directory)
        if model is not None:
            loaded = _prepare_model(model)
        else:
            loaded = _load_causal_model(directory)
        _validate_loaded_structure(loaded, injected=injected)
        self._model = loaded
        self._window_limit = _context_window(self._model) - VERDICT_MAX_TOKENS
        if self._window_limit < 1:
            raise GuardError("guard context configuration is invalid")
        self._eos_ids, self._accepted_eos = _generation_eos(
            self._model, self._tokenizer
        )
        self._pad_token_id = _pad_token_id(self._tokenizer, self._eos_ids)

    @property
    def workers(self) -> int:
        return self._workers

    @property
    def threads(self) -> int:
        return self._threads

    @property
    def long_input(self) -> int:
        return self._long_input

    @property
    def input_threshold(self) -> float:
        return self._input_threshold

    @property
    def output_threshold(self) -> float:
        return self._output_threshold

    def _token_ids(self, text: str) -> list[int]:
        """Tokenize exactly like the shared contract: no specials, no truncation."""
        if not isinstance(text, str) or not text:
            raise GuardError("guard input is invalid")
        try:
            encoded = self._tokenizer(
                text,
                add_special_tokens=False,
                truncation=False,
            )
        except GuardError:
            raise
        except Exception:
            raise GuardError("guard tokenization failed") from None
        return _ids_from_encoding(encoded)

    def _verdict(
        self, serialized: str, *, lane: str, reply: str | None = None
    ) -> Any:
        """Deliver the complete framed prompt once and parse the verdict.

        The prompt is rendered through the artifact's own chat template, so the
        chat-trained guard sees its trained boundaries instead of a plain
        concatenation.  The verdict text is parsed by the one shared parser with
        the lane of the slot that produced it: the input slot expects the
        artifact's official Safety + Categories verdict, the output slot the
        strict three-line product verdict.  The payload budget is measured on
        the serialized text before any template work; the window budget is
        measured on the template-delivered text.  No truncation and no window
        split: an over-budget payload is rejected before any forward pass, and a
        prompt that does not fit the model window plus verdict reserve is
        rejected as unscreenable, not shortened.
        """
        budget_text = (
            serialized if reply is None else serialized + "\nassistant: " + reply
        )
        payload_ids = self._token_ids(budget_text)
        if len(payload_ids) > self._long_input:
            raise GuardInputLimit("guard input exceeds the configured limit")
        rendered = render_guard_prompt(self._tokenizer, serialized, reply=reply)
        prompt_ids = self._token_ids(rendered)
        if len(prompt_ids) > self._window_limit:
            raise GuardInputLimit("guard input exceeds the configured model window")
        text = _generated_verdict_text(
            self._model,
            self._tokenizer,
            prompt_ids,
            backend=self._backend,
            max_new_tokens=VERDICT_MAX_TOKENS,
            eos_ids=self._eos_ids,
            accepted_eos=self._accepted_eos,
            pad_token_id=self._pad_token_id,
        )
        return parse_verdict_fields(text, lane=lane)

    def count_tokens(self, serialized: str) -> int:
        """Token count of the screened text, without the fixed framing."""
        with self._pool.slot():
            return len(self._token_ids(serialized))

    def scan_attack(
        self,
        serialized: str,
        *,
        scan_context: Any = None,
    ) -> dict[str, str]:
        """Classify one complete serialized input; fail closed on any error."""

        def _scan() -> Any:
            return self._verdict(serialized, lane=LANE_INPUT)

        verdict = self._run_scan(serialized, _scan, scan_context)
        decision = (
            "block"
            if verdict_blocks(verdict, self._input_threshold)
            else "allow"
        )
        return {"decision": decision}

    def scan_response(self, messages: Any, output: Any) -> dict[str, bool]:
        """Classify the complete masked context plus the buffered output."""
        conversation = validate_conversation(messages, output)
        reply = conversation[-1]["content"]
        serialized = serialize_messages(conversation[:-1])
        with self._pool.slot():
            verdict = self._verdict(
                serialized, lane=LANE_RESPONSE, reply=reply
            )
        return {"safe": not verdict_blocks(verdict, self._output_threshold)}

    def _run_scan(
        self, serialized: Any, scan: Any, scan_context: Any
    ) -> Any:
        """Validate input/context, then run one pooled scan exactly once."""
        if not isinstance(serialized, str) or not serialized:
            raise GuardError("guard input is invalid")
        if scan_context is not None and not callable(
            getattr(scan_context, "cancelled", None)
        ):
            raise GuardError("guard scan context is invalid")
        deadline = (
            None if scan_context is None else getattr(scan_context, "deadline", None)
        )
        with self._pool.slot(deadline=deadline, scan_context=scan_context):
            return scan()
