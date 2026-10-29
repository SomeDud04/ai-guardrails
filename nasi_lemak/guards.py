"""Local-only guard adapters: Prompt Guard 2 (attack) and Llama Guard 3 (output).

These adapters run real Transformers inference when the optional ``guards`` extra
is installed and the operator supplies an **existing local model directory**.
There is no Hub-ID resolution, no default download, no cache fallback and no
network access at run time: every load passes ``local_files_only=True``,
``trust_remote_code=False`` and ``token=False``, and model weights are loaded
from safetensors only.

The module top level imports **standard library only**. ``torch`` and
``transformers`` are imported lazily inside the loaders, so importing
``nasi_lemak.guards`` never requires the optional ML dependencies. When a
dependency, model file, tokenizer, label mapping or verifier output is
unavailable or malformed the adapter raises :class:`GuardError` with a fixed,
generic message. It never returns a default "safe"/"allow" verdict, never
includes raw prompt text, paths or tokens in an error, and never logs input.

Every constructor also accepts explicit ``tokenizer``/``model``/``backend``
objects. Those keyword arguments exist only as a deterministic **test injection
seam** ("inference doubles"). They do not represent real guard efficacy and must
not be used to approve a deployment.

No claims about detection quality, latency or hardware are made here. Model
approval, artifact revisions, license acceptance and hardware proof remain
operator prerequisites, and no pretrained checkpoint has been executed in this
workspace.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .guard_errors import GuardError, GuardInputLimit
from .guard_pool import GuardInferencePool

__all__ = [
    "GuardError",
    "GuardInputLimit",
    "GuardInferencePool",
    "LlamaGuard3",
    "LLAMA_GUARD_VERDICT_TOKENS",
    "PROMPT_GUARD_MAX_TOKENS",
    "PromptGuard2",
]

# Meta Prompt Guard 2 is specified with a 512-token window. The count includes
# special tokens because ``add_special_tokens=True`` is used consistently.
PROMPT_GUARD_MAX_TOKENS = 512

# Llama Guard 3 emits a short verdict ("safe" or "unsafe" plus optional
# S1..S13 category codes). Reserve this many generated tokens and bound the
# prompt so prompt + verdict stays inside the model context window.
LLAMA_GUARD_VERDICT_TOKENS = 32

_ACCEPTED_ROLES = frozenset({"system", "user", "assistant"})
_CATEGORY = re.compile(r"S(?:[1-9]|1[0-3])\Z")
_BENIGN = "benign"
_MALICIOUS = "malicious"

# ``GuardError``/``GuardInputLimit`` are defined in ``guard_errors`` so the
# shared Qwen3Guard contract and the inference pool can use the same failure
# vocabulary without an import cycle.  They are re-exported above, so every
# existing ``from nasi_lemak.guards import GuardError`` keeps working.


def _local_directory(model_dir: Any) -> str:
    """Return an existing local directory path, or fail closed.

    Only filesystem directories are accepted. A Hub repository ID such as
    ``meta-llama/Llama-Guard-3-1B`` is not an existing directory here, and a
    URL is rejected outright, so no implicit download can be triggered.
    """
    if isinstance(model_dir, bool) or not isinstance(model_dir, (str, Path)):
        raise GuardError("guard model directory is not configured")
    text = str(model_dir)
    if not text or "\x00" in text or "://" in text:
        raise GuardError("guard model directory is not configured")
    try:
        path = Path(text).expanduser()
        if not path.is_dir():
            raise GuardError("guard model directory is not available")
    except (OSError, ValueError):
        raise GuardError("guard model directory is not available") from None
    return str(path)


def _import_transformers() -> Any:
    try:
        import transformers  # type: ignore[import-not-found]
    except Exception:
        raise GuardError("guard dependencies are unavailable") from None
    return transformers


def _import_torch() -> Any:
    try:
        import torch  # type: ignore[import-not-found]
    except Exception:
        raise GuardError("guard dependencies are unavailable") from None
    return torch


def _prepare_model(model: Any) -> Any:
    """Put a loaded model in eval mode on CPU. No GPU/cloud substitution."""
    if model is None:
        raise GuardError("guard model could not be loaded")
    try:
        if callable(getattr(model, "eval", None)):
            model.eval()
        if callable(getattr(model, "to", None)):
            model.to("cpu")
    except Exception:
        raise GuardError("guard model could not be prepared") from None
    return model


def _load_tokenizer(model_dir: str) -> Any:
    transformers = _import_transformers()
    try:
        tokenizer = transformers.AutoTokenizer.from_pretrained(
            model_dir,
            token=False,
            local_files_only=True,
            trust_remote_code=False,
        )
    except Exception:
        raise GuardError("guard tokenizer could not be loaded") from None
    if tokenizer is None:
        raise GuardError("guard tokenizer could not be loaded")
    return tokenizer


def _load_classifier(model_dir: str) -> Any:
    transformers = _import_transformers()
    try:
        model = transformers.AutoModelForSequenceClassification.from_pretrained(
            model_dir,
            token=False,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
    except Exception:
        raise GuardError("guard model could not be loaded") from None
    return _prepare_model(model)


def _load_causal_model(model_dir: str) -> Any:
    transformers = _import_transformers()
    try:
        model = transformers.AutoModelForCausalLM.from_pretrained(
            model_dir,
            token=False,
            local_files_only=True,
            trust_remote_code=False,
            use_safetensors=True,
        )
    except Exception:
        raise GuardError("guard model could not be loaded") from None
    return _prepare_model(model)


def _to_list(value: Any) -> Any:
    """Convert a value to plain Python data with one pass over tensor methods.

    A real tensor's ``detach()`` (and ``cpu()``) returns *another tensor*, so a
    loop that keeps calling ``detach`` would never reach ``tolist()``. Convert
    each stage exactly once, in the documented order: ``detach()`` if present,
    then ``cpu()`` if present, then ``tolist()`` if present.
    """
    current = value
    try:
        detach = getattr(current, "detach", None)
        if callable(detach):
            current = detach()
        cpu = getattr(current, "cpu", None)
        if callable(cpu):
            current = cpu()
        tolist = getattr(current, "tolist", None)
        if callable(tolist):
            current = tolist()
    except Exception:
        raise GuardError("guard value could not be converted") from None
    if isinstance(current, tuple):
        current = list(current)
    return current


def _flat_ids(value: Any, message: str) -> list[int]:
    """Normalise one token-id sequence to a flat list of non-negative ints."""
    values = _to_list(value)
    if isinstance(values, dict):
        values = values.get("input_ids")
    if not isinstance(values, (list, tuple)):
        raise GuardError(message)
    values = list(values)
    if values and isinstance(values[0], (list, tuple)):
        if len(values) != 1:
            raise GuardError(message)
        values = list(values[0])
    for item in values:
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise GuardError(message)
    return values


def _ids_from_encoding(encoded: Any) -> list[int]:
    if isinstance(encoded, dict):
        ids = encoded.get("input_ids")
    else:
        ids = getattr(encoded, "input_ids", None)
    if ids is None:
        raise GuardError("guard tokenization failed")
    return _flat_ids(ids, "guard tokenization failed")


def _validate_threshold(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GuardError("guard threshold is invalid")
    threshold = float(value)
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise GuardError("guard threshold is invalid")
    return threshold


def _binary_label_index(config: Any) -> int:
    """Return the index of the MALICIOUS class in a validated binary mapping."""
    mapping = getattr(config, "id2label", None)
    if not isinstance(mapping, dict) or len(mapping) != 2:
        raise GuardError("guard label mapping is invalid")
    if {type(key) for key in mapping} != {int} or set(mapping) != {0, 1}:
        raise GuardError("guard label mapping is invalid")
    by_name: dict[str, int] = {}
    for key, label in mapping.items():
        if not isinstance(label, str):
            raise GuardError("guard label mapping is invalid")
        name = label.strip().lower()
        if name not in (_BENIGN, _MALICIOUS) or name in by_name:
            raise GuardError("guard label mapping is invalid")
        by_name[name] = key
    if set(by_name) != {_BENIGN, _MALICIOUS}:
        raise GuardError("guard label mapping is invalid")
    return by_name[_MALICIOUS]


def _malicious_probability(logits: Any, malicious_index: int) -> float:
    """Finite softmax probability of the MALICIOUS class from raw logits."""
    values = _to_list(logits)
    if not isinstance(values, (list, tuple)):
        raise GuardError("guard model returned invalid scores")
    values = list(values)
    if values and isinstance(values[0], (list, tuple)):
        if len(values) != 1:
            raise GuardError("guard model returned invalid scores")
        values = list(values[0])
    if len(values) != 2:
        raise GuardError("guard model returned invalid scores")
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise GuardError("guard model returned invalid scores")
        if not math.isfinite(float(value)):
            raise GuardError("guard model returned invalid scores")
    peak = max(float(value) for value in values)
    exponentials = [math.exp(float(value) - peak) for value in values]
    total = sum(exponentials)
    if not math.isfinite(total) or total <= 0.0:
        raise GuardError("guard model returned invalid scores")
    probability = exponentials[malicious_index] / total
    if not math.isfinite(probability):
        raise GuardError("guard model returned invalid scores")
    return probability


def _extract_logits(outputs: Any) -> Any:
    if isinstance(outputs, dict):
        logits = outputs.get("logits")
    else:
        logits = getattr(outputs, "logits", None)
    if logits is None:
        if isinstance(outputs, (list, tuple)) or callable(getattr(outputs, "tolist", None)):
            logits = outputs
    if logits is None:
        raise GuardError("guard model returned invalid scores")
    return logits


def _as_tensor(values: Any, backend: Any) -> Any:
    if backend is None:
        factory = getattr(_import_torch(), "tensor", None)
    else:
        factory = getattr(backend, "tensor", None)
        if not callable(factory):
            factory = getattr(backend, "as_tensor", None)
    if not callable(factory):
        raise GuardError("guard inference backend is unavailable")
    try:
        return factory(values)
    except GuardError:
        raise
    except Exception:
        raise GuardError("guard inference backend is unavailable") from None


def _inference_context(backend: Any) -> Any:
    """Return an inference_mode/no_grad context manager for the compute stage."""
    if backend is None:
        torch = _import_torch()
        factory = getattr(torch, "inference_mode", None)
        if not callable(factory):
            factory = getattr(torch, "no_grad", None)
    else:
        factory = getattr(backend, "inference_mode", None)
        if not callable(factory):
            factory = getattr(backend, "no_grad", None)
    if not callable(factory):
        raise GuardError("guard inference backend is unavailable")
    try:
        return factory()
    except Exception:
        raise GuardError("guard inference backend is unavailable") from None


class PromptGuard2:
    """Meta Prompt Guard 2 binary attack classifier (local, CPU, fail-closed).

    ``count_tokens`` and ``scan_attack`` tokenize the *complete* serialized
    conversation with the same local tokenizer and the same
    ``add_special_tokens=True``/``truncation=False`` settings, so the gateway's
    token budget and the classifier window are directly comparable. Inputs over
    :data:`PROMPT_GUARD_MAX_TOKENS` are rejected as ``block`` before any forward
    pass. The malicious-class probability is a finite softmax value compared to
    an explicitly uncalibrated threshold (default 0.5).
    """

    def __init__(
        self,
        model_dir: Any,
        *,
        threshold: float = 0.5,
        workers: int = 1,
        tokenizer: Any = None,
        model: Any = None,
        backend: Any = None,
    ) -> None:
        self._threshold = _validate_threshold(threshold)
        directory = _local_directory(model_dir)
        # A bounded pool with a derived/validated thread budget replaced the one
        # process-wide lock.  Prompt Guard 2 is a single 512-token forward pass
        # per scan, so its default stays one slot; the budget is still validated.
        self._pool = GuardInferencePool(workers)
        self._backend = backend
        self._tokenizer = tokenizer if tokenizer is not None else _load_tokenizer(directory)
        self._model = _prepare_model(model) if model is not None else _load_classifier(directory)
        self._malicious_index = _binary_label_index(getattr(self._model, "config", None))

    def _token_ids(self, serialized: Any) -> list[int]:
        if not isinstance(serialized, str):
            raise GuardError("guard input is invalid")
        try:
            encoded = self._tokenizer(
                serialized,
                add_special_tokens=True,
                truncation=False,
            )
        except GuardError:
            raise
        except Exception:
            raise GuardError("guard tokenization failed") from None
        return _ids_from_encoding(encoded)

    def _forward(self, ids: list[int]) -> Any:
        inputs = {
            "input_ids": _as_tensor([ids], self._backend),
            "attention_mask": _as_tensor([[1] * len(ids)], self._backend),
        }
        try:
            with _inference_context(self._backend):
                outputs = self._model(**inputs)
        except GuardError:
            raise
        except Exception:
            raise GuardError("guard inference failed") from None
        return _extract_logits(outputs)

    def count_tokens(self, serialized: str) -> int:
        """Exact token count of the serialized conversation, specials included."""
        with self._pool.slot():
            return len(self._token_ids(serialized))

    def scan_attack(self, serialized: str) -> dict[str, str]:
        """Return ``{"decision": "allow"|"block"}`` for the serialized input."""
        with self._pool.slot():
            ids = self._token_ids(serialized)
            if len(ids) > PROMPT_GUARD_MAX_TOKENS:
                return {"decision": "block"}
            logits = self._forward(ids)
        probability = _malicious_probability(logits, self._malicious_index)
        decision = "block" if probability >= self._threshold else "allow"
        return {"decision": decision}


def _serialize_context(messages: list[dict[str, str]]) -> str:
    """Complete accepted context, one line per turn, roles preserved."""
    return "\n".join(f"{message['role']}: {message['content']}" for message in messages)


def _context_window(model: Any) -> int:
    config = getattr(model, "config", None)
    value = getattr(config, "max_position_embeddings", None)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GuardError("guard model context window is unavailable")
    return value


def _validate_context_limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GuardError("guard context limit is invalid")
    return value


def _validate_eos_ids(value: Any) -> int | list[int]:
    """Validate a generation EOS specification: an int or a non-empty int list."""
    message = "guard end-of-sequence configuration is invalid"
    if isinstance(value, bool):
        raise GuardError(message)
    if isinstance(value, int):
        if value < 0:
            raise GuardError(message)
        return value
    if isinstance(value, (list, tuple)):
        if not value:
            raise GuardError(message)
        identifiers: list[int] = []
        for item in value:
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise GuardError(message)
            identifiers.append(item)
        if len(set(identifiers)) != len(identifiers):
            raise GuardError(message)
        return identifiers
    raise GuardError(message)


def _generation_eos(model: Any, tokenizer: Any) -> tuple[int | list[int], frozenset[int]]:
    """Derive accepted EOS ids without overriding a model's own termination set.

    The model's ``generation_config.eos_token_id`` wins when supplied, then its
    config, then the tokenizer. A supplied but malformed value fails closed
    instead of silently falling back to a different token. Multiple valid ids
    (for example ``[128001, 128009]``) are preserved as a list.
    """
    for source in (getattr(model, "generation_config", None), getattr(model, "config", None)):
        if source is None:
            continue
        value = getattr(source, "eos_token_id", None)
        if value is not None:
            eos = _validate_eos_ids(value)
            accepted = frozenset([eos] if isinstance(eos, int) else eos)
            return eos, accepted
    value = getattr(tokenizer, "eos_token_id", None)
    if value is None:
        raise GuardError("guard tokenizer has no end-of-sequence token")
    eos = _validate_eos_ids(value)
    accepted = frozenset([eos] if isinstance(eos, int) else eos)
    return eos, accepted


def _parse_verdict(text: Any) -> bool:
    """Strict Llama Guard verdict parse. Only the exact token ``safe`` releases."""
    if not isinstance(text, str):
        raise GuardError("guard output was not a recognized verdict")
    stripped = text.strip()
    if stripped == "safe":
        return True
    if stripped == "unsafe":
        return False
    lines = [line.strip() for line in stripped.splitlines()]
    lines = [line for line in lines if line]
    if not lines or lines[0] != "unsafe":
        raise GuardError("guard output was not a recognized verdict")
    categories = 0
    for line in lines[1:]:
        for token in line.replace(",", " ").split():
            if not _CATEGORY.fullmatch(token):
                raise GuardError("guard output was not a recognized verdict")
            categories += 1
    if categories == 0:
        raise GuardError("guard output was not a recognized verdict")
    return False


def _generated_verdict_text(
    model: Any,
    tokenizer: Any,
    prompt_ids: list[int],
    *,
    backend: Any,
    max_new_tokens: int,
    eos_ids: int | list[int],
    accepted_eos: frozenset[int],
    pad_token_id: int,
) -> str:
    """Run one deterministic generation and return only the new verdict text.

    Shared by every local causal guard transport so generation plumbing is not
    copied per model: greedy decoding, a hard new-token ceiling, EOS supplied by
    the caller, the prompt sequence checked as a prefix, no truncation and no
    retry.  A non-EOS-terminated, over-long or undecodable sequence fails closed.
    """
    inputs = {
        "input_ids": _as_tensor([prompt_ids], backend),
        "attention_mask": _as_tensor([[1] * len(prompt_ids)], backend),
    }
    try:
        with _inference_context(backend):
            generated = model.generate(
                max_new_tokens=max_new_tokens,
                do_sample=False,
                eos_token_id=eos_ids,
                pad_token_id=pad_token_id,
                **inputs,
            )
    except GuardError:
        raise
    except Exception:
        raise GuardError("guard inference failed") from None
    if hasattr(generated, "sequences"):
        generated = generated.sequences
    ids = _flat_ids(generated, "guard model returned an invalid sequence")
    if len(ids) <= len(prompt_ids) or ids[: len(prompt_ids)] != list(prompt_ids):
        raise GuardError("guard model returned an invalid sequence")
    new_ids = ids[len(prompt_ids) :]
    if len(new_ids) > max_new_tokens:
        raise GuardError("guard model exceeded the verdict window")
    if not new_ids or new_ids[-1] not in accepted_eos:
        raise GuardError("guard model output was truncated")
    if any(token in accepted_eos for token in new_ids[:-1]):
        raise GuardError("guard model returned an invalid sequence")
    try:
        text = tokenizer.decode(new_ids[:-1], skip_special_tokens=True)
    except GuardError:
        raise
    except Exception:
        raise GuardError("guard output could not be decoded") from None
    if not isinstance(text, str):
        raise GuardError("guard output could not be decoded")
    return text


def _pad_token_id(tokenizer: Any, eos_ids: int | list[int]) -> int:
    """Return the tokenizer's pad id, or the first EOS id when it has none."""
    pad = getattr(tokenizer, "pad_token_id", None)
    if isinstance(pad, bool) or not isinstance(pad, int) or pad < 0:
        return eos_ids if isinstance(eos_ids, int) else eos_ids[0]
    return pad


class LlamaGuard3:
    """Meta Llama Guard 3 contextual output guard (local, CPU, fail-closed).

    ``scan_response`` includes *every* accepted message and role in one user
    message, appends the buffered model output as the assistant turn, and then
    applies the model's own chat template (``add_generation_prompt=True``,
    ``tokenize=True``, no truncation) so the full context reaches the tokenizer
    without silently dropping turns or system fields.

    The template's exact token IDs (special tokens included) are counted against
    ``min(context_limit, model.config.max_position_embeddings) - 32``. Generation
    is deterministic (``do_sample=False``, at most 32 new tokens) and only the
    newly generated IDs are decoded. Accepted EOS ids come from the model's
    ``generation_config.eos_token_id`` when supplied, otherwise from its config
    or the tokenizer; a malformed configuration fails closed. A missing EOS, a
    truncated or non-finite sequence, a malformed decode or any verdict text
    other than an exact ``safe``/``unsafe`` (with optional S1..S13 codes) fails
    closed.
    """

    def __init__(
        self,
        model_dir: Any,
        *,
        context_limit: int,
        workers: int = 1,
        tokenizer: Any = None,
        model: Any = None,
        backend: Any = None,
    ) -> None:
        limit = _validate_context_limit(context_limit)
        directory = _local_directory(model_dir)
        # Bounded pool instead of one process-wide lock.  A Llama Guard scan is
        # one short generation, so one slot is the default; the budget is still
        # validated and the pool fails closed exactly like the lock did.
        self._pool = GuardInferencePool(workers)
        self._backend = backend
        self._tokenizer = tokenizer if tokenizer is not None else _load_tokenizer(directory)
        self._model = _prepare_model(model) if model is not None else _load_causal_model(directory)
        self._max_position_embeddings = _context_window(self._model)
        self._prompt_limit = min(limit, self._max_position_embeddings) - LLAMA_GUARD_VERDICT_TOKENS
        if self._prompt_limit < 1:
            raise GuardError("guard context configuration is invalid")
        self._eos_ids, self._accepted_eos = _generation_eos(self._model, self._tokenizer)
        self._pad_token_id = _pad_token_id(self._tokenizer, self._eos_ids)

    def _template_ids(self, conversation: list[dict[str, str]]) -> list[int]:
        try:
            encoded = self._tokenizer.apply_chat_template(
                conversation,
                tokenize=True,
                add_generation_prompt=True,
            )
        except GuardError:
            raise
        except Exception:
            raise GuardError("guard tokenization failed") from None
        return _flat_ids(encoded, "guard tokenization failed")

    def _verdict(self, prompt_ids: list[int]) -> str:
        return _generated_verdict_text(
            self._model,
            self._tokenizer,
            prompt_ids,
            backend=self._backend,
            max_new_tokens=LLAMA_GUARD_VERDICT_TOKENS,
            eos_ids=self._eos_ids,
            accepted_eos=self._accepted_eos,
            pad_token_id=self._pad_token_id,
        )

    def scan_response(self, messages: list[dict[str, str]], output: str) -> dict[str, bool]:
        """Return ``{"safe": bool}`` for the complete context plus buffered output."""
        if not isinstance(messages, list) or not messages:
            raise GuardError("guard context is invalid")
        if not isinstance(output, str):
            raise GuardError("guard output is invalid")
        for message in messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                raise GuardError("guard context is invalid")
            role, content = message["role"], message["content"]
            if not isinstance(role, str) or role not in _ACCEPTED_ROLES or not isinstance(content, str):
                raise GuardError("guard context is invalid")
        conversation = [
            {"role": "user", "content": _serialize_context(messages)},
            {"role": "assistant", "content": output},
        ]
        with self._pool.slot():
            prompt_ids = self._template_ids(conversation)
            if len(prompt_ids) > self._prompt_limit:
                raise GuardError("guard context exceeds the configured window")
            verdict = self._verdict(prompt_ids)
        return {"safe": _parse_verdict(verdict)}
