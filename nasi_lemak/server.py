"""FastAPI ASGI gateway server.

The server is deliberately thin: it validates the HTTP surface, reads a bounded
raw body off the event loop, and hands synchronous guard/generation/audit work to
a worker thread.  All safety logic remains in ``Gateway``.

The application is fail-closed.  A missing or invalid configuration produces an
application that is live but not ready; protected chat requests return a generic
503.  No demo adapters, allow-all guards or environment-selected demo mode are
installed here.  Tests may inject an explicitly constructed ``Gateway``.

No docs, redoc, OpenAPI schema, debug page or trailing-slash redirect is exposed.
Request bodies are bounded while streaming, independently of Content-Length, and
concurrency is admitted before the body is read.  Raw exception text, request
bodies, credentials and DSNs are never returned or logged by this module.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from .admin_page import ADMIN_SECURITY_HEADERS, admin_html
from .audit import PostgresAuditStore, UnreadyAuditStore
from .demo_page import DEMO_SECURITY_HEADERS, demo_html
from .workspace_page import WORKSPACE_SECURITY_HEADERS, workspace_html
from .export import (
    EXPORT_FILENAME,
    ExportAuditEntry,
    ExportTooLarge,
    PostgresExportAuditLog,
    build_export_csv,
    sha256_hex,
    utc_iso,
)
from .gateway import Gateway, Policy
from .generation import (
    ENV_ALLOW_INSECURE_HTTP,
    ENV_API_KEY,
    ENV_AUTH,
    ENV_MODEL,
    ENV_URL,
    RealGatewayAdapters,
    TestGatewayAdapters,
)
from .guard_api import (
    INPUT_GUARD_CONTRACT_V1,
    InputGuardApiAdapter,
    Qwen3GuardOutputAdapter,
    guard_client_config,
)
from .limits import ChatLimits, ChatLimitsError, has_explicit_env
from .hosted_guards import (
    CLOUDFLARE_LLAMA_GUARD_MODEL,
    GROQ_PROMPT_GUARD_MODEL,
    CloudflareLlamaGuardOutputAdapter,
    GroqPromptGuardInputAdapter,
)
from .operator import (
    OperatorQueryError,
    PostgresAuditReader,
    parse_event_query,
    parse_export_query,
)
from .policy import load_policy
from .workspace_http import load_workspace_runtime, register_workspace_routes


# HTTP surface bounds.  The gateway itself has a 4096-character conversation
# limit; the body limit allows generous JSON overhead without unbounded memory.
DEFAULT_MAX_BODY_BYTES = 64 * 1024
MAX_CONFIGURED_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_BODY_READ_TIMEOUT = 5.0
MAX_CONFIGURED_BODY_READ_TIMEOUT = 60.0
# Absolute HTTP deadline for one dispatched chat worker (input guard, generation,
# output guard and terminal audit).  This is a response deadline only: it does
# not terminate the synchronous thread or add a native model deadline.
DEFAULT_CHAT_WORK_TIMEOUT = 60.0
MAX_CONFIGURED_CHAT_WORK_TIMEOUT = 300.0
DEFAULT_MAX_CONCURRENCY = 5
MAX_CONFIGURED_CONCURRENCY = 256
# Control-plane work (readiness probes and authenticated operator reads/writes)
# uses a separate, smaller bound than chat.  Exhaustion rejects immediately; no
# request waits in a queue.
DEFAULT_CONTROL_CONCURRENCY = 2
MAX_CONFIGURED_CONTROL_CONCURRENCY = 64
READINESS_TIMEOUT = 5.0
ADMIN_READ_TIMEOUT = 5.0
ADMIN_TOKEN_MAX_LENGTH = 4096

_ERROR_MESSAGES = {
    "INVALID_REQUEST": "Request is not supported.",
    "UNAUTHORIZED": "Authentication required.",
    "INPUT_LIMIT": "Request exceeds the supported input limit.",
    "UNAVAILABLE": "Required safety control is unavailable.",
    "POLICY_BLOCK": "Request did not pass safety checks.",
}

_ADAPTER_METHODS = ("count_tokens", "scan_attack", "generate", "scan_output")

# Explicit local guard configuration. There is deliberately no default Hub ID,
# download, cache fallback or demo adapter. The two model directories must
# already exist on disk and contain a compatible tokenizer/config/safetensors
# bundle obtained independently by the operator.
ENV_PROMPT_GUARD_MODEL_DIR = "NASI_LEMAK_PROMPT_GUARD_MODEL_DIR"
ENV_LLAMA_GUARD_MODEL_DIR = "NASI_LEMAK_LLAMA_GUARD_MODEL_DIR"
ENV_PROMPT_GUARD_THRESHOLD = "NASI_LEMAK_PROMPT_GUARD_THRESHOLD"
ENV_LLAMA_GUARD_CONTEXT_LIMIT = "NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT"

# Explicit guard backend selection.  ``local`` preserves the existing native
# Meta artifacts; ``api`` uses the versioned input contract plus the Qwen3Guard
# output adapter over dedicated guard clients; ``qwen3guard-local`` runs
# Qwen3Guard-Gen in-process for both slots.  No mixed backend and no silent
# fallback between them is supported.
ENV_GUARD_BACKEND = "NASI_LEMAK_GUARD_BACKEND"
GUARD_BACKEND_LOCAL = "local"
GUARD_BACKEND_API = "api"
GUARD_BACKEND_QWEN3GUARD = "qwen3guard-local"
GUARD_BACKENDS = (
    GUARD_BACKEND_LOCAL,
    GUARD_BACKEND_API,
    GUARD_BACKEND_QWEN3GUARD,
)

# Local Qwen3Guard-Gen contract.  Every setting is independent: no directory,
# threshold, URL or budget is inferred from another backend's value.  The
# thresholds default to the categorical severity floor (0.5) and can only
# tighten, never relax it.  Worker/thread defaults come from guard_pool.
ENV_QWEN3GUARD_MODEL_DIR = "NASI_LEMAK_QWEN3GUARD_MODEL_DIR"
ENV_QWEN3GUARD_INPUT_THRESHOLD = "NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD"
ENV_QWEN3GUARD_OUTPUT_THRESHOLD = "NASI_LEMAK_QWEN3GUARD_OUTPUT_THRESHOLD"
ENV_QWEN3GUARD_WORKERS = "NASI_LEMAK_QWEN3GUARD_WORKERS"
ENV_QWEN3GUARD_THREADS = "NASI_LEMAK_QWEN3GUARD_THREADS"
ENV_QWEN3GUARD_LONG_INPUT = "NASI_LEMAK_QWEN3GUARD_LONG_INPUT"

INPUT_GUARD_ENV_PREFIX = "NASI_LEMAK_INPUT_GUARD"
OUTPUT_GUARD_ENV_PREFIX = "NASI_LEMAK_OUTPUT_GUARD"
ENV_INPUT_GUARD_URL = f"{INPUT_GUARD_ENV_PREFIX}_URL"
ENV_INPUT_GUARD_MODEL = f"{INPUT_GUARD_ENV_PREFIX}_MODEL"
ENV_INPUT_GUARD_AUTH = f"{INPUT_GUARD_ENV_PREFIX}_AUTH"
ENV_INPUT_GUARD_API_KEY = f"{INPUT_GUARD_ENV_PREFIX}_API_KEY"
ENV_INPUT_GUARD_API_KEY_FILE = f"{INPUT_GUARD_ENV_PREFIX}_API_KEY_FILE"
ENV_INPUT_GUARD_THRESHOLD = f"{INPUT_GUARD_ENV_PREFIX}_THRESHOLD"
ENV_INPUT_GUARD_CONTRACT = f"{INPUT_GUARD_ENV_PREFIX}_CONTRACT"
ENV_INPUT_GUARD_PROVIDER = f"{INPUT_GUARD_ENV_PREFIX}_PROVIDER"
ENV_OUTPUT_GUARD_URL = f"{OUTPUT_GUARD_ENV_PREFIX}_URL"
ENV_OUTPUT_GUARD_MODEL = f"{OUTPUT_GUARD_ENV_PREFIX}_MODEL"
ENV_OUTPUT_GUARD_AUTH = f"{OUTPUT_GUARD_ENV_PREFIX}_AUTH"
ENV_OUTPUT_GUARD_API_KEY = f"{OUTPUT_GUARD_ENV_PREFIX}_API_KEY"
ENV_OUTPUT_GUARD_API_KEY_FILE = f"{OUTPUT_GUARD_ENV_PREFIX}_API_KEY_FILE"
ENV_OUTPUT_GUARD_PROVIDER = f"{OUTPUT_GUARD_ENV_PREFIX}_PROVIDER"

# Optional hosted provider pair.  Both selectors must be supplied together;
# leaving both unset preserves the existing gateway-owned input contract and
# Qwen3Guard output adapter.  No provider is inferred from a URL or model.
INPUT_GUARD_PROVIDER_GROQ = "groq-prompt-guard"
OUTPUT_GUARD_PROVIDER_CLOUDFLARE = "cloudflare-llama-guard"

ENV_POLICY_FILE = "NASI_LEMAK_POLICY_FILE"
ENV_OPERATOR_KEY_DIGEST = "NASI_LEMAK_OPERATOR_KEY_DIGEST"
ENV_OPERATOR_AUDIT_DSN = "NASI_LEMAK_OPERATOR_AUDIT_DSN"

ENV_MODE = "NASI_LEMAK_MODE"
ENV_ALLOW_UNGUARDED_TEST = "NASI_LEMAK_ALLOW_UNGUARDED_TEST"
MODE_GUARDED = "guarded"
MODE_TEST = "test"

OPERATOR_DISABLED = "disabled"
OPERATOR_READY = "ready"
OPERATOR_UNAVAILABLE = "unavailable"

POLICY_ACTIVATION_YAML = "yaml-policy"
POLICY_ACTIVATION_EXPLICIT = "explicit-policy-object"
POLICY_ACTIVATION_GATEWAY = "caller-injected gateway"
POLICY_ACTIVATION_UNAVAILABLE = "policy-unavailable"
# Kept as a compatibility alias for earlier imports. It no longer means that a
# built-in policy was activated: an unavailable policy is never substituted.
POLICY_ACTIVATION_PENDING = POLICY_ACTIVATION_UNAVAILABLE


class _BodyTooLarge(Exception):
    pass


class _BodyTimeout(Exception):
    pass


class _DuplicateKeys(Exception):
    pass


class _ChatBodyError(Exception):
    """The /chat testing shape is not the accepted ``{"prompt": str}`` form."""


def _error_payload(request_id: str, code: str) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": _ERROR_MESSAGES.get(code, _ERROR_MESSAGES["UNAVAILABLE"]),
            "request_id": request_id,
        }
    }


def _input_safety_label(result_sink: dict[str, Any]) -> str:
    """Coarse label for the validated input verdict; ``unknown`` if it did not run.

    The gateways expose only ``allow``/``block``; the categorical classifier
    severity is discarded by the adapters and is deliberately not invented.
    """
    decision = result_sink.get("input_decision")
    if decision == "allow":
        return "safe"
    if decision == "block":
        return "blocked"
    return "unknown"


def _output_safety_label(result_sink: dict[str, Any]) -> str:
    """Coarse label for the validated output verdict; ``unknown`` if it did not run."""
    value = result_sink.get("output_safe")
    if value is True:
        return "safe"
    if value is False:
        return "blocked"
    return "unknown"


def _sanitized_prompt(result_sink: dict[str, Any]) -> str | None:
    """Masked user text this request actually passed to generation.

    No masking is recomputed here: the value is read from the same request's
    pipeline sink, which is only populated once masking has already run.
    """
    messages = result_sink.get("sanitized_messages")
    if not isinstance(messages, list):
        return None
    parts = [
        message["content"]
        for message in messages
        if isinstance(message, dict)
        and message.get("role") == "user"
        and isinstance(message.get("content"), str)
    ]
    return "\n".join(parts) if parts else None


def _error_response(request_id: str, code: str, status_code: int) -> JSONResponse:
    return JSONResponse(_error_payload(request_id, code), status_code=status_code)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKeys(key)
        seen.add(key)
    return dict(pairs)


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON constant")


def _parse_json_object(raw: bytes) -> dict[str, Any] | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (_DuplicateKeys, json.JSONDecodeError, ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def _read_limited_body(request: Request, max_bytes: int, timeout: float) -> bytes:
    """Read the actual streamed bytes, bounded and with one complete deadline."""
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + timeout
    iterator = request.stream().__aiter__()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _BodyTimeout()
        try:
            chunk = await asyncio.wait_for(iterator.__anext__(), timeout=remaining)
        except StopAsyncIteration:
            break
        except asyncio.TimeoutError:
            raise _BodyTimeout() from None
        if not isinstance(chunk, (bytes, bytearray)):
            raise ValueError("invalid body chunk")
        total += len(chunk)
        if total > max_bytes:
            raise _BodyTooLarge()
        chunks.append(bytes(chunk))
    return b"".join(chunks)


def _is_hex_digest(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def _normalize_key_digest(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if _is_hex_digest(value) else None


def _file_env(name: str, environ: dict[str, str]) -> str | None:
    """Support Docker secrets via a _FILE suffix variable.

    An explicitly configured but unreadable secret file is a configuration
    failure; it never silently falls back to an inline value.
    """
    file_key = f"{name}_FILE"
    if file_key in environ:
        path = environ[file_key]
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except (OSError, UnicodeError, ValueError, TypeError):
            return None
    return environ.get(name)


def _valid_positive_int(value: Any, maximum: int) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and 1 <= value <= maximum
    )


def _valid_positive_float(value: Any, maximum: float) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and 0 < value <= maximum
    )


def _adapters_ready(adapters: Any) -> bool:
    if adapters is None:
        return False
    try:
        return all(callable(getattr(adapters, name, None)) for name in _ADAPTER_METHODS)
    except Exception:
        return False


def _gateway_static_ready(gateway: Gateway) -> bool:
    """Cheap structural checks only; no adapter, model or network probes."""
    try:
        store = getattr(gateway, "audit_store", None)
        policy = getattr(gateway, "policy", None)
        return (
            bool(getattr(gateway, "_key_valid", False))
            and _adapters_ready(getattr(gateway, "adapters", None))
            and callable(getattr(store, "ready", None))
            and isinstance(policy, Policy)
            and policy.model == "pilot-local"
            and policy.app_id == getattr(gateway, "app_id", None)
        )
    except Exception:
        return False


def _required_guard_setting(environ: dict[str, str], name: str) -> str:
    value = environ.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("required guard setting is missing")
    return value.strip()


def _existing_guard_directory(value: str) -> str:
    if "\x00" in value or "://" in value:
        raise ValueError("guard model directory is not a local path")
    try:
        path = Path(value).expanduser()
        if not path.is_dir():
            raise ValueError("guard model directory is unavailable")
    except (OSError, ValueError):
        raise ValueError("guard model directory is unavailable") from None
    return str(path)


def _guard_threshold(value: str) -> float:
    try:
        threshold = float(value)
    except (TypeError, ValueError):
        raise ValueError("guard threshold is invalid") from None
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("guard threshold is invalid")
    return threshold


def _guard_context_limit(value: str) -> int:
    try:
        limit = int(value, 10)
    except (TypeError, ValueError):
        raise ValueError("guard context limit is invalid") from None
    # LlamaGuard3 reserves its verdict tokens inside the effective context.
    if limit < 33:
        raise ValueError("guard context limit is invalid")
    return limit


def _qwen3guard_threshold(
    environ: dict[str, str], name: str, default: float
) -> float:
    """Validate one independent categorical severity floor (ceiling 0.5)."""
    raw = environ.get(name)
    if raw is None:
        return default
    if not isinstance(raw, str):
        raise ValueError("guard threshold is invalid")
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        raise ValueError("guard threshold is invalid") from None
    from .qwen3guard import validate_threshold

    try:
        return validate_threshold(parsed)
    except Exception:
        # A value above the controversial severity is invalid configuration,
        # not a laxer knob, and produces no adapter.
        raise ValueError("guard threshold is invalid") from None


def _qwen3guard_optional_int(environ: dict[str, str], name: str) -> int | None:
    """Parse an optional integer without inferring a default here."""
    raw = environ.get(name)
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise ValueError("guard worker budget is invalid")
    try:
        return int(raw, 10)
    except (TypeError, ValueError):
        raise ValueError("guard worker budget is invalid") from None


def _qwen3guard_long_input(environ: dict[str, str]) -> int:
    from .qwen3guard import (
        DEFAULT_LONG_INPUT_TOKENS,
        MAX_LONG_INPUT_TOKENS,
        MIN_LONG_INPUT_TOKENS,
    )

    raw = environ.get(ENV_QWEN3GUARD_LONG_INPUT)
    if raw is None:
        return DEFAULT_LONG_INPUT_TOKENS
    if not isinstance(raw, str):
        raise ValueError("guard input budget is invalid")
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        raise ValueError("guard input budget is invalid") from None
    if not MIN_LONG_INPUT_TOKENS <= value <= MAX_LONG_INPUT_TOKENS:
        raise ValueError("guard input budget is invalid")
    return value


def _qwen3guard_config(
    environ: dict[str, str],
) -> tuple[str, float, float, int, int, int]:
    """Validate every local Qwen3Guard setting before any loader runs.

    The directory, both thresholds, the explicit worker/thread budget and the
    long-input budget are all independent.  Nothing is inferred from a Meta
    guard directory, the API backend or another Qwen3Guard setting.  Any
    failure propagates to the caller, which returns no adapter.
    """
    from .guard_pool import resolve_inference_budget
    from .qwen3guard import DEFAULT_THRESHOLD

    directory = _existing_guard_directory(
        _required_guard_setting(environ, ENV_QWEN3GUARD_MODEL_DIR)
    )
    input_threshold = _qwen3guard_threshold(
        environ, ENV_QWEN3GUARD_INPUT_THRESHOLD, DEFAULT_THRESHOLD
    )
    output_threshold = _qwen3guard_threshold(
        environ, ENV_QWEN3GUARD_OUTPUT_THRESHOLD, DEFAULT_THRESHOLD
    )
    workers, threads = resolve_inference_budget(
        _qwen3guard_optional_int(environ, ENV_QWEN3GUARD_WORKERS),
        _qwen3guard_optional_int(environ, ENV_QWEN3GUARD_THREADS),
    )
    return (
        directory,
        input_threshold,
        output_threshold,
        workers,
        threads,
        _qwen3guard_long_input(environ),
    )


def _load_prompt_guard(directory: str, *, threshold: float) -> Any:
    from .guards import PromptGuard2

    return PromptGuard2(directory, threshold=threshold)


def _load_llama_guard(directory: str, *, context_limit: int) -> Any:
    from .guards import LlamaGuard3

    return LlamaGuard3(directory, context_limit=context_limit)


def _load_qwen3guard_local(
    directory: str,
    *,
    input_threshold: float,
    output_threshold: float,
    workers: int,
    threads: int,
    long_input: int,
) -> Any:
    from .qwen3_local import Qwen3GuardLocal

    return Qwen3GuardLocal(
        directory,
        input_threshold=input_threshold,
        output_threshold=output_threshold,
        workers=workers,
        threads=threads,
        long_input=long_input,
    )


def _load_generation_client(config: Any) -> Any:
    from .generation import GenerationClient

    return GenerationClient(config)


def _guard_backend(env: dict[str, str]) -> str:
    backend = env.get(ENV_GUARD_BACKEND, GUARD_BACKEND_LOCAL)
    if not isinstance(backend, str):
        return ""
    backend = backend.strip().lower()
    return backend if backend in GUARD_BACKENDS else ""


def _hosted_guard_providers(env: dict[str, str]) -> tuple[str, str]:
    """Return the explicit hosted provider pair, or two empty defaults.

    Defaults apply only when BOTH selector variables are absent (``None``).
    An explicitly supplied empty or whitespace-only pair is invalid, as is a
    single selector, an unknown value, a mixed value or a non-string.  This
    runs before config/key-file reads and before any client loader.
    """
    input_provider = env.get(ENV_INPUT_GUARD_PROVIDER)
    output_provider = env.get(ENV_OUTPUT_GUARD_PROVIDER)
    if input_provider is None and output_provider is None:
        return "", ""
    if not isinstance(input_provider, str) or not isinstance(output_provider, str):
        raise ValueError("guard provider selection is not supported")
    input_provider = input_provider.strip()
    output_provider = output_provider.strip()
    if (
        input_provider == INPUT_GUARD_PROVIDER_GROQ
        and output_provider == OUTPUT_GUARD_PROVIDER_CLOUDFLARE
    ):
        return input_provider, output_provider
    raise ValueError("guard provider selection is not supported")


def _api_guard_config(
    env: dict[str, str],
) -> tuple[Any, Any, float, str, str]:
    """Validate every API guard setting before any client is constructed.

    The hosted pair ignores the gateway-owned input contract, requires exact
    approved model IDs and bearer auth on both dedicated guard configs, and
    creates no fallback for a missing or invalid selection.  The default pair
    still requires the version-1 input contract.
    """
    input_provider, output_provider = _hosted_guard_providers(env)
    if not input_provider:
        contract = env.get(ENV_INPUT_GUARD_CONTRACT)
        if not isinstance(contract, str) or contract.strip() != INPUT_GUARD_CONTRACT_V1:
            raise ValueError("input guard contract is not supported")
    threshold = _guard_threshold(
        _required_guard_setting(env, ENV_INPUT_GUARD_THRESHOLD)
    )
    input_config = guard_client_config(env, INPUT_GUARD_ENV_PREFIX)
    output_config = guard_client_config(env, OUTPUT_GUARD_ENV_PREFIX)
    if input_provider:
        if input_config.auth_mode != "bearer" or output_config.auth_mode != "bearer":
            raise ValueError("hosted guard providers require bearer auth")
        if (
            input_config.model != GROQ_PROMPT_GUARD_MODEL
            or output_config.model != CLOUDFLARE_LLAMA_GUARD_MODEL
        ):
            raise ValueError("hosted guard model is not supported")
    return input_config, output_config, threshold, input_provider, output_provider


def _mode_from_env(env: dict[str, str]) -> str:
    mode = env.get(ENV_MODE, MODE_GUARDED).strip().lower()
    return mode if mode in (MODE_GUARDED, MODE_TEST) else ""


def _test_acknowledged(env: dict[str, str]) -> bool:
    return env.get(ENV_ALLOW_UNGUARDED_TEST, "").strip().lower() == "true"


def make_adapters_from_env(
    environ: dict[str, str] | None = None,
    *,
    prompt_guard_loader: Any = None,
    llama_guard_loader: Any = None,
    qwen3guard_loader: Any = None,
    client_loader: Any = None,
) -> Any:
    """Build real local guard/generation adapters from server-side settings.

    The keyword loader arguments are an explicit test seam only. They must not
    be used as evidence that a pretrained checkpoint was executed. Production
    calls use the lazy default loaders, and every model directory must already
    exist locally. Missing files, optional ML dependencies, an invalid config
    or a failed load returns ``None`` (the server then stays explicitly
    unavailable). No model is downloaded, no demo/allow-all adapter is
    substituted, and no secret, path or raw exception is returned or logged.

    Required settings:

    * ``NASI_LEMAK_MODE``: ``guarded`` (default) or ``test``.
    * For ``test``: explicit ``NASI_LEMAK_ALLOW_UNGUARDED_TEST=true`` plus a
      valid generation configuration.
    * ``NASI_LEMAK_GUARD_BACKEND``: ``local`` (default), ``api`` or
      ``qwen3guard-local``. Unknown or partial values return ``None``; there is
      no fallback between backends.
    * For ``guarded`` + ``local``: ``NASI_LEMAK_GENERATION_URL`` and
      ``NASI_LEMAK_GENERATION_MODEL`` (plus the existing auth settings),
      ``NASI_LEMAK_PROMPT_GUARD_MODEL_DIR``, ``NASI_LEMAK_LLAMA_GUARD_MODEL_DIR``,
      ``NASI_LEMAK_PROMPT_GUARD_THRESHOLD`` and
      ``NASI_LEMAK_LLAMA_GUARD_CONTEXT_LIMIT``.
    * For ``guarded`` + ``qwen3guard-local``: the same generation settings plus
      ``NASI_LEMAK_QWEN3GUARD_MODEL_DIR`` (required). Optional, independent
      settings are ``NASI_LEMAK_QWEN3GUARD_INPUT_THRESHOLD`` and
      ``..._OUTPUT_THRESHOLD`` (default 0.5, valid range 0.0..0.5),
      ``..._WORKERS`` and ``..._THREADS`` (defaults derived from the CPU count
      by :mod:`nasi_lemak.guard_pool`) and ``..._LONG_INPUT`` (default 8192,
      minimum 512, maximum 32768). No Meta guard directory, URL or threshold is
      read on this path, and every value is validated before the loader runs.
    * For ``guarded`` + ``api``: the same generation settings plus explicit
      ``NASI_LEMAK_INPUT_GUARD_{URL,MODEL,AUTH,THRESHOLD,CONTRACT}`` and
      ``NASI_LEMAK_OUTPUT_GUARD_{URL,MODEL,AUTH}``, each with exactly one of
      ``..._API_KEY`` or ``..._API_KEY_FILE`` when auth is ``bearer``. No local
      guard directories or ML dependencies are required or loaded.
    * Optional hosted pair: set both ``NASI_LEMAK_INPUT_GUARD_PROVIDER=
      groq-prompt-guard`` and ``NASI_LEMAK_OUTPUT_GUARD_PROVIDER=
      cloudflare-llama-guard``. The models must be exactly
      ``meta-llama/llama-prompt-guard-2-86m`` and
      ``@cf/meta/llama-guard-3-8b``, both auth modes must be ``bearer``, and
      the input contract is not required. One selector, an unknown value or a
      different model leaves the app unready before any loader or network call.
    """
    env = os.environ if environ is None else environ
    mode = _mode_from_env(env)
    if mode == "":
        return None
    backend = _guard_backend(env)
    if backend == "":
        return None

    # Cheap admission checks run before any model/client loader is invoked.
    # A missing test acknowledgement or invalid generation configuration must
    # never touch disk- or network-backed loaders (including optional ML deps).
    if mode == MODE_TEST and not _test_acknowledged(env):
        return None

    try:
        from .generation import GenerationConfig

        config = GenerationConfig.from_env(env)
        if not config.model:
            raise ValueError("generation model is required")
    except Exception:
        return None

    generation_loader = client_loader or _load_generation_client

    if mode == MODE_GUARDED and backend == GUARD_BACKEND_API:
        # API backend: validate the provider selection, contract/threshold and
        # both dedicated configs (including explicit key files) before any
        # client loader runs.  It requires no local guard artifact directories
        # or ML imports.  A hosted selection has no fallback to the default
        # custom-input/Qwen-output pair.
        try:
            (
                input_config,
                output_config,
                threshold,
                input_provider,
                output_provider,
            ) = _api_guard_config(env)
            input_client = generation_loader(input_config)
            output_client = generation_loader(output_config)
            client = generation_loader(config)
            if input_provider and output_provider:
                input_guard = GroqPromptGuardInputAdapter(
                    input_client, threshold=threshold
                )
                output_guard = CloudflareLlamaGuardOutputAdapter(output_client)
            else:
                input_guard = InputGuardApiAdapter(
                    input_client, threshold=threshold
                )
                output_guard = Qwen3GuardOutputAdapter(output_client)
            return RealGatewayAdapters(
                client,
                tokenizer=input_guard,
                attack_guard=input_guard,
                output_guard=output_guard,
            )
        except Exception:
            return None

    if mode == MODE_GUARDED and backend == GUARD_BACKEND_QWEN3GUARD:
        # Local Qwen3Guard-Gen: validate every dedicated setting before any
        # loader, then build one causal guard shared by the tokenizer, attack
        # and output slots.  A failure at any stage yields no adapter; the Meta
        # directories and the API settings are never consulted.
        try:
            (
                qwen_directory,
                qwen_input_threshold,
                qwen_output_threshold,
                qwen_workers,
                qwen_threads,
                qwen_long_input,
            ) = _qwen3guard_config(env)
        except Exception:
            return None
        try:
            client = generation_loader(config)
        except Exception:
            return None
        try:
            guard_loader = qwen3guard_loader or _load_qwen3guard_local
            guard = guard_loader(
                qwen_directory,
                input_threshold=qwen_input_threshold,
                output_threshold=qwen_output_threshold,
                workers=qwen_workers,
                threads=qwen_threads,
                long_input=qwen_long_input,
            )
            return RealGatewayAdapters(
                client,
                tokenizer=guard,
                attack_guard=guard,
                output_guard=guard,
            )
        except Exception:
            return None

    prompt_dir: str | None = None
    llama_dir: str | None = None
    threshold: float | None = None
    context_limit: int | None = None
    if mode == MODE_GUARDED:
        # Guarded mode: every local artifact and setting is mandatory, and all
        # of them are validated before either guard/model loader runs.
        try:
            prompt_dir = _existing_guard_directory(
                _required_guard_setting(env, ENV_PROMPT_GUARD_MODEL_DIR)
            )
            llama_dir = _existing_guard_directory(
                _required_guard_setting(env, ENV_LLAMA_GUARD_MODEL_DIR)
            )
            threshold = _guard_threshold(
                _required_guard_setting(env, ENV_PROMPT_GUARD_THRESHOLD)
            )
            context_limit = _guard_context_limit(
                _required_guard_setting(env, ENV_LLAMA_GUARD_CONTEXT_LIMIT)
            )
        except Exception:
            return None

    generation_loader = client_loader or _load_generation_client
    try:
        client = generation_loader(config)
    except Exception:
        return None

    if mode == MODE_TEST:
        try:
            return TestGatewayAdapters(client)
        except Exception:
            return None

    try:
        prompt_loader = prompt_guard_loader or _load_prompt_guard
        llama_loader = llama_guard_loader or _load_llama_guard
        prompt_guard = prompt_loader(prompt_dir, threshold=threshold)
        llama_guard = llama_loader(llama_dir, context_limit=context_limit)
        return RealGatewayAdapters(
            client,
            tokenizer=prompt_guard,
            attack_guard=prompt_guard,
            output_guard=llama_guard,
        )
    except Exception:
        return None


def _clone_gateway_with_limits(gateway: Gateway, limits: ChatLimits) -> Gateway:
    """Return an app-owned Gateway sharing the injected safety dependencies.

    The injected object is never mutated: test fixtures and other applications
    can keep using it with their original limits.
    """
    if not isinstance(gateway, Gateway):
        raise ValueError("invalid gateway")
    digest = getattr(gateway, "_key_digest", None)
    if (
        not getattr(gateway, "_key_valid", False)
        or not isinstance(digest, (bytes, bytearray))
        or len(digest) != 32
    ):
        raise ValueError("invalid gateway key")
    return Gateway(
        key_digest=bytes(digest).hex(),
        audit_store=gateway.audit_store,
        adapters=gateway.adapters,
        policy=gateway.policy,
        app_id=gateway.app_id,
        limits=limits,
    )


def _build_runtime_gateway(
    environ: dict[str, str],
    app_key_digest: str | None,
    audit_dsn: str | None,
    adapters: Any,
    policy: Policy | None,
    app_id: str,
    limits: ChatLimits | None = None,
) -> tuple[Gateway, bool, str]:
    config_ready = True
    activation = POLICY_ACTIVATION_UNAVAILABLE

    # Resolve the cheap policy first. A missing, unreadable or invalid file must
    # never trigger expensive guard/model loading or activate built-in defaults.
    resolved: Policy | None = None
    if isinstance(policy, Policy):
        # Explicit Python test seam: this object is the server-side identity.
        resolved = policy
        activation = POLICY_ACTIVATION_EXPLICIT
    elif policy is not None:
        # A supplied but invalid policy is a configuration failure. Do not
        # silently replace it with a valid one while claiming readiness.
        config_ready = False
    else:
        try:
            resolved = load_policy(environ.get(ENV_POLICY_FILE))
            activation = POLICY_ACTIVATION_YAML
        except Exception:
            # Includes missing/unreadable/invalid files and a missing loader
            # dependency.  Never fall back to built-in defaults.
            resolved = None

    if resolved is None:
        config_ready = False
        resolved = Policy()
        activation = POLICY_ACTIVATION_UNAVAILABLE
    elif activation == POLICY_ACTIVATION_YAML:
        # Production startup binds YAML identity to the server-side app config.
        if not isinstance(app_id, str) or not app_id or resolved.app_id != app_id:
            config_ready = False
            resolved = Policy()
            activation = POLICY_ACTIVATION_UNAVAILABLE
    elif not isinstance(app_id, str) or not app_id:
        config_ready = False

    # For an explicit policy the policy itself is the trusted identity source;
    # ``app_id`` remains a validated server-side setting for YAML activation.
    gateway_app_id = resolved.app_id

    digest = _normalize_key_digest(app_key_digest)
    if digest is None:
        config_ready = False
        digest = "0" * 64

    if audit_dsn:
        try:
            audit_store = PostgresAuditStore(audit_dsn)
        except Exception:
            audit_store = UnreadyAuditStore()
            config_ready = False
    else:
        audit_store = UnreadyAuditStore()
        config_ready = False

    if adapters is None and activation != POLICY_ACTIVATION_UNAVAILABLE:
        try:
            adapters = make_adapters_from_env(environ)
        except Exception:
            adapters = None
    if not _adapters_ready(adapters):
        config_ready = False

    try:
        gateway = Gateway(
            key_digest=digest,
            audit_store=audit_store,
            adapters=adapters,
            policy=resolved,
            app_id=gateway_app_id,
            limits=limits,
        )
    except Exception:
        config_ready = False
        activation = POLICY_ACTIVATION_UNAVAILABLE
        gateway = Gateway(
            key_digest="0" * 64,
            audit_store=UnreadyAuditStore(),
            adapters=None,
            policy=Policy(),
            limits=limits,
        )

    if not _gateway_static_ready(gateway):
        config_ready = False
    return gateway, config_ready, activation


class _OperatorState:
    """Resolved operator configuration; never rendered or serialized directly."""

    __slots__ = ("mode", "digest", "reader")

    def __init__(
        self,
        mode: str,
        digest: bytes | None = None,
        reader: Any = None,
    ) -> None:
        self.mode = mode
        self.digest = digest
        self.reader = reader


def _resolve_operator(
    environ: dict[str, str],
    gateway: Gateway,
    explicit_digest: str | None,
    explicit_reader: Any,
    runtime_dsn: str | None,
) -> _OperatorState:
    """Resolve the optional operator view without affecting chat readiness.

    Absent configuration disables the routes (safe 404).  A partial or invalid
    configuration disables them with a safe 503; it never makes chat unavailable.
    The operator key must be a distinct digest, and the reader DSN must differ
    from the runtime writer DSN.
    """
    explicitly_configured = explicit_digest is not None or explicit_reader is not None
    if explicitly_configured:
        raw_digest = explicit_digest
        reader = explicit_reader
        dsn = None
    else:
        configured = any(
            name in environ
            for name in (
                ENV_OPERATOR_KEY_DIGEST,
                f"{ENV_OPERATOR_KEY_DIGEST}_FILE",
                ENV_OPERATOR_AUDIT_DSN,
                f"{ENV_OPERATOR_AUDIT_DSN}_FILE",
            )
        )
        if not configured:
            return _OperatorState(OPERATOR_DISABLED)
        raw_digest = _file_env(ENV_OPERATOR_KEY_DIGEST, environ)
        dsn = _file_env(ENV_OPERATOR_AUDIT_DSN, environ)
        reader = None

    digest_hex = _normalize_key_digest(raw_digest)
    if digest_hex is None:
        return _OperatorState(OPERATOR_UNAVAILABLE)
    digest = bytes.fromhex(digest_hex)
    if bool(getattr(gateway, "_key_valid", False)) and hmac.compare_digest(
        digest, gateway._key_digest
    ):
        # The chat and operator credentials are separate authority boundaries.
        return _OperatorState(OPERATOR_UNAVAILABLE)

    if reader is None:
        if not isinstance(dsn, str) or not dsn.strip():
            return _OperatorState(OPERATOR_UNAVAILABLE)
        dsn = dsn.strip()
        if isinstance(runtime_dsn, str) and dsn == runtime_dsn.strip():
            return _OperatorState(OPERATOR_UNAVAILABLE)
        try:
            reader = PostgresAuditReader(dsn)
        except Exception:
            return _OperatorState(OPERATOR_UNAVAILABLE)
    if not callable(getattr(reader, "fetch_page", None)):
        return _OperatorState(OPERATOR_UNAVAILABLE)
    return _OperatorState(OPERATOR_READY, digest, reader)


def _resolve_export_log(
    explicit_log: Any,
    runtime_writer_dsn: str | None,
    *,
    allow_runtime_postgres: bool,
) -> Any:
    """Resolve the append-only export-audit writer without affecting chat.

    An explicit injected writer is the only seam local tests/demo may use.  The
    production path (no injected gateway) reuses the existing runtime writer DSN
    and constructs the PostgreSQL writer lazily; a missing or invalid setup
    leaves the export route unavailable.  No in-memory fallback exists.
    """
    if explicit_log is not None:
        if callable(getattr(explicit_log, "record", None)):
            return explicit_log
        return None
    if not allow_runtime_postgres:
        return None
    if not isinstance(runtime_writer_dsn, str) or not runtime_writer_dsn.strip():
        return None
    try:
        return PostgresExportAuditLog(runtime_writer_dsn.strip())
    except Exception:
        return None


# Shared "HTTP deadline expired" sentinel returned by _await_control_call for
# both control-plane work and dispatched chat work.
_CONTROL_TIMEOUT = object()


class _ControlPlaneAdmission:
    """Bounded, non-queuing admission for synchronous control-plane work.

    ``asyncio.to_thread`` cannot stop a running thread.  A slot therefore stays
    held until the real synchronous call returns, even after the HTTP request
    has timed out or been cancelled.  This bounds concurrent worker dispatch; it
    is not thread termination or a native-model timeout.
    """

    __slots__ = ("_limit", "_in_use", "_tasks")

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._in_use = 0
        self._tasks: set[asyncio.Task] = set()

    @property
    def in_use(self) -> int:
        return self._in_use

    def try_acquire(self) -> bool:
        """Reserve one slot or reject immediately; never wait for capacity."""
        if self._in_use >= self._limit:
            return False
        self._in_use += 1
        return True

    async def run(self, func: Any, *args: Any, timeout: float) -> Any:
        """Dispatch one synchronous call and wait at most ``timeout`` seconds.

        Returns ``_CONTROL_TIMEOUT`` when the deadline expires.  The slot is
        still held then and is released by the done callback only when the
        thread really finishes.  Cancellation is deferred until the thread
        finishes or the original deadline expires, whichever comes first; a
        remembered ``CancelledError`` is then re-raised instead of the sentinel.
        """
        task = asyncio.create_task(asyncio.to_thread(func, *args))
        self._tasks.add(task)
        released = False

        def finish(done: "asyncio.Task") -> None:
            nonlocal released
            if not released:
                released = True
                self._tasks.discard(done)
                if self._in_use > 0:
                    self._in_use -= 1
            try:
                done.exception()
            except BaseException:
                pass

        task.add_done_callback(finish)
        return await _await_control_call(task, timeout, finish)


async def _await_control_call(task: "asyncio.Task", timeout: float, finish: Any) -> Any:
    """Wait for a shielded worker, retaining its slot across timeout/cancel.

    Shared by control-plane admission and the dispatched chat worker.  A timeout
    returns ``_CONTROL_TIMEOUT`` without cancelling the worker; the done callback
    (or ``finish``) releases the slot on real completion.  Repeated client
    cancellation is deferred until the worker finishes or the original deadline
    expires, whichever comes first.  A remembered cancellation is re-raised at
    that point (never replaced by the sentinel or a late worker result/error),
    while the shielded worker keeps its slot until it really finishes.
    """
    cancelled = False
    deadline = time.monotonic() + timeout
    while True:
        if task.done():
            finish(task)
            if cancelled:
                raise asyncio.CancelledError()
            return task.result()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if cancelled:
                raise asyncio.CancelledError()
            return _CONTROL_TIMEOUT
        try:
            result = await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
        except asyncio.TimeoutError:
            if task.done():
                # The worker itself raised ``TimeoutError``; it is a real
                # exception, not this deadline.
                finish(task)
                if cancelled:
                    raise asyncio.CancelledError()
                raise
            if cancelled:
                raise asyncio.CancelledError()
            return _CONTROL_TIMEOUT
        except asyncio.CancelledError:
            cancelled = True
            continue
        except BaseException:
            finish(task)
            if cancelled:
                raise asyncio.CancelledError()
            raise
        finish(task)
        if cancelled:
            raise asyncio.CancelledError()
        return result


async def _runtime_ready(
    gateway: Gateway,
    config_ready: bool,
    admission: _ControlPlaneAdmission,
) -> bool:
    """Bounded structural plus audit-store readiness check.

    Admission is non-blocking and shared with the authenticated operator routes.
    A saturated or timed-out probe reports not-ready without dispatching another
    worker thread.  Once acquired, the slot is held until the synchronous
    readiness call really finishes.
    """
    if not config_ready or not _gateway_static_ready(gateway):
        return False
    if not admission.try_acquire():
        return False
    try:
        result = await admission.run(
            gateway.audit_store.ready,
            timeout=READINESS_TIMEOUT,
        )
    except Exception:
        return False
    return result is True


def make_app(
    *,
    gateway: Gateway | None = None,
    app_key_digest: str | None = None,
    audit_dsn: str | None = None,
    adapters: Any = None,
    policy: Policy | None = None,
    operator_key_digest: str | None = None,
    operator_reader: Any = None,
    export_log: Any = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    body_read_timeout: float = DEFAULT_BODY_READ_TIMEOUT,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
    control_concurrency: int = DEFAULT_CONTROL_CONCURRENCY,
    chat_work_timeout: float = DEFAULT_CHAT_WORK_TIMEOUT,
    app_id: str = "nasi-lemak",
    environ: dict[str, str] | None = None,
    workspace_store: Any = None,
) -> FastAPI:
    """Create the FastAPI application.

    Production configuration comes from the environment.  Without an injected
    ``Gateway`` or explicit ``Policy``, ``NASI_LEMAK_POLICY_FILE`` must name one
    valid versioned YAML policy; otherwise the app is live but not ready.  A
    ``Gateway`` or ``Policy`` may be injected explicitly for local synthetic
    tests; that is not a demo mode and never changes the default fail-closed
    behaviour.  Policy activation happens only here, at construction.
    """
    env = os.environ if environ is None else environ

    # Parse the shared chat limits exactly once.  An explicit invalid value is
    # a configuration failure: the app stays live but not ready, so it can
    # report the problem without ever silently substituting a wider window.
    try:
        chat_limits = ChatLimits.from_env(env)
        chat_limits_ok = True
    except ChatLimitsError:
        chat_limits = ChatLimits.defaults()
        chat_limits_ok = False

    numeric_ok = (
        _valid_positive_int(max_body_bytes, MAX_CONFIGURED_BODY_BYTES)
        and _valid_positive_float(body_read_timeout, MAX_CONFIGURED_BODY_READ_TIMEOUT)
        and _valid_positive_int(max_concurrency, MAX_CONFIGURED_CONCURRENCY)
        and _valid_positive_int(control_concurrency, MAX_CONFIGURED_CONTROL_CONCURRENCY)
        and _valid_positive_float(chat_work_timeout, MAX_CONFIGURED_CHAT_WORK_TIMEOUT)
    )
    # Invalid numeric configuration must not crash startup.  Use safe defaults
    # for the live-but-not-ready application; readiness and chat stay closed.
    body_limit = max_body_bytes if _valid_positive_int(max_body_bytes, MAX_CONFIGURED_BODY_BYTES) else DEFAULT_MAX_BODY_BYTES
    read_timeout = body_read_timeout if _valid_positive_float(body_read_timeout, MAX_CONFIGURED_BODY_READ_TIMEOUT) else DEFAULT_BODY_READ_TIMEOUT
    concurrency = max_concurrency if _valid_positive_int(max_concurrency, MAX_CONFIGURED_CONCURRENCY) else DEFAULT_MAX_CONCURRENCY
    control_limit = control_concurrency if _valid_positive_int(control_concurrency, MAX_CONFIGURED_CONTROL_CONCURRENCY) else DEFAULT_CONTROL_CONCURRENCY
    chat_timeout = chat_work_timeout if _valid_positive_float(chat_work_timeout, MAX_CONFIGURED_CHAT_WORK_TIMEOUT) else DEFAULT_CHAT_WORK_TIMEOUT

    runtime_writer_dsn = (
        _file_env("NASI_LEMAK_AUDIT_DSN", env) if audit_dsn is None else audit_dsn
    )
    explicit_chat_limits = has_explicit_env(env)
    if gateway is not None:
        runtime_gateway = gateway
        config_ready = True
        policy_activation = POLICY_ACTIVATION_GATEWAY
        if explicit_chat_limits and chat_limits_ok:
            # An explicit environment setting is app-owned configuration.  Build
            # a clone instead of mutating a caller/fixture Gateway in place.
            try:
                runtime_gateway = _clone_gateway_with_limits(gateway, chat_limits)
            except Exception:
                runtime_gateway = gateway
                config_ready = False
        elif explicit_chat_limits:
            config_ready = False
    else:
        runtime_gateway, config_ready, policy_activation = _build_runtime_gateway(
            env,
            _file_env("NASI_LEMAK_APP_KEY_DIGEST", env) if app_key_digest is None else app_key_digest,
            runtime_writer_dsn,
            adapters,
            policy,
            app_id,
            limits=chat_limits,
        )
    # An unknown mode is never treated as guarded or test. It keeps the app
    # live but not ready, and the header/admin surface must not imply either
    # supported safety posture.
    valid_mode = _mode_from_env(env)
    config_ready = config_ready and numeric_ok and valid_mode != "" and chat_limits_ok

    operator_state = _resolve_operator(
        env,
        runtime_gateway,
        operator_key_digest,
        operator_reader,
        runtime_writer_dsn,
    )
    export_log_state = _resolve_export_log(
        export_log,
        runtime_writer_dsn,
        allow_runtime_postgres=gateway is None,
    )
    workspace_runtime = load_workspace_runtime(
        env,
        store=workspace_store,
        gateway=runtime_gateway,
        audit_writer_dsn=runtime_writer_dsn,
        audit_reader_dsn=_file_env(ENV_OPERATOR_AUDIT_DSN, env),
        chat_work_timeout=chat_timeout,
    )
    if workspace_runtime.enabled and not chat_limits_ok:
        # The workspace has its own readiness component; make invalid shared
        # limits close it as well, before any provider work can be dispatched.
        workspace_runtime.ready = False
        workspace_runtime.error = "chat limits configuration is invalid"

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        store = getattr(getattr(_app.state, "gateway", None), "audit_store", None)
        close = getattr(store, "close", None)
        if callable(close):
            try:
                await asyncio.to_thread(close)
            except Exception:
                # Shutdown cleanup is best effort and never emits a traceback.
                pass
        reader = getattr(getattr(_app.state, "operator", None), "reader", None)
        reader_close = getattr(reader, "close", None)
        if callable(reader_close):
            try:
                await asyncio.to_thread(reader_close)
            except Exception:
                pass
        export_writer = getattr(_app.state, "export_log", None)
        export_close = getattr(export_writer, "close", None)
        if callable(export_close):
            try:
                await asyncio.to_thread(export_close)
            except Exception:
                pass
        workspace = getattr(_app.state, "workspace", None)
        workspace_store = getattr(workspace, "store", None)
        workspace_close = getattr(workspace_store, "close", None)
        if callable(workspace_close):
            try:
                await asyncio.to_thread(workspace_close)
            except Exception:
                pass

    configured_mode = valid_mode or "invalid"
    guards_active = (
        isinstance(getattr(runtime_gateway, "adapters", None), RealGatewayAdapters)
        and configured_mode == MODE_GUARDED
    )

    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        debug=False,
        redirect_slashes=False,
        lifespan=lifespan,
    )
    app.state.gateway = runtime_gateway
    app.state.config_ready = config_ready
    app.state.policy_activation = policy_activation
    app.state.operator = operator_state
    app.state.export_log = export_log_state
    policy_active = policy_activation != POLICY_ACTIVATION_UNAVAILABLE
    app.state.policy_digest = runtime_gateway.policy.digest if policy_active else None
    app.state.policy_version = runtime_gateway.policy.version if policy_active else None
    app.state.max_body_bytes = body_limit
    app.state.body_read_timeout = read_timeout
    app.state.max_concurrency = concurrency
    app.state.sem = asyncio.Semaphore(concurrency)
    app.state.control_concurrency = control_limit
    app.state.control_admission = _ControlPlaneAdmission(control_limit)
    app.state.chat_work_timeout = chat_timeout
    app.state.mode = configured_mode
    app.state.guards_active = guards_active
    # Retain a strong reference to every dispatched chat worker task so a
    # timed-out request cannot let the task be garbage-collected while its
    # thread still runs.  The done callback removes it only on real completion.
    app.state.chat_tasks: set[asyncio.Task] = set()
    app.state.workspace = workspace_runtime
    app.state.workspace_tasks: set[asyncio.Task] = set()

    @app.middleware("http")
    async def assign_request_id(request: Request, call_next):
        request_id = "req_" + uuid.uuid4().hex
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            # Convert unexpected failures before the ASGI server can log raw
            # exception text.  The response carries no body or provider detail.
            response = _error_response(request_id, "UNAVAILABLE", 503)
        response.headers["X-Nasi-Lemak-Mode"] = request.app.state.mode
        response.headers["X-Nasi-Lemak-Guards-Active"] = (
            "true" if request.app.state.guards_active else "false"
        )
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        request_id = getattr(request.state, "request_id", "req_unknown")
        status_code = exc.status_code if exc.status_code in (404, 405) else 400
        return _error_response(request_id, "INVALID_REQUEST", status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        request_id = getattr(request.state, "request_id", "req_unknown")
        return _error_response(request_id, "INVALID_REQUEST", 400)

    @app.get("/")
    async def demo_page(request: Request):
        # The shell is available even while the gateway is unready so the page
        # itself can report the real mode/readiness from /health/ready.
        html = demo_html(
            mode=request.app.state.mode,
            guards_active=request.app.state.guards_active,
        )
        return HTMLResponse(html, headers=DEMO_SECURITY_HEADERS)

    @app.get("/health/live")
    async def health_live(request: Request):
        return {"status": "ok"}

    @app.get("/health/ready")
    async def health_ready(request: Request):
        ready = await _runtime_ready(
            request.app.state.gateway,
            request.app.state.config_ready,
            request.app.state.control_admission,
        )
        payload = {
            "status": "ready" if ready else "not_ready",
            "mode": request.app.state.mode,
            "guards_active": request.app.state.guards_active,
        }
        workspace = getattr(request.app.state, "workspace", None)
        if workspace is not None and workspace.enabled:
            workspace_ready = await workspace.check_ready(
                request.app.state.control_admission
            )
            payload["workspace"] = "ready" if workspace_ready else "not_ready"
            # Fixed-key, content-free counters only; never prompt, response,
            # provider payload or credential material.
            payload["diagnostics"] = workspace.diagnostics.snapshot()
            if not workspace_ready:
                ready = False
                payload["status"] = "not_ready"
        if ready:
            return payload
        return JSONResponse(payload, status_code=503)

    def admin_error(request: Request, status_code: int, code: str) -> JSONResponse:
        response = _error_response(request.state.request_id, code, status_code)
        response.headers.update(ADMIN_SECURITY_HEADERS)
        return response

    def operator_auth_error(request: Request, state: Any) -> JSONResponse | None:
        """Shared exact operator bearer check for every operator data route.

        Authentication runs before any reader call, export snapshot or audit
        write.  There is deliberately no query-string or weaker alternative.
        """
        auth_headers = request.headers.getlist("authorization")
        if len(auth_headers) != 1:
            return admin_error(request, 401, "UNAUTHORIZED")
        supplied = auth_headers[0]
        if not isinstance(supplied, str) or not supplied.startswith("Bearer "):
            return admin_error(request, 401, "UNAUTHORIZED")
        candidate = supplied[7:]
        if not candidate or len(candidate) > ADMIN_TOKEN_MAX_LENGTH:
            return admin_error(request, 401, "UNAUTHORIZED")
        try:
            candidate_digest = hashlib.sha256(candidate.encode("utf-8")).digest()
        except UnicodeError:
            return admin_error(request, 401, "UNAUTHORIZED")
        if state.digest is None or not hmac.compare_digest(candidate_digest, state.digest):
            return admin_error(request, 401, "UNAUTHORIZED")
        return None

    @app.get("/admin")
    async def admin_page(request: Request):
        state = getattr(request.app.state, "operator", None)
        if state is None or state.mode == OPERATOR_DISABLED:
            return admin_error(request, 404, "INVALID_REQUEST")
        if state.mode != OPERATOR_READY:
            return admin_error(request, 503, "UNAVAILABLE")
        html = admin_html(
            mode=request.app.state.mode,
            guards_active=request.app.state.guards_active,
        )
        return HTMLResponse(html, headers=ADMIN_SECURITY_HEADERS)

    @app.get("/admin/events")
    async def admin_events(request: Request):
        state = getattr(request.app.state, "operator", None)
        if state is None or state.mode == OPERATOR_DISABLED:
            return admin_error(request, 404, "INVALID_REQUEST")
        if state.mode != OPERATOR_READY:
            return admin_error(request, 503, "UNAVAILABLE")

        auth_error = operator_auth_error(request, state)
        if auth_error is not None:
            return auth_error

        try:
            filters = parse_event_query(request.query_params.multi_items())
        except OperatorQueryError:
            return admin_error(request, 400, "INVALID_REQUEST")

        # Authentication and query validation are complete before admission, so
        # unauthenticated or malformed traffic never consumes control-plane
        # capacity or dispatches a reader thread.
        admission = request.app.state.control_admission
        if not admission.try_acquire():
            return admin_error(request, 503, "UNAVAILABLE")

        try:
            page = await admission.run(
                state.reader.fetch_page,
                request.app.state.gateway.app_id,
                filters,
                timeout=ADMIN_READ_TIMEOUT,
            )
        except Exception:
            # Reader/query failures are generic: no DSN, SQL or driver text.
            return admin_error(request, 503, "UNAVAILABLE")
        if page is _CONTROL_TIMEOUT:
            # The worker thread may still be running, but this request is over.
            # No deferred continuation retries the read.
            return admin_error(request, 503, "UNAVAILABLE")

        health = await _runtime_ready(
            request.app.state.gateway,
            request.app.state.config_ready,
            admission,
        )
        payload = {
            "events": page.events,
            "has_more": page.has_more,
            "next_cursor": page.next_cursor,
            "policy": {
                "version": request.app.state.policy_version,
                "digest": request.app.state.policy_digest,
            },
            "health": "ready" if health else "not_ready",
        }
        return JSONResponse(payload, headers=ADMIN_SECURITY_HEADERS)

    @app.get("/admin/export.csv")
    async def admin_export_csv(request: Request):
        state = getattr(request.app.state, "operator", None)
        if state is None or state.mode == OPERATOR_DISABLED:
            return admin_error(request, 404, "INVALID_REQUEST")
        if state.mode != OPERATOR_READY:
            return admin_error(request, 503, "UNAVAILABLE")

        auth_error = operator_auth_error(request, state)
        if auth_error is not None:
            return auth_error

        try:
            filters = parse_export_query(request.query_params.multi_items())
        except OperatorQueryError:
            return admin_error(request, 400, "INVALID_REQUEST")

        export_log = getattr(request.app.state, "export_log", None)
        reader = getattr(state, "reader", None)
        if (
            export_log is None
            or not callable(getattr(export_log, "record", None))
            or not callable(getattr(reader, "fetch_export", None))
        ):
            # Missing audit setup means the export is unavailable, never a
            # silent in-memory log or an unaudited CSV.
            return admin_error(request, 503, "UNAVAILABLE")

        app_id = request.app.state.gateway.app_id
        policy_version = getattr(request.app.state, "policy_version", None)
        policy_digest = getattr(request.app.state, "policy_digest", None)
        if (
            not isinstance(policy_version, str)
            or not policy_version
            or not isinstance(policy_digest, str)
            or len(policy_digest) != 64
            or any(ch not in "0123456789abcdef" for ch in policy_digest)
        ):
            # An unavailable or invalid startup policy must not produce an
            # apparently valid export audit row with blank policy metadata.
            return admin_error(request, 503, "UNAVAILABLE")

        # Authentication and query validation are complete before admission.
        admission = request.app.state.control_admission
        if not admission.try_acquire():
            return admin_error(request, 503, "UNAVAILABLE")

        try:
            snapshot = await admission.run(
                reader.fetch_export,
                app_id,
                filters,
                timeout=ADMIN_READ_TIMEOUT,
            )
        except Exception:
            return admin_error(request, 503, "UNAVAILABLE")
        if snapshot is _CONTROL_TIMEOUT:
            # A timed-out read never continues to CSV assembly or audit; the
            # slot stays held until the thread actually returns.
            return admin_error(request, 503, "UNAVAILABLE")

        export_id = "exp_" + uuid.uuid4().hex
        created_at = time.time()
        created_utc = utc_iso(created_at)
        filters_repr = filters.canonical()

        try:
            csv_bytes = build_export_csv(
                snapshot.rows,
                app_id=app_id,
                export_id=export_id,
                created_utc=created_utc,
                filters=filters_repr,
            )
        except ExportTooLarge:
            # A 413 is returned before any CSV body or audit row is produced.
            return admin_error(request, 413, "INPUT_LIMIT")

        try:
            entry = ExportAuditEntry(
                export_id=export_id,
                app_id=app_id,
                created_at=created_at,
                filters=filters_repr,
                row_count=len(snapshot.rows),
                sha256=sha256_hex(csv_bytes),
                policy_version=policy_version,
                policy_digest=policy_digest,
                upper_seq=snapshot.upper_seq,
            )
        except ValueError:
            return admin_error(request, 503, "UNAVAILABLE")

        # The export audit is a second bounded control-plane operation.  If the
        # shared capacity is exhausted, the request fails closed: an unaudited
        # CSV is never returned and no audit thread is queued.
        if not admission.try_acquire():
            return admin_error(request, 503, "UNAVAILABLE")
        try:
            # The audit row is committed before the response object exists.
            recorded = await admission.run(
                export_log.record,
                entry,
                timeout=ADMIN_READ_TIMEOUT,
            )
        except Exception:
            return admin_error(request, 503, "UNAVAILABLE")
        if recorded is _CONTROL_TIMEOUT:
            # The audit may still commit in its worker thread, but this response
            # already failed: CSV bytes are not released.
            return admin_error(request, 503, "UNAVAILABLE")

        headers = dict(ADMIN_SECURITY_HEADERS)
        headers["Content-Type"] = "text/csv; charset=utf-8"
        headers["Content-Disposition"] = (
            f'attachment; filename="{EXPORT_FILENAME}"'
        )
        # Trusted prepared-export metadata; no token, DSN or raw row is exposed.
        headers["X-Export-Row-Count"] = str(entry.row_count)
        headers["X-Export-Id"] = entry.export_id
        headers["X-Export-Sha256"] = entry.sha256
        return Response(content=csv_bytes, headers=headers)

    def _chat_completions_body(
        request: Request, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate the ``/chat`` convenience shape and map it to the pipeline."""
        if set(body) != {"prompt"}:
            raise _ChatBodyError()
        prompt = body["prompt"]
        if not isinstance(prompt, str) or not prompt:
            raise _ChatBodyError()
        # The role/content framing is the same internal request a client would
        # send to the OpenAI-compatible route.  Limits, auth, audit and masking
        # remain owned by the gateway below; this is only a shape translation.
        return {
            "model": request.app.state.gateway.policy.model,
            "messages": [{"role": "user", "content": prompt}],
        }

    async def _serve_chat(
        request: Request,
        *,
        body_builder: Any,
        result_sink: dict[str, Any] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Shared preflight, bounded read and single admission lane.

        Both public chat routes call ``gateway.handle("POST",
        "/v1/chat/completions")`` exactly once through this function.  There is
        no second pipeline, separate semaphore, alternate audit path or weaker
        error mapping for the ``/chat`` testing surface.
        """
        request_id = request.state.request_id

        content_type = request.headers.get("content-type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return 400, _error_payload(request_id, "INVALID_REQUEST")

        auth_headers = request.headers.getlist("authorization")
        if len(auth_headers) != 1:
            return 401, _error_payload(request_id, "UNAUTHORIZED")

        if not request.app.state.config_ready:
            return 503, _error_payload(request_id, "UNAVAILABLE")

        gateway = request.app.state.gateway
        if not _gateway_static_ready(gateway):
            return 503, _error_payload(request_id, "UNAVAILABLE")

        sem = request.app.state.sem
        # Admission is checked without queueing.  ``acquire`` cannot yield when a
        # slot is free, so this check and acquisition are atomic on the loop.
        if sem.locked():
            return 503, _error_payload(request_id, "UNAVAILABLE")
        await sem.acquire()

        dispatched = False
        released = False

        def release_once() -> None:
            nonlocal released
            if not released:
                released = True
                sem.release()

        def release_when_worker_done(task: "asyncio.Task") -> None:
            # Consume the worker result/exception here so no unfinished-task
            # warning or raw traceback is emitted.  The slot is released exactly
            # once, after the synchronous handler has really finished.  The
            # strong reference is dropped only at that same real completion, not
            # when the HTTP deadline expires.
            request.app.state.chat_tasks.discard(task)
            try:
                task.exception()
            except BaseException:
                pass
            release_once()

        try:
            try:
                body_bytes = await _read_limited_body(
                    request,
                    request.app.state.max_body_bytes,
                    request.app.state.body_read_timeout,
                )
            except _BodyTimeout:
                return 503, _error_payload(request_id, "UNAVAILABLE")
            except _BodyTooLarge:
                return 413, _error_payload(request_id, "INPUT_LIMIT")
            except asyncio.CancelledError:
                raise
            except Exception:
                return 400, _error_payload(request_id, "INVALID_REQUEST")

            body = _parse_json_object(body_bytes)
            if body is None:
                return 400, _error_payload(request_id, "INVALID_REQUEST")

            try:
                chat_body = body_builder(body)
            except _ChatBodyError:
                return 400, _error_payload(request_id, "INVALID_REQUEST")

            headers = {"Authorization": auth_headers[0]}
            task = asyncio.create_task(
                asyncio.to_thread(
                    gateway.handle,
                    "POST",
                    "/v1/chat/completions",
                    headers,
                    chat_body,
                    result_sink=result_sink,
                )
            )
            dispatched = True
            request.app.state.chat_tasks.add(task)
            task.add_done_callback(release_when_worker_done)
            result = await _await_control_call(
                task,
                request.app.state.chat_work_timeout,
                release_when_worker_done,
            )
            if result is _CONTROL_TIMEOUT:
                # The HTTP deadline expired, but the shielded worker keeps its
                # admission slot until the native call really returns.  Any late
                # success/error is consumed and never becomes a response.
                return 503, _error_payload(request_id, "UNAVAILABLE")
            return result
        finally:
            if not dispatched:
                release_once()

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        status, payload = await _serve_chat(
            request,
            body_builder=lambda body: body,
        )
        return JSONResponse(payload, status_code=status)

    @app.post("/chat")
    async def chat_testing(request: Request):
        """Blueprint testing surface: a thin map over the real pipeline.

        The optional result sink is created once per HTTP call and filled by the
        same ``gateway.handle`` dispatch as ``/v1``.  It is request-local memory
        only: audit rows, masking, admission and error mapping are unchanged.
        """
        result_sink: dict[str, Any] = {}
        status, payload = await _serve_chat(
            request,
            body_builder=lambda body: _chat_completions_body(request, body),
            result_sink=result_sink,
        )

        if status == 200:
            content: Any = None
            choices = payload.get("choices")
            if isinstance(choices, list) and choices:
                first = choices[0]
                if isinstance(first, dict):
                    message = first.get("message")
                    if isinstance(message, dict):
                        content = message.get("content")
            reply: dict[str, Any] = {
                "decision": "ALLOW",
                "input_safety_label": _input_safety_label(result_sink),
                "output_safety_label": _output_safety_label(result_sink),
                "response": content,
            }
            sanitized_prompt = _sanitized_prompt(result_sink)
            if sanitized_prompt is not None:
                reply["sanitized_prompt"] = sanitized_prompt
            return JSONResponse(reply, status_code=200)

        if status == 403:
            block = payload.get("error", {}).get("block", {})
            if not isinstance(block, dict):
                block = {}
            reason_code = block.get("reason_code")
            reply = {
                "decision": "BLOCK",
                "reason": block.get("reason", _ERROR_MESSAGES["POLICY_BLOCK"]),
                "input_safety_label": _input_safety_label(result_sink),
            }
            if isinstance(reason_code, str) and reason_code:
                reply["category"] = reason_code
            # Output-stage blocks already ran masking before withholding the
            # output, so this request's sanitized text is available.  Input
            # blocks never masked and the field is simply absent.  No block
            # response carries output_safety_label.
            sanitized_prompt = _sanitized_prompt(result_sink)
            if sanitized_prompt is not None:
                reply["sanitized_prompt"] = sanitized_prompt
            return JSONResponse(reply, status_code=403)

        # 400/401/413/503 stay the standard generic envelope, exactly as /v1.
        return JSONResponse(payload, status_code=status)

    if workspace_runtime.enabled:
        # The same static shell serves the legacy entry and the three explicit
        # views.  The browser selects the view from the URL only after the API
        # confirms the session and permission; the API remains authoritative.
        @app.get("/workspace")
        @app.get("/workspace/")
        @app.get("/workspace/chat")
        @app.get("/workspace/chat/")
        @app.get("/workspace/review")
        @app.get("/workspace/review/")
        @app.get("/workspace/admin")
        @app.get("/workspace/admin/")
        async def workspace_page(request: Request):
            return HTMLResponse(
                workspace_html(ready=workspace_runtime.ready),
                headers=WORKSPACE_SECURITY_HEADERS,
            )

    register_workspace_routes(app, workspace_runtime)

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"],
    )
    async def catch_all(request: Request, path: str):
        # Keep known paths explicit so a wrong method returns 405 rather than
        # being swallowed by the catch-all route.
        if path in (
            "",
            "v1/chat/completions",
            "chat",
            "health/live",
            "health/ready",
            "admin",
            "admin/events",
            "admin/export.csv",
        ):
            return _error_response(request.state.request_id, "INVALID_REQUEST", 405)
        if workspace_runtime.enabled and (
            path == "workspace" or path.startswith("workspace/")
        ):
            return _error_response(request.state.request_id, "INVALID_REQUEST", 405)
        return _error_response(request.state.request_id, "INVALID_REQUEST", 404)

    return app


# Module-level app for ``uvicorn nasi_lemak.server:app``.  Missing or invalid
# environment configuration produces an unavailable but live application.
app = make_app()
