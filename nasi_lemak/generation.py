"""Server-side OpenAI-compatible chat generation transport.

This module performs no network access on import, configuration loading or
``GenerationConfig.from_env``. Only an explicit ``generate``, ``list_models`` or
``probe`` call opens a connection. There is no retry, proxy or cloud fallback.

Configuration is read only from server-side environment variables:

* ``NASI_LEMAK_GENERATION_URL``: API base URL, including any provider path
  prefix (for example ``https://approved-host.internal/openai/v1``). The client
  appends ``/chat/completions`` or ``/models``; it never appends ``/v1`` itself.
* ``NASI_LEMAK_GENERATION_MODEL``: exact upstream provider model identifier.
  Optional for model listing; required before any generation or probe call.
* ``NASI_LEMAK_GENERATION_AUTH``: ``bearer`` (default) or ``none``. With
  ``none`` no Authorization header is sent, even if a key variable is set.
* ``NASI_LEMAK_GENERATION_API_KEY``: bearer credential held only in process.
  Required for ``bearer`` auth and ignored for ``none``.
* ``NASI_LEMAK_GENERATION_TIMEOUT``: optional finite positive seconds.
* ``NASI_LEMAK_GENERATION_CA_FILE``: optional CA bundle path for private TLS.
* ``NASI_LEMAK_GENERATION_MAX_RESPONSE_BYTES``: optional response size bound.
* ``NASI_LEMAK_GENERATION_ALLOW_INSECURE_HTTP``: optional explicit ``true``/``1``
  opt-in for a non-loopback plain-HTTP endpoint. Defaults to off.
* ``NASI_LEMAK_GENERATION_ENABLE_THINKING``: optional strict ``true`` or
  ``false``.  Unset preserves the existing request body exactly.  When set, the
  value is forwarded only as ``chat_template_kwargs.enable_thinking``.  Whether
  the served model honours that provider-specific argument must be verified by
  the operator; this client makes no such claim and never adds arbitrary
  ``extra_body`` fields.
* ``NASI_LEMAK_GENERATION_SYSTEM_PROMPT``: optional server-side concise-reply
  instruction.  Unset preserves the existing request body exactly.  When set it
  is prepended as exactly one ``system`` message to the upstream payload only;
  guard scans, audit rows and the output-scan context never receive it.

Plain HTTP is accepted for loopback hosts by default. A non-loopback plain-HTTP
endpoint additionally requires the explicit insecure-HTTP opt-in; TLS
verification itself is never disabled.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

ENV_URL = "NASI_LEMAK_GENERATION_URL"
ENV_MODEL = "NASI_LEMAK_GENERATION_MODEL"
ENV_API_KEY = "NASI_LEMAK_GENERATION_API_KEY"
ENV_AUTH = "NASI_LEMAK_GENERATION_AUTH"
ENV_TIMEOUT = "NASI_LEMAK_GENERATION_TIMEOUT"
ENV_CA_FILE = "NASI_LEMAK_GENERATION_CA_FILE"
ENV_MAX_RESPONSE_BYTES = "NASI_LEMAK_GENERATION_MAX_RESPONSE_BYTES"
ENV_ALLOW_INSECURE_HTTP = "NASI_LEMAK_GENERATION_ALLOW_INSECURE_HTTP"
ENV_ENABLE_THINKING = "NASI_LEMAK_GENERATION_ENABLE_THINKING"
ENV_SYSTEM_PROMPT = "NASI_LEMAK_GENERATION_SYSTEM_PROMPT"

AUTH_BEARER = "bearer"
AUTH_NONE = "none"
AUTH_MODES = (AUTH_BEARER, AUTH_NONE)
TRUE_VALUES = ("1", "true")
FALSE_VALUES = ("0", "false")

PUBLIC_MODEL_ALIAS = "pilot-local"
# Stable, honest application identity sent on every upstream request.  Some
# provider front ends block urllib's default Python User-Agent, so this must not
# be omitted or made configurable (it carries no credentials).
APPLICATION_USER_AGENT = "nasi-lemak-gateway/0.1"
DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_TIMEOUT_SECONDS = 600.0
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024
MIN_MAX_RESPONSE_BYTES = 1024
MAX_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_TOKENS = 8192
MAX_MESSAGES = 32
MAX_MESSAGE_CHARS = 64 * 1024
MAX_SYSTEM_PROMPT_CHARS = 1000


class GenerationConfigError(ValueError):
    """Invalid or missing server-side generation configuration."""


class GenerationError(RuntimeError):
    """Safe, generic generation transport failure.

    Messages never contain prompts, response bodies, credentials or the URL.
    ``diagnostic_code`` is an optional fixed internal signal (see
    :mod:`nasi_lemak.diagnostics`) and is never rendered to a client.
    """

    def __init__(self, message: str, *, diagnostic_code: str | None = None) -> None:
        super().__init__(message)
        self.diagnostic_code = diagnostic_code


def conservative_byte_budget(serialized: str) -> int:
    """Conservative UTF-8 byte budget, never a model tokenizer count.

    The small framing allowance covers per-message overhead.  Callers must not
    report this number as a tokenizer result or as a model-window claim.
    """
    if not isinstance(serialized, str):
        raise ValueError("serialized input is invalid")
    body = len(serialized.encode("utf-8"))
    messages = serialized.count("\n") + 1
    framing = messages * 2 + 2
    return body + framing


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _is_loopback(host: str) -> bool:
    host = host.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_url(url: Any, *, allow_insecure_http: bool = False) -> None:
    if not isinstance(url, str) or not url or url != url.strip():
        raise GenerationConfigError("generation URL is missing or contains surrounding whitespace")
    if _has_control_characters(url) or " " in url or "\\" in url:
        raise GenerationConfigError("generation URL contains forbidden characters")
    lowered = url.lower()
    if any(encoded in lowered for encoded in ("%0a", "%0d", "%00")):
        raise GenerationConfigError("generation URL contains forbidden encoded characters")
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
        parts.port
    except ValueError:
        raise GenerationConfigError("generation URL is malformed") from None
    if parts.scheme not in ("https", "http"):
        raise GenerationConfigError("generation URL must use HTTPS (or explicitly approved HTTP)")
    if parts.username is not None or parts.password is not None:
        raise GenerationConfigError("generation URL must not embed credentials")
    if parts.query or parts.fragment:
        raise GenerationConfigError("generation URL must not contain a query or fragment")
    if not hostname:
        raise GenerationConfigError("generation URL must include a host")
    if parts.scheme == "http" and not _is_loopback(hostname) and not allow_insecure_http:
        raise GenerationConfigError(
            "plain HTTP generation URLs require the explicit insecure-HTTP opt-in"
        )
    normalized_path = (parts.path or "").rstrip("/")
    if normalized_path.endswith("/chat/completions") or normalized_path.endswith("/models"):
        raise GenerationConfigError("generation URL must be the API base URL, not a full endpoint")


def _validate_identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise GenerationConfigError(f"generation {label} is missing or malformed")
    if _has_control_characters(value):
        raise GenerationConfigError(f"generation {label} contains forbidden characters")


def _parse_positive_number(raw: str, *, label: str, maximum: float) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise GenerationConfigError(f"generation {label} must be a finite positive number") from None
    if value != value or value in (float("inf"), float("-inf")) or not 0 < value <= maximum:
        raise GenerationConfigError(f"generation {label} must be a finite positive number")
    return value


def _parse_positive_int(raw: str, *, label: str, minimum: int, maximum: int) -> int:
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        raise GenerationConfigError(f"generation {label} must be a bounded integer") from None
    if isinstance(value, bool) or not minimum <= value <= maximum:
        raise GenerationConfigError(f"generation {label} must be a bounded integer")
    return value


@dataclass(frozen=True)
class GenerationConfig:
    """Validated upstream endpoint settings.

    ``api_key`` is excluded from ``repr`` and equality so accidental logging or
    comparison is less likely to reveal it. Access it only when constructing the
    Authorization header for bearer auth. With ``auth_mode="none"`` it is
    discarded at validation time and no Authorization header is ever built.
    """

    url: str
    model: str = ""
    api_key: str | None = field(default=None, repr=False, compare=False)
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    ca_file: str | None = None
    auth_mode: str = AUTH_BEARER
    allow_insecure_http: bool = False
    enable_thinking: bool | None = None
    system_prompt: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.auth_mode not in AUTH_MODES:
            raise GenerationConfigError("generation auth mode must be 'bearer' or 'none'")
        if not isinstance(self.allow_insecure_http, bool):
            raise GenerationConfigError("generation insecure-HTTP opt-in must be a boolean")
        if self.enable_thinking is not None and not isinstance(self.enable_thinking, bool):
            raise GenerationConfigError(
                "generation thinking opt-in must be true, false or unset"
            )
        if self.system_prompt is not None:
            if (
                not isinstance(self.system_prompt, str)
                or not self.system_prompt.strip()
            ):
                raise GenerationConfigError(
                    "generation system prompt must be non-empty text"
                )
            if len(self.system_prompt) > MAX_SYSTEM_PROMPT_CHARS:
                raise GenerationConfigError(
                    "generation system prompt exceeds the supported length"
                )
            if _has_control_characters(self.system_prompt):
                raise GenerationConfigError(
                    "generation system prompt contains forbidden characters"
                )
        _validate_url(self.url, allow_insecure_http=self.allow_insecure_http)
        if self.model is None:
            object.__setattr__(self, "model", "")
        if self.model != "":
            _validate_identifier(self.model, "model")
        if self.auth_mode == AUTH_NONE:
            # A stale key in the environment must not survive into a header.
            object.__setattr__(self, "api_key", None)
        else:
            if not isinstance(self.api_key, str) or not self.api_key.strip():
                raise GenerationConfigError("generation API key is not configured")
            if any(not 0x21 <= ord(character) <= 0x7E for character in self.api_key):
                raise GenerationConfigError("generation API key contains forbidden characters")
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)):
            raise GenerationConfigError("generation timeout must be a finite positive number")
        timeout = float(self.timeout)
        if timeout != timeout or timeout in (float("inf"), float("-inf")) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise GenerationConfigError("generation timeout must be a finite positive number")
        object.__setattr__(self, "timeout", timeout)
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not MIN_MAX_RESPONSE_BYTES <= self.max_response_bytes <= MAX_MAX_RESPONSE_BYTES
        ):
            raise GenerationConfigError("generation response-byte limit must be a bounded integer")
        if self.ca_file is not None:
            if not isinstance(self.ca_file, str) or not self.ca_file or _has_control_characters(self.ca_file):
                raise GenerationConfigError("generation CA file path is malformed")
            if not Path(self.ca_file).is_file():
                raise GenerationConfigError("generation CA file does not exist")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, *, api_key_override: str | None = None) -> "GenerationConfig":
        """Build configuration from an explicit mapping; never contacts the network."""
        env = os.environ if environ is None else environ
        missing = [name for name in (ENV_URL,) if not env.get(name)]
        auth_mode = (env.get(ENV_AUTH) or AUTH_BEARER).strip().lower()
        if auth_mode not in AUTH_MODES:
            raise GenerationConfigError("generation auth mode must be 'bearer' or 'none'")
        unresolved_auth: list[str] = []
        if auth_mode == AUTH_BEARER and not env.get(ENV_API_KEY) and api_key_override is None:
            unresolved_auth.append(ENV_API_KEY)
        if missing or unresolved_auth:
            raise GenerationConfigError("missing generation settings: " + ", ".join(missing + unresolved_auth))
        timeout_raw = env.get(ENV_TIMEOUT)
        timeout = _parse_positive_number(timeout_raw, label="timeout", maximum=MAX_TIMEOUT_SECONDS) if timeout_raw else DEFAULT_TIMEOUT_SECONDS
        max_bytes_raw = env.get(ENV_MAX_RESPONSE_BYTES)
        max_bytes = (
            _parse_positive_int(
                max_bytes_raw,
                label="response-byte limit",
                minimum=MIN_MAX_RESPONSE_BYTES,
                maximum=MAX_MAX_RESPONSE_BYTES,
            )
            if max_bytes_raw
            else DEFAULT_MAX_RESPONSE_BYTES
        )
        allow_insecure_raw = env.get(ENV_ALLOW_INSECURE_HTTP)
        if allow_insecure_raw is None or allow_insecure_raw.strip().lower() == "":
            allow_insecure_http = False
        elif allow_insecure_raw.strip().lower() in TRUE_VALUES:
            allow_insecure_http = True
        elif allow_insecure_raw.strip().lower() in FALSE_VALUES:
            allow_insecure_http = False
        else:
            raise GenerationConfigError(
                "generation insecure-HTTP opt-in must be true/false or 1/0"
            )
        enable_thinking_raw = env.get(ENV_ENABLE_THINKING)
        if enable_thinking_raw is None or enable_thinking_raw.strip() == "":
            enable_thinking = None
        elif enable_thinking_raw.strip().lower() in TRUE_VALUES:
            enable_thinking = True
        elif enable_thinking_raw.strip().lower() in FALSE_VALUES:
            enable_thinking = False
        else:
            raise GenerationConfigError(
                "generation thinking opt-in must be true/false or unset"
            )
        system_prompt_raw = env.get(ENV_SYSTEM_PROMPT)
        if system_prompt_raw is None or (
            isinstance(system_prompt_raw, str) and system_prompt_raw.strip() == ""
        ):
            system_prompt = None
        else:
            system_prompt = system_prompt_raw
        api_key = None if auth_mode == AUTH_NONE else (
            env[ENV_API_KEY] if api_key_override is None else api_key_override
        )
        return cls(
            url=env[ENV_URL],
            model=env.get(ENV_MODEL) or "",
            api_key=api_key,
            timeout=timeout,
            max_response_bytes=max_bytes,
            ca_file=env.get(ENV_CA_FILE) or None,
            auth_mode=auth_mode,
            allow_insecure_http=allow_insecure_http,
            enable_thinking=enable_thinking,
            system_prompt=system_prompt,
        )

    @property
    def api_base(self) -> str:
        return self.url.rstrip("/")

    @property
    def chat_completions_url(self) -> str:
        return self.api_base + "/chat/completions"

    @property
    def models_url(self) -> str:
        return self.api_base + "/models"

    def safe_summary(self) -> dict[str, Any]:
        parts = urllib.parse.urlsplit(self.url)
        hostname = parts.hostname or ""
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        return {
            "url_origin": f"{parts.scheme}://{display_host}"
            + (f":{parts.port}" if parts.port else ""),
            "url_path": parts.path or "/",
            "upstream_model": self.model or "not_configured",
            "auth_mode": self.auth_mode,
            "api_key_configured": self.auth_mode == AUTH_BEARER,
            "allow_insecure_http": self.allow_insecure_http,
            "timeout_seconds": self.timeout,
            "max_response_bytes": self.max_response_bytes,
            "ca_file_configured": self.ca_file is not None,
            "enable_thinking": self.enable_thinking,
            "system_prompt_configured": self.system_prompt is not None,
            "system_prompt_chars": (
                len(self.system_prompt) if self.system_prompt is not None else 0
            ),
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so the bearer token cannot be sent to another endpoint."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError("duplicate JSON key")
        mapping[key] = value
    return mapping


def _reject_json_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON number")


def _validate_json_path(path: Any) -> str:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 128:
        raise ValueError("generation request path is invalid")
    if path == "/" or "//" in path or ".." in path:
        raise ValueError("generation request path is invalid")
    if any(
        not (character.isalnum() or character in "-._/")
        for character in path
    ):
        raise ValueError("generation request path is invalid")
    return path


def _validate_messages(messages: Any) -> list[dict[str, str]]:
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_MESSAGES:
        raise ValueError("generation messages are invalid")
    clean: list[dict[str, str]] = []
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise ValueError("generation messages are invalid")
        role = message["role"]
        content = message["content"]
        if role not in ("user", "assistant", "system") or not isinstance(content, str) or not content:
            raise ValueError("generation messages are invalid")
        if len(content) > MAX_MESSAGE_CHARS:
            raise ValueError("generation messages are invalid")
        clean.append({"role": role, "content": content})
    return clean


def _extract_content(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise GenerationError("generation endpoint returned an invalid response")
    if "error" in payload:
        raise GenerationError("generation endpoint returned an error response")
    choices = payload.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise GenerationError("generation endpoint returned an unsupported response")
    choice = choices[0]
    if not isinstance(choice, dict):
        raise GenerationError("generation endpoint returned an unsupported response")
    if choice.get("index", 0) != 0:
        raise GenerationError("generation endpoint returned an unsupported response")
    finish_reason = choice.get("finish_reason")
    if finish_reason != "stop":
        # A reasoning-style model can spend its whole budget on hidden
        # reasoning_content and report ``length`` with empty visible content.
        # That is a failed turn, never a partial answer.  The fixed internal
        # signal helps an operator distinguish it without exposing reasoning.
        # Only ``length`` receives that code; any other unsupported reason is
        # still a safe generic failure and must not be mislabelled as truncation.
        if finish_reason == "length":
            raise GenerationError(
                "generation endpoint returned a truncated or unsupported completion",
                diagnostic_code="generation_truncated",
            )
        raise GenerationError(
            "generation endpoint returned a truncated or unsupported completion"
        )
    message = choice.get("message")
    if not isinstance(message, dict):
        raise GenerationError("generation endpoint returned an unsupported response")
    if message.get("role") != "assistant":
        raise GenerationError("generation endpoint returned an unsupported response")
    if message.get("tool_calls") or message.get("function_call"):
        raise GenerationError("generation endpoint returned an unsupported tool response")
    if message.get("refusal"):
        raise GenerationError("generation endpoint returned a refusal response")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        # ``reasoning_content`` is deliberately ignored and never returned.
        raise GenerationError(
            "generation endpoint returned no text content",
            diagnostic_code="generation_no_final_content",
        )
    return content.lstrip()


class GenerationClient:
    """Single-shot, bounded OpenAI-compatible chat-completions client."""

    def __init__(self, config: GenerationConfig):
        if not isinstance(config, GenerationConfig):
            raise GenerationConfigError("generation configuration is required")
        self.config = config
        try:
            self._ssl_context = ssl.create_default_context(cafile=config.ca_file)
        except (OSError, ssl.SSLError):
            raise GenerationConfigError("generation CA file could not be loaded") from None

    def _opener(self) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self._ssl_context),
            _NoRedirect(),
        )

    def _request_json(
        self,
        url: str,
        *,
        method: str,
        payload: dict[str, Any] | None = None,
        strict_json: bool = False,
        timeout: float | None = None,
    ) -> Any:
        # A caller may narrow (never extend) the configured transport timeout
        # for one request, for example to stay inside a remaining scan deadline.
        # The shared configuration is never mutated.
        if timeout is None:
            request_timeout = self.config.timeout
        else:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise ValueError("generation timeout override is invalid")
            candidate = float(timeout)
            if (
                candidate != candidate
                or candidate in (float("inf"), float("-inf"))
                or not 0 < candidate <= self.config.timeout
            ):
                raise ValueError("generation timeout override is invalid")
            request_timeout = candidate
        headers = {
            "Accept": "application/json",
            "User-Agent": APPLICATION_USER_AGENT,
        }
        if self.config.auth_mode == AUTH_BEARER:
            headers["Authorization"] = "Bearer " + self.config.api_key
        # auth_mode == AUTH_NONE deliberately sends no Authorization header.
        data = None
        if payload is not None:
            try:
                data = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError):
                raise GenerationError("generation request could not be encoded") from None
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        limit = self.config.max_response_bytes
        try:
            with self._opener().open(request, timeout=request_timeout) as response:
                if response.status != 200:
                    raise GenerationError("generation endpoint returned an unsupported status")
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        declared_length = int(declared)
                    except ValueError:
                        raise GenerationError("generation endpoint returned an invalid response length") from None
                    if declared_length < 0 or declared_length > limit:
                        raise GenerationError("generation endpoint response exceeded the size limit")
                body = response.read(limit + 1)
        except GenerationError:
            raise
        except urllib.error.HTTPError as exc:
            try:
                exc.close()
            except Exception:
                pass
            if 300 <= exc.code < 400:
                raise GenerationError("generation endpoint attempted a redirect") from None
            raise GenerationError(f"generation endpoint returned HTTP {exc.code}") from None
        except (TimeoutError, socket.timeout):
            raise GenerationError("generation endpoint timed out") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise GenerationError("generation endpoint timed out") from None
            raise GenerationError("generation endpoint was unreachable") from None
        except (OSError, http.client.HTTPException):
            raise GenerationError("generation endpoint response failed") from None
        if len(body) > limit:
            raise GenerationError("generation endpoint response exceeded the size limit")
        try:
            if strict_json:
                return json.loads(
                    body.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_json_keys,
                    parse_constant=_reject_json_constant,
                )
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise GenerationError("generation endpoint returned invalid JSON") from None

    def _require_model(self) -> None:
        if not self.config.model:
            raise GenerationConfigError("generation model is not configured")

    def generate(self, messages: list[dict[str, str]], max_tokens: int = 256) -> str:
        """Generate one completion. The upstream model comes only from config."""
        self._require_model()
        clean = _validate_messages(messages)
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or not 1 <= max_tokens <= MAX_OUTPUT_TOKENS:
            raise ValueError("generation max_tokens is invalid")
        upstream_messages = clean
        if self.config.system_prompt is not None:
            # The server-side concise-reply instruction belongs only to the
            # upstream payload; guard scans, audit and the output scan context
            # keep the caller's sanitized conversation unchanged.
            upstream_messages = [
                {"role": "system", "content": self.config.system_prompt},
                *clean,
            ]
        payload = {
            "model": self.config.model,
            "messages": upstream_messages,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if self.config.enable_thinking is not None:
            # Only the fixed Qwen chat-template switch; no arbitrary extra_body.
            payload["chat_template_kwargs"] = {
                "enable_thinking": self.config.enable_thinking
            }
        return _extract_content(self._request_json(self.config.chat_completions_url, method="POST", payload=payload))

    def list_models(self) -> list[str]:
        """Return sorted unique upstream model IDs without persisting anything."""
        payload = self._request_json(self.config.models_url, method="GET")
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise GenerationError("generation endpoint returned an invalid model list")
        models: set[str] = set()
        for entry in payload["data"]:
            if not isinstance(entry, dict):
                raise GenerationError("generation endpoint returned an invalid model list")
            model_id = entry.get("id")
            if not isinstance(model_id, str) or not model_id or _has_control_characters(model_id):
                raise GenerationError("generation endpoint returned an invalid model list")
            models.add(model_id)
        return sorted(models)

    def post_json(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        strict_json: bool = False,
        timeout: float | None = None,
    ) -> Any:
        """POST one bounded JSON object to a configured relative path.

        This is a narrow shared transport for guard adapters.  It uses the same
        TLS context, no-redirect policy, proxy suppression, timeout and response
        size bound as generation, and does not add retries.  Callers remain
        responsible for the payload and response schema.  ``strict_json``
        additionally rejects duplicate keys and non-finite numbers.
        ``timeout`` may only narrow the configured timeout for this one call.
        """
        relative = _validate_json_path(path)
        if not isinstance(payload, dict):
            raise ValueError("generation request payload is invalid")
        return self._request_json(
            self.config.api_base + relative,
            method="POST",
            payload=payload,
            strict_json=strict_json,
            timeout=timeout,
        )

    def probe(self) -> dict[str, Any]:
        """One fixed synthetic connectivity check; returns metadata only.

        This is an unguarded diagnostic, not a gateway entry point. The generated
        text is deliberately discarded and never returned or logged.
        """
        content = self.generate(
            [{"role": "user", "content": "Reply with the single word: ready"}],
            max_tokens=16,
        )
        return {
            "ok": True,
            "upstream_model": self.config.model,
            "response_bytes": len(content.encode("utf-8")),
            "response_content": "not_printed",
        }


def _require_adapter(adapter: Any, method_name: str, label: str) -> None:
    if adapter is None or not callable(getattr(adapter, method_name, None)):
        raise ValueError(f"real gateway requires an explicit {label} adapter")


class RealGatewayAdapters:
    """Gateway adapter composition for real generation plus explicit guards.

    Generation is delegated to the configured client, but the public gateway
    alias must remain ``pilot-local``. This class never supplies default allow
    guards, synthetic tokenizers or memory generation.
    """

    # Tells the gateway that an explicit per-request scan context may be
    # forwarded.  The context is still per call; nothing is cached here.
    supports_scan_context = True

    def __init__(self, client: Any, *, tokenizer: Any, attack_guard: Any, output_guard: Any):
        if client is None or not callable(getattr(client, "generate", None)):
            raise ValueError("real gateway requires an explicit generation client")
        _require_adapter(tokenizer, "count_tokens", "tokenizer")
        _require_adapter(attack_guard, "scan_attack", "attack guard")
        _require_adapter(output_guard, "scan_response", "output guard")
        self.client = client
        self.tokenizer = tokenizer
        self.attack_guard = attack_guard
        self.output_guard = output_guard

    def count_tokens(self, serialized: str) -> Any:
        return self.tokenizer.count_tokens(serialized)

    def scan_attack(self, text: str, *, scan_context: Any = None) -> Any:
        guard = self.attack_guard
        if scan_context is not None and getattr(
            guard, "supports_scan_context", False
        ):
            return guard.scan_attack(text, scan_context=scan_context)
        return guard.scan_attack(text)

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        if model != PUBLIC_MODEL_ALIAS:
            raise ValueError("unsupported public model alias")
        return self.client.generate(messages, max_tokens)

    def scan_response(self, messages: list[dict[str, str]], output: str) -> Any:
        """Screen the complete current-request context plus buffered output."""
        if not isinstance(messages, list) or not messages:
            raise ValueError("contextual output guard requires a conversation")
        return self.output_guard.scan_response(
            [dict(message) for message in messages], output
        )

    def scan_output(self, text: str) -> Any:
        """Fail closed: the genuine guard path requires full context.

        ``scan_output`` is retained only because the readiness check inspects
        this structural method name. It is never used as a silent response-only
        fallback for a real output guard.
        """
        raise ValueError("contextual output guard requires the full conversation")


class TestGatewayAdapters:
    """Explicit test-mode adapters: real generation, intentionally inactive guards.

    This adapter is constructed only when the server-side environment selects
    ``NASI_LEMAK_MODE=test`` together with the explicit acknowledgement
    ``NASI_LEMAK_ALLOW_UNGUARDED_TEST=true``. It uses the real
    :class:`GenerationClient` for upstream calls, but the native guard methods
    are deliberately inactive and named to make that obvious.

    The token budget uses a conservative UTF-8 byte estimate plus a small
    framing allowance. This is **not** a model tokenizer and must never be
    reported or mistaken for one.
    """

    def __init__(self, client: GenerationClient):
        if not isinstance(client, GenerationClient):
            raise ValueError("test adapters require a real GenerationClient")
        self.client = client

    @staticmethod
    def _byte_budget(serialized: str) -> int:
        body = len(serialized.encode("utf-8"))
        messages = serialized.count("\n") + 1
        framing = messages * 2 + 2
        return body + framing

    def count_tokens(self, serialized: str) -> int:
        """Conservative byte budget; not a tokenizer."""
        return self._byte_budget(serialized)

    def scan_attack(self, text: str) -> dict[str, str]:
        """Inactive in test mode: always allows."""
        return {"decision": "allow"}

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        if model != PUBLIC_MODEL_ALIAS:
            raise ValueError("unsupported public model alias")
        return self.client.generate(messages, max_tokens)

    def scan_response(self, messages: list[dict[str, str]], output: str) -> dict[str, bool]:
        """Inactive in test mode: always reports safe."""
        return {"safe": True}

    def scan_output(self, text: str) -> dict[str, bool]:
        """Inactive in test mode: always reports safe."""
        return {"safe": True}


def make_real_gateway(
    app_key: str,
    audit_path: Any,
    client: Any,
    *,
    tokenizer: Any,
    attack_guard: Any,
    output_guard: Any,
    policy: Any = None,
):
    """Compose the in-process gateway with real generation and required guards."""
    from .gateway import Gateway, Policy

    if not isinstance(client, GenerationClient):
        raise ValueError("real gateway requires a configured generation client")
    if not client.config.model:
        raise GenerationConfigError("real gateway requires a configured generation model")
    adapters = RealGatewayAdapters(
        client,
        tokenizer=tokenizer,
        attack_guard=attack_guard,
        output_guard=output_guard,
    )
    return Gateway(app_key, audit_path, adapters, policy if policy is not None else Policy())
