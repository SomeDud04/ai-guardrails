"""End-user terminal client for the gateway's ``POST /chat`` surface.

Each turn shows what the blueprint's web UI shows: the decision, the input and
output safety labels, whether PII was masked, the server-reported latency (or
the client round trip when the server did not report one) and the request id
when the reply carries one.  Then the released response text is printed.

The client is deliberately standard-library only and talks to exactly one
explicitly supplied endpoint: there is no localhost default, no retry of a
blocked request and no second pipeline.  The bearer token is read from
``NASI_GATEWAY_TOKEN`` (or prompted with :mod:`getpass`) and is kept in memory
for the life of the process: it is never printed, logged, written to disk or
included in an error message.

Examples::

    nasi-chat --base-url https://guardrail.example
    NASI_GATEWAY_URL=https://guardrail.example nasi-chat --prompt "Hello"
    nasi-chat --base-url https://guardrail.example --json --prompt "Hello"
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping, Sequence

BASE_URL_ENV = "NASI_GATEWAY_URL"
TOKEN_ENV = "NASI_GATEWAY_TOKEN"
DEFAULT_TIMEOUT = 90.0
MAX_RESULT_BYTES = 64 * 1024

# Exit codes for a one-shot prompt.  The REPL keeps running instead of exiting.
EXIT_ALLOW = 0
EXIT_BLOCK = 1
EXIT_ERROR = 2

_GREEN = "\x1b[32m"
_RED = "\x1b[31m"
_YELLOW = "\x1b[33m"
_RESET = "\x1b[0m"


class UsageError(ValueError):
    """Invalid command line or environment configuration."""


class RequestFailure(RuntimeError):
    """The endpoint could not be reached or did not return parseable JSON."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nasi-chat",
        description="Talk to the guardrail's POST /chat testing surface.",
    )
    parser.add_argument(
        "--base-url",
        help=f"Explicit gateway base URL, e.g. https://guardrail.example "
        f"(or set {BASE_URL_ENV}; there is no localhost default).",
    )
    parser.add_argument(
        "--prompt",
        help="Send one prompt and exit. Omit for an interactive session.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_only",
        help="Print each raw reply JSON instead of the human status line.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout in seconds (default {DEFAULT_TIMEOUT:g}).",
    )
    return parser


def resolve_base_url(
    explicit: str | None, environ: Mapping[str, str] | None = None
) -> str:
    """Return the configured base URL; never fall back to a local default."""
    env = os.environ if environ is None else environ
    for candidate in (explicit, env.get(BASE_URL_ENV)):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    raise UsageError(f"--base-url or {BASE_URL_ENV} is required")


def chat_endpoint(base_url: str) -> str:
    """Validate ``base_url`` and append the ``/chat`` path."""
    if not isinstance(base_url, str) or not base_url.strip():
        raise UsageError("--base-url is required")
    parsed = urllib.parse.urlsplit(base_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise UsageError("--base-url must be an absolute http(s) URL")
    if parsed.query or parsed.fragment:
        raise UsageError("--base-url must not include a query or fragment")
    return base_url.strip().rstrip("/") + "/chat"


def insecure_http_warning_needed(base_url: str) -> bool:
    """True when the bearer token would cross plaintext http off loopback."""
    parsed = urllib.parse.urlsplit(base_url.strip())
    if parsed.scheme != "http":
        return False
    host = parsed.hostname
    if not host:
        return False
    if host.rstrip(".").lower() == "localhost":
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return not address.is_loopback


def resolve_token(
    environ: Mapping[str, str] | None = None,
    *,
    prompt: Callable[[str], str] | None = None,
) -> str:
    """Return the bearer token without persisting or printing it."""
    env = os.environ if environ is None else environ
    token = env.get(TOKEN_ENV)
    if isinstance(token, str) and token.strip():
        return token.strip()
    ask = getpass.getpass if prompt is None else prompt
    try:
        token = ask("Gateway token: ")
    except (EOFError, KeyboardInterrupt):
        raise UsageError("a bearer token is required") from None
    if not isinstance(token, str) or not token.strip():
        raise UsageError(f"a bearer token is required via {TOKEN_ENV}")
    return token.strip()


def resolve_timeout(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise UsageError("--timeout must be a positive number")
    return float(value)


def post_chat(
    endpoint: str,
    token: str,
    prompt: str,
    timeout: float,
    *,
    opener: Callable[..., Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """POST one prompt and return ``(status, parsed_json)``.

    ``HTTPError`` is a normal response for a blocked prompt, so its body is
    parsed too.  Connection, timeout and decoding failures are raised as
    :class:`RequestFailure` with no credential or body text.
    """
    body = json.dumps({"prompt": prompt}, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    open_url = urllib.request.urlopen if opener is None else opener
    try:
        with open_url(request, timeout=timeout) as response:
            status = int(getattr(response, "status", response.getcode()))
            raw = response.read(MAX_RESULT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            status = int(exc.code)
            raw = exc.read(MAX_RESULT_BYTES + 1)
        except Exception:
            raise RequestFailure(
                "request failed while reading the response"
            ) from None
    except Exception:
        raise RequestFailure("request failed before a response was received") from None
    if len(raw) > MAX_RESULT_BYTES:
        raise RequestFailure("response body exceeds the client bound")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise RequestFailure("response body is not JSON") from None
    if not isinstance(payload, dict):
        raise RequestFailure("response body is not a JSON object")
    return status, payload


def _is_number(value: Any) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float))


def _colour_enabled(stream: Any, environ: Mapping[str, str]) -> bool:
    if "NO_COLOR" in environ:
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _paint(text: str, colour: str, enabled: bool) -> str:
    return f"{colour}{text}{_RESET}" if enabled else text


def _request_id(payload: dict[str, Any]) -> str | None:
    """Return the request id a reply actually carries, if any."""
    candidate = payload.get("request_id")
    if isinstance(candidate, str) and candidate:
        return candidate
    error = payload.get("error")
    if isinstance(error, dict):
        candidate = error.get("request_id")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _timing(payload: dict[str, Any], elapsed: float) -> str:
    latency = payload.get("latency_ms")
    if _is_number(latency) and latency >= 0:
        # The server value comes from the request's own audit timestamps.
        return f"{latency / 1000:.1f} s server"
    return f"{elapsed:.1f} s round trip"


def _label(payload: dict[str, Any], name: str) -> str:
    value = payload.get(name)
    return value if isinstance(value, str) and value else "unknown"


def _pii_masked(payload: dict[str, Any], prompt: str) -> bool:
    sanitized = payload.get("sanitized_prompt")
    return isinstance(sanitized, str) and sanitized != prompt


def _allow_line(
    payload: dict[str, Any], prompt: str, elapsed: float
) -> str:
    parts = [
        "ALLOW (200)",
        "input: " + _label(payload, "input_safety_label"),
        "output: " + _label(payload, "output_safety_label"),
        "PII: " + ("masked" if _pii_masked(payload, prompt) else "none"),
        _timing(payload, elapsed),
    ]
    request_id = _request_id(payload)
    if request_id:
        parts.append(request_id)
    return " \u00b7 ".join(parts)


def _block_line(payload: dict[str, Any]) -> str:
    parts = ["BLOCK (403)"]
    category = payload.get("category")
    if isinstance(category, str) and category:
        parts.append(category)
    parts.append("input: " + _label(payload, "input_safety_label"))
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason:
        reason = "Request did not pass safety checks."
    parts.append(f'"{reason}"')
    return " \u00b7 ".join(parts)


def _error_line(status: int, payload: dict[str, Any]) -> str:
    error = payload.get("error")
    if not isinstance(error, dict):
        error = {}
    code = error.get("code")
    message = error.get("message")
    if not isinstance(code, str) or not code:
        code = "UNEXPECTED_RESPONSE"
    if not isinstance(message, str) or not message:
        message = "Unexpected response body."
    line = f"ERROR ({status}) {code}: {message}"
    request_id = _request_id(payload)
    if request_id:
        line += f" \u00b7 {request_id}"
    return line


def render_turn(
    status: int,
    payload: dict[str, Any],
    *,
    prompt: str,
    elapsed: float,
    colour: bool,
) -> tuple[str, str | None, int]:
    """Return ``(status_line, response_text_or_None, exit_code)`` for one reply."""
    if status == 200:
        line = _paint(_allow_line(payload, prompt, elapsed), _GREEN, colour)
        content = payload.get("response")
        text = content.strip() if isinstance(content, str) else ""
        return line, text or None, EXIT_ALLOW
    if status == 403:
        line = _paint(_block_line(payload), _RED, colour)
        return line, None, EXIT_BLOCK
    return _paint(_error_line(status, payload), _YELLOW, colour), None, EXIT_ERROR


def run_turn(
    prompt: str,
    *,
    endpoint: str,
    token: str,
    timeout: float,
    opener: Callable[..., Any] | None,
    out: Any,
    err: Any,
    json_only: bool,
    colour: bool,
) -> int:
    """Send one prompt, print its result and return the turn's exit code."""
    started = time.perf_counter()
    try:
        status, payload = post_chat(
            endpoint, token, prompt, timeout, opener=opener
        )
    except RequestFailure as exc:
        # One line, no token and no response body.
        print(f"ERROR: {exc}", file=err, flush=True)
        return EXIT_ERROR
    elapsed = time.perf_counter() - started

    if json_only:
        print(json.dumps(payload), file=out, flush=True)
        if status == 200:
            return EXIT_ALLOW
        return EXIT_BLOCK if status == 403 else EXIT_ERROR

    line, text, code = render_turn(
        status, payload, prompt=prompt, elapsed=elapsed, colour=colour
    )
    print(line, file=out, flush=True)
    if text is not None:
        print(text, file=out, flush=True)
    return code


def run(
    *,
    base_url: str,
    token: str,
    prompt: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    json_only: bool = False,
    opener: Callable[..., Any] | None = None,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Run one shot (``prompt`` given) or the interactive REPL."""
    env = os.environ if environ is None else environ
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    endpoint = chat_endpoint(base_url)
    timeout = resolve_timeout(timeout)
    colour = _colour_enabled(out, env)

    if insecure_http_warning_needed(base_url):
        print(
            "WARNING: sending the bearer token over plaintext http; use https.",
            file=err,
            flush=True,
        )

    if prompt is not None:
        return run_turn(
            prompt,
            endpoint=endpoint,
            token=token,
            timeout=timeout,
            opener=opener,
            out=out,
            err=err,
            json_only=json_only,
            colour=colour,
        )

    source = sys.stdin if stdin is None else stdin
    interactive = False
    try:
        interactive = bool(source.isatty())
    except Exception:
        interactive = False
    if interactive:
        print("nasi-chat: type a prompt; /quit or Ctrl-D exits.", file=err, flush=True)
    while True:
        if interactive:
            print("> ", end="", file=err, flush=True)
        try:
            line = source.readline()
        except KeyboardInterrupt:
            print("", file=out, flush=True)
            break
        if not line:
            break
        text = line.strip()
        if not text:
            continue
        if text in ("/quit", "/exit"):
            break
        run_turn(
            line.rstrip("\r\n"),
            endpoint=endpoint,
            token=token,
            timeout=timeout,
            opener=opener,
            out=out,
            err=err,
            json_only=json_only,
            colour=colour,
        )
    return EXIT_ALLOW


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    opener: Callable[..., Any] | None = None,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    try:
        base_url = resolve_base_url(args.base_url, env)
        timeout = resolve_timeout(args.timeout)
        token = resolve_token(env)
    except UsageError as exc:
        parser.error(str(exc))
        return EXIT_ERROR  # argparse.error raises SystemExit; retained for clarity.
    return run(
        base_url=base_url,
        token=token,
        prompt=args.prompt,
        timeout=timeout,
        json_only=args.json_only,
        opener=opener,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        environ=env,
    )


if __name__ == "__main__":
    sys.exit(main())
