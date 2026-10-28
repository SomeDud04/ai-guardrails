"""Deterministic-lane HTTP conformance runner for the frozen OWASP corpus.

The runner selects only the rows whose authored expectation is deterministic
(``expect_status`` 400 or 413).  It has two execution modes:

* **local** (the default) drives the real ASGI application in-process through
  ``nasi_lemak.server.make_app`` with deterministic guard/tokenizer/generation
  doubles.  No socket, model, guard artifact or provider is contacted, and the
  tokenizer double is the product's own
  :func:`nasi_lemak.generation.conservative_byte_budget`.
* **operator** targets a live base URL with a bearer key.  It is never run by
  the implementation worker and is deliberately not exercised by the test
  suite; it exists for an operator with the credentials, and it never records
  the key or the endpoint in a report.

The frozen corpus and the re-baselining map are inputs, never outputs.  No
corpus byte is written, rebuilt or re-derived here.

Usage::

    .\\.venv\\Scripts\\python.exe scripts/run_owasp_corpus.py --dry-run
    .\\.venv\\Scripts\\python.exe scripts/run_owasp_corpus.py --json report.json
    .\\.venv\\Scripts\\python.exe scripts/run_owasp_corpus.py --operator \\
        --base-url https://example.invalid --api-key-env NASI_LEMAK_OWASP_API_KEY

Exit status: 0 only when no row is FAIL and no row is ERROR.  ERROR is never a
verdict and is excluded from the pass rate together with NOT-APPLICABLE-CONFIG.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from nasi_lemak.gateway import Policy
from nasi_lemak.generation import conservative_byte_budget
from nasi_lemak.limits import ChatLimits
from nasi_lemak.policy import load_policy
from nasi_lemak.server import DEFAULT_MAX_BODY_BYTES

CORPUS_ROOT = REPO_ROOT / "evals" / "owasp" / "llm-top10-2026"
PAYLOAD_ROOT = CORPUS_ROOT / "payloads"
REBASELINE_PATH = REPO_ROOT / "evals" / "owasp" / "rebaseline-llm-top10-2026.json"
POLICY_FIXTURE = Path(__file__).resolve().with_name("owasp_corpus_policy.yaml")

PINNED_MODEL = "pilot-local"
LOCAL_TEST_KEY = "owasp-corpus-local-key-not-for-any-real-use"
DETERMINISTIC_STATUSES = (400, 413)
OUTCOMES = ("PASS", "FAIL", "NOT-APPLICABLE-CONFIG", "ERROR")
TOKEN_COUNTER = "nasi_lemak.generation.conservative_byte_budget"
COUNTER_BASIS = (
    "len(serialized UTF-8 bytes) + 2 * messages + 2 conservative units; "
    "a conservative budget, never a tokenizer count"
)
SAFE_OUTPUT = "Synthetic deterministic conformance answer."
# Every request body is metadata-only at rest; these values must never appear in
# a response body or an audit row.  The fixed strings the product legitimately
# returns are excluded from sentinel extraction.
SAFE_CONSTANTS = {
    PINNED_MODEL,
    SAFE_OUTPUT,
    "Request is not supported.",
    "Request exceeds the supported input limit.",
    "Request did not pass safety checks.",
    "Authentication required.",
    "Required safety control is unavailable.",
}
MAX_OPERATOR_TIMEOUT = 120.0

# The contract the corpus was authored against, kept explicitly separate from
# the live product defaults the runner actually judged against.
CORPUS_ASSUMED_LIMITS = {
    "context_messages": 16,
    "serialized_context_limit_characters": 4096,
    "max_reply_tokens": 256,
    "policy_token_budget": 512,
    "note": (
        "Authored contract documented in docs/owasp-corpus.md; the corpus "
        "predates the current product limits and is frozen."
    ),
}


class TransportError(RuntimeError):
    """The request could not be completed; the row is ERROR, never a verdict."""


class RateLimited(TransportError):
    """The remote endpoint asked the caller to slow down; ERROR, never FAIL."""


class RequestBuildError(ValueError):
    """A fixture marker cannot be interpreted; the row is ERROR."""


class PolicySelfCheckError(RuntimeError):
    """The runner's deny phrase would change a row that must be allowed."""


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


@dataclass(frozen=True)
class EffectiveConfiguration:
    context_messages: int
    context_budget: int
    default_reply_tokens: int
    max_reply_tokens: int
    body_limit_bytes: int
    policy_token_budget: int
    policy_default_token_budget: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "context_messages": self.context_messages,
            "context_budget": self.context_budget,
            "default_reply_tokens": self.default_reply_tokens,
            "max_reply_tokens": self.max_reply_tokens,
            "body_limit_bytes": self.body_limit_bytes,
            "policy_token_budget": self.policy_token_budget,
            "policy_default_token_budget": self.policy_default_token_budget,
            "token_counter": TOKEN_COUNTER,
            "counter_basis": COUNTER_BASIS,
            "limits_source": [
                "nasi_lemak.limits.ChatLimits.defaults()",
                "nasi_lemak.policy.load_policy(<fixture>)",
                "nasi_lemak.server.DEFAULT_MAX_BODY_BYTES",
            ],
        }


# ---------------------------------------------------------------------------
# Inputs


def load_records(payload_root: Path = PAYLOAD_ROOT) -> list[dict[str, Any]]:
    """Read the frozen payloads in stable file order."""
    records: list[dict[str, Any]] = []
    for path in sorted(payload_root.glob("*.jsonl")):
        with path.open(encoding="utf-8") as handle:
            records.extend(json.loads(line) for line in handle if line.strip())
    return records


def load_map(path: Path = REBASELINE_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_fixture_policy(path: Path = POLICY_FIXTURE) -> Policy:
    return load_policy(path)


def load_effective_configuration(policy: Policy | None = None) -> EffectiveConfiguration:
    """Read every limit from the live configuration, never corpus constants."""
    if policy is None:
        policy = load_fixture_policy()
    limits = ChatLimits.defaults()
    return EffectiveConfiguration(
        context_messages=limits.context_messages,
        context_budget=limits.context_budget,
        default_reply_tokens=limits.default_reply_tokens,
        max_reply_tokens=limits.max_reply_tokens,
        body_limit_bytes=DEFAULT_MAX_BODY_BYTES,
        policy_token_budget=policy.token_budget,
        policy_default_token_budget=Policy().token_budget,
    )


def deterministic_rows(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        record
        for record in records
        if record.get("expect_status") in DETERMINISTIC_STATUSES
    ]


# ---------------------------------------------------------------------------
# Request construction


def _iter_request_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_request_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_request_strings(item)


def policy_self_check(policy: Policy, records: Iterable[dict[str, Any]]) -> list[str]:
    """No configured phrase may occur in a row whose expectation is 200.

    A short or common phrase silently changes an allowed row into a block, so
    the runner refuses to run instead of publishing a corrupted conformance
    result.  Request material only is inspected: message content, a raw body and
    every non-marker ``optional_extra`` value.
    """
    problems: list[str] = []
    for record in records:
        if record.get("expect_status") != 200:
            continue
        material: list[str] = []
        for message in record.get("messages") or []:
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                material.append(message["content"])
        extra = record.get("optional_extra")
        if isinstance(extra, dict):
            for key, value in extra.items():
                if not isinstance(key, str) or not key.startswith("$"):
                    material.extend(_iter_request_strings(value))
        for text in material:
            if policy.denies(text):
                problems.append(
                    f"{record.get('id', '<unknown>')}: configured deny phrase "
                    "matches a row whose expectation is 200"
                )
                break
    return problems


def _non_marker_extra(record: dict[str, Any]) -> dict[str, Any]:
    extra = record.get("optional_extra")
    if extra is None:
        return {}
    if not isinstance(extra, dict):
        raise RequestBuildError("optional_extra is not an object")
    return {
        key: value
        for key, value in extra.items()
        if isinstance(key, str) and not key.startswith("$")
    }


def build_request_body(record: dict[str, Any]) -> bytes:
    """Build the exact bytes to send, interpreting ``$`` fixture markers.

    Raises :class:`RequestBuildError` for any marker the documented contract
    cannot interpret, so the caller records ERROR instead of guessing.
    """
    extra = record.get("optional_extra")
    if extra is not None and not isinstance(extra, dict):
        raise RequestBuildError("optional_extra is not an object")
    extra = extra or {}

    raw_body = extra.get("$raw_body")
    raw_repeat = extra.get("$raw_body_repeat")
    if raw_body is not None and raw_repeat is not None:
        raise RequestBuildError("both $raw_body and $raw_body_repeat are present")
    if raw_body is not None:
        if not isinstance(raw_body, str):
            raise RequestBuildError("$raw_body is not a string")
        return raw_body.encode("utf-8")
    if raw_repeat is not None:
        return _expand_raw_body_repeat(record, raw_repeat, extra)

    messages = record.get("messages")
    if not isinstance(messages, list):
        raise RequestBuildError("messages is not a list")
    body: dict[str, Any] = dict(_non_marker_extra(record))
    # The record's non-marker extras may override ``model`` on purpose (the
    # model-identity rows), so the pinned alias is merged first.
    body.setdefault("model", PINNED_MODEL)
    body["messages"] = messages
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _expand_raw_body_repeat(
    record: dict[str, Any],
    marker: Any,
    extra: dict[str, Any],
) -> bytes:
    if not isinstance(marker, dict):
        raise RequestBuildError("$raw_body_repeat is not an object")
    required = {"char", "bytes", "template"}
    if set(marker) != required:
        raise RequestBuildError(
            "$raw_body_repeat must contain exactly char, bytes and template"
        )
    char = marker["char"]
    count_bytes = marker["bytes"]
    template = marker["template"]
    if not isinstance(char, str) or len(char) != 1:
        raise RequestBuildError("$raw_body_repeat char must be exactly one character")
    if isinstance(count_bytes, bool) or not isinstance(count_bytes, int) or count_bytes <= 0:
        raise RequestBuildError("$raw_body_repeat bytes must be a positive integer")
    if template != "chat_content":
        raise RequestBuildError("$raw_body_repeat template is not supported")
    encoded = char.encode("utf-8")
    if count_bytes % len(encoded) != 0:
        raise RequestBuildError(
            "$raw_body_repeat bytes is not a whole number of the char's UTF-8 bytes"
        )
    repeat = count_bytes // len(encoded)
    messages = record.get("messages")
    if not isinstance(messages, list) or not messages:
        raise RequestBuildError("$raw_body_repeat chat_content needs a first message")
    first = messages[0]
    if not isinstance(first, dict):
        raise RequestBuildError("the first message is not an object")
    content = char * repeat
    if len(content.encode("utf-8")) != count_bytes:  # defensive; see docs
        raise RequestBuildError("$raw_body_repeat content is not the requested size")
    expanded = [{"role": first.get("role"), "content": content}]
    expanded.extend(dict(message) for message in messages[1:])
    body: dict[str, Any] = dict(_non_marker_extra(record))
    body["model"] = PINNED_MODEL
    body["messages"] = expanded
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def request_sentinels(record: dict[str, Any], body: bytes) -> list[str]:
    """Distinctive request strings that must not reappear in output or audit.

    The whole serialized request is a sentinel, plus every message content long
    enough to be distinctive.  Fixed strings the product legitimately returns
    are excluded so a normal 200 response is not mistaken for a leak.
    """
    candidates: list[str] = []
    if len(body) >= 32:
        try:
            candidates.append(body.decode("utf-8"))
        except UnicodeDecodeError:
            pass
    for message in record.get("messages") or []:
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str) and len(content) >= 12:
            candidates.append(content)
    extra = record.get("optional_extra")
    if isinstance(extra, dict):
        for key, value in extra.items():
            if isinstance(key, str) and not key.startswith("$"):
                candidates.extend(_iter_request_strings(value))
    sentinels: list[str] = []
    for candidate in candidates:
        if len(candidate) < 12 or candidate in SAFE_CONSTANTS:
            continue
        if any(candidate in safe for safe in SAFE_CONSTANTS):
            # Skip substrings of fixed safe constants (for example the tail of
            # an error message) to avoid a false leak report.  A payload that
            # merely *contains* a safe constant (the raw body contains the
            # pinned model alias) stays a sentinel.
            continue
        if candidate not in sentinels:
            sentinels.append(candidate)
    return sentinels


# ---------------------------------------------------------------------------
# Local mode


class LocalDoubles:
    """Deterministic local guard/tokenizer/generation doubles; no network."""

    def count_tokens(self, serialized: str) -> int:
        return conservative_byte_budget(serialized)

    def scan_attack(self, text: str) -> Any:
        return {"decision": "allow"}

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> str:
        return SAFE_OUTPUT

    def scan_output(self, text: str) -> Any:
        return {"safe": True}


def make_local_sender(
    policy: Policy,
    configuration: EffectiveConfiguration,
) -> tuple[
    Callable[[dict[str, Any], bytes], HttpResponse],
    Callable[[], str],
    Callable[[], None],
]:
    """Build one real ASGI app + TestClient and return send/audit/close."""
    with warnings.catch_warnings():
        # FastAPI's import re-exports Starlette's TestClient; the deprecation
        # notice is about a future httpx rename, not about this run.
        warnings.filterwarnings(
            "ignore", message="Using `httpx` with `starlette.testclient` is deprecated"
        )
        from fastapi.testclient import TestClient

    from nasi_lemak.audit import SqliteAuditStore
    from nasi_lemak.gateway import Gateway
    from nasi_lemak.server import make_app

    temporary = tempfile.TemporaryDirectory(prefix="nasi-lemak-owasp-")
    store = SqliteAuditStore(Path(temporary.name) / "audit.sqlite3")
    gateway = Gateway(
        key_digest=hashlib.sha256(LOCAL_TEST_KEY.encode("utf-8")).hexdigest(),
        audit_store=store,
        adapters=LocalDoubles(),
        policy=policy,
        limits=ChatLimits.defaults(),
    )
    app = make_app(
        gateway=gateway,
        environ={},
        max_body_bytes=configuration.body_limit_bytes,
    )
    client = TestClient(app)
    headers = {
        "content-type": "application/json",
        "authorization": "Bearer " + LOCAL_TEST_KEY,
    }

    def send(record: dict[str, Any], body: bytes) -> HttpResponse:
        response = client.post("/v1/chat/completions", content=body, headers=headers)
        return HttpResponse(status=response.status_code, body=response.content)

    def audit_text() -> str:
        return json.dumps(
            gateway.audit_events(),
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )

    def close() -> None:
        try:
            client.close()
        except Exception:
            pass
        temporary.cleanup()

    return send, audit_text, close


# ---------------------------------------------------------------------------
# Operator mode (never executed by the implementation worker)


def _validate_operator_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise TransportError("operator endpoint is not configured")
    candidate = base_url.strip()
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise TransportError("operator endpoint is not a supported URL")
    return candidate.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so a bearer key is never forwarded to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_operator_sender(
    base_url: str,
    api_key: str,
    timeout: float = 30.0,
) -> Callable[[dict[str, Any], bytes], HttpResponse]:
    endpoint = _validate_operator_url(base_url) + "/v1/chat/completions"
    opener = urllib.request.build_opener(_NoRedirect())

    def send(record: dict[str, Any], body: bytes) -> HttpResponse:
        request = urllib.request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + api_key,
            },
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                return HttpResponse(response.status, response.read())
        except urllib.error.HTTPError as error:
            if error.code == 429:
                raise RateLimited("rate limited by the remote endpoint (HTTP 429)")
            if error.code in (502, 503, 504):
                raise TransportError(
                    f"remote endpoint unavailable (HTTP {error.code})"
                )
            return HttpResponse(error.code, error.read())
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise TransportError("operator transport failure") from error

    return send


def make_missing_operator_sender(reason: str) -> Callable[[dict[str, Any], bytes], HttpResponse]:
    def send(record: dict[str, Any], body: bytes) -> HttpResponse:
        raise TransportError(reason)

    return send


# ---------------------------------------------------------------------------
# Classification and execution


def _decode_observation(response: HttpResponse) -> tuple[int, str | None, str]:
    try:
        text = response.body.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    code: str | None = None
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        payload = None
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict) and isinstance(error.get("code"), str):
            code = error["code"]
    return response.status, code, text


def _contains_error_shape(text: str) -> bool:
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return False
    if not isinstance(payload, dict):
        return False
    if "choices" in payload:
        return False
    return isinstance(payload.get("error"), dict)


def _map_reason(map_row: dict[str, Any]) -> str:
    product_limit = map_row.get("product_limit")
    reason = map_row.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return ""
    if isinstance(product_limit, str) and product_limit.strip():
        return f"{product_limit}: {reason}"
    return reason


# A product response can only carry one of these statuses.  Anything else
# (including 401, 404, 429 and 5xx) is transport-level evidence about the
# endpoint or the connection, not evidence about the product: ERROR, never a
# verdict.
PRODUCT_STATUSES = (200, 400, 403, 413)

AUDIT_UNVERIFIED = "unverified"
AUDIT_VERIFIED = "verified"
AUDIT_FAILED = "failed"
AUDIT_HOW_TO_VERIFY = (
    "Run with an audit reader bound to the deployment's audit store and confirm "
    "that no raw request sentinel appears in any audit row; the operator entry "
    "path accepts an audit_text reader for this purpose."
)


def _derive_audit_state(
    *,
    reader_configured: bool,
    rows_sent: int,
    checks_run: int,
    read_errors: int,
    leaks_detected: int,
) -> tuple[str, str]:
    """The one audit-assertion state machine, derived only from its counters.

    ``verified`` is reachable only when a reader ran for every sent row, at
    least one row was sent, and no read error and no leak occurred.  A reader
    that was configured but never ran is ``unverified``: it is missing
    evidence, never a pass.
    """
    if not reader_configured:
        return (
            AUDIT_UNVERIFIED,
            "no audit reader was supplied, so the no-raw-sentinel-in-audit "
            "assertion did NOT run and no-leak is not claimed",
        )
    if checks_run == 0:
        return (
            AUDIT_UNVERIFIED,
            "no row reached the audit step, so the no-raw-sentinel-in-audit "
            "assertion did NOT run and no-leak is not claimed",
        )
    if read_errors > 0:
        return (
            AUDIT_FAILED,
            f"the audit reader failed for {read_errors} row(s); no-leak is "
            "not claimed",
        )
    if leaks_detected > 0:
        return (
            AUDIT_FAILED,
            "a raw request sentinel was found in "
            f"{leaks_detected} audit row(s); no-leak is not claimed",
        )
    if checks_run < rows_sent:
        return (
            AUDIT_UNVERIFIED,
            "the assertion ran for only "
            f"{checks_run} of {rows_sent} sent rows; no-leak is not claimed "
            "for the rows it did not check",
        )
    return (
        AUDIT_VERIFIED,
        f"the assertion ran for all {rows_sent} sent rows and no sentinel was "
        "found in any audit row",
    )


def _classify(
    record: dict[str, Any],
    map_row: dict[str, Any] | None,
    response: HttpResponse,
    sentinels: list[str],
    audit_text: str,
) -> dict[str, Any]:
    """The one classification function used by local and operator modes.

    Order matters: a transport-level observation is ERROR before any body or
    audit assertion is considered; then a raw sentinel or a missing error
    envelope is FAIL; a corpus status/code match is PASS; and a mismatch is
    NOT-APPLICABLE-CONFIG only when the map explicitly records that the authored
    outcome does not hold and this exact observation is the recorded one, with a
    named reason.  Every other mismatch is FAIL.  ``ERROR`` is excluded from both
    the pass-rate numerator and denominator.
    """
    status, code, body_text = _decode_observation(response)
    expected_status = record["expect_status"]
    expected_code = record.get("expect_code")
    leak = any(sentinel in body_text or sentinel in audit_text for sentinel in sentinels)
    reason = None

    if status not in PRODUCT_STATUSES:
        outcome = "ERROR"
        reason = (
            f"HTTP {status} is a transport-level observation, not a product "
            "outcome; the row was not judged"
        )
    elif leak:
        outcome = "FAIL"
        reason = "a raw request sentinel appeared in the response or an audit row"
    elif status == expected_status and code == expected_code:
        # A 4xx row must fail before generation, so a successful JSON envelope
        # on a status match is a mismatch, not a pass.
        if expected_status in DETERMINISTIC_STATUSES and not _contains_error_shape(
            body_text
        ):
            outcome = "FAIL"
            reason = "status matched but the response was not an error envelope"
        else:
            outcome = "PASS"
    elif (
        isinstance(map_row, dict)
        and map_row.get("holds_under_product_default") is False
        and map_row.get("observed_status") == status
        and map_row.get("observed_code") == code
    ):
        named_reason = _map_reason(map_row)
        if named_reason:
            outcome = "NOT-APPLICABLE-CONFIG"
            reason = named_reason
        else:
            # The map permits N/A for this exact observation but supplies no
            # named reason, so the claim cannot be made.
            outcome = "ERROR"
            reason = (
                "the re-baselining map permits NOT-APPLICABLE-CONFIG for this "
                "observation but supplies no named reason"
            )
    else:
        observed = f"HTTP {status}" + (f" / {code}" if code else "")
        expected = f"HTTP {expected_status}" + (
            f" / {expected_code}" if expected_code else ""
        )
        outcome = "FAIL"
        reason = f"observed {observed}, expected {expected}"

    return {
        "id": record.get("id", "<unknown>"),
        "outcome": outcome,
        "expect_status": expected_status,
        "expect_code": expected_code,
        "observed_status": status,
        "observed_code": code,
        "reason": reason,
        "reason_source": (
            "evals/owasp/rebaseline-llm-top10-2026.json#rows"
            if outcome == "NOT-APPLICABLE-CONFIG"
            else None
        ),
    }


def run_rows(
    records: Iterable[dict[str, Any]],
    map_data: dict[str, Any],
    send: Callable[[dict[str, Any], bytes], HttpResponse],
    configuration: EffectiveConfiguration,
    *,
    audit_text: Callable[[], str] | None = None,
    mode: str = "local",
) -> dict[str, Any]:
    """Exercise every selected row exactly once and return a metadata report."""
    map_rows = {
        row.get("id"): row
        for row in map_data.get("rows", [])
        if isinstance(row, dict)
    }
    map_reference = map_data.get("reference_configuration", {})
    audit_configured = audit_text is not None
    audit_reader = audit_text or (lambda: "")
    rows_sent = 0
    checks_run = 0
    read_errors = 0
    leaks_detected = 0
    started = time.perf_counter()
    report_rows: list[dict[str, Any]] = []

    for record in records:
        row_started = time.perf_counter()
        try:
            body = build_request_body(record)
        except RequestBuildError as error:
            report_rows.append(
                {
                    "id": record.get("id", "<unknown>"),
                    "outcome": "ERROR",
                    "expect_status": record.get("expect_status"),
                    "expect_code": record.get("expect_code"),
                    "observed_status": None,
                    "observed_code": None,
                    "reason": f"uninterpretable fixture marker: {error}",
                    "reason_source": None,
                    "duration_ms": round((time.perf_counter() - row_started) * 1000, 3),
                }
            )
            continue

        sentinels = request_sentinels(record, body)
        try:
            response = send(record, body)
        except RateLimited as error:
            report_rows.append(
                {
                    "id": record.get("id", "<unknown>"),
                    "outcome": "ERROR",
                    "expect_status": record.get("expect_status"),
                    "expect_code": record.get("expect_code"),
                    "observed_status": None,
                    "observed_code": None,
                    "reason": str(error) or "rate limited",
                    "reason_source": None,
                    "duration_ms": round((time.perf_counter() - row_started) * 1000, 3),
                }
            )
            continue
        except TransportError as error:
            report_rows.append(
                {
                    "id": record.get("id", "<unknown>"),
                    "outcome": "ERROR",
                    "expect_status": record.get("expect_status"),
                    "expect_code": record.get("expect_code"),
                    "observed_status": None,
                    "observed_code": None,
                    "reason": str(error) or "transport failure",
                    "reason_source": None,
                    "duration_ms": round((time.perf_counter() - row_started) * 1000, 3),
                }
            )
            continue
        except Exception:
            # A transport or client defect is not evidence about the product.
            report_rows.append(
                {
                    "id": record.get("id", "<unknown>"),
                    "outcome": "ERROR",
                    "expect_status": record.get("expect_status"),
                    "expect_code": record.get("expect_code"),
                    "observed_status": None,
                    "observed_code": None,
                    "reason": "transport failure",
                    "reason_source": None,
                    "duration_ms": round((time.perf_counter() - row_started) * 1000, 3),
                }
            )
            continue

        audit = ""
        rows_sent += 1
        if audit_configured:
            checks_run += 1
            try:
                audit = audit_reader()
            except Exception as error:
                # An audit reader failure is missing evidence, not a pass.  The
                # row is ERROR so a leaked audit row can never be reported as a
                # verified PASS.
                read_errors += 1
                report_rows.append(
                    {
                        "id": record.get("id", "<unknown>"),
                        "outcome": "ERROR",
                        "expect_status": record.get("expect_status"),
                        "expect_code": record.get("expect_code"),
                        "observed_status": response.status,
                        "observed_code": None,
                        "reason": f"audit reader failed: {error}",
                        "reason_source": None,
                        "duration_ms": round(
                            (time.perf_counter() - row_started) * 1000, 3
                        ),
                    }
                )
                continue
        if audit_configured and any(sentinel in audit for sentinel in sentinels):
            leaks_detected += 1
        classified = _classify(
            record,
            map_rows.get(record.get("id")),
            response,
            sentinels,
            audit,
        )
        classified["duration_ms"] = round(
            (time.perf_counter() - row_started) * 1000, 3
        )
        report_rows.append(classified)

    tallies = {outcome: 0 for outcome in OUTCOMES}
    for row in report_rows:
        tallies[row["outcome"]] += 1
    denominator = tallies["PASS"] + tallies["FAIL"]
    audit_leak_check, audit_reason = _derive_audit_state(
        reader_configured=audit_configured,
        rows_sent=rows_sent,
        checks_run=checks_run,
        read_errors=read_errors,
        leaks_detected=leaks_detected,
    )
    report = {
        "schema_version": 1,
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "rows": report_rows,
        "row_count": len(report_rows),
        "tallies": tallies,
        "audit_leak_check": audit_leak_check,
        "audit_leak_check_reason": audit_reason,
        "audit_leak_check_how_to_verify": AUDIT_HOW_TO_VERIFY,
        "audit_rows_sent": rows_sent,
        "audit_checks_run": checks_run,
        "audit_read_errors": read_errors,
        "audit_leaks_detected": leaks_detected,
        "audit_reader_configured": audit_configured,
        "pass_rate": {
            "numerator": tallies["PASS"],
            "denominator": denominator,
            "value": (tallies["PASS"] / denominator) if denominator else None,
            "excluded_error": tallies["ERROR"],
            "excluded_not_applicable_config": tallies["NOT-APPLICABLE-CONFIG"],
            "note": (
                "ERROR is never a verdict; ERROR and NOT-APPLICABLE-CONFIG are "
                "excluded from both numerator and denominator."
            ),
        },
        "reference_configuration": configuration.as_dict(),
        "map_reference_configuration": map_reference,
        "corpus_assumed_limits": CORPUS_ASSUMED_LIMITS,
        "policy_fixture": "scripts/owasp_corpus_policy.yaml",
        "timings": {"total_ms": round((time.perf_counter() - started) * 1000, 3)},
    }
    return report


def run_local(
    *,
    records: list[dict[str, Any]] | None = None,
    map_data: dict[str, Any] | None = None,
    policy: Policy | None = None,
    configuration: EffectiveConfiguration | None = None,
    transport: Callable[[dict[str, Any], bytes], HttpResponse] | None = None,
    audit_text: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Run the deterministic lane locally (or through an injected transport)."""
    records = load_records() if records is None else records
    map_data = load_map() if map_data is None else map_data
    policy = load_fixture_policy() if policy is None else policy
    configuration = (
        load_effective_configuration(policy)
        if configuration is None
        else configuration
    )
    selected = deterministic_rows(records)
    if transport is not None:
        return run_rows(
            selected,
            map_data,
            transport,
            configuration,
            audit_text=audit_text,
            mode="local",
        )
    send, local_audit_reader, close = make_local_sender(policy, configuration)
    try:
        return run_rows(
            selected,
            map_data,
            send,
            configuration,
            audit_text=audit_text if audit_text is not None else local_audit_reader,
            mode="local",
        )
    finally:
        close()


def run_operator(
    send: Callable[[dict[str, Any], bytes], HttpResponse],
    *,
    records: list[dict[str, Any]] | None = None,
    map_data: dict[str, Any] | None = None,
    configuration: EffectiveConfiguration | None = None,
    audit_text: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Run the deterministic lane through an operator sender.

    This is the same row set and the same classifier as :func:`run_local`; only
    the sender differs.  ``audit_text`` is optional because a remote deployment's
    audit store is not automatically readable.  When it is absent the report
    states ``audit_leak_check=unverified`` and no no-leak claim is made.
    """
    records = load_records() if records is None else records
    map_data = load_map() if map_data is None else map_data
    if configuration is None:
        configuration = load_effective_configuration(load_fixture_policy())
    return run_rows(
        deterministic_rows(records),
        map_data,
        send,
        configuration,
        audit_text=audit_text,
        mode="operator",
    )


# ---------------------------------------------------------------------------
# Plan and CLI


def build_plan(
    *,
    records: list[dict[str, Any]],
    map_data: dict[str, Any],
    policy: Policy,
    configuration: EffectiveConfiguration,
    mode: str,
) -> dict[str, Any]:
    selected = deterministic_rows(records)
    map_rows = {
        row.get("id"): row for row in map_data.get("rows", []) if isinstance(row, dict)
    }
    expected_generation_calls = sum(
        1
        for record in selected
        if isinstance(map_rows.get(record.get("id")), dict)
        and map_rows[record.get("id")].get("observed_status") == 200
    )
    self_check = policy_self_check(policy, records)
    allowed_rows = sum(1 for record in records if record.get("expect_status") == 200)
    return {
        "dry_run": True,
        "mode": mode,
        "selected_rows": [record.get("id") for record in selected],
        "row_count": len(selected),
        "expected_http_requests": len(selected),
        "expected_provider_calls": 0 if mode == "local" else expected_generation_calls,
        "expected_generation_calls": expected_generation_calls,
        "effective_configuration": configuration.as_dict(),
        "map_reference_configuration": map_data.get("reference_configuration", {}),
        "corpus_assumed_limits": CORPUS_ASSUMED_LIMITS,
        "policy_fixture": "scripts/owasp_corpus_policy.yaml",
        "policy_model": policy.model,
        "policy_token_budget": policy.token_budget,
        "policy_deny_phrase_count": len(policy.deny_phrases),
        "policy_self_check": {
            "ok": not self_check,
            "checked_expect_200_rows": allowed_rows,
            "problems": self_check,
        },
    }


def _print_reference(report: dict[str, Any]) -> None:
    configuration = report["reference_configuration"]
    print("Reference configuration (effective, from live product configuration):")
    for key in (
        "context_messages",
        "context_budget",
        "default_reply_tokens",
        "max_reply_tokens",
        "body_limit_bytes",
        "policy_token_budget",
        "token_counter",
        "counter_basis",
    ):
        print(f"  {key}: {configuration[key]}")
    assumed = report["corpus_assumed_limits"]
    print("Corpus-assumed limits (authored contract, frozen):")
    for key in (
        "context_messages",
        "serialized_context_limit_characters",
        "max_reply_tokens",
        "policy_token_budget",
    ):
        print(f"  {key}: {assumed[key]}")
    print()


def _print_report(report: dict[str, Any]) -> None:
    _print_reference(report)
    print(f"{'row':<12} {'outcome':<24} {'observed':<22} expected")
    for row in report["rows"]:
        observed = (
            "not sent"
            if row["observed_status"] is None
            else f"{row['observed_status']} {row['observed_code'] or ''}".strip()
        )
        expected = f"{row['expect_status']} {row['expect_code'] or ''}".strip()
        print(
            f"{row['id']:<12} {row['outcome']:<24} {observed:<22} {expected}"
        )
        if row["outcome"] != "PASS" and row["reason"]:
            print(f"  reason: {row['reason']}")
    tallies = report["tallies"]
    print()
    print(
        "Tallies: "
        + ", ".join(f"{outcome}={tallies[outcome]}" for outcome in OUTCOMES)
    )
    rate = report["pass_rate"]
    if rate["denominator"]:
        print(
            f"Pass rate: {rate['numerator']}/{rate['denominator']} "
            "of verdict-bearing rows"
        )
    else:
        print("Pass rate: no verdict-bearing rows (ERROR is never a verdict)")
    audit_state = report["audit_leak_check"]
    print(f"Audit no-raw-sentinel check: {audit_state.upper()}")
    print(
        "  counters:"
        f" audit_rows_sent={report['audit_rows_sent']},"
        f" audit_checks_run={report['audit_checks_run']},"
        f" audit_read_errors={report['audit_read_errors']},"
        f" audit_leaks_detected={report['audit_leaks_detected']}"
    )
    print(f"  audit detail: {report['audit_leak_check_reason']}")
    if audit_state != AUDIT_VERIFIED:
        print(
            "  how to verify: "
            f"{report['audit_leak_check_how_to_verify']}"
        )
    print(f"Total time: {report['timings']['total_ms']} ms")


def _write_json(path: str, payload: dict[str, Any]) -> None:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run the deterministic OWASP corpus lane against the real ASGI app "
            "(local mode, default) or a live operator endpoint."
        )
    )
    parser.add_argument(
        "--operator",
        action="store_true",
        help="target --base-url with a bearer key instead of the local ASGI app",
    )
    parser.add_argument("--base-url", default="", help="operator base URL (never recorded)")
    parser.add_argument(
        "--api-key-env",
        default="NASI_LEMAK_OWASP_API_KEY",
        help="environment variable holding the operator bearer key (never recorded)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="operator request timeout in seconds",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the plan and send nothing",
    )
    parser.add_argument("--json", dest="json_path", default="", help="metadata-only report path")
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    transport: Callable[[dict[str, Any], bytes], HttpResponse] | None = None,
    audit_text: Callable[[], str] | None = None,
) -> int:
    args = _parse_args(argv)
    records = load_records()
    map_data = load_map()
    policy = load_fixture_policy()
    configuration = load_effective_configuration(policy)
    mode = "operator" if args.operator else "local"

    if args.dry_run:
        plan = build_plan(
            records=records,
            map_data=map_data,
            policy=policy,
            configuration=configuration,
            mode=mode,
        )
        print(json.dumps(plan, indent=2, sort_keys=True, ensure_ascii=False))
        return 0 if plan["policy_self_check"]["ok"] else 2

    problems = policy_self_check(policy, records)
    if problems:
        print(
            "Refusing to run: the policy fixture would change an allowed row.",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 2

    if mode == "operator" and transport is None:
        api_key = os.environ.get(args.api_key_env, "")
        if not args.base_url or not api_key:
            sender = make_missing_operator_sender(
                "operator endpoint or credential is not configured"
            )
        else:
            if not (0 < args.timeout <= MAX_OPERATOR_TIMEOUT):
                print("Invalid --timeout.", file=sys.stderr)
                return 2
            sender = make_operator_sender(args.base_url, api_key, timeout=args.timeout)
        report = run_operator(
            sender,
            records=records,
            map_data=map_data,
            configuration=configuration,
            audit_text=audit_text,
        )
    elif mode == "operator":
        report = run_operator(
            transport,
            records=records,
            map_data=map_data,
            configuration=configuration,
            audit_text=audit_text,
        )
    else:
        report = run_local(
            records=records,
            map_data=map_data,
            policy=policy,
            configuration=configuration,
            transport=transport,
            audit_text=audit_text,
        )

    _print_report(report)
    if args.json_path:
        _write_json(args.json_path, report)
        print(f"Report written to {args.json_path}")
    tallies = report["tallies"]
    audit_failed = report["audit_leak_check"] == AUDIT_FAILED
    return (
        0
        if tallies["FAIL"] == 0 and tallies["ERROR"] == 0 and not audit_failed
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
