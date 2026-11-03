"""Fail-closed, in-process chat gateway. This is not an HTTP server."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import threading
import time
import unicodedata
import uuid
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .audit import AuditStore, SqliteAuditStore
from .controls import API_KEY_PREFIX, GatewayControl, block_detail
from .deny_variants import variants as _deny_variants
from .live_metrics import LiveMetrics
from .diagnostics import GENERATION_TRUNCATED, SIGNAL_CODES, record_signal
from .generation import GenerationError, conservative_byte_budget
from .guards import GuardInputLimit
from .limits import LIMIT_FIELDS, ChatLimits, tighten
from .pii import mask_text
from .qwen3guard import serialize_messages
from .scan_context import ScanContext
from .system_settings import RuntimeSettings


LOGGER = logging.getLogger(__name__)
# Added after the guards read the reply, so it is the one fixed text they never see.
CUT_OFF_NOTICE = "\n\n[This reply was cut off at the length limit. Ask for a shorter answer.]"
# Fixed stage vocabulary for the one content-free failure log line.
FAILURE_STAGES = frozenset(
    {"input_guard", "generation", "output_guard", "audit", "other"}
)
# Fixed vocabulary for the one content-free rejection log line.  A reason that
# is not in this tuple is never rendered: it collapses to ``invalid_request``.
REJECTION_REASONS = (
    "content_type",
    "auth_header",
    "not_ready",
    "admission_full",
    "body_timeout",
    "body_too_large",
    "invalid_json",
    "invalid_body",
    "unauthorized",
    "paused",
    "rate_limited",
    "model_mismatch",
    "unknown_field",
    "invalid_request",
    "input_limit",
)
# The only keys ``_validate`` accepts in a chat body.
CHAT_BODY_FIELDS = frozenset({"model", "messages", "stream", "max_tokens"})


MAX_TOKEN_BUDGET = 32768
MAX_APP_ID_LENGTH = 128
MAX_POLICY_VERSION_LENGTH = 128
MAX_DENY_PHRASES = 64
MAX_DENY_PHRASE_LENGTH = 256
_APP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


class _InputLimit(Exception):
    """Internal marker: the request exceeds the configured context budget."""


class _ScanCancelled(Exception):
    """Internal marker: the per-request scan context is cancelled/deadlined."""


def _normalize_deny_text(text: str) -> str:
    """Canonical form (a) shared by policy phrases and candidate text.

    NFKC first, so compatibility variants (for example fullwidth letters) fold
    to their canonical spelling.  Every Unicode ``Cf`` character (zero-width
    space, bidi controls, soft hyphen, BOM and the rest) is then **deleted**, all
    whitespace runs collapse to one ASCII space and the edges are stripped, and
    the result is casefolded.  This form catches a format character inserted
    inside a word.  Accents are preserved: this is canonical equivalence, not
    accent or diacritic stripping.

    Form (a) is matched only against :func:`_normalize_deny_text_spaced`'s
    counterpart for the candidate; see ``Policy.denies``.
    """
    normalized = unicodedata.normalize("NFKC", text)
    visible = "".join(
        char for char in normalized if unicodedata.category(char) != "Cf"
    )
    return " ".join(visible.split()).casefold()


def _normalize_deny_text_spaced(text: str) -> str:
    """Canonical form (b): every ``Cf`` character becomes one ASCII space.

    Used together with :func:`_normalize_deny_text` and never instead of it.
    Deleting a format character that stands in for the word separator would
    join two words ("synthetic\\u200bdenied" -> "syntheticdenied") and evade a
    literal phrase, so form (b) keeps the separation.  Whitespace runs still
    collapse to a single space and are never removed, so a phrase itself still
    requires its own word boundaries.  NFKC and casefold are identical to form
    (a); accents stay preserved.
    """
    normalized = unicodedata.normalize("NFKC", text)
    spaced = "".join(
        " " if unicodedata.category(char) == "Cf" else char
        for char in normalized
    )
    return " ".join(spaced.split()).casefold()


# Bound once for the variant check in ``Policy.denies``.  The configured text
# is still normalized through the module attributes, so callers that observe
# them (tests included) see exactly one pass for the message itself.
_DENY_NORMALIZE = _normalize_deny_text
_DENY_NORMALIZE_SPACED = _normalize_deny_text_spaced


def _denies_variant(
    text: str,
    normalized_phrases: tuple[str, ...],
    spaced_phrases: tuple[str, ...],
) -> bool:
    normalized = _DENY_NORMALIZE(text)
    if any(phrase in normalized for phrase in normalized_phrases):
        return True
    spaced = _DENY_NORMALIZE_SPACED(text)
    return any(phrase in spaced for phrase in spaced_phrases)


def log_rejection(request_id: str, status: int, reason: str) -> None:
    """Emit exactly one content-free rejection line.

    Only the server-generated request id, the numeric status and a fixed
    vocabulary reason are rendered.  Headers, keys, bodies, model and field
    names, paths and exception text are never passed here.
    """
    safe_reason = reason if reason in REJECTION_REASONS else "invalid_request"
    LOGGER.warning(
        "request_rejected request_id=%s status=%s reason=%s",
        request_id,
        status,
        safe_reason,
    )


@dataclass(frozen=True)
class Policy:
    """Immutable activated policy.

    There are deliberately no knobs for PII masking or audit ordering: those
    controls are unconditional in ``Gateway``.  A policy only selects the public
    app identity, version, alias, token budget, the bounded literal deny-phrase
    list, an optional set of chat-limit tightening values and the guard
    categories it allows on each lane.  ``limits`` is ``None`` when the policy
    file omitted the key, and a flat mapping of field name to positive integer
    otherwise.  Both allow lists are empty unless the policy names categories.
    """

    version: str = "synthetic-0.1"
    model: str = "pilot-local"
    token_budget: int = 512
    app_id: str = "synthetic-app"
    deny_phrases: tuple[str, ...] = ()
    limits: dict[str, int] | None = None
    input_allow_categories: tuple[str, ...] = ()
    output_allow_categories: tuple[str, ...] = ()
    # Derived once at construction, never serialized, hashed or exposed.  They
    # are excluded from equality so policy identity stays the raw configured
    # fields.  Matching uses the union of both canonical forms: (a) deletes
    # format characters, (b) turns each one into a word separator.
    _normalized_deny_phrases: tuple[str, ...] = field(
        init=False, repr=False, compare=False, default=()
    )
    _spaced_deny_phrases: tuple[str, ...] = field(
        init=False, repr=False, compare=False, default=()
    )

    def __post_init__(self):
        if isinstance(self.deny_phrases, list):
            object.__setattr__(self, "deny_phrases", tuple(self.deny_phrases))
        if (
            not isinstance(self.app_id, str)
            or not self.app_id
            or len(self.app_id) > MAX_APP_ID_LENGTH
            or _APP_ID.fullmatch(self.app_id) is None
        ):
            raise ValueError("invalid policy")
        if (
            not isinstance(self.version, str)
            or not self.version
            or len(self.version) > MAX_POLICY_VERSION_LENGTH
            or any(ord(char) < 32 or ord(char) == 127 for char in self.version)
        ):
            raise ValueError("invalid policy")
        if self.model != "pilot-local":
            raise ValueError("invalid policy")
        if (
            isinstance(self.token_budget, bool)
            or not isinstance(self.token_budget, int)
            or not 1 <= self.token_budget <= MAX_TOKEN_BUDGET
        ):
            raise ValueError("invalid policy")
        if not isinstance(self.deny_phrases, tuple) or len(self.deny_phrases) > MAX_DENY_PHRASES:
            raise ValueError("invalid policy")
        for phrase in self.deny_phrases:
            if (
                not isinstance(phrase, str)
                or not phrase
                or len(phrase) > MAX_DENY_PHRASE_LENGTH
            ):
                raise ValueError("invalid policy")
        normalized: list[str] = []
        spaced: list[str] = []
        for phrase in self.deny_phrases:
            candidate = _normalize_deny_text(phrase)
            spaced_candidate = _normalize_deny_text_spaced(phrase)
            # A phrase made only of format characters and/or whitespace would
            # normalize to "", and an empty needle matches every text.  Reject
            # it instead of silently dropping the phrase or denying everything.
            if not candidate or not spaced_candidate:
                raise ValueError("invalid policy")
            normalized.append(candidate)
            spaced.append(spaced_candidate)
        object.__setattr__(self, "_normalized_deny_phrases", tuple(normalized))
        object.__setattr__(self, "_spaced_deny_phrases", tuple(spaced))
        if self.limits is not None:
            raw_limits = self.limits
            if isinstance(raw_limits, (str, bytes, bytearray)) or isinstance(
                raw_limits, bool
            ):
                raise ValueError("invalid policy")
            try:
                supplied = dict(raw_limits)
            except (TypeError, ValueError):
                raise ValueError("invalid policy") from None
            for name, value in supplied.items():
                if name not in LIMIT_FIELDS:
                    raise ValueError("invalid policy")
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    raise ValueError("invalid policy")
            if (
                "default_reply_tokens" in supplied
                and "max_reply_tokens" in supplied
                and supplied["default_reply_tokens"] > supplied["max_reply_tokens"]
            ):
                raise ValueError("invalid policy")
            object.__setattr__(
                self,
                "limits",
                {name: supplied[name] for name in LIMIT_FIELDS if name in supplied},
            )

    def __hash__(self) -> int:
        return hash(
            (
                self.version,
                self.model,
                self.token_budget,
                self.app_id,
                self.deny_phrases,
                None
                if self.limits is None
                else tuple(sorted(self.limits.items())),
            )
        )

    def denies(self, text: str) -> bool:
        """Literal substring match on both normalized forms; never a regex.

        Policy phrases and candidate text use the same two normalizers, so
        compatibility variants, invisible format characters and whitespace
        runs cannot hide a configured phrase.  Form (a) deletes format
        characters (catching one inserted inside a word); form (b) turns each
        into a space (catching one standing in for the word separator).  A
        phrase is only compared with the candidate in its own form, so real
        whitespace is still required: ``"notallowed"`` never matches
        ``"not allowed"``.  The same check is repeated for the light-encoding
        candidates from :mod:`nasi_lemak.deny_variants` (spaced-out letters,
        ROT13 and printable Base64), so those cannot hide the phrase either.
        Callers check each message (or the complete buffered output)
        separately: this method never joins turn boundaries, so a phrase split
        across turns is not matched.
        """
        if not isinstance(text, str):
            return True
        normalized = _normalize_deny_text(text)
        if any(
            phrase in normalized for phrase in self._normalized_deny_phrases
        ):
            return True
        spaced = _normalize_deny_text_spaced(text)
        if any(phrase in spaced for phrase in self._spaced_deny_phrases):
            return True
        return any(
            _denies_variant(
                variant,
                self._normalized_deny_phrases,
                self._spaced_deny_phrases,
            )
            for variant in _deny_variants(text)
        )

    @property
    def digest(self) -> str:
        canonical_document = {
            "app_id": self.app_id,
            "deny_phrases": list(self.deny_phrases),
            "model": self.model,
            "token_budget": self.token_budget,
            "version": self.version,
        }
        if self.limits is not None:
            # Only a policy that actually has the optional key changes the
            # digest, so existing five-key files and audit rows stay comparable.
            canonical_document["limits"] = dict(self.limits)
        if self.input_allow_categories or self.output_allow_categories:
            canonical_document["guard"] = {
                "input_allow_categories": sorted(self.input_allow_categories),
                "output_allow_categories": sorted(self.output_allow_categories),
            }
        canonical = json.dumps(
            canonical_document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _elapsed_ms(started: float) -> int:
    return round((time.perf_counter() - started) * 1000.0)


def _ip_allowed(client_ip: str | None, networks: list[str]) -> bool:
    """True when a key has no allowlist, or the caller is inside it."""
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(client_ip or "")
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network) for network in networks)


def _policy_allows(result: dict[str, Any], allowed: tuple[str, ...]) -> bool:
    """True when every category behind a block is one the policy allows.

    A block that names no category stays a block.
    """
    categories = result.get("categories")
    return (
        bool(allowed)
        and isinstance(categories, (list, tuple))
        and bool(categories)
        and all(category in allowed for category in categories)
    )


class MemoryAdapters:
    """Deterministic synthetic demo fixture. Its token counter is not a tokenizer."""

    def __init__(self):
        self.attack_inputs: list[str] = []
        self.generation_inputs: list[list[dict[str, str]]] = []
        self.generate_options: list[tuple[str, int]] = []
        self.generated = "Synthetic local answer."
        self.attack_result: Any = {"decision": "allow"}
        self.output_result: Any = {"safe": True}
        self.attack_error: Exception | None = None
        self.output_error: Exception | None = None
        self.token_count = lambda serialized: max(1, len(serialized.split()))

    def scan_attack(self, text: str) -> Any:
        self.attack_inputs.append(text)
        if self.attack_error:
            raise self.attack_error
        return self.attack_result

    def count_tokens(self, serialized: str) -> Any:
        return self.token_count(serialized)

    def generate(self, messages: list[dict[str, str]], model: str, max_tokens: int) -> Any:
        self.generation_inputs.append([dict(m) for m in messages])
        self.generate_options.append((model, max_tokens))
        return self.generated

    def scan_output(self, text: str) -> Any:
        if self.output_error:
            raise self.output_error
        return self.output_result


def mask_pii(text: str, masks: tuple[str, ...] | None = None) -> str:
    """Experimental ASCII format recognizers; false positives/negatives expected.

    The spans live in :mod:`nasi_lemak.pii` and are shared with the offline
    evaluator.  Format matching does not establish identity validity.
    ``masks`` is the explicit per-request selection; ``None`` preserves the
    original all-recognizer behaviour.
    """
    return mask_text(text, masks)


class Gateway:
    def __init__(
        self,
        app_key: str | None = None,
        audit_path: str | Path | None = None,
        adapters: Any = None,
        policy: Policy = Policy(),
        *,
        key_digest: str | None = None,
        audit_store: AuditStore | None = None,
        app_id: str | None = None,
        limits: ChatLimits | None = None,
        diagnostics: Any = None,
    ):
        if key_digest is not None:
            if not isinstance(key_digest, str) or len(key_digest) != 64:
                raise ValueError("invalid key digest")
            self._key_digest = bytes.fromhex(key_digest)
            self._key_valid = True
        elif isinstance(app_key, str) and app_key:
            self._key_digest = hashlib.sha256(app_key.encode()).digest()
            self._key_valid = True
        else:
            self._key_digest = b""
            self._key_valid = False

        if audit_store is not None:
            if not isinstance(audit_store, AuditStore):
                raise ValueError("invalid audit store")
            self.audit_store = audit_store
        elif audit_path is not None:
            self.audit_store = SqliteAuditStore(audit_path)
        else:
            raise ValueError("audit path or store required")

        self.adapters = adapters
        self.metrics = LiveMetrics()
        # Set by the server when the workspace store can answer for named keys.
        self.api_keys: Any = None
        # Replaced by the server with the instance both gateways share.
        self.settings = RuntimeSettings()
        self._key_hits: dict[str, deque[float]] = {}
        self._key_hits_lock = threading.Lock()
        self._extra_denies: tuple[int, Policy] | None = None
        if not isinstance(policy, Policy):
            raise ValueError("invalid policy")
        if limits is None:
            limits = ChatLimits.defaults()
        elif not isinstance(limits, ChatLimits):
            raise ValueError("invalid chat limits")
        self.limits = limits
        if app_id is None:
            app_id = policy.app_id
        elif app_id != policy.app_id:
            # Identity is selected server-side and is part of the canonical
            # policy digest.  A caller cannot pair one policy with another app.
            raise ValueError("invalid app identity")
        self.policy = policy
        self._audit_lock = threading.Lock()
        self.fail_audit_stage: str | None = None
        # Optional fixed-code diagnostic sink (for example ``SafeDiagnostics``).
        # It is best-effort and never changes fail-closed ordering.
        self.diagnostics = diagnostics
        self.app_id = app_id

    def _audit(self, request_id: str, event_type: str, decision: str, code: str | None = None) -> float:
        """Write one audit row and return the timestamp that row recorded.

        Nothing else is timed here: the returned value is the audit store's own
        ``timestamp`` column value, so a served latency can be derived from the
        two audit rows without inventing a second timer.
        """
        stage = "initial" if event_type == "request_started" else "terminal"
        if self.fail_audit_stage == stage:
            raise OSError("audit unavailable")
        version, digest = self.settings.effective_policy(
            self.policy.version, self.policy.digest
        )
        with self._audit_lock:
            if event_type == "request_started":
                return self.audit_store.record_initial(
                    request_id,
                    self.app_id,
                    self.policy.model,
                    version,
                    digest,
                )
            return self.audit_store.record_terminal(
                request_id,
                event_type,
                decision,
                code,
                app_id=self.app_id,
                model=self.policy.model,
                policy_version=version,
                policy_digest=digest,
            )

    def audit_events(self) -> list[dict[str, Any]]:
        with self._audit_lock:
            return self.audit_store.read_events()

    def reconcile_incomplete(self, *, offline: bool = False) -> int:
        """Explicit offline recovery. Stop all gateway writers before calling."""
        if offline is not True:
            raise ValueError("offline confirmation required")
        with self._audit_lock:
            return self.audit_store.reconcile_incomplete(offline=True)

    @staticmethod
    def _error(status: int, code: str, request_id: str):
        messages = {"INVALID_REQUEST": "Request is not supported.", "UNAUTHORIZED": "Authentication required.", "INPUT_LIMIT": "Request exceeds the supported input limit.", "UNAVAILABLE": "Required safety control is unavailable.", "POLICY_BLOCK": "Request did not pass safety checks.", "RATE_LIMITED": "Too many requests for this key."}
        return status, {"error": {"code": code, "message": messages[code], "request_id": request_id}}

    @classmethod
    def _blocked(cls, request_id: str, reason_code: str):
        status, body = cls._error(403, "POLICY_BLOCK", request_id)
        # Fixed, bounded detail only: never classifier verdict text, rules,
        # the original prompt or any withheld output.
        body["error"]["block"] = block_detail(reason_code)
        return status, body

    @staticmethod
    def _resolve_control(control: GatewayControl | None) -> GatewayControl:
        if control is None:
            return GatewayControl()
        if not isinstance(control, GatewayControl):
            raise ValueError("invalid gateway control")
        return control

    def handle(
        self,
        method: str,
        path: str,
        headers: Any,
        body: Any,
        *,
        scan_context: ScanContext | None = None,
        control: GatewayControl | None = None,
        result_sink: dict[str, Any] | None = None,
        client_ip: str | None = None,
    ):
        """Run the pipeline and record its timing for the Monitor screen."""
        timing: dict[str, Any] = {}
        status = 0
        sink = {} if result_sink is None else result_sink
        self.metrics.enter()
        try:
            outcome = self._pipeline(
                method,
                path,
                headers,
                body,
                timing,
                scan_context=scan_context,
                control=control,
                result_sink=sink,
                client_ip=client_ip,
            )
            outcome = self._finish_named_key(timing, outcome, sink)
            status = outcome[0]
            return outcome
        finally:
            self.metrics.leave(timing, status)

    def _named_key(
        self, candidate: str, digest: bytes, client_ip: str | None
    ) -> dict[str, Any] | None:
        if self.api_keys is None or not candidate.startswith(API_KEY_PREFIX):
            return None
        key = self.api_keys.resolve_api_key(digest.hex())
        if key is None or not _ip_allowed(client_ip, key["allowed_ips"]):
            return None
        return key

    def _shared_key_allowed(self) -> bool:
        # The workspace's internal gateway has no ``api_keys`` and keeps working.
        return self.api_keys is None or self.settings.snapshot()[1]["shared_key_enabled"]

    def _within_rate(self, key: dict[str, Any]) -> bool:
        limit = key["requests_per_minute"]
        if limit is None:
            limit = self.settings.snapshot()[1]["key_requests_per_minute"]
        if limit is None:
            return True
        now = time.monotonic()
        with self._key_hits_lock:
            hits = self._key_hits.setdefault(key["id"], deque())
            while hits and now - hits[0] >= 60.0:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def _denied(self, text: str) -> bool:
        """Check the policy file's phrases, then any added in Settings."""
        if self.policy.denies(text):
            return True
        revision, values = self.settings.snapshot()
        if not values["deny_phrases"]:
            return False
        cached = self._extra_denies
        if cached is None or cached[0] != revision:
            cached = (
                revision,
                replace(self.policy, deny_phrases=tuple(values["deny_phrases"])),
            )
            self._extra_denies = cached
        return cached[1].denies(text)

    def _allowed_categories(self, lane: str) -> tuple[str, ...]:
        """The file's allowed categories, narrowed by Settings, never widened."""
        allowed = getattr(self.policy, f"{lane}_allow_categories")
        chosen = self.settings.snapshot()[1][f"{lane}_allow_categories"]
        return allowed if chosen is None else tuple(c for c in allowed if c in chosen)

    def _finish_named_key(
        self, timing: dict[str, Any], outcome: Any, sink: dict[str, Any]
    ) -> Any:
        """Record how a key's request ended, before anything is released.

        The audit log stays the authority, so this is best effort, unless the
        key's text must be kept: a reply that cannot be stored is withheld.
        """
        key = timing.get("named_key")
        if key is None:
            return outcome
        request_id = timing["request_id"]
        status, body = outcome
        result = "allowed" if status == 200 else "blocked" if status in (403, 413) else "failed"
        error = body.get("error", {}) if isinstance(body, dict) else {}
        alert = None
        if isinstance(error.get("block"), dict):
            metadata = timing["control"].metadata()
            alert = {
                "stage": error["block"]["stage"],
                "reason_code": error["block"]["reason_code"],
                "revision": metadata["revision"],
                "digest": metadata["digest"],
                "sources": metadata["sources"],
            }
        prompt = reply = None
        if key["store_text"]:
            prompt = json.dumps(
                sink.get("sanitized_messages") or timing["messages"], ensure_ascii=False
            )
            if status == 200:
                reply = body["choices"][0]["message"]["content"]
        try:
            self.api_keys.record_api_key_result(
                key,
                request_id,
                outcome=result,
                error_code=error.get("code"),
                alert=alert,
                prompt=prompt,
                reply=reply,
            )
        except Exception:
            self._log_failure(request_id, "other", None)
            if key["store_text"] and status == 200:
                return self._error(503, "UNAVAILABLE", request_id)
        return outcome

    def _pipeline(
        self,
        method: str,
        path: str,
        headers: Any,
        body: Any,
        timing: dict[str, Any],
        *,
        scan_context: ScanContext | None = None,
        control: GatewayControl | None = None,
        result_sink: dict[str, Any] | None = None,
        client_ip: str | None = None,
    ):
        """Run the one guarded pipeline for one request.

        ``result_sink`` is an optional, request-local, in-memory mapping that is
        filled alongside the existing successful stages.  It never changes
        control ordering, audit rows, releases or return values.  Keys are
        bounded pipeline facts only: ``input_decision`` (the validated adapter
        verdict ``allow``/``block``), ``output_safe`` (the validated output
        verdict boolean), ``sanitized_messages`` (the exact masked messages
        passed to generation), ``audit_started_at`` and ``audit_terminal_at``
        (the timestamps the audit store itself wrote) and ``api_key_name``.  Raw withheld output and
        classifier text are never written.  Fields for stages that did not run
        stay absent.
        """
        request_id = "req_" + uuid.uuid4().hex
        if method != "POST" or path != "/v1/chat/completions":
            return self._error(404, "INVALID_REQUEST", request_id)
        if not isinstance(headers, dict):
            log_rejection(request_id, 401, "unauthorized")
            return self._error(401, "UNAUTHORIZED", request_id)
        supplied = next((value for key, value in headers.items() if isinstance(key, str) and key.lower() == "authorization"), "")
        if not isinstance(supplied, str):
            log_rejection(request_id, 401, "unauthorized")
            return self._error(401, "UNAUTHORIZED", request_id)
        candidate = supplied[7:] if supplied.startswith("Bearer ") else ""
        candidate_digest = hashlib.sha256(candidate.encode()).digest()
        named_key = None
        if (
            not self._key_valid
            or not hmac.compare_digest(candidate_digest, self._key_digest)
            or not self._shared_key_allowed()
        ):
            # The shared key is checked first and needs no database, so a
            # workspace outage can only affect named keys.
            try:
                named_key = self._named_key(candidate, candidate_digest, client_ip)
            except Exception:
                log_rejection(request_id, 503, "not_ready")
                return self._error(503, "UNAVAILABLE", request_id)
            if named_key is None:
                log_rejection(request_id, 401, "unauthorized")
                return self._error(401, "UNAUTHORIZED", request_id)
            if result_sink is not None:
                result_sink["api_key_name"] = named_key["name"]
        if self.adapters is None:
            log_rejection(request_id, 503, "not_ready")
            return self._error(503, "UNAVAILABLE", request_id)
        settings = self.settings.snapshot()[1]
        if settings["paused"]:
            log_rejection(request_id, 503, "paused")
            return self._error(503, "UNAVAILABLE", request_id)
        if named_key is not None:
            if not self._within_rate(named_key):
                log_rejection(request_id, 429, "rate_limited")
                return self._error(429, "RATE_LIMITED", request_id)
            try:
                # A key follows its owner's policy, the same as their chats.
                control = self.api_keys.resolve_gateway_control(named_key["owner_id"])
            except Exception:
                log_rejection(request_id, 503, "not_ready")
                return self._error(503, "UNAVAILABLE", request_id)
        try:
            control = self._resolve_control(control)
        except ValueError:
            log_rejection(request_id, 503, "not_ready")
            return self._error(503, "UNAVAILABLE", request_id)
        effective_limits = tighten(
            tighten(self.limits, settings["chat_limits"]), dict(control.limits)
        )
        parsed = self._validate(body, effective_limits)
        if parsed == "input_limit":
            log_rejection(request_id, 413, "input_limit")
            return self._error(413, "INPUT_LIMIT", request_id)
        if parsed is None:
            log_rejection(request_id, 400, self._validate_reason(body))
            return self._error(400, "INVALID_REQUEST", request_id)
        messages, max_tokens = parsed

        def _sink(name: str, value: Any) -> None:
            if result_sink is not None:
                result_sink[name] = value

        def _audit_sink(
            event_type: str, decision: str, code: str | None = None
        ) -> float:
            """Write the audit row, then expose the timestamp it recorded.

            The sink only receives the timestamp the store actually wrote, so a
            missing pipeline stage stays absent rather than being estimated.
            """
            timestamp = self._audit(request_id, event_type, decision, code)
            _sink(
                "audit_started_at"
                if event_type == "request_started"
                else "audit_terminal_at",
                timestamp,
            )
            return timestamp

        try:
            # Written first, so no request can reach the model unattributed.
            if named_key is not None:
                self.api_keys.record_api_key_use(named_key["id"], request_id, client_ip)
                timing.update(
                    named_key=named_key,
                    request_id=request_id,
                    control=control,
                    messages=messages,
                )
            _audit_sink("request_started", "pending")
        except Exception:
            return self._error(503, "UNAVAILABLE", request_id)
        timing["started"] = time.perf_counter()
        serialized = serialize_messages(messages)
        try:
            if conservative_byte_budget(serialized) > effective_limits.context_budget:
                raise _InputLimit()
            count = self.adapters.count_tokens(serialized)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("invalid token count")
        except _InputLimit:
            try:
                _audit_sink("request_blocked", "blocked", "INPUT_LIMIT")
            except Exception:
                return self._error(503, "UNAVAILABLE", request_id)
            return self._error(413, "INPUT_LIMIT", request_id)
        except Exception:
            self._terminal_best_effort(
                request_id, "failed", "UNAVAILABLE", stage="input_guard"
            )
            return self._error(503, "UNAVAILABLE", request_id)
        if count > self.policy.token_budget:
            try:
                _audit_sink("request_blocked", "blocked", "INPUT_LIMIT")
            except Exception:
                return self._error(503, "UNAVAILABLE", request_id)
            return self._error(413, "INPUT_LIMIT", request_id)
        # Track the current pipeline stage so a generic failure is labelled with
        # the step that raised it.  Only fixed vocabulary values are stored.
        stage = "other"
        try:
            if scan_context is not None and scan_context.cancelled():
                raise _ScanCancelled()
            stage = "input_guard"
            if control.input_check_enabled:
                scan_started = time.perf_counter()
                if scan_context is not None and getattr(
                    self.adapters, "supports_scan_context", False
                ):
                    result = self.adapters.scan_attack(
                        serialized, scan_context=scan_context
                    )
                else:
                    result = self.adapters.scan_attack(serialized)
                timing["input_ms"] = _elapsed_ms(scan_started)
                if not isinstance(result, dict) or result.get("decision") not in ("allow", "block"):
                    raise ValueError("invalid attack result")
                if result["decision"] == "block" and not _policy_allows(
                    result, self._allowed_categories("input")
                ):
                    _sink("input_decision", "block")
                    _audit_sink("request_blocked", "blocked", "POLICY_BLOCK")
                    return self._blocked(request_id, "INPUT_GUARD_BLOCK")
                _sink("input_decision", "allow")
            stage = "other"
            # Deny phrases are literal policy text, checked across every accepted
            # input turn before generation.  Disabling the model classifier never
            # disables this server-side policy control.
            if any(self._denied(message["content"]) for message in messages):
                _audit_sink("request_blocked", "blocked", "POLICY_BLOCK")
                return self._blocked(request_id, "INPUT_POLICY_BLOCK")
            # A cancelled/deadlined workspace request must not launch new
            # inference after a successful scan.
            if scan_context is not None and scan_context.cancelled():
                raise _ScanCancelled()
            safe_messages = [
                {
                    "role": message["role"],
                    "content": mask_pii(message["content"], control.input_masks),
                }
                for message in messages
            ]
            _sink("sanitized_messages", [dict(message) for message in safe_messages])
            stage = "generation"
            generation_started = time.perf_counter()
            output = self.adapters.generate(safe_messages, self.policy.model, max_tokens)
            timing["generation_ms"] = _elapsed_ms(generation_started)
            read_usage = getattr(self.adapters, "last_usage", None)
            usage = read_usage() if callable(read_usage) else None
            if usage:
                timing["prompt_tokens"] = usage["prompt_tokens"]
                timing["reply_tokens"] = usage["completion_tokens"]
            read_finish = getattr(self.adapters, "last_finish_reason", None)
            cut_off = callable(read_finish) and read_finish() == "length"
            if not isinstance(output, str):
                raise ValueError("invalid generation result")
        except GenerationError as exc:
            # Preserve the failed-versus-blocked distinction: this is a failed
            # generation, not a policy block, and no alert is written.  Only a
            # fixed internal code crosses the boundary.
            if exc.diagnostic_code:
                self._note_diagnostic(scan_context, exc.diagnostic_code)
            self._terminal_best_effort(
                request_id,
                "failed",
                "UNAVAILABLE",
                stage="generation",
                diagnostic_code=exc.diagnostic_code,
            )
            return self._error(503, "UNAVAILABLE", request_id)
        except GuardInputLimit:
            try:
                _audit_sink("request_blocked", "blocked", "INPUT_LIMIT")
            except Exception:
                return self._error(503, "UNAVAILABLE", request_id)
            return self._error(413, "INPUT_LIMIT", request_id)
        except Exception:
            self._terminal_best_effort(
                request_id, "failed", "UNAVAILABLE", stage=stage
            )
            return self._error(503, "UNAVAILABLE", request_id)
        try:
            if scan_context is not None and scan_context.cancelled():
                raise _ScanCancelled()
            if control.output_check_enabled:
                scan_started = time.perf_counter()
                contextual_scan = getattr(self.adapters, "scan_response", None)
                if callable(contextual_scan):
                    # Each request passes its own complete sanitized conversation.
                    # Guard/composite objects must not cache it between requests.
                    context = [dict(message) for message in safe_messages]
                    result = contextual_scan(context, output)
                else:
                    # Legacy synthetic test adapters only implement response-only
                    # scanning. Genuine adapters must provide ``scan_response``.
                    result = self.adapters.scan_output(output)
                timing["output_ms"] = _elapsed_ms(scan_started)
                if not isinstance(result, dict) or not isinstance(result.get("safe"), bool):
                    raise ValueError("invalid output result")
                safe = result["safe"] or _policy_allows(
                    result, self._allowed_categories("output")
                )
                _sink("output_safe", safe)
                if not safe:
                    _audit_sink("request_blocked", "blocked", "POLICY_BLOCK")
                    return self._blocked(request_id, "OUTPUT_GUARD_BLOCK")
            # The complete buffered output is checked before any release.
            # Disabling the model output classifier never bypasses the literal
            # policy deny list.
            if self._denied(output):
                _audit_sink("request_blocked", "blocked", "POLICY_BLOCK")
                return self._blocked(request_id, "OUTPUT_POLICY_BLOCK")
            masked_output = mask_pii(output, control.output_masks)
            _sink("output_masked", masked_output != output)
        except Exception:
            self._terminal_best_effort(
                request_id, "failed", "UNAVAILABLE", stage="output_guard"
            )
            return self._error(503, "UNAVAILABLE", request_id)
        try:
            _audit_sink("request_completed", "allowed")
        except Exception:
            self._terminal_best_effort(
                request_id, "failed", "UNAVAILABLE", stage="audit"
            )
            return self._error(503, "UNAVAILABLE", request_id)
        if cut_off:
            self._note_diagnostic(scan_context, GENERATION_TRUNCATED)
            masked_output += CUT_OFF_NOTICE
        return 200, {"id": request_id, "object": "chat.completion", "model": self.policy.model, "choices": [{"index": 0, "message": {"role": "assistant", "content": masked_output}, "finish_reason": "length" if cut_off else "stop"}]}

    def _note_diagnostic(self, scan_context: ScanContext | None, code: str) -> None:
        """Record one fixed code on the per-request and/or gateway sink once."""
        if scan_context is not None:
            scan_context.note(code)
            if self.diagnostics is not None and scan_context.diagnostic is self.diagnostics:
                return
        record_signal(self.diagnostics, code)

    def _terminal_best_effort(
        self,
        request_id: str,
        decision: str,
        code: str,
        *,
        stage: str = "other",
        diagnostic_code: str | None = None,
    ):
        self._log_failure(request_id, stage, diagnostic_code)
        try:
            self._audit(request_id, "request_failed", decision, code)
        except Exception:
            pass

    @staticmethod
    def _log_failure(
        request_id: str, stage: str, diagnostic_code: str | None
    ) -> None:
        """Emit exactly one content-free failure stage line.

        Only the server-generated request id and fixed vocabulary values are
        rendered.  Prompts, replies, provider bodies, exception text and keys
        are never passed here.
        """
        safe_stage = stage if stage in FAILURE_STAGES else "other"
        fields = [f"request_failed request_id={request_id}", f"stage={safe_stage}"]
        if diagnostic_code in SIGNAL_CODES:
            fields.append(f"diagnostic={diagnostic_code}")
        LOGGER.warning(" ".join(fields))

    def _validate_reason(self, body: Any) -> str:
        """Derive the fixed rejection reason for a ``_validate`` failure.

        The derivation is read-only and does not affect ``_validate``'s return
        values.  It distinguishes a model mismatch, an unknown top-level field
        and everything else, without ever rendering the body itself.
        """
        if not isinstance(body, dict):
            return "invalid_request"
        if set(body) - CHAT_BODY_FIELDS:
            return "unknown_field"
        if "model" in body and body["model"] != self.policy.model:
            return "model_mismatch"
        return "invalid_request"

    def _validate(self, body: Any, limits: ChatLimits | None = None):
        if limits is None:
            limits = self.limits
        if not isinstance(body, dict) or set(body) - CHAT_BODY_FIELDS:
            return None
        if body.get("model") != self.policy.model or body.get("stream", False) is not False:
            return None
        max_tokens = body.get("max_tokens", limits.default_reply_tokens)
        if (
            isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)
            or not 1 <= max_tokens <= limits.max_reply_tokens
        ):
            return None
        messages = body.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= limits.context_messages:
            return None
        clean = []
        for message in messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                return None
            role, content = message["role"], message["content"]
            if not isinstance(role, str) or role not in ("user", "assistant", "system") or not isinstance(content, str) or not content:
                return None
            clean.append({"role": role, "content": content})
        serialized = serialize_messages(clean)
        # Finite memory bound before the conservative-unit budget check that
        # runs after the audit start.  The configured budget is authoritative.
        if len(serialized) > limits.context_budget:
            return "input_limit"
        return clean, max_tokens


def make_demo_gateway(audit_path: str | Path):
    key = "demo_" + secrets.token_urlsafe(32)
    adapters = MemoryAdapters()
    return Gateway(key, audit_path, adapters), adapters, key
