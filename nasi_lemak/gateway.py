"""Fail-closed, in-process chat gateway. This is not an HTTP server."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditStore, SqliteAuditStore
from .pii import mask_text


MAX_TOKEN_BUDGET = 512
MAX_APP_ID_LENGTH = 128
MAX_POLICY_VERSION_LENGTH = 128
MAX_DENY_PHRASES = 64
MAX_DENY_PHRASE_LENGTH = 256
_APP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


@dataclass(frozen=True)
class Policy:
    """Immutable activated policy.

    There are deliberately no knobs for PII masking, guard verdict handling or
    audit ordering: those controls are unconditional in ``Gateway``.  A policy
    only selects the public app identity, version, alias, token budget and the
    bounded literal deny-phrase list.
    """

    version: str = "synthetic-0.1"
    model: str = "pilot-local"
    token_budget: int = 512
    app_id: str = "synthetic-app"
    deny_phrases: tuple[str, ...] = ()

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

    def denies(self, text: str) -> bool:
        """Literal, case-insensitive substring match; never a regex search."""
        if not isinstance(text, str):
            return True
        folded = text.casefold()
        return any(phrase.casefold() in folded for phrase in self.deny_phrases)

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            {
                "app_id": self.app_id,
                "deny_phrases": list(self.deny_phrases),
                "model": self.model,
                "token_budget": self.token_budget,
                "version": self.version,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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


def mask_pii(text: str) -> str:
    """Experimental ASCII format recognizers; false positives/negatives expected.

    The spans live in :mod:`nasi_lemak.pii` and are shared with the offline
    evaluator.  Format matching does not establish identity validity.
    """
    return mask_text(text)


def serialize_messages(messages: list[dict[str, str]]) -> str:
    """Canonical complete conversation checked by coverage and attack adapters."""
    return "\n".join(f"{message['role']}: {message['content']}" for message in messages)


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
        if not isinstance(policy, Policy):
            raise ValueError("invalid policy")
        if app_id is None:
            app_id = policy.app_id
        elif app_id != policy.app_id:
            # Identity is selected server-side and is part of the canonical
            # policy digest.  A caller cannot pair one policy with another app.
            raise ValueError("invalid app identity")
        self.policy = policy
        self._audit_lock = threading.Lock()
        self.fail_audit_stage: str | None = None
        self.app_id = app_id

    def _audit(self, request_id: str, event_type: str, decision: str, code: str | None = None) -> None:
        stage = "initial" if event_type == "request_started" else "terminal"
        if self.fail_audit_stage == stage:
            raise OSError("audit unavailable")
        with self._audit_lock:
            if event_type == "request_started":
                self.audit_store.record_initial(
                    request_id,
                    self.app_id,
                    self.policy.model,
                    self.policy.version,
                    self.policy.digest,
                )
            else:
                self.audit_store.record_terminal(
                    request_id,
                    event_type,
                    decision,
                    code,
                    app_id=self.app_id,
                    model=self.policy.model,
                    policy_version=self.policy.version,
                    policy_digest=self.policy.digest,
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
        messages = {"INVALID_REQUEST": "Request is not supported.", "UNAUTHORIZED": "Authentication required.", "INPUT_LIMIT": "Request exceeds the supported input limit.", "UNAVAILABLE": "Required safety control is unavailable.", "POLICY_BLOCK": "Request did not pass safety checks."}
        return status, {"error": {"code": code, "message": messages[code], "request_id": request_id}}

    def handle(self, method: str, path: str, headers: Any, body: Any):
        request_id = "req_" + uuid.uuid4().hex
        if method != "POST" or path != "/v1/chat/completions":
            return self._error(404, "INVALID_REQUEST", request_id)
        if not isinstance(headers, dict):
            return self._error(401, "UNAUTHORIZED", request_id)
        supplied = next((value for key, value in headers.items() if isinstance(key, str) and key.lower() == "authorization"), "")
        if not isinstance(supplied, str):
            return self._error(401, "UNAUTHORIZED", request_id)
        candidate = supplied[7:] if supplied.startswith("Bearer ") else ""
        candidate_digest = hashlib.sha256(candidate.encode()).digest()
        if not self._key_valid or not hmac.compare_digest(candidate_digest, self._key_digest):
            return self._error(401, "UNAUTHORIZED", request_id)
        parsed = self._validate(body)
        if parsed == "input_limit":
            return self._error(413, "INPUT_LIMIT", request_id)
        if parsed is None:
            return self._error(400, "INVALID_REQUEST", request_id)
        messages, max_tokens = parsed
        if self.adapters is None:
            return self._error(503, "UNAVAILABLE", request_id)
        try:
            self._audit(request_id, "request_started", "pending")
        except Exception:
            return self._error(503, "UNAVAILABLE", request_id)
        serialized = serialize_messages(messages)
        try:
            count = self.adapters.count_tokens(serialized)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("invalid token count")
        except Exception:
            self._terminal_best_effort(request_id, "failed", "UNAVAILABLE")
            return self._error(503, "UNAVAILABLE", request_id)
        if count > self.policy.token_budget:
            try:
                self._audit(request_id, "request_blocked", "blocked", "INPUT_LIMIT")
            except Exception:
                return self._error(503, "UNAVAILABLE", request_id)
            return self._error(413, "INPUT_LIMIT", request_id)
        try:
            result = self.adapters.scan_attack(serialized)
            if not isinstance(result, dict) or result.get("decision") not in ("allow", "block"):
                raise ValueError("invalid attack result")
            if result["decision"] == "block":
                self._audit(request_id, "request_blocked", "blocked", "POLICY_BLOCK")
                return self._error(403, "POLICY_BLOCK", request_id)
            # Deny phrases are literal policy text, checked across every accepted
            # input turn after the mandatory attack guard and before generation.
            if any(self.policy.denies(message["content"]) for message in messages):
                self._audit(request_id, "request_blocked", "blocked", "POLICY_BLOCK")
                return self._error(403, "POLICY_BLOCK", request_id)
            safe_messages = [{"role": message["role"], "content": mask_pii(message["content"])} for message in messages]
            output = self.adapters.generate(safe_messages, self.policy.model, max_tokens)
            if not isinstance(output, str):
                raise ValueError("invalid generation result")
        except Exception:
            self._terminal_best_effort(request_id, "failed", "UNAVAILABLE")
            return self._error(503, "UNAVAILABLE", request_id)
        try:
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
            if not isinstance(result, dict) or not isinstance(result.get("safe"), bool):
                raise ValueError("invalid output result")
            if not result["safe"]:
                self._audit(request_id, "request_blocked", "blocked", "POLICY_BLOCK")
                return self._error(403, "POLICY_BLOCK", request_id)
            # The complete buffered output is checked before any release.  The
            # mandatory output guard above has already run; this check only
            # adds a policy denial and cannot bypass an unsafe verdict.
            if self.policy.denies(output):
                self._audit(request_id, "request_blocked", "blocked", "POLICY_BLOCK")
                return self._error(403, "POLICY_BLOCK", request_id)
            masked_output = mask_pii(output)
            self._audit(request_id, "request_completed", "allowed")
        except Exception:
            self._terminal_best_effort(request_id, "failed", "UNAVAILABLE")
            return self._error(503, "UNAVAILABLE", request_id)
        return 200, {"id": request_id, "object": "chat.completion", "model": self.policy.model, "choices": [{"index": 0, "message": {"role": "assistant", "content": masked_output}, "finish_reason": "stop"}]}

    def _terminal_best_effort(self, request_id: str, decision: str, code: str):
        try:
            self._audit(request_id, "request_failed", decision, code)
        except Exception:
            pass

    def _validate(self, body: Any):
        if not isinstance(body, dict) or set(body) - {"model", "messages", "stream", "max_tokens"}:
            return None
        if body.get("model") != self.policy.model or body.get("stream", False) is not False:
            return None
        max_tokens = body.get("max_tokens", 256)
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or not 1 <= max_tokens <= 256:
            return None
        messages = body.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 16:
            return None
        clean = []
        for message in messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                return None
            role, content = message["role"], message["content"]
            if not isinstance(role, str) or role not in ("user", "assistant", "system") or not isinstance(content, str) or not content:
                return None
            clean.append({"role": role, "content": content})
        if len(serialize_messages(clean)) > 4096:
            return "input_limit"
        return clean, max_tokens


def make_demo_gateway(audit_path: str | Path):
    key = "demo_" + secrets.token_urlsafe(32)
    adapters = MemoryAdapters()
    return Gateway(key, audit_path, adapters), adapters, key
