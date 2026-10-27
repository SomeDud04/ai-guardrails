"""Opt-in HTTP surface for the protected employee workspace.

This module registers the ``/workspace`` routes on the existing FastAPI app. It
is deliberately independent from the legacy demo/chat/admin surface: when
``NASI_LEMAK_WORKSPACE_ENABLED`` is not exactly ``true`` no route, no workspace
database connection and no internal gateway is created.

Security boundaries enforced here:

* Configuration is file-only (``*_DSN_FILE`` / ``*_KEY_FILE``), bounded and
  fail-closed. A missing/invalid configuration leaves the workspace routes
  returning a generic 503 and the readiness component unready. There is no
  automatic empty database, default account, SQLite runtime fallback or
  plaintext environment secret fallback.
* Login is an opaque bearer token in tab memory. Every DB/password operation is
  dispatched through the existing bounded control-plane admission; no request
  waits in an unbounded queue and no thread is dispatched before admission.
* Password login is rate limited in-process before any KDF work. The limiter
  stores only an unkeyed SHA256 digest of IP+username, never the password or
  token.
* Browser-facing credential/session APIs require HTTPS unless the explicit
  ``NASI_LEMAK_WORKSPACE_ALLOW_HTTP=true`` LAN-demo acknowledgement is set.
  ``X-Forwarded-Proto`` is never trusted. Origins are checked, no CORS headers
  are emitted and every workspace response is ``Cache-Control: no-store``.
* Conversation/context building reuses the real ``Gateway.handle`` safety path
  through a server-private gateway credential. The browser never sees that
  credential, and the legacy app key is never reused for workspace calls.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import json
import os
import secrets
import stat
import threading
import time
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .controls import BLOCK_REASONS, GatewayControl, block_detail
from .diagnostics import BLOCK_PAYLOAD_REJECTED, SafeDiagnostics
from .gateway import Gateway, serialize_messages
from .generation import conservative_byte_budget
from .limits import ChatLimits
from .scan_context import ScanContext
from .workspace_store import (
    LEASE_TTL_SECONDS,
    SESSION_TTL_SECONDS,
    AccessDenied,
    AuthError,
    Conflict,
    NotFound,
    WorkspaceError,
    WorkspaceStore,
)

ENV_ENABLED = "NASI_LEMAK_WORKSPACE_ENABLED"
ENV_DSN_FILE = "NASI_LEMAK_WORKSPACE_DSN_FILE"
ENV_KEY_FILE = "NASI_LEMAK_WORKSPACE_KEY_FILE"
ENV_ALLOW_HTTP = "NASI_LEMAK_WORKSPACE_ALLOW_HTTP"

WORKSPACE_BODY_BYTES = 64 * 1024
SECRET_FILE_MAX_BYTES = 8192
WORKSPACE_DB_TIMEOUT = 5.0
# Input/reply bounds now come from the immutable shared ChatLimits object.
LOGIN_WINDOW_SECONDS = 60.0
SESSION_COOKIE = "nasi_lemak_workspace"
COOKIE_PATH = "/workspace"
COOKIE_MAX_BYTES = 4096
LOGIN_MAX_ATTEMPTS = 5
LOGIN_CACHE_MAX = 512
USER_WINDOW_SECONDS = 60.0
USER_MAX_REQUESTS = 30
USER_INFLIGHT_LIMIT = 2
PRINCIPAL_CACHE_MAX = 100

_COMMON_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

_ERROR_MESSAGES = {
    "INVALID_REQUEST": "Request is not supported.",
    "UNAUTHORIZED": "Authentication required.",
    "FORBIDDEN": "Permission denied.",
    "CONFLICT": "The resource is busy.",
    "INPUT_LIMIT": "Request exceeds the supported input limit.",
    "RATE_LIMIT": "Too many attempts; retry later.",
    "IDENTITY_CONFLICT": "This browser session belongs to a different account.",
    "UNAVAILABLE": "Required workspace control is unavailable.",
}

_TIMEOUT = object()


class _Busy(Exception):
    """Shared control-plane admission is saturated or timed out."""


class _BodyProblem(Exception):
    def __init__(self, status: int) -> None:
        super().__init__("workspace body rejected")
        self.status = status


class _AuthProblem(Exception):
    def __init__(self, status: int = 401, code: str = "UNAUTHORIZED") -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class _LoginLimiter:
    """Bounded in-process login limiter; never stores password or token.

    The key is a SHA-256 digest of bounded client IP + normalised username. The
    limiter is a local abuse control, not a distributed guarantee.
    """

    def __init__(self, clock: Any = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    @staticmethod
    def key(ip: str, username: str) -> str:
        raw = f"{str(ip)[:64]}\x00{str(username)[:128].strip().lower()}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()

    def _prune(self, now: float) -> None:
        cutoff = now - LOGIN_WINDOW_SECONDS
        for key in list(self._hits):
            kept = [stamp for stamp in self._hits[key] if stamp > cutoff]
            if kept:
                self._hits[key] = kept
            else:
                del self._hits[key]

    def blocked(self, key: str) -> bool:
        with self._lock:
            now = self._clock()
            self._prune(now)
            if key not in self._hits:
                if len(self._hits) >= LOGIN_CACHE_MAX:
                    # Bound the cache even under a rotating IP/username spray.
                    oldest = min(
                        self._hits,
                        key=lambda item: self._hits[item][-1]
                        if self._hits[item]
                        else 0,
                    )
                    del self._hits[oldest]
                self._hits[key] = []
            return len(self._hits[key]) >= LOGIN_MAX_ATTEMPTS

    def record(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            self._prune(now)
            bucket = self._hits.setdefault(key, [])
            bucket.append(now)
            if len(bucket) > LOGIN_MAX_ATTEMPTS:
                del bucket[: len(bucket) - LOGIN_MAX_ATTEMPTS]
            if len(self._hits) > LOGIN_CACHE_MAX:
                oldest = min(
                    self._hits,
                    key=lambda item: self._hits[item][-1] if self._hits[item] else 0,
                )
                del self._hits[oldest]


class _PrincipalGuard:
    """Bounded per-principal rate/in-flight guard.

    The cache keeps at most ``PRINCIPAL_CACHE_MAX`` principals. Exceeding either
    bound rejects with 429 instead of queueing work.
    """

    def __init__(self, clock: Any = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._inflight: dict[str, int] = {}
        self._windows: dict[str, list[float]] = {}

    def try_begin(self, user_id: str) -> bool:
        with self._lock:
            now = self._clock()
            cutoff = now - USER_WINDOW_SECONDS
            bucket = [stamp for stamp in self._windows.get(user_id, ()) if stamp > cutoff]
            if user_id not in self._windows and len(self._windows) >= PRINCIPAL_CACHE_MAX:
                oldest = min(
                    self._windows,
                    key=lambda item: self._windows[item][-1]
                    if self._windows[item]
                    else 0,
                )
                del self._windows[oldest]
            if len(bucket) >= USER_MAX_REQUESTS:
                self._windows[user_id] = bucket
                return False
            if self._inflight.get(user_id, 0) >= USER_INFLIGHT_LIMIT:
                self._windows[user_id] = bucket
                return False
            bucket.append(now)
            self._windows[user_id] = bucket
            self._inflight[user_id] = self._inflight.get(user_id, 0) + 1
            return True

    def finish(self, user_id: str) -> None:
        with self._lock:
            count = self._inflight.get(user_id, 0) - 1
            if count > 0:
                self._inflight[user_id] = count
            else:
                self._inflight.pop(user_id, None)


class WorkspaceRuntime:
    """Resolved workspace state; secrets are never rendered or serialized."""

    __slots__ = (
        "enabled",
        "ready",
        "store",
        "internal_gateway",
        "chat_limits",
        "_internal_key",
        "allow_http",
        "job_deadline",
        "error",
        "_login_limiter",
        "_principal_guard",
        "_inflight_lock",
        "_inflight_conversations",
        "diagnostics",
    )

    def __init__(self, *, enabled: bool) -> None:
        self.enabled = enabled
        self.ready = False
        self.store: Any = None
        self.internal_gateway: Gateway | None = None
        self.chat_limits: ChatLimits | None = None
        self._internal_key: str | None = None
        self.allow_http = False
        self.job_deadline = 0.0
        self.error: str | None = None
        self._login_limiter = _LoginLimiter()
        self._principal_guard = _PrincipalGuard()
        self._inflight_lock = threading.Lock()
        self._inflight_conversations: set[str] = set()
        # Fixed-code, content-free counters shared by every workspace turn.
        self.diagnostics = SafeDiagnostics()

    def __repr__(self) -> str:
        return (
            f"WorkspaceRuntime(enabled={self.enabled}, ready={self.ready}, "
            f"error={self.error!r})"
        )

    def try_begin_conversation(self, conversation_id: str) -> bool:
        with self._inflight_lock:
            if conversation_id in self._inflight_conversations:
                return False
            self._inflight_conversations.add(conversation_id)
            return True

    def finish_conversation(self, conversation_id: str) -> None:
        with self._inflight_lock:
            self._inflight_conversations.discard(conversation_id)

    async def check_ready(self, admission: Any) -> bool:
        if not self.enabled:
            return True
        if not self.ready or self.store is None:
            return False
        if not admission.try_acquire():
            return False
        try:
            result = await admission.run(
                self.store.ready, timeout=WORKSPACE_DB_TIMEOUT
            )
        except Exception:
            return False
        return result is True


def _read_secret_file(path: Any) -> str | None:
    """Read one bounded, non-empty regular secret file. No env fallback."""
    if not isinstance(path, str) or not path.strip():
        return None
    try:
        candidate = Path(path)
        info = candidate.stat()
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size < 1 or info.st_size > SECRET_FILE_MAX_BYTES:
            return None
        with open(candidate, "rb") as handle:
            data = handle.read(SECRET_FILE_MAX_BYTES + 1)
        if len(data) > SECRET_FILE_MAX_BYTES:
            return None
        value = data.decode("utf-8").strip()
        return value or None
    except (OSError, UnicodeError, ValueError, TypeError):
        return None


def _required_store_methods() -> tuple[str, ...]:
    return (
        "ready",
        "authenticate",
        "logout",
        "resolve_session",
        "get_profile",
        "create_conversation",
        "reserve_turn",
        "read_context",
        "append_exchange",
        "record_failed_turn",
        "cancel_turn",
        "list_conversations",
        "read_conversation",
        "delete_conversation",
        "list_departments",
        "create_department",
        "list_users",
        "create_user",
        "disable_user",
        "enable_user",
        "delete_user",
        "set_user_role",
        "list_grants",
        "grant_review",
        "revoke_grant",
        "reset_password",
        "list_access_log",
        # Persisted policy administration and block-alert bridge.  The runtime
        # refuses to become ready when any of these is missing rather than
        # silently serving turns without per-principal enforcement.
        "create_policy_profile",
        "list_policy_profiles",
        "get_policy_profile",
        "revise_policy_profile",
        "rollback_policy_profile",
        "list_policy_profile_revisions",
        "list_policy_audit",
        "assign_policy_profile",
        "clear_policy_assignment",
        "get_policy_assignment",
        "list_policy_assignments",
        "resolve_effective_policy",
        "resolve_gateway_control",
        "list_block_alerts",
        "get_block_alert",
        "alert_summary",
        "mark_block_alert_read",
        "mark_all_block_alerts_read",
        "acknowledge_block_alert",
    )


def load_workspace_runtime(
    environ: dict[str, str],
    *,
    store: Any,
    gateway: Gateway | None,
    audit_writer_dsn: str | None,
    audit_reader_dsn: str | None,
    chat_work_timeout: float,
) -> WorkspaceRuntime:
    """Resolve the opt-in workspace without affecting a disabled deployment."""
    runtime = WorkspaceRuntime(
        enabled=str(environ.get(ENV_ENABLED, "")).strip().lower() == "true"
    )
    if not runtime.enabled:
        return runtime

    runtime.allow_http = (
        str(environ.get(ENV_ALLOW_HTTP, "")).strip().lower() == "true"
    )
    deadline = min(float(chat_work_timeout), LEASE_TTL_SECONDS - 10.0)
    runtime.job_deadline = max(1.0, deadline)

    if store is None:
        dsn = _read_secret_file(environ.get(ENV_DSN_FILE))
        key = _read_secret_file(environ.get(ENV_KEY_FILE))
        if not dsn or not key:
            runtime.error = "workspace configuration is incomplete"
            return runtime
        if not dsn.lower().startswith(("postgresql://", "postgres://")):
            runtime.error = "workspace database is not supported"
            return runtime
        for other in (audit_writer_dsn, audit_reader_dsn):
            if isinstance(other, str) and other.strip() and dsn == other.strip():
                runtime.error = "workspace credential is not dedicated"
                return runtime
        try:
            store = WorkspaceStore(
                dsn,
                encryption_key=key,
                connect_timeout=5.0,
                migrate=False,
            )
        except Exception:
            runtime.error = "workspace storage is unavailable"
            return runtime

    if not all(
        callable(getattr(store, name, None)) for name in _required_store_methods()
    ):
        runtime.error = "workspace store interface is incomplete"
        return runtime

    if gateway is None:
        runtime.error = "workspace safety gateway is unavailable"
        return runtime
    internal_key = secrets.token_urlsafe(32)
    try:
        internal_gateway = Gateway(
            app_key=internal_key,
            audit_store=gateway.audit_store,
            adapters=gateway.adapters,
            policy=gateway.policy,
            app_id=gateway.app_id,
            limits=getattr(gateway, "limits", None),
        )
    except Exception:
        runtime.error = "workspace safety gateway is unavailable"
        return runtime

    runtime.store = store
    runtime.internal_gateway = internal_gateway
    runtime.chat_limits = internal_gateway.limits
    runtime._internal_key = internal_key
    runtime.ready = True
    return runtime


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _ws_error(
    request: Request,
    code: str,
    status: int,
    message: str | None = None,
    *,
    details: dict[str, Any] | None = None,
):
    request_id = getattr(request.state, "request_id", "req_unknown")
    error: dict[str, Any] = {
        "code": code,
        "message": message or _ERROR_MESSAGES[code],
        "request_id": request_id,
    }
    if details:
        # Bounded, fixed server-side fields only (for example a safe block
        # reason and the gateway turn request id).  Never raw prompt/output.
        error.update(details)
    return JSONResponse(
        {"error": error},
        status_code=status,
        headers=_COMMON_HEADERS,
    )


def _ok(payload: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers=_COMMON_HEADERS)


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin:
        # Compare scheme and authority only; no path is accepted in Origin.
        try:
            parsed = urlsplit(origin.strip())
        except ValueError:
            return False
        if not parsed.scheme or not parsed.netloc:
            return False
        expected = f"{request.url.scheme}://{request.url.netloc}"
        return f"{parsed.scheme}://{parsed.netloc}".lower() == expected.lower()
    if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
        return False
    return True


def _strict_same_origin(request: Request) -> bool:
    """CSRF check for cookie-authenticated writes: exactly one real Origin.

    Missing, ``null``, duplicate, malformed, credential-bearing or path-bearing
    Origin values are rejected.  A real Origin never contains a path, not even
    ``/``.  Only the uvicorn request scope is compared;
    ``Forwarded``/``X-Forwarded-*`` headers are never trusted.
    """
    values = request.headers.getlist("origin")
    if len(values) != 1:
        return False
    raw = values[0].strip()
    if not raw or raw.lower() == "null":
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    if (
        not parsed.scheme
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query
        or parsed.fragment
    ):
        return False
    expected = f"{request.url.scheme}://{request.url.netloc}"
    return f"{parsed.scheme}://{parsed.netloc}".lower() == expected.lower()


def _json_content_type(request: Request) -> bool:
    values = request.headers.getlist("content-type")
    if len(values) != 1:
        return False
    return values[0].split(";", 1)[0].strip().lower() == "application/json"


def _cookie_token(request: Request) -> str | None:
    """Return exactly one unambiguous workspace cookie value, else ``None``."""
    headers = request.headers.getlist("cookie")
    if not headers:
        return None
    if len(headers) != 1:
        raise _AuthProblem(401, "UNAUTHORIZED")
    raw = headers[0]
    if not isinstance(raw, str) or not raw or len(raw) > COOKIE_MAX_BYTES:
        raise _AuthProblem(401, "UNAUTHORIZED")
    count = 0
    value = ""
    for part in raw.split(";"):
        name, separator, candidate = part.strip().partition("=")
        if name != SESSION_COOKIE:
            continue
        count += 1
        value = candidate
    if count == 0:
        return None
    if count != 1:
        raise _AuthProblem(401, "UNAUTHORIZED")
    token = value.strip()
    if token.startswith('"') and token.endswith('"') and len(token) >= 2:
        token = token[1:-1]
    try:
        parsed = SimpleCookie()
        parsed.load(f"{SESSION_COOKIE}={token}")
        token = parsed[SESSION_COOKIE].value
    except Exception:
        raise _AuthProblem(401, "UNAUTHORIZED") from None
    if (
        not isinstance(token, str)
        or not 1 <= len(token) <= 512
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in token)
    ):
        raise _AuthProblem(401, "UNAUTHORIZED")
    return token


def _set_session_cookie(
    response: JSONResponse, request: Request, token: str, expires_at: float
) -> None:
    remaining = int(max(0.0, min(expires_at - time.time(), SESSION_TTL_SECONDS)))
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=remaining,
        path=COOKIE_PATH,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
    )


def _clear_session_cookie(response: JSONResponse, request: Request) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE,
        path=COOKIE_PATH,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
    )


def _cookie_mutation_guard(request: Request, source: str):
    if source != "cookie":
        return None
    if not _strict_same_origin(request) or not _json_content_type(request):
        return _ws_error(request, "FORBIDDEN", 403)
    return None


def _request_guard(request: Request, runtime: WorkspaceRuntime):
    if not _same_origin(request):
        return _ws_error(request, "FORBIDDEN", 403)
    if not runtime.ready:
        return _ws_error(request, "UNAVAILABLE", 503)
    if not runtime.allow_http and request.url.scheme != "https":
        return _ws_error(request, "FORBIDDEN", 403)
    return None


def _client_ip(request: Request) -> str:
    client = request.client
    return str(getattr(client, "host", "") or "unknown")[:64]


def _bearer_token(request: Request) -> str | None:
    headers = request.headers.getlist("authorization")
    if len(headers) != 1:
        return None
    value = headers[0]
    if not isinstance(value, str) or not value.startswith("Bearer "):
        return None
    token = value[7:]
    return token if 1 <= len(token) <= 512 else None


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen.add(key)
    return dict(pairs)


async def _read_json(request: Request, app: FastAPI) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise _BodyProblem(400)
    try:
        raw = await _read_body(
            request,
            app.state.max_body_bytes,
            app.state.body_read_timeout,
            WORKSPACE_BODY_BYTES,
        )
    except _BodyProblem:
        raise
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _BodyProblem(400) from None
    if not isinstance(parsed, dict):
        raise _BodyProblem(400)
    return parsed


async def _read_body(
    request: Request, app_limit: int, timeout: float, endpoint_limit: int
) -> bytes:
    limit = min(app_limit, endpoint_limit)
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    total = 0
    iterator = request.stream().__aiter__()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _BodyProblem(503)
        try:
            chunk = await asyncio.wait_for(iterator.__anext__(), timeout=remaining)
        except StopAsyncIteration:
            break
        except asyncio.TimeoutError:
            raise _BodyProblem(503) from None
        total += len(chunk)
        if total > limit:
            raise _BodyProblem(413)
        chunks.append(bytes(chunk))
    return b"".join(chunks)


async def _db_call(app: FastAPI, func: Any, *args: Any, **kwargs: Any) -> Any:
    admission = app.state.control_admission
    if not admission.try_acquire():
        raise _Busy()
    if kwargs:
        # ``_ControlPlaneAdmission.run`` accepts positional args only.  Bind the
        # keyword arguments once, before dispatch, so no argument is lost.
        call = functools.partial(func, *args, **kwargs)
        args = ()
    else:
        call = func
    try:
        result = await admission.run(call, *args, timeout=WORKSPACE_DB_TIMEOUT)
    except Exception:
        raise
    # Imported lazily to avoid a module import cycle.
    from .server import _CONTROL_TIMEOUT

    if result is _CONTROL_TIMEOUT:
        raise _Busy()
    return result


def _store_error(request: Request, exc: BaseException):
    if isinstance(exc, _Busy):
        return _ws_error(request, "UNAVAILABLE", 503)
    if isinstance(exc, AuthError):
        return _ws_error(request, "UNAUTHORIZED", 401)
    if isinstance(exc, AccessDenied):
        return _ws_error(request, "FORBIDDEN", 403)
    if isinstance(exc, NotFound):
        return _ws_error(request, "INVALID_REQUEST", 404)
    if isinstance(exc, Conflict):
        return _ws_error(request, "CONFLICT", 409)
    if isinstance(exc, ValueError):
        return _ws_error(request, "INVALID_REQUEST", 400)
    return _ws_error(request, "UNAVAILABLE", 503)


async def _resolve_principal(request: Request, app: FastAPI, runtime: WorkspaceRuntime):
    authorization = request.headers.getlist("authorization")
    try:
        cookie = _cookie_token(request)
    except _AuthProblem as exc:
        return None, None, None, _ws_error(request, exc.code, exc.status)
    if authorization and cookie is not None:
        # Never prefer one credential over another: reject ambiguous requests.
        return None, None, None, _ws_error(request, "UNAUTHORIZED", 401)
    if authorization:
        token = _bearer_token(request)
        source = "bearer"
    elif cookie is not None:
        token = cookie
        source = "cookie"
    else:
        token = None
        source = None
    if token is None:
        return None, None, None, _ws_error(request, "UNAUTHORIZED", 401)
    try:
        user = await _db_call(app, runtime.store.resolve_session, token)
    except (AuthError, AccessDenied):
        return None, None, None, _ws_error(request, "UNAUTHORIZED", 401)
    except Exception as exc:
        return None, None, None, _store_error(request, exc)
    if source == "cookie":
        # A cookie is shared by every tab in a browser profile.  Requiring the
        # expected user id stops a stale tab from silently reading or mutating
        # the account that replaced its cookie.  /me is the bootstrap call.
        expected = request.headers.getlist("x-workspace-user")
        if len(expected) > 1:
            return None, None, None, _ws_error(request, "IDENTITY_CONFLICT", 403)
        expected_user = expected[0].strip() if expected else ""
        if expected_user:
            if expected_user != user["id"]:
                return None, None, None, _ws_error(
                    request, "IDENTITY_CONFLICT", 403
                )
        elif request.url.path != "/workspace/api/me":
            return None, None, None, _ws_error(request, "IDENTITY_CONFLICT", 403)
    return token, user, source, None


def _page_query(request: Request) -> tuple[int, str | None]:
    pairs = request.query_params.multi_items()
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen or key not in ("limit", "after"):
            raise ValueError("unknown query parameter")
        seen.add(key)
    limit = 50
    if "limit" in request.query_params:
        raw = request.query_params["limit"]
        if not raw.isdigit():
            raise ValueError("limit is invalid")
        limit = int(raw, 10)
        if not 1 <= limit <= 100:
            raise ValueError("limit is invalid")
    after = request.query_params.get("after")
    if after is not None and (not after or len(after) > 160):
        raise ValueError("cursor is invalid")
    return limit, after


def _body_fields(body: dict[str, Any], allowed: set[str], required: set[str]) -> None:
    if set(body) - allowed or not required.issubset(body):
        raise ValueError("body fields are invalid")


# ---------------------------------------------------------------------------
# route registration
# ---------------------------------------------------------------------------


def register_workspace_routes(app: FastAPI, runtime: WorkspaceRuntime) -> None:
    if not runtime.enabled:
        return

    @app.middleware("http")
    async def workspace_no_store(request: Request, call_next):
        response = await call_next(request)
        if request.url.path == "/workspace" or request.url.path.startswith(
            "/workspace/"
        ):
            for key, value in _COMMON_HEADERS.items():
                response.headers[key] = value
        return response

    @app.post("/workspace/api/login")
    async def workspace_login(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        try:
            body = await _read_json(request, app)
            _body_fields(
                body, {"username", "password", "cookie"}, {"username", "password"}
            )
            username = body["username"]
            password = body["password"]
            cookie_mode = body.get("cookie", False)
            if not isinstance(cookie_mode, bool):
                raise ValueError("cookie option is invalid")
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError("credentials are invalid")
            if len(username) > 128 or len(password) > 128:
                raise ValueError("credentials are invalid")
        except _BodyProblem as exc:
            return _ws_error(
                request,
                "INPUT_LIMIT" if exc.status == 413 else "INVALID_REQUEST",
                exc.status,
            )
        except ValueError:
            return _ws_error(request, "INVALID_REQUEST", 400)

        if cookie_mode and not _strict_same_origin(request):
            # A cookie login creates a persistent shared-browser credential, so
            # it needs the same strict CSRF origin check as every cookie write.
            # Missing/null/path-bearing Origins fail before authentication runs.
            return _ws_error(request, "FORBIDDEN", 403)

        limiter_key = _LoginLimiter.key(_client_ip(request), username)
        if runtime._login_limiter.blocked(limiter_key):
            return _ws_error(request, "RATE_LIMIT", 429)
        runtime._login_limiter.record(limiter_key)
        try:
            result = await _db_call(app, runtime.store.authenticate, username, password)
        except AuthError:
            return _ws_error(request, "UNAUTHORIZED", 401)
        except Exception as exc:
            return _store_error(request, exc)
        payload = {
            "expires": result["expires_at"],
            "user": result["user"],
        }
        if not cookie_mode:
            # Default API behaviour is unchanged: the caller receives the
            # opaque bearer token and manages it itself.
            payload["token"] = result["token"]
        response = _ok(payload)
        if cookie_mode:
            # The page opts into an HttpOnly cookie, so the raw token never
            # reaches JavaScript.  Its lifetime is bounded by the database
            # session expiry, which is enforced on every request.
            _set_session_cookie(
                response, request, result["token"], result["expires_at"]
            )
        return response

    @app.post("/workspace/api/logout")
    async def workspace_logout(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        token, _user, source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            await _db_call(app, runtime.store.logout, token)
        except Exception as exc:
            # Do not acknowledge a sign-out that the server did not perform.
            return _store_error(request, exc)
        response = _ok({"status": "ok"})
        _clear_session_cookie(response, request)
        return response

    @app.get("/workspace/api/policy")
    async def workspace_own_policy(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, _source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        # This endpoint is deliberately self-only.  Any query value (including
        # ``user_id``) is rejected rather than interpreted, so a caller cannot
        # preview another principal's effective policy.
        if request.query_params.multi_items():
            return _ws_error(request, "INVALID_REQUEST", 400)
        try:
            result = await _db_call(
                app, runtime.store.resolve_effective_policy, user["id"]
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/me")
    async def workspace_me(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, _source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        try:
            profile = await _db_call(app, runtime.store.get_profile, user["id"])
        except Exception as exc:
            return _store_error(request, exc)
        payload = dict(profile) if isinstance(profile, dict) else profile
        limits = runtime.chat_limits
        if isinstance(payload, dict) and isinstance(limits, ChatLimits):
            # Non-secret effective configuration only; profile facts and
            # identity stay exactly as the store returned them.
            info = limits.public()
            info["max_prompt_chars"] = limits.max_prompt_chars()
            policy = getattr(runtime.internal_gateway, "policy", None)
            policy_budget = getattr(policy, "token_budget", None)
            if (
                isinstance(policy_budget, int)
                and not isinstance(policy_budget, bool)
                and policy_budget >= 1
            ):
                info["policy_token_budget"] = policy_budget
            payload["chat_limits"] = info
        return _ok(payload)

    # -- admin account management ---------------------------------------
    async def admin_principal(request: Request):
        token, user, source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return None, None, error
        if user.get("role") != "admin":
            return None, None, _ws_error(request, "FORBIDDEN", 403)
        return user, source, None

    def admin_body_error(request: Request, exc: BaseException):
        return _store_error(request, exc)

    @app.get("/workspace/api/admin/departments")
    async def admin_departments(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        user, _source, error = await admin_principal(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app, runtime.store.list_departments, user["id"], limit=limit, after=after
            )
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/departments")
    async def admin_create_department(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        user, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(body, {"name"}, {"name"})
            result = await _db_call(
                app, runtime.store.create_department, user["id"], body["name"]
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result, 201)

    @app.get("/workspace/api/admin/users")
    async def admin_users(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        user, _source, error = await admin_principal(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app, runtime.store.list_users, user["id"], limit=limit, after=after
            )
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/users")
    async def admin_create_user(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        user, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {"username", "password", "full_name", "department_id", "role"},
                {"username", "password", "full_name", "department_id"},
            )
            result = await _db_call(
                app,
                runtime.store.create_user,
                user["id"],
                body["username"],
                body["password"],
                body["full_name"],
                body["department_id"],
                body.get("role", "employee"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result, 201)

    @app.post("/workspace/api/admin/users/{user_id}/disable")
    async def admin_disable_user(request: Request, user_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            if body:
                raise ValueError("body must be empty")
            await _db_call(app, runtime.store.disable_user, actor["id"], user_id)
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok({"status": "disabled"})

    @app.post("/workspace/api/admin/users/{user_id}/enable")
    async def admin_enable_user(request: Request, user_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            if body:
                raise ValueError("body must be empty")
            result = await _db_call(
                app, runtime.store.enable_user, actor["id"], user_id
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/users/{user_id}/delete")
    async def admin_delete_user(request: Request, user_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(body, {"confirm_username"}, {"confirm_username"})
            result = await _db_call(
                app,
                runtime.store.delete_user,
                actor["id"],
                user_id,
                body["confirm_username"],
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/users/{user_id}/role")
    async def admin_set_user_role(request: Request, user_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(body, {"role"}, {"role"})
            result = await _db_call(
                app,
                runtime.store.set_user_role,
                actor["id"],
                user_id,
                body["role"],
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/users/{user_id}/reset-password")
    async def admin_reset_password(request: Request, user_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(body, {"password"}, {"password"})
            await _db_call(
                app, runtime.store.reset_password, actor["id"], user_id, body["password"]
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok({"status": "reset"})

    @app.get("/workspace/api/admin/review-grants")
    async def admin_review_grants(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, _source, error = await admin_principal(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app, runtime.store.list_grants, actor["id"], limit=limit, after=after
            )
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/review-grants")
    async def admin_grant_review(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body, {"user_id", "scope", "department_id"}, {"user_id", "scope"}
            )
            result = await _db_call(
                app,
                runtime.store.grant_review,
                actor["id"],
                body["user_id"],
                body["scope"],
                body.get("department_id"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result, 201)

    @app.delete("/workspace/api/admin/review-grants/{grant_id}")
    async def admin_revoke_grant(request: Request, grant_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, source, error = await admin_principal(request)
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            await _db_call(app, runtime.store.revoke_grant, actor["id"], grant_id)
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok({"status": "revoked"})

    @app.get("/workspace/api/admin/access-log")
    async def admin_access_log(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        actor, _source, error = await admin_principal(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app, runtime.store.list_access_log, actor["id"], limit=limit, after=after
            )
        except Exception as exc:
            return admin_body_error(request, exc)
        return _ok(result)

    # -- conversations ---------------------------------------------------
    @app.get("/workspace/api/conversations")
    async def own_conversations(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, _source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app,
                runtime.store.list_conversations,
                user["id"],
                limit=limit,
                after=after,
                scope="own",
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/conversations")
    async def create_conversation(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            if body:
                raise ValueError("custom conversation titles are not supported")
            result = await _db_call(
                app, runtime.store.create_conversation, user["id"]
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result, 201)

    @app.get("/workspace/api/conversations/{conversation_id}")
    async def read_conversation(request: Request, conversation_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, _source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        try:
            result = await _db_call(
                app, runtime.store.read_conversation, user["id"], conversation_id
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.delete("/workspace/api/conversations/{conversation_id}")
    async def delete_conversation(request: Request, conversation_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        try:
            await _db_call(
                app, runtime.store.delete_conversation, user["id"], conversation_id
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok({"status": "deleted"})

    @app.get("/workspace/api/review/conversations")
    async def review_conversations(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, _source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app,
                runtime.store.list_conversations,
                user["id"],
                limit=limit,
                after=after,
                scope="review",
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/review/conversations/{conversation_id}")
    async def review_conversation(request: Request, conversation_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        _token, user, _source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        try:
            result = await _db_call(
                app, runtime.store.read_conversation, user["id"], conversation_id
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/conversations/{conversation_id}/messages")
    async def send_message(request: Request, conversation_id: str):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return guard
        token, user, source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return error
        csrf = _cookie_mutation_guard(request, source)
        if csrf is not None:
            return csrf
        limits = runtime.chat_limits or ChatLimits.defaults()
        try:
            body = await _read_json(request, app)
            _body_fields(body, {"text", "max_tokens"}, {"text"})
            text = body["text"]
            if not isinstance(text, str) or not text.strip():
                raise ValueError("message text is invalid")
            if len(text) > limits.max_prompt_chars():
                raise _BodyProblem(413)
            max_tokens = body.get("max_tokens", limits.default_reply_tokens)
            if (
                isinstance(max_tokens, bool)
                or not isinstance(max_tokens, int)
                or not 1 <= max_tokens <= limits.max_reply_tokens
            ):
                raise ValueError("max_tokens is invalid")
        except _BodyProblem as exc:
            return _ws_error(
                request,
                "INPUT_LIMIT" if exc.status == 413 else "INVALID_REQUEST",
                exc.status,
                _INPUT_LIMIT_MESSAGE if exc.status == 413 else None,
            )
        except ValueError:
            return _ws_error(request, "INVALID_REQUEST", 400)

        return await _run_turn(
            request=request,
            app=app,
            runtime=runtime,
            token=token,
            user=user,
            conversation_id=conversation_id,
            text=text,
            max_tokens=max_tokens,
        )

    # Admin policy and block-alert routes live in a dedicated module.  The
    # import is local because that module imports these shared guards.
    from .workspace_admin_http import register_admin_policy_routes

    register_admin_policy_routes(app, runtime)


def _turn_error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, Conflict):
        return {"status": 409, "code": "CONFLICT"}
    if isinstance(exc, NotFound):
        return {"status": 404, "code": "INVALID_REQUEST"}
    if isinstance(exc, AccessDenied):
        return {"status": 403, "code": "FORBIDDEN"}
    if isinstance(exc, AuthError):
        return {"status": 401, "code": "UNAUTHORIZED"}
    if isinstance(exc, ValueError):
        return {"status": 400, "code": "INVALID_REQUEST"}
    return {"status": 503, "code": "UNAVAILABLE"}


def _gateway_handle(
    gateway: Gateway,
    *,
    internal_key: str,
    body: dict[str, Any],
    scan_context: ScanContext,
    control: GatewayControl,
):
    """Call the real Gateway with an explicit control, or a legacy test double.

    A configured ``Gateway`` (and any subclass override) must accept the
    ``control`` keyword.  Only an instance-level synthetic replacement that has
    no control parameter is supported without one; that path is for legacy test
    doubles and can never be taken by the configured real gateway.
    """

    handle = gateway.handle
    headers = {"Authorization": f"Bearer {internal_key}"}
    if isinstance(gateway, Gateway) and getattr(handle, "__func__", None) is Gateway.handle:
        return handle(
            "POST",
            "/v1/chat/completions",
            headers,
            body,
            scan_context=scan_context,
            control=control,
        )
    try:
        parameters = inspect.signature(handle).parameters
    except (TypeError, ValueError):
        raise TypeError("gateway control is unsupported") from None
    if "control" in parameters:
        return handle(
            "POST",
            "/v1/chat/completions",
            headers,
            body,
            scan_context=scan_context,
            control=control,
        )
    if isinstance(gateway, Gateway) and getattr(handle, "__func__", None) is not None:
        # A configured Gateway subclass that drops the control argument would
        # bypass per-principal enforcement, so it fails closed.
        raise TypeError("gateway control is unsupported")
    return handle(
        "POST",
        "/v1/chat/completions",
        headers,
        body,
        scan_context=scan_context,
    )


def _known_gateway_block(payload: Any) -> tuple[dict[str, str], str] | None:
    """Return the exact fixed block detail and gateway request id, else ``None``.

    The payload must be a real ``POLICY_BLOCK`` whose ``block`` object equals
    :func:`controls.block_detail` for a known reason code.  No classifier text,
    title, stage or extra field from the gateway is trusted or forwarded.
    """

    if not isinstance(payload, dict):
        return None
    error_body = payload.get("error")
    if not isinstance(error_body, dict) or error_body.get("code") != "POLICY_BLOCK":
        return None
    block = error_body.get("block")
    if not isinstance(block, dict):
        return None
    reason_code = block.get("reason_code")
    if not isinstance(reason_code, str):
        return None
    try:
        expected = block_detail(reason_code)
    except (KeyError, TypeError, ValueError):
        return None
    if set(block) != set(expected) or any(
        block.get(field) != value for field, value in expected.items()
    ):
        return None
    request_id = error_body.get("request_id")
    if (
        not isinstance(request_id, str)
        or not 1 <= len(request_id) <= 128
        or any(ord(char) < 32 or ord(char) == 127 for char in request_id)
    ):
        return None
    return expected, request_id


def _safe_turn_block(value: Any) -> dict[str, str] | None:
    """Rebuild only the fixed client-safe block fields plus its reference."""

    if not isinstance(value, dict):
        return None
    reason_code = value.get("reason_code")
    reference = value.get("ref")
    if not isinstance(reason_code, str) or not isinstance(reference, str):
        return None
    try:
        expected = block_detail(reason_code)
    except (KeyError, TypeError, ValueError):
        return None
    if set(value) != set(expected) | {"ref"}:
        return None
    if any(value.get(field) != detail for field, detail in expected.items()):
        return None
    if (
        not 1 <= len(reference) <= 128
        or any(ord(char) < 32 or ord(char) == 127 for char in reference)
    ):
        return None
    return {**expected, "ref": reference}


def _record_turn_failure(
    store: Any,
    owner_id: str,
    conversation_id: str,
    lease: dict[str, Any],
    text: str,
    outcome: str,
    error_code: str,
    request_id: str | None = None,
    alert: dict[str, Any] | None = None,
) -> bool:
    """Persist the original prompt as failed, else close the lease.

    The encrypted prompt is always recorded so an authorised reviewer can see
    what was asked; no assistant text is ever stored for a failed turn.  A
    blocked turn may carry bounded alert metadata, which the store commits in
    the same transaction.  The return value tells the caller whether the write
    committed so it can fail closed instead of claiming success.
    """
    kwargs: dict[str, Any] = {
        "user_prompt": text,
        "outcome": outcome,
        "request_id": request_id,
        "error_code": error_code,
    }
    if alert is not None:
        kwargs["alert"] = alert
    try:
        store.record_failed_turn(
            owner_id,
            conversation_id,
            lease["token"],
            **kwargs,
        )
        return True
    except Exception:
        try:
            store.cancel_turn(owner_id, conversation_id, lease["token"])
        except Exception:
            pass
        return False


_INPUT_LIMIT_MESSAGE = (
    "Message exceeds the configured input limit; shorten the message or ask an "
    "administrator to increase the chat limits."
)


def _runtime_chat_limits(runtime: WorkspaceRuntime) -> ChatLimits:
    limits = getattr(runtime, "chat_limits", None)
    return limits if isinstance(limits, ChatLimits) else ChatLimits.defaults()


def _valid_history(history: Any) -> bool:
    """Strict complete user/assistant pairing; malformed history never filters."""
    if not isinstance(history, list) or len(history) % 2:
        return False
    for index, item in enumerate(history):
        expected = "user" if index % 2 == 0 else "assistant"
        if (
            not isinstance(item, dict)
            or set(item) != {"role", "content"}
            or item.get("role") != expected
            or not isinstance(item.get("content"), str)
            or not item["content"]
        ):
            return False
    return True


def _context_fits(
    messages: list[dict[str, str]],
    limits: ChatLimits,
    policy_budget: int,
    counter: Any,
) -> bool:
    serialized = serialize_messages(messages)
    if conservative_byte_budget(serialized) > limits.context_budget:
        return False
    if callable(counter):
        count = counter(serialized)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("invalid token count")
        if count > policy_budget:
            return False
    return True


def _select_context(
    history: list[dict[str, str]],
    prompt: dict[str, str],
    limits: ChatLimits,
    policy_budget: int,
    counter: Any,
) -> tuple[list[dict[str, str]], int] | None:
    """Newest complete allowed pairs plus the full newest prompt.

    Only complete pairs are removed, and only from the oldest end.  A newer
    pair that does not fit stops selection so a smaller older pair can never be
    spliced around it.  ``Gateway.handle`` re-checks the conservative byte
    budget and adapter token count immediately before inference.
    """
    pairs = [
        (history[index], history[index + 1])
        for index in range(0, len(history), 2)
    ]
    max_pairs = max(0, (limits.context_messages - 1) // 2)
    selected: list[dict[str, str]] = []
    for pair in reversed(pairs):
        if len(selected) // 2 >= max_pairs:
            break
        candidate = [pair[0], pair[1], *selected, prompt]
        if not _context_fits(candidate, limits, policy_budget, counter):
            break
        selected = [pair[0], pair[1], *selected]
    messages = [*selected, prompt]
    if not _context_fits(messages, limits, policy_budget, counter):
        # The newest prompt alone cannot fit.  Never trim it or claim a new
        # conversation would help; that is an honest configured-limit error.
        return None
    return messages, len(history) - len(selected)


def _run_turn_pipeline(
    *,
    runtime: WorkspaceRuntime,
    store: Any,
    token: str,
    user: dict[str, Any],
    conversation_id: str,
    text: str,
    max_tokens: int,
    scan_context: ScanContext,
    cancel_reason: dict[str, str],
) -> dict[str, Any]:
    """One synchronous chat turn, run in a single bounded worker thread.

    Reserve, context read, provider call, persist-or-record-failed and lease
    cleanup all happen in this one thread.  There is no nested thread dispatch
    per database call, so the shared permits cannot be released before the
    provider work has really finished.
    """
    owner_id = user["id"]
    try:
        lease = store.reserve_turn(owner_id, conversation_id)
    except Exception as exc:
        return _turn_error(exc)

    def fail(
        outcome: str,
        error_code: str,
        request_id: str | None = None,
        alert: dict[str, Any] | None = None,
    ) -> bool:
        return _record_turn_failure(
            store,
            owner_id,
            conversation_id,
            lease,
            text,
            outcome,
            error_code,
            request_id,
            alert,
        )

    # Revalidate the session inside the worker, immediately before provider
    # work.  A revoked or disabled principal cannot reach inference.
    try:
        current = store.resolve_session(token)
        if not isinstance(current, dict) or current.get("id") != owner_id:
            raise AuthError("session invalid")
    except AuthError:
        fail("failed", "UNAUTHORIZED")
        return {"status": 401, "code": "UNAUTHORIZED"}
    except Exception:
        fail("failed", "UNAVAILABLE")
        return {"status": 503, "code": "UNAVAILABLE"}

    # Resolve a fresh immutable control for the authenticated owner from the
    # committed policy rows.  It is never cached and never derived from the
    # request.  Corrupt or unavailable policy fails closed before any provider
    # call.
    try:
        control = store.resolve_gateway_control(owner_id)
    except Exception:
        fail("failed", "UNAVAILABLE")
        return {"status": 503, "code": "UNAVAILABLE"}
    if not isinstance(control, GatewayControl):
        fail("failed", "UNAVAILABLE")
        return {"status": 503, "code": "UNAVAILABLE"}

    try:
        context = store.read_context(owner_id, conversation_id)
    except Exception as exc:
        fail("failed", "CONTEXT_UNAVAILABLE")
        return _turn_error(exc)

    # Fail closed: malformed, extended or unpaired history is never filtered.
    if not isinstance(context, dict) or set(context) != {"messages"}:
        fail("failed", "CONTEXT_INVALID")
        return {"status": 503, "code": "UNAVAILABLE"}
    history = context["messages"]
    if not _valid_history(history):
        fail("failed", "CONTEXT_INVALID")
        return {"status": 503, "code": "UNAVAILABLE"}

    gateway = runtime.internal_gateway
    internal_key = runtime._internal_key
    if gateway is None or not internal_key:
        fail("failed", "UNAVAILABLE")
        return {"status": 503, "code": "UNAVAILABLE"}

    limits = _runtime_chat_limits(runtime)
    policy_budget = getattr(gateway.policy, "token_budget", None)
    if (
        isinstance(policy_budget, bool)
        or not isinstance(policy_budget, int)
        or policy_budget < 1
    ):
        fail("failed", "CONTEXT_INVALID")
        return {"status": 503, "code": "UNAVAILABLE"}
    if len(text) > limits.max_prompt_chars():
        fail("failed", "INPUT_LIMIT")
        return {
            "status": 413,
            "code": "INPUT_LIMIT",
            "message": _INPUT_LIMIT_MESSAGE,
        }
    try:
        selected = _select_context(
            history,
            {"role": "user", "content": text},
            limits,
            policy_budget,
            getattr(gateway.adapters, "count_tokens", None),
        )
    except Exception:
        fail("failed", "CONTEXT_INVALID")
        return {"status": 503, "code": "UNAVAILABLE"}
    if selected is None:
        fail("failed", "INPUT_LIMIT")
        return {
            "status": 413,
            "code": "INPUT_LIMIT",
            "message": _INPUT_LIMIT_MESSAGE,
        }
    messages, omitted = selected
    context_meta = {
        "selected_messages": len(messages),
        "omitted_messages": omitted,
        "context_messages": limits.context_messages,
        "context_budget": limits.context_budget,
        "policy_token_budget": policy_budget,
    }

    if scan_context.cancelled():
        fail("failed", cancel_reason.get("value", "CANCELLED"))
        return {"status": 503, "code": "UNAVAILABLE"}

    gateway_body = {
        "model": gateway.policy.model,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    try:
        status, payload = _gateway_handle(
            gateway,
            internal_key=internal_key,
            body=gateway_body,
            scan_context=scan_context,
            control=control,
        )
    except Exception:
        fail("failed", "UNAVAILABLE")
        return {"status": 503, "code": "UNAVAILABLE"}

    # The HTTP deadline/cancellation is checked after the real provider call
    # and before any reply is persisted or released.
    if scan_context.cancelled():
        fail("failed", cancel_reason.get("value", "CANCELLED"))
        return {"status": 503, "code": "UNAVAILABLE"}

    request_id = None
    if isinstance(payload, dict):
        candidate = payload.get("id")
        if isinstance(candidate, str):
            request_id = candidate

    if status == 200:
        try:
            delivered = payload["choices"][0]["message"]["content"]
            if not isinstance(delivered, str) or not delivered:
                raise ValueError("invalid gateway result")
        except (KeyError, IndexError, TypeError, ValueError):
            fail("failed", "UNAVAILABLE")
            return {"status": 503, "code": "UNAVAILABLE"}
        try:
            store.append_exchange(
                owner_id,
                conversation_id,
                lease["token"],
                user_prompt=text,
                assistant_response=delivered,
                request_id=request_id,
            )
        except Exception:
            # No assistant answer is released unless the transcript committed.
            fail("failed", "PERSIST_FAILED", request_id)
            return {"status": 503, "code": "UNAVAILABLE"}
        return {
            "status": 200,
            "payload": {
                "id": request_id,
                "conversation_id": conversation_id,
                "role": "assistant",
                "content": delivered,
                "context": context_meta,
            },
        }

    code: Any = None
    payload_request_id: Any = None
    if isinstance(payload, dict):
        error_body = payload.get("error")
        if isinstance(error_body, dict):
            code = error_body.get("code")
            payload_request_id = error_body.get("request_id")
    clean_code = code if isinstance(code, str) and len(code) <= 64 else "UNAVAILABLE"
    safe_request_id = (
        payload_request_id
        if isinstance(payload_request_id, str)
        and 1 <= len(payload_request_id) <= 128
        else None
    )

    if status == 403:
        # Only an exact, known POLICY_BLOCK may become a persisted alert.  A
        # malformed or unknown block (or one that does not match the fixed
        # detail table) fails closed without releasing anything.
        parsed = _known_gateway_block(payload)
        if parsed is None:
            scan_context.note(BLOCK_PAYLOAD_REJECTED)
            fail("failed", "UNAVAILABLE", safe_request_id)
            return {"status": 503, "code": "UNAVAILABLE"}
        block, block_request_id = parsed
        try:
            alert = {
                "stage": block["stage"],
                "reason_code": block["reason_code"],
                "revision": control.revision,
                "digest": control.digest,
                "sources": control.metadata()["sources"],
            }
        except Exception:
            fail("failed", "UNAVAILABLE", block_request_id)
            return {"status": 503, "code": "UNAVAILABLE"}
        if not fail(
            "blocked",
            "POLICY_BLOCK",
            block_request_id,
            alert=alert,
        ):
            # The blocked prompt and alert are one transaction.  Never claim a
            # block was recorded when that transaction did not commit.
            return {"status": 503, "code": "UNAVAILABLE"}
        return {
            "status": 403,
            "code": "FORBIDDEN",
            "message": block["title"],
            "block": {**block, "ref": block_request_id},
            "turn_request_id": block_request_id,
        }

    fail("failed", clean_code, safe_request_id)

    if status == 413:
        return {
            "status": 413,
            "code": "INPUT_LIMIT",
            "message": _INPUT_LIMIT_MESSAGE,
        }
    if status == 401:
        return {"status": 401, "code": "UNAUTHORIZED"}
    if status == 429:
        return {"status": 429, "code": "RATE_LIMIT"}
    if status == 503:
        # An unavailable provider/guard stays 503; it is never rewritten to a
        # client input error.
        return {"status": 503, "code": "UNAVAILABLE"}
    return {"status": 400, "code": "INVALID_REQUEST"}


def _turn_response(request: Request, result: Any):
    if not isinstance(result, dict):
        return _ws_error(request, "UNAVAILABLE", 503)
    status = result.get("status")
    if status == 200:
        return _ok(result.get("payload"))
    if not isinstance(status, int) or status not in (400, 401, 403, 404, 409, 413, 429, 503):
        return _ws_error(request, "UNAVAILABLE", 503)
    code = result.get("code")
    if not isinstance(code, str) or code not in _ERROR_MESSAGES:
        code = "UNAVAILABLE" if status == 503 else "INVALID_REQUEST"
    message = result.get("message")
    if not isinstance(message, str) or len(message) > 200:
        message = None
    details = None
    if status == 403:
        block = _safe_turn_block(result.get("block"))
        reference = result.get("turn_request_id")
        if (
            block is not None
            and isinstance(reference, str)
            and 1 <= len(reference) <= 128
            and not any(ord(char) < 32 or ord(char) == 127 for char in reference)
        ):
            details = {"block": block, "turn_request_id": reference}
    return _ws_error(request, code, status, message, details=details)


async def _run_turn(
    *,
    request: Request,
    app: FastAPI,
    runtime: WorkspaceRuntime,
    token: str,
    user: dict[str, Any],
    conversation_id: str,
    text: str,
    max_tokens: int,
):
    owner_id = user["id"]
    if not runtime._principal_guard.try_begin(owner_id):
        return _ws_error(request, "RATE_LIMIT", 429)
    if not runtime.try_begin_conversation(conversation_id):
        runtime._principal_guard.finish(owner_id)
        return _ws_error(request, "CONFLICT", 409)

    sem = app.state.sem
    if sem.locked():
        runtime.finish_conversation(conversation_id)
        runtime._principal_guard.finish(owner_id)
        return _ws_error(request, "UNAVAILABLE", 503)
    await sem.acquire()

    cancel_event = threading.Event()
    cancel_reason = {"value": "CANCELLED"}
    scan_context = ScanContext(
        cancel_event=cancel_event,
        deadline=time.monotonic() + runtime.job_deadline,
        diagnostic=runtime.diagnostics,
    )
    release_lock = threading.Lock()
    released = {"done": False}
    outcome: dict[str, Any] = {}

    def release_once() -> None:
        # All three permits (global semaphore, principal in-flight, conversation
        # guard) are returned exactly once, only from the task done callback.
        with release_lock:
            if released["done"]:
                return
            released["done"] = True
        runtime.finish_conversation(conversation_id)
        runtime._principal_guard.finish(owner_id)
        sem.release()

    def pipeline() -> None:
        try:
            outcome["result"] = _run_turn_pipeline(
                runtime=runtime,
                store=runtime.store,
                token=token,
                user=user,
                conversation_id=conversation_id,
                text=text,
                max_tokens=max_tokens,
                scan_context=scan_context,
                cancel_reason=cancel_reason,
            )
        except BaseException:
            outcome["result"] = {"status": 503, "code": "UNAVAILABLE"}

    task = asyncio.create_task(asyncio.to_thread(pipeline))
    app.state.workspace_tasks.add(task)

    def consume(done: "asyncio.Task") -> None:
        app.state.workspace_tasks.discard(done)
        try:
            done.exception()
        except BaseException:
            pass
        finally:
            release_once()

    task.add_done_callback(consume)

    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=runtime.job_deadline)
    except asyncio.TimeoutError:
        # The worker keeps its permits and finishes the cancelled turn itself:
        # the original prompt becomes a failed message and no late assistant
        # reply is persisted or released.
        cancel_reason["value"] = "DEADLINE"
        cancel_event.set()
        return _ws_error(request, "UNAVAILABLE", 503)
    except asyncio.CancelledError:
        cancel_reason["value"] = "CANCELLED"
        cancel_event.set()
        raise
    return _turn_response(request, outcome.get("result"))
