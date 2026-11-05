"""Bounded HTTP routes for persisted policy administration and block alerts.

The routes in this module are intentionally thin.  They resolve exactly one
authenticated principal from the existing workspace session helpers, require the
persisted ``admin`` role *before* reading any request body, and pass the
authenticated actor id to the store.  No route accepts an actor, role, scope
owner or ``GatewayControl`` from the client.

All reads and writes go through the existing bounded control-plane admission
(``_db_call``); mutations also require the same cookie-origin CSRF rule as the
rest of the workspace.  The store re-checks the active admin role inside each
database transaction, so a role revoked between the session lookup and the store
call still fails closed.
"""

from __future__ import annotations

import csv
import io
import re
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request, Response

from .limits import ChatLimits, tighten
from .system_settings import DEFAULT_SETTINGS, validate_reason, validate_settings
from .workspace_http import (
    _COMMON_HEADERS,
    _BodyProblem,
    _body_fields,
    _cookie_mutation_guard,
    _db_call,
    _may_use_admin_route,
    _ok,
    _page_query,
    _read_json,
    _request_guard,
    _resolve_principal,
    _store_error,
    _ws_error,
)
from .workspace_store import NotFound

MAX_SCOPE_QUERY_LENGTH = 64
AUDIT_EXPORT_MAX_DAYS = 365
_ALERT_FILTERS = {
    "limit",
    "after",
    "stage",
    "user_id",
    "department_id",
    "reason_code",
    "unread",
    "acknowledged",
    "request_id",
}

_REQUEST_ID_FILTER_RE = re.compile(r"(?:req_)?([0-9a-f]{8,32})")


def _request_id_filter(raw: str | None) -> str | None:
    """Normalise one request ID or prefix; reject anything else."""

    if raw is None:
        return None
    match = _REQUEST_ID_FILTER_RE.fullmatch(raw.strip().lower())
    if match is None:
        raise ValueError("request_id filter is invalid")
    return f"req_{match.group(1)}"


def _query_values(request: Request, allowed: set[str]) -> dict[str, str]:
    """Reject duplicate and unknown query keys before any store call."""

    values: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key in values or key not in allowed:
            raise ValueError("query parameter is invalid")
        values[key] = value
    return values


def _pagination(values: dict[str, str]) -> tuple[int, str | None]:
    limit = 50
    raw_limit = values.get("limit")
    if raw_limit is not None:
        if not raw_limit.isdigit():
            raise ValueError("limit is invalid")
        limit = int(raw_limit, 10)
        if not 1 <= limit <= 100:
            raise ValueError("limit is invalid")
    after = values.get("after")
    if after is not None and (not after or len(after) > 160):
        raise ValueError("cursor is invalid")
    return limit, after


def _optional_bool(values: dict[str, str], key: str) -> bool | None:
    raw = values.get(key)
    if raw is None:
        return None
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise ValueError(f"{key} filter is invalid")


def _optional_int(body: dict[str, Any], key: str) -> int | None:
    value = body.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} is invalid")
    return value


def _required_int(body: dict[str, Any], key: str) -> int:
    value = _optional_int(body, key)
    if value is None:
        raise ValueError(f"{key} is invalid")
    return value


def _csv_cell(value: Any) -> str:
    """Return a CSV-safe cell, neutralising spreadsheet formulas."""

    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _csv_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


_BLOCK_SOURCE_LABELS = {
    "deny_phrase_input": "Deny phrase",
    "deny_phrase_output": "Deny phrase (reply)",
    "size_limit": "Size limit",
}


def _stopped_by(item: dict[str, Any]) -> str:
    """The same wording as Monitor's "Stopped by" column."""
    if item.get("block_categories"):
        return ", ".join(item["block_categories"])
    if item.get("allowed_categories"):
        return "Allowed: " + ", ".join(item["allowed_categories"])
    return _BLOCK_SOURCE_LABELS.get(item.get("block_source") or "", "")


def _csv_response(content: str, filename: str) -> Response:
    response = Response(content, media_type="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    for name, value in _COMMON_HEADERS.items():
        response.headers[name] = value
    return response


def _validated_settings(values: Any, ceilings: Any) -> dict[str, Any]:
    return validate_settings(
        values,
        limit_ceilings=ceilings["chat_limits"],
        input_allow=tuple(ceilings["input_allow_categories"]),
        output_allow=tuple(ceilings["output_allow_categories"]),
        concurrency_ceiling=ceilings["max_concurrency"],
        chat_timeout_ceiling=ceilings["chat_timeout_seconds"],
    )


def _scope_query(scope_type: str, scope_id: str | None) -> tuple[str, str | None]:
    if not isinstance(scope_type, str) or scope_type not in (
        "workspace",
        "department",
        "user",
    ):
        raise ValueError("policy scope is invalid")
    if scope_id is not None and (
        not isinstance(scope_id, str)
        or not 1 <= len(scope_id) <= MAX_SCOPE_QUERY_LENGTH
    ):
        raise ValueError("policy scope is invalid")
    return scope_type, scope_id


def _add_limits_ceiling(result: Any, chat_limits: ChatLimits | None) -> Any:
    """Attach raw profile limits and the server effective ceiling to responses."""

    if not isinstance(result, dict) or not isinstance(chat_limits, ChatLimits):
        return result
    ceiling = chat_limits.public()
    if "settings" in result and isinstance(result["settings"], dict):
        result["settings"]["ceiling"] = ceiling
        result["limits"] = dict(result["settings"].get("limits", {}))
    if "items" in result and isinstance(result["items"], list):
        for item in result["items"]:
            if isinstance(item, dict) and isinstance(item.get("settings"), dict):
                item["settings"]["ceiling"] = ceiling
                item["limits"] = dict(item["settings"].get("limits", {}))
    if "is_default" in result:
        raw_limits = dict(result.get("limits", {}))
        result["ceiling"] = ceiling
        result["effective_limits"] = tighten(chat_limits, raw_limits).public()
    return result


def register_admin_policy_routes(app: FastAPI, runtime: Any) -> None:
    async def admin_context(request: Request):
        guard = _request_guard(request, runtime)
        if guard is not None:
            return None, None, guard
        _token, user, source, error = await _resolve_principal(
            request, app, runtime
        )
        if error is not None:
            return None, None, error
        # The persisted session row is authoritative.  This check runs before
        # any request body is read; the store repeats it transactionally.
        if not _may_use_admin_route(user, request):
            return None, None, _ws_error(request, "FORBIDDEN", 403)
        return user, source, None

    def secure_mutation(request: Request, source: str | None):
        return _cookie_mutation_guard(request, source)

    def with_limits(result: Any) -> Any:
        # ``runtime.chat_limits`` is the server effective limits resolved from
        # the env and startup policy, i.e. the ceiling a profile may only
        # tighten.  When no gateway limits are available, results are unchanged.
        return _add_limits_ceiling(result, getattr(runtime, "chat_limits", None))

    # -- policy profiles -------------------------------------------------
    @app.get("/workspace/api/admin/policy/profiles")
    async def admin_policy_profiles(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app,
                runtime.store.list_policy_profiles,
                actor["id"],
                limit=limit,
                after=after,
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(with_limits(result))

    @app.post("/workspace/api/admin/policy/profiles")
    async def admin_create_policy_profile(request: Request):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {
                    "name",
                    "input_check_enabled",
                    "output_check_enabled",
                    "input_masks",
                    "output_masks",
                    "limits",
                },
                {"name"},
            )
            result = await _db_call(
                app,
                runtime.store.create_policy_profile,
                actor["id"],
                body["name"],
                input_check_enabled=body.get("input_check_enabled", True),
                output_check_enabled=body.get("output_check_enabled", True),
                input_masks=body.get("input_masks"),
                output_masks=body.get("output_masks"),
                limits=body.get("limits"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(with_limits(result), 201)

    @app.get("/workspace/api/admin/policy/profiles/{profile_id}/history")
    async def admin_policy_profile_history(request: Request, profile_id: str):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app,
                runtime.store.list_policy_profile_revisions,
                actor["id"],
                profile_id,
                limit=limit,
                after=after,
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(with_limits(result))

    @app.get("/workspace/api/admin/policy/profiles/{profile_id}")
    async def admin_policy_profile(request: Request, profile_id: str):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            result = await _db_call(
                app, runtime.store.get_policy_profile, actor["id"], profile_id
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(with_limits(result))

    @app.post("/workspace/api/admin/policy/profiles/{profile_id}/revise")
    async def admin_revise_policy_profile(request: Request, profile_id: str):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {
                    "expected_revision",
                    "input_check_enabled",
                    "output_check_enabled",
                    "input_masks",
                    "output_masks",
                    "limits",
                },
                {"expected_revision"},
            )
            result = await _db_call(
                app,
                runtime.store.revise_policy_profile,
                actor["id"],
                profile_id,
                _required_int(body, "expected_revision"),
                input_check_enabled=body.get("input_check_enabled", True),
                output_check_enabled=body.get("output_check_enabled", True),
                input_masks=body.get("input_masks"),
                output_masks=body.get("output_masks"),
                limits=body.get("limits"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(with_limits(result))

    @app.post("/workspace/api/admin/policy/profiles/{profile_id}/rollback")
    async def admin_rollback_policy_profile(request: Request, profile_id: str):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {"target_revision", "expected_revision"},
                {"target_revision", "expected_revision"},
            )
            result = await _db_call(
                app,
                runtime.store.rollback_policy_profile,
                actor["id"],
                profile_id,
                _required_int(body, "target_revision"),
                _required_int(body, "expected_revision"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(with_limits(result))

    @app.get("/workspace/api/admin/policy/audit")
    async def admin_policy_audit(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app,
                runtime.store.list_policy_audit,
                actor["id"],
                limit=limit,
                after=after,
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    # -- assignments and effective preview --------------------------------
    @app.get("/workspace/api/admin/policy/assignments")
    async def admin_policy_assignments(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            values = _query_values(request, {"limit", "after", "scope_type"})
            limit, after = _pagination(values)
            scope_type = values.get("scope_type")
            if scope_type is not None and scope_type not in (
                "workspace",
                "department",
                "user",
            ):
                raise ValueError("policy scope is invalid")
            result = await _db_call(
                app,
                runtime.store.list_policy_assignments,
                actor["id"],
                scope_type=scope_type,
                limit=limit,
                after=after,
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/admin/policy/assignments/{scope_type}")
    async def admin_policy_assignment(request: Request, scope_type: str):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            values = _query_values(request, {"scope_id"})
            _scope, scope_id = _scope_query(scope_type, values.get("scope_id"))
            result = await _db_call(
                app,
                runtime.store.get_policy_assignment,
                actor["id"],
                scope_type,
                scope_id,
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok({"assignment": result})

    @app.post("/workspace/api/admin/policy/assignments")
    async def admin_set_policy_assignment(request: Request):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {
                    "scope_type",
                    "scope_id",
                    "profile_id",
                    "profile_revision",
                    "expected_version",
                },
                {"scope_type", "profile_id"},
            )
            result = await _db_call(
                app,
                runtime.store.assign_policy_profile,
                actor["id"],
                body["scope_type"],
                body.get("scope_id"),
                body["profile_id"],
                profile_revision=_optional_int(body, "profile_revision"),
                expected_version=_optional_int(body, "expected_version"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/policy/assignments/{scope_type}/clear")
    async def admin_clear_policy_assignment(request: Request, scope_type: str):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(body, {"scope_id", "expected_version"}, set())
            _scope, scope_id = _scope_query(scope_type, body.get("scope_id"))
            result = await _db_call(
                app,
                runtime.store.clear_policy_assignment,
                actor["id"],
                scope_type,
                scope_id,
                expected_version=_optional_int(body, "expected_version"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/admin/policy/effective")
    async def admin_effective_policy(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            values = _query_values(request, {"user_id"})
            user_id = values.get("user_id")
            if user_id is None or not 1 <= len(user_id) <= MAX_SCOPE_QUERY_LENGTH:
                raise ValueError("user is invalid")
            result = await _db_call(
                app, runtime.store.resolve_effective_policy, actor["id"], user_id
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(with_limits(result))

    # -- named API keys ---------------------------------------------------
    @app.get("/workspace/api/admin/api-keys")
    async def admin_api_keys(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            limit, after = _page_query(request)
            result = await _db_call(
                app, runtime.store.list_api_keys, actor["id"], limit=limit, after=after
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/api-keys")
    async def admin_create_api_key(request: Request):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {
                    "name",
                    "owner_id",
                    "expires_at",
                    "store_text",
                    "allowed_ips",
                    "requests_per_minute",
                },
                {"name"},
            )
            result = await _db_call(
                app,
                runtime.store.create_api_key,
                actor["id"],
                body["name"],
                owner_id=body.get("owner_id"),
                expires_at=body.get("expires_at"),
                store_text=body.get("store_text", False),
                allowed_ips=body.get("allowed_ips", ()),
                requests_per_minute=body.get("requests_per_minute"),
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result, 201)

    @app.post("/workspace/api/admin/api-keys/{key_id}")
    async def admin_update_api_key(request: Request, key_id: str):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            fields = {
                "owner_id",
                "expires_at",
                "store_text",
                "allowed_ips",
                "requests_per_minute",
            }
            _body_fields(body, fields, fields)
            result = await _db_call(
                app,
                runtime.store.update_api_key,
                actor["id"],
                key_id,
                owner_id=body["owner_id"],
                expires_at=body["expires_at"],
                store_text=body["store_text"],
                allowed_ips=body["allowed_ips"],
                requests_per_minute=body["requests_per_minute"],
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/admin/api-keys/{key_id}/requests")
    async def admin_api_key_requests(request: Request, key_id: str):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            values = _query_values(request, {"limit", "after", "request_id"})
            limit, after = _pagination(values)
            result = await _db_call(
                app,
                runtime.store.list_api_key_requests,
                actor["id"],
                key_id,
                limit=limit,
                after=after,
                request_id=_request_id_filter(values.get("request_id")),
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/admin/api-keys/{key_id}/requests.csv")
    async def admin_api_key_requests_csv(request: Request, key_id: str):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        rows: list[dict[str, Any]] = []
        try:
            _query_values(request, set())
            after: str | None = None
            while True:
                page = await _db_call(
                    app,
                    runtime.store.list_api_key_requests,
                    actor["id"],
                    key_id,
                    limit=100,
                    after=after,
                )
                rows.extend(page["items"])
                after = page.get("next")
                if after is None or len(rows) >= 5000:
                    break
        except Exception as exc:
            return _store_error(request, exc)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "time", "request_id", "client_ip", "outcome", "error_code",
                "reply_tokens", "tokens_per_second", "total_ms", "stopped_by",
            ]
        )
        for item in rows[:5000]:
            writer.writerow(
                [
                    _csv_time(item["created_at"]),
                    _csv_cell(item["request_id"]),
                    _csv_cell(item["client_ip"]),
                    _csv_cell(item["outcome"]),
                    _csv_cell(item["error_code"]),
                    _csv_cell(item.get("reply_tokens")),
                    _csv_cell(item.get("tokens_per_second")),
                    _csv_cell(item.get("total_ms")),
                    _csv_cell(_stopped_by(item)),
                ]
            )
        return _csv_response(output.getvalue(), "api-key-requests.csv")

    @app.get("/workspace/api/admin/audit-export.csv")
    async def admin_audit_export(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            days = int(_query_values(request, {"days"}).get("days", "30"))
            if not 1 <= days <= AUDIT_EXPORT_MAX_DAYS:
                raise ValueError("export range is invalid")
            rows = await _db_call(
                app,
                runtime.store.export_audit,
                actor["id"],
                time.time() - days * 86400.0,
            )
        except Exception as exc:
            return _store_error(request, exc)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["time", "source", "actor", "action", "target", "client_ip", "outcome", "detail"]
        )
        for row in rows:
            writer.writerow(
                [
                    _csv_time(float(row["created_at"])),
                    row["source"],
                    *(
                        _csv_cell(row.get(field))
                        for field in ("actor", "action", "target", "client_ip", "outcome", "detail")
                    ),
                ]
            )
        return _csv_response(output.getvalue(), "workspace-audit.csv")

    @app.get(
        "/workspace/api/admin/api-keys/{key_id}/requests/{request_id}/text"
    )
    async def admin_api_key_text(request: Request, key_id: str, request_id: str):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            _query_values(request, set())
            result = await _db_call(
                app,
                runtime.store.read_api_key_text,
                actor["id"],
                key_id,
                request_id,
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/api-keys/{key_id}/revoke")
    async def admin_revoke_api_key(request: Request, key_id: str):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            result = await _db_call(
                app, runtime.store.revoke_api_key, actor["id"], key_id
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    # -- system settings --------------------------------------------------
    @app.get("/workspace/api/admin/system-settings")
    async def admin_system_settings(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            _query_values(request, set())
            current = await _db_call(app, runtime.store.current_system_settings)
            history = await _db_call(
                app, runtime.store.list_system_settings, actor["id"], limit=20
            )
        except Exception as exc:
            return _store_error(request, exc)
        values = current["values"]
        if values is None:
            values = dict(DEFAULT_SETTINGS)
        return _ok(
            {
                "revision": current["revision"],
                "values": values,
                "ceilings": app.state.settings_ceilings,
                "history": history["items"],
            }
        )

    @app.post("/workspace/api/admin/system-settings")
    async def admin_save_system_settings(request: Request):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {"values", "reason", "expected_revision"},
                {"values", "reason", "expected_revision"},
            )
            reason = validate_reason(body["reason"])
            values = _validated_settings(body["values"], app.state.settings_ceilings)
            saved = await _db_call(
                app,
                runtime.store.save_system_settings,
                actor["id"],
                values,
                reason,
                expected_revision=_required_int(body, "expected_revision"),
            )
            runtime.settings.load(saved["revision"], saved["values"])
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(saved)

    @app.post("/workspace/api/admin/system-settings/rollback")
    async def admin_rollback_system_settings(request: Request):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            _body_fields(
                body,
                {"revision", "reason", "expected_revision"},
                {"revision", "reason", "expected_revision"},
            )
            target = _required_int(body, "revision")
            reason = validate_reason(body["reason"])
            expected_revision = _required_int(body, "expected_revision")
            history = await _db_call(
                app, runtime.store.list_system_settings, actor["id"], limit=100
            )
            match = next(
                (
                    item
                    for item in history["items"]
                    if item["revision"] == target
                ),
                None,
            )
            if match is None:
                raise NotFound("settings revision not found")
            values = _validated_settings(match["values"], app.state.settings_ceilings)
            saved = await _db_call(
                app,
                runtime.store.save_system_settings,
                actor["id"],
                values,
                reason,
                expected_revision=expected_revision,
            )
            runtime.settings.load(saved["revision"], saved["values"])
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(saved)

    # -- block alerts -----------------------------------------------------
    @app.get("/workspace/api/admin/alerts/summary")
    async def admin_alert_summary(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            _query_values(request, set())
            result = await _db_call(
                app, runtime.store.alert_summary, actor["id"]
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/admin/alerts")
    async def admin_alerts(request: Request):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            values = _query_values(request, _ALERT_FILTERS)
            limit, after = _pagination(values)
            result = await _db_call(
                app,
                runtime.store.list_block_alerts,
                actor["id"],
                limit=limit,
                after=after,
                stage=values.get("stage"),
                user_id=values.get("user_id"),
                department_id=values.get("department_id"),
                reason_code=values.get("reason_code"),
                unread=_optional_bool(values, "unread"),
                acknowledged=_optional_bool(values, "acknowledged"),
                request_id=_request_id_filter(values.get("request_id")),
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.get("/workspace/api/admin/alerts/{alert_id}")
    async def admin_alert(request: Request, alert_id: str):
        actor, _source, error = await admin_context(request)
        if error is not None:
            return error
        try:
            result = await _db_call(
                app, runtime.store.get_block_alert, actor["id"], alert_id
            )
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/alerts/read-all")
    async def admin_alerts_read_all(request: Request):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            if body:
                raise ValueError("body must be empty")
            result = await _db_call(
                app, runtime.store.mark_all_block_alerts_read, actor["id"]
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/alerts/{alert_id}/read")
    async def admin_alert_read(request: Request, alert_id: str):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            if body:
                raise ValueError("body must be empty")
            result = await _db_call(
                app, runtime.store.mark_block_alert_read, actor["id"], alert_id
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)

    @app.post("/workspace/api/admin/alerts/{alert_id}/ack")
    async def admin_alert_ack(request: Request, alert_id: str):
        actor, source, error = await admin_context(request)
        if error is not None:
            return error
        csrf = secure_mutation(request, source)
        if csrf is not None:
            return csrf
        try:
            body = await _read_json(request, app)
            if body:
                raise ValueError("body must be empty")
            result = await _db_call(
                app, runtime.store.acknowledge_block_alert, actor["id"], alert_id
            )
        except _BodyProblem as exc:
            return _ws_error(request, "INVALID_REQUEST", exc.status)
        except Exception as exc:
            return _store_error(request, exc)
        return _ok(result)
