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

from typing import Any

from fastapi import FastAPI, Request

from .limits import ChatLimits, tighten
from .workspace_http import (
    _BodyProblem,
    _body_fields,
    _cookie_mutation_guard,
    _db_call,
    _ok,
    _page_query,
    _read_json,
    _request_guard,
    _resolve_principal,
    _store_error,
    _ws_error,
)

MAX_SCOPE_QUERY_LENGTH = 64
_ALERT_FILTERS = {
    "limit",
    "after",
    "stage",
    "user_id",
    "department_id",
    "reason_code",
    "unread",
    "acknowledged",
}


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
        if user.get("role") != "admin":
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
