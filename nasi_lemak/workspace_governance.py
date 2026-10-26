"""Administrator policy profiles and block-alert persistence.

This module is mixed into :class:`nasi_lemak.workspace_store.WorkspaceStore`.
It deliberately contains no HTTP, template or notification-integration code:
stage 2 wires these exact methods to the web application.  Every administrative
method re-checks the authenticated actor's persisted ``admin`` role inside the
same database transaction; a caller cannot promote itself through a parameter.

The encryption key, connection backend, generic errors and schema migration are
owned by ``workspace_store``.  No method here reads or writes the legacy audit
tables.  Alert metadata never contains prompt, response or classifier-verdict
text; the original prompt remains encrypted in ``ws_messages`` and is available
only through the existing review-grant path.
"""

from __future__ import annotations

import hmac
import json
import math
import re
import uuid
from functools import wraps
from typing import Any

from .controls import (
    BLOCK_REASONS,
    BLOCK_STAGES,
    MASK_TYPES,
    GatewayControl,
    masks_from_text,
    masks_to_text,
    normalize_masks,
    settings_digest,
)

DEFAULT_PAGE = 50
MAX_PAGE = 100
PROFILE_NAME_MAX = 80
SCOPE_MAX = 64
MAX_SOURCES = 3
MAX_DETAIL_LENGTH = 2048
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_SCOPE_ORDER = {"workspace": 0, "department": 1, "user": 2}


def _policy_guard(operation):
    """Translate unexpected driver failures without leaking their text."""

    @wraps(operation)
    def wrapper(*args, **kwargs):
        from .workspace_store import WorkspaceError, WorkspaceStorageError

        try:
            return operation(*args, **kwargs)
        except (WorkspaceError, ValueError):
            raise
        except Exception:
            raise WorkspaceStorageError(
                "workspace governance operation failed"
            ) from None

    return wrapper


def _errors():
    from . import workspace_store

    return workspace_store


def _require_int(
    value: Any, field: str, *, minimum: int = 1, maximum: int = 1_000_000
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"{field} is invalid")
    return value


def _require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} is invalid")
    return value


def _require_safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        raise ValueError(f"{field} is invalid")
    return value


def _require_text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    candidate = value.strip()
    if not candidate or len(candidate) > maximum:
        raise ValueError(f"{field} is invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        raise ValueError(f"{field} is invalid")
    return candidate


def _limit(value: Any) -> int:
    from .workspace_store import _validate_limit

    return _validate_limit(value)


def _encode_cursor(created_at: float, record_id: str) -> str:
    from .workspace_store import _encode_cursor as encode

    return encode(created_at, record_id)


def _decode_cursor(value: Any) -> tuple[float, str]:
    from .workspace_store import _decode_cursor as decode

    return decode(value)


def _mask_selection(value: Any, field: str) -> tuple[str, ...]:
    """Accept only an explicit list/tuple selection, or ``None`` for defaults.

    A mapping, string or other iterable is not a mask selection.  Rejecting it
    here keeps every persistent setter on the same exact input contract.
    """

    if value is None:
        return normalize_masks(None)
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} is invalid")
    return normalize_masks(value)


def _settings(
    input_check_enabled: Any,
    output_check_enabled: Any,
    input_masks: Any,
    output_masks: Any,
) -> tuple[bool, bool, tuple[str, ...], tuple[str, ...], str, str, str]:
    input_enabled = _require_bool(input_check_enabled, "input check setting")
    output_enabled = _require_bool(output_check_enabled, "output check setting")
    input_selection = _mask_selection(input_masks, "input masks")
    output_selection = _mask_selection(output_masks, "output masks")
    return (
        input_enabled,
        output_enabled,
        input_selection,
        output_selection,
        masks_to_text(input_selection),
        masks_to_text(output_selection),
        settings_digest(
            input_enabled, output_enabled, input_selection, output_selection
        ),
    )


def _stored_bool(row: dict[str, Any], field: str) -> bool:
    """Accept only the exact stored 0/1 integers; never coerce truthiness."""

    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1):
        raise _errors().WorkspaceStorageError("stored policy settings are invalid")
    return bool(value)


def _stored_masks(row: dict[str, Any], field: str) -> list[str]:
    """Accept only the canonical stored mask text; never repair corruption."""

    value = row.get(field)
    try:
        if not isinstance(value, str):
            raise ValueError("stored mask selection is invalid")
        parsed = masks_from_text(value)
        if masks_to_text(parsed) != value:
            raise ValueError("stored mask selection is not canonical")
    except ValueError:
        raise _errors().WorkspaceStorageError(
            "stored policy settings are invalid"
        ) from None
    return list(parsed)


def _settings_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """Validate one immutable revision row before any enforcement use.

    A corrupted toggle, non-canonical mask text or mismatched settings digest
    raises rather than producing a permissive (or any) effective control.
    """

    input_enabled = _stored_bool(row, "input_check_enabled")
    output_enabled = _stored_bool(row, "output_check_enabled")
    input_masks = _stored_masks(row, "input_masks")
    output_masks = _stored_masks(row, "output_masks")
    digest = row.get("digest")
    if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
        raise _errors().WorkspaceStorageError("stored policy settings are invalid")
    expected = settings_digest(
        input_enabled, output_enabled, input_masks, output_masks
    )
    if not hmac.compare_digest(digest, expected):
        raise _errors().WorkspaceStorageError("stored policy settings are invalid")
    return {
        "input_check_enabled": input_enabled,
        "output_check_enabled": output_enabled,
        "input_masks": input_masks,
        "output_masks": output_masks,
    }


def _profile_metadata(profile: dict[str, Any], revision: dict[str, Any]) -> dict[str, Any]:
    settings = _settings_from_row(revision)
    try:
        profile_version = int(profile["version"])
        revision_number = int(revision["revision"])
    except (KeyError, TypeError, ValueError):
        raise _errors().WorkspaceStorageError(
            "stored policy profile is invalid"
        ) from None
    if profile_version < 1 or revision_number != profile_version:
        raise _errors().WorkspaceStorageError("stored policy profile is invalid")
    return {
        "id": profile["id"],
        "name": profile["name"],
        "revision": profile_version,
        "settings": settings,
        "settings_digest": revision["digest"],
        "created_by": profile["created_by"],
        "created_at": float(profile["created_at"]),
        "updated_at": float(profile["updated_at"]),
    }


def _scope_values(
    scope_type: Any, scope_id: Any
) -> tuple[str, str, str | None, str | None]:
    if scope_type == "workspace":
        if scope_id not in (None, "workspace"):
            raise ValueError("policy scope is invalid")
        return "workspace", "workspace", None, None
    if scope_type == "department":
        department_id = _require_safe_id(scope_id, "department")
        return "department", department_id, department_id, None
    if scope_type == "user":
        user_id = _require_safe_id(scope_id, "user")
        return "user", user_id, None, user_id
    raise ValueError("policy scope is invalid")


def _policy_revision(profile: dict[str, Any], revision: Any) -> int:
    value = _require_int(revision, "profile revision")
    if value > int(profile["version"]):
        raise ValueError("profile revision is invalid")
    return value


def _alert_sources(value: Any) -> tuple[tuple[str, str, str, int], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise ValueError("alert sources are invalid")
    if len(value) > MAX_SOURCES:
        raise ValueError("alert sources are invalid")
    sources: list[tuple[str, str, str, int]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "scope_type",
            "scope_id",
            "profile_id",
            "revision",
        }:
            raise ValueError("alert sources are invalid")
        scope_type = item["scope_type"]
        if scope_type not in ("workspace", "department", "user"):
            raise ValueError("alert sources are invalid")
        sources.append(
            (
                scope_type,
                _require_safe_id(item["scope_id"], "alert scope"),
                _require_safe_id(item["profile_id"], "alert profile"),
                _require_int(item["revision"], "alert revision"),
            )
        )
    return tuple(sources)


def _parse_sources(value: Any) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        raise _errors().WorkspaceStorageError(
            "stored alert metadata is invalid"
        ) from None
    if parsed == []:
        return []
    try:
        sources = _alert_sources(parsed)
    except ValueError:
        raise _errors().WorkspaceStorageError(
            "stored alert metadata is invalid"
        ) from None
    return [
        {
            "scope_type": scope_type,
            "scope_id": scope_id,
            "profile_id": profile_id,
            "revision": revision,
        }
        for scope_type, scope_id, profile_id, revision in sources
    ]


class PolicyAdminMixin:
    """Reusable profiles, explicit inheritance and effective snapshots."""

    # -- internal helpers ------------------------------------------------
    @staticmethod
    def _policy_audit(
        db: Any,
        actor_id: str,
        action: str,
        *,
        profile_id: str | None = None,
        revision: int | None = None,
        scope_type: str | None = None,
        scope_id: str | None = None,
        detail: dict[str, Any] | None = None,
        now: float,
    ) -> None:
        detail_json = None
        if detail is not None:
            detail_json = json.dumps(
                detail, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            if len(detail_json) > MAX_DETAIL_LENGTH:
                raise ValueError("policy audit detail is invalid")
        applied = db.execute(
            """
            INSERT INTO ws_policy_audit(
                id, actor_id, action, profile_id, revision, scope_type, scope_id,
                detail, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                actor_id,
                action,
                profile_id,
                revision,
                scope_type,
                scope_id,
                detail_json,
                now,
            ),
        )
        if applied != 1:
            raise _errors().WorkspaceStorageError(
                "policy audit record was not stored"
            )

    @staticmethod
    def _profile_row(db: Any, profile_id: Any) -> dict[str, Any]:
        if not isinstance(profile_id, str) or not profile_id:
            raise _errors().NotFound("policy profile not found")
        row = db.query_one(
            "SELECT id, name, version, created_by, created_at, updated_at "
            "FROM ws_policy_profiles WHERE id = ?",
            (profile_id,),
        )
        if not row:
            raise _errors().NotFound("policy profile not found")
        return row

    @staticmethod
    def _latest_revision_row(db: Any, profile_id: str) -> dict[str, Any]:
        row = db.query_one(
            """
            SELECT profile_id, revision, input_check_enabled,
                   output_check_enabled, input_masks, output_masks, digest,
                   rollback_of, created_by, created_at
            FROM ws_policy_profile_revisions
            WHERE profile_id = ?
            ORDER BY revision DESC LIMIT 1
            """,
            (profile_id,),
        )
        if not row:
            raise _errors().WorkspaceStorageError(
                "stored policy profile is incomplete"
            )
        return row

    @staticmethod
    def _revision_row(
        db: Any, profile_id: str, revision: int
    ) -> dict[str, Any]:
        row = db.query_one(
            """
            SELECT profile_id, revision, input_check_enabled,
                   output_check_enabled, input_masks, output_masks, digest,
                   rollback_of, created_by, created_at
            FROM ws_policy_profile_revisions
            WHERE profile_id = ? AND revision = ?
            """,
            (profile_id, revision),
        )
        if not row:
            raise _errors().NotFound("policy revision not found")
        return row

    @staticmethod
    def _insert_revision(
        db: Any,
        *,
        profile_id: str,
        revision: int,
        input_check_enabled: bool,
        output_check_enabled: bool,
        input_masks: str,
        output_masks: str,
        digest: str,
        actor_id: str,
        now: float,
        rollback_of: int | None = None,
    ) -> None:
        applied = db.execute(
            """
            INSERT INTO ws_policy_profile_revisions(
                id, profile_id, revision, input_check_enabled,
                output_check_enabled, input_masks, output_masks, digest,
                rollback_of, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                profile_id,
                revision,
                1 if input_check_enabled else 0,
                1 if output_check_enabled else 0,
                input_masks,
                output_masks,
                digest,
                rollback_of,
                actor_id,
                now,
            ),
        )
        if applied != 1:
            raise _errors().WorkspaceStorageError(
                "policy revision was not stored"
            )

    @staticmethod
    def _assignment_metadata(row: dict[str, Any]) -> dict[str, Any]:
        settings = _settings_from_row(row)
        return {
            "id": row["id"],
            "scope_type": row["scope_type"],
            "scope_id": row["scope_key"],
            "profile_id": row["profile_id"],
            "profile_name": row.get("profile_name"),
            "profile_revision": int(row["profile_revision"]),
            "version": int(row["version"]),
            "settings": settings,
            "settings_digest": row["digest"],
            "created_by": row["created_by"],
            "updated_by": row["updated_by"],
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }

    # -- profile administration -----------------------------------------
    @_policy_guard
    def create_policy_profile(
        self,
        actor_id: str,
        name: str,
        *,
        input_check_enabled: bool = True,
        output_check_enabled: bool = True,
        input_masks: Any = MASK_TYPES,
        output_masks: Any = MASK_TYPES,
    ) -> dict[str, Any]:
        clean_name = _require_text(name, "profile name", maximum=PROFILE_NAME_MAX)
        name_key = clean_name.casefold()
        (
            input_enabled,
            output_enabled,
            _input_selection,
            _output_selection,
            input_text,
            output_text,
            digest,
        ) = _settings(
            input_check_enabled, output_check_enabled, input_masks, output_masks
        )
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            if db.query_one(
                "SELECT id FROM ws_policy_profiles WHERE name_key = ?", (name_key,)
            ):
                raise _errors().Conflict("policy profile name already exists")
            profile_id = str(uuid.uuid4())
            db.execute(
                """
                INSERT INTO ws_policy_profiles(
                    id, name, name_key, version, created_by, created_at,
                    updated_at
                ) VALUES (?, ?, ?, 1, ?, ?, ?)
                """,
                (profile_id, clean_name, name_key, actor_id, now, now),
            )
            self._insert_revision(
                db,
                profile_id=profile_id,
                revision=1,
                input_check_enabled=input_enabled,
                output_check_enabled=output_enabled,
                input_masks=input_text,
                output_masks=output_text,
                digest=digest,
                actor_id=actor_id,
                now=now,
            )
            self._policy_audit(
                db,
                actor_id,
                "profile.create",
                profile_id=profile_id,
                revision=1,
                detail={"settings_digest": digest},
                now=now,
            )
            profile = self._profile_row(db, profile_id)
            revision = self._revision_row(db, profile_id, 1)
            return _profile_metadata(profile, revision)

    @_policy_guard
    def list_policy_profiles(
        self, actor_id: str, *, limit: int = DEFAULT_PAGE, after: str | None = None
    ) -> dict[str, Any]:
        limit = _limit(limit)
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            params: list[Any] = []
            sql = (
                "SELECT p.id, p.name, p.version, p.created_by, p.created_at, "
                "p.updated_at, r.revision AS revision, r.input_check_enabled, "
                "r.output_check_enabled, r.input_masks, r.output_masks, r.digest "
                "FROM ws_policy_profiles AS p "
                "JOIN ws_policy_profile_revisions AS r ON r.profile_id = p.id "
                "AND r.revision = (SELECT MAX(r2.revision) "
                "FROM ws_policy_profile_revisions AS r2 "
                "WHERE r2.profile_id = p.id) WHERE 1 = 1"
            )
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (p.created_at < ? OR (p.created_at = ? AND p.id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY p.created_at DESC, p.id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [
                _profile_metadata(row, row) for row in rows[:limit]
            ]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    @_policy_guard
    def get_policy_profile(self, actor_id: str, profile_id: str) -> dict[str, Any]:
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            profile = self._profile_row(db, profile_id)
            revision = self._latest_revision_row(db, profile["id"])
            return _profile_metadata(profile, revision)

    @_policy_guard
    def list_policy_profile_revisions(
        self,
        actor_id: str,
        profile_id: str,
        *,
        limit: int = DEFAULT_PAGE,
        after: str | None = None,
    ) -> dict[str, Any]:
        limit = _limit(limit)
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            profile = self._profile_row(db, profile_id)
            params: list[Any] = [profile["id"]]
            sql = (
                "SELECT revision, input_check_enabled, output_check_enabled, "
                "input_masks, output_masks, digest, rollback_of, created_by, "
                "created_at FROM ws_policy_profile_revisions "
                "WHERE profile_id = ?"
            )
            if after is not None:
                if not isinstance(after, str) or not after.isdigit():
                    raise ValueError("revision cursor is invalid")
                cursor = int(after)
                if cursor < 1:
                    raise ValueError("revision cursor is invalid")
                sql += " AND revision < ?"
                params.append(cursor)
            sql += " ORDER BY revision DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [
                {
                    "revision": int(row["revision"]),
                    "settings": _settings_from_row(row),
                    "settings_digest": row["digest"],
                    "rollback_of": row["rollback_of"],
                    "created_by": row["created_by"],
                    "created_at": float(row["created_at"]),
                }
                for row in rows[:limit]
            ]
            next_cursor = (
                str(rows[limit - 1]["revision"]) if len(rows) > limit else None
            )
            return {"items": items, "next": next_cursor}

    @_policy_guard
    def revise_policy_profile(
        self,
        actor_id: str,
        profile_id: str,
        expected_revision: int,
        *,
        input_check_enabled: bool = True,
        output_check_enabled: bool = True,
        input_masks: Any = MASK_TYPES,
        output_masks: Any = MASK_TYPES,
    ) -> dict[str, Any]:
        expected = _require_int(expected_revision, "expected revision")
        (
            input_enabled,
            output_enabled,
            _input_selection,
            _output_selection,
            input_text,
            output_text,
            digest,
        ) = _settings(
            input_check_enabled, output_check_enabled, input_masks, output_masks
        )
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            profile = self._profile_row(db, profile_id)
            current = int(profile["version"])
            if current != expected:
                raise _errors().Conflict("policy profile changed")
            new_revision = current + 1
            applied = db.execute(
                "UPDATE ws_policy_profiles SET version = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (new_revision, now, profile["id"], expected),
            )
            if applied != 1:
                raise _errors().Conflict("policy profile changed")
            self._insert_revision(
                db,
                profile_id=profile["id"],
                revision=new_revision,
                input_check_enabled=input_enabled,
                output_check_enabled=output_enabled,
                input_masks=input_text,
                output_masks=output_text,
                digest=digest,
                actor_id=actor_id,
                now=now,
            )
            self._policy_audit(
                db,
                actor_id,
                "profile.revise",
                profile_id=profile["id"],
                revision=new_revision,
                detail={"from": current, "settings_digest": digest},
                now=now,
            )
            updated = self._profile_row(db, profile["id"])
            revision = self._revision_row(db, profile["id"], new_revision)
            return _profile_metadata(updated, revision)

    @_policy_guard
    def rollback_policy_profile(
        self,
        actor_id: str,
        profile_id: str,
        target_revision: int,
        expected_revision: int,
    ) -> dict[str, Any]:
        target = _require_int(target_revision, "target revision")
        expected = _require_int(expected_revision, "expected revision")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            profile = self._profile_row(db, profile_id)
            current = int(profile["version"])
            if current != expected:
                raise _errors().Conflict("policy profile changed")
            old = self._revision_row(db, profile["id"], target)
            _settings_from_row(old)
            new_revision = current + 1
            applied = db.execute(
                "UPDATE ws_policy_profiles SET version = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (new_revision, now, profile["id"], expected),
            )
            if applied != 1:
                raise _errors().Conflict("policy profile changed")
            self._insert_revision(
                db,
                profile_id=profile["id"],
                revision=new_revision,
                input_check_enabled=bool(int(old["input_check_enabled"])),
                output_check_enabled=bool(int(old["output_check_enabled"])),
                input_masks=old["input_masks"],
                output_masks=old["output_masks"],
                digest=old["digest"],
                actor_id=actor_id,
                now=now,
                rollback_of=target,
            )
            self._policy_audit(
                db,
                actor_id,
                "profile.rollback",
                profile_id=profile["id"],
                revision=new_revision,
                detail={"from": current, "rollback_of": target},
                now=now,
            )
            updated = self._profile_row(db, profile["id"])
            revision = self._revision_row(db, profile["id"], new_revision)
            return _profile_metadata(updated, revision)

    @_policy_guard
    def list_policy_audit(
        self, actor_id: str, *, limit: int = DEFAULT_PAGE, after: str | None = None
    ) -> dict[str, Any]:
        limit = _limit(limit)
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            params: list[Any] = []
            sql = (
                "SELECT id, actor_id, action, profile_id, revision, scope_type, "
                "scope_id, detail, created_at FROM ws_policy_audit WHERE 1 = 1"
            )
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (created_at < ? OR (created_at = ? AND id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [
                {
                    "id": row["id"],
                    "actor_id": row["actor_id"],
                    "action": row["action"],
                    "profile_id": row["profile_id"],
                    "revision": row["revision"],
                    "scope_type": row["scope_type"],
                    "scope_id": row["scope_id"],
                    "detail": row["detail"],
                    "created_at": float(row["created_at"]),
                }
                for row in rows[:limit]
            ]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    # -- assignments ------------------------------------------------------
    @_policy_guard
    def assign_policy_profile(
        self,
        actor_id: str,
        scope_type: str,
        scope_id: str | None,
        profile_id: str,
        *,
        profile_revision: int | None = None,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        scope, scope_key, department_id, user_id = _scope_values(
            scope_type, scope_id
        )
        if expected_version is not None:
            expected_version = _require_int(
                expected_version, "expected assignment version", minimum=0
            )
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            if department_id is not None and not db.query_one(
                "SELECT id FROM ws_departments WHERE id = ?", (department_id,)
            ):
                raise _errors().NotFound("department not found")
            if user_id is not None and not db.query_one(
                "SELECT id FROM ws_users WHERE id = ?", (user_id,)
            ):
                raise _errors().NotFound("user not found")
            profile = self._profile_row(db, profile_id)
            revision = _policy_revision(
                profile,
                profile["version"] if profile_revision is None else profile_revision,
            )
            revision_row = self._revision_row(db, profile["id"], revision)
            _settings_from_row(revision_row)
            existing = db.query_one(
                "SELECT id, version FROM ws_policy_assignments "
                "WHERE scope_type = ? AND scope_key = ?",
                (scope, scope_key),
            )
            if existing:
                if (
                    expected_version is None
                    or expected_version != int(existing["version"])
                ):
                    raise _errors().Conflict("policy assignment changed")
                applied = db.execute(
                    """
                    UPDATE ws_policy_assignments
                    SET profile_id = ?, profile_revision = ?, version = version + 1,
                        updated_by = ?, updated_at = ?
                    WHERE id = ? AND version = ?
                    """,
                    (
                        profile["id"],
                        revision,
                        actor_id,
                        now,
                        existing["id"],
                        expected_version,
                    ),
                )
                if applied != 1:
                    raise _errors().Conflict("policy assignment changed")
                assignment_id = existing["id"]
            else:
                if expected_version not in (None, 0):
                    raise _errors().Conflict("policy assignment changed")
                assignment_id = str(uuid.uuid4())
                db.execute(
                    """
                    INSERT INTO ws_policy_assignments(
                        id, scope_type, scope_key, department_id, user_id,
                        profile_id, profile_revision, version, created_by,
                        updated_by, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                    """,
                    (
                        assignment_id,
                        scope,
                        scope_key,
                        department_id,
                        user_id,
                        profile["id"],
                        revision,
                        actor_id,
                        actor_id,
                        now,
                        now,
                    ),
                )
            self._policy_audit(
                db,
                actor_id,
                "assignment.set",
                profile_id=profile["id"],
                revision=revision,
                scope_type=scope,
                scope_id=scope_key,
                detail={"settings_digest": revision_row["digest"]},
                now=now,
            )
            row = db.query_one(
                "SELECT a.id, a.scope_type, a.scope_key, a.profile_id, "
                "a.profile_revision, a.version, a.created_by, a.updated_by, "
                "a.created_at, a.updated_at, p.name AS profile_name, "
                "r.input_check_enabled, r.output_check_enabled, r.input_masks, "
                "r.output_masks, r.digest "
                "FROM ws_policy_assignments AS a "
                "JOIN ws_policy_profiles AS p ON p.id = a.profile_id "
                "JOIN ws_policy_profile_revisions AS r "
                "ON r.profile_id = a.profile_id AND r.revision = a.profile_revision "
                "WHERE a.id = ?",
                (assignment_id,),
            )
            if not row:
                raise _errors().WorkspaceStorageError(
                    "policy assignment was not stored"
                )
            return self._assignment_metadata(row)

    @_policy_guard
    def clear_policy_assignment(
        self,
        actor_id: str,
        scope_type: str,
        scope_id: str | None,
        *,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        scope, scope_key, _department_id, _user_id = _scope_values(
            scope_type, scope_id
        )
        if expected_version is not None:
            expected_version = _require_int(
                expected_version, "expected assignment version", minimum=0
            )
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            existing = db.query_one(
                "SELECT id, version FROM ws_policy_assignments "
                "WHERE scope_type = ? AND scope_key = ?",
                (scope, scope_key),
            )
            if not existing:
                return {
                    "cleared": False,
                    "scope_type": scope,
                    "scope_id": scope_key,
                }
            if (
                expected_version is not None
                and expected_version != int(existing["version"])
            ):
                raise _errors().Conflict("policy assignment changed")
            applied = db.execute(
                "DELETE FROM ws_policy_assignments WHERE id = ? AND version = ?",
                (existing["id"], int(existing["version"])),
            )
            if applied != 1:
                raise _errors().Conflict("policy assignment changed")
            self._policy_audit(
                db,
                actor_id,
                "assignment.clear",
                scope_type=scope,
                scope_id=scope_key,
                now=now,
            )
            return {"cleared": True, "scope_type": scope, "scope_id": scope_key}

    @_policy_guard
    def get_policy_assignment(
        self, actor_id: str, scope_type: str, scope_id: str | None = None
    ) -> dict[str, Any] | None:
        scope, scope_key, _department_id, _user_id = _scope_values(
            scope_type, scope_id
        )
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            row = db.query_one(
                "SELECT a.id, a.scope_type, a.scope_key, a.profile_id, "
                "a.profile_revision, a.version, a.created_by, a.updated_by, "
                "a.created_at, a.updated_at, p.name AS profile_name, "
                "r.input_check_enabled, r.output_check_enabled, r.input_masks, "
                "r.output_masks, r.digest "
                "FROM ws_policy_assignments AS a "
                "JOIN ws_policy_profiles AS p ON p.id = a.profile_id "
                "JOIN ws_policy_profile_revisions AS r "
                "ON r.profile_id = a.profile_id AND r.revision = a.profile_revision "
                "WHERE a.scope_type = ? AND a.scope_key = ?",
                (scope, scope_key),
            )
            return self._assignment_metadata(row) if row else None

    @_policy_guard
    def list_policy_assignments(
        self,
        actor_id: str,
        *,
        scope_type: str | None = None,
        limit: int = DEFAULT_PAGE,
        after: str | None = None,
    ) -> dict[str, Any]:
        limit = _limit(limit)
        if scope_type is not None and scope_type not in _SCOPE_ORDER:
            raise ValueError("policy scope is invalid")
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            params: list[Any] = []
            sql = (
                "SELECT a.id, a.scope_type, a.scope_key, a.profile_id, "
                "a.profile_revision, a.version, a.created_by, a.updated_by, "
                "a.created_at, a.updated_at, p.name AS profile_name, "
                "r.input_check_enabled, r.output_check_enabled, r.input_masks, "
                "r.output_masks, r.digest "
                "FROM ws_policy_assignments AS a "
                "JOIN ws_policy_profiles AS p ON p.id = a.profile_id "
                "JOIN ws_policy_profile_revisions AS r "
                "ON r.profile_id = a.profile_id AND r.revision = a.profile_revision "
                "WHERE 1 = 1"
            )
            if scope_type is not None:
                sql += " AND a.scope_type = ?"
                params.append(scope_type)
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (a.created_at < ? OR (a.created_at = ? AND a.id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY a.created_at DESC, a.id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [self._assignment_metadata(row) for row in rows[:limit]]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    # -- effective policy -------------------------------------------------
    @_policy_guard
    def resolve_effective_policy(
        self, actor_id: str, user_id: str | None = None
    ) -> dict[str, Any]:
        """Resolve the workspace -> department -> user inheritance chain.

        A regular user may resolve only their own effective policy; an active
        administrator may resolve any user for the preview.  Every call builds a
        fresh immutable snapshot from committed rows, so concurrent policy
        changes cannot mutate a request already in flight.
        """

        target_id = actor_id if user_id is None else user_id
        if not isinstance(target_id, str) or not target_id:
            raise ValueError("user is invalid")
        with self._backend.transaction() as db:
            actor = self._require_active_user(db, actor_id)
            if target_id != actor_id and actor["role"] != "admin":
                raise _errors().AccessDenied("permission denied")
            target = db.query_one(
                "SELECT id, department_id, disabled FROM ws_users WHERE id = ?",
                (target_id,),
            )
            if not target or int(target["disabled"]) != 0:
                raise _errors().NotFound("user not found")
            rows = db.query(
                """
                SELECT a.scope_type, a.scope_key, a.profile_id,
                       a.profile_revision, p.name AS profile_name,
                       r.input_check_enabled, r.output_check_enabled,
                       r.input_masks, r.output_masks, r.digest
                FROM ws_policy_assignments AS a
                JOIN ws_policy_profiles AS p ON p.id = a.profile_id
                JOIN ws_policy_profile_revisions AS r
                  ON r.profile_id = a.profile_id
                 AND r.revision = a.profile_revision
                WHERE (a.scope_type = 'workspace' AND a.scope_key = 'workspace')
                   OR (a.scope_type = 'department' AND a.scope_key = ?)
                   OR (a.scope_type = 'user' AND a.scope_key = ?)
                """,
                (target["department_id"], target["id"]),
            )
            rows.sort(key=lambda row: _SCOPE_ORDER[row["scope_type"]])
            # Validate every inherited revision before producing a snapshot.
            # One corrupt scope row fails the whole resolution closed, even if
            # a later, more specific scope would otherwise win.
            for row in rows:
                _settings_from_row(row)
            sources = [
                {
                    "scope_type": row["scope_type"],
                    "scope_id": row["scope_key"],
                    "profile_id": row["profile_id"],
                    "profile_name": row["profile_name"],
                    "revision": int(row["profile_revision"]),
                    "settings_digest": row["digest"],
                }
                for row in rows
            ]
            if rows:
                applied = rows[-1]
                settings = _settings_from_row(applied)
                revision = (
                    f"profile:{applied['profile_id']}:{int(applied['profile_revision'])}"
                )
                control_sources = tuple(
                    (
                        row["scope_type"],
                        row["scope_key"],
                        row["profile_id"],
                        int(row["profile_revision"]),
                    )
                    for row in rows
                )
                settings_digest_value = applied["digest"]
            else:
                settings = {
                    "input_check_enabled": True,
                    "output_check_enabled": True,
                    "input_masks": list(MASK_TYPES),
                    "output_masks": list(MASK_TYPES),
                }
                revision = "default"
                control_sources = ()
                settings_digest_value = settings_digest(
                    True, True, MASK_TYPES, MASK_TYPES
                )
            control = GatewayControl(
                input_check_enabled=settings["input_check_enabled"],
                output_check_enabled=settings["output_check_enabled"],
                input_masks=tuple(settings["input_masks"]),
                output_masks=tuple(settings["output_masks"]),
                revision=revision,
                sources=control_sources,
            )
            return {
                "user_id": target["id"],
                "department_id": target["department_id"],
                **settings,
                "revision": control.revision,
                "digest": control.digest,
                "settings_digest": settings_digest_value,
                "source": sources[-1] if sources else None,
                "sources": sources,
                "is_default": not bool(rows),
            }

    def resolve_gateway_control(
        self, actor_id: str, user_id: str | None = None
    ) -> GatewayControl:
        """Return the exact immutable control accepted by ``Gateway.handle``.

        This is the stage-2 integration point: the chat pipeline resolves it
        once per turn and passes it explicitly, never through shared adapter
        state or client-supplied JSON.
        """

        data = self.resolve_effective_policy(actor_id, user_id)
        return GatewayControl(
            input_check_enabled=data["input_check_enabled"],
            output_check_enabled=data["output_check_enabled"],
            input_masks=tuple(data["input_masks"]),
            output_masks=tuple(data["output_masks"]),
            revision=data["revision"],
            sources=tuple(
                (
                    source["scope_type"],
                    source["scope_id"],
                    source["profile_id"],
                    source["revision"],
                )
                for source in data["sources"]
            ),
        )


class AlertAdminMixin:
    """Persistent block-alert metadata and per-administrator read/ack state."""

    @staticmethod
    def _prepare_block_alert(
        alert: dict[str, Any] | None,
        *,
        outcome: str,
        request_id: str | None,
    ) -> dict[str, Any] | None:
        if alert is None:
            return None
        if outcome != "blocked":
            raise ValueError("alert requires a blocked turn")
        if not isinstance(alert, dict) or set(alert) != {
            "stage",
            "reason_code",
            "revision",
            "digest",
            "sources",
        }:
            raise ValueError("alert metadata is invalid")
        stage = alert["stage"]
        reason_code = alert["reason_code"]
        if (
            not isinstance(reason_code, str)
            or not isinstance(stage, str)
            or reason_code not in BLOCK_REASONS
            or stage not in BLOCK_STAGES
        ):
            raise ValueError("alert metadata is invalid")
        expected_stage, _title, reason_text = BLOCK_REASONS[reason_code]
        if stage != expected_stage:
            raise ValueError("alert metadata is invalid")
        revision = _require_text(
            alert["revision"], "alert policy revision", maximum=128
        )
        digest = alert["digest"]
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise ValueError("alert metadata is invalid")
        sources = _alert_sources(alert["sources"])
        sources_json = json.dumps(
            [
                {
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "profile_id": profile_id,
                    "revision": revision_number,
                }
                for scope_type, scope_id, profile_id, revision_number in sources
            ],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if len(sources_json) > 4096:
            raise ValueError("alert metadata is invalid")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("alert request reference is required")
        return {
            "request_id": request_id,
            "stage": stage,
            "reason_code": reason_code,
            "reason_text": reason_text,
            "revision": revision,
            "digest": digest,
            "sources": sources_json,
        }

    @staticmethod
    def _insert_block_alert(
        db: Any,
        prepared: dict[str, Any],
        *,
        user_id: str,
        department_id: str,
        conversation_id: str,
        message_id: str,
        now: float,
    ) -> str:
        alert_id = str(uuid.uuid4())
        applied = db.execute(
            """
            INSERT INTO ws_block_alerts(
                id, request_id, user_id, department_id, conversation_id,
                message_id, stage, reason_code, reason_text, control_revision,
                control_digest, control_sources, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (request_id) DO NOTHING
            """,
            (
                alert_id,
                prepared["request_id"],
                user_id,
                department_id,
                conversation_id,
                message_id,
                prepared["stage"],
                prepared["reason_code"],
                prepared["reason_text"],
                prepared["revision"],
                prepared["digest"],
                prepared["sources"],
                now,
            ),
        )
        if applied == 1:
            return alert_id
        row = db.query_one(
            "SELECT id FROM ws_block_alerts WHERE request_id = ?",
            (prepared["request_id"],),
        )
        if not row:
            raise _errors().WorkspaceStorageError(
                "block alert was not stored"
            )
        return row["id"]

    @staticmethod
    def _alert_metadata(row: dict[str, Any]) -> dict[str, Any]:
        read_at = row["read_at"]
        acknowledged_at = row["acknowledged_at"]
        return {
            "id": row["id"],
            "request_id": row["request_id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "full_name": row["full_name"],
            "department_id": row["department_id"],
            "department_name": row["department_name"],
            "conversation_id": row["conversation_id"],
            "message_id": row["message_id"],
            "stage": row["stage"],
            "reason_code": row["reason_code"],
            "reason_text": row["reason_text"],
            "control_revision": row["control_revision"],
            "control_digest": row["control_digest"],
            "control_sources": _parse_sources(row["control_sources"]),
            "created_at": float(row["created_at"]),
            "read": read_at is not None,
            "read_at": float(read_at) if read_at is not None else None,
            "acknowledged": acknowledged_at is not None,
            "acknowledged_at": (
                float(acknowledged_at) if acknowledged_at is not None else None
            ),
        }

    @staticmethod
    def _alert_select(actor_id: str) -> tuple[str, list[Any]]:
        sql = (
            "SELECT a.id, a.request_id, a.user_id, a.department_id, "
            "a.conversation_id, a.message_id, a.stage, a.reason_code, "
            "a.reason_text, a.control_revision, a.control_digest, "
            "a.control_sources, a.created_at, u.username, u.full_name, "
            "d.name AS department_name, s.read_at, s.acknowledged_at "
            "FROM ws_block_alerts AS a "
            "JOIN ws_users AS u ON u.id = a.user_id "
            "JOIN ws_departments AS d ON d.id = a.department_id "
            "LEFT JOIN ws_alert_state AS s ON s.alert_id = a.id "
            "AND s.admin_id = ? WHERE 1 = 1"
        )
        return sql, [actor_id]

    @_policy_guard
    def list_block_alerts(
        self,
        actor_id: str,
        *,
        limit: int = DEFAULT_PAGE,
        after: str | None = None,
        stage: str | None = None,
        user_id: str | None = None,
        department_id: str | None = None,
        reason_code: str | None = None,
        unread: bool | None = None,
        acknowledged: bool | None = None,
    ) -> dict[str, Any]:
        limit = _limit(limit)
        if stage is not None and stage not in BLOCK_STAGES:
            raise ValueError("alert stage is invalid")
        if reason_code is not None and reason_code not in BLOCK_REASONS:
            raise ValueError("alert reason is invalid")
        if unread is not None and not isinstance(unread, bool):
            raise ValueError("alert unread filter is invalid")
        if acknowledged is not None and not isinstance(acknowledged, bool):
            raise ValueError("alert acknowledged filter is invalid")
        if unread is True and acknowledged is True:
            raise ValueError("alert filters are invalid")
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            sql, params = self._alert_select(actor_id)
            if stage is not None:
                sql += " AND a.stage = ?"
                params.append(stage)
            if user_id is not None:
                sql += " AND a.user_id = ?"
                params.append(_require_safe_id(user_id, "user"))
            if department_id is not None:
                sql += " AND a.department_id = ?"
                params.append(_require_safe_id(department_id, "department"))
            if reason_code is not None:
                sql += " AND a.reason_code = ?"
                params.append(reason_code)
            if unread is True:
                sql += " AND s.read_at IS NULL"
            elif unread is False:
                sql += " AND s.read_at IS NOT NULL"
            if acknowledged is True:
                sql += " AND s.acknowledged_at IS NOT NULL"
            elif acknowledged is False:
                sql += " AND s.acknowledged_at IS NULL"
            if after is not None:
                created_at, last_id = _decode_cursor(after)
                sql += " AND (a.created_at < ? OR (a.created_at = ? AND a.id < ?))"
                params.extend((created_at, created_at, last_id))
            sql += " ORDER BY a.created_at DESC, a.id DESC LIMIT ?"
            params.append(limit + 1)
            rows = db.query(sql, tuple(params))
            items = [self._alert_metadata(row) for row in rows[:limit]]
            next_cursor = (
                _encode_cursor(rows[limit - 1]["created_at"], rows[limit - 1]["id"])
                if len(rows) > limit
                else None
            )
            return {"items": items, "next": next_cursor}

    @_policy_guard
    def get_block_alert(self, actor_id: str, alert_id: str) -> dict[str, Any]:
        alert_id = _require_safe_id(alert_id, "alert")
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            sql, params = self._alert_select(actor_id)
            sql += " AND a.id = ?"
            params.append(alert_id)
            row = db.query_one(sql, tuple(params))
            if not row:
                raise _errors().NotFound("alert not found")
            return self._alert_metadata(row)

    @staticmethod
    def _state_metadata(alert_id: str, row: dict[str, Any]) -> dict[str, Any]:
        read_at = row["read_at"]
        acknowledged_at = row["acknowledged_at"]
        return {
            "alert_id": alert_id,
            "read": read_at is not None,
            "read_at": float(read_at) if read_at is not None else None,
            "acknowledged": acknowledged_at is not None,
            "acknowledged_at": (
                float(acknowledged_at) if acknowledged_at is not None else None
            ),
        }

    @_policy_guard
    def mark_block_alert_read(self, actor_id: str, alert_id: str) -> dict[str, Any]:
        alert_id = _require_safe_id(alert_id, "alert")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            if not db.query_one(
                "SELECT id FROM ws_block_alerts WHERE id = ?", (alert_id,)
            ):
                raise _errors().NotFound("alert not found")
            db.execute(
                """
                INSERT INTO ws_alert_state(alert_id, admin_id, read_at, acknowledged_at)
                VALUES (?, ?, ?, NULL)
                ON CONFLICT (alert_id, admin_id) DO NOTHING
                """,
                (alert_id, actor_id, now),
            )
            row = db.query_one(
                "SELECT read_at, acknowledged_at FROM ws_alert_state "
                "WHERE alert_id = ? AND admin_id = ?",
                (alert_id, actor_id),
            )
            if not row:
                raise _errors().WorkspaceStorageError(
                    "alert state was not stored"
                )
            return self._state_metadata(alert_id, row)

    @_policy_guard
    def acknowledge_block_alert(self, actor_id: str, alert_id: str) -> dict[str, Any]:
        alert_id = _require_safe_id(alert_id, "alert")
        now = self._now()
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            if not db.query_one(
                "SELECT id FROM ws_block_alerts WHERE id = ?", (alert_id,)
            ):
                raise _errors().NotFound("alert not found")
            db.execute(
                """
                INSERT INTO ws_alert_state(alert_id, admin_id, read_at, acknowledged_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (alert_id, admin_id) DO UPDATE SET
                    read_at = COALESCE(ws_alert_state.read_at, excluded.read_at),
                    acknowledged_at = COALESCE(
                        ws_alert_state.acknowledged_at, excluded.acknowledged_at
                    )
                """,
                (alert_id, actor_id, now, now),
            )
            row = db.query_one(
                "SELECT read_at, acknowledged_at FROM ws_alert_state "
                "WHERE alert_id = ? AND admin_id = ?",
                (alert_id, actor_id),
            )
            if not row:
                raise _errors().WorkspaceStorageError(
                    "alert state was not stored"
                )
            return self._state_metadata(alert_id, row)

    @_policy_guard
    def alert_summary(self, actor_id: str) -> dict[str, int]:
        with self._backend.transaction() as db:
            self._require_admin(db, actor_id)
            row = db.query_one(
                """
                SELECT COUNT(*) AS total,
                       COALESCE(SUM(CASE WHEN s.read_at IS NULL THEN 1 ELSE 0 END), 0)
                           AS unread,
                       COALESCE(SUM(CASE WHEN s.acknowledged_at IS NOT NULL
                                         THEN 1 ELSE 0 END), 0) AS acknowledged
                FROM ws_block_alerts AS a
                LEFT JOIN ws_alert_state AS s ON s.alert_id = a.id
                 AND s.admin_id = ?
                """,
                (actor_id,),
            )
            if not row:
                return {"total": 0, "unread": 0, "acknowledged": 0}
            return {
                "total": int(row["total"]),
                "unread": int(row["unread"]),
                "acknowledged": int(row["acknowledged"]),
            }
