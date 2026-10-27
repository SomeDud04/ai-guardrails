"""Governance policy profiles, inheritance and block alerts over the real store.

These are synthetic local SQLite tests.  They exercise the persisted store
operations, real transactions and the Gateway conversion point; no PostgreSQL,
HTTP server or external service is contacted.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.fernet import Fernet

from nasi_lemak.controls import MASK_TYPES, settings_digest
from nasi_lemak.workspace_store import (
    SCHEMA_VERSION,
    AccessDenied,
    Conflict,
    NotFound,
    WorkspaceStorageError,
    WorkspaceStore,
    _Cipher,
    _hash_password,
    _schema_statements,
    _schema_v3_statements,
)

GOOD_PASSWORD = "correct-horse-battery-staple"
CANARY = "CANARY-governance-original-prompt-4f21"


class FakeClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class GovernanceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "workspace.db")
        self.key = Fernet.generate_key().decode("ascii")
        self.clock = FakeClock()
        self.store = self._open()
        self.admin = self.store.bootstrap_admin(
            username="root.admin",
            password=GOOD_PASSWORD,
            full_name="Root Admin",
            department_name="IT",
        )
        self.second_admin = self.store.create_user(
            self.admin["id"],
            "second.admin",
            GOOD_PASSWORD,
            "Second Admin",
            self.admin["department_id"],
            "admin",
        )
        self.accounting = self.store.create_department(
            self.admin["id"], "Accounting"
        )
        self.hr = self.store.create_department(self.admin["id"], "Human Resources")
        self.alice = self._user("alice", "Alice Tan", self.accounting["id"])
        self.bob = self._user("bob", "Bob Lim", self.accounting["id"])
        self.carol = self._user("carol", "Carol Ng", self.hr["id"])

    def _open(self, *, migrate: bool = True) -> WorkspaceStore:
        return WorkspaceStore(
            self.path,
            encryption_key=self.key,
            clock=self.clock,
            connect_timeout=5.0,
            migrate=migrate,
        )

    def _user(self, username, full_name, department_id):
        return self.store.create_user(
            self.admin["id"],
            username,
            GOOD_PASSWORD,
            full_name,
            department_id,
            "employee",
        )

    def _rows(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = sqlite3.connect(self.path)
        try:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(sql, params)]
        finally:
            conn.close()

    def _exec(self, sql: str, params: tuple = ()) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("PRAGMA ignore_check_constraints = ON")
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def _raw_bytes(self) -> bytes:
        return Path(self.path).read_bytes()

    def _profile(self, name: str, **kwargs):
        return self.store.create_policy_profile(self.admin["id"], name, **kwargs)

    def _control_alert(self, owner):
        control = self.store.resolve_gateway_control(owner["id"])
        return {
            "stage": "input",
            "reason_code": "INPUT_GUARD_BLOCK",
            "revision": control.revision,
            "digest": control.digest,
            "sources": control.metadata()["sources"],
        }

    def _blocked_turn(
        self,
        owner,
        request_id: str,
        *,
        prompt: str = CANARY,
        stage: str = "input",
        reason_code: str = "INPUT_GUARD_BLOCK",
    ):
        control = self.store.resolve_gateway_control(owner["id"])
        alert = {
            "stage": stage,
            "reason_code": reason_code,
            "revision": control.revision,
            "digest": control.digest,
            "sources": control.metadata()["sources"],
        }
        conversation = self.store.create_conversation(owner["id"])
        lease = self.store.reserve_turn(owner["id"], conversation["id"])
        result = self.store.record_failed_turn(
            owner["id"],
            conversation["id"],
            lease["token"],
            user_prompt=prompt,
            outcome="blocked",
            request_id=request_id,
            error_code="POLICY_BLOCK",
            alert=alert,
        )
        return conversation, result


class PolicyAdminTests(GovernanceTestBase):
    def test_every_governance_api_requires_an_admin_actor(self) -> None:
        profile = self._profile("Baseline")
        assignment = self.store.assign_policy_profile(
            self.admin["id"], "workspace", None, profile["id"]
        )
        _conversation, blocked = self._blocked_turn(self.alice, "req_role_denied")
        alert_id = blocked["alert_id"]
        employee = self.alice["id"]
        calls = {
            "create": lambda: self.store.create_policy_profile(employee, "Denied"),
            "list_profiles": lambda: self.store.list_policy_profiles(employee),
            "get_profile": lambda: self.store.get_policy_profile(
                employee, profile["id"]
            ),
            "list_revisions": lambda: self.store.list_policy_profile_revisions(
                employee, profile["id"]
            ),
            "revise": lambda: self.store.revise_policy_profile(
                employee, profile["id"], 1
            ),
            "rollback": lambda: self.store.rollback_policy_profile(
                employee, profile["id"], 1, 1
            ),
            "policy_audit": lambda: self.store.list_policy_audit(employee),
            "assign": lambda: self.store.assign_policy_profile(
                employee, "workspace", None, profile["id"]
            ),
            "clear": lambda: self.store.clear_policy_assignment(
                employee, "workspace", None
            ),
            "get_assignment": lambda: self.store.get_policy_assignment(
                employee, "workspace"
            ),
            "list_assignments": lambda: self.store.list_policy_assignments(employee),
            "resolve_other": lambda: self.store.resolve_effective_policy(
                employee, self.bob["id"]
            ),
            "resolve_control_other": lambda: self.store.resolve_gateway_control(
                employee, self.bob["id"]
            ),
            "alerts": lambda: self.store.list_block_alerts(employee),
            "alert": lambda: self.store.get_block_alert(employee, alert_id),
            "summary": lambda: self.store.alert_summary(employee),
            "read": lambda: self.store.mark_block_alert_read(employee, alert_id),
            "read_all": lambda: self.store.mark_all_block_alerts_read(employee),
            "ack": lambda: self.store.acknowledge_block_alert(employee, alert_id),
        }
        for name, call in calls.items():
            with self.subTest(api=name):
                with self.assertRaises(AccessDenied):
                    call()
        self.assertEqual(assignment["scope_type"], "workspace")

    def test_profile_create_revise_conflict_and_rollback_keeps_immutable_history(self) -> None:
        profile = self._profile("Strict")
        self.assertEqual(profile["revision"], 1)
        self.assertEqual(profile["settings"]["input_masks"], list(MASK_TYPES))
        self.assertEqual(profile["settings"]["output_masks"], list(MASK_TYPES))
        original_digest = profile["settings_digest"]
        self.assertEqual(
            original_digest,
            settings_digest(True, True, MASK_TYPES, MASK_TYPES),
        )

        revised = self.store.revise_policy_profile(
            self.admin["id"],
            profile["id"],
            1,
            input_check_enabled=False,
            output_check_enabled=True,
            input_masks=(),
            output_masks=("EMAIL",),
        )
        self.assertEqual(revised["revision"], 2)
        self.assertFalse(revised["settings"]["input_check_enabled"])
        self.assertEqual(revised["settings"]["input_masks"], [])
        self.assertEqual(revised["settings"]["output_masks"], ["EMAIL"])

        history = self.store.list_policy_profile_revisions(
            self.admin["id"], profile["id"]
        )["items"]
        self.assertEqual([item["revision"] for item in history], [2, 1])
        self.assertEqual(history[1]["settings"]["input_masks"], list(MASK_TYPES))
        self.assertEqual(history[1]["settings_digest"], original_digest)

        with self.assertRaises(Conflict):
            self.store.revise_policy_profile(
                self.admin["id"], profile["id"], 1, input_check_enabled=False
            )
        self.assertEqual(
            self.store.get_policy_profile(self.admin["id"], profile["id"])[
                "revision"
            ],
            2,
        )

        rolled_back = self.store.rollback_policy_profile(
            self.admin["id"], profile["id"], 1, 2
        )
        self.assertEqual(rolled_back["revision"], 3)
        self.assertEqual(rolled_back["settings"], history[1]["settings"])
        self.assertEqual(rolled_back["settings_digest"], original_digest)
        history = self.store.list_policy_profile_revisions(
            self.admin["id"], profile["id"]
        )["items"]
        self.assertEqual([item["revision"] for item in history], [3, 2, 1])
        self.assertEqual(history[0]["rollback_of"], 1)
        self.assertEqual(history[2]["settings_digest"], original_digest)

        with self.assertRaises(Conflict):
            self.store.rollback_policy_profile(self.admin["id"], profile["id"], 1, 2)

        audit = self.store.list_policy_audit(self.admin["id"])["items"]
        actions = [item["action"] for item in audit]
        self.assertEqual(
            set(actions[:3]),
            {"profile.create", "profile.revise", "profile.rollback"},
        )
        self.assertEqual(len(actions), 3)
        self.assertNotIn(CANARY, json.dumps(audit))

    def test_profile_listing_and_validation(self) -> None:
        for name in ("First", "Second", "Third"):
            self._profile(name)
        first = self.store.list_policy_profiles(self.admin["id"], limit=2)
        self.assertEqual(len(first["items"]), 2)
        self.assertIsNotNone(first["next"])
        second = self.store.list_policy_profiles(
            self.admin["id"], limit=2, after=first["next"]
        )
        self.assertEqual(len(second["items"]), 1)
        self.assertIsNone(second["next"])
        with self.assertRaises(ValueError):
            self.store.create_policy_profile(self.admin["id"], "")
        with self.assertRaises(ValueError):
            self.store.create_policy_profile(
                self.admin["id"], "Bad mask", input_masks=("UNKNOWN",)
            )
        with self.assertRaises(ValueError):
            self.store.create_policy_profile(
                self.admin["id"], "Bad toggle", input_check_enabled=1
            )
        with self.assertRaises(Conflict):
            self._profile("first")  # case-insensitive duplicate
        with self.assertRaises(NotFound):
            self.store.get_policy_profile(self.admin["id"], "missing-profile")

    def test_postal_address_mask_is_independent_per_channel_and_persisted(self):
        profile = self._profile(
            "Postal input only",
            input_masks=("EMAIL", "POSTAL_ADDRESS"),
            output_masks=("MYKAD",),
        )
        self.assertEqual(
            profile["settings"]["input_masks"], ["EMAIL", "POSTAL_ADDRESS"]
        )
        self.assertEqual(profile["settings"]["output_masks"], ["MYKAD"])

        revised = self.store.revise_policy_profile(
            self.admin["id"],
            profile["id"],
            profile["revision"],
            input_masks=("EMAIL",),
            output_masks=("MYKAD", "POSTAL_ADDRESS"),
        )
        self.assertEqual(revised["settings"]["input_masks"], ["EMAIL"])
        self.assertEqual(
            revised["settings"]["output_masks"], ["MYKAD", "POSTAL_ADDRESS"]
        )
        history = self.store.list_policy_profile_revisions(
            self.admin["id"], profile["id"]
        )["items"]
        self.assertEqual(
            history[1]["settings"]["input_masks"], ["EMAIL", "POSTAL_ADDRESS"]
        )
        self.assertEqual(history[1]["settings"]["output_masks"], ["MYKAD"])

        self.store.assign_policy_profile(
            self.admin["id"], "user", self.alice["id"], profile["id"]
        )
        effective = self.store.resolve_effective_policy(
            self.admin["id"], self.alice["id"]
        )
        self.assertEqual(effective["input_masks"], ["EMAIL"])
        self.assertEqual(effective["output_masks"], ["MYKAD", "POSTAL_ADDRESS"])
        control = self.store.resolve_gateway_control(self.alice["id"])
        self.assertEqual(control.input_masks, ("EMAIL",))
        self.assertEqual(control.output_masks, ("MYKAD", "POSTAL_ADDRESS"))

    def test_legacy_explicit_masks_never_gain_postal_address_implicitly(self):
        legacy = ("EMAIL", "MY_PHONE", "MYKAD")
        profile = self._profile(
            "Legacy explicit masks", input_masks=legacy, output_masks=legacy
        )
        self.assertNotIn("POSTAL_ADDRESS", profile["settings"]["input_masks"])
        self.assertNotIn("POSTAL_ADDRESS", profile["settings"]["output_masks"])

        revised = self.store.revise_policy_profile(
            self.admin["id"],
            profile["id"],
            profile["revision"],
            input_masks=legacy,
            output_masks=legacy,
        )
        self.assertEqual(revised["settings"]["input_masks"], list(legacy))
        self.assertEqual(revised["settings"]["output_masks"], list(legacy))

        self.store.assign_policy_profile(
            self.admin["id"], "user", self.alice["id"], profile["id"]
        )
        control = self.store.resolve_gateway_control(self.alice["id"])
        self.assertNotIn("POSTAL_ADDRESS", control.input_masks)
        self.assertNotIn("POSTAL_ADDRESS", control.output_masks)

        # Only an unassigned default profile gets the full recognizer set.
        default = self.store.resolve_effective_policy(
            self.admin["id"], self.bob["id"]
        )
        self.assertTrue(default["is_default"])
        self.assertIn("POSTAL_ADDRESS", default["input_masks"])
        self.assertIn("POSTAL_ADDRESS", default["output_masks"])

    def test_employee_cannot_create_or_revise_a_postal_mask_profile(self):
        profile = self._profile("Admin postal", input_masks=("POSTAL_ADDRESS",))
        with self.assertRaises(AccessDenied):
            self.store.create_policy_profile(
                self.alice["id"], "Employee postal", input_masks=("POSTAL_ADDRESS",)
            )
        with self.assertRaises(AccessDenied):
            self.store.revise_policy_profile(
                self.alice["id"],
                profile["id"],
                profile["revision"],
                input_masks=(),
            )
        stored = self.store.get_policy_profile(self.admin["id"], profile["id"])
        self.assertEqual(stored["revision"], profile["revision"])
        self.assertEqual(stored["settings"]["input_masks"], ["POSTAL_ADDRESS"])


class AssignmentInheritanceTests(GovernanceTestBase):
    def test_default_workspace_department_user_relaxing_and_clear(self) -> None:
        default = self.store.resolve_effective_policy(self.admin["id"], self.alice["id"])
        self.assertTrue(default["is_default"])
        self.assertTrue(default["input_check_enabled"])
        self.assertTrue(default["output_check_enabled"])
        self.assertEqual(default["input_masks"], list(MASK_TYPES))
        self.assertEqual(default["sources"], [])
        default_control = self.store.resolve_gateway_control(
            self.alice["id"], self.alice["id"]
        )
        self.assertEqual(default_control.revision, "default")
        self.assertEqual(default_control.input_masks, MASK_TYPES)

        workspace = self._profile(
            "Workspace relaxing",
            input_check_enabled=False,
            output_check_enabled=True,
            input_masks=(),
            output_masks=("EMAIL",),
        )
        department = self._profile(
            "Department",
            input_check_enabled=True,
            output_check_enabled=False,
            input_masks=("MY_PHONE",),
            output_masks=(),
        )
        user = self._profile(
            "User relaxing",
            input_check_enabled=False,
            output_check_enabled=False,
            input_masks=(),
            output_masks=(),
        )

        ws_assignment = self.store.assign_policy_profile(
            self.admin["id"], "workspace", None, workspace["id"]
        )
        effective = self.store.resolve_effective_policy(
            self.admin["id"], self.alice["id"]
        )
        self.assertFalse(effective["is_default"])
        self.assertFalse(effective["input_check_enabled"])
        self.assertEqual(effective["input_masks"], [])
        self.assertEqual(effective["output_masks"], ["EMAIL"])
        self.assertEqual(
            [source["scope_type"] for source in effective["sources"]],
            ["workspace"],
        )

        dept_assignment = self.store.assign_policy_profile(
            self.admin["id"], "department", self.accounting["id"], department["id"]
        )
        alice_effective = self.store.resolve_effective_policy(
            self.admin["id"], self.alice["id"]
        )
        self.assertTrue(alice_effective["input_check_enabled"])
        self.assertFalse(alice_effective["output_check_enabled"])
        self.assertEqual(alice_effective["input_masks"], ["MY_PHONE"])
        self.assertEqual(
            [source["scope_type"] for source in alice_effective["sources"]],
            ["workspace", "department"],
        )
        bob_effective = self.store.resolve_effective_policy(
            self.admin["id"], self.bob["id"]
        )
        self.assertEqual(bob_effective["input_masks"], ["MY_PHONE"])
        carol_effective = self.store.resolve_effective_policy(
            self.admin["id"], self.carol["id"]
        )
        self.assertEqual(carol_effective["input_masks"], [])

        user_assignment = self.store.assign_policy_profile(
            self.admin["id"], "user", self.alice["id"], user["id"]
        )
        alice_effective = self.store.resolve_effective_policy(
            self.admin["id"], self.alice["id"]
        )
        self.assertFalse(alice_effective["input_check_enabled"])
        self.assertFalse(alice_effective["output_check_enabled"])
        self.assertEqual(alice_effective["input_masks"], [])
        self.assertEqual(
            [source["scope_type"] for source in alice_effective["sources"]],
            ["workspace", "department", "user"],
        )
        control = self.store.resolve_gateway_control(self.alice["id"])
        self.assertEqual(control.revision, alice_effective["revision"])
        self.assertFalse(control.input_check_enabled)
        self.assertFalse(control.output_check_enabled)
        self.assertEqual(control.input_masks, ())

        cleared = self.store.clear_policy_assignment(
            self.admin["id"],
            "user",
            self.alice["id"],
            expected_version=user_assignment["version"],
        )
        self.assertTrue(cleared["cleared"])
        self.assertEqual(
            self.store.resolve_effective_policy(self.admin["id"], self.alice["id"])[
                "input_masks"
            ],
            ["MY_PHONE"],
        )
        self.store.clear_policy_assignment(
            self.admin["id"], "department", self.accounting["id"]
        )
        self.assertEqual(
            self.store.resolve_effective_policy(self.admin["id"], self.alice["id"])[
                "input_masks"
            ],
            [],
        )
        self.store.clear_policy_assignment(self.admin["id"], "workspace", None)
        restored = self.store.resolve_effective_policy(self.admin["id"], self.alice["id"])
        self.assertTrue(restored["is_default"])
        self.assertEqual(restored["input_masks"], list(MASK_TYPES))
        self.assertEqual(
            self.store.clear_policy_assignment(self.admin["id"], "workspace", None),
            {"cleared": False, "scope_type": "workspace", "scope_id": "workspace"},
        )
        self.assertEqual(ws_assignment["version"], 1)
        self.assertEqual(dept_assignment["version"], 1)

    def test_assignment_get_list_optimistic_and_scope_validation(self) -> None:
        profile = self._profile("Assignable")
        assignment = self.store.assign_policy_profile(
            self.admin["id"], "user", self.alice["id"], profile["id"]
        )
        self.assertEqual(
            self.store.get_policy_assignment(
                self.admin["id"], "user", self.alice["id"]
            )["id"],
            assignment["id"],
        )
        listed = self.store.list_policy_assignments(
            self.admin["id"], scope_type="user"
        )
        self.assertEqual(len(listed["items"]), 1)
        self.assertEqual(listed["items"][0]["profile_id"], profile["id"])

        with self.assertRaises(Conflict):
            self.store.assign_policy_profile(
                self.admin["id"], "user", self.alice["id"], profile["id"]
            )
        updated = self.store.assign_policy_profile(
            self.admin["id"],
            "user",
            self.alice["id"],
            profile["id"],
            expected_version=1,
        )
        self.assertEqual(updated["version"], 2)
        with self.assertRaises(Conflict):
            self.store.assign_policy_profile(
                self.admin["id"],
                "user",
                self.alice["id"],
                profile["id"],
                expected_version=1,
            )

        for kwargs in (
            {"scope_type": "global", "scope_id": None},
            {"scope_type": "workspace", "scope_id": "other"},
            {"scope_type": "department", "scope_id": "missing-department"},
            {"scope_type": "user", "scope_id": "missing-user"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises((ValueError, NotFound)):
                    self.store.assign_policy_profile(
                        self.admin["id"],
                        kwargs["scope_type"],
                        kwargs["scope_id"],
                        profile["id"],
                    )
        with self.assertRaises(ValueError):
            self.store.assign_policy_profile(
                self.admin["id"], "user", self.alice["id"], profile["id"], profile_revision=99
            )
        with self.assertRaises(ValueError):
            self.store.clear_policy_assignment(
                self.admin["id"], "user", self.alice["id"], expected_version=-1
            )
        with self.assertRaises(ValueError):
            self.store.list_policy_assignments(self.admin["id"], scope_type="global")


class CorruptionFailClosedTests(GovernanceTestBase):
    def test_corrupt_revision_toggle_digest_or_mask_never_yields_a_control(self) -> None:
        profile = self._profile("Immutable")
        self.store.assign_policy_profile(
            self.admin["id"], "workspace", None, profile["id"]
        )
        original = self._rows(
            "SELECT input_check_enabled, output_check_enabled, input_masks, "
            "output_masks, digest FROM ws_policy_profile_revisions "
            "WHERE profile_id = ?",
            (profile["id"],),
        )[0]
        self.assertTrue(original["input_check_enabled"])

        corruptions = (
            ("UPDATE ws_policy_profile_revisions SET input_check_enabled = 2 "
             "WHERE profile_id = ?", (profile["id"],)),
            ("UPDATE ws_policy_profile_revisions SET output_check_enabled = -1 "
             "WHERE profile_id = ?", (profile["id"],)),
            ("UPDATE ws_policy_profile_revisions SET digest = ? WHERE profile_id = ?",
             ("0" * 64, profile["id"])),
            ("UPDATE ws_policy_profile_revisions SET input_masks = 'EMAIL,UNKNOWN' "
             "WHERE profile_id = ?", (profile["id"],)),
            ("UPDATE ws_policy_profile_revisions SET output_masks = 'MY_PHONE,EMAIL' "
             "WHERE profile_id = ?", (profile["id"],)),
        )
        for sql, params in corruptions:
            with self.subTest(sql=sql):
                self._exec(sql, params)
                with self.assertRaises(WorkspaceStorageError):
                    self.store.resolve_effective_policy(
                        self.admin["id"], self.alice["id"]
                    )
                with self.assertRaises(WorkspaceStorageError):
                    self.store.resolve_gateway_control(self.alice["id"])
                with self.assertRaises(WorkspaceStorageError):
                    self.store.get_policy_profile(self.admin["id"], profile["id"])
                self._exec(
                    "UPDATE ws_policy_profile_revisions SET "
                    "input_check_enabled = ?, output_check_enabled = ?, "
                    "input_masks = ?, output_masks = ?, digest = ? "
                    "WHERE profile_id = ?",
                    (
                        original["input_check_enabled"],
                        original["output_check_enabled"],
                        original["input_masks"],
                        original["output_masks"],
                        original["digest"],
                        profile["id"],
                    ),
                )
        effective = self.store.resolve_effective_policy(
            self.admin["id"], self.alice["id"]
        )
        self.assertTrue(effective["input_check_enabled"])

    def test_corrupt_inherited_source_blocks_a_specific_override(self) -> None:
        workspace = self._profile("Workspace source")
        user = self._profile("User override", input_masks=())
        self.store.assign_policy_profile(
            self.admin["id"], "workspace", None, workspace["id"]
        )
        self.store.assign_policy_profile(
            self.admin["id"], "user", self.alice["id"], user["id"]
        )
        self.assertEqual(
            self.store.resolve_effective_policy(self.admin["id"], self.alice["id"])[
                "input_masks"
            ],
            [],
        )
        self._exec(
            "UPDATE ws_policy_profile_revisions SET input_check_enabled = 2 "
            "WHERE profile_id = ?",
            (workspace["id"],),
        )
        with self.assertRaises(WorkspaceStorageError):
            self.store.resolve_effective_policy(self.admin["id"], self.alice["id"])


class MigrationTests(GovernanceTestBase):
    def test_v2_to_v3_preserves_encrypted_conversation_and_reopen_is_idempotent(self) -> None:
        v2_path = Path(self._tmp.name) / "legacy-v2.db"
        now = self.clock.value
        cipher = _Cipher(self.key)
        department_id = "11111111-1111-4111-8111-111111111111"
        user_id = "22222222-2222-4222-8222-222222222222"
        conversation_id = "33333333-3333-4333-8333-333333333333"
        user_message = "44444444-4444-4444-8444-444444444444"
        assistant_message = "55555555-5555-4555-8555-555555555555"
        conn = sqlite3.connect(v2_path)
        try:
            v3 = set(_schema_v3_statements())
            for statement in _schema_statements():
                if statement not in v3:
                    conn.execute(statement)
            conn.execute(
                "INSERT INTO ws_schema_migrations(version, applied_at) VALUES (2, ?)",
                (now,),
            )
            conn.execute(
                "INSERT INTO ws_meta(key, value) VALUES ('key_verifier', ?)",
                (cipher.make_verifier(),),
            )
            conn.execute(
                "INSERT INTO ws_departments(id, name, name_key, created_at) "
                "VALUES (?, 'Legacy', 'legacy', ?)",
                (department_id, now),
            )
            conn.execute(
                "INSERT INTO ws_users(id, username, full_name, department_id, "
                "role, password_hash, disabled, created_at) "
                "VALUES (?, 'legacy.owner', 'Legacy Owner', ?, 'employee', ?, 0, ?)",
                (user_id, department_id, _hash_password(GOOD_PASSWORD), now),
            )
            conn.execute(
                "INSERT INTO ws_conversations(id, owner_id, department_id, title, "
                "status, lease_hash, lease_expires_at, version, created_at, updated_at) "
                "VALUES (?, ?, ?, 'Legacy chat', 'idle', NULL, NULL, 1, ?, ?)",
                (conversation_id, user_id, department_id, now, now),
            )
            conn.execute(
                "INSERT INTO ws_messages(id, conversation_id, role, position, "
                "ciphertext, outcome, request_id, error_code, created_at) "
                "VALUES (?, ?, 'user', 1, ?, 'allowed', NULL, NULL, ?)",
                (
                    user_message,
                    conversation_id,
                    cipher.encrypt(conversation_id, user_message, "user", "legacy prompt"),
                    now,
                ),
            )
            conn.execute(
                "INSERT INTO ws_messages(id, conversation_id, role, position, "
                "ciphertext, outcome, request_id, error_code, created_at) "
                "VALUES (?, ?, 'assistant', 2, ?, 'allowed', NULL, NULL, ?)",
                (
                    assistant_message,
                    conversation_id,
                    cipher.encrypt(
                        conversation_id, assistant_message, "assistant", "legacy reply"
                    ),
                    now,
                ),
            )
            conn.commit()
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        finally:
            conn.close()
        self.assertNotIn("ws_policy_profiles", tables)

        migrated = WorkspaceStore(
            str(v2_path),
            encryption_key=self.key,
            clock=self.clock,
            migrate=True,
        )
        self.assertTrue(migrated.ready())
        read = migrated.read_conversation(
            user_id, conversation_id
        )["messages"]
        self.assertEqual([item["text"] for item in read], ["legacy prompt", "legacy reply"])
        rows = self._migration_rows(v2_path)
        self.assertEqual(rows, [{"version": SCHEMA_VERSION}])

        tables = {
            row["name"]
            for row in self._raw_rows(
                v2_path, "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        for name in (
            "ws_policy_profiles",
            "ws_policy_profile_revisions",
            "ws_policy_assignments",
            "ws_policy_audit",
            "ws_block_alerts",
            "ws_alert_state",
        ):
            self.assertIn(name, tables)

        reopened = WorkspaceStore(
            str(v2_path),
            encryption_key=self.key,
            clock=self.clock,
            migrate=False,
        )
        self.assertEqual(
            reopened.read_conversation(user_id, conversation_id)["messages"][0][
                "text"
            ],
            "legacy prompt",
        )
        idempotent = WorkspaceStore(
            str(v2_path),
            encryption_key=self.key,
            clock=self.clock,
            migrate=True,
        )
        self.assertTrue(idempotent.ready())
        self.assertEqual(self._migration_rows(v2_path), [{"version": SCHEMA_VERSION}])
        self.assertEqual(
            self._raw_rows(
                v2_path,
                "SELECT COUNT(*) AS count FROM ws_messages WHERE conversation_id = ?",
                (conversation_id,),
            ),
            [{"count": 2}],
        )

    @staticmethod
    def _migration_rows(path: Path) -> list[dict]:
        return MigrationTests._raw_rows(
            path, "SELECT version FROM ws_schema_migrations"
        )

    @staticmethod
    def _raw_rows(path: Path, sql: str, params: tuple = ()) -> list[dict]:
        conn = sqlite3.connect(path)
        try:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(sql, params)]
        finally:
            conn.close()


class RoleGrantTests(unittest.TestCase):
    def test_new_tables_have_exact_least_privileges(self) -> None:
        root = Path(__file__).resolve().parents[1]
        text = (root / "nasi_lemak" / "workspace_roles.sql").read_text(
            encoding="utf-8"
        )
        expected = {
            "ws_policy_profiles": "GRANT SELECT, INSERT, UPDATE ON TABLE public.ws_policy_profiles",
            "ws_policy_profile_revisions": "GRANT SELECT, INSERT ON TABLE public.ws_policy_profile_revisions",
            "ws_policy_assignments": "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.ws_policy_assignments",
            "ws_policy_audit": "GRANT SELECT, INSERT ON TABLE public.ws_policy_audit",
            "ws_block_alerts": "GRANT SELECT, INSERT ON TABLE public.ws_block_alerts",
            "ws_alert_state": "GRANT SELECT, INSERT, UPDATE ON TABLE public.ws_alert_state",
        }
        for table, grant in expected.items():
            with self.subTest(table=table):
                self.assertIn(grant, text)
                self.assertIn(f"public.{table}", text)
        for invariant in (
            "ws_policy_profile_revisions",
            "ws_policy_audit",
            "ws_block_alerts",
        ):
            with self.subTest(invariant=invariant):
                self.assertNotRegex(
                    text,
                    rf"GRANT[^;]*(UPDATE|DELETE)[^;]*public\.{invariant}",
                )


class BlockAlertTests(GovernanceTestBase):
    def test_blocked_turn_and_alert_persist_together_as_metadata_only(self) -> None:
        conversation, blocked = self._blocked_turn(self.alice, "req_alert_metadata")
        self.assertIsNotNone(blocked["alert_id"])
        message = self._rows(
            "SELECT outcome, request_id FROM ws_messages WHERE conversation_id = ?",
            (conversation["id"],),
        )
        self.assertEqual(message, [{"outcome": "blocked", "request_id": "req_alert_metadata"}])
        alert = self.store.get_block_alert(self.admin["id"], blocked["alert_id"])
        self.assertEqual(alert["stage"], "input")
        self.assertEqual(alert["reason_code"], "INPUT_GUARD_BLOCK")
        self.assertEqual(alert["reason_text"], "The prompt did not pass the input safety check.")
        self.assertEqual(alert["control_sources"], [])
        self.assertFalse(alert["read"])
        self.assertFalse(alert["acknowledged"])
        encoded = json.dumps(alert)
        for forbidden in ("response", "ciphertext", "classifier"):
            self.assertNotIn(forbidden, encoded.lower())
        self.assertNotIn(CANARY, encoded)
        self.assertNotIn(CANARY.encode(), self._raw_bytes())
        alert_row = self._rows(
            "SELECT * FROM ws_block_alerts WHERE id = ?", (blocked["alert_id"],)
        )[0]
        self.assertNotIn(CANARY, json.dumps(alert_row))
        self.assertNotIn("prompt", alert_row)
        self.assertNotIn("response", alert_row)

    def test_invalid_alert_metadata_and_rollback_are_atomic(self) -> None:
        conversation = self.store.create_conversation(self.alice["id"])
        lease = self.store.reserve_turn(self.alice["id"], conversation["id"])
        bad_alerts = (
            {
                "stage": "input",
                "reason_code": "OUTPUT_GUARD_BLOCK",
                "revision": "default",
                "digest": "a" * 64,
                "sources": [],
            },
            {
                "stage": "input",
                "reason_code": "INPUT_GUARD_BLOCK",
                "revision": "default",
                "digest": "not-a-digest",
                "sources": [],
            },
            {
                "stage": "input",
                "reason_code": "INPUT_GUARD_BLOCK",
                "revision": "default",
                "digest": "a" * 64,
                "sources": [],
                "prompt": CANARY,
            },
        )
        for alert in bad_alerts:
            with self.subTest(alert=alert):
                with self.assertRaises(ValueError):
                    self.store.record_failed_turn(
                        self.alice["id"],
                        conversation["id"],
                        lease["token"],
                        user_prompt=CANARY,
                        outcome="blocked",
                        request_id="req_invalid_alert",
                        alert=alert,
                    )
                self.assertEqual(self._rows("SELECT * FROM ws_messages"), [])
                self.assertEqual(self._rows("SELECT * FROM ws_block_alerts"), [])
                self.assertEqual(
                    self._rows("SELECT status FROM ws_conversations")[0]["status"],
                    "pending",
                )

        valid = self._control_alert(self.alice)
        valid["request_id"] = "req_rollback_alert"
        with mock.patch.object(
            self.store,
            "_insert_block_alert",
            side_effect=WorkspaceStorageError("injected alert failure"),
        ):
            with self.assertRaises(WorkspaceStorageError):
                self.store.record_failed_turn(
                    self.alice["id"],
                    conversation["id"],
                    lease["token"],
                    user_prompt=CANARY,
                    outcome="blocked",
                    request_id="req_rollback_alert",
                    alert={key: valid[key] for key in (
                        "stage", "reason_code", "revision", "digest", "sources"
                    )},
                )
        self.assertEqual(self._rows("SELECT * FROM ws_messages"), [])
        self.assertEqual(self._rows("SELECT * FROM ws_block_alerts"), [])
        self.assertEqual(
            self._rows("SELECT status FROM ws_conversations")[0]["status"],
            "pending",
        )

    def test_alert_filters_and_pagination(self) -> None:
        _c1, first = self._blocked_turn(self.alice, "req_filter_1")
        _c2, second = self._blocked_turn(
            self.bob,
            "req_filter_2",
            stage="output",
            reason_code="OUTPUT_GUARD_BLOCK",
        )
        _c3, third = self._blocked_turn(
            self.carol,
            "req_filter_3",
            stage="input",
            reason_code="INPUT_POLICY_BLOCK",
        )
        _c4, fourth = self._blocked_turn(self.alice, "req_filter_4")

        def items(**kwargs):
            return self.store.list_block_alerts(self.admin["id"], **kwargs)["items"]

        self.assertEqual(len(items()), 4)
        self.assertEqual(
            {item["id"] for item in items(stage="input")},
            {fourth["alert_id"], third["alert_id"], first["alert_id"]},
        )
        self.assertEqual([item["id"] for item in items(stage="output")], [second["alert_id"]])
        self.assertEqual(
            {item["id"] for item in items(reason_code="INPUT_GUARD_BLOCK")},
            {fourth["alert_id"], first["alert_id"]},
        )
        self.assertEqual(
            [item["id"] for item in items(user_id=self.bob["id"])],
            [second["alert_id"]],
        )
        self.assertEqual(
            [item["id"] for item in items(department_id=self.hr["id"])],
            [third["alert_id"]],
        )
        self.assertEqual(len(items(unread=True)), 4)
        self.assertEqual(len(items(acknowledged=False)), 4)
        self.store.mark_block_alert_read(self.admin["id"], first["alert_id"])
        self.assertEqual(
            {item["id"] for item in items(unread=True)},
            {fourth["alert_id"], third["alert_id"], second["alert_id"]},
        )
        self.assertEqual([item["id"] for item in items(unread=False)], [first["alert_id"]])

        page = self.store.list_block_alerts(self.admin["id"], limit=2)
        self.assertEqual(len(page["items"]), 2)
        self.assertIsNotNone(page["next"])
        second_page = self.store.list_block_alerts(
            self.admin["id"], limit=2, after=page["next"]
        )
        self.assertEqual(len(second_page["items"]), 2)
        self.assertIsNone(second_page["next"])
        with self.assertRaises(ValueError):
            self.store.list_block_alerts(self.admin["id"], stage="middle")
        with self.assertRaises(ValueError):
            self.store.list_block_alerts(self.admin["id"], unread=True, acknowledged=True)

    def test_per_admin_read_ack_is_scoped_and_idempotent(self) -> None:
        _c1, first = self._blocked_turn(self.alice, "req_state_1")
        _c2, second = self._blocked_turn(self.alice, "req_state_2")
        admin_one, admin_two = self.admin["id"], self.second_admin["id"]

        self.assertEqual(
            self.store.alert_summary(admin_one),
            {
                "total": 2,
                "unread": 2,
                "acknowledged": 0,
                "input": 2,
                "output": 0,
                "oldest_unread_at": 1_700_000_000.0,
            },
        )
        self.assertEqual(
            self.store.alert_summary(admin_two),
            {
                "total": 2,
                "unread": 2,
                "acknowledged": 0,
                "input": 2,
                "output": 0,
                "oldest_unread_at": 1_700_000_000.0,
            },
        )

        read_one = self.store.mark_block_alert_read(admin_one, first["alert_id"])
        self.assertTrue(read_one["read"])
        self.assertIsNotNone(read_one["read_at"])
        self.assertEqual(self.store.alert_summary(admin_one)["unread"], 1)
        self.assertEqual(self.store.alert_summary(admin_two)["unread"], 2)
        self.assertTrue(
            self.store.get_block_alert(admin_one, first["alert_id"])["read"]
        )
        self.assertFalse(
            self.store.get_block_alert(admin_two, first["alert_id"])["read"]
        )
        repeated_read = self.store.mark_block_alert_read(admin_one, first["alert_id"])
        self.assertEqual(repeated_read["read_at"], read_one["read_at"])

        self.store.mark_block_alert_read(admin_two, first["alert_id"])
        self.assertEqual(self.store.alert_summary(admin_two)["unread"], 1)

        acked = self.store.acknowledge_block_alert(admin_one, first["alert_id"])
        self.assertTrue(acked["acknowledged"])
        self.assertEqual(acked["read_at"], read_one["read_at"])
        repeated_ack = self.store.acknowledge_block_alert(admin_one, first["alert_id"])
        self.assertEqual(
            (repeated_ack["read_at"], repeated_ack["acknowledged_at"]),
            (acked["read_at"], acked["acknowledged_at"]),
        )
        self.assertEqual(
            self.store.alert_summary(admin_one),
            {
                "total": 2,
                "unread": 1,
                "acknowledged": 1,
                "input": 2,
                "output": 0,
                "oldest_unread_at": 1_700_000_000.0,
            },
        )
        self.assertEqual(self.store.alert_summary(admin_two)["acknowledged"], 0)

        unread_ack = self.store.acknowledge_block_alert(admin_one, second["alert_id"])
        self.assertTrue(unread_ack["read"])
        self.assertTrue(unread_ack["acknowledged"])
        self.assertEqual(
            self.store.alert_summary(admin_one),
            {
                "total": 2,
                "unread": 0,
                "acknowledged": 2,
                "input": 2,
                "output": 0,
                "oldest_unread_at": None,
            },
        )

        for call in (
            lambda: self.store.get_block_alert(admin_one, "missing-alert"),
            lambda: self.store.mark_block_alert_read(admin_one, "missing-alert"),
            lambda: self.store.acknowledge_block_alert(admin_one, "missing-alert"),
        ):
            with self.assertRaises(NotFound):
                call()
        with self.assertRaises(ValueError):
            self.store.get_block_alert(admin_one, "bad alert id")

    def test_alert_summary_counts_stages_and_tracks_oldest_unread(self) -> None:
        alert_ids: list[str] = []
        created: list[float] = []
        for index in range(12):
            self.clock.value = 1_700_000_000.0 + index
            stage = "output" if index % 3 == 0 else "input"
            reason_code = (
                "OUTPUT_GUARD_BLOCK" if stage == "output" else "INPUT_GUARD_BLOCK"
            )
            _conversation, blocked = self._blocked_turn(
                self.alice,
                f"req_summary_{index}",
                stage=stage,
                reason_code=reason_code,
            )
            alert_ids.append(blocked["alert_id"])
            created.append(self.clock.value)

        admin_one = self.admin["id"]
        summary = self.store.alert_summary(admin_one)
        self.assertEqual(
            summary,
            {
                "total": 12,
                "unread": 12,
                "acknowledged": 0,
                "input": 8,
                "output": 4,
                "oldest_unread_at": created[0],
            },
        )

        self.store.acknowledge_block_alert(admin_one, alert_ids[0])
        summary = self.store.alert_summary(admin_one)
        self.assertEqual((summary["unread"], summary["acknowledged"]), (11, 1))
        self.assertEqual(summary["oldest_unread_at"], created[1])

        self.store.mark_block_alert_read(admin_one, alert_ids[1])
        summary = self.store.alert_summary(admin_one)
        self.assertEqual((summary["unread"], summary["acknowledged"]), (10, 1))
        self.assertEqual((summary["input"], summary["output"]), (8, 4))
        self.assertEqual(summary["oldest_unread_at"], created[2])

        other = self.store.alert_summary(self.second_admin["id"])
        self.assertEqual(
            (other["unread"], other["oldest_unread_at"]), (12, created[0])
        )

    def test_mark_all_alerts_read_marks_only_the_admin_and_preserves_state(
        self,
    ) -> None:
        alert_ids: list[str] = []
        for index in range(12):
            self.clock.value = 1_700_000_000.0 + index
            _conversation, blocked = self._blocked_turn(
                self.alice, f"req_mark_all_{index}"
            )
            alert_ids.append(blocked["alert_id"])
        admin_one, admin_two = self.admin["id"], self.second_admin["id"]

        # Pre-existing per-administrator state must survive the bulk mark.
        self.clock.value = 1_700_000_100.0
        acked = self.store.acknowledge_block_alert(admin_one, alert_ids[0])
        self.clock.value = 1_700_000_101.0
        read_only = self.store.mark_block_alert_read(admin_one, alert_ids[1])

        self.clock.value = 1_700_000_200.0
        marked = self.store.mark_all_block_alerts_read(admin_one)
        self.assertEqual(
            marked, {"status": "ok", "marked_read": 10, "total": 12}
        )
        summary = self.store.alert_summary(admin_one)
        self.assertEqual(
            (summary["total"], summary["unread"], summary["acknowledged"]),
            (12, 0, 1),
        )
        preserved_ack = self.store.get_block_alert(admin_one, alert_ids[0])
        self.assertEqual(preserved_ack["read_at"], acked["read_at"])
        self.assertEqual(
            preserved_ack["acknowledged_at"], acked["acknowledged_at"]
        )
        preserved_read = self.store.get_block_alert(admin_one, alert_ids[1])
        self.assertEqual(preserved_read["read_at"], read_only["read_at"])
        self.assertFalse(preserved_read["acknowledged"])
        self.assertEqual(
            self.store.get_block_alert(admin_one, alert_ids[2])["read_at"],
            1_700_000_200.0,
        )

        # Repeating the bulk mark is a no-op and keeps the earlier timestamps.
        self.clock.value = 1_700_000_300.0
        repeated = self.store.mark_all_block_alerts_read(admin_one)
        self.assertEqual(
            repeated, {"status": "ok", "marked_read": 0, "total": 12}
        )
        self.assertEqual(
            self.store.get_block_alert(admin_one, alert_ids[2])["read_at"],
            1_700_000_200.0,
        )

        # The second administrator's state is untouched.
        other = self.store.alert_summary(admin_two)
        self.assertEqual(
            (other["total"], other["unread"], other["acknowledged"]),
            (12, 12, 0),
        )
        self.assertFalse(self.store.get_block_alert(admin_two, alert_ids[0])["read"])
        with self.assertRaises(AccessDenied):
            self.store.mark_all_block_alerts_read(self.alice["id"])
        self.assertEqual(self.store.alert_summary(admin_two)["unread"], 12)

    def test_request_id_makes_alert_persistence_idempotent(self) -> None:
        first_conversation, first = self._blocked_turn(self.alice, "req_same_turn")
        second_conversation, second = self._blocked_turn(self.alice, "req_same_turn")
        self.assertNotEqual(first_conversation["id"], second_conversation["id"])
        self.assertEqual(first["alert_id"], second["alert_id"])
        self.assertEqual(
            len(self.store.list_block_alerts(self.admin["id"])["items"]), 1
        )
        self.assertEqual(
            self._rows("SELECT COUNT(*) AS count FROM ws_messages")[0]["count"], 2
        )
        self.assertEqual(
            self._rows("SELECT COUNT(*) AS count FROM ws_block_alerts")[0]["count"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
