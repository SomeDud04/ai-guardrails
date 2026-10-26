"""Workspace store tests: accounts, sessions, saved conversations and review.

These are synthetic local tests. SQLite exercises real persistence and
transactions; a PostgreSQL round-trip only runs when the operator supplies a
dedicated ``TEST_WORKSPACE_DSN``. No live guard API or VM is contacted.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import unittest
import uuid
from pathlib import Path

from cryptography.fernet import Fernet

from nasi_lemak.workspace_store import (
    AccessDenied,
    AuthError,
    Conflict,
    ContentError,
    NotFound,
    WorkspaceConfigError,
    WorkspaceError,
    WorkspaceStorageError,
    WorkspaceStore,
)

GOOD_PASSWORD = "correct-horse-battery-staple"
OTHER_PASSWORD = "second-long-password-456"
CANARY = "CANARY-workspace-original-prompt-7f3c"
REPLY = "assistant reply CANARY-response-91ab"


class FakeClock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class WorkspaceStoreTest(unittest.TestCase):
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
        self.assertIsNotNone(self.admin)
        self.accounting = self.store.create_department(self.admin["id"], "Accounting")
        self.hr = self.store.create_department(self.admin["id"], "Human Resources")
        self.alice = self._user("alice", "Alice Tan", self.accounting["id"])
        self.bob = self._user("bob", "Bob Lim", self.accounting["id"])
        self.carol = self._user("carol", "Carol Ng", self.hr["id"])

    # -- helpers ---------------------------------------------------------
    def _open(self, key: str | None = None, clock: FakeClock | None = None) -> WorkspaceStore:
        return WorkspaceStore(
            self.path,
            encryption_key=self.key if key is None else key,
            clock=self.clock if clock is None else clock,
            connect_timeout=5.0,
        )

    def _user(self, username: str, full_name: str, department_id: str, role: str = "employee"):
        return self.store.create_user(
            self.admin["id"], username, GOOD_PASSWORD, full_name, department_id, role
        )

    def _conversation(self, owner=None, prompt: str = CANARY, response: str = REPLY):
        owner = owner or self.alice
        conv = self.store.create_conversation(owner["id"])
        lease = self.store.reserve_turn(owner["id"], conv["id"])
        self.store.append_exchange(
            owner["id"],
            conv["id"],
            lease["token"],
            user_prompt=prompt,
            assistant_response=response,
        )
        return conv

    def _rows(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = sqlite3.connect(self.path)
        try:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute(sql, params)]
        finally:
            conn.close()

    def _raw_bytes(self) -> bytes:
        with open(self.path, "rb") as handle:
            return handle.read()

    def _exec(self, sql: str, params: tuple = ()) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("PRAGMA ignore_check_constraints = ON")
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def test_read_context_rejects_corrupt_allowed_metadata(self) -> None:
        conv = self._conversation()
        owner, cid = self.alice["id"], conv["id"]
        self._exec(
            "UPDATE ws_messages SET role = 'assistant' "
            "WHERE conversation_id = ? AND position = 1",
            (cid,),
        )
        with self.assertRaises(ContentError):
            self.store.read_context(owner, cid)
        self._exec(
            "UPDATE ws_messages SET role = 'user', outcome = 'mystery' "
            "WHERE conversation_id = ? AND position = 1",
            (cid,),
        )
        with self.assertRaises(ContentError):
            self.store.read_context(owner, cid)
        self._exec(
            "UPDATE ws_messages SET outcome = 'failed' "
            "WHERE conversation_id = ? AND position = 2",
            (cid,),
        )
        with self.assertRaises(ContentError):
            self.store.read_context(owner, cid)
        self._exec(
            "DELETE FROM ws_messages WHERE conversation_id = ? AND position = 2",
            (cid,),
        )
        with self.assertRaises(ContentError):
            self.store.read_context(owner, cid)

    def test_read_context_skips_blocked_user_between_allowed_pairs(self) -> None:
        conv = self._conversation(prompt="first prompt", response="first reply")
        owner, cid = self.alice["id"], conv["id"]
        lease = self.store.reserve_turn(owner, cid)
        self.store.record_failed_turn(
            owner,
            cid,
            lease["token"],
            user_prompt="blocked middle",
            outcome="blocked",
            error_code="POLICY_BLOCK",
        )
        lease = self.store.reserve_turn(owner, cid)
        self.store.append_exchange(
            owner,
            cid,
            lease["token"],
            user_prompt="second prompt",
            assistant_response="second reply",
        )
        context = self.store.read_context(owner, cid)
        self.assertEqual(
            [item["content"] for item in context["messages"]],
            ["first prompt", "first reply", "second prompt", "second reply"],
        )
        history = self.store.read_conversation(owner, cid)["messages"]
        blocked = [item for item in history if item["outcome"] == "blocked"]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["text"], "blocked middle")

    # -- bootstrap and accounts -----------------------------------------
    def test_bootstrap_is_idempotent_and_has_no_default_accounts(self) -> None:
        self.assertIsNone(
            self.store.bootstrap_admin(
                username="second.admin",
                password=GOOD_PASSWORD,
                full_name="Second Admin",
                department_name="IT",
            )
        )
        for username, password in (("admin", "admin"), ("root.admin", "password1234")):
            with self.assertRaises(AuthError):
                self.store.authenticate(username, password)

    def test_notifications_of_bad_credentials_are_generic(self) -> None:
        self.store.disable_user(self.admin["id"], self.carol["id"])
        failures = []
        for username, password in (
            ("nobody", GOOD_PASSWORD),
            ("alice", "wrong-password-123"),
            ("carol", GOOD_PASSWORD),
            ("ALICE", "wrong-password-123"),
        ):
            with self.assertRaises(AuthError) as caught:
                self.store.authenticate(username, password)
            failures.append(str(caught.exception))
        self.assertEqual(len(set(failures)), 1)
        self.assertNotIn(GOOD_PASSWORD, failures[0])

    def test_password_and_name_bounds(self) -> None:
        for password in ("short", "x" * 129):
            with self.assertRaises(ValueError):
                self.store.create_user(
                    self.admin["id"],
                    "bounded",
                    password,
                    "Bounded User",
                    self.accounting["id"],
                )
        with self.assertRaises(ValueError):
            self.store.create_user(
                self.admin["id"], "bounded", GOOD_PASSWORD, "x" * 200, self.accounting["id"]
            )
        with self.assertRaises(WorkspaceError):
            self.store.create_user(
                self.admin["id"], "bounded", GOOD_PASSWORD, "Name", "missing-department"
            )
        with self.assertRaises(ValueError):
            self.store.create_user(
                self.admin["id"], "bounded", GOOD_PASSWORD, "Name", self.accounting["id"], "owner"
            )

    def test_username_is_normalised_and_unique(self) -> None:
        with self.assertRaises(Conflict):
            self.store.create_user(
                self.admin["id"], "  ALICE  ", GOOD_PASSWORD, "Duplicate", self.accounting["id"]
            )
        with self.assertRaises(Conflict):
            self.store.create_department(self.admin["id"], "accounting")
        users = self.store.list_users(self.admin["id"], limit=50)["items"]
        usernames = {user["username"] for user in users}
        self.assertIn("alice", usernames)
        self.assertNotIn("ALICE", usernames)

    def test_password_hash_and_plaintext_never_stored(self) -> None:
        users = self._rows("SELECT username, password_hash FROM ws_users")
        for row in users:
            self.assertNotIn(GOOD_PASSWORD, row["password_hash"])
            self.assertTrue(row["password_hash"].startswith("scrypt$"))
        self.assertNotIn(GOOD_PASSWORD.encode(), self._raw_bytes())

    def test_session_can_be_resolved_after_restart_and_is_revoked(self) -> None:
        auth = self.store.authenticate("alice", GOOD_PASSWORD)
        self.assertNotIn(auth["token"].encode(), self._raw_bytes())
        reopened = self._open()
        self.assertEqual(reopened.resolve_session(auth["token"])["id"], self.alice["id"])
        reopened.logout(auth["token"])
        with self.assertRaises(AuthError):
            reopened.resolve_session(auth["token"])
        with self.assertRaises(AuthError):
            self.store.resolve_session(auth["token"])

    def test_session_expiry_and_account_disable_invalidate(self) -> None:
        auth = self.store.authenticate("bob", GOOD_PASSWORD)
        self.clock.advance(8 * 3600 + 1)
        with self.assertRaises(AuthError):
            self.store.resolve_session(auth["token"])

        fresh = self.store.authenticate("bob", GOOD_PASSWORD)
        self.store.disable_user(self.admin["id"], self.bob["id"])
        with self.assertRaises(AuthError):
            self.store.resolve_session(fresh["token"])
        with self.assertRaises(AuthError):
            self.store.authenticate("bob", GOOD_PASSWORD)

    # -- conversations and encryption ------------------------------------
    def test_original_text_survives_restart_but_not_plaintext_on_disk(self) -> None:
        conv = self._conversation()
        reopened = self._open()
        read = reopened.read_conversation(self.alice["id"], conv["id"])
        self.assertEqual([m["role"] for m in read["messages"]], ["user", "assistant"])
        self.assertEqual(read["messages"][0]["text"], CANARY)
        self.assertEqual(read["messages"][1]["text"], REPLY)
        self.assertNotEqual(read["title"], CANARY)
        raw = self._raw_bytes()
        self.assertNotIn(CANARY.encode(), raw)
        self.assertNotIn(REPLY.encode(), raw)
        self.assertNotIn(self.key.encode(), raw)

    def test_original_whitespace_survives_restart_and_review(self) -> None:
        prompt = "  leading spaces\n\nline with trailing tab\t\n"
        response = "\n\tassistant reply\nwith trailing newlines\n\n"
        conv = self.store.create_conversation(self.alice["id"])
        lease = self.store.reserve_turn(self.alice["id"], conv["id"])
        self.store.append_exchange(
            self.alice["id"],
            conv["id"],
            lease["token"],
            user_prompt=prompt,
            assistant_response=response,
        )
        reviewer = self._user("rita", "Rita Reviewer", self.hr["id"])
        self.store.grant_review(
            self.admin["id"], reviewer["id"], "department", self.accounting["id"]
        )
        reopened = self._open()
        for actor in (self.alice["id"], reviewer["id"]):
            read = reopened.read_conversation(actor, conv["id"])
            self.assertEqual(read["messages"][0]["text"], prompt)
            self.assertEqual(read["messages"][1]["text"], response)

    def test_wrong_key_and_tampering_fail_closed(self) -> None:
        conv = self._conversation()
        before = self._rows(
            "SELECT id, ciphertext FROM ws_messages WHERE conversation_id = ? "
            "ORDER BY position",
            (conv["id"],),
        )
        verifier = self._rows("SELECT value FROM ws_meta WHERE key = 'key_verifier'")
        self.assertEqual(len(verifier), 1)
        self.assertNotIn(self.key, verifier[0]["value"])
        with self.assertRaises(WorkspaceConfigError) as wrong_key:
            self._open(key=Fernet.generate_key().decode("ascii"))
        self.assertNotIn(CANARY, str(wrong_key.exception))
        self.assertEqual(
            self._rows(
                "SELECT id, ciphertext FROM ws_messages WHERE conversation_id = ? "
                "ORDER BY position",
                (conv["id"],),
            ),
            before,
        )
        # The correct key still opens the same database: no reset fallback.
        self.assertEqual(
            self._open().read_conversation(self.alice["id"], conv["id"])["messages"][0]["text"],
            CANARY,
        )

        messages = self._rows(
            "SELECT id, ciphertext FROM ws_messages WHERE conversation_id = ?", (conv["id"],)
        )
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "UPDATE ws_messages SET ciphertext = ? WHERE id = ?",
                (messages[1]["ciphertext"], messages[0]["id"]),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(WorkspaceError) as tampered:
            self.store.read_conversation(self.alice["id"], conv["id"])
        self.assertNotIn(CANARY, str(tampered.exception))

    def test_custom_titles_are_rejected_and_cannot_leak(self) -> None:
        with self.assertRaises(ValueError):
            self.store.create_conversation(self.alice["id"], CANARY)
        conv = self.store.create_conversation(self.alice["id"])
        self.assertEqual(conv["title"], "Untitled conversation")
        self.assertNotIn(CANARY.encode(), self._raw_bytes())

    def test_message_bounds_and_failed_append_rolls_back(self) -> None:
        conv = self.store.create_conversation(self.alice["id"])
        self.assertNotIn("CANARY", conv["title"])
        lease = self.store.reserve_turn(self.alice["id"], conv["id"])
        with self.assertRaises(ValueError):
            self.store.append_exchange(
                self.alice["id"],
                conv["id"],
                lease["token"],
                user_prompt="x" * 65537,
                assistant_response=REPLY,
            )
        self.assertEqual(
            self._rows("SELECT id FROM ws_messages WHERE conversation_id = ?", (conv["id"],)), []
        )
        for blank_prompt, blank_response in (("   \n\t ", REPLY), (CANARY, " \n ")):
            with self.assertRaises(ValueError):
                self.store.append_exchange(
                    self.alice["id"],
                    conv["id"],
                    lease["token"],
                    user_prompt=blank_prompt,
                    assistant_response=blank_response,
                )
        self.assertEqual(self._rows("SELECT status FROM ws_conversations")[0]["status"], "pending")

    def test_pagination_is_bounded_and_keyset(self) -> None:
        for _ in range(3):
            self.store.create_conversation(self.alice["id"])
        first = self.store.list_conversations(self.alice["id"], limit=2)
        self.assertEqual(len(first["items"]), 2)
        self.assertIsNotNone(first["next"])
        second = self.store.list_conversations(self.alice["id"], limit=2, after=first["next"])
        self.assertEqual(len(second["items"]), 1)
        self.assertIsNone(second["next"])
        for limit in (0, 101):
            with self.assertRaises(ValueError):
                self.store.list_conversations(self.alice["id"], limit=limit)

    # -- authorization and review ---------------------------------------
    def test_non_owner_read_list_delete_is_denied_without_audit(self) -> None:
        conv = self._conversation()
        with self.assertRaises(AccessDenied):
            self.store.read_conversation(self.bob["id"], conv["id"])
        with self.assertRaises(AccessDenied):
            self.store.delete_conversation(self.bob["id"], conv["id"])
        own = self.store.list_conversations(self.bob["id"])["items"]
        self.assertEqual(own, [])
        self.assertEqual(self._rows("SELECT * FROM ws_access_log"), [])
        self.assertIsNotNone(self.store.read_conversation(self.alice["id"], conv["id"]))

    def test_unknown_conversation_is_not_found(self) -> None:
        with self.assertRaises(NotFound):
            self.store.read_conversation(self.alice["id"], "00000000-0000-0000-0000-000000000000")

    def test_admin_without_grant_cannot_read_other_users(self) -> None:
        conv = self._conversation()
        with self.assertRaises(AccessDenied):
            self.store.read_conversation(self.admin["id"], conv["id"])
        self.assertEqual(self._rows("SELECT * FROM ws_access_log"), [])

    def test_department_grant_allows_read_and_is_audited_before_return(self) -> None:
        reviewer = self._user("rita", "Rita Reviewer", self.hr["id"])
        self.store.grant_review(
            self.admin["id"], reviewer["id"], "department", self.accounting["id"]
        )
        conv = self._conversation()
        read = self.store.read_conversation(reviewer["id"], conv["id"])
        self.assertEqual(read["messages"][0]["text"], CANARY)
        with self.assertRaises(AccessDenied):
            self.store.read_conversation(self.carol["id"], conv["id"])

        log = self.store.list_access_log(self.admin["id"])["items"]
        self.assertEqual(len(log), 2)
        review_rows = [row for row in log if row["action"] == "reviewer.read_conversation"]
        self.assertEqual(len(review_rows), 1)
        log = review_rows
        self.assertEqual(log[0]["actor_id"], reviewer["id"])
        self.assertEqual(log[0]["conversation_id"], conv["id"])
        self.assertEqual(log[0]["department_id"], self.accounting["id"])
        self.assertEqual(log[0]["action"], "reviewer.read_conversation")
        self.assertNotIn(CANARY, repr(log))
        self.assertNotIn(REPLY, repr(log))

    def test_global_grant_and_review_list_are_audited_metadata_only(self) -> None:
        reviewer = self._user("rita", "Rita Reviewer", self.hr["id"])
        self.store.grant_review(self.admin["id"], reviewer["id"], "global")
        conv = self._conversation()
        listed = self.store.list_conversations(reviewer["id"], scope="review", limit=20)
        self.assertEqual([item["id"] for item in listed["items"]], [conv["id"]])
        self.assertNotIn("messages", listed["items"][0])
        self.assertNotIn(CANARY, repr(listed))
        self.store.read_conversation(reviewer["id"], conv["id"])
        actions = [row["action"] for row in self.store.list_access_log(self.admin["id"])["items"]]
        self.assertIn("reviewer.list_conversations", actions)
        self.assertIn("reviewer.read_conversation", actions)

    def test_reviewer_read_fails_closed_when_audit_write_fails(self) -> None:
        reviewer = self._user("rita", "Rita Reviewer", self.hr["id"])
        self.store.grant_review(self.admin["id"], reviewer["id"], "global")
        conv = self._conversation()
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("DROP TABLE ws_access_log")
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(WorkspaceError) as caught:
            self.store.read_conversation(reviewer["id"], conv["id"])
        self.assertNotIsInstance(caught.exception, AccessDenied)
        self.assertNotIn(CANARY, str(caught.exception))
        # Owner access does not depend on the review audit log.
        self.assertEqual(
            self.store.read_conversation(self.alice["id"], conv["id"])["messages"][0]["text"],
            CANARY,
        )

    def test_manual_delete_removes_content_but_keeps_access_audit(self) -> None:
        reviewer = self._user("rita", "Rita Reviewer", self.hr["id"])
        self.store.grant_review(self.admin["id"], reviewer["id"], "global")
        conv = self._conversation()
        self.store.read_conversation(reviewer["id"], conv["id"])
        with self.assertRaises(AccessDenied):
            self.store.delete_conversation(reviewer["id"], conv["id"])
        self.store.delete_conversation(self.alice["id"], conv["id"])
        self.assertEqual(
            self._rows("SELECT id FROM ws_messages WHERE conversation_id = ?", (conv["id"],)), []
        )
        self.assertEqual(
            self._rows("SELECT id FROM ws_conversations WHERE id = ?", (conv["id"],)), []
        )
        log = self._rows("SELECT action FROM ws_access_log ORDER BY created_at")
        self.assertEqual(
            sorted(row["action"] for row in log),
            ["admin.grant_review", "owner.delete_conversation", "reviewer.read_conversation"],
        )
        with self.assertRaises(NotFound):
            self.store.read_conversation(self.alice["id"], conv["id"])

    def test_delete_is_rejected_while_a_turn_is_active(self) -> None:
        conv = self._conversation()
        self.store.reserve_turn(self.alice["id"], conv["id"])
        with self.assertRaises(Conflict):
            self.store.delete_conversation(self.alice["id"], conv["id"])
        self.assertEqual(len(self._rows("SELECT id FROM ws_conversations")), 1)
        self.assertEqual(len(self._rows("SELECT id FROM ws_messages")), 2)
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(
                "UPDATE ws_conversations SET status = 'appending' WHERE id = ?",
                (conv["id"],),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(Conflict):
            self.store.delete_conversation(self.alice["id"], conv["id"])

    def test_delete_is_allowed_after_completion_or_expired_lease(self) -> None:
        conv = self._conversation()
        self.store.delete_conversation(self.alice["id"], conv["id"])
        self.assertEqual(self._rows("SELECT id FROM ws_messages"), [])
        expired = self.store.create_conversation(self.alice["id"])
        self.store.reserve_turn(self.alice["id"], expired["id"])
        self.clock.advance(121)
        self.store.delete_conversation(self.alice["id"], expired["id"])
        self.assertEqual(self._rows("SELECT id FROM ws_conversations"), [])
        log = self.store.list_access_log(self.admin["id"])["items"]
        self.assertEqual(
            [row["action"] for row in log], ["owner.delete_conversation"] * 2
        )
        self.assertNotIn(CANARY, repr(log))

    def test_delete_fails_closed_when_audit_write_fails(self) -> None:
        conv = self._conversation()
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("DROP TABLE ws_access_log")
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(WorkspaceError):
            self.store.delete_conversation(self.alice["id"], conv["id"])
        self.assertEqual(len(self._rows("SELECT id FROM ws_conversations")), 1)
        self.assertEqual(len(self._rows("SELECT id FROM ws_messages")), 2)

    def test_reservation_serialises_concurrent_appends(self) -> None:
        conv = self.store.create_conversation(self.alice["id"])
        lease = self.store.reserve_turn(self.alice["id"], conv["id"])
        with self.assertRaises(Conflict):
            self.store.reserve_turn(self.alice["id"], conv["id"])
        with self.assertRaises(Conflict):
            self.store.append_exchange(
                self.alice["id"], conv["id"], "wrong-lease", user_prompt="a", assistant_response="b"
            )

        results: list[str] = []
        barrier = threading.Barrier(2)

        def attempt(store: WorkspaceStore, text: str) -> None:
            barrier.wait()
            try:
                store.append_exchange(
                    self.alice["id"],
                    conv["id"],
                    lease["token"],
                    user_prompt=text,
                    assistant_response=REPLY,
                )
                results.append("ok")
            except Conflict:
                results.append("conflict")

        threads = [
            threading.Thread(target=attempt, args=(self._open(), "first")),
            threading.Thread(target=attempt, args=(self._open(), "second")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(results), ["conflict", "ok"])
        messages = self._rows(
            "SELECT role FROM ws_messages WHERE conversation_id = ? ORDER BY position", (conv["id"],)
        )
        self.assertEqual([row["role"] for row in messages], ["user", "assistant"])
        self.assertEqual(
            self._rows(
                "SELECT version FROM ws_conversations WHERE id = ?", (conv["id"],)
            )[0]["version"],
            1,
        )

    def test_expired_lease_can_be_taken_over(self) -> None:
        conv = self.store.create_conversation(self.alice["id"])
        stale = self.store.reserve_turn(self.alice["id"], conv["id"])
        self.clock.advance(121)
        fresh = self.store.reserve_turn(self.alice["id"], conv["id"])
        with self.assertRaises(Conflict):
            self.store.append_exchange(
                self.alice["id"],
                conv["id"],
                stale["token"],
                user_prompt=CANARY,
                assistant_response=REPLY,
            )
        self.store.append_exchange(
            self.alice["id"],
            conv["id"],
            fresh["token"],
            user_prompt=CANARY,
            assistant_response=REPLY,
        )

    def test_concurrent_reservation_has_exactly_one_winner(self) -> None:
        conv = self.store.create_conversation(self.alice["id"])
        results: list[str] = []
        barrier = threading.Barrier(2)

        def attempt(store: WorkspaceStore) -> None:
            barrier.wait()
            try:
                store.reserve_turn(self.alice["id"], conv["id"])
                results.append("ok")
            except Conflict:
                results.append("conflict")

        threads = [
            threading.Thread(target=attempt, args=(self._open(),)),
            threading.Thread(target=attempt, args=(self._open(),)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(results), ["conflict", "ok"])
        rows = self._rows(
            "SELECT status, lease_hash FROM ws_conversations WHERE id = ?", (conv["id"],)
        )
        self.assertEqual(rows[0]["status"], "pending")
        self.assertIsNotNone(rows[0]["lease_hash"])

    def test_cancelled_turn_releases_reservation(self) -> None:
        conv = self.store.create_conversation(self.alice["id"])
        lease = self.store.reserve_turn(self.alice["id"], conv["id"])
        self.store.cancel_turn(self.alice["id"], conv["id"], lease["token"])
        self.assertEqual(self._rows("SELECT status FROM ws_conversations")[0]["status"], "idle")
        self.store.reserve_turn(self.alice["id"], conv["id"])

    # -- configuration and isolation ------------------------------------
    def test_missing_or_invalid_key_fails_closed(self) -> None:
        for key in (None, "", "not-a-fernet-key"):
            with self.assertRaises(WorkspaceConfigError):
                WorkspaceStore(self.path, encryption_key=key)
        with self.assertRaises(WorkspaceConfigError):
            WorkspaceStore("", encryption_key=self.key)

    def test_existing_audit_tables_are_untouched(self) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY, request_id TEXT)")
            conn.execute("INSERT INTO events(request_id) VALUES ('retained')")
            conn.commit()
        finally:
            conn.close()
        reopened = self._open()
        reopened.ready()
        self.assertEqual(self._rows("SELECT request_id FROM events"), [{"request_id": "retained"}])
        tables = {row["name"] for row in self._rows("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("ws_users", tables)
        self.assertIn("ws_conversations", tables)


@unittest.skipUnless(
    os.environ.get("TEST_WORKSPACE_DSN"), "TEST_WORKSPACE_DSN not set; no database contacted"
)
class PostgresWorkspaceStoreTest(unittest.TestCase):
    """Real PostgreSQL round-trip against a dedicated disposable test database."""

    # A stable, test-only key keeps repeated runs against the same disposable
    # database usable.  The store still verifies the persisted key marker and
    # rejects any other key; this is not a runtime default secret.
    TEST_KEY = "SIuN9xihVB4_BtpG0So_WjfgQNiprJozOTk6YZMA_2o="

    def _open(self, key: str | None = None) -> WorkspaceStore:
        return WorkspaceStore(
            os.environ["TEST_WORKSPACE_DSN"],
            encryption_key=key or self.TEST_KEY,
        )

    def _admin(self, store: WorkspaceStore) -> dict:
        admin = store.bootstrap_admin(
            username="pg.admin.owner",
            password=GOOD_PASSWORD,
            full_name="PG Admin",
            department_name="PG IT",
        )
        if admin is None:
            admin = store.authenticate("pg.admin.owner", GOOD_PASSWORD)["user"]
        return admin

    def test_postgres_roundtrip(self) -> None:
        key = self.TEST_KEY
        store = self._open(key)
        admin = self._admin(store)
        suffix = uuid.uuid4().hex[:8]
        dept = store.create_department(admin["id"], f"PG Engineering {suffix}")
        user = store.create_user(
            admin["id"],
            f"pg.employee.{suffix}",
            GOOD_PASSWORD,
            "PG Employee",
            dept["id"],
            "employee",
        )
        conv = store.create_conversation(user["id"])
        lease = store.reserve_turn(user["id"], conv["id"])
        prompt = f"  {CANARY}\n"
        response = f"{REPLY}\n\t"
        store.append_exchange(
            user["id"],
            conv["id"],
            lease["token"],
            user_prompt=prompt,
            assistant_response=response,
        )
        read = store.read_conversation(user["id"], conv["id"])
        self.assertEqual(read["messages"][0]["text"], prompt)
        self.assertEqual(read["messages"][1]["text"], response)
        self.assertEqual(read["version"], 1)
        store.delete_conversation(user["id"], conv["id"])
        store.disable_user(admin["id"], user["id"])
        store.close()

    def test_postgres_concurrent_reservation_single_winner(self) -> None:
        key = self.TEST_KEY
        store = self._open(key)
        admin = self._admin(store)
        suffix = uuid.uuid4().hex[:8]
        dept = store.create_department(admin["id"], f"PG Concurrent {suffix}")
        user = store.create_user(
            admin["id"],
            f"pg.concurrent.{suffix}",
            GOOD_PASSWORD,
            "PG Concurrent",
            dept["id"],
            "employee",
        )
        conv = store.create_conversation(user["id"])
        workers = [self._open(key), self._open(key)]
        results: list[str] = []
        winners: list[str] = []
        barrier = threading.Barrier(2)

        def attempt(worker: WorkspaceStore) -> None:
            barrier.wait()
            try:
                lease = worker.reserve_turn(user["id"], conv["id"])
                winners.append(lease["token"])
                results.append("ok")
            except Conflict:
                results.append("conflict")

        threads = [threading.Thread(target=attempt, args=(w,)) for w in workers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(sorted(results), ["conflict", "ok"])
        self.assertEqual(len(winners), 1)
        store.cancel_turn(user["id"], conv["id"], winners[0])
        store.delete_conversation(user["id"], conv["id"])
        store.disable_user(admin["id"], user["id"])
        for worker in workers:
            worker.close()
        store.close()


@unittest.skipUnless(
    all(
        os.environ.get(name)
        for name in (
            "TEST_WORKSPACE_DSN",
            "TEST_WORKSPACE_ADMIN_DSN",
            "TEST_WORKSPACE_RUNTIME_DSN",
        )
    )
    and os.environ.get("TEST_WORKSPACE_DISPOSABLE") == "1",
    "PostgreSQL privilege verification needs owner, admin and runtime DSNs "
    "and TEST_WORKSPACE_DISPOSABLE=1",
)
class PostgresWorkspacePrivilegeTests(unittest.TestCase):
    """Real PostgreSQL least-privilege and bootstrap regression checks.

    ``TEST_WORKSPACE_DSN`` is the dedicated database owner, the admin DSN can
    apply ``workspace_roles.sql``, and the runtime DSN is a LOGIN that is only a
    member of the fixed ``nasi_lemak_workspace`` group.  These tests TRUNCATE
    every workspace row, so ``TEST_WORKSPACE_DISPOSABLE=1`` is mandatory and
    must only be set for an isolated disposable database; the owner DSN alone
    never authorises destructive setup.
    """

    TEST_KEY = PostgresWorkspaceStoreTest.TEST_KEY

    def setUp(self) -> None:
        self.owner_dsn = os.environ["TEST_WORKSPACE_DSN"]
        self.admin_dsn = os.environ["TEST_WORKSPACE_ADMIN_DSN"]
        self.runtime_dsn = os.environ["TEST_WORKSPACE_RUNTIME_DSN"]
        self._apply_roles()
        import psycopg

        with psycopg.connect(self.owner_dsn, autocommit=True) as conn:
            conn.execute("DELETE FROM ws_meta WHERE key = 'bootstrap_admin'")
            conn.execute(
                "TRUNCATE ws_access_log, ws_messages, ws_review_grants, "
                "ws_sessions, ws_conversations, ws_users, ws_departments CASCADE"
            )

    def _apply_roles(self) -> None:
        import psycopg

        roles_sql = (
            Path(__file__).resolve().parents[1]
            / "nasi_lemak"
            / "workspace_roles.sql"
        ).read_text(encoding="utf-8")
        with psycopg.connect(self.admin_dsn, autocommit=True) as conn:
            conn.execute(roles_sql)

    def _bootstrap(self, dsn: str):
        return WorkspaceStore(
            dsn, encryption_key=self.TEST_KEY, migrate=False
        ).bootstrap_admin(
            username="pg.admin.owner",
            password=GOOD_PASSWORD,
            full_name="PG Admin",
            department_name="PG IT",
        )

    def test_runtime_cannot_bootstrap_but_privileged_setup_can(self) -> None:
        import psycopg

        with self.assertRaises(WorkspaceStorageError):
            self._bootstrap(self.runtime_dsn)

        admin = self._bootstrap(self.owner_dsn)
        self.assertIsNotNone(admin)
        self.assertEqual(admin["username"], "pg.admin.owner")

        # The runtime role has normal operational access after the one-time
        # privileged bootstrap, including encrypted save/reopen and deletion.
        store = WorkspaceStore(
            self.runtime_dsn, encryption_key=self.TEST_KEY, migrate=False
        )
        dept = store.create_department(admin["id"], "Runtime Engineering")
        user = store.create_user(
            admin["id"],
            "runtime.employee",
            GOOD_PASSWORD,
            "Runtime Employee",
            dept["id"],
            "employee",
        )
        reviewer = store.create_user(
            admin["id"],
            "runtime.reviewer",
            GOOD_PASSWORD,
            "Runtime Reviewer",
            dept["id"],
            "employee",
        )
        conversation = store.create_conversation(user["id"])
        lease = store.reserve_turn(user["id"], conversation["id"])
        store.append_exchange(
            user["id"],
            conversation["id"],
            lease["token"],
            user_prompt="runtime prompt",
            assistant_response="runtime response",
        )
        self.assertEqual(
            [m["text"] for m in store.read_conversation(user["id"], conversation["id"])["messages"]],
            ["runtime prompt", "runtime response"],
        )
        grant = store.grant_review(
            admin["id"], reviewer["id"], "department", dept["id"]
        )
        self.assertEqual(
            store.read_conversation(reviewer["id"], conversation["id"])["id"],
            conversation["id"],
        )
        store.revoke_grant(admin["id"], grant["id"])
        store.delete_conversation(user["id"], conversation["id"])
        store.close()

        # The runtime connection still cannot alter setup metadata, including
        # the bootstrap marker and the append-only access audit.
        with psycopg.connect(self.runtime_dsn, autocommit=True) as conn:
            for statement in (
                "INSERT INTO ws_meta(key, value) VALUES ('runtime', 'write')",
                "UPDATE ws_meta SET value = 'write' WHERE key = 'key_verifier'",
                "DELETE FROM ws_meta",
            ):
                with self.subTest(statement=statement):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        conn.execute(statement)

    def test_runtime_grants_are_idempotent_and_access_log_is_append_only(self) -> None:
        import psycopg

        # Reapplying the fixed grant script must not fail or broaden access.
        self._apply_roles()
        with psycopg.connect(self.runtime_dsn, autocommit=True) as conn:
            conn.execute(
                "INSERT INTO ws_access_log(id, actor_id, action, created_at) "
                "VALUES ('log-1', 'runtime', 'read', 1.0)"
            )
            self.assertEqual(
                conn.execute("SELECT count(*) FROM ws_meta").fetchone()[0], 1
            )
            self.assertEqual(
                conn.execute(
                    "SELECT count(*) FROM ws_schema_migrations"
                ).fetchone()[0],
                1,
            )
            for statement in (
                "UPDATE ws_access_log SET action = 'tampered'",
                "DELETE FROM ws_access_log",
                "CREATE TABLE ws_runtime_ddl(id integer)",
                "INSERT INTO ws_meta(key, value) VALUES ('runtime', 'write')",
            ):
                with self.subTest(statement=statement):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        conn.execute(statement)
            self.assertEqual(
                conn.execute(
                    "SELECT action FROM ws_access_log WHERE id = 'log-1'"
                ).fetchone()[0],
                "read",
            )


if __name__ == "__main__":
    unittest.main()
