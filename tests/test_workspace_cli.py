"""Tests for the workspace operator CLI.

These are synthetic local tests. The production CLI accepts only PostgreSQL
DSNs; the tests inject a store factory so the real SQLite-backed
``WorkspaceStore`` exercises schema creation, key binding and bootstrap without
a live database. No Docker, network, model or credential is contacted.
"""

from __future__ import annotations

import io
import os
import stat
import tempfile
import unittest
from unittest import mock

from cryptography.fernet import Fernet

from nasi_lemak import workspace_cli
from nasi_lemak.workspace_store import AuthError, WorkspaceStore

GOOD_PASSWORD = "correct-horse-battery-staple"
OTHER_PASSWORD = "another-long-password-789"


class _NoTty:
    @staticmethod
    def isatty() -> bool:
        return False


class WorkspaceCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.db_path = os.path.join(self.root, "workspace.db")
        self.key_path = os.path.join(self.root, "workspace_key")
        self.dsn_path = os.path.join(self.root, "workspace_dsn")

    # -- helpers ---------------------------------------------------------
    def _write(self, path: str, value: str | bytes) -> None:
        mode = "wb" if isinstance(value, bytes) else "w"
        with open(path, mode) as handle:
            handle.write(value)

    def _factory(self, dsn, *, encryption_key, migrate, connect_timeout):
        return WorkspaceStore(
            dsn,
            encryption_key=encryption_key,
            migrate=migrate,
            connect_timeout=connect_timeout,
        )

    def _run(self, *argv, password_reader=None, factory=None):
        out = io.StringIO()
        err = io.StringIO()
        code = workspace_cli.main(
            list(argv),
            store_factory=self._factory if factory is None else factory,
            password_reader=password_reader,
            output=out,
            error_output=err,
        )
        return code, out.getvalue(), err.getvalue()

    def _init(self, key_path: str | None = None, dsn: str | None = None):
        self._write(self.dsn_path, dsn or self.db_path)
        self._write(key_path or self.key_path, self._key_material(key_path))
        return self._run(
            "init", "--dsn-file", self.dsn_path, "--key-file", self.key_path
        )

    def _key_material(self, key_path: str | None) -> str:
        candidate = key_path or self.key_path
        if candidate == self.key_path and os.path.exists(self.key_path):
            with open(self.key_path, encoding="ascii") as handle:
                return handle.read().strip()
        return Fernet.generate_key().decode("ascii")

    def _bootstrap(self, password_reader=None):
        return self._run(
            "bootstrap-admin",
            "--dsn-file",
            self.dsn_path,
            "--key-file",
            self.key_path,
            "--username",
            "root.admin",
            "--full-name",
            "Root Admin",
            "--department",
            "IT",
            password_reader=password_reader or (lambda prompt: GOOD_PASSWORD),
        )

    # -- retention -------------------------------------------------------
    def _purge(self, days: str):
        return self._run(
            "purge-expired",
            "--dsn-file",
            self.dsn_path,
            "--key-file",
            self.key_path,
            "--older-than-days",
            days,
        )

    def test_purge_reports_the_count_without_secrets(self) -> None:
        self._init()
        code, out, _err = self._purge("30")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "deleted 0 expired conversations")

    def test_purge_rejects_a_bad_period(self) -> None:
        self._init()
        code, _out, err = self._purge("0")
        self.assertEqual(code, 2)
        self.assertIn("retention period is invalid", err)

    # -- key generation --------------------------------------------------
    def test_generate_key_is_exclusive_and_never_overwrites(self) -> None:
        code, out, err = self._run(
            "generate-key", "--key-file", self.key_path, factory=None
        )
        self.assertEqual(code, 0, err)
        with open(self.key_path, "rb") as handle:
            first = handle.read()
        self.assertEqual(len(first), 45)  # 44-byte Fernet key plus newline
        self.assertNotIn(first.decode("ascii").strip(), out)
        if os.name == "posix":
            self.assertEqual(
                stat.S_IMODE(os.stat(self.key_path).st_mode), 0o600
            )

        code, out, err = self._run(
            "generate-key", "--key-file", self.key_path, factory=None
        )
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)
        self.assertNotIn("Traceback", err)
        with open(self.key_path, "rb") as handle:
            self.assertEqual(handle.read(), first)

    def test_generate_key_does_not_overwrite_an_unrelated_file(self) -> None:
        self._write(self.key_path, "operator-owned-existing-file")
        code, _, err = self._run(
            "generate-key", "--key-file", self.key_path, factory=None
        )
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)
        with open(self.key_path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "operator-owned-existing-file")

    def test_secret_files_are_bounded_regular_and_non_empty(self) -> None:
        self._write(self.key_path, Fernet.generate_key())
        self._write(self.dsn_path, "")
        code, _, err = self._run(
            "init", "--dsn-file", self.dsn_path, "--key-file", self.key_path
        )
        self.assertEqual(code, 2)
        self.assertIn("empty", err)

        self._write(self.dsn_path, "x" * (workspace_cli.MAX_SECRET_BYTES + 1))
        code, _, err = self._run(
            "init", "--dsn-file", self.dsn_path, "--key-file", self.key_path
        )
        self.assertEqual(code, 2)
        self.assertIn("unsupported size", err)

        code, _, err = self._run(
            "init", "--dsn-file", self.root, "--key-file", self.key_path
        )
        self.assertEqual(code, 2)
        self.assertIn("regular file", err)

        code, _, err = self._run(
            "init",
            "--dsn-file",
            os.path.join(self.root, "missing"),
            "--key-file",
            self.key_path,
        )
        self.assertEqual(code, 2)
        self.assertIn("unavailable", err)

    def test_errors_are_generic_and_never_leak_secrets_or_tracebacks(self) -> None:
        canary = "CANARY-dsn-value-must-not-leak"
        self._write(self.key_path, Fernet.generate_key())
        self._write(self.dsn_path, f"sqlite:///{canary}.db")
        # No injected factory here, so the default production path refuses a
        # non-PostgreSQL DSN before any store is opened.
        out = io.StringIO()
        err = io.StringIO()
        code = workspace_cli.main(
            ["init", "--dsn-file", self.dsn_path, "--key-file", self.key_path],
            store_factory=None,
            output=out,
            error_output=err,
        )
        self.assertEqual(code, 2)
        combined = out.getvalue() + err.getvalue()
        self.assertNotIn(canary, combined)
        self.assertNotIn("Traceback", combined)
        self.assertIn("PostgreSQL", err.getvalue())

        def exploding_factory(*args, **kwargs):
            raise RuntimeError("CANARY-factory-detail-must-not-leak")

        self._write(self.dsn_path, self.db_path)
        code, out, err = self._run(
            "init",
            "--dsn-file",
            self.dsn_path,
            "--key-file",
            self.key_path,
            factory=exploding_factory,
        )
        self.assertEqual(code, 2)
        self.assertIn("storage is unavailable", err)
        self.assertNotIn("CANARY", out + err)
        self.assertNotIn("Traceback", out + err)
    def test_bootstrap_refuses_non_tty_password_reader(self) -> None:
        self.assertEqual(self._init()[0], 0)
        called = []
        with mock.patch.object(workspace_cli.sys, "stdin", _NoTty()):
            code, out, err = self._run(
                "bootstrap-admin",
                "--dsn-file",
                self.dsn_path,
                "--key-file",
                self.key_path,
                "--username",
                "root.admin",
                "--full-name",
                "Root Admin",
                "--department",
                "IT",
                factory=lambda *args, **kwargs: called.append(True),
            )
        self.assertEqual(code, 2)
        self.assertIn("interactive terminal", err)
        self.assertEqual(called, [])
        self.assertNotIn(GOOD_PASSWORD, out + err)

    def test_bootstrap_rejects_password_mismatch_before_store_access(self) -> None:
        self.assertEqual(self._init()[0], 0)
        answers = iter([GOOD_PASSWORD, OTHER_PASSWORD])
        called = []

        def factory(*args, **kwargs):
            called.append(True)

        code, out, err = self._run(
            "bootstrap-admin",
            "--dsn-file",
            self.dsn_path,
            "--key-file",
            self.key_path,
            "--username",
            "root.admin",
            "--full-name",
            "Root Admin",
            "--department",
            "IT",
            password_reader=lambda prompt: next(answers),
            factory=factory,
        )
        self.assertEqual(code, 2)
        self.assertIn("do not match", err)
        self.assertEqual(called, [])
        self.assertNotIn(GOOD_PASSWORD, out + err)

    def test_argument_errors_never_echo_rejected_values(self) -> None:
        sentinel = "SYNTHETIC-NOT-A-REAL-PASSWORD"
        key_path = os.path.join(self.root, "unused-caller-file")
        code, out, err = self._run(
            "generate-key", "--key-file", key_path, "--password", sentinel
        )
        self.assertEqual(code, 2)
        self.assertIn("invalid command line arguments", err)
        self.assertNotIn(sentinel, out + err)
        self.assertFalse(os.path.exists(key_path))

    # -- schema initialisation ------------------------------------------
    def test_init_is_repeatable_and_restart_opens_without_migration(self) -> None:
        for _ in range(2):
            code, _, err = self._init()
            self.assertEqual(code, 0, err)
        store = WorkspaceStore(
            self.db_path,
            encryption_key=self._key_material(self.key_path),
            migrate=False,
        )
        try:
            self.assertTrue(store.ready())
        finally:
            store.close()

    def test_wrong_key_fails_without_committed_writes(self) -> None:
        self.assertEqual(self._init()[0], 0)
        self.assertEqual(self._bootstrap()[0], 0)

        wrong_path = os.path.join(self.root, "wrong_key")
        self._write(wrong_path, Fernet.generate_key())
        code, out, err = self._run(
            "init", "--dsn-file", self.dsn_path, "--key-file", wrong_path
        )
        self.assertEqual(code, 2, out)
        self.assertIn("storage is unavailable", err)
        self.assertNotIn("Traceback", out + err)

        store = WorkspaceStore(
            self.db_path,
            encryption_key=self._key_material(self.key_path),
            migrate=False,
        )
        try:
            admin = store.authenticate("root.admin", GOOD_PASSWORD)
            self.assertEqual(admin["user"]["username"], "root.admin")
            self.assertEqual(store.list_grants(admin["user"]["id"])["items"], [])
        finally:
            store.close()

    # -- bootstrap and review grants ------------------------------------
    def test_bootstrap_without_review_grants_survives_restart(self) -> None:
        self.assertEqual(self._init()[0], 0)
        code, out, err = self._bootstrap()
        self.assertEqual(code, 0, err)
        self.assertNotIn(GOOD_PASSWORD, out)

        store = WorkspaceStore(
            self.db_path,
            encryption_key=self._key_material(self.key_path),
            migrate=False,
        )
        try:
            admin = store.authenticate("root.admin", GOOD_PASSWORD)
            profile = store.get_profile(admin["user"]["id"])
            self.assertIsNone(profile["review_scope"])
            self.assertEqual(profile["review_grants"], [])
            self.assertEqual(
                store.list_grants(admin["user"]["id"])["items"], []
            )
        finally:
            store.close()

    def test_bootstrap_accepts_unicode_password_without_leaking_it(self) -> None:
        unicode_password = "p\u00e4ssw\u00f6rd-\u6b63\u786e-horse-battery"
        self.assertEqual(self._init()[0], 0)
        code, out, err = self._bootstrap(
            password_reader=lambda prompt: unicode_password
        )
        self.assertEqual(code, 0, err)
        self.assertNotIn(unicode_password, out + err)
        store = WorkspaceStore(
            self.db_path,
            encryption_key=self._key_material(self.key_path),
            migrate=False,
        )
        try:
            admin = store.authenticate("root.admin", unicode_password)
            self.assertEqual(admin["user"]["username"], "root.admin")
        finally:
            store.close()

    def test_bootstrap_existing_admin_refuses_and_does_not_reset(self) -> None:
        self.assertEqual(self._init()[0], 0)
        self.assertEqual(self._bootstrap()[0], 0)
        code, _, err = self._bootstrap(
            password_reader=lambda prompt: OTHER_PASSWORD
        )
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)

        store = WorkspaceStore(
            self.db_path,
            encryption_key=self._key_material(self.key_path),
            migrate=False,
        )
        try:
            admin = store.authenticate("root.admin", GOOD_PASSWORD)
            self.assertEqual(admin["user"]["username"], "root.admin")
            with self.assertRaises(AuthError):
                store.authenticate("root.admin", OTHER_PASSWORD)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
