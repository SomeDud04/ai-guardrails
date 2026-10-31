"""Tests for the opt-in employee workspace page and its inline JavaScript.

The HTTP tests use the real application, a temporary SQLite workspace store and
synthetic in-process adapters.  The JavaScript test executes the page script in
Node with a deterministic DOM and deferred fetch replies; it is not a browser
engine claim.  No external service is contacted.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_workspace_http import PASSWORD, LEGACY_KEY, WorkspaceHTTPBase


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "workspace_page_harness.js"


def _node() -> str | None:
    configured = os.environ.get("NASI_LEMAK_NODE")
    if configured and Path(configured).is_file():
        return configured
    found = shutil.which("node")
    if found:
        return found
    bundled = Path(
        r"C:\Users\user\.cache\codex-runtimes\codex-primary-runtime\dependencies"
        r"\node\bin\node.exe"
    )
    return str(bundled) if bundled.is_file() else None


class WorkspacePageHTTPTests(WorkspaceHTTPBase):
    def _page(self):
        response = self.client.get("/workspace")
        self.assertEqual(response.status_code, 200, response.text)
        return response

    def test_workspace_page_routes_are_opt_in_and_legacy_pages_survive(self) -> None:
        page = self._page()
        self.assertEqual(self.client.get("/workspace/").status_code, 200)
        self.assertEqual(page.headers.get("cache-control"), "no-store")
        self.assertEqual(page.headers.get("x-content-type-options"), "nosniff")
        self.assertIn("default-src 'none'", page.headers.get("content-security-policy", ""))
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        self.assertEqual(self.client.get("/").status_code, 200)
        # The legacy admin page remains governed by the operator configuration;
        # this fixture has no operator, so its documented response is 404.
        self.assertEqual(self.client.get("/admin").status_code, 404)

        disabled = self.make_client(
            self.make_app(
                environ={
                    "NASI_LEMAK_MODE": "test",
                    "NASI_LEMAK_ALLOW_UNGUARDED_TEST": "true",
                }
            )
        )
        self.assertEqual(disabled.get("/workspace").status_code, 404)
        self.assertEqual(disabled.get("/workspace/").status_code, 404)
        self.assertEqual(disabled.get("/").status_code, 200)
        self.assertEqual(disabled.get("/admin").status_code, 404)

    def test_workspace_view_urls_serve_the_same_shell_and_headers(self) -> None:
        legacy = self._page()
        for path in (
            "/workspace/",
            "/workspace/chat",
            "/workspace/chat/",
            "/workspace/review",
            "/workspace/review/",
            "/workspace/admin",
            "/workspace/admin/",
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.text, legacy.text)
                self.assertEqual(response.headers.get("cache-control"), "no-store")
                self.assertEqual(response.headers.get("x-content-type-options"), "nosniff")
                self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

        disabled = self.make_client(
            self.make_app(
                environ={
                    "NASI_LEMAK_MODE": "test",
                    "NASI_LEMAK_ALLOW_UNGUARDED_TEST": "true",
                }
            )
        )
        for path in ("/workspace/chat", "/workspace/review", "/workspace/admin"):
            with self.subTest(path=path, enabled=False):
                self.assertEqual(disabled.get(path).status_code, 404)

    def test_csp_hashes_match_the_single_style_and_script(self) -> None:
        html = self._page().text
        styles = re.findall(r"<style>(.*?)</style>", html, re.S)
        scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
        self.assertEqual(len(styles), 1)
        self.assertEqual(len(scripts), 1)
        csp = self._page().headers["content-security-policy"]
        for kind, text in (("style", styles[0]), ("script", scripts[0])):
            digest = base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode()
            self.assertIn(f"{kind}-src 'sha256-{digest}'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)

    def test_page_has_no_secret_or_runtime_configuration_interpolation(self) -> None:
        html = self._page().text
        for secret in (self.key, self.db_path, PASSWORD, LEGACY_KEY):
            self.assertNotIn(secret, html)
        self.assertNotIn("postgresql://", html)
        self.assertNotIn("localStorage", html)
        self.assertNotIn("sessionStorage", html)
        self.assertNotIn("document.cookie", html)
        self.assertNotIn("innerHTML", html)
        self.assertIn('id="tab-admin"', html)
        self.assertRegex(html, r'<button id="tab-admin"[^>]*hidden')
        self.assertIn('id="admin-panel"', html)
        self.assertIn("Account administration", html)
        self.assertIn(
            "Your history is private to your account and authorised reviewers.", html
        )
        self.assertNotIn("Only you can read your conversations", html)
        self.assertIn(
            "Your original prompt and the delivered assistant reply are saved encrypted "
            "on the server until you delete the conversation. A blocked or failed prompt "
            "is saved with its outcome; no blocked assistant reply is stored.",
            html,
        )
        self.assertIn("#workspace-view {", html)
        self.assertIn("flex-direction: column;", html)

    def test_policy_form_exposes_independent_postal_mask_checkboxes(self) -> None:
        html = self._page().text
        for control in ("policy-input-postal", "policy-output-postal"):
            self.assertRegex(
                html, rf'<input id="{control}" type="checkbox" checked>'
            )
        self.assertEqual(html.count("Mask Postal address"), 2)
        self.assertIn("Postal address masking recognises", html)
        self.assertIn(
            "A numbered street address that follows an explicit Address: or "
            "Alamat: label is also masked without a postcode.",
            html,
        )
        self.assertIn("bounded ASCII Malaysian single-line address shape", html)
        self.assertIn("each direction is selected independently", html)

    def test_policy_form_exposes_the_four_chat_limit_fields(self) -> None:
        html = self._page().text
        fields = (
            "policy-limit-context-messages",
            "policy-limit-context-budget",
            "policy-limit-default-reply-tokens",
            "policy-limit-max-reply-tokens",
        )
        self.assertIn("<legend>Chat limits</legend>", html)
        for control in fields:
            self.assertRegex(
                html,
                rf'<input id="{control}"[^>]*type="number"[^>]*'
                rf'min="1"[^>]*step="1"',
            )
            self.assertIn(f'<span id="{control}-hint"', html)
        self.assertEqual(html.count('class="policy-limit-hint"'), 4)
        self.assertIn("will be clamped", html)

    def test_admin_table_density_and_identifier_styles_are_present(self) -> None:
        html = self._page().text
        styles = re.findall(r"<style>(.*?)</style>", html, re.S)
        self.assertEqual(len(styles), 1)
        css = styles[0]
        # UX-01: one dense rhythm for every admin row and explicit widths for
        # the three list tables an administrator reads row by row.
        self.assertIn(".admin-table-head, .admin-table-row {", css)
        self.assertIn("padding: 12px 16px;", css)
        self.assertIn("gap: 12px;", css)
        self.assertIn("#user-list .cols-5", css)
        self.assertIn("#access-list .cols-5", css)
        self.assertIn("#alert-list .cols-6", css)
        self.assertIn(".cell-truncate", css)
        self.assertIn("text-overflow: ellipsis;", css)
        self.assertIn("white-space: nowrap;", css)
        # The narrow layout turns these lists into labelled cards instead of a
        # horizontally scrolled table whose actions sit off-screen.
        self.assertIn(".admin-table-list", css)
        self.assertIn("content: attr(data-label);", css)
        for table_id in ("user-list", "alert-list", "access-list"):
            self.assertIn(
                f'id="{table_id}" class="admin-table admin-table-list"', html
            )

    def test_admin_settings_tab_is_read_only_and_uses_the_placeholder(self) -> None:
        html = self._page().text
        self.assertRegex(
            html,
            r'<button id="admin-tab-settings"[^>]*role="tab"[^>]*'
            r'aria-controls="admin-settings-panel"[^>]*aria-selected="false"[^>]*>'
            r"Settings</button>",
        )
        self.assertRegex(
            html,
            r'<section id="admin-settings-panel"[^>]*role="tabpanel"[^>]*'
            r'aria-labelledby="admin-tab-settings"[^>]*hidden',
        )
        self.assertIn('id="settings-copy-curl"', html)
        self.assertIn('id="settings-copy-chat"', html)
        # The tab is read-only: no form and no mutation control of its own.
        panel = html.split('id="admin-settings-panel"', 1)[1].split("</section>", 1)[0]
        self.assertNotIn("<form", panel)
        self.assertNotIn("<input", panel)
        self.assertNotIn('method="POST"', panel)
        # Snippets are built in the browser from the current origin and carry
        # only the literal placeholder, never a configured credential.
        self.assertIn("window.location.origin", html)
        self.assertIn("$NASI_LEMAK_API_KEY", html)
        self.assertIn("NASI_GATEWAY_TOKEN", html)
        self.assertIn("--base-url", html)
        for secret in (self.key, self.db_path, LEGACY_KEY, PASSWORD):
            self.assertNotIn(secret, html)

    def test_mobile_topbar_keeps_wrapped_guard_status_inside_the_header(self) -> None:
        html = self._page().text
        css = re.findall(r"<style>(.*?)</style>", html, re.S)[0]
        topbar = re.search(r"\.topbar\s*\{([^}]*)\}", css, re.S)
        self.assertIsNotNone(topbar)
        # At 390px the topbar wraps to several lines. As a flex item in .main it
        # must not shrink below that content height, otherwise #guard-status
        # overflows onto the Admin heading while its own box stays 63px tall.
        self.assertRegex(topbar.group(1), r"flex:\s*none;")
        self.assertIn("flex-wrap: wrap;", css)
        self.assertIn(".guard-status { order: 10; flex-basis: 100%;", css)

    def test_alert_mark_all_control_is_accessible_and_admin_only(self) -> None:
        html = self._page().text
        self.assertRegex(
            html,
            r'<button id="alert-mark-all"[^>]*type="button"[^>]*'
            r'aria-label="Mark all alerts read"[^>]*hidden[^>]*>Mark all read</button>',
        )
        alerts = html.split('id="admin-alerts-panel"', 1)[1]
        self.assertLess(
            alerts.index('id="alert-mark-all"'), alerts.index('id="alert-list"')
        )

    def test_review_metadata_is_joined_and_stays_inside_the_grant(self) -> None:
        self.store.grant_review(
            self.admin["id"], self.bob["id"], "department", self.accounting["id"]
        )
        alice_conversation = self.seeded_conversation(
            self.alice, "Alice original prompt", "Alice answer"
        )
        carol_conversation = self.seeded_conversation(
            self.carol, "Carol secret prompt", "Carol answer"
        )
        bob_token = self.login("bob")
        response = self.client.get(
            "/workspace/api/review/conversations",
            headers=self.auth(bob_token),
        )
        self.assertEqual(response.status_code, 200, response.text)
        items = response.json()["items"]
        by_id = {item["id"]: item for item in items}
        self.assertIn(alice_conversation, by_id)
        self.assertNotIn(carol_conversation, by_id)
        self.assertEqual(by_id[alice_conversation]["owner_full_name"], "Alice Tan")
        self.assertEqual(by_id[alice_conversation]["department_name"], "Accounting")
        self.assertNotIn("Carol Ng", response.text)
        self.assertNotIn("Human Resources", response.text)

        denied = self.client.get(
            f"/workspace/api/review/conversations/{carol_conversation}",
            headers=self.auth(bob_token),
        )
        self.assert_error(denied, 403, "FORBIDDEN")

        own = self.client.get(
            "/workspace/api/conversations", headers=self.auth(self.login("alice"))
        )
        own_item = next(item for item in own.json()["items"] if item["id"] == alice_conversation)
        self.assertEqual(own_item["owner_full_name"], "Alice Tan")
        self.assertEqual(own_item["department_name"], "Accounting")

    def test_unready_workspace_page_reports_unavailable_generically(self) -> None:
        client = self.make_client(self.make_app(store=False, environ=self.env()))
        page = client.get("/workspace")
        self.assertEqual(page.status_code, 200, page.text)
        self.assertIn("Workspace unavailable", page.text)
        self.assertNotIn("workspace configuration is incomplete", page.text)


class WorkspacePageJavaScriptTests(unittest.TestCase):
    def test_workspace_page_behavior(self) -> None:
        node = _node()
        if node is None:
            self.skipTest("Node.js runtime not available")
        from nasi_lemak.workspace_page import WORKSPACE_HTML

        match = re.search(r"<script>(.*?)</script>", WORKSPACE_HTML, re.S)
        self.assertIsNotNone(match, "workspace page contains one inline script")
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "workspace-page.js"
            script_path.write_text(match.group(1), encoding="utf-8")
            completed = subprocess.run(
                [node, str(HARNESS), str(script_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("all scenarios passed", completed.stdout)


if __name__ == "__main__":
    unittest.main()
