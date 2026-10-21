"""HTTP and CSP checks for the customer demo page at ``GET /``.

The page is served by the real FastAPI application with an injected synthetic
gateway. These tests prove the HTML surface, independent script/style hashes and
security headers; they are not a browser or CSP execution claim.
"""

from __future__ import annotations

import base64
import hashlib
import re
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from nasi_lemak.audit import SqliteAuditStore
from nasi_lemak.demo_page import DEMO_HTML, DEMO_SECURITY_HEADERS, demo_html
from nasi_lemak.gateway import Gateway, Policy
from nasi_lemak.server import ENV_MODE, make_app

TEST_KEY = "demo-page-chat-key"


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


class DemoPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.gateway = Gateway(
            key_digest=hashlib.sha256(TEST_KEY.encode()).hexdigest(),
            audit_store=SqliteAuditStore(Path(self.tmp.name) / "audit.sqlite3"),
            policy=Policy(),
        )

    def _client(self, mode: str = "test") -> TestClient:
        return TestClient(make_app(gateway=self.gateway, environ={ENV_MODE: mode}))

    def test_root_serves_html_with_security_headers(self) -> None:
        response = self._client().get("/")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.headers["content-type"].startswith("text/html"))
        for name, value in DEMO_SECURITY_HEADERS.items():
            self.assertEqual(response.headers[name], value, name)
        self.assertEqual(response.headers["X-Nasi-Lemak-Mode"], "test")
        self.assertEqual(response.headers["X-Nasi-Lemak-Guards-Active"], "false")

    def test_csp_hashes_match_the_actual_inline_script_and_style(self) -> None:
        html = self._client().get("/").text
        styles = re.findall(r"<style>(.*?)</style>", html, re.S)
        scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
        self.assertEqual(len(styles), 1, "page has one inline stylesheet")
        self.assertEqual(len(scripts), 1, "page has one inline script")
        csp = DEMO_SECURITY_HEADERS["Content-Security-Policy"]
        self.assertIn(f"style-src {_csp_hash(styles[0])}", csp)
        self.assertIn(f"script-src {_csp_hash(scripts[0])}", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("default-src 'none'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'none'", csp)
        self.assertIn("form-action 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_test_mode_page_clearly_reports_inactive_guards(self) -> None:
        html = self._client("test").get("/").text
        self.assertIn("Test mode", html)
        self.assertIn("model-based injection and output checks are inactive", html)
        self.assertIn(">test<", html)
        self.assertNotIn("native guard", html.lower())
        self.assertNotIn("guards are active", html.lower())

    def test_guarded_but_unready_page_does_not_claim_guard_protection(self) -> None:
        html = self._client("guarded").get("/").text
        self.assertIn("Guards are not active", html)
        self.assertNotIn(
            '<div id="test-banner" class="banner" role="note">Test mode', html
        )
        self.assertIn(">guarded<", html)

    def test_page_has_chat_shell_controls_status_and_separate_admin_link(self) -> None:
        html = self._client().get("/").text
        # Compact sidebar with product title, new chat, key controls and status.
        self.assertIn('class="sidebar"', html)
        self.assertIn("<h1>Nasi Lemak</h1>", html)
        self.assertIn('id="new-chat"', html)
        self.assertIn('id="chat-key"', html)
        self.assertIn('type="password"', html)
        self.assertIn('autocomplete="off"', html)
        self.assertIn('id="key-state"', html)
        self.assertIn('id="mode-value"', html)
        self.assertIn('id="readiness-value"', html)
        self.assertIn('id="guards-value"', html)
        self.assertIn('href="/admin"', html)
        # Spacious conversation leading to a bottom composer.
        self.assertIn('id="empty-state"', html)
        self.assertIn('id="exchange"', html)
        self.assertIn('id="last-prompt"', html)
        self.assertIn('id="prompt"', html)
        self.assertIn('id="response"', html)
        self.assertIn('id="status"', html)
        self.assertIn('id="send"', html)
        self.assertIn('id="clear"', html)
        self.assertIn("Ask the gateway something", html)
        self.assertIn("Responses come from the configured model and may be inaccurate.", html)
        self.assertIn("The key stays in this tab's memory", html)
        self.assertIn("uses a separate operator key", html)
        self.assertIn("Ctrl/Command + Enter sends.", html)
        self.assertIn("Each prompt is sent independently", html)
        self.assertNotIn("API-only deployment", html)
        self.assertNotIn("Model alias", html)
        self.assertNotIn("Not verified", html)
        self.assertNotIn("demo-page-chat-key", html)
        self.assertNotIn("innerHTML", html)

    def test_responsive_shell_has_keyboard_sidebar_control_and_no_remote_assets(self) -> None:
        html = self._client().get("/").text
        self.assertIn('id="sidebar-toggle"', html)
        self.assertIn('aria-controls="sidebar"', html)
        self.assertIn('aria-expanded="false"', html)
        self.assertIn("@media (max-width: 820px)", html)
        self.assertIn("color-scheme: dark", html)
        self.assertIn("system-ui", html)
        self.assertIn("focus-visible", html)
        # The shell is self-authored: no remote fonts, CDNs, frameworks or
        # inline event handlers that would weaken the hash-based CSP.
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<link", html)
        self.assertNotIn("onclick=", html)
        self.assertNotIn("onload=", html)
        self.assertNotIn("@import", html)

    def test_root_wrong_method_and_unknown_routes_remain_strict(self) -> None:
        client = self._client()
        wrong_method = client.post("/", json={})
        self.assertEqual(wrong_method.status_code, 405)
        self.assertEqual(wrong_method.json()["error"]["code"], "INVALID_REQUEST")
        unknown = client.get("/still-unknown")
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(unknown.json()["error"]["code"], "INVALID_REQUEST")

    def test_demo_html_replaces_mode_without_changing_static_script(self) -> None:
        html = demo_html(mode="invalid", guards_active=False)
        self.assertIn(">invalid<", html)
        self.assertIn("Guards are not active", html)
        self.assertIn("<!-- MODE_BANNER -->", DEMO_HTML, "static template keeps its marker")
        self.assertNotIn("<!-- MODE_BANNER -->", html)
        self.assertNotIn("<!-- MODE_VALUE -->", html)
        self.assertEqual(
            re.search(r"<script>(.*?)</script>", html, re.S).group(1),
            re.search(r"<script>(.*?)</script>", DEMO_HTML, re.S).group(1),
        )


if __name__ == "__main__":
    unittest.main()
