"""Behavior regression for the customer demo page's inline JavaScript.

The script is extracted from the real ``DEMO_HTML`` and executed in the local
Node.js runtime with a small deterministic DOM, fake clock and deferred fetch
replies. This proves request shape, plain-text rendering, status mapping, abort
and stale-reply handling at the JavaScript level; it is not a browser engine or
CSP execution claim.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from nasi_lemak.demo_page import DEMO_HTML


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "demo_page_harness.js"


class DemoPageJavaScriptTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js runtime not available")
    def test_demo_page_behavior(self):
        match = re.search(r"<script>(.*?)</script>", DEMO_HTML, re.S)
        self.assertIsNotNone(match, "demo page contains one inline script")
        script = match.group(1)
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "demo-page.js"
            script_path.write_text(script, encoding="utf-8")
            completed = subprocess.run(
                [shutil.which("node"), str(HARNESS), str(script_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stdout + completed.stderr,
        )
        self.assertIn("all scenarios passed", completed.stdout)


if __name__ == "__main__":
    unittest.main()
