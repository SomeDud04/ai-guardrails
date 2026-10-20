"""Behavior regression for the operator shell's inline JavaScript.

The script is extracted from the real ``ADMIN_HTML`` and executed in the local
Node.js runtime with a small deterministic DOM and deferred fetch replies. This
proves request-generation, abort and pagehide handling at the JavaScript level;
it is not a browser engine or CSP execution claim.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from nasi_lemak.admin_page import ADMIN_HTML


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "admin_page_harness.js"


class AdminPageJavaScriptTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js runtime not available")
    def test_disconnects_aborts_and_stale_replies_cannot_repopulate(self):
        match = re.search(r"<script>(.*?)</script>", ADMIN_HTML, re.S)
        self.assertIsNotNone(match, "admin page contains one inline script")
        script = match.group(1)
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "admin-page.js"
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
