"""Structural tests for the optional unencrypted demo ingress.

These tests parse the authored Compose overlay and nginx configuration.  They
are not ``docker compose config``, an nginx syntax check, an image pull or a
runtime acceptance test.  Docker and nginx are absent from this Windows
workspace; no container, port or proxy was executed.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - the test extra pins PyYAML
    yaml = None

from nasi_lemak.server import DEFAULT_MAX_BODY_BYTES

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "compose.demo.yaml"
NGINX = ROOT / "deploy" / "nginx-demo.conf"
DOC = ROOT / "docs" / "demo-access.md"


def _load(name: str):
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


class DemoComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if yaml is None:
            raise unittest.SkipTest("PyYAML is not installed")
        cls.base = _load("compose.yaml")
        cls.demo = _load("compose.demo.yaml")
        cls.service = cls.demo["services"]["nginx"]

    def test_overlay_adds_only_the_nginx_service(self):
        self.assertEqual(set(self.demo["services"]), {"nginx"})
        self.assertNotIn("db", self.demo["services"])
        self.assertNotIn("gateway", self.demo["services"])
        # The demo file must not redeclare secrets, volumes or networks.
        for key in ("secrets", "volumes", "networks"):
            with self.subTest(key=key):
                self.assertNotIn(key, self.demo)

    def test_gateway_and_database_keep_private_defaults(self):
        gateway = self.base["services"]["gateway"]
        self.assertEqual(gateway["ports"], ["127.0.0.1:${GATEWAY_PORT:-8000}:8000"])
        self.assertNotIn("ports", self.base["services"]["db"])
        self.assertEqual(self.base["services"]["db"]["networks"], ["db_internal"])

    def test_nginx_joins_only_the_default_network_and_mounts_no_secrets(self):
        self.assertEqual(self.service["networks"], ["default"])
        self.assertNotIn("db_internal", self.service["networks"])
        self.assertNotIn("secrets", self.service)
        volumes = self.service["volumes"]
        self.assertEqual(len(volumes), 1)
        self.assertEqual(volumes[0]["type"], "bind")
        self.assertEqual(volumes[0]["target"], "/etc/nginx/nginx.conf")
        self.assertIs(volumes[0]["read_only"], True)
        self.assertIs(volumes[0]["bind"]["create_host_path"], False)
        self.assertFalse(volumes[0]["source"].startswith("/"))

    def test_bind_address_is_explicit_and_port_defaults_to_8080(self):
        ports = self.service["ports"]
        self.assertEqual(len(ports), 1)
        port = ports[0]
        # `:?` requires the variable; no `:-` fallback and no wildcard.
        self.assertIn("${DEMO_BIND_IP:?", port)
        self.assertNotIn("${DEMO_BIND_IP:-", port)
        self.assertNotIn("0.0.0.0", port)
        self.assertIn("${DEMO_PORT:-8080}", port)
        self.assertTrue(port.endswith(":8080"))

    def test_image_entrypoint_and_non_root_runtime(self):
        self.assertEqual(self.service["image"], "nginx:stable-alpine")
        self.assertEqual(self.service["entrypoint"], ["nginx", "-g", "daemon off;"])
        self.assertEqual(self.service["user"], "101:101")
        self.assertIs(self.service["read_only"], True)
        self.assertEqual(self.service["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", self.service["security_opt"])
        self.assertNotIn("privileged", self.service)
        self.assertNotIn("build", self.service)

    def test_tmpfs_is_the_only_writable_path(self):
        tmpfs = self.service["tmpfs"]
        self.assertEqual(len(tmpfs), 1)
        self.assertRegex(tmpfs[0], r"^/tmp:")
        self.assertIn("mode=1777", tmpfs[0])
        self.assertTrue(self.service["read_only"])

    def test_resource_limits_are_finite(self):
        mem = self.service["mem_limit"]
        self.assertRegex(str(mem), r"^\d+[mg]$")
        self.assertGreater(int(str(mem).rstrip("mg")), 0)
        cpus = self.service["cpus"]
        self.assertIsInstance(cpus, (int, float))
        self.assertTrue(0 < float(cpus) <= 2.0)
        self.assertGreater(int(self.service["pids_limit"]), 0)
        self.assertLessEqual(int(self.service["pids_limit"]), 256)

    def test_healthcheck_is_local_liveness_only(self):
        check = self.service["healthcheck"]
        test = check["test"]
        self.assertEqual(test[0], "CMD")
        self.assertIn("wget", test)
        url = test[-1]
        self.assertEqual(url, "http://127.0.0.1:8080/health/live")
        self.assertNotIn("/health/ready", url)
        for key in ("interval", "timeout"):
            self.assertRegex(check[key], r"^\d+s$")
        self.assertLessEqual(int(check["timeout"].rstrip("s")), 10)
        self.assertNotIn("curl", test)


class NginxConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = NGINX.read_text(encoding="utf-8")
        cls.flat = " ".join(line.strip() for line in cls.text.splitlines())

    def test_process_paths_and_logging_avoid_the_read_only_root(self):
        self.assertIn("pid /tmp/nginx.pid;", self.text)
        self.assertIn("error_log /dev/stderr crit;", self.text)
        self.assertIn("access_log off;", self.text)
        self.assertNotRegex(self.text, r"access_log\s+/")
        self.assertNotRegex(self.text, r"access_log\s+\S*\$request")
        for path in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            self.assertIn(f"/tmp/{path}", self.text)

    def test_listens_on_unprivileged_http_only(self):
        self.assertRegex(self.text, r"listen\s+8080;")
        self.assertNotRegex(self.text, r"listen\s+80\s*;")
        self.assertNotIn("ssl_certificate", self.text)
        self.assertNotIn("ssl_protocols", self.text)
        self.assertNotIn("0.0.0.0", self.text)

    def test_uses_docker_dns_with_finite_resolution_and_connect(self):
        self.assertIn("resolver 127.0.0.11", self.text)
        self.assertIn("valid=10s", self.text)
        self.assertIn("ipv6=off", self.text)
        self.assertIn("resolver_timeout 2s;", self.text)
        self.assertIn("proxy_connect_timeout 5s;", self.text)
        # Exactly one proxy_pass directive (ignore prose comments), variable
        # based, with no rewritten URI.
        directives = "\n".join(
            line
            for line in self.text.splitlines()
            if not line.strip().startswith("#")
        )
        targets = re.findall(r"proxy_pass\s+([^;]+);", directives)
        self.assertEqual(targets, ["http://$gateway_upstream:8000"])

    def test_forwards_original_uri_authorization_and_upstream_headers(self):
        self.assertIn("proxy_set_header Authorization $http_authorization;", self.text)
        self.assertNotIn("proxy_hide_header", self.text)
        self.assertNotIn("add_header", self.text)
        self.assertNotIn("sub_filter", self.text)
        self.assertIn("proxy_intercept_errors off;", self.text)
        self.assertIn("proxy_cache off;", self.text)
        # No retries, particularly for POST requests to chat/audit.
        self.assertIn("proxy_next_upstream off;", self.text)
        self.assertNotRegex(self.text, r"proxy_next_upstream\s+(?!off;)")

    def test_forwards_the_original_host_verbatim_including_any_port(self):
        self.assertIn("proxy_set_header Host $http_host;", self.text)
        # `$host` would strip an explicit :8080 port; `$http_host` preserves it.
        self.assertNotRegex(self.text, r"proxy_set_header\s+Host\s+\$host\s*;")
        directives = "\n".join(
            line
            for line in self.text.splitlines()
            if not line.strip().startswith("#")
        )
        # The proxy neither generates nor trusts client forwarding metadata.
        for header in ("X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "Forwarded"):
            with self.subTest(header=header):
                self.assertNotIn(header, directives)

    def test_body_limit_matches_server_default_and_keeps_slow_clients_out(self):
        self.assertEqual(DEFAULT_MAX_BODY_BYTES, 64 * 1024)
        self.assertIn("client_max_body_size 64k;", self.text)
        self.assertIn("client_body_buffer_size 64k;", self.text)
        self.assertIn("proxy_request_buffering on;", self.text)

    def test_response_deadlines_exceed_the_default_chat_deadline(self):
        self.assertIn("proxy_read_timeout 90s;", self.text)
        self.assertIn("proxy_send_timeout 90s;", self.text)
        self.assertGreater(90, 60)

    def test_no_extra_authentication_or_secret_references(self):
        for marker in ("auth_basic", "proxy_set_header X-API-Key", "env ", "include /run/secrets"):
            self.assertNotIn(marker, self.text)
        self.assertNotIn("$http_authorization", self.text.replace(
            "proxy_set_header Authorization $http_authorization;", ""
        ))


class DemoDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding="utf-8")

    def test_document_states_scope_and_pending_acceptance(self):
        for marker in (
            "trusted LAN",
            "TLS",
            "test mode",
            "not been executed",
            "VM acceptance",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.text)

    def test_document_uses_placeholders_and_never_advises_down_v(self):
        self.assertIn("VM_LAN_IP", self.text)
        self.assertIn("ADMIN_IP", self.text)
        self.assertIn("never", self.text.lower())
        self.assertIn("down -v", self.text)
        self.assertNotIn("82haf69n.flexinfra.com.my", self.text)
        # Wildcard mentions must be negated warnings, never runnable examples.
        self.assertNotIn("DEMO_BIND_IP=0.0.0.0", self.text)
        self.assertNotIn(":0.0.0.0:8080", self.text)

    def test_document_names_the_required_env_file_and_rollback(self):
        self.assertIn(".secrets/compose.demo.env", self.text)
        self.assertIn("DEMO_BIND_IP", self.text)
        self.assertIn("DEMO_PORT", self.text)
        self.assertIn("nginx -t", self.text)
        self.assertIn("--entrypoint nginx", self.text)
        self.assertIn("stop nginx", self.text)
        self.assertIn("never run", self.text.lower())

    def test_document_does_not_claim_loopback_8080_for_a_lan_only_bind(self):
        # Regression: DEMO_BIND_IP publishes only the VM LAN address, so a
        # loopback request to 8080 is not a valid ingress check.
        self.assertIn("http://VM_LAN_IP:8080/health/live", self.text)
        self.assertIn("not published", self.text)
        self.assertIn("DEMO_BIND_IP", self.text)
        runnable = [
            line
            for line in self.text.splitlines()
            if "curl" in line and not line.strip().startswith("#")
        ]
        self.assertTrue(runnable)
        for line in runnable:
            with self.subTest(line=line):
                self.assertNotIn("127.0.0.1:8080", line)
                self.assertNotIn("localhost:8080", line)
        # The backend publication on 8000 stays a separate loopback check.
        self.assertIn("http://127.0.0.1:8000/health/live", self.text)

    def test_update_uses_an_explicit_checkout_path_not_a_home_assumption(self):
        # The operator may be root while the checkout lives in another home.
        self.assertIn("/path/to/existing/ai-guardrails", self.text)
        self.assertIn("replace", self.text.lower())
        self.assertNotIn("cd ~/ai-guardrails", self.text)
        self.assertNotRegex(self.text, r"cd\s+~/")

    def test_update_command_skips_dependencies(self):
        self.assertIn("up -d --no-deps --build gateway nginx", self.text)
        self.assertNotIn("up -d --build gateway nginx", self.text)
        self.assertIn("--no-deps", self.text)
        lower = self.text.lower()
        self.assertIn("database", lower)
        self.assertIn("prerequisite", lower)


if __name__ == "__main__":
    unittest.main()
