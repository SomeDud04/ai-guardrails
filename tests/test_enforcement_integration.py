"""Assembled-path enforcement checks.

These tests exercise the real FastAPI ASGI application, the strict YAML policy
loader, the in-process ``Gateway``, ``RealGatewayAdapters`` and a real
``GenerationClient`` against a loopback HTTP fixture.  Audit uses real SQLite
writes; only the production ``PostgresAuditStore`` constructor is replaced.

Guard and tokenizer verdicts are explicit deterministic doubles.  Nothing here
is evidence of native classifier quality, and no live endpoint is contacted.
"""

import contextlib
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from nasi_lemak import server as server_module
from nasi_lemak.audit import AuditError, SqliteAuditStore
from nasi_lemak.generation import (
    AUTH_NONE,
    ENV_AUTH,
    ENV_MODEL,
    ENV_TIMEOUT,
    ENV_URL,
    GenerationClient,
    GenerationConfig,
    RealGatewayAdapters,
)
from nasi_lemak.guards import GuardError
from nasi_lemak.server import make_app

APP_KEY = "integration-app-key-not-real"
APP_KEY_DIGEST = hashlib.sha256(APP_KEY.encode("utf-8")).hexdigest()
UPSTREAM_MODEL = "upstream-model-42"
POLICY_VERSION = "2026-10-20.1"
DENY_PHRASE = "synthetic denied phrase"
SENTINEL = "UPSTREAM-RAW-SENTINEL"


def _chat_reply(content, *, finish="stop"):
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 0,
        "model": UPSTREAM_MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish,
            }
        ],
    }


def _reply(payload=None, *, status=200, raw=None, delay=0.0, headers=None):
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    return (
        delay,
        status,
        headers if headers is not None else {"Content-Type": "application/json"},
        body,
    )


def _header(request, name):
    for key, value in request["headers"].items():
        if key.lower() == name.lower():
            return value
    return None


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length else 0
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        self.server.requests.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            }
        )
        delay, status, headers, payload = self.server.replies.pop(0)
        if delay:
            time.sleep(delay)
        self.close_connection = True
        try:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except ConnectionError:
            pass


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Tokenizer:
    """Deterministic character counter, never a model tokenizer."""

    def __init__(self, *, count=None, error=None):
        self.count = count
        self.error = error
        self.calls = []

    def count_tokens(self, serialized):
        self.calls.append(serialized)
        if self.error is not None:
            raise self.error
        if self.count is not None:
            return self.count
        return len(serialized)


class _AttackGuard:
    """Deterministic attack verdict double."""

    def __init__(self, *, result=None, error=None):
        self.result = {"decision": "allow"} if result is None else result
        self.error = error
        self.calls = []

    def scan_attack(self, text):
        self.calls.append(text)
        if self.error is not None:
            raise self.error
        return self.result


class _OutputGuard:
    """Deterministic contextual output verdict double with call capture."""

    def __init__(self, *, safe=True, result=None, error=None):
        self.safe = safe
        self.result = result
        self.error = error
        self.calls = []

    def scan_response(self, messages, output):
        self.calls.append(([dict(message) for message in messages], output))
        if self.error is not None:
            raise self.error
        if self.result is not None:
            return dict(self.result)
        return {"safe": self.safe}


class _ReadOnlyAuditStore(SqliteAuditStore):
    """Real SQLite store whose runtime writes hit a read-only connection."""

    def __init__(self, path):
        super().__init__(path)
        self.read_only = True

    @contextlib.contextmanager
    def _connection(self):
        if not getattr(self, "read_only", False):
            with super()._connection() as db:
                yield db
            return
        with self._lock:
            try:
                connection = sqlite3.connect(
                    f"file:{self.path.as_posix()}?mode=ro",
                    uri=True,
                    timeout=self.connect_timeout,
                )
            except sqlite3.Error as exc:
                raise AuditError("audit database unavailable") from exc
            try:
                yield connection
            finally:
                connection.close()


class _TerminalWriteFailureAuditStore(SqliteAuditStore):
    """Initial write succeeds; the terminal write uses a read-only connection."""

    def record_terminal(self, *args, **kwargs):
        self.read_only = True
        return super().record_terminal(*args, **kwargs)

    @contextlib.contextmanager
    def _connection(self):
        if not getattr(self, "read_only", False):
            with super()._connection() as db:
                yield db
            return
        with self._lock:
            connection = sqlite3.connect(
                f"file:{self.path.as_posix()}?mode=ro",
                uri=True,
                timeout=self.connect_timeout,
            )
            try:
                yield connection
            finally:
                connection.close()


class EnforcementIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.policy_path = self.root / "policy.yaml"
        self._write_policy(256)

    # -- fixtures ---------------------------------------------------------

    def _write_policy(self, budget):
        self.policy_path.write_text(
            "app_id: nasi-lemak\n"
            f'version: "{POLICY_VERSION}"\n'
            "model: pilot-local\n"
            f"token_budget: {budget}\n"
            "deny_phrases:\n"
            f'  - "{DENY_PHRASE}"\n',
            encoding="utf-8",
        )

    def _start_upstream(self, *replies):
        httpd = _FixtureServer(("127.0.0.1", 0), _UpstreamHandler)
        httpd.requests = []
        httpd.replies = list(replies) or [_reply(_chat_reply("Synthetic answer."))]
        thread = threading.Thread(
            target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True
        )
        thread.start()

        def cleanup():
            httpd.shutdown()
            thread.join(timeout=2)
            httpd.server_close()

        self.addCleanup(cleanup)
        return httpd

    def _generation_env(self, httpd, *, timeout=2.0):
        return {
            ENV_URL: f"http://127.0.0.1:{httpd.server_address[1]}/v1",
            ENV_MODEL: UPSTREAM_MODEL,
            ENV_AUTH: AUTH_NONE,
            ENV_TIMEOUT: str(timeout),
            "NASI_LEMAK_POLICY_FILE": str(self.policy_path),
        }

    def _make(
        self,
        httpd,
        *,
        policy_budget=256,
        tokenizer=None,
        attack=None,
        output=None,
        timeout=2.0,
        store_factory=None,
    ):
        self._write_policy(policy_budget)
        env = self._generation_env(httpd, timeout=timeout)
        tokenizer = tokenizer if tokenizer is not None else _Tokenizer()
        attack = attack if attack is not None else _AttackGuard()
        output = output if output is not None else _OutputGuard()
        client = GenerationClient(GenerationConfig.from_env(env))
        adapters = RealGatewayAdapters(
            client,
            tokenizer=tokenizer,
            attack_guard=attack,
            output_guard=output,
        )
        audit_path = self.root / f"audit-{uuid.uuid4().hex}.sqlite3"
        if store_factory is None:

            def store_factory(_dsn):
                return SqliteAuditStore(audit_path)

        with patch.object(server_module, "PostgresAuditStore", new=store_factory):
            app = make_app(
                environ=env,
                app_key_digest=APP_KEY_DIGEST,
                audit_dsn="postgresql://synthetic-audit/none",
                adapters=adapters,
            )
        self.assertTrue(app.state.config_ready)
        self.assertEqual(app.state.policy_activation, "yaml-policy")
        self.assertEqual(app.state.policy_version, POLICY_VERSION)
        test_client = TestClient(app)
        self.addCleanup(test_client.close)
        return test_client, adapters, app.state.gateway

    @staticmethod
    def _auth():
        return {"Authorization": f"Bearer {APP_KEY}"}

    @staticmethod
    def _body(messages, **extra):
        body = {"model": "pilot-local", "messages": messages}
        body.update(extra)
        return body

    def _post(self, client, payload, headers=None):
        headers = self._auth() if headers is None else headers
        if isinstance(payload, bytes):
            return client.post(
                "/v1/chat/completions",
                content=payload,
                headers={**headers, "Content-Type": "application/json"},
            )
        return client.post("/v1/chat/completions", json=payload, headers=headers)

    def _assert_metadata_only(self, events, *, gateway):
        self.assertTrue(events)
        digest = gateway.policy.digest
        for event in events:
            self.assertEqual(event["app_id"], "nasi-lemak")
            self.assertEqual(event["model"], "pilot-local")
            self.assertEqual(event["policy_version"], POLICY_VERSION)
            self.assertEqual(event["policy_digest"], digest)
            self.assertEqual(len(event["policy_digest"]), 64)
        blob = json.dumps(events)
        for secret in (
            "synthetic.user@example.com",
            "+60123456789",
            "901234-56-7890",
            APP_KEY,
            UPSTREAM_MODEL,
            SENTINEL,
            "Synthetic answer.",
        ):
            self.assertNotIn(secret, blob)
        self.assertNotIn("[EMAIL]", blob)
        self.assertNotIn("[MYKAD]", blob)

    # -- success path -----------------------------------------------------

    def test_success_path_masks_pii_guards_and_audits_metadata_only(self):
        email = "synthetic.user@example.com"
        phone = "+60123456789"
        mykad = "901234-56-7890"
        generated = f"reply to {email} or {phone}; id {mykad}"
        httpd = self._start_upstream(_reply(_chat_reply(generated)))
        attack = _AttackGuard()
        output = _OutputGuard()
        client, _adapters, gateway = self._make(
            httpd, attack=attack, output=output
        )
        messages = [
            {"role": "system", "content": f"policy contact {email}"},
            {"role": "user", "content": f"call me on {phone}"},
            {"role": "assistant", "content": f"my id is {mykad}"},
        ]

        response = self._post(client, self._body(messages), self._auth())

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(httpd.requests), 1)
        captured = httpd.requests[0]
        payload = json.loads(captured["body"])
        self.assertEqual(payload["model"], UPSTREAM_MODEL)
        self.assertIsNone(_header(captured, "Authorization"))
        raw_request = captured["body"].decode("utf-8")
        for secret in (email, phone, mykad):
            self.assertNotIn(secret, raw_request)
        for mask in ("[EMAIL]", "[MY_PHONE]", "[MYKAD]"):
            self.assertIn(mask, raw_request)
        sanitized = [
            {"role": "system", "content": "policy contact [EMAIL]"},
            {"role": "user", "content": "call me on [MY_PHONE]"},
            {"role": "assistant", "content": "my id is [MYKAD]"},
        ]
        self.assertEqual(payload["messages"], sanitized)

        # The attack guard sees the complete original conversation.
        self.assertEqual(
            attack.calls,
            [
                "system: policy contact "
                + email
                + "\nuser: call me on "
                + phone
                + "\nassistant: my id is "
                + mykad
            ],
        )
        # The contextual output guard sees sanitized context plus raw output.
        self.assertEqual(len(output.calls), 1)
        context, seen_output = output.calls[0]
        self.assertEqual(context, sanitized)
        self.assertEqual(seen_output, generated)

        choice = response.json()["choices"][0]["message"]["content"]
        self.assertEqual(choice, "reply to [EMAIL] or [MY_PHONE]; id [MYKAD]")
        self.assertEqual(response.json()["model"], "pilot-local")

        events = gateway.audit_events()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_completed"],
        )
        self.assertEqual(events[1]["decision"], "allowed")
        self._assert_metadata_only(events, gateway=gateway)

        # Success control: the assembled system is not permanently blocked.
        self.assertIn("choices", response.json())

    def test_email_before_terminal_period_survives_assembled_masking(self):
        # Regression for the caller-review privacy gap: an email followed by a
        # sentence period must be masked before the real HTTP transport, while
        # the period and surrounding punctuation stay in the client text.
        email = "synthetic.user@example.invalid"
        generated = f"reply to {email}."
        httpd = self._start_upstream(_reply(_chat_reply(generated)))
        attack = _AttackGuard()
        output = _OutputGuard()
        client, _adapters, gateway = self._make(
            httpd, attack=attack, output=output
        )
        messages = [
            {"role": "system", "content": f"policy contact {email}."},
            {"role": "user", "content": f"ask {email}?"},
            {"role": "assistant", "content": f"prior reply {email},"},
        ]

        response = self._post(client, self._body(messages), self._auth())

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(httpd.requests), 1)
        captured = httpd.requests[0]
        raw_request = captured["body"].decode("utf-8")
        self.assertNotIn(email, raw_request)
        self.assertIn("[EMAIL]", raw_request)
        # The sentence period and other punctuation are retained, not masked.
        self.assertIn("policy contact [EMAIL].", raw_request)
        self.assertIn("ask [EMAIL]?", raw_request)

        sanitized = [
            {"role": "system", "content": "policy contact [EMAIL]."},
            {"role": "user", "content": "ask [EMAIL]?"},
            {"role": "assistant", "content": "prior reply [EMAIL],"},
        ]
        self.assertEqual(json.loads(captured["body"])["messages"], sanitized)

        # The attack guard still sees the complete original all-role input.
        self.assertEqual(
            attack.calls,
            [
                f"system: policy contact {email}."
                f"\nuser: ask {email}?"
                f"\nassistant: prior reply {email},"
            ],
        )
        # The output guard sees the sanitized context and the raw buffered reply.
        self.assertEqual(len(output.calls), 1)
        context, seen_output = output.calls[0]
        self.assertEqual(context, sanitized)
        self.assertEqual(seen_output, generated)

        choice = response.json()["choices"][0]["message"]["content"]
        self.assertEqual(choice, "reply to [EMAIL].")

        events = gateway.audit_events()
        self.assertEqual(
            [event["event_type"] for event in events],
            ["request_started", "request_completed"],
        )
        self.assertEqual(events[1]["decision"], "allowed")
        self.assertNotIn(email, json.dumps(events))
        self._assert_metadata_only(events, gateway=gateway)

    def test_exact_token_boundary_allows_full_content_and_rejects_one_over(self):
        httpd = self._start_upstream(_reply(_chat_reply("ok")))
        tokenizer = _Tokenizer()
        client, _adapters, _gateway = self._make(
            httpd, policy_budget=64, tokenizer=tokenizer
        )
        prefix = len("user: ")
        boundary = "a" * (64 - prefix)
        response = self._post(
            client, self._body([{"role": "user", "content": boundary}])
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(httpd.requests), 1)
        payload = json.loads(httpd.requests[0]["body"])
        self.assertEqual(payload["messages"][0]["content"], boundary)
        self.assertEqual(len(payload["messages"][0]["content"]), 64 - prefix)

        over = "a" * (64 - prefix + 1)
        response = self._post(client, self._body([{"role": "user", "content": over}]))
        self.assertEqual(response.status_code, 413, response.text)
        self.assertEqual(response.json()["error"]["code"], "INPUT_LIMIT")
        self.assertEqual(len(httpd.requests), 1)

    # -- pre-generation rejections ---------------------------------------

    def test_pre_generation_rejections_never_contact_upstream(self):
        hello = [{"role": "user", "content": "hello"}]
        base = self._body(hello)
        cases = [
            (
                "wrong_auth",
                base,
                {"Authorization": "Bearer wrong-key"},
                401,
                "UNAUTHORIZED",
                None,
                None,
            ),
            (
                "unknown_field",
                {**base, "temperature": 0},
                None,
                400,
                "INVALID_REQUEST",
                None,
                None,
            ),
            (
                "unknown_model",
                {**base, "model": "other-model"},
                None,
                400,
                "INVALID_REQUEST",
                None,
                None,
            ),
            (
                "policy_override",
                {**base, "token_budget": 1},
                None,
                400,
                "INVALID_REQUEST",
                None,
                None,
            ),
            (
                "stream_unsupported",
                {**base, "stream": True},
                None,
                400,
                "INVALID_REQUEST",
                None,
                None,
            ),
            (
                "tools_unsupported",
                {**base, "tools": []},
                None,
                400,
                "INVALID_REQUEST",
                None,
                None,
            ),
            (
                "malformed_json",
                b'{"model":',
                None,
                400,
                "INVALID_REQUEST",
                None,
                None,
            ),
            (
                "duplicate_keys",
                (
                    b'{"model":"pilot-local","model":"pilot-local",'
                    b'"messages":[{"role":"user","content":"hello"}]}'
                ),
                None,
                400,
                "INVALID_REQUEST",
                None,
                None,
            ),
            (
                "character_overflow",
                self._body([{"role": "user", "content": "a" * 4091}]),
                None,
                413,
                "INPUT_LIMIT",
                None,
                None,
            ),
            (
                "token_count_invalid_bool",
                base,
                None,
                503,
                "UNAVAILABLE",
                _Tokenizer(count=True),
                None,
            ),
            (
                "token_count_error",
                base,
                None,
                503,
                "UNAVAILABLE",
                _Tokenizer(error=RuntimeError("tokenizer unavailable")),
                None,
            ),
            (
                "attack_block",
                base,
                None,
                403,
                "POLICY_BLOCK",
                None,
                _AttackGuard(result={"decision": "block"}),
            ),
            (
                "attack_malformed",
                base,
                None,
                503,
                "UNAVAILABLE",
                None,
                _AttackGuard(result={"decision": "maybe"}),
            ),
            (
                "attack_exception",
                base,
                None,
                503,
                "UNAVAILABLE",
                None,
                _AttackGuard(error=GuardError("guard inference failed")),
            ),
        ]
        for role in ("system", "user", "assistant"):
            cases.append(
                (
                    f"deny_phrase_{role}",
                    self._body([{"role": role, "content": f"please {DENY_PHRASE}"}]),
                    None,
                    403,
                    "POLICY_BLOCK",
                    None,
                    None,
                )
            )
        # A low budget is used for the token-overflow case but other cases must
        # still succeed up to their intended rejection stage.
        for (
            name,
            payload,
            headers,
            status,
            code,
            tokenizer,
            attack,
        ) in cases:
            with self.subTest(case=name):
                httpd = self._start_upstream()
                client, _adapters, gateway = self._make(
                    httpd, tokenizer=tokenizer, attack=attack
                )
                response = self._post(client, payload, headers)
                self.assertEqual(response.status_code, status, response.text)
                self.assertEqual(response.json()["error"]["code"], code)
                self.assertEqual(httpd.requests, [], name)
                blob = json.dumps(gateway.audit_events())
                self.assertNotIn("hello", blob)
                self.assertNotIn(DENY_PHRASE, blob)

        # Token overflow is a distinct pre-generation rejection.
        with self.subTest(case="token_overflow"):
            httpd = self._start_upstream()
            client, _adapters, _gateway = self._make(httpd, policy_budget=64)
            response = self._post(
                client,
                self._body([{"role": "user", "content": "a" * 200}]),
            )
            self.assertEqual(response.status_code, 413, response.text)
            self.assertEqual(response.json()["error"]["code"], "INPUT_LIMIT")
            self.assertEqual(httpd.requests, [])

        # Success control: a valid request still reaches the upstream fixture.
        with self.subTest(case="success_control"):
            httpd = self._start_upstream(_reply(_chat_reply("ok")))
            client, _adapters, _gateway = self._make(httpd)
            response = self._post(client, base)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(len(httpd.requests), 1)

    # -- post-generation failures ----------------------------------------

    def test_output_and_generation_failures_release_nothing(self):
        messages = [{"role": "user", "content": "hello"}]
        cases = [
            (
                "output_unsafe",
                _reply(_chat_reply(SENTINEL)),
                _OutputGuard(safe=False),
                403,
                "POLICY_BLOCK",
                2.0,
            ),
            (
                "output_malformed",
                _reply(_chat_reply(SENTINEL)),
                _OutputGuard(result={"safe": "yes"}),
                503,
                "UNAVAILABLE",
                2.0,
            ),
            (
                "output_exception",
                _reply(_chat_reply(SENTINEL)),
                _OutputGuard(error=GuardError("guard inference failed")),
                503,
                "UNAVAILABLE",
                2.0,
            ),
            (
                "output_literal_denial",
                _reply(_chat_reply(f"answer {DENY_PHRASE}")),
                _OutputGuard(),
                403,
                "POLICY_BLOCK",
                2.0,
            ),
            (
                "generation_malformed",
                _reply(raw=b'{"choices": []}'),
                _OutputGuard(),
                503,
                "UNAVAILABLE",
                2.0,
            ),
            (
                "generation_http_500",
                _reply(raw=b"upstream error", status=500),
                _OutputGuard(),
                503,
                "UNAVAILABLE",
                2.0,
            ),
            (
                "generation_non_json",
                _reply(raw=b"not-json"),
                _OutputGuard(),
                503,
                "UNAVAILABLE",
                2.0,
            ),
            (
                "generation_truncated",
                _reply(_chat_reply(SENTINEL, finish="length")),
                _OutputGuard(),
                503,
                "UNAVAILABLE",
                2.0,
            ),
            (
                "generation_timeout",
                _reply(_chat_reply(SENTINEL), delay=0.8),
                _OutputGuard(),
                503,
                "UNAVAILABLE",
                0.2,
            ),
        ]
        for name, reply, output, status, code, timeout in cases:
            with self.subTest(case=name):
                httpd = self._start_upstream(reply)
                client, _adapters, gateway = self._make(
                    httpd, output=output, timeout=timeout
                )
                started = time.monotonic()
                response = self._post(client, self._body(messages))
                elapsed = time.monotonic() - started
                self.assertEqual(response.status_code, status, response.text)
                self.assertEqual(response.json()["error"]["code"], code)
                self.assertNotIn("choices", response.json())
                self.assertNotIn(SENTINEL, response.text)
                self.assertNotIn(DENY_PHRASE, response.text)
                # Exactly one request, i.e. no transport retry.
                self.assertEqual(len(httpd.requests), 1)
                self.assertLess(elapsed, 3.0)
                events = gateway.audit_events()
                self.assertEqual(events[0]["event_type"], "request_started")
                expected = (
                    "request_blocked"
                    if status == 403
                    else "request_failed"
                )
                self.assertEqual(events[-1]["event_type"], expected)
                self._assert_metadata_only(events, gateway=gateway)

    def test_initial_audit_write_failure_never_reaches_upstream(self):
        httpd = self._start_upstream()
        path = self.root / f"readonly-{uuid.uuid4().hex}.sqlite3"
        client, _adapters, gateway = self._make(
            httpd, store_factory=lambda _dsn: _ReadOnlyAuditStore(path)
        )
        response = self._post(
            client, self._body([{"role": "user", "content": "hello"}])
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertEqual(httpd.requests, [])
        self.assertEqual(gateway.audit_events(), [])

    def test_terminal_audit_write_failure_withholds_released_output(self):
        httpd = self._start_upstream(_reply(_chat_reply(SENTINEL)))
        path = self.root / f"terminal-{uuid.uuid4().hex}.sqlite3"
        client, _adapters, gateway = self._make(
            httpd, store_factory=lambda _dsn: _TerminalWriteFailureAuditStore(path)
        )
        response = self._post(
            client, self._body([{"role": "user", "content": "hello"}])
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(response.json()["error"]["code"], "UNAVAILABLE")
        self.assertNotIn("choices", response.json())
        self.assertNotIn(SENTINEL, response.text)
        # Generation already happened, so exactly one upstream request exists.
        self.assertEqual(len(httpd.requests), 1)
        events = gateway.audit_events()
        self.assertEqual([event["event_type"] for event in events], ["request_started"])


if __name__ == "__main__":
    unittest.main()
