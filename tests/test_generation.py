import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nasi_lemak import generation_cli
from nasi_lemak.gateway import MemoryAdapters
from nasi_lemak.generation import (
    AUTH_NONE,
    ENV_ALLOW_INSECURE_HTTP,
    ENV_API_KEY,
    ENV_AUTH,
    ENV_CA_FILE,
    ENV_MAX_RESPONSE_BYTES,
    ENV_MODEL,
    ENV_TIMEOUT,
    ENV_URL,
    GenerationClient,
    GenerationConfig,
    GenerationConfigError,
    GenerationError,
    RealGatewayAdapters,
    make_real_gateway,
)

KEY = "unit-test-key-not-real"


def chat_payload(content="safe answer", *, finish="stop", message_extra=None, choices=None):
    message = {"role": "assistant", "content": content}
    if message_extra:
        message.update(message_extra)
    choice = {"index": 0, "message": message, "finish_reason": finish}
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 0,
        "model": "upstream-model-1",
        "choices": choices if choices is not None else [choice],
    }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _handle(self):
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
        if self.server.delay:
            time.sleep(self.server.delay)
        status, headers, response_body = self.server.reply
        self.close_connection = True
        try:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
        except ConnectionError:
            pass

    do_GET = _handle
    do_POST = _handle


class _FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def header(request, name):
    for key, value in request["headers"].items():
        if key.lower() == name.lower():
            return value
    return None


class FixtureMixin(unittest.TestCase):
    def start_server(self, status=200, body=None, headers=None, delay=0):
        httpd = _FixtureServer(("127.0.0.1", 0), _Handler)
        httpd.requests = []
        httpd.delay = delay
        httpd.reply = (
            status,
            headers if headers is not None else {"Content-Type": "application/json"},
            body if body is not None else json.dumps(chat_payload()).encode("utf-8"),
        )
        thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()

        def cleanup():
            httpd.shutdown()
            thread.join(timeout=2)
            httpd.server_close()

        self.addCleanup(cleanup)
        return httpd

    @property
    def base(self):
        raise NotImplementedError

    def config(self, httpd, path="/v1", **overrides):
        values = {
            "url": f"http://127.0.0.1:{httpd.server_address[1]}{path}",
            "model": "upstream-model-1",
            "api_key": KEY,
        }
        values.update(overrides)
        return GenerationConfig(**values)

    def set_json(self, httpd, payload):
        httpd.reply = (200, {"Content-Type": "application/json"}, json.dumps(payload).encode("utf-8"))


class ConfigTests(FixtureMixin):
    def test_missing_and_invalid_configuration_fail_without_network(self):
        with self.assertRaises(GenerationConfigError):
            GenerationConfig.from_env({})
        with self.assertRaises(GenerationConfigError):
            GenerationConfig.from_env({ENV_URL: "https://host/v1", ENV_MODEL: "m"})
        with self.assertRaises(GenerationConfigError):
            GenerationConfig.from_env({ENV_URL: "https://host/v1", ENV_AUTH: "basic", ENV_API_KEY: KEY})
        without_model = GenerationConfig.from_env({ENV_URL: "https://host/v1", ENV_API_KEY: KEY})
        self.assertEqual(without_model.model, "")
        with self.assertRaises(GenerationConfigError):
            GenerationClient(without_model).generate([{"role": "user", "content": "x"}], 8)
        auth_none = GenerationConfig.from_env({ENV_URL: "https://host/v1", ENV_AUTH: AUTH_NONE})
        self.assertIsNone(auth_none.api_key)
        self.assertFalse(auth_none.safe_summary()["api_key_configured"])

    def test_auth_none_ignores_a_stale_key_and_bearer_still_requires_one(self):
        stale = "stale-key-must-not-be-sent"
        config = GenerationConfig.from_env(
            {ENV_URL: "http://127.0.0.1:8000/v1", ENV_AUTH: AUTH_NONE, ENV_API_KEY: stale},
        )
        self.assertEqual(config.auth_mode, AUTH_NONE)
        self.assertIsNone(config.api_key)
        self.assertNotIn(stale, repr(config))
        self.assertNotIn(stale, json.dumps(config.safe_summary()))
        with self.assertRaises(GenerationConfigError):
            GenerationConfig(url="https://host/v1", model="m")
        with self.assertRaises(GenerationConfigError):
            GenerationConfig(url="https://host/v1", model="m", api_key="")
        with self.assertRaises(GenerationConfigError):
            GenerationConfig(url="https://host/v1", model="m", api_key=KEY, auth_mode="basic")

    def test_url_validation_rejects_unsafe_forms_and_allows_loopback_http(self):
        invalid = [
            "https://user:pass@host/v1",
            "https://host/v1?token=x",
            "https://host/v1#fragment",
            "http://example.com/v1",
            "ftp://host/v1",
            "https://host/v1/chat/completions",
            "https://host/v1/models",
            "https://host/v1%0aInjected: yes",
            "https://host/v1\\extra",
            "https://host/v1/with space",
            " https://host/v1",
        ]
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(GenerationConfigError):
                    GenerationConfig(url=url, model="m", api_key=KEY)
        loopback = GenerationConfig(url="http://127.0.0.1:8000/prefix/v1", model="m", api_key=KEY)
        self.assertEqual(loopback.chat_completions_url, "http://127.0.0.1:8000/prefix/v1/chat/completions")
        self.assertEqual(loopback.models_url, "http://127.0.0.1:8000/prefix/v1/models")
        localhost = GenerationConfig(url="http://localhost:8000/v1", model="m", api_key=KEY)
        self.assertEqual(localhost.api_base, "http://localhost:8000/v1")

    def test_non_loopback_http_requires_explicit_opt_in_without_weakening_https(self):
        endpoint = "http://82haf69n.flexinfra.com.my/v1/"
        with self.assertRaises(GenerationConfigError):
            GenerationConfig(url=endpoint, model="m", api_key=KEY)
        with self.assertRaises(GenerationConfigError):
            GenerationConfig.from_env(
                {ENV_URL: endpoint, ENV_MODEL: "m", ENV_API_KEY: KEY, ENV_ALLOW_INSECURE_HTTP: "yes"}
            )
        config = GenerationConfig.from_env(
            {
                ENV_URL: endpoint,
                ENV_AUTH: AUTH_NONE,
                ENV_ALLOW_INSECURE_HTTP: "true",
            }
        )
        self.assertTrue(config.allow_insecure_http)
        self.assertEqual(config.api_base, "http://82haf69n.flexinfra.com.my/v1")
        self.assertEqual(
            config.chat_completions_url,
            "http://82haf69n.flexinfra.com.my/v1/chat/completions",
        )
        self.assertEqual(config.models_url, "http://82haf69n.flexinfra.com.my/v1/models")
        self.assertNotIn("/v1/v1", config.chat_completions_url)
        # The opt-in only relaxes the HTTP scheme rule; other URL safety checks stay on.
        for url in ("http://user:pass@82haf69n.flexinfra.com.my/v1", "http://82haf69n.flexinfra.com.my/v1/models"):
            with self.subTest(url=url):
                with self.assertRaises(GenerationConfigError):
                    GenerationConfig(
                        url=url,
                        model="m",
                        api_key=KEY,
                        allow_insecure_http=True,
                    )
        secure = GenerationConfig(url="https://host/v1", model="m", api_key=KEY, allow_insecure_http=True)
        self.assertTrue(secure.chat_completions_url.startswith("https://"))

    def test_identifiers_and_bounds_reject_injection(self):
        blank = GenerationConfig(url="http://127.0.0.1:8000/v1", model="", api_key=KEY)
        self.assertEqual(blank.model, "")
        for model in (" ", "model\r\nX: y", "model\x00"):
            with self.subTest(model=model):
                with self.assertRaises(GenerationConfigError):
                    GenerationConfig(url="http://127.0.0.1:8000/v1", model=model, api_key=KEY)
        for key in ("", " ", KEY + "\r\nX: y", KEY + "\x00", "key with spaces", "k\u00e9y"):
            with self.subTest(key=key):
                with self.assertRaises(GenerationConfigError):
                    GenerationConfig(url="http://127.0.0.1:8000/v1", model="m", api_key=key)
        for timeout in (0, -1, True, float("nan"), float("inf"), 601):
            with self.subTest(timeout=timeout):
                with self.assertRaises(GenerationConfigError):
                    GenerationConfig(url="http://127.0.0.1:8000/v1", model="m", api_key=KEY, timeout=timeout)
        for maximum in (0, True, 1023, 4 * 1024 * 1024 + 1):
            with self.subTest(maximum=maximum):
                with self.assertRaises(GenerationConfigError):
                    GenerationConfig(url="http://127.0.0.1:8000/v1", model="m", api_key=KEY, max_response_bytes=maximum)

    def test_environment_settings_and_secret_safe_repr(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp, "ca.pem")
            ca.write_text("not a real certificate", encoding="utf-8")
            env = {
                ENV_URL: "https://host.example/openai/v1/",
                ENV_MODEL: "exact-upstream-id",
                ENV_API_KEY: KEY,
                ENV_TIMEOUT: "12.5",
                ENV_MAX_RESPONSE_BYTES: "4096",
                ENV_CA_FILE: str(ca),
            }
            config = GenerationConfig.from_env(env)
        self.assertEqual(config.api_base, "https://host.example/openai/v1")
        self.assertEqual(config.model, "exact-upstream-id")
        self.assertEqual(config.timeout, 12.5)
        self.assertEqual(config.max_response_bytes, 4096)
        self.assertNotIn(KEY, repr(config))
        self.assertNotIn(KEY, str(config))
        self.assertNotIn(KEY, json.dumps(config.safe_summary()))

    def test_invalid_environment_values_are_rejected(self):
        base = {ENV_URL: "https://host/v1", ENV_MODEL: "m", ENV_API_KEY: KEY}
        for name, value in ((ENV_TIMEOUT, "0"), (ENV_TIMEOUT, "nan"), (ENV_MAX_RESPONSE_BYTES, "12"), (ENV_CA_FILE, "Z:/missing/ca.pem")):
            with self.subTest(name=name, value=value):
                env = dict(base)
                env[name] = value
                with self.assertRaises(GenerationConfigError):
                    GenerationConfig.from_env(env)

    def test_malformed_ca_file_fails_client_construction(self):
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp, "ca.pem")
            ca.write_text("not a certificate", encoding="utf-8")
            config = GenerationConfig(url="https://host/v1", model="m", api_key=KEY, ca_file=str(ca))
            with self.assertRaises(GenerationConfigError):
                GenerationClient(config)


class TransportTests(FixtureMixin):
    def test_request_uses_prefix_headers_and_exact_payload(self):
        httpd = self.start_server()
        client = GenerationClient(self.config(httpd, path="/prefix/openai/v1"))
        content = client.generate([{"role": "user", "content": "hello"}], 17)
        self.assertEqual(content, "safe answer")
        self.assertEqual(len(httpd.requests), 1)
        request = httpd.requests[0]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["path"], "/prefix/openai/v1/chat/completions")
        self.assertEqual(header(request, "Authorization"), "Bearer " + KEY)
        self.assertEqual(header(request, "Content-Type"), "application/json")
        self.assertEqual(header(request, "Accept"), "application/json")
        self.assertEqual(
            json.loads(request["body"]),
            {
                "model": "upstream-model-1",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 17,
                "stream": False,
            },
        )

    def test_auth_none_omits_authorization_header_even_with_stale_key(self):
        httpd = self.start_server()
        config = self.config(
            httpd,
            api_key="stale-key-must-not-be-sent",
            auth_mode=AUTH_NONE,
        )
        client = GenerationClient(config)
        client.generate([{"role": "user", "content": "hello"}], 8)
        self.assertIsNone(header(httpd.requests[0], "Authorization"))
        self.assertNotIn("stale-key-must-not-be-sent", httpd.requests[0]["body"].decode("utf-8"))
        self.assertNotIn("stale-key-must-not-be-sent", json.dumps(client.config.safe_summary()))

    def test_model_listing_does_not_require_a_generation_model(self):
        httpd = self.start_server()
        self.set_json(httpd, {"data": [{"id": "alpha"}, {"id": "beta"}]})
        client = GenerationClient(self.config(httpd, model="", api_key=None, auth_mode=AUTH_NONE))
        self.assertEqual(client.list_models(), ["alpha", "beta"])
        self.assertEqual(httpd.requests[-1]["path"], "/v1/models")
        self.assertIsNone(header(httpd.requests[-1], "Authorization"))
        with self.assertRaises(GenerationConfigError):
            client.generate([{"role": "user", "content": "hello"}], 8)
        self.assertEqual(len(httpd.requests), 1)

    def test_base_path_with_v1_is_not_duplicated(self):
        httpd = self.start_server()
        client = GenerationClient(self.config(httpd, path="/v1"))
        client.generate([{"role": "user", "content": "x"}], 8)
        self.assertEqual(httpd.requests[0]["path"], "/v1/chat/completions")
        self.assertNotIn("/v1/v1", httpd.requests[0]["path"])

    def test_malformed_or_unsupported_completions_are_rejected(self):
        httpd = self.start_server()
        client = GenerationClient(self.config(httpd))
        cases = {
            "non-object": [],
            "empty choices": {"choices": []},
            "two choices": chat_payload(choices=[chat_payload()["choices"][0], chat_payload()["choices"][0]]),
            "truncated": chat_payload(finish="length"),
            "missing finish": chat_payload(finish=None),
            "missing content": chat_payload(content=None),
            "blank content": chat_payload(content="  "),
            "non-string content": chat_payload(content=42),
            "wrong role": {"choices": [{"index": 0, "message": {"role": "user", "content": "x"}, "finish_reason": "stop"}]},
            "tools": chat_payload(message_extra={"tool_calls": [{"id": "x"}]}),
            "function call": chat_payload(message_extra={"function_call": {"name": "x"}}),
            "refusal": chat_payload(content="", message_extra={"refusal": "not allowed"}),
            "error payload": {"error": {"message": "provider failure"}},
        }
        for label, payload in cases.items():
            with self.subTest(label=label):
                self.set_json(httpd, payload)
                with self.assertRaises(GenerationError) as caught:
                    client.generate([{"role": "user", "content": "hello"}], 8)
                self.assertNotIn(KEY, str(caught.exception))
                self.assertNotIn("provider failure", str(caught.exception))
        self.assertEqual(len(httpd.requests), len(cases))

    def test_http_error_does_not_echo_secret_or_prompt_and_is_not_retried(self):
        hidden_prompt = "prompt-content-that-must-not-leak"
        httpd = self.start_server(
            status=500,
            body=(KEY + " " + hidden_prompt).encode("utf-8"),
        )
        client = GenerationClient(self.config(httpd))
        with self.assertRaises(GenerationError) as caught:
            client.generate([{"role": "user", "content": hidden_prompt}], 8)
        message = str(caught.exception)
        self.assertNotIn(KEY, message)
        self.assertNotIn(hidden_prompt, message)
        self.assertIn("HTTP 500", message)
        self.assertEqual(len(httpd.requests), 1)

    def test_redirects_are_refused_without_forwarding_credentials(self):
        httpd = self.start_server(status=302, headers={"Location": "/other-endpoint"})
        client = GenerationClient(self.config(httpd))
        with self.assertRaises(GenerationError) as caught:
            client.generate([{"role": "user", "content": "x"}], 8)
        self.assertIn("redirect", str(caught.exception))
        self.assertEqual(len(httpd.requests), 1)
        self.assertEqual(httpd.requests[0]["path"], "/v1/chat/completions")
        self.assertNotIn("/other-endpoint", [request["path"] for request in httpd.requests])

    def test_timeout_is_bounded_and_generic(self):
        httpd = self.start_server(delay=0.4)
        client = GenerationClient(self.config(httpd, timeout=0.05))
        with self.assertRaises(GenerationError) as caught:
            client.generate([{"role": "user", "content": "x"}], 8)
        self.assertIn("timed out", str(caught.exception))
        self.assertNotIn(KEY, str(caught.exception))
        self.assertEqual(len(httpd.requests), 1)

    def test_oversized_invalid_json_and_invalid_utf8_are_rejected(self):
        httpd = self.start_server(body=b"x" * 2048)
        client = GenerationClient(self.config(httpd, max_response_bytes=1024))
        with self.assertRaises(GenerationError) as caught:
            client.generate([{"role": "user", "content": "x"}], 8)
        self.assertIn("size limit", str(caught.exception))

        self.set_json(httpd, {"unexpected": "shape"})
        httpd.reply = (200, {"Content-Type": "application/json"}, b"not json")
        with self.assertRaises(GenerationError):
            client.generate([{"role": "user", "content": "x"}], 8)
        httpd.reply = (200, {"Content-Type": "application/json"}, b"\xff\xfe\x00")
        with self.assertRaises(GenerationError):
            client.generate([{"role": "user", "content": "x"}], 8)
        self.assertEqual(len(httpd.requests), 3)

    def test_list_models_and_probe_return_metadata_only(self):
        httpd = self.start_server()
        self.set_json(httpd, {"data": [{"id": "beta"}, {"id": "alpha"}, {"id": "beta"}]})
        client = GenerationClient(self.config(httpd))
        self.assertEqual(client.list_models(), ["alpha", "beta"])
        request = httpd.requests[-1]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["path"], "/v1/models")
        self.assertEqual(request["body"], b"")
        self.assertEqual(header(request, "Authorization"), "Bearer " + KEY)

        probe_text = "PROBE-COMPLETION-MUST-NOT-APPEAR"
        self.set_json(httpd, chat_payload(probe_text))
        result = client.probe()
        self.assertTrue(result["ok"])
        self.assertEqual(result["upstream_model"], "upstream-model-1")
        self.assertNotIn(probe_text, json.dumps(result))
        self.assertNotIn(probe_text, repr(result))
        self.assertEqual(result["response_content"], "not_printed")
        payload = json.loads(httpd.requests[-1]["body"])
        self.assertEqual(payload["max_tokens"], 16)
        self.assertFalse(payload["stream"])

    def test_list_models_rejects_malformed_payloads(self):
        httpd = self.start_server()
        client = GenerationClient(self.config(httpd))
        for payload in ({"data": "nope"}, {"data": [{"id": ""}]}, {"data": [{"id": 7}]}, {"data": [{"name": "x"}]}):
            with self.subTest(payload=payload):
                self.set_json(httpd, payload)
                with self.assertRaises(GenerationError):
                    client.list_models()

    def test_invalid_generate_arguments_fail_before_transport(self):
        httpd = self.start_server()
        client = GenerationClient(self.config(httpd))
        for max_tokens in (0, -1, True, "8", 8193):
            with self.subTest(max_tokens=max_tokens):
                with self.assertRaises(ValueError):
                    client.generate([{"role": "user", "content": "x"}], max_tokens)
        for messages in ([], [{"role": "tool", "content": "x"}], [{"role": "user", "content": ""}], [{"role": "user", "content": "x", "name": "n"}]):
            with self.subTest(messages=messages):
                with self.assertRaises(ValueError):
                    client.generate(messages, 8)
        self.assertEqual(httpd.requests, [])

    def test_real_adapter_composition_requires_explicit_dependencies_and_fixed_alias(self):
        httpd = self.start_server()
        client = GenerationClient(self.config(httpd))
        tokenizer, attack, output = _Tokenizer(), _Attack(), _Output()
        for kwargs in (
            {"tokenizer": None, "attack_guard": attack, "output_guard": output},
            {"tokenizer": tokenizer, "attack_guard": None, "output_guard": output},
            {"tokenizer": tokenizer, "attack_guard": attack, "output_guard": None},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    RealGatewayAdapters(client, **kwargs)
        adapters = RealGatewayAdapters(client, tokenizer=tokenizer, attack_guard=attack, output_guard=output)
        with self.assertRaises(ValueError):
            adapters.generate([{"role": "user", "content": "x"}], "other-model", 8)
        self.assertEqual(httpd.requests, [])


class _Tokenizer:
    def __init__(self, count=1):
        self.count = count
        self.inputs = []

    def count_tokens(self, serialized):
        self.inputs.append(serialized)
        return self.count


class _Attack:
    def __init__(self, decision="allow"):
        self.decision = decision
        self.inputs = []

    def scan_attack(self, text):
        self.inputs.append(text)
        return {"decision": self.decision}


class _Output:
    def __init__(self, safe=True):
        self.safe = safe
        self.inputs = []

    def scan_output(self, text):
        self.inputs.append(text)
        return {"safe": self.safe}

    def scan_response(self, messages, text):
        # Fixture-only contextual seam: the verdict remains the test's, and
        # recording still proves the buffered output reached the guard.
        return self.scan_output(text)


def gateway_request(content="Hello"):
    return {"model": "pilot-local", "messages": [{"role": "user", "content": content}]}


class GatewayIntegrationTests(FixtureMixin):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, httpd, *, tokenizer=None, attack=None, output=None):
        client = GenerationClient(self.config(httpd))
        tokenizer = tokenizer if tokenizer is not None else _Tokenizer()
        attack = attack if attack is not None else _Attack()
        output = output if output is not None else _Output()
        gateway = make_real_gateway(
            "app-key",
            Path(self.tmp.name) / "audit.sqlite3",
            client,
            tokenizer=tokenizer,
            attack_guard=attack,
            output_guard=output,
        )
        return gateway, tokenizer, attack, output

    def call(self, gateway, content="Hello"):
        return gateway.handle(
            "POST",
            "/v1/chat/completions",
            {"Authorization": "Bearer app-key"},
            gateway_request(content),
        )

    def test_only_masked_text_reaches_real_transport_and_alias_maps_to_upstream(self):
        httpd = self.start_server(body=json.dumps(chat_payload("answer test@example.com")).encode("utf-8"))
        gateway, tokenizer, attack, output = self.build(httpd)
        status, response = self.call(gateway, "contact test@example.com")
        self.assertEqual(status, 200)
        self.assertNotIn("test@example.com", response["choices"][0]["message"]["content"])
        self.assertIn("test@example.com", attack.inputs[0])
        self.assertEqual(len(httpd.requests), 1)
        payload = json.loads(httpd.requests[0]["body"])
        self.assertEqual(payload["model"], "upstream-model-1")
        self.assertNotEqual(payload["model"], "pilot-local")
        self.assertFalse(payload["stream"])
        self.assertNotIn("test@example.com", json.dumps(payload["messages"]))
        self.assertIn("[EMAIL]", payload["messages"][0]["content"])
        self.assertEqual([event["event_type"] for event in gateway.audit_events()], ["request_started", "request_completed"])

    def test_guard_tokenizer_and_audit_failures_prevent_upstream_call(self):
        httpd = self.start_server()
        gateway, tokenizer, attack, output = self.build(httpd, attack=_Attack("block"))
        status, body = self.call(gateway)
        self.assertEqual(status, 403)
        self.assertNotIn("choices", body)
        self.assertEqual(httpd.requests, [])

        gateway, tokenizer, attack, output = self.build(httpd, tokenizer=_Tokenizer(True))
        status, body = self.call(gateway)
        self.assertEqual(status, 503)
        self.assertEqual(httpd.requests, [])

        gateway, tokenizer, attack, output = self.build(httpd)
        gateway.fail_audit_stage = "initial"
        status, body = self.call(gateway)
        self.assertEqual(status, 503)
        self.assertEqual(httpd.requests, [])

    def test_output_guard_failure_withholds_upstream_text(self):
        httpd = self.start_server(body=json.dumps(chat_payload("unsafe completion")).encode("utf-8"))
        gateway, _, _, output = self.build(httpd, output=_Output(False))
        status, body = self.call(gateway)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "POLICY_BLOCK")
        self.assertNotIn("unsafe completion", json.dumps(body))
        self.assertEqual(len(httpd.requests), 1)

    def test_missing_mandatory_adapters_cannot_build_or_call(self):
        httpd = self.start_server()
        client = GenerationClient(self.config(httpd))
        for kwargs in (
            {"tokenizer": None, "attack_guard": _Attack(), "output_guard": _Output()},
            {"tokenizer": _Tokenizer(), "attack_guard": None, "output_guard": _Output()},
            {"tokenizer": _Tokenizer(), "attack_guard": _Attack(), "output_guard": None},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    make_real_gateway("app-key", Path(self.tmp.name) / "x.sqlite3", client, **kwargs)
        with self.assertRaises(ValueError):
            make_real_gateway(
                "app-key",
                Path(self.tmp.name) / "x.sqlite3",
                MemoryAdapters(),
                tokenizer=_Tokenizer(),
                attack_guard=_Attack(),
                output_guard=_Output(),
            )
        self.assertEqual(httpd.requests, [])


class CliTests(FixtureMixin):
    def _run(self, argv, env):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = generation_cli.main(argv, environ=env)
        return code, output.getvalue()

    def test_default_config_check_makes_no_network_call_and_hides_key(self):
        httpd = self.start_server()
        env = {
            ENV_URL: f"http://127.0.0.1:{httpd.server_address[1]}/v1",
            ENV_MODEL: "upstream-model-1",
            ENV_API_KEY: KEY,
        }
        code, output = self._run([], env)
        self.assertEqual(code, 0)
        self.assertIn("config=valid", output)
        self.assertIn("network=not_performed", output)
        self.assertNotIn(KEY, output)
        self.assertEqual(httpd.requests, [])

    def test_missing_config_for_network_action_does_not_connect(self):
        httpd = self.start_server()
        code, output = self._run(
            ["--probe"],
            {
                ENV_URL: f"http://127.0.0.1:{httpd.server_address[1]}/v1",
                ENV_AUTH: AUTH_NONE,
            },
        )
        self.assertEqual(code, 2)
        self.assertIn("config=incomplete", output)
        self.assertIn(ENV_MODEL, output)
        self.assertEqual(httpd.requests, [])

    def test_auth_none_listing_needs_no_model_or_key_and_sends_no_auth(self):
        httpd = self.start_server()
        self.set_json(httpd, {"data": [{"id": "alpha"}]})
        env = {
            ENV_URL: f"http://127.0.0.1:{httpd.server_address[1]}/v1",
            ENV_AUTH: AUTH_NONE,
            ENV_API_KEY: "stale-key-must-not-be-sent",
        }
        code, output = self._run(["--check-config"], env)
        self.assertEqual(code, 0)
        self.assertIn("config=valid", output)
        self.assertIn("auth_mode=none", output)
        self.assertIn("api_key_configured=False", output)
        self.assertIn("upstream_model=not_configured", output)
        self.assertIn("network=not_performed", output)
        self.assertEqual(httpd.requests, [])

        code, output = self._run(["--list-models"], env)
        self.assertEqual(code, 0)
        self.assertIn("models_pass=yes", output)
        self.assertIn("model_id=alpha", output)
        self.assertNotIn("stale-key-must-not-be-sent", output)
        self.assertIsNone(header(httpd.requests[0], "Authorization"))

    def test_bad_ca_file_is_reported_without_traceback(self):
        httpd = self.start_server()
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp, "ca.pem")
            ca.write_text("not a certificate", encoding="utf-8")
            env = {
                ENV_URL: f"https://127.0.0.1:{httpd.server_address[1]}/v1",
                ENV_MODEL: "upstream-model-1",
                ENV_API_KEY: KEY,
                ENV_CA_FILE: str(ca),
            }
            code, output = self._run(["--list-models"], env)
        self.assertEqual(code, 2)
        self.assertIn("config=invalid", output)
        self.assertIn("network=not_performed", output)
        self.assertNotIn(KEY, output)
        self.assertEqual(httpd.requests, [])

    def test_network_action_prompts_hidden_key_when_env_unset(self):
        httpd = self.start_server()
        self.set_json(httpd, chat_payload("PROMPT-PATH-SECRET"))
        env = {
            ENV_URL: f"http://127.0.0.1:{httpd.server_address[1]}/v1",
            ENV_MODEL: "upstream-model-1",
        }
        prompts = []
        original = generation_cli.getpass.getpass

        def fake_getpass(prompt):
            prompts.append(prompt)
            return KEY

        generation_cli.getpass.getpass = fake_getpass
        try:
            code, output = self._run(["--probe"], env)
        finally:
            generation_cli.getpass.getpass = original
        self.assertEqual(code, 0)
        self.assertEqual(len(prompts), 1)
        self.assertIn("hidden", prompts[0])
        self.assertIn("probe=pass", output)
        self.assertNotIn(KEY, output)
        self.assertNotIn("PROMPT-PATH-SECRET", output)
        self.assertEqual(len(httpd.requests), 1)
        self.assertEqual(header(httpd.requests[0], "Authorization"), "Bearer " + KEY)

    def test_probe_and_model_list_print_metadata_not_content(self):
        httpd = self.start_server()
        self.set_json(httpd, chat_payload("CLI-PROBE-SECRET"))
        env = {
            ENV_URL: f"http://127.0.0.1:{httpd.server_address[1]}/v1",
            ENV_MODEL: "upstream-model-1",
            ENV_API_KEY: KEY,
        }
        code, output = self._run(["--probe"], env)
        self.assertEqual(code, 0)
        self.assertIn("unguarded=yes", output)
        self.assertIn("probe=pass", output)
        self.assertIn("response_content=not_printed", output)
        self.assertNotIn("CLI-PROBE-SECRET", output)
        self.assertNotIn(KEY, output)
        self.assertEqual(len(httpd.requests), 1)

        self.set_json(httpd, {"data": [{"id": "alpha"}, {"id": "upstream-model-1"}]})
        code, output = self._run(["--list-models"], env)
        self.assertEqual(code, 0)
        self.assertIn("models_pass=yes", output)
        self.assertIn("model_id=alpha", output)
        self.assertNotIn(KEY, output)


if __name__ == "__main__":
    unittest.main()
