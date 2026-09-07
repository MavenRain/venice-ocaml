#!/usr/bin/env python3
"""No-network controls for the independent fixed-prompt M31 diagnostic."""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("e2ee_probe", ROOT / "scripts/probe_e2ee.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
ORACLE = PROBE.sibling("e2ee_test_oracle", "harness/diff_e2ee.py")
MODEL = "e2ee-test-model"
SECRET = "fake-test-api-key"
PRIVATE_RESPONSE = b"private completion sentinel"
KEY = ORACLE.public_key(11)
ADDRESS = ORACLE._synthetic_ecdsa_receipt("unused")["signing_address"]


def wire(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")


class ConfigInput(io.BytesIO):
    def close(self):
        self.saved = self.getvalue()
        super().close()


class FakeChild:
    """A real bounded-readable pipe, without launching a process or network."""
    def __init__(self, stdout):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, stdout)
        os.close(write_fd)
        self.stdin = ConfigInput()
        self.stdout = os.fdopen(read_fd, "rb")
        self.killed = False

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


class FakeTransport:
    def __init__(self, mutation=None):
        self.calls = []
        self.mutation = mutation or (lambda phase, value: value)
        self.request_body = None
        self.response_body = None

    def __call__(self, method, path, headers, body, key):
        self.calls.append((method, path, headers, body))
        if key != SECRET:
            raise AssertionError("fake key mismatch")
        route = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qs(route.query)
        if route.path == "/models":
            models = {"data": [{"id": MODEL, "model_spec": {"capabilities": {"supportsE2EE": True}}}]}
            return 200, wire(self.mutation("models", models))
        if route.path == "/tee/attestation":
            if query.get("signing_algo") != ["ecdsa"] or query.get("model") != [MODEL]:
                raise AssertionError("attestation query")
            nonce = query["nonce"][0]
            quote = bytearray((ROOT / "fixtures/tdx_quote_v4.bin").read_bytes())
            quote[568:632] = bytes.fromhex(ADDRESS.removeprefix("0x") + "00" * 12 + nonce)
            envelope = {"model": MODEL, "nonce": nonce, "signing_key": KEY,
                        "signing_address": ADDRESS, "signing_algo": "ecdsa",
                        "intel_quote": base64.b64encode(quote).decode("ascii"),
                        "account_info": "private envelope sentinel"}
            return 200, wire(self.mutation("attestation", envelope))
        if route.path == "/chat/completions":
            self.request_body = body
            request = ORACLE.strict_json(body)
            prompt = ORACLE.decrypt_frame(11, request["messages"][0]["content"])
            if prompt != PROBE.PROMPT:
                raise AssertionError("fixed prompt")
            self.prompt = prompt
            self.request = request
            self.headers = headers
            client = headers["X-Venice-TEE-Client-Pub-Key"]
            chunks = []
            for field, plaintext, nonce in (("reasoning_content", b"private reasoning sentinel", b"a" * 12),
                                            ("content", PRIVATE_RESPONSE, b"b" * 12)):
                frame = ORACLE.seal_frame(23, client, nonce, plaintext)
                event = {"id": "chatcmpl-public-test", "model": MODEL,
                         "object": "chat.completion.chunk",
                         "choices": [{"index": 0, "delta": {field: frame}, "finish_reason": None}]}
                chunks.append(b"data: " + wire(self.mutation("event", event)) + b"\n\n")
            finish = {"id": "chatcmpl-public-test", "model": MODEL,
                      "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            response = b"".join(chunks) + b"data: " + wire(finish) + b"\n\ndata: [DONE]\n\n"
            self.response_body = self.mutation("response", response)
            return 200, self.response_body
        if route.path == "/tee/signature":
            if query != {"model": [MODEL], "request_id": ["chatcmpl-public-test"]}:
                raise AssertionError("signature id query")
            receipt = ORACLE._synthetic_ecdsa_receipt(ORACLE.signed_text(self.request_body, self.response_body))
            receipt["account_info"] = "private receipt sentinel"
            return 200, wire(self.mutation("receipt", receipt))
        raise AssertionError("unexpected fake route")


class ProbeTests(unittest.TestCase):
    def run_capture(self, output, transport, env=None):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            status = PROBE.main([MODEL, str(output)],
                                {"VENICE_API_KEY": SECRET} if env is None else env, transport)
        return status, stream.getvalue()

    def test_full_roundtrip_has_fixed_prompt_exact_bytes_and_public_artifact(self):
        transport = FakeTransport()
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "capture.json"
            status, log = self.run_capture(output, transport)
            self.assertEqual(status, 0, log)
            artifact = ORACLE.strict_json(output.read_bytes())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(set(artifact), {"schema", "model", "challenge_hex", "request_id", "signing_key",
                             "signing_address", "request_body_hex", "response_body_hex", "receipt", "checks", "digests"})
            self.assertEqual(bytes.fromhex(artifact["request_body_hex"]), transport.request_body)
            self.assertEqual(bytes.fromhex(artifact["response_body_hex"]), transport.response_body)
            self.assertEqual(artifact["receipt"]["text"], ORACLE.signed_text(transport.request_body, transport.response_body))
            self.assertEqual(artifact["digests"]["response_sha256"], hashlib.sha256(transport.response_body).hexdigest())
            self.assertEqual(artifact["checks"]["gcm_authenticated_frames"], 2)
            self.assertEqual(artifact["checks"]["reportdata"], "structural-only")
            self.assertEqual(set(artifact["receipt"]), PROBE.RECEIPT_FIELDS)
            request = transport.request
            self.assertTrue(request["stream"])
            self.assertEqual(request["n"], 1)
            self.assertEqual(request["max_tokens"], 32)
            self.assertEqual(request["venice_parameters"]["enable_web_search"], "off")
            self.assertTrue(request["venice_parameters"]["enable_e2ee"])
            self.assertEqual(len(request["messages"]), 1)
            self.assertEqual(transport.prompt, b"Reply with the single word VENICE.")
            self.assertEqual({name for name in transport.headers if name.startswith("X-")},
                             {"X-Venice-TEE-Client-Pub-Key", "X-Venice-TEE-Model-Pub-Key", "X-Venice-TEE-Signing-Algo"})
            for secret in (SECRET, PRIVATE_RESPONSE.decode(), "private reasoning sentinel",
                           "private envelope sentinel", "private receipt sentinel", PROBE.PROMPT.decode()):
                self.assertNotIn(secret, output.read_text() + log)
            self.assertEqual([method for method, *_ in transport.calls], ["GET", "GET", "POST", "GET"])
            result = subprocess.run([sys.executable, "-I", str(ROOT / "harness/diff_e2ee.py"), str(output)],
                                    capture_output=True, text=True, check=False, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("cannot", result.stdout)

    def test_no_key_creates_no_paths_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "missing" / "capture.json"
            transport = mock.Mock(side_effect=AssertionError("network called"))
            status, _ = self.run_capture(output, transport, {})
            self.assertEqual(status, 2)
            self.assertFalse(output.parent.exists())
            transport.assert_not_called()

    def test_help_works_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/probe_e2ee.py"), "--help"],
                                    capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(result.returncode, 0)
        self.assertIn("MODEL OUTPUT", result.stdout)

    def test_validation_failures_never_publish(self):
        def change(phase, field, value):
            def mutate(actual_phase, body):
                if phase == actual_phase:
                    body[field] = value
                return body
            return mutate

        def capability(_phase, body):
            if _phase == "models":
                body["data"][0]["model_spec"]["capabilities"]["supportsE2EE"] = "true"
            return body

        def corrupt_frame(phase, body):
            if phase == "event":
                delta = body["choices"][0]["delta"]
                field = next(iter(delta))
                frame = delta[field]
                delta[field] = frame[:-2] + ("01" if frame[-2:] != "01" else "00")
            return body

        cases = [capability, change("attestation", "nonce", "00" * 32),
                 change("attestation", "model", "wrong-model"),
                 change("attestation", "signing_key", "04" + "00" * 64),
                 change("attestation", "signing_address", "0x" + "00" * 20),
                 change("attestation", "intel_quote", "not a quote"),
                 change("attestation", "intel_quote", None),
                 change("attestation", "intel_quote", []),
                 change("attestation", "nvidia_payload", "[]"),
                 change("event", "model", "wrong-model"),
                 change("event", "private", "arbitrary private metadata"), corrupt_frame,
                 change("receipt", "text", "wrong transcript"),
                 change("receipt", "signature", "0x" + "00" * 65)]
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "capture.json"
            for index, mutation in enumerate(cases):
                with self.subTest(case=index):
                    status, log = self.run_capture(output, FakeTransport(mutation))
                    self.assertEqual(status, 1, log)
                    self.assertFalse(output.exists())
                    self.assertEqual(list(pathlib.Path(directory).iterdir()), [])
                    self.assertNotIn(SECRET, log)
                    self.assertNotIn("Traceback", log)

    def test_missing_quote_is_sanitized_before_post(self):
        def remove_quote(phase, body):
            if phase == "attestation":
                del body["intel_quote"]
            return body
        with tempfile.TemporaryDirectory() as directory:
            transport = FakeTransport(remove_quote)
            output = pathlib.Path(directory) / "out"
            status, log = self.run_capture(output, transport)
            self.assertEqual(status, 1)
            self.assertNotIn("Traceback", log)
            self.assertFalse(output.exists())
            self.assertFalse(any(method == "POST" for method, *_ in transport.calls))

    def test_non_200_status_and_oversized_body_never_publish(self):
        # 201 carries the genuine body, so only the status check can reject it.
        for code, replacement in ((201, None), (429, b'{"error":"rate"}')):
            base = FakeTransport()

            def transport(method, path, headers, body, key, code=code, replacement=replacement):
                _, real = base(method, path, headers, body, key)
                return code, real if replacement is None else replacement

            with tempfile.TemporaryDirectory() as directory:
                output = pathlib.Path(directory) / "capture.json"
                status, log = self.run_capture(output, transport)
                with self.subTest(code=code):
                    self.assertEqual(status, 1, log)
                    self.assertFalse(output.exists())
                    self.assertEqual(list(pathlib.Path(directory).iterdir()), [])
                    self.assertFalse(any(method == "POST" for method, *_ in base.calls))
                    self.assertNotIn(SECRET, log)
        for body in (b"x" * (PROBE.LIMIT + 1), "not bytes"):
            with self.subTest(body=type(body).__name__), \
                    self.assertRaisesRegex(ValueError, "HTTP response"):
                PROBE.request(lambda *_, reply=body: (200, reply),
                              "GET", "/models", {}, None, SECRET)

    def test_existing_output_and_symlink_never_overwritten_or_sent(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "capture.json"
            output.write_bytes(b"existing")
            transport = mock.Mock(side_effect=AssertionError("network called"))
            self.assertEqual(self.run_capture(output, transport)[0], 1)
            self.assertEqual(output.read_bytes(), b"existing")
            output.unlink()
            output.symlink_to(pathlib.Path(directory) / "absent")
            self.assertEqual(self.run_capture(output, transport)[0], 1)
            self.assertTrue(output.is_symlink())
            transport.assert_not_called()

    def test_publish_race_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "capture.json"
            output.write_bytes(b"raced")
            with self.assertRaises(FileExistsError):
                PROBE.publish(output, {"public": True})
            self.assertEqual(output.read_bytes(), b"raced")
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [output])

    def test_curl_config_is_escaped_and_key_absent_from_argv_and_env(self):
        with mock.patch.object(PROBE.subprocess, "Popen", side_effect=OSError("fake stop")) as spawn:
            with self.assertRaises(OSError):
                PROBE.curl_transport("POST", "/chat/completions", {"Content-Type": "application/json"},
                                     b'{"content":"ciphertext"}', SECRET)
            args, kwargs = spawn.call_args
            self.assertEqual(args[0], ["curl", "-q", "-K", "-"])
            self.assertNotIn(SECRET, repr(args) + repr(kwargs))
            self.assertNotIn("VENICE_API_KEY", kwargs["env"])
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(PROBE.config_string('a"b\\c'), '"a\\"b\\\\c"')
        with mock.patch.object(PROBE.subprocess, "Popen") as spawn:
            for key in ("", "key\nheader = injected", "key\rhidden", "key\x00"):
                with self.subTest(key=repr(key)), self.assertRaises(ValueError):
                    PROBE.curl_transport("GET", "/models", {}, None, key)
            for headers in ({"Authorization": "Bearer x"}, {"authorization": "Bearer x"},
                            {"X-Request-Hash": "00" * 32}, {"x-request-hash": "00" * 32}):
                with self.subTest(headers=sorted(headers)), \
                        self.assertRaisesRegex(ValueError, "transport header"):
                    PROBE.curl_transport("GET", "/models", headers, None, SECRET)
            spawn.assert_not_called()

    def test_curl_stdin_contains_escaped_auth_body_and_safe_options(self):
        child = FakeChild(b'{"public":true}\n200')
        with mock.patch.object(PROBE.subprocess, "Popen", return_value=child) as spawn:
            status, response = PROBE.curl_transport("POST", "/chat/completions",
                                                     {"Content-Type": "application/json"},
                                                     b'{"content":"ciphertext"}', SECRET)
        self.assertEqual((status, response), (200, b'{"public":true}'))
        config = child.stdin.saved.decode("ascii")
        self.assertIn('header = "Authorization: Bearer ' + SECRET + '"', config)
        self.assertIn('data-binary = "{\\"content\\":\\"ciphertext\\"}"', config)
        for option in ('proto = "=https"', 'proxy = ""', 'noproxy = "*"',
                       "max-redirs = 0", "max-time = 45", f"max-filesize = {PROBE.LIMIT}"):
            self.assertIn(option, config)
        self.assertNotIn(SECRET, repr(spawn.call_args))
        # The caller header loop ran, so this exclusion can fail.
        self.assertIn('header = "Content-Type: application/json"', config)
        self.assertNotIn("X-Request-Hash", config)

    def test_curl_body_reader_enforces_hard_limit_and_status_suffix(self):
        for response in (b"x" * 17 + b"\n200", b"body-no-status"):
            child = FakeChild(response)
            with self.subTest(response=response), mock.patch.object(PROBE, "LIMIT", 16), \
                    mock.patch.object(PROBE.subprocess, "Popen", return_value=child):
                with self.assertRaises(ValueError):
                    PROBE.curl_transport("GET", "/models", {}, None, SECRET)

    def test_untrusted_exceptions_are_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = mock.Mock(side_effect=RuntimeError("private response " + SECRET))
            status, log = self.run_capture(pathlib.Path(directory) / "out", transport)
            self.assertEqual(status, 1)
            self.assertNotIn("private response", log)
            self.assertNotIn(SECRET, log)


if __name__ == "__main__":
    unittest.main()
