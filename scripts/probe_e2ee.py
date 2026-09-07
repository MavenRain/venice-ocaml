#!/usr/bin/env python3
"""Fixed-public-prompt protocol diagnostic, not full TEE or SDK admission.

Only validated encrypted wire bytes and allowlisted public metadata survive.
The ephemeral client scalar and authenticated plaintext exist only in memory.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import secrets
import selectors
import subprocess
import sys
import tempfile
import time
import urllib.parse


ROOT = pathlib.Path(__file__).resolve().parent.parent
ORIGIN = "https://api.venice.ai/api/v1"
PROMPT = b"Reply with the single word VENICE."
LIMIT = 4_194_304
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}\Z")
RECEIPT_FIELDS = frozenset(("text", "signature", "signing_algo", "signing_address"))


def sibling(name, relative, script_tail=False):
    """Load trusted repository helpers with isolated Python's empty local path."""
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    if script_tail:
        source = path.read_text()
        tail = "sys.exit(main(sys.argv[1:]))"
        if not source.endswith(tail + "\n"):
            raise ValueError("quote helper entry point")
        exec(compile(source[:-len(tail + "\n")], str(path), "exec"), module.__dict__)
    else:
        spec.loader.exec_module(module)
    return module


def config_string(value):
    """Reject control bytes before quoting a single curl config argument."""
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise ValueError("transport argument")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def curl_transport(method, path, headers, body, key):
    """Bounded HTTPS transport; credentials travel solely through stdin."""
    if not key:
        raise ValueError("missing key")
    if method not in ("GET", "POST") or not path.startswith("/"):
        raise ValueError("transport request")
    options = [
        "silent", 'proto = "=https"', 'proto-redir = "=https"',
        'proxy = ""', 'noproxy = "*"', "max-redirs = 0",
        "connect-timeout = 10", "max-time = 45", f"max-filesize = {LIMIT}",
        "url = " + config_string(ORIGIN + path),
        "request = " + config_string(method),
        "header = " + config_string("Authorization: Bearer " + key),
        'write-out = "\\n%{http_code}"',
    ]
    for name, value in headers.items():
        if name.lower() in ("authorization", "x-request-hash"):
            raise ValueError("transport header")
        options.append("header = " + config_string(name + ": " + value))
    if body is not None:
        options.append("data-binary = " + config_string(body.decode("ascii")))
    payload = ("\n".join(options) + "\n").encode("ascii")
    # Do not forward VENICE_API_KEY, proxy settings or curl/TLS overrides.
    child_env = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    proc = subprocess.Popen(["curl", "-q", "-K", "-"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env=child_env)
    result = bytearray()
    deadline = time.monotonic() + 50
    try:
        proc.stdin.write(payload)
        proc.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("transport timeout")
                if not selector.select(min(remaining, 1)):
                    continue
                chunk = os.read(proc.stdout.fileno(), min(65536, LIMIT + 5 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > LIMIT + 4:
                    raise ValueError("transport body limit")
        if proc.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError("transport failure")
        raw = bytes(result)
        if len(raw) < 4 or raw[-4:-3] != b"\n" or not raw[-3:].isdigit():
            raise ValueError("transport status")
        return int(raw[-3:]), raw[:-4]
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        if not proc.stdin.closed:
            proc.stdin.close()


def request(transport, method, path, headers, body, key):
    status, response = transport(method, path, headers, body, key)
    if status != 200 or not isinstance(response, bytes) or len(response) > LIMIT:
        raise ValueError("HTTP response")
    return response


def structural_attestation(body, model, challenge, oracle):
    """Reuse M22's structural REPORTDATA/GPU checks without persisting its envelope."""
    if not isinstance(body, dict) or body.get("model") != model:
        raise ValueError("attestation model")
    nonces = [body[name] for name in ("nonce", "request_nonce") if name in body]
    if not nonces or any(value != challenge for value in nonces):
        raise ValueError("attestation nonce")
    if body.get("signing_algo", "ecdsa") != "ecdsa":
        raise ValueError("attestation algorithm")
    if not isinstance(body.get("intel_quote"), str) or not body["intel_quote"]:
        raise ValueError("attestation quote encoding")
    gpu = body.get("nvidia_payload")
    if gpu is not None:
        if isinstance(gpu, str):
            gpu = oracle.strict_json(gpu.encode("utf-8"))
        if (not isinstance(gpu, dict) or gpu.get("nonce") != challenge
                or not isinstance(gpu.get("arch"), str)
                or not isinstance(gpu.get("evidence_list"), list) or not gpu["evidence_list"]):
            raise ValueError("attestation GPU structure")
    keys = [body[name] for name in ("signing_key", "signing_public_key") if name in body]
    if not keys or any(value != keys[0] for value in keys):
        raise ValueError("attestation key")
    point = oracle.parse_public_key(keys[0])
    key = "04" + point[0].to_bytes(32, "big").hex() + point[1].to_bytes(32, "big").hex()
    address = body.get("signing_address")
    if not isinstance(address, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{40}", address):
        raise ValueError("attestation address")
    address = "0x" + address.removeprefix("0x").lower()
    quote_helper = sibling("quote_diagnostic", "harness/diff_quote.py", script_tail=True)
    if quote_helper.eth_address(bytes.fromhex(key)[1:]).hex() != address[2:]:
        raise ValueError("attestation key address")
    # The older helper reports raw envelope details. Capture all such output.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        try:
            quote = quote_helper.live_decode_quote(body.get("intel_quote"))
            if (len(quote) < 636 or int.from_bytes(quote[:2], "little") != 4
                    or int.from_bytes(quote[2:4], "little") != 2
                    or int.from_bytes(quote[4:8], "little") != 0x81
                    or 636 + int.from_bytes(quote[632:636], "little") > len(quote)
                    or quote[168] & 1):
                raise ValueError("attestation quote")
            if quote_helper.live_binding(body, quote[568:632], bytes.fromhex(challenge), challenge) != 0:
                raise ValueError("attestation binding")
        except SystemExit as error:
            raise ValueError("attestation binding") from error
    return key, address


def public_stream(response, model, oracle):
    """The oracle rejects arbitrary envelopes; also bind every public model field."""
    request_id, frames = oracle.parse_stream(response)
    if not IDENTIFIER.fullmatch(request_id):
        raise ValueError("request identifier")
    for line in response.replace(b"\r\n", b"\n").split(b"\n"):
        if line.startswith(b"data:"):
            payload = line[5:].strip()
            if payload != b"[DONE]":
                event = oracle.strict_json(payload)
                if "model" in event and event["model"] != model:
                    raise ValueError("response model")
    return request_id, frames


def publish(output, artifact):
    """Create a complete 0600 artifact atomically, refusing any existing target."""
    encoded = (json.dumps(artifact, sort_keys=True, indent=2) + "\n").encode("ascii")
    fd, temporary = tempfile.mkstemp(prefix=".venice-e2ee-", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output)
    finally:
        os.unlink(temporary)


def capture(model, output, key, transport=curl_transport):
    if not IDENTIFIER.fullmatch(model):
        raise ValueError("model identifier")
    config_string(key)
    if not key:
        raise ValueError("missing key")
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("output path")
    oracle = sibling("e2ee_diagnostic", "harness/diff_e2ee.py")
    models = oracle.strict_json(request(transport, "GET", "/models", {}, None, key))
    if not isinstance(models, dict) or not isinstance(models.get("data"), list):
        raise ValueError("models response")
    matches = [row for row in models["data"] if isinstance(row, dict) and row.get("id") == model]
    if len(matches) != 1:
        raise ValueError("model capability")
    spec = matches[0].get("model_spec")
    capabilities = spec.get("capabilities") if isinstance(spec, dict) else None
    if capabilities is None:
        capabilities = matches[0].get("capabilities")
    if not isinstance(capabilities, dict) or capabilities.get("supportsE2EE") is not True:
        raise ValueError("model capability")
    scalar = secrets.randbelow(ORDER - 1) + 1
    challenge = secrets.token_bytes(32).hex()
    query = urllib.parse.urlencode({"model": model, "nonce": challenge, "signing_algo": "ecdsa"})
    envelope = oracle.strict_json(request(transport, "GET", "/tee/attestation?" + query,
                                         {}, None, key))
    signing_key, address = structural_attestation(envelope, model, challenge, oracle)
    frame = oracle.seal_frame(scalar, signing_key, secrets.token_bytes(12), PROMPT)
    body = json.dumps({
        "model": model, "messages": [{"role": "user", "content": frame}],
        "stream": True, "n": 1, "max_tokens": 32,
        "venice_parameters": {"enable_e2ee": True, "enable_web_search": "off",
                              "enable_web_scraping": False, "enable_x_search": False,
                              "include_venice_system_prompt": False},
    }, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream",
               "X-Venice-TEE-Client-Pub-Key": oracle.public_key(scalar),
               "X-Venice-TEE-Model-Pub-Key": signing_key,
               "X-Venice-TEE-Signing-Algo": "ecdsa"}
    response = request(transport, "POST", "/chat/completions", headers, body, key)
    request_id, frames = public_stream(response, model, oracle)
    if not frames:
        raise ValueError("empty encrypted response")
    plaintext_bytes = 0
    for encrypted in frames:
        plaintext_bytes += len(oracle.decrypt_frame(scalar, encrypted))
    query = urllib.parse.urlencode({"model": model, "request_id": request_id})
    receipt = oracle.strict_json(request(transport, "GET", "/tee/signature?" + query,
                                        {}, None, key))
    oracle.verify_receipt(receipt, body, response, signing_key, address)
    artifact = {
        "schema": "venice-e2ee-diagnostic-v1", "model": model,
        "challenge_hex": challenge, "request_id": request_id,
        "signing_key": signing_key, "signing_address": address,
        "request_body_hex": body.hex(), "response_body_hex": response.hex(),
        "receipt": {name: receipt[name] for name in RECEIPT_FIELDS if name in receipt},
        "checks": {"reportdata": "structural-only", "gcm_authenticated_frames": len(frames),
                   "plaintext_bytes": plaintext_bytes},
        "digests": {"request_sha256": hashlib.sha256(body).hexdigest(),
                    "response_sha256": hashlib.sha256(response).hexdigest()},
    }
    publish(output, artifact)


def main(argv=None, environ=None, transport=curl_transport):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", metavar="MODEL")
    parser.add_argument("output", metavar="OUTPUT")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    key = env.get("VENICE_API_KEY")
    if not key:
        print("probe_e2ee: VENICE_API_KEY is unset; no request or capture created", file=sys.stderr)
        return 2
    try:
        capture(args.model, pathlib.Path(args.output), key, transport)
    except Exception:
        # Never print exceptions, HTTP bodies, headers, decrypted text or curl stderr.
        print("probe_e2ee: diagnostic failed; no capture published", file=sys.stderr)
        return 1
    print("probe_e2ee: capture written; frames authenticated and receipt verified; TEE checks structural only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
