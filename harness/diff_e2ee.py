#!/usr/bin/env python3
"""M31 offline transcript oracle. SYNTHETIC fixtures prove no live service claim.

The producer signs hashes of original request bytes and complete SSE bytes.
The affine secp256k1 and HKDF implementation comes from the independent M29
oracle; AES-GCM, Keccak and Ed25519 come from PyCryptodome. No network is used.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
MAX_REQUEST = 4 * 1024 * 1024
MAX_RESPONSE = 8 * 1024 * 1024
MAX_CAPTURE = 2 * (MAX_REQUEST + MAX_RESPONSE) + 65536
_spec = importlib.util.spec_from_file_location(
    "venice_m29_oracle", pathlib.Path(__file__).with_name("diff_session.py"))
_session = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_session)
P, N, G = _session.P, _session.N, _session.G
add, multiply = _session.add, _session.multiply


def strict_json(body: bytes):
    """Decode JSON without duplicate names, nonfinite numbers or excess bytes."""
    if not isinstance(body, bytes) or len(body) > MAX_CAPTURE:
        raise ValueError("JSON byte limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("nonfinite JSON number")

    try:
        result = json.loads(body.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("malformed JSON") from error
    pending = [(result, 0)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("nonfinite JSON number")
        if depth > 64:
            raise ValueError("JSON nesting limit")
        children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        pending.extend((child, depth + 1) for child in children)
    return result


def _hex(value, length=None, prefix=False, maximum=MAX_RESPONSE):
    if not isinstance(value, str):
        raise ValueError("hex string required")
    if prefix and value.startswith("0x"):
        value = value[2:]
    if (len(value) > maximum * 2 or len(value) % 2 or
            re.fullmatch(r"[0-9a-fA-F]*", value) is None):
        raise ValueError("malformed hex")
    result = bytes.fromhex(value)
    if length is not None and len(result) != length:
        raise ValueError("hex length")
    return result


def _scalar(value):
    if type(value) is not int or not 1 <= value < N:
        raise ValueError("invalid private scalar")
    return value


def parse_public_key(value: str) -> tuple[int, int]:
    encoded = _hex(value, maximum=65, prefix=True)
    if len(encoded) == 65 and encoded[0] == 4:
        encoded = encoded[1:]
    if len(encoded) != 64:
        raise ValueError("public key encoding")
    x, y = int.from_bytes(encoded[:32], "big"), int.from_bytes(encoded[32:], "big")
    if x >= P or y >= P or (y * y - x * x * x - 7) % P:
        raise ValueError("public key point")
    return x, y


def public_key(scalar: int) -> str:
    return _session.sec1(multiply(_scalar(scalar))).hex()


def _key(scalar, peer):
    shared = multiply(_scalar(scalar), peer)
    if shared is None:
        raise ValueError("invalid shared point")
    return _session.derive(shared[0].to_bytes(32, "big"))


def _frame(frame_hex):
    frame = _hex(frame_hex)
    if len(frame) < 93:
        raise ValueError("encrypted frame shorter than 93 bytes")
    return frame, parse_public_key(frame[:65].hex())


def seal_frame(scalar: int, peer_hex: str, nonce: bytes, plaintext: bytes) -> str:
    from Crypto.Cipher import AES
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("nonce length")
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_RESPONSE - 93:
        raise ValueError("plaintext byte limit")
    key = _key(scalar, parse_public_key(peer_hex))
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return public_key(scalar) + (nonce + ciphertext + tag).hex()


def decrypt_frame(client_scalar: int, frame_hex: str) -> bytes:
    from Crypto.Cipher import AES
    frame, peer = _frame(frame_hex)
    cipher = AES.new(_key(client_scalar, peer), AES.MODE_GCM,
                     nonce=frame[65:77], mac_len=16)
    try:
        return cipher.decrypt_and_verify(frame[77:-16], frame[-16:])
    except ValueError as error:
        raise ValueError("encrypted frame authentication") from error


def _natural(value):
    return type(value) is int and 0 <= value <= (1 << 63) - 1


def _parse_stream(body: bytes):
    """Validate a complete restricted SSE transcript without rewriting its bytes."""
    if not isinstance(body, bytes) or not body or len(body) > MAX_RESPONSE:
        raise ValueError("response byte limit")
    # Splitting a view is safe: the caller retains the original body for hashes.
    normalized = body.replace(b"\r\n", b"\n")
    if b"\r" in normalized or not normalized.endswith(b"\n\n"):
        raise ValueError("incomplete SSE event")
    events = normalized[:-2].split(b"\n\n")
    identity = None
    frames = []
    done = False
    finished = False
    for event in events:
        if done:
            raise ValueError("SSE data after DONE")
        if not event.startswith(b"data:") or b"\n" in event:
            raise ValueError("unsupported SSE event")
        payload = event[5:]
        if payload.startswith(b" "):
            payload = payload[1:]
        if payload == b"[DONE]":
            done = True
            continue
        chunk = strict_json(payload)
        allowed = {"id", "model", "object", "created", "choices", "usage", "system_fingerprint"}
        if not isinstance(chunk, dict) or set(chunk) - allowed:
            raise ValueError("SSE chunk shape")
        current = (chunk.get("id"), chunk.get("model"))
        if any(not isinstance(s, str) or
               re.fullmatch(r"[A-Za-z0-9._:/-]{1,200}", s) is None for s in current):
            raise ValueError("SSE identity")
        if identity is None:
            identity = current
        if current != identity:
            raise ValueError("SSE identity changed")
        if "object" in chunk and chunk["object"] != "chat.completion.chunk":
            raise ValueError("SSE object")
        if "created" in chunk and not _natural(chunk["created"]):
            raise ValueError("SSE created")
        fingerprint = chunk.get("system_fingerprint")
        if fingerprint is not None and (not isinstance(fingerprint, str) or
                re.fullmatch(r"[A-Za-z0-9_-]{1,100}", fingerprint) is None):
            raise ValueError("SSE fingerprint")
        usage = chunk.get("usage")
        if usage is not None and (not isinstance(usage, dict) or
                set(usage) - {"prompt_tokens", "completion_tokens", "total_tokens"} or
                any(not _natural(v) for v in usage.values())):
            raise ValueError("SSE usage")
        choices = chunk.get("choices")
        if choices == [] and finished and isinstance(usage, dict):
            continue
        if finished:
            raise ValueError("SSE choice after finish")
        if not isinstance(choices, list) or len(choices) != 1:
            raise ValueError("SSE choices")
        choice = choices[0]
        if (not isinstance(choice, dict) or
                set(choice) - {"index", "delta", "finish_reason"} or
                type(choice.get("index")) is not int or choice["index"] != 0 or
                choice.get("finish_reason") not in (None, "stop", "length", "content_filter")):
            raise ValueError("SSE choice")
        delta = choice.get("delta")
        if (not isinstance(delta, dict) or
                set(delta) - {"role", "content", "reasoning_content"} or
                ("role" in delta and delta["role"] != "assistant")):
            raise ValueError("SSE delta")
        for field in ("content", "reasoning_content"):
            if field in delta:
                value = delta[field]
                if not isinstance(value, str):
                    raise ValueError("encrypted delta type")
                if not value:
                    continue
                _frame(value)
                frames.append(value)
        finished = choice.get("finish_reason") is not None
    if not done or not finished or identity is None or not frames:
        raise ValueError("incomplete encrypted stream")
    return identity, frames


def parse_stream(body: bytes) -> tuple[str, list[str]]:
    identity, frames = _parse_stream(body)
    return identity[0], frames


def signed_text(request_body: bytes, response_body: bytes) -> str:
    if (not isinstance(request_body, bytes) or not request_body or
            len(request_body) > MAX_REQUEST or not isinstance(response_body, bytes) or
            not response_body or len(response_body) > MAX_RESPONSE):
        raise ValueError("transcript byte limit")
    return hashlib.sha256(request_body).hexdigest() + ":" + hashlib.sha256(response_body).hexdigest()


def _keccak(message):
    from Crypto.Hash import keccak
    return keccak.new(digest_bits=256, data=message).digest()


def _address(point):
    return _keccak(_session.sec1(point)[1:])[-20:]


def _eip191(text):
    message = text.encode("utf-8")
    return _keccak(b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii") + message)


def self_check():
    _session.self_check()
    # Published ethers v6 hashMessage examples, independently pinned:
    # https://docs.ethers.org/v6/api/hashing/
    vectors = (
        ("Hello World", "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"),
        ("0x4243", "6d91b221f765224b256762dcba32d62209cf78e9bebb0a1b758ca26c76db3af4"),
        ("BC", "0d3abc18ec299cf9b42ba439ac6f7e3e6ec9f5c048943704e30fc2d9c7981438"),
    )
    for message, expected in vectors:
        if _eip191(message).hex() != expected:
            raise ValueError("published EIP-191 hash vector")


ED_P = (1 << 255) - 19
ED_L = (1 << 252) + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, -1, ED_P) % ED_P
ED_IDENTITY = (0, 1)


def _ed_point(encoded):
    """Decode a canonical RFC 8032 Edwards point independently of the verifier."""
    if len(encoded) != 32:
        raise ValueError("Ed25519 point length")
    packed = int.from_bytes(encoded, "little")
    sign, y = packed >> 255, packed & ((1 << 255) - 1)
    if y >= ED_P:
        raise ValueError("Ed25519 noncanonical point")
    square = (y * y - 1) * pow((ED_D * y * y + 1) % ED_P, -1, ED_P) % ED_P
    x = pow(square, (ED_P + 3) // 8, ED_P)
    if x * x % ED_P != square:
        x = x * pow(2, (ED_P - 1) // 4, ED_P) % ED_P
    if x * x % ED_P != square or (x == 0 and sign):
        raise ValueError("Ed25519 invalid point")
    if x % 2 != sign:
        x = ED_P - x
    return x, y


def _ed_add(left, right):
    x, y = left
    u, v = right
    product = ED_D * x * u * y * v % ED_P
    return ((x * v + y * u) * pow((1 + product) % ED_P, -1, ED_P) % ED_P,
            (y * v + x * u) * pow((1 - product) % ED_P, -1, ED_P) % ED_P)


def _ed_multiply(scalar, point):
    result = ED_IDENTITY
    while scalar:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _verify_ed25519(key, message, signature):
    from Crypto.Signature import eddsa
    if len(key) != 32 or len(signature) != 64:
        raise ValueError("Ed25519 encoding length")
    public, commitment = _ed_point(key), _ed_point(signature[:32])
    if (public == ED_IDENTITY or _ed_multiply(ED_L, public) != ED_IDENTITY or
            _ed_multiply(ED_L, commitment) != ED_IDENTITY or
            int.from_bytes(signature[32:], "little") >= ED_L):
        raise ValueError("Ed25519 subgroup or scalar")
    try:
        eddsa.new(eddsa.import_public_key(key), "rfc8032").verify(message, signature)
    except ValueError as error:
        raise ValueError("receipt signature verification") from error


def verify_receipt(receipt: dict, request_body: bytes, response_body: bytes,
                   signing_key: str, signing_address: str) -> None:
    """Bind exact transcript bytes first, then verify identity and signature."""
    expected = signed_text(request_body, response_body)
    if not isinstance(receipt, dict) or receipt.get("text") != expected:
        raise ValueError("receipt transcript binding")
    required = {"text", "signature", "signing_address", "signing_algo"}
    if not required <= receipt.keys() or any(not isinstance(receipt[k], str) for k in required):
        raise ValueError("receipt fields")
    algorithm = receipt["signing_algo"]
    if algorithm == "ecdsa":
        point = parse_public_key(signing_key)
        if "signing_key" in receipt and parse_public_key(receipt["signing_key"]) != point:
            raise ValueError("receipt signer mismatch")
        address = _hex(signing_address, 20, prefix=True, maximum=20)
        claimed = _hex(receipt["signing_address"], 20, prefix=True, maximum=20)
        if address != claimed or _address(point) != address:
            raise ValueError("receipt signer mismatch")
        signature = _hex(receipt["signature"], 65, prefix=True, maximum=65)
        r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big")
        recovery = signature[64]
        if recovery in (27, 28):
            recovery -= 27
        if not 1 <= r < N or not 1 <= s <= N // 2 or recovery not in (0, 1):
            raise ValueError("receipt signature encoding")
        square = (r * r * r + 7) % P
        y = pow(square, (P + 1) // 4, P)
        if y * y % P != square:
            raise ValueError("receipt recovery point")
        if y % 2 != recovery:
            y = P - y
        z = int.from_bytes(_eip191(expected), "big")
        candidate = add(multiply(s, (r, y)), multiply((-z) % N))
        recovered = multiply(pow(r, -1, N), candidate)
        if recovered != point:
            raise ValueError("receipt signature verification")
    elif algorithm == "ed25519":
        key = _hex(signing_key, 32, maximum=32)
        if "signing_key" in receipt and _hex(receipt["signing_key"], 32, maximum=32) != key:
            raise ValueError("receipt signer mismatch")
        address = _hex(signing_address, 32, maximum=32)
        claimed = _hex(receipt["signing_address"], 32, maximum=32)
        if key != address or key != claimed:
            raise ValueError("receipt signer mismatch")
        signature = _hex(receipt["signature"], 64, maximum=64)
        _verify_ed25519(key, expected.encode(), signature)
    else:
        raise ValueError("receipt algorithm")


def _synthetic_ecdsa_receipt(text, scalar=11):
    """Deterministic signing for explicitly public synthetic test keys only."""
    digest = _eip191(text)
    nonce = int.from_bytes(hashlib.sha256(b"M31 SYNTHETIC nonce" + digest).digest(), "big") % (N - 1) + 1
    x, y = multiply(nonce)
    r = x % N
    s = pow(nonce, -1, N) * (int.from_bytes(digest, "big") + r * scalar) % N
    recovery = y % 2
    if x >= N or r == 0 or s == 0:
        raise ValueError("synthetic signer nonce")
    if s > N // 2:
        s, recovery = N - s, recovery ^ 1
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recovery])
    return {"text": text, "signature": "0x" + signature.hex(), "signing_algo": "ecdsa",
            "signing_address": "0x" + _address(multiply(scalar)).hex()}


def _json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def synthetic_fixture():
    from Crypto.Signature import eddsa
    client, prompt, response = 3, 7, 13
    request = _json({"model": "SYNTHETIC-model", "stream": True,
                     "messages": [{"role": "user", "content": seal_frame(
                         client, public_key(prompt), bytes(range(12)), b"SYNTHETIC prompt")}],
                     "client_public_key": public_key(client)})
    frames = [seal_frame(response, public_key(client), bytes(range(12, 24)), b"Synthetic answer."),
              seal_frame(response, public_key(client), bytes(range(24, 36)), b"Synthetic reasoning.")]
    chunks = [{"id": "SYNTHETIC-request-1", "model": "SYNTHETIC-model",
               "object": "chat.completion.chunk", "created": 0,
               "choices": [{"index": 0, "delta": {field: frame}, "finish_reason": None}]}
              for field, frame in zip(("content", "reasoning_content"), frames)]
    chunks.append({"id": "SYNTHETIC-request-1", "model": "SYNTHETIC-model",
                   "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    response_body = b"".join(b"data: " + _json(chunk) + b"\n\n" for chunk in chunks) + b"data: [DONE]\n\n"
    text = signed_text(request, response_body)
    ed_key = eddsa.import_private_key(bytes(range(32)))
    ed_public = ed_key.public_key().export_key(format="raw").hex()
    ed_receipt = {"text": text, "signature": eddsa.new(ed_key, "rfc8032").sign(text.encode()).hex(),
                  "signing_algo": "ed25519", "signing_address": ed_public}
    receipt = _synthetic_ecdsa_receipt(text)
    return {"schema": "venice-e2ee-synthetic-v1", "origin": "SYNTHETIC, never sent to Venice",
            "private_material": {"client_scalar": client, "prompt_scalar": prompt,
                                 "response_scalar": response, "ecdsa_signer_scalar": 11,
                                 "ed25519_seed_hex": bytes(range(32)).hex()},
            "request_body_hex": request.hex(), "response_body_hex": response_body.hex(),
            "signing_key": public_key(11), "signing_address": receipt["signing_address"],
            "receipt": receipt, "ed25519": {"signing_key": ed_public,
                                               "signing_address": ed_public, "receipt": ed_receipt}}


def check_fixture(path):
    self_check()
    with path.open("rb") as source:
        raw = source.read(MAX_CAPTURE + 1)
    fixture = strict_json(raw)
    if not isinstance(fixture, dict):
        raise ValueError("capture shape")
    schema = fixture.get("schema")
    if schema not in ("venice-e2ee-synthetic-v1", "venice-e2ee-diagnostic-v1"):
        raise ValueError("capture schema")
    try:
        request = _hex(fixture["request_body_hex"], maximum=MAX_REQUEST)
        response = _hex(fixture["response_body_hex"], maximum=MAX_RESPONSE)
        (request_id, response_model), frames = _parse_stream(response)
        verify_receipt(fixture["receipt"], request, response,
                       fixture["signing_key"], fixture["signing_address"])
        if schema == "venice-e2ee-synthetic-v1":
            if fixture != synthetic_fixture():
                raise ValueError("synthetic deterministic fixture mismatch")
            private = fixture["private_material"]
            prompt_frame = strict_json(request)["messages"][0]["content"]
            if decrypt_frame(private["prompt_scalar"], prompt_frame) != b"SYNTHETIC prompt":
                raise ValueError("synthetic prompt plaintext")
            plaintexts = [decrypt_frame(private["client_scalar"], frame) for frame in frames]
            if plaintexts != [b"Synthetic answer.", b"Synthetic reasoning."]:
                raise ValueError("synthetic response plaintext")
            ed = fixture["ed25519"]
            verify_receipt(ed["receipt"], request, response, ed["signing_key"], ed["signing_address"])
            return "SYNTHETIC: prompt and 2 response frames authenticate; ECDSA and Ed25519 receipts verify"
        if fixture.get("request_id") != request_id:
            raise ValueError("capture request id mismatch")
        request_value = strict_json(request)
        if (not isinstance(request_value, dict) or
                request_value.get("model") != fixture.get("model") or
                request_value.get("model") != response_model or
                request_value.get("stream") is not True):
            raise ValueError("capture request model or stream")
        messages = request_value.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("capture request messages")
        for message in messages:
            if (not isinstance(message, dict) or set(message) != {"role", "content"} or
                    message["role"] not in ("user", "system")):
                raise ValueError("capture request message shape")
            _frame(message["content"])
        # Recompute every stored summary. A saved claim is never evidence.
        if fixture["digests"] != {"request_sha256": hashlib.sha256(request).hexdigest(),
                                  "response_sha256": hashlib.sha256(response).hexdigest()}:
            raise ValueError("capture digests")
        checks = fixture["checks"]
        if (not isinstance(checks, dict) or set(checks) != {"reportdata", "gcm_authenticated_frames",
                                                            "plaintext_bytes"} or
                checks["reportdata"] != "structural-only" or
                not _natural(checks["gcm_authenticated_frames"]) or
                checks["gcm_authenticated_frames"] != len(frames) or
                not _natural(checks["plaintext_bytes"]) or
                checks["plaintext_bytes"] != sum(len(frame) // 2 - 93 for frame in frames)):
            raise ValueError("capture checks")
        _hex(fixture["challenge_hex"], 32, maximum=32)
        return ("diagnostic capture: exact-byte receipt signature and encrypted frame structure verify; "
                "ciphertext authentication cannot be replayed without the client scalar; "
                "signing key attestation is not verified by this replay")
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError("capture fields") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", nargs="?", type=pathlib.Path,
                        default=ROOT / "fixtures/e2ee_synthetic.json")
    parser.add_argument("--write-synthetic", action="store_true",
                        help="regenerate the deterministic public synthetic fixture")
    args = parser.parse_args(argv)
    try:
        if args.write_synthetic:
            if args.capture.resolve() != (ROOT / "fixtures/e2ee_synthetic.json").resolve():
                raise ValueError("synthetic output path")
            args.capture.write_text(json.dumps(synthetic_fixture(), indent=2) + "\n", encoding="utf-8")
        print("diff_e2ee: " + check_fixture(args.capture))
        return 0
    except (OSError, ValueError, ImportError) as error:
        print("diff_e2ee: FAIL " + (str(error) if isinstance(error, ValueError) else type(error).__name__))
        return 1


if __name__ == "__main__":
    sys.exit(main())
