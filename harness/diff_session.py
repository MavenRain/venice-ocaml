#!/usr/bin/env python3
"""M29 key schedule oracle: affine secp256k1, stdlib HKDF and PyCryptodome.

The suite exposes opaque derived keys by encrypting fixed test data. This
oracle recomputes those ciphertext/tag pins and compares the executable's
actual KAT output. Source literals alone cannot satisfy the runtime check.
PyCryptodome is a gate dependency, not a library dependency.
"""

import argparse
import hashlib
import hmac
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
INFO = b"ecdsa_encryption"
NONCE = bytes(range(12))
AAD = b"m29 known-answer"
MESSAGE = b"venice-ocaml M29 session key"


def add(a, b):
    """Affine addition with integer inverses, independent of OCaml Jacobians."""
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x * pow(2 * y, -1, P)) if a == b else
             ((v - y) * pow(u - x, -1, P))) % P
    out_x = (slope * slope - x - u) % P
    return out_x, (slope * (x - out_x) - y) % P


def multiply(scalar, point=G):
    out = None
    while scalar:
        if scalar & 1:
            out = add(out, point)
        point = add(point, point)
        scalar >>= 1
    return out


def sec1(point):
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def derive(ikm, info=INFO, salt=b""):
    """RFC 5869 extract plus the first 32-byte expand block."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def seal(key, nonce=NONCE, aad=AAD, message=MESSAGE):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    return cipher.encrypt_and_digest(message)


def vectors():
    # The final case is the first positive multiple of G whose x starts
    # with zero. It catches trimming the fixed-width ECDH input to HKDF.
    zero_scalar = next(k for k in range(1, 4097)
                       if multiply(k)[0].to_bytes(32, "big")[0] == 0)
    pairs = [
        ("one", 1, 7),
        ("two", 2, 11),
        ("order-minus-one", N - 1, 13),
        ("nontrivial", int.from_bytes(hashlib.sha256(b"m29-client").digest(), "big"),
         int.from_bytes(hashlib.sha256(b"m29-peer").digest(), "big")),
        ("leading-zero", zero_scalar, 1),
    ]
    out = []
    for name, scalar, peer_scalar in pairs:
        peer = multiply(peer_scalar)
        shared = multiply(scalar, peer)
        ikm = shared[0].to_bytes(32, "big")
        key = derive(ikm)
        ct, tag = seal(key)
        out.append(dict(name=name, scalar=scalar.to_bytes(32, "big").hex(),
                        peer=sec1(peer).hex(), client=sec1(multiply(scalar)).hex(),
                        shared=sec1(shared).hex(), ikm=ikm.hex(), key=key.hex(),
                        ct=ct.hex(), tag=tag.hex()))
    return out


def self_check():
    if multiply(2)[0] != 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5:
        raise ValueError("secp256k1 2G x")
    if multiply(N) is not None or multiply(N - 1) != (G[0], P - G[1]):
        raise ValueError("secp256k1 group order")
    if multiply(7, multiply(11)) != multiply(11, multiply(7)):
        raise ValueError("ECDH symmetry")
    rfc = derive(b"\x0b" * 22, bytes(range(0xF0, 0xFA)), bytes(range(13)))
    if rfc.hex() != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf":
        raise ValueError("RFC 5869 case 1 first 32 bytes")
    ct, tag = seal(bytes(32), bytes(12), b"", bytes(16))
    if (ct.hex(), tag.hex()) != (
            "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"):
        raise ValueError("AES-256-GCM published vector")


def strip_comments(source):
    """Strip nested OCaml comments while preserving string literals."""
    out = []
    depth = 0
    quoted = False
    i = 0
    while i < len(source):
        if depth:
            if source.startswith("(*", i):
                depth += 1
                i += 2
            elif source.startswith("*)", i):
                depth -= 1
                i += 2
                out.append(" ")
            else:
                i += 1
        elif quoted:
            out.append(source[i])
            if source[i] == "\\" and i + 1 < len(source):
                i += 1
                out.append(source[i])
            elif source[i] == '"':
                quoted = False
            i += 1
        elif source.startswith("(*", i):
            depth = 1
            i += 2
        else:
            quoted = source[i] == '"'
            out.append(source[i])
            i += 1
    if depth or quoted:
        raise ValueError("unterminated OCaml comment or string")
    return "".join(out)


ROW_START = re.compile(r'^\s*(?:\[\s*)?\(\s*"(?:[^"\\]|\\.)*"\s*,')


def check_bodies(source):
    rows = []
    current = None
    for line in strip_comments(source).splitlines():
        start = ROW_START.match(line)
        if start:
            if current is not None:
                rows.append("\n".join(current))
            current = [line[start.end():]]
        elif current is not None:
            if line and not line[0].isspace():
                rows.append("\n".join(current))
                current = None
            else:
                current.append(line)
    if current is not None:
        rows.append("\n".join(current))
    return rows


def verify_pins(source, expected):
    bodies = check_bodies(source)
    for row in expected:
        needles = [f'~{field}:"{row[field]}"'
                   for field in ("name", "scalar", "peer", "client", "ct", "tag")]
        if not any(all(needle in body for needle in needles) for body in bodies):
            raise ValueError(f"{row['name']}: recomputed inputs/outputs absent from a KAT row")


def verify_output(output, expected):
    observed = {}
    for line in output.splitlines():
        if not line.startswith("SESSION_KAT\t"):
            continue
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValueError("malformed executable KAT row")
        _, name, client, ct, tag = fields
        if name in observed:
            raise ValueError(f"duplicate executable KAT: {name}")
        observed[name] = (client, ct, tag)
    wanted = {row["name"]: (row["client"], row["ct"], row["tag"]) for row in expected}
    if observed != wanted:
        bad = sorted(name for name in observed.keys() | wanted.keys()
                     if observed.get(name) != wanted.get(name))
        raise ValueError("executable KAT mismatch: " + ", ".join(bad))


def run(executable, source):
    self_check()
    expected = vectors()
    verify_pins(source.read_text(), expected)
    result = subprocess.run([str(executable)], text=True, capture_output=True,
                            check=False, timeout=180)
    if result.returncode != 0 or "FAIL" in result.stdout:
        raise ValueError("OCaml suite failed: " + result.stdout + result.stderr)
    verify_output(result.stdout, expected)
    return len(expected)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=pathlib.Path,
                        default=ROOT / "_build/default/test/test_sessx.exe")
    parser.add_argument("--source", type=pathlib.Path,
                        default=ROOT / "test/test_sessx.ml")
    args = parser.parse_args(argv)
    try:
        count = run(args.exe.resolve(), args.source)
    except (OSError, ValueError, ImportError, subprocess.TimeoutExpired) as error:
        print(f"diff_session: FAIL {error}")
        return 1
    print(f"diff_session: {count} source KATs and actual executable outputs agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
