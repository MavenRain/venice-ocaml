#!/usr/bin/env python3
"""M30 executable encryption-frame oracle using independent PyCryptodome.

Every accepted row binds a fixed plaintext to the entire wire frame:
SEC1 client public key, nonce, ciphertext and final authentication tag.
PyCryptodome is a gate dependency, not a library dependency.
"""

import argparse
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
KEY = bytes(32)
NONCE = bytes(12)
CLIENT = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
MESSAGES = {
    "empty": b"",
    "zero16": bytes(16),
    "utf8": bytes.fromhex("6869f09f8c8a"),
    "binary": bytes.fromhex("0001ff807f10000a0d5c22"),
}


def seal(message):
    from Crypto.Cipher import AES
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=NONCE, mac_len=16)
    return cipher.encrypt_and_digest(message)


def self_check():
    ct, tag = seal(bytes(16))
    if (ct.hex(), tag.hex()) != (
            "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"):
        raise ValueError("AES-256-GCM published vector")


def vectors():
    expected = {}
    for name, message in MESSAGES.items():
        ct, tag = seal(message)
        expected[name] = (message.hex(), (CLIENT + NONCE + ct + tag).hex())
    return expected


def verify_output(output, expected):
    observed = {}
    if "FAIL" in output:
        raise ValueError("OCaml suite failed: " + output)
    for line in output.splitlines():
        if not line.startswith("ENCRYPT_KAT"):
            continue
        fields = line.split("\t")
        if len(fields) != 4 or fields[0] != "ENCRYPT_KAT":
            raise ValueError("malformed executable KAT row")
        _, name, plaintext, frame = fields
        if name in observed:
            raise ValueError(f"duplicate executable KAT: {name}")
        observed[name] = (plaintext, frame)
    if observed != expected:
        bad = sorted(name for name in observed.keys() | expected.keys()
                     if observed.get(name) != expected.get(name))
        raise ValueError("executable KAT mismatch: " + ", ".join(bad))


def run(executable):
    self_check()
    expected = vectors()
    result = subprocess.run([str(executable)], text=True, capture_output=True,
                            check=False, timeout=180)
    if result.returncode != 0 or "FAIL" in result.stdout or "FAIL" in result.stderr:
        raise ValueError("OCaml suite failed: " + result.stdout + result.stderr)
    verify_output(result.stdout, expected)
    return len(expected)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=pathlib.Path,
                        default=ROOT / "_build/default/test/test_encryptx.exe")
    args = parser.parse_args(argv)
    try:
        count = run(args.exe.resolve())
    except (OSError, ValueError, ImportError, subprocess.TimeoutExpired) as error:
        print(f"diff_encrypt: FAIL {error}")
        return 1
    print(f"diff_encrypt: {count} actual executable frames agree with PyCryptodome")
    return 0


if __name__ == "__main__":
    sys.exit(main())
