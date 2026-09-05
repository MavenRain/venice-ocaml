#!/usr/bin/env python3
"""Exercise the quote probe without any third-party Python packages."""

import base64
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
NONCE = "11" * 32
ADDRESS = "22" * 20


class QuoteProbeTests(unittest.TestCase):
    def run_probe(self, *args):
        return subprocess.run(
            [sys.executable, "-S", str(ROOT / "harness/diff_quote.py"), *args],
            capture_output=True, text=True, check=False,
        )

    def test_fixture_oracle_without_site_packages(self):
        result = self.run_probe()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("formula self-check ok", result.stdout)

    def test_live_layout(self):
        # This tests structural capture validation, not signature verification.
        quote = bytearray((ROOT / "fixtures/tdx_quote_v4.bin").read_bytes())
        quote[568:632] = bytes.fromhex(ADDRESS + "00" * 12 + NONCE)
        end = 636 + struct.unpack_from("<I", quote, 632)[0]
        wrong_type = quote[:]
        struct.pack_into("<H", wrong_type, 2, 99)
        oversized = quote[:]
        struct.pack_into("<I", oversized, 632, 0xffffffff)
        cases = [
            ("padding", quote, 0, "trailing bytes 70"),
            ("exact extent", quote[:end], 0, "trailing bytes 0"),
            ("missing signature", quote[:636], 1, "extends beyond the quote"),
            ("one byte short", quote[:end - 1], 1, "extends beyond the quote"),
            ("oversized extent", oversized, 1, "extends beyond the quote"),
            ("unsupported key type", wrong_type, 1, "att_key_type is not 2"),
        ]
        with tempfile.TemporaryDirectory(prefix="quote-probe-test-") as tmp:
            capture = pathlib.Path(tmp) / "capture.json"
            for name, data, status, message in cases:
                with self.subTest(name=name):
                    capture.write_text(json.dumps({
                        "nonce": NONCE,
                        "signing_algo": "ecdsa",
                        "signing_address": ADDRESS,
                        "intel_quote": base64.b64encode(data).decode(),
                    }))
                    result = self.run_probe("live", str(capture), "--expect-nonce", NONCE)
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    self.assertIn(message, result.stdout)
                    self.assertEqual("live check ok" in result.stdout, status == 0)


if __name__ == "__main__":
    unittest.main()
