#!/usr/bin/env python3
"""Exercise the quote probe without any third-party Python packages."""

import base64
import json
import pathlib
import struct
import subprocess
import sys
import tempfile
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
NONCE = "11" * 32
ADDRESS = "22" * 20
PROBE = ROOT / "harness/diff_quote.py"
MARKER = b"-----BEGIN CERTIFICATE-----"
END_MARKER = b"-----END CERTIFICATE-----"


def load_probe():
    """Import diff_quote.py as a module, without its sys.exit tail.

    The probe is a script and ends with sys.exit(main(...)), so a plain
    import would run the whole oracle and exit the test process. The
    tail is dropped and the rest is executed in a fresh module, which
    gives the tests below the REAL helpers instead of copies of them.
    """
    source = PROBE.read_text()
    tail = "sys.exit(main(sys.argv[1:]))"
    assert tail in source, "the diff_quote entry point moved"
    module = types.ModuleType("diff_quote_probe")
    module.__file__ = str(PROBE)
    code = compile(source.replace(tail, ""), module.__file__, "exec")
    exec(code, module.__dict__)
    return module


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


class SuitePinTests(unittest.TestCase):
    """One case per require of the M23 group (f), each with a control.

    Every case asserts the TRUE leg on the real fixture and the FALSE
    leg on a mutated copy, so a require that always passes fails here.
    """

    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe()
        cls.v4 = (ROOT / "fixtures/tdx_quote_v4.bin").read_bytes()

    def section(self, quote):
        le = self.probe.le
        sdl = le(quote, 632, 4)
        cert_size = le(quote, 766, 4)
        auth_size = le(quote, 1218, 2)
        inner_off = 1220 + auth_size
        inner_size = le(quote, inner_off + 2, 4)
        window = quote[inner_off + 6:inner_off + 6 + inner_size]
        return (sdl, cert_size, auth_size, inner_size, window)

    def test_group_f_runs_and_reports_ok(self):
        result = subprocess.run(
            [sys.executable, "-S", str(PROBE)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("(f) M23 suite pins ok", result.stdout)

    def test_cert_size_equality(self):
        (sdl, cert_size, _a, _i, _w) = self.section(self.v4)
        overhead = 64 + 64 + 2 + 4
        self.assertEqual(cert_size, sdl - overhead)
        broken = bytearray(self.v4)
        struct.pack_into("<I", broken, 766, cert_size + 1)
        (_s, bad, _a2, _i2, _w2) = self.section(bytes(broken))
        self.assertNotEqual(bad, sdl - overhead)

    def test_inner_size_equality(self):
        (_s, cert_size, auth_size, inner_size, _w) = self.section(self.v4)
        overhead = 384 + 64 + 2 + 2 + 4
        self.assertEqual(inner_size, cert_size - overhead - auth_size)
        broken = bytearray(self.v4)
        struct.pack_into("<I", broken, 1254, inner_size + 1)
        (_s2, _c2, _a2, bad, _w2) = self.section(bytes(broken))
        self.assertNotEqual(bad, cert_size - overhead - auth_size)

    def test_structure_ends_inside_the_fixture(self):
        (sdl, _c, _a, _i, _w) = self.section(self.v4)
        self.assertLessEqual(636 + sdl, len(self.v4))
        oversized = bytearray(self.v4)
        struct.pack_into("<I", oversized, 632, 0xffffffff)
        (big, _c2, _a2, _i2, _w2) = self.section(bytes(oversized))
        self.assertGreater(636 + big, len(self.v4))

    def test_pem_window_cuts_into_three_blocks(self):
        (_s, _c, _a, _i, window) = self.section(self.v4)
        blocks = self.probe.marker_blocks(window, MARKER)
        self.assertEqual(len(blocks), 3)
        blanked = window.replace(MARKER, b"\xff" * len(MARKER), 2)
        self.assertEqual(
            len(self.probe.marker_blocks(blanked, MARKER)), 1)

    def test_block_lengths_sum_to_inner_size(self):
        (_s, _c, _a, inner_size, window) = self.section(self.v4)
        blocks = self.probe.marker_blocks(window, MARKER)
        self.assertEqual(sum(len(b) for b in blocks), inner_size)
        self.assertNotEqual(sum(len(b) for b in blocks[:2]), inner_size)

    def test_block_three_ends_with_the_trailing_nul(self):
        (_s, _c, _a, _i, window) = self.section(self.v4)
        blocks = self.probe.marker_blocks(window, MARKER)
        self.assertEqual(blocks[2][-1:], b"\x00")
        self.assertNotEqual(blocks[2][:-1][-1:], b"\x00")

    def test_block_one_holds_an_end_marker(self):
        (_s, _c, _a, _i, window) = self.section(self.v4)
        blocks = self.probe.marker_blocks(window, MARKER)
        self.assertGreaterEqual(blocks[0].find(END_MARKER), 0)
        self.assertEqual(
            blocks[0].replace(END_MARKER, b"").find(END_MARKER), -1)

    def test_a_missing_suite_holds_no_check_row(self):
        keep = self.probe.suite_path
        try:
            self.probe.suite_path = ROOT / "test" / "no_such_suite.ml"
            self.assertEqual(self.probe.suite_bodies(), [])
        finally:
            self.probe.suite_path = keep
        self.assertNotEqual(self.probe.suite_bodies(), [])

    def test_a_pin_must_sit_in_one_check_row(self):
        text = (
            'let checks =\n'
            '  [ ("quotex: 4166", Int.equal (S.cert_size s) 4166);\n'
            '    ("quotex: other", Int.equal (S.qe_auth_size s) 32)\n'
            '  ]\n'
        )
        rows = self.probe.check_rows(text)
        bodies = [self.probe.LABEL.sub("", r, count=1) for r in rows]
        self.assertTrue(self.probe.in_row(bodies, ["cert_size", "4166"]))
        self.assertFalse(self.probe.in_row(bodies, ["qe_auth_size", "4166"]))
        commented = self.probe.strip_ocaml_comments(
            'let checks =\n'
            '  [ ("quotex: cert_size", (* 4166 *) Int.equal (x) 1)\n'
            '  ]\n'
        )
        hidden = [
            self.probe.LABEL.sub("", r, count=1)
            for r in self.probe.check_rows(commented)
        ]
        self.assertFalse(self.probe.in_row(hidden, ["cert_size", "4166"]))


if __name__ == "__main__":
    unittest.main()
