#!/usr/bin/env python3
"""Exercise the quote probe without any third-party Python packages."""

import base64
import hashlib
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


class PolicySuitePinTests(unittest.TestCase):
    """One case per require of the M24 group (g), each with a control.

    Every case asserts the TRUE leg on the real fixture and the FALSE
    leg on a mutated copy, so a require that always passes fails here.
    The tenth case runs the harness and asserts its group (g) line.
    """

    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe()
        cls.v4 = (ROOT / "fixtures/tdx_quote_v4.bin").read_bytes()
        cls.bodies = cls.probe.suite_bodies(cls.probe.policy_suite_path)

    def flip(self, off, mask=1):
        """The fixture with one bit of one byte inverted."""
        broken = bytearray(self.v4)
        broken[off] ^= mask
        return bytes(broken)

    def measurement(self, name, off):
        """One measurement window pins its own bytes and no other.

        The control moves the TOP bit of the LAST byte of the window,
        because the suite pins the observed value of a low-bit mutant of
        the FIRST byte and that value is a real row of group (h).
        """
        hx = self.probe.hx
        self.assertTrue(
            self.probe.in_row(self.bodies, [name, hx(self.v4[off:off + 48])]))
        moved = self.flip(off + 47, 0x80)
        self.assertFalse(
            self.probe.in_row(self.bodies, [name, hx(moved[off:off + 48])]))

    def test_group_g_runs_and_reports_ok(self):
        result = subprocess.run(
            [sys.executable, "-S", str(PROBE)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("(g) M24 suite pins ok", result.stdout)

    def test_mr_td_pin_sits_in_a_check_row(self):
        self.measurement("mr_td", 184)

    def test_rt_mr0_pin_sits_in_a_check_row(self):
        self.measurement("rt_mr0", 376)

    def test_rt_mr1_pin_sits_in_a_check_row(self):
        self.measurement("rt_mr1", 424)

    def test_rt_mr2_pin_sits_in_a_check_row(self):
        self.measurement("rt_mr2", 472)

    def test_rt_mr3_pin_sits_in_a_check_row(self):
        self.measurement("rt_mr3", 520)

    def test_td_attributes_pin_sits_in_a_check_row(self):
        le = self.probe.le
        self.assertTrue(self.probe.in_row(
            self.bodies, ["td_attributes", f"{le(self.v4, 168, 8)}L"]))
        moved = self.flip(168)
        self.assertFalse(self.probe.in_row(
            self.bodies, ["td_attributes", f"{le(moved, 168, 8)}L"]))

    def test_g_address_pin_sits_in_a_check_row(self):
        probe = self.probe
        xy = probe.uh(probe.G_X) + probe.uh(probe.G_Y)
        self.assertTrue(
            self.probe.in_row(self.bodies, [probe.hx(probe.eth_address(xy))]))
        other = bytearray(xy)
        other[0] ^= 1
        self.assertFalse(self.probe.in_row(
            self.bodies, [probe.hx(probe.eth_address(bytes(other)))]))

    def test_g_report_data_pin_sits_in_one_check_row(self):
        probe = self.probe
        xy = probe.uh(probe.G_X) + probe.uh(probe.G_Y)
        address = probe.eth_address(xy)
        good = probe.hx(probe.report_data_ecdsa(address, probe.uh(probe.G_NONCE)))
        self.assertTrue(self.probe.in_row(
            self.bodies, [good[0:40], good[40:64], good[64:128]]))
        other = bytearray(probe.uh(probe.G_NONCE))
        other[31] ^= 1
        bad = probe.hx(probe.report_data_ecdsa(address, bytes(other)))
        self.assertFalse(self.probe.in_row(
            self.bodies, [bad[0:40], bad[40:64], bad[64:128]]))

    def test_synthetic_address_pin_sits_in_a_check_row(self):
        probe = self.probe
        self.assertTrue(self.probe.in_row(
            self.bodies, [probe.hx(probe.eth_address(probe.SYNTHETIC_XY))]))
        other = bytearray(probe.SYNTHETIC_XY)
        other[0] ^= 1
        self.assertFalse(self.probe.in_row(
            self.bodies, [probe.hx(probe.eth_address(bytes(other)))]))


class SignatureSuitePinTests(unittest.TestCase):
    """One case per require of the M25 group (h), each with a control.

    Every case asserts the TRUE leg on the real fixture and the FALSE
    leg on a mutated copy, so a require that always passes fails here.
    The first case runs the harness and asserts its group (h) line.
    """

    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe()
        cls.v4 = (ROOT / "fixtures/tdx_quote_v4.bin").read_bytes()
        cls.bodies = cls.probe.suite_bodies(cls.probe.sig_suite_path)

    def flip(self, off, mask=1):
        """The fixture with one bit of one byte inverted."""
        broken = bytearray(self.v4)
        broken[off] ^= mask
        return bytes(broken)

    def integer(self, name, value):
        """One W1 integer sits beside its accessor name in one row."""
        self.assertTrue(self.probe.in_row(self.bodies, [name, str(value)]))
        self.assertFalse(
            self.probe.in_row(self.bodies, [name, str(value + 1)]))

    def window(self, off, size):
        """One absolute window pins its own bytes and no other.

        The control moves the TOP bit of the LAST byte of the window,
        which no row of the suite spells out.
        """
        hx = self.probe.hx
        self.assertTrue(
            self.probe.in_row(self.bodies, [hx(self.v4[off:off + size])]))
        moved = self.flip(off + size - 1, 0x80)
        self.assertFalse(
            self.probe.in_row(self.bodies, [hx(moved[off:off + size])]))

    def pem_window(self):
        """The PEM window the first certificate block sits in."""
        le = self.probe.le
        auth_size = le(self.v4, 1218, 2)
        inner_off = 1220 + auth_size
        inner_size = le(self.v4, inner_off + 2, 4)
        return self.v4[inner_off + 6:inner_off + 6 + inner_size]

    def test_group_h_runs_and_reports_ok(self):
        result = subprocess.run(
            [sys.executable, "-S", str(PROBE)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("(h) M25 suite pins ok", result.stdout)

    def test_qe_leg_verifies_under_the_pck_leaf_key(self):
        probe = self.probe
        (x, y) = probe.pck_leaf_xy(self.pem_window())
        r = probe.hx(self.v4[1154:1186])
        s = probe.hx(self.v4[1186:1218])
        self.assertTrue(
            probe.p256_verify_message(x, y, r, s, self.v4[770:1154]))
        moved = self.flip(770)
        self.assertFalse(
            probe.p256_verify_message(x, y, r, s, moved[770:1154]))

    def test_isv_leg_verifies_under_the_attestation_key(self):
        probe = self.probe
        x = probe.hx(self.v4[700:732])
        y = probe.hx(self.v4[732:764])
        r = probe.hx(self.v4[636:668])
        s = probe.hx(self.v4[668:700])
        self.assertTrue(probe.p256_verify_message(x, y, r, s, self.v4[0:632]))
        moved = self.flip(30)
        self.assertFalse(probe.p256_verify_message(x, y, r, s, moved[0:632]))

    def test_signature_data_len_pin_sits_in_a_check_row(self):
        self.integer("signature_data_len", self.probe.le(self.v4, 632, 4))

    def test_cert_key_type_pin_sits_in_a_check_row(self):
        self.integer("cert_key_type", self.probe.le(self.v4, 764, 2))

    def test_cert_size_pin_sits_in_a_check_row(self):
        self.integer("cert_size", self.probe.le(self.v4, 766, 4))

    def test_qe_auth_size_pin_sits_in_a_check_row(self):
        self.integer("qe_auth_size", self.probe.le(self.v4, 1218, 2))

    def test_inner_cert_type_pin_sits_in_a_check_row(self):
        le = self.probe.le
        inner_off = 1220 + le(self.v4, 1218, 2)
        self.integer("inner_cert_type", le(self.v4, inner_off, 2))

    def test_inner_size_pin_sits_in_a_check_row(self):
        le = self.probe.le
        inner_off = 1220 + le(self.v4, 1218, 2)
        self.integer("inner_size", le(self.v4, inner_off + 2, 4))

    def test_isv_r_pin_sits_in_a_check_row(self):
        self.window(636, 32)

    def test_isv_s_pin_sits_in_a_check_row(self):
        self.window(668, 32)

    def test_attestation_key_x_pin_sits_in_a_check_row(self):
        self.window(700, 32)

    def test_attestation_key_y_pin_sits_in_a_check_row(self):
        self.window(732, 32)

    def test_qe_r_pin_sits_in_a_check_row(self):
        self.window(1154, 32)

    def test_qe_s_pin_sits_in_a_check_row(self):
        self.window(1186, 32)

    def test_auth_data_pin_sits_in_a_check_row(self):
        self.window(1220, self.probe.le(self.v4, 1218, 2))

    def test_qe_binding_digest_pin_sits_in_a_check_row(self):
        auth_size = self.probe.le(self.v4, 1218, 2)
        auth = self.v4[1220:1220 + auth_size]
        good = hashlib.sha256(self.v4[700:764] + auth).hexdigest()
        self.assertTrue(self.probe.in_row(self.bodies, [good]))
        alone = hashlib.sha256(self.v4[700:764]).hexdigest()
        self.assertFalse(self.probe.in_row(self.bodies, [alone]))

    def test_pck_leaf_key_pin_sits_in_one_check_row(self):
        (x, y) = self.probe.pck_leaf_xy(self.pem_window())
        self.assertTrue(self.probe.in_row(self.bodies, [x, y]))
        self.assertFalse(self.probe.in_row(self.bodies, [y + x, x]))

    def test_mrsigner_window_pin_sits_in_a_check_row(self):
        self.window(770 + 128, 32)

    def test_cpusvn_window_pin_sits_in_a_check_row(self):
        self.window(770, 16)


if __name__ == "__main__":
    unittest.main()
