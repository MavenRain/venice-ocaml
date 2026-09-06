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


class ChainSuitePinTests(unittest.TestCase):
    """One case per require of the M26 group (i), each with a control.

    Every case asserts the TRUE leg on the real fixture and the FALSE
    leg on a mutated copy or a moved value, so a require that always
    passes fails here. The first case runs the harness and asserts its
    group (i) line, which stays RED until test/test_derx.ml lands.
    """

    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe()
        cls.v4 = (ROOT / "fixtures/tdx_quote_v4.bin").read_bytes()
        cls.bodies = cls.probe.suite_bodies(cls.probe.cert_suite_path)
        probe = cls.probe
        inner = 1220 + probe.le(cls.v4, 1218, 2)
        cls.pem_off = inner + 6
        cls.pem = cls.v4[cls.pem_off:
                         cls.pem_off + probe.le(cls.v4, inner + 2, 4)]
        cls.blocks = probe.marker_blocks(cls.pem, MARKER)
        cls.ders = probe.chain_ders(cls.pem)
        cls.certs = [probe.cert_fields(d) for d in cls.ders]
        cls.tbs = [c["tbs_window"] for c in cls.certs]
        cls.points = [probe.spki_point(d, c["spki"])
                      for (d, c) in zip(cls.ders, cls.certs)]
        cls.xy = [(probe.hx(x["point"][1:33]), probe.hx(x["point"][33:65]))
                  for x in cls.points]
        cls.sigs = [probe.sig_halves(d, c["sig_bits"])
                    for (d, c) in zip(cls.ders, cls.certs)]
        cls.rs = [(probe.hx(x["r"][-32:]), probe.hx(x["s"][-32:]))
                  for x in cls.sigs]
        cls.exts = [probe.ext_rows(d, c["exts"])
                    for (d, c) in zip(cls.ders, cls.certs)]

    def row(self, needles: list, control: list) -> None:
        """One needle list sits in a check row and its control does not."""
        self.assertTrue(self.probe.in_row(self.bodies, needles))
        self.assertFalse(self.probe.in_row(self.bodies, control))

    def leg(self, key: int, sig: int, message: bytes) -> bool:
        """One tbs window verified under one certificate point."""
        return self.probe.p256_verify_message(
            self.xy[key][0], self.xy[key][1], self.rs[sig][0],
            self.rs[sig][1], message)

    def test_group_i_runs_and_reports_ok(self):
        result = subprocess.run(
            [sys.executable, "-S", str(PROBE)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("(i) M26 chain pins ok", result.stdout)

    def test_pem_window_offset_and_length(self):
        self.assertEqual(self.pem_off, 1258)
        self.assertEqual(len(self.pem), 3678)
        self.assertEqual(self.pem.count(b"\x00"), 1)
        self.assertEqual(self.pem.count(b"\r"), 0)
        self.assertNotEqual(len(self.pem), 3679)

    def test_block_offsets_and_lengths(self):
        lens = [len(x) for x in self.blocks]
        self.assertEqual(lens, [1773, 956, 949])
        self.assertEqual([sum(lens[0:k]) for k in range(len(lens))],
                         [0, 1773, 2729])
        self.assertNotEqual(lens, [1773, 956, 950])

    def test_newline_counts_per_block_and_between_markers(self):
        self.assertEqual([x.count(b"\n") for x in self.blocks], [29, 16, 16])
        between = [x.split(MARKER, 1)[-1].split(END_MARKER, 1)[0]
                   for x in self.blocks]
        self.assertEqual([x.count(b"\n") for x in between], [28, 15, 15])
        self.assertNotEqual([x.count(b"\n") for x in between], [29, 16, 16])

    def test_base64_body_lengths_and_pads(self):
        bodies = [self.probe.pem_body(x) for x in self.blocks]
        self.assertEqual([len(x) for x in bodies], [1692, 888, 880])
        self.assertEqual([x.count("=") for x in bodies], [0, 0, 1])
        self.assertNotIn("\n", "".join(bodies))

    def test_block_three_tail_bytes(self):
        self.assertEqual(self.probe.hx(self.blocks[2][-10:]),
                         "4154452d2d2d2d2d0a00")
        self.assertNotEqual(self.probe.hx(self.blocks[1][-10:]),
                            "4154452d2d2d2d2d0a00")

    def test_der_sizes_and_digests_sit_in_check_rows(self):
        self.assertEqual([len(x) for x in self.ders], [1269, 666, 659])
        for der in self.ders:
            good = hashlib.sha256(der).hexdigest()
            other = hashlib.sha256(der[0:-1]).hexdigest()
            self.row([good], [other])

    def test_tbs_windows_and_digests_sit_in_check_rows(self):
        self.assertEqual([len(x) for x in self.tbs], [1178, 577, 568])
        self.assertEqual([c["tbs"][3] for c in self.certs],
                         [1174, 573, 564])
        for window in self.tbs:
            self.row([hashlib.sha256(window).hexdigest()],
                     [hashlib.sha256(window[4:]).hexdigest()])

    def test_version_and_serial_shape(self):
        self.assertEqual({self.probe.hx(c["version"]) for c in self.certs},
                         {"a003020102"})
        self.assertEqual([len(c["serial"]) for c in self.certs],
                         [20, 21, 20])
        self.assertEqual(self.certs[1]["serial"][0], 0)
        self.assertNotEqual(self.certs[0]["serial"][0], 0)

    def test_signature_algorithm_agrees_inside_and_out(self):
        for cert in self.certs:
            self.assertEqual(self.probe.hx(cert["outer_alg"]),
                             "300a06082a8648ce3d040302")
            self.assertEqual(cert["tbs_alg"], cert["outer_alg"])
        self.assertNotEqual(self.probe.hx(self.certs[0]["outer_alg"]),
                            "300a06082a8648ce3d040303")

    def test_root_pin_equals_the_collateral_file(self):
        pinned = (ROOT / "fixtures/collateral/TrustedRootCA.der").read_bytes()
        self.assertEqual(self.ders[2], pinned)
        self.assertEqual(len(pinned), 659)
        moved = bytearray(pinned)
        moved[0] ^= 1
        self.assertNotEqual(self.ders[2], bytes(moved))
        self.row(["root_pin", "659"], ["root_pin", "660"])

    def test_root_issuer_equals_the_root_subject(self):
        self.assertEqual(self.certs[2]["issuer"], self.certs[2]["subject"])
        self.assertNotEqual(self.certs[0]["issuer"], self.certs[0]["subject"])

    def test_point_offsets_and_sec1_lead_byte(self):
        self.assertEqual([x["at"] for x in self.points], [333, 326, 317])
        for point in self.points:
            self.assertEqual(point["bits_len"], 66)
            self.assertEqual(point["unused"], 0)
            self.assertEqual(len(point["point"]), 65)
            self.assertEqual(point["point"][0], 0x04)

    def test_leaf_point_halves_sit_in_one_check_row(self):
        (x, y) = self.xy[0]
        self.assertEqual((x, y), self.probe.pck_leaf_xy(self.pem))
        self.row([x, y], [y + x, x + x])

    def test_ca_point_halves_sit_in_check_rows(self):
        self.row([self.xy[1][0], self.xy[1][1]],
                 [self.xy[1][1] + self.xy[1][0], self.xy[1][0] + "00"])
        self.row([self.xy[2][0], self.xy[2][1]],
                 [self.xy[2][1] + self.xy[2][0], self.xy[2][0] + "00"])


    def test_leaf_leg_verifies_under_the_intermediate_key(self):
        self.assertTrue(self.leg(1, 0, self.tbs[0]))
        broken = bytes([self.tbs[0][0] ^ 1]) + self.tbs[0][1:]
        self.assertFalse(self.leg(1, 0, broken))

    def test_intermediate_leg_verifies_under_the_root_key(self):
        self.assertTrue(self.leg(2, 1, self.tbs[1]))
        broken = self.tbs[1][0:-1] + bytes([self.tbs[1][-1] ^ 0x80])
        self.assertFalse(self.leg(2, 1, broken))

    def test_the_two_cross_legs_fail(self):
        self.assertFalse(self.leg(2, 0, self.tbs[0]))
        self.assertFalse(self.leg(0, 1, self.tbs[1]))
        self.assertTrue(self.leg(2, 2, self.tbs[2]))

    def test_the_twin_s_verifies_so_no_low_s_rule_is_owed(self):
        probe = self.probe
        twin = probe.hx(
            (probe.P256_N - int(self.rs[0][1], 16)).to_bytes(32, "big"))
        self.assertTrue(probe.p256_verify_message(
            self.xy[1][0], self.xy[1][1], self.rs[0][0], twin, self.tbs[0]))
        self.assertNotEqual(twin, self.rs[0][1])
        self.assertEqual([int(x[1], 16) * 2 < probe.P256_N for x in self.rs],
                         [False, True, False])

    def test_signature_half_lengths_and_first_bytes(self):
        self.assertEqual([x["sig_bits"][1] for x in self.certs],
                         [1194, 593, 584])
        self.assertEqual([x["inner"][3] for x in self.sigs], [70, 68, 70])
        self.assertEqual([(len(x["r"]), len(x["s"])) for x in self.sigs],
                         [(33, 33), (32, 32), (33, 33)])
        self.assertEqual([(x["r"][0], x["s"][0]) for x in self.sigs],
                         [(0, 0), (94, 38), (0, 0)])
        self.assertEqual({x["unused"] for x in self.sigs}, {0})

    def test_signature_halves_sit_in_check_rows(self):
        self.row([self.rs[0][0], self.rs[0][1]],
                 [self.rs[0][0], self.rs[0][1] + "00"])
        self.row([self.rs[1][0], self.rs[1][1]],
                 [self.rs[1][0], self.rs[1][1] + "00"])

    def test_issuer_chain_equalities_and_the_control(self):
        self.assertEqual(self.certs[0]["issuer"], self.certs[1]["subject"])
        self.assertEqual(self.certs[1]["issuer"], self.certs[2]["subject"])
        self.assertNotEqual(self.certs[0]["subject"],
                            self.certs[1]["subject"])
        probe = self.probe
        offs = [probe.der_kids(d, c["tbs"])[3][1]
                for (d, c) in zip(self.ders, self.certs)]
        self.assertEqual(offs, [47, 48, 47])
        self.assertEqual([(len(c["issuer"]), len(c["subject"]))
                          for c in self.certs],
                         [(114, 114), (106, 114), (106, 106)])

    def test_validity_strings_and_offsets(self):
        probe = self.probe
        rows = [probe.der_kids(d, c["validity"])
                for (d, c) in zip(self.ders, self.certs)]
        times = [[probe.der_body(d, n).decode("ascii") for n in row]
                 for (d, row) in zip(self.ders, rows)]
        self.assertEqual(times, [["250206232551Z", "320206232551Z"],
                                 ["180521105010Z", "330521105010Z"],
                                 ["180521104510Z", "491231235959Z"]])
        self.assertEqual([[n[1] for n in row] for row in rows],
                         [[163, 178], [156, 171], [155, 170]])
        for row in rows:
            for node in row:
                self.assertEqual(node[0], 0x17)
                self.assertEqual(node[3], 13)

    def test_the_pivoted_witnesses_sit_in_check_rows(self):
        self.row(["20250206232551", "20320206232551"],
                 ["19250206232551", "20320206232551"])
        self.row(["20180521105010", "20330521105010"],
                 ["19180521105010", "20330521105010"])
        self.row(["20180521104510", "20491231235959"],
                 ["19180521104510", "20491231235959"])

    def test_the_five_now_answers_sit_in_check_rows(self):
        self.row(["20260906000000"], ["20260906000001", "20260906000000"])
        self.row(["20240101000000", "not yet valid"],
                 ["20240101000000", "not yet valid ever"])
        self.row(["20320206232552", "expired"],
                 ["20320206232553", "expired"])
        self.row(["20330521105011", "expired"],
                 ["20330521105012", "expired"])
        self.row(["20500101000000", "expired"],
                 ["20500101000001", "expired"])

    def test_the_utc_pivot_rows_sit_in_check_rows(self):
        self.row(["491231235959Z", "20491231235959"],
                 ["491231235959Z", "19491231235959"])
        self.row(["500101000000Z", "19500101000000"],
                 ["500101000000Z", "20500101000000"])

    def test_extension_counts_offsets_and_critical_flags(self):
        self.assertEqual([len(x) for x in self.exts], [6, 5, 5])
        self.assertEqual([x["oid_at"] for x in self.exts[0]],
                         [408, 441, 550, 581, 597, 613])
        self.assertEqual([x["value"][3] for x in self.exts[0]],
                         [24, 100, 22, 4, 2, 554])
        self.assertEqual([x["critical"] for x in self.exts[0]],
                         [False, False, False, True, True, False])
        self.assertEqual([x["oid_at"] for x in self.exts[1]],
                         [399, 432, 516, 547, 563])
        self.assertEqual([x["oid_at"] for x in self.exts[2]],
                         [390, 423, 507, 538, 554])
        for rows in self.exts:
            for row in rows:
                self.assertIn(row["flag"], (b"", b"\xff"))

    def test_key_usage_and_basic_constraints_sit_in_check_rows(self):
        probe = self.probe
        ku = [probe.hx(probe.ext_value(d, r, "551d0f"))
              for (d, r) in zip(self.ders, self.exts)]
        bc = [probe.hx(probe.ext_value(d, r, "551d13"))
              for (d, r) in zip(self.ders, self.exts)]
        self.assertEqual(ku, ["030206c0", "03020106", "03020106"])
        self.assertEqual(bc, ["3000", "30060101ff020100",
                              "30060101ff020101"])
        self.row([ku[0]], [ku[0] + "ff"])
        self.row([bc[1]], [bc[1] + "ff"])

    def test_sgx_offsets_and_member_tails(self):
        probe = self.probe
        octet = probe.ext_node(self.exts[0], probe.hx(probe.SGX_EXT_OID))
        self.assertEqual((octet[1], octet[3]), (624, 554))
        seq = probe.der_kids(self.ders[0], octet)[0]
        self.assertEqual((seq[1], seq[3]), (628, 550))
        members = probe.sgx_members(self.ders[0], seq)
        self.assertEqual(sorted(members.keys()), [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(members[probe.SGX_TCB_TAIL][1], 680)
        tcb = probe.sgx_members(self.ders[0], members[probe.SGX_TCB_TAIL])
        self.assertEqual(len(tcb), 18)
        self.assertEqual(tcb[probe.TCB_PCESVN_TAIL][1], 987)
        self.assertEqual(tcb[probe.TCB_CPUSVN_TAIL][1], 1005)
        self.assertEqual(members[probe.SGX_PCE_ID_TAIL][1], 1037)
        self.assertEqual(members[probe.SGX_FMSPC_TAIL][1], 1055)

    def sgx(self):
        """The four SGX values M27 consumes, plus the components."""
        probe = self.probe
        octet = probe.ext_node(self.exts[0], probe.hx(probe.SGX_EXT_OID))
        seq = probe.der_kids(self.ders[0], octet)[0]
        members = probe.sgx_members(self.ders[0], seq)
        tcb = probe.sgx_members(self.ders[0], members[probe.SGX_TCB_TAIL])
        body = (lambda node: probe.der_body(self.ders[0], node))
        return {
            "pcesvn": int.from_bytes(body(tcb[probe.TCB_PCESVN_TAIL]),
                                     "big"),
            "cpusvn": probe.hx(body(tcb[probe.TCB_CPUSVN_TAIL])),
            "pce_id": probe.hx(body(members[probe.SGX_PCE_ID_TAIL])),
            "fmspc": probe.hx(body(members[probe.SGX_FMSPC_TAIL])),
            "components": [int.from_bytes(body(tcb[k]), "big")
                           for k in range(1, 17)],
        }

    def test_sgx_numbers_sit_in_check_rows(self):
        values = self.sgx()
        self.assertEqual(values["pcesvn"], 11)
        self.assertEqual(values["cpusvn"],
                         "03030202040100050000000000000000")
        self.assertEqual(values["fmspc"], "b0c06f000000")
        self.assertEqual(values["pce_id"], "0000")
        self.row(["pcesvn", "11"], ["pcesvn", "12"])
        self.row(["cpusvn", values["cpusvn"]],
                 ["cpusvn", values["cpusvn"] + "00"])
        self.row(["fmspc", values["fmspc"]],
                 ["fmspc", values["fmspc"] + "00"])
        self.row(["pce_id", values["pce_id"]],
                 ["pce_id", values["pce_id"] + "00"])

    def test_tcb_components_pin_and_the_cpusvn_agreement(self):
        values = self.sgx()
        self.assertEqual(values["components"],
                         [3, 3, 2, 2, 4, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(self.probe.hx(bytes(values["components"])),
                         values["cpusvn"])
        spelled = "; ".join(str(x) for x in values["components"])
        self.row(["tcb_components", spelled],
                 ["tcb_components", spelled + "; 0"])
        self.row(["tcb_components", "cpusvn"],
                 ["tcb_components", "pcesvn_of_cpusvn"])

    def test_no_ca_certificate_carries_the_sgx_extension(self):
        probe = self.probe
        wanted = probe.hx(probe.SGX_EXT_OID)
        self.assertIsNotNone(probe.ext_node(self.exts[0], wanted))
        self.assertIsNone(probe.ext_node(self.exts[1], wanted))
        self.assertIsNone(probe.ext_node(self.exts[2], wanted))

    def test_the_second_der_reader_reads_both_length_forms(self):
        probe = self.probe
        short = bytes.fromhex("0403010203")
        self.assertEqual(probe.der_elem(short, 0), (0x04, 0, 2, 3))
        long_form = bytes.fromhex("308202") + b"\x8f" + b"\x00" * 655
        self.assertEqual(probe.der_elem(long_form, 0), (0x30, 0, 4, 655))
        self.assertEqual(probe.der_elem(self.ders[0], 0)[3], 1265)

    def test_the_oid_content_strings_sit_in_check_rows(self):
        self.row(["2a8648ce3d040302"], ["2a8648ce3d040303"])
        self.row(["2a8648ce3d030107"], ["2a8648ce3d030108"])
        self.row([self.probe.hx(self.probe.SGX_EXT_OID)],
                 [self.probe.hx(self.probe.SGX_EXT_OID) + "01"])


if __name__ == "__main__":
    unittest.main()
