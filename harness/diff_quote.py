#!/usr/bin/env python3
"""M22 fixture oracle over the TDX quote fixtures under fixtures/
(DESIGN.md section 8).

It decodes a REAL Intel-signed production TDX quote at every pinned
offset and requires every decoded field to equal its pin, and it proves
its own arithmetic first. The bytes come from fixtures/tdx_quote_v4.bin
and fixtures/tdx_quote_v5.bin, which are byte-identical copies of
Phala-Network/dcap-qvl sample/tdx_quote and sample/tdx_quote_outdated at
commit 7cb5caceb9dcce345a7d1413110c69df3a907479, MIT licence, and from
fixtures/collateral/, which holds sample/tdx_quote_collateral.json and
src/TrustedRootCA.der from the same commit. fixtures/README.md carries
the provenance table and fixtures/LICENSE.dcap-qvl carries the licence
text those copies require.

No line of any upstream project is copied here. The layout table below
is a table of absolute offsets, one row per field, restated from the two
independent code sources dcap-qvl src/quote.rs and go-tdx-guest
abi/abi.go, which agree on every byte range. The REPORTDATA formula is
one concatenation and it carries its own controls.

Three SELF-CHECK legs run BEFORE any pin is read, which is the M18 to
M21 rule of DESIGN.md section 8. (i) The QE binding is recomputed with
hashlib on every run: sha256(attestation_key || qe_auth_data) must equal
qe_report_data[0..32]. (ii) The REPORTDATA formula runs on a known
synthetic pair and must equal the hand-laid address || 12 zero bytes ||
nonce, with a flipped-nonce control that MUST mismatch and a non-zero
pad control that the zero test MUST reject. (iii) The version-5 fixture
decodes to its own descriptor and its own length identity.

The fixture's OWN report_data is NOT expected to satisfy the Venice
formula. The sample is Phala's and not a Venice quote, so the harness
prints one info line and never tests that binding on these bytes. The
ISV P-256 signature is NOT verified here either, because the gate
interpreter carries no P-256 library; M25 owns that check.

In fixture mode require counts a failure, prints its label and
CONTINUES, so one gate run reports EVERY failing group. Only the live
mode of D3(b) exits 1 at its first failure.

Usage:
  diff_quote.py                                fixture mode, the gate
  diff_quote.py live FILE [--expect-nonce HEX] live mode, the probe
"""

import base64
import hashlib
import json
import pathlib
import re
import struct
import sys


# Paths are resolved against THIS file, never the working directory, so
# a scratch copy of the tree reads its own scratch fixtures.
here = pathlib.Path(__file__).resolve().parent
root = here.parent
fixtures = root / "fixtures"
v4_path = fixtures / "tdx_quote_v4.bin"
v5_path = fixtures / "tdx_quote_v5.bin"
collateral_json_path = fixtures / "collateral" / "tdx_quote_collateral.json"
root_ca_path = fixtures / "collateral" / "TrustedRootCA.der"

# The M23 suite the group (f) pins are QUOTATIONS of (D11).
suite_path = root / "test" / "test_quotex.ml"

# The M24 suite the group (g) pins are QUOTATIONS of (D11).
policy_suite_path = root / "test" / "test_policyx.ml"

# The M25 suite the group (h) pins are QUOTATIONS of (D11).
sig_suite_path = root / "test" / "test_sigx.ml"

# The M26 suite the group (i) pins are QUOTATIONS of (D11).
cert_suite_path = root / "test" / "test_derx.ml"

fail = 0


def hx(b: bytes) -> str:
    """The lower-case hex of a byte string."""
    return b.hex()


def uh(s: str) -> bytes:
    """The bytes of a lower-case hex string."""
    return bytes.fromhex(s)


def bail(message: str) -> None:
    """A self-check that fails leaves nothing worth pinning."""
    print(f"diff_quote: SELF-CHECK FAILED: {message}")
    sys.exit(1)


def require(label: str, ok: bool) -> None:
    """Count a failure, print its label and CONTINUE (D3, A10)."""
    global fail
    if not ok:
        print(f"diff_quote: {label}: FAILED")
        fail += 1


def pin(label: str, got: str, want: str) -> None:
    """Require one decoded field to equal its pinned value."""
    global fail
    if got != want:
        print(f"diff_quote: {label}: the fixture disagrees with the pin")
        print(f"  wanted: {want}")
        print(f"  got:    {got}")
        fail += 1


def group(name: str, before: int) -> None:
    """One diff_quote: <group> ok line per group, when nothing failed."""
    if fail == before:
        print(f"diff_quote: {name} ok")


def read_fixture(path: pathlib.Path) -> bytes:
    """A missing fixture is a RED gate, never a silent skip."""
    if not path.is_file():
        print(f"diff_quote: the fixture is missing: {path}")
        sys.exit(1)
    return path.read_bytes()


def u16(b: bytes, off: int) -> int:
    """The little-endian u16 at an absolute offset."""
    return struct.unpack_from("<H", b, off)[0]


def u32(b: bytes, off: int) -> int:
    """The little-endian u32 at an absolute offset."""
    return struct.unpack_from("<I", b, off)[0]


# ---------- the M23 suite matcher (D11) -------------------------------
#
# strip_ocaml_comments, check_rows and the LABEL pattern are copied
# VERBATIM from harness/diff_gcm.py:559, :585 and :626. A suite pin that
# a later edit moves into a comment, into an unread top-level let or
# into a row NAME then sits inside no check row, and group (f) below
# turns the gate RED.


def strip_ocaml_comments(text: str) -> str:
    """Replace every (* ... *) comment with one space, nesting aware."""
    out = []
    depth = 0
    i = 0
    end = len(text)
    while i < end:
        if text.startswith("(*", i):
            depth += 1
            i += 2
            continue
        if text.startswith("*)", i) and depth > 0:
            depth -= 1
            i += 2
            out.append(" ")
            continue
        if depth == 0:
            out.append(text[i])
        i += 1
    return "".join(out)


ROW_START = re.compile(r'^\s*(?:\[\s*)?\(\s*"')
TOP_LEVEL = re.compile(r"^\S")


def check_rows(text: str) -> list:
    """Split the stripped suite into check rows.

    A row opens on an indented `( "label",` line and closes at the next
    row or at the next column-zero definition, so a constant sitting in
    a top-level let is outside every row.
    """
    rows = []
    current = None
    for line in text.splitlines():
        if ROW_START.match(line):
            if current is not None:
                rows.append("\n".join(current))
            current = [line]
        elif current is not None:
            if TOP_LEVEL.match(line):
                rows.append("\n".join(current))
                current = None
            else:
                current.append(line)
    if current is not None:
        rows.append("\n".join(current))
    return rows


LABEL = re.compile(r'^\s*(?:\[\s*)?\(\s*"(?:[^"\\]|\\.)*"')


def suite_bodies(path=None) -> list:
    """Every check row of one suite file, with its NAME removed.

    The name is dropped so a value that only appears in a row TITLE
    never satisfies a pin. The default is the module-level suite_path,
    read at CALL time, so the group (f) call keeps the behavior it had
    before M24 added group (g).
    """
    chosen = suite_path if path is None else path
    if not chosen.is_file():
        return []
    stripped = strip_ocaml_comments(chosen.read_text())
    return [LABEL.sub("", row, count=1) for row in check_rows(stripped)]


def in_row(bodies: list, needles: list) -> bool:
    """True when ONE check row holds EVERY needle of a pin."""
    return any(all(x in body for x in needles) for body in bodies)


# ---------- the group (f) recompute, struct-free (D11) ----------------
#
# These two readers share no cursor with lib/quotex.ml and no line with
# the struct-based u16 and u32 above, so the oracle and the unit can
# only agree by agreeing on the BYTES.


def le(b: bytes, off: int, size: int) -> int:
    """A little-endian integer of `size` bytes at an ABSOLUTE offset."""
    return int.from_bytes(b[off:off + size], "little")


def marker_blocks(window: bytes, marker: bytes) -> list:
    """Cut a PEM window marker to marker, the last block to the end."""
    starts = [i for i in range(len(window) - len(marker) + 1)
              if window[i:i + len(marker)] == marker]
    ends = starts[1:] + [len(window)]
    return [window[a:b] for (a, b) in zip(starts, ends)]


# Standard-library Keccak oracle reused from harness/diff_keccak.py.
# Keep the generated round constants and rho offsets independent of OCaml.
MASK = (1 << 64) - 1
RATE = 136
HASH_LEN = 32


# ---------- the reference implementation, tables generated ----------


def round_constants() -> list:
    """FIPS 202 3.2.5: rc(t) from the 8-bit LFSR, 24 lane constants."""
    out = []
    lfsr = 1
    for _ in range(24):
        lane = 0
        for j in range(7):
            if lfsr & 1:
                lane ^= 1 << ((1 << j) - 1)
            lfsr <<= 1
            if lfsr & 0x100:
                lfsr ^= 0x171
        out.append(lane)
    return out


def rho_offsets() -> dict:
    """FIPS 202 3.2.2: the offsets from the (x, y) recurrence."""
    off = {(0, 0): 0}
    x, y = 1, 0
    for t in range(24):
        off[(x, y)] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return off


RC = round_constants()
RHO = rho_offsets()


def rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & MASK if n else v


def keccak_f(lanes: list) -> list:
    """keccak-p[1600, 24]; lane (x, y) sits at index x + 5 * y."""
    for rc in RC:
        col = [
            lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20]
            for x in range(5)
        ]
        d = [col[(x - 1) % 5] ^ rotl(col[(x + 1) % 5], 1) for x in range(5)]
        lanes = [lanes[x + 5 * y] ^ d[x] for y in range(5) for x in range(5)]
        b = [0] * 25
        for y in range(5):
            for x in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(lanes[x + 5 * y], RHO[(x, y)])
        lanes = [
            b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y] & MASK)
            for y in range(5)
            for x in range(5)
        ]
        lanes[0] = lanes[0] ^ rc
    return lanes


def pad(msg: bytes, domain: int) -> bytes:
    """The multi-rate pad at rate 136."""
    tail = len(msg) % RATE
    if tail == RATE - 1:
        return msg + bytes([domain | 0x80])
    return msg + bytes([domain]) + bytes(RATE - tail - 2) + bytes([0x80])


def sponge(msg: bytes, domain: int) -> bytes:
    lanes = [0] * 25
    block = pad(msg, domain)
    for start in range(0, len(block), RATE):
        chunk = block[start : start + RATE]
        for i in range(17):
            lanes[i] = lanes[i] ^ int.from_bytes(chunk[8 * i : 8 * i + 8], "little")
        lanes = keccak_f(lanes)
    out = b""
    for i in range(4):
        out = out + lanes[i].to_bytes(8, "little")
    return out[:HASH_LEN]


def keccak256(b: bytes) -> bytes:
    """Keccak-256 with its original domain separator, not SHA3-256."""
    return sponge(b, 0x01)


def eth_address(xy: bytes) -> bytes:
    """The last 20 bytes of keccak-256 over the 64-byte X || Y.

    The 0x04 prefix of an uncompressed SEC1 point is stripped by the
    caller, because the digest runs over the 64 coordinate bytes alone
    (consumer venice-e2ee/src/attestation.ts:134-145).
    """
    return keccak256(xy)[12:32]


def report_data_ecdsa(address20: bytes, nonce32: bytes) -> bytes:
    """report_data = address20 || 0x00 x 12 || nonce32 (W1).

    The producer writes this as one line, an ljust to 32 bytes with a
    zero pad followed by the raw nonce
    (private-ml-sdk/vllm-proxy/src/app/quote/quote.py:50). There is no
    hash of the nonce, no prefix and no length byte.
    """
    return address20.ljust(32, b"\x00") + nonce32


def report_data_ed25519(key32: bytes, nonce32: bytes) -> bytes:
    """The ED25519 branch: the raw 32-byte public key, then the nonce.

    The same ljust pads NOTHING here, so bytes 20..32 carry key bytes
    and the zero window of the ECDSA path does not apply (A1, A3).
    """
    return key32.ljust(32, b"\x00") + nonce32


# ---------- the pinned bytes of the four copied files (D1, A15) ----------
#
# The sha256 AND the byte count of every copied file, so a corrupted or
# a truncated collateral file makes the gate RED at M22 and not at M26.

SHA256_V4 = "c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db"
SHA256_V5 = "4c453ea417a7863ed67c215fe4735d91e26f359c760e5984a277866d8d5758e9"
SHA256_COLLATERAL_JSON = (
    "b0a5f5fd620a8881b1eda45261fdf30dd930b49aff93231556645c81fcb4c0bc"
)
SHA256_ROOT_CA_DER = (
    "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
)
BYTES_V4 = 5006
BYTES_V5 = 5006
BYTES_COLLATERAL_JSON = 16072
BYTES_ROOT_CA_DER = 659

# ---------- the version-4 layout, one row per field (W3, A8) ----------
#
# A FLAT table of ABSOLUTE offsets. One row per field, so moving one row
# moves only that row's pin and no other check reads it. Header 48 bytes
# at 0, TD report 1.0 584 bytes at 48, report_data ending at 632.

V4_ROWS = [
    ("version", 0, 2, "0400"),
    ("att_key_type", 2, 2, "0200"),
    ("tee_type", 4, 4, "81000000"),
    ("header_u16_at_8", 8, 2, "0000"),
    ("header_u16_at_10", 10, 2, "0000"),
    ("qe_vendor_id", 12, 16, "939a7233f79c4ca9940a0db3957f0607"),
    ("user_data", 28, 20, "889b7d6ff9df2405b240a830e73faf3d00000000"),
    ("tee_tcb_svn", 48, 16, "06010300000000000000000000000000"),
    ("mr_seam", 64, 48,
     "5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c43"
     "6489d6c8e4f92f160b7cad34207b00c1"),
    ("mrsigner_seam", 112, 48, "00" * 48),
    ("seam_attributes", 160, 8, "0000000000000000"),
    ("td_attributes", 168, 8, "0000001000000000"),
    ("xfam", 176, 8, "e702060000000000"),
    ("mr_td", 184, 48,
     "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407"
     "de03ae6dc5f87f27428b2538873118b7"),
    ("mr_config_id", 232, 48, "00" * 48),
    ("mr_owner", 280, 48, "00" * 48),
    ("mr_owner_config", 328, 48, "00" * 48),
    ("rt_mr0", 376, 48,
     "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c"
     "48aca29b220b80b6a540cf994b9bc9c0"),
    ("rt_mr1", 424, 48,
     "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7"
     "aea8c323c173019b3093d54e579e9378"),
    ("rt_mr2", 472, 48,
     "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3"
     "ba80b70870d7330733642e01d48c3132"),
    ("rt_mr3", 520, 48, "00" * 48),
    ("report_data", 568, 64,
     "9a9d48e7f6799642d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9"
     "eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20"),
]

V4_OFFSET = {name: off for (name, off, _size, _want) in V4_ROWS}

# The signature section and the certification chain of the same quote.
V4_SIGNATURE_DATA_LEN_OFF = 632
V4_SIGNATURE_DATA_LEN = 4300
V4_SIGNATURE_OFF = 636
V4_ATT_KEY_OFF = 700
V4_CERT_KEY_TYPE_OFF = 764
V4_CERT_SIZE_OFF = 766
V4_QE_REPORT_OFF = 770
V4_QE_REPORT_DATA_OFF = 1090
V4_QE_SIGNATURE_OFF = 1154
V4_AUTH_SIZE_OFF = 1218
V4_AUTH_DATA_OFF = 1220
V4_INNER_TYPE_OFF = 1252
V4_INNER_SIZE_OFF = 1254
V4_PEM_OFF = 1258
V4_CERT_SIZE = 4166
V4_AUTH_SIZE = 32
V4_INNER_SIZE = 3678
PEM_MARKER = b"-----BEGIN CERTIFICATE-----"

QE_BINDING = "c936492a774946af9b588f6b3bd8beddc5957d1761ded2c0bb61d7b64de5b324"

# ---------- the version-5 delta (W4) ----------
#
# A v5 quote inserts a 6-byte body descriptor between the header and the
# report, so every TD 1.0 field shifts by 6 and the signed region ends
# at 702 instead of 632.

V5_BODY_TYPE_OFF = 48
V5_BODY_SIZE_OFF = 50
V5_TD_ATTRIBUTES_OFF = 174
V5_XFAM_OFF = 182
V5_REPORT_DATA_OFF = 574
V5_TEE_TCB_SVN2_OFF = 638
V5_MR_SERVICE_TD_OFF = 654
V5_SIGNATURE_DATA_LEN_OFF = 702
V5_SIGNATURE_OFF = 706
V5_BODY_TYPE = 3
V5_BODY_SIZE = 648
V5_TD_ATTRIBUTES = "0000001000000000"
V5_XFAM = "e718060000000000"
V5_TEE_TCB_SVN2 = "0d010300000000000000000000000000"
V5_SIGNATURE_DATA_LEN = 4300

# ---------- the synthetic pair the formula self-check runs on ----------
#
# A FIXED pair, so the self-check proves the formula and never borrows a
# value from the fixture it is about to pin.

SYNTHETIC_XY = bytes(range(0x40))
SYNTHETIC_KECCAK = (
    "002030bde3d4cf89919649775cd71875c4d0ab1708a380e03fefc3a28aa24831"
)
SYNTHETIC_ADDRESS = "5cd71875c4d0ab1708a380e03fefc3a28aa24831"
SYNTHETIC_NONCE = (
    "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293"
)
SYNTHETIC_REPORT_DATA = (
    "5cd71875c4d0ab1708a380e03fefc3a28aa24831"
    "000000000000000000000000"
    "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293"
)
SYNTHETIC_ZERO_WINDOW = "000000000000000000000000"
# The ED25519 control: the raw key bytes 0x40..0x5f fill the window the
# ECDSA path requires to be zero, so the zero test MUST reject it.
ED25519_CONTROL_WINDOW = "5455565758595a5b5c5d5e5f"

# ---------- the W5 real-key vector the M24 suite binds against --------
#
# The suite mints the secp256k1 generator as Secpx.Pubkey.of_scalar of
# the scalar 1. The oracle keeps the two COORDINATES only and re-derives
# the address and the report_data from its own keccak, so a constant
# copied out of lib/policyx.ml or out of the suite cannot satisfy the
# pins below.

G_X = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
G_Y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
# The M24 suite paints the SAME nonce the synthetic pair carries (W5).
G_NONCE = SYNTHETIC_NONCE


# ---------- self-check (i): the QE binding, recomputed every run ------
#
# sha256(attestation_key || qe_auth_data) must equal qe_report_data
# [0..32]. Both operands come out of the fixture, so this leg proves the
# decode and the digest before any pinned constant is read.


def self_check_qe_binding(quote: bytes) -> None:
    """Recompute the QE binding with hashlib and require the match."""
    auth_size = u16(quote, V4_AUTH_SIZE_OFF)
    attkey = quote[V4_ATT_KEY_OFF:V4_ATT_KEY_OFF + 64]
    auth = quote[V4_AUTH_DATA_OFF:V4_AUTH_DATA_OFF + auth_size]
    qe_report_data = quote[V4_QE_REPORT_DATA_OFF:V4_QE_REPORT_DATA_OFF + 64]
    recomputed = hashlib.sha256(attkey + auth).hexdigest()
    before = fail
    require(
        "qe-binding sha256(attkey || qe_auth_data) == qe_report_data[0..32]",
        recomputed == hx(qe_report_data[:32]),
    )
    require(
        "qe-binding qe_report_data[32..64] is zero",
        qe_report_data[32:] == bytes(32),
    )
    group("qe-binding self-check", before)


# ---------- self-check (ii): the formula and its two controls ---------
#
# The formula runs on a FIXED synthetic pair, never on the fixture, so a
# python bug is visible before a pin is read. Two controls follow: a
# flipped nonce byte MUST mismatch, and a non-zero pad MUST be rejected
# by the zero test on bytes 20..32.


def self_check_formula() -> None:
    """Prove the address derivation and the concatenation of W1."""
    before = fail
    digest = keccak256(SYNTHETIC_XY)
    address = eth_address(SYNTHETIC_XY)
    built = report_data_ecdsa(address, uh(SYNTHETIC_NONCE))
    hand_laid = address + bytes(12) + uh(SYNTHETIC_NONCE)
    require("formula keccak256 of the synthetic pair",
            hx(digest) == SYNTHETIC_KECCAK)
    require("formula address is the last 20 digest bytes",
            hx(address) == SYNTHETIC_ADDRESS)
    require("formula output is 64 bytes", len(built) == 64)
    require("formula output equals the pinned value",
            hx(built) == SYNTHETIC_REPORT_DATA)
    require("formula output equals address || 12 zero bytes || nonce",
            built == hand_laid)
    require("formula zero window 20..32",
            hx(built[20:32]) == SYNTHETIC_ZERO_WINDOW)
    group("formula self-check", before)

    # Control 1: flip the first nonce byte from 5f to 5e. The formula
    # MUST produce a different 64 bytes.
    before = fail
    flipped = bytes([uh(SYNTHETIC_NONCE)[0] ^ 0x01]) + uh(SYNTHETIC_NONCE)[1:]
    require("formula control the flipped nonce starts 5e",
            hx(flipped)[:2] == "5e")
    require("formula control the flipped nonce mismatches",
            report_data_ecdsa(address, flipped) != built)
    group("formula control flipped nonce", before)

    # Control 2: set byte 25 to 0x7f. The zero test on 20..32 MUST
    # reject it. The ED25519 window of A1 is the same rejection on real
    # key bytes, which is why the zero test is an ECDSA-path rule.
    before = fail
    tampered = bytearray(built)
    tampered[25] = 0x7F
    require("formula control the non-zero pad is rejected",
            bytes(tampered[20:32]) != bytes(12))
    require("formula control the untouched pad is accepted",
            built[20:32] == bytes(12))
    ed_window = report_data_ed25519(bytes(range(0x40, 0x60)),
                                    uh(SYNTHETIC_NONCE))[20:32]
    require("formula control the ed25519 window is not zero",
            hx(ed_window) == ED25519_CONTROL_WINDOW)
    group("formula control non-zero pad", before)


# ---------- self-check (iii): the version-5 delta ---------------------
#
# The v5 fixture carries its OWN descriptor and its OWN length identity,
# 706 + signature_data_len == 5006 with no trailing padding, so it is
# decoded on its own terms and not against the v4 table.


def self_check_v5(quote: bytes) -> None:
    """Decode the v5 fixture at the shifted offsets of W4."""
    before = fail
    require("v5 version 5", u16(quote, V4_OFFSET["version"]) == 5)
    require("v5 body type 3", u16(quote, V5_BODY_TYPE_OFF) == V5_BODY_TYPE)
    require("v5 body size 648", u32(quote, V5_BODY_SIZE_OFF) == V5_BODY_SIZE)
    td_attributes = quote[V5_TD_ATTRIBUTES_OFF:V5_TD_ATTRIBUTES_OFF + 8]
    require("v5 td_attributes at 174", hx(td_attributes) == V5_TD_ATTRIBUTES)
    require("v5 DEBUG bit clear", (td_attributes[0] & 0x01) == 0)
    require("v5 xfam at 182",
            hx(quote[V5_XFAM_OFF:V5_XFAM_OFF + 8]) == V5_XFAM)
    require("v5 tee_tcb_svn2 at 638",
            hx(quote[V5_TEE_TCB_SVN2_OFF:V5_TEE_TCB_SVN2_OFF + 16])
            == V5_TEE_TCB_SVN2)
    require("v5 mr_service_td at 654 is zero",
            quote[V5_MR_SERVICE_TD_OFF:V5_MR_SERVICE_TD_OFF + 48] == bytes(48))
    signature_data_len = u32(quote, V5_SIGNATURE_DATA_LEN_OFF)
    require("v5 signature_data_len 4300 at 702",
            signature_data_len == V5_SIGNATURE_DATA_LEN)
    require("v5 706 + signature_data_len == length",
            V5_SIGNATURE_OFF + signature_data_len == len(quote))
    require("v5 report_data at 574 is 64 bytes",
            len(quote[V5_REPORT_DATA_OFF:V5_REPORT_DATA_OFF + 64]) == 64)
    group("v5 self-check", before)


# ---------- the affine P-256 group (h) owns (D11) ---------------------
#
# Transcribed from harness/diff_p256.py lines 54 to 120 and NOT
# imported: that file carries no if __name__ == "__main__" guard, so an
# import of it runs its own pin sweep over test/test_p256x.ml and can
# exit this process. The names carry a P256 prefix so nothing here
# collides with the keccak oracle above. ec_verify there takes the
# message digest as an INTEGER, so the wrapper below hashes the message
# itself. lib/p256x.ml runs Jacobian coordinates; this runs affine ones
# over python integers, so the unit and the oracle agree only when both
# are right.

P256_P = int(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16
)
P256_N = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16
)
P256_B = int(
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16
)
P256_G = (
    int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
    int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
)
P256_SPKI_MARKER = bytes.fromhex("03420004")


def p256_on_curve(point) -> bool:
    """y^2 = x^3 - 3x + b over the field prime. None is not a pair."""
    if point is None:
        return False
    x, y = point
    return (y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0


def p256_add(pa, pb):
    """Affine addition; None is the point at infinity."""
    if pa is None:
        return pb
    if pb is None:
        return pa
    x1, y1 = pa
    x2, y2 = pb
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if pa == pb:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    return (x3, (lam * (x1 - x3) - y1) % P256_P)


def p256_mul(k: int, point):
    """Double-and-add, LSB-first, over the affine addition above."""
    acc = None
    addend = point
    while k > 0:
        if k & 1:
            acc = p256_add(acc, addend)
        addend = p256_add(addend, addend)
        k >>= 1
    return acc


def p256_verify(pub, r: int, s: int, e: int) -> bool:
    """FIPS 186-4 verification, with the psychic rejects first."""
    if not 1 <= r < P256_N or not 1 <= s < P256_N:
        return False
    w = pow(s, -1, P256_N)
    shared = p256_add(
        p256_mul(e * w % P256_N, P256_G), p256_mul(r * w % P256_N, pub)
    )
    if shared is None:
        return False
    return shared[0] % P256_N == r


def p256_verify_message(x_hex: str, y_hex: str, r_hex: str, s_hex: str,
                        message: bytes) -> bool:
    """Verify a raw r || s under a raw X || Y over a whole message."""
    if len(x_hex) != 64 or len(y_hex) != 64:
        return False
    pub = (int(x_hex, 16), int(y_hex, 16))
    if not p256_on_curve(pub):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return p256_verify(pub, int(r_hex, 16), int(s_hex, 16), e)


def pck_leaf_xy(pem_window: bytes):
    """The SPKI point of the FIRST PEM block, X and Y as hex.

    The block is cut by marker_blocks, its base64 body is decoded to
    DER, and the 64 point bytes sit 4 bytes after the 03 42 00 04
    marker, which is DER offset 330 on the fixture. Two empty strings
    report a walk that found nothing, so the pins below turn RED
    instead of raising.
    """
    blocks = marker_blocks(pem_window, PEM_MARKER)
    if not blocks:
        return ("", "")
    text = blocks[0].decode("ascii", "ignore")
    opened = text.split("-----BEGIN CERTIFICATE-----", 1)
    if len(opened) != 2:
        return ("", "")
    closed = opened[1].split("-----END CERTIFICATE-----", 1)
    if len(closed) != 2:
        return ("", "")
    der = base64.b64decode("".join(closed[0].split()))
    at = der.find(P256_SPKI_MARKER)
    if at < 0:
        return ("", "")
    point = der[at + 4:at + 68]
    if len(point) != 64:
        return ("", "")
    return (hx(point[0:32]), hx(point[32:64]))


# ---------- the group (i) DER walk, struct-free (D12) -----------------
#
# A SECOND DER reader, written for the harness alone. It shares no
# cursor and no line with lib/derx.ml, so the unit and the oracle can
# only agree by agreeing on the BYTES. It reads the short definite form
# and the long definite form and nothing else, which is all the three
# fixture certificates carry. The affine P-256 above and pck_leaf_xy
# are REUSED by the group (i) legs and never duplicated.

TBS_AT = 4
POINT_LEN = 65
SGX_EXT_OID = bytes.fromhex("2a864886f84d010d01")
SGX_TCB_TAIL = 0x02
SGX_PCE_ID_TAIL = 0x03
SGX_FMSPC_TAIL = 0x04
TCB_PCESVN_TAIL = 0x11
TCB_CPUSVN_TAIL = 0x12
BEGIN_TEXT = "-----BEGIN CERTIFICATE-----"
END_TEXT = "-----END CERTIFICATE-----"


def der_elem(b: bytes, off: int):
    """One element at off, as (tag, offset, header size, content length)."""
    first = b[off + 1]
    if first < 0x80:
        return (b[off], off, 2, first)
    count = first - 0x80
    return (b[off], off, 2 + count,
            int.from_bytes(b[off + 2:off + 2 + count], "big"))


def der_siblings(b: bytes, off: int, stop: int) -> list:
    """Every element between off and stop, in wire order."""
    out = []
    while off < stop:
        node = der_elem(b, off)
        out.append(node)
        off += node[2] + node[3]
    return out


def der_kids(b: bytes, node) -> list:
    """The elements inside one element, in wire order."""
    (_, off, hdr, size) = node
    return der_siblings(b, off + hdr, off + hdr + size)


def der_body(b: bytes, node) -> bytes:
    """The CONTENT bytes of one element."""
    (_, off, hdr, size) = node
    return b[off + hdr:off + hdr + size]


def der_whole(b: bytes, node) -> bytes:
    """The element bytes, header included, which is a signed window."""
    (_, off, hdr, size) = node
    return b[off:off + hdr + size]


def pem_body(block: bytes) -> str:
    """The base64 body of one PEM block, every newline removed."""
    text = block.decode("ascii", "ignore")
    opened = text.split(BEGIN_TEXT, 1)
    if len(opened) != 2:
        return ""
    closed = opened[1].split(END_TEXT, 1)
    if len(closed) != 2:
        return ""
    return "".join(closed[0].split())


def chain_ders(pem_window: bytes) -> list:
    """The DER of every PEM block of one window, in wire order."""
    return [base64.b64decode(pem_body(x))
            for x in marker_blocks(pem_window, PEM_MARKER)
            if pem_body(x)]


def cert_fields(der: bytes) -> dict:
    """The tbs window and the eight tbs children of one certificate.

    The tbs element sits at TBS_AT in all three fixture certificates
    and its children are version, serialNumber, signature, issuer,
    validity, subject, subjectPublicKeyInfo and the a3 extensions.
    """
    tbs = der_elem(der, TBS_AT)
    kids = der_kids(der, tbs)
    outer = der_kids(der, der_elem(der, 0))
    return {
        "tbs": tbs,
        "tbs_window": der_whole(der, tbs),
        "version": der_whole(der, kids[0]),
        "serial": der_body(der, kids[1]),
        "tbs_alg": der_whole(der, kids[2]),
        "issuer": der_whole(der, kids[3]),
        "validity": kids[4],
        "subject": der_whole(der, kids[5]),
        "spki": kids[6],
        "exts": kids[7],
        "outer_alg": der_whole(der, outer[1]),
        "sig_bits": outer[2],
    }


def sig_halves(der: bytes, bits) -> dict:
    """The r and s CONTENT bytes inside one signature BIT STRING.

    The BIT STRING carries ZERO unused bits, so the SEQUENCE of the two
    INTEGER halves opens one byte after the content starts.
    """
    (_, off, hdr, _) = bits
    inner = der_elem(der, off + hdr + 1)
    kids = der_kids(der, inner)
    return {
        "unused": der_body(der, bits)[0],
        "inner": inner,
        "r": der_body(der, kids[0]),
        "s": der_body(der, kids[1]),
    }


def spki_point(der: bytes, spki) -> dict:
    """The 65 SEC 1 bytes of one SubjectPublicKeyInfo and their offset."""
    kids = der_kids(der, spki)
    (_, off, hdr, size) = kids[1]
    at = off + hdr + 1
    return {
        "alg": der_whole(der, kids[0]),
        "bits_len": size,
        "unused": der[off + hdr],
        "at": at,
        "point": der[at:at + POINT_LEN],
    }


def ext_rows(der: bytes, exts) -> list:
    """One row per extension of one a3 element, in wire order.

    A row carries the OID CONTENT bytes, the OID ELEMENT offset, the
    critical flag, which is TRUE exactly when the BOOLEAN is present,
    and the extnValue node.
    """
    rows = []
    for ext in der_kids(der, der_kids(der, exts)[0]):
        kids = der_kids(der, ext)
        rows.append({
            "oid": der_body(der, kids[0]),
            "oid_at": kids[0][1],
            "critical": len(kids) == 3,
            "flag": der_body(der, kids[1]) if len(kids) == 3 else b"",
            "value": kids[-1],
        })
    return rows


def sgx_members(b: bytes, node) -> dict:
    """The members of one SGX SEQUENCE, keyed by their LAST OID byte."""
    out = {}
    for member in der_kids(b, node):
        kids = der_kids(b, member)
        out[der_body(b, kids[0])[-1]] = kids[1]
    return out


def ext_value(b: bytes, rows: list, oid_text: str) -> bytes:
    """The extnValue CONTENT bytes of the row whose OID matches."""
    node = ext_node(rows, oid_text)
    return b"" if node is None else der_body(b, node)


def ext_node(rows: list, oid_text: str):
    """The extnValue NODE of the row whose OID matches, else None."""
    wanted = bytes.fromhex(oid_text)
    matched = [row["value"] for row in rows if row["oid"] == wanted]
    return matched[0] if matched else None


# ---------- fixture mode, the default and the gate --------------------


def digest_of(path: pathlib.Path) -> str:
    """The sha256 of a copied file, recomputed on every gate run."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_mode() -> int:
    """Run the self-checks, then every pin group, then report."""
    v4 = read_fixture(v4_path)
    v5 = read_fixture(v5_path)
    if len(v4) < V4_PEM_OFF + len(PEM_MARKER):
        bail(f"{v4_path} is too short to decode at all")
    if len(v5) < V5_SIGNATURE_OFF:
        bail(f"{v5_path} is too short to decode at all")

    # The three SELF-CHECK legs, BEFORE any pin (A9).
    self_check_qe_binding(v4)
    self_check_formula()
    self_check_v5(v5)

    # The one thing this fixture cannot show. Its report_data is Phala's
    # and not a Venice REPORTDATA, so the W1 binding is never tested on
    # these bytes. scripts/probe_attestation.sh closes that debt.
    print(
        "diff_quote: info the fixture report_data is Phala's, not a Venice "
        "REPORTDATA, so the W1 binding is not tested on these bytes"
    )

    # ---------- pin (a): the four copied files, digest and length ----
    before = fail
    pin("sha256 pin v4", digest_of(v4_path), SHA256_V4)
    require("bytes pin v4", len(v4) == BYTES_V4)
    pin("sha256 pin v5", digest_of(v5_path), SHA256_V5)
    require("bytes pin v5", len(v5) == BYTES_V5)
    if collateral_json_path.is_file():
        pin("sha256 pin collateral json",
            digest_of(collateral_json_path), SHA256_COLLATERAL_JSON)
        require("bytes pin collateral json",
                collateral_json_path.stat().st_size == BYTES_COLLATERAL_JSON)
    else:
        require(f"the collateral file is missing: {collateral_json_path}",
                False)
    if root_ca_path.is_file():
        pin("sha256 pin root ca der",
            digest_of(root_ca_path), SHA256_ROOT_CA_DER)
        require("bytes pin root ca der",
                root_ca_path.stat().st_size == BYTES_ROOT_CA_DER)
    else:
        require(f"the collateral file is missing: {root_ca_path}", False)
    group("(a) fixture digests", before)

    # ---------- pin (b): every W3 row of the v4 quote (A8) -----------
    #
    # One pin per table row. Moving one row moves only that row's pin.
    before = fail
    for (name, off, size, want) in V4_ROWS:
        pin(f"{name} pin", hx(v4[off:off + size]), want)
    require("version 4",
            u16(v4, V4_OFFSET["version"]) == 4)
    require("att_key_type 2",
            u16(v4, V4_OFFSET["att_key_type"]) == 2)
    require("tee_type 0x00000081",
            u32(v4, V4_OFFSET["tee_type"]) == 0x00000081)
    require("DEBUG bit clear",
            (v4[V4_OFFSET["td_attributes"]] & 0x01) == 0)
    group("(b) v4 header and body fields", before)

    # ---------- pin (c): the length rule and the trailing padding ----
    #
    # W5: the quote structure ends at 636 + signature_data_len and the
    # surplus is padding a strict decoder would break on.
    before = fail
    signature_data_len = u32(v4, V4_SIGNATURE_DATA_LEN_OFF)
    require("signature_data_len 4300 at 632",
            signature_data_len == V4_SIGNATURE_DATA_LEN)
    end = V4_SIGNATURE_OFF + signature_data_len
    require("636 + signature_data_len <= length", end <= len(v4))
    surplus = v4[end:] if end <= len(v4) else b""
    require("surplus is 70 bytes", len(surplus) == 70)
    require("surplus bytes all zero", surplus == bytes(len(surplus)))
    group("(c) v4 length rule and padding", before)

    # ---------- pin (d): the certification chain (W3, W7) ------------
    before = fail
    require("cert_key_type 6 at 764",
            u16(v4, V4_CERT_KEY_TYPE_OFF) == 6)
    require("cert size 4166 at 766",
            u32(v4, V4_CERT_SIZE_OFF) == V4_CERT_SIZE)
    require("auth size 32 at 1218",
            u16(v4, V4_AUTH_SIZE_OFF) == V4_AUTH_SIZE)
    require("inner certification type 5 at 1252",
            u16(v4, V4_INNER_TYPE_OFF) == 5)
    require("inner size 3678 at 1254",
            u32(v4, V4_INNER_SIZE_OFF) == V4_INNER_SIZE)
    require("PEM at 1258 begins BEGIN CERTIFICATE",
            v4[V4_PEM_OFF:V4_PEM_OFF + len(PEM_MARKER)] == PEM_MARKER)
    require("the PEM chain holds three certificates",
            v4[V4_PEM_OFF:V4_PEM_OFF + V4_INNER_SIZE].count(PEM_MARKER) == 3)
    group("(d) v4 certification chain", before)

    # ---------- pin (e): the QE binding value -------------------------
    #
    # The self-check above proved the recompute. This group pins the
    # value itself, so a fixture swap that keeps its own binding
    # consistent still turns the gate RED.
    before = fail
    qe_report_data = v4[V4_QE_REPORT_DATA_OFF:V4_QE_REPORT_DATA_OFF + 64]
    pin("qe_report_data[0..32] pin", hx(qe_report_data[:32]), QE_BINDING)
    require("the QE report sits at 770 and is 384 bytes",
            V4_QE_REPORT_OFF + 384 == V4_QE_REPORT_DATA_OFF + 64)
    require("the QE report signature sits at 1154",
            V4_QE_SIGNATURE_OFF + 64 == V4_AUTH_SIZE_OFF)
    group("(e) v4 qe binding value", before)

    # ---------- pin (f): the M23 suite pins (D11 as amended by A17) ---
    #
    # Every value of the test/test_quotex.ml groups (b) to (e) is
    # recomputed HERE from the fixture bytes, with absolute offsets and
    # no struct call, and is then REQUIRED to sit inside a CHECK ROW of
    # the suite beside the accessor that produces it. The D7 arithmetic
    # and the W7 block lengths are DERIVED and never quoted, so a suite
    # that copies a wrong constant turns the gate RED instead of
    # agreeing with itself.
    before = fail
    f_signed = v4[0:632]
    f_signed_sha = hashlib.sha256(f_signed).hexdigest()
    f_sdl = le(v4, 632, 4)
    f_end = 636 + f_sdl
    f_surplus = len(v4) - f_end
    f_signature = v4[636:700]
    f_att_key = v4[700:764]
    f_cert_key_type = le(v4, 764, 2)
    f_cert_size = le(v4, 766, 4)
    f_qe_report = v4[770:1154]
    f_qe_report_data = v4[1090:1154]
    f_qe_sig = v4[1154:1218]
    f_auth_size = le(v4, 1218, 2)
    f_auth_data = v4[1220:1220 + f_auth_size]
    f_inner_off = 1220 + f_auth_size
    f_inner_type = le(v4, f_inner_off, 2)
    f_inner_size = le(v4, f_inner_off + 2, 4)
    f_pem = v4[f_inner_off + 6:f_inner_off + 6 + f_inner_size]
    f_blocks = marker_blocks(f_pem, PEM_MARKER)

    # The two D7 equalities, derived from the SIZES of the section
    # fields: 134 is the signature, the attestation key, the
    # cert_key_type word and the cert_size word; 456 is the QE report,
    # the QE report signature, the qe_auth_size word, the inner type
    # word and the inner size word.
    f_cert_overhead = 64 + 64 + 2 + 4
    f_inner_overhead = 384 + 64 + 2 + 2 + 4
    require("(f) cert_size is signature_data_len minus the cert overhead",
            f_cert_size == f_sdl - f_cert_overhead)
    require("(f) inner_size is cert_size minus the inner overhead and "
            "qe_auth_size",
            f_inner_size == f_cert_size - f_inner_overhead - f_auth_size)
    require("(f) the quote structure ends inside the fixture",
            f_end <= len(v4))
    require("(f) the PEM window cuts into three marker blocks",
            len(f_blocks) == 3)
    require("(f) the three block lengths sum to inner_size",
            sum(len(x) for x in f_blocks) == f_inner_size)
    require("(f) block 3 ends with the trailing NUL of W7",
            len(f_blocks) == 3 and f_blocks[2][-1:] == b"\x00")

    # The END marker is LOCATED in block 1 and never typed here.
    f_end_at = f_blocks[0].find(b"-----END") if f_blocks else -1
    require("(f) block 1 holds an END marker", f_end_at >= 0)
    f_begin_text = f_pem[0:len(PEM_MARKER)].decode("ascii", "replace")
    f_end_text = f_blocks[0][
        f_end_at:f_end_at + len(PEM_MARKER) - 2
    ].decode("ascii", "replace") if f_end_at >= 0 else ""

    # One entry per suite value. The first needle is the ACCESSOR the
    # row must call and the second is the recomputed value, and BOTH
    # must sit in the SAME check row, so a value pinned against the
    # wrong field never satisfies its own pin.
    f_pins = [
        ("version", ["version", str(le(v4, 0, 2))]),
        ("att_key_type", ["att_key_type", str(le(v4, 2, 2))]),
        ("tee_type", ["tee_type", str(le(v4, 4, 4))]),
        ("header_u16_at_8", ["header_u16_at_8", str(le(v4, 8, 2))]),
        ("header_u16_at_10", ["header_u16_at_10", str(le(v4, 10, 2))]),
        ("qe_vendor_id", ["qe_vendor_id", hx(v4[12:28])]),
        ("user_data", ["user_data", hx(v4[28:48])]),
        ("tee_tcb_svn", ["tee_tcb_svn", hx(v4[48:64])]),
        ("mr_seam", ["mr_seam", hx(v4[64:112])]),
        ("mrsigner_seam", ["mrsigner_seam", hx(v4[112:160])]),
        ("seam_attributes", ["seam_attributes", f"{le(v4, 160, 8)}L"]),
        ("td_attributes", ["td_attributes", f"{le(v4, 168, 8)}L"]),
        ("xfam", ["xfam", f"{le(v4, 176, 8)}L"]),
        ("mr_td", ["mr_td", hx(v4[184:232])]),
        ("mr_config_id", ["mr_config_id", hx(v4[232:280])]),
        ("mr_owner", ["mr_owner", hx(v4[280:328])]),
        ("mr_owner_config", ["mr_owner_config", hx(v4[328:376])]),
        ("rt_mr0", ["rt_mr0", hx(v4[376:424])]),
        ("rt_mr1", ["rt_mr1", hx(v4[424:472])]),
        ("rt_mr2", ["rt_mr2", hx(v4[472:520])]),
        ("rt_mr3", ["rt_mr3", hx(v4[520:568])]),
        ("report_data", ["report_data", hx(v4[568:632])]),
        ("signed_region length", ["signed_region", str(len(f_signed))]),
        ("signed_region sha256", ["signed_region", f_signed_sha]),
        ("signature_data_len", ["signature_data_len", str(f_sdl)]),
        ("surplus", ["surplus", str(f_surplus)]),
        ("signature", ["signature", hx(f_signature)]),
        ("attestation_key", ["attestation_key", hx(f_att_key)]),
        ("cert_key_type", ["cert_key_type", str(f_cert_key_type)]),
        ("cert_size", ["cert_size", str(f_cert_size)]),
        ("qe_report length", ["qe_report", str(len(f_qe_report))]),
        ("qe_report_data", ["qe_report_data", hx(f_qe_report_data)]),
        ("qe_report_signature", ["qe_report_signature", hx(f_qe_sig)]),
        ("qe_auth_size", ["qe_auth_size", str(f_auth_size)]),
        ("qe_auth_data", ["qe_auth_data", hx(f_auth_data)]),
        ("inner_cert_type", ["inner_cert_type", str(f_inner_type)]),
        ("inner_size", ["inner_size", str(f_inner_size)]),
        ("pem_window length", ["pem_window", str(len(f_pem))]),
        ("pem_chain count", ["pem_chain", str(len(f_blocks))]),
        ("pem_chain BEGIN prefix", ["pem_chain", f_begin_text]),
        ("pem_chain END substring", ["pem_chain", f_end_text]),
        ("pem_chain block 3 trailing NUL", ["pem_chain", "\\000"]),
    ] + [
        (f"pem_chain block {n} length", ["pem_chain", str(len(block))])
        for (n, block) in enumerate(f_blocks, start=1)
    ]

    f_bodies = suite_bodies()
    if not f_bodies:
        require(f"(f) the M23 suite holds no check row: {suite_path}",
                False)
    else:
        for (f_name, f_needles) in f_pins:
            require(f"(f) suite pin {f_name} sits in no check row",
                    in_row(f_bodies, f_needles))
    group("(f) M23 suite pins", before)

    # ---------- group (g), the M24 suite pins (D11) -------------------
    #
    # The five measurement hex strings and byte 168 come straight out of
    # the fixture bytes through the struct-free le reader, and the G
    # address, the G report_data and the synthetic address come out of
    # the keccak of this file. Nothing here is read from lib/policyx.ml,
    # so the unit and the oracle can only agree by agreeing on the
    # BYTES. Each value then has to sit inside a check row of
    # test/test_policyx.ml, whose NAME the matcher strips first.
    before = fail

    g_address = hx(eth_address(uh(G_X) + uh(G_Y)))
    g_report_data = hx(report_data_ecdsa(uh(g_address), uh(G_NONCE)))
    g_synthetic_address = hx(eth_address(SYNTHETIC_XY))

    g_pins = [
        ("mr_td", ["mr_td", hx(v4[184:232])]),
        ("rt_mr0", ["rt_mr0", hx(v4[376:424])]),
        ("rt_mr1", ["rt_mr1", hx(v4[424:472])]),
        ("rt_mr2", ["rt_mr2", hx(v4[472:520])]),
        ("rt_mr3", ["rt_mr3", hx(v4[520:568])]),
        ("td_attributes", ["td_attributes", f"{le(v4, 168, 8)}L"]),
        ("the G address", [g_address]),
        # The three windows of W1, so a row that CONCATENATES the
        # address, the zero pad and the nonce satisfies the pin as well
        # as a row that spells the 64 bytes out.
        ("the G report_data", [g_report_data[0:40],
                               g_report_data[40:64],
                               g_report_data[64:128]]),
        ("the synthetic address", [g_synthetic_address]),
    ]

    g_bodies = suite_bodies(policy_suite_path)
    if not g_bodies:
        require(f"(g) the M24 suite holds no check row: {policy_suite_path}",
                False)
    else:
        for (g_name, g_needles) in g_pins:
            require(f"(g) suite pin {g_name} sits in no check row",
                    in_row(g_bodies, g_needles))
    group("(g) M24 suite pins", before)

    # ---------- group (h), the M25 suite pins (D11) -------------------
    #
    # Every value below is recomputed HERE from the fixture bytes: the
    # W1 integers through the struct-free le reader, the W2 and W4
    # halves by absolute slices, the W3 binding digest by the same
    # hashlib computation the qe-binding self-check runs, the W4 PCK
    # leaf key by a base64 decode of the FIRST PEM block, and the two
    # W5 windows out of the QE report. The oracle then VERIFIES both
    # ECDSA legs with the affine P-256 above. Nothing here is read from
    # lib/sigx.ml, so the unit and the oracle can only agree by
    # agreeing on the BYTES. Each recomputed value then has to sit
    # inside a check row of test/test_sigx.ml, whose NAME the matcher
    # strips first.
    before = fail

    h_sdl = le(v4, 632, 4)
    h_isv_r = hx(v4[636:668])
    h_isv_s = hx(v4[668:700])
    h_key_x = hx(v4[700:732])
    h_key_y = hx(v4[732:764])
    h_cert_key_type = le(v4, 764, 2)
    h_cert_size = le(v4, 766, 4)
    h_qe_report = v4[770:1154]
    h_qe_r = hx(v4[1154:1186])
    h_qe_s = hx(v4[1186:1218])
    h_auth_size = le(v4, 1218, 2)
    h_auth = v4[1220:1220 + h_auth_size]
    h_inner_off = 1220 + h_auth_size
    h_inner_type = le(v4, h_inner_off, 2)
    h_inner_size = le(v4, h_inner_off + 2, 4)
    h_pem = v4[h_inner_off + 6:h_inner_off + 6 + h_inner_size]
    h_binding = hashlib.sha256(v4[700:764] + h_auth).hexdigest()
    h_cpusvn = hx(h_qe_report[0:16])
    h_mrsigner = hx(h_qe_report[128:160])
    (h_leaf_x, h_leaf_y) = pck_leaf_xy(h_pem)

    # The two ECDSA legs, VERIFIED and never quoted. They run before
    # the suite pins, so a fixture swap reddens the arithmetic first.
    require("(h) the QE report signature verifies under the PCK leaf key",
            p256_verify_message(h_leaf_x, h_leaf_y, h_qe_r, h_qe_s,
                                h_qe_report))
    require("(h) the ISV signature verifies under the attestation key",
            p256_verify_message(h_key_x, h_key_y, h_isv_r, h_isv_s,
                                v4[0:632]))

    h_pins = [
        ("signature_data_len", ["signature_data_len", str(h_sdl)]),
        ("cert_key_type", ["cert_key_type", str(h_cert_key_type)]),
        ("cert_size", ["cert_size", str(h_cert_size)]),
        ("qe_auth_size", ["qe_auth_size", str(h_auth_size)]),
        ("inner_cert_type", ["inner_cert_type", str(h_inner_type)]),
        ("inner_size", ["inner_size", str(h_inner_size)]),
        ("the ISV r at 636", [h_isv_r]),
        ("the ISV s at 668", [h_isv_s]),
        ("the attestation key X at 700", [h_key_x]),
        ("the attestation key Y at 732", [h_key_y]),
        ("the QE r at 1154", [h_qe_r]),
        ("the QE s at 1186", [h_qe_s]),
        ("the auth data at 1220", [hx(h_auth)]),
        ("the QE binding digest", [h_binding]),
        # The two leaf halves are needled apart, so a row that spells
        # the 128 hex characters out satisfies the pin as well as a row
        # that concatenates the halves.
        ("the PCK leaf key", [h_leaf_x, h_leaf_y]),
        ("the mrsigner window at report offset 128", [h_mrsigner]),
        ("the cpusvn window at report offset 0", [h_cpusvn]),
    ]

    h_bodies = suite_bodies(sig_suite_path)
    if not h_bodies:
        require(f"(h) the M25 suite holds no check row: {sig_suite_path}",
                False)
    else:
        for (h_name, h_needles) in h_pins:
            require(f"(h) suite pin {h_name} sits in no check row",
                    in_row(h_bodies, h_needles))
    group("(h) M25 suite pins", before)

    # ---------- group (i), the M26 chain pins (D12) --------------------
    #
    # Every value below is recomputed HERE from the fixture bytes by the
    # second DER reader above: the W1 block shape through marker_blocks,
    # the W2 sizes and digests through a base64 decode and hashlib, the
    # W3 pin against fixtures/collateral/TrustedRootCA.der on disk, the
    # W4 OIDs and points through the tbs walk, the W5 halves and BOTH
    # chain legs through the affine P-256 of group (h), the W6 Name
    # compares as RAW TLV bytes, the W7 time strings out of the two
    # Validity elements, and the W8 extension rows and SGX members
    # through an OID walk. Nothing here is read from lib/derx.ml, so the
    # unit and the oracle can only agree by agreeing on the BYTES. Each
    # recomputed value then has to sit inside a check row of
    # test/test_derx.ml, whose NAME the matcher strips first.
    before = fail

    i_auth = le(v4, 1218, 2)
    i_inner = 1220 + i_auth
    i_pem_off = i_inner + 6
    i_pem = v4[i_pem_off:i_pem_off + le(v4, i_inner + 2, 4)]
    pin("(i) the pem window offset", str(i_pem_off), "1258")
    pin("(i) the pem window length", str(len(i_pem)), "3678")
    pin("(i) the pem window nul count", str(i_pem.count(b"\x00")), "1")
    pin("(i) the pem window carriage return count",
        str(i_pem.count(b"\r")), "0")

    i_blocks = marker_blocks(i_pem, PEM_MARKER)
    i_lens = [len(x) for x in i_blocks]
    i_offs = [sum(i_lens[0:k]) for k in range(len(i_lens))]
    pin("(i) the block count", str(len(i_blocks)), "3")
    pin("(i) the block lengths", str(i_lens), "[1773, 956, 949]")
    pin("(i) the block offsets", str(i_offs), "[0, 1773, 2729]")
    pin("(i) the newlines per whole block",
        str([x.count(b"\n") for x in i_blocks]), "[29, 16, 16]")
    i_between = [x.split(PEM_MARKER, 1)[-1].split(END_TEXT.encode(), 1)[0]
                 for x in i_blocks]
    pin("(i) the newlines between the markers",
        str([x.count(b"\n") for x in i_between]), "[28, 15, 15]")
    i_b64 = [pem_body(x) for x in i_blocks]
    pin("(i) the base64 body lengths",
        str([len(x) for x in i_b64]), "[1692, 888, 880]")
    pin("(i) the base64 pad counts",
        str([x.count("=") for x in i_b64]), "[0, 0, 1]")
    pin("(i) the block 3 tail bytes", hx(i_blocks[2][-10:]),
        "4154452d2d2d2d2d0a00")

    i_ders = chain_ders(i_pem)
    i_der_sha = [hashlib.sha256(x).hexdigest() for x in i_ders]
    pin("(i) the der sizes", str([len(x) for x in i_ders]),
        "[1269, 666, 659]")
    pin("(i) the leaf der digest", i_der_sha[0],
        "c2fb4124d84998cc005c38e13766843777e1c47a1e0b89ad720fd70c2e90927e")
    pin("(i) the intermediate der digest", i_der_sha[1],
        "22eb770dca215b607b5ccfc21a672b1da5cc660b1ad0365020567979edcaa0e1")
    pin("(i) the root der digest", i_der_sha[2],
        "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3")

    i_certs = [cert_fields(x) for x in i_ders]
    i_tbs = [x["tbs_window"] for x in i_certs]
    i_tbs_sha = [hashlib.sha256(x).hexdigest() for x in i_tbs]
    pin("(i) the tbs element sizes", str([len(x) for x in i_tbs]),
        "[1178, 577, 568]")
    pin("(i) the tbs content lengths",
        str([x["tbs"][3] for x in i_certs]), "[1174, 573, 564]")
    pin("(i) the leaf tbs digest", i_tbs_sha[0],
        "504501ea2c2013ec9e2f8b4f78773c63675899d73f2036e0671c4a3e73ed6a9f")
    pin("(i) the intermediate tbs digest", i_tbs_sha[1],
        "581d1ff77ba97123a71722be563b50238f861198a174eb3e2d32cd8d5b710e70")
    pin("(i) the root tbs digest", i_tbs_sha[2],
        "0e1c8ad1fad9254ad1d0bc362c4c83dad27f32fc903cbb9cda58349ec2a4626a")
    pin("(i) the version elements",
        str(sorted({hx(x["version"]) for x in i_certs})), "['a003020102']")
    pin("(i) the serial content lengths",
        str([len(x["serial"]) for x in i_certs]), "[20, 21, 20]")
    require("(i) the intermediate serial carries a leading sign byte",
            i_certs[1]["serial"][0] == 0)
    require("(i) every outer signatureAlgorithm is ecdsa-with-SHA256",
            all(hx(x["outer_alg"]) == "300a06082a8648ce3d040302"
                for x in i_certs))
    require("(i) every tbs signatureAlgorithm equals the outer one",
            all(x["tbs_alg"] == x["outer_alg"] for x in i_certs))

    i_root_file = read_fixture(root_ca_path)
    require("(i) block 3 equals the pinned Intel SGX Root CA file",
            i_ders[2] == i_root_file)
    pin("(i) the pinned root length", str(len(i_root_file)), "659")
    require("(i) the root issuer and subject are the same raw TLV",
            i_certs[2]["issuer"] == i_certs[2]["subject"])

    i_points = [spki_point(d, c["spki"]) for (d, c) in zip(i_ders, i_certs)]
    i_xy = [(hx(x["point"][1:33]), hx(x["point"][33:65])) for x in i_points]
    pin("(i) the point offsets", str([x["at"] for x in i_points]),
        "[333, 326, 317]")
    require("(i) every spki bit string holds 66 bytes and no unused bit",
            all(x["bits_len"] == 66 and x["unused"] == 0 for x in i_points))
    require("(i) every point is 65 bytes and opens with the SEC 1 lead 04",
            all(len(x["point"]) == POINT_LEN and x["point"][0] == 0x04
                for x in i_points))
    require("(i) every spki algorithm names ecPublicKey and prime256v1",
            all(bytes.fromhex("2a8648ce3d0201") in x["alg"]
                and bytes.fromhex("2a8648ce3d030107") in x["alg"]
                for x in i_points))
    pin("(i) the leaf point x", i_xy[0][0],
        "1720fa04edef8680bfb748fd965af93d61a417a8f1f29910e8b88b3666dfff6d")
    pin("(i) the leaf point y", i_xy[0][1],
        "2b2660f3288f203356f90253a7f6f76616e24212c22cfcc3e66d681f971c9769")
    pin("(i) the intermediate point x", i_xy[1][0],
        "35207feeddb595748ed82bb3a71c3be1e241ef61320c6816e6b5c2b71dad5532")
    pin("(i) the intermediate point y", i_xy[1][1],
        "eaea12a4eb3f948916429ea47ba6c3af82a15e4b19664e52657939a2d96633de")
    pin("(i) the root point x", i_xy[2][0],
        "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f5")
    pin("(i) the root point y", i_xy[2][1],
        "67918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394")
    require("(i) the leaf point equals the M25 pck leaf key of W9",
            i_xy[0] == pck_leaf_xy(i_pem))

    # The two chain legs, VERIFIED and never quoted, plus the four W5
    # controls. They run before the suite pins, so a fixture swap
    # reddens the arithmetic first.
    i_sigs = [sig_halves(d, c["sig_bits"]) for (d, c) in zip(i_ders, i_certs)]
    i_rs = [(hx(x["r"][-32:]), hx(x["s"][-32:])) for x in i_sigs]
    pin("(i) the signature bit string offsets",
        str([x["sig_bits"][1] for x in i_certs]), "[1194, 593, 584]")
    pin("(i) the inner sequence content lengths",
        str([x["inner"][3] for x in i_sigs]), "[70, 68, 70]")
    pin("(i) the r and s content lengths",
        str([(len(x["r"]), len(x["s"])) for x in i_sigs]),
        "[(33, 33), (32, 32), (33, 33)]")
    pin("(i) the r and s first content bytes",
        str([(x["r"][0], x["s"][0]) for x in i_sigs]),
        "[(0, 0), (94, 38), (0, 0)]")
    require("(i) every signature bit string carries zero unused bits",
            all(x["unused"] == 0 for x in i_sigs))
    require("(i) the leaf tbs window verifies under the intermediate key",
            p256_verify_message(i_xy[1][0], i_xy[1][1], i_rs[0][0],
                                i_rs[0][1], i_tbs[0]))
    require("(i) the intermediate tbs window verifies under the root key",
            p256_verify_message(i_xy[2][0], i_xy[2][1], i_rs[1][0],
                                i_rs[1][1], i_tbs[1]))
    require("(i) the root tbs window verifies under its OWN key, which "
            "derx never checks",
            p256_verify_message(i_xy[2][0], i_xy[2][1], i_rs[2][0],
                                i_rs[2][1], i_tbs[2]))
    require("(i) control the leaf tbs window fails under the root key",
            not p256_verify_message(i_xy[2][0], i_xy[2][1], i_rs[0][0],
                                    i_rs[0][1], i_tbs[0]))
    require("(i) control the intermediate tbs window fails under the leaf "
            "key",
            not p256_verify_message(i_xy[0][0], i_xy[0][1], i_rs[1][0],
                                    i_rs[1][1], i_tbs[1]))
    require("(i) control one flipped tbs byte breaks the leaf leg",
            not p256_verify_message(
                i_xy[1][0], i_xy[1][1], i_rs[0][0], i_rs[0][1],
                bytes([i_tbs[0][0] ^ 1]) + i_tbs[0][1:]))
    require("(i) control the twin s verifies, so no low-s rule is owed",
            p256_verify_message(
                i_xy[1][0], i_xy[1][1], i_rs[0][0],
                hx((P256_N - int(i_rs[0][1], 16)).to_bytes(32, "big")),
                i_tbs[0]))
    pin("(i) the low-s answers",
        str([int(x[1], 16) * 2 < P256_N for x in i_rs]),
        "[False, True, False]")

    require("(i) the leaf issuer equals the intermediate subject",
            i_certs[0]["issuer"] == i_certs[1]["subject"])
    require("(i) the intermediate issuer equals the root subject",
            i_certs[1]["issuer"] == i_certs[2]["subject"])
    require("(i) control the leaf subject differs from the intermediate "
            "subject, so the compare is not vacuous",
            i_certs[0]["subject"] != i_certs[1]["subject"])
    pin("(i) the issuer element offsets",
        str([der_kids(d, c["tbs"])[3][1] for (d, c) in zip(i_ders, i_certs)]),
        "[47, 48, 47]")
    pin("(i) the subject element offsets",
        str([der_kids(d, c["tbs"])[5][1] for (d, c) in zip(i_ders, i_certs)]),
        "[193, 186, 185]")
    pin("(i) the name element lengths",
        str([(len(x["issuer"]), len(x["subject"])) for x in i_certs]),
        "[(114, 114), (106, 114), (106, 106)]")

    i_val = [der_kids(d, c["validity"]) for (d, c) in zip(i_ders, i_certs)]
    i_times = [[der_body(d, n).decode("ascii", "ignore") for n in row]
               for (d, row) in zip(i_ders, i_val)]
    pin("(i) the six validity strings", str(i_times),
        "[['250206232551Z', '320206232551Z'], "
        "['180521105010Z', '330521105010Z'], "
        "['180521104510Z', '491231235959Z']]")
    pin("(i) the validity element offsets",
        str([[n[1] for n in row] for row in i_val]),
        "[[163, 178], [156, 171], [155, 170]]")
    require("(i) every validity element is UTCTime with 13 content bytes",
            all(n[0] == 0x17 and n[3] == 13 for row in i_val for n in row))
    i_pivot = [("20" if int(t[0:2]) < 50 else "19") + t[0:12]
               for row in i_times for t in row]
    pin("(i) the pivoted witnesses of RFC 5280 4.1.2.5.1", str(i_pivot),
        "['20250206232551', '20320206232551', '20180521105010', "
        "'20330521105010', '20180521104510', '20491231235959']")

    i_exts = [ext_rows(d, c["exts"]) for (d, c) in zip(i_ders, i_certs)]
    pin("(i) the extension counts", str([len(x) for x in i_exts]),
        "[6, 5, 5]")
    pin("(i) the leaf extension oid offsets",
        str([x["oid_at"] for x in i_exts[0]]),
        "[408, 441, 550, 581, 597, 613]")
    pin("(i) the leaf extension value lengths",
        str([x["value"][3] for x in i_exts[0]]),
        "[24, 100, 22, 4, 2, 554]")
    pin("(i) the leaf critical flags",
        str([x["critical"] for x in i_exts[0]]),
        "[False, False, False, True, True, False]")
    pin("(i) the intermediate extension oid offsets",
        str([x["oid_at"] for x in i_exts[1]]), "[399, 432, 516, 547, 563]")
    pin("(i) the root extension oid offsets",
        str([x["oid_at"] for x in i_exts[2]]), "[390, 423, 507, 538, 554]")
    pin("(i) the ca extension value lengths",
        str([[x["value"][3] for x in row] for row in i_exts[1:]]),
        "[[24, 75, 22, 4, 8], [24, 75, 22, 4, 8]]")
    require("(i) a present critical boolean always encodes ff",
            all(x["flag"] in (b"", b"\xff") for row in i_exts for x in row))
    i_ku = [hx(ext_value(d, row, "551d0f")) for (d, row) in zip(i_ders,
                                                               i_exts)]
    pin("(i) the key usage values", str(i_ku),
        "['030206c0', '03020106', '03020106']")
    i_bc = [hx(ext_value(d, row, "551d13")) for (d, row) in zip(i_ders,
                                                               i_exts)]
    pin("(i) the basic constraints values", str(i_bc),
        "['3000', '30060101ff020100', '30060101ff020101']")

    i_oct = ext_node(i_exts[0], hx(SGX_EXT_OID))
    pin("(i) the sgx octet string offset", str(i_oct[1]), "624")
    pin("(i) the sgx octet string content length", str(i_oct[3]), "554")
    i_seq = der_kids(i_ders[0], i_oct)[0]
    pin("(i) the sgx sequence offset", str(i_seq[1]), "628")
    pin("(i) the sgx sequence content length", str(i_seq[3]), "550")
    i_members = sgx_members(i_ders[0], i_seq)
    pin("(i) the sgx member tails", str(sorted(i_members.keys())),
        "[1, 2, 3, 4, 5, 6, 7]")
    pin("(i) the tcb value element offset",
        str(i_members[SGX_TCB_TAIL][1]), "680")
    i_tcb = sgx_members(i_ders[0], i_members[SGX_TCB_TAIL])
    pin("(i) the tcb member count", str(len(i_tcb)), "18")
    i_comps = [int.from_bytes(der_body(i_ders[0], i_tcb[k]), "big")
               for k in range(1, 17)]
    pin("(i) the sixteen tcb components of RUL-M26-3", str(i_comps),
        "[3, 3, 2, 2, 4, 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0]")
    i_pcesvn = int.from_bytes(der_body(i_ders[0], i_tcb[TCB_PCESVN_TAIL]),
                              "big")
    pin("(i) the pcesvn", str(i_pcesvn), "11")
    pin("(i) the pcesvn element offset",
        str(i_tcb[TCB_PCESVN_TAIL][1]), "987")
    i_cpusvn = hx(der_body(i_ders[0], i_tcb[TCB_CPUSVN_TAIL]))
    pin("(i) the cpusvn", i_cpusvn, "03030202040100050000000000000000")
    pin("(i) the cpusvn element offset",
        str(i_tcb[TCB_CPUSVN_TAIL][1]), "1005")
    i_pce_id = hx(der_body(i_ders[0], i_members[SGX_PCE_ID_TAIL]))
    pin("(i) the pce id", i_pce_id, "0000")
    pin("(i) the pce id element offset",
        str(i_members[SGX_PCE_ID_TAIL][1]), "1037")
    i_fmspc = hx(der_body(i_ders[0], i_members[SGX_FMSPC_TAIL]))
    pin("(i) the fmspc", i_fmspc, "b0c06f000000")
    pin("(i) the fmspc element offset",
        str(i_members[SGX_FMSPC_TAIL][1]), "1055")
    require("(i) the sixteen tcb components equal the cpusvn bytes "
            "(RUL-M26-3)", hx(bytes(i_comps)) == i_cpusvn)
    require("(i) no ca certificate carries the sgx extension",
            all(ext_node(row, hx(SGX_EXT_OID)) is None
                for row in i_exts[1:]))

    # Each recomputed value now has to sit inside ONE check row of the
    # M26 suite. A needle list is satisfied by one row that holds EVERY
    # needle, so the halves of a key or a time and its answer are
    # needled apart and a row title never satisfies a pin.
    i_pins = [
        ("the pem window length", ["pem_window", "3678"]),
        ("the three block lengths", ["1773", "956", "949"]),
        ("the leaf der size", ["1269"]),
        ("the intermediate der size", ["666"]),
        ("the root der size", ["659"]),
        ("the leaf der digest", [i_der_sha[0]]),
        ("the intermediate der digest", [i_der_sha[1]]),
        ("the root der digest", [i_der_sha[2]]),
        ("the three tbs element sizes", ["1178", "577", "568"]),
        ("the leaf tbs digest", [i_tbs_sha[0]]),
        ("the intermediate tbs digest", [i_tbs_sha[1]]),
        ("the root tbs digest", [i_tbs_sha[2]]),
        ("the root pin length", ["root_pin", "659"]),
        ("the root pin digest", ["root_pin", i_der_sha[2]]),
        ("the leaf point halves", [i_xy[0][0], i_xy[0][1]]),
        ("the intermediate point halves", [i_xy[1][0], i_xy[1][1]]),
        ("the root point halves", [i_xy[2][0], i_xy[2][1]]),
        ("the pck_key accessor beside the leaf point",
         ["pck_key", i_xy[0][0]]),
        ("the leaf signature halves", [i_rs[0][0], i_rs[0][1]]),
        ("the intermediate signature halves", [i_rs[1][0], i_rs[1][1]]),
        ("the leaf validity window", [i_pivot[0], i_pivot[1]]),
        ("the intermediate validity window", [i_pivot[2], i_pivot[3]]),
        ("the root validity window", [i_pivot[4], i_pivot[5]]),
        ("the ok witness", ["20260906000000"]),
        ("the not yet valid witness", ["20240101000000", "not yet valid"]),
        ("the one second past notAfter witness",
         ["20320206232552", "expired"]),
        ("the intermediate expiry witness", ["20330521105011", "expired"]),
        ("the far future witness", ["20500101000000", "expired"]),
        ("the utc pivot low row", ["491231235959Z", "20491231235959"]),
        ("the utc pivot high row", ["500101000000Z", "19500101000000"]),
        ("the pcesvn", ["pcesvn", str(i_pcesvn)]),
        ("the cpusvn", ["cpusvn", i_cpusvn]),
        ("the fmspc", ["fmspc", i_fmspc]),
        ("the pce id", ["pce_id", i_pce_id]),
        ("the sixteen tcb components",
         ["tcb_components", "; ".join(str(x) for x in i_comps)]),
        ("the tcb components beside the cpusvn bytes",
         ["tcb_components", "cpusvn"]),
        ("the leaf key usage value", ["030206c0"]),
        ("the ca key usage value", ["03020106"]),
        ("the leaf basic constraints value", ["3000"]),
        ("the intermediate basic constraints value", ["30060101ff020100"]),
        ("the root basic constraints value", ["30060101ff020101"]),
        ("the ecdsa-with-SHA256 oid content", ["2a8648ce3d040302"]),
        ("the prime256v1 oid content", ["2a8648ce3d030107"]),
        ("the intel sgx extension oid content", [hx(SGX_EXT_OID)]),
    ]

    i_bodies = suite_bodies(cert_suite_path)
    if not i_bodies:
        require(f"(i) the M26 suite holds no check row: {cert_suite_path}",
                False)
    else:
        for (i_name, i_needles) in i_pins:
            require(f"(i) suite pin {i_name} sits in no check row",
                    in_row(i_bodies, i_needles))
    group("(i) M26 chain pins", before)

    return fail


# ---------- live mode, the probe the gate never calls -----------------
#
# Seven tolerances are EXPLICIT and each one prints a line when it fires
# (D5 as amended by A4). Everything else is strict, and this mode exits
# 1 at its FIRST failure, unlike the fixture mode above.

TOLERANCES = [
    "the nonce member spelling, nonce or request_nonce",
    "the intel_quote encoding, strict base64 or hex",
    "the nvidia_payload form, JSON string, object or absent",
    "the presence of signing_key",
    "the presence of signing_address",
    "the arch label, HOPPER pinned and any other recorded once",
    "the signing_algo value, ecdsa pinned and ed25519 accepted",
]


def live_note(message: str) -> None:
    """A tolerance that fires, or a member the probe recorded."""
    print(f"diff_quote: live: {message}")


def live_fail(message: str) -> None:
    """The live mode stops at its first failure."""
    print(f"diff_quote: live: {message}")
    sys.exit(1)


def live_looks_like_a_quote(quote: bytes) -> bool:
    """A decoding WORKED when it yields a version-4 TDX quote.

    A hex quote whose length is a multiple of four is also valid strict
    base64, because [0-9a-f] sits inside the base64 alphabet, so the
    encoding cannot be told from the string alone. Strict base64 is
    tried first, as D3(b) fixes the order, and the decoded bytes settle
    which reading was the real one.
    """
    return len(quote) >= 636 and u16(quote, V4_OFFSET["version"]) == 4


def live_decode_quote(text: str) -> bytes:
    """Strict base64 first, then hex, and record which one worked."""
    try:
        quote = base64.b64decode(text, validate=True)
        if live_looks_like_a_quote(quote):
            live_note("tolerance intel_quote arrived as strict base64")
            return quote
    except (ValueError, TypeError):
        pass
    try:
        quote = uh(text.removeprefix("0x"))
        if live_looks_like_a_quote(quote):
            live_note("tolerance intel_quote arrived as hex")
            return quote
    except ValueError:
        pass
    live_fail("intel_quote decodes to a version-4 quote as neither strict "
              "base64 nor hex")
    return b""


def live_nvidia(body: dict, nonce_hex: str) -> None:
    """The W10 bound: a JSON string with three members, or a recorded
    absence when the model carries no GPU leg."""
    payload = body.get("nvidia_payload")
    if payload is None:
        provider = str(body.get("tee_provider", ""))
        live_note(
            "tolerance nvidia_payload is absent, tee_provider is "
            f"{provider!r}, the model may be CPU only"
        )
        return
    if isinstance(payload, str):
        live_note("tolerance nvidia_payload arrived as a JSON string")
        try:
            inner = json.loads(payload)
        except ValueError:
            live_fail("nvidia_payload is a string that is not JSON")
            return
    elif isinstance(payload, dict):
        live_note("tolerance nvidia_payload arrived as an object")
        inner = payload
    else:
        live_fail(f"nvidia_payload is neither a string nor an object: "
                  f"{type(payload).__name__}")
        return
    live_note(f"nvidia_payload members {sorted(inner.keys())}")
    for name in ("nonce", "evidence_list", "arch"):
        if name not in inner:
            live_fail(f"nvidia_payload has no {name} member")
    if str(inner["nonce"]).lower() != nonce_hex:
        live_fail("the nvidia_payload nonce differs from the request nonce")
    if not isinstance(inner["evidence_list"], list) or not inner["evidence_list"]:
        live_fail("the nvidia_payload evidence_list is not a non-empty array")
    arch = str(inner["arch"])
    if arch == "HOPPER":
        live_note("nvidia_payload arch HOPPER, the pinned label")
    else:
        live_note(f"tolerance nvidia_payload arch {arch!r}, a new label, "
                  "recorded and accepted once")


def live_mode(path_text: str, expect_nonce: str) -> int:
    """Check one captured attestation body against W1, W3 and W10."""
    path = pathlib.Path(path_text)
    if not path.is_file():
        live_fail(f"the capture is missing: {path}")
    body = json.loads(path.read_text())
    if not isinstance(body, dict):
        live_fail("the capture is not a JSON object")
    live_note(f"members {sorted(body.keys())}")

    # Tolerance 1: the nonce member spelling (W9).
    if "nonce" in body:
        live_note("tolerance the nonce member is spelled nonce")
        nonce_hex = str(body["nonce"]).lower()
    elif "request_nonce" in body:
        live_note("tolerance the nonce member is spelled request_nonce")
        nonce_hex = str(body["request_nonce"]).lower()
    else:
        live_fail("the capture carries neither nonce nor request_nonce")
        return 1
    if len(nonce_hex) != 64:
        live_fail(f"the nonce is {len(nonce_hex)} hex characters, not 64")
    nonce32 = uh(nonce_hex)
    if expect_nonce and nonce_hex != expect_nonce.lower():
        live_fail("the echoed nonce differs from the minted nonce")
    live_note(f"nonce {nonce_hex}")

    # Tolerance 2: the intel_quote encoding.
    if "intel_quote" not in body:
        live_fail("the capture carries no intel_quote member")
    quote = live_decode_quote(str(body["intel_quote"]))
    if len(quote) < 636:
        live_fail(f"the quote is {len(quote)} bytes, too short for a header "
                  "and a TD report")
    if u16(quote, V4_OFFSET["version"]) != 4:
        live_fail(f"the quote version is "
                  f"{u16(quote, V4_OFFSET['version'])}, not 4")
    if u32(quote, V4_OFFSET["tee_type"]) != 0x00000081:
        live_fail("the quote tee_type is not 0x00000081")
    if u16(quote, V4_OFFSET["att_key_type"]) != 2:
        live_fail("the quote att_key_type is not 2")
    signature_data_len = u32(quote, V4_SIGNATURE_DATA_LEN_OFF)
    if V4_SIGNATURE_OFF + signature_data_len > len(quote):
        live_fail("the declared signature data extends beyond the quote")
    # Trailing bytes are permitted by the fixture's length rule, but
    # never counted as signature data.
    surplus = len(quote) - V4_SIGNATURE_OFF - signature_data_len
    live_note(f"signature_data_len {signature_data_len}, trailing bytes {surplus}")
    if (quote[V4_OFFSET["td_attributes"]] & 0x01) != 0:
        live_fail("the DEBUG bit of td_attributes is set")
    live_note("version 4, tee_type 0x00000081, DEBUG bit clear")
    report_data = quote[V4_OFFSET["report_data"]:V4_OFFSET["report_data"] + 64]
    live_note(f"report_data {hx(report_data)}")
    return live_binding(body, report_data, nonce32, nonce_hex)


def live_key_bytes(text: str) -> bytes:
    """The raw key bytes of a hex member, with any 0x prefix removed.

    An uncompressed SEC1 point arrives as 65 bytes with a leading 0x04.
    The keccak digest of W1 runs over the 64 coordinate bytes alone, so
    that prefix byte is stripped here and nowhere else.
    """
    raw = text.strip()
    if raw.startswith("0x") or raw.startswith("0X"):
        raw = raw[2:]
    try:
        return uh(raw)
    except ValueError:
        live_fail(f"a key member is not hex: {text!r}")
        return b""


def live_binding(body: dict, report_data: bytes, nonce32: bytes,
                 nonce_hex: str) -> int:
    """The REPORTDATA binding, on the branch signing_algo selects (A3)."""
    key_member = body.get("signing_key", body.get("signing_public_key"))
    address_member = body.get("signing_address")

    # A4: the key SOURCE is tolerated, its ABSENCE is not. A skipped
    # binding check is the one failure this probe exists to catch, so
    # this line is printed verbatim and the probe stops.
    if key_member is None and address_member is None:
        print("live: no address source, REPORTDATA binding unchecked")
        sys.exit(1)
    if key_member is None:
        live_note("tolerance signing_key is absent, the address member "
                  "carries the binding")
    if address_member is None:
        live_note("tolerance signing_address is absent, the key member "
                  "carries the binding")

    algo = body.get("signing_algo")
    if algo is None:
        live_note("tolerance signing_algo is absent, the producer default "
                  "is ecdsa")
    else:
        live_note(f"signing_algo {str(algo)!r}")
    branch = "" if algo is None else str(algo).lower()

    address20 = b""
    if address_member is not None:
        address20 = live_key_bytes(str(address_member))

    if branch == "" and len(address20) != 20:
        live_fail("signing_algo is absent and signing_address is not 20 "
                  "bytes of hex, so no branch is settled")
    if branch not in ("", "ecdsa", "ed25519"):
        live_fail(f"signing_algo {str(algo)!r} is neither ecdsa nor ed25519")

    if branch in ("", "ecdsa"):
        if key_member is not None:
            xy = live_key_bytes(str(key_member))
            if len(xy) == 65 and xy[0] == 0x04:
                xy = xy[1:]
            if len(xy) != 64:
                live_fail(f"signing_key is {len(xy)} bytes, not the 64 "
                          "coordinate bytes of an uncompressed point")
            derived = eth_address(xy)
            live_note(f"derived address {hx(derived)}")
            if address20 and derived != address20:
                live_fail("the derived address differs from signing_address")
            address20 = derived
        if len(address20) != 20:
            live_fail(f"the address is {len(address20)} bytes, not 20")
        want = report_data_ecdsa(address20, nonce32)
        if report_data[0:20] != address20:
            live_fail("report_data[0..20] is not the signing address")
        if report_data[20:32] != bytes(12):
            live_fail("report_data[20..32] is not zero on the ecdsa path")
        if report_data[32:64] != nonce32:
            live_fail("report_data[32..64] is not the request nonce")
        if report_data != want:
            live_fail("report_data is not address20 || 12 zero bytes || nonce")
        live_note("ecdsa REPORTDATA binding ok, zero window included")
    else:
        if key_member is None:
            live_fail("the ed25519 branch needs signing_key, the 32-byte "
                      "raw public key")
        key32 = live_key_bytes(str(key_member))
        if len(key32) != 32:
            live_fail(f"signing_key is {len(key32)} bytes, not the 32 raw "
                      "ed25519 public key bytes")
        if report_data[0:32] != key32:
            live_fail("report_data[0..32] is not the ed25519 public key")
        if report_data[32:64] != nonce32:
            live_fail("report_data[32..64] is not the request nonce")
        live_note("ed25519 REPORTDATA binding ok, no zero test applies")

    live_nvidia(body, nonce_hex)
    print("diff_quote: live check ok")
    return 0


# ---------- the dispatch ----------------------------------------------


def usage() -> None:
    """One usage line per mode, the fixture mode first."""
    print("usage: diff_quote.py")
    print("       diff_quote.py live FILE [--expect-nonce HEX]")


def main(argv: list) -> int:
    """Fixture mode with no argument, live mode with the live verb."""
    if not argv:
        return fixture_mode()
    if argv[0] != "live":
        print(f"diff_quote: unknown mode: {argv[0]}")
        usage()
        return 2
    if len(argv) < 2:
        print("diff_quote: live mode needs the captured attestation file")
        usage()
        return 2
    expect_nonce = ""
    rest = argv[2:]
    if rest:
        if rest[0] != "--expect-nonce" or len(rest) != 2:
            print(f"diff_quote: unknown live argument: {rest[0]}")
            usage()
            return 2
        expect_nonce = rest[1]
    print("diff_quote: live mode, the seven tolerances of D5 are:")
    for (n, text) in enumerate(TOLERANCES, start=1):
        print(f"  ({n}) {text}")
    return live_mode(argv[1], expect_nonce)


sys.exit(main(sys.argv[1:]))
