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
