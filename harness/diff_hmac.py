#!/usr/bin/env python3
"""M17 differential gate over lib/hmacx.ml.

Every HMAC and HKDF constant that test/test_hmacx.ml pins is recomputed
here from the RFC INPUTS, which this file embeds, with python's hmac and
hashlib and a twelve-line RFC 5869 HKDF, an implementation the OCaml
unit shares no code with. A recomputed value must then sit VERBATIM
inside a CHECK ROW of the suite, which is the part a raw substring test
cannot give: a `must_contain` over the whole file text also passes for a
pin parked in a comment or in a let that no check ever reads.

`strip_ocaml_comments` and the check-row matcher below are COPIED
verbatim from harness/diff_limbs.py (M16). A shared module would change
that file, which is out of scope for M17.

The suite computes each tag from the inputs it holds, so an input that
drifts from the RFC text turns a row false and the gate RED: the suite
and this oracle must agree on inputs AND outputs.

The pins are (a) the RFC 4231 section 4 cases 1 to 7 tags, case 5 as its
16-byte prefix; (b) the boundary keys of 0, 63, 64, 65 and 128 bytes of
0x0b over the message "boundary", where 64 against 65 is the hashed-key
branch; (c) the RFC 5869 appendix A cases 1 to 3, PRK and OKM each; (d)
the top-of-cap expansion of case 1 at len 8160, pinned as the hex of its
LAST 32 bytes, so the 255th block and the counter byte 0xff are
exercised without a 16320-character row.

Then two negative controls. The first: the corrupted twin of case 1's
OKM, its last nibble flipped, must be ABSENT from the stripped text. The
absent twin alone proves only that the search CAN fail; the row context
is what proves the pin sits inside an executed check. The second: the
FULL untruncated RFC 4231 case 5 tag must be ABSENT while its 32-hex-char
prefix is present, so a suite that pinned the whole tag cannot pass the
truncation row for the wrong reason.

Standard library only: hmac, hashlib, re, pathlib, sys.
"""

import hashlib
import hmac
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
root = here.parent
suite_path = root / "test" / "test_hmacx.ml"

fail = 0


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


if not suite_path.is_file():
    print(f"diff_hmac: the suite is missing: {suite_path}")
    sys.exit(1)

RAW = suite_path.read_text()
STRIPPED = strip_ocaml_comments(RAW)
ROWS = check_rows(STRIPPED)

if not ROWS:
    print("diff_hmac: no check row found in the suite; the oracle is vacuous")
    sys.exit(1)


def pin(name: str, needles: list) -> None:
    """Require every needle of a pin to sit inside one check row."""
    global fail
    missing = [x for x in needles if not any(x in row for row in ROWS)]
    for x in missing:
        print(f"diff_hmac: {name}: recomputed value is in no check row")
        print(f"  wanted: {x}")
    if missing:
        fail = 1
    else:
        print(f"diff_hmac: {name} ok")


def require(name: str, ok: bool) -> None:
    """A pure cryptographic fact about a pin, independent of the suite."""
    global fail
    if not ok:
        print(f"diff_hmac: {name}: the python recompute disagrees with itself")
        fail = 1


# ---------- the reference implementation ----------

HASH_LEN = 32
BLOCK_SIZE = 64
MAX_LEN = 255 * HASH_LEN


def mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 section 2.2."""
    return mac(salt, ikm)


def expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 section 2.3."""
    out = b""
    prev = b""
    counter = 1
    while len(out) < length:
        prev = mac(prk, prev + info + bytes([counter]))
        out = out + prev
        counter = counter + 1
    return out[:length]


# ---------- pin (a): RFC 4231 section 4, cases 1 to 7 ----------

RFC4231 = [
    (b"\x0b" * 20, b"Hi There"),
    (b"Jefe", b"what do ya want for nothing?"),
    (b"\xaa" * 20, b"\xdd" * 50),
    (bytes(range(1, 26)), b"\xcd" * 50),
    (b"\x0c" * 20, b"Test With Truncation"),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
    (
        b"\xaa" * 131,
        b"This is a test using a larger than block-size key and a larger "
        b"than block-size data. The key needs to be hashed before being "
        b"used by the HMAC algorithm.",
    ),
]

require("pin a", len(RFC4231) == 7)
require("pin a case 6 key", len(RFC4231[5][0]) > BLOCK_SIZE)
require("pin a case 7 key", len(RFC4231[6][0]) > BLOCK_SIZE)

TAGS = [mac(k, m).hex() for (k, m) in RFC4231]

for index, tag in enumerate(TAGS, 1):
    # Case 5 is the truncation case: the RFC pins its first 128 bits.
    needle = tag[:32] if index == 5 else tag
    require(f"pin a case {index}", len(needle) in (32, 64))
    pin(f"pin a RFC 4231 case {index} tag", [needle])

# ---------- pin (b): the key-length boundaries of pad_key ----------

BOUNDARY_MSG = b"boundary"
BOUNDARY_KEYS = [0, 63, 64, 65, 128]
BOUNDARY = {n: mac(b"\x0b" * n, BOUNDARY_MSG).hex() for n in BOUNDARY_KEYS}

require("pin b", BOUNDARY[64] != BOUNDARY[65])
require("pin b hashed key", BOUNDARY[65] == mac(hashlib.sha256(b"\x0b" * 65).digest(), BOUNDARY_MSG).hex())
require("pin b short key", BOUNDARY[63] == mac(b"\x0b" * 63 + b"\x00", BOUNDARY_MSG).hex())

for n in BOUNDARY_KEYS:
    pin(f"pin b boundary key of {n} bytes", [BOUNDARY[n]])

EMPTY_TAG = mac(b"", b"").hex()
pin("pin b the empty key with the empty message", [EMPTY_TAG])

# ---------- pin (c): RFC 5869 appendix A, cases 1 to 3 ----------

RFC5869 = [
    (b"\x0b" * 22, bytes(range(0x00, 0x0D)), bytes(range(0xF0, 0xFA)), 42),
    (
        bytes(range(0x00, 0x50)),
        bytes(range(0x60, 0xB0)),
        bytes(range(0xB0, 0x100)),
        82,
    ),
    (b"\x0b" * 22, b"", b"", 42),
]

require("pin c", len(RFC5869) == 3)
require("pin c case 2 is three blocks", RFC5869[1][3] > 2 * HASH_LEN)

PRKS = []
OKMS = []
for index, (ikm, salt, info, length) in enumerate(RFC5869, 1):
    prk = extract(salt, ikm)
    okm = expand(prk, info, length)
    require(f"pin c case {index} prk length", len(prk) == HASH_LEN)
    require(f"pin c case {index} okm length", len(okm) == length)
    PRKS.append(prk)
    OKMS.append(okm)
    pin(f"pin c RFC 5869 case {index} PRK", [prk.hex()])
    pin(f"pin c RFC 5869 case {index} OKM", [okm.hex()])

# W4: an empty salt IS the HashLen-zeros default, so no default argument
# is needed and the "empty salt to 32 zero bytes" mutant is equivalent.
require(
    "pin c the empty salt is the HashLen-zeros default",
    extract(b"", RFC5869[2][0]) == extract(bytes(HASH_LEN), RFC5869[2][0]),
)

# ---------- pin (d): the top of the RFC 5869 output cap ----------

CAP = expand(PRKS[0], RFC5869[0][2], MAX_LEN)
require("pin d", len(CAP) == MAX_LEN and MAX_LEN == 8160)
CAP_LAST = CAP[-HASH_LEN:].hex()
require("pin d last block", len(CAP_LAST) == 64)
pin("pin d the last 32 bytes at the 8160-byte cap", [CAP_LAST])

# ---------- the negative control ----------

okm1 = OKMS[0].hex()
twin = okm1[:-1] + format(int(okm1[-1], 16) ^ 1, "x")
if twin == okm1:
    print("diff_hmac: negative control is broken: the twin equals the pin")
    fail = 1
elif twin in STRIPPED:
    print("diff_hmac: negative control FAILED: the corrupted twin of case 1's OKM is present")
    print(f"  twin: {twin}")
    fail = 1
else:
    print("diff_hmac: negative control ok, the corrupted twin of case 1's OKM is absent")

# The second negative control: case 5 is pinned as its 128-bit prefix, so
# the FULL untruncated tag must be ABSENT from the stripped text while
# that prefix is present. A suite that pinned the whole tag would pass
# the truncation row for the wrong reason.
CASE5_FULL = TAGS[4]
CASE5_PREFIX = CASE5_FULL[:32]
if len(CASE5_FULL) != 64:
    print("diff_hmac: case 5 control is broken: the recomputed tag is not 64 hex chars")
    fail = 1
elif CASE5_FULL in STRIPPED:
    print("diff_hmac: case 5 control FAILED: the full RFC 4231 case 5 tag is present")
    print(f"  full: {CASE5_FULL}")
    fail = 1
elif CASE5_PREFIX not in STRIPPED:
    print("diff_hmac: case 5 control FAILED: the 128-bit prefix of case 5 is absent")
    print(f"  prefix: {CASE5_PREFIX}")
    fail = 1
else:
    print("diff_hmac: case 5 control ok, the full case 5 tag is absent and its 128-bit prefix is present")

sys.exit(fail)
