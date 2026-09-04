#!/usr/bin/env python3
"""M19 differential oracle over test/test_p256x.ml (DESIGN.md section 8).

It recomputes every constant the suite pins and requires each one to sit
inside a CHECK ROW of the suite, never merely somewhere in the file. The
suite matcher is the M18 one: strip_ocaml_comments, check_rows, the
LABEL pattern, BODIES, pin and require are copied from
harness/diff_keccak.py with the name of this harness in their messages
and no other change.

The arithmetic shares NO formula with the OCaml unit. lib/p256x.ml runs
Jacobian coordinates with a = -3 and one Fermat inverse per scalar walk;
this file runs AFFINE coordinates over python integers and takes every
inverse from the three-argument pow with a negative exponent, so the two
implementations agree only when both are right. The jose precedent is
/Users/oobi/Documents/jose-caml/harness/diff_rfc.py lines 144 to 251.

Before any pin is read the file SIGNS: it reproduces the RFC 6979 A.2.5
SHA-256 signature over "sample" from the published private key and the
published nonce, checks the published public key against the private
key, and verifies the result. A mismatch exits 1 on the spot, so a
python bug cannot certify an OCaml bug.

Everything here comes from the standard library.
"""

import base64
import hashlib
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
root = here.parent
suite_path = root / "test" / "test_p256x.ml"

fail = 0

# ---------- the curve, as integers ----------

P = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
N = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
B = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
GX = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
GY = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
G = (GX, GY)


def hex256(value: int) -> str:
    """Exactly 64 lowercase hex characters, the suite's text shape."""
    return format(value, "064x")


def on_curve(point) -> bool:
    """y^2 = x^3 - 3x + b over the field prime. None is not a pair."""
    if point is None:
        return False
    x, y = point
    return (y * y - (x * x * x - 3 * x + B)) % P == 0


def ec_add(pa, pb):
    """Affine addition; None is the point at infinity."""
    if pa is None:
        return pb
    if pb is None:
        return pa
    x1, y1 = pa
    x2, y2 = pb
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if pa == pb:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def ec_mul(k: int, point):
    """Double-and-add, LSB-first, over the affine addition above."""
    acc = None
    addend = point
    while k > 0:
        if k & 1:
            acc = ec_add(acc, addend)
        addend = ec_add(addend, addend)
        k >>= 1
    return acc


def sha256_int(message: bytes) -> int:
    """The SHA-256 digest of a message as a big-endian integer."""
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def ec_sign(secret: int, nonce: int, e: int):
    """FIPS 186-4 signing with a caller-supplied nonce; None on a
    degenerate nonce, which no vector here reaches."""
    point = ec_mul(nonce, G)
    if point is None:
        return None
    r = point[0] % N
    s = pow(nonce, -1, N) * (e + r * secret) % N
    if r == 0 or s == 0:
        return None
    return (r, s)


def ec_verify(pub, r: int, s: int, e: int) -> bool:
    """FIPS 186-4 verification, with the psychic rejects first."""
    if not 1 <= r < N or not 1 <= s < N:
        return False
    w = pow(s, -1, N)
    shared = ec_add(ec_mul(e * w % N, G), ec_mul(r * w % N, pub))
    if shared is None:
        return False
    return shared[0] % N == r


# ---------- the self-check, before any pin is read ----------

A25_D = int("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 16)
A25_SAMPLE_K = int(
    "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60", 16
)
A25_SAMPLE_R = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
A25_SAMPLE_S = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
A25_UX = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
A25_UY = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"

A25_U = ec_mul(A25_D, G)
SAMPLE_E = sha256_int(b"sample")
SELF = ec_sign(A25_D, A25_SAMPLE_K, SAMPLE_E % N)

if not on_curve(G) or ec_mul(N, G) is not None:
    print("diff_p256: self-check FAILED: the base point is wrong")
    sys.exit(1)
if A25_U is None or hex256(A25_U[0]) != A25_UX or hex256(A25_U[1]) != A25_UY:
    print("diff_p256: self-check FAILED: the A.2.5 public key is not d times G")
    sys.exit(1)
if SELF is None or hex256(SELF[0]) != A25_SAMPLE_R or hex256(SELF[1]) != A25_SAMPLE_S:
    print("diff_p256: self-check FAILED: the A.2.5 sample signature is not reproduced")
    sys.exit(1)
if not ec_verify(A25_U, SELF[0], SELF[1], SAMPLE_E % N):
    print("diff_p256: self-check FAILED: the signature it just made does not verify")
    sys.exit(1)

print("diff_p256: rfc6979 self-check ok")

# ---------- the suite matcher ----------


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
    print(f"diff_p256: the suite is missing: {suite_path}")
    sys.exit(1)

RAW = suite_path.read_text()
STRIPPED = strip_ocaml_comments(RAW)
ROWS = check_rows(STRIPPED)

if not ROWS:
    print("diff_p256: no check row found in the suite; the oracle is vacuous")
    sys.exit(1)

LABEL = re.compile(r'^\s*(?:\[\s*)?\(\s*"(?:[^"\\]|\\.)*"')
BODIES = [LABEL.sub("", row, count=1) for row in ROWS]


def pin(name: str, needles: list) -> None:
    """Require every needle of a pin to sit inside one check row."""
    global fail
    missing = [x for x in needles if not any(x in body for body in BODIES)]
    for x in missing:
        print(f"diff_p256: {name}: recomputed value is in no check row")
        print(f"  wanted: {x}")
    if missing:
        fail = 1
    else:
        print(f"diff_p256: {name} ok")


def require(name: str, ok: bool) -> None:
    """A pure cryptographic fact about a pin, independent of the suite."""
    global fail
    if not ok:
        print(f"diff_p256: {name}: the python recompute disagrees with itself")
        fail = 1


# ---------- pin (a): the curve constants a check row can hold ----------
#
# p, n, gx and gy only. b, p-2 and n-2 are internal to the field and the
# scalar arithmetic, no entry point of the surface takes them, and the
# suite plans no row that holds them, so pinning their text would ask
# for a needle no row carries. They are covered DYNAMICALLY instead: a
# mistyped b turns every of_xy row red through the curve test, a
# mistyped p-2 breaks the field inverse and a mistyped n-2 breaks w, so
# each one turns every accept row of groups (2), (3) and (4) red.

require("pin a G is on the curve", on_curve(G))
require("pin a the group order kills G", ec_mul(N, G) is None)
require("pin a the field prime is above the group order", P > N)
pin("pin a the curve constants", [hex256(P), hex256(N), hex256(GX), hex256(GY)])

# ---------- pin (b): the RFC 6979 A.2.5 SHA-256 signatures ----------

A25_TEST_K = int(
    "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0", 16
)
TEST_E = sha256_int(b"test")
A25_TEST = ec_sign(A25_D, A25_TEST_K, TEST_E % N)

require("pin b the sample digest", hex256(SAMPLE_E) == hashlib.sha256(b"sample").hexdigest())
require("pin b the test signature exists", A25_TEST is not None)
require(
    "pin b the sample signature verifies",
    ec_verify(A25_U, SELF[0], SELF[1], SAMPLE_E % N),
)
require(
    "pin b the test signature verifies",
    ec_verify(A25_U, A25_TEST[0], A25_TEST[1], TEST_E % N),
)
pin(
    "pin b the RFC 6979 A.2.5 SHA-256 signatures",
    [
        hex256(A25_U[0]),
        hex256(A25_U[1]),
        hex256(SAMPLE_E),
        hex256(SELF[0]),
        hex256(SELF[1]),
        hex256(TEST_E),
        hex256(A25_TEST[0]),
        hex256(A25_TEST[1]),
    ],
)

# ---------- pin (c): the RFC 7515 A.3 ES256 vector ----------
#
# The base64url text is the jose one at test/test_p256.ml lines 18 to 33,
# with the padding that file omits added back here.


def b64u(text: str) -> bytes:
    """base64url with the padding restored."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


A3_H64 = "eyJhbGciOiJFUzI1NiJ9"
A3_P64 = (
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
)
A3_X64 = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
A3_Y64 = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
A3_S64 = (
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
    "pmWQxfKTUJqPP3-Kg6NU1Q"
)

A3_INPUT = (A3_H64 + "." + A3_P64).encode("ascii")
A3_E = sha256_int(A3_INPUT)
A3_X = int.from_bytes(b64u(A3_X64), "big")
A3_Y = int.from_bytes(b64u(A3_Y64), "big")
A3_SIG = b64u(A3_S64)
A3_R = int.from_bytes(A3_SIG[:32], "big")
A3_S = int.from_bytes(A3_SIG[32:], "big")
A3_Q = (A3_X, A3_Y)
A3_OFF_Y = A3_Y ^ 1

require("pin c the signing input is 115 bytes", len(A3_INPUT) == 115)
require("pin c the signature is 64 bytes", len(A3_SIG) == 64)
require("pin c the A.3 key is on the curve", on_curve(A3_Q))
require("pin c the A.3 signature verifies", ec_verify(A3_Q, A3_R, A3_S, A3_E % N))
require("pin c the off-curve twin is below the field prime", A3_OFF_Y < P)
require("pin c the off-curve twin is off the curve", not on_curve((A3_X, A3_OFF_Y)))
pin(
    "pin c the RFC 7515 A.3 ES256 vector",
    [hex256(A3_X), hex256(A3_Y), hex256(A3_E), hex256(A3_R), hex256(A3_S)],
)

# ---------- pin (d): the vector this oracle GENERATES ----------
#
# The private key, the nonce and the message are the only literals; the
# public point and both halves of the signature are recomputed here, so
# this vector proves the oracle can SIGN and not only check, and it is
# the one vector a mistyped published constant cannot poison.

W8_D = 1 + int.from_bytes(b"venice-ocaml M19", "big")
W8_K = 2**128 + 3
W8_MESSAGE = b"venice-ocaml m19 p256x"
W8_E = sha256_int(W8_MESSAGE)
W8_Q = ec_mul(W8_D, G)
W8_SIG = ec_sign(W8_D, W8_K, W8_E % N)

require("pin d the private key is in range", 1 <= W8_D < N)
require("pin d the nonce is in range", 1 <= W8_K < N)
require("pin d the public point is on the curve", on_curve(W8_Q))
require("pin d the generated signature exists", W8_SIG is not None)
require(
    "pin d the generated signature verifies",
    ec_verify(W8_Q, W8_SIG[0], W8_SIG[1], W8_E % N),
)
pin(
    "pin d the oracle-generated vector",
    [
        hex256(W8_Q[0]),
        hex256(W8_Q[1]),
        hex256(W8_E),
        hex256(W8_SIG[0]),
        hex256(W8_SIG[1]),
    ],
)

# ---------- pin (e): the boundary constants the reject rows hold ----------

N_MINUS_1 = N - 1
P_MINUS_GY = P - GY
P_PLUS_5 = P + 5
RHS_5 = (5 * 5 * 5 - 3 * 5 + B) % P
ROOT_5 = pow(RHS_5, (P + 1) // 4, P)
Y_OF_5 = min(ROOT_5, P - ROOT_5)
SAMPLE_S_FLIPPED = SELF[1] ^ 1
SAMPLE_TWIN_S = N - SELF[1]

require("pin e the negated base point is on the curve", on_curve((GX, P_MINUS_GY)))
require(
    "pin e p + 5 is 32 bytes and above the field prime",
    P_PLUS_5 > P and P_PLUS_5 < 2**256,
)
require("pin e the residue of p + 5 is 5", P_PLUS_5 % P == 5)
require("pin e 5 is a curve x", on_curve((5, Y_OF_5)))
require("pin e the flipped sample s is not the sample s", SAMPLE_S_FLIPPED != SELF[1])
require("pin e the malleable twin is in range", 1 <= SAMPLE_TWIN_S < N)

# The infinity witness: with s = 1 the shared point is e G + r Q, so a r
# that makes r Q the negative of e G drives the verifier onto the point
# at infinity. Solve r from the discrete log this oracle already knows:
# r Q = r d G, so r = -e times the inverse of d, modulo the group order.
INF_R = (-(W8_E % N) * pow(W8_D, -1, N)) % N
INF_SHARED = ec_add(ec_mul(W8_E % N, G), ec_mul(INF_R % N, W8_Q))

require("pin e the infinity witness is in range", 1 <= INF_R < N)
require("pin e the infinity witness gives the point at infinity", INF_SHARED is None)
require(
    "pin e the infinity witness does not verify",
    not ec_verify(W8_Q, INF_R, 1, W8_E % N),
)
pin(
    "pin e the boundary constants",
    [
        hex256(N),
        hex256(N_MINUS_1),
        hex256(P),
        hex256(A3_OFF_Y),
        hex256(P_MINUS_GY),
        hex256(P_PLUS_5),
        hex256(Y_OF_5),
        hex256(SAMPLE_S_FLIPPED),
        hex256(SAMPLE_TWIN_S),
        hex256(INF_R),
    ],
)

# ---------- the malleable-twin control ----------
#
# FIPS 186-4 carries no low-s rule, so (r, n - s) is a valid signature
# for the same key over the same digest. The suite pins that behaviour,
# and this control proves the pin describes the arithmetic and not a
# defect of the OCaml unit.

W8_TWIN_S = N - W8_SIG[1]

require(
    "malleable-twin control the sample twin verifies",
    ec_verify(A25_U, SELF[0], SAMPLE_TWIN_S, SAMPLE_E % N),
)
require(
    "malleable-twin control the oracle twin verifies",
    ec_verify(W8_Q, W8_SIG[0], W8_TWIN_S, W8_E % N),
)
require("malleable-twin control the twins differ", W8_TWIN_S != W8_SIG[1])
pin("malleable-twin control", [hex256(SAMPLE_TWIN_S), hex256(W8_TWIN_S)])

# ---------- the negative controls ----------

twin = hex256(SELF[0])[:-1] + format(int(hex256(SELF[0])[-1], 16) ^ 1, "x")
if twin == hex256(SELF[0]):
    print("diff_p256: negative control is broken: the twin equals the pin")
    fail = 1
elif twin in STRIPPED:
    print(
        "diff_p256: negative control FAILED: the corrupted twin of the sample "
        "signature r is present"
    )
    print(f"  twin: {twin}")
    fail = 1
else:
    print(
        "diff_p256: negative control ok, the corrupted twin of the sample "
        "signature r is absent"
    )

# The second control proves the label stripping on a row held in memory:
# a value that sits only in the row NAME must be reported MISSING, so a
# pin parked in a label can never satisfy this oracle.
SYNTH_ROW = f'  ( "{hex256(SELF[0])} sits only in this label",\n    true );'
SYNTH_BODY = LABEL.sub("", SYNTH_ROW, count=1)
if hex256(SELF[0]) not in SYNTH_ROW:
    print("diff_p256: label control is broken: the synthetic row holds no value")
    fail = 1
elif hex256(SELF[0]) in SYNTH_BODY:
    print("diff_p256: label control FAILED: a value in a row label survives the strip")
    fail = 1
else:
    print("diff_p256: label control ok, a value parked in a row name is not found")

sys.exit(fail)
