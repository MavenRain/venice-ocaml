#!/usr/bin/env python3
"""M20 differential oracle over test/test_secpx.ml (DESIGN.md section 8).

It recomputes every constant the suite pins and requires each one to sit
inside a CHECK ROW of the suite, never merely somewhere in the file. The
suite matcher is the M18 one: strip_ocaml_comments, check_rows, the
LABEL pattern, BODIES, pin and require are copied from
harness/diff_p256.py with the name of this harness in their messages and
no other change.

The arithmetic shares NO formula with the OCaml unit. lib/secpx.ml runs
projective coordinates with a = 0 and one fixed-shape Montgomery ladder;
this file runs AFFINE coordinates over python integers and takes every
inverse from the three-argument pow with a negative exponent, so the two
implementations agree only when both are right.

Provenance of the embedded Wycheproof subset. The ECDSA file is
/Users/oobi/Documents/signatures/thirdparty/wycheproof/testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json,
algorithm "ECDSA", schema "ecdsa_p1363_verify_schema_v1.json",
numberOfTests 242. The ECDH file is
/Users/oobi/Documents/signatures/thirdparty/wycheproof/testvectors_v1/ecdh_secp256k1_test.json,
algorithm "ECDH", schema "ecdh_test_schema_v1.json", numberOfTests 752,
one group of curve "secp256k1" and encoding "asn", so the public key
arrives inside an SPKI wrapper and this file strips the 23-byte prefix
itself. There is no secp256k1 ecpoint file in this checkout, only the
secp224r1, secp256r1, secp384r1 and secp521r1 ones, so the SPKI file is
the ECDH source. NEITHER file carries a generatorVersion key. The
checkout commit is 0fd0ec1cf2114f456f5c3e7c61ba807fb1311b45
(git -C /Users/oobi/Documents/signatures/thirdparty/wycheproof
rev-parse HEAD, describe wycheproof-v0-vectors-40-g0fd0ec1), and
git -C /Users/oobi/Documents/signatures submodule status prints nothing,
so that directory's own HEAD is the provenance. The corpus is
Apache-2.0
(/Users/oobi/Documents/signatures/thirdparty/wycheproof/LICENSE lines 2
and 3), and the checkout carries no NOTICE file, so section 4(d) owes
nothing and this header is the whole attribution.

When both files sit on disk the oracle also CROSS-CHECKS every embedded
record against them by tcId, so a typo in a literal below is caught at
its source. When they are absent the embedded subset stands alone and
the oracle says so, because a pin must not depend on a checkout the gate
does not own.

Pin group (a) holds p, n, gx and gy as TEXT. The curve coefficient b,
p - 2 and n - 2 are NOT pinned as text and are covered DYNAMICALLY
instead: no entry point of the surface takes them and no check row holds
them, so pinning their text would ask for a needle no row carries. A
mistyped b turns every of_xy and of_scalar row red through the curve
test, a mistyped p - 2 breaks the field inverse and so breaks to_affine
on every accept row, and a mistyped n - 2 breaks w and so breaks every
verify accept row.

Before any pin is read the file SELF-CHECKS in three parts: every
embedded valid ECDSA vector must verify and every invalid one must fail
under this arithmetic, every embedded ECDH vector must reproduce its
shared x, the oracle must sign its own generated vector and verify both
it and its malleable twin, and both sides of the generated ECDH pair
must agree. A mismatch exits 1 on the spot, so a python bug cannot
certify an OCaml bug.

Everything here comes from the standard library.
"""

import hashlib
import json
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
root = here.parent
suite_path = root / "test" / "test_secpx.ml"

wycheproof_dir = pathlib.Path(
    "/Users/oobi/Documents/signatures/thirdparty/wycheproof/testvectors_v1"
)
ecdsa_path = wycheproof_dir / "ecdsa_secp256k1_sha256_p1363_test.json"
ecdh_spki_path = wycheproof_dir / "ecdh_secp256k1_test.json"
ecdh_point_path = wycheproof_dir / "ecdh_secp256k1_ecpoint_test.json"

fail = 0

# ---------- the curve, as integers ----------

P = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
N = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
B = 7
GX = int("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
GY = int("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
G = (GX, GY)


def hex256(value: int) -> str:
    """Exactly 64 lowercase hex characters, the suite's text shape."""
    return format(value, "064x")


def on_curve(point) -> bool:
    """y^2 = x^3 + 7 over the field prime. None is not a pair."""
    if point is None:
        return False
    x, y = point
    if not 0 <= x < P or not 0 <= y < P:
        return False
    return (y * y - (x * x * x + B)) % P == 0


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
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
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
    """Signing with a caller-supplied nonce; None on a degenerate nonce,
    which no vector here reaches."""
    point = ec_mul(nonce, G)
    if point is None:
        return None
    r = point[0] % N
    s = pow(nonce, -1, N) * (e + r * secret) % N
    if r == 0 or s == 0:
        return None
    return (r, s)


def ec_verify(pub, r: int, s: int, e: int) -> bool:
    """Verification, with the psychic rejects first."""
    if not 1 <= r < N or not 1 <= s < N:
        return False
    w = pow(s, -1, N)
    shared = ec_add(ec_mul(e * w % N, G), ec_mul(r * w % N, pub))
    if shared is None:
        return False
    return shared[0] % N == r


# ---------- the embedded Wycheproof ECDSA subset ----------
#
# 20 vectors by tcId, plus the malleable twin the draft computes because
# the file does not carry it as a test of its own. The class of each
# rejection is named, because the OCaml unit rejects them at different
# places: "psychic" dies in Signature.of_raw on the 1 .. n-1 range test,
# "length" dies in Signature.of_raw on the byte count, and "math" builds
# a Signature.t and then fails in verify.

Q1X = "b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
Q1Y = "f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
DG1 = "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
Q115X = "07310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc362"
Q115Y = "26a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0"
Q202X = "2ea7133432339c69d27f9b267281bd2ddd5f19d6338d400a05cd3647b157a385"
Q202Y = "3547808298448edb5e701ade84cd5fb1ac9567ba5e8fb68a6b933ec4b5cc84cc"
Q203Y = "cab87f7d67bb7124a18fe5217b32a04e536a9845a1704975946cc13a4a337763"
Q121X = "1877045be25d34a1d0600f9d5c00d0645a2a54379b6ceefad2e6bf5c2a3352ce"
Q121Y = "821a532cc1751ee1d36d41c3d6ab4e9b143e44ec46d73478ea6a79a5c0e54159"


def ecdsa(tcid, comment, cls, r, s, qx=Q1X, qy=Q1Y, digest=DG1):
    """One 64-byte-signature vector: r and s are 32 bytes each."""
    return {
        "tcId": tcid,
        "comment": comment,
        "cls": cls,
        "qx": qx,
        "qy": qy,
        "digest": digest,
        "r": r,
        "s": s,
        "sig": r + s,
    }


def ecdsa_len(tcid, comment, raw, qx=Q1X, qy=Q1Y, digest=DG1):
    """One wrong-length vector: it has no 32-byte halves, so the pin is
    the RAW signature hex and the self-check never verifies it."""
    return {
        "tcId": tcid,
        "comment": comment,
        "cls": "length",
        "qx": qx,
        "qy": qy,
        "digest": digest,
        "r": None,
        "s": None,
        "sig": raw,
    }


ECDSA_VECTORS = [
    ecdsa(
        1,
        "signature malleability",
        "valid",
        "813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365",
        "900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87",
    ),
    ecdsa_len(
        2,
        "replaced r by r + n",
        "01813ef79ccefa9a56f7ba805f0e478583b90deabca4b05c4574e49b5899b964a600"
        "6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba",
    ),
    ecdsa(
        4,
        "replaced r by n - r",
        "math",
        "7ec10863310565a908457fa0f1b87a79bc4fcf10b9e0e4320ac021c106b31ddc",
        "6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba",
    ),
    ecdsa(
        11,
        "r and s are both 0",
        "psychic",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    ecdsa(
        12,
        "r is 0 and s is 1",
        "psychic",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    ecdsa(
        18,
        "r is 1 and s is 0",
        "psychic",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    ecdsa(
        19,
        "r is 1 and s is 1",
        "math",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    ecdsa(
        20,
        "r is 1 and s is the group order",
        "psychic",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    ),
    ecdsa(
        27,
        "r and s are both the group order",
        "psychic",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    ),
    ecdsa(
        35,
        "r and s are both n - 1",
        "math",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    ),
    ecdsa(
        43,
        "r and s are both n + 1",
        "psychic",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
    ),
    ecdsa(
        51,
        "r and s are both the field prime",
        "psychic",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
    ),
]

ECDSA_VECTORS += [
    ecdsa(
        60,
        "Edge case for Shamir multiplication",
        "valid",
        "dd1b7d09a7bd8218961034a39a87fecf5314f00c4d25eb58a07ac85e85eab516",
        "35138c401ef8d3493d65c9002fe62b43aee568731b744548358996d9cc427e06",
        digest="b78f33ca6d031315ab4c29b4429e6e8f8978517d49192c90fb2266bea6842918",
    ),
    ecdsa(
        61,
        "special case hash, leading zero bytes",
        "valid",
        "95c29267d972a043d955224546222bba343fc1d4db0fec262a33ac61305696ae",
        "6edfe96713aed56f8a28a6653f57e0b829712e5eddc67f34682b24f0676b2640",
        digest="00000000690ed426ccf17803ebe2bd0884bcd58a1bb5e7477ead3645f356e7a9",
    ),
    ecdsa(
        114,
        "special case hash, trailing ff bytes",
        "valid",
        "52c683144e44119ae2013749d4964ef67509278f6d38ba869adcfa69970e123d",
        "3479910167408f45bda420a626ec9c4ec711c1274be092198b4187c018b562ca",
        digest="d59291cc2cf89f3087715fcb1aa4e79aa2403f748e97d7cd28ecaefeffffffff",
    ),
    ecdsa(
        115,
        "k*G has a large x-coordinate",
        "valid",
        "000000000000000000000000000000014551231950b75fc4402da1722fc9baeb",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
        qx=Q115X,
        qy=Q115Y,
    ),
    ecdsa(
        116,
        "r too large",
        "psychic",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e",
        qx=Q115X,
        qy=Q115Y,
    ),
    ecdsa_len(121, "incorrect size of signature", "0101", qx=Q121X, qy=Q121Y),
    ecdsa(
        202,
        "point duplication during verification",
        "valid",
        "32b0d10d8d0e04bc8d4d064d270699e87cffc9b49c5c20730e1c26f6105ddcda",
        "d612c2984c2afa416aa7f2882a486d4a8426cb6cfc91ed5b737278f9fca8be68",
        qx=Q202X,
        qy=Q202Y,
    ),
    ecdsa(
        203,
        "duplication bug",
        "math",
        "32b0d10d8d0e04bc8d4d064d270699e87cffc9b49c5c20730e1c26f6105ddcda",
        "d612c2984c2afa416aa7f2882a486d4a8426cb6cfc91ed5b737278f9fca8be68",
        qx=Q202X,
        qy=Q203Y,
    ),
]

# The malleable twin of tcId 1, computed by this draft because the file
# does not carry it as a test of its own. It VERIFIES: the standard has
# no low-s rule.
TC1_TWIN_S = "6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"
TC1_TWIN = ecdsa(
    1001,
    "tcId 1 malleable twin (r, n - s), draft-computed",
    "valid",
    ECDSA_VECTORS[0]["r"],
    TC1_TWIN_S,
)


# ---------- the embedded Wycheproof ECDH subset ----------
#
# 12 vectors: 7 valid, 4 with a public point off the curve, and the one
# compressed test. The compressed record sits OUTSIDE the self-check
# counts, because its rejection is an M20 scope exclusion and not a
# Wycheproof verdict. Every private key is shown LEFT-PADDED to 32
# bytes, which is what the suite hands Scalar.of_bytes: the file gives
# tcId 459 one byte and tcId 460 twenty-nine.

D_TC1 = "f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254"
D_TC3 = "a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a"
X_TC459 = "32bdd978eb62b1f369a56d0949ab8551a7ad527d9602e891ce457586c2a8569e"
Y_TC459 = "981e67fae053b03fc33e1a291f0a3beb58fceb2e85bb1205dacee1232dfd316b"
ZERO32 = "0000000000000000000000000000000000000000000000000000000000000000"
P_MINUS_1 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"
P_HEX = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"


def ecdh(tcid, comment, private, x, y, shared):
    """A valid ECDH vector: d Q has x = shared."""
    return {
        "tcId": tcid,
        "comment": comment,
        "cls": "valid",
        "private": private,
        "x": x,
        "y": y,
        "shared": shared,
    }


def ecdh_bad(tcid, comment, x, y):
    """A public point off the curve: Pubkey.of_bytes is None."""
    return {
        "tcId": tcid,
        "comment": comment,
        "cls": "offcurve",
        "private": None,
        "x": x,
        "y": y,
        "shared": None,
    }


ECDH_VECTORS = [
    ecdh(
        1,
        "normal case",
        D_TC1,
        "d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b",
        "396812ea1686e7472e9692eaf3e958e50e9500d3b4c77243db1f2acd67ba9cc4",
        "544dfae22af6af939042b1d85b71a1e49e9a5614123c4d6ad0c8af65baf87d65",
    ),
    ecdh(
        3,
        "shared secret has x-coordinate that satisfies x**2 + a = 1",
        D_TC3,
        "965ff42d654e058ee7317cced7caf093fbb180d8d3a74b0dcd9d8cd47a39d5cb",
        "9c2aa4daac01a4be37c20467ede964662f12983e0b5272a47a5f2785685d8087",
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    ecdh(
        4,
        "shared secret has x-coordinate that satisfies x**2 + a = 4",
        D_TC3,
        "06c4b87ba76c6dcb101f54a050a086aa2cb0722f03137df5a922472f1bdc11b9",
        "82e3c735c4b6c481d09269559f080ad08632f370a054af12c1fd1eced2ea9211",
        "0000000000000000000000000000000000000000000000000000000000000002",
    ),
    ecdh(
        5,
        "shared secret has x-coordinate that satisfies x**2 + a = 9",
        D_TC3,
        "bba30eef7967a2f2f08a2ffadac0e41fd4db12a93cef0b045b5706f2853821e6",
        "d50b2bf8cbf530e619869e07c021ef16f693cfc0a4b0d4ed5a8f464692bf3d6e",
        "0000000000000000000000000000000000000000000000000000000000000003",
    ),
    ecdh(
        6,
        "shared secret has x-coordinate p-3",
        D_TC3,
        "6da9eb2cdac02122d5f05cf6a8cd768e378f664ea4a7871d10e25f57eb1ee1cc",
        "5b2b5abf9c6c6596f8f383ddbcb3bcc2d5a7cc605984931239ca9669946032ee",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c",
    ),
    ecdh(
        459,
        "edge case private key, one byte in the file",
        "0000000000000000000000000000000000000000000000000000000000000003",
        X_TC459,
        Y_TC459,
        "34005694e3cac09332aa42807e3afdc3b3b3bc7c7be887d1f98d76778c55cfd7",
    ),
    ecdh(
        460,
        "edge case private key, 29 bytes in the file",
        "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        X_TC459,
        Y_TC459,
        "5841acd3cff2d62861bbe11084738006d68ccf35acae615ee9524726e93d0da5",
    ),
    ecdh_bad(475, "point is not on curve, the zero pair", ZERO32, ZERO32),
    ecdh_bad(
        479,
        "point is not on curve, x = 1 and y = 0",
        "0000000000000000000000000000000000000000000000000000000000000001",
        ZERO32,
    ),
    ecdh_bad(485, "point is not on curve, p - 1 twice", P_MINUS_1, P_MINUS_1),
    ecdh_bad(490, "point is not on curve, p twice", P_HEX, P_HEX),
    {
        "tcId": 2,
        "comment": "compressed public key, an M20 scope exclusion",
        "cls": "compressed",
        "private": D_TC1,
        "x": None,
        "y": None,
        "shared": None,
        "point": "02d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b",
        "twin": "03d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b",
    },
]

SPKI_UNCOMPRESSED = "3056301006072a8648ce3d020106052b8104000a034200"
SPKI_COMPRESSED = "3036301006072a8648ce3d020106052b8104000a032200"


# ---------- the generated vectors ----------
#
# Nothing here is a Wycheproof value. The secret is the big-endian
# integer of the 22 ASCII bytes of the message itself, the nonce is
# 2^128 + 3, and both ECDH scalars are round powers of two plus a small
# odd constant, so every one of them is reproducible by hand.

GEN_MESSAGE = b"venice-ocaml m20 secpx"
GEN_D_HEX = "0000000000000000000076656e6963652d6f63616d6c206d3230207365637078"
GEN_DIGEST = "87f9faaefe8a069f022c2bbe069c549aa058c94a5680692cbba0a8fcde0d7e7b"
GEN_QX = "faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
GEN_QY = "dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1"
GEN_R = "d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0"
GEN_S = "6a7041b9df179c76b4e7e86b89ace566e76c08d8ba660a146c476f723e90e4c7"
GEN_TWIN_S = "958fbe4620e863894b18179476531a97d342d40df4e29627538aef1a91a55c7a"
GEN_R_CORRUPTED = "d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e1"
GEN_K = (1 << 128) + 3

ECDH_DA_HEX = "0000000000000100000000000000000000000000000000000000000000000007"
ECDH_DB_HEX = "000000000000000000000000000000000000001000000000000000000000000b"
ECDH_QA_X = "a5415496ed54f41daa134e10d91925e0dc962fa4fbb7372006781b3b69d0fb60"
ECDH_QA_Y = "63c62edce476b3fa4cfd92adf7816734ab18eb1760c02588923285344960ddfe"
ECDH_QB_X = "94b32e5d15041c3b8773c454fe4cef707a9a1867f06238dc8fa0afa90813d7bf"
ECDH_QB_Y = "a2b2dd48c683e5c830321dda407c2baf77b8b8d1620b031557ec641d198158be"
ECDH_GEN_SHARED_X = "21149db0e3cf824c897b8193c4759fc31ac484bb67ed10732353a911086e4ea3"
ECDH_GEN_SHARED_Y = "03442f0b70d3249799995f7a4527e18d35efc097ff23f13725a0fab749d5c97a"

OFFCURVE_Y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9"
N_HEX = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
N_MINUS_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"


def stop(message: str) -> None:
    """A self-check mismatch is fatal on the spot: a python bug must
    never certify an OCaml bug."""
    print("diff_secp: SELF-CHECK FAILED: " + message)
    sys.exit(1)


# ---------- the corpus cross-check ----------


def corpus_records(path, wanted):
    """Every test of the file whose tcId is wanted, flattened with its
    group's public key. Returns an empty dict when the file is absent."""
    if not path.exists():
        return {}
    document = json.loads(path.read_text())
    found = {}
    for group in document.get("testGroups", []):
        key = group.get("publicKey", {})
        for test in group.get("tests", []):
            if test.get("tcId") in wanted:
                found[test["tcId"]] = {"test": test, "key": key}
    return found


def cross_check() -> None:
    """Compare every embedded literal against the corpus by tcId. This
    runs only when both files sit on disk, because a pin must not depend
    on a checkout the gate does not own."""
    if not ecdsa_path.exists() or not ecdh_spki_path.exists():
        print("diff_secp: corpus absent, the embedded subset stands alone")
        return
    ecdsa_found = corpus_records(ecdsa_path, {v["tcId"] for v in ECDSA_VECTORS})
    for vector in ECDSA_VECTORS:
        record = ecdsa_found.get(vector["tcId"])
        if record is None:
            stop("ECDSA tcId %d is not in the corpus" % vector["tcId"])
        digest = hashlib.sha256(bytes.fromhex(record["test"]["msg"])).hexdigest()
        if digest != vector["digest"]:
            stop("ECDSA tcId %d digest disagrees" % vector["tcId"])
        if record["test"]["sig"] != vector["sig"]:
            stop("ECDSA tcId %d signature disagrees" % vector["tcId"])
        if record["key"]["wx"].lstrip("0") != vector["qx"].lstrip("0"):
            stop("ECDSA tcId %d qx disagrees" % vector["tcId"])
        if record["key"]["wy"].lstrip("0") != vector["qy"].lstrip("0"):
            stop("ECDSA tcId %d qy disagrees" % vector["tcId"])
    ecdh_found = corpus_records(ecdh_spki_path, {v["tcId"] for v in ECDH_VECTORS})
    for vector in ECDH_VECTORS:
        record = ecdh_found.get(vector["tcId"])
        if record is None:
            stop("ECDH tcId %d is not in the corpus" % vector["tcId"])
        test = record["test"]
        if vector["private"] is not None:
            padded = format(int(test["private"], 16), "064x")
            if padded != vector["private"]:
                stop("ECDH tcId %d private disagrees" % vector["tcId"])
        if vector["cls"] == "compressed":
            if not test["public"].startswith(SPKI_COMPRESSED):
                stop("ECDH tcId 2 is not the compressed SPKI")
            if SPKI_COMPRESSED + vector["point"] != test["public"]:
                stop("ECDH tcId 2 point disagrees")
        else:
            uncompressed = SPKI_UNCOMPRESSED + "04" + vector["x"] + vector["y"]
            if test["public"] != uncompressed:
                stop("ECDH tcId %d point disagrees" % vector["tcId"])
        if vector["shared"] is not None:
            if format(int(test["shared"], 16), "064x") != vector["shared"]:
                stop("ECDH tcId %d shared disagrees" % vector["tcId"])
    print(
        "diff_secp: corpus cross-check ok (%d ecdsa, %d ecdh, from %s)"
        % (len(ECDSA_VECTORS), len(ECDH_VECTORS), ecdh_spki_path.name)
    )


# ---------- part one of the self-check: the Wycheproof subset ----------


def self_check_wycheproof() -> None:
    """Every embedded valid vector verifies and every invalid one fails,
    and every embedded ECDH vector reproduces its shared x. The two
    wrong-length vectors are classed by their BYTE COUNT and never
    verified, and the compressed ECDH vector is excluded outright."""
    valid = 0
    invalid = 0
    for vector in ECDSA_VECTORS:
        if vector["cls"] == "length":
            if len(bytes.fromhex(vector["sig"])) == 64:
                stop("ECDSA tcId %d is 64 bytes after all" % vector["tcId"])
            continue
        if len(bytes.fromhex(vector["sig"])) != 64:
            stop("ECDSA tcId %d is not 64 bytes" % vector["tcId"])
        pub = (int(vector["qx"], 16), int(vector["qy"], 16))
        if not on_curve(pub):
            stop("ECDSA tcId %d public key is off the curve" % vector["tcId"])
        r = int(vector["r"], 16)
        s = int(vector["s"], 16)
        in_range = 1 <= r < N and 1 <= s < N
        if vector["cls"] == "psychic" and in_range:
            stop("ECDSA tcId %d is in range, not psychic" % vector["tcId"])
        if vector["cls"] != "psychic" and not in_range:
            stop("ECDSA tcId %d is out of range" % vector["tcId"])
        got = ec_verify(pub, r, s, int(vector["digest"], 16))
        if vector["cls"] == "valid":
            if not got:
                stop("ECDSA tcId %d should verify" % vector["tcId"])
            valid += 1
        else:
            if got:
                stop("ECDSA tcId %d should not verify" % vector["tcId"])
            invalid += 1
    twin_pub = (int(TC1_TWIN["qx"], 16), int(TC1_TWIN["qy"], 16))
    if int(TC1_TWIN["s"], 16) != N - int(ECDSA_VECTORS[0]["s"], 16):
        stop("the tcId 1 twin s is not n - s")
    if not ec_verify(
        twin_pub,
        int(TC1_TWIN["r"], 16),
        int(TC1_TWIN["s"], 16),
        int(TC1_TWIN["digest"], 16),
    ):
        stop("the tcId 1 malleable twin should verify")
    ecdh_seen = 0
    for vector in ECDH_VECTORS:
        if vector["cls"] == "compressed":
            if len(bytes.fromhex(vector["point"])) != 33:
                stop("the compressed ECDH point is not 33 bytes")
            if len(bytes.fromhex(vector["twin"])) != 33:
                stop("the compressed ECDH twin is not 33 bytes")
            continue
        pub = (int(vector["x"], 16), int(vector["y"], 16))
        if vector["cls"] == "offcurve":
            if on_curve(pub):
                stop("ECDH tcId %d is on the curve after all" % vector["tcId"])
            ecdh_seen += 1
            continue
        if not on_curve(pub):
            stop("ECDH tcId %d public point is off the curve" % vector["tcId"])
        shared = ec_mul(int(vector["private"], 16), pub)
        if shared is None:
            stop("ECDH tcId %d reached infinity" % vector["tcId"])
        if hex256(shared[0]) != vector["shared"]:
            stop("ECDH tcId %d shared x disagrees" % vector["tcId"])
        ecdh_seen += 1
    print(
        "diff_secp: wycheproof self-check ok (%d valid, %d invalid, %d ecdh)"
        % (valid, invalid, ecdh_seen)
    )


# ---------- parts two and three: the generated vectors ----------


def self_check_generated() -> None:
    """The oracle signs its own vector and verifies it and its malleable
    twin, then derives both sides of the generated ECDH pair."""
    secret = int.from_bytes(GEN_MESSAGE, "big")
    if hex256(secret) != GEN_D_HEX:
        stop("the generated secret is not the message integer")
    digest = sha256_int(GEN_MESSAGE)
    if hex256(digest) != GEN_DIGEST:
        stop("the generated digest disagrees")
    pub = ec_mul(secret, G)
    if pub is None or hex256(pub[0]) != GEN_QX or hex256(pub[1]) != GEN_QY:
        stop("the generated public key disagrees")
    signed = ec_sign(secret, GEN_K, digest)
    if signed is None:
        stop("the generated nonce is degenerate")
    r, s = signed
    if hex256(r) != GEN_R or hex256(s) != GEN_S:
        stop("the generated signature disagrees")
    if not ec_verify(pub, r, s, digest):
        stop("the generated signature should verify")
    twin_s = N - s
    if hex256(twin_s) != GEN_TWIN_S:
        stop("the generated malleable twin disagrees")
    if not ec_verify(pub, r, twin_s, digest):
        stop("the generated malleable twin should verify")
    if hex256(r ^ 1) != GEN_R_CORRUPTED:
        stop("the corrupted r is not the last-bit flip of r")
    if ec_verify(pub, r ^ 1, s, digest):
        stop("the corrupted r should not verify")
    da = int(ECDH_DA_HEX, 16)
    db = int(ECDH_DB_HEX, 16)
    if da != (1 << 200) + 7 or db != (1 << 100) + 11:
        stop("the generated ECDH scalars disagree")
    qa = ec_mul(da, G)
    qb = ec_mul(db, G)
    if qa is None or hex256(qa[0]) != ECDH_QA_X or hex256(qa[1]) != ECDH_QA_Y:
        stop("QA disagrees")
    if qb is None or hex256(qb[0]) != ECDH_QB_X or hex256(qb[1]) != ECDH_QB_Y:
        stop("QB disagrees")
    left = ec_mul(da, qb)
    right = ec_mul(db, qa)
    if left is None or right is None or left != right:
        stop("the two ECDH sides disagree")
    if hex256(left[0]) != ECDH_GEN_SHARED_X:
        stop("the generated shared x disagrees")
    if hex256(left[1]) != ECDH_GEN_SHARED_Y:
        stop("the generated shared y disagrees")
    print("diff_secp: generated-vector self-check ok")


# ---------- run the self-check before a single pin is read ----------

if ecdh_point_path.exists():
    print("diff_secp: SELF-CHECK FAILED: an ecpoint file appeared; re-read W3")
    sys.exit(1)

cross_check()
self_check_wycheproof()
self_check_generated()

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
    print(f"diff_secp: the suite is missing: {suite_path}")
    sys.exit(1)

RAW = suite_path.read_text()
STRIPPED = strip_ocaml_comments(RAW)
ROWS = check_rows(STRIPPED)

if not ROWS:
    print("diff_secp: no check row found in the suite; the oracle is vacuous")
    sys.exit(1)

LABEL = re.compile(r'^\s*(?:\[\s*)?\(\s*"(?:[^"\\]|\\.)*"')
BODIES = [LABEL.sub("", row, count=1) for row in ROWS]


def pin(name: str, needles: list) -> None:
    """Require every needle of a pin to sit inside one check row."""
    global fail
    missing = [x for x in needles if not any(x in body for body in BODIES)]
    for x in missing:
        print(f"diff_secp: {name}: recomputed value is in no check row")
        print(f"  wanted: {x}")
    if missing:
        fail = 1
    else:
        print(f"diff_secp: {name} ok")


def require(name: str, ok: bool) -> None:
    """A pure cryptographic fact about a pin, independent of the suite."""
    global fail
    if not ok:
        print(f"diff_secp: {name}: the python recompute disagrees with itself")
        fail = 1


# ---------- pin (a): the curve constants a check row can hold ----------
#
# p, n, gx and gy only. b, p - 2 and n - 2 are internal to the field and
# the scalar arithmetic, no entry point of the surface takes them and no
# check row holds them, so they are covered dynamically instead: the
# header says which row turns red for each of them.

require("(a) G is on the curve", on_curve(G))
require("(a) n G is the point at infinity", ec_mul(N, G) is None)
require("(a) p is above n", P > N)
pin("(a) curve constants", [hex256(P), hex256(N), hex256(GX), hex256(GY)])

# ---------- pin (b): the Wycheproof ECDSA subset ----------
#
# Every vector's digest, and its r and s where the signature is exactly
# 64 bytes. The two wrong-length vectors have no 32-byte halves, so
# their pin is the RAW signature hex. The draft-computed twin s of
# tcId 1 is pinned here as well, and it is also tcId 4's s, so one value
# serves two rows and both rows must hold it.

ECDSA_NEEDLES = []
for VECTOR in ECDSA_VECTORS:
    ECDSA_NEEDLES.append(VECTOR["digest"])
    if VECTOR["cls"] == "length":
        ECDSA_NEEDLES.append(VECTOR["sig"])
    else:
        ECDSA_NEEDLES.append(VECTOR["r"])
        ECDSA_NEEDLES.append(VECTOR["s"])
ECDSA_NEEDLES.append(TC1_TWIN["s"])
require(
    "(b) the twin s is also tcId 4's s",
    TC1_TWIN["s"] == ECDSA_VECTORS[2]["s"] and ECDSA_VECTORS[2]["tcId"] == 4,
)
pin("(b) wycheproof ecdsa", sorted(set(ECDSA_NEEDLES)))

# ---------- pin (c): the Wycheproof ECDH subset ----------
#
# Every vector's normalized private key, its public point as X || Y and
# its shared x. The compressed vector has no X || Y, so its pin is the
# 33-byte point and the draft-synthesized 0x03 twin of the same X.

ECDH_NEEDLES = []
for VECTOR in ECDH_VECTORS:
    if VECTOR["private"] is not None:
        ECDH_NEEDLES.append(VECTOR["private"])
    if VECTOR["cls"] == "compressed":
        ECDH_NEEDLES.append(VECTOR["point"])
        ECDH_NEEDLES.append(VECTOR["twin"])
    else:
        ECDH_NEEDLES.append(VECTOR["x"] + VECTOR["y"])
    if VECTOR["shared"] is not None:
        ECDH_NEEDLES.append(VECTOR["shared"])
pin("(c) wycheproof ecdh", sorted(set(ECDH_NEEDLES)))

# ---------- pin (d): the generated vectors ----------

pin(
    "(d) generated ecdsa",
    [GEN_QX, GEN_QY, GEN_R, GEN_S, GEN_DIGEST],
)
pin(
    "(d) generated ecdh",
    [
        ECDH_DA_HEX,
        ECDH_DB_HEX,
        ECDH_QA_X,
        ECDH_QA_Y,
        ECDH_QB_X,
        ECDH_QB_Y,
        ECDH_GEN_SHARED_X,
    ],
)

# ---------- pin (e): the boundary constants of the negative rows ----------

require(
    "(e) the off-curve y is gy with its last bit flipped",
    int(OFFCURVE_Y, 16) == GY ^ 1 and not on_curve((GX, int(OFFCURVE_Y, 16))),
)
require("(e) n - 1 is right", int(N_MINUS_1, 16) == N - 1)
require("(e) p - 1 is right", int(P_MINUS_1, 16) == P - 1)
require(
    "(e) the generated twin is n - s",
    int(GEN_TWIN_S, 16) == N - int(GEN_S, 16),
)
pin(
    "(e) boundary constants",
    [N_HEX, N_MINUS_1, P_HEX, P_MINUS_1, OFFCURVE_Y, GEN_TWIN_S],
)

# ---------- the malleable-twin control ----------
#
# The standard carries no low-s rule, so (r, n - s) is a valid signature
# for the same key over the same digest. The suite pins that behaviour
# on the Wycheproof tcId 1 twin and on the generated twin, and this
# control proves the pin describes the arithmetic and not a defect of
# the OCaml unit.

require(
    "malleable-twin control the tcId 1 twin verifies",
    ec_verify(
        (int(TC1_TWIN["qx"], 16), int(TC1_TWIN["qy"], 16)),
        int(TC1_TWIN["r"], 16),
        int(TC1_TWIN_S, 16),
        int(TC1_TWIN["digest"], 16),
    ),
)
require(
    "malleable-twin control the generated twin verifies",
    ec_verify(
        (int(GEN_QX, 16), int(GEN_QY, 16)),
        int(GEN_R, 16),
        int(GEN_TWIN_S, 16),
        int(GEN_DIGEST, 16),
    ),
)
require(
    "malleable-twin control the twins differ from their originals",
    TC1_TWIN_S != ECDSA_VECTORS[0]["s"] and GEN_TWIN_S != GEN_S,
)
pin("malleable-twin control", [TC1_TWIN_S, GEN_TWIN_S])

# ---------- the negative control ----------

TWIN = GEN_R_CORRUPTED
if TWIN == GEN_R:
    print("diff_secp: negative control is broken: the twin equals the pin")
    fail = 1
elif TWIN in STRIPPED:
    print(
        "diff_secp: negative control FAILED: the corrupted twin of the "
        "generated r is present"
    )
    print(f"  twin: {TWIN}")
    fail = 1
else:
    print(
        "diff_secp: negative control ok, the corrupted twin of the "
        "generated r is absent"
    )

# The second control proves the label stripping on a row held in memory:
# a value that sits only in the row NAME must be reported MISSING, so a
# pin parked in a label can never satisfy this oracle.
SYNTH_ROW = f'  ( "{GEN_R} sits only in this label",\n    true );'
SYNTH_BODY = LABEL.sub("", SYNTH_ROW, count=1)
if GEN_R not in SYNTH_ROW:
    print("diff_secp: label control is broken: the synthetic row holds no value")
    fail = 1
elif GEN_R in SYNTH_BODY:
    print("diff_secp: label control FAILED: a value in a row label survives the strip")
    fail = 1
else:
    print("diff_secp: label control ok, a value parked in a row name is not found")

sys.exit(fail)
