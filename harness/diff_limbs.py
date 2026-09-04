#!/usr/bin/env python3
"""M16 differential gate over lib/limbsx.ml.

Every arithmetic constant that test/test_limbsx.ml pins is recomputed
here with python integers and pow(), an implementation the OCaml unit
shares no code with. A recomputed value must then sit VERBATIM inside a
CHECK ROW of the suite, which is the part a raw substring test cannot
give: `must_contain` over the whole file text also passes for a pin
parked in a comment or in a let that no check ever reads.

So the negative control has two parts (A3):

1. The suite text is stripped of OCaml comments, nesting aware, before
   any search, and each pin must match inside a check row, that is
   inside one element of a `(string * bool) list` literal.
2. A corrupted twin of pin (a)'s result, its last nibble flipped, must
   be ABSENT from the stripped text. The absent twin alone proves only
   that the search CAN fail; the row context is what proves the pin
   sits inside an executed check.

One `diff_limbs: <name> ok` line is printed per pin, so the gate log
proves coverage. Any miss exits 1.

Standard library only: pow, int, re, pathlib, sys.
"""

import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
root = here.parent
suite_path = root / "test" / "test_limbsx.ml"

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
    print(f"diff_limbs: the suite is missing: {suite_path}")
    sys.exit(1)

RAW = suite_path.read_text()
STRIPPED = strip_ocaml_comments(RAW)
ROWS = check_rows(STRIPPED)

if not ROWS:
    print("diff_limbs: no check row found in the suite; the oracle is vacuous")
    sys.exit(1)


def hex256(v: int) -> str:
    return format(v, "064x")


def pin(name: str, needles: list) -> None:
    """Require every needle of a pin to sit inside one check row."""
    global fail
    missing = [x for x in needles if not any(x in row for row in ROWS)]
    for x in missing:
        print(f"diff_limbs: {name}: recomputed value is in no check row")
        print(f"  wanted: {x}")
    if missing:
        fail = 1
    else:
        print(f"diff_limbs: {name} ok")


def require(name: str, ok: bool) -> None:
    """A pure arithmetic fact about a pin, independent of the suite."""
    global fail
    if not ok:
        print(f"diff_limbs: {name}: the python recompute disagrees with itself")
        fail = 1


# ---------- pin (a): the jose 255-bit modexp vector ----------

m255 = 2**255 - 19
b255 = int("4a7c559911fa2016c34479067b47d02be2b17b0b1b0d8a2d6d312bc939b204d1", 16)
r255 = hex256(pow(b255, 65537, m255))
require("pin a", b255 < m255)
pin("pin a 255-bit modexp e=65537", [hex256(m255), hex256(b255), r255])

# ---------- pin (b): the P-256 prime and a Fermat inverse ----------

p256 = 2**256 - 2**224 + 2**192 + 2**96 - 1
a_p256 = int("2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe", 16)
inv_p256 = pow(a_p256, p256 - 2, p256)
require("pin b", a_p256 < p256 and a_p256 * inv_p256 % p256 == 1)
pin(
    "pin b P-256 prime and Fermat inverse",
    [hex256(p256), hex256(a_p256), hex256(inv_p256)],
)

# ---------- pin (c): the secp256k1 prime and a Fermat inverse ----------

psecp = 2**256 - 2**32 - 977
a_secp = int("3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8", 16)
inv_secp = pow(a_secp, psecp - 2, psecp)
require("pin c", a_secp < psecp and a_secp * inv_secp % psecp == 1)
pin(
    "pin c secp256k1 prime and Fermat inverse",
    [hex256(psecp), hex256(a_secp), hex256(inv_secp)],
)

# ---------- pin (d): a 512-bit product reduced mod the P-256 prime ----------

a_mul = int("9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95", 16)
b_mul = int("517cc1b727220a94fe13abe8fa9a6ee06db14acc9e21c820ff28b1d5ef5de2b0", 16)
prod_red = a_mul * b_mul % p256
require("pin d", (a_mul * b_mul).bit_length() > 256 and prod_red < p256)
pin(
    "pin d 512-bit product reduced mod P-256",
    [hex256(a_mul), hex256(b_mul), hex256(prod_red)],
)

# ---------- pin (e): a borrow chain through every limb ----------

a_sub = 2**255
b_sub = 1
diff = a_sub - b_sub
require("pin e", a_sub % 65536 < b_sub % 65536 and diff + b_sub == a_sub)
pin("pin e 256-bit borrow chain", [hex256(a_sub), hex256(b_sub), hex256(diff)])

# ---------- the negative control ----------

twin = r255[:-1] + format(int(r255[-1], 16) ^ 1, "x")
if twin == r255:
    print("diff_limbs: negative control is broken: the twin equals the pin")
    fail = 1
elif twin in STRIPPED:
    print("diff_limbs: negative control FAILED: the corrupted twin of pin a is present")
    print(f"  twin: {twin}")
    fail = 1
else:
    print("diff_limbs: negative control ok, the corrupted twin of pin a is absent")

sys.exit(fail)
