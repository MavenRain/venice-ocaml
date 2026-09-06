#!/usr/bin/env bash
# Gate ladder (DESIGN.md section 8): dunecho build + every suite +
# compile-fail harnesses + model check + correspondence +
# zxlint --errors-only + omlz check over the core-module list
# (bpf build gate joins at M38).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

dunecho build

# Test suites; grows one entry per milestone that lands a suite.
suites="test_codec test_bytes test_jsonx test_modelx test_paramsx test_msgx test_headx test_chatx test_respx test_ssex test_accx test_streamx test_transport test_curlx test_retryx test_clientx test_limbsx test_hmacx test_keccakx test_p256x test_secpx test_aesx test_gcmx test_quotex test_policyx test_sigx"
# The capture sits in an if-condition so a failing suite cannot abort
# the script (set -e) before its output and name reach the log; the
# FAIL-text case still guards a suite that prints FAIL yet exits 0.
for t in $suites; do
  if out="$("$here/_build/default/test/$t.exe")"; then
    echo "$t: $out"
    case "$out" in
      *FAIL*) echo "gate: $t failed"; exit 1 ;;
    esac
  else
    echo "$t: $out"
    echo "gate: $t failed"
    exit 1
  fi
done

# Compile-fail harnesses (M12, M34). The call is unconditional: a
# missing or non-executable harness must turn the gate RED, because a
# skipped battery is a vacuous gate.
"$here/harness/compile_fail_i.sh"

# The python differential harness (M16, DESIGN.md section 8). It
# recomputes every constant that test_limbsx.ml pins and requires each
# one to sit inside a check row of the suite. The call is
# unconditional, exactly like the compile-fail call above: a missing
# interpreter is a RED gate, never a silent skip. The probe names the
# interpreter by absolute path when PATH carries no python3.
py="$(command -v python3 || true)"
if [ -z "$py" ]; then
  py="/opt/homebrew/bin/python3"
fi
"$py" "$here/harness/diff_limbs.py"

# The M17 differential harness, the same shape over test_hmacx.ml: the
# RFC 4231 and RFC 5869 vectors are recomputed with python hmac and
# hashlib and each one must sit inside a check row. Unconditional too.
"$py" "$here/harness/diff_hmac.py"

# The M18 differential harness over test_keccakx.ml. Its keccak shares
# no table with the OCaml unit, and it validates its OWN sponge against
# hashlib.sha3_256 (the sha3 self-check line) before it reads a pin.
"$py" "$here/harness/diff_keccak.py"

# The M19 differential harness over test_p256x.ml. Its P-256 runs in
# AFFINE coordinates over python integers and shares no formula with the
# Jacobian unit, and it SIGNS the RFC 6979 vector and re-verifies the
# result before it reads a pin (the rfc6979 self-check line).
"$py" "$here/harness/diff_p256.py"

# The M20 differential harness over test_secpx.ml. Its secp256k1 runs in
# AFFINE coordinates over python integers and shares no formula with the
# Jacobian unit, and it VERIFIES every embedded Wycheproof vector and
# re-signs its own generated vector before it reads a pin (the
# wycheproof self-check and generated-vector self-check lines). Its pin
# groups are (a) the curve constants, (b) the Wycheproof ECDSA subset,
# (c) the Wycheproof ECDH subset, (d) the generated vectors and (e) the
# boundary values.
"$py" "$here/harness/diff_secp.py"

# The M21 differential harness over test_aesx.ml and test_gcmx.ml. Its
# AES-256 takes the S-box inverse from a log and antilog TABLE over the
# generator 3 and its GHASH runs over ONE python integer, so it shares
# no formula with the computed S-box and the Int64 pair of the OCaml
# units, and it validates its OWN arithmetic against the FIPS 197 and
# GCM-specification known answers, the Wycheproof subset and
# pycryptodome before it reads a pin (the aes, gcm-spec, lnsym,
# wycheproof, corpus and pycryptodome self-check lines). Its pin groups
# are (a) the aesx known answers, (b) the Wycheproof subset fields, (c)
# the SP 800-38D cases 13 to 16, (d) the generated vectors and (e) the
# length cap.
"$py" "$here/harness/diff_gcm.py"

# The M22 differential harness over the real TDX fixtures. It decodes
# fixtures/tdx_quote_v4.bin and fixtures/tdx_quote_v5.bin at ABSOLUTE
# offsets with struct, so it shares no cursor with the OCaml quotex,
# and it re-proves the QE binding sha256(attestation_key ||
# qe_auth_data) and the W1 REPORTDATA formula on synthetic keys, with
# two controls, before it reads a pin (the qe-binding, formula and v5
# self-check lines). Its pin groups are (a) the fixture digests and
# byte counts, (b) the v4 header and body fields, (c) the length rule
# and the trailing padding, (d) the certification chain and (e) the qe
# binding value, (f) the M23 suite pins, (g) the M24 suite pins
# and (h) the M25 suite pins. A
# failed pin COUNTS and the run continues, so one red gate reports every
# disagreement.
"$py" "$here/harness/diff_quote.py"
"$py" "$here/harness/test_diff_quote.py"

# Model check + correspondence (M35..M37).
if [ -x "$here/model/check.sh" ]; then
  "$here/model/check.sh"
fi

# ZxCaml core gate; grows as core modules land. zxlint runs on every
# core module. omlz check joins only for the bpf-artifact modules
# (quotex + policy, M38+): the omlz subset has no functors, so the
# Map-based codec layer is zxlint-clean but not omlz-checkable.
# Paths relative to lib/, core module first (zxlint requirement).
# curlx.ml, fakex.ml, streamx.ml, clockx.ml and clientx.ml are HOST
# modules (Unix, Bytes, refs, the one try-with guard, the one effect
# handler): they stay out of this list by design.  clockx.ml links unix
# for the wall clock and holds a ref in its Fake; clientx.ml links no
# unix of its own but drives a transport and a clock, so it is host by
# its dependencies.  retryx.ml is pure and joins the core list.
# limbsx.ml is the FIRST crypto-tower module (M16): pure, sans-io, no
# Bytes, no Buffer, no Array and no refs, with the one division of the
# whole unit inside div_pos, so it joins the core list after retryx.ml
# and keeps the list in dependency order.
# hmacx.ml is the SECOND crypto-tower module (M17): pure and sans-io in
# the same shape, no Bytes, no Buffer, no Array, no refs and no
# division line at all, with block_size and hash_len as unit thunks so
# the trap-2 rule holds inside every helper. It links sha2 for the
# SHA-256 compression function, which is an external library call and
# zxlint-clean, so it joins the list after limbsx.ml.
# keccakx.ml is the THIRD crypto-tower module (M18): pure and sans-io in
# the same shape, no Bytes, no Buffer, no Array, no refs, no division
# line and no remainder either, because the sponge tracks the fill of
# the current block inside the fold over the input instead of dividing
# the input length. The 25 lanes are int64 values in named record
# FIELDS, five to a row and five rows to a state, so no array and no
# index arithmetic addresses a lane, and rotl is called only with
# literal offsets in 1 .. 63, never with 0 or 64. It links nothing new
# (Int64 is stdlib), so it joins the list after hmacx.ml.
# p256x.ml is the FOURTH crypto-tower module (M19): pure and sans-io in
# the same shape, no Bytes, no Buffer, no Array, no reference cell, no
# division line and no remainder either, because every reduction goes
# through the limbsx mod_red helper and every inverse through the limbsx
# mod_pow helper, so the modulus is always an explicit argument. The
# seven curve constants and the four small multipliers of the Jacobian
# formulas are carried as a record PARAMETER, so no helper reads a
# top-level constant under trap 2. It links nothing new, because sha2
# arrived at M17, so it joins the list after keccakx.ml.
# secpx.ml is the FIFTH crypto-tower module (M20): pure and sans-io in
# the same shape, no Bytes, no Buffer, no Array, no reference cell, no
# division line and no remainder either, because every reduction and
# every inverse goes through the limbsx helpers with the modulus as an
# explicit argument. The twelve curve constants of secp256k1 ride a
# record PARAMETER, so no helper reads a top-level constant under trap
# 2, and the trap fires CROSS-MODULE, so this file is linted beside
# limbsx.ml and never alone. ONE fixed-shape 256-step Montgomery ladder
# serves verify, Pubkey.of_scalar, shared_point and shared_x: it makes
# 256 addition calls and 256 doubling calls for every scalar, so the
# CALL shape never depends on a secret bit, although the
# field-operation count is not constant. It links nothing new, so it
# joins the list after p256x.ml.
# aesx.ml is the SIXTH crypto-tower module (M21): pure and sans-io in
# the same shape, no Bytes, no Buffer, no Array, no reference cell, no
# division line and no remainder either, because the state is four
# packed 32-bit columns in a record and no arithmetic runs on an index.
# The S-box is COMPUTED on every call as the GF(2^8) inverse a^254
# through a chain of eleven gf_mul calls, each of which is eight masked
# doublings with eight masked selects, so no secret indexes memory and
# no branch reads a bit of either operand. It links nothing new, so it
# joins the list after secpx.ml.
# gcmx.ml is the SEVENTH crypto-tower module (M21): pure and sans-io in
# the same shape, with the block fill carried as a counter the fold
# tests with Int.equal, so the unit holds no division line and no
# remainder. GHASH multiplication is ONE fold of exactly 128 MASKED
# steps over a pair of Int64 halves, where each mask is the arithmetic
# negation of one shifted bit and is therefore all-zero or all-one, so
# no branch reads a key bit or a data bit. It reads aesx, bytesx and
# hmacx, and trap 2 fires CROSS-MODULE, so both files are linted beside
# bytesx.ml and hmacx.ml and never alone.
# quotex.ml is the FIRST attestation-tower module (M23): pure and
# sans-io in the same shape, no Bytes, no Buffer, no Array, no
# reference cell, no division line and no remainder either, because
# every window is a total bytesx cursor and every integer is a bytesx
# little-endian reader, so no arithmetic runs on an index. ONE layout
# record built by layout () carries every offset, every size and every
# expected constant, and it is passed FIRST to every helper, so no
# helper reads a top-level constant under trap 2. The PEM chain is cut
# by a RECURSIVE marker scan with no loop keyword and no reference
# cell. It reads bytesx and errx only, and trap 2 fires CROSS-MODULE,
# so this file is linted beside bytesx.ml and never alone. It is the
# FIRST module the omlz note at lines 105 to 108 above names as a bpf
# artifact, so it holds no functor and no Map and stays eligible for
# the M38 gate that the ladder does not run today.
# policyx.ml is the SECOND attestation-tower module (M24): quotex
# DECODES the bytes and this unit DECIDES on them, pure and sans-io in
# the same shape, no Bytes, no Buffer, no Array, no reference cell, no
# division line and no remainder, and no loop keyword. It reads quotex,
# keccakx, secpx, bytesx, hexx and errx, and trap 2 fires CROSS-MODULE,
# so this file is linted beside all six and never alone. ONE rules
# record built by rules () carries every report_data offset, every
# length and the DEBUG mask, and it is passed FIRST to every helper, so
# no helper reads a top-level constant under trap 2 and no numeric
# literal sits outside that record. The two expectation markers, full
# and structural, are UNINHABITED phantom types: they pin the level in
# the signature and cost nothing at run time. The unit applies no
# functor and holds no Map, so it is the SECOND module the omlz note at
# lines 105 to 108 above names as a bpf artifact, eligible for the M38
# gate that the ladder does not run today.
# sigx.ml is the THIRD attestation-tower module (M25): quotex DECODES
# the bytes, policyx DECIDES on the body and this unit PROVES the
# signature section, pure and sans-io in the same shape, no Bytes, no
# Buffer, no Array, no reference cell, no division line and no
# remainder, and no loop keyword. It reads quotex, p256x, bytesx and
# errx and calls Sha2.Sha256.digest, and trap 2 fires CROSS-MODULE, so
# this file is linted beside all four and never alone. ONE rules record
# built by rules () carries the QE binding offset and the binding
# length, and it is passed FIRST to every helper, so no helper reads a
# top-level constant under trap 2 and no numeric literal sits outside
# that record. It calls P256x.verify_message TWICE, once for the QE
# report signature under the PCK leaf key and once for the ISV
# signature under the attestation key, and Sha2.Sha256.digest ONCE,
# inside binding_digest, because the p256x message verify hashes the
# message itself. The unit applies no functor and holds no Map. The
# omlz note at lines 105 to 108 above names quotex plus policy only, so
# this ladder runs no omlz command for it.
core="errx.ml bytesx.ml hexx.ml b64x.ml jsonx.ml paramsx.ml modelx.ml msgx.ml headx.ml chatx.ml respx.ml ssex.ml accx.ml keyx.ml httpx.ml cfgx.ml wirex.ml retryx.ml limbsx.ml hmacx.ml keccakx.ml p256x.ml secpx.ml aesx.ml gcmx.ml quotex.ml policyx.ml sigx.ml"
if [ -n "$core" ]; then
  # The list is echoed so the gate LOG proves which modules zxlint
  # covered; zxlint itself prints only a verdict.
  echo "zxlint core: $core"
  files=""
  for f in $core; do files="$files $here/lib/$f"; done
  # shellcheck disable=SC2086
  zxlint --errors-only $files
fi

echo "gates: all green"
