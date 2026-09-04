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
suites="test_codec test_bytes test_jsonx test_modelx test_paramsx test_msgx test_headx test_chatx test_respx test_ssex test_accx test_streamx test_transport test_curlx test_retryx test_clientx test_limbsx test_hmacx test_keccakx"
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
core="errx.ml bytesx.ml hexx.ml b64x.ml jsonx.ml paramsx.ml modelx.ml msgx.ml headx.ml chatx.ml respx.ml ssex.ml accx.ml keyx.ml httpx.ml cfgx.ml wirex.ml retryx.ml limbsx.ml hmacx.ml keccakx.ml"
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
