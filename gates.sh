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
suites="test_codec test_bytes test_jsonx test_modelx test_paramsx test_msgx test_headx test_chatx"
for t in $suites; do
  out="$("$here/_build/default/test/$t.exe")"
  echo "$t: $out"
  case "$out" in
    *FAIL*) echo "gate: $t failed"; exit 1 ;;
  esac
done

# M7 compile-fail battery: every case must fail against the built
# library for the EXPECTED reason (asserted error-text substrings,
# never bare nonzero exit). The control MUST compile first, or the
# battery is vacuous (wrong include path, stale artifacts).
cfsrc="$here/compile_fail"
cfdir="$here/_build/compile_fail"
cfinc="$here/_build/default/lib/.venice.objs/byte"
rm -rf "$cfdir"
mkdir -p "$cfdir"
cp "$cfsrc"/*.ml "$cfdir/"

if (cd "$cfdir" && ocamlc -c -color never -I "$cfinc" cf_ok_control.ml) ; then
  echo "compile_fail: control ok"
else
  echo "gate: compile-fail control did not compile (battery vacuous)"
  exit 1
fi

expect_fail() {
  src="$1"; shift
  if out="$( (cd "$cfdir" && ocamlc -c -color never -I "$cfinc" "$src") 2>&1 )"; then
    echo "gate: $src compiled but must not"
    exit 1
  fi
  for needle in "$@"; do
    case "$out" in
      *"$needle"*) ;;
      *)
        echo "gate: $src failed for the wrong reason; missing [$needle] in:"
        echo "$out"
        exit 1
        ;;
    esac
  done
  echo "compile_fail: $src rejected as expected"
}

expect_fail cf_a_unwitnessed.ml "Venice.Model.vision"
expect_fail cf_b_wrong_witness.ml "Venice.Model.audio" "not compatible"
expect_fail cf_c_two_models.ml "bound by the constructor" "Pack"
expect_fail cf_d_stacked.ml "Venice.Model.vision" "not compatible"
expect_fail cf_e_repack.ml "Venice.Msg.nonempty" "not compatible"
expect_fail cf_f_effort_wrong_model.ml "Venice.Model.reasoning_effort" "not compatible"

# Compile-fail harnesses (M12, M34).
if [ -x "$here/harness/compile_fail.sh" ]; then
  "$here/harness/compile_fail.sh"
fi

# Model check + correspondence (M35..M37).
if [ -x "$here/model/check.sh" ]; then
  "$here/model/check.sh"
fi

# ZxCaml core gate; grows as core modules land. zxlint runs on every
# core module. omlz check joins only for the bpf-artifact modules
# (quotex + policy, M38+): the omlz subset has no functors, so the
# Map-based codec layer is zxlint-clean but not omlz-checkable.
# Paths relative to lib/, core module first (zxlint requirement).
core="errx.ml bytesx.ml hexx.ml b64x.ml jsonx.ml paramsx.ml modelx.ml msgx.ml headx.ml chatx.ml"
if [ -n "$core" ]; then
  files=""
  for f in $core; do files="$files $here/lib/$f"; done
  # shellcheck disable=SC2086
  zxlint --errors-only $files
fi

echo "gates: all green"
