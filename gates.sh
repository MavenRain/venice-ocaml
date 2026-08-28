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
suites="test_codec test_bytes"
for t in $suites; do
  out="$("$here/_build/default/test/$t.exe")"
  echo "$t: $out"
  case "$out" in
    *FAIL*) echo "gate: $t failed"; exit 1 ;;
  esac
done

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
core="errx.ml bytesx.ml hexx.ml b64x.ml"
if [ -n "$core" ]; then
  files=""
  for f in $core; do files="$files $here/lib/$f"; done
  # shellcheck disable=SC2086
  zxlint --errors-only $files
fi

echo "gates: all green"
