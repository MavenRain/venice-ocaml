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
suites="test_codec test_bytes test_jsonx test_modelx test_paramsx test_msgx test_headx test_chatx test_respx test_ssex test_transport test_curlx"
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

# Model check + correspondence (M35..M37).
if [ -x "$here/model/check.sh" ]; then
  "$here/model/check.sh"
fi

# ZxCaml core gate; grows as core modules land. zxlint runs on every
# core module. omlz check joins only for the bpf-artifact modules
# (quotex + policy, M38+): the omlz subset has no functors, so the
# Map-based codec layer is zxlint-clean but not omlz-checkable.
# Paths relative to lib/, core module first (zxlint requirement).
# curlx.ml and fakex.ml are HOST modules (Unix, Bytes, refs, the one
# try-with guard): they stay out of this list by design.
core="errx.ml bytesx.ml hexx.ml b64x.ml jsonx.ml paramsx.ml modelx.ml msgx.ml headx.ml chatx.ml respx.ml ssex.ml keyx.ml httpx.ml cfgx.ml wirex.ml"
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
