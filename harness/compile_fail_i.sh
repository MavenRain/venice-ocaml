#!/usr/bin/env bash
# Compile-fail harness I (M12): every case must fail against the built
# library for the EXPECTED reason (asserted error-text substrings,
# never a bare nonzero exit). The control MUST compile first, or the
# battery is vacuous (wrong include path, stale artifacts).
#
# Moved out of gates.sh unchanged except for the paths: gates.sh
# derived them from its own "here", so this script computes "root"
# from its own location instead. M34 adds compile_fail_ii.sh.
#
# Every substring below is pinned from a REAL ocamlc 5.3 run. Never
# guess one: ocamlc quotes type names, so a guessed needle passes for
# the wrong reason or fails for none.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

cfsrc="$root/compile_fail"
cfdir="$root/_build/compile_fail"
cfinc="$root/_build/default/lib/.venice.objs/byte"
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
expect_fail cf_g_tools_wrong_model.ml "Venice.Model.tools" "not compatible"
expect_fail cf_h_response_format_wrong_model.ml "Venice.Model.response_schema" "not compatible"
expect_fail cf_i_logprobs_wrong_model.ml "Venice.Model.log_probs" "not compatible"
expect_fail cf_j_video_wrong_model.ml "Venice.Model.video" "not compatible"
expect_fail cf_k_key_no_projection.ml "Unbound value" "Venice.Api_key.to_string"
expect_fail cf_l_route_wrong_method.ml "Venice.Http.Route.post" "not compatible"
expect_fail cf_m_chat_foreign_messages.ml "Venice.Msg.nonempty" "not compatible"
