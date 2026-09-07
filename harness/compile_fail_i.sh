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
expect_fail cf_n_stream_sealed_effect.ml "Unbound constructor" "Venice.Stream.Delta"
expect_fail cf_o_client_delay_unminted.ml "Unbound value" "Venice.Delay.of_ms"

# The M21 case (D1): Gcmx.Key is abstract and carries NO to_bytes, so a
# caller cannot project a key back to its bytes.  Its source is written
# here instead of under compile_fail/, because M21 owns this harness and
# not that directory;  the case is otherwise the cf_k shape, an abstract
# type with no projection.  gcmx is internal, so the caller must reach
# it through the mangled name.
cat > "$cfdir/cf_p_key_has_no_to_bytes.ml" <<'CF_P'
let leak (k : Venice__Gcmx.Key.t) : string = Venice__Gcmx.Key.to_bytes k
CF_P
expect_fail cf_p_key_has_no_to_bytes.ml "Unbound value" "Venice__Gcmx.Key.to_bytes"

# M28: both witness levels compile, but structural cannot become full.
cat > "$cfdir/cf_q_attest_control.ml" <<'CF_Q'
module A = Venice__Attestx
module P = Venice__Policyx
let structural (w : P.Expect.structural A.Attested.t) = A.Attested.policy w
let full (w : P.Expect.full A.Attested.t) = A.Attested.policy w
CF_Q
(cd "$cfdir" && ocamlc -c -color never -I "$cfinc" cf_q_attest_control.ml)
echo "compile_fail: attestation control ok"
cat > "$cfdir/cf_q_attest_level.ml" <<'CF_Q'
module A = Venice__Attestx
module P = Venice__Policyx
let promote (w : P.Expect.structural A.Attested.t) : P.Expect.full A.Attested.t = w
CF_Q
expect_fail cf_q_attest_level.ml "P.Expect.structural" "P.Expect.full" "not compatible"

# M29 public surface: the fully witnessed call compiles first.
cat > "$cfdir/cf_r_session_control.ml" <<'CF_R'
let establish ~entropy ~fresh ~cpu_only ~now
    (attested : Venice.Tee.Expect.full Venice.Tee.Attested.t)
    (model : ('c * Venice.Model.e2ee) Venice.Model.t) =
  Venice.Session.establish ~entropy ~fresh ~cpu_only ~now ~attested ~model
let prepare ~entropy ~measurements ~now ~collateral ~response =
  Result.bind (Venice.Fresh.make ~entropy) (fun fresh ->
    let nonce = Venice.Fresh.nonce fresh in
    let expect = Venice.Tee.Expect.make ~measurements in
    Result.map (fun attested -> (fresh, attested))
      (Venice.Tee.verify ~now ~expect ~nonce ~collateral ~response))
CF_R
(cd "$cfdir" && ocamlc -c -color never -I "$cfinc" cf_r_session_control.ml)
echo "compile_fail: session control ok"

cat > "$cfdir/cf_r_session_structural.ml" <<'CF_R'
let reject ~entropy ~fresh ~cpu_only ~now ~model
    (attested : Venice.Tee.Expect.structural Venice.Tee.Attested.t) =
  Venice.Session.establish ~entropy ~fresh ~cpu_only ~now ~attested ~model
CF_R
expect_fail cf_r_session_structural.ml "Venice.Tee.Expect.structural" "Venice.Tee.Expect.full"

cat > "$cfdir/cf_s_session_capability.ml" <<'CF_S'
let reject ~entropy ~fresh ~cpu_only ~now ~attested
    (model : unit Venice.Model.t) =
  Venice.Session.establish ~entropy ~fresh ~cpu_only ~now ~attested ~model
CF_S
expect_fail cf_s_session_capability.ml "Venice.Model.e2ee" "unit"

cat > "$cfdir/cf_t_fresh_abstract.ml" <<'CF_T'
let forged : Venice.Fresh.t = ()
CF_T
expect_fail cf_t_fresh_abstract.ml "Venice.Fresh.t" "unit"

cat > "$cfdir/cf_u_session_secret.ml" <<'CF_U'
let leak (session : 'c Venice.Session.t) = Venice.Session.scalar session
CF_U
expect_fail cf_u_session_secret.ml "Unbound value" "Venice.Session.scalar"

cat > "$cfdir/cf_v_session_key.ml" <<'CF_V'
let leak (session : 'c Venice.Session.t) = Venice.Session.key session
CF_V
expect_fail cf_v_session_key.ml "Unbound value" "Venice.Session.key"

cat > "$cfdir/cf_w_entropy_script.ml" <<'CF_W'
let weak = Venice.Entropy.Fake.make []
CF_W
expect_fail cf_w_entropy_script.ml "Unbound module" "Venice.Entropy.Fake"

cat > "$cfdir/cf_x_cpu_policy.ml" <<'CF_X'
let inferred : Venice.Session.Cpu_only.t = ()
CF_X
expect_fail cf_x_cpu_policy.ml "Venice.Session.Cpu_only.t" "unit"

# M30: both request construction and explicit encryption typecheck using
# the public boundary. Challenge and encryption handles remain distinct.
cat > "$cfdir/cf_y_encrypt_control.ml" <<'CF_Y'
let encrypt ~fresh (session : 'c Venice.Session.t) =
  Venice.Session.encrypt ~fresh session "hello"
let request ~entropy (session : 'c Venice.Session.t) (chat : 'c Venice.Chat.t) =
  Venice.Session.request ~entropy session chat
let inspect (ciphertext : Venice.Ciphertext.t) = Venice.Ciphertext.to_hex ciphertext
CF_Y
(cd "$cfdir" && ocamlc -c -color never -I "$cfinc" cf_y_encrypt_control.ml)
echo "compile_fail: encryption control ok"

cat > "$cfdir/cf_y_nonce_kind.ml" <<'CF_Y'
let reject (fresh : Venice.Fresh.t) session =
  Venice.Session.encrypt ~fresh session "hello"
CF_Y
expect_fail cf_y_nonce_kind.ml "Venice.Fresh.t" "Venice.Gcm_fresh.t"

cat > "$cfdir/cf_z_nonce_forge.ml" <<'CF_Z'
let forged : Venice.Gcm_fresh.t = ()
CF_Z
expect_fail cf_z_nonce_forge.ml "Venice.Gcm_fresh.t" "unit"

cat > "$cfdir/cf_aa_ciphertext_forge.ml" <<'CF_AA'
let forged : Venice.Ciphertext.t = "plaintext"
CF_AA
expect_fail cf_aa_ciphertext_forge.ml "Venice.Ciphertext.t" "string"

cat > "$cfdir/cf_ab_session_forge.ml" <<'CF_AB'
let reject ~entropy chat = Venice.Session.request ~entropy () chat
CF_AB
expect_fail cf_ab_session_forge.ml "Venice.Session.t" "unit"

cat > "$cfdir/cf_ac_request_brand.ml" <<'CF_AC'
let reject ~entropy (session : unit Venice.Session.t) (chat : bool Venice.Chat.t) =
  Venice.Session.request ~entropy session chat
CF_AC
expect_fail cf_ac_request_brand.ml "Venice.Chat.t" "bool" "unit"

cat > "$cfdir/cf_ad_nonce_bytes.ml" <<'CF_AD'
let forge = Venice.Gcm_fresh.of_bytes "012345678901"
CF_AD
expect_fail cf_ad_nonce_bytes.ml "Unbound value" "Venice.Gcm_fresh.of_bytes"
