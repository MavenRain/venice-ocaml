(* Pure M29 session core. See sessx.mli for the trust boundary. *)
let ( let* ) = Result.bind

let fail (word : string) : ('a, Errx.t) result =
  Error (Errx.Session_invalid word)

let require (word : string) (value : 'a option) : ('a, Errx.t) result =
  Option.fold ~none:(fail word) ~some:(fun x -> Ok x) value

let current (word : string) (status : Tcbx.Status.t) : (unit, Errx.t) result =
  match status with
  | Tcbx.Status.Up_to_date -> Ok ()
  | Tcbx.Status.Sw_hardening_needed
  | Tcbx.Status.Configuration_needed
  | Tcbx.Status.Configuration_and_sw_hardening_needed
  | Tcbx.Status.Out_of_date
  | Tcbx.Status.Out_of_date_configuration_needed
  | Tcbx.Status.Revoked -> fail word

let check_admission ~(model_id : string) ~(attested_model : string option)
    ~(platform_status : Tcbx.Status.t) ~(qe_status : Tcbx.Status.t)
    ~(gpu : Attestx.Gpu.t) : (unit, Errx.t) result =
  let* named_model = require "model missing" attested_model in
  let* () = if String.equal model_id named_model then Ok ()
    else fail "model mismatch" in
  let* () = current "platform tcb" platform_status in
  let* () = current "qe tcb" qe_status in
  match gpu with
  | Attestx.Gpu.Absent -> Ok ()
  | Attestx.Gpu.Present (_ : Attestx.Gpu.Payload.t) -> fail "gpu unauthenticated"

type 'c admission = {
  model : ('c * Modelx.e2ee) Modelx.t;
  attested : Policyx.Expect.full Attestx.Attested.t;
}

module Cpu_only = struct
  type t = Policyx.Measurements.t
  let trust ~(measurements : Policyx.Measurements.t) : t = measurements
end

let check_cpu_only (trusted : Cpu_only.t) (observed : Policyx.Measurements.t) :
    (unit, Errx.t) result =
  if Policyx.Measurements.equal trusted observed then Ok ()
  else fail "cpu measurements"

let admit ~(cpu_only : Cpu_only.t) ~(now : Derx.Now.t)
    ~(attested : Policyx.Expect.full Attestx.Attested.t)
    ~(model : ('c * Modelx.e2ee) Modelx.t) : ('c admission, Errx.t) result =
  let* () = Attestx.Attested.revalidate ~now attested in
  let* () = check_cpu_only cpu_only
    (Policyx.measurements (Attestx.Attested.policy attested)) in
  let tcb = Attestx.Attested.tcb attested in
  let* () = check_admission ~model_id:(Modelx.id model)
    ~attested_model:(Attestx.Attested.model attested)
    ~platform_status:(Tcbx.platform_status tcb) ~qe_status:(Tcbx.qe_status tcb)
    ~gpu:(Attestx.Attested.gpu attested) in
  Ok { model; attested }

let client_key ~(scalar : Secpx.Scalar.t) : (Secpx.Pubkey.t, Errx.t) result =
  require "client key" (Secpx.Pubkey.of_scalar scalar)

let derive_key ~(scalar : Secpx.Scalar.t) ~(peer : Secpx.Pubkey.t) :
    (Gcmx.Key.t, Errx.t) result =
  let* ikm = require "shared secret" (Secpx.shared_x scalar peer) in
  let* bytes = require "key derivation"
    (Hmacx.Hkdf.derive ~salt:"" ~ikm ~info:"ecdsa_encryption"
      ~len:(Gcmx.key_len ())) in
  require "key derivation" (Gcmx.Key.of_bytes bytes)

type 'c t = {
  admitted : 'c admission;
  secret : Secpx.Scalar.t;
  client_key : Secpx.Pubkey.t;
  cipher_key : Gcmx.Key.t;
}

let establish ~(scalar : Secpx.Scalar.t) (admitted : 'c admission) :
    ('c t, Errx.t) result =
  let* client_key = client_key ~scalar in
  let* cipher_key = derive_key ~scalar
    ~peer:(Attestx.Attested.signing_key admitted.attested) in
  Ok { admitted; secret = scalar; client_key; cipher_key }

let client_pubkey_hex (t : 'c t) : string =
  Hexx.encode (Secpx.Pubkey.to_sec1 t.client_key)
let model_pubkey_hex (t : 'c t) : string =
  Hexx.encode (Secpx.Pubkey.to_sec1 (Attestx.Attested.signing_key t.admitted.attested))
let model_id (t : 'c t) : string = Modelx.id t.admitted.model
let key (t : 'c t) : Gcmx.Key.t = t.cipher_key
let scalar (t : 'c t) : Secpx.Scalar.t = t.secret
