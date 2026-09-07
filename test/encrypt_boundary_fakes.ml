(* Test-only admission witnesses for the verbatim Sessionx host copy.
   Client public keys and AES keys use the real scalar multiplication,
   ECDH and HKDF. No accepting witness is added to the library. *)
module Errx = Venice__Errx
module Entropyx = Venice__Entropyx
module Policyx = Venice__Policyx
module Derx = Venice__Derx
module Secpx = Venice__Secpx
module Gcmx = Venice__Gcmx
module Hexx = Venice__Hexx
module Chatx = Venice__Chatx
module Httpx = Venice__Httpx
module Encryptx = Venice__Encryptx

module Modelx = struct
  type e2ee = |
  type 'c t = string
end

module Attestx = struct
  module Attested = struct
    type 'l t = { nonce_value : Policyx.Nonce.t }
    let nonce (t : 'l t) : Policyx.Nonce.t = t.nonce_value
  end
end

let peer_hex (() : unit) : string =
  "045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da"

module Sessx = struct
  module Cpu_only = struct type t = unit end
  type 'c admission = string
  type 'c t = {
    model : string;
    client_key : Secpx.Pubkey.t;
    cipher_key : Gcmx.Key.t;
  }

  let admit ~(cpu_only : Cpu_only.t) ~(now : Derx.Now.t)
      ~(attested : Policyx.Expect.full Attestx.Attested.t)
      ~(model : ('c * Modelx.e2ee) Modelx.t) : ('c admission, Errx.t) result =
    let (_ : Cpu_only.t) = cpu_only in
    let (_ : Derx.Now.t) = now in
    let (_ : Policyx.Expect.full Attestx.Attested.t) = attested in
    Ok model

  let establish ~(scalar : Secpx.Scalar.t) (model : 'c admission) :
      ('c t, Errx.t) result =
    let ( let* ) = Result.bind in
    let* client_key = Venice__Sessx.client_key ~scalar in
    let* bytes = Hexx.decode (peer_hex ()) in
    let* peer = Option.to_result ~none:(Errx.Session_invalid "test peer")
      (Secpx.Pubkey.of_bytes bytes) in
    Result.map (fun cipher_key -> { model; client_key; cipher_key })
      (Venice__Sessx.derive_key ~scalar ~peer)

  let client_pubkey_hex (t : 'c t) : string =
    Hexx.encode (Secpx.Pubkey.to_sec1 t.client_key)
  let model_pubkey_hex (_ : 'c t) : string = peer_hex ()
  let model_id (t : 'c t) : string = t.model
  let key (t : 'c t) : Gcmx.Key.t = t.cipher_key
end
