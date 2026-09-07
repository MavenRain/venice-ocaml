(* Test doubles for the pure admission dependency. The host orchestrator
   is copied verbatim by dune, so these tests exercise its actual order
   with real Fresh tokens and real scalar sampling. No witness constructor
   is added to the library and no successful real quote is simulated. *)
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
    type 'l t = {
      nonce_value : Policyx.Nonce.t;
      admission_error : Errx.t option;
      derivation_error : Errx.t option;
    }
    let nonce (t : 'l t) : Policyx.Nonce.t = t.nonce_value
  end
end

module Sessx = struct
  module Cpu_only = struct type t = unit end
  type 'c admission = Policyx.Expect.full Attestx.Attested.t
  type 'c t = { scalar_hex : string; cipher_key : Gcmx.Key.t }
  let admissions : int Atomic.t = Atomic.make 0
  let derivations : int Atomic.t = Atomic.make 0
  (* The instant the orchestrator forwarded on the last admission. *)
  let last_now : string Atomic.t = Atomic.make ""
  let admit ~(cpu_only : Cpu_only.t) ~(now : Derx.Now.t)
      ~(attested : Policyx.Expect.full Attestx.Attested.t)
      ~(model : ('c * Modelx.e2ee) Modelx.t) : ('c admission, Errx.t) result =
    let (_ : Cpu_only.t) = cpu_only in
    let (_ : ('c * Modelx.e2ee) Modelx.t) = model in
    Atomic.set last_now (Derx.Now.to_string now);
    Atomic.incr admissions;
    Option.fold ~none:(Ok attested) ~some:(fun e -> Error e)
      attested.admission_error
  (* Result.fold defers the derivation work to the success arm, because
     Option.fold takes a value for ~none and would run it every call. *)
  let establish ~(scalar : Secpx.Scalar.t) (a : 'c admission) :
      ('c t, Errx.t) result =
    Atomic.incr derivations;
    Result.fold ~ok:(fun (e : Errx.t) -> Error e)
      ~error:(fun (() : unit) ->
        let bytes = Secpx.Scalar.to_bytes scalar in
        Result.map (fun cipher_key ->
          { scalar_hex = Venice.Hex.encode bytes; cipher_key })
          (Option.to_result ~none:(Errx.Session_invalid "test key")
            (Gcmx.Key.of_bytes bytes)))
      (Option.to_result ~none:() a.derivation_error)
  let client_pubkey_hex (t : 'c t) : string = t.scalar_hex
  let model_pubkey_hex (t : 'c t) : string = t.scalar_hex
  let model_id (t : 'c t) : string = t.scalar_hex
  let key (t : 'c t) : Gcmx.Key.t = t.cipher_key
end
