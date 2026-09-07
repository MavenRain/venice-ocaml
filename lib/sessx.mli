(* M29 pure session admission and key schedule. Fresh consumption and
   scalar rejection sampling belong to the host Sessionx boundary.
   Secrets inherit Secpx's variable-time limb and infinity behavior. *)

val check_admission : model_id:string -> attested_model:string option ->
  platform_status:Tcbx.Status.t -> qe_status:Tcbx.Status.t ->
  gpu:Attestx.Gpu.t -> (unit, Errx.t) result

module Cpu_only : sig
  type t
  (* Explicit deployment trust: the caller independently knows these
     measurements confine inference to the CPU TEE. Missing unsigned
     GPU metadata cannot establish that fact. *)
  val trust : measurements:Policyx.Measurements.t -> t
end
val check_cpu_only : Cpu_only.t -> Policyx.Measurements.t -> (unit, Errx.t) result

(* Both grades must be UpToDate and GPU evidence must be absent, since
   M28 authenticates no GPU evidence. Exact present model metadata is
   required for routing consistency; REPORTDATA does not bind a slug. *)
type 'c admission
val admit : cpu_only:Cpu_only.t -> now:Derx.Now.t ->
  attested:Policyx.Expect.full Attestx.Attested.t ->
  model:('c * Modelx.e2ee) Modelx.t -> ('c admission, Errx.t) result

val client_key : scalar:Secpx.Scalar.t -> (Secpx.Pubkey.t, Errx.t) result
(* HKDF-SHA256(x(d Q), empty salt, "ecdsa_encryption", 32).
   The returned AES key has no byte projection. *)
val derive_key : scalar:Secpx.Scalar.t -> peer:Secpx.Pubkey.t ->
  (Gcmx.Key.t, Errx.t) result

type 'c t
val establish : scalar:Secpx.Scalar.t -> 'c admission -> ('c t, Errx.t) result
val client_pubkey_hex : 'c t -> string
val model_pubkey_hex : 'c t -> string
val model_id : 'c t -> string

(* Internal M30/M32 consumers only. Venice.Session exposes neither
   the secret scalar nor the symmetric key. *)
val key : 'c t -> Gcmx.Key.t
val scalar : 'c t -> Secpx.Scalar.t
