(* Host admission boundary. A Fresh token is consumed before every
   check, including nonce mismatch, stale collateral and entropy failure. *)
type 'c t = 'c Sessx.t
module Cpu_only = Sessx.Cpu_only
val establish : entropy:Entropyx.t -> fresh:Entropyx.Fresh.t ->
  cpu_only:Cpu_only.t -> now:Derx.Now.t ->
  attested:Policyx.Expect.full Attestx.Attested.t ->
  model:('c * Modelx.e2ee) Modelx.t -> ('c t, Errx.t) result
val client_pubkey_hex : 'c t -> string
val model_pubkey_hex : 'c t -> string
val model_id : 'c t -> string
