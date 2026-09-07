(* M29 host orchestration. No secret escapes the public signature. *)
let ( let* ) = Result.bind
type 'c t = 'c Sessx.t
module Cpu_only = Sessx.Cpu_only

let establish ~(entropy : Entropyx.t) ~(fresh : Entropyx.Fresh.t)
    ~(cpu_only : Cpu_only.t)
    ~(now : Derx.Now.t) ~(attested : Policyx.Expect.full Attestx.Attested.t)
    ~(model : ('c * Modelx.e2ee) Modelx.t) : ('c t, Errx.t) result =
  let* () = Entropyx.Fresh.consume fresh ~nonce:(Attestx.Attested.nonce attested) in
  let* admitted = Sessx.admit ~cpu_only ~now ~attested ~model in
  let* scalar = Entropyx.scalar entropy in
  Sessx.establish ~scalar admitted

let client_pubkey_hex = Sessx.client_pubkey_hex
let model_pubkey_hex = Sessx.model_pubkey_hex
let model_id = Sessx.model_id
