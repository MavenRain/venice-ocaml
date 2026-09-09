(* Host admission boundary. A Fresh token is consumed before every
   check, including nonce mismatch, stale collateral and entropy failure. *)
type 'c t
module Cpu_only = Sessx.Cpu_only
val establish : entropy:Entropyx.t -> fresh:Entropyx.Fresh.t ->
  cpu_only:Cpu_only.t -> now:Derx.Now.t ->
  attested:Policyx.Expect.full Attestx.Attested.t ->
  model:('c * Modelx.e2ee) Modelx.t -> ('c t, Errx.t) result
val client_pubkey_hex : 'c t -> string
val model_pubkey_hex : 'c t -> string
val model_id : 'c t -> string

(* Burn fresh before every attempt, then reserve its nonce in the shared
   session registry. Duplicate bytes reject even from distinct handles.
   The registry permits at most 65,536 reservations, including failures. *)
val encrypt : fresh:Entropyx.Gcm_fresh.t -> 'c t -> string ->
  (Encryptx.Ciphertext.t, Errx.t) result

(* Validate the entire chat before drawing one nonce per message. No
   partial request is returned. The result is immutable and can be sent
   through the existing transport and decoded with Stream below. *)
val request : entropy:Entropyx.t -> 'c t -> 'c Chatx.t ->
  (Httpx.Request.t, Errx.t) result

(* GCM-checked chunks, not receipt-verified responses. Requires DONE:
   closing defaults to Require_done. A caller that meets a clean EOF
   passes ~closing:Ssex.Allow_eof.
   Earlier chunks may have been consumed when a later frame fails. *)
module Stream (T : Streamx.S) : sig
  val run : ?closing:Ssex.closing -> ?max_line_bytes:int -> ?max_event_bytes:int ->
    'c t -> T.body -> (Streamx.cursor -> 'a) -> 'a * Streamx.outcome
end
