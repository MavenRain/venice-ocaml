(* M30 pure encryption and request preparation. Sessionx owns nonce
   allocation and consumption. This unit performs no IO or mutation. *)

module Ciphertext : sig
  type t
  val to_hex : t -> string
end

(* AES-256-GCM with empty AAD. The lowercase hex frame is the 65-byte
   SEC 1 client key, 12-byte nonce, ciphertext, then 16-byte tag.
   Plaintext above 2_000_000 bytes rejects before AES with
   Session_invalid "plaintext length". *)
val seal : key:Gcmx.Key.t -> client_pubkey:Secpx.Pubkey.t ->
  nonce:Gcmx.Nonce.t -> string -> (Ciphertext.t, Errx.t) result

type 'c plan

(* Accept only bare-string user/system messages without metadata.
   Reject unsupported roles, media, tools, prompt-bearing metadata and
   enabled searches. The model must equal the session's model_id.
   Force streaming and E2EE, disable search, and check the exact final
   encrypted JSON length before any encryption takes place. *)
val prepare : model_id:string -> 'c Chatx.t -> ('c plan, Errx.t) result
val plaintexts : 'c plan -> string list

(* Ciphertexts must correspond to the prepared messages in order.
   Creates the three E2EE headers and passes the final body through the
   ordinary HTTP request mint. No plaintext projection is transmitted. *)
val finish : client_pubkey_hex:string -> model_pubkey_hex:string ->
  'c plan -> Ciphertext.t list -> (Httpx.Request.t, Errx.t) result
