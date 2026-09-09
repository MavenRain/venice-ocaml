(* Internal M32 boundary. Per-frame ECDH and empty-salt HKDF-SHA256;
   SEC1 key (65), nonce (12), ciphertext, final tag (16). No plaintext
   escapes on authentication failure. Frame plaintext is capped at
   2,000,000 bytes. That cap is the decoder bound. Session.Stream.run
   reaches it only when the caller raises max_line_bytes above about
   4,000,400, because the Ssex line default is 1,048,576.
   This does not establish signer identity or freshness. *)
val frame : scalar:Secpx.Scalar.t -> string -> (string, Errx.t) result

(* Decrypt all nonempty content and reasoning_content fields atomically
   within a chunk. Empty and null content and reasoning_content fields
   are metadata and are not authenticated, so a blanked field passes
   here. A null delta object and a null choices member both reject.
   Any string role value is accepted. Other delta members reject.
   Route model must match; metadata is not authenticated.
   Errors do not quote the encrypted or decrypted payload. *)
val chunk : scalar:Secpx.Scalar.t -> model_id:string -> string ->
  (Ssex.Chunk.t, Errx.t) result

(* Pure incremental decoder. First chunk requires the ordinary identity;
   later chunks may omit object/created, as M31's terminal fixture does.
   Explicit id/model/created changes reject. An error terminates the run. *)
type t
val make : scalar:Secpx.Scalar.t -> model_id:string -> t
val step : t -> string -> (t * Ssex.Chunk.t, Errx.t) result
