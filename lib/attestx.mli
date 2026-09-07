(* M28: the internal, pure attestation pipeline. The only mint of an
   Attested witness is verify. The level is preserved from Expect.

   Order: envelope shape and required strings, nonce echo, quote
   encoding and parse, signing key and address, PCK chain, signatures,
   TCB, REPORTDATA and measurements, GPU payload, witness.

   Lower-unit errors pass through unchanged. Attest_invalid uses only:
   "envelope", "intel quote member", "intel quote encoding",
   "signing key member", "signing key", "signing address member",
   "signing address", "nonce member", "nonce echo", "nvidia payload",
   "nvidia payload json", "nvidia payload members",
   "nvidia payload nonce", "nvidia evidence list".

   This verifies the ECDSA binding only. Non-Revoked TCB grades are
   carried, not promoted to UpToDate. GPU evidence is structurally
   checked but never authenticated by NRAS; absence is accepted at
   both levels, and an explicit JSON null nvidia_payload counts as
   absence, as the harness oracle reads it. The verified flag is untrusted metadata. No CRL,
   network, clock, entropy or nonce consumption occurs here. M29 owns
   session admission and nonce consumption. The synthetic fixture has
   no accepting end-to-end case: its signed binding belongs to Phala.
   M29 exports the pipeline through Venice.Tee and implements the host
   Fresh/session boundary separately. *)

module Envelope : sig
  type t
  (* Primary nonce wins when present. Missing differs from JSON null.
     Optional metadata of the wrong type is carried as None. *)
  val of_json : string -> (t, Errx.t) result
  val intel_quote : t -> string
  val nonce_echo : t -> string
  val signing_key_hex : t -> string
  val signing_address_hex : t -> string
  val nvidia_payload : t -> Jsonx.t option
  val model : t -> string option
end

module Gpu : sig
  module Payload : sig
    type t
    val nonce_hex : t -> string
    val arch : t -> string
    val evidence_count : t -> int
  end
  (* Absent for a missing member and for an explicit JSON null. *)
  type t = Absent | Present of Payload.t
end

(* Try strict standard base64, then hex. Commit the first candidate
   with little-endian version 4, then parse exactly once. Malformed
   v4 bytes return Quote_invalid; other versions are encoding errors. *)
val decode_quote : string -> (Quotex.t, Errx.t) result
val check_echo : echo:string -> nonce:Policyx.Nonce.t -> (unit, Errx.t) result
val check_signing_key : key_hex:string -> address_hex:string ->
  (Secpx.Pubkey.t * Keccakx.Address.t, Errx.t) result

(* String containing an object or an object directly. Require nonce
   and arch strings and an evidence_list member, then nonce equality,
   then a nonempty list. Arch and evidence contents are not verified.
   The expected nonce is explicit so the public leg cannot skip it. *)
val parse_payload : nonce:Policyx.Nonce.t -> Jsonx.t -> (Gpu.Payload.t, Errx.t) result
val check_gpu : nonce:Policyx.Nonce.t -> Jsonx.t option -> (Gpu.t, Errx.t) result

(* Whole Unix seconds, inclusive 0..253402300799. Gregorian calendar,
   no leap seconds. None outside the supported four-digit year range. *)
val now_of_unix : seconds:int -> Derx.Now.t option

(* Recheck a quote and the supplied original collateral at an explicit
   instant. The signature witness is re-minted from the same quote, so
   the QE report and the signed 632-byte region are re-bound here and no
   foreign witness can be paired with these bytes. No Attested witness is
   minted here; REPORTDATA and measurements remain separate. *)
val revalidate_evidence : now:Derx.Now.t -> collateral:Tcbx.Collateral.t ->
  quote:Quotex.t -> (unit, Errx.t) result

module Attested : sig
  type 'level t
  val quote : 'l t -> Quotex.t
  val chain : 'l t -> Derx.t
  val signature : 'l t -> Sigx.t
  val tcb : 'l t -> Tcbx.t
  val policy : 'l t -> 'l Policyx.t
  val nonce : 'l t -> Policyx.Nonce.t
  val signing_key : 'l t -> Secpx.Pubkey.t
  val signing_address : 'l t -> Keccakx.Address.t
  val gpu : 'l t -> Gpu.t
  val model : 'l t -> string option
  val tee_provider : 'l t -> string option
  val verified_flag : 'l t -> bool option
  (* Recheck the original PCK chain and signed collateral at a new
     caller-supplied instant. Lower-unit errors pass through. *)
  val revalidate : now:Derx.Now.t -> 'l t -> (unit, Errx.t) result
end

val verify : now:Derx.Now.t -> expect:'l Policyx.Expect.t ->
  nonce:Policyx.Nonce.t -> collateral:Tcbx.Collateral.t -> response:string ->
  ('l Attested.t, Errx.t) result
