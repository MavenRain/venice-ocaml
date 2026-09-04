(* HMAC-SHA256 and HKDF-SHA256. Internal unit: venice.mli does not
   re-export it, and the private helpers (pad_key, xor_with) stay
   inside the implementation. Every rejection is an option; this unit
   adds no Errx constructor. *)

(* The HMAC block size in bytes, 64. A unit function, not a constant:
   ZxCaml trap 2 makes a top-level constant invisible inside a
   helper. *)
val block_size : unit -> int

(* The SHA-256 output size in bytes, 32. *)
val hash_len : unit -> int

(* RFC 2104 HMAC-SHA256, TOTAL: the raw 32-byte tag of msg under key.
   A key longer than block_size () bytes is replaced by its SHA-256
   digest (the RFC 4231 cases 6 and 7 path), then the key is
   zero-padded to block_size () bytes. No input cap: HMAC is linear in
   the input and the host bounds the strings it reads. *)
val sha256 : key:string -> string -> string

(* Constant-time comparison. False when the lengths differ, because
   lengths are public; otherwise the OR of every byte difference is
   folded and compared to zero ONCE, with no early exit, so the running
   time does not depend on where the first difference sits. *)
val equal_ct : string -> string -> bool

(* equal_ct of the recomputed tag against the offered one: the ONLY tag
   check a consumer should write. *)
val verify : key:string -> string -> tag:string -> bool

(* HKDF-SHA256, RFC 5869: extract a pseudorandom key, then expand it to
   the length a consumer asks for. Like the HMAC above, every branch
   here reads a LENGTH and never a key byte or a data byte. derive is
   the M29 entry point: a raw ECDH shared secret goes through extract,
   never straight to expand. *)
module Hkdf : sig
  (* Exactly hash_len () bytes. ABSTRACT, so a pseudorandom key is
     minted ONLY by extract and expand cannot be handed raw keying
     material by mistake. *)
  type prk

  (* RFC 5869 section 2.2, TOTAL. An empty salt IS the "HashLen zeros"
     default of the RFC, because HMAC zero-pads a short key to the
     block size, so this takes a plain salt with no optional argument
     and no default value. *)
  val extract : salt:string -> ikm:string -> prk

  (* The hash_len () raw bytes of the pseudorandom key. *)
  val prk_to_string : prk -> string

  (* The RFC 5869 section 2.3 output cap in bytes, 255 * hash_len () =
     8160. *)
  val max_len : unit -> int

  (* RFC 5869 section 2.3. None when len is negative and None when len
     is above max_len (); Some "" at len 0; otherwise the first len
     bytes of T(1) || T(2) || ... where T(0) = "" and T(i) =
     sha256 ~key:prk (T(i-1) ^ info ^ byte i). *)
  val expand : prk -> info:string -> len:int -> string option

  (* extract then expand: the one call a session key schedule needs. *)
  val derive : salt:string -> ikm:string -> info:string -> len:int ->
    string option
end
