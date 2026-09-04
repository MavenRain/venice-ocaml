(* ECDSA over the NIST P-256 curve with SHA-256 digests, verification
   only. Internal unit: venice.mli does not re-export it, and the curve
   record, the Jacobian point and the field helpers stay inside the
   implementation. Every rejection is an option or a false, so this
   unit adds no Errx constructor. M25 (sigx) and M26 (derx) export what
   they need.

   The unit is VARIABLE-TIME by design and reads only PUBLIC inputs
   (attestation quotes, certificates, signatures), exactly the limbsx
   stance of M16. No ladder here is fixed-shape and none is owed. *)

module Pubkey : sig
  (* A VALIDATED affine point. ABSTRACT, so a key exists only when both
     coordinates sit below the field prime and the pair is on the
     curve. *)
  type t

  (* Each coordinate is exactly 32 big-endian bytes. None when either
     length is wrong, when either value is at or above the field prime,
     and when the pair is off the curve. The zero pair falls out of the
     curve test, because 0 = b has no solution. *)
  val of_xy : x:string -> y:string -> t option

  (* 64 bytes are X || Y. 65 bytes whose first byte is 0x04 are the
     SEC 1 uncompressed form that M26 hands over, and the 64-byte tail
     is read. Every other length is None, and so is a 65-byte input
     under any other first byte: the compressed 0x02 and 0x03 forms
     included, because this unit decompresses nothing. *)
  val of_bytes : string -> t option

  (* The 64 bytes X || Y, each coordinate zero-padded on the left. *)
  val to_bytes : t -> string

  (* Coordinate equality. A public key is PUBLIC, so no constant-time
     compare is owed. *)
  val equal : t -> t -> bool
end

module Signature : sig
  (* ABSTRACT, and the invariant is the point of the type: r and s both
     sit in 1 .. n-1 BY CONSTRUCTION. The psychic signatures of
     CVE-2022-21449 (r = 0 or s = 0, and the out-of-range twins r >= n
     and s >= n) are rejected here, before any point arithmetic
     runs. *)
  type t

  (* Exactly 64 bytes, r || s, each half 32 big-endian bytes. None on
     any other length and on a half outside 1 .. n-1. *)
  val of_raw : string -> t option

  (* Each half is 1 to 32 big-endian bytes, the shape M26 hands over
     once it strips the DER sign byte. The same value rule applies, so
     a 33-byte half is None even when its integer sits in range. *)
  val of_rs : r:string -> s:string -> t option

  (* The 64 bytes r || s, each half zero-padded on the left to 32. *)
  val to_raw : t -> string
end

(* True exactly when the signature is valid for the key over the
   digest. The digest must be exactly digest_len () bytes, so a
   truncated digest and a zero-prefixed digest are both false; the
   second matters, because a 33-byte string whose first byte is zero
   carries the same big-endian integer as the 32-byte digest.

   The malleable twin (r, n - s) VERIFIES. FIPS 186-4 carries no low-s
   rule, so this is the standard behaviour and not a defect. A consumer
   that needs one signature per message owes its own uniqueness check.

   VARIABLE-TIME, on public inputs only. *)
val verify : Pubkey.t -> Signature.t -> digest:string -> bool

(* verify over the SHA-256 digest of the message. *)
val verify_message : Pubkey.t -> Signature.t -> string -> bool

(* The accepted digest size in bytes, 32. A unit function, not a
   constant: ZxCaml trap 2 makes a top-level constant invisible inside
   a helper. *)
val digest_len : unit -> int
