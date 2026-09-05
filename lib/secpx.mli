(* secp256k1: ECDSA VERIFICATION over a caller-supplied digest, and
   ECDH. Internal unit: venice.mli does not re-export it, and the curve
   record, the Jacobian point, the field helpers and the scalar ladder
   stay inside the implementation. Every rejection is an option or a
   false, so this unit adds no Errx constructor. M29 (sessx) and M33
   (the response signature) export what they need.

   The unit HASHES nothing. verify takes a digest, because the signed
   message formula of the /tee/signature route is UNPINNED until M31,
   so a message-taking entry would guess it. It decompresses nothing,
   so the 0x02 and 0x03 point forms are rejections and never inputs,
   and it recovers no public key, because the enclave signing key is an
   attested field.

   ONE scalar walk serves verify, Pubkey.of_scalar, shared_point and
   shared_x: a FIXED-SHAPE Montgomery ladder over a 256-entry bit list
   that makes 256 addition calls and 256 doubling calls for every
   scalar, so the CALL shape never depends on a secret bit. The
   field-operation count is NOT constant, and two residual leaks stay.
   The limbsx arithmetic underneath is VARIABLE-TIME, so the values
   that flow through a step still leak through timing; and the addition
   returns early while the accumulator is still the point at infinity,
   so the bit LENGTH of the scalar leaks. A constant-time tower is the
   M39 hardening candidate. *)

module Scalar : sig
  (* A SECRET scalar in 1 .. n-1. ABSTRACT, so the range invariant
     holds by construction. Every walk that reads one runs the
     fixed-shape ladder above, with the two residual leaks that
     paragraph names. *)
  type t

  (* Exactly 32 big-endian bytes whose value sits in 1 .. n-1. Zero, n,
     any value above n and every other length are None, which is what
     rejection sampling needs: M29 retries on None. *)
  val of_bytes : string -> t option

  (* The 32 bytes of the scalar, zero-padded on the left. *)
  val to_bytes : t -> string
end

module Pubkey : sig
  (* A VALIDATED affine point. ABSTRACT, so a key exists only when both
     coordinates sit below the field prime and the pair is on the
     curve. *)
  type t

  (* Each coordinate is exactly 32 big-endian bytes. None when either
     length is wrong, when either value is at or above the field prime,
     and when the pair is off the curve. The zero pair falls out of the
     curve test, because 0 = 7 has no solution. *)
  val of_xy : x:string -> y:string -> t option

  (* 64 bytes are X || Y. 65 bytes whose first byte is 0x04 are the
     SEC 1 uncompressed form the E2EE header and every response chunk
     carry, and the 64-byte tail is read. Every other length is None,
     and so is a 65-byte input under any other first byte: the
     compressed 0x02 and 0x03 forms included, because this unit
     decompresses nothing. *)
  val of_bytes : string -> t option

  (* The 64 bytes X || Y, each coordinate zero-padded on the left. *)
  val to_bytes : t -> string

  (* The 65 bytes 0x04 || X || Y, the SEC 1 uncompressed form the
     X-Venice-TEE-Client-Pub-Key header carries. *)
  val to_sec1 : t -> string

  (* Coordinate equality. A public key is PUBLIC, so no constant-time
     compare is owed. *)
  val equal : t -> t -> bool

  (* d G in affine, through the fixed-shape ladder. None only at the
     point at infinity, which is unreachable: d sits in 1 .. n-1 and
     the group order is prime, so the caller fails closed on a value it
     can never see. *)
  val of_scalar : Scalar.t -> t option
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

   The digest is read as a big-endian integer with no reduction of its
   own, and the final compare is against the residue of x(R) by the
   group order, which a corpus vector with x(R) above n exercises.

   The malleable twin (r, n - s) VERIFIES. The standard carries no
   low-s rule, so this is the standard behaviour and not a defect; the
   EIP-2 rule is a consumer decision, and a consumer that needs one
   signature per message owes its own uniqueness check.

   This unit exposes no message-taking entry, and that absence is
   deliberate: the signed message formula is unpinned until M31, so this
   unit hashes nothing.

   VARIABLE-TIME, on public inputs only. *)
val verify : Pubkey.t -> Signature.t -> digest:string -> bool

(* d Q in affine, through the same fixed-shape ladder verify runs, and
   re-validated as a public key. None only at the point at infinity,
   which is unreachable for a validated Q: the group has prime order
   and cofactor 1. Exposed beside shared_x because the KDF input is
   unpinned until the M22 and M31 probes. *)
val shared_point : Scalar.t -> Pubkey.t -> Pubkey.t option

(* The 32-byte big-endian x of d Q, the SEC 1 section 3.3.1 shared
   secret value and the Wycheproof shared field. Defined through
   shared_point, so the two cannot drift. *)
val shared_x : Scalar.t -> Pubkey.t -> string option

(* The accepted digest size in bytes, 32. A unit function, not a
   constant: ZxCaml trap 2 makes a top-level constant invisible inside
   a helper. *)
val digest_len : unit -> int
