(* M21 gcmx: AES-256-GCM of SP 800-38D, seal and unseal, over the
   forward AES-256 of aesx.  Internal unit: venice.mli does not
   re-export it, and the field element, GHASH, the CTR pass and the tag
   arithmetic stay inside the implementation.  M30 (the encrypt path)
   and M32 (the decrypt path) are the consumers, one chunk per call.
   Every rejection is an option, so this unit adds no Errx constructor.

   The name is unseal because open is an OCaml keyword;  the roadmap
   row's "open" is the AEAD verb and not an identifier.

   GHASH runs exactly 128 masked steps per block and the tag compare
   runs through Hmacx.equal_ct, so no branch reads a key byte or a data
   byte: no secret-indexed memory access and no secret-dependent branch
   in the S-box, MixColumns, the key schedule or GHASH;  residual: the
   OCaml native compiler, the allocator and the * operator are not
   constant-time by contract, M39.

   Out of scope, each with its owner.  No IV outside 96 bits, so no
   GHASH-derived J0;  no tag truncation;  no streaming or incremental
   API, because M32 calls unseal once per chunk;  no nonce generation,
   which M29 and M30 own through Fresh.t;  no key derivation, which the
   M17 HKDF owns;  no hex framing, which M30's Ciphertext.t owns;  and
   no GCM-SIV. *)

module Key : sig
  (* The AES-256 key as its expanded schedule and its H, both computed
     ONCE at construction.  ABSTRACT with no to_bytes and no equal,
     because a key never leaves this unit. *)
  type t

  (* EXACTLY 32 key bytes, None on every other length. *)
  val of_bytes : string -> t option
end

module Nonce : sig
  (* The 96-bit GCM nonce.  Uniqueness per key is the CALLER's
     obligation, M30's Fresh.t under model spec P3 (DESIGN.md:56);
     this unit cannot check it, and a repeat is catastrophic. *)
  type t

  (* EXACTLY 12 bytes, None on every other length. *)
  val of_bytes : string -> t option

  (* The 12 nonce bytes, for the wire header M30 assembles. *)
  val to_bytes : t -> string
end

module Tag : sig
  (* The 128-bit GCM authentication tag. *)
  type t

  (* EXACTLY 16 bytes, None on every other length. *)
  val of_bytes : string -> t option

  (* The 16 tag bytes, for the wire header M30 assembles. *)
  val to_bytes : t -> string

  (* The constant-time compare of Hmacx.equal_ct: the OR of every byte
     difference with no early exit.  unseal already runs it, so a
     consumer needs this only to compare two tags of its own. *)
  val equal_ct : t -> t -> bool
end

(* The ciphertext and its tag over the AAD and the plaintext.  The AAD
   is an explicit labelled argument with no default, because M30 and
   M32 pass "" until M31 pins the chunk layout.  None ONLY when the
   plaintext is longer than max_len ().  An empty plaintext is GMAC
   over the AAD. *)
val seal : Key.t -> Nonce.t -> aad:string -> string -> (string * Tag.t) option

(* The plaintext of a ciphertext that carries a MATCHING tag.  The tag
   is checked over the offered ciphertext FIRST, so None arrives on a
   tag mismatch before any plaintext byte exists;  None also arrives
   when the ciphertext is longer than max_len (). *)
val unseal : Key.t -> Nonce.t -> aad:string -> string -> Tag.t -> string option

(* The SP 800-38D section 5.2.1.1 plaintext and ciphertext cap in
   bytes, (2^32 - 2) * 16 = 68719476704.  The AAD is uncapped here,
   because its 2^61-byte bound is unreachable on this host. *)
val max_len : unit -> int

(* The key size in bytes, 32.  A unit function, because ZxCaml trap 2
   makes a top-level constant invisible inside a helper. *)
val key_len : unit -> int

(* The nonce size in bytes, 12. *)
val nonce_len : unit -> int

(* The tag size in bytes, 16. *)
val tag_len : unit -> int
