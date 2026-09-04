(* keccak-256, the SHA3-256 permutation witness and the Ethereum
   address. Internal unit: venice.mli does not re-export it, and the
   lane types (row, state), the padding domain and the sponge helpers
   stay inside the implementation. Every rejection is an option; this
   unit adds no Errx constructor. M33 exports what it needs under the
   sketch name Eth_address when Tee.Attested.signing_address lands. *)

(* The sponge rate in bytes for a 256-bit digest, 136. A unit function,
   not a constant: ZxCaml trap 2 makes a top-level constant invisible
   inside a helper. *)
val rate : unit -> int

(* The digest size in bytes, 32. *)
val hash_len : unit -> int

(* keccak-256, TOTAL: the raw 32-byte digest under the ORIGINAL Keccak
   multi-rate pad (domain byte 0x01), which is what Ethereum hashes
   with and what SHA3-256 is NOT. No input cap: the sponge is linear in
   the input and the host bounds the strings it reads. *)
val hash : string -> string

(* SHA3-256 of FIPS 202, TOTAL: the same sponge under the 0x06 domain
   byte. Its ONLY purpose is to witness the permutation, because the
   suite pins NIST SHA3-256 values that python's C hashlib recomputes,
   so the permutation is checked against a second, foreign
   implementation. No consumer of this library needs it. *)
val sha3_256 : string -> string

(* Hexx.encode of hash, lowercase and with no prefix: the M33
   convenience. *)
val hash_hex : string -> string

(* The Ethereum address, the rightmost 160 bits of keccak-256 of the
   uncompressed public key (yellow paper appendix F), with the EIP-55
   mixed-case checksum in and out. An address and a public key are
   PUBLIC, so no comparison here is constant-time and none is owed. *)
module Address : sig
  (* Exactly 20 bytes. ABSTRACT, so an address is minted only by
     of_pubkey, of_bytes, of_hex and of_checksum_hex. *)
  type t

  (* The rightmost 20 bytes of the keccak-256 digest of the 64-byte
     public key X || Y. A 65-byte input whose first byte is 0x04 (the
     SEC 1 uncompressed prefix) is accepted too and its 64-byte tail is
     hashed, because no source pins the byte shape of signing_key yet:
     the live fixture at M22 and the parse at M33 decide which form
     arrives, and the accepted set narrows to one then. Every other
     length, and a 65-byte input under any other first byte, is None. *)
  val of_pubkey : string -> t option

  (* Some when the input is exactly 20 bytes, None otherwise. *)
  val of_bytes : string -> t option

  (* The raw 20 bytes. *)
  val to_bytes : t -> string

  (* "0x" then 40 lowercase hex characters. *)
  val to_hex : t -> string

  (* "0x" then the 40 EIP-55 mixed-case characters: a hex letter is
     uppercased when the nibble at the same index of keccak-256 of the
     40 lowercase characters is 8 or more. *)
  val to_checksum_hex : t -> string

  (* A 42-character string under the "0x" or "0X" prefix, or a bare
     40-character string. NO checksum is enforced: a mixed-case string
     whose checksum is wrong still parses here, and of_checksum_hex is
     the strict reader. Any other length, and any byte outside the hex
     alphabet, is None. *)
  val of_hex : string -> t option

  (* of_hex under the EIP-55 acceptance rule: an all-lowercase and an
     all-uppercase body carry no checksum and are accepted, and any
     other body must equal the checksum form of the address it
     denotes. *)
  val of_checksum_hex : string -> t option

  (* Byte equality. An address is PUBLIC, so no constant-time compare
     is owed. *)
  val equal : t -> t -> bool
end
