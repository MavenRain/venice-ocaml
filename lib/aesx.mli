(* M21 aesx: the FORWARD AES-256 block cipher of FIPS 197.  Internal
   unit: venice.mli does not re-export it, and the column record, the
   round steps and the key schedule stay inside the implementation.
   gcmx (M21) is the only reader today;  M30 and M32 reach gcmx and
   never this unit directly.  Every rejection is an option, so this
   unit adds no Errx constructor.

   The unit is the FORWARD cipher ONLY.  There is no decrypt_block, no
   InvSubBytes, no InvMixColumns and no inverse schedule, because GCM
   runs the forward cipher for both seal and unseal.  AES-128 and
   AES-192 are out of scope, so key_of_bytes accepts 32 bytes alone.

   The identities the implementation relies on, all of FIPS 197: the
   state is filled COLUMN-MAJOR, so input byte 4c + r is s[r][c]
   (section 3.4);  SubBytes is the GF(2^8) inverse under the modulus
   whose reduction byte is 0x1b with 0 mapped to 0, then the affine map
   b ^ rotl8(b,1) ^ rotl8(b,2) ^ rotl8(b,3) ^ rotl8(b,4) ^ 0x63
   (section 5.1.1);  ShiftRows rotates row r left by r (section 5.1.2);
   MixColumns is the (2 3 1 1) circulant (section 5.1.3);  the Nk = 8
   schedule applies SubWord(RotWord(w)) and the Rcon xor at i mod 8 = 0
   and SubWord alone at i mod 8 = 4 (section 5.2);  and Nr = 14, so
   thirteen middle rounds run with MixColumns and the last round runs
   without it.

   The S-box is COMPUTED on every call and is never a table: no
   secret-indexed memory access and no secret-dependent branch in the
   S-box, MixColumns, the key schedule or GHASH;  residual: the OCaml
   native compiler, the allocator and the * operator are not
   constant-time by contract, M39. *)

(* The AES block size in bytes, 16.  A unit function, because ZxCaml
   trap 2 makes a top-level constant invisible inside a helper. *)
val block_len : unit -> int

(* The AES-256 key size in bytes, 32. *)
val key_len : unit -> int

(* The FIPS 197 S-box, computed through the GF(2^8) inverse and the
   affine map.  TOTAL on every int: the argument is masked with 0xff
   first, so sbox 0x1ff and sbox (-1) both equal sbox 0xff.  Exported
   so the suite and the oracle can pin it. *)
val sbox : int -> int

(* The expanded AES-256 schedule.  ABSTRACT: it is a SECRET, so it
   carries no to_bytes, no equal and no show, and it leaves this unit
   only as a cipher argument. *)
type key

(* The expanded schedule of EXACTLY 32 key bytes.  None on 16 bytes, on
   24 bytes and on every other length, because this unit is AES-256
   alone. *)
val key_of_bytes : string -> key option

(* The forward cipher on ONE block.  Some 16 bytes when the input is
   exactly 16 bytes, None on every other length. *)
val encrypt_block : key -> string -> string option
