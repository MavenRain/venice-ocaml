(* The canonical 16-bit-limb bignum. Internal unit: venice.mli does
   not re-export it, and the private helpers (trim, pad_to, carry_norm,
   add_lists, sub_limbs, shift_limbs, mul_limbs, div_pos) stay inside
   the implementation. Every rejection is an option; this unit adds no
   Errx constructor. *)

(* A number in base 2^16, least significant limb first. ABSTRACT, so
   the invariant holds by construction: every limb sits in 0 .. 0xffff,
   there is no most significant zero limb, and zero is the empty limb
   list. Every function below returns a canonical value. *)
type t

(* The operand cap in bytes, 1024 (8192 bits). It bounds every public
   constructor, so no caller can hand the schoolbook multiply an
   unbounded operand. *)
val max_bytes : unit -> int

val zero : t
val one : t

(* None below zero. *)
val of_int : int -> t option

(* None when any limb falls outside 0 .. 0xffff, and None when the
   list holds more than max_bytes () / 2 limbs BEFORE trimming, so an
   oversized list is rejected instead of trimming away to a small
   value. Most significant zero limbs are trimmed, not rejected. *)
val of_limbs : int list -> t option

(* The canonical limbs, least significant first. *)
val to_limbs : t -> int list

(* Big-endian bytes; leading zero bytes fold away. None above
   max_bytes () bytes. *)
val of_be_string : string -> t option

(* Exactly len big-endian bytes, zero-padded on the left. None when
   the value needs more than len bytes, when len is negative, and when
   len is above max_bytes (), so the padding never allocates past the
   cap. len 0 with zero gives Some "". *)
val to_be_string : len:int -> t -> string option

(* Hexx.decode then of_be_string, so a byte outside the alphabet or an
   odd length is None, never a silent zero. Both letter cases are
   accepted, exactly as Hexx.decode accepts them. *)
val of_hex : string -> t option

val add : t -> t -> t

(* None when the first operand is smaller; Some zero when they are
   equal. *)
val sub : t -> t -> t option

val mul : t -> t -> t

(* Negative, zero or positive, as numbers. *)
val cmp : t -> t -> int

val equal : t -> t -> bool
val is_zero : t -> bool
val num_limbs : t -> int

(* LSB-first bits, exactly 16 per limb, so the list length is
   16 * num_limbs. Zero gives the empty list. *)
val bits : t -> int list

(* The canonical residue. None when m is zero. VARIABLE-TIME: the
   quotient-estimate loop branches on limb values, so this is for
   public inputs only unless the caller's ladder is fixed-shape. *)
val mod_red : m:t -> t -> t option

(* base then exponent. None when m is zero; Some zero when m is one;
   an exponent of zero gives one reduced by m, for every base.
   VARIABLE-TIME: square-and-multiply branches on the exponent bits
   and reduces through mod_red, so this is for public inputs only
   unless the caller's ladder is fixed-shape. *)
val mod_pow : m:t -> t -> t -> t option
