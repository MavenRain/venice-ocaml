(* venice-ocaml: typed Venice.ai SDK.

   The signature below is the whole public API. M3 exposes the codec
   floor: the seed error type, total byte cursors, strict hex, and
   strict base64 in both wire alphabets. *)

val version : string

module Error : sig
  type t =
    | Hex_invalid of string
    | B64_invalid of string
    | Json_invalid of string

  val to_string : t -> string
end

module Cursor : sig
  (* Total byte readers. Every reader returns None when any byte of its
     window falls outside the buffer. Offsets count from zero. u64 is
     Int64 so no wire bit truncates into a 63-bit int. *)
  val take : string -> int -> int -> string option
  val u8 : string -> int -> int option
  val u16le : string -> int -> int option
  val u32le : string -> int -> int option
  val u64le : string -> int -> int64 option
end

module Hex : sig
  (* Strict hex: decode rejects foreign bytes and odd length, and
     accepts both letter cases. Encode emits lowercase. *)
  val encode : string -> string
  val decode : string -> (string, Error.t) result
end

module B64 : sig
  (* Strict base64. url: no padding, canonical trailing bits, length
     mod 4 <> 1. std: mandatory canonical '=' padding over the same
     core. Foreign bytes reject in both. *)
  val encode_url : string -> string
  val decode_url : string -> (string, Error.t) result
  val encode_std : string -> string
  val decode_std : string -> (string, Error.t) result
end

module Json : sig
  (* Strict minimal JSON. Numbers are exact: canonical integers parse
     to Jint (18-digit cap, no leading zeros); fraction forms parse to
     Jdec as sign/mantissa/scale ints, where the value is
     (-1)^negative * mantissa / 10^scale and scale counts the fraction
     digits as written, so "1.50" round-trips byte-exact. No float
     crosses this boundary and exponents reject. Depth cap 32, object
     width cap 4096 members, array width cap 65536 items, duplicate
     keys reject at every depth, raw control characters reject in
     strings. \u escapes cover all of Unicode: each escape is a 16-bit
     code unit, a high/low surrogate pair combines into one code point
     and the result is emitted as UTF-8, and a lone surrogate (high
     with no valid low escape after it, or a bare low) rejects. *)
  type dec = { negative : bool; mantissa : int; scale : int }

  type t =
    | Jnull
    | Jbool of bool
    | Jint of int
    | Jdec of dec
    | Jstring of string
    | Jlist of t list
    | Jobj of (string * t) list

  val emit : t -> string
  val parse : string -> (t, Error.t) result
  val member : string -> t -> t option
  val as_string : t -> string option
  val as_int : t -> int option
  val as_bool : t -> bool option
  val as_list : t -> t list option
  val as_obj : t -> (string * t) list option

  (* Numeric view: a Jint reads as a scale-zero dec, so one case
     consumes any wire number. None for Jint min_int: that magnitude
     is not representable as a non-negative mantissa. *)
  val as_dec : t -> dec option
end
