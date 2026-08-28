(* venice-ocaml: typed Venice.ai SDK.

   The signature below is the whole public API. M3 exposes the codec
   floor: the seed error type, total byte cursors, strict hex, and
   strict base64 in both wire alphabets. *)

val version : string

module Error : sig
  type t =
    | Hex_invalid of string
    | B64_invalid of string

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
