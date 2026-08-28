(* Shared byte helpers and total cursor readers. No Char.chr and no
   partial indexing anywhere: emission goes through a 256-byte table
   with a masked total lookup, and every reader returns None when any
   byte of its window falls outside the buffer.
   ZxCaml trap 2 makes top-level constants invisible inside helpers, so
   the table is a unit function and each entrypoint binds its lookup
   map locally. *)

let byte_table (() : unit) : string =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  ^ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
  ^ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
  ^ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  ^ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
  ^ "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
  ^ "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
  ^ "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
  ^ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
  ^ "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  ^ "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
  ^ "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
  ^ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
  ^ "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
  ^ "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
  ^ "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

module Imap = Map.Make (Int)

(* Total: the index is masked to [0, 255], so the lookup always hits.
   A Map keeps the accessor total without the O(n) list scan per byte. *)
let chr_in (m : char Imap.t) (i : int) : char =
  Option.value (Imap.find_opt (i land 255) m) ~default:'\x00'

let of_codes (codes : int list) : string =
  let m =
    Seq.fold_left
      (fun m (i, c) -> Imap.add i c m)
      Imap.empty
      (String.to_seqi (byte_table ()))
  in
  String.of_seq (List.to_seq (List.map (chr_in m) codes))

(* Total substring: None unless the whole window [off, off + len) sits
   inside the buffer. Seq.take and Seq.drop reject negative arguments,
   so the sign guards come first. *)
let take (s : string) (off : int) (len : int) : string option =
  if off < 0 || len < 0 || off > String.length s then None
  else
    let sub = String.of_seq (Seq.take len (Seq.drop off (String.to_seq s))) in
    if Int.equal (String.length sub) len then Some sub else None

let u8 (s : string) (off : int) : int option =
  if off < 0 then None
  else
    Option.map
      (fun ((c : char), (_ : char Seq.t)) -> Char.code c)
      (Seq.uncons (Seq.drop off (String.to_seq s)))

(* Little-endian recombination of a full window minted by take. *)
let le_int (window : string) : int =
  Seq.fold_left
    (fun acc (i, c) -> acc lor (Char.code c lsl (8 * i)))
    0 (String.to_seqi window)

let u16le (s : string) (off : int) : int option =
  Option.map le_int (take s off 2)

let u32le (s : string) (off : int) : int option =
  Option.map le_int (take s off 4)

(* u64 stays lossless: an OCaml int holds 63 bits, so the top byte of a
   wire u64 (td_attributes, xfam) would silently truncate. Int64 keeps
   every bit. *)
let le_int64 (window : string) : int64 =
  Seq.fold_left
    (fun acc (i, c) ->
      Int64.logor acc (Int64.shift_left (Int64.of_int (Char.code c)) (8 * i)))
    0L (String.to_seqi window)

let u64le (s : string) (off : int) : int64 option =
  Option.map le_int64 (take s off 8)
