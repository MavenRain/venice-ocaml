(* M17 hmacx: HMAC-SHA256 (RFC 2104 / FIPS 198-1) over the pinned sha2
   library, and the HKDF-SHA256 extract-and-expand of RFC 5869 built on
   it. The HMAC half is a port of jose-caml/lib/hmacx.ml; the HKDF half
   is new code written here (DESIGN.md section 4).

   Pure and sans-io, like limbsx.ml: no Bytes, no Buffer, no Array, no
   refs, no exceptions and no try-with. Every byte is emitted through
   Bytesx.of_codes and every window is cut through Bytesx.take, so no
   Char.chr, no String.sub and no String.get appears here. The unit
   holds NO division line at all: expand never computes a block count,
   it appends blocks until the accumulator is long enough.

   TIMING (DESIGN.md section 6, "Tag and MAC comparison is
   constant-time"): every branch below reads a LENGTH, never a key byte
   and never a data byte. The hashed-key branch reads the key length,
   the expand guards read len, and the block loop reads the length of
   the accumulator. The sha2 compression function is arithmetic with no
   data-dependent branch. equal_ct is the constant-time compare and
   verify is the only tag check a consumer should write. Nothing here
   is zeroized: OCaml strings are immutable and the M37 sweep owns
   that.

   ZxCaml trap 2 makes a top-level constant invisible inside a helper,
   so block_size and hash_len are unit functions and each pad mask is a
   literal inside the helper that uses it. *)

let block_size (() : unit) : int = 64
let hash_len (() : unit) : int = 32

(* RFC 2104 key conditioning. A key longer than one block is replaced
   by its digest first (the RFC 4231 cases 6 and 7 path), so the pad
   count below is already non-negative on both branches; Int.max keeps
   it total by construction whatever the branch. *)
let pad_key (key : string) : string =
  let k =
    match () with
    | () when String.length key > block_size () -> Sha2.Sha256.digest key
    | () -> key
  in
  k
  ^ Bytesx.of_codes
      (List.init (Int.max 0 (block_size () - String.length k))
         (fun (_ : int) -> 0))

(* The jose port maps Char.chr over the string; this tower has one byte
   emitter, so the XOR runs over the byte CODES and Bytesx.of_codes
   rebuilds the string. *)
let xor_with (mask : int) (s : string) : string =
  Bytesx.of_codes
    (List.map
       (fun (c : char) -> Char.code c lxor mask)
       (List.of_seq (String.to_seq s)))

let sha256 ~(key : string) (msg : string) : string =
  let k = pad_key key in
  Sha2.Sha256.digest
    (xor_with 0x5c k ^ Sha2.Sha256.digest (xor_with 0x36 k ^ msg))

(* Accumulate the OR of every byte difference; no early exit, so the
   running time does not depend on where the first difference sits. The
   length guard comes first because lengths are public, and Seq.zip
   alone stops at the shorter string, which would call "ab" and "abc"
   equal. *)
let equal_ct (a : string) (b : string) : bool =
  Int.equal (String.length a) (String.length b)
  && Int.equal
       (Seq.fold_left
          (fun acc (x, y) -> acc lor (Char.code x lxor Char.code y))
          0
          (Seq.zip (String.to_seq a) (String.to_seq b)))
       0

let verify ~(key : string) (msg : string) ~(tag : string) : bool =
  equal_ct (sha256 ~key msg) tag

(* HKDF-SHA256, RFC 5869. The pseudorandom key is ABSTRACT in the mli
   and is minted ONLY by extract, so expand cannot be handed raw keying
   material by mistake. derive is the M29 entry point: a raw ECDH
   shared secret goes through extract, never straight to expand. The
   timing stance of the unit header holds here too: extract and expand
   branch on lengths only. *)
module Hkdf = struct
  type prk = Prk of string

  (* RFC 5869 section 2.2. An empty salt IS the "HashLen zeros" default
     of the RFC, because HMAC zero-pads a short key to the block size,
     so no optional argument and no default value exists here. *)
  let extract ~(salt : string) ~(ikm : string) : prk =
    Prk (sha256 ~key:salt ikm)

  let prk_to_string (Prk s : prk) : string = s

  (* RFC 5869 section 2.3: 255 blocks of hash_len () bytes, 8160. *)
  let max_len (() : unit) : int = 255 * hash_len ()

  (* T(1) || T(2) || ... truncated to len bytes, with T(0) = "" and
     T(i) = sha256 ~key:prk (T(i-1) ^ info ^ byte i).

     The loop is bounded WITHOUT a division: each step appends
     hash_len () bytes and len is at most max_len () = 255 * hash_len (),
     so the accumulator reaches len after at most 255 steps and the
     counter byte stays inside 1 .. 255. Bytesx.take returns the option
     unchanged, so a None would surface as None and never be masked by
     a default. *)
  let expand (p : prk) ~(info : string) ~(len : int) : string option =
    let key = prk_to_string p in
    let rec go (i : int) (prev : string) (acc : string) : string =
      match () with
      | () when String.length acc >= len -> acc
      | () ->
        let t = sha256 ~key (prev ^ info ^ Bytesx.of_codes [ i ]) in
        go (i + 1) t (acc ^ t)
    in
    match () with
    | () when len < 0 -> None
    | () when len > max_len () -> None
    | () when Int.equal len 0 -> Some ""
    | () -> Bytesx.take (go 1 "" "") 0 len

  (* extract then expand, the one call the M29 session key schedule
     needs. *)
  let derive ~(salt : string) ~(ikm : string) ~(info : string) ~(len : int) :
      string option =
    expand (extract ~salt ~ikm) ~info ~len
end
