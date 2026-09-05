(* M21 gcmx: AES-256-GCM of SP 800-38D, seal and unseal, over the
   forward AES-256 of aesx.  The name is unseal because open is an
   OCaml keyword.  M30 seals one chunk per request and M32 unseals one
   chunk per response, each chunk carrying its own nonce and tag, so
   there is no streaming and no incremental API here.  Every rejection
   is an option, so this unit adds no Errx constructor.

   Pure and sans-io, like aesx.ml and hmacx.ml: no Bytes, no Buffer, no
   Array, no ref, no exception and no try-with.  Every window is cut
   through Bytesx.take and every byte is emitted through
   Bytesx.of_codes, and the unit holds no division line and no mod
   line: the block fill is a counter the fold tests with Int.equal, as
   keccakx.ml:223-233 does, and never a quotient.  Every shift amount
   is a LITERAL, which keccakx.ml:66-72 requires for Int64 because a
   shift of 0 or of 64 is unspecified.

   GHASH.  A field element is the two big-endian halves of a 16-byte
   block in a RECORD, fe, read through be64 over Bytesx.take windows at
   the offsets 0 and 8.  be64 is local, because bytesx carries
   little-endian readers only and both of those shift by the computed
   amount 8 * i.  H is E_K of 16 zero bytes.  Multiplication is
   Algorithm 1 of SP 800-38D driven from the most significant bit of
   byte 0: ONE fold of exactly 128 masked steps, so no branch reads a
   key bit or a data bit.  The GHASH input is the AAD zero-padded, then
   the ciphertext zero-padded, then the lengths block in BITS, and the
   lengths block is ALWAYS absorbed.  A partial final block is emitted
   only when the fill is not zero: an all-zero block is NOT neutral in
   GHASH, because absorbing it multiplies the accumulator by H.

   CTR.  With the 12-byte nonce, J0 is the nonce with the counter 1,
   and the keystream block for plaintext block i, 0-based, is E_K of
   the nonce with the counter 2 + i.  The counter never exceeds
   2^32 - 1 under max_len, so it never wraps.  The tag is
   GHASH_H(aad, ct) lxor E_K(J0), sixteen bytes.

   TIMING (DESIGN.md section 2, "Tag compare leak").  unseal computes
   the tag over the OFFERED ciphertext FIRST and compares it through
   Hmacx.equal_ct, which folds the OR of every byte difference with no
   early exit;  the CTR pass runs ONLY under a matching tag, so no
   plaintext byte is ever produced under a mismatch.  The posture of
   aesx holds here too: no secret-indexed memory access and no
   secret-dependent branch in the S-box, MixColumns, the key schedule
   or GHASH;  residual: the OCaml native compiler, the allocator and
   the * operator are not constant-time by contract, M39.

   NONCE.  Uniqueness per key is the CALLER's obligation, M30's Fresh.t
   under model spec P3 (DESIGN.md:56).  This unit cannot check it.

   ZxCaml trap 2 makes a top-level constant invisible inside a helper
   and fires ACROSS modules, so every constant here is a unit function
   or a literal at its use site, and NO top-level alias of a Bytesx, a
   Hmacx or an Aesx value is written: Tag.equal_ct is eta-expanded over
   Hmacx.equal_ct and never bound to it. *)

let key_len (() : unit) : int = 32
let nonce_len (() : unit) : int = 12
let tag_len (() : unit) : int = 16

(* The SP 800-38D section 5.2.1.1 plaintext and ciphertext cap,
   (2^32 - 2) * 16 bytes.  The last permitted block runs under the
   counter 2 + (2^32 - 3) = 4294967295, so the 32-bit counter reaches
   its maximum and never wraps below the cap.  The AAD is uncapped
   here, because its 2^61-byte bound is unreachable on this host. *)
let max_len (() : unit) : int = 68719476704

(* One GHASH block: the two big-endian halves.  hi and lo are read by
   gmul, by fe_xor and by codes_of_fe. *)
type fe = { hi : int64;  lo : int64 }

let fe_zero (() : unit) : fe = { hi = 0L;  lo = 0L }

(* R of SP 800-38D section 6.3, the reduction polynomial. *)
let reduction (() : unit) : fe = { hi = 0xe100000000000000L;  lo = 0L }

let zero_block (() : unit) : string =
  Bytesx.of_codes (List.init 16 (fun (_ : int) -> 0))

(* Big-endian recombination of an 8-byte window minted by Bytesx.take.
   The accumulator shifts by the LITERAL 8, so this reader is NOT the
   mirror of Bytesx.le_int64, which shifts by the computed 8 * i. *)
let be64 (w : string) : int64 =
  Seq.fold_left
    (fun (acc : int64) (c : char) ->
      Int64.logor (Int64.shift_left acc 8) (Int64.of_int (Char.code c)))
    0L (String.to_seq w)

let fe_of_block (b : string) : fe option =
  Option.bind (Bytesx.take b 0 8) (fun (top : string) ->
      Option.map
        (fun (bot : string) -> { hi = be64 top;  lo = be64 bot })
        (Bytesx.take b 8 8))

let fe_xor (a : fe) (b : fe) : fe =
  { hi = Int64.logxor a.hi b.hi;  lo = Int64.logxor a.lo b.lo }

(* One shift right over the 128-bit pair: the low bit of hi moves into
   the top of lo.  Both amounts are literals inside 0..63. *)
let shr1 (v : fe) : fe =
  { hi = Int64.shift_right_logical v.hi 1;
    lo =
      Int64.logor
        (Int64.shift_right_logical v.lo 1)
        (Int64.shift_left v.hi 63) }

(* One shift left over the 128-bit pair: the top bit of lo moves into
   the low bit of hi. *)
let shl1 (v : fe) : fe =
  { hi =
      Int64.logor (Int64.shift_left v.hi 1)
        (Int64.shift_right_logical v.lo 63);
    lo = Int64.shift_left v.lo 1 }

(* Algorithm 1 of SP 800-38D as ONE fold of exactly 128 masked steps.
   The element of the list is ignored: every step reads the top bit of
   the CARRIED x with the literal 63 and shifts x left by the literal
   1, so no shift amount is ever taken off the list.  Int64.neg 0L is
   0L and Int64.neg 1L is 0xffffffffffffffffL, so each mask is a full
   0 or a full 1 and no branch reads a bit of either operand. *)
let gmul (data : fe) (h : fe) : fe =
  let step ((z : fe), (v : fe), (x : fe)) (_ : int) =
    let mask_x = Int64.neg (Int64.shift_right_logical x.hi 63) in
    let z' =
      { hi = Int64.logxor z.hi (Int64.logand v.hi mask_x);
        lo = Int64.logxor z.lo (Int64.logand v.lo mask_x) }
    in
    let mask_lsb = Int64.neg (Int64.logand v.lo 1L) in
    let vs = shr1 v in
    let r = reduction () in
    let v' =
      { hi = Int64.logxor vs.hi (Int64.logand r.hi mask_lsb);
        lo = Int64.logxor vs.lo (Int64.logand r.lo mask_lsb) }
    in
    (z', v', shl1 x)
  in
  let ((z : fe), (_ : fe), (_ : fe)) =
    List.fold_left step
      (fe_zero (), h, data)
      (List.init 128 (fun (i : int) -> i))
  in
  z

(* The blocking fold of keccakx.ml:223-233: the fill is a counter the
   step tests with Int.equal, so no quotient and no remainder appears.
   The final partial block is emitted ONLY when the fill is not zero,
   because an all-zero block is not neutral in GHASH;  the guard reads
   a LENGTH and never a data byte, and the fill sits in 1..15 there
   because the fold flushed at 16. *)
let blocks_of (s : string) : string list =
  let step ((fill : int), (codes : int list), (acc : string list)) (c : char) =
    let codes' = Char.code c :: codes in
    if Int.equal (fill + 1) 16 then
      (0, [], Bytesx.of_codes (List.rev codes') :: acc)
    else (fill + 1, codes', acc)
  in
  let ((fill : int), (codes : int list), (acc : string list)) =
    Seq.fold_left step (0, [], []) (String.to_seq s)
  in
  List.rev
    (if Int.equal fill 0 then acc
     else
       Bytesx.of_codes
         (List.rev codes @ List.init (16 - fill) (fun (_ : int) -> 0))
       :: acc)

(* GHASH_H over the AAD zero-padded, then the ciphertext zero-padded,
   then the lengths block in BITS.  The lengths block is ALWAYS
   absorbed, even when both inputs are empty: a mutant that drops it
   leaves the tag of GCM case 13 unchanged, and the rows that kill such
   a mutant are case 14 and every Wycheproof row with a non-empty
   AAD. *)
let ghash (h : fe) (aad : string) (ct : string) : fe option =
  let absorb (acc : fe option) (blk : string) : fe option =
    Option.bind acc (fun (y : fe) ->
        Option.map (fun (b : fe) -> gmul (fe_xor y b) h) (fe_of_block blk))
  in
  let lens =
    { hi = Int64.of_int (8 * String.length aad);
      lo = Int64.of_int (8 * String.length ct) }
  in
  Option.map
    (fun (y : fe) -> gmul (fe_xor y lens) h)
    (List.fold_left absorb
       (Some (fe_zero ()))
       (blocks_of aad @ blocks_of ct))

(* The tag emission runs big-endian with the literal amounts 56, 48,
   40, 32, 24, 16 and 8, and the low byte is read by a mask alone, so
   no Int64 shift of 0 is written. *)
let codes_of_fe (v : fe) : int list =
  [ Int64.to_int (Int64.logand (Int64.shift_right_logical v.hi 56) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.hi 48) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.hi 40) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.hi 32) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.hi 24) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.hi 16) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.hi 8) 0xffL);
    Int64.to_int (Int64.logand v.hi 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.lo 56) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.lo 48) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.lo 40) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.lo 32) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.lo 24) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.lo 16) 0xffL);
    Int64.to_int (Int64.logand (Int64.shift_right_logical v.lo 8) 0xffL);
    Int64.to_int (Int64.logand v.lo 0xffL) ]

(* The nonce with a 32-bit counter, emitted from the LITERAL shifts 24,
   16, 8 and 0.  J0 carries the counter 1 and the first data block
   carries the counter 2. *)
let counter_block (nonce : string) (n : int) : string =
  nonce
  ^ Bytesx.of_codes
      [ (n lsr 24) land 0xff;  (n lsr 16) land 0xff;  (n lsr 8) land 0xff;
        n land 0xff ]

let xor_bytes (a : string) (b : string) : string =
  Bytesx.of_codes
    (List.of_seq
       (Seq.map
          (fun ((x : char), (y : char)) -> Char.code x lxor Char.code y)
          (Seq.zip (String.to_seq a) (String.to_seq b))))

(* The CTR pass, which serves seal and unseal alike because GCM runs
   the FORWARD cipher both ways.  The fold carries the block index, the
   remaining keystream codes of the current block and the output codes,
   and it refills the keystream when the remaining list is empty.  The
   return type is an option and NOT a string, because Aesx.encrypt_block
   is partial: collapsing it with a default would return the empty
   string under a VALID tag, which is a wrong plaintext.  The match on
   the REMAINING codes is a two-arm total match with no default.  The
   [] arm of the match on a FRESHLY minted keystream block is the ONE
   default arm of this unit and it is UNREACHABLE: encrypt_block
   returns exactly 16 bytes or None, so a minted block is never
   empty. *)
let ctr_pass (k : Aesx.key) (nonce : string) (s : string) : string option =
  let step (acc : (int * int list * int list) option) (c : char) =
    Option.bind acc (fun ((i : int), (ks : int list), (out : int list)) ->
        match ks with
        | k0 :: rest -> Some (i, rest, (Char.code c lxor k0) :: out)
        | [] ->
            Option.bind
              (Aesx.encrypt_block k (counter_block nonce (2 + i)))
              (fun (blk : string) ->
                match List.map Char.code (List.of_seq (String.to_seq blk)) with
                | k0 :: rest -> Some (i + 1, rest, (Char.code c lxor k0) :: out)
                | [] -> None))
  in
  Option.map
    (fun ((_ : int), (_ : int list), (out : int list)) ->
      Bytesx.of_codes (List.rev out))
    (Seq.fold_left step (Some (0, [], [])) (String.to_seq s))

module Key = struct
  (* The expanded AES schedule and H, both computed ONCE at
     construction.  sched is read by seal, by unseal and by tag_of, and
     h is read by tag_of. *)
  type t = { sched : Aesx.key;  h : fe }

  let of_bytes (s : string) : t option =
    if Int.equal (String.length s) (key_len ()) then
      Option.bind (Aesx.key_of_bytes s) (fun (sched : Aesx.key) ->
          Option.bind (Aesx.encrypt_block sched (zero_block ()))
            (fun (b : string) ->
              Option.map (fun (h : fe) -> { sched;  h }) (fe_of_block b)))
    else None
end

module Nonce = struct
  (* raw is read by to_bytes. *)
  type t = { raw : string }

  let of_bytes (s : string) : t option =
    if Int.equal (String.length s) (nonce_len ()) then Some { raw = s }
    else None

  let to_bytes (n : t) : string = n.raw
end

module Tag = struct
  (* raw is read by to_bytes and by equal_ct. *)
  type t = { raw : string }

  let of_bytes (s : string) : t option =
    if Int.equal (String.length s) (tag_len ()) then Some { raw = s } else None

  let to_bytes (t : t) : string = t.raw

  (* ETA-EXPANDED over Hmacx.equal_ct and never bound to it: a
     top-level alias is a constant under ZxCaml trap 2, and the trap
     fires cross-module by NAME. *)
  let equal_ct (a : t) (b : t) : bool = Hmacx.equal_ct a.raw b.raw
end

(* GHASH_H(aad, ct) lxor E_K(J0). *)
let tag_of (k : Key.t) (nonce : string) (aad : string) (ct : string) :
    Tag.t option =
  Option.bind (ghash k.Key.h aad ct) (fun (y : fe) ->
      Option.bind
        (Aesx.encrypt_block k.Key.sched (counter_block nonce 1))
        (fun (ekj0 : string) ->
          Tag.of_bytes (xor_bytes (Bytesx.of_codes (codes_of_fe y)) ekj0)))

(* The ciphertext first, then the tag over the ciphertext just made.
   An empty plaintext IS GMAC and needs no separate surface. *)
let seal (k : Key.t) (nonce : Nonce.t) ~(aad : string) (msg : string) :
    (string * Tag.t) option =
  if String.length msg > max_len () then None
  else
    Option.bind
      (ctr_pass k.Key.sched (Nonce.to_bytes nonce) msg)
      (fun (ct : string) ->
        Option.map
          (fun (t : Tag.t) -> (ct, t))
          (tag_of k (Nonce.to_bytes nonce) aad ct))

(* The tag over the OFFERED ciphertext FIRST, the constant-time compare
   next, and the CTR pass ONLY under a matching tag. *)
let unseal (k : Key.t) (nonce : Nonce.t) ~(aad : string) (ct : string)
    (tag : Tag.t) : string option =
  if String.length ct > max_len () then None
  else
    Option.bind (tag_of k (Nonce.to_bytes nonce) aad ct) (fun (t : Tag.t) ->
        if Tag.equal_ct t tag then
          ctr_pass k.Key.sched (Nonce.to_bytes nonce) ct
        else None)
