(* M18 keccakx: keccak-256 (the original Keccak padding, domain byte
   0x01, which is what Ethereum hashes with), the SHA3-256 of FIPS 202
   (domain byte 0x06) as a permutation witness, and the Ethereum address
   projection with its EIP-55 checksum. New crypto written here
   (DESIGN.md section 4), not a port.

   Pure and sans-io, like limbsx.ml and hmacx.ml: no Bytes, no Buffer,
   no Array, no refs, no exceptions and no exception handler. Every byte
   is emitted through Bytesx.of_codes and every window is cut through
   Bytesx.take, so no partial character builder and no partial substring
   reader appears here. The unit holds NO division line and no remainder:
   the sponge tracks the fill of the current block inside the fold over
   the input, so a block boundary is an equality test on a counter and
   never a quotient of the input length.

   A lane is an int64 (the bytesx precedent at lib/bytesx.ml:71-81) and
   the 25 lanes live in named record FIELDS, five lanes to a row and
   five rows to a state, so every lane access is a field name: no array,
   no list index and no index arithmetic addresses a lane. rotl is
   called only with literal offsets in 1 .. 63, because Int64.shift_left
   and Int64.shift_right_logical are unspecified for a shift of 0 or 64;
   lane (0, 0) carries the rho offset 0 and is copied, never rotated.
   The squeeze shifts right by 0, 8, .., 56, and a shift by 0 is
   specified.

   TIMING (DESIGN.md section 6): nothing secret enters this unit, so the
   section 2 table gains no row. keccak-f has no data-dependent branch
   at all (the rotations are by literal offsets, chi is boolean and iota
   is a constant XOR), and the sponge branches only on the fill COUNT of
   the current block, which is a length. The address half is covered by
   the Address header below.

   ZxCaml trap 2 makes a top-level constant invisible inside a helper,
   so rate, hash_len and round_constants are unit functions. *)

let rate (() : unit) : int = 136
let hash_len (() : unit) : int = 32

(* The 24 FIPS 202 round constants, section 3.2.5, in round order. They
   are the LFSR output; harness/diff_keccak.py GENERATES them from that
   LFSR instead of pasting them, so the two sides share no table. *)
let round_constants (() : unit) : int64 list =
  [ 0x0000000000000001L; 0x0000000000008082L; 0x800000000000808aL;
    0x8000000080008000L; 0x000000000000808bL; 0x0000000080000001L;
    0x8000000080008081L; 0x8000000000008009L; 0x000000000000008aL;
    0x0000000000000088L; 0x0000000080008009L; 0x000000008000000aL;
    0x000000008000808bL; 0x800000000000008bL; 0x8000000000008089L;
    0x8000000000008003L; 0x8000000000008002L; 0x8000000000000080L;
    0x000000000000800aL; 0x800000008000000aL; 0x8000000080008081L;
    0x8000000000008080L; 0x0000000080000001L; 0x8000000080008008L ]

(* Lane (x, y) is field cx of field yy. The linear lane index of the
   sponge is x + 5 * y, so the 17 absorbed lanes of a 136-byte block are
   y0, y1, y2 and then c0 and c1 of y3. Neither type leaves the unit. *)
type row = { c0 : int64; c1 : int64; c2 : int64; c3 : int64; c4 : int64 }

type state = { y0 : row; y1 : row; y2 : row; y3 : row; y4 : row }

let zero_row (() : unit) : row =
  { c0 = 0L; c1 = 0L; c2 = 0L; c3 = 0L; c4 = 0L }

let zero_state (() : unit) : state =
  { y0 = zero_row (); y1 = zero_row (); y2 = zero_row (); y3 = zero_row ();
    y4 = zero_row () }

(* CONTRACT: 1 <= n <= 63. Int64.shift_left and
   Int64.shift_right_logical are unspecified for a shift of 0 or of 64,
   so a rotation by either would be undefined; every call site below
   passes a LITERAL in that range and lane (0, 0), whose rho offset is
   0, is copied instead. The contract is a comment and not a guard on
   purpose: a guard would answer a programming error with a wrong lane
   and hide it, while a literal is audited by reading the call sites. *)
let rotl (x : int64) (n : int) : int64 =
  Int64.logor (Int64.shift_left x n) (Int64.shift_right_logical x (64 - n))

let xor_row (a : row) (b : row) : row =
  { c0 = Int64.logxor a.c0 b.c0;
    c1 = Int64.logxor a.c1 b.c1;
    c2 = Int64.logxor a.c2 b.c2;
    c3 = Int64.logxor a.c3 b.c3;
    c4 = Int64.logxor a.c4 b.c4 }

(* FIPS 202 3.2.1. The column parity row is the fieldwise XOR of the
   five rows, and d.cx is c.c(x-1) XOR rotl c.c(x+1) 1, written out. *)
let theta (st : state) : state =
  let c = xor_row (xor_row (xor_row (xor_row st.y0 st.y1) st.y2) st.y3) st.y4 in
  let d =
    { c0 = Int64.logxor c.c4 (rotl c.c1 1);
      c1 = Int64.logxor c.c0 (rotl c.c2 1);
      c2 = Int64.logxor c.c1 (rotl c.c3 1);
      c3 = Int64.logxor c.c2 (rotl c.c4 1);
      c4 = Int64.logxor c.c3 (rotl c.c0 1) }
  in
  { y0 = xor_row st.y0 d;
    y1 = xor_row st.y1 d;
    y2 = xor_row st.y2 d;
    y3 = xor_row st.y3 d;
    y4 = xor_row st.y4 d }

(* FIPS 202 3.2.2 and 3.2.3 in one record literal of 25 field
   expressions: lane (x, y), that is field cx of row yy, moves to field
   c_y of row y_((2x + 3y) reduced modulo 5) carrying rotl A[x][y]
   r[x][y]. The FIRST index below is the field c and the SECOND the row
   y. The 24 offsets come from the recurrence (x, y) <- (y, (2x + 3y)
   reduced modulo 5) with offset (t + 1) (t + 2) halved and taken
   modulo 64 from (1, 0); the oracle generates
   the same recurrence, and one wrong offset changes every digest. Lane
   (0, 0) has offset 0 and is copied. *)
let rho_pi (a : state) : state =
  { y0 =
      { c0 = a.y0.c0;
        c1 = rotl a.y1.c1 44;
        c2 = rotl a.y2.c2 43;
        c3 = rotl a.y3.c3 21;
        c4 = rotl a.y4.c4 14 };
    y1 =
      { c0 = rotl a.y0.c3 28;
        c1 = rotl a.y1.c4 20;
        c2 = rotl a.y2.c0 3;
        c3 = rotl a.y3.c1 45;
        c4 = rotl a.y4.c2 61 };
    y2 =
      { c0 = rotl a.y0.c1 1;
        c1 = rotl a.y1.c2 6;
        c2 = rotl a.y2.c3 25;
        c3 = rotl a.y3.c4 8;
        c4 = rotl a.y4.c0 18 };
    y3 =
      { c0 = rotl a.y0.c4 27;
        c1 = rotl a.y1.c0 36;
        c2 = rotl a.y2.c1 10;
        c3 = rotl a.y3.c2 15;
        c4 = rotl a.y4.c3 56 };
    y4 =
      { c0 = rotl a.y0.c2 62;
        c1 = rotl a.y1.c3 55;
        c2 = rotl a.y2.c4 39;
        c3 = rotl a.y3.c0 41;
        c4 = rotl a.y4.c1 2 } }

(* FIPS 202 3.2.4, per row: c(x) becomes c(x) XOR (NOT c(x+1) AND
   c(x+2)), the indices cyclic in the row. *)
let chi_row (r : row) : row =
  { c0 = Int64.logxor r.c0 (Int64.logand (Int64.lognot r.c1) r.c2);
    c1 = Int64.logxor r.c1 (Int64.logand (Int64.lognot r.c2) r.c3);
    c2 = Int64.logxor r.c2 (Int64.logand (Int64.lognot r.c3) r.c4);
    c3 = Int64.logxor r.c3 (Int64.logand (Int64.lognot r.c4) r.c0);
    c4 = Int64.logxor r.c4 (Int64.logand (Int64.lognot r.c0) r.c1) }

let chi (st : state) : state =
  { y0 = chi_row st.y0;
    y1 = chi_row st.y1;
    y2 = chi_row st.y2;
    y3 = chi_row st.y3;
    y4 = chi_row st.y4 }

(* FIPS 202 3.2.5: the round constant meets lane (0, 0) alone. *)
let iota (st : state) (rc : int64) : state =
  { st with y0 = { st.y0 with c0 = Int64.logxor st.y0.c0 rc } }

(* keccak-p[1600, 24]. The round count is the LENGTH of the constant
   list, so no counter and no index appears: dropping a constant drops a
   round. *)
let keccak_f (st : state) : state =
  List.fold_left
    (fun (st : state) (rc : int64) -> iota (chi (rho_pi (theta st))) rc)
    st (round_constants ())

(* The padding domain, a closed sum and never a bare byte flag: Keccak
   is the ORIGINAL multi-rate pad that Ethereum hashes with, Sha3 is the
   FIPS 202 pad. The two differ only in this byte. *)
type domain = Keccak | Sha3

let domain_byte (d : domain) : int =
  match d with Keccak -> 0x01 | Sha3 -> 0x06

(* Up to eight codes off the front of the list, little-endian, and the
   rest of the list. A short list yields the partial lane and [], which
   is what the last lane of a padded block needs; the recursion is
   structural on the list and bounded by the counter, and the shift
   never leaves 0 .. 56. *)
let rec lane_go (n : int) (shift : int) (acc : int64) (codes : int list) :
    int64 * int list =
  match codes with
  | [] -> (acc, [])
  | c :: rest ->
      if n <= 0 then (acc, codes)
      else
        lane_go (n - 1) (shift + 8)
          (Int64.logor acc
             (Int64.shift_left (Int64.of_int (c land 0xff)) shift))
          rest

let lane8 (codes : int list) : int64 * int list = lane_go 8 0 0L codes

let row5 (codes : int list) : row * int list =
  let c0, r0 = lane8 codes in
  let c1, r1 = lane8 r0 in
  let c2, r2 = lane8 r1 in
  let c3, r3 = lane8 r2 in
  let c4, r4 = lane8 r3 in
  ({ c0; c1; c2; c3; c4 }, r4)

(* One 136-byte block: seventeen lanes through three row5 calls and two
   lane8 calls, XORed into lanes 0 .. 16 fieldwise, then the
   permutation. No 17-element list pattern and no catch-all arm. *)
let absorb_block (st : state) (codes : int list) : state =
  let r0, rest0 = row5 codes in
  let r1, rest1 = row5 rest0 in
  let r2, rest2 = row5 rest1 in
  let l15, rest3 = lane8 rest2 in
  let l16, (_ : int list) = lane8 rest3 in
  keccak_f
    { y0 = xor_row st.y0 r0;
      y1 = xor_row st.y1 r1;
      y2 = xor_row st.y2 r2;
      y3 =
        { st.y3 with
          c0 = Int64.logxor st.y3.c0 l15;
          c1 = Int64.logxor st.y3.c1 l16 };
      y4 = st.y4 }

(* blk holds the codes of the current block in REVERSE and fill counts
   them, so a full block flushes the moment fill reaches rate () and
   fill is in 0 .. rate () - 1 at finalize by construction. *)
type acc = { st : state; blk : int list; fill : int }

let push (a : acc) (ch : char) : acc =
  let blk = Char.code ch :: a.blk in
  let fill = a.fill + 1 in
  if Int.equal fill (rate ()) then
    { st = absorb_block a.st (List.rev blk); blk = []; fill = 0 }
  else { st = a.st; blk; fill }

let absorb (s : string) : acc =
  Seq.fold_left push
    { st = zero_state (); blk = []; fill = 0 }
    (String.to_seq s)

(* The multi-rate pad. One byte when the block lacks exactly one, the
   domain byte then zeros then 0x80 otherwise, so a message whose length
   is already a multiple of the rate gains a whole extra block. fill is
   at most rate () - 2 on the second branch, so the zero count is never
   negative; Int.max keeps List.init total whatever the branch, on the
   hmacx pad_key precedent. *)
let finalize (d : domain) (a : acc) : state =
  let pad =
    if Int.equal a.fill (rate () - 1) then [ domain_byte d lor 0x80 ]
    else
      (domain_byte d
      :: List.init (Int.max 0 (rate () - a.fill - 2)) (fun (_ : int) -> 0))
      @ [ 0x80 ]
  in
  absorb_block a.st (List.rev a.blk @ pad)

(* Eight little-endian codes of one lane. The shift by 0 is the one
   shift of this unit that is not in 1 .. 63, and the stdlib specifies
   it: it returns the lane. *)
let lane_codes (v : int64) : int list =
  let code_at (k : int) : int =
    Int64.to_int (Int64.logand (Int64.shift_right_logical v k) 0xffL)
  in
  [ code_at 0; code_at 8; code_at 16; code_at 24; code_at 32; code_at 40;
    code_at 48; code_at 56 ]

(* The first 32 squeezed bytes are lanes (0, 0), (1, 0), (2, 0) and
   (3, 0), each little-endian, which is fields c0 .. c3 of row y0. *)
let squeeze (st : state) : string =
  Bytesx.of_codes
    (lane_codes st.y0.c0 @ lane_codes st.y0.c1 @ lane_codes st.y0.c2
   @ lane_codes st.y0.c3)

let sponge (d : domain) (s : string) : string = squeeze (finalize d (absorb s))

let hash (s : string) : string = sponge Keccak s
let sha3_256 (s : string) : string = sponge Sha3 s
let hash_hex (s : string) : string = Hexx.encode (hash s)

(* The Ethereum address, yellow paper appendix F: the rightmost 20 bytes
   of keccak-256 of the 64-byte uncompressed public key X || Y.

   TIMING: an address is PUBLIC and a public key is public, so no
   constant-time compare is owed here and equal is String.equal. The
   EIP-55 branch reads nibbles of the hash of a public 40-character
   string. Nothing is zeroized (M37 owns that). *)
module Address = struct
  type t = string

  let of_bytes (s : string) : t option =
    if Int.equal (String.length s) 20 then Some s else None

  let to_bytes (a : t) : string = a
  let equal (a : t) (b : t) : bool = String.equal a b

  (* Both uncompressed shapes are accepted because NO source pins the
     byte shape of signing_key: FACTS.md:221-222 only names it "pubkey
     the enclave signs responses with", the M22 row (DESIGN.md:371) pins
     the quote layout, the REPORTDATA binding formula and the
     nvidia_payload shape and is silent on that field, and Venice's own
     uncompressed convention elsewhere is the 04-prefixed 65-byte form
     (FACTS.md:241-242, FACTS.md:246-247). The live fixture at M22 and
     the parse at M33 decide which form arrives, and the accepted set
     narrows to one then. Every other length, and a 65-byte input under
     any other prefix, is None. *)
  let of_pubkey (s : string) : t option =
    let tail_address (body : string) : t option =
      Bytesx.take (hash body) 12 20
    in
    match () with
    | () when Int.equal (String.length s) 64 -> tail_address s
    | () when
        Int.equal (String.length s) 65
        && Option.fold ~none:false
             ~some:(fun (b : int) -> Int.equal b 0x04)
             (Bytesx.u8 s 0) ->
        Option.bind (Bytesx.take s 1 64) tail_address
    | () -> None

  let to_hex (a : t) : string = "0x" ^ Hexx.encode a

  (* EIP-55: a hex letter is uppercased when the nibble at the same
     index of keccak-256 of the 40 lowercase ASCII characters is 8 or
     more. Seq.zip truncates to the shorter side, so the 40 characters
     meet the first 40 of the 64 nibbles with no length arithmetic.
     Char.uppercase_ascii is a no-op on a digit, which is the rule. *)
  let to_checksum_hex (a : t) : string =
    let body = Hexx.encode a in
    let nibbles =
      List.concat_map
        (fun (c : char) -> [ Char.code c lsr 4; Char.code c land 0xf ])
        (List.of_seq (String.to_seq (hash body)))
    in
    "0x"
    ^ String.of_seq
        (Seq.map
           (fun ((c : char), (n : int)) ->
             if n >= 8 then Char.uppercase_ascii c else c)
           (Seq.zip (String.to_seq body) (List.to_seq nibbles)))

  (* The 40-character body of an address string: a 42-character input
     under either prefix case loses its prefix, a 40-character input is
     the body, anything else is None. Three arms, so a match () guard
     and not an if ladder. *)
  let body_of (s : string) : string option =
    match () with
    | () when
        Int.equal (String.length s) 42
        && (String.starts_with ~prefix:"0x" s
           || String.starts_with ~prefix:"0X" s) ->
        Bytesx.take s 2 40
    | () when Int.equal (String.length s) 40 -> Some s
    | () -> None

  (* NO checksum enforcement: a mixed-case string whose checksum is
     wrong still parses here. of_checksum_hex is the strict reader. *)
  let of_hex (s : string) : t option =
    Option.bind (body_of s) (fun (b : string) ->
        Option.bind (Result.to_option (Hexx.decode b)) of_bytes)

  (* The EIP-55 acceptance rule, applied to the 40-character BODY so the
     prefixed and the bare form of one string are accepted alike: an
     all-lowercase and an all-uppercase body carry no checksum and are
     accepted, and any other body must equal the checksum form. The case
     tests compare the body against its own lowercase and uppercase,
     never against the Hexx.upper () alphabet, which holds no digits. *)
  let of_checksum_hex (s : string) : t option =
    Option.bind (of_hex s) (fun (a : t) ->
        Option.bind (body_of s) (fun (b : string) ->
            let checked =
              Option.fold ~none:false ~some:(String.equal b)
                (Bytesx.take (to_checksum_hex a) 2 40)
            in
            if
              String.equal b (String.lowercase_ascii b)
              || String.equal b (String.uppercase_ascii b)
              || checked
            then Some a
            else None))
end
