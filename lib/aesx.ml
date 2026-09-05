(* M21 aesx: the FORWARD AES-256 block cipher of FIPS 197, written for
   gcmx and for the M30 and M32 chunk paths.  There is no decrypt
   block, no InvSubBytes, no InvMixColumns and no inverse schedule: GCM
   runs the forward cipher in both directions, so an inverse cipher
   would be dead code.  AES-128 and AES-192 are out of scope: no
   consumer row names them, so key_of_bytes takes 32 bytes alone.

   Pure and sans-io, like hmacx.ml and keccakx.ml: no Bytes, no Buffer,
   no Array, no ref, no exception and no try-with.  Every window is cut
   through Bytesx.take and every byte is emitted through
   Bytesx.of_codes, so no Char.chr, no String.sub and no String.get
   appears here.  The unit holds no division line and no mod line, and
   every shift amount is a LITERAL, which keccakx.ml:66-72 explains for
   Int64 and which this unit keeps for int as well.

   THE STATE (FIPS 197 section 3.4).  The state is four packed 32-bit
   columns in a RECORD, col, never an array and never a list read by
   position.  The state is filled COLUMN-MAJOR, so input byte 4c + r is
   s[r][c] and column c is the big-endian read of bytes 4c to 4c + 3.
   Column c holds s[0][c] in its top byte down to s[3][c] in its low
   byte, so a key-schedule word is a column and a round key is the same
   record.  be32 is local, because bytesx carries little-endian readers
   only (bytesx.ml:60 and bytesx.ml:74) and both of those shift by the
   computed amount 8 * i.

   THE S-BOX (FIPS 197 section 5.1.1) is COMPUTED and never a table.
   sbox masks its argument with 0xff first, so it is total on every
   int, and it is the GF(2^8) multiplicative inverse under the modulus
   x^8 + x^4 + x^3 + x + 1, whose reduction byte is 0x1b, followed by
   the affine map b ^ rotl8(b,1) ^ rotl8(b,2) ^ rotl8(b,3) ^
   rotl8(b,4) ^ 0x63.  The inverse is a^254 by a fixed chain of ELEVEN
   gf_mul calls, and gf_mul is eight masked doublings with eight masked
   selects, so 0 maps to 0 with no special case and no branch reads a
   bit of either operand.  A 256-byte table with a masked Map lookup is
   REJECTED: a Map lookup walks a secret-dependent path through the
   tree, which leaks through branch and cache timing.

   THE ROUNDS.  ShiftRows is four literal masks over the four columns,
   MixColumns is the packed identity xt and mix (FIPS 197 section
   5.1.3, the (2 3 1 1) circulant), and AddRoundKey is the field-wise
   lxor of two records.  The Nk = 8 schedule (FIPS 197 section 5.2)
   builds { k0;  mids;  k14 } ONCE, so encrypt_block never splits a
   list and needs no default arm.

   TIMING (DESIGN.md section 2, "Timing side channel on client
   secrets"): no secret-indexed memory access and no secret-dependent
   branch in the S-box, MixColumns, the key schedule or GHASH;
   residual: the OCaml native compiler, the allocator and the *
   operator are not constant-time by contract, M39.

   ZxCaml trap 2 makes a top-level constant invisible inside a helper
   and fires ACROSS modules, so block_len, key_len and rcon are unit
   functions, every mask is a literal at its use site, and no
   top-level alias of a Bytesx value is written here. *)

let block_len (() : unit) : int = 16
let key_len (() : unit) : int = 32

type col = { c0 : int;  c1 : int;  c2 : int;  c3 : int }

(* The expanded schedule: the first round key, the 13 middle round keys
   and the last round key.  k0 is read by cipher, mids is read by
   cipher, and k14 is read by cipher. *)
type key = { k0 : col;  mids : col list;  k14 : col }

(* FIPS 197 figure 11, the first seven Rcon bytes.  The schedule takes
   the first six of them by List.filteri and passes 0x40 by hand. *)
let rcon (() : unit) : int list = [ 0x01; 0x02; 0x04; 0x08; 0x10; 0x20; 0x40 ]

(* Big-endian recombination of a 4-byte window minted by Bytesx.take.
   The accumulator shifts by the LITERAL 8, so this reader is NOT the
   mirror of Bytesx.le_int, which shifts by the computed 8 * i. *)
let be32 (w : string) : int =
  Seq.fold_left
    (fun (acc : int) (c : char) -> (acc lsl 8) lor Char.code c)
    0 (String.to_seq w)

(* Doubling in GF(2^8): the mask is 0 or -1 from the top bit alone, so
   the reduction is unconditional arithmetic and never a branch. *)
let xtime (a : int) : int =
  ((a lsl 1) land 0xff) lxor (0x1b land (0 - (a lsr 7)))

(* EIGHT explicit masked steps and never a fold over a list of shift
   amounts: a fold takes its amount off the list at run time, and every
   shift amount in this unit is a literal. *)
let gf_mul (a : int) (b : int) : int =
  let m = b land 0xff in
  let a0 = a land 0xff in
  let a1 = xtime a0 in
  let a2 = xtime a1 in
  let a3 = xtime a2 in
  let a4 = xtime a3 in
  let a5 = xtime a4 in
  let a6 = xtime a5 in
  let a7 = xtime a6 in
  (a0 land (0 - (m land 1)))
  lxor (a1 land (0 - ((m lsr 1) land 1)))
  lxor (a2 land (0 - ((m lsr 2) land 1)))
  lxor (a3 land (0 - ((m lsr 3) land 1)))
  lxor (a4 land (0 - ((m lsr 4) land 1)))
  lxor (a5 land (0 - ((m lsr 5) land 1)))
  lxor (a6 land (0 - ((m lsr 6) land 1)))
  lxor (a7 land (0 - ((m lsr 7) land 1)))

(* The affine rotation of FIPS 197 section 5.1.1.  The amount arrives
   as a literal at every call site, and each arm shifts by its own pair
   of literals, so no shift amount is ever computed. *)
let rotl8 (b : int) (n : int) : int =
  match () with
  | () when Int.equal n 1 -> ((b lsl 1) lor (b lsr 7)) land 0xff
  | () when Int.equal n 2 -> ((b lsl 2) lor (b lsr 6)) land 0xff
  | () when Int.equal n 3 -> ((b lsl 3) lor (b lsr 5)) land 0xff
  | () -> ((b lsl 4) lor (b lsr 4)) land 0xff

(* The multiplicative inverse a^254 by the fixed ELEVEN-call chain,
   then the affine map.  Squaring is gf_mul of a value with itself, so
   the eleven calls are seven squarings and four products and the
   evaluation is straight-line masked arithmetic. *)
let sbox (x : int) : int =
  let a = x land 0xff in
  let a2 = gf_mul a a in
  let a3 = gf_mul a2 a in
  let a6 = gf_mul a3 a3 in
  let a12 = gf_mul a6 a6 in
  let a15 = gf_mul a12 a3 in
  let a30 = gf_mul a15 a15 in
  let a60 = gf_mul a30 a30 in
  let a120 = gf_mul a60 a60 in
  let a240 = gf_mul a120 a120 in
  let a252 = gf_mul a240 a12 in
  let b = gf_mul a252 a2 in
  b lxor rotl8 b 1 lxor rotl8 b 2 lxor rotl8 b 3 lxor rotl8 b 4 lxor 0x63

(* SubWord of FIPS 197 section 5.2 and one column of SubBytes: the four
   byte lanes through masks and the LITERAL shifts 24, 16 and 8. *)
let sub_col (w : int) : int =
  (sbox ((w lsr 24) land 0xff) lsl 24)
  lor (sbox ((w lsr 16) land 0xff) lsl 16)
  lor (sbox ((w lsr 8) land 0xff) lsl 8)
  lor sbox (w land 0xff)

let sub_bytes (s : col) : col =
  { c0 = sub_col s.c0;  c1 = sub_col s.c1;  c2 = sub_col s.c2;  c3 = sub_col s.c3 }

(* s'[r][c] = s[r][(c + r) mod 4] as literal masks over the four
   columns: row r sits at bits 24 - 8r of every column, so the rotation
   of a row is the choice of the column each mask reads.  No arithmetic
   runs on an index. *)
let shift_rows (s : col) : col =
  { c0 =
      (s.c0 land 0xff000000) lor (s.c1 land 0x00ff0000)
      lor (s.c2 land 0x0000ff00) lor (s.c3 land 0x000000ff);
    c1 =
      (s.c1 land 0xff000000) lor (s.c2 land 0x00ff0000)
      lor (s.c3 land 0x0000ff00) lor (s.c0 land 0x000000ff);
    c2 =
      (s.c2 land 0xff000000) lor (s.c3 land 0x00ff0000)
      lor (s.c0 land 0x0000ff00) lor (s.c1 land 0x000000ff);
    c3 =
      (s.c3 land 0xff000000) lor (s.c0 land 0x00ff0000)
      lor (s.c1 land 0x0000ff00) lor (s.c2 land 0x000000ff) }

(* RotWord of FIPS 197 section 5.2 and the MixColumns rotations.  The
   amount arrives as a literal at every call site and each arm shifts
   by its own pair of literals. *)
let rotl32 (x : int) (n : int) : int =
  match () with
  | () when Int.equal n 8 -> ((x lsl 8) lor (x lsr 24)) land 0xffffffff
  | () when Int.equal n 16 -> ((x lsl 16) lor (x lsr 16)) land 0xffffffff
  | () -> ((x lsl 24) lor (x lsr 8)) land 0xffffffff

(* Four packed doublings at once: the low seven bits of every byte
   shift left, and the top bit of every byte selects the reduction byte
   through the 0x01010101 mask, so the product never carries between
   bytes. *)
let xt (x : int) : int =
  ((x land 0x7f7f7f7f) lsl 1) lxor (((x lsr 7) land 0x01010101) * 0x1b)

(* The (2 3 1 1) circulant, packed.  Byte r sits at bits 24 - 8r, so
   rotl32 x3 8 brings byte r + 1 of 3 s into position r, rotl32 c 16
   brings byte r + 2 and rotl32 c 24 brings byte r + 3, which is
   2 s[r] ^ 3 s[r+1] ^ s[r+2] ^ s[r+3] on every row. *)
let mix (c : int) : int =
  let x2 = xt c in
  let x3 = x2 lxor c in
  x2 lxor rotl32 x3 8 lxor rotl32 c 16 lxor rotl32 c 24

let mix_columns (s : col) : col =
  { c0 = mix s.c0;  c1 = mix s.c1;  c2 = mix s.c2;  c3 = mix s.c3 }

let add_round_key (s : col) (k : col) : col =
  { c0 = s.c0 lxor k.c0;  c1 = s.c1 lxor k.c1;  c2 = s.c2 lxor k.c2;
    c3 = s.c3 lxor k.c3 }

(* The i mod 8 = 0 rule of FIPS 197 section 5.2: SubWord(RotWord(w))
   xor the Rcon word, then each next word is the previous word xor
   w[i-8].  prev2 holds w[i-8] .. w[i-5] and prev1 holds w[i-4] ..
   w[i-1]. *)
let next_first (prev2 : col) (prev1 : col) (rc : int) : col =
  let w0 = prev2.c0 lxor sub_col (rotl32 prev1.c3 8) lxor (rc lsl 24) in
  let w1 = prev2.c1 lxor w0 in
  let w2 = prev2.c2 lxor w1 in
  let w3 = prev2.c3 lxor w2 in
  { c0 = w0;  c1 = w1;  c2 = w2;  c3 = w3 }

(* The i mod 8 = 4 rule, SubWord alone, which applies because Nk > 6. *)
let next_second (prev2 : col) (prev1 : col) : col =
  let w0 = prev2.c0 lxor sub_col prev1.c3 in
  let w1 = prev2.c1 lxor w0 in
  let w2 = prev2.c2 lxor w1 in
  let w3 = prev2.c3 lxor w2 in
  { c0 = w0;  c1 = w1;  c2 = w2;  c3 = w3 }

(* Six fold steps over the FIRST SIX Rcon values, each step minting two
   round keys, then ONE further next_first with the literal 0x40 mints
   k14.  A seventh fold step would build a sixteenth round key the
   cipher never uses and a list split would then have to drop, and a
   list split needs a default arm;  this shape never builds it.  mids
   is k1 :: List.rev acc and holds exactly 13 entries, so 13 middle
   rounds plus the final round is Nr = 14. *)
let schedule (k0 : col) (k1 : col) : key =
  let step ((prev2 : col), (prev1 : col), (acc : col list)) (rc : int) =
    let g1 = next_first prev2 prev1 rc in
    let g2 = next_second prev1 g1 in
    (g1, g2, g2 :: g1 :: acc)
  in
  let ((p2 : col), (p1 : col), (acc : col list)) =
    List.fold_left step (k0, k1, [])
      (List.filteri (fun (i : int) (_ : int) -> i < 6) (rcon ()))
  in
  { k0;  mids = k1 :: List.rev acc;  k14 = next_first p2 p1 0x40 }

let word_at (s : string) (off : int) : int option =
  Option.map be32 (Bytesx.take s off 4)

(* Four big-endian words, so column c is bytes 4c to 4c + 3 of the
   window that starts at off. *)
let col_at (s : string) (off : int) : col option =
  Option.bind (word_at s off) (fun (a : int) ->
      Option.bind (word_at s (off + 4)) (fun (b : int) ->
          Option.bind (word_at s (off + 8)) (fun (c : int) ->
              Option.map
                (fun (d : int) -> { c0 = a;  c1 = b;  c2 = c;  c3 = d })
                (word_at s (off + 12)))))

(* The state back to bytes, column by column, top byte first. *)
let codes_of_col (s : col) : int list =
  [ (s.c0 lsr 24) land 0xff;  (s.c0 lsr 16) land 0xff;
    (s.c0 lsr 8) land 0xff;  s.c0 land 0xff;
    (s.c1 lsr 24) land 0xff;  (s.c1 lsr 16) land 0xff;
    (s.c1 lsr 8) land 0xff;  s.c1 land 0xff;
    (s.c2 lsr 24) land 0xff;  (s.c2 lsr 16) land 0xff;
    (s.c2 lsr 8) land 0xff;  s.c2 land 0xff;
    (s.c3 lsr 24) land 0xff;  (s.c3 lsr 16) land 0xff;
    (s.c3 lsr 8) land 0xff;  s.c3 land 0xff ]

(* AddRoundKey with k0, then one fold over the 13 middle round keys
   with (sub, shift, mix, add), then the final round (sub, shift, add
   k14) with NO mix. *)
let cipher (k : key) (st : col) : col =
  let mid =
    List.fold_left
      (fun (s : col) (rk : col) ->
        add_round_key (mix_columns (shift_rows (sub_bytes s))) rk)
      (add_round_key st k.k0) k.mids
  in
  add_round_key (shift_rows (sub_bytes mid)) k.k14

let key_of_bytes (s : string) : key option =
  if Int.equal (String.length s) (key_len ()) then
    Option.bind (col_at s 0) (fun (a : col) ->
        Option.map (fun (b : col) -> schedule a b) (col_at s 16))
  else None

let encrypt_block (k : key) (block : string) : string option =
  if Int.equal (String.length block) (block_len ()) then
    Option.map
      (fun (st : col) -> Bytesx.of_codes (codes_of_col (cipher k st)))
      (col_at block 0)
  else None
