(* M16 limbsx: a canonical little-endian 16-bit-limb bignum with
   arbitrary-modulus modular exponentiation. Ported from
   jose-caml/lib/limbsx.ml, itself a port of tinysvid sig/limbs.ml. A
   number is an immutable int list, base 2^16, least significant limb
   first. 16-bit limbs keep every partial product under 32 bits and
   every column sum under 63 bits, so no intermediate value overflows
   an OCaml int.

   The representation is CANONICAL: every limb sits in 0 .. 0xffff,
   there is no most significant zero limb, and zero is the empty list.
   Every function that returns a t returns a canonical one, so no
   caller can hold a padded or oversized value.

   NOT constant-time, by design and like both ancestors: the reduction
   branches on limb values and the exponentiation branches on exponent
   bits. Every consumer that feeds a secret in states its ladder shape
   in its own brief (M20 ECDH, M29 keygen); a constant-time tower is a
   hardening candidate at M39.

   ZxCaml trap 2 makes a top-level constant invisible inside a helper,
   so the byte cap is a unit function and the limb mask is bound
   locally in every helper that reads it. *)

type t = int list

(* The operand cap, in bytes: 8192 bits. The largest operand any
   roadmap row names is a 512-bit product; the cap bounds the O(n^2)
   schoolbook work on hostile input. *)
let max_bytes (() : unit) : int = 1024

(* ---------- private list helpers ---------- *)

(* Total fold over two lists: stops at the shorter one. *)
let rec fold2t (f : 'a -> int -> int -> 'a) (acc : 'a) (a : int list)
    (b : int list) : 'a =
  match (a, b) with
  | [], _ -> acc
  | _ :: _, [] -> acc
  | x :: xs, y :: ys -> fold2t f (f acc x y) xs ys

(* Drop zero limbs at the MOST significant end, so the result is
   canonical in length. *)
let trim (ls : int list) : int list =
  let rec dropz (l : int list) : int list =
    match l with
    | [] -> []
    | 0 :: rest -> dropz rest
    | v :: rest -> v :: rest
  in
  List.rev (dropz (List.rev ls))

(* Zero-extend at the most significant end to n limbs. *)
let pad_to (n : int) (ls : int list) : int list =
  let len = List.length ls in
  match () with
  | () when len >= n -> ls
  | () -> ls @ List.init (n - len) (fun (_ : int) -> 0)

(* Carry-propagate nonnegative limbs into canonical 16-bit limbs. This
   never trims: the result may still carry most significant zero
   limbs, and the callers that need a canonical value trim after it. *)
let carry_norm (ls : int list) : int list =
  let mask = 0xffff in
  (* The remaining carry becomes limbs above; push builds MSB first. *)
  let rec push (m : int) (c : int) (acc : int list) : int list =
    match () with
    | () when Int.equal c 0 -> acc
    | () -> push m (c lsr 16) ((c land m) :: acc)
  in
  let folded =
    List.fold_left
      (fun ((acc : int list), (cy : int)) (v : int) ->
        let s = v + cy in
        ((s land mask) :: acc, s lsr 16))
      ([], 0) ls
  in
  List.rev (push mask (snd folded) [] @ fst folded)

(* Element-wise add; the shorter list is zero-padded. Limbs may leave
   the 16-bit range, so a caller normalizes afterwards. *)
let rec add_lists (a : int list) (b : int list) : int list =
  match (a, b) with
  | [], rest -> rest
  | rest, [] -> rest
  | x :: xs, y :: ys -> (x + y) :: add_lists xs ys

(* Compare as numbers: negative, zero, positive. *)
let cmp_limbs (a : int list) (b : int list) : int =
  let ta = trim a in
  let tb = trim b in
  let la = List.length ta in
  let lb = List.length tb in
  match () with
  | () when not (Int.equal la lb) -> Int.compare la lb
  | () ->
    fold2t
      (fun (acc : int) (x : int) (y : int) ->
        match () with
        | () when not (Int.equal acc 0) -> acc
        | () -> Int.compare x y)
      0 (List.rev ta) (List.rev tb)

(* a - b, for a at least b as numbers; the result has the length of a.
   fold2t stops at the shorter list, so cells of b above the top of a
   are dropped: the callers only ever pass a subtrahend whose extra
   cells are zero. *)
let sub_limbs (a : int list) (b : int list) : int list =
  let bp = pad_to (List.length a) b in
  let folded =
    fold2t
      (fun ((acc : int list), (bor : int)) (x : int) (y : int) ->
        let s = x - y - bor in
        match () with
        | () when s < 0 -> ((s + 0x10000) :: acc, 1)
        | () -> (s :: acc, 0))
      ([], 0) a bp
  in
  List.rev (fst folded)

(* Multiply by B^k, B = 2^16: prepend k zero limbs. *)
let shift_limbs (ls : int list) (k : int) : int list =
  List.init (Int.max k 0) (fun (_ : int) -> 0) @ ls

(* Schoolbook multiply. Both inputs carry limbs under 2^16, so every
   partial product stays under 2^32 and the column sums stay small. *)
let mul_limbs (a : int list) (b : int list) : int list =
  let partials =
    List.mapi
      (fun (i : int) (ai : int) ->
        shift_limbs (List.map (fun (bj : int) -> ai * bj) b) i)
      a
  in
  List.fold_left add_lists [] partials

(* LSB-first bits of a limb list, exactly 16 per limb. *)
let bits_of_limbs (ls : int list) : int list =
  List.concat_map
    (fun (limb : int) -> List.init 16 (fun (i : int) -> (limb lsr i) land 1))
    ls

(* The ONE division in the unit. None unless the divisor is above zero
   and the dividend is at least zero, so no caller can divide by zero
   and no caller can read a quotient rounded toward zero from a
   negative dividend. *)
let div_pos (n : int) (d : int) : int option =
  match () with
  | () when d <= 0 -> None
  | () when n < 0 -> None
  | () -> Some (n / d) (* @total-accessor *)

(* Little-endian byte list to 16-bit limbs. *)
let rec limbs_of_le_bytes (bl : int list) : int list =
  match bl with
  | [] -> []
  | [ b0 ] -> [ b0 ]
  | b0 :: b1 :: rest -> (b0 lor (b1 lsl 8)) :: limbs_of_le_bytes rest

(* v mod m by quotient-estimate subtraction. m is trimmed and nonzero;
   the caller rejects the zero modulus. v may carry oversized limbs (a
   schoolbook product does), so the first act is a carry-normalize.
   The result is trimmed and canonical.

   STEP BOUND (A2): the cost is NOT a function of the operand size.
   The equal-limb-count case (sh = 0) is plain repeated subtraction
   with no quotient estimate, so ONE reduction runs up to 2^16 - 1
   steps at any operand size (m = 65536 with v = 0xffff0000 takes
   65535 steps; m = 3 with v = 0xffff takes 21845). mod_pow therefore
   costs up to 2 * e_bits * 65535 steps, about 1.07e9 at the 8192-bit
   operand cap. No roadmap consumer picks the modulus from untrusted
   input, and a modulus whose top limb is 0xffff or 0x7fff runs the
   equal-limb case at most a couple of steps. *)
let mod_red_limbs (mt : int list) (v : int list) : int list =
  let lm = List.length mt in
  let mtop =
    match List.rev mt with
    | [] -> 1
    | t :: _ -> t + 1
  in
  (* TERMINATION AND SAFETY (W5 as amended by A5). mtop = t + 1 >= 2,
     because m is canonical and nonzero, so the max ... 1 fallback on
     the two-limb estimate is a no-op and both div_pos defaults are
     unreachable. For sh >= 1 the estimate q satisfies
     q * m * B^sh <= v, because m < mtop * B^(limbs m - 1); so
     sub_limbs never sees a smaller minuend, q >= 1, and every step
     strictly decreases v. The sh = 0 case is not an estimate: it
     subtracts m once per step and decreases v by m.
     DROPPED CELLS: carry_norm never trims, so the subtrahend
     carry_norm (shift_limbs ...) may hold MORE list cells than v. The
     same inequality makes those extra cells zero, and fold2t stops at
     the shorter list, so sub_limbs drops them and never borrows past
     the top of v. *)
  let rec go (v : int list) : int list =
    let vt = trim v in
    let sh = List.length vt - lm in
    match () with
    | () when cmp_limbs vt mt < 0 -> vt
    | () when Int.equal sh 0 -> go (sub_limbs vt mt)
    | () ->
      let est =
        match List.rev vt with
        | [] -> (1, sh)
        | [ _ ] -> (1, sh)
        | t1 :: t2 :: _ ->
          (* A4: the one-limb estimate defaults to 0, so a None falls
             into the two-limb branch, which is always safe. The
             two-limb estimate defaults to 1 inside the max guard,
             where 1 * m * B^(sh - 1) <= v holds unconditionally. *)
          let q1 = Option.value (div_pos t1 mtop) ~default:0 in
          (match () with
           | () when q1 >= 1 -> (q1, sh)
           | () ->
             let wide = (t1 * 65536) + t2 in
             ( Int.max (Option.value (div_pos wide mtop) ~default:1) 1,
               sh - 1 ))
      in
      let q = fst est in
      let sq = snd est in
      go
        (sub_limbs vt
           (carry_norm (shift_limbs (List.map (fun (x : int) -> x * q) mt) sq)))
  in
  go (trim (carry_norm v))

(* base ^ e mod m by LSB-first square-and-multiply over the exponent
   bits, the jose structure verbatim. m is trimmed and nonzero. acc
   starts at one, so an empty exponent returns one reduced by m for
   EVERY base, the zero base included (A6). Variable-time: the 1-bit
   branch and the bit count are both visible in the running time. *)
let mod_pow_limbs (mt : int list) (base : int list) (e : int list) : int list =
  let red = mod_red_limbs mt in
  let folded =
    List.fold_left
      (fun ((acc : int list), (sq : int list)) (bit : int) ->
        let stepped =
          match () with
          | () when Int.equal bit 1 -> red (mul_limbs acc sq)
          | () -> acc
        in
        (stepped, red (mul_limbs sq sq)))
      ([ 1 ], red base)
      (bits_of_limbs (trim e))
  in
  red (fst folded)

(* ---------- constructors and projections ---------- *)

let zero : t = []
let one : t = [ 1 ]

let of_int (n : int) : t option =
  let rec limbs (v : int) : int list =
    match () with
    | () when v <= 0 -> []
    | () -> (v land 0xffff) :: limbs (v lsr 16)
  in
  match () with
  | () when n < 0 -> None
  | () -> Some (limbs n)

let of_limbs (ls : int list) : t option =
  let in_range (v : int) : bool =
    match () with
    | () when v < 0 -> false
    | () when v > 0xffff -> false
    | () -> true
  in
  (* The count is taken BEFORE trimming, so a huge all-zero list is
     rejected instead of trimming away to zero (A1). Two bytes per
     limb, so the limb cap is max_bytes () / 2, written as a
     multiplication to keep the one division inside div_pos. *)
  match () with
  | () when List.length ls * 2 > max_bytes () -> None
  | () when not (List.for_all in_range ls) -> None
  | () -> Some (trim ls)

let to_limbs (x : t) : int list = x
let num_limbs (x : t) : int = List.length x

let is_zero (x : t) : bool =
  match x with
  | [] -> true
  | _ :: _ -> false

let of_be_string (s : string) : t option =
  match () with
  | () when String.length s > max_bytes () -> None
  | () ->
    let be = List.map Char.code (List.of_seq (String.to_seq s)) in
    Some (trim (limbs_of_le_bytes (List.rev be)))

let to_be_string ~(len : int) (x : t) : string option =
  let le_bytes =
    List.concat_map
      (fun (limb : int) -> [ limb land 0xff; (limb lsr 8) land 0xff ])
      x
  in
  (* trim drops the high zero bytes at the END of the LSB-first list,
     so the reversal below is the minimal big-endian encoding. *)
  let be = List.rev (trim le_bytes) in
  let need = List.length be in
  match () with
  | () when len < 0 -> None
  | () when len > max_bytes () -> None
  | () when need > len -> None
  | () ->
    Some (Bytesx.of_codes (List.init (len - need) (fun (_ : int) -> 0) @ be))

(* Strict: Hexx.decode rejects any byte outside the alphabet and any
   odd length, so a bad character is never read as a zero nibble. The
   length guard comes FIRST, so hostile input is refused in O(1)
   instead of decoded into 2 * max_bytes () bytes and capped after the
   fact. Output-equivalent: the decode-then-cap path answered None for
   the same strings. *)
let of_hex (s : string) : t option =
  match () with
  | () when String.length s > 2 * max_bytes () -> None
  | () -> Option.bind (Result.to_option (Hexx.decode s)) of_be_string

(* ---------- arithmetic ---------- *)

let cmp (a : t) (b : t) : int = cmp_limbs a b
let equal (a : t) (b : t) : bool = Int.equal (cmp_limbs a b) 0
let add (a : t) (b : t) : t = trim (carry_norm (add_lists a b))

let sub (a : t) (b : t) : t option =
  match () with
  | () when cmp_limbs a b < 0 -> None
  | () -> Some (trim (sub_limbs a b))

let mul (a : t) (b : t) : t = trim (carry_norm (mul_limbs a b))
let bits (x : t) : int list = bits_of_limbs x

let mod_red ~(m : t) (v : t) : t option =
  match trim m with
  | [] -> None
  | _ :: _ -> Some (mod_red_limbs (trim m) v)

let mod_pow ~(m : t) (base : t) (e : t) : t option =
  match trim m with
  | [] -> None
  | _ :: _ -> Some (mod_pow_limbs (trim m) base e)
