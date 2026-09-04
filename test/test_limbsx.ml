(* M16 limbsx: the canonical 16-bit-limb bignum and its modular
   exponentiation, through the PUBLIC surface only. The private
   helpers (trim, carry_norm, sub_limbs, mul_limbs, div_pos) are
   reached by the operations that use them: a sub that borrows, a mul
   that carries, a mod_red that shifts.

   The hex constants below are recomputed by harness/diff_limbs.py
   with python integers and pow(), and that harness requires each one
   to sit inside a CHECK ROW of this file, not merely somewhere in it.
   Moving a pin into a comment or into an unread let turns the gate
   RED.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal module by its mangled name, exactly as test_retryx
   and test_clientx do. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module L = Venice__Limbsx

(* ---------- readers ---------- *)

(* A failed constructor folds to zero, and every constructor is pinned
   by its own row, so a broken decode cannot hide inside a later row. *)
let n (v : int) : L.t = Option.value (L.of_int v) ~default:L.zero
let hx (s : string) : L.t = Option.value (L.of_hex s) ~default:L.zero
let lm (ls : int list) : L.t = Option.value (L.of_limbs ls) ~default:L.zero

let opt_eq (a : L.t option) (b : L.t option) : bool =
  Option.fold ~none:false
    ~some:(fun (x : L.t) ->
      Option.fold ~none:false ~some:(fun (y : L.t) -> L.equal x y) b)
    a

let sopt_eq (a : string option) (b : string option) : bool =
  Option.fold ~none:false
    ~some:(fun (x : string) ->
      Option.fold ~none:false ~some:(String.equal x) b)
    a

let limbs_eq (a : L.t option) (ls : int list) : bool =
  Option.fold ~none:false
    ~some:(fun (x : L.t) -> List.equal Int.equal (L.to_limbs x) ls)
    a

let zeros (k : int) : int list = List.init (Int.max k 0) (fun (_ : int) -> 0)

(* k hex zero characters, without String.make: the oversized-input row
   feeds a string longer than the of_hex length guard allows. *)
let hex_zeros (k : int) : string =
  String.concat "" (List.init (Int.max k 0) (fun (_ : int) -> "0"))

(* ---------- the pinned values ---------- *)

(* 2^255 - 19, an arbitrary base under it, and the e = 65537 modexp
   result: the jose vector, pin (a). *)
let m255 : L.t =
  hx "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"

let b255 : L.t =
  hx "4a7c559911fa2016c34479067b47d02be2b17b0b1b0d8a2d6d312bc939b204d1"

(* The P-256 field prime and a fixed element, pin (b). *)
let p256 : L.t =
  hx "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"

let a_p256 : L.t =
  hx "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe"

let inv_p256 : L.t option =
  Option.bind (L.sub p256 (n 2)) (fun (e : L.t) -> L.mod_pow ~m:p256 a_p256 e)

(* The secp256k1 field prime and another fixed element, pin (c). *)
let psecp : L.t =
  hx "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"

let a_secp : L.t =
  hx "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8"

let inv_secp : L.t option =
  Option.bind (L.sub psecp (n 2)) (fun (e : L.t) ->
      L.mod_pow ~m:psecp a_secp e)

(* Two fixed 256-bit factors whose 512-bit product is reduced mod the
   P-256 prime, pin (d). *)
let a_mul : L.t =
  hx "9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95"

let b_mul : L.t =
  hx "517cc1b727220a94fe13abe8fa9a6ee06db14acc9e21c820ff28b1d5ef5de2b0"

let prod : L.t = L.mul a_mul b_mul
let prod_red : L.t option = L.mod_red ~m:p256 prod

(* A borrow chain the difference itself shows, pin (e): the subtrahend
   is nonzero in its low FIVE limbs, so 15 of the 16 limbs borrow out
   and the chain stays visible in four fffe limbs of the difference
   instead of in a single trailing limb. *)
let a_sub : L.t =
  hx "8000000000000000000000000000000000000000000000000000000000000000"

let b_sub : L.t =
  hx "0000000000000000000000000000000000000000000000010001000100010001"

let diff : L.t option = L.sub a_sub b_sub

(* ---------- the checks ---------- *)

let construction_checks : (string * bool) list =
  [ ( "limbsx: of_limbs rejects a limb above the base",
      Option.is_none (L.of_limbs [ 0x10000 ]) );
    ( "limbsx: of_limbs rejects a negative limb",
      Option.is_none (L.of_limbs [ -1 ]) );
    ( "limbsx: of_limbs accepts the top limb value",
      limbs_eq (L.of_limbs [ 0xffff ]) [ 0xffff ] );
    ( "limbsx: of_limbs trims most significant zeros",
      limbs_eq (L.of_limbs [ 5; 0; 0 ]) [ 5 ] );
    ( "limbsx: of_limbs of the empty list is zero",
      opt_eq (L.of_limbs []) (Some L.zero) );
    ( "limbsx: of_limbs of an all-zero list is zero",
      opt_eq (L.of_limbs [ 0; 0; 0 ]) (Some L.zero) );
    ( "limbsx: of_limbs rejects 513 limbs, counted before trimming",
      Option.is_none (L.of_limbs (List.init 513 (fun (_ : int) -> 1))) );
    ( "limbsx: of_limbs rejects 513 ZERO limbs, counted before trimming",
      Option.is_none (L.of_limbs (List.init 513 (fun (_ : int) -> 0))) );
    ( "limbsx: of_limbs accepts 512 limbs",
      Option.is_some (L.of_limbs (List.init 512 (fun (_ : int) -> 1))) );
    ("limbsx: of_int rejects a negative", Option.is_none (L.of_int (-1)));
    ("limbsx: of_int of zero is zero", opt_eq (L.of_int 0) (Some L.zero));
    ( "limbsx: of_int splits into base 2^16 limbs",
      limbs_eq (L.of_int 0x12345) [ 0x2345; 1 ] );
    ( "limbsx: to_limbs of zero is the empty list",
      List.equal Int.equal (L.to_limbs L.zero) [] );
    ( "limbsx: to_limbs of one is a single limb",
      List.equal Int.equal (L.to_limbs L.one) [ 1 ] );
    ( "limbsx: num_limbs counts the canonical limbs",
      Int.equal (L.num_limbs (n 0x12345)) 2 );
    ("limbsx: num_limbs of zero is zero", Int.equal (L.num_limbs L.zero) 0);
    ("limbsx: is_zero holds for zero", L.is_zero L.zero);
    ("limbsx: is_zero is false for one", not (L.is_zero L.one)) ]

let bytes_checks : (string * bool) list =
  [ ( "limbsx: of_be_string folds leading zero bytes",
      opt_eq (L.of_be_string "\x00\x00\x01") (L.of_int 1) );
    ( "limbsx: of_be_string of the empty string is zero",
      opt_eq (L.of_be_string "") (Some L.zero) );
    ( "limbsx: of_be_string pairs bytes into limbs",
      limbs_eq (L.of_be_string "\x01\x02\x03") [ 0x0203; 1 ] );
    ( "limbsx: of_be_string accepts exactly max_bytes",
      Option.is_some (L.of_be_string (String.make (L.max_bytes ()) '\x01')) );
    ( "limbsx: of_be_string rejects one byte above max_bytes",
      Option.is_none
        (L.of_be_string (String.make (L.max_bytes () + 1) '\x01')) );
    ( "limbsx: to_be_string emits big-endian bytes",
      sopt_eq (L.to_be_string ~len:2 (n 0x1234)) (Some "\x12\x34") );
    ( "limbsx: to_be_string pads on the left",
      sopt_eq (L.to_be_string ~len:3 (n 0x1234)) (Some "\x00\x12\x34") );
    ( "limbsx: to_be_string one byte short is None",
      Option.is_none (L.to_be_string ~len:1 (n 0x1234)) );
    ( "limbsx: to_be_string of a negative len is None",
      Option.is_none (L.to_be_string ~len:(-1) L.one) );
    ( "limbsx: to_be_string of zero at len 0 is the empty string",
      sopt_eq (L.to_be_string ~len:0 L.zero) (Some "") );
    ( "limbsx: to_be_string above max_bytes is None",
      Option.is_none (L.to_be_string ~len:(L.max_bytes () + 1) L.one) );
    ( "limbsx: to_be_string at max_bytes is Some",
      Option.is_some (L.to_be_string ~len:(L.max_bytes ()) L.one) );
    ( "limbsx: to_be_string of one at len 32 is 31 zero bytes then 0x01",
      sopt_eq
        (L.to_be_string ~len:32 L.one)
        (Some (String.make 31 '\x00' ^ "\x01")) );
    ( "limbsx: to_be_string round trips a 256-bit value",
      Option.fold ~none:false
        ~some:(fun (s : string) -> opt_eq (L.of_be_string s) (Some a_p256))
        (L.to_be_string ~len:32 a_p256) ) ]

let hex_checks : (string * bool) list =
  [ ( "limbsx: of_hex rejects a byte outside the alphabet",
      Option.is_none (L.of_hex "0g") );
    ("limbsx: of_hex rejects an odd length", Option.is_none (L.of_hex "abc"));
    ( "limbsx: of_hex never reads a bad character as a zero nibble",
      Option.is_none (L.of_hex "00zz") );
    ( "limbsx: of_hex accepts upper case",
      opt_eq (L.of_hex "AABB") (L.of_hex "aabb") );
    ( "limbsx: of_hex pairs two bytes into one limb",
      limbs_eq (L.of_hex "0102") [ 0x0102 ] );
    ( "limbsx: of_hex of the empty string is zero",
      opt_eq (L.of_hex "") (Some L.zero) );
    ( "limbsx: of_hex refuses an oversized string before it decodes it",
      Option.is_none (L.of_hex (hex_zeros ((2 * L.max_bytes ()) + 2))) ) ]

let cmp_checks : (string * bool) list =
  [ ( "limbsx: cmp is negative at the same limb count",
      L.cmp (lm [ 0; 1 ]) (lm [ 1; 1 ]) < 0 );
    ( "limbsx: cmp orders by limb count",
      L.cmp (lm [ 0xffff ]) (lm [ 0; 1 ]) < 0 );
    ( "limbsx: cmp trims before comparing",
      Int.equal (L.cmp (lm [ 7; 0 ]) (lm [ 7 ])) 0 );
    ( "limbsx: cmp is antisymmetric",
      Int.equal (L.cmp a_p256 p256) (Int.neg (L.cmp p256 a_p256)) );
    ("limbsx: cmp of a value with itself is zero",
      Int.equal (L.cmp a_p256 a_p256) 0 );
    ( "limbsx: equal agrees with cmp = 0",
      Bool.equal (L.equal a_p256 a_p256) (Int.equal (L.cmp a_p256 a_p256) 0) );
    ("limbsx: equal is false across values", not (L.equal a_p256 p256));
    ("limbsx: equal holds for zero", L.equal L.zero L.zero) ]

let arith_checks : (string * bool) list =
  [ ( "limbsx: add carries into a new limb",
      limbs_eq (Some (L.add (n 0xffff) L.one)) [ 0; 1 ] );
    ("limbsx: add of zero is the identity", L.equal (L.add a_p256 L.zero) a_p256);
    ( "limbsx: add commutes",
      L.equal (L.add a_p256 b_mul) (L.add b_mul a_p256) );
    ( "limbsx: sub borrows across a limb",
      opt_eq (L.sub (lm [ 0; 1 ]) L.one) (L.of_int 0xffff) );
    ( "limbsx: sub of equal values is zero",
      opt_eq (L.sub a_p256 a_p256) (Some L.zero) );
    ( "limbsx: sub rejects a smaller minuend",
      Option.is_none (L.sub L.one (n 2)) );
    ( "limbsx: sub undoes add",
      opt_eq (L.sub (L.add a_p256 b_mul) b_mul) (Some a_p256) );
    ( "limbsx: mul squares the top limb value",
      opt_eq (Some (L.mul (n 0xffff) (n 0xffff))) (L.of_int 0xfffe0001) );
    ("limbsx: mul by zero is zero", L.is_zero (L.mul a_p256 L.zero));
    ("limbsx: mul by one is the identity", L.equal (L.mul a_p256 L.one) a_p256);
    ( "limbsx: mul commutes",
      L.equal (L.mul a_p256 b_mul) (L.mul b_mul a_p256) );
    ( "limbsx: the product of two 256-bit values holds 32 limbs",
      Int.equal (L.num_limbs prod) 32 ) ]

let bits_checks : (string * bool) list =
  [ ("limbsx: bits of zero is the empty list",
      List.equal Int.equal (L.bits L.zero) [] );
    ( "limbsx: bits of two is a single one at index one",
      List.equal Int.equal (L.bits (n 2)) (0 :: 1 :: zeros 14) );
    ( "limbsx: bits of one is a single one at index zero",
      List.equal Int.equal (L.bits L.one) (1 :: zeros 15) );
    ( "limbsx: bits holds exactly 16 entries per limb",
      Int.equal (List.length (L.bits a_p256)) (16 * L.num_limbs a_p256) );
    ( "limbsx: every bit is zero or one",
      List.for_all
        (fun (b : int) -> Int.equal (b * (b - 1)) 0)
        (L.bits a_p256) ) ]

let mod_red_checks : (string * bool) list =
  [ ( "limbsx: mod_red of 100 by 7",
      opt_eq (L.mod_red ~m:(n 7) (n 100)) (L.of_int 2) );
    ( "limbsx: mod_red below the modulus returns the value",
      opt_eq (L.mod_red ~m:(n 1000) (n 999)) (L.of_int 999) );
    ( "limbsx: mod_red of a multiple is zero",
      Option.fold ~none:false ~some:L.is_zero
        (L.mod_red ~m:(n 1000) (n 1000000)) );
    ( "limbsx: mod_red rejects a zero modulus",
      Option.is_none (L.mod_red ~m:L.zero (n 5)) );
    ( "limbsx: mod_red by one is zero",
      Option.fold ~none:false ~some:L.is_zero (L.mod_red ~m:L.one a_p256) );
    ( "limbsx: mod_red of the modulus itself is zero",
      Option.fold ~none:false ~some:L.is_zero (L.mod_red ~m:p256 p256) );
    ( "limbsx: mod_red of a 512-bit product lands below the modulus",
      Option.fold ~none:false
        ~some:(fun (r : L.t) -> L.cmp r p256 < 0)
        prod_red );
    ( "limbsx: mod_red is idempotent",
      opt_eq
        (Option.bind prod_red (fun (r : L.t) -> L.mod_red ~m:p256 r))
        prod_red ) ]

let mod_pow_checks : (string * bool) list =
  [ ( "limbsx: mod_pow 3^5 mod 7",
      opt_eq (L.mod_pow ~m:(n 7) (n 3) (n 5)) (L.of_int 5) );
    ( "limbsx: mod_pow 2^10 mod 1000",
      opt_eq (L.mod_pow ~m:(n 1000) (n 2) (n 10)) (L.of_int 24) );
    ( "limbsx: mod_pow toy RSA sign 65^17 mod 3233",
      opt_eq (L.mod_pow ~m:(n 3233) (n 65) (n 17)) (L.of_int 2790) );
    ( "limbsx: mod_pow toy RSA verify 2790^2753 mod 3233",
      opt_eq (L.mod_pow ~m:(n 3233) (n 2790) (n 2753)) (L.of_int 65) );
    ( "limbsx: mod_pow with a zero exponent gives one",
      opt_eq (L.mod_pow ~m:(n 7) (n 3) L.zero) (Some L.one) );
    ( "limbsx: mod_pow of zero to the zero power gives one",
      opt_eq (L.mod_pow ~m:(n 7) L.zero L.zero) (Some L.one) );
    ( "limbsx: mod_pow of a zero base with a nonzero exponent is zero",
      Option.fold ~none:false ~some:L.is_zero
        (L.mod_pow ~m:(n 7) L.zero (n 5)) );
    ( "limbsx: mod_pow with a modulus of one is zero",
      Option.fold ~none:false ~some:L.is_zero
        (L.mod_pow ~m:L.one (n 3) (n 5)) );
    ( "limbsx: mod_pow rejects a zero modulus",
      Option.is_none (L.mod_pow ~m:L.zero (n 3) (n 5)) );
    ( "limbsx: mod_pow with an exponent of one is the reduced base",
      opt_eq (L.mod_pow ~m:(n 7) (n 100) L.one) (L.of_int 2) ) ]

(* The pins the python oracle recomputes. Every constant below sits
   inside its own check row on purpose: harness/diff_limbs.py strips
   the comments and then requires a row context, so a pin that drifts
   out of an executed check turns the gate RED. *)
let pin_checks : (string * bool) list =
  [ ( "limbsx: pin a, the 2^255 - 19 modulus text",
      opt_eq
        (L.of_hex
           "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
        (Some m255) );
    ( "limbsx: pin a, the 255-bit base text",
      opt_eq
        (L.of_hex
           "4a7c559911fa2016c34479067b47d02be2b17b0b1b0d8a2d6d312bc939b204d1")
        (Some b255) );
    ( "limbsx: pin a, the base is already reduced",
      opt_eq (L.mod_red ~m:m255 b255) (Some b255) );
    ( "limbsx: pin a, the 255-bit modexp with e = 65537",
      opt_eq
        (L.mod_pow ~m:m255 b255 (n 65537))
        (L.of_hex
           "5eb83da95dcbbc85d618d524bffd39e9edd7b8a0de199ebd5e43829a52b80264")
    );
    ( "limbsx: pin b, the P-256 field prime text",
      opt_eq
        (L.of_hex
           "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
        (Some p256) );
    ( "limbsx: pin b, the P-256 element text",
      opt_eq
        (L.of_hex
           "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe")
        (Some a_p256) );
    ( "limbsx: pin b, the Fermat inverse mod the P-256 prime",
      opt_eq inv_p256
        (L.of_hex
           "dcfe3ea582f6a5d20f4f3f72fbf60e4bc877c4878790a716929c9b27164395d4")
    );
    ( "limbsx: pin b, the Fermat inverse really inverts",
      Option.fold ~none:false
        ~some:(fun (i : L.t) ->
          opt_eq (L.mod_red ~m:p256 (L.mul a_p256 i)) (Some L.one))
        inv_p256 );
    ( "limbsx: pin c, the secp256k1 field prime text",
      opt_eq
        (L.of_hex
           "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
        (Some psecp) );
    ( "limbsx: pin c, the secp256k1 element text",
      opt_eq
        (L.of_hex
           "3243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c8")
        (Some a_secp) );
    ( "limbsx: pin c, the Fermat inverse mod the secp256k1 prime",
      opt_eq inv_secp
        (L.of_hex
           "c0392f2df4c6e5f6aa085cd66db96717bc68465f44ef54ebbe49d46d87006962")
    );
    ( "limbsx: pin c, the Fermat inverse really inverts",
      Option.fold ~none:false
        ~some:(fun (i : L.t) ->
          opt_eq (L.mod_red ~m:psecp (L.mul a_secp i)) (Some L.one))
        inv_secp );
    ( "limbsx: pin d, the first factor text",
      opt_eq
        (L.of_hex
           "9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95")
        (Some a_mul) );
    ( "limbsx: pin d, the second factor text",
      opt_eq
        (L.of_hex
           "517cc1b727220a94fe13abe8fa9a6ee06db14acc9e21c820ff28b1d5ef5de2b0")
        (Some b_mul) );
    ( "limbsx: pin d, the 512-bit product reduced mod the P-256 prime",
      opt_eq prod_red
        (L.of_hex
           "24fdee06c6db54a6e3330c648750c5f156f79d4f62876be20e75aaba86cb18bd")
    );
    ( "limbsx: pin d, the reduced product re-encodes to 32 bytes",
      Option.fold ~none:false
        ~some:(fun (r : L.t) -> Option.is_some (L.to_be_string ~len:32 r))
        prod_red );
    ( "limbsx: pin e, the minuend text",
      opt_eq
        (L.of_hex
           "8000000000000000000000000000000000000000000000000000000000000000")
        (Some a_sub) );
    ( "limbsx: pin e, the subtrahend text",
      opt_eq
        (L.of_hex
           "0000000000000000000000000000000000000000000000010001000100010001")
        (Some b_sub) );
    ( "limbsx: pin e, the borrow chain runs through every limb",
      opt_eq diff
        (L.of_hex
           "7ffffffffffffffffffffffffffffffffffffffffffffffefffefffefffeffff")
    );
    ( "limbsx: pin e, adding the subtrahend back gives the minuend",
      opt_eq (Option.map (fun (d : L.t) -> L.add d b_sub) diff) (Some a_sub) )
  ]

let () =
  run
    (List.concat
       [ construction_checks;
         bytes_checks;
         hex_checks;
         cmp_checks;
         arith_checks;
         bits_checks;
         mod_red_checks;
         mod_pow_checks;
         pin_checks ])
