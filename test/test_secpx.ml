(* M20 secpx: secp256k1 ECDSA verification over a caller-supplied
   digest, and ECDH, through the PUBLIC surface only. The curve record,
   the Jacobian point, the field helpers and the ONE fixed-shape ladder
   are reached by the entry points that use them: every accept row walks
   the ladder, the doubling, the general addition and both Fermat
   inverses, the tcId 202 row walks the P = Q arm of the addition and the
   tcId 203 row walks the P = -Q arm, which gives the point at infinity.

   Every hex constant below is recomputed by harness/diff_secp.py from
   the INPUTS this file names, by a secp256k1 in AFFINE coordinates over
   python integers that shares no formula with the Jacobian OCaml unit.
   That harness re-verifies every embedded Wycheproof vector, valid and
   invalid, and it SIGNS its own generated vector before it reads a pin,
   so a python bug cannot certify an OCaml bug. It also requires each
   constant to sit inside a CHECK ROW of this file, not merely somewhere
   in it, and it strips the row LABEL before it searches, so a pin moved
   into a comment, into an unread let or into a row name turns the gate
   RED. Every pin therefore sits INLINE in the boolean of its own row.

   Three curve values are NOT pinned as text, because no entry point
   takes one and no check row can hold one: b, p - 2 and n - 2. They are
   covered DYNAMICALLY instead. A mistyped b turns every of_xy row and
   every of_scalar row red through the curve test; a mistyped p - 2
   breaks the field inverse and so breaks every row that reads an affine
   point; and a mistyped n - 2 breaks w and so breaks every verify
   accept row.

   The vectors are a subset of the Wycheproof secp256k1 corpus, 20 ECDSA
   tests of ecdsa_secp256k1_sha256_p1363_test.json and 12 ECDH tests of
   ecdh_secp256k1_test.json, plus the draft-computed malleable twin of
   tcId 1 and the vectors the oracle GENERATES at gate time from a
   private key, a nonce and a message that only this milestone holds,
   which are the vectors a mistyped published constant cannot poison.

   The run filter below carries TWO typed wildcards: (_ : string) in the
   filter and (_ : bool) in the printer. No bare wildcard arm appears
   anywhere in this file.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal module by its mangled name, exactly as test_limbsx,
   test_hmacx, test_keccakx and test_p256x do. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module S = Venice__Secpx
module Hx = Venice__Hexx
module B = Venice__Bytesx

(* ---------- readers ---------- *)

(* A strict hex reader: a byte outside the alphabet or an odd length
   gives the empty string, which no length test below accepts. *)
let bytes_of_hex (h : string) : string =
  Option.value ~default:"" (Result.to_option (Hx.decode h))

(* One byte from its code, so a prefix byte is written as a number and
   never as an escape the oracle would have to parse. *)
let byte (code : int) : string = B.of_codes [ code ]

(* A prefix of a byte string, for the wrong-length rows. Bytesx.take is
   total and returns an option; the default is the empty string, which
   every length test rejects. *)
let take_bytes (s : string) (n : int) : string =
  Option.value ~default:"" (B.take s 0 n)

let key_of ~(x : string) ~(y : string) : S.Pubkey.t option =
  S.Pubkey.of_xy ~x:(bytes_of_hex x) ~y:(bytes_of_hex y)

let key_of_hex (h : string) : S.Pubkey.t option =
  S.Pubkey.of_bytes (bytes_of_hex h)

let scalar_of (h : string) : S.Scalar.t option =
  S.Scalar.of_bytes (bytes_of_hex h)

let raw_of ~(r : string) ~(s : string) : S.Signature.t option =
  S.Signature.of_raw (bytes_of_hex (r ^ s))

let key_bytes (o : S.Pubkey.t option) : string =
  Option.fold ~none:"" ~some:(fun (k : S.Pubkey.t) -> S.Pubkey.to_bytes k) o

let key_hex (o : S.Pubkey.t option) : string = Hx.encode (key_bytes o)

let sec1_hex (o : S.Pubkey.t option) : string =
  Hx.encode
    (Option.fold ~none:"" ~some:(fun (k : S.Pubkey.t) -> S.Pubkey.to_sec1 k) o)

let sig_hex (o : S.Signature.t option) : string =
  Hx.encode
    (Option.fold ~none:""
       ~some:(fun (sg : S.Signature.t) -> S.Signature.to_raw sg)
       o)

let scalar_hex (h : string) : string =
  Hx.encode
    (Option.fold ~none:""
       ~some:(fun (d : S.Scalar.t) -> S.Scalar.to_bytes d)
       (scalar_of h))

let key_eq (a : S.Pubkey.t option) (v : S.Pubkey.t option) : bool =
  Option.fold ~none:false
    ~some:(fun (k : S.Pubkey.t) ->
      Option.fold ~none:false ~some:(S.Pubkey.equal k) v)
    a

(* d G through the ONE ladder, as lowercase X || Y hex. *)
let pub_of_scalar_hex (h : string) : string =
  key_hex
    (Option.bind (scalar_of h) (fun (d : S.Scalar.t) -> S.Pubkey.of_scalar d))

let verify_hex ~(x : string) ~(y : string) ~(r : string) ~(s : string)
    ~(digest : string) : bool =
  Option.fold ~none:false
    ~some:(fun (k : S.Pubkey.t) ->
      Option.fold ~none:false
        ~some:(fun (sg : S.Signature.t) ->
          S.verify k sg ~digest:(bytes_of_hex digest))
        (raw_of ~r ~s))
    (key_of ~x ~y)

(* A MATH rejection: the signature is well formed, so of_raw mints it,
   and verify still returns false. *)
let math_reject ~(x : string) ~(y : string) ~(r : string) ~(s : string)
    ~(digest : string) : bool =
  Option.is_some (raw_of ~r ~s) && not (verify_hex ~x ~y ~r ~s ~digest)

(* A PSYCHIC rejection: of_raw returns None before any point math runs,
   because r or s sits outside 1 .. n-1. *)
let psychic_reject ~(r : string) ~(s : string) : bool =
  not (Option.is_some (raw_of ~r ~s))

(* The Wycheproof shared field: the 32-byte x of d Q, as hex. *)
let shared_hex ~(d : string) ~(pub : string) : string =
  Option.value ~default:""
    (Option.bind (scalar_of d) (fun (dv : S.Scalar.t) ->
         Option.bind (key_of_hex pub) (fun (k : S.Pubkey.t) ->
             Option.map Hx.encode (S.shared_x dv k))))

let shared_key ~(d : string) ~(pub : string) : S.Pubkey.t option =
  Option.bind (scalar_of d) (fun (dv : S.Scalar.t) ->
      Option.bind (key_of_hex pub) (fun (k : S.Pubkey.t) ->
          S.shared_point dv k))

(* ---------- group (a): the constants and the curve identities ------- *)

let curve_checks : (string * bool) list =
  [ ( "secpx: of_scalar of 1 gives the base point",
      String.equal
        (pub_of_scalar_hex
           "0000000000000000000000000000000000000000000000000000000000000001")
        ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
       ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
    ( "secpx: of_scalar of 2 gives the pinned doubling of the base point",
      String.equal
        (pub_of_scalar_hex
           "0000000000000000000000000000000000000000000000000000000000000002")
        ("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
       ^ "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a")
    );
    ( "secpx: of_scalar of n - 1 gives the base point with the negated y",
      String.equal
        (pub_of_scalar_hex
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
        ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
       ^ "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777")
    );
    ( "secpx: the base point is accepted through of_xy",
      Option.is_some
        (key_of
           ~x:"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
           ~y:"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
    ( "secpx: the base point round-trips through to_bytes and of_bytes",
      key_eq
        (key_of_hex
           ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        (key_of
           ~x:"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
           ~y:"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
    ("secpx: the digest length is 32 bytes", Int.equal (S.digest_len ()) 32)
  ]

(* ---------- group (b): Scalar, the 1 .. n-1 construction rule ------- *)

let scalar_checks : (string * bool) list =
  [ ( "secpx: the zero scalar is None",
      not
        (Option.is_some
           (scalar_of
              "0000000000000000000000000000000000000000000000000000000000000000"))
    );
    ( "secpx: the scalar n is None",
      not
        (Option.is_some
           (scalar_of
              "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"))
    );
    ( "secpx: the scalar n + 1 is None",
      not
        (Option.is_some
           (scalar_of
              "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"))
    );
    ( "secpx: the scalar 2^256 - 1 is None",
      not
        (Option.is_some
           (scalar_of
              "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
    );
    ( "secpx: a 31-byte scalar is None",
      not
        (Option.is_some
           (scalar_of
              "00000000000000000000000000000000000000000000000000000000000001"))
    );
    ( "secpx: a 33-byte scalar with a leading zero byte is None",
      not
        (Option.is_some
           (scalar_of
              "000000000000000000000000000000000000000000000000000000000000000001"))
    );
    ( "secpx: the scalar 1 is Some and round-trips through to_bytes",
      Option.is_some
        (scalar_of
           "0000000000000000000000000000000000000000000000000000000000000001")
      && String.equal
           (scalar_hex
              "0000000000000000000000000000000000000000000000000000000000000001")
           "0000000000000000000000000000000000000000000000000000000000000001"
    );
    ( "secpx: the scalar n - 1 is Some",
      Option.is_some
        (scalar_of
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
    );
    ( "secpx: the scalar n - 1 round-trips through to_bytes",
      String.equal
        (scalar_hex
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
    );
    ( "secpx: the scalar 2^255 is Some",
      Option.is_some
        (scalar_of
           "8000000000000000000000000000000000000000000000000000000000000000")
    );
    ( "secpx: the scalar 2^255 round-trips through to_bytes",
      String.equal
        (scalar_hex
           "8000000000000000000000000000000000000000000000000000000000000000")
        "8000000000000000000000000000000000000000000000000000000000000000"
    )
  ]

(* ---------- group (c): the Pubkey encodings ---------- *)

let pubkey_checks : (string * bool) list =
  [ ( "secpx: of_bytes on the 64-byte X || Y form gives a key",
      Option.is_some
        (key_of_hex
           ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    );
    ( "secpx: the 65-byte 0x04 form gives the same key as the 64-byte form",
      key_eq
        (S.Pubkey.of_bytes
           (byte 4
           ^ bytes_of_hex
               "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
           ^ bytes_of_hex
               "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        (key_of
           ~x:"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
           ~y:"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
    ( "secpx: a 65-byte key under a 0x02 prefix is rejected",
      not
        (Option.is_some
           (S.Pubkey.of_bytes
              (byte 2
              ^ bytes_of_hex
                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              ^ bytes_of_hex
                  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")))
    );
    ( "secpx: a 65-byte key under a 0x03 prefix is rejected",
      not
        (Option.is_some
           (S.Pubkey.of_bytes
              (byte 3
              ^ bytes_of_hex
                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              ^ bytes_of_hex
                  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")))
    );
    ( "secpx: a 65-byte key under a 0x05 prefix is rejected",
      not
        (Option.is_some
           (S.Pubkey.of_bytes
              (byte 5
              ^ bytes_of_hex
                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              ^ bytes_of_hex
                  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")))
    );
    ( "secpx: a 63-byte key is rejected",
      not
        (Option.is_some
           (S.Pubkey.of_bytes
              (take_bytes
                 (bytes_of_hex
                    ("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                   ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
                 63)))
    );
    ( "secpx: a 66-byte key is rejected",
      not
        (Option.is_some
           (S.Pubkey.of_bytes
              (byte 4
              ^ bytes_of_hex
                  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              ^ bytes_of_hex
                  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
              ^ byte 0)))
    );
    ( "secpx: the 33-byte compressed form is rejected, no decompression",
      not
        (Option.is_some
           (key_of_hex
              "02d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b"))
    );
    ( "secpx: of_xy with x = p is rejected",
      not
        (Option.is_some
           (key_of
              ~x:
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
              ~y:
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    );
    ( "secpx: of_xy with gy's last bit flipped is off the curve",
      not
        (Option.is_some
           (key_of
              ~x:
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              ~y:
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9"))
    );
    ( "secpx: of_xy on the zero pair is rejected, 0 = 7 has no solution",
      not
        (Option.is_some
           (key_of
              ~x:
                "0000000000000000000000000000000000000000000000000000000000000000"
              ~y:
                "0000000000000000000000000000000000000000000000000000000000000000"))
    );
    ( "secpx: to_bytes gives 64 bytes",
      Int.equal
        (String.length
           (key_bytes
              (key_of
                 ~x:
                   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                 ~y:
                   "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")))
        64
    );
    ( "secpx: to_sec1 gives 65 bytes with a leading 0x04",
      String.equal
        (sec1_hex
           (key_of
              ~x:
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              ~y:
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        ("04"
       ^ "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
       ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
    ( "secpx: equal is false between the base point and its doubling",
      not
        (key_eq
           (key_of
              ~x:
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
              ~y:
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
           (key_of
              ~x:
                "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
              ~y:
                "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"))
    )
  ]

(* ---------- group (d): Signature, the psychic rejects and the shape - *)

let signature_checks : (string * bool) list =
  [ ( "secpx: of_raw with r = 0 is None",
      psychic_reject
        ~r:"0000000000000000000000000000000000000000000000000000000000000000"
        ~s:"900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87"
    );
    ( "secpx: of_raw with s = 0 is None",
      psychic_reject
        ~r:"813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        ~s:"0000000000000000000000000000000000000000000000000000000000000000"
    );
    ( "secpx: of_raw with r = n is None",
      psychic_reject
        ~r:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ~s:"900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87"
    );
    ( "secpx: of_raw with s = n is None",
      psychic_reject
        ~r:"813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        ~s:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    );
    ( "secpx: of_raw with r = p is None",
      psychic_reject
        ~r:"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        ~s:"900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87"
    );
    ( "secpx: of_raw with r = n - 1 and an in-range s is Some",
      Option.is_some
        (raw_of
           ~r:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
           ~s:"900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87")
    );
    ( "secpx: of_raw on 63 bytes is None",
      not
        (Option.is_some
           (S.Signature.of_raw
              (take_bytes
                 (bytes_of_hex
                    ("813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
                   ^ "900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87"))
                 63)))
    );
    ( "secpx: of_raw on 65 bytes is None",
      not
        (Option.is_some
           (S.Signature.of_raw
              (bytes_of_hex
                 ("813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
                ^ "900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87")
              ^ byte 0)))
    );
    ( "secpx: of_rs with a 33-byte half is None",
      not
        (Option.is_some
           (S.Signature.of_rs
              ~r:
                (bytes_of_hex
                   "000000000000000000000000000000000000000000000000000000000000000001")
              ~s:(bytes_of_hex "01")))
    );
    ( "secpx: of_rs with two one-byte halves is Some and to_raw pads both",
      String.equal
        (sig_hex
           (S.Signature.of_rs ~r:(bytes_of_hex "07") ~s:(bytes_of_hex "09")))
        ("0000000000000000000000000000000000000000000000000000000000000007"
       ^ "0000000000000000000000000000000000000000000000000000000000000009")
    )
  ]

(* ---------- group (e): the Wycheproof ECDSA subset, one row a vector -

   ecdsa_secp256k1_sha256_p1363_test.json, 20 tests by tcId plus the
   draft-computed malleable twin of tcId 1. A VALID vector's row asserts
   verify true; a PSYCHIC or a WRONG-LENGTH vector's row asserts the
   constructor is None; a MATH vector's row asserts the constructor is
   Some and verify false. *)

let wycheproof_ecdsa_checks : (string * bool) list =
  [ ( "secpx: wycheproof ecdsa tcId 1, signature malleability, valid",
      verify_hex
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        ~s:"900e75ad233fcc908509dbff5922647db37c21f4afd3203ae8dc4ae7794b0f87"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    );
    ( "secpx: the draft-computed malleable twin of tcId 1 verifies as well",
      verify_hex
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365"
        ~s:"6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    );
    ( "secpx: wycheproof ecdsa tcId 2, replaced r by r + n, 66 bytes, invalid",
      not
        (Option.is_some
           (S.Signature.of_raw
              (bytes_of_hex
                 "01813ef79ccefa9a56f7ba805f0e478583b90deabca4b05c4574e49b5899b964a6006ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba")))
    );
    ( "secpx: wycheproof ecdsa tcId 4, replaced r by n - r, invalid",
      math_reject
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"7ec10863310565a908457fa0f1b87a79bc4fcf10b9e0e4320ac021c106b31ddc"
        ~s:"6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    );
    ( "secpx: wycheproof ecdsa tcId 11, r and s are both 0, invalid",
      psychic_reject
        ~r:"0000000000000000000000000000000000000000000000000000000000000000"
        ~s:"0000000000000000000000000000000000000000000000000000000000000000"
    );
    ( "secpx: wycheproof ecdsa tcId 12, r is 0 and s is 1, invalid",
      psychic_reject
        ~r:"0000000000000000000000000000000000000000000000000000000000000000"
        ~s:"0000000000000000000000000000000000000000000000000000000000000001"
    );
    ( "secpx: wycheproof ecdsa tcId 18, r is 1 and s is 0, invalid",
      psychic_reject
        ~r:"0000000000000000000000000000000000000000000000000000000000000001"
        ~s:"0000000000000000000000000000000000000000000000000000000000000000"
    );
    ( "secpx: wycheproof ecdsa tcId 19, r is 1 and s is 1, invalid",
      math_reject
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"0000000000000000000000000000000000000000000000000000000000000001"
        ~s:"0000000000000000000000000000000000000000000000000000000000000001"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    );
    ( "secpx: wycheproof ecdsa tcId 20, r is 1 and s is the group order",
      psychic_reject
        ~r:"0000000000000000000000000000000000000000000000000000000000000001"
        ~s:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    );
    ( "secpx: wycheproof ecdsa tcId 27, r and s are both the group order",
      psychic_reject
        ~r:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        ~s:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    );
    ( "secpx: wycheproof ecdsa tcId 35, r and s are both n - 1, invalid",
      math_reject
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        ~s:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    );
    ( "secpx: wycheproof ecdsa tcId 43, r and s are both n + 1, invalid",
      psychic_reject
        ~r:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
        ~s:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"
    );
    ( "secpx: wycheproof ecdsa tcId 51, r and s are both the field prime",
      psychic_reject
        ~r:"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        ~s:"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    );
    ( "secpx: wycheproof ecdsa tcId 60, edge case for Shamir, valid",
      verify_hex
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"dd1b7d09a7bd8218961034a39a87fecf5314f00c4d25eb58a07ac85e85eab516"
        ~s:"35138c401ef8d3493d65c9002fe62b43aee568731b744548358996d9cc427e06"
        ~digest:
          "b78f33ca6d031315ab4c29b4429e6e8f8978517d49192c90fb2266bea6842918"
    );
    ( "secpx: wycheproof ecdsa tcId 61, hash with leading zero bytes, valid",
      verify_hex
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"95c29267d972a043d955224546222bba343fc1d4db0fec262a33ac61305696ae"
        ~s:"6edfe96713aed56f8a28a6653f57e0b829712e5eddc67f34682b24f0676b2640"
        ~digest:
          "00000000690ed426ccf17803ebe2bd0884bcd58a1bb5e7477ead3645f356e7a9"
    );
    ( "secpx: wycheproof ecdsa tcId 114, hash with trailing ff bytes, valid",
      verify_hex
        ~x:"b838ff44e5bc177bf21189d0766082fc9d843226887fc9760371100b7ee20a6f"
        ~y:"f0c9d75bfba7b31a6bca1974496eeb56de357071955d83c4b1badaa0b21832e9"
        ~r:"52c683144e44119ae2013749d4964ef67509278f6d38ba869adcfa69970e123d"
        ~s:"3479910167408f45bda420a626ec9c4ec711c1274be092198b4187c018b562ca"
        ~digest:
          "d59291cc2cf89f3087715fcb1aa4e79aa2403f748e97d7cd28ecaefeffffffff"
    );
    ( "secpx: wycheproof ecdsa tcId 115, k G has a large x, valid, and the \
       final compare reduces x(R) by the group order",
      verify_hex
        ~x:"07310f90a9eae149a08402f54194a0f7b4ac427bf8d9bd6c7681071dc47dc362"
        ~y:"26a6d37ac46d61fd600c0bf1bff87689ed117dda6b0e59318ae010a197a26ca0"
        ~r:"000000000000000000000000000000014551231950b75fc4402da1722fc9baeb"
        ~s:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    );
    ( "secpx: wycheproof ecdsa tcId 116, r is too large, invalid",
      psychic_reject
        ~r:"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c"
        ~s:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413e"
    );
    ( "secpx: wycheproof ecdsa tcId 121, incorrect size of signature, invalid",
      not (Option.is_some (S.Signature.of_raw (bytes_of_hex "0101")))
    );
    ( "secpx: wycheproof ecdsa tcId 202, point duplication, valid",
      verify_hex
        ~x:"2ea7133432339c69d27f9b267281bd2ddd5f19d6338d400a05cd3647b157a385"
        ~y:"3547808298448edb5e701ade84cd5fb1ac9567ba5e8fb68a6b933ec4b5cc84cc"
        ~r:"32b0d10d8d0e04bc8d4d064d270699e87cffc9b49c5c20730e1c26f6105ddcda"
        ~s:"d612c2984c2afa416aa7f2882a486d4a8426cb6cfc91ed5b737278f9fca8be68"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    );
    ( "secpx: wycheproof ecdsa tcId 203, the duplication bug, same signature \
       under the negated key, invalid",
      math_reject
        ~x:"2ea7133432339c69d27f9b267281bd2ddd5f19d6338d400a05cd3647b157a385"
        ~y:"cab87f7d67bb7124a18fe5217b32a04e536a9845a1704975946cc13a4a337763"
        ~r:"32b0d10d8d0e04bc8d4d064d270699e87cffc9b49c5c20730e1c26f6105ddcda"
        ~s:"d612c2984c2afa416aa7f2882a486d4a8426cb6cfc91ed5b737278f9fca8be68"
        ~digest:
          "bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023"
    )
  ]

(* ---------- group (f): the Wycheproof ECDH subset, one row a vector -

   ecdh_secp256k1_test.json, 12 tests by tcId. Each public point is
   written as ONE 128-character literal, X then Y, which is the shape
   Pubkey.of_bytes reads and the shape the oracle pins. A VALID vector's
   row asserts shared_x; an OFF-CURVE vector's row asserts the key is
   None; the compressed vector is an M20 scope exclusion, so its row
   asserts both point forms are None. *)

let wycheproof_ecdh_checks : (string * bool) list =
  [ ( "secpx: wycheproof ecdh tcId 1, normal case, the shared x agrees and \
       the shared POINT re-validates as a public key",
      let d =
        "f4b7ff7cccc98813a69fae3df222bfe3f4e28f764bf91b4a10d8096ce446b254"
      in
      let pub =
        "d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b396812ea1686e7472e9692eaf3e958e50e9500d3b4c77243db1f2acd67ba9cc4"
      in
      String.equal (shared_hex ~d ~pub)
        "544dfae22af6af939042b1d85b71a1e49e9a5614123c4d6ad0c8af65baf87d65"
      && Option.is_some (shared_key ~d ~pub) );
    ( "secpx: wycheproof ecdh tcId 3, shared x is 1",
      String.equal
        (shared_hex
           ~d:"a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a"
           ~pub:
             "965ff42d654e058ee7317cced7caf093fbb180d8d3a74b0dcd9d8cd47a39d5cb9c2aa4daac01a4be37c20467ede964662f12983e0b5272a47a5f2785685d8087")
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    ( "secpx: wycheproof ecdh tcId 4, shared x is 2",
      String.equal
        (shared_hex
           ~d:"a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a"
           ~pub:
             "06c4b87ba76c6dcb101f54a050a086aa2cb0722f03137df5a922472f1bdc11b982e3c735c4b6c481d09269559f080ad08632f370a054af12c1fd1eced2ea9211")
        "0000000000000000000000000000000000000000000000000000000000000002"
    );
    ( "secpx: wycheproof ecdh tcId 5, shared x is 3",
      String.equal
        (shared_hex
           ~d:"a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a"
           ~pub:
             "bba30eef7967a2f2f08a2ffadac0e41fd4db12a93cef0b045b5706f2853821e6d50b2bf8cbf530e619869e07c021ef16f693cfc0a4b0d4ed5a8f464692bf3d6e")
        "0000000000000000000000000000000000000000000000000000000000000003"
    );
    ( "secpx: wycheproof ecdh tcId 6, shared x is p - 3",
      String.equal
        (shared_hex
           ~d:"a2b6442a37f8a3764aeff4011a4c422b389a1e509669c43f279c8b7e32d80c3a"
           ~pub:
             "6da9eb2cdac02122d5f05cf6a8cd768e378f664ea4a7871d10e25f57eb1ee1cc5b2b5abf9c6c6596f8f383ddbcb3bcc2d5a7cc605984931239ca9669946032ee")
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c"
    );
    ( "secpx: wycheproof ecdh tcId 459, one-byte private key, left-padded to \
       32 bytes",
      String.equal
        (shared_hex
           ~d:"0000000000000000000000000000000000000000000000000000000000000003"
           ~pub:
             "32bdd978eb62b1f369a56d0949ab8551a7ad527d9602e891ce457586c2a8569e981e67fae053b03fc33e1a291f0a3beb58fceb2e85bb1205dacee1232dfd316b")
        "34005694e3cac09332aa42807e3afdc3b3b3bc7c7be887d1f98d76778c55cfd7"
    );
    ( "secpx: wycheproof ecdh tcId 460, 29-byte private key, left-padded to \
       32 bytes",
      String.equal
        (shared_hex
           ~d:"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
           ~pub:
             "32bdd978eb62b1f369a56d0949ab8551a7ad527d9602e891ce457586c2a8569e981e67fae053b03fc33e1a291f0a3beb58fceb2e85bb1205dacee1232dfd316b")
        "5841acd3cff2d62861bbe11084738006d68ccf35acae615ee9524726e93d0da5"
    );
    ( "secpx: wycheproof ecdh tcId 475, the zero pair is off the curve",
      not
        (Option.is_some
           (key_of_hex
              "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
    );
    ( "secpx: wycheproof ecdh tcId 479, x is 1 and y is 0, off the curve",
      not
        (Option.is_some
           (key_of_hex
              "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"))
    );
    ( "secpx: wycheproof ecdh tcId 485, p - 1 twice, off the curve",
      not
        (Option.is_some
           (key_of_hex
              "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e"))
    );
    ( "secpx: wycheproof ecdh tcId 490, p twice, at the field prime, rejected \
       before the curve test",
      not
        (Option.is_some
           (key_of_hex
              "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"))
    );
    ( "secpx: wycheproof ecdh tcId 2, both compressed forms are rejected, an \
       M20 scope exclusion",
      (not
         (Option.is_some
            (S.Pubkey.of_bytes
               (bytes_of_hex
                  "02d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b"))))
      && not
           (Option.is_some
              (S.Pubkey.of_bytes
                 (bytes_of_hex
                    "03d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b")))
    )
  ]

(* ---------- group (g): the generated vectors ------------------------

   Nothing here is a Wycheproof value. The harness recomputes every one
   of them from the curve law, so the suite and the oracle agree only
   when both walks agree. The signing secret is the big-endian integer
   of the message bytes, and the two ECDH scalars are round powers of
   two plus a small odd constant. *)

let generated_checks : (string * bool) list =
  [ ( "secpx: the generated signing key d G has the pinned coordinates",
      String.equal
        (pub_of_scalar_hex
           "0000000000000000000076656e6963652d6f63616d6c206d3230207365637078")
        ("faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
       ^ "dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1")
    );
    ( "secpx: the generated signature verifies under the generated key",
      verify_hex
        ~x:"faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
        ~y:"dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1"
        ~r:"d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0"
        ~s:"6a7041b9df179c76b4e7e86b89ace566e76c08d8ba660a146c476f723e90e4c7"
        ~digest:
          "87f9faaefe8a069f022c2bbe069c549aa058c94a5680692cbba0a8fcde0d7e7b"
    );
    ( "secpx: the malleable twin (r, n - s) of the generated signature \
       verifies as well, because the standard carries no low-s rule",
      verify_hex
        ~x:"faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
        ~y:"dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1"
        ~r:"d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0"
        ~s:"958fbe4620e863894b18179476531a97d342d40df4e29627538aef1a91a55c7a"
        ~digest:
          "87f9faaefe8a069f022c2bbe069c549aa058c94a5680692cbba0a8fcde0d7e7b"
    );
    ( "secpx: the generated signature fails under a digest of one flipped \
       nibble",
      math_reject
        ~x:"faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
        ~y:"dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1"
        ~r:"d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0"
        ~s:"6a7041b9df179c76b4e7e86b89ace566e76c08d8ba660a146c476f723e90e4c7"
        ~digest:
          "87f9faaefe8a069f022c2bbe069c549aa058c94a5680692cbba0a8fcde0d7e7a"
    );
    ( "secpx: the generated ECDH key A is da G",
      String.equal
        (pub_of_scalar_hex
           "0000000000000100000000000000000000000000000000000000000000000007")
        ("a5415496ed54f41daa134e10d91925e0dc962fa4fbb7372006781b3b69d0fb60"
       ^ "63c62edce476b3fa4cfd92adf7816734ab18eb1760c02588923285344960ddfe")
    );
    ( "secpx: the generated ECDH key B is db G",
      String.equal
        (pub_of_scalar_hex
           "000000000000000000000000000000000000001000000000000000000000000b")
        ("94b32e5d15041c3b8773c454fe4cef707a9a1867f06238dc8fa0afa90813d7bf"
       ^ "a2b2dd48c683e5c830321dda407c2baf77b8b8d1620b031557ec641d198158be")
    );
    ( "secpx: da B and db A agree on the pinned shared x",
      String.equal
        (shared_hex
           ~d:"0000000000000100000000000000000000000000000000000000000000000007"
           ~pub:
             "94b32e5d15041c3b8773c454fe4cef707a9a1867f06238dc8fa0afa90813d7bfa2b2dd48c683e5c830321dda407c2baf77b8b8d1620b031557ec641d198158be")
        "21149db0e3cf824c897b8193c4759fc31ac484bb67ed10732353a911086e4ea3"
      && String.equal
           (shared_hex
              ~d:"000000000000000000000000000000000000001000000000000000000000000b"
              ~pub:
                "a5415496ed54f41daa134e10d91925e0dc962fa4fbb7372006781b3b69d0fb6063c62edce476b3fa4cfd92adf7816734ab18eb1760c02588923285344960ddfe")
           "21149db0e3cf824c897b8193c4759fc31ac484bb67ed10732353a911086e4ea3"
    )
  ]

(* ---------- group (h): the digest length rule -----------------------

   verify takes a digest of exactly digest_len () bytes. The
   zero-prefixed row is the one that matters: 33 bytes whose first byte
   is zero carry the same big-endian integer as the 32-byte digest, so a
   length test that read the INTEGER would accept it. *)

let digest_checks : (string * bool) list =
  [ ("secpx: the accepted digest size is 32 bytes", S.digest_len () = 32);
    ( "secpx: a digest of 31 bytes is rejected, even though the signature is \
       well formed",
      math_reject
        ~x:"faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
        ~y:"dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1"
        ~r:"d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0"
        ~s:"6a7041b9df179c76b4e7e86b89ace566e76c08d8ba660a146c476f723e90e4c7"
        ~digest:"87f9faaefe8a069f022c2bbe069c549aa058c94a5680692cbba0a8fcde0d7e"
    );
    ( "secpx: a digest of 33 bytes with a leading zero byte is rejected, \
       although it carries the same integer",
      math_reject
        ~x:"faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
        ~y:"dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1"
        ~r:"d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0"
        ~s:"6a7041b9df179c76b4e7e86b89ace566e76c08d8ba660a146c476f723e90e4c7"
        ~digest:
          ("00"
          ^ "87f9faaefe8a069f022c2bbe069c549aa058c94a5680692cbba0a8fcde0d7e7b")
    );
    ( "secpx: an empty digest is rejected", 
      math_reject
        ~x:"faca1afad9e59c9d5257e77330abf30d541398940303ad4920ccf8bfbdd251fb"
        ~y:"dce9f06850f13d3848e10aac5f7f41a4da532e69ad0a607961b3c8d6f8f98bd1"
        ~r:"d2083f9e07d640f2764fc7912d2f204420eceb4f0c00dd6eadba3cee444245e0"
        ~s:"6a7041b9df179c76b4e7e86b89ace566e76c08d8ba660a146c476f723e90e4c7"
        ~digest:""
    )
  ]

let () =
  run
    (curve_checks @ scalar_checks @ pubkey_checks @ signature_checks
   @ wycheproof_ecdsa_checks @ wycheproof_ecdh_checks @ generated_checks
   @ digest_checks)
