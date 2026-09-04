(* M17 hmacx: HMAC-SHA256 and HKDF-SHA256 through the PUBLIC surface
   only. The private helpers (pad_key, xor_with) are reached by the
   entrypoints that use them: a short key that is zero-padded, a
   131-byte key that is hashed first, an expansion that chains blocks.

   The hex constants below are recomputed by harness/diff_hmac.py with
   python's hmac and hashlib from the RFC INPUTS, and that harness
   requires each one to sit inside a CHECK ROW of this file, not merely
   somewhere in it. Moving a pin into a comment or into an unread let
   turns the gate RED. The inputs are built here from byte codes, so an
   input that drifts from the RFC text turns its row false.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal module by its mangled name, exactly as test_limbsx
   and test_clientx do. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module H = Venice__Hmacx
module Hx = Venice__Hexx
module B = Venice__Bytesx

(* ---------- readers ---------- *)

let hex (s : string) : string = Hx.encode s

(* n copies of one byte, and n ascending bytes from first: the RFC
   inputs are written as byte codes, never as hex text, so the suite
   and the oracle agree on the INPUTS by construction. *)
let rep (n : int) (code : int) : string =
  B.of_codes (List.init (Int.max n 0) (fun (_ : int) -> code))

let ascending (first : int) (n : int) : string =
  B.of_codes (List.init (Int.max n 0) (fun (i : int) -> first + i))

let hex_is (o : string option) (want : string) : bool =
  Option.fold ~none:false
    ~some:(fun (s : string) -> String.equal (hex s) want)
    o

let len_is (o : string option) (want : int) : bool =
  Option.fold ~none:false
    ~some:(fun (s : string) -> Int.equal (String.length s) want)
    o

let sopt_eq (a : string option) (b : string option) : bool =
  Option.fold ~none:false
    ~some:(fun (x : string) ->
      Option.fold ~none:false ~some:(String.equal x) b)
    a

(* A one-bit flip in the byte at off, total: an out-of-range offset
   leaves the string untouched, so a broken helper cannot silently make
   a difference row pass. *)
let flip (s : string) (off : int) : string =
  B.of_codes
    (List.mapi
       (fun (i : int) (c : char) ->
         match () with
         | () when Int.equal i off -> Char.code c lxor 1
         | () -> Char.code c)
       (List.of_seq (String.to_seq s)))

(* ---------- the RFC 4231 section 4 inputs ---------- *)

let k1 : string = rep 20 0x0b
let m1 : string = "Hi There"
let k2 : string = "Jefe"
let m2 : string = "what do ya want for nothing?"
let k3 : string = rep 20 0xaa
let m3 : string = rep 50 0xdd
let k4 : string = ascending 0x01 25
let m4 : string = rep 50 0xcd
let k5 : string = rep 20 0x0c
let m5 : string = "Test With Truncation"
let k6 : string = rep 131 0xaa
let m6 : string = "Test Using Larger Than Block-Size Key - Hash Key First"
let k7 : string = rep 131 0xaa

let m7 : string =
  "This is a test using a larger than block-size key and a larger than "
  ^ "block-size data. The key needs to be hashed before being used by "
  ^ "the HMAC algorithm."

let t1 : string = H.sha256 ~key:k1 m1
let t5 : string = H.sha256 ~key:k5 m5

(* ---------- the key-length boundaries ---------- *)

let bmsg : string = "boundary"

(* ---------- the RFC 5869 appendix A inputs ---------- *)

let ikm1 : string = rep 22 0x0b
let salt1 : string = ascending 0x00 13
let info1 : string = ascending 0xf0 10
let ikm2 : string = ascending 0x00 80
let salt2 : string = ascending 0x60 80
let info2 : string = ascending 0xb0 80
let ikm3 : string = rep 22 0x0b
let prk1 : H.Hkdf.prk = H.Hkdf.extract ~salt:salt1 ~ikm:ikm1
let prk2 : H.Hkdf.prk = H.Hkdf.extract ~salt:salt2 ~ikm:ikm2
let prk3 : H.Hkdf.prk = H.Hkdf.extract ~salt:"" ~ikm:ikm3
let okm1 : string option = H.Hkdf.expand prk1 ~info:info1 ~len:42
let okm2 : string option = H.Hkdf.expand prk2 ~info:info2 ~len:82
let okm3 : string option = H.Hkdf.expand prk3 ~info:"" ~len:42
let cap : string option = H.Hkdf.expand prk1 ~info:info1 ~len:(H.Hkdf.max_len ())

let cap_last : string option =
  Option.bind cap (fun (s : string) ->
      B.take s (String.length s - H.hash_len ()) (H.hash_len ()))

(* ---------- the checks ---------- *)

let rfc4231_checks : (string * bool) list =
  [ ( "hmacx: RFC 4231 case 1, a 20-byte key over Hi There",
      String.equal (hex t1)
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" );
    ( "hmacx: RFC 4231 case 1 tag is hash_len () bytes",
      Int.equal (String.length t1) (H.hash_len ()) );
    ( "hmacx: RFC 4231 case 2, a 4-byte key",
      String.equal
        (hex (H.sha256 ~key:k2 m2))
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" );
    ( "hmacx: RFC 4231 case 3, a 50-byte message of 0xdd",
      String.equal
        (hex (H.sha256 ~key:k3 m3))
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" );
    ( "hmacx: RFC 4231 case 4, an ascending 25-byte key",
      String.equal
        (hex (H.sha256 ~key:k4 m4))
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" );
    ( "hmacx: RFC 4231 case 5, the tag truncated to 128 bits",
      hex_is (B.take t5 0 16) "a3b6167473100ee06e0c796c2955552b" );
    ( "hmacx: RFC 4231 case 5, the truncation is 16 bytes",
      len_is (B.take t5 0 16) 16 );
    ( "hmacx: RFC 4231 case 6, a 131-byte key is hashed first",
      String.equal
        (hex (H.sha256 ~key:k6 m6))
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" );
    ( "hmacx: RFC 4231 case 6, that key is longer than block_size ()",
      String.length k6 > H.block_size () );
    ( "hmacx: RFC 4231 case 7, a 131-byte key over a 152-byte message",
      String.equal
        (hex (H.sha256 ~key:k7 m7))
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" );
    ( "hmacx: RFC 4231 cases 6 and 7 share a key and differ by message",
      String.equal k6 k7
      && not (String.equal (H.sha256 ~key:k6 m6) (H.sha256 ~key:k7 m7)) ) ]

let boundary_checks : (string * bool) list =
  [ ( "hmacx: boundary, an empty key over boundary",
      String.equal
        (hex (H.sha256 ~key:(rep 0 0x0b) bmsg))
        "2c6150df91d94a25a8bf27130093b7a25b6ac1238c7092be2efffc3040248e73" );
    ( "hmacx: boundary, a 63-byte key is zero-padded to one block",
      String.equal
        (hex (H.sha256 ~key:(rep 63 0x0b) bmsg))
        "69dd3b2a23ab1bd7d3fa380f9fe18089b94473bd755694f7ddab9e1c313b16fd" );
    ( "hmacx: boundary, a 64-byte key is used as it stands",
      String.equal
        (hex (H.sha256 ~key:(rep 64 0x0b) bmsg))
        "ed9fcf831879b0334eb8680861331b8e6fc144881818fe12200d1127275e0fb7" );
    ( "hmacx: boundary, a 65-byte key crosses into the hashed branch",
      String.equal
        (hex (H.sha256 ~key:(rep 65 0x0b) bmsg))
        "3288ffa348abfa666d98b69361c6b2f2d9eb39d31576581bf893c3457a43387b" );
    ( "hmacx: boundary, a 128-byte key is hashed to 32 bytes",
      String.equal
        (hex (H.sha256 ~key:(rep 128 0x0b) bmsg))
        "f7625c02aa9bd26f3eeba32ca070443b4682591f19a46fac7f66f0b2ef91e462" );
    ( "hmacx: boundary, 64 bytes and 65 bytes of key give different tags",
      not
        (String.equal
           (H.sha256 ~key:(rep 64 0x0b) bmsg)
           (H.sha256 ~key:(rep 65 0x0b) bmsg)) );
    ( "hmacx: boundary, the empty key over the empty message",
      String.equal (hex (H.sha256 ~key:"" ""))
        "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad" ) ]

let equal_ct_checks : (string * bool) list =
  [ ("hmacx: equal_ct holds on equal strings", H.equal_ct "abc" "abc");
    ("hmacx: equal_ct holds on a tag against itself", H.equal_ct t1 t1);
    ( "hmacx: equal_ct rejects a one-bit difference in the FIRST byte",
      not (H.equal_ct t1 (flip t1 0)) );
    ( "hmacx: equal_ct rejects a one-bit difference in the LAST byte",
      not (H.equal_ct t1 (flip t1 (String.length t1 - 1))) );
    ( "hmacx: equal_ct rejects a shorter second string, which Seq.zip \
       alone would call equal",
      not (H.equal_ct "abc" "ab") );
    ( "hmacx: equal_ct rejects a shorter first string",
      not (H.equal_ct "ab" "abc") );
    ("hmacx: equal_ct holds on two empty strings", H.equal_ct "" "") ]

let verify_checks : (string * bool) list =
  [ ("hmacx: verify accepts the true tag", H.verify ~key:k1 m1 ~tag:t1);
    ( "hmacx: verify rejects a tag with one bit flipped",
      not (H.verify ~key:k1 m1 ~tag:(flip t1 7)) );
    ( "hmacx: verify rejects the true tag under the wrong key",
      not (H.verify ~key:k3 m1 ~tag:t1) );
    ( "hmacx: verify rejects a 31-byte tag",
      not
        (H.verify ~key:k1 m1
           ~tag:(Option.value (B.take t1 0 31) ~default:"")) );
    ("hmacx: verify rejects an empty tag", not (H.verify ~key:k1 m1 ~tag:"")) ]

let hkdf_checks : (string * bool) list =
  [ ( "hmacx: RFC 5869 case 1 PRK, a 13-byte salt over a 22-byte IKM",
      String.equal
        (hex (H.Hkdf.prk_to_string prk1))
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" );
    ( "hmacx: RFC 5869 case 1 OKM at len 42",
      hex_is okm1
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    ("hmacx: RFC 5869 case 1 OKM is 42 bytes", len_is okm1 42);
    ( "hmacx: RFC 5869 case 2 PRK, an 80-byte salt over an 80-byte IKM",
      String.equal
        (hex (H.Hkdf.prk_to_string prk2))
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244" );
    ( "hmacx: RFC 5869 case 2 OKM at len 82, three chained blocks",
      hex_is okm2
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );
    ("hmacx: RFC 5869 case 2 OKM is 82 bytes", len_is okm2 82);
    ( "hmacx: RFC 5869 case 2 spans more than two blocks",
      len_is okm2 82 && 82 > 2 * H.hash_len () );
    ( "hmacx: RFC 5869 case 3 PRK, an empty salt over a 22-byte IKM",
      String.equal
        (hex (H.Hkdf.prk_to_string prk3))
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04" );
    ( "hmacx: RFC 5869 case 3 OKM at len 42, empty salt and empty info",
      hex_is okm3
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
    ("hmacx: RFC 5869 case 3 OKM is 42 bytes", len_is okm3 42) ]

let prk_checks : (string * bool) list =
  [ ( "hmacx: extract prk is 32 bytes (RFC 5869 case 1)",
      Int.equal
        (String.length
           (H.Hkdf.prk_to_string (H.Hkdf.extract ~salt:salt1 ~ikm:ikm1)))
        32 );
    ( "hmacx: extract prk is 32 bytes (RFC 5869 case 2)",
      Int.equal
        (String.length
           (H.Hkdf.prk_to_string (H.Hkdf.extract ~salt:salt2 ~ikm:ikm2)))
        32 );
    ( "hmacx: extract prk is 32 bytes (RFC 5869 case 3)",
      Int.equal
        (String.length
           (H.Hkdf.prk_to_string (H.Hkdf.extract ~salt:"" ~ikm:ikm3)))
        32 );
    ( "hmacx: extract of empty salt and empty ikm is 32 bytes",
      Int.equal
        (String.length
           (H.Hkdf.prk_to_string (H.Hkdf.extract ~salt:"" ~ikm:"")))
        32 );
    ( "hmacx: an extracted PRK is hash_len () bytes",
      Int.equal (String.length (H.Hkdf.prk_to_string prk1)) (H.hash_len ()) ) ]

let expand_checks : (string * bool) list =
  [ ( "hmacx: expand refuses a negative len",
      Option.is_none (H.Hkdf.expand prk1 ~info:info1 ~len:(-1)) );
    ( "hmacx: expand at len 0 is the empty string, not None",
      sopt_eq (H.Hkdf.expand prk1 ~info:info1 ~len:0) (Some "") );
    ( "hmacx: expand at len 1 cuts the first block to one byte",
      hex_is (H.Hkdf.expand prk1 ~info:info1 ~len:1) "3c" );
    ( "hmacx: expand at len hash_len () is the whole first block",
      hex_is
        (H.Hkdf.expand prk1 ~info:info1 ~len:(H.hash_len ()))
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" );
    ( "hmacx: expand at the 8160-byte cap answers Some of that length",
      len_is cap (H.Hkdf.max_len ()) );
    ( "hmacx: expand at the cap, the LAST 32 bytes, the 255th block",
      hex_is cap_last
        "76a3f78bcffe95fecf91923c22ad6ee64d48a6d1b981d7e523d5c0f22154ee88" );
    ( "hmacx: expand refuses one byte above the cap",
      Option.is_none
        (H.Hkdf.expand prk1 ~info:info1 ~len:(H.Hkdf.max_len () + 1)) ) ]

let derive_checks : (string * bool) list =
  [ ( "hmacx: derive is extract then expand on RFC 5869 case 1",
      sopt_eq
        (H.Hkdf.derive ~salt:salt1 ~ikm:ikm1 ~info:info1 ~len:42)
        okm1 );
    ( "hmacx: derive on case 1 answers the pinned OKM",
      hex_is
        (H.Hkdf.derive ~salt:salt1 ~ikm:ikm1 ~info:info1 ~len:42)
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    ( "hmacx: derive carries the cap guard of expand",
      Option.is_none
        (H.Hkdf.derive ~salt:salt1 ~ikm:ikm1 ~info:info1
           ~len:(H.Hkdf.max_len () + 1)) ) ]

let default_salt_checks : (string * bool) list =
  [ ( "hmacx: an empty salt IS the HashLen-zeros default of RFC 5869",
      String.equal
        (H.Hkdf.prk_to_string (H.Hkdf.extract ~salt:"" ~ikm:ikm3))
        (H.Hkdf.prk_to_string
           (H.Hkdf.extract ~salt:(rep (H.hash_len ()) 0x00) ~ikm:ikm3)) );
    ( "hmacx: that PRK is the RFC 5869 case 3 PRK",
      String.equal
        (hex
           (H.Hkdf.prk_to_string
              (H.Hkdf.extract ~salt:(rep (H.hash_len ()) 0x00) ~ikm:ikm3)))
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04" ) ]

let constant_checks : (string * bool) list =
  [ ("hmacx: block_size () is 64", Int.equal (H.block_size ()) 64);
    ("hmacx: hash_len () is 32", Int.equal (H.hash_len ()) 32);
    ("hmacx: max_len () is 8160", Int.equal (H.Hkdf.max_len ()) 8160);
    ( "hmacx: max_len () is 255 blocks of hash_len ()",
      Int.equal (H.Hkdf.max_len ()) (255 * H.hash_len ()) ) ]

let () =
  run
    (List.concat
       [ rfc4231_checks;
         boundary_checks;
         equal_ct_checks;
         verify_checks;
         hkdf_checks;
         prk_checks;
         expand_checks;
         derive_checks;
         default_salt_checks;
         constant_checks ])
