(* M19 p256x: ECDSA P-256 verification over SHA-256 digests, through
   the PUBLIC surface only. The curve record, the Jacobian point and
   every field helper are reached by the entrypoints that use them: the
   accept rows walk the two scalar multiplications, the doubling, the
   general addition and both Fermat inverses, and the infinity row of
   group (9) walks the arm that gives the point at infinity.

   Every hex constant below is recomputed by harness/diff_p256.py from
   the INPUTS this file names, by a P-256 in AFFINE coordinates over
   python integers that shares no formula with the Jacobian OCaml unit.
   That harness SIGNS the RFC 6979 A.2.5 vector before it reads a pin,
   so a python bug cannot certify an OCaml bug. It also requires each
   constant to sit inside a CHECK ROW of this file, not merely
   somewhere in it, and it strips the row LABEL before it searches, so
   a pin moved into a comment, into an unread let or into a row name
   turns the gate RED. Every pin therefore sits INLINE in the boolean
   of its own row.

   The vectors are the RFC 6979 A.2.5 SHA-256 signatures over "sample"
   and "test", the RFC 7515 A.3 ES256 signature over its 115-byte
   signing input, and one vector the oracle GENERATES at gate time from
   a private key, a nonce and a message that only this milestone holds,
   which is the one vector a mistyped published constant cannot poison.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal module by its mangled name, exactly as test_limbsx,
   test_hmacx and test_keccakx do. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module P = Venice__P256x
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

let key_of ~(x : string) ~(y : string) : P.Pubkey.t option =
  P.Pubkey.of_xy ~x:(bytes_of_hex x) ~y:(bytes_of_hex y)

let sig_of ~(r : string) ~(s : string) : P.Signature.t option =
  P.Signature.of_rs ~r:(bytes_of_hex r) ~s:(bytes_of_hex s)

let raw_of ~(r : string) ~(s : string) : P.Signature.t option =
  P.Signature.of_raw (bytes_of_hex (r ^ s))

let key_bytes (o : P.Pubkey.t option) : string =
  Option.fold ~none:"" ~some:(fun (k : P.Pubkey.t) -> P.Pubkey.to_bytes k) o

let sig_bytes (o : P.Signature.t option) : string =
  Option.fold ~none:""
    ~some:(fun (sg : P.Signature.t) -> P.Signature.to_raw sg)
    o

let key_eq (a : P.Pubkey.t option) (v : P.Pubkey.t option) : bool =
  Option.fold ~none:false
    ~some:(fun (k : P.Pubkey.t) ->
      Option.fold ~none:false ~some:(P.Pubkey.equal k) v)
    a

let verify_hex ~(x : string) ~(y : string) ~(r : string) ~(s : string)
    ~(digest : string) : bool =
  Option.fold ~none:false
    ~some:(fun (k : P.Pubkey.t) ->
      Option.fold ~none:false
        ~some:(fun (sg : P.Signature.t) ->
          P.verify k sg ~digest:(bytes_of_hex digest))
        (sig_of ~r ~s))
    (key_of ~x ~y)

let verify_msg ~(x : string) ~(y : string) ~(r : string) ~(s : string)
    ~(message : string) : bool =
  Option.fold ~none:false
    ~some:(fun (k : P.Pubkey.t) ->
      Option.fold ~none:false
        ~some:(fun (sg : P.Signature.t) -> P.verify_message k sg message)
        (sig_of ~r ~s))
    (key_of ~x ~y)

(* ---------- group (1): the curve constants and the digest size ------ *)

let curve_checks : (string * bool) list =
  [ ( "p256x: the base point is accepted through of_xy",
      Option.is_some
        (key_of
           ~x:
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
           ~y:
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );
    ( "p256x: the base point round-trips through to_bytes",
      String.equal
        (Hx.encode
           (key_bytes
              (key_of
                 ~x:
                   "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                 ~y:
                   "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
        ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
       ^ "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );
    ( "p256x: the 65-byte 0x04 form gives the same key as the 64-byte form",
      key_eq
        (P.Pubkey.of_bytes
           (byte 4
           ^ bytes_of_hex
               "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
           ^ bytes_of_hex
               "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
        (key_of
           ~x:
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
           ~y:
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );
    ( "p256x: the base point with the negated y is on the curve",
      Option.is_some
        (key_of
           ~x:
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
           ~y:
             "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a")
    );
    ("p256x: the digest length is 32 bytes", Int.equal (P.digest_len ()) 32);
    ( "p256x: the field prime text is rejected as an r",
      not
        (Option.is_some
           (sig_of
              ~r:
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
    );
    ( "p256x: the group order text is rejected as an r",
      not
        (Option.is_some
           (sig_of
              ~r:
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
    );
    ( "p256x: the group order text is rejected as an s",
      not
        (Option.is_some
           (sig_of
              ~r:
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
              ~s:
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
    )
  ]

(* ---------- group (2): the RFC 6979 A.2.5 SHA-256 signatures -------- *)

let rfc6979_checks : (string * bool) list =
  [ ( "p256x: the RFC 6979 sample signature verifies on the pinned digest",
      verify_hex
        ~x:"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        ~y:"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        ~r:"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        ~s:"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        ~digest:
          "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    );
    ( "p256x: the RFC 6979 sample signature verifies over the ASCII message",
      verify_msg
        ~x:"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        ~y:"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        ~r:"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        ~s:"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        ~message:"sample" );
    ( "p256x: the sample digest text is the one verify accepts",
      verify_hex
        ~x:"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        ~y:"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        ~r:"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        ~s:"f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        ~digest:
          "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
      && not
           (verify_hex
              ~x:
                "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
              ~y:
                "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
              ~r:
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
              ~digest:
                "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1be")
    );
    ( "p256x: the RFC 6979 test signature verifies on the pinned digest",
      verify_hex
        ~x:"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        ~y:"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        ~r:"f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
        ~s:"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
        ~digest:
          "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
    ( "p256x: the RFC 6979 test signature verifies over the ASCII message",
      verify_msg
        ~x:"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        ~y:"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        ~r:"f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
        ~s:"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
        ~message:"test" );
    ( "p256x: the test digest text is the one verify accepts",
      verify_hex
        ~x:"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        ~y:"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        ~r:"f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
        ~s:"019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
        ~digest:
          "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
      && not
           (verify_hex
              ~x:
                "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
              ~y:
                "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
              ~r:
                "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
              ~s:
                "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
              ~digest:
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a09")
    )
  ]

(* ---------- group (3): the RFC 7515 A.3 ES256 vector ---------------- *)

let jws_checks : (string * bool) list =
  [ ( "p256x: the RFC 7515 A.3 signature verifies over the signing input",
      verify_msg
        ~x:"7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
        ~y:"c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad"
        ~r:"0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
        ~s:"c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5"
        ~message:
          ("eyJhbGciOiJFUzI1NiJ9."
         ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
         ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ") );
    ( "p256x: the RFC 7515 A.3 signature verifies on the pinned digest",
      verify_hex
        ~x:"7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
        ~y:"c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad"
        ~r:"0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
        ~s:"c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5"
        ~digest:
          "21c67368f436577f447f805162ca13b80d046a3fe467247e65ea477aa750fa2e"
    );
    ( "p256x: the RFC 7515 A.3 key parses from the 64-byte form",
      key_eq
        (P.Pubkey.of_bytes
           (bytes_of_hex
              ("7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
             ^ "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad")))
        (key_of
           ~x:
             "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
           ~y:
             "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad")
    );
    ( "p256x: the RFC 7515 A.3 signature parses from the raw 64-byte form",
      Option.fold ~none:false
        ~some:(fun (k : P.Pubkey.t) ->
          Option.fold ~none:false
            ~some:(fun (sg : P.Signature.t) ->
              P.verify k sg
                ~digest:
                  (bytes_of_hex
                     "21c67368f436577f447f805162ca13b80d046a3fe467247e65ea477aa750fa2e"))
            (raw_of
               ~r:
                 "0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
               ~s:
                 "c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5"))
        (key_of
           ~x:
             "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
           ~y:
             "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad")
    );
    ( "p256x: a flipped RFC 7515 signing input is refused",
      not
        (verify_msg
           ~x:
             "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
           ~y:
             "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad"
           ~r:
             "0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
           ~s:
             "c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5"
           ~message:
             ("eyJhbGciOiJFUzI1NiJ9."
            ^ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
            ^ "cGxlLmNvbS9pc19yb290Ijp0cnVlfR")) );
    ( "p256x: the RFC 7515 A.3 halves come back out of to_raw",
      String.equal
        (Hx.encode
           (sig_bytes
              (sig_of
                 ~r:
                   "0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
                 ~s:
                   "c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5")))
        ("0ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
       ^ "c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5")
    )
  ]

(* ---------- group (4): the oracle-generated vector ------------------ *)

let oracle_checks : (string * bool) list =
  [ ( "p256x: the oracle public point is accepted through of_xy",
      Option.is_some
        (key_of
           ~x:
             "64d363388b22f2324a8f005eb642b7cb361532120360d7befd7799a60acb1242"
           ~y:
             "72193947bb5620b8cc5d1ded17703313e7bccb3ad45c00fe695e2f71c5d98ef9")
    );
    ( "p256x: the oracle signature verifies on the pinned digest",
      verify_hex
        ~x:"64d363388b22f2324a8f005eb642b7cb361532120360d7befd7799a60acb1242"
        ~y:"72193947bb5620b8cc5d1ded17703313e7bccb3ad45c00fe695e2f71c5d98ef9"
        ~r:"3346681a746742aec98869eb613a2adb7045edfbfc4b1e4043e193800bc490c6"
        ~s:"905c62ede654099cd5e4c574e9706e56e52662146523109d1fbc2966a00885aa"
        ~digest:
          "bb859b4daaff5f2f48b811d275a64abd46cc50976546d943f1995cfce973c0f4"
    );
    ( "p256x: the oracle signature verifies over its ASCII message",
      verify_msg
        ~x:"64d363388b22f2324a8f005eb642b7cb361532120360d7befd7799a60acb1242"
        ~y:"72193947bb5620b8cc5d1ded17703313e7bccb3ad45c00fe695e2f71c5d98ef9"
        ~r:"3346681a746742aec98869eb613a2adb7045edfbfc4b1e4043e193800bc490c6"
        ~s:"905c62ede654099cd5e4c574e9706e56e52662146523109d1fbc2966a00885aa"
        ~message:"venice-ocaml m19 p256x" );
    ( "p256x: the oracle message digest text is the one verify accepts",
      verify_hex
        ~x:"64d363388b22f2324a8f005eb642b7cb361532120360d7befd7799a60acb1242"
        ~y:"72193947bb5620b8cc5d1ded17703313e7bccb3ad45c00fe695e2f71c5d98ef9"
        ~r:"3346681a746742aec98869eb613a2adb7045edfbfc4b1e4043e193800bc490c6"
        ~s:"905c62ede654099cd5e4c574e9706e56e52662146523109d1fbc2966a00885aa"
        ~digest:
          "bb859b4daaff5f2f48b811d275a64abd46cc50976546d943f1995cfce973c0f4"
      && not
           (verify_hex
              ~x:
                "64d363388b22f2324a8f005eb642b7cb361532120360d7befd7799a60acb1242"
              ~y:
                "72193947bb5620b8cc5d1ded17703313e7bccb3ad45c00fe695e2f71c5d98ef9"
              ~r:
                "3346681a746742aec98869eb613a2adb7045edfbfc4b1e4043e193800bc490c6"
              ~s:
                "905c62ede654099cd5e4c574e9706e56e52662146523109d1fbc2966a00885aa"
              ~digest:
                "bb859b4daaff5f2f48b811d275a64abd46cc50976546d943f1995cfce973c0f5")
    );
    ( "p256x: the oracle halves come back out of to_raw",
      String.equal
        (Hx.encode
           (sig_bytes
              (sig_of
                 ~r:
                   "3346681a746742aec98869eb613a2adb7045edfbfc4b1e4043e193800bc490c6"
                 ~s:
                   "905c62ede654099cd5e4c574e9706e56e52662146523109d1fbc2966a00885aa")))
        ("3346681a746742aec98869eb613a2adb7045edfbfc4b1e4043e193800bc490c6"
       ^ "905c62ede654099cd5e4c574e9706e56e52662146523109d1fbc2966a00885aa")
    )
  ]

(* ---------- group (5): the psychic rejects at construction ---------- *)

let psychic_checks : (string * bool) list =
  [ ( "p256x: of_raw with r = 0 is None",
      not
        (Option.is_some
           (raw_of
              ~r:
                "0000000000000000000000000000000000000000000000000000000000000000"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
    );
    ( "p256x: of_raw with s = 0 is None",
      not
        (Option.is_some
           (raw_of
              ~r:
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
              ~s:
                "0000000000000000000000000000000000000000000000000000000000000000"))
    );
    ( "p256x: of_raw with both halves zero is None",
      not
        (Option.is_some
           (raw_of
              ~r:
                "0000000000000000000000000000000000000000000000000000000000000000"
              ~s:
                "0000000000000000000000000000000000000000000000000000000000000000"))
    );
    ( "p256x: of_raw with r at the group order is None",
      not
        (Option.is_some
           (raw_of
              ~r:
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
    );
    ( "p256x: of_raw with s at the group order is None",
      not
        (Option.is_some
           (raw_of
              ~r:
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
              ~s:
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
    );
    ( "p256x: of_raw with r at the field prime is None",
      not
        (Option.is_some
           (raw_of
              ~r:
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
    );
    ( "p256x: of_rs with r = 0 is None",
      not
        (Option.is_some
           (sig_of
              ~r:
                "0000000000000000000000000000000000000000000000000000000000000000"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
    );
    ( "p256x: of_rs with s at the group order is None",
      not
        (Option.is_some
           (sig_of
              ~r:
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
              ~s:
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))
    )
  ]

(* ---------- group (6): in-range garbage is refused ------------------ *)

let garbage_checks : (string * bool) list =
  [ ( "p256x: the group order less one as r does not verify",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"
           ~s:
             "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
           ~digest:
             "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")
    );
    ( "p256x: the sample r with s = 1 does not verify",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "0000000000000000000000000000000000000000000000000000000000000001"
           ~digest:
             "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")
    );
    ( "p256x: the sample s with its last bit flipped does not verify",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda9"
           ~digest:
             "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")
    );
    ( "p256x: the sample r with the test s does not verify",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
           ~digest:
             "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")
    )
  ]

(* ---------- group (7): the key rejects at construction -------------- *)

let key_reject_checks : (string * bool) list =
  [ ( "p256x: an x at the field prime is rejected",
      not
        (Option.is_some
           (key_of
              ~x:
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
              ~y:
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
    );
    ( "p256x: a y at the field prime is rejected",
      not
        (Option.is_some
           (key_of
              ~x:
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              ~y:
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"))
    );
    ( "p256x: the coordinate p + 5 is rejected although its residue is a \
       curve x",
      not
        (Option.is_some
           (key_of
              ~x:
                "ffffffff00000001000000000000000000000001000000000000000000000004"
              ~y:
                "459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbcc"))
    );
    ( "p256x: the off-curve y of the RFC 7515 key is rejected",
      not
        (Option.is_some
           (key_of
              ~x:
                "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
              ~y:
                "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ac"))
    );
    ( "p256x: the zero pair is rejected",
      not
        (Option.is_some
           (key_of
              ~x:
                "0000000000000000000000000000000000000000000000000000000000000000"
              ~y:
                "0000000000000000000000000000000000000000000000000000000000000000"))
    );
    ( "p256x: a 31-byte x is rejected",
      not
        (Option.is_some
           (key_of
              ~x:"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2"
              ~y:
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
    );
    ( "p256x: a 33-byte x is rejected",
      not
        (Option.is_some
           (key_of
              ~x:
                "006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              ~y:
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))
    );
    ( "p256x: a 31-byte y is rejected",
      not
        (Option.is_some
           (key_of
              ~x:
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              ~y:"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51"))
    );
    ( "p256x: a 63-byte of_bytes input is rejected",
      not (Option.is_some (P.Pubkey.of_bytes (String.make 63 '\000'))) );
    ( "p256x: a 66-byte of_bytes input is rejected",
      not (Option.is_some (P.Pubkey.of_bytes (String.make 66 '\000'))) );
    ( "p256x: a 65-byte key under a 0x02 prefix is rejected",
      not
        (Option.is_some
           (P.Pubkey.of_bytes
              (byte 2
              ^ bytes_of_hex
                  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              ^ bytes_of_hex
                  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
    );
    ( "p256x: a 65-byte key under a 0x03 prefix is rejected",
      not
        (Option.is_some
           (P.Pubkey.of_bytes
              (byte 3
              ^ bytes_of_hex
                  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              ^ bytes_of_hex
                  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
    );
    ( "p256x: an empty of_bytes input is rejected",
      not (Option.is_some (P.Pubkey.of_bytes "")) );
    ( "p256x: the base point is accepted through of_xy and through of_bytes",
      Option.is_some
        (key_of
           ~x:
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
           ~y:
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
      && Option.is_some
           (P.Pubkey.of_bytes
              (bytes_of_hex
                 ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                ^ "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
    )
  ]

(* ---------- group (8): the malleable twin, which VERIFIES ----------- *)

let malleable_checks : (string * bool) list =
  [ ( "p256x: the malleable twin of the sample signature verifies",
      verify_hex
        ~x:"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        ~y:"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
        ~r:"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        ~s:"0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9"
        ~digest:
          "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    );
    ( "p256x: the malleable twin of the oracle signature verifies",
      verify_hex
        ~x:"64d363388b22f2324a8f005eb642b7cb361532120360d7befd7799a60acb1242"
        ~y:"72193947bb5620b8cc5d1ded17703313e7bccb3ad45c00fe695e2f71c5d98ef9"
        ~r:"3346681a746742aec98869eb613a2adb7045edfbfc4b1e4043e193800bc490c6"
        ~s:"6fa39d1119abf6642a1b3a8b168f91a8d7c0989941f48de7d3fda15c5c5a9fa7"
        ~digest:
          "bb859b4daaff5f2f48b811d275a64abd46cc50976546d943f1995cfce973c0f4"
    );
    ( "p256x: the twin s differs from the published s",
      not
        (String.equal
           "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9"
           "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
    );
    ( "p256x: to_raw of the twin differs from to_raw of the original",
      not
        (String.equal
           (Hx.encode
              (sig_bytes
                 (sig_of
                    ~r:
                      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                    ~s:
                      "0834e36ad29a83bf2bc9385e491d6099c8fdf9d1ed67aa7ea5f51f93782857a9")))
           (Hx.encode
              (sig_bytes
                 (sig_of
                    ~r:
                      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                    ~s:
                      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))))
    )
  ]

(* ---------- group (9): cross checks and the infinity path ----------- *)

let cross_checks : (string * bool) list =
  [ ( "p256x: the sample signature under the test digest is false",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
           ~digest:
             "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
    );
    ( "p256x: the sample signature under the RFC 7515 key is false",
      not
        (verify_hex
           ~x:
             "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
           ~y:
             "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
           ~digest:
             "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")
    );
    ( "p256x: a 31-byte digest is false",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
           ~digest:
             "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1")
    );
    ( "p256x: a 33-byte digest of a zero byte then the sample digest is false",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
           ~digest:
             "00af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")
    );
    ( "p256x: an empty digest is false",
      not
        (verify_hex
           ~x:
             "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
           ~y:
             "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
           ~r:
             "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
           ~s:
             "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
           ~digest:"") );
    ( "p256x: the crafted witness whose shared point is infinity is false",
      not
        (verify_hex
           ~x:
             "64d363388b22f2324a8f005eb642b7cb361532120360d7befd7799a60acb1242"
           ~y:
             "72193947bb5620b8cc5d1ded17703313e7bccb3ad45c00fe695e2f71c5d98ef9"
           ~r:
             "9cde18152f7e50002c96349c6cf9c4cb4fe2ed8b8b0b01f70aa005bdad7d53ee"
           ~s:
             "0000000000000000000000000000000000000000000000000000000000000001"
           ~digest:
             "bb859b4daaff5f2f48b811d275a64abd46cc50976546d943f1995cfce973c0f4")
    )
  ]

(* ---------- group (10): the shape of the two abstract types --------- *)

let shape_checks : (string * bool) list =
  [ ( "p256x: to_bytes gives 64 bytes",
      Int.equal
        (String.length
           (key_bytes
              (key_of
                 ~x:
                   "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                 ~y:
                   "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
        64 );
    ( "p256x: to_raw gives 64 bytes",
      Int.equal
        (String.length
           (sig_bytes
              (sig_of
                 ~r:
                   "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                 ~s:
                   "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")))
        64 );
    ( "p256x: of_bytes on 64 bytes and on 65 bytes gives equal keys",
      key_eq
        (P.Pubkey.of_bytes
           (bytes_of_hex
              ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
             ^ "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
        (P.Pubkey.of_bytes
           (byte 4
           ^ bytes_of_hex
               ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              ^ "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
    );
    ( "p256x: to_bytes round-trips through of_bytes",
      key_eq
        (P.Pubkey.of_bytes
           (key_bytes
              (key_of
                 ~x:
                   "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                 ~y:
                   "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
        (key_of
           ~x:
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
           ~y:
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );
    ( "p256x: of_rs on two 32-byte halves agrees with of_raw",
      String.equal
        (Hx.encode
           (sig_bytes
              (sig_of
                 ~r:
                   "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                 ~s:
                   "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")))
        (Hx.encode
           (sig_bytes
              (raw_of
                 ~r:
                   "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                 ~s:
                   "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")))
    );
    ( "p256x: of_rs accepts two one-byte halves",
      Option.is_some (P.Signature.of_rs ~r:(byte 1) ~s:(byte 1)) );
    ( "p256x: of_rs with a 33-byte half is None although the value is in \
       range",
      not
        (Option.is_some
           (sig_of
              ~r:
                "00efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
              ~s:
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"))
    );
    ( "p256x: to_raw round-trips through of_raw",
      String.equal
        (Hx.encode
           (sig_bytes
              (P.Signature.of_raw
                 (sig_bytes
                    (sig_of
                       ~r:
                         "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                       ~s:
                         "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")))))
        ("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
       ^ "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
    );
    ( "p256x: equal is true on two constructions of the base point",
      key_eq
        (key_of
           ~x:
             "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
           ~y:
             "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        (P.Pubkey.of_bytes
           (bytes_of_hex
              ("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
             ^ "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")))
    );
    ( "p256x: equal is false between the base point and the RFC 7515 key",
      not
        (key_eq
           (key_of
              ~x:
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
              ~y:
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
           (key_of
              ~x:
                "7fcdce2770f6c45d4183cbee6fdb4b7b580733357be9ef13bacf6e3c7bd15445"
              ~y:
                "c7f144cd1bbd9b7e872cdfedb9eeb9f4b3695d6ea90b24ad8a4623288588e5ad"))
    )
  ]

let () =
  run
    (curve_checks @ rfc6979_checks @ jws_checks @ oracle_checks
   @ psychic_checks @ garbage_checks @ key_reject_checks @ malleable_checks
   @ cross_checks @ shape_checks)
