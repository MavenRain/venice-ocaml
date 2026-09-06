(* test_sigx: the M25 signature suite (D10).  It proves the two ECDSA
   legs of the committed v4 fixture, the QE binding hash, the six-word
   reject vocabulary and the check ORDER of sigx.

   Every pin is a LITERAL inside the boolean of its own row.  The
   stanza links venice ALONE and no sha2 (D2), so this file computes no
   digest of its own:  a digest row compares what the unit returns
   against a pinned string, and harness/diff_quote.py group (h)
   recomputes each pin from the fixture bytes.

   Every painted quote is re-parsed through Quotex.parse, so every row
   reads a real Quotex.t and never a hand-built one.  The painting
   discipline of D8 holds:  a painted byte reaches EXACTLY the leg its
   row names.  Bytes 636 to 700 reach step 5 or step 6, bytes 700 to
   764 reach step 3 first, bytes 770 to 1154 reach step 2 first, bytes
   1154 to 1218 reach step 1 or step 2, bytes 1220 to 1252 reach step 3
   only, and a free byte below 632 reaches step 6 only.

   The run filter below carries TWO typed wildcards, (_ : string) in
   the filter and (_ : bool) in the printer.  No bare wildcard arm
   appears anywhere in this file. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module S = Venice__Sigx
module Q = Venice__Quotex
module Sec = Q.Signature_section
module Errx = Venice__Errx
module Pk = Venice__P256x.Pubkey
module C = Venice.Cursor

let v4 : string = Fixture_sig.bytes ()
let hex (s : string) : string = Venice.Hex.encode s

(* The bytes of a hex string, or the empty string when the string is
   not strict hex.  An empty answer makes its row FALSE and never
   raises. *)
let unhex (h : string) : string =
  Option.value ~default:"" (Result.to_option (Venice.Hex.decode h))

(* A TOTAL window read.  An out-of-range request answers the empty
   string, which makes its row FALSE and never raises. *)
let win (s : string) (off : int) (len : int) : string =
  Option.value ~default:"" (C.take s off len)

(* A TOTAL splice: the bytes of repl overwrite the same count of bytes
   at off and nothing else moves.  Both pieces are bounded by
   Venice.Cursor.take, so an out-of-range request returns the input
   unchanged instead of raising, and no String.sub and no index
   appears. *)
let patch (s : string) (off : int) (repl : string) : string =
  let n = String.length repl in
  Option.value ~default:s
    (Option.bind (C.take s 0 off) (fun (head : string) ->
         Option.map
           (fun (tail : string) -> head ^ repl ^ tail)
           (C.take s (off + n) (String.length s - off - n))))

(* The parse of a quote, as an option, so every row below reads a value
   that exists only when parse succeeded. *)
let parsed (s : string) : Q.t option = Result.to_option (Q.parse s)

(* The two keys.  The PCK leaf key is the W4 point M26 will hand in,
   built here from the two hex halves of the first PEM block, and the
   attestation key is the W2 point at 700.  Each is an option, so a
   broken vector makes its row FALSE and never raises. *)
let pck : Pk.t option =
  Pk.of_bytes
    (unhex
       ("1720fa04edef8680bfb748fd965af93d61a417a8f1f29910e8b88b3666dfff6d"
      ^ "2b2660f3288f203356f90253a7f6f76616e24212c22cfcc3e66d681f971c9769"))

let att : Pk.t option =
  Pk.of_bytes
    (unhex
       ("c78ac5859b9f567238fad82ad63202bc516ee7ad14ec1d9adfc633e4cf5f71f7"
      ^ "3d6138ce76d0d9c1443f695464d1ed419c37ce696e70e95a5b317894a5897907"))

(* The verdict of the whole order as TEXT, under a caller-named key, so
   a row pins the reason string and never a constructor shape.  "ok" is
   the accept. *)
let verify_under (key : Pk.t option) (s : string) : string =
  Option.fold ~none:"no key"
    ~some:(fun (k : Pk.t) ->
      Option.fold ~none:"parse failed"
        ~some:(fun (q : Q.t) ->
          Result.fold
            ~ok:(fun (_ : S.t) -> "ok")
            ~error:(fun (e : Errx.t) -> Errx.to_string e)
            (S.verify ~pck_key:k q))
        (parsed s))
    key

let verify_text (s : string) : string = verify_under pck s

(* A predicate over the WITNESS a successful verify mints, false when
   any step refused. *)
let on_witness (s : string) (f : S.t -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun (k : Pk.t) ->
      Option.fold ~none:false
        ~some:(fun (q : Q.t) ->
          Result.fold ~ok:f
            ~error:(fun (_ : Errx.t) -> false)
            (S.verify ~pck_key:k q))
        (parsed s))
    pck

(* A predicate over the parsed signature section and over the parsed
   quote, for the rows that read an accessor and not a verdict. *)
let on_section (s : string) (f : Sec.t -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun (q : Q.t) -> f (Q.signature_section q))
    (parsed s)

let on_quote (s : string) (f : Q.t -> bool) : bool =
  Option.fold ~none:false ~some:f (parsed s)

(* The verdict of ONE leg over the section, as text. *)
let sec_text (f : Sec.t -> (unit, Errx.t) result) (s : string) : string =
  Option.fold ~none:"parse failed"
    ~some:(fun (q : Q.t) ->
      Result.fold
        ~ok:(fun (() : unit) -> "ok")
        ~error:(fun (e : Errx.t) -> Errx.to_string e)
        (f (Q.signature_section q)))
    (parsed s)

let qe_text (key : Pk.t option) (s : string) : string =
  Option.fold ~none:"no key"
    ~some:(fun (k : Pk.t) -> sec_text (S.check_qe_signature ~pck_key:k) s)
    key

let binding_text (s : string) : string = sec_text S.check_qe_binding s

(* The ISV leg, which takes the outer quote because signed_region lives
   there, under a caller-named key. *)
let isv_text (key : Pk.t option) (s : string) : string =
  Option.fold ~none:"no key"
    ~some:(fun (k : Pk.t) ->
      Option.fold ~none:"parse failed"
        ~some:(fun (q : Q.t) ->
          Result.fold
            ~ok:(fun (() : unit) -> "ok")
            ~error:(fun (e : Errx.t) -> Errx.to_string e)
            (S.check_isv_signature ~att_key:k q))
        (parsed s))
    key

(* Step 4 reached DIRECTLY, as text and as the hex of the point it
   mints, because verify never reaches this arm on a QE-signed quote. *)
let akey_text (s : string) : string =
  Option.fold ~none:"parse failed"
    ~some:(fun (q : Q.t) ->
      Result.fold
        ~ok:(fun (_ : Pk.t) -> "ok")
        ~error:(fun (e : Errx.t) -> Errx.to_string e)
        (S.attestation_key_of_section (Q.signature_section q)))
    (parsed s)

let akey_hex (s : string) : string =
  Option.fold ~none:""
    ~some:(fun (q : Q.t) ->
      Result.fold
        ~ok:(fun (k : Pk.t) -> hex (Pk.to_bytes k))
        ~error:(fun (_ : Errx.t) -> "")
        (S.attestation_key_of_section (Q.signature_section q)))
    (parsed s)

(* The parse verdict itself, which group (j) reads. *)
let parse_text (s : string) : string =
  Result.fold
    ~ok:(fun (_ : Q.t) -> "ok")
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    (Q.parse s)

(* ---------- group (a), the fixture identity and the W1 layout ------ *)

let identity_checks : (string * bool) list =
  [
    ("sigx: (a) the embedded v4 fixture is 5006 bytes",
      Int.equal (String.length v4) 5006);
    ( "sigx: (a) the first 16 fixture bytes are the v4 header opening",
      String.equal (hex (win v4 0 16)) "040002008100000000000000939a7233" );
    ( "sigx: (a) the last 16 fixture bytes are the trailing padding",
      String.equal (hex (win v4 4990 16)) "00000000000000000000000000000000" );
    ( "sigx: (a) signature_data_len at 632 is 4300",
      on_quote v4 (fun (q : Q.t) -> Int.equal (Q.signature_data_len q) 4300) );
    ( "sigx: (a) cert_key_type at 764 is 6",
      on_section v4 (fun (s : Sec.t) -> Int.equal (Sec.cert_key_type s) 6) );
    ( "sigx: (a) cert_size at 766 is 4166",
      on_section v4 (fun (s : Sec.t) -> Int.equal (Sec.cert_size s) 4166) );
    ( "sigx: (a) qe_auth_size at 1218 is 32",
      on_section v4 (fun (s : Sec.t) -> Int.equal (Sec.qe_auth_size s) 32) );
    ( "sigx: (a) inner_cert_type at 1252 is 5",
      on_section v4 (fun (s : Sec.t) -> Int.equal (Sec.inner_cert_type s) 5) );
    ( "sigx: (a) inner_size at 1254 is 3678",
      on_section v4 (fun (s : Sec.t) -> Int.equal (Sec.inner_size s) 3678) );
    ( "sigx: (a) the quote structure ends at 4936 and 70 bytes follow",
      on_quote v4 (fun (q : Q.t) -> Int.equal (Q.surplus q) 70) );
    ( "sigx: (a) the ISV signature at 636 is 64 bytes and the key at 700 \
       is 64 bytes",
      on_section v4 (fun (s : Sec.t) ->
          Int.equal (String.length (Sec.signature s)) 64
          && Int.equal (String.length (Sec.attestation_key s)) 64) );
    ( "sigx: (a) the QE report at 770 is 384 bytes and qe_report_data at \
       1090 is 64 bytes",
      on_section v4 (fun (s : Sec.t) ->
          Int.equal (String.length (Sec.qe_report s)) 384
          && Int.equal (String.length (Sec.qe_report_data s)) 64) );
    ( "sigx: (a) the QE signature at 1154 is 64 bytes and the auth data \
       at 1220 is 32 bytes",
      on_section v4 (fun (s : Sec.t) ->
          Int.equal (String.length (Sec.qe_report_signature s)) 64
          && Int.equal (String.length (Sec.qe_auth_data s)) 32) );
    ( "sigx: (a) the PEM window cuts into three blocks",
      on_section v4 (fun (s : Sec.t) ->
          Int.equal (List.length (Sec.pem_chain s)) 3) );
    ( "sigx: (a) the signed region is the 632 bytes at 0",
      on_quote v4 (fun (q : Q.t) ->
          Int.equal (String.length (Q.signed_region q)) 632) );
    ( "sigx: (a) the ISV r is the first half of the 64 bytes at 636",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (win (Sec.signature s) 0 32))
            "f156eac8ad01d79f7cce668f60005819b22f2151a66155a430ad4f7a9538ae31") );
    ( "sigx: (a) the ISV s is the second half of the 64 bytes at 636",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (win (Sec.signature s) 32 32))
            "330f9dfd5424e7c4124b44a668cb97fe2da48e617252ee5aeb6252d48e9324e5") );
    ( "sigx: (a) the attestation key X is the first half of the 64 bytes \
       at 700",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (win (Sec.attestation_key s) 0 32))
            "c78ac5859b9f567238fad82ad63202bc516ee7ad14ec1d9adfc633e4cf5f71f7") );
    ( "sigx: (a) the attestation key Y is the second half of the 64 bytes \
       at 700",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (win (Sec.attestation_key s) 32 32))
            "3d6138ce76d0d9c1443f695464d1ed419c37ce696e70e95a5b317894a5897907") );
    ( "sigx: (a) the QE r is the first half of the 64 bytes at 1154",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (win (Sec.qe_report_signature s) 0 32))
            "ca1bd340a4c8437b3d3d6fcf8b40030ddb7ac7f22d9597f4b593120350c891ca") );
    ( "sigx: (a) the QE s is the second half of the 64 bytes at 1154",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (win (Sec.qe_report_signature s) 32 32))
            "fdf7c699e6feac62e44d474b48c653114a2adf325623b6a218a166a27dfe8550") );
    ( "sigx: (a) the auth data at 1220 is the 32 counting bytes",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (Sec.qe_auth_data s))
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") );
  ]

(* ---------- group (b), the PCK leaf key and the happy path --------- *)

let leaf_checks : (string * bool) list =
  [
    ( "sigx: (b) the W4 PCK leaf key is a point P256x accepts",
      Option.is_some
        (Pk.of_bytes
           (unhex ("1720fa04edef8680bfb748fd965af93d61a417a8f1f29910e8b88b3666dfff6d" ^ "2b2660f3288f203356f90253a7f6f76616e24212c22cfcc3e66d681f971c9769")))
    );
    ( "sigx: (b) the W4 PCK leaf key round-trips through to_bytes",
      Option.fold ~none:false
        ~some:(fun (k : Pk.t) ->
          String.equal (hex (Pk.to_bytes k))
            ("1720fa04edef8680bfb748fd965af93d61a417a8f1f29910e8b88b3666dfff6d" ^ "2b2660f3288f203356f90253a7f6f76616e24212c22cfcc3e66d681f971c9769"))
        pck );
    ("sigx: (b) verify under the PCK leaf key on the unpainted fixture is ok",
      String.equal (verify_text v4) "ok");
    ( "sigx: (b) the witness attestation key is the W2 X then Y",
      on_witness v4 (fun (w : S.t) ->
          String.equal
            (hex (Pk.to_bytes (S.attestation_key w)))
            ("c78ac5859b9f567238fad82ad63202bc516ee7ad14ec1d9adfc633e4cf5f71f7"
           ^ "3d6138ce76d0d9c1443f695464d1ed419c37ce696e70e95a5b317894a5897907"))
    );
    ( "sigx: (b) the witness pck key is the key the QE leg verified under",
      on_witness v4 (fun (w : S.t) ->
          Option.fold ~none:false
            ~some:(fun (k : Pk.t) -> Pk.equal (S.pck_key w) k)
            pck) );
    ( "sigx: (b) the witness QE report is the 384 bytes at 770",
      on_witness v4 (fun (w : S.t) ->
          Int.equal (String.length (S.qe_report w)) 384) );
    ( "sigx: (b) the witness QE report carries the W5 mrsigner at report \
       offset 128",
      on_witness v4 (fun (w : S.t) ->
          String.equal
            (hex (win (S.qe_report w) 128 32))
            "dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5")
    );
    ( "sigx: (b) the witness QE report carries the W5 cpusvn at report \
       offset 0",
      on_witness v4 (fun (w : S.t) ->
          String.equal
            (hex (win (S.qe_report w) 0 16))
            "0303191b04ff00060000000000000000") );
    ( "sigx: (b) the witness QE report carries isvprodid 2 at report \
       offset 256",
      on_witness v4 (fun (w : S.t) ->
          Option.fold ~none:false
            ~some:(fun (i : int) -> Int.equal i 2)
            (C.u16le (S.qe_report w) 256)) );
    ( "sigx: (b) the witness QE report carries isvsvn 6 at report offset \
       258",
      on_witness v4 (fun (w : S.t) ->
          Option.fold ~none:false
            ~some:(fun (i : int) -> Int.equal i 6)
            (C.u16le (S.qe_report w) 258)) );
    ( "sigx: (b) binding_digest is the W3 sha256 of the key then the auth \
       data",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (S.binding_digest s))
            "c936492a774946af9b588f6b3bd8beddc5957d1761ded2c0bb61d7b64de5b324")
    );
    ( "sigx: (b) binding_digest equals the first 32 bytes of \
       qe_report_data at 1090",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (S.binding_digest s))
            (hex (win (Sec.qe_report_data s) 0 32))) );
    ( "sigx: (b) the qe_report_data tail at 1122 is 32 zero bytes",
      on_section v4 (fun (s : Sec.t) ->
          String.equal
            (hex (win (Sec.qe_report_data s) 32 32))
            "0000000000000000000000000000000000000000000000000000000000000000")
    );
  ]

(* ---------- group (c), the QE signature, step 1 and step 2 --------- *)

let qe_signature_checks : (string * bool) list =
  [
    ( "sigx: (c) a psychic QE r of 32 zero bytes at 1154 is a parse reject",
      String.equal
        (verify_text (patch v4 1154 (String.make 32 '\000')))
        "sig: qe signature" );
    ( "sigx: (c) a psychic QE s of 32 zero bytes at 1186 is a parse reject",
      String.equal
        (verify_text (patch v4 1186 (String.make 32 '\000')))
        "sig: qe signature" );
    ( "sigx: (c) a QE r of the group order n at 1154 is a parse reject",
      String.equal
        (verify_text
           (patch v4 1154
              (unhex
                 "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")))
        "sig: qe signature" );
    ( "sigx: (c) a QE s of the group order n at 1186 is a parse reject",
      String.equal
        (verify_text
           (patch v4 1186
              (unhex
                 "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")))
        "sig: qe signature" );
    ( "sigx: (c) the QE signature byte at 1154 flipped is a verify reject",
      String.equal
        (verify_text (patch v4 1154 "\203"))
        "sig: qe signature mismatch" );
    ( "sigx: (c) the first cpusvn byte at 770 flipped is a verify reject",
      String.equal
        (verify_text (patch v4 770 "\002"))
        "sig: qe signature mismatch" );
    ( "sigx: (c) the zero tail byte at 1122 flipped is a QE verify reject \
       and never a binding reject",
      String.equal
        (verify_text (patch v4 1122 "\001"))
        "sig: qe signature mismatch" );
    ( "sigx: (c) the attestation key handed in as pck_key is a verify \
       reject",
      String.equal (verify_under att v4) "sig: qe signature mismatch" );
    ( "sigx: (c) the malleable QE twin at 1186 verifies",
      String.equal
        (verify_text
           (patch v4 1186
              (unhex
                 "020839651901539e1bb2b8b4b739acee72bc1b7b50f3e7e2db1864207e64a001")))
        "ok" );
    ( "sigx: (c) check_qe_signature under the leaf key on the fixture is ok",
      String.equal (qe_text pck v4) "ok" );
    ( "sigx: (c) check_qe_signature under the attestation key is a verify \
       reject",
      String.equal (qe_text att v4) "sig: qe signature mismatch" );
  ]

(* ---------- group (d), the QE binding, step 3 --------------------- *)

let binding_checks : (string * bool) list =
  [
    ( "sigx: (d) the first auth byte at 1220 flipped is a binding reject",
      String.equal
        (verify_text (patch v4 1220 "\001"))
        "sig: qe binding mismatch" );
    ( "sigx: (d) the last auth byte at 1251 flipped is a binding reject",
      String.equal
        (verify_text (patch v4 1251 "\030"))
        "sig: qe binding mismatch" );
    ( "sigx: (d) the first key byte at 700 flipped stops at the binding \
       and never at step 4",
      String.equal
        (verify_text (patch v4 700 "\198"))
        "sig: qe binding mismatch" );
    ( "sigx: (d) the last key byte at 763 flipped stops at the binding and \
       never at step 4",
      String.equal
        (verify_text (patch v4 763 "\006"))
        "sig: qe binding mismatch" );
    ( "sigx: (d) check_qe_binding on the unpainted fixture is ok",
      String.equal (binding_text v4) "ok" );
    ( "sigx: (d) check_qe_binding on the flipped auth byte at 1220 is a \
       binding reject",
      String.equal
        (binding_text (patch v4 1220 "\001"))
        "sig: qe binding mismatch" );
  ]

(* ---------- group (e), step 4 reached DIRECTLY -------------------- *)

let key_checks : (string * bool) list =
  [
    ( "sigx: (e) attestation_key_of_section on the fixture is ok",
      String.equal (akey_text v4) "ok" );
    ( "sigx: (e) the point it mints is the W2 X then Y",
      String.equal (akey_hex v4)
        ("c78ac5859b9f567238fad82ad63202bc516ee7ad14ec1d9adfc633e4cf5f71f7"
       ^ "3d6138ce76d0d9c1443f695464d1ed419c37ce696e70e95a5b317894a5897907")
    );
    ( "sigx: (e) an X of 32 zero bytes at 700 is off the curve",
      String.equal
        (akey_text (patch v4 700 (String.make 32 '\000')))
        "sig: attestation key" );
    ( "sigx: (e) an X at the field prime p is refused",
      String.equal
        (akey_text
           (patch v4 700
              (unhex
                 "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")))
        "sig: attestation key" );
    ( "sigx: (e) the Y byte at 763 flipped is off the curve",
      String.equal (akey_text (patch v4 763 "\006")) "sig: attestation key" );
  ]

(* ---------- group (f), the ISV signature PARSE, step 5 ------------ *)

let isv_parse_checks : (string * bool) list =
  [
    ( "sigx: (f) a psychic ISV r of 32 zero bytes at 636 is a parse reject",
      String.equal
        (verify_text (patch v4 636 (String.make 32 '\000')))
        "sig: isv signature" );
    ( "sigx: (f) a psychic ISV s of 32 zero bytes at 668 is a parse reject",
      String.equal
        (verify_text (patch v4 668 (String.make 32 '\000')))
        "sig: isv signature" );
    ( "sigx: (f) an ISV r of the group order n at 636 is a parse reject",
      String.equal
        (verify_text
           (patch v4 636
              (unhex
                 "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")))
        "sig: isv signature" );
    ( "sigx: (f) an ISV s of the group order n at 668 is a parse reject",
      String.equal
        (verify_text
           (patch v4 668
              (unhex
                 "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")))
        "sig: isv signature" );
  ]

(* ---------- group (g), the ISV VERIFY, step 6 --------------------- *)

let isv_verify_checks : (string * bool) list =
  [
    ( "sigx: (g) the user_data byte at 30 flipped is an ISV verify reject",
      String.equal
        (verify_text (patch v4 30 "\124"))
        "sig: isv signature mismatch" );
    ( "sigx: (g) the mr_td byte at 200 flipped is an ISV verify reject",
      String.equal
        (verify_text (patch v4 200 "\123"))
        "sig: isv signature mismatch" );
    ( "sigx: (g) the ISV signature byte at 640 flipped is an ISV verify \
       reject",
      String.equal
        (verify_text (patch v4 640 "\172"))
        "sig: isv signature mismatch" );
    ( "sigx: (g) the malleable ISV twin at 668 verifies",
      String.equal
        (verify_text
           (patch v4 668
              (unhex
                 "ccf06201abdb183cedb4bb59973468018f426c4c34c4b02a085777ee6dd0006c")))
        "ok" );
    ( "sigx: (g) check_isv_signature under the PCK leaf key is an ISV \
       verify reject",
      String.equal (isv_text pck v4) "sig: isv signature mismatch" );
    ( "sigx: (g) check_isv_signature under the attestation key is ok",
      String.equal (isv_text att v4) "ok" );
  ]

(* ---------- group (h), the ORDER pairs ---------------------------- *)

let order_checks : (string * bool) list =
  [
    ( "sigx: (h) a psychic QE r at 1154 with the auth byte at 1220 \
       flipped answers the QE parse word",
      String.equal
        (verify_text
           (patch (patch v4 1154 (String.make 32 '\000')) 1220 "\001"))
        "sig: qe signature" );
    ( "sigx: (h) the QE signature byte at 1154 flipped with the auth byte \
       at 1220 flipped answers the QE verify word",
      String.equal
        (verify_text (patch (patch v4 1154 "\203") 1220 "\001"))
        "sig: qe signature mismatch" );
    ( "sigx: (h) the auth byte at 1220 flipped with a psychic ISV r at \
       636 answers the binding word",
      String.equal
        (verify_text
           (patch (patch v4 1220 "\001") 636 (String.make 32 '\000')))
        "sig: qe binding mismatch" );
    ( "sigx: (h) a psychic ISV r at 636 with the byte at 30 flipped \
       answers the ISV parse word",
      String.equal
        (verify_text
           (patch (patch v4 636 (String.make 32 '\000')) 30 "\124"))
        "sig: isv signature" );
  ]

(* ---------- group (i), the Errx surface --------------------------- *)

let text_checks : (string * bool) list =
  [
    ( "sigx: (i) the word qe signature prints under the sig prefix",
      String.equal
        (Errx.to_string (Errx.Sig_invalid "qe signature"))
        "sig: qe signature" );
    ( "sigx: (i) the word qe signature mismatch prints under the sig prefix",
      String.equal
        (Errx.to_string (Errx.Sig_invalid "qe signature mismatch"))
        "sig: qe signature mismatch" );
    ( "sigx: (i) the word qe binding mismatch prints under the sig prefix",
      String.equal
        (Errx.to_string (Errx.Sig_invalid "qe binding mismatch"))
        "sig: qe binding mismatch" );
    ( "sigx: (i) the word attestation key prints under the sig prefix",
      String.equal
        (Errx.to_string (Errx.Sig_invalid "attestation key"))
        "sig: attestation key" );
    ( "sigx: (i) the word isv signature prints under the sig prefix",
      String.equal
        (Errx.to_string (Errx.Sig_invalid "isv signature"))
        "sig: isv signature" );
    ( "sigx: (i) the word isv signature mismatch prints under the sig \
       prefix",
      String.equal
        (Errx.to_string (Errx.Sig_invalid "isv signature mismatch"))
        "sig: isv signature mismatch" );
    ( "sigx: (i) the six reason words are pairwise distinct",
      Int.equal
        (List.length
           (List.sort_uniq String.compare
              [
                "qe signature";
                "qe signature mismatch";
                "qe binding mismatch";
                "attestation key";
                "isv signature";
                "isv signature mismatch";
              ]))
        6 );
  ]

(* ---------- group (j), the v5 twin -------------------------------- *)

let version_checks : (string * bool) list =
  [
    ( "sigx: (j) a quote whose version reads 5 is a quote reject and never \
       a signature reject",
      String.equal
        (parse_text (patch v4 0 "\005\000"))
        (Errx.to_string (Errx.Quote_invalid "version 5"))
      && String.equal
           (verify_text (patch v4 0 "\005\000"))
           "parse failed" );
  ]

let () =
  run
    (identity_checks @ leaf_checks @ qe_signature_checks @ binding_checks
   @ key_checks @ isv_parse_checks @ isv_verify_checks @ order_checks
   @ text_checks @ version_checks)
