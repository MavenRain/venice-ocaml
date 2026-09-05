(* M23 quotex, the TDX version-4 quote decoder (DESIGN.md:402).

   Nine groups, in the order of the design brief:  (a) fixture
   identity, (b) the header, (c) the TD report body, (d) the signed
   region and the length rule, (e) the signature section and the PEM
   chain, (f) the PAINTED quote, (g) rule 4, (h) the reject vocabulary
   with the three check-ORDER rows, and (i) the error text.

   Every pin sits INLINE in the boolean of its own row, because
   harness/diff_quote.py group (f) recomputes each value from the
   fixture bytes and then requires it to sit inside a CHECK ROW beside
   the accessor that produces it.  A constant moved into a comment,
   into an unread top-level let or into a row NAME satisfies no pin and
   turns the gate RED.

   The two fixtures arrive as GENERATED modules.  test/dune runs
   embed.exe over fixtures/tdx_quote_v4.bin and
   fixtures/tdx_quote_v5.bin at BUILD time, so this suite reads no file
   and carries no relative path (D2).  Group (a) pins both byte counts
   and both digests, so a broken embedding is caught before any field
   pin runs.

   Group (f) exists because the zero fixture cannot see a field swap
   between two all-zero windows, nor a u64 read narrowed to a u32.  The
   paint gives each of the five all-zero 48-byte FIELDS its own byte,
   it writes eight distinct bytes at 160 and it writes two distinct
   header words at 8 and 10, so every such swap changes a pinned value.

   The unit lives behind venice.mli, so this suite binds it by its
   mangled name, exactly as test_limbsx, test_hmacx, test_keccakx,
   test_p256x, test_secpx and test_gcmx do.

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

module Q = Venice__Quotex
module Errx = Venice__Errx
module H = Q.Header
module B = Q.Body
module S = Q.Signature_section
module C = Venice.Cursor

let v4 : string = Fixture_v4.bytes ()
let v5 : string = Fixture_v5.bytes ()
let hex (s : string) : string = Venice.Hex.encode s
let sha (s : string) : string = Venice.Hex.encode (Sha2.Sha256.digest s)

(* The parse of a quote, as an option, so every row below reads a value
   that exists only when parse succeeded.  A failed parse makes its
   rows FALSE and never raises. *)
let parsed (s : string) : Q.t option = Result.to_option (Q.parse s)

let q4 : Q.t option = parsed v4

(* One row helper per surface, so a row names the accessor it pins and
   nothing else. *)
let on_quote (f : Q.t -> bool) : bool = Option.fold ~none:false ~some:f q4

let on_header (f : H.t -> bool) : bool =
  on_quote (fun (q : Q.t) -> f (Q.header q))

let on_body (f : B.t -> bool) : bool =
  on_quote (fun (q : Q.t) -> f (Q.body q))

let on_sec (f : S.t -> bool) : bool =
  on_quote (fun (q : Q.t) -> f (Q.signature_section q))

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

(* The quote truncated to n bytes, by the same total cursor. *)
let cut (s : string) (n : int) : string =
  Option.value ~default:s (C.take s 0 n)

(* True when the parse of s refuses with exactly the given error, which
   is compared through Errx.to_string so the row pins the REASON TEXT
   and not a constructor shape. *)
let rejects (s : string) (e : Errx.t) : bool =
  Result.fold
    ~ok:(fun (_ : Q.t) -> false)
    ~error:(fun (got : Errx.t) ->
      String.equal (Errx.to_string got) (Errx.to_string e))
    (Q.parse s)

(* A total substring test, one window at a time through the cursor. *)
let contains (hay : string) (needle : string) : bool =
  let n = String.length needle in
  let rec at (i : int) : bool =
    match () with
    | () when i + n > String.length hay -> false
    | () when Option.fold ~none:false ~some:(String.equal needle) (C.take hay i n)
      ->
        true
    | () -> at (i + 1)
  in
  at 0

(* The PAINTED quote of group (f).  paint is PURE: String.mapi rebuilds
   the string one byte at a time, so no Bytes value and no Buffer value
   exists here.  Each guard names one window and the byte it fills.

   The eight bytes at 160 are written 08 07 06 05 04 03 02 01, because
   seam_attributes is LITTLE-endian and must read back as
   72623859790382856L; the reversed fill would read 578437695752307201L
   instead. *)
let paint (s : string) : string =
  String.mapi
    (fun (i : int) (c : char) ->
      match () with
      | () when i >= 112 && i < 160 -> '\xa1'
      | () when i >= 232 && i < 280 -> '\xa2'
      | () when i >= 280 && i < 328 -> '\xa3'
      | () when i >= 328 && i < 376 -> '\xa4'
      | () when i >= 520 && i < 568 -> '\xa6'
      | () when i >= 1122 && i < 1154 -> '\xa5'
      | () when Int.equal i 160 -> '\x08'
      | () when Int.equal i 161 -> '\x07'
      | () when Int.equal i 162 -> '\x06'
      | () when Int.equal i 163 -> '\x05'
      | () when Int.equal i 164 -> '\x04'
      | () when Int.equal i 165 -> '\x03'
      | () when Int.equal i 166 -> '\x02'
      | () when Int.equal i 167 -> '\x01'
      | () when Int.equal i 8 -> '\x01'
      | () when Int.equal i 9 -> '\x00'
      | () when Int.equal i 10 -> '\x02'
      | () when Int.equal i 11 -> '\x00'
      | () -> c)
    s

let painted : string = paint v4
let qp : Q.t option = parsed painted
let on_painted (f : Q.t -> bool) : bool = Option.fold ~none:false ~some:f qp

let on_painted_body (f : B.t -> bool) : bool =
  on_painted (fun (q : Q.t) -> f (Q.body q))

(* ---------- (a) fixture identity ---------------------------------- *)

let identity_checks : (string * bool) list =
  [ ( "quotex: (a) the v4 fixture embeds 5006 bytes",
      Int.equal (String.length v4) 5006 );
    ( "quotex: (a) the v5 fixture embeds 5006 bytes",
      Int.equal (String.length v5) 5006 );
    ( "quotex: (a) the v4 fixture sha256",
      String.equal (sha v4)
        "c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db" );
    ( "quotex: (a) the v5 fixture sha256",
      String.equal (sha v5)
        "4c453ea417a7863ed67c215fe4735d91e26f359c760e5984a277866d8d5758e9" )
  ]

(* ---------- (b) the header, 48 bytes at 0 ------------------------- *)

let header_checks : (string * bool) list =
  [ ( "quotex: (b) version",
      on_header (fun (h : H.t) -> Int.equal (H.version h) 4) );
    ( "quotex: (b) att_key_type",
      on_header (fun (h : H.t) -> Int.equal (H.att_key_type h) 2) );
    ( "quotex: (b) tee_type",
      on_header (fun (h : H.t) -> Int.equal (H.tee_type h) 129) );
    ( "quotex: (b) the raw u16 at 8",
      on_header (fun (h : H.t) -> Int.equal (H.header_u16_at_8 h) 0) );
    ( "quotex: (b) the raw u16 at 10",
      on_header (fun (h : H.t) -> Int.equal (H.header_u16_at_10 h) 0) );
    ( "quotex: (b) qe_vendor_id",
      on_header (fun (h : H.t) ->
          String.equal
            (hex (H.qe_vendor_id h))
            "939a7233f79c4ca9940a0db3957f0607") );
    ( "quotex: (b) user_data",
      on_header (fun (h : H.t) ->
          String.equal
            (hex (H.user_data h))
            "889b7d6ff9df2405b240a830e73faf3d00000000") )
  ]

(* ---------- (c) the TD report 1.0 body, 584 bytes at 48 ----------- *)

let body_checks : (string * bool) list =
  [ ( "quotex: (c) tee_tcb_svn",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.tee_tcb_svn b)) "06010300000000000000000000000000") );
    ( "quotex: (c) mr_seam",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.mr_seam b))
            "5b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c1") );
    ( "quotex: (c) mrsigner_seam is all zero",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.mrsigner_seam b))
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") );
    ( "quotex: (c) mr_td",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.mr_td b))
            "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7") );
    ( "quotex: (c) mr_config_id is all zero",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.mr_config_id b))
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") );
    ( "quotex: (c) mr_owner is all zero",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.mr_owner b))
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") );
    ( "quotex: (c) mr_owner_config is all zero",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.mr_owner_config b))
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") );
    ( "quotex: (c) rt_mr0",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.rt_mr0 b))
            "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0") );
    ( "quotex: (c) rt_mr1",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.rt_mr1 b))
            "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378") );
    ( "quotex: (c) rt_mr2",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.rt_mr2 b))
            "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132") );
    ( "quotex: (c) rt_mr3 is all zero",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.rt_mr3 b))
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") );
    ( "quotex: (c) report_data",
      on_body (fun (b : B.t) ->
          String.equal (hex (B.report_data b))
            "9a9d48e7f6799642d3d1b34e1e5e1742d4bb02dd6ddd551862c1211d35c304f9eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20") );
    ( "quotex: (c) seam_attributes as int64",
      on_body (fun (b : B.t) -> Int64.equal (B.seam_attributes b) 0L) );
    ( "quotex: (c) td_attributes as int64, bit 28 set and the DEBUG bit clear",
      on_body (fun (b : B.t) -> Int64.equal (B.td_attributes b) 268435456L) );
    ( "quotex: (c) xfam as int64",
      on_body (fun (b : B.t) -> Int64.equal (B.xfam b) 393959L) )
  ]

(* ---------- (d) the signed region and the length rule ------------- *)

let signed_checks : (string * bool) list =
  [ ( "quotex: (d) signed_region is 632 bytes",
      on_quote (fun (q : Q.t) -> Int.equal (String.length (Q.signed_region q)) 632) );
    ( "quotex: (d) signed_region sha256",
      on_quote (fun (q : Q.t) ->
          String.equal
            (sha (Q.signed_region q))
            "263b491bb14d627cc0d13408888dbe1ef550b7b8265794702303300bc388ef17") );
    ( "quotex: (d) signature_data_len",
      on_quote (fun (q : Q.t) -> Int.equal (Q.signature_data_len q) 4300) );
    ( "quotex: (d) surplus, the trailing padding rule 4 records",
      on_quote (fun (q : Q.t) -> Int.equal (Q.surplus q) 70) )
  ]

(* ---------- (e) the signature section and the PEM chain ----------- *)

let section_checks : (string * bool) list =
  [ ( "quotex: (e) signature, 64 bytes at 636",
      on_sec (fun (s : S.t) ->
          String.equal (hex (S.signature s))
            "f156eac8ad01d79f7cce668f60005819b22f2151a66155a430ad4f7a9538ae31330f9dfd5424e7c4124b44a668cb97fe2da48e617252ee5aeb6252d48e9324e5") );
    ( "quotex: (e) attestation_key, 64 bytes at 700",
      on_sec (fun (s : S.t) ->
          String.equal (hex (S.attestation_key s))
            "c78ac5859b9f567238fad82ad63202bc516ee7ad14ec1d9adfc633e4cf5f71f73d6138ce76d0d9c1443f695464d1ed419c37ce696e70e95a5b317894a5897907") );
    ( "quotex: (e) cert_key_type",
      on_sec (fun (s : S.t) -> Int.equal (S.cert_key_type s) 6) );
    ( "quotex: (e) cert_size, which is signature_data_len minus 134",
      on_sec (fun (s : S.t) -> Int.equal (S.cert_size s) 4166) );
    ( "quotex: (e) qe_report is 384 bytes",
      on_sec (fun (s : S.t) -> Int.equal (String.length (S.qe_report s)) 384) );
    ( "quotex: (e) qe_report_data, the QE binding then 32 zero bytes",
      on_sec (fun (s : S.t) ->
          String.equal (hex (S.qe_report_data s))
            "c936492a774946af9b588f6b3bd8beddc5957d1761ded2c0bb61d7b64de5b3240000000000000000000000000000000000000000000000000000000000000000") );
    ( "quotex: (e) qe_report_signature, 64 bytes at 1154",
      on_sec (fun (s : S.t) ->
          String.equal (hex (S.qe_report_signature s))
            "ca1bd340a4c8437b3d3d6fcf8b40030ddb7ac7f22d9597f4b593120350c891cafdf7c699e6feac62e44d474b48c653114a2adf325623b6a218a166a27dfe8550") );
    ( "quotex: (e) qe_auth_size",
      on_sec (fun (s : S.t) -> Int.equal (S.qe_auth_size s) 32) );
    ( "quotex: (e) qe_auth_data",
      on_sec (fun (s : S.t) ->
          String.equal (hex (S.qe_auth_data s))
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f") );
    ( "quotex: (e) inner_cert_type, PCK_CERT_CHAIN",
      on_sec (fun (s : S.t) -> Int.equal (S.inner_cert_type s) 5) );
    ( "quotex: (e) inner_size, which is cert_size minus 456 minus qe_auth_size",
      on_sec (fun (s : S.t) -> Int.equal (S.inner_size s) 3678) );
    ( "quotex: (e) pem_window is 3678 bytes",
      on_sec (fun (s : S.t) -> Int.equal (String.length (S.pem_window s)) 3678) );
    ( "quotex: (e) pem_chain holds three blocks",
      on_sec (fun (s : S.t) -> Int.equal (List.length (S.pem_chain s)) 3) );
    ( "quotex: (e) pem_chain block lengths sum to the window",
      on_sec (fun (s : S.t) ->
          List.equal Int.equal
            (List.map String.length (S.pem_chain s))
            [ 1773; 956; 949 ]) );
    ( "quotex: (e) every pem_chain block opens on the BEGIN marker",
      on_sec (fun (s : S.t) ->
          List.for_all
            (fun (b : string) ->
              String.starts_with ~prefix:"-----BEGIN CERTIFICATE-----" b)
            (S.pem_chain s)) );
    ( "quotex: (e) every pem_chain block holds an END marker",
      on_sec (fun (s : S.t) ->
          List.for_all
            (fun (b : string) -> contains b "-----END CERTIFICATE-----")
            (S.pem_chain s)) );
    ( "quotex: (e) pem_chain block 3 keeps the one trailing NUL byte",
      on_sec (fun (s : S.t) ->
          match S.pem_chain s with
          | (_ : string) :: (_ : string) :: b3 :: (_ : string list) ->
              Option.fold ~none:false ~some:(String.equal "\000")
                (C.take b3 (String.length b3 - 1) 1)
          | (_ : string list) -> false) )
  ]

(* ---------- (f) the painted quote --------------------------------- *)

let painted_checks : (string * bool) list =
  [ ( "quotex: (f) the painted quote still parses and keeps its surplus",
      on_painted (fun (q : Q.t) -> Int.equal (Q.surplus q) 70) );
    ( "quotex: (f) the painted quote sha256",
      String.equal (sha painted)
        "c238f199840f534cd9a35e557b6f612e5701a6af247b5182c41c4027da59d713" );
    ( "quotex: (f) the painted signed region sha256",
      on_painted (fun (q : Q.t) ->
          String.equal
            (sha (Q.signed_region q))
            "f1e722cbaa0d5b8a196b99630a290402397de82e4b695a4b099e5a2922d65fd4") );
    ( "quotex: (f) painted mrsigner_seam holds its own byte",
      on_painted_body (fun (b : B.t) ->
          String.equal (hex (B.mrsigner_seam b))
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1") );
    ( "quotex: (f) painted mr_config_id holds its own byte",
      on_painted_body (fun (b : B.t) ->
          String.equal (hex (B.mr_config_id b))
            "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2") );
    ( "quotex: (f) painted mr_owner holds its own byte",
      on_painted_body (fun (b : B.t) ->
          String.equal (hex (B.mr_owner b))
            "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3") );
    ( "quotex: (f) painted mr_owner_config holds its own byte",
      on_painted_body (fun (b : B.t) ->
          String.equal (hex (B.mr_owner_config b))
            "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4") );
    ( "quotex: (f) painted rt_mr3 holds its own byte",
      on_painted_body (fun (b : B.t) ->
          String.equal (hex (B.rt_mr3 b))
            "a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6") );
    ( "quotex: (f) painted seam_attributes keeps every one of its eight bytes",
      on_painted_body (fun (b : B.t) ->
          Int64.equal (B.seam_attributes b) 72623859790382856L) );
    ( "quotex: (f) painted header_u16_at_8",
      on_painted (fun (q : Q.t) ->
          Int.equal (H.header_u16_at_8 (Q.header q)) 1) );
    ( "quotex: (f) painted header_u16_at_10",
      on_painted (fun (q : Q.t) ->
          Int.equal (H.header_u16_at_10 (Q.header q)) 2) );
    ( "quotex: (f) painted qe_report_data keeps the QE binding and paints its tail",
      on_painted (fun (q : Q.t) ->
          String.equal
            (hex (S.qe_report_data (Q.signature_section q)))
            "c936492a774946af9b588f6b3bd8beddc5957d1761ded2c0bb61d7b64de5b324a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5") );
    ( "quotex: (f) the painted quote keeps its three PEM blocks",
      on_painted (fun (q : Q.t) ->
          List.equal Int.equal
            (List.map String.length (S.pem_chain (Q.signature_section q)))
            [ 1773; 956; 949 ]) )
  ]

(* ---------- (g) rule 4, the ONE inequality ------------------------ *)

let rule4_checks : (string * bool) list =
  [ ( "quotex: (g) the fixture cut to the exact extent 4936 parses with no surplus",
      Option.fold ~none:false
        ~some:(fun (q : Q.t) -> Int.equal (Q.surplus q) 0)
        (parsed (cut v4 4936)) );
    ( "quotex: (g) the fixture cut to 4935 is one byte short of the section",
      rejects (cut v4 4935) (Errx.Quote_invalid "short: signature data") );
    ( "quotex: (g) seven appended zero bytes only grow the surplus",
      Option.fold ~none:false
        ~some:(fun (q : Q.t) -> Int.equal (Q.surplus q) 77)
        (parsed (v4 ^ String.make 7 '\000')) )
  ]

(* ---------- (h) the reject vocabulary and the check order --------- *)
(*
   One row per word of the CLOSED nineteen-word vocabulary, each built
   by the pure patch above over the v4 fixture, then the three
   two-fault rows that pin the check ORDER, then the v5 fixture itself.

   A two-fault row proves that the FIRST check of the wire order names
   the reason: without the order, a refactor could answer with the
   second fault and no single-fault row would notice. *)

let reject_checks : (string * bool) list =
  [ ( "quotex: (h) version 5 rejects by version",
      rejects (patch v4 0 "\005\000") (Errx.Quote_invalid "version 5") );
    ( "quotex: (h) att_key_type 3 rejects",
      rejects (patch v4 2 "\003\000") (Errx.Quote_invalid "att_key_type 3") );
    ( "quotex: (h) tee_type 0x80 rejects",
      rejects
        (patch v4 4 "\128\000\000\000")
        (Errx.Quote_invalid "tee_type 128") );
    ( "quotex: (h) a quote cut to 1 byte has no header",
      rejects (cut v4 1) (Errx.Quote_invalid "short: header") );
    ( "quotex: (h) a quote cut to 600 bytes has no body",
      rejects (cut v4 600) (Errx.Quote_invalid "short: body") );
    ( "quotex: (h) a quote cut to 634 bytes has no length word",
      rejects (cut v4 634) (Errx.Quote_invalid "short: signature_data_len") );
    ( "quotex: (h) a quote cut to 700 bytes fails rule 4",
      rejects (cut v4 700) (Errx.Quote_invalid "short: signature data") );
    ( "quotex: (h) signature_data_len 100 leaves no room for the cert header",
      rejects
        (patch v4 632 "\100\000\000\000")
        (Errx.Quote_invalid "short: cert header") );
    ( "quotex: (h) signature_data_len 200 leaves no room for the qe report",
      rejects
        (patch (patch v4 632 "\200\000\000\000") 766 "\066\000\000\000")
        (Errx.Quote_invalid "short: qe report") );
    ( "quotex: (h) signature_data_len 534 leaves no room for the qe signature",
      rejects
        (patch (patch v4 632 "\022\002\000\000") 766 "\144\001\000\000")
        (Errx.Quote_invalid "short: qe signature") );
    ( "quotex: (h) signature_data_len 583 leaves no room for the auth size",
      rejects
        (patch (patch v4 632 "\071\002\000\000") 766 "\193\001\000\000")
        (Errx.Quote_invalid "short: auth size") );
    ( "quotex: (h) qe_auth_size 5000 leaves no room for the auth data",
      rejects (patch v4 1218 "\136\019") (Errx.Quote_invalid "short: auth data") );
    ( "quotex: (h) signature_data_len 617 leaves no room for the inner type",
      rejects
        (patch (patch v4 632 "\105\002\000\000") 766 "\227\001\000\000")
        (Errx.Quote_invalid "short: inner type") );
    ( "quotex: (h) cert_key_type 7 rejects",
      rejects (patch v4 764 "\007\000") (Errx.Quote_invalid "cert_key_type 7") );
    ( "quotex: (h) cert_size 4096 breaks the first size equality",
      rejects
        (patch v4 766 "\000\016\000\000")
        (Errx.Quote_invalid "cert_size 4096") );
    ( "quotex: (h) inner certification type 4 rejects",
      rejects (patch v4 1252 "\004\000") (Errx.Quote_invalid "inner cert type 4") );
    ( "quotex: (h) inner size 4096 breaks the second size equality",
      rejects
        (patch v4 1254 "\000\016\000\000")
        (Errx.Quote_invalid "inner size 4096") );
    ( "quotex: (h) a pem window that does not open on the marker rejects",
      rejects
        (patch v4 1258 (String.make 27 '\255'))
        (Errx.Quote_invalid "pem chain: no marker at 0") );
    ( "quotex: (h) a blanked second marker leaves two certificates",
      rejects
        (patch v4 3031 (String.make 27 '\255'))
        (Errx.Quote_invalid "pem chain: 2 certificates") );
    ( "quotex: (h) order row 1, the v5 bytes cut to 40 still answer by version",
      rejects (cut v5 40) (Errx.Quote_invalid "version 5") );
    ( "quotex: (h) order row 2, att_key_type is read before tee_type",
      rejects
        (patch (patch v4 2 "\003\000") 4 "\128\000\000\000")
        (Errx.Quote_invalid "att_key_type 3") );
    ( "quotex: (h) order row 3, rule 4 fires before the certification data",
      rejects
        (cut (patch v4 764 "\007\000") 800)
        (Errx.Quote_invalid "short: signature data") );
    ( "quotex: (h) the v5 fixture is refused at the first check",
      rejects v5 (Errx.Quote_invalid "version 5") )
  ]

(* ---------- (i) the error text ------------------------------------ *)

let text_checks : (string * bool) list =
  [ ( "quotex: (i) a quote reason prints under the quote prefix",
      String.equal
        (Errx.to_string (Errx.Quote_invalid "version 5"))
        "quote: version 5" )
  ]

let () =
  run
    (identity_checks @ header_checks @ body_checks @ signed_checks
   @ section_checks @ painted_checks @ rule4_checks @ reject_checks
   @ text_checks)
