(* M24 policyx, the TDX attestation POLICY unit (DESIGN.md:404).

   Ten groups, in the order of the design brief:  (a) fixture identity
   and the five measurement pins, (b) Nonce, (c) Measurements, (d)
   address_of_key on the generator G, (e) the DEBUG bit, (f) the
   REPORTDATA binding, (g) the measurements against an Expect, (h) the
   check ORDER, (i) verify end to end and (j) the error text.

   Every pin sits INLINE in the boolean of its own row, because
   harness/diff_quote.py group (g) recomputes the five measurements,
   byte 168, the G address, the G report_data and the synthetic address
   from the fixture bytes and from its own keccak, and then requires
   each value to sit inside a CHECK ROW of this file with the row label
   stripped first.  A constant moved into a comment, into an unread
   top-level let or into a row NAME satisfies no pin and turns the gate
   RED.

   The fixture arrives as a GENERATED module.  test/dune runs embed.exe
   over fixtures/tdx_quote_v4.bin a third time, because a dune module
   belongs to exactly one stanza and fixture_v4 belongs to the
   test_quotex stanza, so this suite reads no file and carries no
   relative path (D2).

   The fixture report_data at 568 is PHALA's binding and not Venice's,
   so every binding row runs on a PAINTED copy through the patch idiom
   below and the UNPAINTED fixture is a reject row (W4).

   The unit lives behind venice.mli, so this suite binds it by its
   mangled name, exactly as test_keccakx, test_secpx and test_quotex
   do.

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

module P = Venice__Policyx
module Q = Venice__Quotex
module Errx = Venice__Errx
module B = Q.Body
module Addr = Venice__Keccakx.Address
module Pk = Venice__Secpx.Pubkey
module Sc = Venice__Secpx.Scalar
module C = Venice.Cursor

let v4 : string = Fixture_policy.bytes ()
let hex (s : string) : string = Venice.Hex.encode s
let sha (s : string) : string = Venice.Hex.encode (Sha2.Sha256.digest s)

(* The bytes of a hex string, or the empty string when the string is
   not strict hex.  An empty answer makes its row FALSE and never
   raises. *)
let unhex (h : string) : string =
  Option.value ~default:"" (Result.to_option (Venice.Hex.decode h))

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

let on_body_of (s : string) (f : B.t -> bool) : bool =
  Option.fold ~none:false ~some:(fun (q : Q.t) -> f (Q.body q)) (parsed s)

(* The verdict of a unit-answering check as TEXT, so a row pins the
   reason string and never a constructor shape.  "ok" is the accept. *)
let body_text (s : string) (f : B.t -> (unit, Errx.t) result) : string =
  Option.fold ~none:"parse failed"
    ~some:(fun (q : Q.t) ->
      Result.fold
        ~ok:(fun (() : unit) -> "ok")
        ~error:(fun (e : Errx.t) -> Errx.to_string e)
        (f (Q.body q)))
    (parsed s)

(* The same for check_measurements, which answers the measurements it
   observed.  The locally abstract type carries the expectation level
   through unchanged. *)
let meas_text (type l) (e : l P.Expect.t) (s : string) : string =
  Option.fold ~none:"parse failed"
    ~some:(fun (q : Q.t) ->
      Result.fold
        ~ok:(fun (_ : P.Measurements.t) -> "ok")
        ~error:(fun (er : Errx.t) -> Errx.to_string er)
        (P.check_measurements e (Q.body q)))
    (parsed s)

(* The whole order, as text.  This is the helper every group (h) and
   group (i) reject row reads. *)
let verify_text (type l) (expect : l P.Expect.t) (nonce : P.Nonce.t)
    (key : Pk.t) (s : string) : string =
  Option.fold ~none:"parse failed"
    ~some:(fun (q : Q.t) ->
      Result.fold
        ~ok:(fun (_ : l P.t) -> "ok")
        ~error:(fun (er : Errx.t) -> Errx.to_string er)
        (P.verify ~expect ~nonce ~signing_key:key q))
    (parsed s)

(* A predicate over the WITNESS a successful verify mints, false when
   any earlier step refused. *)
let on_witness (type l) (expect : l P.Expect.t) (nonce : P.Nonce.t)
    (key : Pk.t) (s : string) (f : l P.t -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun (q : Q.t) ->
      Result.fold ~ok:f
        ~error:(fun (_ : Errx.t) -> false)
        (P.verify ~expect ~nonce ~signing_key:key q))
    (parsed s)

(* ---------- the vectors ------------------------------------------- *)

(* The secp256k1 generator G, minted as the public key of the scalar 1
   (W5), and the nonce of the harness synthetic pair (W6). *)
let g_key : Pk.t option =
  Option.bind
    (Sc.of_bytes
       (unhex
          "0000000000000000000000000000000000000000000000000000000000000001"))
    Pk.of_scalar

let g_address : Addr.t option = Option.bind g_key P.address_of_key

let g_nonce : P.Nonce.t option =
  P.Nonce.of_hex
    "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293"

(* The five measurements the fixture carries (W3), as an expectation. *)
let fixture_meas : P.Measurements.t option =
  P.Measurements.make
    ~mr_td:
      (unhex
         "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7")
    ~rt_mr0:
      (unhex
         "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0")
    ~rt_mr1:
      (unhex
         "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378")
    ~rt_mr2:
      (unhex
         "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132")
    ~rt_mr3:(String.make 48 '\000')

let full_expect : P.Expect.full P.Expect.t option =
  Option.map
    (fun (m : P.Measurements.t) -> P.Expect.make ~measurements:m)
    fixture_meas

(* The PAINTED quote: the G address, twelve zero bytes and the RAW
   nonce written over the 64-byte report_data window at 568 (W1, W5). *)
let painted : string =
  patch v4 568
    (unhex "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    ^ String.make 12 '\000'
    ^ unhex
        "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293")

(* The same binding under the SYNTHETIC address of the harness, which
   is off the curve and therefore reaches the unit as an address and
   never as a public key (W6). *)
let synthetic : string =
  patch v4 568
    (unhex "5cd71875c4d0ab1708a380e03fefc3a28aa24831"
    ^ String.make 12 '\000'
    ^ unhex
        "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293")

(* The binding verdict of one quote against one address, as text. *)
let binds (s : string) (address : Addr.t option) : string =
  Option.fold ~none:"no vector"
    ~some:(fun (((n : P.Nonce.t), (a : Addr.t)) : P.Nonce.t * Addr.t) ->
      body_text s (P.check_binding ~nonce:n ~address:a))
    (Option.bind g_nonce (fun (n : P.Nonce.t) ->
         Option.map (fun (a : Addr.t) -> (n, a)) address))

(* The full and the structural setups.  A row that needs the whole
   order reads one of these, so a missing vector makes the row FALSE
   and never raises. *)
let full_setup : (P.Expect.full P.Expect.t * P.Nonce.t * Pk.t) option =
  Option.bind full_expect (fun (e : P.Expect.full P.Expect.t) ->
      Option.bind g_nonce (fun (n : P.Nonce.t) ->
          Option.map (fun (k : Pk.t) -> (e, n, k)) g_key))

let tofu_setup : (P.Expect.structural P.Expect.t * P.Nonce.t * Pk.t) option =
  Option.bind g_nonce (fun (n : P.Nonce.t) ->
      Option.map (fun (k : Pk.t) -> (P.Expect.tofu (), n, k)) g_key)

let on_full
    (f : P.Expect.full P.Expect.t -> P.Nonce.t -> Pk.t -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun (((e : P.Expect.full P.Expect.t), (n : P.Nonce.t), (k : Pk.t)) :
                 P.Expect.full P.Expect.t * P.Nonce.t * Pk.t) -> f e n k)
    full_setup

let on_tofu
    (f : P.Expect.structural P.Expect.t -> P.Nonce.t -> Pk.t -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun (((e : P.Expect.structural P.Expect.t), (n : P.Nonce.t),
                 (k : Pk.t)) :
                 P.Expect.structural P.Expect.t * P.Nonce.t * Pk.t) -> f e n k)
    tofu_setup

(* The five measurements a body carries, as one hex string per field,
   so a row pins what the unit OBSERVED. *)
let observed_hex (w : 'l P.t) (f : P.Measurements.t -> string) : string =
  hex (f (P.measurements w))

let on_nonce (f : P.Nonce.t -> bool) : bool =
  Option.fold ~none:false ~some:f g_nonce

let zero48 : string = String.make 48 '\000'
let one48 : string = String.make 48 '\001'

(* The name first_mismatch answers, or "none" when the five agree and
   "no vector" when a build refused. *)
let mismatch_name (expected : P.Measurements.t option)
    (observed : P.Measurements.t option) : string =
  Option.value ~default:"no vector"
    (Option.bind expected (fun (x : P.Measurements.t) ->
         Option.map
           (fun (y : P.Measurements.t) ->
             Option.value ~default:"none"
               (P.Measurements.first_mismatch ~expected:x ~observed:y))
           observed))

(* ---------- (a) fixture identity and the W3 pins ------------------- *)

let identity_checks : (string * bool) list =
  [ ("policyx: (a) the embedded fixture is 5006 bytes",
     Int.equal (String.length v4) 5006);
    ( "policyx: (a) the embedded fixture digest",
      String.equal (sha v4)
        "c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db" );
    ( "policyx: (a) mr_td at 184",
      on_body_of v4 (fun (b : B.t) ->
          String.equal (hex (B.mr_td b))
            "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7")
    );
    ( "policyx: (a) rt_mr0 at 376",
      on_body_of v4 (fun (b : B.t) ->
          String.equal (hex (B.rt_mr0 b))
            "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0")
    );
    ( "policyx: (a) rt_mr1 at 424",
      on_body_of v4 (fun (b : B.t) ->
          String.equal (hex (B.rt_mr1 b))
            "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378")
    );
    ( "policyx: (a) rt_mr2 at 472",
      on_body_of v4 (fun (b : B.t) ->
          String.equal (hex (B.rt_mr2 b))
            "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132")
    );
    ( "policyx: (a) rt_mr3 at 520 is all zero",
      on_body_of v4 (fun (b : B.t) ->
          String.equal (hex (B.rt_mr3 b))
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    );
    ( "policyx: (a) td_attributes at 168 is 268435456L and byte 168 is zero",
      on_body_of v4 (fun (b : B.t) ->
          Int64.equal (B.td_attributes b) 268435456L
          && Int64.equal (Int64.logand (B.td_attributes b) 255L) 0L) );
    ( "policyx: (a) seam_attributes at 160 is zero",
      on_body_of v4 (fun (b : B.t) -> Int64.equal (B.seam_attributes b) 0L) )
  ]

(* ---------- (b) Nonce ---------------------------------------------- *)

let nonce_checks : (string * bool) list =
  [ ("policyx: (b) Nonce.len is 32", Int.equal (P.Nonce.len ()) 32);
    ( "policyx: (b) of_bytes refuses 31 bytes",
      Option.is_none (P.Nonce.of_bytes (String.make 31 '\000')) );
    ( "policyx: (b) of_bytes accepts 32 bytes",
      Option.is_some (P.Nonce.of_bytes (String.make 32 '\000')) );
    ( "policyx: (b) of_bytes refuses 33 bytes",
      Option.is_none (P.Nonce.of_bytes (String.make 33 '\000')) );
    ( "policyx: (b) of_hex refuses 63 characters",
      Option.is_none (P.Nonce.of_hex (String.make 63 '0')) );
    ( "policyx: (b) of_hex accepts 64 characters",
      Option.is_some (P.Nonce.of_hex (String.make 64 '0')) );
    ( "policyx: (b) of_hex refuses 65 characters",
      Option.is_none (P.Nonce.of_hex (String.make 65 '0')) );
    ( "policyx: (b) of_hex refuses one byte outside the hex alphabet",
      Option.is_none (P.Nonce.of_hex (String.make 63 '0' ^ "z")) );
    ( "policyx: (b) to_bytes round trips the raw 32 bytes",
      on_nonce (fun (n : P.Nonce.t) ->
          String.equal (hex (P.Nonce.to_bytes n))
            "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293")
    );
    ( "policyx: (b) to_hex round trips the 64 characters",
      on_nonce (fun (n : P.Nonce.t) ->
          String.equal (P.Nonce.to_hex n)
            "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293")
    );
    ( "policyx: (b) equal is true on a rebuild of the same bytes",
      on_nonce (fun (n : P.Nonce.t) ->
          Option.fold ~none:false
            ~some:(fun (m : P.Nonce.t) -> P.Nonce.equal n m)
            (P.Nonce.of_bytes (P.Nonce.to_bytes n))) );
    ( "policyx: (b) equal is false on the last-byte flip",
      on_nonce (fun (n : P.Nonce.t) ->
          Option.fold ~none:false
            ~some:(fun (m : P.Nonce.t) -> not (P.Nonce.equal n m))
            (P.Nonce.of_hex
               "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718292"))
    )
  ]

(* ---------- (c) Measurements --------------------------------------- *)

let measurement_checks : (string * bool) list =
  [ ( "policyx: (c) make refuses a 47-byte mr_td",
      Option.is_none
        (P.Measurements.make ~mr_td:(String.make 47 '\000') ~rt_mr0:zero48
           ~rt_mr1:zero48 ~rt_mr2:zero48 ~rt_mr3:zero48) );
    ( "policyx: (c) make refuses a 49-byte rt_mr3",
      Option.is_none
        (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
           ~rt_mr2:zero48 ~rt_mr3:(String.make 49 '\000')) );
    ( "policyx: (c) make refuses a short rt_mr0",
      Option.is_none
        (P.Measurements.make ~mr_td:zero48 ~rt_mr0:(String.make 47 '\000')
           ~rt_mr1:zero48 ~rt_mr2:zero48 ~rt_mr3:zero48) );
    ( "policyx: (c) make refuses a short rt_mr1",
      Option.is_none
        (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48
           ~rt_mr1:(String.make 47 '\000') ~rt_mr2:zero48 ~rt_mr3:zero48) );
    ( "policyx: (c) make refuses a short rt_mr2",
      Option.is_none
        (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
           ~rt_mr2:(String.make 47 '\000') ~rt_mr3:zero48) );
    ( "policyx: (c) make accepts five 48-byte fields",
      Option.is_some
        (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
           ~rt_mr2:zero48 ~rt_mr3:zero48) );
    ( "policyx: (c) of_body equals make of the five W3 pins",
      on_body_of v4 (fun (b : B.t) ->
          Option.fold ~none:false
            ~some:(fun (m : P.Measurements.t) ->
              P.Measurements.equal m (P.Measurements.of_body b))
            (P.Measurements.make
               ~mr_td:
                 (unhex
                    "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7")
               ~rt_mr0:
                 (unhex
                    "44c0197b39157fdd7a4dcc44767f9d6b0bb3977c7a8e347b8492f827fe9d9e5c48aca29b220b80b6a540cf994b9bc9c0")
               ~rt_mr1:
                 (unhex
                    "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378")
               ~rt_mr2:
                 (unhex
                    "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132")
               ~rt_mr3:
                 (unhex
                    "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")))
    );
    ( "policyx: (c) the mr_td accessor answers the fixture value",
      on_body_of v4 (fun (b : B.t) ->
          String.equal
            (hex (P.Measurements.mr_td (P.Measurements.of_body b)))
            (hex (B.mr_td b))) );
    ( "policyx: (c) the four rtmr accessors answer the fixture values",
      on_body_of v4 (fun (b : B.t) ->
          let m = P.Measurements.of_body b in
          String.equal (P.Measurements.rt_mr0 m) (B.rt_mr0 b)
          && String.equal (P.Measurements.rt_mr1 m) (B.rt_mr1 b)
          && String.equal (P.Measurements.rt_mr2 m) (B.rt_mr2 b)
          && String.equal (P.Measurements.rt_mr3 m) (B.rt_mr3 b)) );
    ( "policyx: (c) equal is true on two identical builds",
      on_body_of v4 (fun (b : B.t) ->
          P.Measurements.equal
            (P.Measurements.of_body b)
            (P.Measurements.of_body b)) );
    ( "policyx: (c) equal is false when one field differs",
      Option.fold ~none:false
        ~some:(fun (m : P.Measurements.t) ->
          Option.fold ~none:false
            ~some:(fun (n : P.Measurements.t) ->
              not (P.Measurements.equal m n))
            (P.Measurements.make ~mr_td:one48 ~rt_mr0:zero48 ~rt_mr1:zero48
               ~rt_mr2:zero48 ~rt_mr3:zero48))
        (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
           ~rt_mr2:zero48 ~rt_mr3:zero48) );
    ( "policyx: (c) first_mismatch is None when all five agree",
      String.equal
        (mismatch_name
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48)
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48))
        "none" );
    ( "policyx: (c) first_mismatch names mr_td",
      String.equal
        (mismatch_name
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48)
           (P.Measurements.make ~mr_td:one48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48))
        "mr_td" );
    ( "policyx: (c) first_mismatch names rt_mr0",
      String.equal
        (mismatch_name
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48)
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:one48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48))
        "rt_mr0" );
    ( "policyx: (c) first_mismatch names rt_mr1",
      String.equal
        (mismatch_name
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48)
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:one48
              ~rt_mr2:zero48 ~rt_mr3:zero48))
        "rt_mr1" );
    ( "policyx: (c) first_mismatch names rt_mr2",
      String.equal
        (mismatch_name
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48)
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:one48 ~rt_mr3:zero48))
        "rt_mr2" );
    ( "policyx: (c) first_mismatch names rt_mr3",
      String.equal
        (mismatch_name
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48)
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:one48))
        "rt_mr3" );
    ( "policyx: (c) two faults answer the FIRST field of the order",
      String.equal
        (mismatch_name
           (P.Measurements.make ~mr_td:zero48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:zero48)
           (P.Measurements.make ~mr_td:one48 ~rt_mr0:zero48 ~rt_mr1:zero48
              ~rt_mr2:zero48 ~rt_mr3:one48))
        "mr_td" )
  ]

(* ---------- (d) address_of_key on the generator G ------------------ *)

let on_key (f : Pk.t -> bool) : bool = Option.fold ~none:false ~some:f g_key

let on_address (f : Addr.t -> bool) : bool =
  Option.fold ~none:false ~some:f g_address

let key_checks : (string * bool) list =
  [ ("policyx: (d) the scalar 1 mints a public key", Option.is_some g_key);
    ( "policyx: (d) to_bytes of G is the 64 bytes X then Y",
      on_key (fun (k : Pk.t) ->
          String.equal (hex (Pk.to_bytes k))
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
    ( "policyx: (d) address_of_key answers an address for G",
      Option.is_some g_address );
    ( "policyx: (d) the address of G is the well-known one",
      on_address (fun (a : Addr.t) ->
          String.equal (Addr.to_hex a)
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") );
    ( "policyx: (d) that address equals of_hex of the same 40 characters",
      on_address (fun (a : Addr.t) ->
          Option.fold ~none:false
            ~some:(fun (b : Addr.t) -> Addr.equal a b)
            (Addr.of_hex "7e5f4552091a69125d5dfcb7b8c2659029395bdf")) )
  ]

(* ---------- (e) the DEBUG bit, a MASK and never a byte test -------- *)

let debug_checks : (string * bool) list =
  [ ( "policyx: (e) the untouched fixture passes check_debug",
      String.equal (body_text v4 P.check_debug) "ok" );
    ( "policyx: (e) byte 168 set to 0x01 is a debug td reject",
      String.equal
        (body_text (patch v4 168 "\001") P.check_debug)
        "policy: debug td" );
    ( "policyx: (e) byte 168 set to 0x02 passes, because the test is a mask",
      String.equal (body_text (patch v4 168 "\002") P.check_debug) "ok" );
    ( "policyx: (e) byte 168 set to 0x11 is a debug td reject",
      String.equal
        (body_text (patch v4 168 "\017") P.check_debug)
        "policy: debug td" );
    ( "policyx: (e) byte 160 set to 0x01 passes and moves seam_attributes only",
      String.equal (body_text (patch v4 160 "\001") P.check_debug) "ok"
      && on_body_of (patch v4 160 "\001") (fun (b : B.t) ->
             Int64.equal (B.seam_attributes b) 1L
             && Int64.equal (B.td_attributes b) 268435456L) )
  ]

(* ---------- (f) the REPORTDATA binding ----------------------------- *)

let binding_checks : (string * bool) list =
  [ ( "policyx: (f) the painted report_data is the address, the zero pad and the RAW nonce",
      on_body_of painted (fun (b : B.t) ->
          let want =
            "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
            ^ "000000000000000000000000"
            ^ "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293"
          in
          String.equal (hex (B.report_data b)) want) );
    ( "policyx: (f) the painted quote passes the binding",
      String.equal (binds painted g_address) "ok" );
    ( "policyx: (f) the last nonce byte flipped at 631 is a nonce mismatch",
      String.equal
        (binds (patch painted 631 "\146") g_address)
        "policy: nonce mismatch" );
    ( "policyx: (f) address byte 0 flipped at 568 is an address mismatch",
      String.equal
        (binds (patch painted 568 "\127") g_address)
        "policy: address mismatch" );
    ( "policyx: (f) pad byte 20 at 588 set non-zero is pad not zero",
      String.equal
        (binds (patch painted 588 "\001") g_address)
        "policy: pad not zero" );
    ( "policyx: (f) pad byte 31 at 599 set non-zero is pad not zero",
      String.equal
        (binds (patch painted 599 "\001") g_address)
        "policy: pad not zero" );
    ( "policyx: (f) the ED25519 key window at 588 is pad not zero",
      String.equal
        (binds
           (patch painted 588 (unhex "5455565758595a5b5c5d5e5f"))
           g_address)
        "policy: pad not zero" );
    ( "policyx: (f) the UNPAINTED fixture is an address mismatch",
      String.equal (binds v4 g_address) "policy: address mismatch" );
    ( "policyx: (f) the synthetic address and nonce pair passes",
      String.equal
        (binds synthetic
           (Addr.of_hex "5cd71875c4d0ab1708a380e03fefc3a28aa24831"))
        "ok" );
    ( "policyx: (f) a sha256 of the nonce written at 600 is a nonce mismatch",
      String.equal
        (sha
           (unhex
              "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293"))
        "fdf9a774d8e482405f342b30f6a8ba747d0d7de0badd8dfbe5f7c0ad35adab94"
      && String.equal
           (binds
              (patch painted 600
                 (Sha2.Sha256.digest
                    (unhex
                       "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293")))
              g_address)
           "policy: nonce mismatch" )
  ]

(* ---------- (g) the measurements against an Expect ----------------- *)

let meas_full (s : string) : string =
  Option.fold ~none:"no vector"
    ~some:(fun (e : P.Expect.full P.Expect.t) -> meas_text e s)
    full_expect

let expect_checks : (string * bool) list =
  [ ( "policyx: (g) a full Expect over the five W3 pins passes on the painted body",
      String.equal (meas_full painted) "ok" );
    ( "policyx: (g) Expect.measurements answers the five it was built from",
      Option.fold ~none:false
        ~some:(fun (e : P.Expect.full P.Expect.t) ->
          Option.fold ~none:false
            ~some:(fun (m : P.Measurements.t) ->
              P.Measurements.equal (P.Expect.measurements e) m)
            fixture_meas)
        full_expect );
    ( "policyx: (g) the witness measurements equal of_body of the same body",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          on_witness e n k painted (fun (w : P.Expect.full P.t) ->
              on_body_of painted (fun (b : B.t) ->
                  P.Measurements.equal (P.measurements w)
                    (P.Measurements.of_body b)))) );
    ( "policyx: (g) mr_td painted at 184 is a mr_td mismatch",
      String.equal
        (meas_full (patch painted 184 "\144"))
        "policy: mr_td mismatch" );
    ( "policyx: (g) rt_mr0 painted at 376 is a rt_mr0 mismatch",
      String.equal
        (meas_full (patch painted 376 "\069"))
        "policy: rt_mr0 mismatch" );
    ( "policyx: (g) rt_mr1 painted at 424 is a rt_mr1 mismatch",
      String.equal
        (meas_full (patch painted 424 "\001"))
        "policy: rt_mr1 mismatch" );
    ( "policyx: (g) rt_mr2 painted at 472 is a rt_mr2 mismatch",
      String.equal
        (meas_full (patch painted 472 "\217"))
        "policy: rt_mr2 mismatch" );
    ( "policyx: (g) rt_mr3 painted at 520 is a rt_mr3 mismatch",
      String.equal
        (meas_full (patch painted 520 "\001"))
        "policy: rt_mr3 mismatch" );
    ( "policyx: (g) mr_td and rt_mr3 both painted answer the FIRST field",
      String.equal
        (meas_full (patch (patch painted 184 "\144") 520 "\001"))
        "policy: mr_td mismatch" );
    ( "policyx: (g) a tofu Expect compares nothing and passes the painted mr_td",
      String.equal
        (meas_text (P.Expect.tofu ()) (patch painted 184 "\144"))
        "ok" );
    ( "policyx: (g) a tofu witness records the PAINTED measurements it saw",
      on_tofu
        (fun (e : P.Expect.structural P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          on_witness e n k
            (patch painted 184 "\144")
            (fun (w : P.Expect.structural P.t) ->
              String.equal
                (observed_hex w P.Measurements.mr_td)
                "90eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7"))
    )
  ]

(* ---------- (h) the check ORDER, six pairs ------------------------- *)

let order_checks : (string * bool) list =
  [ ( "policyx: (h) debug set and a bad address answer debug td",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal
            (verify_text e n k (patch (patch painted 168 "\001") 568 "\127"))
            "policy: debug td") );
    ( "policyx: (h) a bad address and a bad pad answer address mismatch",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal
            (verify_text e n k (patch (patch painted 568 "\127") 588 "\001"))
            "policy: address mismatch") );
    ( "policyx: (h) a bad pad and a bad nonce answer pad not zero",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal
            (verify_text e n k (patch (patch painted 588 "\001") 631 "\146"))
            "policy: pad not zero") );
    ( "policyx: (h) a bad nonce and a bad mr_td answer nonce mismatch",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal
            (verify_text e n k (patch (patch painted 631 "\146") 184 "\144"))
            "policy: nonce mismatch") );
    ( "policyx: (h) debug set and a bad nonce answer debug td",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal
            (verify_text e n k (patch (patch painted 168 "\001") 631 "\146"))
            "policy: debug td") );
    ( "policyx: (h) a bad address and a bad nonce answer address mismatch",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal
            (verify_text e n k (patch (patch painted 568 "\127") 631 "\146"))
            "policy: address mismatch") )
  ]

(* ---------- (i) verify end to end ---------------------------------- *)

(* The parse verdict as text, so the W9 row pins the REASON of the
   quote layer and proves it is not a policy word. *)
let quote_text (s : string) : string =
  Result.fold
    ~ok:(fun (_ : Q.t) -> "ok")
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    (Q.parse s)

let end_to_end_checks : (string * bool) list =
  [ ( "policyx: (i) verify of the painted quote with G answers Ok",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal (verify_text e n k painted) "ok") );
    ( "policyx: (i) the witness signing_address is the address of G",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          on_witness e n k painted (fun (w : P.Expect.full P.t) ->
              String.equal
                (Addr.to_hex (P.signing_address w))
                "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")) );
    ( "policyx: (i) the witness nonce round trips to the 64 characters",
      on_full (fun (e : P.Expect.full P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          on_witness e n k painted (fun (w : P.Expect.full P.t) ->
              String.equal
                (P.Nonce.to_hex (P.nonce w))
                "5f7a1c93b20e46d8a1f0c3b7e59d4826ac13f0d5e6b7981a2c3d4e5f60718293"))
    );
    ( "policyx: (i) a structural verify row compiles and answers Ok",
      on_tofu
        (fun (e : P.Expect.structural P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          String.equal (verify_text e n k painted) "ok") );
    ( "policyx: (i) the structural witness carries the same address",
      on_tofu
        (fun (e : P.Expect.structural P.Expect.t) (n : P.Nonce.t) (k : Pk.t) ->
          on_witness e n k painted (fun (w : P.Expect.structural P.t) ->
              String.equal
                (Addr.to_hex (P.signing_address w))
                "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")) );
    ( "policyx: (i) a version 5 quote is refused before policy runs",
      String.equal
        (quote_text (patch v4 0 "\005\000"))
        "quote: version 5" );
    ( "policyx: (i) that version reject carries no policy word",
      Option.fold ~none:false
        ~some:(fun (p : string) ->
          String.equal p "quote:" && not (String.equal p "policy"))
        (C.take (quote_text (patch v4 0 "\005\000")) 0 6) )
  ]

(* ---------- (j) the error text, ten words -------------------------- *)

let text_checks : (string * bool) list =
  [ ( "policyx: (j) a policy reason prints under the policy prefix",
      String.equal
        (Errx.to_string (Errx.Policy_rejected "debug td"))
        "policy: debug td" );
    ( "policyx: (j) the word debug td comes from the DEBUG reject",
      String.equal
        (body_text (patch v4 168 "\001") P.check_debug)
        (Errx.to_string (Errx.Policy_rejected "debug td")) );
    ( "policyx: (j) the word signing key is the fail-closed arm of address_of_key",
      String.equal
        (Errx.to_string (Errx.Policy_rejected "signing key"))
        "policy: signing key" );
    ( "policyx: (j) the word address mismatch comes from the address window",
      String.equal (binds v4 g_address)
        (Errx.to_string (Errx.Policy_rejected "address mismatch")) );
    ( "policyx: (j) the word pad not zero comes from the zero pad window",
      String.equal
        (binds (patch painted 588 "\001") g_address)
        (Errx.to_string (Errx.Policy_rejected "pad not zero")) );
    ( "policyx: (j) the word nonce mismatch comes from the nonce window",
      String.equal
        (binds (patch painted 631 "\146") g_address)
        (Errx.to_string (Errx.Policy_rejected "nonce mismatch")) );
    ( "policyx: (j) the word mr_td mismatch comes from the first measurement",
      String.equal
        (meas_full (patch painted 184 "\144"))
        (Errx.to_string (Errx.Policy_rejected "mr_td mismatch")) );
    ( "policyx: (j) the word rt_mr0 mismatch comes from the second measurement",
      String.equal
        (meas_full (patch painted 376 "\069"))
        (Errx.to_string (Errx.Policy_rejected "rt_mr0 mismatch")) );
    ( "policyx: (j) the word rt_mr1 mismatch comes from the third measurement",
      String.equal
        (meas_full (patch painted 424 "\001"))
        (Errx.to_string (Errx.Policy_rejected "rt_mr1 mismatch")) );
    ( "policyx: (j) the word rt_mr2 mismatch comes from the fourth measurement",
      String.equal
        (meas_full (patch painted 472 "\217"))
        (Errx.to_string (Errx.Policy_rejected "rt_mr2 mismatch")) );
    ( "policyx: (j) the word rt_mr3 mismatch comes from the fifth measurement",
      String.equal
        (meas_full (patch painted 520 "\001"))
        (Errx.to_string (Errx.Policy_rejected "rt_mr3 mismatch")) )
  ]

let () =
  run
    (identity_checks @ nonce_checks @ measurement_checks @ key_checks
   @ debug_checks @ binding_checks @ expect_checks @ order_checks
   @ end_to_end_checks @ text_checks)
