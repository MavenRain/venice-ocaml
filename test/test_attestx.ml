(* Synthetic envelope, real Intel-signed quote. A successful pipeline
   cannot be demonstrated with this fixture's Phala binding. *)
module A = Venice__Attestx
module P = Venice__Policyx
module Q = Venice__Quotex
module D = Venice__Derx
module T = Venice__Tcbx
module J = Venice__Jsonx
module E = Venice__Errx

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (name, (_ : bool)) -> print_endline ("FAIL " ^ name)) bad;
  Printf.printf "%d/%d ok\n" (List.length checks - List.length bad) (List.length checks);
  exit (if List.is_empty bad then 0 else 1)

let v4 = Fixture_attest_quote.bytes ()
let envelope = Fixture_attest_envelope.bytes ()
let collateral = T.Collateral.of_envelope (Fixture_attest_collateral.bytes ())
let parsed = A.Envelope.of_json envelope
let sha (s : string) : string = Venice.Hex.encode (Sha2.Sha256.digest s)
let good (f : 'a -> bool) (r : ('a, E.t) result) : bool =
  Result.fold ~ok:f ~error:(fun (_ : E.t) -> false) r
let error (word : string) (r : ('a, E.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> false)
    ~error:(fun e -> String.equal (E.to_string e) word) r
let win (s : string) (off : int) (len : int) : string =
  Option.value ~default:"" (Venice.Cursor.take s off len)
let patch (s : string) (off : int) (repl : string) : string =
  let len = String.length repl in
  win s 0 off ^ repl ^ win s (off + len) (String.length s - off - len)
let nonce = P.Nonce.of_bytes (win v4 600 32)
let with_nonce (f : P.Nonce.t -> bool) : bool = Option.fold ~none:false ~some:f nonce
let nonce_hex = Venice.Hex.encode (win v4 600 32)
let key_hex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
let address_hex = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
let base_fields = Option.value ~default:[]
  (Option.bind (Result.to_option (J.parse envelope)) J.as_obj)
let set (fields : (string * J.t) list) (name : string) (value : J.t) : (string * J.t) list =
  (name, value) :: List.filter (fun (key, (_ : J.t)) -> not (String.equal name key)) fields
let drop (fields : (string * J.t) list) (name : string) : (string * J.t) list =
  List.filter (fun (key, (_ : J.t)) -> not (String.equal name key)) fields
let response (fields : (string * J.t) list) : string = J.emit (J.Jobj fields)
let payload_fields = ["nonce", J.Jstring nonce_hex; "arch", J.Jstring "HOPPER";
                      "evidence_list", J.Jlist [J.Jstring "c3ludGhldGlj"]]
let payload (fields : (string * J.t) list) : J.t = J.Jobj fields
let payload_ok (value : J.t) : bool = with_nonce (fun nonce ->
  Result.is_ok (A.parse_payload ~nonce value))
let payload_error (word : string) (value : J.t) : bool = with_nonce (fun nonce ->
  error word (A.parse_payload ~nonce value))
let at (seconds : int) (digits : string) : bool =
  Option.fold ~none:false ~some:(fun now -> String.equal (D.Now.to_string now) digits)
    (A.now_of_unix ~seconds)
let verify_with ~(digits : string) ~(collateral : (T.Collateral.t, E.t) result)
    (fields : (string * J.t) list) : (P.Expect.structural A.Attested.t, E.t) result =
  Option.fold ~none:(Error (E.Attest_invalid "test nonce")) ~some:(fun nonce ->
    Option.fold ~none:(Error (E.Attest_invalid "test time")) ~some:(fun now ->
      Result.bind collateral (fun collateral ->
        A.verify ~now ~expect:(P.Expect.tofu ()) ~nonce ~collateral
          ~response:(response fields))) (D.Now.of_digits digits)) nonce
let verify (fields : (string * J.t) list) : (P.Expect.structural A.Attested.t, E.t) result =
  verify_with ~digits:"20250620103227" ~collateral fields
(* The pinned collateral with its TCB Info signature zeroed, the ONE
   collateral fault a row can drive through verify without a forgery. *)
let faulty_collateral : (T.Collateral.t, E.t) result =
  Result.map (fun c ->
    T.Collateral.make ~tcb_info:(T.Collateral.tcb_info c)
      ~tcb_info_signature:(String.make 128 '0')
      ~tcb_info_chain:(T.Collateral.tcb_info_chain c)
      ~qe_identity:(T.Collateral.qe_identity c)
      ~qe_identity_signature:(T.Collateral.qe_identity_signature c)
      ~qe_identity_chain:(T.Collateral.qe_identity_chain c)) collateral

let full_verify (expect : P.Expect.full P.Expect.t) ~(now : D.Now.t)
    ~(nonce : P.Nonce.t) ~(collateral : T.Collateral.t) ~(response : string) :
    (P.Expect.full A.Attested.t, E.t) result =
  A.verify ~now ~expect ~nonce ~collateral ~response

let () = run [
  ("attestx: (j) full expectation still requires the binding",
   with_nonce (fun nonce -> good (fun quote ->
     Option.fold ~none:false ~some:(fun now -> good (fun collateral ->
       error "policy: address mismatch"
         (full_verify (P.Expect.make ~measurements:(P.Measurements.of_body (Q.body quote)))
            ~now ~nonce ~collateral ~response:envelope)) collateral)
       (D.Now.of_digits "20250620103227")) (Q.parse v4)));
  ("attestx: (a) quote bytes",
   Int.equal (String.length v4) 5006);
  ("attestx: (a) envelope bytes",
   Int.equal (String.length envelope) 7244);
  ("attestx: (a) quote digest",
   String.equal (sha v4) "c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db");
  ("attestx: (a) envelope digest",
   String.equal (sha envelope) "42ae89da0487d362d33824c0db8e2d8a4cd7ddc6f28a71eb6bf9d3cb4a0515ee");
  ("attestx: (a) quote member length",
   good (fun e -> Int.equal (String.length (A.Envelope.intel_quote e)) 6676) parsed);
  ("attestx: (a) quote member digest",
   good (fun e -> String.equal (sha (A.Envelope.intel_quote e)) "53461521bc893f93cecd4279e1e0762deb7cbe503b29d295ebe4efb18e2e49f5") parsed);
  ("attestx: (a) echo pin",
   good (fun e -> String.equal (A.Envelope.nonce_echo e) "eca3efdbb481601c163cf52493d6e44aed55d51ec39b7e518fadb92c2b523f20") parsed);
  ("attestx: (a) key pin",
   good (fun e -> String.equal (A.Envelope.signing_key_hex e) "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8") parsed);
  ("attestx: (a) address pin",
   good (fun e -> String.equal (A.Envelope.signing_address_hex e) "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") parsed);
  ("attestx: (a) model metadata",
   good (fun e -> Option.equal String.equal (A.Envelope.model e) (Some "synthetic-fixture")) parsed);
  ("attestx: (b) reject top 10",
   error "attest: envelope" (A.Envelope.of_json "[]"));
  ("attestx: (b) reject top 11",
   error "attest: envelope" (A.Envelope.of_json "null"));
  ("attestx: (b) reject top 12",
   error "attest: envelope" (A.Envelope.of_json "true"));
  ("attestx: (b) reject top 13",
   error "attest: envelope" (A.Envelope.of_json "1"));
  ("attestx: (b) reject top 14",
   error "attest: envelope" (A.Envelope.of_json "\"object\""));
  ("attestx: (b) reject top 15",
   error "attest: envelope" (A.Envelope.of_json "{"));
  ("attestx: (b) reject top 16",
   error "attest: envelope" (A.Envelope.of_json "{\"intel_quote\":\"x\",\"intel_quote\":\"y\"}"));
  ("attestx: (b) intel_quote missing",
   error "attest: intel quote member" (A.Envelope.of_json (response (drop base_fields "intel_quote"))));
  ("attestx: (b) intel_quote null",
   error "attest: intel quote member" (A.Envelope.of_json (response (set base_fields "intel_quote" J.Jnull))));
  ("attestx: (b) intel_quote number",
   error "attest: intel quote member" (A.Envelope.of_json (response (set base_fields "intel_quote" (J.Jint 1)))));
  ("attestx: (b) signing_key missing",
   error "attest: signing key member" (A.Envelope.of_json (response (drop base_fields "signing_key"))));
  ("attestx: (b) signing_key null",
   error "attest: signing key member" (A.Envelope.of_json (response (set base_fields "signing_key" J.Jnull))));
  ("attestx: (b) signing_key number",
   error "attest: signing key member" (A.Envelope.of_json (response (set base_fields "signing_key" (J.Jint 1)))));
  ("attestx: (b) signing_address missing",
   error "attest: signing address member" (A.Envelope.of_json (response (drop base_fields "signing_address"))));
  ("attestx: (b) signing_address null",
   error "attest: signing address member" (A.Envelope.of_json (response (set base_fields "signing_address" J.Jnull))));
  ("attestx: (b) signing_address number",
   error "attest: signing address member" (A.Envelope.of_json (response (set base_fields "signing_address" (J.Jint 1)))));
  ("attestx: (b) nonce missing",
   error "attest: nonce member" (A.Envelope.of_json (response (drop base_fields "nonce"))));
  ("attestx: (b) nonce null",
   error "attest: nonce member" (A.Envelope.of_json (response (set base_fields "nonce" J.Jnull))));
  ("attestx: (b) nonce number",
   error "attest: nonce member" (A.Envelope.of_json (response (set base_fields "nonce" (J.Jint 1)))));
  ("attestx: (b) alternate echo",
   Result.is_ok (A.Envelope.of_json (response (set (drop base_fields "nonce") "request_nonce" (J.Jstring nonce_hex)))));
  ("attestx: (b) primary malformed no fallback",
   error "attest: nonce member" (A.Envelope.of_json (response (set (set base_fields "nonce" J.Jnull) "request_nonce" (J.Jstring nonce_hex)))));
  ("attestx: (b) optional model wrong type",
   good (fun e -> Option.is_none (A.Envelope.model e)) (A.Envelope.of_json (response (set base_fields "model" (J.Jint 1)))));
  ("attestx: (c) raw",
   with_nonce (fun nonce -> Result.is_ok (A.check_echo ~nonce ~echo:(nonce_hex))));
  ("attestx: (c) uppercase",
   with_nonce (fun nonce -> Result.is_ok (A.check_echo ~nonce ~echo:(String.uppercase_ascii nonce_hex))));
  ("attestx: (c) changed",
   with_nonce (fun nonce -> error "attest: nonce echo" (A.check_echo ~nonce ~echo:(String.make 64 '0'))));
  ("attestx: (c) short",
   with_nonce (fun nonce -> error "attest: nonce echo" (A.check_echo ~nonce ~echo:(win nonce_hex 0 62))));
  ("attestx: (c) prefixed",
   with_nonce (fun nonce -> error "attest: nonce echo" (A.check_echo ~nonce ~echo:("0x" ^ nonce_hex))));
  ("attestx: (d) base64",
   good (fun quote -> String.equal (Q.signed_region quote) (win v4 0 632)) (A.decode_quote (Venice.B64.encode_std v4)));
  ("attestx: (d) hex",
   good (fun quote -> String.equal (Q.signed_region quote) (win v4 0 632)) (A.decode_quote (Venice.Hex.encode v4)));
  ("attestx: (d) bad alphabet",
   error "attest: intel quote encoding" (A.decode_quote ("!")));
  ("attestx: (d) empty",
   error "attest: intel quote encoding" (A.decode_quote ("")));
  ("attestx: (d) v5",
   error "attest: intel quote encoding" (A.decode_quote (Venice.B64.encode_std (patch v4 0 "\005\000"))));
  ("attestx: (d) v4 truncated",
   error "quote: short: header" (A.decode_quote ("BAA=")));
  ("attestx: (d) v4 bad tee",
   error "quote: tee_type 0" (A.decode_quote (Venice.B64.encode_std (patch v4 4 "\000\000\000\000"))));
  ("attestx: (e) SEC1",
   Result.is_ok (A.check_signing_key ~key_hex:(key_hex) ~address_hex));
  ("attestx: (e) raw64",
   Result.is_ok (A.check_signing_key ~key_hex:(win key_hex 2 128) ~address_hex));
  ("attestx: (e) prefixed",
   Result.is_ok (A.check_signing_key ~key_hex:("0x" ^ key_hex) ~address_hex));
  ("attestx: (e) uppercase",
   Result.is_ok (A.check_signing_key ~key_hex:(String.uppercase_ascii key_hex) ~address_hex));
  ("attestx: (e) bad hex",
   error "attest: signing key" (A.check_signing_key ~key_hex:("zz") ~address_hex));
  ("attestx: (e) off curve",
   error "attest: signing key" (A.check_signing_key ~key_hex:(String.make 128 '0') ~address_hex));
  ("attestx: (e) compressed",
   error "attest: signing key" (A.check_signing_key ~key_hex:("02" ^ win key_hex 2 64) ~address_hex));
  ("attestx: (e) bad prefix",
   error "attest: signing key" (A.check_signing_key ~key_hex:("05" ^ win key_hex 2 128) ~address_hex));
  ("attestx: (e) address mismatch",
   error "attest: signing address" (A.check_signing_key ~key_hex ~address_hex:(String.make 40 '0')));
  ("attestx: (e) address malformed",
   error "attest: signing address" (A.check_signing_key ~key_hex ~address_hex:"zz"));
  ("attestx: (e) address uppercase",
   Result.is_ok (A.check_signing_key ~key_hex ~address_hex:(String.uppercase_ascii (win address_hex 2 40))));
  ("attestx: (f) object",
   payload_ok (payload payload_fields));
  ("attestx: (f) string",
   payload_ok (J.Jstring (J.emit (payload payload_fields))));
  ("attestx: (f) payload fields",
   with_nonce (fun nonce -> good (fun p -> String.equal (A.Gpu.Payload.nonce_hex p) nonce_hex && String.equal (A.Gpu.Payload.arch p) "HOPPER" && Int.equal (A.Gpu.Payload.evidence_count p) 1) (A.parse_payload ~nonce (payload payload_fields))));
  ("attestx: (f) wrong outer 58",
   payload_error "attest: nvidia payload" (J.Jnull));
  ("attestx: (f) wrong outer 59",
   payload_error "attest: nvidia payload" (J.Jbool true));
  ("attestx: (f) wrong outer 60",
   payload_error "attest: nvidia payload" (J.Jint 1));
  ("attestx: (f) wrong outer 61",
   payload_error "attest: nvidia payload" (J.Jlist []));
  ("attestx: (f) bad inner 62",
   payload_error "attest: nvidia payload json" (J.Jstring "{"));
  ("attestx: (f) bad inner 63",
   payload_error "attest: nvidia payload json" (J.Jstring "[]"));
  ("attestx: (f) bad inner 64",
   payload_error "attest: nvidia payload json" (J.Jstring "null"));
  ("attestx: (f) bad inner 65",
   payload_error "attest: nvidia payload json" (J.Jstring "{\"nonce\":\"x\",\"nonce\":\"y\"}"));
  ("attestx: (f) missing nonce",
   payload_error "attest: nvidia payload members" (payload (drop payload_fields "nonce")));
  ("attestx: (f) missing arch",
   payload_error "attest: nvidia payload members" (payload (drop payload_fields "arch")));
  ("attestx: (f) missing evidence_list",
   payload_error "attest: nvidia payload members" (payload (drop payload_fields "evidence_list")));
  ("attestx: (f) wrong nonce",
   payload_error "attest: nvidia payload members" (payload (set payload_fields "nonce" J.Jnull)));
  ("attestx: (f) wrong arch",
   payload_error "attest: nvidia payload members" (payload (set payload_fields "arch" J.Jnull)));
  ("attestx: (f) mismatch",
   payload_error "attest: nvidia payload nonce" (payload (set payload_fields "nonce" (J.Jstring (String.make 64 '0')))));
  ("attestx: (f) short",
   payload_error "attest: nvidia payload nonce" (payload (set payload_fields "nonce" (J.Jstring (win nonce_hex 0 62)))));
  ("attestx: (f) uppercase nonce",
   payload_ok (payload (set payload_fields "nonce" (J.Jstring (String.uppercase_ascii nonce_hex)))));
  ("attestx: (f) empty list",
   payload_error "attest: nvidia evidence list" (payload (set payload_fields "evidence_list" (J.Jlist []))));
  ("attestx: (f) string evidence",
   payload_error "attest: nvidia evidence list" (payload (set payload_fields "evidence_list" (J.Jstring "x"))));
  ("attestx: (f) null evidence",
   payload_error "attest: nvidia evidence list" (payload (set payload_fields "evidence_list" (J.Jnull))));
  ("attestx: (f) arch carried",
   with_nonce (fun nonce -> good (fun p -> String.equal (A.Gpu.Payload.arch p) "BLACKWELL") (A.parse_payload ~nonce (payload (set payload_fields "arch" (J.Jstring "BLACKWELL"))))));
  ("attestx: (f) evidence contents opaque",
   payload_ok (payload (set payload_fields "evidence_list" (J.Jlist [J.Jnull; J.Jint 1]))));
  ("attestx: (g) absent",
   with_nonce (fun nonce -> good (function A.Gpu.Absent -> true | A.Gpu.Present (_ : A.Gpu.Payload.t) -> false) (A.check_gpu ~nonce None)));
  ("attestx: (g) present",
   with_nonce (fun nonce -> good (function A.Gpu.Absent -> false | A.Gpu.Present p -> Int.equal (A.Gpu.Payload.evidence_count p) 1) (A.check_gpu ~nonce (Some (payload payload_fields)))));
  ("attestx: (g) null is absent",
   with_nonce (fun nonce -> good (function A.Gpu.Absent -> true | A.Gpu.Present (_ : A.Gpu.Payload.t) -> false) (A.check_gpu ~nonce (Some J.Jnull))));
  ("attestx: (g) a bool is present invalid",
   with_nonce (fun nonce -> error "attest: nvidia payload" (A.check_gpu ~nonce (Some (J.Jbool true)))));
  ("attestx: (g) a list is present invalid",
   with_nonce (fun nonce -> error "attest: nvidia payload" (A.check_gpu ~nonce (Some (J.Jlist [])))));
  ("attestx: (h) 0",
   at 0 "19700101000000");
  ("attestx: (h) 1",
   at 1 "19700101000001");
  ("attestx: (h) 59",
   at 59 "19700101000059");
  ("attestx: (h) 60",
   at 60 "19700101000100");
  ("attestx: (h) 3599",
   at 3599 "19700101005959");
  ("attestx: (h) 3600",
   at 3600 "19700101010000");
  ("attestx: (h) 86399",
   at 86399 "19700101235959");
  ("attestx: (h) 86400",
   at 86400 "19700102000000");
  ("attestx: (h) 951782399",
   at 951782399 "20000228235959");
  ("attestx: (h) 951782400",
   at 951782400 "20000229000000");
  ("attestx: (h) 1709164800",
   at 1709164800 "20240229000000");
  ("attestx: (h) 4107542400",
   at 4107542400 "21000301000000");
  ("attestx: (h) 253402300799",
   at 253402300799 "99991231235959");
  ("attestx: (h) month 1",
   at 1735689600 "20250101000000");
  ("attestx: (h) month 2",
   at 1738368000 "20250201000000");
  ("attestx: (h) month 3",
   at 1740787200 "20250301000000");
  ("attestx: (h) month 4",
   at 1743465600 "20250401000000");
  ("attestx: (h) month 5",
   at 1746057600 "20250501000000");
  ("attestx: (h) month 6",
   at 1748736000 "20250601000000");
  ("attestx: (h) month 7",
   at 1751328000 "20250701000000");
  ("attestx: (h) month 8",
   at 1754006400 "20250801000000");
  ("attestx: (h) month 9",
   at 1756684800 "20250901000000");
  ("attestx: (h) month 10",
   at 1759276800 "20251001000000");
  ("attestx: (h) month 11",
   at 1761955200 "20251101000000");
  ("attestx: (h) month 12",
   at 1764547200 "20251201000000");
  ("attestx: (h) out of range -1",
   Option.is_none (A.now_of_unix ~seconds:(-1)));
  ("attestx: (h) out of range 253402300800",
   Option.is_none (A.now_of_unix ~seconds:(253402300800)));
  ("attestx: (i) chain signature TCB",
   good (fun quote -> Option.fold ~none:false ~some:(fun now -> good (fun chain -> good (fun signature -> good (fun collateral -> Result.is_ok (T.verify ~now ~collateral ~chain ~quote ~sig_:signature)) collateral) (Venice__Sigx.verify ~pck_key:(D.pck_key chain) quote)) (D.verify_chain ~now (Q.Signature_section.pem_chain (Q.signature_section quote)))) (D.Now.of_digits "20250620103227")) (Q.parse v4));
  ("attestx: (j) deepest policy failure",
   error "policy: address mismatch" (verify base_fields));
  ("attestx: (j) painted binding breaks signature",
   error "sig: isv signature mismatch" (verify (set base_fields "intel_quote" (J.Jstring (Venice.B64.encode_std (patch v4 568 (Option.value ~default:"" (Result.to_option (Venice.Hex.decode (win address_hex 2 40))) ^ String.make 12 '\000' ^ win v4 600 32)))))));
  ("attestx: (k) echo before encoding",
   error "attest: nonce echo" (verify (set (set base_fields "nonce" (J.Jstring "bad")) "intel_quote" (J.Jstring "!"))));
  ("attestx: (k) encoding before key",
   error "attest: intel quote encoding" (verify (set (set base_fields "intel_quote" (J.Jstring "!")) "signing_key" (J.Jstring "!"))));
  ("attestx: (k) key before policy",
   error "attest: signing key" (verify (set base_fields "signing_key" (J.Jstring "!"))));
  ("attestx: (k) address before policy",
   error "attest: signing address" (verify (set base_fields "signing_address" (J.Jstring "!"))));
  ("attestx: (k) policy before GPU",
   error "policy: address mismatch" (verify (set base_fields "nvidia_payload" (J.Jbool true))));
  ("attestx: (k) a null GPU payload is absent through verify",
   error "policy: address mismatch" (verify (set base_fields "nvidia_payload" J.Jnull)));
  (* Amendment A2: ONE flipped byte at 636, the first ECDSA signature
     byte, OUTSIDE the 632 signed bytes; the pinned byte is 0xf1. *)
  ("attestx: (k) signature before policy",
   error "sig: isv signature mismatch" (verify (set base_fields "intel_quote" (J.Jstring (Venice.B64.encode_std (patch v4 636 "\000"))))));
  ("attestx: (k) a stale now fails the chain through verify",
   error "cert: expired" (verify_with ~digits:"20330101000000" ~collateral base_fields));
  ("attestx: (k) an early now fails the chain through verify",
   error "cert: not yet valid" (verify_with ~digits:"20200101000000" ~collateral base_fields));
  ("attestx: (k) a zeroed tcb info signature fails the collateral through verify",
   error "tcb: tcb info signature" (verify_with ~digits:"20250620103227" ~collateral:faulty_collateral base_fields));
  ("attestx: (k) payload members before nonce",
   payload_error "attest: nvidia payload members" (payload (drop (set payload_fields "nonce" (J.Jstring "bad")) "arch")));
  ("attestx: (k) payload nonce before evidence",
   payload_error "attest: nvidia payload nonce" (payload (set (set payload_fields "nonce" (J.Jstring "bad")) "evidence_list" (J.Jlist []))));
  ("attestx: (l) envelope",
   String.equal (E.to_string (E.Attest_invalid "envelope")) "attest: envelope");
  ("attestx: (l) intel quote member",
   String.equal (E.to_string (E.Attest_invalid "intel quote member")) "attest: intel quote member");
  ("attestx: (l) intel quote encoding",
   String.equal (E.to_string (E.Attest_invalid "intel quote encoding")) "attest: intel quote encoding");
  ("attestx: (l) signing key member",
   String.equal (E.to_string (E.Attest_invalid "signing key member")) "attest: signing key member");
  ("attestx: (l) signing key",
   String.equal (E.to_string (E.Attest_invalid "signing key")) "attest: signing key");
  ("attestx: (l) signing address member",
   String.equal (E.to_string (E.Attest_invalid "signing address member")) "attest: signing address member");
  ("attestx: (l) signing address",
   String.equal (E.to_string (E.Attest_invalid "signing address")) "attest: signing address");
  ("attestx: (l) nonce member",
   String.equal (E.to_string (E.Attest_invalid "nonce member")) "attest: nonce member");
  ("attestx: (l) nonce echo",
   String.equal (E.to_string (E.Attest_invalid "nonce echo")) "attest: nonce echo");
  ("attestx: (l) nvidia payload",
   String.equal (E.to_string (E.Attest_invalid "nvidia payload")) "attest: nvidia payload");
  ("attestx: (l) nvidia payload json",
   String.equal (E.to_string (E.Attest_invalid "nvidia payload json")) "attest: nvidia payload json");
  ("attestx: (l) nvidia payload members",
   String.equal (E.to_string (E.Attest_invalid "nvidia payload members")) "attest: nvidia payload members");
  ("attestx: (l) nvidia payload nonce",
   String.equal (E.to_string (E.Attest_invalid "nvidia payload nonce")) "attest: nvidia payload nonce");
  ("attestx: (l) nvidia evidence list",
   String.equal (E.to_string (E.Attest_invalid "nvidia evidence list")) "attest: nvidia evidence list");
]
