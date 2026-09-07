(* test_tcbx: the M27 TCB suite (D11).  It proves the PCS collateral
   envelope, the TCB Info and QE Identity documents, the TCB Signing
   chain anchored to the pinned Intel SGX Root CA, the two detached
   document signatures, the platform and QE grades, the D4 check ORDER
   with its step (0) witness binding and the CLOSED thirty-two word
   reject vocabulary of tcbx.

   Every pin is a LITERAL inside the boolean of its own row, so
   harness/diff_quote.py group (j) can require each one to sit inside a
   check row and recompute it from the fixture bytes.

   The painting discipline of D8 holds.  A painted byte reaches the
   unit ONLY through a rebuilt input: a document row paints the
   document text or a hex digit of its signature and mints a fresh
   Collateral.make; a certificate row paints the DECODED DER, base64
   encodes it again, wraps it at the 64-character PEM line width and
   hands the rebuilt block back; a report row paints the 384 QE report
   bytes.  A painted byte then reaches EXACTLY the leg its row names,
   in the order the module header states: the binding, the chain, the
   TCB Info signature, its shape, its platform checks, its TDX module
   checks, its grade, the QE chain, the QE Identity signature, its
   shape, its checks and its grade.

   The twelve groups are (a) the envelope and the fixture identity,
   (b) the status map, (c) now_of_iso, (d) the two documents and their
   signatures, (e) the TCB Signing chain, (f) the TCB Info fields,
   (g) the platform grade, (h) the TDX module legs, (i) the QE
   Identity fields, (j) the QE grade, (k) verify end to end and its
   order, and (l) the closed vocabulary.

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

module T = Venice__Tcbx
module D = Venice__Derx
module Q = Venice__Quotex
module Sec = Q.Signature_section
module S = Venice__Sigx
module Errx = Venice__Errx
module P = Venice__P256x
module Pk = P.Pubkey
module C = Venice.Cursor
module J = Venice.Json

let v4 : string = Fixture_tcb.bytes ()
let envelope : string = Fixture_collateral.bytes ()
let hex (s : string) : string = Venice.Hex.encode s
let sha (s : string) : string = Venice.Hex.encode (Sha2.Sha256.digest s)

(* A TOTAL window read.  An out-of-range request answers the empty
   string, which makes its row FALSE and never raises. *)
let win (s : string) (off : int) (len : int) : string =
  Option.value ~default:"" (C.take s off len)

(* A TOTAL splice: the bytes of repl overwrite the same count of bytes
   at off and nothing else moves. *)
let patch (s : string) (off : int) (repl : string) : string =
  let n = String.length repl in
  Option.value ~default:s
    (Option.bind (C.take s 0 off) (fun (head : string) ->
         Option.map
           (fun (tail : string) -> head ^ repl ^ tail)
           (C.take s (off + n) (String.length s - off - n))))

(* The raw bytes of a hex string, the empty string when it is not hex,
   which no row accepts. *)
let raw (h : string) : string =
  Result.fold
    ~ok:(fun (s : string) -> s)
    ~error:(fun ((_ : Errx.t)) -> "")
    (Venice__Hexx.decode h)

(* The base64 body of a rebuilt block, wrapped at the 64-character PEM
   line width.  Both cuts are bounded by Venice.Cursor.take. *)
let rec wrap64 (s : string) (i : int) : string =
  let left = String.length s - i in
  if left <= 64 then win s i left else win s i 64 ^ "\n" ^ wrap64 s (i + 64)

(* ONE PEM block around raw DER bytes, in the shape the collateral
   uses: the 27-byte BEGIN marker, the wrapped body and the 25-byte
   END marker, each on its own line. *)
let block_of (der : string) : string =
  "-----BEGIN CERTIFICATE-----\n"
  ^ wrap64 (Venice.B64.encode_std der) 0
  ^ "\n-----END CERTIFICATE-----\n"

(* The instant the pinned collateral is fresh at, inside its own
   issueDate and nextUpdate windows. *)
let pinned (() : unit) : string = "20250620103227"

(* The verdict of a unit leg as TEXT, so a row pins the reason string
   and never a constructor shape.  "ok" is the accept. *)
let res_text (r : (unit, Errx.t) result) : string =
  Result.fold
    ~ok:(fun (() : unit) -> "ok")
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    r

(* ---------- the quote, the chain and the two witnesses ---------- *)

let quote_of (bytes : string) : Q.t option = Result.to_option (Q.parse bytes)
let quote (() : unit) : Q.t option = quote_of v4

let sec_str (f : Sec.t -> string) : string =
  Option.fold ~none:""
    ~some:(fun (q : Q.t) -> f (Q.signature_section q))
    (quote ())

let body_str (f : Q.Body.t -> string) : string =
  Option.fold ~none:"" ~some:(fun (q : Q.t) -> f (Q.body q)) (quote ())

let seam_attributes (() : unit) : int64 =
  Option.fold ~none:0L
    ~some:(fun (q : Q.t) -> Q.Body.seam_attributes (Q.body q))
    (quote ())

(* The 384 QE report bytes of the fixture, the buffer every QE grade
   row paints. *)
let report (() : unit) : string = sec_str Sec.qe_report

(* The three PEM blocks of the quote, leaf first and the pinned root
   last.  They are NOT the TCB Signing chain: a row hands one of them
   to check_signing_chain to reach the root pin and the keyUsage
   legs. *)
let pck_chain (() : unit) : string list =
  Option.fold ~none:[]
    ~some:(fun (q : Q.t) -> Sec.pem_chain (Q.signature_section q))
    (quote ())

let pck_block (i : int) : string =
  Option.value ~default:"" (List.nth_opt (pck_chain ()) i)

(* The M26 certificate witness, minted inside the PCK chain validity
   window, and the M25 signature witness it binds. *)
let derw (() : unit) : D.t option =
  Option.bind (D.Now.of_digits "20260906000000") (fun (n : D.Now.t) ->
      Result.to_option (D.verify_chain ~now:n (pck_chain ())))

let sigw (() : unit) : S.t option =
  Option.bind (derw ()) (fun (w : D.t) ->
      Option.bind (quote ()) (fun (q : Q.t) ->
          Result.to_option (S.verify ~pck_key:(D.pck_key w) q)))

(* ---------- the collateral ---------- *)

let col (() : unit) : T.Collateral.t option =
  Result.to_option (T.Collateral.of_envelope envelope)

let col_str (f : T.Collateral.t -> string) : string =
  Option.fold ~none:"" ~some:f (col ())

(* ONE string member of the envelope, read through the JSON unit, so a
   row pins the byte count of a member Collateral IGNORES. *)
let member (name : string) : string =
  Option.value ~default:""
    (Option.bind (Result.to_option (J.parse envelope)) (fun (j : J.t) ->
         Option.bind (J.member name j) (fun (v : J.t) -> J.as_string v)))

(* A collateral value with the named strings replaced and the rest
   taken from the fixture, the ONE way a painted document reaches
   verify. *)
let mint ?(tcb_info = col_str T.Collateral.tcb_info)
    ?(tcb_info_signature = col_str T.Collateral.tcb_info_signature)
    ?(tcb_info_chain = col_str T.Collateral.tcb_info_chain)
    ?(qe_identity = col_str T.Collateral.qe_identity)
    ?(qe_identity_signature = col_str T.Collateral.qe_identity_signature)
    ?(qe_identity_chain = col_str T.Collateral.qe_identity_chain) (() : unit) :
    T.Collateral.t =
  T.Collateral.make ~tcb_info ~tcb_info_signature ~tcb_info_chain ~qe_identity
    ~qe_identity_signature ~qe_identity_chain

(* ---------- the TCB Signing chain ---------- *)

let tcb_blocks (() : unit) : string list =
  T.blocks_of_chain (col_str T.Collateral.tcb_info_chain)

let signing_block (() : unit) : string =
  Option.value ~default:"" (List.nth_opt (tcb_blocks ()) 0)

let signing_cert (() : unit) : D.Cert.t option =
  Result.to_option (D.Cert.of_pem (signing_block ()))

let signing_der (() : unit) : string =
  Option.fold ~none:"" ~some:D.Cert.der (signing_cert ())

(* Block 1 with the bytes of repl painted over the same count of bytes
   at off of its DECODED DER, rebuilt into a PEM block. *)
let paint (off : int) (repl : string) : string =
  block_of (patch (signing_der ()) off repl)

(* Block 1 with basicConstraints cA TRUE. The pinned value at 568 is
   the empty SEQUENCE 30 00 (cA DEFAULT FALSE); it becomes
   30 03 01 01 ff and the six enclosing lengths grow by three: the
   Certificate at 2, the tbsCertificate at 6, the [3] extensions at
   388, the extensions SEQUENCE at 391, the extension SEQUENCE at 557
   and the OCTET STRING at 567. The keyUsage keeps digitalSignature and
   the signature no longer verifies, so the leg must refuse it BEFORE
   the signature step, under "signing cert". *)
let ca_block (() : unit) : string =
  let der = signing_der () in
  let grown =
    win der 0 568 ^ raw "300301" ^ raw "01ff"
    ^ win der 570 (String.length der - 570)
  in
  block_of
    (List.fold_left
       (fun (s : string) ((off : int), (hex : string)) -> patch s off (raw hex))
       grown
       [ (2, "0290"); (6, "0235"); (388, "b8"); (391, "b5"); (557, "0f"); (567, "05") ])

(* The verdict of check_signing_chain as TEXT, with the anchor
   EXPLICIT, so a row can hand it a certificate that is not the
   pinned root. *)
let chain_text ~(now : string) ~(root_pin : string) (blocks : string list) :
    string =
  Option.fold ~none:"no now"
    ~some:(fun (n : D.Now.t) ->
      Result.fold
        ~ok:(fun ((_ : Pk.t)) -> "ok")
        ~error:(fun (e : Errx.t) -> Errx.to_string e)
        (T.check_signing_chain ~now:n ~root_pin blocks))
    (D.Now.of_digits now)

let pin_text ~(now : string) (blocks : string list) : string =
  chain_text ~now ~root_pin:(D.root_pin ()) blocks

(* The TCB Signing key the pinned chain yields, the key both document
   rows verify under. *)
let signing_key (() : unit) : Pk.t option =
  Option.bind (D.Now.of_digits (pinned ())) (fun (n : D.Now.t) ->
      Result.to_option
        (T.check_signing_chain ~now:n ~root_pin:(D.root_pin ()) (tcb_blocks ())))

let doc_text ~(word : string) ~(signature : string) (document : string) :
    string =
  Option.fold ~none:"no key"
    ~some:(fun (k : Pk.t) ->
      res_text (T.check_document ~word ~key:k ~signature document))
    (signing_key ())

(* ---------- the two documents ---------- *)

let info_of (text : string) : T.Tcb_info.t option =
  Result.to_option (T.Tcb_info.of_json text)

let info (() : unit) : T.Tcb_info.t option =
  info_of (col_str T.Collateral.tcb_info)

let info_text (text : string) : string =
  Result.fold
    ~ok:(fun ((_ : T.Tcb_info.t)) -> "ok")
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    (T.Tcb_info.of_json text)

let i_str (f : T.Tcb_info.t -> string) : string =
  Option.fold ~none:"" ~some:f (info ())

let i_int (f : T.Tcb_info.t -> int) : int =
  Option.fold ~none:(-1) ~some:f (info ())

let i_time (f : T.Tcb_info.t -> D.Now.t) : string =
  Option.fold ~none:""
    ~some:(fun (v : T.Tcb_info.t) -> D.Now.to_string (f v))
    (info ())

let i_ids (() : unit) : string list =
  Option.fold ~none:[] ~some:T.Tcb_info.identity_ids (info ())

let i_mask (() : unit) : int64 =
  Option.fold ~none:1L ~some:T.Tcb_info.tdx_module_attributes_mask (info ())

let i_attributes (() : unit) : int64 =
  Option.fold ~none:1L ~some:T.Tcb_info.tdx_module_attributes (info ())

let qi_of (text : string) : T.Qe_identity.t option =
  Result.to_option (T.Qe_identity.of_json text)

let qi (() : unit) : T.Qe_identity.t option =
  qi_of (col_str T.Collateral.qe_identity)

let qi_text (text : string) : string =
  Result.fold
    ~ok:(fun ((_ : T.Qe_identity.t)) -> "ok")
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    (T.Qe_identity.of_json text)

let q_str (f : T.Qe_identity.t -> string) : string =
  Option.fold ~none:"" ~some:f (qi ())

let q_int (f : T.Qe_identity.t -> int) : int =
  Option.fold ~none:(-1) ~some:f (qi ())

let q_time (f : T.Qe_identity.t -> D.Now.t) : string =
  Option.fold ~none:""
    ~some:(fun (v : T.Qe_identity.t) -> D.Now.to_string (f v))
    (qi ())

(* ---------- the grades ---------- *)

(* The CONSTRUCTOR name of a status, so a row pins the OCaml spelling
   beside the Intel spelling of group (b). *)
let st_name (s : T.Status.t) : string =
  match s with
  | T.Status.Up_to_date -> "Up_to_date"
  | T.Status.Sw_hardening_needed -> "Sw_hardening_needed"
  | T.Status.Configuration_needed -> "Configuration_needed"
  | T.Status.Configuration_and_sw_hardening_needed ->
      "Configuration_and_sw_hardening_needed"
  | T.Status.Out_of_date -> "Out_of_date"
  | T.Status.Out_of_date_configuration_needed ->
      "Out_of_date_configuration_needed"
  | T.Status.Revoked -> "Revoked"

let of_name (text : string) : string =
  Option.fold ~none:"none" ~some:st_name (T.Status.of_string text)

let level_text (r : (T.Level.t, Errx.t) result) : string =
  Result.fold
    ~ok:(fun (lv : T.Level.t) -> st_name (T.Level.status lv))
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    r

let level_date (r : (T.Level.t, Errx.t) result) : string =
  Result.fold
    ~ok:(fun (lv : T.Level.t) -> D.Now.to_string (T.Level.tcb_date lv))
    ~error:(fun ((_ : Errx.t)) -> "")
    r

let level_advisories (r : (T.Level.t, Errx.t) result) : string list =
  Result.fold ~ok:T.Level.advisories ~error:(fun ((_ : Errx.t)) -> []) r

(* The platform grade of one TCB Info text under the named platform
   values. *)
let grade_of ~(cpusvn : string) ~(pcesvn : int) ~(tee_tcb_svn : string)
    (text : string) : (T.Level.t, Errx.t) result =
  Option.fold
    ~none:(Error (Errx.Tcb_invalid "no info"))
    ~some:(fun (v : T.Tcb_info.t) ->
      T.Tcb_info.grade v ~cpusvn ~pcesvn ~tee_tcb_svn)
    (info_of text)

let plat_text ~(now : string) ~(fmspc : string) ~(pce_id : string)
    (text : string) : string =
  Option.fold ~none:"no now"
    ~some:(fun (n : D.Now.t) ->
      Option.fold ~none:"no info"
        ~some:(fun (v : T.Tcb_info.t) ->
          res_text (T.Tcb_info.check_platform v ~now:n ~fmspc ~pce_id))
        (info_of text))
    (D.Now.of_digits now)

(* The verdict of check_tdx_module as TEXT: "ok" when no identity was
   graded, the status name of the graded identity level, or the reason. *)
let module_text ~(mrsigner_seam : string) ~(seam_attributes : int64)
    ~(tee_tcb_svn : string) (text : string) : string =
  Option.fold ~none:"no info"
    ~some:(fun (v : T.Tcb_info.t) ->
      Result.fold
        ~ok:(fun (m : T.Status.t option) ->
          Option.fold ~none:"ok" ~some:st_name m)
        ~error:(fun (e : Errx.t) -> Errx.to_string e)
        (T.Tcb_info.check_tdx_module v ~mrsigner_seam ~seam_attributes
           ~tee_tcb_svn))
    (info_of text)

let identity_text ~(now : string) (text : string) : string =
  Option.fold ~none:"no now"
    ~some:(fun (n : D.Now.t) ->
      Option.fold ~none:"no identity"
        ~some:(fun (v : T.Qe_identity.t) ->
          res_text (T.Qe_identity.check_identity v ~now:n))
        (qi_of text))
    (D.Now.of_digits now)

let qe_grade ~(qe_report : string) (text : string) : (T.Level.t, Errx.t) result
    =
  Option.fold
    ~none:(Error (Errx.Tcb_invalid "no identity"))
    ~some:(fun (v : T.Qe_identity.t) -> T.Qe_identity.grade v ~qe_report)
    (qi_of text)

(* ---------- verify end to end ---------- *)

(* The D4 answer over ONE collateral value and ONE quote buffer.  The
   Derx and Sigx witnesses come from the UNPAINTED quote, so a painted
   quote reaches step (0) instead of failing to parse a chain. *)
let witness_of ~(now : string) ~(bytes : string) (c : T.Collateral.t) :
    (T.t, Errx.t) result option =
  Option.bind (D.Now.of_digits now) (fun (n : D.Now.t) ->
      Option.bind (derw ()) (fun (w : D.t) ->
          Option.bind (sigw ()) (fun (s : S.t) ->
              Option.map
                (fun (q : Q.t) ->
                  T.verify ~now:n ~collateral:c ~chain:w ~quote:q ~sig_:s)
                (quote_of bytes))))

let verify_text ~(now : string) ~(bytes : string) (c : T.Collateral.t) : string
    =
  Option.fold ~none:"no witness"
    ~some:(fun (r : (T.t, Errx.t) result) ->
      Result.fold
        ~ok:(fun ((_ : T.t)) -> "ok")
        ~error:(fun (e : Errx.t) -> Errx.to_string e)
        r)
    (witness_of ~now ~bytes c)

(* The witness the pinned inputs mint, as an option, so an accessor
   row reads a value verify proved. *)
let witness (() : unit) : T.t option =
  Option.bind
    (witness_of ~now:(pinned ()) ~bytes:v4 (mint ()))
    Result.to_option

let w_str (f : T.t -> string) : string =
  Option.fold ~none:"" ~some:f (witness ())

let w_int (f : T.t -> int) : int = Option.fold ~none:(-1) ~some:f (witness ())

let w_status (f : T.t -> T.Status.t) : string =
  Option.fold ~none:"" ~some:(fun (w : T.t) -> st_name (f w)) (witness ())

let w_time (f : T.t -> D.Now.t) : string =
  Option.fold ~none:""
    ~some:(fun (w : T.t) -> D.Now.to_string (f w))
    (witness ())

let w_list (f : T.t -> string list) : string list =
  Option.fold ~none:[ "none" ] ~some:f (witness ())

(* ---------- the synthetic documents ---------- *)

(* D15: a field row reaches a check the pinned document alone cannot
   show, because every byte of the pinned document is covered by a
   signature this suite never forges.  A synthetic text goes straight
   to of_json and to the check leg, never through verify. *)

let rec pad (v : int list) (n : int) : int list =
  if n <= 0 then v else pad (v @ [ 0 ]) (n - 1)

(* Sixteen component svn, the head given and zeros after it. *)
let vec (head : int list) : int list = pad head (16 - List.length head)

let comps (v : int list) : string =
  "["
  ^ String.concat ","
      (List.map (fun (n : int) -> "{\"svn\":" ^ string_of_int n ^ "}") v)
  ^ "]"

let ti_level ?(sgx = [ 2; 2; 2; 2; 3; 1; 0; 5 ]) ?(pcesvn = 11)
    ?(tdx = [ 5; 0; 2 ]) ?(date = "2024-03-13T00:00:00Z")
    ?(status = "UpToDate") ?(advisories = "") (() : unit) : string =
  "{\"tcb\":{\"sgxtcbcomponents\":"
  ^ comps (vec sgx) ^ ",\"pcesvn\":" ^ string_of_int pcesvn
  ^ ",\"tdxtcbcomponents\":" ^ comps (vec tdx) ^ "},\"tcbDate\":\"" ^ date
  ^ "\",\"tcbStatus\":\"" ^ status ^ "\"" ^ advisories ^ "}"

let mod_level ?(isvsvn = 4) ?(date = "2024-03-13T00:00:00Z")
    ?(status = "UpToDate") (() : unit) : string =
  "{\"tcb\":{\"isvsvn\":" ^ string_of_int isvsvn ^ "},\"tcbDate\":\"" ^ date
  ^ "\",\"tcbStatus\":\"" ^ status ^ "\"}"

(* Ninety-six hex digits, the forty-eight zero bytes of the pinned
   tdxModule mrsigner. *)
let zeros96 (() : unit) : string =
  String.concat "" (List.map (fun (_ : int) -> "00") (pad [] 48))

let ti_identity ?(id = "TDX_01") ?(mrsigner = zeros96 ())
    ?(attributes = "0000000000000000") ?(mask = "FFFFFFFFFFFFFFFF")
    ?(levels = mod_level ()) (() : unit) : string =
  "{\"id\":\"" ^ id ^ "\",\"mrsigner\":\"" ^ mrsigner ^ "\",\"attributes\":\""
  ^ attributes ^ "\",\"attributesMask\":\"" ^ mask ^ "\",\"tcbLevels\":["
  ^ levels ^ "]}"

let ti_doc ?(id = "TDX") ?(version = "3") ?(issue = "2025-06-19T10:16:03Z")
    ?(next = "2025-07-19T10:16:03Z") ?(fmspc = "B0C06F000000")
    ?(pce_id = "0000") ?(tcb_type = "0") ?(eval = "17")
    ?(mrsigner = zeros96 ()) ?(attributes = "0000000000000000")
    ?(mask = "FFFFFFFFFFFFFFFF") ?(identities = ti_identity ())
    ?(with_identities = true) ?(levels = ti_level ()) (() : unit) : string =
  let identities_member =
    if with_identities then "\"tdxModuleIdentities\":[" ^ identities ^ "],"
    else ""
  in
  "{\"id\":\"" ^ id ^ "\",\"version\":" ^ version ^ ",\"issueDate\":\"" ^ issue
  ^ "\",\"nextUpdate\":\"" ^ next ^ "\",\"fmspc\":\"" ^ fmspc
  ^ "\",\"pceId\":\"" ^ pce_id ^ "\",\"tcbType\":" ^ tcb_type
  ^ ",\"tcbEvaluationDataNumber\":" ^ eval ^ ",\"tdxModule\":{\"mrsigner\":\""
  ^ mrsigner ^ "\",\"attributes\":\"" ^ attributes ^ "\",\"attributesMask\":\""
  ^ mask ^ "\"}," ^ identities_member ^ "\"tcbLevels\":[" ^ levels ^ "]}"

(* The converged platform status as TEXT: the platform level of a
   synthetic document with ONE level of status platform, converged with
   the named module status, None for no module status. *)
let converged ~(platform : string) ~(module_status : string option) : string =
  level_text
    (Result.map
       (fun (lv : T.Level.t) ->
         T.Tcb_info.converge lv (Option.bind module_status T.Status.of_string))
       (grade_of ~cpusvn:(raw "03030202040100050000000000000000") ~pcesvn:11
          ~tee_tcb_svn:(raw "06010300000000000000000000000000")
          (ti_doc ~levels:(ti_level ~status:platform ()) ())))

let qe_level ?(isvsvn = 4) ?(date = "2024-03-13T00:00:00Z")
    ?(status = "UpToDate") ?(advisories = "") (() : unit) : string =
  "{\"tcb\":{\"isvsvn\":" ^ string_of_int isvsvn ^ "},\"tcbDate\":\"" ^ date
  ^ "\",\"tcbStatus\":\"" ^ status ^ "\"" ^ advisories ^ "}"

let qe_doc ?(id = "TD_QE") ?(version = "2") ?(issue = "2025-06-19T10:32:27Z")
    ?(next = "2025-07-19T10:32:27Z") ?(eval = "17") ?(miscselect = "00000000")
    ?(miscselect_mask = "FFFFFFFF")
    ?(attributes = "11000000000000000000000000000000")
    ?(attributes_mask = "FBFFFFFFFFFFFFFF0000000000000000")
    ?(mrsigner =
      "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8C5")
    ?(isvprodid = "2") ?(levels = qe_level ()) (() : unit) : string =
  "{\"id\":\"" ^ id ^ "\",\"version\":" ^ version ^ ",\"issueDate\":\"" ^ issue
  ^ "\",\"nextUpdate\":\"" ^ next ^ "\",\"tcbEvaluationDataNumber\":" ^ eval
  ^ ",\"miscselect\":\"" ^ miscselect ^ "\",\"miscselectMask\":\""
  ^ miscselect_mask ^ "\",\"attributes\":\"" ^ attributes
  ^ "\",\"attributesMask\":\"" ^ attributes_mask ^ "\",\"mrsigner\":\""
  ^ mrsigner ^ "\",\"isvprodid\":" ^ isvprodid ^ ",\"tcbLevels\":[" ^ levels
  ^ "]}"

let () =
  run
    [
      (* ---------- (a) the envelope and the fixture identity ---------- *)
      ( "tcbx: (a) the collateral envelope is 16072 bytes",
        Int.equal (String.length envelope) 16072 );
      ( "tcbx: (a) the collateral envelope digest",
        String.equal (sha envelope)
          "b0a5f5fd620a8881b1eda45261fdf30dd930b49aff93231556645c81fcb4c0bc" );
      ( "tcbx: (a) the three CRL members are 1904, 584 and 5326 bytes",
        Int.equal (String.length (member "pck_crl_issuer_chain")) 1904
        && Int.equal (String.length (member "root_ca_crl")) 584
        && Int.equal (String.length (member "pck_crl")) 5326 );
      ( "tcbx: (a) the two issuer chains are 1892 bytes and the same string",
        Int.equal (String.length (member "tcb_info_issuer_chain")) 1892
        && Int.equal (String.length (member "qe_identity_issuer_chain")) 1892
        && String.equal
             (member "tcb_info_issuer_chain")
             (member "qe_identity_issuer_chain") );
      ( "tcbx: (a) the tcb info document is 2934 bytes",
        Int.equal (String.length (col_str T.Collateral.tcb_info)) 2934 );
      ( "tcbx: (a) the tcb info document digest",
        String.equal
          (sha (col_str T.Collateral.tcb_info))
          "369f99a122169e850d32bacb7970da74356f9746526256818124d9f646dd6ace" );
      ( "tcbx: (a) the qe identity document is 461 bytes",
        Int.equal (String.length (col_str T.Collateral.qe_identity)) 461 );
      ( "tcbx: (a) the qe identity document digest",
        String.equal
          (sha (col_str T.Collateral.qe_identity))
          "261a8b43ded29851e71f61b094e0aea2f12a6e6b75e38da2a49447e97ae15e96" );
      ( "tcbx: (a) the tcb info signature is 128 hex digits",
        String.equal
          (col_str T.Collateral.tcb_info_signature)
          "027ef6ca41bac64e61edbbd672b1c97eb0b2997400c5018eee002e66421b3fd27e71676891c9df47dc6ea3ea2e757ad3e080f394da0e0cddd76b2debe6790b4f"
        && Int.equal
             (String.length (col_str T.Collateral.tcb_info_signature))
             128 );
      ( "tcbx: (a) the qe identity signature is 128 hex digits",
        String.equal
          (col_str T.Collateral.qe_identity_signature)
          "d6d709840544c26e2ab3d680067d04b6160551f78aa23062cc79ab1be2ffe5414e21bf0fa9f0bea3c69be6c97d0a16585b82f6cc481059ad4affdc1c9bccfa15"
        && Int.equal
             (String.length (col_str T.Collateral.qe_identity_signature))
             128 );
      ( "tcbx: (a) of_envelope reads the six members and ignores the CRLs",
        String.equal (col_str T.Collateral.tcb_info) (member "tcb_info")
        && String.equal
             (col_str T.Collateral.tcb_info_signature)
             (member "tcb_info_signature")
        && String.equal
             (col_str T.Collateral.tcb_info_chain)
             (member "tcb_info_issuer_chain")
        && String.equal (col_str T.Collateral.qe_identity) (member "qe_identity")
        && String.equal
             (col_str T.Collateral.qe_identity_signature)
             (member "qe_identity_signature")
        && String.equal
             (col_str T.Collateral.qe_identity_chain)
             (member "qe_identity_issuer_chain") );
      ( "tcbx: (a) a non-object envelope says envelope",
        String.equal
          (res_text
             (Result.map
                (fun ((_ : T.Collateral.t)) -> ())
                (T.Collateral.of_envelope "[]")))
          "tcb: envelope" );
      ( "tcbx: (a) an envelope missing tcb_info says envelope",
        String.equal
          (res_text
             (Result.map
                (fun ((_ : T.Collateral.t)) -> ())
                (T.Collateral.of_envelope "{\"tcb_info_signature\":\"00\"}")))
          "tcb: envelope" );
      ( "tcbx: (a) an envelope whose tcb_info is a number says envelope",
        String.equal
          (res_text
             (Result.map
                (fun ((_ : T.Collateral.t)) -> ())
                (T.Collateral.of_envelope "{\"tcb_info\":3}")))
          "tcb: envelope" );
      ( "tcbx: (a) an empty envelope says envelope",
        String.equal
          (res_text
             (Result.map
                (fun ((_ : T.Collateral.t)) -> ())
                (T.Collateral.of_envelope "")))
          "tcb: envelope" );
      ( "tcbx: (a) the QE report is 384 bytes and carries its pinned digest",
        Int.equal (String.length (report ())) 384
        && String.equal (sha (report ()))
             "01e3193c8f71faf088438be15a615919e351669d9fc3c852d08e73120aa30b1f" );
      ( "tcbx: (a) the QE report cpusvn window at 0",
        String.equal
          (hex (win (report ()) 0 16))
          "0303191b04ff00060000000000000000" );
      ( "tcbx: (a) the QE report miscselect window at 16",
        String.equal (hex (win (report ()) 16 4)) "00000000" );
      ( "tcbx: (a) the QE report attributes window at 48",
        String.equal
          (hex (win (report ()) 48 16))
          "1500000000000000e700000000000000" );
      ( "tcbx: (a) the QE report mrsigner window at 128",
        String.equal
          (hex (win (report ()) 128 32))
          "dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5" );
      ( "tcbx: (a) the QE report isvprodid window at 256 and isvsvn at 258",
        String.equal (hex (win (report ()) 256 2)) "0200"
        && String.equal (hex (win (report ()) 258 2)) "0600" );
      ( "tcbx: (a) the body tee tcb svn is 06010300000000000000000000000000",
        String.equal
          (hex (body_str Q.Body.tee_tcb_svn))
          "06010300000000000000000000000000" );
      ( "tcbx: (a) the body mrsigner seam is forty-eight zero bytes",
        String.equal
          (hex (body_str Q.Body.mrsigner_seam))
          "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" );
      ( "tcbx: (a) the body seam attributes are zero",
        Int64.equal (seam_attributes ()) 0L );
      ( "tcbx: (a) the PCK leaf cpusvn is 03030202040100050000000000000000",
        String.equal
          (Option.fold ~none:"" ~some:(fun (w : D.t) -> hex (D.cpusvn w))
             (derw ()))
          "03030202040100050000000000000000" );
      ( "tcbx: (a) the PCK leaf pcesvn is 11 and its fmspc is b0c06f000000",
        Int.equal
          (Option.fold ~none:(-1) ~some:D.pcesvn (derw ()))
          11
        && String.equal
             (Option.fold ~none:""
                ~some:(fun (w : D.t) -> hex (D.fmspc w))
                (derw ()))
             "b0c06f000000" );
      ( "tcbx: (a) the PCK leaf pce id is 0000",
        String.equal
          (Option.fold ~none:""
             ~some:(fun (w : D.t) -> hex (D.pce_id w))
             (derw ()))
          "0000" );
      (* ---------- (b) the status map ---------- *)
      ( "tcbx: (b) UpToDate maps to Up_to_date and back",
        String.equal (of_name "UpToDate") "Up_to_date"
        && String.equal (T.Status.to_string T.Status.Up_to_date) "UpToDate" );
      ( "tcbx: (b) SWHardeningNeeded maps to Sw_hardening_needed and back",
        String.equal (of_name "SWHardeningNeeded") "Sw_hardening_needed"
        && String.equal
             (T.Status.to_string T.Status.Sw_hardening_needed)
             "SWHardeningNeeded" );
      ( "tcbx: (b) ConfigurationNeeded maps to Configuration_needed and back",
        String.equal (of_name "ConfigurationNeeded") "Configuration_needed"
        && String.equal
             (T.Status.to_string T.Status.Configuration_needed)
             "ConfigurationNeeded" );
      ( "tcbx: (b) ConfigurationAndSWHardeningNeeded maps and back",
        String.equal
          (of_name "ConfigurationAndSWHardeningNeeded")
          "Configuration_and_sw_hardening_needed"
        && String.equal
             (T.Status.to_string T.Status.Configuration_and_sw_hardening_needed)
             "ConfigurationAndSWHardeningNeeded" );
      ( "tcbx: (b) OutOfDate maps to Out_of_date and back",
        String.equal (of_name "OutOfDate") "Out_of_date"
        && String.equal (T.Status.to_string T.Status.Out_of_date) "OutOfDate" );
      ( "tcbx: (b) OutOfDateConfigurationNeeded maps and back",
        String.equal
          (of_name "OutOfDateConfigurationNeeded")
          "Out_of_date_configuration_needed"
        && String.equal
             (T.Status.to_string T.Status.Out_of_date_configuration_needed)
             "OutOfDateConfigurationNeeded" );
      ( "tcbx: (b) Revoked maps to Revoked and back",
        String.equal (of_name "Revoked") "Revoked"
        && String.equal (T.Status.to_string T.Status.Revoked) "Revoked" );
      ( "tcbx: (b) the map is CLOSED: uptodate, UPTODATE and Unknown are none",
        String.equal (of_name "uptodate") "none"
        && String.equal (of_name "UPTODATE") "none"
        && String.equal (of_name "Unknown") "none" );
      ( "tcbx: (b) the empty spelling is none",
        String.equal (of_name "") "none" );
      ( "tcbx: (b) equal is constructor equality",
        T.Status.equal T.Status.Up_to_date T.Status.Up_to_date
        && not (T.Status.equal T.Status.Up_to_date T.Status.Out_of_date) );
      ( "tcbx: (b) to_string is the inverse of of_string over the seven",
        List.for_all
          (fun (s : string) ->
            String.equal
              (Option.fold ~none:"" ~some:T.Status.to_string
                 (T.Status.of_string s))
              s)
          [
            "UpToDate";
            "SWHardeningNeeded";
            "ConfigurationNeeded";
            "ConfigurationAndSWHardeningNeeded";
            "OutOfDate";
            "OutOfDateConfigurationNeeded";
            "Revoked";
          ]
        && not
             (String.equal
                (Option.fold ~none:"" ~some:T.Status.to_string
                   (T.Status.of_string "uptodate"))
                "uptodate")
        && List.for_all
             (fun (s : T.Status.t) ->
               String.equal (of_name (T.Status.to_string s)) (st_name s))
             [
               T.Status.Up_to_date;
               T.Status.Sw_hardening_needed;
               T.Status.Configuration_needed;
               T.Status.Configuration_and_sw_hardening_needed;
               T.Status.Out_of_date;
               T.Status.Out_of_date_configuration_needed;
               T.Status.Revoked;
             ] );
      (* ---------- (c) now_of_iso ---------- *)
      ( "tcbx: (c) the tcb info issueDate cuts to 20250619101603",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-06-19T10:16:03Z"))
          "20250619101603" );
      ( "tcbx: (c) the tcb info nextUpdate cuts to 20250719101603",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-07-19T10:16:03Z"))
          "20250719101603" );
      ( "tcbx: (c) the qe identity issueDate cuts to 20250619103227",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-06-19T10:32:27Z"))
          "20250619103227" );
      ( "tcbx: (c) the pinned tcbDate cuts to 20240313000000",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2024-03-13T00:00:00Z"))
          "20240313000000" );
      ( "tcbx: (c) a nineteen character instant is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-06-19T10:16:03"))
          "none" );
      ( "tcbx: (c) a twenty-one character instant is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-06-19T10:16:03ZZ"))
          "none" );
      ( "tcbx: (c) a space where the T sits is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-06-19 10:16:03Z"))
          "none" );
      ( "tcbx: (c) a lower case z is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-06-19T10:16:03z"))
          "none" );
      ( "tcbx: (c) a slash where the first dash sits is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025/06-19T10:16:03Z"))
          "none" );
      ( "tcbx: (c) a dot where the first colon sits is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-06-19T10.16:03Z"))
          "none" );
      ( "tcbx: (c) a non-digit inside the year is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "202X-06-19T10:16:03Z"))
          "none" );
      ( "tcbx: (c) a thirteenth month is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string
             (T.now_of_iso "2025-13-19T10:16:03Z"))
          "none" );
      ( "tcbx: (c) the empty instant is none",
        String.equal
          (Option.fold ~none:"none" ~some:D.Now.to_string (T.now_of_iso ""))
          "none" );
      (* ---------- (d) the two documents and their signatures ---------- *)
      ( "tcbx: (d) the tcb info signature verifies under the signing key",
        String.equal
          (doc_text ~word:"tcb info signature"
             ~signature:(col_str T.Collateral.tcb_info_signature)
             (col_str T.Collateral.tcb_info))
          "ok" );
      ( "tcbx: (d) the qe identity signature verifies under the signing key",
        String.equal
          (doc_text ~word:"qe identity signature"
             ~signature:(col_str T.Collateral.qe_identity_signature)
             (col_str T.Collateral.qe_identity))
          "ok" );
      ( "tcbx: (d) one painted byte of the tcb info document breaks it",
        String.equal
          (doc_text ~word:"tcb info signature"
             ~signature:(col_str T.Collateral.tcb_info_signature)
             (patch (col_str T.Collateral.tcb_info) 2000 "X"))
          "tcb: tcb info signature" );
      ( "tcbx: (d) one painted hex digit of the tcb info signature breaks it",
        String.equal
          (doc_text ~word:"tcb info signature"
             ~signature:
               (patch (col_str T.Collateral.tcb_info_signature) 3 "f")
             (col_str T.Collateral.tcb_info))
          "tcb: tcb info signature" );
      ( "tcbx: (d) one painted byte of the qe identity document breaks it",
        String.equal
          (doc_text ~word:"qe identity signature"
             ~signature:(col_str T.Collateral.qe_identity_signature)
             (patch (col_str T.Collateral.qe_identity) 400 "X"))
          "tcb: qe identity signature" );
      ( "tcbx: (d) one painted hex digit of the qe signature breaks it",
        String.equal
          (doc_text ~word:"qe identity signature"
             ~signature:
               (patch (col_str T.Collateral.qe_identity_signature) 1 "0")
             (col_str T.Collateral.qe_identity))
          "tcb: qe identity signature" );
      ( "tcbx: (d) a 126 digit signature is refused by the length leg",
        String.equal
          (doc_text ~word:"tcb info signature"
             ~signature:(win (col_str T.Collateral.tcb_info_signature) 0 126)
             (col_str T.Collateral.tcb_info))
          "tcb: tcb info signature" );
      ( "tcbx: (d) a non-hex signature is refused by the hex leg",
        String.equal
          (doc_text ~word:"tcb info signature"
             ~signature:(patch (col_str T.Collateral.tcb_info_signature) 0 "z")
             (col_str T.Collateral.tcb_info))
          "tcb: tcb info signature" );
      ( "tcbx: (d) the qe signature does not sign the tcb info document",
        String.equal
          (doc_text ~word:"tcb info signature"
             ~signature:(col_str T.Collateral.qe_identity_signature)
             (col_str T.Collateral.tcb_info))
          "tcb: tcb info signature" );
      ( "tcbx: (d) the tcb info signature does not sign the qe document",
        String.equal
          (doc_text ~word:"qe identity signature"
             ~signature:(col_str T.Collateral.tcb_info_signature)
             (col_str T.Collateral.qe_identity))
          "tcb: qe identity signature" );
      ( "tcbx: (d) the signing certificate key halves",
        String.equal
          (Option.fold ~none:"" ~some:(fun (k : Pk.t) -> hex (Pk.to_bytes k))
             (signing_key ()))
          "43451bcc73c9d5917caf766e61af3fe98087dd4f13257b261e851897799dd13d6811fb47713803bb9bae587fccddc2e31be9a28b86962acc6daf96da58eeca96" );
      (* ---------- (e) the TCB Signing chain ---------- *)
      ( "tcbx: (e) blocks_of_chain cuts the issuer chain into two blocks",
        Int.equal (List.length (tcb_blocks ())) 2
        && String.equal
             (win (signing_block ()) 0 27)
             "-----BEGIN CERTIFICATE-----" );
      ( "tcbx: (e) the qe identity chain cuts into the same two blocks",
        Int.equal
          (List.length
             (T.blocks_of_chain (col_str T.Collateral.qe_identity_chain)))
          2
        && String.equal
             (String.concat ""
                (T.blocks_of_chain (col_str T.Collateral.qe_identity_chain)))
             (String.concat "" (tcb_blocks ())) );
      ( "tcbx: (e) the pinned chain yields the TCB Signing key",
        String.equal (pin_text ~now:(pinned ()) (tcb_blocks ())) "ok" );
      ( "tcbx: (e) a one-block chain says chain length",
        String.equal
          (chain_text ~now:(pinned ()) ~root_pin:(D.root_pin ())
             [ signing_block () ])
          "tcb: chain length" );
      ( "tcbx: (e) a three-block chain says chain length",
        String.equal
          (pin_text ~now:(pinned ())
             (tcb_blocks () @ [ signing_block () ]))
          "tcb: chain length" );
      ( "tcbx: (e) an empty chain says chain length",
        String.equal (pin_text ~now:(pinned ()) []) "tcb: chain length"
        && Int.equal (List.length (T.blocks_of_chain "")) 0 );
      ( "tcbx: (e) block 2 is presence only and is never parsed",
        String.equal
          (pin_text ~now:(pinned ()) [ signing_block (); "not a certificate" ])
          "ok" );
      ( "tcbx: (e) the PCK leaf as block 1 says root pin",
        String.equal
          (pin_text ~now:(pinned ()) [ pck_block 0; signing_block () ])
          "tcb: root pin" );
      ( "tcbx: (e) an anchor that is not the pinned root says root pin",
        String.equal
          (chain_text ~now:(pinned ())
             ~root_pin:
               (Option.fold ~none:"" ~some:D.Cert.der
                  (Result.to_option (D.Cert.of_pem (pck_block 0))))
             (tcb_blocks ()))
          "tcb: root pin" );
      ( "tcbx: (e) the PCK intermediate as block 1 says signing cert",
        String.equal
          (pin_text ~now:(pinned ()) [ pck_block 1; signing_block () ])
          "tcb: signing cert" );
      ( "tcbx: (e) the cA TRUE block parses, signs and is a CA",
        Option.fold ~none:false
          ~some:(fun (c : D.Cert.t) ->
            D.Cert.is_ca c && D.Cert.digital_signature c)
          (Result.to_option (D.Cert.of_pem (ca_block ()))) );
      ( "tcbx: (e) a signing certificate with cA TRUE says signing cert",
        String.equal
          (pin_text ~now:(pinned ()) [ ca_block (); signing_block () ])
          "tcb: signing cert" );
      ( "tcbx: (e) one painted tbs byte says signing cert signature",
        String.equal
          (pin_text ~now:(pinned ()) [ paint 157 "3"; signing_block () ])
          "tcb: signing cert signature" );
      ( "tcbx: (e) the second before notBefore says signing cert not yet valid",
        String.equal
          (pin_text ~now:"20250506092459" (tcb_blocks ()))
          "tcb: signing cert not yet valid" );
      ( "tcbx: (e) notBefore itself is inside the window",
        String.equal (pin_text ~now:"20250506092500" (tcb_blocks ())) "ok" );
      ( "tcbx: (e) notAfter itself is inside the window",
        String.equal (pin_text ~now:"20320506092500" (tcb_blocks ())) "ok" );
      ( "tcbx: (e) the second after notAfter says signing cert expired",
        String.equal
          (pin_text ~now:"20320506092501" (tcb_blocks ()))
          "tcb: signing cert expired" );
      ( "tcbx: (e) the signing certificate validity window",
        String.equal (win (signing_der ()) 157 13) "250506092500Z"
        && String.equal (win (signing_der ()) 172 13) "320506092500Z"
        && String.equal
             (Option.fold ~none:""
                ~some:(fun (c : D.Cert.t) ->
                  D.Now.to_string (D.Cert.not_before c))
                (signing_cert ()))
             "20250506092500"
        && String.equal
             (Option.fold ~none:""
                ~some:(fun (c : D.Cert.t) ->
                  D.Now.to_string (D.Cert.not_after c))
                (signing_cert ()))
             "20320506092500" );
      ( "tcbx: (e) the issuer of block 1 is the subject of the pinned root",
        String.equal
          (Option.fold ~none:"x" ~some:D.Cert.issuer (signing_cert ()))
          (Option.fold ~none:"y" ~some:D.Cert.subject
             (Result.to_option (D.Cert.of_der (D.root_pin ())))) );
      ( "tcbx: (e) the signing certificate signs and is not a CA",
        Option.fold ~none:false ~some:D.Cert.digital_signature (signing_cert ())
        && not
             (Option.fold ~none:true ~some:D.Cert.is_ca (signing_cert ())) );
      (* ---------- (f) the TCB Info fields ---------- *)
      ( "tcbx: (f) the id is TDX and another id says tcb info id",
        String.equal (i_str T.Tcb_info.id) "TDX"
        && String.equal
             (plat_text ~now:(pinned ()) ~fmspc:(raw "b0c06f000000")
                ~pce_id:(raw "0000")
                (ti_doc ~id:"SGX" ()))
             "tcb: tcb info id" );
      ( "tcbx: (f) the version is 3 and version 2 says tcb info version",
        Int.equal (i_int T.Tcb_info.version) 3
        && String.equal
             (plat_text ~now:(pinned ()) ~fmspc:(raw "b0c06f000000")
                ~pce_id:(raw "0000")
                (ti_doc ~version:"2" ()))
             "tcb: tcb info version" );
      ( "tcbx: (f) the tcb type is 0 and type 1 says tcb type",
        Int.equal (i_int T.Tcb_info.tcb_type) 0
        && String.equal
             (plat_text ~now:(pinned ()) ~fmspc:(raw "b0c06f000000")
                ~pce_id:(raw "0000")
                (ti_doc ~tcb_type:"1" ()))
             "tcb: tcb type" );
      ( "tcbx: (f) the fmspc is b0c06f000000 and another one mismatches",
        String.equal (hex (i_str T.Tcb_info.fmspc)) "b0c06f000000"
        && String.equal
             (plat_text ~now:(pinned ()) ~fmspc:(raw "c0c06f000000")
                ~pce_id:(raw "0000")
                (col_str T.Collateral.tcb_info))
             "tcb: fmspc mismatch" );
      ( "tcbx: (f) the pce_id is 0000 and another one mismatches",
        String.equal (hex (i_str T.Tcb_info.pce_id)) "0000"
        && String.equal
             (plat_text ~now:(pinned ()) ~fmspc:(raw "b0c06f000000")
                ~pce_id:(raw "0001")
                (col_str T.Collateral.tcb_info))
             "tcb: pce id mismatch" );
      ( "tcbx: (f) the tcb evaluation data number is 17",
        Int.equal (i_int T.Tcb_info.tcb_evaluation_data_number) 17 );
      ( "tcbx: (f) the issueDate and the nextUpdate of the document",
        String.equal (i_time T.Tcb_info.issue_date) "20250619101603"
        && String.equal (i_time T.Tcb_info.next_update) "20250719101603" );
      ( "tcbx: (f) the pinned now sits inside the freshness window",
        String.equal
          (plat_text ~now:(pinned ()) ~fmspc:(raw "b0c06f000000")
             ~pce_id:(raw "0000")
             (col_str T.Collateral.tcb_info))
          "ok" );
      ( "tcbx: (f) the issueDate itself is inside the window",
        String.equal
          (plat_text ~now:"20250619101603" ~fmspc:(raw "b0c06f000000")
             ~pce_id:(raw "0000")
             (col_str T.Collateral.tcb_info))
          "ok" );
      ( "tcbx: (f) the second before the issueDate says tcb info not yet valid",
        String.equal
          (plat_text ~now:"20250619101602" ~fmspc:(raw "b0c06f000000")
             ~pce_id:(raw "0000")
             (col_str T.Collateral.tcb_info))
          "tcb: tcb info not yet valid" );
      ( "tcbx: (f) the nextUpdate itself says tcb info expired",
        String.equal
          (plat_text ~now:"20250719101603" ~fmspc:(raw "b0c06f000000")
             ~pce_id:(raw "0000")
             (col_str T.Collateral.tcb_info))
          "tcb: tcb info expired" );
      ( "tcbx: (f) the second before the nextUpdate is still fresh",
        String.equal
          (plat_text ~now:"20250719101602" ~fmspc:(raw "b0c06f000000")
             ~pce_id:(raw "0000")
             (col_str T.Collateral.tcb_info))
          "ok" );
      ( "tcbx: (f) the tdx module identity ids are TDX_03 then TDX_01",
        List.equal String.equal (i_ids ()) [ "TDX_03"; "TDX_01" ] );
      ( "tcbx: (f) the tdx module mrsigner is forty-eight zero bytes",
        String.equal
          (hex (i_str T.Tcb_info.tdx_module_mrsigner))
          "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" );
      ( "tcbx: (f) the tdx module attributes are 0 and the mask is all ones",
        Int64.equal (i_attributes ()) 0L
        && String.equal (Printf.sprintf "%Lx" (i_mask ())) "ffffffffffffffff" );
      ( "tcbx: (f) a non-object document says tcb info",
        String.equal (info_text "[]") "tcb: tcb info" );
      ( "tcbx: (f) a document without tcbLevels says tcb info",
        String.equal (info_text "{\"id\":\"TDX\"}") "tcb: tcb info" );
      ( "tcbx: (f) an unknown tcbStatus says tcb info",
        String.equal
          (info_text (ti_doc ~levels:(ti_level ~status:"Unknown" ()) ()))
          "tcb: tcb info" );
      ( "tcbx: (f) fifteen sgx components say tcb info",
        String.equal
          (info_text
             (ti_doc
                ~levels:
                  ("{\"tcb\":{\"sgxtcbcomponents\":" ^ comps (pad [] 15)
                 ^ ",\"pcesvn\":11,\"tdxtcbcomponents\":" ^ comps (vec [])
                 ^ "},\"tcbDate\":\"2024-03-13T00:00:00Z\",\"tcbStatus\":\"UpToDate\"}"
                  )
                ()))
          "tcb: tcb info" );
      ( "tcbx: (f) a nineteen character tcbDate says tcb info",
        String.equal
          (info_text (ti_doc ~levels:(ti_level ~date:"2024-03-13T00:00:00" ()) ()))
          "tcb: tcb info" );
      ( "tcbx: (f) a five byte fmspc says tcb info",
        String.equal (info_text (ti_doc ~fmspc:"B0C06F0000" ())) "tcb: tcb info" );
      ( "tcbx: (f) a non-hex fmspc says tcb info",
        String.equal (info_text (ti_doc ~fmspc:"Z0C06F000000" ())) "tcb: tcb info" );
      ( "tcbx: (f) a seven byte tdxModule mrsigner says tcb info",
        String.equal (info_text (ti_doc ~mrsigner:"00112233445566" ()))
          "tcb: tcb info" );
      ( "tcbx: (f) the synthetic document of this suite parses",
        String.equal (info_text (ti_doc ())) "ok" );
      (* ---------- (g) the platform grade ---------- *)
      ( "tcbx: (g) the pinned cpusvn and pcesvn 11 grade Up_to_date",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "Up_to_date" );
      ( "tcbx: (g) the graded level carries the tcb date 20240313000000",
        String.equal
          (level_date
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "20240313000000" );
      ( "tcbx: (g) the graded level carries no advisory",
        Int.equal
          (List.length
             (level_advisories
                (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                   ~pcesvn:11
                   ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                   (col_str T.Collateral.tcb_info))))
          0 );
      ( "tcbx: (g) pcesvn 10 falls to the second level, Out_of_date",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:10 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "Out_of_date"
        && String.equal
             (level_date
                (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                   ~pcesvn:10
                   ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                   (col_str T.Collateral.tcb_info)))
             "20180104000000"
        && Int.equal
             (List.length
                (level_advisories
                   (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                      ~pcesvn:10
                      ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                      (col_str T.Collateral.tcb_info))))
             14 );
      ( "tcbx: (g) one lowered cpusvn byte says tcb level",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202020100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "tcb: tcb level" );
      ( "tcbx: (g) a pcesvn below every level says tcb level",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000") ~pcesvn:4
                ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "tcb: tcb level" );
      ( "tcbx: (g) a tee tcb svn byte below the level says tcb level",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010100000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "tcb: tcb level" );
      (* Intel's isTdxTcbHigherOrEqual: components 0 and 1 belong to the
         module identity when byte 1, the SEAM major version, is not 0. *)
      ( "tcbx: (g) tdx component 0 below the level is skipped at module major 1",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "04010300000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "Up_to_date" );
      ( "tcbx: (g) tdx component 0 below the level says tcb level at module major 0",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "04000300000000000000000000000000")
                (col_str T.Collateral.tcb_info)))
          "tcb: tcb level" );
      ( "tcbx: (g) a level equal to the platform vectors matches",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc
                   ~levels:
                     (ti_level ~sgx:[ 3; 3; 2; 2; 4; 1; 0; 5 ] ~pcesvn:11
                        ~tdx:[ 6; 1; 3 ] ())
                   ())))
          "Up_to_date" );
      ( "tcbx: (g) a level one above the platform pcesvn says tcb level",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc ~levels:(ti_level ~pcesvn:12 ()) ())))
          "tcb: tcb level" );
      ( "tcbx: (g) a level one above a tdx component says tcb level",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc ~levels:(ti_level ~tdx:[ 5; 0; 4 ] ()) ())))
          "tcb: tcb level" );
      ( "tcbx: (g) a level one above tdx component 0 matches at module major 1",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc ~levels:(ti_level ~tdx:[ 7; 0; 2 ] ()) ())))
          "Up_to_date" );
      ( "tcbx: (g) a level one above tdx component 0 says tcb level at module major 0",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06000300000000000000000000000000")
                (ti_doc ~levels:(ti_level ~tdx:[ 7; 0; 2 ] ()) ())))
          "tcb: tcb level" );
      (* ---------- (g) the convergence with the module status ---------- *)
      ( "tcbx: (g) a module OutOfDate lowers UpToDate to Out_of_date",
        String.equal
          (converged ~platform:"UpToDate" ~module_status:(Some "OutOfDate"))
          "Out_of_date" );
      ( "tcbx: (g) a module OutOfDate lowers SWHardeningNeeded to Out_of_date",
        String.equal
          (converged ~platform:"SWHardeningNeeded"
             ~module_status:(Some "OutOfDate"))
          "Out_of_date" );
      ( "tcbx: (g) a module OutOfDate lowers ConfigurationNeeded to Out_of_date_configuration_needed",
        String.equal
          (converged ~platform:"ConfigurationNeeded"
             ~module_status:(Some "OutOfDate"))
          "Out_of_date_configuration_needed" );
      ( "tcbx: (g) a module OutOfDate lowers ConfigurationAndSWHardeningNeeded to Out_of_date_configuration_needed",
        String.equal
          (converged ~platform:"ConfigurationAndSWHardeningNeeded"
             ~module_status:(Some "OutOfDate"))
          "Out_of_date_configuration_needed" );
      ( "tcbx: (g) a module OutOfDate keeps OutOfDate and OutOfDateConfigurationNeeded",
        String.equal
          (converged ~platform:"OutOfDate" ~module_status:(Some "OutOfDate"))
          "Out_of_date"
        && String.equal
             (converged ~platform:"OutOfDateConfigurationNeeded"
                ~module_status:(Some "OutOfDate"))
             "Out_of_date_configuration_needed" );
      ( "tcbx: (g) a module UpToDate keeps every platform status",
        String.equal
          (converged ~platform:"UpToDate" ~module_status:(Some "UpToDate"))
          "Up_to_date"
        && String.equal
             (converged ~platform:"ConfigurationNeeded"
                ~module_status:(Some "UpToDate"))
             "Configuration_needed"
        && String.equal
             (converged ~platform:"SWHardeningNeeded"
                ~module_status:(Some "UpToDate"))
             "Sw_hardening_needed" );
      ( "tcbx: (g) no module status keeps every platform status",
        String.equal (converged ~platform:"UpToDate" ~module_status:None)
          "Up_to_date"
        && String.equal
             (converged ~platform:"ConfigurationNeeded" ~module_status:None)
             "Configuration_needed" );
      ( "tcbx: (g) the FIRST matching level wins",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc
                   ~levels:
                     (ti_level ~status:"OutOfDate" () ^ "," ^ ti_level ())
                   ())))
          "Out_of_date" );
      ( "tcbx: (g) a matched Revoked level says revoked",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc ~levels:(ti_level ~status:"Revoked" ()) ())))
          "tcb: revoked" );
      ( "tcbx: (g) a document with no level says tcb level",
        String.equal
          (level_text
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc ~levels:"" ())))
          "tcb: tcb level" );
      ( "tcbx: (g) the advisories of the matched level are carried",
        List.equal String.equal
          (level_advisories
             (grade_of ~cpusvn:(raw "03030202040100050000000000000000")
                ~pcesvn:11 ~tee_tcb_svn:(raw "06010300000000000000000000000000")
                (ti_doc
                   ~levels:
                     (ti_level
                        ~advisories:",\"advisoryIDs\":[\"INTEL-SA-00106\"]" ())
                   ())))
          [ "INTEL-SA-00106" ] );
      (* ---------- (h) the TDX module legs ---------- *)
      ( "tcbx: (h) the pinned seam values grade the TDX_01 level Up_to_date",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "Up_to_date" );
      ( "tcbx: (h) one painted seam mrsigner byte says tdx module at major 0",
        String.equal
          (module_text
             ~mrsigner_seam:(patch (body_str Q.Body.mrsigner_seam) 0 "\001")
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06000300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "tcb: tdx module" );
      ( "tcbx: (h) one painted seam mrsigner byte says tdx module identity at major 1",
        String.equal
          (module_text
             ~mrsigner_seam:(patch (body_str Q.Body.mrsigner_seam) 0 "\001")
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "tcb: tdx module identity" );
      ( "tcbx: (h) seam attributes the mask keeps say tdx module at major 0",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:1L
             ~tee_tcb_svn:(raw "06000300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "tcb: tdx module" );
      ( "tcbx: (h) seam attributes the mask keeps say tdx module identity at major 1",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:1L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "tcb: tdx module identity" );
      (* Intel's QuoteVerifier reads the top-level tdxModule ONLY when
         the SEAM major version is 0. At major 1 the identity mask of
         zero hides the attributes while the top-level mask keeps them,
         and at major 0 the top-level mask of zero hides them. *)
      ( "tcbx: (h) the identity mask of zero hides the seam attributes at major 1",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:1L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc ~identities:(ti_identity ~mask:"0000000000000000" ()) ()))
          "Up_to_date" );
      ( "tcbx: (h) the tdxModule mask of zero hides the seam attributes at major 0",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:1L
             ~tee_tcb_svn:(raw "06000300000000000000000000000000")
             (ti_doc ~mask:"0000000000000000" ()))
          "ok" );
      ( "tcbx: (h) the tdxModule mask of zero does not reach major 1",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:1L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc ~mask:"0000000000000000" ()))
          "tcb: tdx module identity" );
      ( "tcbx: (h) an absent tdxModuleIdentities member parses",
        Option.is_some (info_of (ti_doc ~with_identities:false ())) );
      ( "tcbx: (h) an absent tdxModuleIdentities member passes at major 0",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06000300000000000000000000000000")
             (ti_doc ~with_identities:false ()))
          "ok" );
      ( "tcbx: (h) an absent tdxModuleIdentities member says tdx module identity at major 1",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc ~with_identities:false ()))
          "tcb: tdx module identity" );
      ( "tcbx: (h) a zero SEAM major version takes no identity",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06000300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "ok" );
      ( "tcbx: (h) SEAM major 3 grades against TDX_03",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06030300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "Up_to_date" );
      ( "tcbx: (h) SEAM major 3 below its level says tdx module identity",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "02030300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "tcb: tdx module identity" );
      ( "tcbx: (h) SEAM major 1 with module svn 2 takes the OutOfDate level",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "02010300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "Out_of_date" );
      ( "tcbx: (h) SEAM major 1 with module svn 1 says tdx module identity",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "01010300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "tcb: tdx module identity" );
      ( "tcbx: (h) a SEAM major no identity names says tdx module identity",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06090300000000000000000000000000")
             (col_str T.Collateral.tcb_info))
          "tcb: tdx module identity" );
      ( "tcbx: (h) an identity mrsigner that differs says tdx module identity",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc
                ~identities:
                  (ti_identity
                     ~mrsigner:
                       ("01"
                      ^ win (zeros96 ()) 2 94)
                     ())
                ()))
          "tcb: tdx module identity" );
      ( "tcbx: (h) a Revoked module level says revoked",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc
                ~identities:
                  (ti_identity ~levels:(mod_level ~status:"Revoked" ()) ())
                ()))
          "tcb: revoked" );
      ( "tcbx: (h) an identity id of five characters is never found",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc ~identities:(ti_identity ~id:"TDX_1" ()) ()))
          "tcb: tdx module identity" );
      ( "tcbx: (h) an identity id whose digits are not decimal is never found",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc ~identities:(ti_identity ~id:"TDX_0x" ()) ()))
          "tcb: tdx module identity" );
      ( "tcbx: (h) an identity with no level says tdx module identity",
        String.equal
          (module_text
             ~mrsigner_seam:(body_str Q.Body.mrsigner_seam)
             ~seam_attributes:0L
             ~tee_tcb_svn:(raw "06010300000000000000000000000000")
             (ti_doc ~identities:(ti_identity ~levels:"" ()) ()))
          "tcb: tdx module identity" );
      (* ---------- (i) the QE Identity fields ---------- *)
      ( "tcbx: (i) the id is TD_QE and the version is 2",
        String.equal (q_str T.Qe_identity.id) "TD_QE"
        && Int.equal (q_int T.Qe_identity.version) 2 );
      ( "tcbx: (i) the miscselect is 0 and its mask is 4294967295",
        Int.equal (q_int T.Qe_identity.miscselect) 0
        && Int.equal (q_int T.Qe_identity.miscselect_mask) 4294967295 );
      ( "tcbx: (i) the attributes and the attributes mask of the identity",
        String.equal
          (hex (q_str T.Qe_identity.attributes))
          "11000000000000000000000000000000"
        && String.equal
             (hex (q_str T.Qe_identity.attributes_mask))
             "fbffffffffffffff0000000000000000" );
      ( "tcbx: (i) the identity mrsigner is the QE report mrsigner",
        String.equal
          (hex (q_str T.Qe_identity.mrsigner))
          "dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5" );
      ( "tcbx: (i) the isvprodid is 2 and the evaluation number is 17",
        Int.equal (q_int T.Qe_identity.isvprodid) 2
        && Int.equal (q_int T.Qe_identity.tcb_evaluation_data_number) 17 );
      ( "tcbx: (i) the issueDate and the nextUpdate of the identity",
        String.equal (q_time T.Qe_identity.issue_date) "20250619103227"
        && String.equal (q_time T.Qe_identity.next_update) "20250719103227" );
      ( "tcbx: (i) the pinned now sits inside the identity window",
        String.equal
          (identity_text ~now:(pinned ()) (col_str T.Collateral.qe_identity))
          "ok" );
      ( "tcbx: (i) another id says qe identity id",
        String.equal
          (identity_text ~now:(pinned ()) (qe_doc ~id:"QE" ()))
          "tcb: qe identity id" );
      ( "tcbx: (i) version 3 says qe identity version",
        String.equal
          (identity_text ~now:(pinned ()) (qe_doc ~version:"3" ()))
          "tcb: qe identity version" );
      ( "tcbx: (i) the second before the issueDate says qe identity not yet valid",
        String.equal
          (identity_text ~now:"20250619103226"
             (col_str T.Collateral.qe_identity))
          "tcb: qe identity not yet valid" );
      ( "tcbx: (i) the nextUpdate itself says qe identity expired",
        String.equal
          (identity_text ~now:"20250719103227"
             (col_str T.Collateral.qe_identity))
          "tcb: qe identity expired" );
      ( "tcbx: (i) the second before the nextUpdate is still fresh",
        String.equal
          (identity_text ~now:"20250719103226"
             (col_str T.Collateral.qe_identity))
          "ok" );
      ( "tcbx: (i) a non-object identity says qe identity",
        String.equal (qi_text "[]") "tcb: qe identity" );
      ( "tcbx: (i) an identity without tcbLevels says qe identity",
        String.equal (qi_text "{\"id\":\"TD_QE\"}") "tcb: qe identity" );
      ( "tcbx: (i) a thirty-one byte mrsigner says qe identity",
        String.equal
          (qi_text
             (qe_doc
                ~mrsigner:
                  "DC9E2A7C6F948F17474E34A7FC43ED030F7C1563F1BABDDF6340C82E0E54A8"
                ()))
          "tcb: qe identity" );
      ( "tcbx: (i) a five byte miscselect says qe identity",
        String.equal (qi_text (qe_doc ~miscselect:"0000000000" ()))
          "tcb: qe identity" );
      ( "tcbx: (i) an unknown QE tcbStatus says qe identity",
        String.equal
          (qi_text (qe_doc ~levels:(qe_level ~status:"Unknown" ()) ()))
          "tcb: qe identity" );
      ( "tcbx: (i) a nineteen character QE tcbDate says qe identity",
        String.equal
          (qi_text (qe_doc ~levels:(qe_level ~date:"2024-03-13T00:00:00" ()) ()))
          "tcb: qe identity" );
      ( "tcbx: (i) the synthetic identity of this suite parses",
        String.equal (qi_text (qe_doc ())) "ok" );
      (* ---------- (j) the QE grade ---------- *)
      ( "tcbx: (j) the pinned QE report grades Up_to_date at 20240313000000",
        String.equal
          (level_text
             (qe_grade ~qe_report:(report ())
                (col_str T.Collateral.qe_identity)))
          "Up_to_date"
        && String.equal
             (level_date
                (qe_grade ~qe_report:(report ())
                   (col_str T.Collateral.qe_identity)))
             "20240313000000" );
      ( "tcbx: (j) a 383 byte report says qe miscselect",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(win (report ()) 0 383)
                (col_str T.Collateral.qe_identity)))
          "tcb: qe miscselect" );
      ( "tcbx: (j) a painted miscselect says qe miscselect",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(patch (report ()) 16 (raw "ffffffff"))
                (col_str T.Collateral.qe_identity)))
          "tcb: qe miscselect" );
      ( "tcbx: (j) a painted attributes byte the mask keeps says qe attributes",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(patch (report ()) 48 (raw "14"))
                (col_str T.Collateral.qe_identity)))
          "tcb: qe attributes" );
      ( "tcbx: (j) a painted attributes byte the mask hides still grades",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(patch (report ()) 56 (raw "00"))
                (col_str T.Collateral.qe_identity)))
          "Up_to_date" );
      ( "tcbx: (j) an all ones attributes mask refuses the raw attributes",
        String.equal
          (level_text
             (qe_grade ~qe_report:(report ())
                (qe_doc
                   ~attributes_mask:"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ())))
          "tcb: qe attributes" );
      ( "tcbx: (j) a painted mrsigner byte says qe mrsigner",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(patch (report ()) 128 (raw "dd"))
                (col_str T.Collateral.qe_identity)))
          "tcb: qe mrsigner" );
      ( "tcbx: (j) a painted isvprodid says qe isvprodid",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(patch (report ()) 256 (raw "0300"))
                (col_str T.Collateral.qe_identity)))
          "tcb: qe isvprodid" );
      ( "tcbx: (j) an isvsvn below every level says qe isvsvn",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(patch (report ()) 258 (raw "0000"))
                (col_str T.Collateral.qe_identity)))
          "tcb: qe isvsvn" );
      ( "tcbx: (j) an isvsvn EQUAL to the level matches",
        String.equal
          (level_text
             (qe_grade
                ~qe_report:(patch (report ()) 258 (raw "0400"))
                (col_str T.Collateral.qe_identity)))
          "Up_to_date" );
      ( "tcbx: (j) a level isvsvn equal to the report isvsvn matches",
        String.equal
          (level_text
             (qe_grade ~qe_report:(report ()) (qe_doc ~levels:(qe_level ~isvsvn:6 ()) ())))
          "Up_to_date"
        && String.equal (hex (win (report ()) 256 2)) "0200" );
      ( "tcbx: (j) a level isvsvn above the report isvsvn says qe isvsvn",
        String.equal
          (level_text
             (qe_grade ~qe_report:(report ())
                (qe_doc ~levels:(qe_level ~isvsvn:7 ()) ())))
          "tcb: qe isvsvn" );
      ( "tcbx: (j) an identity with no level says qe isvsvn",
        String.equal
          (level_text (qe_grade ~qe_report:(report ()) (qe_doc ~levels:"" ())))
          "tcb: qe isvsvn" );
      ( "tcbx: (j) a matched Revoked QE level says revoked",
        String.equal
          (level_text
             (qe_grade ~qe_report:(report ())
                (qe_doc ~levels:(qe_level ~status:"Revoked" ()) ())))
          "tcb: revoked" );
      ( "tcbx: (j) the QE advisories of the matched level are carried",
        List.equal String.equal
          (level_advisories
             (qe_grade ~qe_report:(report ())
                (qe_doc
                   ~levels:
                     (qe_level ~advisories:",\"advisoryIDs\":[\"INTEL-SA-00615\"]"
                        ())
                   ())))
          [ "INTEL-SA-00615" ] );
      (* ---------- (k) verify end to end and its order ---------- *)
      ( "tcbx: (k) the pinned inputs verify at the pinned now",
        String.equal (verify_text ~now:(pinned ()) ~bytes:v4 (mint ())) "ok" );
      ( "tcbx: (k) the witness carries the platform_status Up_to_date",
        String.equal (w_status T.platform_status) "Up_to_date" );
      ( "tcbx: (k) the witness carries the platform tcb date 20240313000000",
        String.equal (w_time T.platform_tcb_date) "20240313000000" );
      ( "tcbx: (k) the witness carries no platform advisory",
        Int.equal (List.length (w_list T.platform_advisories)) 0 );
      ( "tcbx: (k) the witness carries the module_status Up_to_date of TDX_01",
        String.equal
          (Option.fold ~none:"none" ~some:st_name
             (Option.bind (witness ()) T.module_status))
          "Up_to_date" );
      ( "tcbx: (k) the witness carries the qe_status Up_to_date",
        String.equal (w_status T.qe_status) "Up_to_date" );
      ( "tcbx: (k) the witness carries the qe tcb date 20240313000000",
        String.equal (w_time T.qe_tcb_date) "20240313000000" );
      ( "tcbx: (k) the witness carries tcb_evaluation_data_number 17",
        Int.equal (w_int T.tcb_evaluation_data_number) 17 );
      ( "tcbx: (k) the witness carries the fmspc b0c06f000000",
        String.equal (hex (w_str T.fmspc)) "b0c06f000000" );
      ( "tcbx: (k) step (0) binds the three witnesses to one platform",
        Option.fold ~none:false
          ~some:(fun (w : D.t) ->
            Option.fold ~none:false
              ~some:(fun (s : S.t) -> Pk.equal (D.pck_key w) (S.pck_key s))
              (sigw ()))
          (derw ())
        && String.equal
             (Option.fold ~none:"" ~some:S.qe_report (sigw ()))
             (sec_str Sec.qe_report) );
      ( "tcbx: (k) a quote whose QE report differs says witness mismatch",
        String.equal
          (verify_text ~now:(pinned ())
             ~bytes:(patch v4 770 "\001")
             (mint ()))
          "tcb: witness mismatch" );
      ( "tcbx: (k) the binding runs BEFORE the chain",
        String.equal
          (verify_text ~now:(pinned ())
             ~bytes:(patch v4 770 "\001")
             (mint ~tcb_info_chain:(signing_block ()) ()))
          "tcb: witness mismatch" );
      ( "tcbx: (k) a one-block tcb info chain says chain length",
        String.equal
          (verify_text ~now:(pinned ()) ~bytes:v4
             (mint ~tcb_info_chain:(signing_block ()) ()))
          "tcb: chain length" );
      ( "tcbx: (k) the chain runs BEFORE the tcb info signature",
        String.equal
          (verify_text ~now:(pinned ()) ~bytes:v4
             (mint ~tcb_info_chain:(signing_block ())
                ~tcb_info:(patch (col_str T.Collateral.tcb_info) 2000 "X") ()))
          "tcb: chain length" );
      ( "tcbx: (k) a painted tcb info document says tcb info signature",
        String.equal
          (verify_text ~now:(pinned ()) ~bytes:v4
             (mint ~tcb_info:(patch (col_str T.Collateral.tcb_info) 2000 "X") ()))
          "tcb: tcb info signature" );
      ( "tcbx: (k) the tcb info signature runs BEFORE the qe identity one",
        String.equal
          (verify_text ~now:(pinned ()) ~bytes:v4
             (mint
                ~tcb_info_signature:
                  (patch (col_str T.Collateral.tcb_info_signature) 3 "f")
                ~qe_identity:
                  (patch (col_str T.Collateral.qe_identity) 400 "X") ()))
          "tcb: tcb info signature" );
      ( "tcbx: (k) the platform window runs BEFORE the qe identity chain",
        String.equal
          (verify_text ~now:"20250719101603" ~bytes:v4
             (mint ~qe_identity_chain:(signing_block ()) ()))
          "tcb: tcb info expired" );
      ( "tcbx: (k) the second before the tcb info issueDate is refused",
        String.equal
          (verify_text ~now:"20250619101602" ~bytes:v4 (mint ()))
          "tcb: tcb info not yet valid" );
      ( "tcbx: (k) a one-block qe identity chain says chain length",
        String.equal
          (verify_text ~now:(pinned ()) ~bytes:v4
             (mint ~qe_identity_chain:(signing_block ()) ()))
          "tcb: chain length" );
      ( "tcbx: (k) a painted qe identity document says qe identity signature",
        String.equal
          (verify_text ~now:(pinned ()) ~bytes:v4
             (mint
                ~qe_identity:(patch (col_str T.Collateral.qe_identity) 400 "X")
                ()))
          "tcb: qe identity signature" );
      ( "tcbx: (k) the tcb info document under the qe signature is refused",
        String.equal
          (verify_text ~now:(pinned ()) ~bytes:v4
             (mint ~qe_identity:(col_str T.Collateral.tcb_info) ()))
          "tcb: qe identity signature" );
      ( "tcbx: (k) the last second of the tcb info window still verifies",
        String.equal
          (verify_text ~now:"20250719101602" ~bytes:v4 (mint ()))
          "ok" );
      ( "tcbx: (k) the qe identity window is the LATER of the two",
        String.equal
          (verify_text ~now:"20250619101603" ~bytes:v4 (mint ()))
          "tcb: qe identity not yet valid" );
      (* ---------- (l) the closed vocabulary ---------- *)
      ( "tcbx: (l) the word witness mismatch",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "witness mismatch"))
          "tcb: witness mismatch" );
      ( "tcbx: (l) the word chain length",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "chain length"))
          "tcb: chain length" );
      ( "tcbx: (l) the word root pin",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "root pin"))
          "tcb: root pin" );
      ( "tcbx: (l) the word signing cert",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "signing cert"))
          "tcb: signing cert" );
      ( "tcbx: (l) the word signing cert signature",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "signing cert signature"))
          "tcb: signing cert signature" );
      ( "tcbx: (l) the word signing cert not yet valid",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "signing cert not yet valid"))
          "tcb: signing cert not yet valid" );
      ( "tcbx: (l) the word signing cert expired",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "signing cert expired"))
          "tcb: signing cert expired" );
      ( "tcbx: (l) the word tcb info signature",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb info signature"))
          "tcb: tcb info signature" );
      ( "tcbx: (l) the word tcb info",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb info"))
          "tcb: tcb info" );
      ( "tcbx: (l) the word tcb info id",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb info id"))
          "tcb: tcb info id" );
      ( "tcbx: (l) the word tcb info version",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb info version"))
          "tcb: tcb info version" );
      ( "tcbx: (l) the word tcb type",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb type"))
          "tcb: tcb type" );
      ( "tcbx: (l) the word tcb info not yet valid",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb info not yet valid"))
          "tcb: tcb info not yet valid" );
      ( "tcbx: (l) the word tcb info expired",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb info expired"))
          "tcb: tcb info expired" );
      ( "tcbx: (l) the word fmspc mismatch",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "fmspc mismatch"))
          "tcb: fmspc mismatch" );
      ( "tcbx: (l) the word pce id mismatch",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "pce id mismatch"))
          "tcb: pce id mismatch" );
      ( "tcbx: (l) the word tdx module",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tdx module"))
          "tcb: tdx module" );
      ( "tcbx: (l) the word tdx module identity",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tdx module identity"))
          "tcb: tdx module identity" );
      ( "tcbx: (l) the word tcb level",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "tcb level"))
          "tcb: tcb level" );
      ( "tcbx: (l) the word revoked",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "revoked"))
          "tcb: revoked" );
      ( "tcbx: (l) the word qe identity signature",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe identity signature"))
          "tcb: qe identity signature" );
      ( "tcbx: (l) the word qe identity",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe identity"))
          "tcb: qe identity" );
      ( "tcbx: (l) the word qe identity id",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe identity id"))
          "tcb: qe identity id" );
      ( "tcbx: (l) the word qe identity version",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe identity version"))
          "tcb: qe identity version" );
      ( "tcbx: (l) the word qe identity not yet valid",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe identity not yet valid"))
          "tcb: qe identity not yet valid" );
      ( "tcbx: (l) the word qe identity expired",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe identity expired"))
          "tcb: qe identity expired" );
      ( "tcbx: (l) the word qe miscselect",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe miscselect"))
          "tcb: qe miscselect" );
      ( "tcbx: (l) the word qe attributes",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe attributes"))
          "tcb: qe attributes" );
      ( "tcbx: (l) the word qe mrsigner",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe mrsigner"))
          "tcb: qe mrsigner" );
      ( "tcbx: (l) the word qe isvprodid",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe isvprodid"))
          "tcb: qe isvprodid" );
      ( "tcbx: (l) the word qe isvsvn",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "qe isvsvn"))
          "tcb: qe isvsvn" );
      ( "tcbx: (l) the word envelope, the one word verify never says",
        String.equal
          (Errx.to_string (Errx.Tcb_invalid "envelope"))
          "tcb: envelope" );
      ( "tcbx: (l) the vocabulary is thirty-one words plus envelope",
        Int.equal
          (List.length
             (List.sort_uniq String.compare
                [
                  "witness mismatch";
                  "chain length";
                  "root pin";
                  "signing cert";
                  "signing cert signature";
                  "signing cert not yet valid";
                  "signing cert expired";
                  "tcb info signature";
                  "tcb info";
                  "tcb info id";
                  "tcb info version";
                  "tcb type";
                  "tcb info not yet valid";
                  "tcb info expired";
                  "fmspc mismatch";
                  "pce id mismatch";
                  "tdx module";
                  "tdx module identity";
                  "tcb level";
                  "revoked";
                  "qe identity signature";
                  "qe identity";
                  "qe identity id";
                  "qe identity version";
                  "qe identity not yet valid";
                  "qe identity expired";
                  "qe miscselect";
                  "qe attributes";
                  "qe mrsigner";
                  "qe isvprodid";
                  "qe isvsvn";
                  "envelope";
                ]))
          32 );
    ]
