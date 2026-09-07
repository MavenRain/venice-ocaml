(* M29: admission policy and the opaque session key schedule. The
   independent affine/HKDF/AES oracle in harness/diff_session.py checks
   each inline KAT and the actual SESSION_KAT output. Only fixed test
   scalars are used here. No accepting attestation witness is forged. *)

module S = Venice__Sessx
module C = Venice__Secpx
module G = Venice__Gcmx
module H = Venice__Hexx
module E = Venice__Errx
module T = Venice__Tcbx
module A = Venice__Attestx
module P = Venice__Policyx
module J = Venice__Jsonx

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (name, (_ : bool)) -> print_endline ("FAIL " ^ name)) bad;
  Printf.printf "%d/%d ok\n" (List.length checks - List.length bad)
    (List.length checks);
  exit (if List.is_empty bad then 0 else 1)

let bytes (hex : string) : string option = Result.to_option (H.decode hex)

let scalar_of_hex (hex : string) : C.Scalar.t option =
  Option.bind (bytes hex) C.Scalar.of_bytes

let peer_of_hex (hex : string) : C.Pubkey.t option =
  Option.bind (bytes hex) C.Pubkey.of_bytes

let actual ~(scalar : string) ~(peer : string) :
    (string * string * string) option =
  Option.bind (scalar_of_hex scalar) (fun secret ->
    Option.bind (peer_of_hex peer) (fun model_key ->
      Option.bind (Result.to_option (S.client_key ~scalar:secret)) (fun client ->
        Option.bind
          (Result.to_option (S.derive_key ~scalar:secret ~peer:model_key))
          (fun key ->
            Option.bind (bytes "000102030405060708090a0b") (fun nonce_bytes ->
              Option.bind (G.Nonce.of_bytes nonce_bytes) (fun nonce ->
                Option.map
                  (fun (ct, tag) ->
                    (H.encode (C.Pubkey.to_sec1 client), H.encode ct,
                     H.encode (G.Tag.to_bytes tag)))
                  (G.seal key nonce ~aad:"m29 known-answer"
                     "venice-ocaml M29 session key")))))))

let kat ~(name : string) ~(scalar : string) ~(peer : string)
    ~(client : string) ~(ct : string) ~(tag : string) : bool =
  Option.fold ~none:false
    ~some:(fun (got_client, got_ct, got_tag) ->
      Printf.printf "SESSION_KAT\t%s\t%s\t%s\t%s\n"
        name got_client got_ct got_tag;
      String.equal got_client client && String.equal got_ct ct
      && String.equal got_tag tag)
    (actual ~scalar ~peer)

let kat_checks : (string * bool) list =
  [ ( "sessx: key schedule one",
      kat
      ~name:"one"
      ~scalar:"0000000000000000000000000000000000000000000000000000000000000001"
      ~peer:"045cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da"
      ~client:"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      ~ct:"d2e45f86bc7c907339b33411acac96469b54f00ed997fa1057cca54c"
      ~tag:"c7f73c9a87678f1534b4c19e7ca762b4" );
    ( "sessx: key schedule two",
      kat
      ~name:"two"
      ~scalar:"0000000000000000000000000000000000000000000000000000000000000002"
      ~peer:"04774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cbd984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b"
      ~client:"04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
      ~ct:"4717ee62d2236f2db133e3bc99f6abb01a235d6284fe292844a6078a"
      ~tag:"9fa25a820a92e65cbdce78bd8923e4aa" );
    ( "sessx: key schedule order-minus-one",
      kat
      ~name:"order-minus-one"
      ~scalar:"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
      ~peer:"04f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa80ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81"
      ~client:"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"
      ~ct:"9e5d8bcf209516ccdbc0af06c6ce59e4e51d634eb51e0d6a84d18d03"
      ~tag:"58737cf7bddab088be2269ae71bde64d" );
    ( "sessx: key schedule nontrivial",
      kat
      ~name:"nontrivial"
      ~scalar:"af1d69c1a0beaa67d8be9af986f591bc7340cdff57acbd275715137763ae7c68"
      ~peer:"043e69aa6d97849b14d0a7d8204e61dcf4b794f53e4ffa41bfa0c67ebb1ec8406079b1cc1a417317ae16d0674040994afa116460b95ad9766ba0890795aba02511"
      ~client:"04a5d73734151a5ff66acbbe392b84a637cb22f622d433572141058867954de6f759737f480ee22207bd674403a5e5f4c5891080f39aedecb1e0e2a81c66aa1fa1"
      ~ct:"502645e3b041c655ab81bfa3a1be8e9e0b445542ac6a750e9a2150bc"
      ~tag:"13742ff401c873ad1c44f542d7d80d2c" );
    ( "sessx: key schedule leading-zero",
      kat
      ~name:"leading-zero"
      ~scalar:"0000000000000000000000000000000000000000000000000000000000000099"
      ~peer:"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      ~client:"0400e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f458892aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4"
      ~ct:"fce207ebd8bfdde853a54548912c77378231d5ea833fc9f97a85bb20"
      ~tag:"da55e487629b5766dd0a6a6819d6d484" ) ]

let admission ?(model = Some "e2ee-test") ?(platform = T.Status.Up_to_date)
    ?(qe = T.Status.Up_to_date) ?(gpu = A.Gpu.Absent) (() : unit) :
    (unit, E.t) result =
  S.check_admission ~model_id:"e2ee-test" ~attested_model:model
    ~platform_status:platform ~qe_status:qe ~gpu

let error (word : string) (result : ('a, E.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> false)
    ~error:(fun e -> String.equal (E.to_string e) ("session: " ^ word)) result

let with_gpu (f : A.Gpu.t -> bool) : bool =
  let hex = String.make 64 '1' in
  Option.fold ~none:false ~some:f
    (Option.bind (P.Nonce.of_hex hex) (fun nonce ->
      Result.to_option
        (A.check_gpu ~nonce
          (Some (J.Jobj [ ("nonce", J.Jstring hex);
                         ("arch", J.Jstring "HOPPER");
                         ("evidence_list", J.Jlist [ J.Jobj [] ]) ])))))

let statuses : T.Status.t list =
  [ T.Status.Up_to_date; T.Status.Sw_hardening_needed;
    T.Status.Configuration_needed; T.Status.Configuration_and_sw_hardening_needed;
    T.Status.Out_of_date; T.Status.Out_of_date_configuration_needed;
    T.Status.Revoked ]

let grade_passes (status : T.Status.t) (word : string)
    (result : (unit, E.t) result) : bool =
  match status with
  | T.Status.Up_to_date -> Result.is_ok result
  | T.Status.Sw_hardening_needed | T.Status.Configuration_needed
  | T.Status.Configuration_and_sw_hardening_needed | T.Status.Out_of_date
  | T.Status.Out_of_date_configuration_needed | T.Status.Revoked -> error word result

let status_checks : (string * bool) list =
  List.concat_map
    (fun status ->
      [ ("sessx: platform " ^ T.Status.to_string status,
         grade_passes status "platform tcb" (admission ~platform:status ()));
        ("sessx: QE " ^ T.Status.to_string status,
         grade_passes status "qe tcb" (admission ~qe:status ())) ])
    statuses

let admission_checks : (string * bool) list =
  [ ( "sessx: exact model and current CPU-only grades admit",
      Result.is_ok (admission ()) );
    ( "sessx: missing model rejects",
      error "model missing" (admission ~model:None ()) );
    ( "sessx: wrong model rejects",
      error "model mismatch" (admission ~model:(Some "other") ()) );
    ( "sessx: empty model rejects",
      error "model mismatch" (admission ~model:(Some "") ()) );
    ( "sessx: model match is byte exact",
      error "model mismatch" (admission ~model:(Some "E2EE-test") ()) );
    ( "sessx: model whitespace is not normalized",
      error "model mismatch" (admission ~model:(Some "e2ee-test ") ()) );
    ( "sessx: structurally checked GPU evidence remains unauthenticated",
      with_gpu (fun gpu -> error "gpu unauthenticated" (admission ~gpu ())) );
    ( "sessx: missing model precedes platform grade",
      error "model missing"
        (admission ~model:None ~platform:T.Status.Revoked ()) );
    ( "sessx: wrong model precedes QE grade",
      error "model mismatch"
        (admission ~model:(Some "other") ~qe:T.Status.Revoked ()) );
    ( "sessx: platform grade precedes QE grade",
      error "platform tcb"
        (admission ~platform:T.Status.Out_of_date ~qe:T.Status.Revoked ()) );
    ( "sessx: QE grade precedes GPU evidence",
      with_gpu (fun gpu -> error "qe tcb"
        (admission ~qe:T.Status.Out_of_date ~gpu ())) );
    ( "sessx: model precedes all later admission failures",
      with_gpu (fun gpu -> error "model mismatch"
        (admission ~model:(Some "other") ~platform:T.Status.Out_of_date
          ~qe:T.Status.Out_of_date ~gpu ())) ) ]

let measurements ?(mr_td = 'a') ?(rt_mr0 = 'b') ?(rt_mr1 = 'c')
    ?(rt_mr2 = 'd') ?(rt_mr3 = 'e') (() : unit) : P.Measurements.t option =
  P.Measurements.make ~mr_td:(String.make 48 mr_td) ~rt_mr0:(String.make 48 rt_mr0)
    ~rt_mr1:(String.make 48 rt_mr1) ~rt_mr2:(String.make 48 rt_mr2)
    ~rt_mr3:(String.make 48 rt_mr3)

let cpu_check (observed : P.Measurements.t option)
    (accept : (unit, E.t) result -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun trusted ->
      Option.fold ~none:false
        ~some:(fun actual ->
          accept (S.check_cpu_only (S.Cpu_only.trust ~measurements:trusted) actual))
        observed)
    (measurements ())

let cpu_checks : (string * bool) list =
  [ ( "sessx: explicitly trusted CPU measurements match",
      cpu_check (measurements ()) Result.is_ok );
    ( "sessx: CPU identity checks MRTD",
      cpu_check (measurements ~mr_td:'x' ()) (error "cpu measurements") );
    ( "sessx: CPU identity checks RTMR0",
      cpu_check (measurements ~rt_mr0:'x' ()) (error "cpu measurements") );
    ( "sessx: CPU identity checks RTMR1",
      cpu_check (measurements ~rt_mr1:'x' ()) (error "cpu measurements") );
    ( "sessx: CPU identity checks RTMR2",
      cpu_check (measurements ~rt_mr2:'x' ()) (error "cpu measurements") );
    ( "sessx: CPU identity checks RTMR3",
      cpu_check (measurements ~rt_mr3:'x' ()) (error "cpu measurements") );
    ( "sessx: removing unsigned GPU evidence cannot satisfy CPU identity",
      Result.is_ok (admission ~gpu:A.Gpu.Absent ())
      && cpu_check (measurements ~mr_td:'x' ()) (error "cpu measurements") ) ]

let () = run (kat_checks @ status_checks @ admission_checks @ cpu_checks)
