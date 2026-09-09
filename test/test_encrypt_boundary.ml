(* The generated implementation is the real Sessionx host source.
   Only admission is faked; entropy, key derivation, encryption, chat
   construction and transport capture use production implementations. *)
module F = Encrypt_boundary_fakes
module S = Encrypt_boundary_impl
module E = Venice__Entropyx
module R = Venice__Errx
module D = Venice__Derx
module G = Venice__Gcmx
module H = Venice__Hexx
module B = Venice__Bytesx
module X = Venice__Encryptx
module M = Venice__Modelx
module Msg = Venice__Msgx
module C = Venice__Chatx
module J = Venice__Jsonx
module Http = Venice__Httpx
module Fake = Venice__Fakex

let ( let* ) = Result.bind

let check_ok (r : ('a, R.t) result) (f : 'a -> bool) : bool =
  Result.fold ~ok:f ~error:(fun _ -> false) r

let error_is (word : string) (r : ('a, R.t) result) : bool =
  Result.fold ~ok:(fun _ -> false)
    ~error:(fun e -> e = R.Session_invalid word) r

let draw (c : char) : string = String.make 32 c
let fresh (c : char) : (E.Gcm_fresh.t, R.t) result =
  E.Gcm_fresh.make ~entropy:(E.Fake.make [draw c])

let make_session ~(entropy : E.t) ~(model : string) : ('c S.t, R.t) result =
  let* token = E.Fresh.make ~entropy in
  let* now = Option.to_result ~none:(R.Session_invalid "test time")
    (D.Now.of_digits "20250620103227") in
  let attested = { F.Attestx.Attested.nonce_value = E.Fresh.nonce token } in
  S.establish ~entropy ~fresh:token ~cpu_only:() ~now ~attested ~model

let with_session (f : 'c S.t -> bool) : bool =
  let entropy = E.Fake.make [draw 'a'; String.make 31 '\000' ^ "\001"] in
  check_ok (make_session ~entropy ~model:"chatty") f

let encrypt (session : 'c S.t) (c : char) (plaintext : string) :
    (X.Ciphertext.t, R.t) result =
  let* token = fresh c in
  S.encrypt ~fresh:token session plaintext

type frame = { client : string; nonce : G.Nonce.t; ciphertext : string; tag : G.Tag.t }

let frame (hex : string) : frame option =
  let ( let* ) = Option.bind in
  let* bytes = Result.to_option (H.decode hex) in
  let length = String.length bytes in
  if length < 93 then None
  else
    let* client = B.take bytes 0 65 in
    let* nonce_bytes = B.take bytes 65 12 in
    let* nonce = G.Nonce.of_bytes nonce_bytes in
    let* ciphertext = B.take bytes 77 (length - 93) in
    let* tag_bytes = B.take bytes (length - 16) 16 in
    let* tag = G.Tag.of_bytes tag_bytes in
    Some { client; nonce; ciphertext; tag }

let frame_plaintext (session : 'c S.t) ~(plaintext : string) (hex : string) : bool =
  Option.fold ~none:false ~some:(fun value ->
    String.equal (H.encode value.client) (S.client_pubkey_hex session)
    && Option.equal String.equal (Some plaintext)
         (G.unseal session.core.cipher_key value.nonce ~aad:"" value.ciphertext value.tag))
    (frame hex)

let frame_nonce (hex : string) : string option =
  Option.map (fun value -> G.Nonce.to_bytes value.nonce) (frame hex)

(* Independent pin from harness/diff_session.py: scalar 1, peer 7G,
   HKDF info ecdsa_encryption, empty AAD, and twelve ASCII n bytes.
   The derived AES key is nonzero and is never projected by the SDK. *)
let pinned_frame (() : unit) : string =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b86e6e6e6e6e6e6e6e6e6e6e6e8259934f7ece3a7b3049f7a3f1180d562041fea97b89d527e2cef616a5fb"

let encryption_checks : (string * bool) list =
  [ ( "host encrypt: real derived key emits the independently pinned complete frame",
      with_session (fun session ->
        check_ok (encrypt session 'n' "private prompt") (fun ciphertext ->
          let hex = X.Ciphertext.to_hex ciphertext in
          String.equal hex (pinned_frame ())
          && frame_plaintext session ~plaintext:"private prompt" hex)) );
    ( "host encrypt: alias replay rejects before a second reservation",
      with_session (fun session -> check_ok (fresh 'n') (fun token ->
        let alias = token in
        Result.is_ok (S.encrypt ~fresh:token session "first")
        && error_is "gcm nonce consumed" (S.encrypt ~fresh:alias session "second")
        && (Atomic.get session.used).count = 1)) );
    ( "host encrypt: oversized plaintext burns both the handle and nonce reservation",
      with_session (fun session -> check_ok (fresh 'n') (fun token ->
        error_is "plaintext length"
          (S.encrypt ~fresh:token session (String.make 2_000_001 'x'))
        && error_is "gcm nonce consumed" (S.encrypt ~fresh:token session "retry")
        && error_is "gcm nonce reused" (encrypt session 'n' "new handle")
        && (Atomic.get session.used).count = 1)) );
    ( "host encrypt: independent handles cannot reuse nonce bytes in one session",
      with_session (fun session ->
        Result.is_ok (encrypt session 'n' "first")
        && check_ok (fresh 'n') (fun token ->
          error_is "gcm nonce reused" (S.encrypt ~fresh:token session "second")
          && error_is "gcm nonce consumed" (S.encrypt ~fresh:token session "third")
          && (Atomic.get session.used).count = 1)) );
    ( "host encrypt: distinct nonces allow independent encryptions",
      with_session (fun session ->
        check_ok (encrypt session 'n' "first") (fun first ->
          check_ok (encrypt session 'm' "second") (fun second ->
            frame_plaintext session ~plaintext:"first" (X.Ciphertext.to_hex first)
            && frame_plaintext session ~plaintext:"second" (X.Ciphertext.to_hex second)
            && (Atomic.get session.used).count = 2))) ) ]

let rec await_start (started : bool Atomic.t) : unit =
  if Atomic.get started then ()
  else (Domain.cpu_relax (); await_start started)

let rec await_ready (ready : int Atomic.t) (count : int) : unit =
  if Atomic.get ready = count then ()
  else (Domain.cpu_relax (); await_ready ready count)

let race (jobs : (unit -> ('a, R.t) result) list) : ('a, R.t) result list =
  let started = Atomic.make false in
  let ready = Atomic.make 0 in
  let domains = List.map (fun job -> Domain.spawn (fun () ->
    Atomic.incr ready;
    await_start started; job ())) jobs in
  await_ready ready (List.length jobs);
  Atomic.set started true;
  List.map Domain.join domains

let one_winner (word : string) (results : ('a, R.t) result list) : bool =
  List.length (List.filter Result.is_ok results) = 1
  && List.length (List.filter (error_is word) results) = List.length results - 1

let set_count (session : 'c S.t) (count : int) : unit =
  (* Only the copied module exposes this record. Synthetic occupancy
     reaches the boundary without 65,536 expensive AES operations. *)
  Atomic.set session.used { S.nonces = S.Nonce_set.empty; count }

let concurrency_checks : (string * bool) list =
  [ ( "host encrypt: concurrent aliases of one token produce one winner",
      with_session (fun session -> check_ok (fresh 'n') (fun token ->
        let results = race (List.init 8 (fun _ -> fun () ->
          S.encrypt ~fresh:token session "race")) in
        one_winner "gcm nonce consumed" results
        && (Atomic.get session.used).count = 1)) );
    ( "host encrypt: independently drawn equal nonces share one atomic reservation",
      with_session (fun session ->
        let results = race (List.init 8 (fun _ -> fun () ->
          encrypt session 'n' "race")) in
        one_winner "gcm nonce reused" results
        && (Atomic.get session.used).count = 1) );
    ( "host encrypt: nonce 65,536 is accepted and the next token burns at the cap",
      with_session (fun session ->
        set_count session 65_535;
        Result.is_ok (encrypt session 'n' "last slot")
        && (Atomic.get session.used).count = 65_536
        && check_ok (fresh 'm') (fun token ->
          error_is "gcm nonce limit" (S.encrypt ~fresh:token session "over cap")
          && error_is "gcm nonce consumed" (S.encrypt ~fresh:token session "retry")
          && (Atomic.get session.used).count = 65_536)) );
    ( "host encrypt: a session already at the cap refuses any new nonce",
      with_session (fun session ->
        set_count session 65_536;
        error_is "gcm nonce limit" (encrypt session 'n' "over cap")
        && S.Nonce_set.is_empty (Atomic.get session.used).nonces) );
    ( "host encrypt: contenders for the final budget slot produce one winner",
      with_session (fun session ->
        set_count session 65_535;
        let results = race (List.map (fun c -> fun () ->
          encrypt session c "final slot") ['a'; 'b'; 'c'; 'd'; 'e'; 'f'; 'g'; 'h']) in
        one_winner "gcm nonce limit" results
        && (Atomic.get session.used).count = 65_536
        && S.Nonce_set.cardinal (Atomic.get session.used).nonces = 1) ) ]

(* The exact chatty fixture used by test_chatx, through the real model mint. *)
let chatty (() : unit) : string =
  {|{"id":"chatty","type":"text","capabilities":{"supportsReasoningEffort":true,"supportsLogProbs":true,"supportsFunctionCalling":true,"supportsResponseSchema":true,"reasoningEffortOptions":["low","medium","high"]},"model_spec":{"availableContextTokens":4096,"maxCompletionTokens":2048}}|}

type checker = { f : 'c. 'c M.t -> bool }

let on_model (json : string) (check : checker) : bool =
  check_ok (let* value = J.parse json in M.of_json value)
    (fun packed -> match packed with M.Pack model -> check.f model)

let chat (model : 'c M.t) : ('c C.t, R.t) result =
  let* system = Msg.system "secret system instruction" in
  let* user = Msg.user_text "secret user question" in
  let* messages = Msg.nonempty [Msg.lift system; user] in
  C.make ~seed:7 ~max_completion:32 model messages ()

let late_assistant (model : 'c M.t) : ('c C.t, R.t) result =
  let* user = Msg.user_text "secret user question" in
  let* assistant = Msg.assistant ~content:"late assistant" () in
  let* messages = Msg.nonempty [user; Msg.lift assistant] in
  C.make model messages ()

let member (name : string) (value : J.t) : J.t option =
  Option.bind (J.as_obj value) (List.assoc_opt name)

let contents (req : Http.Request.t) : string list option =
  let ( let* ) = Option.bind in
  let* body = Http.Request.body req in
  let* values = Option.bind (member "messages" body) J.as_list in
  List.fold_right (fun item rest ->
    let* text = Option.bind (member "content" item) J.as_string in
    let* tail = rest in Some (text :: tail)) values (Some [])

let truthful_headers (session : 'c S.t) (req : Http.Request.t) : bool =
  let headers = Http.Request.headers req in
  List.length headers = 3
  && List.assoc_opt "x-venice-tee-client-pub-key" headers = Some (S.client_pubkey_hex session)
  && List.assoc_opt "x-venice-tee-model-pub-key" headers = Some (S.model_pubkey_hex session)
  && List.assoc_opt "x-venice-tee-signing-algo" headers = Some "ecdsa"

let request_body (session : 'c S.t) (req : Http.Request.t) : bool =
  Option.fold ~none:false ~some:(fun body ->
    Option.bind (member "stream" body) J.as_bool = Some true
    && Option.fold ~none:false ~some:(fun params ->
      Option.bind (member "enable_e2ee" params) J.as_bool = Some true
      && Option.bind (member "enable_web_search" params) J.as_string = Some "off"
      && Option.bind (member "enable_web_scraping" params) J.as_bool = Some false
      && Option.bind (member "enable_x_search" params) J.as_bool = Some false)
      (member "venice_parameters" body)
    && Option.fold ~none:false ~some:(fun hexes -> match hexes with
      | [system; user] ->
        frame_plaintext session ~plaintext:"secret system instruction" system
        && frame_plaintext session ~plaintext:"secret user question" user
        && frame_nonce system <> frame_nonce user
      | [] | [_] | _ :: _ :: _ :: _ -> false) (contents req))
    (Http.Request.body req)

let request_checks : (string * bool) list =
  [ ( "host request: all user/system messages encrypt with distinct nonces and truthful headers",
      on_model (chatty ()) { f = fun model -> with_session (fun session ->
        check_ok (chat model) (fun input ->
          let entropy = E.Fake.make [draw 'n'; draw 'm'; draw 'o'] in
          check_ok (S.request ~entropy session input) (fun req ->
            E.Fake.remaining entropy = 1 && truthful_headers session req
            && request_body session req
            && (Atomic.get session.used).count = 2))) } );
    ( "host request: model mismatch refuses before any entropy draw",
      on_model {|{"id":"uncapped","type":"text"}|} { f = fun model ->
        with_session (fun session -> check_ok (chat model) (fun input ->
          let entropy = E.Fake.make [draw 'n'; draw 'm'] in
          error_is "model mismatch" (S.request ~entropy session input)
          && E.Fake.remaining entropy = 2 && (Atomic.get session.used).count = 0)) } );
    ( "host request: a late unsupported role refuses before any entropy draw",
      on_model (chatty ()) { f = fun model -> with_session (fun session ->
        check_ok (late_assistant model) (fun input ->
          let entropy = E.Fake.make [draw 'n'; draw 'm'] in
          error_is "message role" (S.request ~entropy session input)
          && E.Fake.remaining entropy = 2 && (Atomic.get session.used).count = 0)) } );
    ( "host request: oversized encrypted body refuses before any entropy draw",
      on_model (chatty ()) { f = fun model -> with_session (fun session ->
        let input =
          let* first = Msg.user_text (String.make 1_100_000 'x') in
          let* second = Msg.user_text (String.make 1_100_000 'y') in
          let* messages = Msg.nonempty [first; second] in
          C.make model messages ()
        in
        check_ok input (fun input ->
          let entropy = E.Fake.make [draw 'n'; draw 'm'] in
          error_is "encrypted body length" (S.request ~entropy session input)
          && E.Fake.remaining entropy = 2 && (Atomic.get session.used).count = 0)) } );
    ( "host request: later entropy exhaustion returns only an error and retains the first reservation",
      on_model (chatty ()) { f = fun model -> with_session (fun session ->
        check_ok (chat model) (fun input ->
          let entropy = E.Fake.make [draw 'n'] in
          error_is "entropy exhausted" (S.request ~entropy session input)
          && E.Fake.remaining entropy = 0 && (Atomic.get session.used).count = 1
          && error_is "gcm nonce reused" (encrypt session 'n' "retry")
          && Result.is_ok (encrypt session 'm' "new nonce"))) } );
    ( "host request: later malformed entropy preserves the first reservation",
      on_model (chatty ()) { f = fun model -> with_session (fun session ->
        check_ok (chat model) (fun input ->
          let entropy = E.Fake.make [draw 'n'; "bad"; draw 'm'] in
          error_is "entropy length" (S.request ~entropy session input)
          && E.Fake.remaining entropy = 1 && (Atomic.get session.used).count = 1
          && error_is "gcm nonce reused" (encrypt session 'n' "retry"))) } );
    ( "host request: duplicate scripted nonces across messages refuse the request",
      on_model (chatty ()) { f = fun model -> with_session (fun session ->
        check_ok (chat model) (fun input ->
          let entropy = E.Fake.make [draw 'n'; draw 'n'; draw 'm'] in
          error_is "gcm nonce reused" (S.request ~entropy session input)
          && E.Fake.remaining entropy = 1 && (Atomic.get session.used).count = 1)) } );
    ( "host request: production entropy prepares an encrypted request captured by transport",
      on_model (chatty ()) { f = fun model ->
        let entropy = E.system () in
        check_ok (make_session ~entropy ~model:"chatty") (fun session ->
          check_ok (chat model) (fun input ->
            check_ok (S.request ~entropy session input) (fun req ->
              let transport = Fake.make [Fake.exchange
                ~head:"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"
                ~chunks:[] ()] in
              check_ok (Venice__Keyx.make "test-transport-key") (fun key ->
                check_ok (Fake.send transport ~key req) (fun (_, body) ->
                  Result.is_ok (Fake.close body)
                  && match Fake.requests transport with
                    | [sent] -> truthful_headers session sent && request_body session sent
                    | [] | _ :: _ :: _ -> false))))) } ) ]

module Decrypt_stream = S.Stream (Fake)

(* Replace the first occurrence of needle, through total accessors. *)
let replace source needle replacement =
  let rec loop offset =
    Option.fold ~none:(fun () -> source) ~some:(fun found () ->
      if String.equal found needle then
        Option.value ~default:"" (B.take source 0 offset) ^ replacement ^
        Option.value ~default:"" (B.take source (offset + String.length needle)
          (String.length source - offset - String.length needle))
      else loop (offset + 1))
      (B.take source offset (String.length needle)) () in
  loop 0

let without_done wire = replace wire "data: [DONE]\n\n" ""

let response_run ?(transform = Fun.id) scalar model =
  let entropy = E.Fake.make [draw 'a'; String.make 31 '\000' ^ B.of_codes [scalar]] in
  let* session = make_session ~entropy ~model in
  let* fixture = J.parse (Fixture_decrypt_host.bytes ()) in
  let* hex = Option.to_result ~none:(R.Session_invalid "test fixture")
    (Option.bind (J.member "response_body_hex" fixture) J.as_string) in
  let* wire = Result.map transform (H.decode hex) in
  let* key = Venice__Keyx.make "test" in
  let* request = Http.Request.get Http.Route.models in
  let transport = Fake.make [Fake.exchange
    ~head:"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"
    ~chunks:[wire] ()] in
  let* _, body = Fake.send transport ~key request in
  let contents, outcome = Decrypt_stream.run session body (fun cursor ->
    Venice__Streamx.fold cursor ~init:[] ~f:(fun acc chunk ->
      acc @ List.concat_map (fun choice ->
        let delta = Venice__Ssex.Chunk.Choice.delta choice in
        List.filter_map Fun.id [Venice__Ssex.Chunk.Delta.content delta;
          Venice__Ssex.Chunk.Delta.reasoning_content delta])
        (Venice__Ssex.Chunk.choices chunk))) in
  Ok (contents, outcome, Fake.closes body)

let response_checks = [
  "host response: session scalar decrypts independent fixture",
    check_ok (response_run 3 "SYNTHETIC-model") (function
      | ["Synthetic answer."; "Synthetic reasoning."], Venice__Streamx.Complete, 1 -> true
      | _, (Venice__Streamx.Complete | Venice__Streamx.Cut | Venice__Streamx.Failed _), _ -> false);
  "host response: wrong session key releases no plaintext",
    check_ok (response_run 4 "SYNTHETIC-model") (function
      | [], Venice__Streamx.Failed (R.Session_invalid "response authentication"), 1 -> true
      | _, (Venice__Streamx.Complete | Venice__Streamx.Cut | Venice__Streamx.Failed _), _ -> false);
  "host response: session model mismatch releases no plaintext",
    check_ok (response_run 3 "wrong-model") (function
      | [], Venice__Streamx.Failed (R.Session_invalid "response model"), 1 -> true
      | _, (Venice__Streamx.Complete | Venice__Streamx.Cut | Venice__Streamx.Failed _), _ -> false);
  (* The host path defaults to Require_done, so a stream that stops at a
     clean EOF fails. *)
  "host response: a stream without DONE fails",
    check_ok (response_run ~transform:without_done 3 "SYNTHETIC-model") (function
      | _, Venice__Streamx.Failed _, 1 -> true
      | _, (Venice__Streamx.Complete | Venice__Streamx.Cut | Venice__Streamx.Failed _), _ -> false)
]

let () =
  let checks = encryption_checks @ concurrency_checks @ request_checks @ response_checks in
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (name, (_ : bool)) -> print_endline ("FAIL " ^ name)) bad;
  Printf.printf "%d/%d ok\n" (List.length checks - List.length bad) (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)
