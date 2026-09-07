(* M30 framing and fail-closed request preparation. Pins were computed
   independently with PyCryptodome AES-GCM. diff_encrypt.py checks the
   actual runtime ENCRYPT_KAT rows with its separate AES implementation. *)
module X = Venice__Encryptx
module G = Venice__Gcmx
module S = Venice__Secpx
module H = Venice__Hexx
module J = Venice__Jsonx
module E = Venice__Errx
module M = Venice__Modelx
module Msg = Venice__Msgx
module C = Venice__Chatx
module P = Venice__Paramsx
module Http = Venice__Httpx

let ( let* ) = Result.bind
let generator () =
  "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  ^ "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

let option word value =
  Option.fold ~none:(Error (E.Session_invalid word)) ~some:Result.ok value

let seal text =
  let* key = option "test key" (G.Key.of_bytes (String.make 32 '\000')) in
  let* raw = H.decode (generator ()) in
  let* client_pubkey = option "test pubkey" (S.Pubkey.of_bytes raw) in
  let* nonce = option "test nonce" (G.Nonce.of_bytes (String.make 12 '\000')) in
  X.seal ~key ~client_pubkey ~nonce text

let ok f r = Result.fold ~error:(fun (_ : E.t) -> false) ~ok:f r
let rejects word r = Result.fold ~ok:(fun _ -> false)
  ~error:(fun e -> String.equal (E.to_string e) ("session: " ^ word)) r

type checker = { f : 'c. 'c M.t -> bool }
let on_model c =
  ok (fun packed -> match packed with M.Pack model -> c.f model)
    (let* json = J.parse
      {|{"id":"encrypted","type":"text","capabilities":{"supportsFunctionCalling":true,"supportsVision":true,"supportsVideoInput":true,"supportsAudioInput":true,"supportsResponseSchema":true}}|} in
     M.of_json json)

let user text = let* message = Msg.user_text text in Msg.nonempty [message]
let chat model = let* messages = user "prompt secret" in C.make model messages ()
let prepare = X.prepare ~model_id:"encrypted"
let finish plan ciphertexts = X.finish ~client_pubkey_hex:(generator ())
  ~model_pubkey_hex:(generator ()) plan ciphertexts

let contains haystack needle =
  let rec scan i =
    if i + String.length needle > String.length haystack then false
    else if String.equal
      (String.of_seq (Seq.take (String.length needle)
        (Seq.drop i (String.to_seq haystack)))) needle then true
    else scan (i + 1) in
  scan 0

let kats () =
  [ "empty", "", "", "530f8afbc74536b9a963b4f1c4cb738b";
    "zero16", String.make 32 '0', "cea7403d4d606b6e074ec5d3baf39d18",
      "d0d1c8a799996bf0265b98b5d48ab919";
    "utf8", "6869f09f8c8a", "a6ceb0a2c1ea", "f6d005ca086ce54c0a5e058e54d71a16";
    "binary", "0001ff807f10000a0d5c22", "cea6bfbd32706b640a12e7",
      "5055e8fb2b45daa2a06dc101fc71c860" ]

let kat_checks () = List.map
  (fun (name, plaintext_hex, ciphertext, tag) ->
    "seal " ^ name, ok (fun encrypted ->
      let frame = X.Ciphertext.to_hex encrypted in
      Printf.printf "ENCRYPT_KAT\t%s\t%s\t%s\n" name plaintext_hex frame;
      String.equal frame (generator () ^ String.make 24 '0' ^ ciphertext ^ tag))
      (let* plaintext = H.decode plaintext_hex in seal plaintext)) (kats ())

let message_reject word make_messages = on_model { f = fun model ->
  rejects word (let* messages = make_messages () in
    let* request = C.make model messages () in prepare request) }

let lifted mint () = let* m = mint () in Msg.nonempty [Msg.lift m]

let venice_case value expected = on_model { f = fun model ->
  let result = let* messages = user "private" in
    let* request = C.make ~venice:value model messages () in prepare request in
  if expected then Result.is_ok result else rejects "venice feature" result }

let configured_rejections () =
  List.map (fun (name, value) -> name, venice_case value false)
    [ "character", P.Venice_params.make ~character_slug:"private character" ();
      "web on", P.Venice_params.make ~enable_web_search:P.Venice_params.On ();
      "web auto", P.Venice_params.make ~enable_web_search:P.Venice_params.Auto ();
      "scraping", P.Venice_params.make ~enable_web_scraping:true ();
      "citations", P.Venice_params.make ~enable_web_citations:true ();
      "stream search results", P.Venice_params.make ~include_search_results_in_stream:true ();
      "search documents", P.Venice_params.make ~return_search_results_as_documents:true ();
      "x search", P.Venice_params.make ~enable_x_search:true () ]

let checks () = [
  "oversized plaintext rejects before AES", rejects "plaintext length"
    (seal (String.make 2_000_001 'p'));
  "model mismatch", on_model { f = fun model ->
    rejects "model mismatch" (let* request = chat model in
      X.prepare ~model_id:"other" request) };
  "plaintext projection keeps message order", on_model { f = fun model ->
    ok (fun plan -> X.plaintexts plan = ["first"; "second"])
      (let* system = Msg.system "first" in let* u = Msg.user_text "second" in
       let* messages = Msg.nonempty [Msg.lift system; u] in
       let* request = C.make model messages () in prepare request) };
  "assistant role", message_reject "message role"
    (lifted (fun () -> Msg.assistant ~content:"private history" ()));
  "developer role", message_reject "message role"
    (lifted (fun () -> Msg.developer "private instruction"));
  "tool role", message_reject "message role"
    (lifted (fun () -> Msg.tool ~tool_call_id:"call" "private result"));
  "user name", message_reject "message metadata" (fun () ->
    let* u = Msg.user_text ~name:"private name" "private" in Msg.nonempty [u]);
  "system name", message_reject "message metadata"
    (lifted (fun () -> Msg.system ~name:"private name" "private"));
  "multipart user", message_reject "message content" (fun () ->
    let* a = Msg.text "first" in let* b = Msg.text "second" in
    let* u = Msg.user [Msg.of_text a; Msg.of_text b] in Msg.nonempty [u]);
  "cached user", message_reject "message content" (fun () ->
    let* a = Msg.text ~cache:Msg.Cache.ephemeral "private" in
    let* u = Msg.user [Msg.of_text a] in Msg.nonempty [u]);
  "multipart system", message_reject "message content" (fun () ->
    let* a = Msg.text "first" in let* b = Msg.text "second" in
    let* s = Msg.system_parts [a; b] in Msg.nonempty [Msg.lift s]);
  "cached system", message_reject "message content" (fun () ->
    let* a = Msg.text ~cache:Msg.Cache.ephemeral "private" in
    let* s = Msg.system_parts [a] in Msg.nonempty [Msg.lift s]);
  "file", message_reject "message content" (fun () ->
    let* part = Msg.file "data:text/plain;base64,cHJpdmF0ZQ==" in
    let* u = Msg.user [Msg.of_file part] in Msg.nonempty [u]);
  "image", on_model { f = fun model ->
    Option.fold ~none:false ~some:(fun witnessed ->
      rejects "message content" (let* part = Msg.image witnessed ~url:"https://private.example/image" in
        let* u = Msg.user [part] in let* messages = Msg.nonempty [u] in
        let* request = C.make model messages () in prepare request)) (M.vision model) };
  "audio", on_model { f = fun model ->
    Option.fold ~none:false ~some:(fun witnessed ->
      rejects "message content" (let* part = Msg.audio witnessed ~data:"cHJpdmF0ZQ==" in
        let* u = Msg.user [part] in let* messages = Msg.nonempty [u] in
        let* request = C.make model messages () in prepare request)) (M.audio model) };
  "video", on_model { f = fun model ->
    Option.fold ~none:false ~some:(fun witnessed ->
      rejects "message content" (let* part = Msg.video witnessed ~url:"https://private.example/video" in
        let* u = Msg.user [part] in let* messages = Msg.nonempty [u] in
        let* request = C.make model messages () in prepare request)) (M.video model) };
  "tools", on_model { f = fun model ->
    Option.fold ~none:false ~some:(fun witnessed ->
      rejects "request feature" (let* messages = user "private" in
        let* tool = C.Tool.function_ ~name:"private_tool" () in
        let* request = C.make ~tools:(witnessed, [tool]) model messages () in
        prepare request)) (M.tools model) };
  "tool choice", on_model { f = fun model ->
    rejects "request feature" (let* messages = user "private" in
      let* request = C.make ~tool_choice:C.Tool_none model messages () in prepare request) };
  "parallel tool calls even false", on_model { f = fun model ->
    rejects "request feature" (let* messages = user "private" in
      let* request = C.make ~parallel_tool_calls:false model messages () in prepare request) };
  "response format", on_model { f = fun model ->
    rejects "request feature" (let* messages = user "private" in
      let* request = C.make ~response_format:C.Rf_json_object model messages () in prepare request) };
  "response schema", on_model { f = fun model ->
    Option.fold ~none:false ~some:(fun witnessed ->
      rejects "request feature" (let* messages = user "private" in
        let* request = C.make ~response_format:(C.Rf_json_schema (witnessed,
          J.Jobj ["description", J.Jstring "private schema"])) model messages () in
        prepare request)) (M.response_schema model) };
  "prompt cache key", on_model { f = fun model ->
    rejects "request feature" (let* messages = user "private" in
      let* request = C.make ~prompt_cache_key:"private key" model messages () in prepare request) };
  "stop sequence", on_model { f = fun model ->
    rejects "request feature" (let* messages = user "private" in
      let* stop = C.Stop.of_string "private stop" in
      let* request = C.make ~stop model messages () in prepare request) };
  "disabled search options and safe booleans", venice_case
    (P.Venice_params.make ~strip_thinking_response:true ~disable_thinking:false
      ~include_venice_system_prompt:false ~enable_web_search:P.Venice_params.Off
      ~enable_web_scraping:false ~enable_web_citations:false
      ~include_search_results_in_stream:false ~return_search_results_as_documents:false
      ~enable_x_search:false ()) true;
  (* The independently rendered template is 234 bytes with seed=7 and
     two empty user contents. Two frames add 372 hex overhead bytes:
     234 + 372 + 2 * (2_000_000 + 96_849) = 4_194_304 exactly. *)
  "exact encrypted body cap accepts before seal", on_model { f = fun model ->
    Result.is_ok (let* a = Msg.user_text (String.make 2_000_000 'a') in
      let* b = Msg.user_text (String.make 96_849 'b') in
      let* messages = Msg.nonempty [a; b] in
      let* request = C.make ~seed:7 model messages () in prepare request) };
  "one plaintext byte beyond encrypted body cap rejects", on_model { f = fun model ->
    rejects "encrypted body length"
      (let* a = Msg.user_text (String.make 2_000_000 'a') in
       let* b = Msg.user_text (String.make 96_850 'b') in
       let* messages = Msg.nonempty [a; b] in
       let* request = C.make ~seed:7 model messages () in prepare request) };
  "aggregate ciphertext expansion rejects before seal", on_model { f = fun model ->
    rejects "encrypted body length" (let* a = Msg.user_text (String.make 1_100_000 'a') in
      let* b = Msg.user_text (String.make 1_100_000 'b') in
      let* messages = Msg.nonempty [a; b] in
      let* request = C.make model messages () in prepare request) };
  "individual preflight length cap", on_model { f = fun model ->
    rejects "plaintext length" (let* messages = user (String.make 2_000_001 'p') in
      let* request = C.make model messages () in prepare request) };
  "missing ciphertext", on_model { f = fun model ->
    rejects "ciphertext count" (let* request = chat model in let* plan = prepare request in
      finish plan []) };
  "extra ciphertext", on_model { f = fun model ->
    rejects "ciphertext count" (let* request = chat model in let* plan = prepare request in
      let* ciphertext = seal "prompt secret" in finish plan [ciphertext; ciphertext]) };
  "encrypted request body headers and log", on_model { f = fun model ->
    ok (fun (request, first, second) ->
      let expected_headers = [
        "x-venice-tee-client-pub-key", generator ();
        "x-venice-tee-model-pub-key", generator ();
        "x-venice-tee-signing-algo", "ecdsa"] in
      let expected = "{\"model\":\"encrypted\",\"messages\":[{\"role\":\"system\",\"content\":\""
        ^ X.Ciphertext.to_hex first ^ "\"},{\"role\":\"user\",\"content\":\""
        ^ X.Ciphertext.to_hex second ^ "\"}],\"max_completion_tokens\":8,\"stream\":true,\"seed\":7,"
        ^ "\"venice_parameters\":{\"enable_e2ee\":true,\"enable_web_search\":\"off\","
        ^ "\"enable_web_scraping\":false,\"enable_x_search\":false}}" in
      let log = Http.Request.to_log request in
      Http.Request.headers request = expected_headers &&
      Http.Request.meth request = Http.Request.Post &&
      String.equal (Http.Request.path request) "/chat/completions" &&
      Option.equal String.equal (Http.Request.rendered request) (Some expected) &&
      not (contains expected "system secret") && not (contains expected "prompt secret") &&
      not (contains log "system secret") && not (contains log "prompt secret") &&
      not (contains log (X.Ciphertext.to_hex first)) && not (contains log (generator ())))
      (let* system = Msg.system "system secret" in let* u = Msg.user_text "prompt secret" in
       let* messages = Msg.nonempty [Msg.lift system; u] in
       let* request = C.make ~max_completion:8 ~seed:7 model messages () in
       let* plan = prepare request in
       let* first = seal "system secret" in let* second = seal "prompt secret" in
       let* request = finish plan [first; second] in Ok (request, first, second)) }
]

let () =
  let all = kat_checks () @ checks () @ configured_rejections () in
  let failed = List.filter (fun (_, value) -> not value) all in
  List.iter (fun (name, _) -> print_endline ("FAIL " ^ name)) failed;
  Printf.printf "%d/%d ok\n" (List.length all - List.length failed) (List.length all);
  exit (if List.is_empty failed then 0 else 1)
