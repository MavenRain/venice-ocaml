(* M30 pure encryption. The host reserves each nonce before seal.
   Plans retain prompt bytes only for the seal calls; the request body
   template contains empty content slots, never the original prompt. *)
let ( let* ) = Result.bind
let invalid (word : string) : ('a, Errx.t) result =
  Error (Errx.Session_invalid word)

let max_plaintext (() : unit) : int = 2_000_000
let max_body (() : unit) : int = 4_194_304
let frame_overhead (() : unit) : int = 93

module Ciphertext = struct
  type t = string
  let to_hex (t : t) : string = t
end

let seal ~(key : Gcmx.Key.t) ~(client_pubkey : Secpx.Pubkey.t)
    ~(nonce : Gcmx.Nonce.t) (plaintext : string) :
    (Ciphertext.t, Errx.t) result =
  if String.length plaintext > max_plaintext () then invalid "plaintext length"
  else
    Option.fold ~none:(invalid "plaintext length")
      ~some:(fun ((ciphertext : string), (tag : Gcmx.Tag.t)) ->
        Ok (Hexx.encode
          (Secpx.Pubkey.to_sec1 client_pubkey ^ Gcmx.Nonce.to_bytes nonce
           ^ ciphertext ^ Gcmx.Tag.to_bytes tag)))
      (Gcmx.seal key nonce ~aad:"" plaintext)

type message = { role : string; plaintext : string }
type repr = { fields : (string * Jsonx.t) list; messages : message list }
type 'c plan = repr

let object_fields (word : string) (value : Jsonx.t) :
    ((string * Jsonx.t) list, Errx.t) result =
  Option.fold ~none:(invalid word) ~some:(fun fields -> Ok fields)
    (Jsonx.as_obj value)

let string_member (word : string) (name : string)
    (fields : (string * Jsonx.t) list) : (string, Errx.t) result =
  Option.fold ~none:(invalid word) ~some:(fun value -> Ok value)
    (Option.bind (List.assoc_opt name fields) Jsonx.as_string)

let message (value : Jsonx.t) : (message, Errx.t) result =
  let* fields = object_fields "message shape" value in
  let* role = string_member "message role" "role" fields in
  if not (String.equal role "user" || String.equal role "system") then
    invalid "message role"
  else if List.exists
    (fun ((name : string), (_ : Jsonx.t)) ->
      not (String.equal name "role" || String.equal name "content")) fields then
    invalid "message metadata"
  else
    let* plaintext = string_member "message content" "content" fields in
    if String.length plaintext > max_plaintext () then invalid "plaintext length"
    else Ok { role; plaintext }

let messages (fields : (string * Jsonx.t) list) :
    (message list, Errx.t) result =
  let* items = Option.fold ~none:(invalid "messages")
    ~some:(fun values -> Ok values)
    (Option.bind (List.assoc_opt "messages" fields) Jsonx.as_list) in
  match items with
  | [] -> invalid "messages"
  | _ :: _ ->
    Result.map List.rev (List.fold_left
      (fun acc value ->
        let* parsed = acc in
        let* next = message value in
        Ok (next :: parsed)) (Ok []) items)

let safe_members (() : unit) : string list =
  [ "model"; "messages"; "temperature"; "top_p"; "frequency_penalty";
    "presence_penalty"; "repetition_penalty"; "top_k";
    "venice_parameters"; "max_completion_tokens"; "stream";
    "stop_token_ids"; "seed"; "n"; "logprobs"; "top_logprobs";
    "reasoning_effort"; "prompt_cache_retention" ]

let check_members (fields : (string * Jsonx.t) list) : (unit, Errx.t) result =
  if List.for_all
    (fun ((name : string), (_ : Jsonx.t)) -> List.mem name (safe_members ()))
    fields then Ok ()
  else invalid "request feature"

let forced_venice (() : unit) : (string * Jsonx.t) list =
  [ "enable_e2ee", Jsonx.Jbool true;
    "enable_web_search", Jsonx.Jstring "off";
    "enable_web_scraping", Jsonx.Jbool false;
    "enable_x_search", Jsonx.Jbool false ]

let check_venice_member ((name : string), (value : Jsonx.t)) :
    (unit, Errx.t) result =
  match name with
  | "strip_thinking_response" | "disable_thinking" | "include_venice_system_prompt" ->
    Option.fold ~none:(invalid "venice feature")
      ~some:(fun (_ : bool) -> Ok ()) (Jsonx.as_bool value)
  | "enable_web_search" ->
    if Option.equal String.equal (Jsonx.as_string value) (Some "off") then Ok ()
    else invalid "venice feature"
  | "enable_web_scraping" | "enable_web_citations"
  | "include_search_results_in_stream" | "return_search_results_as_documents"
  | "enable_x_search" ->
    if Option.equal Bool.equal (Jsonx.as_bool value) (Some false) then Ok ()
    else invalid "venice feature"
  | _ -> invalid "venice feature"

let venice_fields (fields : (string * Jsonx.t) list) :
    ((string * Jsonx.t) list, Errx.t) result =
  let* configured = Option.fold ~none:(Ok [])
    ~some:(object_fields "venice feature")
    (List.assoc_opt "venice_parameters" fields) in
  let* () = List.fold_left
    (fun acc item -> let* () = acc in check_venice_member item)
    (Ok ()) configured in
  let retained = List.filter
    (fun ((name : string), (_ : Jsonx.t)) ->
      not (List.mem_assoc name (forced_venice ()))) configured in
  Ok (forced_venice () @ retained)

let wire_message (role : string) (content : string) : Jsonx.t =
  Jsonx.Jobj [ "role", Jsonx.Jstring role; "content", Jsonx.Jstring content ]

let replace_messages (fields : (string * Jsonx.t) list)
    (values : Jsonx.t list) : Jsonx.t =
  Jsonx.Jobj (List.map
    (fun ((name : string), (value : Jsonx.t)) ->
      if String.equal name "messages" then name, Jsonx.Jlist values
      else name, value) fields)

(* Each ciphertext contributes exactly twice (plaintext length + 93)
   bytes to an already quoted empty string. Hex needs no JSON escapes.
   The bounded accumulator cannot overflow even for a huge message list. *)
let check_length (plan : repr) : (unit, Errx.t) result =
  let empty_messages = List.map
    (fun (m : message) -> wire_message m.role "") plan.messages in
  let base = String.length (Jsonx.emit (replace_messages plan.fields empty_messages)) in
  if base > max_body () then invalid "encrypted body length"
  else Result.map (fun (_ : int) -> ())
    (List.fold_left
      (fun acc (m : message) ->
        let* used = acc in
        let added = 2 * (String.length m.plaintext + frame_overhead ()) in
        if added > max_body () - used then invalid "encrypted body length"
        else Ok (used + added)) (Ok base) plan.messages)

let prepare ~(model_id : string) (chat : 'c Chatx.t) :
    ('c plan, Errx.t) result =
  let* original = object_fields "request shape" (Chatx.to_json ~stream:true chat) in
  let* actual_model = string_member "model mismatch" "model" original in
  if not (String.equal model_id actual_model) then invalid "model mismatch"
  else
    let* () = check_members original in
    let* messages = messages original in
    let* venice = venice_fields original in
    let fields = List.map
      (fun ((name : string), (value : Jsonx.t)) ->
        if String.equal name "messages" then name, Jsonx.Jlist []
        else name, value)
      (List.filter
        (fun ((name : string), (_ : Jsonx.t)) ->
          not (String.equal name "venice_parameters")) original)
      @ [ "venice_parameters", Jsonx.Jobj venice ] in
    let plan = { fields; messages } in
    let* () = check_length plan in
    Ok plan

let plaintexts (plan : 'c plan) : string list =
  List.map (fun (m : message) -> m.plaintext) plan.messages

let rec encrypted_messages (messages : message list)
    (ciphertexts : Ciphertext.t list) (acc : Jsonx.t list) :
    (Jsonx.t list, Errx.t) result =
  match messages, ciphertexts with
  | [], [] -> Ok (List.rev acc)
  | m :: rest, ciphertext :: tail ->
    encrypted_messages rest tail
      (wire_message m.role (Ciphertext.to_hex ciphertext) :: acc)
  | [], _ :: _ | _ :: _, [] -> invalid "ciphertext count"

let finish ~(client_pubkey_hex : string) ~(model_pubkey_hex : string)
    (plan : 'c plan) (ciphertexts : Ciphertext.t list) :
    (Httpx.Request.t, Errx.t) result =
  let* values = encrypted_messages plan.messages ciphertexts [] in
  Httpx.Request.post Httpx.Route.chat_completions
    ~headers:[ "X-Venice-TEE-Client-Pub-Key", client_pubkey_hex;
      "X-Venice-TEE-Model-Pub-Key", model_pubkey_hex;
      "X-Venice-TEE-Signing-Algo", "ecdsa" ]
    ~body:(replace_messages plan.fields values)
