(* M32 pure response decoding. Authentication precedes plaintext parsing. *)
let ( let* ) = Result.bind
let fail word = Error (Errx.Session_invalid word)
let require word value = Option.to_result ~none:(Errx.Session_invalid word) value

let max_frame_hex () = 4_000_186

let frame ~(scalar : Secpx.Scalar.t) (hex : string) : (string, Errx.t) result =
  if String.length hex > max_frame_hex () then fail "response frame length"
  else
    let* bytes = Result.map_error
      (fun (_ : Errx.t) -> Errx.Session_invalid "response frame hex") (Hexx.decode hex) in
    let length = String.length bytes in
    if length < 93 then fail "response frame length"
    else
      let* public = require "response public key" (Bytesx.take bytes 0 65) in
      let* peer = require "response public key" (Secpx.Pubkey.of_bytes public) in
      let* iv = require "response nonce" (Bytesx.take bytes 65 12) in
      let* nonce = require "response nonce" (Gcmx.Nonce.of_bytes iv) in
      let* ciphertext = require "response frame length" (Bytesx.take bytes 77 (length - 93)) in
      let* mac = require "response tag" (Bytesx.take bytes (length - 16) 16) in
      let* tag = require "response tag" (Gcmx.Tag.of_bytes mac) in
      let* key = Sessx.derive_key ~scalar ~peer in
      require "response authentication" (Gcmx.unseal key nonce ~aad:"" ciphertext tag)

let traverse f values =
  Result.map List.rev (List.fold_left (fun acc value ->
    let* reversed = acc in
    let* mapped = f value in
    Ok (mapped :: reversed)) (Ok []) values)

let delta_member ~scalar (name, value) =
  match name, value with
  | ("content" | "reasoning_content"), Jsonx.Jnull -> Ok (name, value)
  | ("content" | "reasoning_content"), Jsonx.Jstring "" -> Ok (name, value)
  | ("content" | "reasoning_content"), Jsonx.Jstring hex ->
    let* plaintext = frame ~scalar hex in
    Ok (name, Jsonx.Jstring plaintext)
  | "role", Jsonx.Jstring (_ : string) -> Ok (name, value)
  | (_ : string), (_ : Jsonx.t) -> fail "response delta"

let choice ~scalar value =
  let* fields = require "response choice" (Jsonx.as_obj value) in
  let* mapped = traverse (fun (name, value) ->
    if String.equal name "delta" then
      let* fields = require "response delta" (Jsonx.as_obj value) in
      let* fields = traverse (delta_member ~scalar) fields in
      Ok (name, Jsonx.Jobj fields)
    else Ok (name, value)) fields in
  Ok (Jsonx.Jobj mapped)

type identity = { id : string; created : int }
type t = { scalar : Secpx.Scalar.t; model_id : string; previous : identity option }
let make ~scalar ~model_id = { scalar; model_id; previous = None }

let step state payload =
  (* Do not include untrusted payload bytes in errors at this boundary. *)
  let* json = Result.map_error
    (fun (_ : Errx.t) -> Errx.Session_invalid "response json") (Jsonx.parse payload) in
  let* fields = require "response shape" (Jsonx.as_obj json) in
  let* model = require "response model" (Option.bind (List.assoc_opt "model" fields) Jsonx.as_string) in
  if not (String.equal model state.model_id) then fail "response model"
  else
    let fields = Option.fold ~none:fields ~some:(fun previous ->
      List.fold_left (fun fields (name, value) ->
        if List.mem_assoc name fields then fields else (name, value) :: fields)
        fields ["object", Jsonx.Jstring "chat.completion.chunk";
          "created", Jsonx.Jint previous.created]) state.previous in
    let* fields = traverse (fun (name, value) ->
      if String.equal name "choices" then
        let* values = require "response choices" (Jsonx.as_list value) in
        let* values = traverse (choice ~scalar:state.scalar) values in
        Ok (name, Jsonx.Jlist values)
      else Ok (name, value)) fields in
    let* chunk = Result.map_error (fun (_ : Errx.t) -> Errx.Session_invalid "response chunk")
      (Ssex.Chunk.of_string (Jsonx.emit (Jsonx.Jobj fields))) in
    let identity = { id = Ssex.Chunk.id chunk; created = Ssex.Chunk.created chunk } in
    let matches = Option.fold ~none:true ~some:(fun previous ->
      String.equal previous.id identity.id && Int.equal previous.created identity.created)
      state.previous in
    if matches then Ok ({ state with previous = Some identity }, chunk)
    else fail "response identity"

let chunk ~scalar ~model_id payload =
  Result.map snd (step (make ~scalar ~model_id) payload)
