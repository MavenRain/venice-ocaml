(* M14 direct-style streaming demo.

   The build compiles this file on every gate run, so the public
   surface stays callable. The gate never RUNS it: it needs an API key
   and a network. Run it by hand with VENICE_API_KEY set:

     dune exec examples/stream_demo.exe

   The flow uses the PUBLIC surface only. It reads the model listing,
   picks one small text model, sends one streaming chat request, and
   prints each content delta as it arrives. One consumer per run: the
   cursor is consumed by the iter below, so a second pass over
   Stream.collect is impossible and is not attempted. *)

open Venice

let ( let* ) = Result.bind

let fail (r : ('a, Error.t) result) : ('a, string) result =
  Result.map_error Error.to_string r

let preferred : string list =
  [ "qwen3-4b"; "llama-3.2-3b"; "qwen-2.5-qwq-32b"; "venice-uncensored" ]

let is_text : Model.packed -> bool = function
  | Model.Pack m ->
    (match Model.kind m with
     | Model.Text -> true
     | Model.Code -> false
     | Model.Image -> false
     | Model.Embedding -> false
     | Model.Tts -> false
     | Model.Asr -> false
     | Model.Music -> false
     | Model.Upscale -> false
     | Model.Inpaint -> false
     | Model.Video -> false)

let is_preferred : Model.packed -> bool = function
  | Model.Pack m -> List.exists (String.equal (Model.id m)) preferred

(* Prefer a small published model, else take the first text model the
   listing offers. *)
let pick (rows : Model.packed list) : (Model.packed, string) result =
  let (texts : Model.packed list) = List.filter is_text rows in
  Option.fold
    ~none:(Error "the listing offers no text model")
    ~some:(fun (p : Model.packed) -> Ok p)
    (Option.fold
       ~none:(List.nth_opt texts 0)
       ~some:(fun (p : Model.packed) -> Some p)
       (List.find_opt is_preferred texts))

let outcome_text (o : Stream.outcome) : string =
  match o with
  | Stream.Complete -> "complete"
  | Stream.Cut -> "cut"
  | Stream.Failed e -> "failed: " ^ Error.to_string e

(* One chunk on the wire, printed the moment it arrives. *)
let print_delta (x : Sse.Chunk.t) : unit =
  List.iter
    (fun (c : Sse.Chunk.Choice.t) ->
      Option.iter print_string
        (Sse.Chunk.Delta.content (Sse.Chunk.Choice.delta c)))
    (Sse.Chunk.choices x);
  flush stdout

let read_body (b : Transport.Curl.body) : (string, string) result =
  let* text = fail (Transport.Curl.read_all b) in
  let* (() : unit) = fail (Transport.Curl.close b) in
  Ok text

let listing (c : Transport.Curl.t) ~(key : Api_key.t) :
    (Model.packed list, string) result =
  let* req = fail (Http.Request.get Http.Route.models) in
  let* ((head : Http.Wire.head), (body : Transport.Curl.body)) =
    fail (Transport.Curl.send c ~key req)
  in
  let* text = read_body body in
  match () with
  | () when Int.equal head.status 200 ->
    let* j = fail (Json.parse text) in
    fail (Model.of_listing j)
  | () ->
    Error ("GET /models answered " ^ string_of_int head.status ^ ": " ^ text)

(* The streaming call. stream:true asks for SSE and include_usage:true
   asks for the usage-only final chunk (D10). *)
let converse (c : Transport.Curl.t) ~(key : Api_key.t) (p : Model.packed) :
    (unit, string) result =
  match p with
  | Model.Pack m ->
    let* msg = fail (Msg.user_text "Say hello in five words.") in
    let* msgs = fail (Msg.nonempty [ msg ]) in
    let* chat = fail (Chat.make m msgs ()) in
    let* req =
      fail
        (Http.Request.post Http.Route.chat_completions
           ~body:(Chat.to_json ~stream:true ~include_usage:true chat))
    in
    let* ((head : Http.Wire.head), (body : Transport.Curl.body)) =
      fail (Transport.Curl.send c ~key req)
    in
    (match () with
     | () when Int.equal head.status 200 ->
       let module Drive = Stream.Make (Transport.Curl) in
       let (pair : unit * Stream.outcome) =
         Drive.run body (fun (cur : Stream.cursor) ->
             Stream.iter cur print_delta)
       in
       let (((() : unit)), (o : Stream.outcome)) = pair in
       print_newline ();
       print_endline ("model: " ^ Model.id m);
       print_endline ("outcome: " ^ outcome_text o);
       Ok ()
     | () ->
       let* text = read_body body in
       Error
         ("POST /chat/completions answered "
          ^ string_of_int head.status
          ^ ": " ^ text))

let demo (() : unit) : (unit, string) result =
  let* key = fail (Api_key.from_env ()) in
  let* c = fail (Transport.Curl.make ()) in
  let* rows = listing c ~key in
  let* p = pick rows in
  converse c ~key p

let () =
  Result.fold
    ~ok:(fun (() : unit) -> ())
    ~error:(fun (m : string) ->
      prerr_endline ("stream_demo: " ^ m);
      exit 1)
    (demo ())
