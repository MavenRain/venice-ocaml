(* Battery control: this file MUST compile against the built library,
   or the battery is vacuous (wrong include path, stale artifacts).
   It exercises the positive multimodal path and structure-level
   payload reuse through the PUBLIC surface only, which also locks the
   venice.mli boundary the runtime suite bypasses. *)

(* Unbranded payloads minted once, no type variable, shared across
   models. *)
let sys : (Venice.Msg.msg, Venice.Error.t) result =
  Venice.Msg.system "you are helpful"

let caption : (Venice.Msg.text_part, Venice.Error.t) result =
  Venice.Msg.text "describe this"

let request (p : Venice.Model.packed) ~(url : string) ~(data : string) :
    (Venice.Json.t, Venice.Error.t) result option =
  match p with
  | Venice.Model.Pack m ->
    let media = Venice.Model.media m in
    Option.bind media.Venice.Model.vision (fun vm ->
        Option.map
          (fun am ->
            Result.bind sys (fun s ->
                Result.bind caption (fun c ->
                    Result.bind (Venice.Msg.image vm ~url) (fun i ->
                        Result.bind (Venice.Msg.audio am ~data) (fun a ->
                            Result.bind
                              (Venice.Msg.user
                                 [ i; a; Venice.Msg.of_text c ])
                              (fun u ->
                                Result.map
                                  (fun ((_ : _ Venice.Msg.nonempty)) ->
                                    Venice.Json.Jnull)
                                  (Venice.Msg.nonempty
                                     [ Venice.Msg.lift s; u ])))))))
          media.Venice.Model.audio)

(* The same structure-level payloads serve two distinct models. *)
let both (p : Venice.Model.packed) (q : Venice.Model.packed) :
    (Venice.Json.t, Venice.Error.t) result option list =
  [ request p ~url:"https://a/1.png" ~data:"aGVsbG8=";
    request q ~url:"https://b/2.png" ~data:"aGVsbG8=" ]

(* M9: a witnessed effort call on the SAME model row compiles; this is
   the positive twin of cf_f_effort_wrong_model.ml. *)
let chat (p : Venice.Model.packed) : (string, Venice.Error.t) result option
    =
  match p with
  | Venice.Model.Pack m ->
    Option.map
      (fun w ->
        Result.bind (Venice.Msg.user_text "hello") (fun u ->
            Result.bind (Venice.Msg.nonempty [ u ]) (fun msgs ->
                Result.map Venice.Chat.emit
                  (Venice.Chat.make m msgs
                     ~effort:(w, Venice.Effort.Low) ()))))
      (Venice.Model.reasoning_effort m)

(* M10a: witnessed tools + response_format on the SAME model row
   compile, with the tool_choice and parallel_tool_calls members
   along for the ride; the positive twin of cf_g and cf_h. *)
let tool_chat (p : Venice.Model.packed) :
    (string, Venice.Error.t) result option =
  match p with
  | Venice.Model.Pack m ->
    Option.bind (Venice.Model.tools m) (fun tw ->
        Option.map
          (fun rw ->
            Result.bind (Venice.Msg.user_text "hello") (fun u ->
                Result.bind (Venice.Msg.nonempty [ u ]) (fun msgs ->
                    Result.bind (Venice.Tool.function_ ~name:"f" ())
                      (fun t ->
                        Result.map Venice.Chat.emit
                          (Venice.Chat.make m msgs ~tools:(tw, [ t ])
                             ~tool_choice:(Venice.Chat.Tool_function "f")
                             ~parallel_tool_calls:false
                             ~response_format:
                               (Venice.Chat.Rf_json_schema
                                  (rw, Venice.Json.Jobj []))
                             ())))))
          (Venice.Model.response_schema m))

(* M10a: the public Tool_call mint feeds Msg.assistant ~tool_calls
   through the venice.mli boundary. *)
let replay : (Venice.Msg.msg, Venice.Error.t) result =
  Result.bind (Venice.Tool_call.make ~id:"c1" ~name:"f" ~arguments:"{}")
    (fun tc -> Venice.Msg.assistant ~tool_calls:[ tc ] ())

(* M13: the transport surface through the public boundary. Api_key
   mints, both request builders take their own route method, and the
   Fake transport answers a scripted exchange. *)
let key : (Venice.Api_key.t, Venice.Error.t) result =
  Venice.Api_key.make "sk-test-0123456789"

let listing : (Venice.Http.Request.t, Venice.Error.t) result =
  Venice.Http.Request.get ~query:[ ("model", "venice-uncensored") ]
    Venice.Http.Route.models

let completion : (Venice.Http.Request.t, Venice.Error.t) result =
  Venice.Http.Request.post
    ~headers:[ ("x-trace", "abc") ]
    Venice.Http.Route.chat_completions
    ~body:(Venice.Json.Jobj [ ("stream", Venice.Json.Jbool false) ])

let scripted : Venice.Transport.Fake.t =
  Venice.Transport.Fake.make
    [ Venice.Transport.Fake.exchange
        ~head:"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n"
        ~chunks:[ "{}" ] () ]

let round_trip : (string, Venice.Error.t) result =
  Result.bind key (fun (k : Venice.Api_key.t) ->
      Result.bind completion (fun (req : Venice.Http.Request.t) ->
          Result.bind (Venice.Transport.Fake.send scripted ~key:k req)
            (fun ((_ : Venice.Http.Wire.head), b) ->
              Result.bind (Venice.Transport.Fake.read_all b)
                (fun (body : string) ->
                  Result.map (fun (() : unit) -> body)
                    (Venice.Transport.Fake.close b)))))

let logged : string list =
  List.map Venice.Http.Request.to_log
    (Venice.Transport.Fake.requests scripted)

let base : string =
  Result.fold
    ~ok:(fun (r : Venice.Http.Request.t) ->
      Venice.Http.Request.url Venice.Http.Endpoint.default r)
    ~error:Venice.Error.to_string listing

(* M14: the streaming surface through the public boundary. Stream.Make
   applies to BOTH shipped transports, the cursor combinators read the
   published chunk type, and the accumulator folds chunks into a
   chat.completion document. This is a SURFACE control: an API break
   shows up here as a control failure instead of a false "rejected as
   expected". The drift guard is a separate thing and lives in
   lib/venice.ml (A6). *)
module Sf = Venice.Stream.Make (Venice.Transport.Fake)
module Sc = Venice.Stream.Make (Venice.Transport.Curl)

let streaming_request (p : Venice.Model.packed) :
    (Venice.Http.Request.t, Venice.Error.t) result =
  match p with
  | Venice.Model.Pack m ->
    Result.bind (Venice.Msg.user_text "hello") (fun u ->
        Result.bind (Venice.Msg.nonempty [ u ]) (fun msgs ->
            Result.bind (Venice.Chat.make m msgs ()) (fun c ->
                Venice.Http.Request.post Venice.Http.Route.chat_completions
                  ~body:
                    (Venice.Chat.to_json ~stream:true ~include_usage:true c))))

let stream_script : Venice.Transport.Fake.t =
  Venice.Transport.Fake.make
    [ Venice.Transport.Fake.exchange
        ~head:
          "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"
        ~chunks:[ "data: [DONE]\n\n" ] () ]

let streamed (p : Venice.Model.packed) :
    (int * Venice.Stream.outcome, Venice.Error.t) result =
  Result.bind key (fun (k : Venice.Api_key.t) ->
      Result.bind (streaming_request p) (fun (req : Venice.Http.Request.t) ->
          Result.map
            (fun (((_ : Venice.Http.Wire.head), b)) ->
              Sf.run b (fun (cur : Venice.Stream.cursor) ->
                  Venice.Stream.fold cur ~init:0
                    ~f:(fun (n : int) ((_ : Venice.Sse.Chunk.t)) -> n + 1)))
            (Venice.Transport.Fake.send stream_script ~key:k req)))

(* The curl functor application is a type-level control only: nothing
   here opens a subprocess. *)
let curl_run (t : Venice.Transport.Curl.t) (b : Venice.Transport.Curl.body) :
    (Venice.Sse.Acc.final, Venice.Error.t) result * Venice.Stream.outcome =
  let (_ : Venice.Transport.Curl.t) = t in
  Sc.run b Venice.Stream.collect

(* The accumulator through the public boundary: one chunk in, one
   chat.completion document out, read by the non-streaming parser. *)
let accumulate (c : Venice.Sse.Chunk.t) :
    (Venice.Response.t, Venice.Error.t) result =
  Result.bind (Venice.Sse.Acc.step Venice.Sse.Acc.empty c)
    (fun (a : Venice.Sse.Acc.t) ->
      Result.bind (Venice.Sse.Acc.finish a) Venice.Sse.Acc.to_response)

let accumulated_choices (f : Venice.Sse.Acc.final) : string list =
  List.map
    (fun (c : Venice.Sse.Acc.Choice.t) -> Venice.Sse.Acc.Choice.finish_raw c)
    (Venice.Sse.Acc.choices f)

(* M15 control: the client functor applies over the scripted transport
   and the scripted clock, the policy window mints a t, and a Delay is
   READ off an Attempt. Nothing here sends a request. *)
module Cf = Venice.Client.Make (Venice.Transport.Fake) (Venice.Clock.Fake)

let client (k : Venice.Api_key.t) (t : Venice.Transport.Fake.t) :
    (Cf.t, Venice.Error.t) result =
  Cf.make ~key:k ~policy:Venice.Client.Policy.default ~transport:t
    ~clock:(Venice.Clock.Fake.make ()) ()

let tighter (() : unit) : (Venice.Client.Policy.t, Venice.Error.t) result =
  Venice.Client.Policy.make ~max_attempts:2 ~base_ms:250 ()

let waited (a : Venice.Client.Attempt.t) : int =
  Venice.Delay.ms (Venice.Client.Attempt.slept a)

let filtered (c : Cf.t) :
    (Venice.Model.packed list Venice.Client.reply, Venice.Client.error) result
    =
  Cf.models ~filter:(Venice.Model_filter.Kind Venice.Model.Text) c
