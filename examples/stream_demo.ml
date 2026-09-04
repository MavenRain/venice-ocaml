(* M15 streaming demo, over the client session layer.

   The build compiles this file on every gate run, so the public
   surface stays callable. The gate never RUNS it: it needs an API key
   and a network. Run it by hand with VENICE_API_KEY set:

     dune exec examples/stream_demo.exe

   The flow uses the PUBLIC surface only. It reads the model listing
   filtered to text models, picks one small model, sends one streaming
   chat request through Client.chat_stream, and prints each content
   delta as it arrives. One consumer per run: the cursor is consumed
   by the iter below, so a second pass over Stream.collect is
   impossible and is not attempted.

   M15 replaced the hand-rolled status branch of the M14 demo. The
   client owns the send, the media-type check, the body close and the
   bounded retry, so this file holds no HTTP status test at all. It
   prints the attempt count, which is the number of obstacles the
   client rode over before the answer it returns. *)

open Venice

let ( let* ) = Result.bind

let fail (r : ('a, Error.t) result) : ('a, string) result =
  Result.map_error Error.to_string r

let preferred : string list =
  [ "qwen3-4b"; "llama-3.2-3b"; "qwen-2.5-qwq-32b"; "venice-uncensored" ]

let is_preferred : Model.packed -> bool = function
  | Model.Pack m -> List.exists (String.equal (Model.id m)) preferred

(* Prefer a small published model, else take the first row the listing
   offers. The listing is already filtered to text models by the
   query, so no kind test is needed here. *)
let pick (rows : Model.packed list) : (Model.packed, string) result =
  Option.fold
    ~none:(Error "the listing offers no text model")
    ~some:(fun (p : Model.packed) -> Ok p)
    (Option.fold
       ~none:(List.nth_opt rows 0)
       ~some:(fun (p : Model.packed) -> Some p)
       (List.find_opt is_preferred rows))

let outcome_text (o : Stream.outcome) : string =
  match o with
  | Stream.Complete -> "complete"
  | Stream.Cut -> "cut"
  | Stream.Failed e -> "failed: " ^ Error.to_string e

let stop_text (s : Client.Stop.t) : string =
  match s with
  | Client.Stop.Not_retryable -> "not retryable"
  | Client.Stop.Attempts_exhausted -> "attempts exhausted"
  | Client.Stop.Hint_over_cap d ->
    "the server asked for " ^ string_of_int (Delay.ms d)
    ^ " ms, above the per-wait cap"
  | Client.Stop.Budget_exhausted d ->
    "the next wait of " ^ string_of_int (Delay.ms d)
    ^ " ms is over the total budget"

let failure_text (f : Head.failure) : string =
  match f with
  | Head.Rate_limited { head = _; head_error = _; body = _; raw = _ } ->
    "429 rate limited"
  | Head.Client { status; head = _; head_error = _; body = _; raw = _ } ->
    string_of_int status ^ " client fault"
  | Head.Server { status; head = _; head_error = _; body = _; raw = _ } ->
    string_of_int status ^ " server fault"
  | Head.Unexpected_status { status; head = _; head_error = _; raw = _ } ->
    string_of_int status ^ " unexpected status"

(* The ledger reads as one line per attempt the client rode over. It
   carries no body and no key byte, so printing it is safe. *)
let attempt_text (a : Client.Attempt.t) : string =
  let waited = string_of_int (Delay.ms (Client.Attempt.slept a)) in
  match Client.Attempt.obstacle a with
  | Client.Obstacle.Rate_limited hint ->
    "rate limited, hint "
    ^ Option.fold ~none:"none"
        ~some:(fun (d : Delay.t) -> string_of_int (Delay.ms d) ^ " ms")
        hint
    ^ ", waited " ^ waited ^ " ms"
  | Client.Obstacle.Gateway status ->
    "gateway " ^ string_of_int status ^ ", waited " ^ waited ^ " ms"
  | Client.Obstacle.Unreachable why ->
    "unreachable (" ^ why ^ "), waited " ^ waited ^ " ms"

let client_error_text (e : Client.error) : string =
  match e with
  | Client.Http { failure; attempts; stop } ->
    failure_text failure ^ " after " ^ string_of_int (List.length attempts)
    ^ " attempt(s), stopped because " ^ stop_text stop
  | Client.Failed { error; attempts; stop } ->
    Error.to_string error ^ " after "
    ^ string_of_int (List.length attempts)
    ^ " attempt(s), stopped because " ^ stop_text stop

let served (r : ('a Client.reply, Client.error) result) : ('a, string) result =
  Result.map_error client_error_text
    (Result.map (fun (rep : 'a Client.reply) -> rep.value) r)

(* One chunk on the wire, printed the moment it arrives. *)
let print_delta (x : Sse.Chunk.t) : unit =
  List.iter
    (fun (c : Sse.Chunk.Choice.t) ->
      Option.iter print_string
        (Sse.Chunk.Delta.content (Sse.Chunk.Choice.delta c)))
    (Sse.Chunk.choices x);
  flush stdout

(* The client over the shipped transport and the real wall clock. The
   demo is the ONE place in the repo that builds a Clock.System: every
   test drives Clock.Fake, so no suite ever sleeps. *)
module Session = Client.Make (Transport.Curl) (Clock.System)

let converse (c : Session.t) (p : Model.packed) : (unit, string) result =
  match p with
  | Model.Pack m ->
    let* msg = fail (Msg.user_text "Say hello in five words.") in
    let* msgs = fail (Msg.nonempty [ msg ]) in
    let* chat = fail (Chat.make m msgs ()) in
    let (answer : ((unit * Stream.outcome) Client.reply, Client.error) result)
        =
      Session.chat_stream c chat (fun (cur : Stream.cursor) ->
          Stream.iter cur print_delta)
    in
    Result.fold
      ~ok:(fun (rep : (unit * Stream.outcome) Client.reply) ->
        let (((() : unit)), (o : Stream.outcome)) = rep.value in
        print_newline ();
        print_endline ("model: " ^ Model.id m);
        print_endline ("outcome: " ^ outcome_text o);
        print_endline
          ("attempts before the answer: "
           ^ string_of_int (List.length rep.attempts));
        List.iter
          (fun (a : Client.Attempt.t) ->
            print_endline ("  retried: " ^ attempt_text a))
          rep.attempts;
        Ok ())
      ~error:(fun (e : Client.error) -> Error (client_error_text e))
      answer

let demo (() : unit) : (unit, string) result =
  let* key = fail (Api_key.from_env ()) in
  let* transport = fail (Transport.Curl.make ()) in
  let* c =
    fail
      (Session.make ~key ~transport ~clock:(Clock.System.make ()) ())
  in
  let* rows =
    served (Session.models ~filter:(Model_filter.Kind Model.Text) c)
  in
  let* p = pick rows in
  converse c p

let () =
  Result.fold
    ~ok:(fun (() : unit) -> ())
    ~error:(fun (m : string) ->
      prerr_endline ("stream_demo: " ^ m);
      exit 1)
    (demo ())
