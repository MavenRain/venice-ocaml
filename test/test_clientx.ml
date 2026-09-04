(* M15 clientx: the session layer end to end over the scripted
   transport and the scripted clock. No process runs and no real sleep
   is taken, so the suite needs no watchdog (A14) and no test ever
   builds a Clock.System.

   Every scenario drives its OWN script, its OWN clock and its OWN
   client. A Fake body is stateful and OCaml evaluates list elements
   right to left, so a shared script would be consumed by the later
   check first; each scenario is a top-level let that runs once, in
   source order, and the check list only reads the recorded values.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal modules by their mangled names, exactly as
   test_streamx does. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module Cl = Venice__Clientx
module Rx = Venice__Retryx
module Ck = Venice__Clockx
module F = Venice__Fakex
module E = Venice__Errx
module K = Venice__Keyx
module H = Venice__Headx
module Hx = Venice__Httpx
module M = Venice__Modelx
module Ch = Venice__Chatx
module Mg = Venice__Msgx
module Rp = Venice__Respx
module St = Venice__Streamx
module S = Venice__Ssex
module J = Venice__Jsonx

(* The close and read counters. The client owns the body, so the only
   way to pin "closed exactly once" on every branch is to wrap the
   scripted transport, exactly as test_streamx wraps it for the
   re-entrancy probe. *)
let n_closes : int ref = ref 0
let n_reads : int ref = ref 0

module Probe = struct
  include F

  let read (b : body) : (string option, E.t) result =
    n_reads := !n_reads + 1;
    F.read b

  let close (b : body) : (unit, E.t) result =
    n_closes := !n_closes + 1;
    F.close b
end

module C = Cl.Make (Probe) (Ck.Fake)

(* ---------- the key (D11) ---------- *)

let key_text : string = "sk-DISTINCTIVE-KEY-9f8e7d6c5b4a3210"
let key_result : (K.t, E.t) result = K.make key_text

(* ---------- renderers ---------- *)

let dopt (d : Rx.Delay.t option) : string =
  Option.fold ~none:"none"
    ~some:(fun (x : Rx.Delay.t) -> string_of_int (Rx.Delay.ms x))
    d

let obstacle_text (o : Rx.Obstacle.t) : string =
  match o with
  | Rx.Obstacle.Rate_limited h -> "rate_limited " ^ dopt h
  | Rx.Obstacle.Gateway n -> "gateway " ^ string_of_int n
  | Rx.Obstacle.Unreachable s -> "unreachable " ^ s

let ladder_row (a : Rx.Attempt.t) : string =
  obstacle_text (Rx.Attempt.obstacle a)
  ^ " slept " ^ string_of_int (Rx.Delay.ms (Rx.Attempt.slept a))

let stop_text (s : Rx.Stop.t) : string =
  match s with
  | Rx.Stop.Not_retryable -> "not_retryable"
  | Rx.Stop.Attempts_exhausted -> "attempts_exhausted"
  | Rx.Stop.Hint_over_cap d -> "hint_over_cap " ^ string_of_int (Rx.Delay.ms d)
  | Rx.Stop.Budget_exhausted d ->
    "budget_exhausted " ^ string_of_int (Rx.Delay.ms d)

let failure_text (f : H.failure) : string =
  match f with
  | H.Rate_limited { head = _; head_error = _; body = _; raw = _ } ->
    "rate_limited"
  | H.Server { status; head = _; head_error = _; body = _; raw = _ } ->
    "server " ^ string_of_int status
  | H.Client { status; head = _; head_error = _; body = _; raw = _ } ->
    "client " ^ string_of_int status
  | H.Unexpected_status { status; head = _; head_error = _; raw = _ } ->
    "unexpected " ^ string_of_int status

let error_text (e : Cl.error) : string =
  match e with
  | Cl.Http { failure; attempts = _; stop = _ } ->
    "http " ^ failure_text failure
  | Cl.Failed { error; attempts = _; stop = _ } ->
    "failed " ^ E.to_string error

let attempts_of (e : Cl.error) : Rx.Attempt.t list =
  match e with
  | Cl.Http { failure = _; attempts; stop = _ } -> attempts
  | Cl.Failed { error = _; attempts; stop = _ } -> attempts

let stop_of (e : Cl.error) : Rx.Stop.t =
  match e with
  | Cl.Http { failure = _; attempts = _; stop } -> stop
  | Cl.Failed { error = _; attempts = _; stop } -> stop

let head_text (h : (H.t, E.t) result) : string =
  Result.fold ~ok:(fun (_ : H.t) -> "ok") ~error:(fun (_ : E.t) -> "error") h

type answer =
  { a_text : string; a_head : string; a_ladder : string list; a_stop : string }

let answer_of (render : 'v -> string) (r : ('v Cl.reply, Cl.error) result) :
    answer =
  Result.fold
    ~ok:(fun (rep : 'v Cl.reply) ->
      { a_text = "ok " ^ render rep.Cl.value;
        a_head = head_text rep.Cl.head;
        a_ladder = List.map ladder_row rep.Cl.attempts;
        a_stop = "none" })
    ~error:(fun (e : Cl.error) ->
      { a_text = error_text e;
        a_head = "none";
        a_ladder = List.map ladder_row (attempts_of e);
        a_stop = stop_text (stop_of e) })
    r

(* ---------- fixtures ---------- *)

let now (() : unit) : int = 1_700_000_000

let head_bytes ~(status : int) ~(reason : string)
    (pairs : (string * string) list) : string =
  "HTTP/1.1 " ^ string_of_int status ^ " " ^ reason ^ "\r\n"
  ^ String.concat ""
      (List.map
         (fun ((n : string), (v : string)) -> n ^ ": " ^ v ^ "\r\n")
         pairs)
  ^ "\r\n"

let json_head (status : int) (reason : string) : string =
  head_bytes ~status ~reason [ ("content-type", "application/json") ]

let ok_head : string = json_head 200 "OK"

let sse_head : string =
  head_bytes ~status:200 ~reason:"OK"
    [ ("content-type", "text/event-stream") ]

let requests_triple ~(remaining : int) ~(reset : int) :
    (string * string) list =
  [ ("x-ratelimit-limit-requests", "100");
    ("x-ratelimit-remaining-requests", string_of_int remaining);
    ("x-ratelimit-reset-requests", string_of_int reset) ]

let tokens_triple ~(remaining : int) ~(reset : string) :
    (string * string) list =
  [ ("x-ratelimit-limit-tokens", "100000");
    ("x-ratelimit-remaining-tokens", string_of_int remaining);
    ("x-ratelimit-reset-tokens", reset) ]

(* A8: every scripted 429 carries FULL triples, so Head.of_pairs is Ok
   and the hint comes from the exhausted triple. *)
let rate_head ?(extra : (string * string) list = [])
    ~(requests_remaining : int) ~(reset : int) ~(tokens_remaining : int)
    ~(tokens_reset : string) (() : unit) : string =
  head_bytes ~status:429 ~reason:"Too Many Requests"
    (List.concat
       [ [ ("content-type", "application/json") ];
         requests_triple ~remaining:requests_remaining ~reset;
         tokens_triple ~remaining:tokens_remaining ~reset:tokens_reset;
         extra ])

let completion : string =
  {|{"id":"c1","object":"chat.completion","created":7,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}|}

let listing : string =
  {|{"object":"list","data":[{"id":"m1","type":"text"},{"id":"flux-dev","type":"image"}]}|}

let error_body : string = {|{"error":"nope"}|}

let chunk1 : string =
  {|{"id":"c1","object":"chat.completion.chunk","created":7,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}|}

let chunk2 : string =
  {|{"id":"c1","object":"chat.completion.chunk","created":7,"model":"m","choices":[{"index":0,"delta":{"content":"lo"}}]}|}

let ev (payload : string) : string = "data: " ^ payload ^ "\n\n"
let stream_body : string = ev chunk1 ^ ev chunk2 ^ "data: [DONE]\n\n"
let answer (head : string) (body : string) : F.exchange =
  F.exchange ~head ~chunks:[ body ] ()

let answer_closing (head : string) (body : string) (close_error : string) :
    F.exchange =
  F.exchange ~head ~chunks:[ body ] ~close_error ()

(* ---------- the chat fixture ---------- *)

type any_chat = Any : 'c Ch.t -> any_chat

let text_model : M.packed option =
  Result.to_option
    (Result.bind (J.parse {|{"id":"m1","type":"text"}|}) M.of_json)

let any_chat : any_chat option =
  Option.bind text_model (fun (p : M.packed) ->
      match p with
      | M.Pack m ->
        Option.map
          (fun (c : _ Ch.t) -> Any c)
          (Result.to_option
             (Result.bind (Mg.user_text "hello") (fun (u : _ Mg.t) ->
                  Result.bind (Mg.nonempty [ u ])
                    (fun (msgs : _ Mg.nonempty) -> Ch.make m msgs ())))))

let no_fixture : Cl.error =
  Cl.Failed
    { error = E.Chat_invalid "test fixture missing";
      attempts = [];
      stop = Rx.Stop.Not_retryable }

let chat_call (cl : C.t) : (Rp.t Cl.reply, Cl.error) result =
  Option.fold ~none:(Error no_fixture)
    ~some:(fun (Any ch) -> C.chat cl ch)
    any_chat

let stream_call (consume : St.cursor -> 'a) (cl : C.t) :
    (('a * St.outcome) Cl.reply, Cl.error) result =
  Option.fold ~none:(Error no_fixture)
    ~some:(fun (Any ch) -> C.chat_stream cl ch consume)
    any_chat

let count_all (c : St.cursor) : int =
  St.fold c ~init:0 ~f:(fun (n : int) (_ : S.Chunk.t) -> n + 1)

let count_one (c : St.cursor) : int =
  Option.fold ~none:0 ~some:(fun (_ : S.Chunk.t) -> 1) (St.next c)

let outcome_text (o : St.outcome) : string =
  match o with
  | St.Complete -> "complete"
  | St.Cut -> "cut"
  | St.Failed e -> "failed " ^ E.to_string e

let stream_render ((n : int), (o : St.outcome)) : string =
  string_of_int n ^ "/" ^ outcome_text o

let resp_render (r : Rp.t) : string = Rp.id r
let models_render (ps : M.packed list) : string =
  string_of_int (List.length ps)

(* ---------- the scenario runner ---------- *)

type obs =
  { o_text : string;
    o_head : string;
    o_ladder : string list;
    o_stop : string;
    o_slept : int list;
    o_reqs : Hx.Request.t list;
    o_closes : int;
    o_reads : int }

let broken (text : string) : obs =
  { o_text = text;
    o_head = "none";
    o_ladder = [];
    o_stop = "none";
    o_slept = [];
    o_reqs = [];
    o_closes = 0;
    o_reads = 0 }

let scenario ?(policy : Rx.Policy.t = Rx.Policy.default)
    ?(max_body : int = 16_777_216) (script : F.exchange list)
    (call : C.t -> answer) : obs =
  n_reads := 0;
  n_closes := 0;
  let t = F.make script in
  let clock = Ck.Fake.make ~now:(now ()) () in
  Result.fold
    ~ok:(fun (k : K.t) ->
      Result.fold
        ~ok:(fun (cl : C.t) ->
          let a = call cl in
          { o_text = a.a_text;
            o_head = a.a_head;
            o_ladder = a.a_ladder;
            o_stop = a.a_stop;
            o_slept = List.map Rx.Delay.ms (Ck.Fake.slept clock);
            o_reqs = F.requests t;
            o_closes = !n_closes;
            o_reads = !n_reads })
        ~error:(fun (e : E.t) -> broken ("failed " ^ E.to_string e))
        (C.make ~key:k ~policy ~max_body ~transport:t ~clock ()))
    ~error:(fun (e : E.t) -> broken ("failed " ^ E.to_string e))
    key_result

let chat_scenario ?(policy : Rx.Policy.t = Rx.Policy.default)
    ?(max_body : int = 16_777_216) (script : F.exchange list) : obs =
  scenario ~policy ~max_body script (fun (cl : C.t) ->
      answer_of resp_render (chat_call cl))

let bodies (o : obs) : string list =
  List.map
    (fun (r : Hx.Request.t) ->
      Option.value ~default:"<none>" (Hx.Request.rendered r))
    o.o_reqs

let queries (o : obs) : (string * string) list list =
  List.map Hx.Request.query o.o_reqs

let identical (o : obs) : bool =
  match bodies o with
  | [] -> false
  | first :: rest ->
    List.for_all (fun (b : string) -> String.equal b first) rest
    && Int.equal (List.length rest) 1

(* ---------- scenarios, in evaluation order ---------- *)

let s_ok : obs = chat_scenario [ answer ok_head completion ]

let s_ok_bad_head : obs =
  chat_scenario
    [ answer
        (head_bytes ~status:200 ~reason:"OK"
           [ ("content-type", "application/json");
             ("x-ratelimit-remaining-requests", "0") ])
        completion ]

let s_429_requests : obs =
  chat_scenario
    [ answer
        (rate_head ~requests_remaining:0 ~reset:(now () + 2)
           ~tokens_remaining:50 ~tokens_reset:"9" ())
        error_body;
      answer ok_head completion ]

let s_429_tokens : obs =
  chat_scenario
    [ answer
        (rate_head ~requests_remaining:9 ~reset:(now () + 30)
           ~tokens_remaining:0 ~tokens_reset:"1.5" ())
        error_body;
      answer ok_head completion ]

let s_429_both : obs =
  chat_scenario
    [ answer
        (rate_head ~requests_remaining:0 ~reset:(now () + 2)
           ~tokens_remaining:0 ~tokens_reset:"5" ())
        error_body;
      answer ok_head completion ]

let s_429_over_cap : obs =
  chat_scenario
    [ answer
        (rate_head ~requests_remaining:0 ~reset:(now () + 45)
           ~tokens_remaining:9 ~tokens_reset:"1" ())
        error_body ]

let s_429_no_hint : obs =
  chat_scenario
    [ answer
        (rate_head ~requests_remaining:9 ~reset:(now () + 2)
           ~tokens_remaining:9 ~tokens_reset:"1" ())
        error_body;
      answer ok_head completion ]

let s_429_retry_after : obs =
  chat_scenario
    [ answer
        (rate_head ~requests_remaining:9 ~reset:(now () + 2)
           ~tokens_remaining:9 ~tokens_reset:"1"
           ~extra:[ ("retry-after", "3") ]
           ())
        error_body;
      answer ok_head completion ]

let s_429_half_triple : obs =
  chat_scenario
    [ answer
        (head_bytes ~status:429 ~reason:"Too Many Requests"
           [ ("content-type", "application/json");
             ("x-ratelimit-remaining-requests", "0") ])
        error_body;
      answer ok_head completion ]

let s_503_503_200 : obs =
  chat_scenario
    [ answer (json_head 503 "Service Unavailable") error_body;
      answer (json_head 503 "Service Unavailable") error_body;
      answer ok_head completion ]

let s_503_x3 : obs =
  chat_scenario
    [ answer (json_head 503 "Service Unavailable") error_body;
      answer (json_head 503 "Service Unavailable") error_body;
      answer (json_head 503 "Service Unavailable") error_body ]

let s_502 : obs =
  chat_scenario
    [ answer (json_head 502 "Bad Gateway") error_body;
      answer ok_head completion ]

let s_504 : obs =
  chat_scenario
    [ answer (json_head 504 "Gateway Timeout") error_body;
      answer ok_head completion ]

let s_500 : obs =
  chat_scenario
    [ answer (json_head 500 "Internal Server Error") error_body;
      answer ok_head completion ]

let s_400 : obs =
  chat_scenario
    [ answer (json_head 400 "Bad Request") error_body;
      answer ok_head completion ]

let s_unreachable : obs =
  chat_scenario
    [ F.refusal (E.Transport_unreachable "curl exit 6 (dns): no host");
      answer ok_head completion ]

let s_transport_failed : obs =
  chat_scenario
    [ F.refusal (E.Transport_failed "curl exit 28 (timeout)");
      answer ok_head completion ]

let s_html : obs =
  chat_scenario
    [ answer
        (head_bytes ~status:200 ~reason:"OK" [ ("content-type", "text/html") ])
        "<html/>" ]

let s_no_media : obs =
  chat_scenario [ answer (head_bytes ~status:200 ~reason:"OK" []) completion ]

let s_charset : obs =
  chat_scenario
    [ answer
        (head_bytes ~status:200 ~reason:"OK"
           [ ("content-type", "application/json; charset=utf-8") ])
        completion ]

let s_problem_json : obs =
  chat_scenario
    [ answer
        (head_bytes ~status:200 ~reason:"OK"
           [ ("content-type", "application/problem+json") ])
        completion ]

let s_close_error : obs =
  chat_scenario [ answer_closing ok_head completion "boom" ]

let s_over_body : obs =
  chat_scenario ~max_body:10 [ answer ok_head completion ]

let policy_none : Rx.Policy.t = Rx.Policy.none

let s_policy_none : obs =
  chat_scenario ~policy:policy_none
    [ answer (json_head 503 "Service Unavailable") error_body;
      answer ok_head completion ]

let budget_policy : Rx.Policy.t =
  Result.fold
    ~ok:(fun (p : Rx.Policy.t) -> p)
    ~error:(fun (_ : E.t) -> Rx.Policy.default)
    (Rx.Policy.make ~max_attempts:4 ~base_ms:1_000 ~max_delay_ms:1_000
       ~max_total_ms:1_500 ())

let s_budget : obs =
  chat_scenario ~policy:budget_policy
    [ answer (json_head 503 "Service Unavailable") error_body;
      answer (json_head 503 "Service Unavailable") error_body;
      answer (json_head 503 "Service Unavailable") error_body ]

(* A2: the status wins. A read that blows the error cap and a close
   that reports a failure must NOT erase the 503. *)
let huge_body : string = String.make 1_100_000 'x'

let s_big_error_body : obs =
  chat_scenario
    [ answer (json_head 503 "Service Unavailable") huge_body;
      answer ok_head completion ]

let s_error_close_error : obs =
  chat_scenario
    [ answer_closing (json_head 503 "Service Unavailable") error_body "boom";
      answer ok_head completion ]

(* ---------- models ---------- *)

let models_scenario ?(filter : M.Model_filter.t option)
    (script : F.exchange list) : obs =
  scenario script (fun (cl : C.t) ->
      answer_of models_render (C.models ?filter cl))

let s_models_default : obs = models_scenario [ answer ok_head listing ]

let s_models_all : obs =
  models_scenario ~filter:M.Model_filter.All [ answer ok_head listing ]

let s_models_kind : obs =
  models_scenario
    ~filter:(M.Model_filter.Kind M.Image)
    [ answer ok_head listing ]

let s_models_500 : obs =
  models_scenario
    [ answer (json_head 500 "Internal Server Error") error_body ]

(* ---------- chat_stream ---------- *)

let s_stream : obs =
  scenario
    [ answer sse_head stream_body ]
    (fun (cl : C.t) -> answer_of stream_render (stream_call count_all cl))

let s_stream_json : obs =
  scenario
    [ answer ok_head completion ]
    (fun (cl : C.t) -> answer_of stream_render (stream_call count_all cl))

let s_stream_html : obs =
  scenario
    [ answer
        (head_bytes ~status:200 ~reason:"OK" [ ("content-type", "text/html") ])
        "<html/>" ]
    (fun (cl : C.t) -> answer_of stream_render (stream_call count_all cl))

let s_stream_retry : obs =
  scenario
    [ answer
        (rate_head ~requests_remaining:0 ~reset:(now () + 2)
           ~tokens_remaining:9 ~tokens_reset:"1" ())
        error_body;
      answer sse_head stream_body ]
    (fun (cl : C.t) -> answer_of stream_render (stream_call count_all cl))

let s_stream_cut : obs =
  scenario
    [ answer sse_head stream_body ]
    (fun (cl : C.t) -> answer_of stream_render (stream_call count_one cl))

(* M16 (M15 verify residual 3, the READ half). The application/json
   refusal path reads the body BEFORE it refuses: chat_stream binds
   read_then_close, and read_then_close calls T.read_all. Fakex.read_all
   drives the Fakex read itself, so the test_streamx precedent that
   overrides read only would leave this path green and the row would
   observe Client_invalid. This fixture overrides read_all instead. The
   head is a 2xx application/json, the read FAILS and the close
   SUCCEEDS, so the Result.bind never reaches its continuation and the
   caller is told the TRANSPORT error, not the "server answered
   application/json, not a stream" text. The close half of the residual
   stays open and is named in the M16 residuals. *)
module Json_read_fail = struct
  include F

  let read_all ?cap:(_ : int option) (_ : body) : (string, E.t) result =
    Error (E.Transport_failed "read boom")
end

module Cjf = Cl.Make (Json_read_fail) (Ck.Fake)

let broken_answer (text : string) : answer =
  { a_text = text; a_head = "none"; a_ladder = []; a_stop = "none" }

let s_stream_json_read : answer =
  Result.fold
    ~ok:(fun (k : K.t) ->
      Result.fold
        ~ok:(fun (cl : Cjf.t) ->
          Option.fold ~none:(broken_answer "test fixture missing")
            ~some:(fun (Any ch) ->
              answer_of stream_render (Cjf.chat_stream cl ch count_all))
            any_chat)
        ~error:(fun (e : E.t) -> broken_answer ("failed " ^ E.to_string e))
        (Cjf.make ~key:k
           ~transport:(F.make [ answer ok_head completion ])
           ~clock:(Ck.Fake.make ~now:(now ()) ())
           ()))
    ~error:(fun (e : E.t) -> broken_answer ("failed " ^ E.to_string e))
    key_result

(* ---------- max_body window ---------- *)

let window_text (r : (C.t, E.t) result) : string =
  Result.fold ~ok:(fun (_ : C.t) -> "ok") ~error:E.to_string r

let client_with (max_body : int) : (C.t, E.t) result =
  Result.bind key_result (fun (k : K.t) ->
      C.make ~key:k ~max_body ~transport:(F.make [])
        ~clock:(Ck.Fake.make ()) ())

(* ---------- the checks ---------- *)

let happy_checks : (string * bool) list =
  [ ("clientx: the key fixture mints", Result.is_ok key_result);
    ("clientx: the chat fixture builds", Option.is_some any_chat);
    ("clientx: a 200 answers the parsed response",
      String.equal s_ok.o_text "ok c1" );
    ("clientx: a 200 head parses", String.equal s_ok.o_head "ok");
    ("clientx: a 200 needs no attempt", Int.equal (List.length s_ok.o_ladder) 0);
    ("clientx: a 200 sleeps not at all", Int.equal (List.length s_ok.o_slept) 0);
    ("clientx: a 200 sends one request", Int.equal (List.length s_ok.o_reqs) 1);
    ("clientx: a 200 closes the body exactly once", Int.equal s_ok.o_closes 1);
    ( "clientx: a POST carries the rendered body",
      match bodies s_ok with
      | [] -> false
      | b :: (_ : string list) -> String.length b > 0 );
    ( "clientx: the chat request is a POST to the completions route",
      match s_ok.o_reqs with
      | [] -> false
      | r :: (_ : Hx.Request.t list) ->
        String.equal (Hx.Request.path r) "/chat/completions" );
    ( "clientx: a head that fails of_pairs still returns the value",
      String.equal s_ok_bad_head.o_text "ok c1" );
    ( "clientx: a head that fails of_pairs reads Error in the reply",
      String.equal s_ok_bad_head.o_head "error" ) ]

let rate_checks : (string * bool) list =
  [ ( "clientx: a 429 with the requests reset 2 s ahead sleeps 2000 ms",
      List.equal Int.equal s_429_requests.o_slept [ 2_000 ] );
    ( "clientx: that 429 records one attempt",
      List.equal String.equal s_429_requests.o_ladder
        [ "rate_limited 2000 slept 2000" ] );
    ( "clientx: that 429 then answers the 200",
      String.equal s_429_requests.o_text "ok c1" );
    ( "clientx: a retry sends a SECOND request",
      Int.equal (List.length s_429_requests.o_reqs) 2 );
    ( "clientx: the re-sent body is byte-identical",
      identical s_429_requests );
    ( "clientx: each answered body closes once, retry included",
      Int.equal s_429_requests.o_closes 2 );
    ( "clientx: a 429 with the tokens reset 1.5 s ahead sleeps 1500 ms",
      List.equal Int.equal s_429_tokens.o_slept [ 1_500 ] );
    ( "clientx: the tokens hint reaches the ladder",
      List.equal String.equal s_429_tokens.o_ladder
        [ "rate_limited 1500 slept 1500" ] );
    ( "clientx: with both triples exhausted the LARGER hint wins",
      List.equal Int.equal s_429_both.o_slept [ 5_000 ] );
    ( "clientx: a 45 s hint under the 30 s cap stops the loop",
      String.equal s_429_over_cap.o_stop "hint_over_cap 45000" );
    ( "clientx: that stop returns the rate-limit failure",
      String.equal s_429_over_cap.o_text "http rate_limited" );
    ( "clientx: an over-cap hint sleeps not at all",
      Int.equal (List.length s_429_over_cap.o_slept) 0 );
    ( "clientx: an over-cap hint sends no second request",
      Int.equal (List.length s_429_over_cap.o_reqs) 1 );
    ( "clientx: a 429 with no exhausted triple takes the 1000 ms backoff",
      List.equal Int.equal s_429_no_hint.o_slept [ 1_000 ] );
    ( "clientx: that backoff carries no hint in the obstacle",
      List.equal String.equal s_429_no_hint.o_ladder
        [ "rate_limited none slept 1000" ] );
    ( "clientx: retry-after 3 sleeps 3000 ms",
      List.equal Int.equal s_429_retry_after.o_slept [ 3_000 ] );
    ( "clientx: a HALF triple leaves the head an Error and takes the backoff",
      List.equal Int.equal s_429_half_triple.o_slept [ 1_000 ] );
    ( "clientx: the half-triple retry still answers the 200",
      String.equal s_429_half_triple.o_text "ok c1" ) ]

let gateway_checks : (string * bool) list =
  [ ( "clientx: 503, 503, 200 sleeps 1000 then 2000",
      List.equal Int.equal s_503_503_200.o_slept [ 1_000; 2_000 ] );
    ( "clientx: 503, 503, 200 records TWO attempts",
      List.equal String.equal s_503_503_200.o_ladder
        [ "gateway 503 slept 1000"; "gateway 503 slept 2000" ] );
    ( "clientx: 503, 503, 200 answers the parsed response",
      String.equal s_503_503_200.o_text "ok c1" );
    ( "clientx: 503, 503, 200 sends three requests",
      Int.equal (List.length s_503_503_200.o_reqs) 3 );
    ( "clientx: three 503s under three attempts return the 503",
      String.equal s_503_x3.o_text "http server 503" );
    ( "clientx: three 503s stop with attempts exhausted",
      String.equal s_503_x3.o_stop "attempts_exhausted" );
    ( "clientx: three 503s record two attempts",
      Int.equal (List.length s_503_x3.o_ladder) 2 );
    ("clientx: a 502 retries", String.equal s_502.o_text "ok c1");
    ( "clientx: the 502 obstacle names the status",
      List.equal String.equal s_502.o_ladder [ "gateway 502 slept 1000" ] );
    ("clientx: a 504 retries", String.equal s_504.o_text "ok c1");
    ( "clientx: a 500 does NOT retry",
      String.equal s_500.o_text "http server 500" );
    ( "clientx: a 500 stops as not retryable",
      String.equal s_500.o_stop "not_retryable" );
    ("clientx: a 500 sleeps not at all", Int.equal (List.length s_500.o_slept) 0);
    ( "clientx: a 500 sends exactly one request",
      Int.equal (List.length s_500.o_reqs) 1 );
    ( "clientx: a 400 is a client failure",
      String.equal s_400.o_text "http client 400" );
    ("clientx: a 400 sleeps not at all", Int.equal (List.length s_400.o_slept) 0);
    ( "clientx: a 400 sends exactly one request",
      Int.equal (List.length s_400.o_reqs) 1 );
    ( "clientx: a non-2xx body closes exactly once",
      Int.equal s_400.o_closes 1 ) ]

let transport_checks : (string * bool) list =
  [ ( "clientx: a never-sent transport failure retries",
      String.equal s_unreachable.o_text "ok c1" );
    ( "clientx: the unreachable obstacle carries the payload",
      List.equal String.equal s_unreachable.o_ladder
        [ "unreachable curl exit 6 (dns): no host slept 1000" ] );
    ( "clientx: the unreachable retry sleeps the backoff",
      List.equal Int.equal s_unreachable.o_slept [ 1_000 ] );
    ( "clientx: a refused send still counts as a request",
      Int.equal (List.length s_unreachable.o_reqs) 2 );
    ( "clientx: a plain transport failure does NOT retry",
      String.equal s_transport_failed.o_text
        "failed transport: curl exit 28 (timeout)" );
    ( "clientx: a plain transport failure stops as not retryable",
      String.equal s_transport_failed.o_stop "not_retryable" );
    ( "clientx: a plain transport failure sleeps not at all",
      Int.equal (List.length s_transport_failed.o_slept) 0 );
    ( "clientx: a plain transport failure sends one request",
      Int.equal (List.length s_transport_failed.o_reqs) 1 ) ]

let media_checks : (string * bool) list =
  [ ( "clientx: a 2xx text/html is the client's own rejection",
      String.equal s_html.o_text "failed client: content-type: text/html" );
    ( "clientx: the rejected media type closes the body exactly once",
      Int.equal s_html.o_closes 1 );
    ( "clientx: the rejected media type sends no second request",
      Int.equal (List.length s_html.o_reqs) 1 );
    ( "clientx: an ABSENT content-type parses",
      String.equal s_no_media.o_text "ok c1" );
    ( "clientx: a charset parameter parses",
      String.equal s_charset.o_text "ok c1" );
    ( "clientx: a +json structured suffix parses",
      String.equal s_problem_json.o_text "ok c1" );
    ( "clientx: a close error WINS over a parsed 2xx body",
      String.equal s_close_error.o_text "failed transport: boom" );
    ( "clientx: the close-wins path closed the body once",
      Int.equal s_close_error.o_closes 1 );
    ( "clientx: a body above max_body is a failure",
      String.equal s_over_body.o_text
        "failed transport: read_all: body exceeds 10 bytes" );
    ( "clientx: the over-cap body still closes once",
      Int.equal s_over_body.o_closes 1 ) ]

let policy_checks : (string * bool) list =
  [ ( "clientx: Policy.none takes one attempt only",
      String.equal s_policy_none.o_text "http server 503" );
    ( "clientx: Policy.none sleeps not at all",
      Int.equal (List.length s_policy_none.o_slept) 0 );
    ( "clientx: Policy.none records no attempt",
      Int.equal (List.length s_policy_none.o_ladder) 0 );
    ( "clientx: Policy.none sends one request",
      Int.equal (List.length s_policy_none.o_reqs) 1 );
    ( "clientx: the total budget stops the second retry",
      String.equal s_budget.o_stop "budget_exhausted 1000" );
    ( "clientx: the budget stop keeps the 503",
      String.equal s_budget.o_text "http server 503" );
    ( "clientx: the budget allowed exactly one sleep",
      List.equal Int.equal s_budget.o_slept [ 1_000 ] );
    ( "clientx: max_body below the window rejects",
      String.equal (window_text (client_with 0))
        "client: max_body: 0 is below 1" );
    ( "clientx: max_body above the window rejects",
      String.equal
        (window_text (client_with 268_435_457))
        "client: max_body: 268435457 is above 268435456" );
    ( "clientx: max_body inside the window mints",
      String.equal (window_text (client_with 1_024)) "ok" ) ]

let status_wins_checks : (string * bool) list =
  [ ( "clientx: an error body above the cap does NOT erase the 503",
      String.equal s_big_error_body.o_text "ok c1" );
    ( "clientx: that oversized error body still retried as a gateway",
      List.equal String.equal s_big_error_body.o_ladder
        [ "gateway 503 slept 1000" ] );
    ( "clientx: a close error on a non-2xx does NOT erase the 503",
      String.equal s_error_close_error.o_text "ok c1" );
    ( "clientx: that close error still retried as a gateway",
      List.equal String.equal s_error_close_error.o_ladder
        [ "gateway 503 slept 1000" ] );
    ( "clientx: the non-2xx close error still closed the body",
      Int.equal s_error_close_error.o_closes 2 ) ]

let models_checks : (string * bool) list =
  [ ( "clientx: models parses the listing",
      String.equal s_models_default.o_text "ok 2" );
    ( "clientx: an ABSENT filter still sends type=all",
      List.equal
        (fun ((a : string), (b : string)) ((c : string), (d : string)) ->
          String.equal a c && String.equal b d)
        (List.concat (queries s_models_default))
        [ ("type", "all") ] );
    ( "clientx: All sends type=all",
      List.equal
        (fun ((a : string), (b : string)) ((c : string), (d : string)) ->
          String.equal a c && String.equal b d)
        (List.concat (queries s_models_all))
        [ ("type", "all") ] );
    ( "clientx: Kind Image sends the slug",
      List.equal
        (fun ((a : string), (b : string)) ((c : string), (d : string)) ->
          String.equal a c && String.equal b d)
        (List.concat (queries s_models_kind))
        [ ("type", "image") ] );
    ( "clientx: models uses the models route",
      match s_models_kind.o_reqs with
      | [] -> false
      | r :: (_ : Hx.Request.t list) ->
        String.equal (Hx.Request.path r) "/models" );
    ( "clientx: models parses under a filter too",
      String.equal s_models_kind.o_text "ok 2" );
    ( "clientx: models on a 500 takes the same failure path",
      String.equal s_models_500.o_text "http server 500" );
    ( "clientx: models on a 500 does not retry a 500",
      String.equal s_models_500.o_stop "not_retryable" );
    ( "clientx: the models body closes exactly once",
      Int.equal s_models_default.o_closes 1 ) ]

let stream_checks : (string * bool) list =
  [ ( "clientx: a stream head drives the consumer to Complete",
      String.equal s_stream.o_text "ok 2/complete" );
    ( "clientx: the streamed body closes exactly once",
      Int.equal s_stream.o_closes 1 );
    ( "clientx: the streamed body was actually read",
      s_stream.o_reads > 0 );
    ( "clientx: a stream head parses its head block",
      String.equal s_stream.o_head "ok" );
    ( "clientx: application/json on a stream is REFUSED, not an empty \
       Complete",
      String.equal s_stream_json.o_text
        "failed client: chat_stream: server answered application/json, not a \
         stream" );
    ( "clientx: the refused JSON stream closed the body once",
      Int.equal s_stream_json.o_closes 1 );
    ( "clientx: the refused JSON stream drove no cursor read",
      Int.equal s_stream_json.o_reads 0 );
    ( "clientx: a third media type on a stream is rejected",
      String.equal s_stream_html.o_text
        "failed client: content-type: text/html" );
    ( "clientx: the rejected stream media closed the body once",
      Int.equal s_stream_html.o_closes 1 );
    ( "clientx: a 429 before a stream sleeps then streams",
      String.equal s_stream_retry.o_text "ok 2/complete" );
    ( "clientx: that stream retry slept the hint",
      List.equal Int.equal s_stream_retry.o_slept [ 2_000 ] );
    ( "clientx: that stream retry records one attempt",
      Int.equal (List.length s_stream_retry.o_ladder) 1 );
    ( "clientx: a consumer that stops early yields Cut as a VALUE",
      String.equal s_stream_cut.o_text "ok 1/cut" );
    ( "clientx: the cut stream still closed the body once",
      Int.equal s_stream_cut.o_closes 1 );
    ( "clientx: the cut stream is not an error",
      String.equal s_stream_cut.o_stop "none" );
    ( "clientx: a failing read on the application/json refusal keeps the \
       transport text",
      String.equal s_stream_json_read.a_text "failed transport: read boom" ) ]

(* D11: no error text, no obstacle text and no rendered stop may carry
   a key byte. The test key is distinctive, so a substring search is
   a real sweep and not a coincidence. *)
let has_key (s : string) : bool =
  let n = String.length key_text in
  List.exists
    (fun (i : int) ->
      Option.fold ~none:false ~some:(String.equal key_text)
        (Venice__Bytesx.take s i n))
    (List.init (Int.max 0 (String.length s - n + 1)) Fun.id)

let swept : string list =
  List.concat
    (List.map
       (fun (o : obs) -> o.o_text :: o.o_stop :: o.o_ladder)
       [ s_ok;
         s_ok_bad_head;
         s_429_requests;
         s_429_tokens;
         s_429_both;
         s_429_over_cap;
         s_429_no_hint;
         s_429_retry_after;
         s_429_half_triple;
         s_503_503_200;
         s_503_x3;
         s_502;
         s_504;
         s_500;
         s_400;
         s_unreachable;
         s_transport_failed;
         s_html;
         s_no_media;
         s_charset;
         s_problem_json;
         s_close_error;
         s_over_body;
         s_policy_none;
         s_budget;
         s_big_error_body;
         s_error_close_error;
         s_models_default;
         s_models_all;
         s_models_kind;
         s_models_500;
         s_stream;
         s_stream_json;
         s_stream_html;
         s_stream_retry;
         s_stream_cut ])

let key_checks : (string * bool) list =
  [ ( "clientx: the key sweep has something to sweep",
      List.length swept > 60 );
    ( "clientx: the sweep would catch a leak",
      has_key ("prefix " ^ key_text ^ " suffix") );
    ( "clientx: no produced text carries a key byte",
      not (List.exists has_key swept) );
    ( "clientx: the media-type rejection carries no key byte",
      not (has_key s_html.o_text) );
    ( "clientx: the window rejection carries no key byte",
      not (has_key (window_text (client_with 0))) ) ]

let () =
  run
    (List.concat
       [ happy_checks;
         rate_checks;
         gateway_checks;
         transport_checks;
         media_checks;
         policy_checks;
         status_wins_checks;
         models_checks;
         stream_checks;
         key_checks ])
