(* M15 clientx: the session layer. HOST unit: a functor over the
   transport and the clock. No ref, no try-with, no float. *)

type error =
  | Http of
      { failure : Headx.failure;
        attempts : Retryx.Attempt.t list;
        stop : Retryx.Stop.t }
  | Failed of
      { error : Errx.t;
        attempts : Retryx.Attempt.t list;
        stop : Retryx.Stop.t }

type 'a reply =
  { value : 'a;
    head : (Headx.t, Errx.t) result;
    attempts : Retryx.Attempt.t list }

(* ---------- window and caps (D2) ---------- *)

let max_body_floor (() : unit) : int = 1
let max_body_ceiling (() : unit) : int = 268_435_456
let default_max_body (() : unit) : int = 16_777_216

(* The error body of a non-2xx answer, capped separately and not
   widenable by a caller: a failure story does not need 16 MiB. *)
let max_error_body (() : unit) : int = 1_048_576

(* ---------- media types (A3, A4) ---------- *)

let header_name (() : unit) : string = "content-type"
let retry_after_name (() : unit) : string = "retry-after"
let sse_media (() : unit) : string = "text/event-stream"
let json_media (() : unit) : string = "application/json"
let json_suffix (() : unit) : string = "+json"
let json_subtype (() : unit) : string = "json"

let find_pair (pairs : (string * string) list) (name : string) :
    string option =
  List.find_map
    (fun ((n : string), (v : string)) ->
      match String.equal (String.lowercase_ascii n) name with
      | true -> Some v
      | false -> None)
    pairs

(* The bytes before the first ";", ASCII-lowercased and edge-trimmed.
   A parameter list ("; charset=utf-8") never changes the type. *)
let media_of (v : string) : string =
  String.trim
    (String.lowercase_ascii
       (String.of_seq
          (Seq.take_while
             (fun (c : char) -> not (Char.equal c ';'))
             (String.to_seq v))))

let subtype_of (m : string) : string =
  Option.fold ~none:m
    ~some:(fun (i : int) ->
      Option.fold ~none:m
        ~some:(fun (s : string) -> s)
        (Bytesx.take m (i + 1) (String.length m - i - 1)))
    (String.index_opt m '/')

(* A4: present-and-wrong, not present-and-equal. A "json" subtype and
   a "+json" structured suffix both parse; an ABSENT type proceeds,
   because the parser is the real decider. *)
let json_like (m : string) : bool =
  let sub = subtype_of m in
  String.equal sub (json_subtype ())
  || String.ends_with ~suffix:(json_suffix ()) sub

let json_verdict (pairs : (string * string) list) : (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (v : string) ->
      match json_like (media_of v) with
      | true -> Ok ()
      | false -> Error (Errx.Client_invalid ("content-type: " ^ v)))
    (find_pair pairs (header_name ()))

type stream_media =
  | Sse
  | Json_answer
  | Wrong_media of string

(* A3: the stream arm is SPLIT, not widened. The SSE machine ignores
   every non-data field, so a JSON body would dispatch zero payloads
   and the answer would vanish behind an Ok. *)
let stream_verdict (pairs : (string * string) list) : stream_media =
  Option.fold ~none:Sse
    ~some:(fun (v : string) ->
      let m = media_of v in
      match () with
      | () when String.equal m (sse_media ()) -> Sse
      | () when String.equal m (json_media ()) -> Json_answer
      | () -> Wrong_media v)
    (find_pair pairs (header_name ()))

(* ---------- the obstacle table (D3) ---------- *)

let gateway_obstacle (status : int) : Retryx.Obstacle.t option =
  match () with
  | () when Int.equal status 502 || Int.equal status 503
            || Int.equal status 504 ->
    Some (Retryx.Obstacle.Gateway status)
  | () -> None

(* Only a transport that proved NOTHING was sent may be retried; a
   timeout and a reset can strike after the request went out, so they
   are returned as they are. *)
let obstacle_of_error (e : Errx.t) : Retryx.Obstacle.t option =
  match e with
  | Errx.Transport_unreachable s -> Some (Retryx.Obstacle.Unreachable s)
  | Errx.Transport_failed (_ : string) -> None
  | Errx.Hex_invalid (_ : string) -> None
  | Errx.B64_invalid (_ : string) -> None
  | Errx.Json_invalid (_ : string) -> None
  | Errx.Model_invalid (_ : string) -> None
  | Errx.Param_invalid (_ : string) -> None
  | Errx.Msg_invalid (_ : string) -> None
  | Errx.Head_invalid (_ : string) -> None
  | Errx.Chat_invalid (_ : string) -> None
  | Errx.Resp_invalid (_ : string) -> None
  | Errx.Sse_invalid (_ : string) -> None
  | Errx.Chunk_invalid (_ : string) -> None
  | Errx.Key_invalid (_ : string) -> None
  | Errx.Req_invalid (_ : string) -> None
  | Errx.Wire_invalid (_ : string) -> None
  | Errx.Stream_invalid (_ : string) -> None
  | Errx.Client_invalid (_ : string) -> None

type stopper =
  | Http_stop of Headx.failure
  | Err_stop of Errx.t

type 'v landing =
  | Landed of 'v * (Headx.t, Errx.t) result
  | Blocked of Retryx.Obstacle.t * stopper
  | Halted of stopper

let halt (s : stopper) (attempts : Retryx.Attempt.t list)
    (stop : Retryx.Stop.t) : error =
  match s with
  | Http_stop f -> Http { failure = f; attempts; stop }
  | Err_stop e -> Failed { error = e; attempts; stop }

module Make (T : Streamx.S) (C : Clockx.S) = struct
  module Drive = Streamx.Make (T)

  type t =
    { key : Keyx.t;
      policy : Retryx.Policy.t;
      max_body : int;
      transport : T.t;
      clock : C.t }

  let make ~(key : Keyx.t) ?(policy : Retryx.Policy.t = Retryx.Policy.default)
      ?(max_body : int = default_max_body ()) ~(transport : T.t) ~(clock : C.t)
      (() : unit) : (t, Errx.t) result =
    match () with
    | () when max_body < max_body_floor () ->
      Error
        (Errx.Client_invalid
           ("max_body: " ^ string_of_int max_body ^ " is below "
          ^ string_of_int (max_body_floor ())))
    | () when max_body > max_body_ceiling () ->
      Error
        (Errx.Client_invalid
           ("max_body: " ^ string_of_int max_body ^ " is above "
          ^ string_of_int (max_body_ceiling ())))
    | () -> Ok { key; policy; max_body; transport; clock }

  (* The 2xx read: a close error WINS over the read result, parsed or
     not (the M14 D4 rule). A transport that reports failure is not
     trusted to have delivered the whole body. *)
  let read_then_close (cap : int) (body : T.body) : (string, Errx.t) result =
    let got = T.read_all ~cap body in
    Result.fold
      ~ok:(fun (() : unit) -> got)
      ~error:(fun (e : Errx.t) -> Error e)
      (T.close body)

  (* A2, the non-2xx read: the STATUS wins. Neither a read error nor a
     close error may erase it, so the bytes that arrived, or "" when
     none did, go to classify and the failure keeps its status. *)
  let read_for_status (body : T.body) : string =
    let got = T.read_all ~cap:(max_error_body ()) body in
    let (_ : (unit, Errx.t) result) = T.close body in
    Result.fold
      ~ok:(fun (s : string) -> s)
      ~error:(fun (_ : Errx.t) -> "")
      got

  let close_with (e : Errx.t) (body : T.body) : ('v, Errx.t) result =
    let (_ : (unit, Errx.t) result) = T.close body in
    Error e

  let read_json (c : t) (h : Wirex.head) (body : T.body) :
      (string, Errx.t) result =
    Result.fold
      ~ok:(fun (() : unit) -> read_then_close c.max_body body)
      ~error:(fun (e : Errx.t) -> close_with e body)
      (json_verdict h.Wirex.pairs)

  let rate_hint (c : t) (h : Wirex.head) (hres : (Headx.t, Errx.t) result) :
      Retryx.Delay.t option =
    Retryx.best_hint
      (Retryx.hints_of ~head:hres
         ~now:(C.now c.clock)
         ~retry_after:(find_pair h.Wirex.pairs (retry_after_name ())))

  let obstacle_of_failure (c : t) (h : Wirex.head)
      (hres : (Headx.t, Errx.t) result) (f : Headx.failure) :
      Retryx.Obstacle.t option =
    match f with
    | Headx.Rate_limited { head = _; head_error = _; body = _; raw = _ } ->
      Some (Retryx.Obstacle.Rate_limited (rate_hint c h hres))
    | Headx.Server { status; head = _; head_error = _; body = _; raw = _ } ->
      gateway_obstacle status
    | Headx.Client
        { status = _; head = _; head_error = _; body = _; raw = _ } ->
      None
    | Headx.Unexpected_status
        { status = _; head = _; head_error = _; raw = _ } ->
      None

  let non_2xx (c : t) (h : Wirex.head) (body : T.body)
      (hres : (Headx.t, Errx.t) result) : 'v landing =
    let raw = read_for_status body in
    Result.fold
      ~ok:(fun (fo : Headx.failure option) ->
        Option.fold
          ~none:
            (Halted
               (Err_stop
                  (Errx.Client_invalid
                     ("classify: no failure for status "
                    ^ string_of_int h.Wirex.status))))
          ~some:(fun (f : Headx.failure) ->
            Option.fold ~none:(Halted (Http_stop f))
              ~some:(fun (o : Retryx.Obstacle.t) -> Blocked (o, Http_stop f))
              (obstacle_of_failure c h hres f))
          fo)
      ~error:(fun (e : Errx.t) -> Halted (Err_stop e))
      (Headx.classify ~status:h.Wirex.status ~head:hres ~raw)

  let attempt (c : t) (req : Httpx.Request.t)
      (handle : Wirex.head -> T.body -> ('v, Errx.t) result) : 'v landing =
    Result.fold
      ~ok:(fun (((h : Wirex.head), (body : T.body)) : Wirex.head * T.body) ->
        let hres = Headx.of_pairs h.Wirex.pairs in
        match () with
        | () when 200 <= h.Wirex.status && h.Wirex.status <= 299 ->
          Result.fold
            ~ok:(fun (v : 'v) -> Landed (v, hres))
            ~error:(fun (e : Errx.t) -> Halted (Err_stop e))
            (handle h body)
        | () -> non_2xx c h body hres)
      ~error:(fun (e : Errx.t) ->
        Option.fold ~none:(Halted (Err_stop e))
          ~some:(fun (o : Retryx.Obstacle.t) -> Blocked (o, Err_stop e))
          (obstacle_of_error e))
      (T.send c.transport ~key:c.key req)

  (* The loop. It threads the attempt number, the slept total and the
     reversed ledger as ARGUMENTS: the client holds no ref. *)
  let rec drive (c : t) (req : Httpx.Request.t)
      (handle : Wirex.head -> T.body -> ('v, Errx.t) result) (n : int)
      (waited : Retryx.Delay.t) (acc : Retryx.Attempt.t list) :
      ('v reply, error) result =
    match attempt c req handle with
    | Landed (v, hres) ->
      Ok { value = v; head = hres; attempts = List.rev acc }
    | Halted s -> Error (halt s (List.rev acc) Retryx.Stop.Not_retryable)
    | Blocked (o, s) ->
      Result.fold
        ~ok:(fun (wait : Retryx.Delay.t) ->
          C.sleep c.clock wait;
          drive c req handle (n + 1)
            (Retryx.Delay.saturate
               (Retryx.Delay.ms waited + Retryx.Delay.ms wait))
            (Retryx.Attempt.make ~obstacle:o ~slept:wait :: acc))
        ~error:(fun (stop : Retryx.Stop.t) ->
          Error (halt s (List.rev acc) stop))
        (Retryx.decide c.policy ~attempt:n ~waited ~now:(C.now c.clock) o)

  let start (c : t) (built : (Httpx.Request.t, Errx.t) result)
      (handle : Wirex.head -> T.body -> ('v, Errx.t) result) :
      ('v reply, error) result =
    Result.fold
      ~ok:(fun (req : Httpx.Request.t) ->
        drive c req handle 1 (Retryx.Delay.zero ()) [])
      ~error:(fun (e : Errx.t) ->
        Error
          (Failed
             { error = e; attempts = []; stop = Retryx.Stop.Not_retryable }))
      built

  let models ?(filter : Modelx.Model_filter.t = Modelx.Model_filter.All)
      (c : t) : (Modelx.packed list reply, error) result =
    let handle (h : Wirex.head) (body : T.body) :
        (Modelx.packed list, Errx.t) result =
      Result.bind (read_json c h body) (fun (raw : string) ->
          Result.bind (Jsonx.parse raw) Modelx.of_listing)
    in
    start c
      (Httpx.Request.get
         ~query:[ ("type", Modelx.Model_filter.slug filter) ]
         Httpx.Route.models)
      handle

  let chat (c : t) (ch : 'ch Chatx.t) : (Respx.t reply, error) result =
    let handle (h : Wirex.head) (body : T.body) : (Respx.t, Errx.t) result =
      Result.bind (read_json c h body) Respx.of_string
    in
    start c
      (Httpx.Request.post Httpx.Route.chat_completions
         ~body:(Chatx.to_json ch))
      handle

  let chat_stream (c : t) (ch : 'ch Chatx.t)
      (consume : Streamx.cursor -> 'a) :
      (('a * Streamx.outcome) reply, error) result =
    let handle (h : Wirex.head) (body : T.body) :
        ('a * Streamx.outcome, Errx.t) result =
      match stream_verdict h.Wirex.pairs with
      | Sse -> Ok (Drive.run body consume)
      | Json_answer ->
        Result.bind (read_then_close c.max_body body) (fun (_ : string) ->
            Error
              (Errx.Client_invalid
                 "chat_stream: server answered application/json, not a \
                  stream"))
      | Wrong_media v -> close_with (Errx.Client_invalid ("content-type: " ^ v)) body
    in
    start c
      (Httpx.Request.post Httpx.Route.chat_completions
         ~body:(Chatx.to_json ~stream:true ~include_usage:true ch))
      handle
end
