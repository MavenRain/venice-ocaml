(* M14 streamx: the effect-handler PULL driver over the scripted Fake
   transport. The pure fold is test_accx; this suite pins the driver
   ledger, which is read granularity, the exit outcomes, the
   close-exactly-once latch, the dead cursor after the run, the
   post-[DONE] drain caps and the consumer-fault bracket.

   Every case drives its OWN body. A body is stateful and OCaml
   evaluates list elements right to left, so a shared body would be
   consumed by the later check first; each report is a top-level let
   that runs once, in source order, and the check list only reads the
   recorded values.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal modules by their mangled names, exactly as
   test_ssex does. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module St = Venice__Streamx
module S = Venice__Ssex
module A = Venice__Accx
module F = Venice__Fakex
module E = Venice__Errx
module K = Venice__Keyx
module H = Venice__Httpx
module W = Venice__Wirex
module R = Venice__Respx
module B = Venice__Bytesx

(* The functor applies to the scripted transport with nothing else
   changed, which is the M15 shape (D3). *)
module Drive = St.Make (F)

(* D6/A18 re-entrancy probe. hook is armed by the consumer and fires
   INSIDE a transport read, which is the one place a re-entrant next
   can meet the continuation the driver is running right now. The A18
   mutant "skip-clear-pending" leaves that resumed continuation in the
   state ref, so the inner next resumes it a second time and the
   stdlib aborts the suite with Continuation_already_resumed: that
   crash IS the kill, and no repo code raises anything. *)
let hook : (unit -> unit) ref = ref (fun (() : unit) -> ())

module Probe = struct
  include F

  let read (b : body) : (string option, E.t) result =
    !hook ();
    F.read b
end

module Reenter = St.Make (Probe)

(* ---------- helpers ---------- *)

let contains (hay : string) (needle : string) : bool =
  let n = String.length needle in
  let h = String.length hay in
  let rec go (i : int) : bool =
    match () with
    | () when i + n > h -> false
    | () when
        Option.fold ~none:false ~some:(String.equal needle) (B.take hay i n) ->
      true
    | () -> go (i + 1)
  in
  go 0

let outcome_text (o : St.outcome) : string =
  match o with
  | St.Complete -> "complete"
  | St.Cut -> "cut"
  | St.Failed e -> "failed:" ^ E.to_string e

(* One chunk seen by the consumer, reported by its content delta. *)
let marker (c : S.Chunk.t) : string =
  Option.fold ~none:"<no choice>"
    ~some:(fun (ch : S.Chunk.Choice.t) ->
      Option.value ~default:"<none>"
        (S.Chunk.Delta.content (S.Chunk.Choice.delta ch)))
    (List.nth_opt (S.Chunk.choices c) 0)

let ok_head : string =
  "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"

let listing : (H.Request.t, E.t) result = H.Request.get H.Route.models

let open_body ?(close_error : string option) (chunks : string list) :
    F.body option =
  Result.to_option
    (Result.bind (K.make "sk-abc") (fun (k : K.t) ->
         Result.bind listing (fun (req : H.Request.t) ->
             Result.map
               (fun ((_ : W.head), (b : F.body)) -> b)
               (F.send
                  (F.make [ F.exchange ~head:ok_head ~chunks ?close_error () ])
                  ~key:k req))))

type rep =
  { markers : string list;
    outcome : string;
    reads : int;
    closes : int;
    body : F.body option }

let no_body : rep =
  { markers = [ "<no body>" ];
    outcome = "<no body>";
    reads = 0;
    closes = 0;
    body = None }

(* The counters are read into lets before the record is built: a
   record literal evaluates its fields right to left, so an inline
   read would count itself. *)
let report ?(close_error : string option) ?(closing : S.closing option)
    (script : string list) (consume : St.cursor -> string list) : rep =
  Option.fold ~none:no_body
    ~some:(fun (b : F.body) ->
      let (pair : string list * St.outcome) = Drive.run ?closing b consume in
      let ((ms : string list), (o : St.outcome)) = pair in
      let (rd : int) = F.reads b in
      let (cl : int) = F.closes b in
      { markers = ms;
        outcome = outcome_text o;
        reads = rd;
        closes = cl;
        body = Some b
      })
    (open_body ?close_error script)

(* ---------- consumers ---------- *)

let all_markers (c : St.cursor) : string list =
  List.rev
    (St.fold c ~init:[] ~f:(fun (acc : string list) (x : S.Chunk.t) ->
         marker x :: acc))

let take_n (n : int) (c : St.cursor) : string list =
  let rec go (i : int) (acc : string list) : string list =
    match () with
    | () when i <= 0 -> List.rev acc
    | () ->
      Option.fold ~none:(List.rev acc)
        ~some:(fun (x : S.Chunk.t) -> go (i - 1) (marker x :: acc))
        (St.next c)
  in
  go n []

let cut_one (c : St.cursor) : string list = take_n 1 c
let cut_two (c : St.cursor) : string list = take_n 2 c

(* ---------- fixtures ---------- *)

let d1 : string =
  {|{"id":"c1","object":"chat.completion.chunk","created":7,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}|}

let d2 : string =
  {|{"id":"c1","object":"chat.completion.chunk","created":7,"model":"m","choices":[{"index":0,"delta":{"content":"lo"}}]}|}

let d3 : string =
  {|{"id":"c1","object":"chat.completion.chunk","created":7,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}|}

let ev (payload : string) : string = "data: " ^ payload ^ "\n\n"
let done_ev : string = "data: [DONE]\n\n"
let whole : string = ev d1 ^ ev d2 ^ ev d3 ^ done_ev
let events : string list = [ ev d1; ev d2; ev d3; done_ev ]
let seen : string list = [ "Hel"; "lo"; "<none>" ]
let bad_events : string list = [ ev d1; ev d2; ev "not-json"; done_ev ]

let bytewise (s : string) : string list =
  List.filter_map
    (fun (i : int) -> B.take s i 1)
    (List.init (String.length s) Fun.id)

(* n = 3 puts a read boundary inside the "data:" prefix and inside the
   payloads alike. *)
let by_n (n : int) (s : string) : string list =
  let rec go (i : int) (acc : string list) : string list =
    match () with
    | () when i >= String.length s -> List.rev acc
    | () ->
      Option.fold ~none:(List.rev acc)
        ~some:(fun (p : string) -> go (i + n) (p :: acc))
        (B.take s i (Int.min n (String.length s - i)))
  in
  go 0 []

let equivalent : string =
  {|{"id":"c1","object":"chat.completion","created":7,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}|}

let resp_text (resp : R.t) : string =
  R.id resp ^ "|" ^ R.model resp ^ "|"
  ^ string_of_int (R.created resp)
  ^ "|"
  ^ string_of_int (R.Usage.total_tokens (R.usage resp))
  ^ "|"
  ^ Option.fold ~none:"<no choice>"
      ~some:(fun (ch : R.Choice.t) ->
        string_of_int (R.Choice.index ch)
        ^ "/"
        ^ Option.value ~default:"<none>" (R.Choice.content ch)
        ^ "/"
        ^ R.Finish.to_string (R.Choice.finish ch))
      (List.nth_opt (R.choices resp) 0)

let equivalent_text : string =
  Result.fold ~ok:resp_text ~error:E.to_string (R.of_string equivalent)

(* ---------- reports, in evaluation order ---------- *)

let one_read : rep = report [ whole ] all_markers
let byte_read : rep = report (bytewise whole) all_markers
let split3 : rep = report (by_n 3 whole) all_markers
let per_event : rep = report events all_markers
let cut_rep : rep = report events cut_one
let cut_err_rep : rep = report ~close_error:"boom" events cut_one

(* No [DONE]: Require_done rejects at Ssex.close while the transport
   close is Ok, so exactly one error is present. *)
let trunc_rep : rep = report [ ev d1; ev d2 ] all_markers

(* [DONE] plus a scripted close_error: again exactly one error, the
   transport one. *)
let done_close_rep : rep = report ~close_error:"boom" events all_markers

(* A9: BOTH closes fail, which is the only shape that can read the D4
   precedence rule. *)
let both_fail_rep : rep =
  report ~close_error:"boom" [ ev d1; ev d2 ] all_markers

let bad_rep : rep = report bad_events all_markers
let lazy_rep : rep = report bad_events cut_two

let tail_none_consumer (c : St.cursor) : string list =
  let (ms : string list) = all_markers c in
  let (n1 : string) = Option.fold ~none:"none" ~some:marker (St.next c) in
  let (n2 : string) = Option.fold ~none:"none" ~some:marker (St.next c) in
  List.append ms [ n1; n2 ]

let tail_rep : rep = report events tail_none_consumer

(* A1: the consumer stores the cursor, the run ends Cut, and the two
   later next calls must read None without touching the transport. *)
let a1_saved : St.cursor option ref = ref None

let a1_rep : rep =
  report events (fun (c : St.cursor) ->
      a1_saved := Some c;
      cut_one c)

let a1_after : string list =
  Option.fold ~none:[ "<no cursor>" ]
    ~some:(fun (c : St.cursor) ->
      let (n1 : string) = Option.fold ~none:"none" ~some:marker (St.next c) in
      let (n2 : string) = Option.fold ~none:"none" ~some:marker (St.next c) in
      [ n1; n2 ])
    !a1_saved

let a1_reads_after : int = Option.fold ~none:(-1) ~some:F.reads a1_rep.body
let a1_closes_after : int = Option.fold ~none:(-1) ~some:F.closes a1_rep.body

(* W8(d): 10_000 yields at constant handler depth. *)
let big_events : string list =
  List.append (List.init 10_000 (fun (_ : int) -> ev d2)) [ done_ev ]

let big_rep : rep =
  report big_events (fun (c : St.cursor) ->
      [ string_of_int
          (St.fold c ~init:0 ~f:(fun (n : int) (_ : S.Chunk.t) -> n + 1)) ])

let iter_seen : string list ref = ref []

let iter_rep : rep =
  report events (fun (c : St.cursor) ->
      St.iter c (fun (x : S.Chunk.t) -> iter_seen := marker x :: !iter_seen);
      List.rev !iter_seen)

let collect_consumer (c : St.cursor) : string list =
  Result.fold
    ~ok:(fun (f : A.final) ->
      [ A.id f;
        A.model f;
        string_of_int (A.created f);
        string_of_int (List.length (A.choices f));
        Option.value ~default:"<none>"
          (Option.bind (List.nth_opt (A.choices f) 0) A.Choice.content)
      ])
    ~error:(fun (e : E.t) -> [ E.to_string e ])
    (St.collect c)

let collect_rep : rep = report events collect_consumer

let response_consumer (c : St.cursor) : string list =
  Result.fold
    ~ok:(fun (f : A.final) ->
      [ Result.fold ~ok:resp_text ~error:E.to_string (A.to_response f) ])
    ~error:(fun (e : E.t) -> [ E.to_string e ])
    (St.collect c)

let response_rep : rep = report events response_consumer

let eof_rep : rep =
  report ~closing:S.Allow_eof [ ev d1; ev d2; ev d3 ] all_markers

let done_only_rep : rep = report [ done_ev ] all_markers
let empty_rep : rep = report [] all_markers

(* A3: 5000 comment events after [DONE] dispatch nothing, so only the
   drain cap can end the run. *)
let flood : string list =
  done_ev :: List.init 5000 (fun (_ : int) -> ": keepalive\n\n")

let a3_rep : rep = report flood all_markers

let a3_unspent : bool =
  Option.fold ~none:false
    ~some:(fun (b : F.body) ->
      Result.fold ~ok:Option.is_some
        ~error:(fun (_ : E.t) -> false)
        (F.read b))
    a3_rep.body

(* A3(bytes): a handful of large comment reads after [DONE] cross the
   1 MiB byte cap far short of the 4096-read cap, so this isolates the
   byte counter from the read counter. *)
let big_comment (n : int) : string = ": " ^ String.make n 'x' ^ "\n\n"

let byte_flood : string list =
  done_ev :: List.init 5000 (fun (_ : int) -> big_comment 2000)

let a3b_rep : rep = report byte_flood all_markers

let a3b_unspent : bool =
  Option.fold ~none:false
    ~some:(fun (b : F.body) ->
      Result.fold ~ok:Option.is_some
        ~error:(fun (_ : E.t) -> false)
        (F.read b))
    a3b_rep.body

(* D6/A18: the consumer arms the probe AFTER the first next and
   disarms it after the second. run parks the first chunk, so the
   first next answers from queued and resumes nothing; the second next
   is the first one that resumes the producer, and the read inside
   that resumed continuation is where the inner next lands. *)
let reenter_consumer (c : St.cursor) : string list =
  let (m1 : string) = Option.fold ~none:"none" ~some:marker (St.next c) in
  hook :=
    (fun (() : unit) ->
      let (_ : S.Chunk.t option) = St.next c in
      ());
  let (m2 : string) = Option.fold ~none:"none" ~some:marker (St.next c) in
  hook := (fun (() : unit) -> ());
  List.append [ m1; m2 ] (all_markers c)

let reenter_rep : rep =
  Option.fold ~none:no_body
    ~some:(fun (b : F.body) ->
      let (pair : string list * St.outcome) = Reenter.run b reenter_consumer in
      let ((ms : string list), (o : St.outcome)) = pair in
      let (rd : int) = F.reads b in
      let (cl : int) = F.closes b in
      { markers = ms;
        outcome = outcome_text o;
        reads = rd;
        closes = cl;
        body = Some b
      })
    (open_body events)

let reenter_second : string =
  Option.value ~default:"<none>" (List.nth_opt reenter_rep.markers 1)

(* A13: the consumer faults after two chunks. It performs an effect no
   handler owns, so the runtime raises Effect.Unhandled: a caller
   fault the SDK never produces itself, minted with no raise and no
   partial accessor. run must still close the body and let the fault
   out. The exception arm is the ONE documented catch-all exemption,
   because exn is an OPEN type. *)
type _ Effect.t += Fault : unit Effect.t

let a13_body : F.body option = open_body events

let fault_consumer (c : St.cursor) : string list =
  let (ms : string list) = take_n 2 c in
  Effect.perform Fault;
  ms

let a13_outcome : string =
  Option.fold ~none:"<no body>"
    ~some:(fun (b : F.body) ->
      match Drive.run b fault_consumer with
      | ((ms : string list), (o : St.outcome)) ->
        "returned:" ^ String.concat "," ms ^ ":" ^ outcome_text o
      | exception _ -> "raised")
    a13_body

let a13_closes : int = Option.fold ~none:(-1) ~some:F.closes a13_body

(* ---------- checks ---------- *)

let determinism_checks : (string * bool) list =
  [ ( "determinism: the whole stream in one read yields the chunks in order",
      List.equal String.equal one_read.markers seen
      && String.equal one_read.outcome "complete" );
    ( "determinism: byte-at-a-time reads yield the same sequence",
      List.equal String.equal byte_read.markers seen
      && String.equal byte_read.outcome "complete" );
    ( "determinism: reads split inside payloads and inside data: agree",
      List.equal String.equal split3.markers seen
      && String.equal split3.outcome "complete" );
    ( "determinism: one SSE event per read agrees",
      List.equal String.equal per_event.markers seen
      && String.equal per_event.outcome "complete" );
    ( "determinism: the read counts differ while the chunks do not",
      byte_read.reads > one_read.reads )
  ]

let outcome_checks : (string * bool) list =
  [ ( "cut: a consumer that stops early ends the run Cut",
      List.equal String.equal cut_rep.markers [ "Hel" ]
      && String.equal cut_rep.outcome "cut" );
    ( "cut: a scripted close_error turns the cut into Failed",
      String.equal cut_err_rep.outcome "failed:transport: boom" );
    ( "truncated: no [DONE] fails with the ssex close error",
      contains trunc_rep.outcome "sse: close before [DONE]" );
    ( "[DONE] then a scripted close_error fails with the transport error",
      String.equal done_close_rep.outcome "failed:transport: boom" );
    ( "A9: a truncated stream plus a close_error yields the TRANSPORT error",
      String.equal both_fail_rep.outcome "failed:transport: boom" );
    ( "A9: the transport error is not the ssex text",
      not (contains both_fail_rep.outcome "sse: close before [DONE]") );
    ( "malformed chunk: the earlier chunks reach the consumer first",
      List.equal String.equal bad_rep.markers [ "Hel"; "lo" ] );
    ( "malformed chunk: the ssex parse error surfaces verbatim",
      String.equal bad_rep.outcome "failed:json: expected literal null" );
    ( "laziness: a cut before the malformed chunk ends Cut, not Failed",
      List.equal String.equal lazy_rep.markers [ "Hel"; "lo" ]
      && String.equal lazy_rep.outcome "cut" );
    ( "[DONE] alone completes with no chunk",
      List.equal String.equal done_only_rep.markers []
      && String.equal done_only_rep.outcome "complete" );
    ( "an empty script fails at close with no payload seen",
      contains empty_rep.outcome "sse: close before [DONE]; no payload seen" );
    ( "Allow_eof: a stream that ends at EOF completes",
      List.equal String.equal eof_rep.markers seen
      && String.equal eof_rep.outcome "complete" )
  ]

let close_checks : (string * bool) list =
  [ ( "A5: the body closes exactly once after Complete",
      Int.equal one_read.closes 1 );
    ("A5: the body closes exactly once after Cut", Int.equal cut_rep.closes 1);
    ( "A5: the body closes exactly once after Failed",
      Int.equal trunc_rep.closes 1 );
    ( "A5: a scripted close_error is still one close",
      Int.equal cut_err_rep.closes 1 )
  ]

let cursor_checks : (string * bool) list =
  [ ( "next after None stays None",
      List.equal String.equal tail_rep.markers
        [ "Hel"; "lo"; "<none>"; "none"; "none" ] );
    ( "A1: the run that stored the cursor ended Cut",
      String.equal a1_rep.outcome "cut" );
    ( "A1: post-run cursor is dead, two later next calls read None",
      List.equal String.equal a1_after [ "none"; "none" ] );
    ( "A1: the dead cursor reads nothing more from the transport",
      Int.equal a1_reads_after a1_rep.reads );
    ( "A1: the dead cursor closes the body no second time",
      Int.equal a1_closes_after 1 )
  ]

let drain_checks : (string * bool) list =
  [ ( "A3: a post-Done comment flood stops at the drain cap",
      String.equal a3_rep.outcome "complete" );
    ("A3: the drain cap leaves the script unspent", a3_unspent);
    ( "A3: the drain reads no more than the cap plus the [DONE] read",
      a3_rep.reads <= 4098 );
    ( "A3(bytes): a large-comment flood stops at the byte cap, not the read cap",
      String.equal a3b_rep.outcome "complete"
      && a3b_rep.reads < 600 );
    ("A3(bytes): the byte cap leaves the script unspent", a3b_unspent)
  ]

let consumer_checks : (string * bool) list =
  [ ( "iter visits every chunk in order",
      List.equal String.equal iter_rep.markers seen
      && String.equal iter_rep.outcome "complete" );
    ( "fold and iter agree on the same script",
      List.equal String.equal iter_rep.markers per_event.markers );
    ( "collect drains the stream into the accumulator",
      List.equal String.equal collect_rep.markers
        [ "c1"; "m"; "7"; "1"; "Hello" ]
      && String.equal collect_rep.outcome "complete" );
    ( "collect plus to_response equals the non-streaming document",
      List.equal String.equal response_rep.markers [ equivalent_text ]
      && String.equal equivalent_text "c1|m|7|5|0/Hello/stop" );
    ( "10_000 chunks complete at constant handler depth",
      List.equal String.equal big_rep.markers [ "10000" ]
      && String.equal big_rep.outcome "complete" );
    ("A13: a consumer fault propagates out of run",
     String.equal a13_outcome "raised");
    ("A13: a consumer fault still closes the body", Int.equal a13_closes 1)
  ]

(* D6/A18: a re-entrant next from inside a transport read resumes
   nothing twice. *)
let reenter_checks : (string * bool) list =
  [ ( "D6/A18: the second next still yields the second chunk under a \
       re-entrant next",
      String.equal reenter_second "lo" );
    ( "D6/A18: the re-entrant run yields every scripted chunk, none lost",
      List.equal String.equal reenter_rep.markers seen );
    ( "D6/A18: the re-entrant run completes",
      String.equal reenter_rep.outcome "complete" );
    ( "D6/A18: the re-entrant run closes the body exactly once",
      Int.equal reenter_rep.closes 1 )
  ]

let () =
  run
    (List.concat
       [ determinism_checks;
         outcome_checks;
         close_checks;
         cursor_checks;
         drain_checks;
         consumer_checks;
         reenter_checks
       ])
