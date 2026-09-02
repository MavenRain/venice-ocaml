(* M11 ssex: WHATWG framing (terminators, BOM, fields, caps), the
   [DONE] discipline with both closing policies, the chunk document
   parse with its raw+view splits, and the A10 granularity
   differential (byte-at-a-time vs one-shot over every corpus
   stream, compared on events, pending projections and close text;
   polymorphic equality on Machine.t is banned by design). The
   internal seams live behind venice.mli, so this suite binds the
   library-internal modules by their mangled names. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module S = Venice__Ssex
module R = Venice__Respx
module J = Venice__Jsonx
module E = Venice__Errx

let err_text (expect : string) (e : E.t) : bool =
  String.equal (E.to_string e) expect

let opt_str_eq (a : string option) (b : string option) : bool =
  Option.equal String.equal a b

(* ---------- machine harness ---------- *)

let m_feed_all (m0 : S.Machine.t) (chunks : string list) :
    (S.Machine.t * string list, E.t) result =
  List.fold_left
    (fun acc chunk ->
      Result.bind acc (fun ((m : S.Machine.t), (evs : string list)) ->
          Result.map
            (fun ((m' : S.Machine.t), (evs' : string list)) ->
              (m', evs @ evs'))
            (S.Machine.feed m chunk)))
    (Ok (m0, [])) chunks

let m_run ?max_line_bytes ?max_event_bytes (chunks : string list) :
    (S.Machine.t * string list, E.t) result =
  Result.bind
    (S.Machine.make ?max_line_bytes ?max_event_bytes ())
    (fun m -> m_feed_all m chunks)

let m_events_close_ok ?max_line_bytes ?max_event_bytes
    (chunks : string list) (expect : string list) : bool =
  Result.fold
    ~ok:(fun ((m : S.Machine.t), (evs : string list)) ->
      List.equal String.equal evs expect
      && Result.fold
           ~ok:(fun (() : unit) -> true)
           ~error:(fun ((_ : E.t)) -> false)
           (S.Machine.close m))
    ~error:(fun ((_ : E.t)) -> false)
    (m_run ?max_line_bytes ?max_event_bytes chunks)

let m_feed_rejects ?max_line_bytes ?max_event_bytes
    (chunks : string list) (expect : string) : bool =
  Result.fold
    ~ok:(fun ((_ : S.Machine.t), (_ : string list)) -> false)
    ~error:(err_text expect)
    (m_run ?max_line_bytes ?max_event_bytes chunks)

let m_close_rejects (chunks : string list) (expect : string) : bool =
  Result.fold
    ~ok:(fun ((m : S.Machine.t), (_ : string list)) ->
      Result.fold
        ~ok:(fun (() : unit) -> false)
        ~error:(err_text expect) (S.Machine.close m))
    ~error:(fun ((_ : E.t)) -> false)
    (m_run chunks)

(* ---------- discipline harness ---------- *)

let event_eq (a : S.event) (b : S.event) : bool =
  match (a, b) with
  | S.Data x, S.Data y -> String.equal x y
  | S.Done, S.Done -> true
  | S.Data (_ : string), S.Done | S.Done, S.Data (_ : string) -> false

let s_run ?closing (chunks : string list) :
    (S.t * S.event list, E.t) result =
  Result.bind (S.make ?closing ()) (fun s0 ->
      List.fold_left
        (fun acc chunk ->
          Result.bind acc (fun ((s : S.t), (evs : S.event list)) ->
              Result.map
                (fun ((s' : S.t), (evs' : S.event list)) ->
                  (s', evs @ evs'))
                (S.feed s chunk)))
        (Ok (s0, [])) chunks)

let s_events ?closing (chunks : string list) (expect : S.event list) :
    bool =
  Result.fold
    ~ok:(fun ((_ : S.t), (evs : S.event list)) ->
      List.equal event_eq evs expect)
    ~error:(fun ((_ : E.t)) -> false)
    (s_run ?closing chunks)

let s_events_close_ok ?closing (chunks : string list)
    (expect : S.event list) : bool =
  Result.fold
    ~ok:(fun ((s : S.t), (evs : S.event list)) ->
      List.equal event_eq evs expect
      && Result.fold
           ~ok:(fun (() : unit) -> true)
           ~error:(fun ((_ : E.t)) -> false)
           (S.close s))
    ~error:(fun ((_ : E.t)) -> false)
    (s_run ?closing chunks)

let s_feed_rejects ?closing (chunks : string list) (expect : string) :
    bool =
  Result.fold
    ~ok:(fun ((_ : S.t), (_ : S.event list)) -> false)
    ~error:(err_text expect)
    (s_run ?closing chunks)

let s_close_rejects ?closing (chunks : string list) (expect : string) :
    bool =
  Result.fold
    ~ok:(fun ((s : S.t), (_ : S.event list)) ->
      Result.fold
        ~ok:(fun (() : unit) -> false)
        ~error:(err_text expect) (S.close s))
    ~error:(fun ((_ : E.t)) -> false)
    (s_run ?closing chunks)

(* ---------- chunk harness ---------- *)

let ok_chunk (s : string) (f : S.Chunk.t -> bool) : bool =
  Result.fold ~ok:f
    ~error:(fun ((_ : E.t)) -> false)
    (S.Chunk.of_string s)

let chunk_rejects (s : string) (expect : string) : bool =
  Result.fold
    ~ok:(fun ((_ : S.Chunk.t)) -> false)
    ~error:(err_text expect) (S.Chunk.of_string s)

let on_choice (s : string) (f : S.Chunk.Choice.t -> bool) : bool =
  ok_chunk s (fun c ->
      match S.Chunk.choices c with
      | [ ch ] -> f ch
      | [] | _ :: _ -> false)

let on_delta (s : string) (f : S.Chunk.Delta.t -> bool) : bool =
  on_choice s (fun ch -> f (S.Chunk.Choice.delta ch))

let raw_is (expect : string) (o : J.t option) : bool =
  Option.fold ~none:false
    ~some:(fun (v : J.t) -> String.equal (J.emit v) expect)
    o

let finish_eq (a : R.Finish.t) (b : R.Finish.t) : bool =
  match (a, b) with
  | R.Finish.Stop, R.Finish.Stop -> true
  | R.Finish.Length, R.Finish.Length -> true
  | R.Finish.Tool_calls, R.Finish.Tool_calls -> true
  | R.Finish.Stop, (R.Finish.Length | R.Finish.Tool_calls)
  | R.Finish.Length, (R.Finish.Stop | R.Finish.Tool_calls)
  | R.Finish.Tool_calls, (R.Finish.Stop | R.Finish.Length) -> false

let stop_eq (a : R.Stop_reason.t) (b : R.Stop_reason.t) : bool =
  match (a, b) with
  | R.Stop_reason.Stop, R.Stop_reason.Stop -> true
  | R.Stop_reason.Length, R.Stop_reason.Length -> true
  | R.Stop_reason.Stop, R.Stop_reason.Length
  | R.Stop_reason.Length, R.Stop_reason.Stop -> false

(* Fixture builders: the minimal valid floor with pluggable extra
   members, written without spaces so raw slices byte-match
   Jsonx.emit output. *)

let chunk_doc (rest : string) : string =
  {|{"id":"i","model":"m","created":1,"object":"chat.completion.chunk"|}
  ^ rest ^ "}"

let with_choice (choice : string) : string =
  chunk_doc ({|,"choices":[|} ^ choice ^ "]")

let ok_usage : string =
  {|{"completion_tokens":1,"prompt_tokens":2,"total_tokens":3}|}

(* ---------- granularity differential (A10) ---------- *)

let explode (s : string) : string list =
  List.rev
    (String.fold_left
       (fun acc (c : char) -> String.make 1 c :: acc)
       [] s)

let close_text (m : S.Machine.t) : string =
  Result.fold
    ~ok:(fun (() : unit) -> "closed")
    ~error:E.to_string (S.Machine.close m)

(* The whole observable outcome rendered to one string: events,
   pending_bytes, pending_cr, close result by Errx.to_string. The
   comparison never touches a Machine.t with polymorphic equality. *)
let outcome ?max_line_bytes ?max_event_bytes (chunks : string list) :
    string =
  Result.fold
    ~ok:(fun ((m : S.Machine.t), (evs : string list)) ->
      "ok|" ^ String.concat "\x01" evs ^ "|"
      ^ string_of_int (S.pending_bytes m)
      ^ "|"
      ^ Bool.to_string (S.pending_cr m)
      ^ "|" ^ close_text m)
    ~error:(fun (e : E.t) -> "err|" ^ E.to_string e)
    (m_run ?max_line_bytes ?max_event_bytes chunks)

let differential ?max_line_bytes ?max_event_bytes (s : string) : bool =
  String.equal
    (outcome ?max_line_bytes ?max_event_bytes [ s ])
    (outcome ?max_line_bytes ?max_event_bytes (explode s))

let corpus : (string * string) list =
  [ ("lf", "data: a\n\n");
    ("crlf", "data: a\r\n\r\n");
    ("mixed join", "data: a\r\ndata: b\n\n");
    ("bom", "\xEF\xBB\xBFdata: x\n\n");
    ("false bom prefix", "\xEF\xBBdata: hi\n\ndata: yo\n\n");
    ("held ef", "\xEF");
    ("held ef bb", "\xEF\xBB");
    ("field zoo", ": c\nevent: e\nid: 1\nretry: 5\nzeta: y\ndata\ndata: z\n\n");
    ("pending cr", "data: x\r");
    ("bare cr", "data: x\rZ");
    ("empty payload", "data:\n\n");
    ("blank lines", "\n\n\n");
    ("done payload", "data: [DONE]\n\n");
    ("partial line", "data: par");
    ("undispatched data", "data: x\n");
    ("mid-stream bom bytes", "data: x\n\n\xEF\xBB\xBFdata: y\n\n") ]

let capped : (string * int * int * string) list =
  [ ("line cap flood", 8, 4_194_304, String.make 100 'x');
    ("replayed bom cap", 3, 4_194_304, "\xEF\xBBab");
    ("event cap flood", 1_048_576, 3, "data: abc\n");
    ("line at cap", 7, 4_194_304, "data: x\n\n") ]

let differential_checks : (string * bool) list =
  List.map
    (fun ((n : string), (s : string)) ->
      ("differential " ^ n, differential s))
    corpus
  @ List.map
      (fun ((n : string), (ml : int), (me : int), (s : string)) ->
        ( "differential " ^ n,
          differential ~max_line_bytes:ml ~max_event_bytes:me s ))
      capped

let checks : (string * bool) list =
  [ (* framing: terminators *)
    ("LF events dispatch",
     m_events_close_ok [ "data: a\n\ndata: b\n\n" ] [ "a"; "b" ]);
    ("CRLF events dispatch",
     m_events_close_ok [ "data: a\r\n\r\n" ] [ "a" ]);
    ("mixed CRLF and LF join one event",
     m_events_close_ok [ "data: a\r\ndata: b\n\n" ] [ "a\nb" ]);
    ("CRLF split across feeds dispatches once",
     m_events_close_ok [ "data: a\r"; "\n\r"; "\n" ] [ "a" ]);
    ("bare CR mid-feed rejects",
     m_feed_rejects [ "data: x\rZ" ] "sse: bare CR");
    ("machine close rejects a pending CR",
     m_close_rejects [ "data: x\r" ] "sse: close: pending CR");
    ("empty feed is a no-op", m_events_close_ok [ "" ] []);
    (* framing: fields *)
    ("comment lines are ignored",
     m_events_close_ok [ ": hello\ndata: x\n\n" ] [ "x" ]);
    ("event id retry and unknown fields are ignored",
     m_events_close_ok
       [ "event: e\nid: 1\nretry: 7\nzeta: q\ndata: x\n\n" ]
       [ "x" ]);
    ("field names are case-sensitive",
     m_events_close_ok [ "Data: x\n\n" ] []);
    ("no-colon data line appends the empty value",
     m_events_close_ok [ "data\n\n" ] [ "" ]);
    ("exactly one leading space strips",
     m_events_close_ok [ "data:  two\n\n" ] [ " two" ]);
    ("no leading space is fine",
     m_events_close_ok [ "data:x\n\n" ] [ "x" ]);
    ("multi-line data joins with LF",
     m_events_close_ok [ "data: a\ndata: b\n\n" ] [ "a\nb" ]);
    ("blank line with empty buffer dispatches nothing",
     m_events_close_ok [ "\n\n: c\n\n" ] []);
    ("data colon alone dispatches the empty payload",
     m_events_close_ok [ "data:\n\n" ] [ "" ]);
    (* framing: BOM *)
    ("leading BOM strips once",
     m_events_close_ok [ "\xEF\xBB\xBFdata: x\n\n" ] [ "x" ]);
    ("split BOM strips across feeds",
     m_events_close_ok [ "\xEF"; "\xBB"; "\xBFdata: x\n\n" ] [ "x" ]);
    ("false BOM prefix replays as line content",
     m_events_close_ok
       [ "\xEF\xBBdata: hi\n\ndata: yo\n\n" ]
       [ "yo" ]);
    ("BOM bytes mid-stream are ordinary content",
     m_events_close_ok [ "data: x\n\n\xEF\xBB\xBFdata: y\n\n" ] [ "x" ]);
    ("close after a lone EF rejects",
     m_close_rejects [ "\xEF" ] "sse: close: held BOM prefix pending");
    ("close after EF BB rejects",
     m_close_rejects [ "\xEF\xBB" ] "sse: close: held BOM prefix pending");
    ("split BOM prefix is held and counted",
     Result.fold
       ~ok:(fun (m0 : S.Machine.t) ->
         Result.fold
           ~ok:(fun ((m1 : S.Machine.t), (e1 : string list)) ->
             List.equal String.equal e1 []
             && Int.equal (S.pending_bytes m1) 1
             && Result.fold
                  ~ok:(fun ((m2 : S.Machine.t), (_ : string list)) ->
                    Int.equal (S.pending_bytes m2) 2
                    && not (S.pending_cr m2))
                  ~error:(fun ((_ : E.t)) -> false)
                  (S.Machine.feed m1 "\xBB"))
           ~error:(fun ((_ : E.t)) -> false)
           (S.Machine.feed m0 "\xEF"))
       ~error:(fun ((_ : E.t)) -> false)
       (S.Machine.make ()));
    ("replayed BOM prefix bytes count toward the line cap",
     m_feed_rejects ~max_line_bytes:3 [ "\xEF\xBB"; "ab" ]
       "sse: line exceeds max_line_bytes"
     && m_feed_rejects ~max_line_bytes:3 [ "\xEF\xBBab" ]
          "sse: line exceeds max_line_bytes");
    (* framing: bounds *)
    ("line at cap passes",
     m_events_close_ok ~max_line_bytes:7 [ "data: x\n\n" ] [ "x" ]);
    ("line over cap rejects",
     m_feed_rejects ~max_line_bytes:7 [ "data: xy\n\n" ]
       "sse: line exceeds max_line_bytes");
    ("event at cap passes",
     m_events_close_ok ~max_event_bytes:4 [ "data: abc\n\n" ] [ "abc" ]);
    ("event over cap rejects during accumulation",
     m_feed_rejects ~max_event_bytes:3 [ "data: abc\n" ]
       "sse: event exceeds max_event_bytes");
    ("multi-line event over cap rejects during accumulation",
     m_feed_rejects ~max_event_bytes:4 [ "data: ab\ndata: c\n" ]
       "sse: event exceeds max_event_bytes");
    ("terminator-free flood rejects at the line cap",
     m_feed_rejects ~max_line_bytes:8
       [ String.make 100 'x' ]
       "sse: line exceeds max_line_bytes");
    ("make rejects a zero line cap",
     Result.fold
       ~ok:(fun ((_ : S.Machine.t)) -> false)
       ~error:(err_text "sse: max_line_bytes: not positive")
       (S.Machine.make ~max_line_bytes:0 ()));
    ("make rejects a zero event cap",
     Result.fold
       ~ok:(fun ((_ : S.Machine.t)) -> false)
       ~error:(err_text "sse: max_event_bytes: not positive")
       (S.Machine.make ~max_event_bytes:0 ()));
    ("discipline make validates the caps",
     Result.fold
       ~ok:(fun ((_ : S.t)) -> false)
       ~error:(err_text "sse: max_line_bytes: not positive")
       (S.make ~max_line_bytes:0 ()));
    (* discipline *)
    ("require-done stream closes after DONE",
     s_events_close_ok
       [ "data: a\n\ndata: [DONE]\n\n" ]
       [ S.Data "a"; S.Done ]);
    ("DONE without a space matches",
     s_events_close_ok [ "data:[DONE]\n\n" ] [ S.Done ]);
    ("multi-line DONE join stays data",
     s_events [ "data: [DO\ndata: NE]\n\n" ] [ S.Data "[DO\nNE]" ]);
    ("two-space DONE stays data",
     s_events [ "data:  [DONE]\n\n" ] [ S.Data " [DONE]" ]);
    ("payload after DONE rejects",
     s_feed_rejects
       [ "data: [DONE]\n\ndata: x\n\n" ]
       "sse: event after [DONE]");
    ("second DONE rejects",
     s_feed_rejects
       [ "data: [DONE]\n\n"; "data: [DONE]\n\n" ]
       "sse: event after [DONE]");
    ("comment and blank lines after DONE are fine",
     s_events_close_ok
       [ "data: [DONE]\n\n: bye\nevent: x\n\n" ]
       [ S.Done ]);
    ("trailing partial line after DONE rejects at close",
     s_close_rejects
       [ "data: [DONE]\n\ndata: x" ]
       "sse: close: partial line pending");
    ("close before DONE carries the last payload",
     s_close_rejects [ "data: hello\n\n" ]
       "sse: close before [DONE]; last payload: hello");
    ("close before DONE with no payload seen",
     Result.fold
       ~ok:(fun (s : S.t) ->
         Result.fold
           ~ok:(fun (() : unit) -> false)
           ~error:
             (err_text "sse: close before [DONE]; no payload seen")
           (S.close s))
       ~error:(fun ((_ : E.t)) -> false)
       (S.make ()));
    ("truncation error keeps the server-error payload",
     s_close_rejects
       [ "data: {\"error\":\"boom\"}\n\ndata: par" ]
       "sse: close: partial line pending; last payload: {\"error\":\"boom\"}");
    ("last payload note stops at 200 bytes",
     s_close_rejects
       [ "data: " ^ String.make 250 'z' ^ "\n\ndata: par" ]
       ("sse: close: partial line pending; last payload: "
       ^ String.make 200 'z'));
    ("allow-eof close after clean EOF passes",
     s_events_close_ok ~closing:S.Allow_eof [ "data: a\n\n" ]
       [ S.Data "a" ]);
    ("allow-eof close with zero payloads passes",
     s_events_close_ok ~closing:S.Allow_eof [ "" ] []);
    ("allow-eof still rejects a partial line",
     s_close_rejects ~closing:S.Allow_eof
       [ "data: a\n\ndata: par" ]
       "sse: close: partial line pending; last payload: a");
    ("allow-eof still rejects undispatched data",
     s_close_rejects ~closing:S.Allow_eof [ "data: x\n" ]
       "sse: close: undispatched data pending; no payload seen");
    ("machine close rejects undispatched data",
     m_close_rejects [ "data: x\n" ]
       "sse: close: undispatched data pending");
    ("machine close rejects a partial line",
     m_close_rejects [ "data: pa" ] "sse: close: partial line pending");
    ("e2ee hex payload passes framing as data",
     s_events [ "data: 04a1b2c3d4\n\n" ] [ S.Data "04a1b2c3d4" ]);
    (* chunk: floor *)
    ("minimal chunk parses with the empty delta",
     on_choice (with_choice {|{"index":0,"delta":{}}|}) (fun ch ->
         Int.equal (S.Chunk.Choice.index ch) 0
         && (let d = S.Chunk.Choice.delta ch in
             Option.is_none (S.Chunk.Delta.role d)
             && Option.is_none (S.Chunk.Delta.content d)
             && Option.is_none (S.Chunk.Delta.reasoning_content d)
             && List.equal
                  (fun (a : J.t) (b : J.t) ->
                    String.equal (J.emit a) (J.emit b))
                  (S.Chunk.Delta.tool_calls_raw d)
                  [])
         && Option.is_none (S.Chunk.Choice.finish_reason_raw ch)
         && Option.is_none (S.Chunk.Choice.stop_reason_raw ch)));
    ("document accessors read the floor members",
     ok_chunk (with_choice {|{"index":0,"delta":{}}|}) (fun c ->
         String.equal (S.Chunk.id c) "i"
         && String.equal (S.Chunk.model c) "m"
         && Int.equal (S.Chunk.created c) 1));
    ("server error payload surfaces bounded",
     chunk_rejects {|{"error":"boom"}|}
       {|chunk: server error: {"error":"boom"}|});
    ("provider error object rides the same channel",
     chunk_rejects {|{"error":{"message":"m"}}|}
       {|chunk: server error: {"error":{"message":"m"}}|});
    ("server error render stops at 200 bytes",
     chunk_rejects
       ({|{"error":"|} ^ String.make 300 'b' ^ {|"}|})
       ("chunk: server error: " ^ {|{"error":"|} ^ String.make 190 'b'));
    ("wrong object rejects",
     chunk_rejects
       {|{"id":"i","model":"m","created":1,"object":"chat.completion"}|}
       "chunk: object: not chat.completion.chunk");
    ("missing object rejects",
     chunk_rejects {|{"id":"i","model":"m","created":1}|}
       "chunk: object: missing");
    ("missing id rejects",
     chunk_rejects
       {|{"model":"m","created":1,"object":"chat.completion.chunk"}|}
       "chunk: id: missing");
    ("missing model rejects",
     chunk_rejects
       {|{"id":"i","created":1,"object":"chat.completion.chunk"}|}
       "chunk: model: missing");
    ("missing created rejects",
     chunk_rejects
       {|{"id":"i","model":"m","object":"chat.completion.chunk"}|}
       "chunk: created: missing");
    ("negative created rejects",
     chunk_rejects
       {|{"id":"i","model":"m","created":-1,"object":"chat.completion.chunk"}|}
       "chunk: created: negative");
    ("non-object payload rejects",
     chunk_rejects "[1]" "chunk: not a JSON object");
    ("empty payload is a json-domain error",
     Result.fold
       ~ok:(fun ((_ : S.Chunk.t)) -> false)
       ~error:(fun (e : E.t) ->
         String.starts_with ~prefix:"json: " (E.to_string e))
       (S.Chunk.of_string ""));
    ("choices non-array rejects",
     chunk_rejects (chunk_doc {|,"choices":5|})
       "chunk: choices: not an array");
    ("choice non-object rejects with its path",
     chunk_rejects (with_choice "5") "chunk: choices[0]: not an object");
    ("choice index missing rejects",
     chunk_rejects (with_choice {|{"delta":{}}|})
       "chunk: choices[0].index: missing");
    ("choice index negative rejects",
     chunk_rejects (with_choice {|{"index":-1,"delta":{}}|})
       "chunk: choices[0].index: negative");
    (* chunk: delta tolerance (A6) *)
    ("delta absent reads the empty delta",
     on_delta (with_choice {|{"index":0}|}) (fun d ->
         Option.is_none (S.Chunk.Delta.role d)
         && Option.is_none (S.Chunk.Delta.content d)));
    ("delta null reads the empty delta",
     on_delta (with_choice {|{"index":0,"delta":null}|}) (fun d ->
         Option.is_none (S.Chunk.Delta.content d)));
    ("delta foreign value rejects the document",
     chunk_rejects (with_choice {|{"index":0,"delta":5}|})
       "chunk: choices[0].delta: not an object");
    (* chunk: null parity (A13) *)
    ("chunk choices null reads the empty list",
     ok_chunk (chunk_doc {|,"choices":null|}) (fun c ->
         match S.Chunk.choices c with
         | [] -> true
         | _ :: _ -> false));
    ("chunk usage null reads none",
     ok_chunk (chunk_doc {|,"usage":null|}) (fun c ->
         Option.is_none (S.Chunk.usage_opt c)));
    ("delta content null reads none",
     on_delta
       (with_choice {|{"index":0,"delta":{"content":null}}|})
       (fun d -> Option.is_none (S.Chunk.Delta.content d)));
    ("delta tool_calls null member reads the empty list",
     on_delta
       (with_choice {|{"index":0,"delta":{"tool_calls":null}}|})
       (fun d ->
         match S.Chunk.Delta.tool_calls_raw d with
         | [] -> true
         | _ :: _ -> false));
    ("delta tool_calls null item keeps raw and fails the fragment view",
     on_delta
       (with_choice {|{"index":0,"delta":{"tool_calls":[null]}}|})
       (fun d ->
         (match S.Chunk.Delta.tool_calls_raw d with
          | [ J.Jnull ] -> true
          | [] | _ :: _ -> false)
         && Result.fold
              ~ok:(fun ((_ : S.Chunk.Delta.fragment list)) -> false)
              ~error:
                (err_text
                   "chunk: choices[0].delta.tool_calls[0]: not an object")
              (S.Chunk.Delta.tool_call_fragments d)));
    ("chunk stop_reason null reads none",
     on_choice
       (with_choice {|{"index":0,"delta":{},"stop_reason":null}|})
       (fun ch ->
         Option.is_none (S.Chunk.Choice.stop_reason_raw ch)
         && Result.fold
              ~ok:(fun (o : R.Stop_reason.t option) -> Option.is_none o)
              ~error:(fun ((_ : E.t)) -> false)
              (S.Chunk.Choice.stop_reason ch)));
    (* chunk: raw + typed views (A3) *)
    ("finish_reason stop reads through the typed view",
     on_choice
       (with_choice {|{"index":0,"delta":{},"finish_reason":"stop"}|})
       (fun ch ->
         raw_is {|"stop"|} (S.Chunk.Choice.finish_reason_raw ch)
         && Result.fold
              ~ok:(fun (o : R.Finish.t option) ->
                Option.fold ~none:false
                  ~some:(fun (f : R.Finish.t) ->
                    finish_eq f R.Finish.Stop)
                  o)
              ~error:(fun ((_ : E.t)) -> false)
              (S.Chunk.Choice.finish ch)));
    ("stop_reason stop reads through the typed view",
     on_choice
       (with_choice {|{"index":0,"delta":{},"stop_reason":"stop"}|})
       (fun ch ->
         Result.fold
           ~ok:(fun (o : R.Stop_reason.t option) ->
             Option.fold ~none:false
               ~some:(fun (s : R.Stop_reason.t) ->
                 stop_eq s R.Stop_reason.Stop)
               o)
           ~error:(fun ((_ : E.t)) -> false)
           (S.Chunk.Choice.stop_reason ch)));
    ("foreign finish_reason keeps raw and fails the view only",
     on_choice
       (with_choice {|{"index":0,"delta":{},"finish_reason":"banana"}|})
       (fun ch ->
         raw_is {|"banana"|} (S.Chunk.Choice.finish_reason_raw ch)
         && Result.fold
              ~ok:(fun ((_ : R.Finish.t option)) -> false)
              ~error:
                (err_text
                   "chunk: choices[0].finish_reason: unknown value banana")
              (S.Chunk.Choice.finish ch)));
    ("non-string finish_reason fails the view only",
     on_choice
       (with_choice {|{"index":0,"delta":{},"finish_reason":7}|})
       (fun ch ->
         raw_is "7" (S.Chunk.Choice.finish_reason_raw ch)
         && Result.fold
              ~ok:(fun ((_ : R.Finish.t option)) -> false)
              ~error:
                (err_text "chunk: choices[0].finish_reason: not a string")
              (S.Chunk.Choice.finish ch)));
    ("foreign stop_reason fails the view with its path",
     ok_chunk
       (chunk_doc
          ({|,"choices":[{"index":0,"delta":{}},{"index":1,"delta":{},"stop_reason":"banana"}]|}))
       (fun c ->
         match S.Chunk.choices c with
         | [ (_ : S.Chunk.Choice.t); ch ] ->
           Result.fold
             ~ok:(fun ((_ : R.Stop_reason.t option)) -> false)
             ~error:
               (err_text
                  "chunk: choices[1].stop_reason: unknown value banana")
             (S.Chunk.Choice.stop_reason ch)
         | [] | [ _ ] | _ :: _ :: _ :: _ -> false));
    (* chunk: usage via the A8 seam *)
    ("usage-only final chunk parses with empty choices",
     ok_chunk (chunk_doc ({|,"usage":|} ^ ok_usage)) (fun c ->
         (match S.Chunk.choices c with
          | [] -> true
          | _ :: _ -> false)
         && Option.fold ~none:false
              ~some:(fun (u : R.Usage.t) ->
                Int.equal (R.Usage.completion_tokens u) 1
                && Int.equal (R.Usage.prompt_tokens u) 2
                && Int.equal (R.Usage.total_tokens u) 3)
              (S.Chunk.usage_opt c)));
    ("usage errors carry the chunk domain not resp",
     chunk_rejects
       (chunk_doc
          {|,"usage":{"completion_tokens":-1,"prompt_tokens":1,"total_tokens":1}|})
       "chunk: usage: usage.completion_tokens: negative");
    (* chunk: delta members *)
    ("role and empty content read faithfully",
     on_delta
       (with_choice
          {|{"index":0,"delta":{"role":"assistant","content":""}}|})
       (fun d ->
         opt_str_eq (S.Chunk.Delta.role d) (Some "assistant")
         && opt_str_eq (S.Chunk.Delta.content d) (Some "")));
    ("content piece reads",
     on_delta (with_choice {|{"index":0,"delta":{"content":"he"}}|})
       (fun d -> opt_str_eq (S.Chunk.Delta.content d) (Some "he")));
    ("reasoning_content reads",
     on_delta
       (with_choice {|{"index":0,"delta":{"reasoning_content":"th"}}|})
       (fun d ->
         opt_str_eq (S.Chunk.Delta.reasoning_content d) (Some "th")));
    ("delta content non-string rejects the document",
     chunk_rejects
       (with_choice {|{"index":0,"delta":{"content":5}}|})
       "chunk: choices[0].delta.content: not a string");
    ("unknown members tolerated everywhere",
     on_delta
       (chunk_doc
          {|,"zeta":1,"choices":[{"index":0,"eta":2,"delta":{"theta":3,"content":"x"}}]|})
       (fun d -> opt_str_eq (S.Chunk.Delta.content d) (Some "x")));
    (* chunk: tool-call fragments (D10) *)
    ("tool_call fragment view positive",
     on_delta
       (with_choice
          {|{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"f","arguments":"{\"a\""}}]}}|})
       (fun d ->
         Result.fold
           ~ok:(fun (fs : S.Chunk.Delta.fragment list) ->
             match fs with
             | [ f ] ->
               Int.equal (S.Chunk.Delta.fragment_index f) 0
               && opt_str_eq (S.Chunk.Delta.fragment_id f) (Some "c1")
               && opt_str_eq (S.Chunk.Delta.fragment_name f) (Some "f")
               && opt_str_eq
                    (S.Chunk.Delta.fragment_arguments f)
                    (Some {|{"a"|})
               && String.equal
                    (J.emit (S.Chunk.Delta.fragment_raw f))
                    {|{"index":0,"id":"c1","type":"function","function":{"name":"f","arguments":"{\"a\""}}|}
             | [] | _ :: _ -> false)
           ~error:(fun ((_ : E.t)) -> false)
           (S.Chunk.Delta.tool_call_fragments d)));
    ("fragment without index fails with the exact path",
     on_delta
       (with_choice
          {|{"index":0,"delta":{"tool_calls":[{"id":"c1"}]}}|})
       (fun d ->
         List.equal
           (fun (a : J.t) (b : J.t) ->
             String.equal (J.emit a) (J.emit b))
           (S.Chunk.Delta.tool_calls_raw d)
           [ J.Jobj [ ("id", J.Jstring "c1") ] ]
         && Result.fold
              ~ok:(fun ((_ : S.Chunk.Delta.fragment list)) -> false)
              ~error:
                (err_text
                   "chunk: choices[0].delta.tool_calls[0].index: missing")
              (S.Chunk.Delta.tool_call_fragments d)));
    ("fragment function non-object fails with the exact path",
     on_delta
       (with_choice
          {|{"index":0,"delta":{"tool_calls":[{"index":0,"function":5}]}}|})
       (fun d ->
         Result.fold
           ~ok:(fun ((_ : S.Chunk.Delta.fragment list)) -> false)
           ~error:
             (err_text
                "chunk: choices[0].delta.tool_calls[0].function: not an object")
           (S.Chunk.Delta.tool_call_fragments d)));
    ("tool_calls non-array member rejects the document",
     chunk_rejects
       (with_choice {|{"index":0,"delta":{"tool_calls":"x"}}|})
       "chunk: choices[0].delta.tool_calls: not an array")
  ]

let () = run (checks @ differential_checks)
