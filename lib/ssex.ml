(* M11 streaming, sans-io, three layers in one module (D1). Machine:
   incremental WHATWG-profile framing, bytes in, dispatched
   data-payload strings out. The top-level discipline: the public
   face, payloads classified into Data | Done ([DONE] sentinel), the
   after-[DONE] and close disciplines. Chunk: the
   chat.completion.chunk parse applied to one Data payload string.
   E2EE (M32) reuses Machine + the discipline unchanged (its payloads
   are hex ciphertext, never assumed JSON); effects (M14 streamx)
   drive the discipline + Chunk from the host layer. Pure and total:
   no IO, no effects, no exceptions, no mutation. *)

let ( let* ) = Result.bind

(* Bounded render of a payload: the first 200 bytes. Used for the
   last-payload retention (A5b) and the server-error channel (A5a).
   Bytesx.take yields the window only when the whole window exists, so
   a short payload falls back to itself. *)
let prefix200 (p : string) : string =
  Option.value ~default:p (Bytesx.take p 0 200)

module Machine = struct
  (* WHATWG event-stream framing, incremental (feed/close), bounded,
     granularity-independent: byte-at-a-time feeding and one-shot
     feeding reach the same events and the same terminal state (the
     A10 differential pins it). Strictness narrower than the spec
     (D2): CRLF and LF terminate lines; a bare CR (CR followed by
     anything but LF, or a CR pending at close) rejects, because
     lone-CR terminators are a parser-disagreement smuggling vector.
     One leading UTF-8 BOM strips at stream start, split-safe: a 1-2
     byte prefix of the BOM waits for the next feed, and a prefix
     that then mismatches replays the held bytes as ordinary content,
     counting toward the line cap of the line they land in exactly as
     one-shot (A11). event/id/retry and unknown fields are ignored
     (D4: a request-scoped completion stream has no reconnection
     machinery). UTF-8 is NOT validated here: payload consumers own
     it (jsonx for chunks, hexx for E2EE).

     Bounds (D6): max_line_bytes counts one line's bytes excluding
     terminators; max_event_bytes counts the accumulated data buffer,
     joined LFs included. Both are enforced DURING accumulation, so a
     terminator-free flood rejects at the cap instead of buffering;
     at-cap exactly passes. The scan converts each feed once via
     List.of_seq (String.to_seq s) and consumes it head-first (A9);
     the transient char list costs ~16x the feed's bytes in memory,
     which the caps keep bounded. Bytesx.u8/take are banned inside
     the scan loop: both are O(offset) via Seq.drop, so per-index
     scanning would be quadratic. Pieces rebuild at line end via
     String.of_seq / String.concat, never per byte. *)

  type bom =
    | Held of string
    | Resolved

  type t =
    { max_line : int;
      max_event : int;
      bom : bom;
      cr : bool;
      line_rev : string list;
      line_len : int;
      data_rev : string list;
      data_len : int }

  let invalid (msg : string) : ('a, Errx.t) result =
    Error (Errx.Sse_invalid msg)

  let make ?(max_line_bytes = 1_048_576) ?(max_event_bytes = 4_194_304)
      (() : unit) : (t, Errx.t) result =
    match () with
    | () when max_line_bytes < 1 -> invalid "max_line_bytes: not positive"
    | () when max_event_bytes < 1 ->
      invalid "max_event_bytes: not positive"
    | () ->
      Ok
        { max_line = max_line_bytes;
          max_event = max_event_bytes;
          bom = Held "";
          cr = false;
          line_rev = [];
          line_len = 0;
          data_rev = [];
          data_len = 0 }

  (* The current feed's line chars fold into one piece at feed end or
     line end; only non-empty pieces are kept, so line_len > 0 is the
     one partial-line test. *)
  let flush (lacc : char list) (line_rev : string list) : string list =
    match lacc with
    | [] -> line_rev
    | (_ : char) :: (_ : char list) ->
      String.of_seq (List.to_seq (List.rev lacc)) :: line_rev

  let strip_one_space (cs : char list) : char list =
    match cs with
    | ' ' :: tail -> tail
    | other -> other

  (* First-colon split (D4): name before the first ':', value after
     with exactly one leading SPACE stripped; a line with no colon is
     a field name with empty value. Tail recursive. *)
  let split_field (cs : char list) : string * string =
    let rec walk (nacc : char list) (rest : char list) : string * string =
      match rest with
      | [] -> (String.of_seq (List.to_seq (List.rev nacc)), "")
      | ':' :: tail ->
        ( String.of_seq (List.to_seq (List.rev nacc)),
          String.of_seq (List.to_seq (strip_one_space tail)) )
      | c :: tail -> walk (c :: nacc) tail
    in
    walk [] cs

  (* One completed line. Blank line dispatches: the spec's step-2
     emptiness test runs BEFORE the step-3 LF strip, so an empty data
     buffer dispatches nothing while "data:" alone (buffer "\n")
     dispatches "". The buffer holds the data values reversed and the
     dispatch joins them with LF, which is exactly append-value+LF
     then strip-one-trailing-LF; data_len counts value bytes plus one
     LF each, the spec's buffer length. Comment lines and non-data
     fields (event/id/retry included) are ignored. *)
  let line_step (max_event : int) (line : string)
      (data_rev : string list) (data_len : int) (evs_rev : string list) :
      (string list * int * string list, Errx.t) result =
    match List.of_seq (String.to_seq line) with
    | [] ->
      if Int.equal data_len 0 then Ok (data_rev, data_len, evs_rev)
      else Ok ([], 0, String.concat "\n" (List.rev data_rev) :: evs_rev)
    | ':' :: (_ : char list) -> Ok (data_rev, data_len, evs_rev)
    | (_ :: _) as cs ->
      let name, value = split_field cs in
      let grown = data_len + String.length value + 1 in
      (match () with
       | () when not (String.equal name "data") ->
         Ok (data_rev, data_len, evs_rev)
       | () when grown > max_event ->
         invalid "event exceeds max_event_bytes"
       | () -> Ok (value :: data_rev, grown, evs_rev))

  let bom_bytes (() : unit) : string = "\xEF\xBB\xBF"

  (* Errors are terminal by contract (D7): the old t is still a
     value, feeding it again is caller misuse. Empty feed is a
     no-op. *)
  let feed (m : t) (input : string) : (t * string list, Errx.t) result =
    let rec go (bom : bom) (cr : bool) (line_rev : string list)
        (line_len : int) (lacc : char list) (data_rev : string list)
        (data_len : int) (evs_rev : string list) (cs : char list) :
        (t * string list, Errx.t) result =
      match cs with
      | [] ->
        Ok
          ( { m with
              bom;
              cr;
              line_rev = flush lacc line_rev;
              line_len;
              data_rev;
              data_len },
            List.rev evs_rev )
      | c :: rest ->
        (match bom with
         | Held held ->
           let cand = held ^ String.make 1 c in
           (match () with
            | () when String.equal cand (bom_bytes ()) ->
              go Resolved cr line_rev line_len lacc data_rev data_len
                evs_rev rest
            | () when
                String.equal cand "\xEF" || String.equal cand "\xEF\xBB"
              ->
              go (Held cand) cr line_rev line_len lacc data_rev data_len
                evs_rev rest
            | () ->
              go Resolved cr line_rev line_len lacc data_rev data_len
                evs_rev
                (List.of_seq (String.to_seq cand) @ rest))
         | Resolved ->
           (match () with
            | () when cr ->
              if Char.equal c '\n' then
                line_end line_rev lacc data_rev data_len evs_rev rest
              else invalid "bare CR"
            | () when Char.equal c '\r' ->
              go Resolved true line_rev line_len lacc data_rev data_len
                evs_rev rest
            | () when Char.equal c '\n' ->
              line_end line_rev lacc data_rev data_len evs_rev rest
            | () when line_len + 1 > m.max_line ->
              invalid "line exceeds max_line_bytes"
            | () ->
              go Resolved cr line_rev (line_len + 1) (c :: lacc) data_rev
                data_len evs_rev rest))
    and line_end (line_rev : string list) (lacc : char list)
        (data_rev : string list) (data_len : int)
        (evs_rev : string list) (rest : char list) :
        (t * string list, Errx.t) result =
      let line = String.concat "" (List.rev (flush lacc line_rev)) in
      let* data_rev', data_len', evs_rev' =
        line_step m.max_event line data_rev data_len evs_rev
      in
      go Resolved false [] 0 [] data_rev' data_len' evs_rev' rest
    in
    go m.bom m.cr m.line_rev m.line_len [] m.data_rev m.data_len []
      (List.of_seq (String.to_seq input))

  let held_len (b : bom) : int =
    match b with
    | Held h -> String.length h
    | Resolved -> 0

  (* Truncation detection (D7 + A11): the spec DISCARDS pending data
     at EOF, we reject instead. The four residues: pending CR, held
     BOM-prefix bytes, partial line, un-dispatched data. *)
  let close (m : t) : (unit, Errx.t) result =
    match () with
    | () when m.cr -> invalid "close: pending CR"
    | () when held_len m.bom > 0 -> invalid "close: held BOM prefix pending"
    | () when m.line_len > 0 -> invalid "close: partial line pending"
    | () when m.data_len > 0 -> invalid "close: undispatched data pending"
    | () -> Ok ()

  (* Test seams (A10): the byte-granularity differential compares
     these projections, never machines themselves (the reversed-piece
     representation is granularity-dependent by construction). *)
  let pending_bytes (m : t) : int =
    m.line_len + held_len m.bom + m.data_len

  let pending_cr (m : t) : bool = m.cr
end

(* ---------- the Venice discipline (D8, A4, A12) ---------- *)

type event =
  | Data of string
  | Done

type closing =
  | Require_done
  | Allow_eof

type phase =
  | Streaming
  | Terminated

type t =
  { machine : Machine.t;
    closing : closing;
    phase : phase;
    last : string option }

let make ?(closing = Require_done) ?max_line_bytes ?max_event_bytes
    (() : unit) : (t, Errx.t) result =
  Result.map
    (fun (machine : Machine.t) ->
      { machine; closing; phase = Streaming; last = None })
    (Machine.make ?max_line_bytes ?max_event_bytes ())

(* A payload equal to "[DONE]" (exact match after the one-space
   strip) becomes Done; ANY dispatched payload after Done, a second
   [DONE] included, rejects. Comments, ignored fields and blank lines
   after Done dispatch nothing and stay fine. A 200-byte prefix of
   the last payload is retained for the close-before-Done error
   (A5b), so a truncation error can never mask the server error that
   preceded it. *)
let classify
    (acc : (phase * string option * event list, Errx.t) result)
    (payload : string) :
    (phase * string option * event list, Errx.t) result =
  Result.bind acc
    (fun
        (((phase : phase), ((_ : string option)), (evs_rev : event list)))
      ->
      let last = Some (prefix200 payload) in
      match phase with
      | Terminated -> Error (Errx.Sse_invalid "event after [DONE]")
      | Streaming ->
        if String.equal payload "[DONE]" then
          Ok (Terminated, last, Done :: evs_rev)
        else Ok (Streaming, last, Data payload :: evs_rev))

let feed (s : t) (input : string) : (t * event list, Errx.t) result =
  let* machine, payloads = Machine.feed s.machine input in
  Result.map
    (fun
        (((phase : phase), (last : string option), (evs_rev : event list)))
      -> ({ s with machine; phase; last }, List.rev evs_rev))
    (List.fold_left classify (Ok (s.phase, s.last, [])) payloads)

let last_note (last : string option) : string =
  Option.fold ~none:"; no payload seen"
    ~some:(fun (p : string) -> "; last payload: " ^ p)
    last

let with_last (last : string option) (e : Errx.t) : Errx.t =
  match e with
  | Errx.Sse_invalid msg -> Errx.Sse_invalid (msg ^ last_note last)
  | Errx.Hex_invalid _ | Errx.B64_invalid _ | Errx.Json_invalid _
  | Errx.Model_invalid _ | Errx.Param_invalid _ | Errx.Msg_invalid _
  | Errx.Head_invalid _ | Errx.Chat_invalid _ | Errx.Resp_invalid _
  | Errx.Chunk_invalid _ | Errx.Key_invalid _ | Errx.Req_invalid _
  | Errx.Wire_invalid _ | Errx.Transport_failed _ ->
    e

(* Close policy (A4): Require_done (default) rejects a close before
   Done even over clean framing (a mid-completion cut is detectable
   even when the transport reports success); Allow_eof accepts a
   clean EOF after any number of payloads. Both reject the four
   Machine residues, and every before-Done rejection carries the
   last-payload prefix. *)
let close (s : t) : (unit, Errx.t) result =
  match s.phase with
  | Terminated -> Machine.close s.machine
  | Streaming ->
    (match s.closing with
     | Allow_eof ->
       Result.map_error (with_last s.last) (Machine.close s.machine)
     | Require_done ->
       Result.fold
         ~ok:(fun (() : unit) ->
           Error
             (Errx.Sse_invalid ("close before [DONE]" ^ last_note s.last)))
         ~error:(fun (e : Errx.t) -> Error (with_last s.last e))
         (Machine.close s.machine))

let pending_bytes (m : Machine.t) : int = Machine.pending_bytes m
let pending_cr (m : Machine.t) : bool = Machine.pending_cr m

(* ---------- the chunk document parse (D9-D10, A3, A5, A6) ---------- *)

module Chunk = struct
  (* One Data payload as a chat.completion.chunk document,
     all-or-nothing per chunk in the respx D8 tradition; unknown
     members tolerated everywhere. The WHOLE shape is the
     OpenAI-compat hypothesis (no Venice schema exists), so every
     strictness choice fails loudly naming the member, and the M2
     probe corrects from the error text alone. *)

  let invalid (msg : string) : ('a, Errx.t) result =
    Error (Errx.Chunk_invalid msg)

  let req_string (what : string) (o : Jsonx.t option) :
      (string, Errx.t) result =
    Option.fold
      ~none:(invalid (what ^ ": missing"))
      ~some:(fun (v : Jsonx.t) ->
        Option.fold
          ~none:(invalid (what ^ ": not a string"))
          ~some:Result.ok (Jsonx.as_string v))
      o

  (* Wire integer with the >= 0 floor; the floor is SDK-imposed
     strictness (no schema pins these at all), stated in the .mli
     ledger. *)
  let nat_of (what : string) (v : Jsonx.t) : (int, Errx.t) result =
    Option.fold
      ~none:(invalid (what ^ ": not an integer"))
      ~some:(fun (n : int) ->
        if n < 0 then invalid (what ^ ": negative") else Ok n)
      (Jsonx.as_int v)

  let req_nat (what : string) (o : Jsonx.t option) : (int, Errx.t) result =
    Option.fold ~none:(invalid (what ^ ": missing")) ~some:(nat_of what) o

  (* Absent and null collapse to None; a present value must be a
     string. content "" stays Some "" (faithful;
     concatenation-neutral). *)
  let opt_string (what : string) (o : Jsonx.t option) :
      (string option, Errx.t) result =
    Option.fold ~none:(Ok None)
      ~some:(fun (v : Jsonx.t) ->
        match v with
        | Jsonx.Jnull -> Ok None
        | Jsonx.Jstring s -> Ok (Some s)
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jlist _
        | Jsonx.Jobj _ ->
          invalid (what ^ ": not a string"))
      o

  (* Absent and null collapse to None; any other value is kept raw
     verbatim and never rejects the document (A3). *)
  let opt_raw (o : Jsonx.t option) : Jsonx.t option =
    Option.bind o (fun (v : Jsonx.t) ->
        match v with
        | Jsonx.Jnull -> None
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
        | Jsonx.Jlist _ | Jsonx.Jobj _ ->
          Some v)

  (* Absent and null collapse to []; ITEMS are held verbatim, a
     malformed item never rejects the document (the A2/M10a
     doctrine). *)
  let raw_items (what : string) (o : Jsonx.t option) :
      (Jsonx.t list, Errx.t) result =
    Option.fold ~none:(Ok [])
      ~some:(fun (v : Jsonx.t) ->
        match v with
        | Jsonx.Jnull -> Ok []
        | Jsonx.Jlist items -> Ok items
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
        | Jsonx.Jobj _ ->
          invalid (what ^ ": not an array"))
      o

  module Delta = struct
    (* Per-chunk tool-call fragment view (D10): the OpenAI-compat
       item hypothesis {index, id?, function: {name?, arguments?}},
       arguments a verbatim piece of a streamed JSON string.
       Cross-chunk accumulation into Msgx.Tool_call is DEFERRED to
       M14 (DESIGN.md M14 row); M11 ships the per-chunk view only. *)
    type fragment =
      { f_index : int;
        f_id : string option;
        f_name : string option;
        f_arguments : string option;
        f_raw : Jsonx.t }

    let fragment_index (f : fragment) : int = f.f_index
    let fragment_id (f : fragment) : string option = f.f_id
    let fragment_name (f : fragment) : string option = f.f_name
    let fragment_arguments (f : fragment) : string option = f.f_arguments
    let fragment_raw (f : fragment) : Jsonx.t = f.f_raw

    type t =
      { role : string option;
        content : string option;
        reasoning_content : string option;
        tool_calls_raw : Jsonx.t list;
        path : string }

    let role (d : t) : string option = d.role
    let content (d : t) : string option = d.content

    let reasoning_content (d : t) : string option = d.reasoning_content
    let tool_calls_raw (d : t) : Jsonx.t list = d.tool_calls_raw

    let function_of (at : string) (o : Jsonx.t option) :
        (string option * string option, Errx.t) result =
      Option.fold
        ~none:(Ok (None, None))
        ~some:(fun (v : Jsonx.t) ->
          match v with
          | Jsonx.Jnull -> Ok (None, None)
          | Jsonx.Jobj _ ->
            let* name =
              opt_string (at ^ ".function.name") (Jsonx.member "name" v)
            in
            let* arguments =
              opt_string
                (at ^ ".function.arguments")
                (Jsonx.member "arguments" v)
            in
            Ok (name, arguments)
          | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
          | Jsonx.Jlist _ ->
            invalid (at ^ ".function: not an object"))
        o

    let fragment_of (base : string) (j : int) (item : Jsonx.t) :
        (fragment, Errx.t) result =
      let at = base ^ "[" ^ string_of_int j ^ "]" in
      match item with
      | Jsonx.Jobj _ ->
        let* index = req_nat (at ^ ".index") (Jsonx.member "index" item) in
        let* id = opt_string (at ^ ".id") (Jsonx.member "id" item) in
        let* name, arguments =
          function_of at (Jsonx.member "function" item)
        in
        Ok { f_index = index; f_id = id; f_name = name;
             f_arguments = arguments; f_raw = item }
      | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _
      | Jsonx.Jstring _ | Jsonx.Jlist _ ->
        invalid (at ^ ": not an object")

    (* The typed view over tool_calls_raw; the first failing item
       wins and carries its choices[i].delta.tool_calls[j] path.
       Tail recursive: the array is untrusted wire input. *)
    let tool_call_fragments (d : t) : (fragment list, Errx.t) result =
      let base = d.path ^ ".tool_calls" in
      let rec go (j : int) (acc : fragment list) (rest : Jsonx.t list) :
          (fragment list, Errx.t) result =
        match rest with
        | [] -> Ok (List.rev acc)
        | item :: tl ->
          let* f = fragment_of base j item in
          go (j + 1) (f :: acc) tl
      in
      go 0 [] d.tool_calls_raw
  end

  (* Absent or null delta reads the EMPTY delta (A6): same
     absent-vs-null reasoning as the respx logprobs tolerance. *)
  let empty_delta (path : string) : Delta.t =
    { Delta.role = None;
      content = None;
      reasoning_content = None;
      tool_calls_raw = [];
      path }

  let delta_of (path : string) (o : Jsonx.t option) :
      (Delta.t, Errx.t) result =
    Option.fold
      ~none:(Ok (empty_delta path))
      ~some:(fun (v : Jsonx.t) ->
        match v with
        | Jsonx.Jnull -> Ok (empty_delta path)
        | Jsonx.Jobj _ ->
          let* role = opt_string (path ^ ".role") (Jsonx.member "role" v) in
          let* content =
            opt_string (path ^ ".content") (Jsonx.member "content" v)
          in
          let* reasoning_content =
            opt_string
              (path ^ ".reasoning_content")
              (Jsonx.member "reasoning_content" v)
          in
          let* tool_calls_raw =
            raw_items (path ^ ".tool_calls") (Jsonx.member "tool_calls" v)
          in
          Ok
            { Delta.role;
              content;
              reasoning_content;
              tool_calls_raw;
              path }
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
        | Jsonx.Jlist _ ->
          invalid (path ^ ": not an object"))
      o

  module Choice = struct
    (* One chunk choice: index + delta, finish_reason/stop_reason
       held raw (absent OR null -> None, a foreign value never
       rejects the document) with typed views that fail loudly (A3):
       the chunk has no schema, and a foreign value on the TERMINAL
       chunk must not destroy the end-of-turn signal. *)
    type t =
      { index : int;
        delta : Delta.t;
        finish_raw : Jsonx.t option;
        stop_raw : Jsonx.t option;
        logprobs_raw : Jsonx.t option;
        path : string }

    let index (c : t) : int = c.index
    let delta (c : t) : Delta.t = c.delta
    let finish_reason_raw (c : t) : Jsonx.t option = c.finish_raw
    let stop_reason_raw (c : t) : Jsonx.t option = c.stop_raw
    let logprobs_raw (c : t) : Jsonx.t option = c.logprobs_raw

    (* The typed views reuse the respx closed enums, re-domained with
       this choice's path; a non-string or unknown value fails the
       VIEW only. *)
    let view_enum (what : string)
        (read : string -> ('a, Errx.t) result) (raw : Jsonx.t option) :
        ('a option, Errx.t) result =
      Option.fold ~none:(Ok None)
        ~some:(fun (v : Jsonx.t) ->
          Option.fold
            ~none:(invalid (what ^ ": not a string"))
            ~some:(fun (s : string) ->
              Result.fold
                ~ok:(fun x -> Ok (Some x))
                ~error:(fun ((_ : Errx.t)) ->
                  invalid (what ^ ": unknown value " ^ s))
                (read s))
            (Jsonx.as_string v))
        raw

    let finish (c : t) : (Respx.Finish.t option, Errx.t) result =
      view_enum (c.path ^ ".finish_reason") Respx.Finish.of_string
        c.finish_raw

    let stop_reason (c : t) : (Respx.Stop_reason.t option, Errx.t) result
        =
      view_enum (c.path ^ ".stop_reason") Respx.Stop_reason.of_string
        c.stop_raw
  end

  let choice_of (what : string) (item : Jsonx.t) :
      (Choice.t, Errx.t) result =
    match item with
    | Jsonx.Jobj _ ->
      let* index = req_nat (what ^ ".index") (Jsonx.member "index" item) in
      let* delta = delta_of (what ^ ".delta") (Jsonx.member "delta" item) in
      Ok
        { Choice.index;
          delta;
          finish_raw = opt_raw (Jsonx.member "finish_reason" item);
          stop_raw = opt_raw (Jsonx.member "stop_reason" item);
          logprobs_raw = Jsonx.member "logprobs" item;
          path = what }
    | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _
    | Jsonx.Jstring _ | Jsonx.Jlist _ ->
      invalid (what ^ ": not an object")

  (* i counts the position for error paths; the wire index member is
     data, not the address of the fault. Tail recursive. *)
  let choices_of (items : Jsonx.t list) : (Choice.t list, Errx.t) result =
    let rec go (i : int) (acc : Choice.t list) (rest : Jsonx.t list) :
        (Choice.t list, Errx.t) result =
      match rest with
      | [] -> Ok (List.rev acc)
      | item :: tl ->
        let* c = choice_of ("choices[" ^ string_of_int i ^ "]") item in
        go (i + 1) (c :: acc) tl
    in
    go 0 [] items

  (* usage rides the ONE respx usage grammar through the A8 seam, so
     the streaming and non-streaming readings cannot drift; errors
     re-domain as Chunk_invalid. *)
  let usage_of_opt (o : Jsonx.t option) :
      (Respx.Usage.t option, Errx.t) result =
    Option.fold ~none:(Ok None)
      ~some:(fun (v : Jsonx.t) ->
        match v with
        | Jsonx.Jnull -> Ok None
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
        | Jsonx.Jlist _ | Jsonx.Jobj _ ->
          Result.map Option.some
            (Respx.usage_of_json_x
               ~wrap:(fun (s : string) -> Errx.Chunk_invalid s)
               ~path:"usage" v))
      o

  type t =
    { id : string;
      model : string;
      created : int;
      choices : Choice.t list;
      usage : Respx.Usage.t option;
      venice_parameters_raw : Jsonx.t option }

  let id (c : t) : string = c.id
  let model (c : t) : string = c.model
  let created (c : t) : int = c.created
  let choices (c : t) : Choice.t list = c.choices
  let usage_opt (c : t) : Respx.Usage.t option = c.usage

  let venice_parameters_raw (c : t) : Jsonx.t option =
    c.venice_parameters_raw

  let of_string (payload : string) : (t, Errx.t) result =
    let* j = Jsonx.parse payload in
    let* (() : unit) =
      Option.fold
        ~none:(invalid "not a JSON object")
        ~some:(fun ((_ : (string * Jsonx.t) list)) -> Ok ())
        (Jsonx.as_obj j)
    in
    (* A5a: a top-level error member (StandardError {error: string},
       ProviderContentPolicyError {error: {message}}) surfaces the
       payload verbatim, bounded, instead of "object: missing". *)
    let* (() : unit) =
      Option.fold ~none:(Ok ())
        ~some:(fun ((_ : Jsonx.t)) ->
          invalid ("server error: " ^ prefix200 payload))
        (Jsonx.member "error" j)
    in
    let* obj = req_string "object" (Jsonx.member "object" j) in
    let* (() : unit) =
      if String.equal obj "chat.completion.chunk" then Ok ()
      else invalid "object: not chat.completion.chunk"
    in
    let* id = req_string "id" (Jsonx.member "id" j) in
    let* model = req_string "model" (Jsonx.member "model" j) in
    let* created = req_nat "created" (Jsonx.member "created" j) in
    let* usage = usage_of_opt (Jsonx.member "usage" j) in
    (* Absent choices parses as [] (a usage-only final chunk has
       choices []); wire null collapses to the same []. *)
    let* choices =
      Option.fold ~none:(Ok [])
        ~some:(fun (v : Jsonx.t) ->
          match v with
          | Jsonx.Jnull -> Ok []
          | Jsonx.Jlist items -> choices_of items
          | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
          | Jsonx.Jobj _ ->
            invalid "choices: not an array")
        (Jsonx.member "choices" j)
    in
    Ok
      { id;
        model;
        created;
        choices;
        usage;
        venice_parameters_raw = Jsonx.member "venice_parameters" j }
end
