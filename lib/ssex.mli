(* M11 streaming interface: incremental SSE machine + chunk parse,
   sans-io, three layers (D1). Machine is WHATWG-profile framing
   (bytes in, dispatched data payloads out); the top level is the
   Venice discipline (payloads classified Data | Done, the
   after-[DONE] and close policies); Chunk is the
   chat.completion.chunk parse applied to one Data payload. E2EE
   (M32) reuses Machine + the discipline unchanged: payloads are
   never assumed JSON. Pure and total: no IO, no effects, no
   exceptions, no mutation.

   Framing ledger (D2-D8), closed; every departure from the WHATWG
   processing model is listed here.
   - Narrower than the spec: CRLF and LF terminate lines; a bare CR
     (CR followed by anything but LF, or a CR pending at close)
     rejects, though the spec allows lone-CR terminators. Lone CR is
     a parser-disagreement smuggling vector and the M11 row pins
     "CRLF and LF".
   - Narrower at EOF: the spec DISCARDS pending data when the stream
     ends; close instead rejects the four residues (partial line,
     pending CR, held BOM-prefix bytes, un-dispatched data), so a
     truncated stream is always detected.
   - Divergence: event, id and retry fields are ignored exactly like
     unknown fields. A request-scoped completion stream has no
     reconnection machinery, so last-event-id and retry timers are
     dead state. Field names are case-sensitive; the value strips
     exactly one leading SPACE; a line with no colon is a field name
     with empty value.
   - Tolerance: UTF-8 is NOT validated at framing although the spec
     requires it; payload consumers own encoding (jsonx for chunks,
     hexx for E2EE ciphertext).
   - Bounds: both caps are enforced DURING accumulation (a
     terminator-free flood rejects at the cap, never buffers to
     dispatch); at-cap exactly passes. Line bytes exclude
     terminators; event bytes count the data buffer with one LF per
     data line, the spec's own buffer length.

   Chunk ledger (D9-D10, A3, A5, A6): the WHOLE chunk shape is the
   OpenAI-compat hypothesis (the saved swagger has no
   chat.completion.chunk schema), so every strictness choice fails
   loudly naming the member and the M2 probe corrects from the error
   text alone. The created and index >= 0 floors are SDK-imposed
   strictness. Unknown members are tolerated everywhere. A top-level
   error member surfaces as Chunk_invalid "server error: " plus a
   bounded 200-byte payload render (A5). tool_calls ITEMS are held
   raw; a malformed item never rejects the document, validation
   lives on the typed fragment view alone (the M10a doctrine).
   finish_reason / stop_reason are held raw with typed views that
   reuse the respx closed enums and fail loudly on a foreign value
   without destroying the document (A3).

   Null-collapse table (A13); a wire null reads as the member's
   absent projection in every row.
   - chunk choices absent-or-null reads [].
   - chunk usage absent-or-null reads None.
   - choice delta absent-or-null reads the EMPTY delta (role None,
     content None, reasoning_content None, tool_calls []) (A6).
   - delta role / content / reasoning_content absent-or-null read
     None; content "" stays Some "" (faithful;
     concatenation-neutral).
   - delta tool_calls absent-or-null member reads []; a null ITEM is
     kept raw and fails only the fragment view.
   - choice finish_reason / stop_reason absent-or-null read None in
     both the raw and the typed views. *)

module Machine : sig
  (* WHATWG event-stream framing, incremental, bounded,
     granularity-independent: byte-at-a-time feeding and one-shot
     feeding reach the same events and the same terminal state.
     Internal seam (D12); venice.mli does not re-export it. M32 E2EE
     composes on it directly. *)
  type t

  val make :
    ?max_line_bytes:int ->
    ?max_event_bytes:int ->
    unit ->
    (t, Errx.t) result
  (* defaults 1_048_576 (line) and 4_194_304 (event); each must be
     >= 1 or make rejects. Ints, not newtypes: SDK-local tuning
     knobs, not wire domain values. *)

  val feed : t -> string -> (t * string list, Errx.t) result
  (* Dispatched data payloads in dispatch order. Errors are terminal
     by contract: the old t is still a value, feeding it again is
     caller misuse. Empty feed is a no-op. *)

  val close : t -> (unit, Errx.t) result
  (* Rejects the four residues: partial line, pending CR, held
     BOM-prefix bytes, un-dispatched data. *)
end

type event =
  | Data of string
  | Done

type closing =
  | Require_done
  | Allow_eof

type t

val make :
  ?closing:closing ->
  ?max_line_bytes:int ->
  ?max_event_bytes:int ->
  unit ->
  (t, Errx.t) result
(* closing defaults Require_done (A4): close before [DONE] rejects
   even over clean framing, because a mid-completion cut is
   detectable even when the transport reports success. Allow_eof
   accepts a clean EOF after any number of payloads but still
   rejects the four Machine residues; M32 E2EE composes with
   Allow_eof until the M31 capture pins the E2EE terminator. *)

val feed : t -> string -> (t * event list, Errx.t) result
(* A payload equal to "[DONE]" (exact match after the one-space
   strip) classifies Done; ANY dispatched payload after Done, a
   second [DONE] included, rejects. Comments, ignored fields and
   blank lines after Done dispatch nothing and stay fine. *)

val close : t -> (unit, Errx.t) result
(* Every close rejection before Done carries a 200-byte prefix of
   the last payload seen (A5), so a truncation error can never mask
   the server error that preceded it. *)

(* Test seams (A10): the byte-granularity differential compares
   these projections, never machine values themselves (the internal
   piece representation is granularity-dependent by construction). *)

val pending_bytes : Machine.t -> int
(* partial line + held BOM prefix + un-dispatched data bytes,
   terminators excluded *)

val pending_cr : Machine.t -> bool

module Chunk : sig
  (* One Data payload as a chat.completion.chunk document,
     all-or-nothing per chunk in the respx D8 tradition; the ledger
     above governs every tolerance. *)

  module Delta : sig
    (* The per-chunk delta. Cross-chunk accumulation of fragments
       into Msgx.Tool_call is DEFERRED to M14 (DESIGN.md M14 row);
       M11 ships the per-chunk view only. *)

    type fragment
    (* One tool_calls item under the OpenAI-compat hypothesis
       {index, id?, function: {name?, arguments?}}; arguments is a
       verbatim piece of a streamed JSON string. *)

    val fragment_index : fragment -> int
    val fragment_id : fragment -> string option
    val fragment_name : fragment -> string option
    val fragment_arguments : fragment -> string option
    val fragment_raw : fragment -> Jsonx.t

    type t

    val role : t -> string option
    (* verbatim string, NO enum: wholly unpinned member *)

    val content : t -> string option
    val reasoning_content : t -> string option

    val tool_calls_raw : t -> Jsonx.t list
    (* items verbatim; the document parse never inspects an item *)

    val tool_call_fragments : t -> (fragment list, Errx.t) result
    (* the typed view: the first failing item wins and carries its
       choices[i].delta.tool_calls[j] path *)
  end

  module Choice : sig
    type t

    val index : t -> int
    val delta : t -> Delta.t

    val finish_reason_raw : t -> Jsonx.t option
    val stop_reason_raw : t -> Jsonx.t option
    (* absent OR null -> None; a foreign value never rejects the
       document (A3): the terminal chunk must not lose its
       end-of-turn signal to an unpinned enum *)

    val finish : t -> (Respx.Finish.t option, Errx.t) result
    val stop_reason : t -> (Respx.Stop_reason.t option, Errx.t) result
    (* typed views over the raw members, reusing the respx closed
       enums; a non-string or unknown value fails the VIEW only,
       with the choices[i].finish_reason / choices[i].stop_reason
       path *)

    val logprobs_raw : t -> Jsonx.t option
    (* internal seam for M15; unpinned in chunks, typed reading
       deferred *)
  end

  type t

  val of_string : string -> (t, Errx.t) result
  (* Enforced floor (HYPOTHESIS, no schema): object present and
     equal to "chat.completion.chunk"; id, model, created present;
     created integer >= 0; per-choice index required integer >= 0.
     Besides Chunk_invalid, of_string can return Json_invalid (the
     underlying Jsonx.parse); each error keeps its own prefix. A
     top-level error member returns Chunk_invalid "server error: "
     plus the bounded payload (A5). *)

  val id : t -> string
  val model : t -> string
  val created : t -> int
  val choices : t -> Choice.t list

  val usage_opt : t -> Respx.Usage.t option
  (* final-chunk convention; parsed by the ONE respx usage grammar
     through the usage_of_json_x seam (A8), re-domained
     Chunk_invalid, so the streaming and non-streaming readings
     cannot drift *)

  val usage_raw : t -> Jsonx.t option
  (* internal seam (M14 A2): the raw usage object beside the typed
     reading, absent OR null reading None exactly like usage_opt. The
     M14 accumulator re-emits these bytes, so the rendered document
     carries the server's own usage member. venice.mli does not
     re-export it. *)

  val venice_parameters_raw : t -> Jsonx.t option
  (* internal seam for M15; the first-chunk citations /
     search-results facts ride here, shape unpinned *)
end
