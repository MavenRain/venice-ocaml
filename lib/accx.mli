(* M14 cross-chunk accumulator: streamed chat.completion.chunk
   documents folded into ONE chat.completion document, pure and total
   (D1, D7, D8). No IO, no effects, no exceptions, no mutation: the
   fold is a value the caller threads, so the cursor consumer, a test
   and a replay share one implementation.

   Accumulation ledger (D7), closed.
   - id, model and created are FIRST-WINS; a later chunk that
     disagrees rejects, because two ids in one stream is a
     multiplexing fault the SDK must not paper over.
   - Per choice, role is first-wins; content and reasoning_content
     append in received order and the pieces join ONCE at finish, so
     the fold never rebuilds a string per chunk.
   - usage is LAST-WINS (the final-chunk convention), typed and raw
     together (A2), so the rendered document carries the server's own
     usage bytes.
   - venice_parameters is first-wins and raw (A15). It renders LAST,
     after usage.
   - tool_call fragments key on the WIRE index and sparse indices are
     legal (A10). id and name are first-wins, a changed id rejects, a
     fragment with no id and no open call rejects, and a call with no
     name rejects at finish.
   - Caps count DISTINCT KEYS (A8): 128 choice indices per document
     and 64 fragment indices per choice.
   - finish_reason is required on every choice at finish. It is held
     RAW and read through the respx closed enum on demand (A7), so a
     foreign value keeps the document readable.
   Every rejection is Errx.Stream_invalid with a bare payload (A14);
   Errx.to_string adds the "stream: " prefix. *)

type t

val empty : t

val step : t -> Ssex.Chunk.t -> (t, Errx.t) result
(* One chunk into the fold, all-or-nothing: a rejected chunk leaves
   the caller the old t, which is still a value. *)

val chunks : t -> int
(* chunks folded so far *)

module Choice : sig
  (* One accumulated choice. The projections are total: finish
     reports the RAW wire string, and the typed view fails alone. *)
  type t

  val index : t -> int
  val role : t -> string option
  val content : t -> string option
  val reasoning_content : t -> string option
  val tool_calls : t -> Msgx.Tool_call.t list
  (* minted in ascending wire-index order *)

  val finish_raw : t -> string
  val finish : t -> (Respx.Finish.t, Errx.t) result
  val stop_reason_raw : t -> string option
  val stop_reason : t -> (Respx.Stop_reason.t option, Errx.t) result
end

type final

val finish : t -> (final, Errx.t) result
(* Rejects an empty fold, a choice with no finish_reason and a
   tool_call with no name. *)

val id : final -> string
val model : final -> string
val created : final -> int
val choices : final -> Choice.t list
(* ascending wire-index order *)

val usage_opt : final -> Respx.Usage.t option

val to_response : final -> (Respx.t, Errx.t) result
(* The rendered document re-parsed by Respx.of_string: ONE grammar
   reads the streaming and the non-streaming path, so the two
   readings cannot drift. A respx rejection returns VERBATIM. *)

(* Internal seams (D8, A2, A15); venice.mli does not re-export
   them. *)

val venice_parameters_raw : final -> Jsonx.t option
val usage_raw : final -> Jsonx.t option

val to_json : final -> Jsonx.t
(* the rendered document before the re-parse; member order is part of
   the contract (A15) *)
