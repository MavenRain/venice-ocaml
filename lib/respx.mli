(* M10 chat response domain interface. of_string is the one entry:
   the whole 200-response body parses or the whole document rejects
   (D8 all-or-nothing; a tool-role choice message rejects everything,
   so a mixed array's id/usage/cost cannot be salvaged by accident).
   Unknown members are tolerated everywhere: the response schema
   never sets additionalProperties: false.

   Floors provenance (D7): only cost.usd / cost.diem carry a schema
   minimum: 0. created, choice index, the three usage counts and the
   nested details ints are bare type: integer with NO minimum, so the
   >= 0 floors on those are SDK-imposed strictness in the msgx
   tradition, not schema enforcement: a response carrying a negative
   value in one of those integer members is wire-legal per the pinned
   schema and is rejected by respx alone.

   Tolerance ledger (D7), closed; every departure from the pinned
   schema in the tolerant direction is listed here.
   - Required-list tolerance: logprobs is in the swagger's required
     list, but absent-or-null parses as None. The example bodies
     themselves show logprobs: null, OpenAI-compat servers routinely
     omit it, and absent-vs-null is not distinguishable downstream.
   - Null-collapse tolerances: the schema marks none of these
     members nullable, yet a wire null reads as the member's absent
     projection, for the same absent-vs-null reason: choices null
     reads []; message.reasoning_details null reads [];
     logprobs.top_logprobs null reads []; logprobs bytes null (flat
     record and entries) reads None; cost null reads None.
     message.tool_calls absent or null reads [] too (the request-side
     schema does mark that member nullable).
   - Item-strictness split: message.tool_calls ITEMS are held raw by
     the document parse (the swagger leaves the item shape untyped),
     so a malformed item never rejects the document; validation
     against the nested hypothesis shape lives on the typed
     Choice.tool_calls view alone.

   Extra strictness beyond the D7 floors: logprobs bytes items are
   narrowed to wire integers although the schema types them number,
   so a fractional byte value rejects the whole document
   (SDK-imposed strictness in the msgx tradition).

   Total, sans-io. *)

module Finish : sig
  (* finish_reason wire enum, closed; transparent by design.
     Tool_calls signals a tool-call turn: read the calls through
     Choice.tool_calls. *)
  type t =
    | Stop
    | Length
    | Tool_calls

  val to_string : t -> string
  (* lowercase wire names *)

  val of_string : string -> (t, Errx.t) result
end

module Stop_reason : sig
  (* stop_reason wire enum, closed; the member itself is nullable. *)
  type t =
    | Stop
    | Length

  val to_string : t -> string
  val of_string : string -> (t, Errx.t) result
end

module Usage : sig
  (* The three counts are required wire integers; the details
     members project as options (null or absent details objects
     collapse to None). No cross-field arithmetic check: prompt +
     completion vs total is server-owned, advisory checks belong to
     the caller. *)
  type t

  val completion_tokens : t -> int
  val prompt_tokens : t -> int
  val total_tokens : t -> int

  val reasoning_tokens : t -> int option
  (* completion_tokens_details.reasoning_tokens *)

  val cached_tokens : t -> int option
  (* prompt_tokens_details.cached_tokens *)

  val cache_creation_tokens : t -> int option
  (* prompt_tokens_details.cache_creation_input_tokens *)
end

module Logprobs : sig
  (* The swagger's flat token record plus top_logprobs; NOT OpenAI's
     content array. logprob is exact (no float crosses the core). *)
  type entry

  val entry_token : entry -> string
  val entry_logprob : entry -> Jsonx.dec
  val entry_bytes : entry -> int list option

  type t

  val token : t -> string
  val logprob : t -> Jsonx.dec
  val bytes : t -> int list option
  val top_logprobs : t -> entry list
  (* absent top_logprobs reads [] *)
end

module Cost : sig
  (* Optional member; when present both currencies are required and
     >= 0 (the schema's only minimum: 0 keywords). *)
  type t

  val usd : t -> Jsonx.dec
  val diem : t -> Jsonx.dec
end

module Choice : sig
  (* One parsed assistant choice. content collapses the wire's three
     variants: a string reads Some, null/absent read None, and a
     text-parts array reads Some of the parts' texts concatenated in
     received order. That concatenation is a projection, not a claim
     the wire sent one string. content "" and content [] are both
     wire-legal (the schema sets no minLength or minItems): the
     string "" projects to Some "" (the faithful reading;
     Msgx.assistant rejects it as empty on a text-only turn but
     collapses it to absent when tool_calls is nonempty, so the
     passthrough call round-trips either way), while the empty parts
     array projects to None (no parts, no text). reasoning_details
     collapses absent, null and [] to the same [], so the
     parse-then-passthrough call Msgx.assistant
     ?reasoning_details:(Some (reasoning_details c))
     type-checks and round-trips without Error. *)
  type t

  val finish : t -> Finish.t
  val index : t -> int
  val content : t -> string option
  val reasoning_content : t -> string option
  val reasoning_details : t -> Msgx.Reasoning_detail.t list
  val thought_signature : t -> Msgx.Thought_signature.t option
  val logprobs : t -> Logprobs.t option
  val stop_reason : t -> Stop_reason.t option

  val tool_calls_raw : t -> Jsonx.t list
  (* message.tool_calls items verbatim; absent or null reads [], and
     the document parse never inspects an item *)

  val tool_calls : t -> (Msgx.Tool_call.t list, Errx.t) result
  (* the typed view: each raw item through the strict Tool_call mint;
     the first failure wins and carries its choices[i].tool_calls[j]
     path *)
end

type t

val of_string : string -> (t, Errx.t) result
(* Enforced (D7): top-level id, model, created, object, usage
   present; object equals "chat.completion"; choice
   finish_reason/index/message present; the usage counts present,
   integers, each >= 0; created >= 0; choice index >= 0; cost
   usd/diem >= 0. Enum strings outside the closed sets reject.
   Absent choices parses as []. Besides Resp_invalid, of_string can
   return Json_invalid (the underlying Jsonx.parse) and Msg_invalid
   (the msgx reasoning_detail seam); each error keeps its own
   prefix, so the failing domain stays identifiable. *)

val id : t -> string
val model : t -> string
val created : t -> int
val choices : t -> Choice.t list
val usage : t -> Usage.t
val cost : t -> Cost.t option

(* Internal seam (D10); venice.mli does not re-export it. The two
   deferred top-level members are held raw so M15 clientx can type
   them without re-parsing; web_search_citations rides inside
   venice_parameters_raw. *)

val venice_parameters_raw : t -> Jsonx.t option
val prompt_logprobs_raw : t -> Jsonx.t option

val usage_of_json_x :
  wrap:(string -> Errx.t) ->
  path:string ->
  Jsonx.t ->
  (Usage.t, Errx.t) result
(* Internal seam (M11 A8); venice.mli does not re-export it. The ONE
   usage grammar applied to a pre-parsed member value; errors are
   re-domained through wrap as wrap (path ^ ": " ^ detail), the detail
   stripped of its "resp: " prefix, so the streaming chunk reading
   reports chunk-domain errors while the two usage readings cannot
   drift. *)
