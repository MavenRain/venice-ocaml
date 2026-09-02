(* M7 message domain interface. The brand is phantom over one erased
   repr; these abstract types are the in-library enforcement, and
   venice.mli re-abstracts the same surface for library users. The
   seam block at the bottom is for sessx, chatx and respx (and the
   tests); venice.mli does not re-export it. Total, sans-io. *)

module Audio_format : sig
  (* input_audio.format wire enum; transparent by design. *)
  type t =
    | Wav
    | Mp3
    | Aiff
    | Aac
    | Ogg
    | Flac
    | M4a
    | Pcm16
    | Pcm24

  val to_string : t -> string
  (* lowercase wire names *)

  val of_string : string -> (t, Errx.t) result

  val default : t
  (* Wav; the wire default when the member is absent *)
end

module Cache : sig
  type t

  val ephemeral : t
  (* cache_control {type:"ephemeral"}. ttl is deferred: beta feature
     behind a header the swagger does not name (FACTS.md). *)
end

module Reasoning_detail : sig
  (* One reasoning_details item, exact by construction: the value
     wraps the raw parsed object, so re-emission preserves the member
     set and order as received (unknown members included). The mint
     is the reasoning_detail_of_json seam below; the Venice entry
     point re-exports neither the seam nor any of_string, so through
     Venice the only source is a real parsed response. The wrapped
     library keeps this compilation unit linkable as Venice__Msgx,
     so "minted only by the parser" is in-library doctrine, not type
     enforcement (D3). *)
  type t

  val type_ : t -> string
  (* the one required member *)

  val data : t -> string option
  val format : t -> string option
  val id : t -> string option
  val text : t -> string option

  val index : t -> Jsonx.t option
  (* the swagger says number; no int coercion *)
end

module Thought_signature : sig
  (* Opaque wire string ("pass it back exactly as received"). The
     mint is the thought_signature_of_parsed seam below; the Venice
     entry point exposes no of_string. The same D3 scope note as
     Reasoning_detail applies: linkage via Venice__Msgx stays
     possible, so the provenance claim is doctrine, not
     enforcement. *)
  type t
end

module Tool_call : sig
  (* One assistant tool_calls item, exact by construction: the value
     wraps raw JSON, so re-emission preserves the member set and
     order as received, unknown members included (the swagger leaves
     the item shape untyped; FACTS.md). Two mints: make builds the
     canonical nested object {id; type:"function"; function:{name;
     arguments}} for replay, and the tool_call_of_json seam below
     parses a received item strictly. The projections are total:
     the mints validated the fields they read. *)
  type t

  val make :
    id:string -> name:string -> arguments:string -> (t, Errx.t) result
  (* id and name must be nonempty; arguments is any string by design
     (a replayed item must not lose bytes to a well-formedness
     gate) *)

  val id : t -> string
  val name : t -> string
  (* function.name *)

  val arguments : t -> string
  (* function.arguments, the exact wire string *)

  val arguments_json : t -> (Jsonx.t, Errx.t) result
  (* arguments parsed on demand; Msg_invalid when it is not JSON *)

  val to_json : t -> Jsonx.t
  (* the raw item verbatim *)
end

(* Unbranded payloads: no type variable, bind once at structure level,
   reuse across models. The injections below instantiate the row per
   use site inside each Pack continuation. *)

type text_part
type file_part

type msg
(* one non-user message: system / developer / assistant / tool *)

val text : ?cache:Cache.t -> string -> (text_part, Errx.t) result
(* minLength 1 (schema rule for text parts) *)

val file :
  ?filename:string -> ?cache:Cache.t -> string -> (file_part, Errx.t) result
(* the string is file_data: uri-shape check (scheme present, or a
   data: URL) *)

val system : ?name:string -> string -> (msg, Errx.t) result
val system_parts : ?name:string -> text_part list -> (msg, Errx.t) result
val developer : ?name:string -> string -> (msg, Errx.t) result

val developer_parts :
  ?name:string -> text_part list -> (msg, Errx.t) result
(* parts-taking forms are restricted to text parts so cache_control is
   expressible where prompt caching pays; the string forms are the
   sugar that emits the collapsed form *)

val assistant :
  ?name:string ->
  ?content:string ->
  ?reasoning_content:string ->
  ?reasoning_details:Reasoning_detail.t list ->
  ?thought_signature:Thought_signature.t ->
  ?tool_calls:Tool_call.t list ->
  unit ->
  (msg, Errx.t) result
(* content or a nonempty tool_calls is required: the reasoning
   passthrough members alone do not make a legal assistant message.
   ?reasoning_details:[] and ?tool_calls:[] are accepted and emit
   nothing (the label behaves as omitted). When tool_calls is
   nonempty, content "" collapses to absent (respx projects a wire ""
   faithfully; the passthrough call must not Error on a tool-call
   turn); with tool_calls absent or empty, "" still rejects as
   empty *)

val tool :
  ?name:string -> tool_call_id:string -> string -> (msg, Errx.t) result
(* the request Tool Message also declares reasoning_content and its
   own tool_calls (swagger 1081-1109, both nullable and not
   required). Both stay unexposed deliberately (D3): a caller-sent
   tool RESULT has no producer semantics for model reasoning or for
   nested calls, so the SDK omits the two members rather than invent
   a meaning for them *)

(* Branded parts: the brand is the PRE-extraction base row of the
   witnessed model. *)

type 'c part

val of_text : text_part -> 'c part
(* injection; generalizes per use *)

val of_file : file_part -> 'c part
(* injection; generalizes per use *)

(* Optionals come before the anonymous witness so they stay erasable
   (warning 16 is an error under the dev profile): only a later
   anonymous argument erases an optional, never a required labelled
   one. *)

val image :
  ?cache:Cache.t ->
  ('c * Modelx.vision) Modelx.t ->
  url:string ->
  ('c part, Errx.t) result

val audio :
  ?format:Audio_format.t ->
  ?cache:Cache.t ->
  ('c * Modelx.audio) Modelx.t ->
  data:string ->
  ('c part, Errx.t) result

val video :
  ?cache:Cache.t ->
  ('c * Modelx.video) Modelx.t ->
  url:string ->
  ('c part, Errx.t) result

(* Branded messages. *)

type 'c t

val user : ?name:string -> 'c part list -> ('c t, Errx.t) result
(* rejects []: SDK-imposed strictness, the schema has no minItems here *)

val user_text : ?name:string -> string -> ('c t, Errx.t) result

val lift : msg -> 'c t
(* injection; generalizes per use *)

type 'c nonempty

val nonempty : 'c t list -> ('c nonempty, Errx.t) result
(* rejects [] ONLY; video counting is out of scope for M7 *)

(* Internal seam for sessx, chatx and respx (and the tests);
   venice.mli does not re-export it. *)

val emit : 'c nonempty -> Jsonx.t
(* the fold of emit_message over the message list *)

val emit_message : 'c t -> Jsonx.t

val content_plaintext : 'c t -> string option
(* plaintext-content projection over user + system messages; None for
   the other roles, and None for a user message with a non-text part *)

val cipher_hex : 'c t -> hex:string -> ('c t, Errx.t) result
(* replace user/system content with the dedicated cipher repr case;
   Error on any other role *)

val reasoning_detail_of_json :
  Jsonx.t -> (Reasoning_detail.t, Errx.t) result
(* the one Reasoning_detail mint: validates type present and a
   string, keeps every member verbatim (unknown members included).
   Named here rather than respx-private because M11 ssex / M14
   streamx must mint the identical type from delta JSON *)

val thought_signature_of_parsed : string -> Thought_signature.t
(* the one Thought_signature mint; same seam rationale *)

val tool_call_of_json : Jsonx.t -> (Tool_call.t, Errx.t) result
(* the one parse-side Tool_call mint: strict against the nested
   hypothesis shape (id nonempty string; type, when present, exactly
   "function"; function.name nonempty string; function.arguments a
   string held verbatim), keeps every member verbatim. Named here
   rather than respx-private for the reasoning_detail_of_json
   reason: M11 ssex / M14 streamx mint the identical type from
   delta JSON. venice.mli re-exports make and the projections but
   not this seam *)
