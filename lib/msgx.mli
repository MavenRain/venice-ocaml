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
     set and order as received (unknown members included). Minted
     only by the reasoning_detail_of_json seam below; no public
     of_string exists, so a value reaching assistant from outside the
     library can only have come from a real parsed response. *)
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
  (* Opaque wire string ("pass it back exactly as received"). Minted
     only by the thought_signature_of_parsed seam below; no public
     of_string exists. *)
  type t
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
  unit ->
  (msg, Errx.t) result
(* content (or, at M10a, tool_calls) is still required: the reasoning
   passthrough members alone do not make a legal assistant message.
   ?reasoning_details:[] is accepted and emits nothing (the label
   behaves as omitted). The tools milestone adds ?tool_calls as a
   pure optional-argument addition, no API break *)

val tool :
  ?name:string -> tool_call_id:string -> string -> (msg, Errx.t) result

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
