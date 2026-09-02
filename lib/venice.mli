(* venice-ocaml: typed Venice.ai SDK.

   The signature below is the whole public API. M3 exposes the codec
   floor: the seed error type, total byte cursors, strict hex, and
   strict base64 in both wire alphabets. *)

val version : string

module Error : sig
  type t =
    | Hex_invalid of string
    | B64_invalid of string
    | Json_invalid of string
    | Model_invalid of string
    | Param_invalid of string
    | Msg_invalid of string

  val to_string : t -> string
end

module Cursor : sig
  (* Total byte readers. Every reader returns None when any byte of its
     window falls outside the buffer. Offsets count from zero. u64 is
     Int64 so no wire bit truncates into a 63-bit int. *)
  val take : string -> int -> int -> string option
  val u8 : string -> int -> int option
  val u16le : string -> int -> int option
  val u32le : string -> int -> int option
  val u64le : string -> int -> int64 option
end

module Hex : sig
  (* Strict hex: decode rejects foreign bytes and odd length, and
     accepts both letter cases. Encode emits lowercase. *)
  val encode : string -> string
  val decode : string -> (string, Error.t) result
end

module B64 : sig
  (* Strict base64. url: no padding, canonical trailing bits, length
     mod 4 <> 1. std: mandatory canonical '=' padding over the same
     core. Foreign bytes reject in both. *)
  val encode_url : string -> string
  val decode_url : string -> (string, Error.t) result
  val encode_std : string -> string
  val decode_std : string -> (string, Error.t) result
end

module Json : sig
  (* Strict minimal JSON. Numbers are exact: canonical integers parse
     to Jint (18-digit cap, no leading zeros); fraction forms parse to
     Jdec as sign/mantissa/scale ints, where the value is
     (-1)^negative * mantissa / 10^scale and scale counts the fraction
     digits as written, so "1.50" round-trips byte-exact. No float
     crosses this boundary and exponents reject. Depth cap 32, object
     width cap 4096 members, array width cap 65536 items, duplicate
     keys reject at every depth, raw control characters reject in
     strings. \u escapes cover all of Unicode: each escape is a 16-bit
     code unit, a high/low surrogate pair combines into one code point
     and the result is emitted as UTF-8, and a lone surrogate (high
     with no valid low escape after it, or a bare low) rejects. *)
  type dec = { negative : bool; mantissa : int; scale : int }

  type t =
    | Jnull
    | Jbool of bool
    | Jint of int
    | Jdec of dec
    | Jstring of string
    | Jlist of t list
    | Jobj of (string * t) list

  val emit : t -> string
  val parse : string -> (t, Error.t) result
  val member : string -> t -> t option
  val as_string : t -> string option
  val as_int : t -> int option
  val as_bool : t -> bool option
  val as_list : t -> t list option
  val as_obj : t -> (string * t) list option

  (* Numeric view: a Jint reads as a scale-zero dec, so one case
     consumes any wire number. None for Jint min_int: that magnitude
     is not representable as a non-negative mantissa. *)
  val as_dec : t -> dec option
end

module Constraints : sig
  (* The typed view of a text model's constraints object: the model's
     asserted default per sampling parameter, each window-checked at
     parse time. Obtained from Model.constraints; the sampling
     newtypes below read their defaults out of it. *)
  type t
end

(* Constraint-bounded sampling newtypes. Each module's make is the
   only mint and checks the chat request schema's documented window
   (FACTS.md), so an out-of-window value cannot reach a request:
   temperature 0..2, top_p 0..1, frequency_penalty and
   presence_penalty -2..2, repetition_penalty >= 0, top_k >= 0.
   Values are exact decimals; no float crosses the boundary. default
   reads the model's asserted default from its constraints, already
   checked against the same window. *)
module Temp : sig
  type t

  val make : Json.dec -> (t, Error.t) result
  val default : Constraints.t -> t option
  val to_dec : t -> Json.dec
end

module Top_p : sig
  type t

  val make : Json.dec -> (t, Error.t) result
  val default : Constraints.t -> t option
  val to_dec : t -> Json.dec
end

module Frequency_penalty : sig
  type t

  val make : Json.dec -> (t, Error.t) result
  val default : Constraints.t -> t option
  val to_dec : t -> Json.dec
end

module Presence_penalty : sig
  type t

  val make : Json.dec -> (t, Error.t) result
  val default : Constraints.t -> t option
  val to_dec : t -> Json.dec
end

module Repetition_penalty : sig
  type t

  val make : Json.dec -> (t, Error.t) result
  val default : Constraints.t -> t option
  val to_dec : t -> Json.dec
end

module Top_k : sig
  type t

  val make : int -> (t, Error.t) result
  val to_int : t -> int
end

module Venice_params : sig
  (* The venice_parameters request object, typed to the wire schema.
     An unset field is not sent, so the server default applies; that
     is not the same act as sending the default value, and to_json
     preserves the difference by emitting present fields only.
     enable_e2ee is deliberately absent from this API: it is a
     downgrade lever (false runs an E2EE-capable model TEE-only even
     when E2EE headers are present), so the session layer owns it and
     nothing here can switch E2EE off. *)
  type web_search =
    | Auto
    | Off
    | On

  type t

  val make :
    ?character_slug:string ->
    ?strip_thinking_response:bool ->
    ?disable_thinking:bool ->
    ?enable_web_search:web_search ->
    ?enable_web_scraping:bool ->
    ?enable_web_citations:bool ->
    ?include_search_results_in_stream:bool ->
    ?return_search_results_as_documents:bool ->
    ?include_venice_system_prompt:bool ->
    ?enable_x_search:bool ->
    unit ->
    t

  val is_empty : t -> bool
  val to_json : t -> Json.t
end

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

  val of_string : string -> (t, Error.t) result

  val default : t
  (* Wav; the wire default when the member is absent *)
end

module Cache : sig
  type t

  val ephemeral : t
  (* cache_control {type:"ephemeral"}. ttl is deferred: beta feature
     behind a header the swagger does not name (FACTS.md). *)
end

module Model : sig
  (* A /models entry as a capability row. 'caps is phantom: it records
     which capability witnesses have been extracted from the server's
     listing, and the extractors below are the only mint, so an API
     that demands e.g. a ('c * vision) t cannot be called without the
     listing having asserted vision support. Closed wire enums (kind,
     privacy, quantization) reject foreign values loudly; slugs are
     open-world, so an unfamiliar id stays usable as Unknown. Field
     names follow FACTS.md and are hypotheses until the M2 probe. *)

  (* Phantom capability markers, uninhabited. *)
  type vision
  type tools
  type reasoning
  type audio
  type tee
  type e2ee

  type video
  (* video-INPUT capability marker. Distinct from the kind constructor
     Video below, which names a video-GENERATION model kind. *)

  type 'caps t
  type packed = Pack : 'c t -> packed

  type slug =
    | E2ee_qwen3_5_122b_a10b
    | E2ee_glm_5
    | Unknown of string

  type kind =
    | Text
    | Code
    | Image
    | Embedding
    | Tts
    | Asr
    | Music
    | Upscale
    | Inpaint
    | Video
    (* video-GENERATION model kind; the video-INPUT capability marker
       is the uninhabited type video above *)

  type privacy =
    | Private
    | Anonymized

  type quantization =
    | Fp4
    | Fp8
    | Fp16
    | Bf16
    | Int8
    | Int4
    | Not_available

  (* Absent or null deprecation reads as Active. A present object keeps
     every date member verbatim as (key, printed value) and pulls out
     the replacement slug by key prefix. *)
  type deprecation =
    | Active
    | Deprecated of
        { dates : (string * string) list;
          replacement : string option }

  val of_json : Json.t -> (packed, Error.t) result
  val of_listing : Json.t -> (packed list, Error.t) result

  (* Witness extraction: Some retypes the model with the marker; a
     model whose listing did not assert the capability reads None. *)
  val vision : 'c t -> ('c * vision) t option
  val tools : 'c t -> ('c * tools) t option
  val reasoning : 'c t -> ('c * reasoning) t option
  val audio : 'c t -> ('c * audio) t option
  val tee : 'c t -> ('c * tee) t option
  val e2ee : 'c t -> ('c * e2ee) t option

  val video : 'c t -> ('c * video) t option
  (* Some iff the listing asserts supportsVideoInput *)

  type 'c media =
    { vision : ('c * vision) t option;
      audio : ('c * audio) t option;
      video : ('c * video) t option }

  val media : 'c t -> 'c media
  (* The paved road: all three witnesses extracted in parallel at row
     'c, so the stacking idiom is never needed for multimodal
     content. *)

  val multiple_images : 'c t -> bool
  (* wire: supportsMultipleImages, required; a model with no
     capabilities object reads false. Single-image vision models
     silently drop all but the last image-bearing message server-side,
     so a caller must be able to read these fields to warn. *)

  val max_images : 'c t -> int option
  (* wire: maxImages, optional *)

  val max_videos : 'c t -> int option
  (* wire: maxVideos, optional *)

  val id : 'c t -> string
  val slug : 'c t -> slug
  val kind : 'c t -> kind
  val created : 'c t -> int option
  val traits : 'c t -> string list
  val offline : 'c t -> bool
  val beta : 'c t -> bool
  val privacy : 'c t -> privacy option
  val context_tokens : 'c t -> int option
  val max_completion_tokens : 'c t -> int option
  val deprecation : 'c t -> deprecation

  (* The typed constraints view parses on access, so a malformed inner
     parameter rejects at the call that needs it (with the model id on
     the error path) instead of failing the whole listing. *)
  val constraints : 'c t -> (Constraints.t, Error.t) result

  val quantization : 'c t -> quantization option
  val effort_options : 'c t -> string list
end

module Msg : sig
  (* Typed chat messages. Branded values (media parts, user messages,
     'c nonempty) carry the phantom base row 'c of the witnessed
     model, so a media part cannot reach a model whose listing never
     asserted the capability. Unbranded payloads carry no type
     variable: bind once at structure level, reuse across models; the
     injections instantiate the row per use site inside each Pack
     continuation. *)

  type text_part
  type file_part

  type msg
  (* one non-user message: system / developer / assistant / tool *)

  val text : ?cache:Cache.t -> string -> (text_part, Error.t) result
  (* minLength 1 (schema rule for text parts) *)

  val file :
    ?filename:string ->
    ?cache:Cache.t ->
    string ->
    (file_part, Error.t) result
  (* the string is file_data: uri-shape check (scheme present, or a
     data: URL) *)

  val system : ?name:string -> string -> (msg, Error.t) result

  val system_parts :
    ?name:string -> text_part list -> (msg, Error.t) result

  val developer : ?name:string -> string -> (msg, Error.t) result

  val developer_parts :
    ?name:string -> text_part list -> (msg, Error.t) result
  (* parts-taking forms are restricted to text parts so cache_control
     is expressible where prompt caching pays (long system prompts);
     the string forms are the sugar that emits the collapsed form *)

  val assistant :
    ?name:string -> ?content:string -> unit -> (msg, Error.t) result
  (* rejects the all-absent case at mint; the tools milestone adds
     ?tool_calls and the M10 passthrough values as pure
     optional-argument additions, no API break *)

  val tool :
    ?name:string ->
    tool_call_id:string ->
    string ->
    (msg, Error.t) result

  (* Branded parts: the brand is the PRE-extraction base row of the
     witnessed model. Extract every witness from the SAME base model;
     Model.media is the paved road. *)
  type 'c part

  val of_text : text_part -> 'c part
  (* injection; generalizes per use *)

  val of_file : file_part -> 'c part
  (* injection; generalizes per use *)

  (* Optionals come before the anonymous witness so they stay
     erasable: only a later anonymous argument erases an optional,
     never a required labelled one. Partial application
     Msg.image vm still reads as "minted against vm". *)

  val image :
    ?cache:Cache.t ->
    ('c * Model.vision) Model.t ->
    url:string ->
    ('c part, Error.t) result

  val audio :
    ?format:Audio_format.t ->
    ?cache:Cache.t ->
    ('c * Model.audio) Model.t ->
    data:string ->
    ('c part, Error.t) result

  val video :
    ?cache:Cache.t ->
    ('c * Model.video) Model.t ->
    url:string ->
    ('c part, Error.t) result

  (* Branded messages. *)
  type 'c t

  val user : ?name:string -> 'c part list -> ('c t, Error.t) result
  (* rejects []: SDK-imposed strictness, the schema has no minItems
     here *)

  val user_text : ?name:string -> string -> ('c t, Error.t) result

  val lift : msg -> 'c t
  (* injection; generalizes per use *)

  type 'c nonempty

  val nonempty : 'c t list -> ('c nonempty, Error.t) result
  (* rejects [] ONLY; video counting is out of scope for M7 *)
end
