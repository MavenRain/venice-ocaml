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
    | Head_invalid of string
    | Chat_invalid of string
    | Resp_invalid of string
    | Sse_invalid of string
    | Chunk_invalid of string
    | Key_invalid of string
    | Req_invalid of string
    | Wire_invalid of string
    | Transport_failed of string

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

  (* Total order on canonical decimals (nonnegative mantissa below
     10^18, scale 0..18, the shape parse mints): sign first, with a
     zero mantissa normalized to zero whatever its scale or negative
     flag, then magnitude on right-padded digit strings. The one
     order in the repo; the sampling windows and the Tier derivation
     both go through it. *)
  val compare_dec : dec -> dec -> int
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

  type reasoning_effort
  (* reasoning_effort request-member capability marker (wire
     supportsReasoningEffort). Distinct from reasoning: the effort
     menu is its own server assertion. *)

  type log_probs
  (* logprobs request-member capability marker (wire
     supportsLogProbs). *)

  type response_schema
  (* response_format json_schema capability marker (wire
     supportsResponseSchema). Gates the schema arm only: json_object
     carries no witness. *)

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

  val reasoning_effort : 'c t -> ('c * reasoning_effort) t option
  (* Some iff the listing asserts supportsReasoningEffort *)

  val log_probs : 'c t -> ('c * log_probs) t option
  (* Some iff the listing asserts supportsLogProbs *)

  val response_schema : 'c t -> ('c * response_schema) t option
  (* Some iff the listing asserts supportsResponseSchema *)

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

module Reasoning_detail : sig
  (* One reasoning_details item from a parsed chat response, exact by
     construction: the value wraps the raw parsed object, so passing
     it back through Msg.assistant re-emits the member set and order
     exactly as received (unknown members included). This interface
     exposes no of_string, so through it the value can only come
     from a real parsed response; the wrapped library's Venice__Msgx
     alias stays linkable underneath, so that provenance is
     in-library doctrine, not type enforcement. *)
  type t

  val type_ : t -> string
  (* the one required member *)

  val data : t -> string option
  val format : t -> string option
  val id : t -> string option
  val text : t -> string option

  val index : t -> Json.t option
  (* the swagger says number; no int coercion *)
end

module Thought_signature : sig
  (* Opaque Gemini thought signature from a parsed chat response
     ("pass it back exactly as received"). This interface exposes no
     of_string; the same doctrine-not-enforcement scope note as
     Reasoning_detail applies. *)
  type t
end

module Tool_call : sig
  (* One assistant tool_calls item, exact by construction: the value
     wraps raw JSON, so re-emission preserves the member set and
     order as received, unknown members included (the swagger leaves
     the item shape untyped; FACTS.md). Two sources only: make below
     builds the canonical nested object {id; type:"function";
     function:{name; arguments}}, and Response.Choice.tool_calls
     mints from a parsed response. This interface exposes no
     of_json; the Reasoning_detail doctrine-not-enforcement scope
     note applies. *)
  type t

  val make :
    id:string -> name:string -> arguments:string -> (t, Error.t) result
  (* id and name must be nonempty; arguments is any string by design
     (a replayed item must not lose bytes to a well-formedness
     gate) *)

  val id : t -> string

  val name : t -> string
  (* function.name *)

  val arguments : t -> string
  (* function.arguments, the exact wire string *)

  val arguments_json : t -> (Json.t, Error.t) result
  (* arguments parsed on demand; Error when it is not JSON *)

  val to_json : t -> Json.t
  (* the raw item verbatim *)
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
    ?name:string ->
    ?content:string ->
    ?reasoning_content:string ->
    ?reasoning_details:Reasoning_detail.t list ->
    ?thought_signature:Thought_signature.t ->
    ?tool_calls:Tool_call.t list ->
    unit ->
    (msg, Error.t) result
  (* content or a nonempty tool_calls is required: the reasoning
     passthrough members alone do not make a legal assistant
     message. ?reasoning_details:[] and ?tool_calls:[] are accepted
     and emit nothing (the label behaves as omitted), so the
     parse-then-passthrough call Response.Choice feeds directly.
     When tool_calls is nonempty, content "" collapses to absent
     (the wire's null, absent and "" agree there is no text on a
     tool-call turn); with tool_calls absent or empty, "" rejects
     as empty *)

  val tool :
    ?name:string ->
    tool_call_id:string ->
    string ->
    (msg, Error.t) result
  (* the request Tool Message also declares reasoning_content and its
     own tool_calls (both nullable and not required; FACTS.md). Both
     stay unexposed deliberately: a caller-sent tool RESULT has no
     producer semantics for model reasoning or for nested calls, so
     the SDK omits the two members rather than invent a meaning for
     them *)

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

(* M8 response-header domain. The header roster (rate-limit sextet,
   balances, x-ratelimit-type) comes from FACTS.md, not the swagger,
   so every header fact below is a hypothesis until the M2 live
   probes. *)

module Reset_at : sig
  (* Absolute unix timestamp from x-ratelimit-reset-requests. A
     distinct newtype from Reset_after so the absolute and the
     relative reset cannot swap at a use site. Minted only by
     Head.of_pairs. *)
  type t

  val seconds : t -> int
end

module Reset_after : sig
  (* Relative duration in seconds from x-ratelimit-reset-tokens.
     Fractional seconds are a live hypothesis, so the value is an
     exact unsigned decimal, not an int. Minted only by
     Head.of_pairs. *)
  type t

  val seconds : t -> Json.dec
end

module Requests_limit : sig
  (* The requests triple: limit + remaining are canonical nonnegative
     counts below 10^18, and the reset is absolute. Present only when
     all three headers arrived (all-or-nothing). *)
  type t

  val limit : t -> int
  val remaining : t -> int
  val reset_at : t -> Reset_at.t
end

module Tokens_limit : sig
  (* The tokens triple; same all-or-nothing rule, relative reset. *)
  type t

  val limit : t -> int
  val remaining : t -> int
  val reset_after : t -> Reset_after.t
end

module Limit_type : sig
  (* x-ratelimit-type. Swagger-undocumented (unpinned axis), so the
     open slug precedent applies: an unfamiliar token stays usable as
     Other with the raw token; M2 probes may tighten it. *)
  type t =
    | User
    | Api_key
    | Global
    | Other of string
end

module Usd : sig
  (* x-venice-balance-usd as an exact decimal. Signed: the wire is
     represented truthfully, and overdraft is not ours to erase. A
     distinct newtype from Diem so the balances cannot swap at a use
     site. Minted only by Head.of_pairs. *)
  type t

  val value : t -> Json.dec
end

module Diem : sig
  (* x-venice-balance-diem as an exact decimal, wei-precision capable
     (up to 18 fraction digits). Minted only by Head.of_pairs. *)
  type t

  val value : t -> Json.dec
end

module Tier : sig
  (* Derived, never a wire field: an inference rule sourced to
     FACTS.md, not a server claim. A positive present balance is
     evidence of Paid; zero balances are NOT evidence of Explorer
     (the daily Diem credit can read 0 on a paid account), so
     Explorer is never minted from headers and of_evidence returns
     None without positive evidence. *)
  type t =
    | Explorer
    | Paid

  val of_evidence : usd:Usd.t option -> diem:Diem.t option -> t option
end

module Head : sig
  (* Typed response headers and typed HTTP failures, sans-io: input
     is the raw (name, value) pair list and the status/body strings a
     transport hands over. of_pairs is the only mint: names match
     ASCII-case-insensitively, values strip edge whitespace (SP,
     HTAB, CR, LF: transport noise), unknown names drop, and a
     repeated recognized name, an interior CR/LF, or a comma inside
     a recognized singleton value rejects (smuggling- and
     duplicate-shaped). Each rate-limit triple is all-or-nothing,
     and a half-triple rejects the WHOLE parse (a mangled response
     is not trimmed down to its clean fields; classify keeps the
     raw pairs inside the failure, so nothing is silently lost);
     balances are two independent options (the x402 path documents
     USD-only account shapes). *)
  type t

  val of_pairs : (string * string) list -> (t, Error.t) result
  val requests : t -> Requests_limit.t option
  val tokens : t -> Tokens_limit.t option
  val limit_type : t -> Limit_type.t option
  val usd : t -> Usd.t option
  val diem : t -> Diem.t option

  (* Typed error bodies, concrete so callers pattern-match. Plain
     covers the swagger's StandardError, DetailedError,
     ContentViolationError and PayloadTooLargeError; Payment_required
     covers both branches of the 402 oneOf (the discovery branch
     often has NO "error", so every member is optional);
     Provider_policy is the provider rejection with its required
     message + credits_refunded. details holds the PRINTED member,
     never a raw Json.t. *)
  type body =
    | Plain of
        { error : string;
          details : string option;
          code : string option;
          suggested_prompt : string option }
    | Provider_policy of
        { message : string;
          recommended_model : string option;
          credits_refunded : bool }
    | Payment_required of
        { error : string option;
          code : string option;
          reason : string option;
          current_balance_usd : Json.dec option;
          minimum_balance_usd : Json.dec option;
          suggested_top_up_usd : Json.dec option }

  (* Every variant carries head + head_error + raw: balances on a
     402/5xx must reach the session layer, and a mangled header block
     never erases the status class. body is three-state: None = empty
     raw; Some (Ok b) = parsed; Some (Error e) = present but refused,
     raw retained verbatim. *)
  type failure =
    | Rate_limited of
        { head : t option;
          head_error : Error.t option;
          body : (body, Error.t) result option;
          raw : string }
    | Client of
        { status : int;
          head : t option;
          head_error : Error.t option;
          body : (body, Error.t) result option;
          raw : string }
    | Server of
        { status : int;
          head : t option;
          head_error : Error.t option;
          body : (body, Error.t) result option;
          raw : string }
    | Unexpected_status of
        { status : int;
          head : t option;
          head_error : Error.t option;
          raw : string }

  (* Parse headers ONCE via of_pairs for every response and pass the
     result: classify demotes an Error head to head_error inside the
     failure, so header content can never lose the status. 2xx reads
     Ok None; 429 is Rate_limited (reset times ride the typed head);
     other 4xx Client; 5xx Server; 1xx/3xx Unexpected_status (the API
     does not redirect, and misclassifying 3xx as a client fault
     would lie). The outer Error fires ONLY for a status outside
     100..599. On a 2xx classify returns Ok None and reports no
     header trouble: inspect your own of_pairs result there, as
     classify surfaces a header failure only inside a failure
     value. *)
  val classify :
    status:int ->
    head:(t, Error.t) result ->
    raw:string ->
    (failure option, Error.t) result
end

(* M9 chat request domain. Stop, Effort, Cache_retention, and (from
   M10a) Tool are hoisted satellites of Chat, like Audio_format/Cache
   ahead of Msg and Reset_at..Tier ahead of Head. *)

module Stop : sig
  (* The stop member: one sequence (of_string) or 1..4 sequences
     (of_list; schema minItems 1, maxItems 4). The empty string
     rejects in both forms as SDK strictness. The wire's null branch
     is expressed by NOT passing ?stop to Chat.make; the SDK never
     emits null. *)
  type t

  val of_string : string -> (t, Error.t) result
  val of_list : string list -> (t, Error.t) result
end

module Effort : sig
  (* reasoning_effort wire enum, closed; None_ avoids the OCaml
     keyword. Emitted only as the top-level reasoning_effort member
     (the precedence winner over reasoning.effort); the nested
     reasoning object is never emitted. *)
  type t =
    | None_
    | Minimal
    | Low
    | Medium
    | High
    | Xhigh
    | Max

  val to_string : t -> string
  (* lowercase wire names *)

  val of_string : string -> (t, Error.t) result
end

module Cache_retention : sig
  (* prompt_cache_retention wire enum, closed; H24 is the "24h" wire
     value. *)
  type t =
    | Default
    | Extended
    | H24

  val to_string : t -> string
  val of_string : string -> (t, Error.t) result
end

module Tool : sig
  (* One function tool definition (the swagger's misnamed "Tool
     Call" item; FACTS.md). function_ avoids the OCaml keyword.
     Server tools (web_search / x_search) are deferred: no
     capability row gates them and their interaction with
     venice_parameters' native-search flags is unresolved. *)
  type t

  val function_ :
    name:string ->
    ?description:string ->
    ?parameters:Json.t ->
    ?strict:bool ->
    unit ->
    (t, Error.t) result
  (* name nonempty; description, when passed, nonempty; parameters,
     when passed, a JSON object emitted verbatim *)
end

module Chat : sig
  (* The chat request: built by the one mint below, never assembled
     by hand. The phantom 'c ties the model witness, the messages
     (whose media parts were witnessed against that model), and every
     capability-gated member to ONE model row, and the encoder reads
     the request model from the same witness, so request model and
     witness model cannot diverge. Only text-like models (kind Text
     or Code) mint: every guard here reads text-model fields. The
     sampling newtypes arrive ALREADY MINTED (one mint path per
     newtype); an absent optional is not sent, so the server default
     applies. stream and stream_options are not mint members:
     streaming is chosen at the client call site (M13+). max_tokens
     is deprecated wire surface and never emitted. The emission
     member order is frozen and SDK-owned; absent optionals are never
     emitted, and no member is ever emitted as null. *)

  (* tool_choice. The three bare strings are legal without ?tools
     (the chat schema's string arm is open; only the /responses
     schema pins the enum, FACTS.md); Tool_function requires ?tools
     and name membership. *)
  type tool_choice =
    | Tool_auto
    | Tool_none
    | Tool_required
    | Tool_function of string

  (* response_format. The json_schema arm carries the
     Model.response_schema witness and the schema object VERBATIM
     (Venice takes the schema directly under the json_schema member,
     no OpenAI name/schema wrapper; FACTS.md); json_object carries
     no witness (no capability row asserts it; the swagger
     deprecates it in favor of json_schema). *)
  type 'c format =
    | Rf_json_object
    | Rf_json_schema of ('c * Model.response_schema) Model.t * Json.t

  type 'c t

  val make :
    ?temperature:Temp.t ->
    ?top_p:Top_p.t ->
    ?frequency_penalty:Frequency_penalty.t ->
    ?presence_penalty:Presence_penalty.t ->
    ?repetition_penalty:Repetition_penalty.t ->
    ?top_k:Top_k.t ->
    ?venice:Venice_params.t ->
    ?max_completion:int ->
    ?stop:Stop.t ->
    ?stop_token_ids:int list ->
    ?seed:int ->
    ?n:int ->
    ?logprobs:(('c * Model.log_probs) Model.t * bool) ->
    ?top_logprobs:int ->
    ?effort:(('c * Model.reasoning_effort) Model.t * Effort.t) ->
    ?prompt_cache_key:string ->
    ?cache_retention:Cache_retention.t ->
    ?tools:(('c * Model.tools) Model.t * Tool.t list) ->
    ?tool_choice:tool_choice ->
    ?parallel_tool_calls:bool ->
    ?response_format:'c format ->
    'c Model.t ->
    'c Msg.nonempty ->
    unit ->
    ('c t, Error.t) result
  (* Mint checks: model kind Text or Code; max_completion >= 1 and at
     most the model's published maxCompletionTokens (a model that
     publishes none accepts any value); seed >= 1; n >= 1; logprobs
     requires the Model.log_probs witness, and top_logprobs (>= 0)
     rejects without logprobs; effort requires the
     Model.reasoning_effort witness from the SAME model row and, when
     the model publishes reasoningEffortOptions, membership in that
     list; stop_token_ids nonempty with every id >= 0;
     prompt_cache_key nonempty; tools requires the Model.tools
     witness from the SAME row, with a nonempty list whose function
     names are pairwise distinct; tool_choice's bare strings pass
     alone while Tool_function requires ?tools and membership;
     parallel_tool_calls is a standalone bool; response_format's
     json_schema arm requires the Model.response_schema witness and
     an object payload. venice_parameters is emitted only when
     non-empty. *)

  val budget : 'c t -> prompt_tokens:int -> (unit, Error.t) result
  (* Advisory context budget, separate from the mint: the SDK has no
     tokenizer, so the caller supplies the prompt token estimate. The
     check is prompt_tokens + effective completion <=
     availableContextTokens, where effective completion is the
     requested max_completion when present, else the model's
     published maxCompletionTokens, else 0. A model that publishes no
     context window reads Ok (absence of a cap is not evidence of
     overflow); prompt_tokens < 0 rejects. *)

  val emit : 'c t -> string
  (* the request body bytes; deterministic, byte-stable member order *)
end

(* M10 chat response domain. of_string parses a 200-response body:
   the whole document parses or the whole document rejects
   (all-or-nothing; a tool-role choice message rejects everything).
   Unknown members are tolerated everywhere (the response schema
   never sets additionalProperties: false); required members, the
   closed enums, and the >= 0 floors are enforced. logprobs is the
   one deliberate required-list tolerance: absent-or-null reads None
   (the swagger's own example bodies show logprobs: null).
   message.tool_calls items are held raw by the document parse and
   validated per item on the typed Choice.tool_calls view (the
   swagger leaves the item shape untyped). Streaming deltas are
   M11. *)

module Response : sig
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

    val of_string : string -> (t, Error.t) result
  end

  module Stop_reason : sig
    (* stop_reason wire enum, closed; the member itself is
       nullable. *)
    type t =
      | Stop
      | Length

    val to_string : t -> string
    val of_string : string -> (t, Error.t) result
  end

  module Usage : sig
    (* The three counts are required wire integers; the details
       members project as options (null or absent details objects
       collapse to None). No cross-field arithmetic check: prompt +
       completion vs total is server-owned. *)
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
    (* The swagger's flat token record plus top_logprobs; NOT
       OpenAI's content array. logprob is exact (no float crosses
       the boundary). *)
    type entry

    val entry_token : entry -> string
    val entry_logprob : entry -> Json.dec
    val entry_bytes : entry -> int list option

    type t

    val token : t -> string
    val logprob : t -> Json.dec
    val bytes : t -> int list option

    val top_logprobs : t -> entry list
    (* absent top_logprobs reads [] *)
  end

  module Cost : sig
    (* Optional member; when present both currencies are required
       and >= 0 (the schema's only minimum: 0 keywords). *)
    type t

    val usd : t -> Json.dec
    val diem : t -> Json.dec
  end

  module Choice : sig
    (* One parsed assistant choice. content collapses the wire's
       three variants: a string reads Some, null/absent read None,
       and a text-parts array reads Some of the parts' texts
       concatenated in received order (a projection, not a claim the
       wire sent one string). content "" and content [] are both
       wire-legal: the string "" projects to Some "" (the faithful
       reading; Msg.assistant rejects it as empty on a text-only
       turn but collapses it to absent when tool_calls is nonempty,
       so the passthrough call round-trips either way), while the
       empty parts array projects to None. reasoning_details
       collapses absent, null and [] to the same [], so
       Msg.assistant ?reasoning_details:(Some (reasoning_details c))
       round-trips without Error. *)
    type t

    val finish : t -> Finish.t
    val index : t -> int
    val content : t -> string option
    val reasoning_content : t -> string option
    val reasoning_details : t -> Reasoning_detail.t list
    val thought_signature : t -> Thought_signature.t option
    val logprobs : t -> Logprobs.t option
    val stop_reason : t -> Stop_reason.t option

    val tool_calls_raw : t -> Json.t list
    (* message.tool_calls items verbatim; absent or null reads [],
       and the document parse never inspects an item *)

    val tool_calls : t -> (Tool_call.t list, Error.t) result
    (* the typed view: each raw item through the strict Tool_call
       mint (id nonempty; type, when present, "function";
       function.name nonempty; function.arguments a string held
       verbatim); the first failure wins and carries its
       choices[i].tool_calls[j] path *)
  end

  type t

  val of_string : string -> (t, Error.t) result
  (* Enforced: top-level id, model, created, object, usage present;
     object equals "chat.completion"; choice
     finish_reason/index/message present; the usage counts present,
     integers, each >= 0; created >= 0; choice index >= 0; cost
     usd/diem >= 0. Only cost carries a schema minimum: 0; the other
     floors are SDK-imposed strictness. Enum strings outside the
     closed sets reject. Absent choices parses as []. Besides
     Resp_invalid, of_string can return Json_invalid (the underlying
     JSON parse) and Msg_invalid (the reasoning_detail seam); each
     error keeps its own prefix, so the failing domain stays
     identifiable. *)

  val id : t -> string
  val model : t -> string
  val created : t -> int
  val choices : t -> Choice.t list
  val usage : t -> Usage.t
  val cost : t -> Cost.t option
end

(* M11 SSE streaming. Incremental WHATWG-profile framing under the
   Venice discipline: dispatched payloads classify as Data | Done
   ([DONE] sentinel), any event after Done rejects, and close
   enforces the closing policy. Strictness narrower than the WHATWG
   spec: CRLF and LF terminate lines, a bare CR rejects, and close
   rejects pending residues where the spec discards them; event, id
   and retry fields are ignored (a request-scoped completion stream
   has no reconnection machinery). Payloads are never assumed JSON
   (E2EE streams carry hex ciphertext); Chunk parses one Data
   payload as a chat.completion.chunk document. The whole chunk
   shape is the OpenAI-compat hypothesis (the swagger has no chunk
   schema), so every rejection names the failing member and the M2
   probe corrects from the error text alone. *)

module Sse : sig
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
    (t, Error.t) result
  (* closing defaults Require_done: close before [DONE] rejects even
     over clean framing (a mid-completion cut is detectable even
     when the transport reports success); Allow_eof accepts a clean
     EOF but still rejects pending residues. Byte caps default
     1_048_576 (line) and 4_194_304 (event), each >= 1, enforced
     during accumulation; at-cap exactly passes. *)

  val feed : t -> string -> (t * event list, Error.t) result
  (* Events in dispatch order. Errors are terminal by contract: the
     old t is still a value, feeding it again is caller misuse.
     Empty feed is a no-op. *)

  val close : t -> (unit, Error.t) result
  (* Every close rejection before Done carries a 200-byte prefix of
     the last payload seen, so a truncation error can never mask the
     server error that preceded it. *)

  module Chunk : sig
    module Delta : sig
      (* The per-chunk delta. Cross-chunk accumulation of tool-call
         fragments into Tool_call.t is deferred to M14; M11 ships
         the per-chunk view only. *)

      type fragment

      val fragment_index : fragment -> int
      val fragment_id : fragment -> string option
      val fragment_name : fragment -> string option
      val fragment_arguments : fragment -> string option
      val fragment_raw : fragment -> Json.t

      type t

      val role : t -> string option
      (* verbatim string, NO enum: wholly unpinned member *)

      val content : t -> string option
      (* absent-or-null reads None; content "" stays Some "" *)

      val reasoning_content : t -> string option

      val tool_calls_raw : t -> Json.t list
      (* items verbatim; absent or null reads [], and the document
         parse never inspects an item *)

      val tool_call_fragments : t -> (fragment list, Error.t) result
      (* the typed view: the first failing item wins and carries its
         choices[i].delta.tool_calls[j] path *)
    end

    module Choice : sig
      (* index required >= 0; delta absent-or-null reads the empty
         delta. finish_reason / stop_reason are held raw (absent or
         null reads None, a foreign value never rejects the
         document) with typed views over the Response closed enums
         that fail loudly with their choices[i] paths: the terminal
         chunk must not lose its end-of-turn signal to an unpinned
         enum. *)
      type t

      val index : t -> int
      val delta : t -> Delta.t
      val finish_reason_raw : t -> Json.t option
      val stop_reason_raw : t -> Json.t option
      val finish : t -> (Response.Finish.t option, Error.t) result

      val stop_reason :
        t -> (Response.Stop_reason.t option, Error.t) result
    end

    type t

    val of_string : string -> (t, Error.t) result
    (* Enforced floor (hypothesis, no schema): object present and
       equal to "chat.completion.chunk"; id, model, created present;
       created >= 0. choices absent or null reads [] (a usage-only
       final chunk has choices []). usage optional, parsed by the
       ONE usage grammar shared with Response, re-domained to the
       chunk prefix. A top-level error member returns the "server
       error: " channel with a bounded payload render. Besides
       Chunk_invalid, of_string can return Json_invalid (the
       underlying JSON parse); each error keeps its own prefix. *)

    val id : t -> string
    val model : t -> string
    val created : t -> int
    val choices : t -> Choice.t list
    val usage_opt : t -> Response.Usage.t option
  end
end

module Api_key : sig
  (* The Venice API key. Bytes 0x21..0x7E only, 1..512 of them, so no
     space, control byte or high byte can fold a header or split a
     curl config line.

     There is deliberately no projection here: the key has no
     printable image THROUGH THE PUBLIC API. This is a boundary, not
     a guarantee. Venice__Keyx.reveal stays reachable from any
     executable that links the library, exactly as the test suite
     reaches the other internal modules. *)
  type t

  val make : string -> (t, Error.t) result
  val from_env : unit -> (t, Error.t) result
  (* reads VENICE_API_KEY; an unset variable rejects by name *)
end

module Http : sig
  (* The sans-io request layer. Nothing here touches a socket or a
     process: Http builds and validates, Transport carries. *)

  module Endpoint : sig
    (* The API base. https only, no trailing slash, no query and no
       fragment, 1..2048 bytes. *)
    type t

    val default : t
    (* https://api.venice.ai/api/v1 *)

    val of_string : string -> (t, Error.t) result
    val to_string : t -> string
  end

  module Route : sig
    (* The four M13 routes, indexed by their method. get and post are
       uninhabited markers, so Request.get on a POST route and
       Request.post on a GET route fail to TYPECHECK. There is no
       run-time method rejection to test. *)
    type get
    type post
    type 'm t

    val chat_completions : post t
    val models : get t
    val tee_attestation : get t
    val tee_signature : get t
    val path : 'm t -> string
  end

  module Request : sig
    (* One request, validated at construction. Query pairs are
       percent-encoded per RFC 3986: unreserved bytes pass, every
       other byte becomes %XX in UPPERCASE hex, one escape per byte,
       so UTF-8 encodes per byte. At most 16 pairs, no duplicate key,
       no empty key.

       Header names are RFC 7230 tchar, 1..128 bytes, lowercased on
       the way in, so the lowercased name is what headers and to_log
       show. The reserved names the transport owns reject in any
       casing: authorization, proxy-authorization, cookie,
       content-type, content-length, host, expect,
       transfer-encoding, connection, accept, accept-encoding and
       user-agent. At most 32 headers, no
       duplicate name. Values are 0x20..0x7E plus HTAB, at most 8192
       bytes, no leading or trailing whitespace, so no value can fold
       a header or inject a line.

       A POST body is rendered ONCE at construction and the rendered
       bytes are carried, so the transport never re-emits JSON and
       the byte count it checks is the byte count it sends. The raw
       cap is 4_194_304 bytes, which stays under the curl config-line
       cap after the worst-case escaping. *)
    type meth =
      | Get
      | Post

    type t

    val get :
      ?query:(string * string) list ->
      ?headers:(string * string) list ->
      Route.get Route.t ->
      (t, Error.t) result

    val post :
      ?headers:(string * string) list ->
      Route.post Route.t ->
      body:Json.t ->
      (t, Error.t) result

    val meth : t -> meth
    val path : t -> string
    val query : t -> (string * string) list
    val headers : t -> (string * string) list
    val body : t -> Json.t option
    val rendered : t -> string option
    (* the body bytes exactly as the transport will send them *)

    val body_bytes : t -> int
    val url : Endpoint.t -> t -> string
    val to_log : t -> string
    (* "METH PATH?QUERY headers=[n1;n2] body_bytes=N", header NAMES
       only, so a log line can never carry a value or a secret *)
  end

  module Wire : sig
    (* The incremental response-head reader. It is fed arbitrary
       chunk boundaries and returns the head once, with the leftover
       body bytes.

       A line ends with CRLF or with a bare LF, because curl -i
       copies the server bytes verbatim and real servers send both.
       A bare CR inside a line rejects, and an obs-fold continuation
       line rejects. At most four 1xx blocks are skipped. The head
       may not exceed 65536 bytes. *)
    type head =
      { version : string;
        status : int;
        reason : string;
        pairs : (string * string) list
      }

    type t

    type step =
      | More of t
      | Head of head * string

    val make : ?max_head_bytes:int -> unit -> (t, Error.t) result
    val feed : t -> string -> (step, Error.t) result
    (* Feeding after Head is impossible by construction: the Head
       step hands back no machine. feed is pure, so the same machine
       and the same bytes always give the same step. *)
  end
end

module Transport : sig
  (* How a request reaches Venice. M15 will functorize the client
     over S, so a test links Fake and a program links Curl with no
     other change. *)

  module type S = sig
    type t
    type body

    val send :
      t ->
      key:Api_key.t ->
      Http.Request.t ->
      (Http.Wire.head * body, Error.t) result

    val read : body -> (string option, Error.t) result
    val read_all : ?cap:int -> body -> (string, Error.t) result
    val close : body -> (unit, Error.t) result
  end

  module Curl : sig
    (* The curl subprocess. argv is [binary; "-q"; "-K"; "-"], so ps
       shows no secret and no URL: the key and the URL arrive on
       stdin as a curl config and die with the process. Errors carry
       the last 4096 bytes of stderr with the key bytes replaced by
       "[redacted]". *)
    include S

    val make :
      ?binary:string ->
      ?endpoint:Http.Endpoint.t ->
      ?connect_timeout:int ->
      ?idle_timeout:int ->
      ?max_time:int ->
      unit ->
      (t, Error.t) result
    (* Defaults: "curl", Endpoint.default, 30, 300, no max_time. make
       probes the binary once with --version and rejects below curl
       7.67.0. It also sets SIGPIPE to ignore, once per process. *)

    val version : t -> string
    val max_line : t -> int
    (* the curl config-line cap for this binary: 10_485_248 from
       8.2.0, 65_536 below it *)
  end

  module Fake : sig
    (* A scripted transport for tests. No process, no network. *)
    include S

    type exchange

    val exchange :
      head:string ->
      chunks:string list ->
      ?close_error:string ->
      unit ->
      exchange
    (* head is the raw head bytes, terminator included; bytes after
       the blank line become the first read *)

    val make : exchange list -> t
    val requests : t -> Http.Request.t list
    (* every request send accepted, in call order *)
  end
end
