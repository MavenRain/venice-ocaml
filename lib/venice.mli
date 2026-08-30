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
