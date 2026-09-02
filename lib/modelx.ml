(* M5 model domain. A /models entry parses to a packed capability row.
   The phantom parameter 'caps records which capability witnesses the
   caller has extracted; the extractors below inspect what the server
   asserted and are the only mint, so an API that demands e.g. a
   ('c * vision) t (M7 content parts, M29 session establish) cannot be
   called without the listing having asserted the capability. The wire
   schema is strict wherever FACTS.md documents a closed set (kind,
   privacy, quantization: foreign values reject loudly) and open only
   where the world is open (model slugs). Every field name is a
   FACTS.md hypothesis until the M2 probe pins fixtures. *)

let ( let* ) = Result.bind

(* Phantom capability markers, uninhabited. audio and tee join the
   DESIGN sketch's four: M7 audio parts and the attestation call (M21+)
   each need their own witness. video joins at M7 for video parts. *)
type vision = |
type tools = |
type reasoning = |
type audio = |
type tee = |
type e2ee = |

(* video-INPUT capability marker (wire supportsVideoInput). Distinct
   from the kind constructor Video below, which names a
   video-GENERATION model kind. *)
type video = |

(* reasoning_effort request-member capability marker (wire
   supportsReasoningEffort). Distinct from reasoning: the effort menu
   is its own server assertion, so it carries its own witness (A1). *)
type reasoning_effort = |

(* logprobs request-member capability marker (wire supportsLogProbs). *)
type log_probs = |

(* response_format json_schema capability marker (wire
   supportsResponseSchema). Gates the schema arm only: json_object
   carries no witness (no capability row asserts it). *)
type response_schema = |

type slug =
  | E2ee_qwen3_5_122b_a10b
  | E2ee_glm_5
  | Unknown of string

let slug_of_id (id : string) : slug =
  match id with
  | "e2ee-qwen3-5-122b-a10b" -> E2ee_qwen3_5_122b_a10b
  | "e2ee-glm-5" -> E2ee_glm_5
  | other -> Unknown other

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
  (* video-GENERATION model kind; the video-INPUT capability marker is
     the uninhabited type video above. *)
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

type deprecation =
  | Active
  | Deprecated of
      { dates : (string * string) list;
        replacement : string option }

(* Capability booleans as asserted by the server; quantization, the
   reasoning-effort menu, and the image/video count limits ride in the
   same wire object. *)
type caps =
  { optimized_for_code : bool;
    function_calling : bool;
    reasoning : bool;
    reasoning_effort : bool;
    response_schema : bool;
    vision : bool;
    multiple_images : bool;
    max_images : int option;
    max_videos : int option;
    video_input : bool;
    audio_input : bool;
    web_search : bool;
    log_probs : bool;
    tee_attestation : bool;
    e2ee : bool;
    x_search : bool;
    effort_options : string list;
    quantization : quantization option }

(* model_spec scalars; every one is optional on the wire. *)
type spec =
  { spec_privacy : privacy option;
    spec_context_tokens : int option;
    spec_max_completion_tokens : int option;
    spec_beta : bool;
    spec_deprecation : deprecation }

type repr =
  { id : string;
    kind : kind;
    created : int option;
    traits : string list;
    offline : bool;
    beta : bool;
    privacy : privacy option;
    context_tokens : int option;
    max_completion_tokens : int option;
    deprecation : deprecation;
    caps : caps option;
    constraints : (string * Jsonx.t) list }

(* 'caps is phantom: this alias erases it inside the library, and
   venice.mli re-abstracts the constructor, which is where the
   guarantee lives; a consumer can neither forge a marker nor cast. *)
type 'caps t = repr

type packed = Pack : 'c t -> packed

let invalid (msg : string) : ('a, Errx.t) result =
  Error (Errx.Model_invalid msg)

let require (what : string) (o : 'a option) : ('a, Errx.t) result =
  Option.fold ~none:(Error (Errx.Model_invalid what)) ~some:Result.ok o

let require_obj (ctx : string) (j : Jsonx.t) :
    ((string * Jsonx.t) list, Errx.t) result =
  require (ctx ^ ": not an object") (Jsonx.as_obj j)

(* Member lookup that normalizes an explicit JSON null to absence:
   every optional field reads through here, so "field": null parses
   exactly like an omitted field instead of failing the whole entry
   (and, folded through of_listing, the whole listing). *)
let member_nn (name : string) (j : Jsonx.t) : Jsonx.t option =
  Option.bind (Jsonx.member name j) (fun v ->
      match (v : Jsonx.t) with
      | Jsonx.Jnull -> None
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jlist _ | Jsonx.Jobj _ -> Some v)

(* One Result-collecting map for every wire list: the fold
   short-circuits on the first error and the single reversal restores
   order. *)
let result_map_list (f : 'a -> ('b, Errx.t) result) (items : 'a list) :
    ('b list, Errx.t) result =
  Result.map List.rev
    (List.fold_left
       (fun acc item ->
         let* xs = acc in
         let* y = f item in
         Ok (y :: xs))
       (Ok []) items)

let str_member (name : string) (j : Jsonx.t) : string option =
  Option.bind (member_nn name j) Jsonx.as_string

(* Absent reads as false: the wire omits capabilities it lacks. A
   present non-bool is a schema surprise and rejects. *)
let bool_member (ctx : string) (name : string) (j : Jsonx.t) :
    (bool, Errx.t) result =
  Option.fold ~none:(Ok false)
    ~some:(fun v ->
      require (ctx ^ "." ^ name ^ ": not a bool") (Jsonx.as_bool v))
    (member_nn name j)

let int_member (ctx : string) (name : string) (j : Jsonx.t) :
    (int option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v ->
      Result.map Option.some
        (require (ctx ^ "." ^ name ^ ": not an int") (Jsonx.as_int v)))
    (member_nn name j)

let strings (what : string) (items : Jsonx.t list) :
    (string list, Errx.t) result =
  result_map_list
    (fun item ->
      require (what ^ ": item not a string") (Jsonx.as_string item))
    items

let string_list_member (what : string) (v : Jsonx.t option) :
    (string list, Errx.t) result =
  Option.fold ~none:(Ok [])
    ~some:(fun j ->
      let* items = require (what ^ ": not a list") (Jsonx.as_list j) in
      strings what items)
    v

let kind_of_string (ctx : string) (s : string) : (kind, Errx.t) result =
  match s with
  | "text" -> Ok Text
  | "code" -> Ok Code
  | "image" -> Ok Image
  | "embedding" -> Ok Embedding
  | "tts" -> Ok Tts
  | "asr" -> Ok Asr
  | "music" -> Ok Music
  | "upscale" -> Ok Upscale
  | "inpaint" -> Ok Inpaint
  | "video" -> Ok Video
  | other -> invalid (ctx ^ ".type: unknown value " ^ other)

let privacy_of_string (ctx : string) (s : string) :
    (privacy, Errx.t) result =
  match s with
  | "private" -> Ok Private
  | "anonymized" -> Ok Anonymized
  | other -> invalid (ctx ^ ".privacy: unknown value " ^ other)

let quantization_of_string (ctx : string) (s : string) :
    (quantization, Errx.t) result =
  match s with
  | "fp4" -> Ok Fp4
  | "fp8" -> Ok Fp8
  | "fp16" -> Ok Fp16
  | "bf16" -> Ok Bf16
  | "int8" -> Ok Int8
  | "int4" -> Ok Int4
  | "not-available" -> Ok Not_available
  | other -> invalid (ctx ^ ".quantization: unknown value " ^ other)

(* A deprecation member whose key starts with "replacement" names the
   successor slug; the exact spelling (replacement / replacementModel)
   is an M2 hypothesis, so match the prefix. Bytesx.take is the total
   substring. *)
let is_replacement (k : string) : bool =
  Option.fold ~none:false ~some:(String.equal "replacement")
    (Bytesx.take k 0 11)

(* Date members arrive as strings or unix-second ints; both keep their
   printed form. Anything else is a schema surprise. *)
let dep_value (ctx : string) (k : string) (v : Jsonx.t) :
    (string, Errx.t) result =
  require
    (ctx ^ ".deprecation." ^ k ^ ": not a string or int")
    (Option.fold
       ~none:(Option.map string_of_int (Jsonx.as_int v))
       ~some:Option.some (Jsonx.as_string v))

let deprecation_of_json (ctx : string) (v : Jsonx.t option) :
    (deprecation, Errx.t) result =
  Option.fold ~none:(Ok Active)
    ~some:(fun j ->
      match (j : Jsonx.t) with
      | Jsonx.Jnull -> Ok Active
      | Jsonx.Jobj fields ->
        let* pairs =
          result_map_list
            (fun ((k : string), jv) ->
              Result.map (fun (s : string) -> (k, s)) (dep_value ctx k jv))
            fields
        in
        let replacement =
          Option.map snd
            (List.find_opt (fun (k, (_ : string)) -> is_replacement k) pairs)
        in
        let dates =
          List.filter (fun (k, (_ : string)) -> not (is_replacement k)) pairs
        in
        (* An empty deprecation object asserts nothing: with no date
           pairs and no replacement it reads Active, never a vacuous
           Deprecated. *)
        (match dates with
         | (_, _) :: _ -> Ok (Deprecated { dates; replacement })
         | [] ->
           Ok
             (Option.fold ~none:Active
                ~some:(fun (r : string) ->
                  Deprecated { dates = []; replacement = Some r })
                replacement))
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jlist _ ->
        invalid (ctx ^ ".deprecation: not an object"))
    v

let caps_of_json (ctx : string) (j : Jsonx.t) : (caps, Errx.t) result =
  let c = ctx ^ ".capabilities" in
  let* (_ : (string * Jsonx.t) list) = require_obj c j in
  let* optimized_for_code = bool_member c "optimizedForCode" j in
  let* function_calling = bool_member c "supportsFunctionCalling" j in
  let* reasoning = bool_member c "supportsReasoning" j in
  let* reasoning_effort = bool_member c "supportsReasoningEffort" j in
  let* response_schema = bool_member c "supportsResponseSchema" j in
  let* vision = bool_member c "supportsVision" j in
  let* multiple_images = bool_member c "supportsMultipleImages" j in
  let* max_images = int_member c "maxImages" j in
  let* max_videos = int_member c "maxVideos" j in
  let* video_input = bool_member c "supportsVideoInput" j in
  let* audio_input = bool_member c "supportsAudioInput" j in
  let* web_search = bool_member c "supportsWebSearch" j in
  let* log_probs = bool_member c "supportsLogProbs" j in
  let* tee_attestation = bool_member c "supportsTeeAttestation" j in
  let* e2ee = bool_member c "supportsE2EE" j in
  let* x_search = bool_member c "supportsXSearch" j in
  (* quantization is optional on the wire: absent (or null) reads
     None, while a present value must be a known enum string. *)
  let* quantization =
    Option.fold ~none:(Ok None)
      ~some:(fun v ->
        let* q =
          require (c ^ ".quantization: not a string") (Jsonx.as_string v)
        in
        Result.map Option.some (quantization_of_string c q))
      (member_nn "quantization" j)
  in
  let* effort_options =
    string_list_member
      (c ^ ".reasoningEffortOptions")
      (member_nn "reasoningEffortOptions" j)
  in
  Ok
    { optimized_for_code;
      function_calling;
      reasoning;
      reasoning_effort;
      response_schema;
      vision;
      multiple_images;
      max_images;
      max_videos;
      video_input;
      audio_input;
      web_search;
      log_probs;
      tee_attestation;
      e2ee;
      x_search;
      effort_options;
      quantization }

(* capabilities / constraints / spec scalars may live under model_spec
   or at the top of the entry: FACTS.md bullets them separately and the
   nesting is an M2 hypothesis, so read the model_spec location first
   and fall back to the top level. The returned context names the
   location the value actually came from, so an error reports the real
   path. *)
let nested_at (ctx : string) (name : string) (spec_j : Jsonx.t option)
    (top : Jsonx.t) : string * Jsonx.t option =
  let top_slot = (ctx, member_nn name top) in
  Option.fold ~none:top_slot
    ~some:(fun sj ->
      Option.fold ~none:top_slot
        ~some:(fun v -> (ctx ^ ".model_spec", Some v))
        (member_nn name sj))
    spec_j

let nested (name : string) (spec_j : Jsonx.t option) (top : Jsonx.t) :
    Jsonx.t option =
  let ((_ : string), v) = nested_at "" name spec_j top in
  v

(* model_spec scalars ride the same model_spec-first / top-level
   fallback as capabilities and constraints: a server that flattens
   deprecation, privacy, beta, or the token limits onto the entry is
   read, never silently defaulted. When both locations hold a value,
   model_spec wins. *)
let spec_of_json (ctx : string) (spec_j : Jsonx.t option) (top : Jsonx.t) :
    (spec, Errx.t) result =
  let* (_ : (string * Jsonx.t) list option) =
    Option.fold ~none:(Ok None)
      ~some:(fun j ->
        Result.map Option.some (require_obj (ctx ^ ".model_spec") j))
      spec_j
  in
  let slot (name : string) : string * Jsonx.t option =
    nested_at ctx name spec_j top
  in
  let int_slot (name : string) : (int option, Errx.t) result =
    let where, v = slot name in
    Option.fold ~none:(Ok None)
      ~some:(fun jv ->
        Result.map Option.some
          (require (where ^ "." ^ name ^ ": not an int") (Jsonx.as_int jv)))
      v
  in
  let* spec_privacy =
    let where, v = slot "privacy" in
    Option.fold ~none:(Ok None)
      ~some:(fun pv ->
        let* ps =
          require (where ^ ".privacy: not a string") (Jsonx.as_string pv)
        in
        Result.map Option.some (privacy_of_string where ps))
      v
  in
  let* spec_context_tokens = int_slot "availableContextTokens" in
  let* spec_max_completion_tokens = int_slot "maxCompletionTokens" in
  let* spec_beta =
    let where, v = slot "beta" in
    Option.fold ~none:(Ok false)
      ~some:(fun bv ->
        require (where ^ ".beta: not a bool") (Jsonx.as_bool bv))
      v
  in
  let* spec_deprecation =
    let where, v = slot "deprecation" in
    deprecation_of_json where v
  in
  Ok
    { spec_privacy;
      spec_context_tokens;
      spec_max_completion_tokens;
      spec_beta;
      spec_deprecation }

let of_json (j : Jsonx.t) : (packed, Errx.t) result =
  let* (_ : (string * Jsonx.t) list) = require_obj "entry" j in
  let* id = require "id: missing or not a string" (str_member "id" j) in
  let ctx = id in
  let* kind_s =
    require (ctx ^ ".type: missing or not a string") (str_member "type" j)
  in
  let* kind = kind_of_string ctx kind_s in
  let* created = int_member ctx "created" j in
  let* offline = bool_member ctx "offline" j in
  let* traits =
    string_list_member (ctx ^ ".traits") (member_nn "traits" j)
  in
  let spec_j = member_nn "model_spec" j in
  let* sp = spec_of_json ctx spec_j j in
  let* caps =
    Option.fold ~none:(Ok None)
      ~some:(fun v -> Result.map Option.some (caps_of_json ctx v))
      (nested "capabilities" spec_j j)
  in
  let* constraints =
    Option.fold ~none:(Ok [])
      ~some:(fun v -> require_obj (ctx ^ ".constraints") v)
      (nested "constraints" spec_j j)
  in
  Ok
    (Pack
       { id;
         kind;
         created;
         traits;
         offline;
         beta = sp.spec_beta;
         privacy = sp.spec_privacy;
         context_tokens = sp.spec_context_tokens;
         max_completion_tokens = sp.spec_max_completion_tokens;
         deprecation = sp.spec_deprecation;
         caps;
         constraints })

let of_listing (j : Jsonx.t) : (packed list, Errx.t) result =
  let* items =
    require "listing.data: missing or not a list"
      (Option.bind (Jsonx.member "data" j) Jsonx.as_list)
  in
  result_map_list of_json items

let id (m : 'c t) : string = m.id
let slug (m : 'c t) : slug = slug_of_id m.id
let kind (m : 'c t) : kind = m.kind
let created (m : 'c t) : int option = m.created
let traits (m : 'c t) : string list = m.traits
let offline (m : 'c t) : bool = m.offline
let beta (m : 'c t) : bool = m.beta
let privacy (m : 'c t) : privacy option = m.privacy
let context_tokens (m : 'c t) : int option = m.context_tokens
let max_completion_tokens (m : 'c t) : int option = m.max_completion_tokens
let deprecation (m : 'c t) : deprecation = m.deprecation

(* The typed constraints view parses on access, so a malformed inner
   parameter rejects at the call that needs it (with the model id on
   the path) instead of killing the whole listing at parse time. *)
let constraints (m : 'c t) : (Paramsx.Constraints.t, Errx.t) result =
  Paramsx.Constraints.of_raw m.id m.constraints

let quantization (m : 'c t) : quantization option =
  Option.bind m.caps (fun (c : caps) -> c.quantization)

let effort_options (m : 'c t) : string list =
  Option.fold ~none:[] ~some:(fun (c : caps) -> c.effort_options) m.caps

(* Witness extraction. A model with no capabilities object (image, tts,
   ...) asserts nothing, so every extractor reads None. *)
let has (f : caps -> bool) (m : 'c t) : bool =
  Option.fold ~none:false ~some:f m.caps

let vision (m : 'c t) : ('c * vision) t option =
  if has (fun c -> c.vision) m then Some m else None

let tools (m : 'c t) : ('c * tools) t option =
  if has (fun c -> c.function_calling) m then Some m else None

let reasoning (m : 'c t) : ('c * reasoning) t option =
  if has (fun c -> c.reasoning) m then Some m else None

let audio (m : 'c t) : ('c * audio) t option =
  if has (fun c -> c.audio_input) m then Some m else None

let tee (m : 'c t) : ('c * tee) t option =
  if has (fun c -> c.tee_attestation) m then Some m else None

let e2ee (m : 'c t) : ('c * e2ee) t option =
  if has (fun c -> c.e2ee) m then Some m else None

(* video-INPUT witness; the gate is caps.video_input
   (wire supportsVideoInput), never the Video model kind. *)
let video (m : 'c t) : ('c * video) t option =
  if has (fun c -> c.video_input) m then Some m else None

(* reasoning_effort witness; the gate is caps.reasoning_effort (wire
   supportsReasoningEffort), never caps.reasoning: the effort menu is
   its own server assertion. *)
let reasoning_effort (m : 'c t) : ('c * reasoning_effort) t option =
  if has (fun c -> c.reasoning_effort) m then Some m else None

(* logprobs witness (wire supportsLogProbs). *)
let log_probs (m : 'c t) : ('c * log_probs) t option =
  if has (fun c -> c.log_probs) m then Some m else None

(* response_format json_schema witness (wire supportsResponseSchema). *)
let response_schema (m : 'c t) : ('c * response_schema) t option =
  if has (fun c -> c.response_schema) m then Some m else None

(* The grouped multimodal view: all three media witnesses extracted in
   parallel at the base row 'c, so multimodal content never needs the
   stacking idiom. *)
type 'c media =
  { vision : ('c * vision) t option;
    audio : ('c * audio) t option;
    video : ('c * video) t option }

let media (m : 'c t) : 'c media =
  { vision = vision m; audio = audio m; video = video m }

(* Image/video count limits. supportsMultipleImages is REQUIRED on the
   wire for text listings; a model with no capabilities object still
   reads false. Single-image vision models silently drop all but the
   last image-bearing message server-side, so a caller must be able to
   read these fields to warn. *)
let multiple_images (m : 'c t) : bool =
  has (fun c -> c.multiple_images) m

let max_images (m : 'c t) : int option =
  Option.bind m.caps (fun (c : caps) -> c.max_images)

let max_videos (m : 'c t) : int option =
  Option.bind m.caps (fun (c : caps) -> c.max_videos)
