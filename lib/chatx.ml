(* M9 chat request domain. One mint (make) builds an erased request
   record behind the phantom brand 'c: the model witness, the
   messages, and every capability-gated member tie to ONE model row,
   and the encoder reads the request model from that witness, so the
   request model and the witness model cannot diverge (D2). Emission
   is deterministic: the frozen member-order list below is the one
   source of order, absent optionals never emit, and no member is
   ever emitted as null (D8/A8). Sans-io: the output is the request
   body bytes; endpoint constants, auth, and E2EE headers belong to
   the transport milestones. *)

let ( let* ) = Result.bind

let invalid (msg : string) : ('a, Errx.t) result =
  Error (Errx.Chat_invalid msg)

module Stop = struct
  (* The stop member: one sequence, or 1..4 sequences (schema
     minItems 1, maxItems 4). The empty string rejects in both forms
     as SDK strictness (bare-string precedent). The wire's null
     branch is expressed by NOT passing ?stop; the SDK never emits
     null (D7). *)
  type t =
    | Sone of string
    | Slist of string list

  let of_string (s : string) : (t, Errx.t) result =
    if String.equal s "" then invalid "stop: empty string"
    else Ok (Sone s)

  let of_list (items : string list) : (t, Errx.t) result =
    let count = List.length items in
    match () with
    | () when Int.equal count 0 -> invalid "stop: empty list"
    | () when count > 4 ->
      invalid ("stop: " ^ string_of_int count ^ " items: above max 4")
    | () when List.exists (String.equal "") items ->
      invalid "stop: item: empty string"
    | () -> Ok (Slist items)

  let to_json (t : t) : Jsonx.t =
    match t with
    | Sone s -> Jsonx.Jstring s
    | Slist items ->
      Jsonx.Jlist (List.map (fun (s : string) -> Jsonx.Jstring s) items)
end

module Effort = struct
  (* reasoning_effort wire enum, closed; None_ avoids the OCaml
     keyword. Emitted only as the top-level reasoning_effort member
     (the precedence winner over reasoning.effort); the nested
     reasoning object is never emitted (D6). *)
  type t =
    | None_
    | Minimal
    | Low
    | Medium
    | High
    | Xhigh
    | Max

  let to_string (e : t) : string =
    match e with
    | None_ -> "none"
    | Minimal -> "minimal"
    | Low -> "low"
    | Medium -> "medium"
    | High -> "high"
    | Xhigh -> "xhigh"
    | Max -> "max"

  let of_string (s : string) : (t, Errx.t) result =
    match s with
    | "none" -> Ok None_
    | "minimal" -> Ok Minimal
    | "low" -> Ok Low
    | "medium" -> Ok Medium
    | "high" -> Ok High
    | "xhigh" -> Ok Xhigh
    | "max" -> Ok Max
    | other -> invalid ("effort: unknown value " ^ other)
end

module Cache_retention = struct
  (* prompt_cache_retention wire enum, closed; H24 is the "24h" wire
     value. *)
  type t =
    | Default
    | Extended
    | H24

  let to_string (r : t) : string =
    match r with
    | Default -> "default"
    | Extended -> "extended"
    | H24 -> "24h"

  let of_string (s : string) : (t, Errx.t) result =
    match s with
    | "default" -> Ok Default
    | "extended" -> Ok Extended
    | "24h" -> Ok H24
    | other -> invalid ("prompt_cache_retention: unknown value " ^ other)
end

(* The erased request repr. messages is stored already emitted through
   the one msgx seam (Msgx.emit), so the brand erases here exactly as
   it does in msgx; the model's context window and completion cap are
   captured at mint for the budget check, and the witness pairs erase
   to their payloads. *)
type repr =
  { model : string;
    messages : Jsonx.t;
    context_tokens : int option;
    model_completion_cap : int option;
    temperature : Paramsx.Temp.t option;
    top_p : Paramsx.Top_p.t option;
    frequency_penalty : Paramsx.Frequency_penalty.t option;
    presence_penalty : Paramsx.Presence_penalty.t option;
    repetition_penalty : Paramsx.Repetition_penalty.t option;
    top_k : Paramsx.Top_k.t option;
    venice : Paramsx.Venice_params.t option;
    max_completion : int option;
    stop : Stop.t option;
    stop_token_ids : int list option;
    seed : int option;
    n : int option;
    logprobs : bool option;
    top_logprobs : int option;
    effort : Effort.t option;
    prompt_cache_key : string option;
    cache_retention : Cache_retention.t option }

type 'c t = repr

let kind_name (k : Modelx.kind) : string =
  match k with
  | Modelx.Text -> "text"
  | Modelx.Code -> "code"
  | Modelx.Image -> "image"
  | Modelx.Embedding -> "embedding"
  | Modelx.Tts -> "tts"
  | Modelx.Asr -> "asr"
  | Modelx.Music -> "music"
  | Modelx.Upscale -> "upscale"
  | Modelx.Inpaint -> "inpaint"
  | Modelx.Video -> "video"

(* A2: every M9 guard reads text-model fields
   (availableContextTokens, maxCompletionTokens), so a model of any
   other kind rejects at mint instead of passing vacuous checks. *)
let check_kind (m : 'c Modelx.t) : (unit, Errx.t) result =
  match Modelx.kind m with
  | Modelx.Text | Modelx.Code -> Ok ()
  | (Modelx.Image | Modelx.Embedding | Modelx.Tts | Modelx.Asr
    | Modelx.Music | Modelx.Upscale | Modelx.Inpaint | Modelx.Video) as k
    ->
    invalid ("make: model kind " ^ kind_name k ^ ": not a text-like model")

let check_min (member : string) (floor : int) (v : int option) :
    (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (x : int) ->
      if x >= floor then Ok ()
      else
        invalid
          ("make: " ^ member ^ " " ^ string_of_int x ^ ": below "
           ^ string_of_int floor))
    v

(* D4(a): mint-time completion cap. A model that publishes no cap
   accepts any minted value. *)
let check_completion_cap (cap : int option) (req : int option) :
    (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (m : int) ->
      Option.fold ~none:(Ok ())
        ~some:(fun (c : int) ->
          if m <= c then Ok ()
          else
            invalid
              ("make: max_completion " ^ string_of_int m
               ^ ": above model cap " ^ string_of_int c))
        cap)
    req

(* A3: top_logprobs rides the logprobs witness AND the carried bool:
   passing it with logprobs absent or false rejects; with logprobs
   true it must be >= 0. *)
let check_top_logprobs (has_logprobs : bool) (tl : int option) :
    (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (v : int) ->
      match () with
      | () when not has_logprobs ->
        invalid "make: top_logprobs: passed without logprobs"
      | () when v < 0 ->
        invalid ("make: top_logprobs " ^ string_of_int v ^ ": below 0")
      | () -> Ok ())
    tl

(* A1: reasoningEffortOptions is published only alongside
   supportsReasoningEffort. With the witness in hand, a present list
   checks membership and an absent list accepts. *)
let check_effort (w : ('c * Modelx.reasoning_effort) Modelx.t)
    (e : Effort.t) : (unit, Errx.t) result =
  let wire = Effort.to_string e in
  match Modelx.effort_options w with
  | [] -> Ok ()
  | (_ :: _) as opts ->
    if List.exists (String.equal wire) opts then Ok ()
    else invalid ("make: effort " ^ wire ^ ": not in reasoningEffortOptions")

let check_stop_token_ids (ids : int list option) : (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (items : int list) ->
      match items with
      | [] -> invalid "make: stop_token_ids: empty list"
      | _ :: _ ->
        Option.fold ~none:(Ok ())
          ~some:(fun (bad : int) ->
            invalid
              ("make: stop_token_ids " ^ string_of_int bad ^ ": below 0"))
          (List.find_opt (fun (x : int) -> x < 0) items))
    ids

let check_cache_key (key : string option) : (unit, Errx.t) result =
  Option.fold ~none:(Ok ())
    ~some:(fun (k : string) ->
      if String.equal k "" then
        invalid "make: prompt_cache_key: empty string"
      else Ok ())
    key

(* The one mint. Optionals first with a trailing unit so every
   optional stays erasable (A4, msgx warning-16 precedent); the
   sampling newtypes arrive ALREADY MINTED (D13), so no constraint
   parsing happens here. *)
let make ?(temperature : Paramsx.Temp.t option)
    ?(top_p : Paramsx.Top_p.t option)
    ?(frequency_penalty : Paramsx.Frequency_penalty.t option)
    ?(presence_penalty : Paramsx.Presence_penalty.t option)
    ?(repetition_penalty : Paramsx.Repetition_penalty.t option)
    ?(top_k : Paramsx.Top_k.t option)
    ?(venice : Paramsx.Venice_params.t option)
    ?(max_completion : int option) ?(stop : Stop.t option)
    ?(stop_token_ids : int list option) ?(seed : int option)
    ?(n : int option)
    ?(logprobs : (('c * Modelx.log_probs) Modelx.t * bool) option)
    ?(top_logprobs : int option)
    ?(effort : (('c * Modelx.reasoning_effort) Modelx.t * Effort.t) option)
    ?(prompt_cache_key : string option)
    ?(cache_retention : Cache_retention.t option) (model : 'c Modelx.t)
    (msgs : 'c Msgx.nonempty) (() : unit) : ('c t, Errx.t) result =
  let* () = check_kind model in
  let* () = check_min "max_completion" 1 max_completion in
  let* () =
    check_completion_cap (Modelx.max_completion_tokens model) max_completion
  in
  let* () = check_min "seed" 1 seed in
  let* () = check_min "n" 1 n in
  let* () =
    check_top_logprobs
      (Option.fold ~none:false ~some:snd logprobs)
      top_logprobs
  in
  let* () =
    Option.fold ~none:(Ok ()) ~some:(fun (w, e) -> check_effort w e) effort
  in
  let* () = check_stop_token_ids stop_token_ids in
  let* () = check_cache_key prompt_cache_key in
  Ok
    { model = Modelx.id model;
      messages = Msgx.emit msgs;
      context_tokens = Modelx.context_tokens model;
      model_completion_cap = Modelx.max_completion_tokens model;
      temperature;
      top_p;
      frequency_penalty;
      presence_penalty;
      repetition_penalty;
      top_k;
      venice;
      max_completion;
      stop;
      stop_token_ids;
      seed;
      n;
      logprobs = Option.map snd logprobs;
      top_logprobs;
      effort = Option.map snd effort;
      prompt_cache_key;
      cache_retention }

(* D4(b): advisory context budget, separate from the mint (a mint
   gate would force every caller to invent an estimate and train them
   to pass 0). effective completion is the requested max_completion
   when present, else the model's published cap, else 0; a model that
   publishes no context window reads Ok (absence of a cap is not
   evidence of overflow). *)
let budget (t : 'c t) ~(prompt_tokens : int) : (unit, Errx.t) result =
  match () with
  | () when prompt_tokens < 0 ->
    invalid
      ("budget: prompt_tokens " ^ string_of_int prompt_tokens ^ ": below 0")
  | () ->
    Option.fold ~none:(Ok ())
      ~some:(fun (ctx : int) ->
        let completion =
          Option.value t.max_completion
            ~default:(Option.value t.model_completion_cap ~default:0)
        in
        if prompt_tokens + completion <= ctx then Ok ()
        else
          invalid
            ("budget: prompt " ^ string_of_int prompt_tokens
             ^ " + completion " ^ string_of_int completion
             ^ ": exceeds context " ^ string_of_int ctx))
      t.context_tokens

(* A8: the SDK-owned frozen emission order: model, messages, then the
   D3 members in D3's listed order. A later milestone APPENDS its
   members here; nothing ever re-slots, so goldens stay byte-stable.
   test_chatx asserts this exact list next to the goldens. *)
let member_order (() : unit) : string list =
  [ "model";
    "messages";
    "temperature";
    "top_p";
    "frequency_penalty";
    "presence_penalty";
    "repetition_penalty";
    "top_k";
    "venice_parameters";
    "max_completion_tokens";
    "stream";
    "stream_options";
    "stop";
    "stop_token_ids";
    "seed";
    "n";
    "logprobs";
    "top_logprobs";
    "reasoning_effort";
    "prompt_cache_key";
    "prompt_cache_retention" ]

let opt_member (name : string) (f : 'a -> Jsonx.t) (v : 'a option) :
    (string * Jsonx.t) list =
  Option.fold ~none:[] ~some:(fun x -> [ (name, f x) ]) v

(* venice_parameters emits only when non-empty (D3): an all-absent
   object asks for every server default, which absence already
   says. *)
let venice_member (v : Paramsx.Venice_params.t option) :
    (string * Jsonx.t) list =
  Option.fold ~none:[]
    ~some:(fun (p : Paramsx.Venice_params.t) ->
      if Paramsx.Venice_params.is_empty p then []
      else [ ("venice_parameters", Paramsx.Venice_params.to_json p) ])
    v

(* Every present member, keyed for the order fold below. stream and
   include_usage arrive per call (A7): streaming is chosen at the
   client call site, not at mint, and the SDK does not tie
   include_usage to stream (the schema does not; rejecting would be a
   guess, D10). *)
let present_members (stream : bool option) (include_usage : bool option)
    (t : repr) : (string * Jsonx.t) list =
  List.concat
    [ [ ("model", Jsonx.Jstring t.model); ("messages", t.messages) ];
      opt_member "temperature"
        (fun v -> Jsonx.Jdec (Paramsx.Temp.to_dec v))
        t.temperature;
      opt_member "top_p"
        (fun v -> Jsonx.Jdec (Paramsx.Top_p.to_dec v))
        t.top_p;
      opt_member "frequency_penalty"
        (fun v -> Jsonx.Jdec (Paramsx.Frequency_penalty.to_dec v))
        t.frequency_penalty;
      opt_member "presence_penalty"
        (fun v -> Jsonx.Jdec (Paramsx.Presence_penalty.to_dec v))
        t.presence_penalty;
      opt_member "repetition_penalty"
        (fun v -> Jsonx.Jdec (Paramsx.Repetition_penalty.to_dec v))
        t.repetition_penalty;
      opt_member "top_k"
        (fun v -> Jsonx.Jint (Paramsx.Top_k.to_int v))
        t.top_k;
      venice_member t.venice;
      opt_member "max_completion_tokens"
        (fun (x : int) -> Jsonx.Jint x)
        t.max_completion;
      opt_member "stream" (fun (b : bool) -> Jsonx.Jbool b) stream;
      opt_member "stream_options"
        (fun (b : bool) -> Jsonx.Jobj [ ("include_usage", Jsonx.Jbool b) ])
        include_usage;
      opt_member "stop" Stop.to_json t.stop;
      opt_member "stop_token_ids"
        (fun (ids : int list) ->
          Jsonx.Jlist (List.map (fun (x : int) -> Jsonx.Jint x) ids))
        t.stop_token_ids;
      opt_member "seed" (fun (x : int) -> Jsonx.Jint x) t.seed;
      opt_member "n" (fun (x : int) -> Jsonx.Jint x) t.n;
      opt_member "logprobs" (fun (b : bool) -> Jsonx.Jbool b) t.logprobs;
      opt_member "top_logprobs"
        (fun (x : int) -> Jsonx.Jint x)
        t.top_logprobs;
      opt_member "reasoning_effort"
        (fun (e : Effort.t) -> Jsonx.Jstring (Effort.to_string e))
        t.effort;
      opt_member "prompt_cache_key"
        (fun (s : string) -> Jsonx.Jstring s)
        t.prompt_cache_key;
      opt_member "prompt_cache_retention"
        (fun (r : Cache_retention.t) ->
          Jsonx.Jstring (Cache_retention.to_string r))
        t.cache_retention ]

(* The emitter folds over the ONE frozen literal above (A8); a member
   absent from present_members simply never emits. *)
let to_json ?(stream : bool option) ?(include_usage : bool option)
    (t : 'c t) : Jsonx.t =
  let avail = present_members stream include_usage t in
  Jsonx.Jobj
    (List.concat_map
       (fun (name : string) ->
         Option.fold ~none:[]
           ~some:(fun (v : Jsonx.t) -> [ (name, v) ])
           (List.assoc_opt name avail))
       (member_order ()))

(* sessx re-key seam (A7): replace the messages, keep every other
   member; the shared 'c keeps the replacement on the same model
   row. *)
let with_messages (msgs : 'c Msgx.nonempty) (t : 'c t) : 'c t =
  { t with messages = Msgx.emit msgs }

let emit (t : 'c t) : string = Jsonx.emit (to_json t)
