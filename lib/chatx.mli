(* M9 chat request interface. The brand is phantom over one erased
   repr; venice.mli re-abstracts make, budget, and emit for library
   users and hoists Stop, Effort, and Cache_retention as top-level
   modules (A5). The seam block at the bottom is for
   sessx/clientx/streamx (and the tests) only: venice.mli does not
   re-export it. Total, sans-io. *)

module Stop : sig
  (* The stop member: one sequence, or 1..4 sequences; "" rejects in
     both forms. The wire's null branch is NOT passing ?stop. *)
  type t

  val of_string : string -> (t, Errx.t) result
  val of_list : string list -> (t, Errx.t) result
end

module Effort : sig
  (* reasoning_effort wire enum, closed; None_ avoids the OCaml
     keyword. *)
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

  val of_string : string -> (t, Errx.t) result
end

module Cache_retention : sig
  (* prompt_cache_retention wire enum, closed; H24 is the "24h" wire
     value. *)
  type t =
    | Default
    | Extended
    | H24

  val to_string : t -> string
  val of_string : string -> (t, Errx.t) result
end

type 'c t

val make :
  ?temperature:Paramsx.Temp.t ->
  ?top_p:Paramsx.Top_p.t ->
  ?frequency_penalty:Paramsx.Frequency_penalty.t ->
  ?presence_penalty:Paramsx.Presence_penalty.t ->
  ?repetition_penalty:Paramsx.Repetition_penalty.t ->
  ?top_k:Paramsx.Top_k.t ->
  ?venice:Paramsx.Venice_params.t ->
  ?max_completion:int ->
  ?stop:Stop.t ->
  ?stop_token_ids:int list ->
  ?seed:int ->
  ?n:int ->
  ?logprobs:(('c * Modelx.log_probs) Modelx.t * bool) ->
  ?top_logprobs:int ->
  ?effort:(('c * Modelx.reasoning_effort) Modelx.t * Effort.t) ->
  ?prompt_cache_key:string ->
  ?cache_retention:Cache_retention.t ->
  'c Modelx.t ->
  'c Msgx.nonempty ->
  unit ->
  ('c t, Errx.t) result
(* the one mint; optionals first with a trailing unit (A4). Checks:
   model kind Text or Code (A2); max_completion >= 1 and at most the
   model's published cap (D4a); seed >= 1; n >= 1; logprobs is
   witness-gated and top_logprobs (>= 0) rejects without logprobs
   (A3); effort is witness-gated with reasoningEffortOptions
   membership when published (A1); stop_token_ids nonempty, each
   >= 0; prompt_cache_key nonempty. *)

val budget : 'c t -> prompt_tokens:int -> (unit, Errx.t) result
(* D4(b) advisory check: prompt_tokens + effective completion must
   fit the model's availableContextTokens; a model that publishes no
   window reads Ok, and prompt_tokens < 0 rejects. *)

val emit : 'c t -> string
(* the request body bytes: to_json below with neither stream member *)

(* Internal seam for sessx/clientx/streamx (and the tests);
   venice.mli does not re-export it. *)

val to_json : ?stream:bool -> ?include_usage:bool -> 'c t -> Jsonx.t
(* stream / stream_options.include_usage are chosen at the client
   call site (A7) and emit only when passed *)

val with_messages : 'c Msgx.nonempty -> 'c t -> 'c t
(* sessx re-key seam: replace the messages, keep every other member *)

val member_order : unit -> string list
(* the frozen A8 emission-order list; test_chatx asserts it next to
   the goldens *)
