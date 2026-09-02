(* M6 sampling domain. The chat request schema bounds every sampling
   parameter to a documented window (FACTS.md: temperature 0..2,
   top_p 0..1, frequency_penalty and presence_penalty -2..2,
   repetition_penalty >= 0, top_k >= 0), and the newtype modules below
   are the only mint, so an out-of-window value cannot reach a request
   and discover its 400 in prod. Values stay exact Jsonx decimals; no
   float crosses the boundary. A model's constraints object carries
   only a default per parameter, so make checks the request window and
   default reads the model's asserted default, which the constraints
   parse window-checks up front: every value behind a newtype holds
   the same invariant no matter which door it came through. *)

let invalid (msg : string) : ('a, Errx.t) result =
  Error (Errx.Param_invalid msg)

(* A canonical decimal is the shape jsonx's number parser produces:
   nonnegative mantissa of at most 18 digits, scale 0..18. The digit
   cap is numeric: a nonnegative mantissa has at most 18 digits
   exactly when it is below 10^18, which fits a 63-bit int. Jsonx.dec
   is concrete in the public signature, so a caller can build one by
   hand; every mint validates first, which keeps the digit-string
   comparison below total (no leading sign, bounded padding). *)
let canonical (d : Jsonx.dec) : bool =
  d.Jsonx.mantissa >= 0 && d.Jsonx.scale >= 0 && d.Jsonx.scale <= 18
  && d.Jsonx.mantissa < 1_000_000_000_000_000_000

(* The canonical-decimal order lives in jsonx since M8 (public as
   Venice.Json.compare_dec); this alias keeps the internal call
   sites on that one definition. *)
let compare_dec (a : Jsonx.dec) (b : Jsonx.dec) : int =
  Jsonx.compare_dec a b

let d_zero : Jsonx.dec = { Jsonx.negative = false; mantissa = 0; scale = 0 }
let d_one : Jsonx.dec = { Jsonx.negative = false; mantissa = 1; scale = 0 }
let d_two : Jsonx.dec = { Jsonx.negative = false; mantissa = 2; scale = 0 }

let d_neg_two : Jsonx.dec =
  { Jsonx.negative = true; mantissa = 2; scale = 0 }

(* A request window; hi None means unbounded above. Both edges are
   inclusive, as the schema's minimum/maximum are. *)
type window =
  { lo : Jsonx.dec;
    hi : Jsonx.dec option }

let in_window (w : window) (d : Jsonx.dec) : bool =
  compare_dec w.lo d <= 0
  && Option.fold ~none:true ~some:(fun h -> compare_dec d h <= 0) w.hi

let checked (what : string) (w : window) (d : Jsonx.dec) :
    (Jsonx.dec, Errx.t) result =
  match () with
  | () when not (canonical d) -> invalid (what ^ ": not a canonical decimal")
  | () when not (in_window w d) ->
    invalid (what ^ ": outside the documented window")
  | () -> Ok d

let temp_window : window = { lo = d_zero; hi = Some d_two }
let top_p_window : window = { lo = d_zero; hi = Some d_one }
let penalty_window : window = { lo = d_neg_two; hi = Some d_two }
let rep_window : window = { lo = d_zero; hi = None }

module Constraints = struct
  (* The typed view of a text model's constraints object: the model's
     asserted default per sampling parameter, each window-checked at
     parse time. Absent and null parameters read None, and image or
     video models carry different constraint keys this view does not
     touch, so the view is total across kinds. A present parameter
     with malformed metadata also reads None: not an object, no
     default member, a default that is not a representable number, or
     a default outside the request window. The request window is
     enforced at the mint (Temp.make and its siblings); the advertised
     default is advisory server metadata, so a model with junk
     metadata simply asserts no usable default. Only a constraints
     value that is not itself an object rejects, and modelx checks
     that at entry parse, before fields reach of_raw. *)
  type t =
    { temperature : Jsonx.dec option;
      top_p : Jsonx.dec option;
      frequency_penalty : Jsonx.dec option;
      presence_penalty : Jsonx.dec option;
      repetition_penalty : Jsonx.dec option }

  (* Assoc lookup that normalizes an explicit JSON null to absence,
     matching modelx's member_nn read of every optional field. *)
  let assoc_nn (name : string) (fields : (string * Jsonx.t) list) :
      Jsonx.t option =
    Option.bind (List.assoc_opt name fields) (fun v ->
        match (v : Jsonx.t) with
        | Jsonx.Jnull -> None
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
        | Jsonx.Jlist _ | Jsonx.Jobj _ -> Some v)

  let default_of (name : string) (w : window)
      (fields : (string * Jsonx.t) list) : Jsonx.dec option =
    Option.bind (assoc_nn name fields) (fun v ->
        Option.bind (Jsonx.as_obj v) (fun obj ->
            Option.bind (Option.bind (assoc_nn "default" obj) Jsonx.as_dec)
              (fun dv ->
                if canonical dv && in_window w dv then Some dv else None)))

  let of_raw ((_ : string)) (fields : (string * Jsonx.t) list) :
      (t, Errx.t) result =
    Ok
      { temperature = default_of "temperature" temp_window fields;
        top_p = default_of "top_p" top_p_window fields;
        frequency_penalty =
          default_of "frequency_penalty" penalty_window fields;
        presence_penalty =
          default_of "presence_penalty" penalty_window fields;
        repetition_penalty =
          default_of "repetition_penalty" rep_window fields }
end

(* The five decimal newtypes share one shape: the type is the
   window-checked decimal, make is the only public mint, and default
   reads the model's constraints view, whose values already passed the
   same check. *)
module Temp = struct
  type t = Jsonx.dec

  let make (d : Jsonx.dec) : (t, Errx.t) result =
    checked "temperature" temp_window d

  let default (c : Constraints.t) : t option = c.Constraints.temperature
  let to_dec (t : t) : Jsonx.dec = t
end

module Top_p = struct
  type t = Jsonx.dec

  let make (d : Jsonx.dec) : (t, Errx.t) result =
    checked "top_p" top_p_window d

  let default (c : Constraints.t) : t option = c.Constraints.top_p
  let to_dec (t : t) : Jsonx.dec = t
end

module Frequency_penalty = struct
  type t = Jsonx.dec

  let make (d : Jsonx.dec) : (t, Errx.t) result =
    checked "frequency_penalty" penalty_window d

  let default (c : Constraints.t) : t option =
    c.Constraints.frequency_penalty

  let to_dec (t : t) : Jsonx.dec = t
end

module Presence_penalty = struct
  type t = Jsonx.dec

  let make (d : Jsonx.dec) : (t, Errx.t) result =
    checked "presence_penalty" penalty_window d

  let default (c : Constraints.t) : t option =
    c.Constraints.presence_penalty

  let to_dec (t : t) : Jsonx.dec = t
end

module Repetition_penalty = struct
  type t = Jsonx.dec

  let make (d : Jsonx.dec) : (t, Errx.t) result =
    checked "repetition_penalty" rep_window d

  let default (c : Constraints.t) : t option =
    c.Constraints.repetition_penalty

  let to_dec (t : t) : Jsonx.dec = t
end

module Top_k = struct
  type t = int

  let make (n : int) : (t, Errx.t) result =
    if n >= 0 then Ok n else invalid "top_k: negative"

  let to_int (t : t) : int = t
end

module Venice_params = struct
  (* The venice_parameters request object, typed to the wire schema.
     None means the field is not sent, so the server default applies;
     that is not the same act as sending the default value, and the
     emitter preserves the difference. enable_e2ee is deliberately
     absent: it is a downgrade lever (false runs an E2EE-capable model
     TEE-only even when E2EE headers are present), so the session
     layer owns it (M28+) and no API here can switch E2EE off. *)

  type web_search =
    | Auto
    | Off
    | On

  let web_search_wire (w : web_search) : string =
    match w with
    | Auto -> "auto"
    | Off -> "off"
    | On -> "on"

  type t =
    { character_slug : string option;
      strip_thinking_response : bool option;
      disable_thinking : bool option;
      enable_web_search : web_search option;
      enable_web_scraping : bool option;
      enable_web_citations : bool option;
      include_search_results_in_stream : bool option;
      return_search_results_as_documents : bool option;
      include_venice_system_prompt : bool option;
      enable_x_search : bool option }

  let make ?(character_slug : string option)
      ?(strip_thinking_response : bool option)
      ?(disable_thinking : bool option)
      ?(enable_web_search : web_search option)
      ?(enable_web_scraping : bool option)
      ?(enable_web_citations : bool option)
      ?(include_search_results_in_stream : bool option)
      ?(return_search_results_as_documents : bool option)
      ?(include_venice_system_prompt : bool option)
      ?(enable_x_search : bool option) (() : unit) : t =
    { character_slug;
      strip_thinking_response;
      disable_thinking;
      enable_web_search;
      enable_web_scraping;
      enable_web_citations;
      include_search_results_in_stream;
      return_search_results_as_documents;
      include_venice_system_prompt;
      enable_x_search }

  let is_empty (p : t) : bool =
    Option.is_none p.character_slug
    && Option.is_none p.strip_thinking_response
    && Option.is_none p.disable_thinking
    && Option.is_none p.enable_web_search
    && Option.is_none p.enable_web_scraping
    && Option.is_none p.enable_web_citations
    && Option.is_none p.include_search_results_in_stream
    && Option.is_none p.return_search_results_as_documents
    && Option.is_none p.include_venice_system_prompt
    && Option.is_none p.enable_x_search

  let field (name : string) (f : 'a -> Jsonx.t) (v : 'a option) :
      (string * Jsonx.t) list =
    Option.fold ~none:[] ~some:(fun x -> [ (name, f x) ]) v

  (* Only present fields emit, in the wire documentation's order. *)
  let to_json (p : t) : Jsonx.t =
    Jsonx.Jobj
      (List.concat
         [ field "character_slug"
             (fun (s : string) -> Jsonx.Jstring s)
             p.character_slug;
           field "strip_thinking_response"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.strip_thinking_response;
           field "disable_thinking"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.disable_thinking;
           field "enable_web_search"
             (fun (w : web_search) -> Jsonx.Jstring (web_search_wire w))
             p.enable_web_search;
           field "enable_web_scraping"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.enable_web_scraping;
           field "enable_web_citations"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.enable_web_citations;
           field "include_search_results_in_stream"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.include_search_results_in_stream;
           field "return_search_results_as_documents"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.return_search_results_as_documents;
           field "include_venice_system_prompt"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.include_venice_system_prompt;
           field "enable_x_search"
             (fun (b : bool) -> Jsonx.Jbool b)
             p.enable_x_search ])
end
