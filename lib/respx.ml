(* M10 chat response domain, sans-io: input is the 200-response body
   bytes a transport hands over. The shape comes from the swagger
   chat.completion schema; the response object never sets
   additionalProperties: false, so unknown members are tolerated
   everywhere. Required members are enforced strictly (D7), the
   reasoning passthrough values are minted through the msgx seam so
   the parse output feeds Msgx.assistant directly (D2/D3), and a
   tool-role choice message rejects the whole document (D8).
   message.tool_calls items are held raw at parse time; the typed
   view Choice.tool_calls validates per item on demand (the swagger
   leaves the item shape untyped, so item strictness is opt-in).
   Response forgery stays a transport threat: M33
   consumes raw completion bytes at the transport, not this parser's
   output. Total, sans-io. *)

let ( let* ) = Result.bind

let invalid (msg : string) : ('a, Errx.t) result =
  Error (Errx.Resp_invalid msg)

module Finish = struct
  (* finish_reason wire enum, closed; a foreign string rejects. *)
  type t =
    | Stop
    | Length
    | Tool_calls

  let to_string (f : t) : string =
    match f with
    | Stop -> "stop"
    | Length -> "length"
    | Tool_calls -> "tool_calls"

  (* Internal (not in the .mli): the same closed set with the
     caller's path prefixed, so choice-level failures carry
     choices[i]. *)
  let of_string_at (what : string) (s : string) : (t, Errx.t) result =
    match s with
    | "stop" -> Ok Stop
    | "length" -> Ok Length
    | "tool_calls" -> Ok Tool_calls
    | other -> invalid (what ^ ": unknown value " ^ other)

  let of_string (s : string) : (t, Errx.t) result =
    of_string_at "finish_reason" s
end

module Stop_reason = struct
  (* stop_reason wire enum, closed; the member itself is nullable. *)
  type t =
    | Stop
    | Length

  let to_string (r : t) : string =
    match r with
    | Stop -> "stop"
    | Length -> "length"

  (* Internal (not in the .mli): the same closed set with the
     caller's path prefixed, so choice-level failures carry
     choices[i]. *)
  let of_string_at (what : string) (s : string) : (t, Errx.t) result =
    match s with
    | "stop" -> Ok Stop
    | "length" -> Ok Length
    | other -> invalid (what ^ ": unknown value " ^ other)

  let of_string (s : string) : (t, Errx.t) result =
    of_string_at "stop_reason" s
end

module Usage = struct
  (* The three counts are required wire integers; the two details
     objects are nullable and their members optional, so those
     project as options (D9). No cross-field arithmetic check:
     prompt + completion vs total is server-owned. *)
  type t =
    { completion_tokens : int;
      prompt_tokens : int;
      total_tokens : int;
      reasoning_tokens : int option;
      cached_tokens : int option;
      cache_creation_tokens : int option }

  let completion_tokens (u : t) : int = u.completion_tokens
  let prompt_tokens (u : t) : int = u.prompt_tokens
  let total_tokens (u : t) : int = u.total_tokens
  let reasoning_tokens (u : t) : int option = u.reasoning_tokens
  let cached_tokens (u : t) : int option = u.cached_tokens

  let cache_creation_tokens (u : t) : int option =
    u.cache_creation_tokens
end

module Logprobs = struct
  (* The swagger gives ONE flat token record plus top_logprobs, not
     OpenAI's content array. logprob is a wire number, held exact as
     a decimal; bytes stays an optional int list. *)
  type entry =
    { e_token : string;
      e_logprob : Jsonx.dec;
      e_bytes : int list option }

  type t =
    { token : string;
      logprob : Jsonx.dec;
      bytes : int list option;
      top : entry list }

  let entry_token (e : entry) : string = e.e_token
  let entry_logprob (e : entry) : Jsonx.dec = e.e_logprob
  let entry_bytes (e : entry) : int list option = e.e_bytes
  let token (l : t) : string = l.token
  let logprob (l : t) : Jsonx.dec = l.logprob
  let bytes (l : t) : int list option = l.bytes
  let top_logprobs (l : t) : entry list = l.top
end

module Cost = struct
  (* Both members are required when the (optional) cost object is
     present; both carry the schema's only minimum: 0 keywords. *)
  type t =
    { usd : Jsonx.dec;
      diem : Jsonx.dec }

  let usd (c : t) : Jsonx.dec = c.usd
  let diem (c : t) : Jsonx.dec = c.diem
end

module Choice = struct
  (* One parsed assistant choice. reasoning_details collapses absent
     and [] to the same [] (D4), so the projection feeds
     Msgx.assistant's ?reasoning_details label directly. *)
  type t =
    { finish : Finish.t;
      index : int;
      content : string option;
      reasoning_content : string option;
      reasoning_details : Msgx.Reasoning_detail.t list;
      thought_signature : Msgx.Thought_signature.t option;
      logprobs : Logprobs.t option;
      stop_reason : Stop_reason.t option;
      tool_calls_raw : Jsonx.t list;
      path : string }

  let finish (c : t) : Finish.t = c.finish
  let index (c : t) : int = c.index
  let content (c : t) : string option = c.content
  let reasoning_content (c : t) : string option = c.reasoning_content

  let reasoning_details (c : t) : Msgx.Reasoning_detail.t list =
    c.reasoning_details

  let thought_signature (c : t) : Msgx.Thought_signature.t option =
    c.thought_signature

  let logprobs (c : t) : Logprobs.t option = c.logprobs
  let stop_reason (c : t) : Stop_reason.t option = c.stop_reason
  let tool_calls_raw (c : t) : Jsonx.t list = c.tool_calls_raw

  (* The typed view over tool_calls_raw. Item validation lives HERE,
     not in the document parse: the swagger leaves the item shape
     untyped, so strictness against the nested hypothesis shape is
     opt-in, and a foreign-shaped item must not reject a whole
     response whose other members are fine. The first failing item
     wins and the error carries its choices[i].tool_calls[j] path;
     the msgx mint's own detail is kept, reprefixed Resp_invalid.
     Same-grammar details strip their domain prefix (Msg_invalid from
     the mint here; Resp_invalid from usage_of through the M11
     usage_of_json_x seam, which re-domains them, so "resp: " never
     leaks into a chunk error text); foreign domains keep their
     prefix so the failing domain stays identifiable. *)
  let item_detail (e : Errx.t) : string =
    match e with
    | Errx.Msg_invalid s -> s
    | Errx.Resp_invalid s -> s
    | Errx.Hex_invalid _ | Errx.B64_invalid _ | Errx.Json_invalid _
    | Errx.Model_invalid _ | Errx.Param_invalid _ | Errx.Head_invalid _
    | Errx.Chat_invalid _ | Errx.Sse_invalid _ | Errx.Chunk_invalid _
    | Errx.Key_invalid _ | Errx.Req_invalid _ | Errx.Wire_invalid _
    | Errx.Transport_failed _ | Errx.Stream_invalid _
    | Errx.Transport_unreachable _ | Errx.Client_invalid _ ->
      Errx.to_string e

  let tool_calls (c : t) : (Msgx.Tool_call.t list, Errx.t) result =
    let rec go (j : int) (acc : Msgx.Tool_call.t list)
        (rest : Jsonx.t list) : (Msgx.Tool_call.t list, Errx.t) result =
      match rest with
      | [] -> Ok (List.rev acc)
      | item :: tl ->
        Result.fold
          ~ok:(fun (tc : Msgx.Tool_call.t) -> go (j + 1) (tc :: acc) tl)
          ~error:(fun (e : Errx.t) ->
            Error
              (Errx.Resp_invalid
                 (c.path ^ ".tool_calls[" ^ string_of_int j ^ "]: "
                 ^ item_detail e)))
          (Msgx.tool_call_of_json item)
    in
    go 0 [] c.tool_calls_raw
end

(* ---------- member helpers ---------- *)

let req_string (what : string) (o : Jsonx.t option) :
    (string, Errx.t) result =
  Option.fold
    ~none:(invalid (what ^ ": missing"))
    ~some:(fun v ->
      Option.fold
        ~none:(invalid (what ^ ": not a string"))
        ~some:Result.ok (Jsonx.as_string v))
    o

(* Wire integer (Jint only; a Jdec token count rejects) with the >= 0
   floor. The floor is SDK-imposed strictness for every member routed
   here except cost (see the .mli provenance note). *)
let nat_of (what : string) (v : Jsonx.t) : (int, Errx.t) result =
  Option.fold
    ~none:(invalid (what ^ ": not an integer"))
    ~some:(fun (n : int) ->
      if n < 0 then invalid (what ^ ": negative") else Ok n)
    (Jsonx.as_int v)

let req_nat (what : string) (o : Jsonx.t option) : (int, Errx.t) result =
  Option.fold ~none:(invalid (what ^ ": missing")) ~some:(nat_of what) o

let opt_nat (what : string) (o : Jsonx.t option) :
    (int option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v -> Result.map Option.some (nat_of what v))
    o

let req_dec (what : string) (o : Jsonx.t option) :
    (Jsonx.dec, Errx.t) result =
  Option.fold
    ~none:(invalid (what ^ ": missing"))
    ~some:(fun v ->
      Option.fold
        ~none:(invalid (what ^ ": not a number"))
        ~some:Result.ok (Jsonx.as_dec v))
    o

let req_nonneg_dec (what : string) (o : Jsonx.t option) :
    (Jsonx.dec, Errx.t) result =
  let dec_zero : Jsonx.dec =
    { Jsonx.negative = false; mantissa = 0; scale = 0 }
  in
  let* d = req_dec what o in
  if Jsonx.compare_dec d dec_zero < 0 then invalid (what ^ ": negative")
  else Ok d

(* Absent and null collapse to None; a present value must be a
   string. *)
let opt_string (what : string) (o : Jsonx.t option) :
    (string option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok None
      | Jsonx.Jstring s -> Ok (Some s)
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jlist _
      | Jsonx.Jobj _ ->
        invalid (what ^ ": not a string"))
    o

let require_obj (what : string) (v : Jsonx.t) : (unit, Errx.t) result =
  Option.fold
    ~none:(invalid (what ^ ": not an object"))
    ~some:(fun ((_ : (string * Jsonx.t) list)) -> Ok ())
    (Jsonx.as_obj v)

(* Result traversal in list order; the first Error wins. Tail
   recursive (the recursive call stays in tail position through
   Result.bind): the arrays routed here are untrusted wire input, so
   a long array must not overflow the stack. *)
let traverse (f : 'a -> ('b, Errx.t) result) (xs : 'a list) :
    ('b list, Errx.t) result =
  let rec go (acc : 'b list) (rest : 'a list) :
      ('b list, Errx.t) result =
    match rest with
    | [] -> Ok (List.rev acc)
    | x :: tl ->
      let* y = f x in
      go (y :: acc) tl
  in
  go [] xs

(* ---------- usage ---------- *)

let completion_details_of (o : Jsonx.t option) :
    (int option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok None
      | Jsonx.Jobj _ ->
        opt_nat "usage.completion_tokens_details.reasoning_tokens"
          (Jsonx.member "reasoning_tokens" v)
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jlist _ ->
        invalid "usage.completion_tokens_details: not an object")
    o

let prompt_details_of (o : Jsonx.t option) :
    (int option * int option, Errx.t) result =
  Option.fold
    ~none:(Ok (None, None))
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok (None, None)
      | Jsonx.Jobj _ ->
        let* cached =
          opt_nat "usage.prompt_tokens_details.cached_tokens"
            (Jsonx.member "cached_tokens" v)
        in
        let* creation =
          opt_nat
            "usage.prompt_tokens_details.cache_creation_input_tokens"
            (Jsonx.member "cache_creation_input_tokens" v)
        in
        Ok (cached, creation)
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jlist _ ->
        invalid "usage.prompt_tokens_details: not an object")
    o

let usage_of (o : Jsonx.t option) : (Usage.t, Errx.t) result =
  Option.fold
    ~none:(invalid "usage: missing")
    ~some:(fun v ->
      let* (() : unit) = require_obj "usage" v in
      let* completion =
        req_nat "usage.completion_tokens"
          (Jsonx.member "completion_tokens" v)
      in
      let* prompt =
        req_nat "usage.prompt_tokens" (Jsonx.member "prompt_tokens" v)
      in
      let* total =
        req_nat "usage.total_tokens" (Jsonx.member "total_tokens" v)
      in
      let* reasoning =
        completion_details_of (Jsonx.member "completion_tokens_details" v)
      in
      let* cached, creation =
        prompt_details_of (Jsonx.member "prompt_tokens_details" v)
      in
      Ok
        { Usage.completion_tokens = completion;
          prompt_tokens = prompt;
          total_tokens = total;
          reasoning_tokens = reasoning;
          cached_tokens = cached;
          cache_creation_tokens = creation })
    o

(* ---------- logprobs ---------- *)

(* bytes departures from the schema, both deliberate and recorded in
   the .mli ledger: a wire null reads None although the schema does
   not mark the array nullable, and each item is narrowed to a wire
   integer although the schema types it number (a fractional byte
   value rejects the whole document). *)
let bytes_of (what : string) (o : Jsonx.t option) :
    (int list option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok None
      | Jsonx.Jlist items ->
        Result.map Option.some
          (traverse
             (fun b ->
               Option.fold
                 ~none:(invalid (what ^ ": not an integer"))
                 ~some:Result.ok (Jsonx.as_int b))
             items)
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jobj _ ->
        invalid (what ^ ": not an array"))
    o

let entry_of (what : string) (j : Jsonx.t) :
    (Logprobs.entry, Errx.t) result =
  let* token = req_string (what ^ ".token") (Jsonx.member "token" j) in
  let* logprob = req_dec (what ^ ".logprob") (Jsonx.member "logprob" j) in
  let* bytes = bytes_of (what ^ ".bytes") (Jsonx.member "bytes" j) in
  Ok { Logprobs.e_token = token; e_logprob = logprob; e_bytes = bytes }

(* The swagger lists logprobs in each choice's required list, but the
   parser accepts absent-or-null as None: the example bodies
   themselves show logprobs: null, OpenAI-compat servers routinely
   omit it, and absent-vs-null is not distinguishable downstream.
   The one deliberate required-list tolerance (D7). *)
let logprobs_of (what : string) (o : Jsonx.t option) :
    (Logprobs.t option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok None
      | Jsonx.Jobj _ ->
        let* token = req_string (what ^ ".token") (Jsonx.member "token" v) in
        let* logprob =
          req_dec (what ^ ".logprob") (Jsonx.member "logprob" v)
        in
        let* bytes = bytes_of (what ^ ".bytes") (Jsonx.member "bytes" v) in
        let* top =
          (* Absent and null collapse to []. *)
          Option.fold ~none:(Ok [])
            ~some:(fun tv ->
              match tv with
              | Jsonx.Jnull -> Ok []
              | Jsonx.Jlist items ->
                traverse (entry_of (what ^ ".top_logprobs")) items
              | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _
              | Jsonx.Jstring _ | Jsonx.Jobj _ ->
                invalid (what ^ ".top_logprobs: not an array"))
            (Jsonx.member "top_logprobs" v)
        in
        Ok (Some { Logprobs.token; logprob; bytes; top })
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jlist _ ->
        invalid (what ^ ": not an object"))
    o

(* ---------- choice message ---------- *)

(* One text part: type must equal "text" (a non-text part type
   rejects; D8), and the schema requires text. *)
let part_text (what : string) (p : Jsonx.t) : (string, Errx.t) result =
  let ty = Option.bind (Jsonx.member "type" p) Jsonx.as_string in
  let text = Option.bind (Jsonx.member "text" p) Jsonx.as_string in
  match () with
  | () when not (Option.fold ~none:false ~some:(String.equal "text") ty) ->
    invalid (what ^ ": non-text part")
  | () ->
    Option.fold
      ~none:(invalid (what ^ ": text part without text"))
      ~some:Result.ok text

(* Content variants (D8): string, null/absent, or a text-parts array
   whose texts concatenate in received order. The concatenation is a
   projection, not a claim the wire sent one string. An EMPTY parts
   array projects to None exactly like null: Some "" would defeat the
   tool_calls fail-forward (callers detect no-content responses). *)
let content_of (what : string) (m : Jsonx.t) :
    (string option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok None
      | Jsonx.Jstring s -> Ok (Some s)
      | Jsonx.Jlist [] -> Ok None
      | Jsonx.Jlist ((_ :: _) as parts) ->
        let* texts = traverse (part_text what) parts in
        Ok (Some (String.concat "" texts))
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jobj _ ->
        invalid (what ^ ": not a string or parts"))
    (Jsonx.member "content" m)

(* Absent, null, and [] all collapse to the same [] projection. *)
let details_of (what : string) (o : Jsonx.t option) :
    (Msgx.Reasoning_detail.t list, Errx.t) result =
  Option.fold ~none:(Ok [])
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok []
      | Jsonx.Jlist items -> traverse Msgx.reasoning_detail_of_json items
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jobj _ ->
        invalid (what ^ ": not an array"))
    o

(* role:"assistant" choice messages only, deliberately and
   permanently: the swagger's two-arm response union puts a Tool
   Message in choices, but no producer of that arm has been observed
   (Venice runs the tool, the CALLER sends tool results in the
   REQUEST), and D8's all-or-nothing rule forbids a partial choice
   array, so a tool-role message rejects the WHOLE document with its
   choices[i] path. Revisit only on a captured response carrying
   one. message.tool_calls parses raw here (absent or null reads []);
   item typing is the Choice.tool_calls view above. *)
let choice_of (what : string) (j : Jsonx.t) : (Choice.t, Errx.t) result =
  let* (() : unit) = require_obj what j in
  let* finish =
    let* s =
      req_string (what ^ ".finish_reason")
        (Jsonx.member "finish_reason" j)
    in
    Finish.of_string_at (what ^ ".finish_reason") s
  in
  let* index = req_nat (what ^ ".index") (Jsonx.member "index" j) in
  let* logprobs =
    logprobs_of (what ^ ".logprobs") (Jsonx.member "logprobs" j)
  in
  let* msg =
    Option.fold
      ~none:(invalid (what ^ ".message: missing"))
      ~some:Result.ok (Jsonx.member "message" j)
  in
  let* role =
    req_string (what ^ ".message.role") (Jsonx.member "role" msg)
  in
  let* (() : unit) =
    if String.equal role "assistant" then Ok ()
    else invalid (what ^ ".message.role: unsupported role " ^ role)
  in
  let* content = content_of (what ^ ".message.content") msg in
  let* reasoning_content =
    opt_string
      (what ^ ".message.reasoning_content")
      (Jsonx.member "reasoning_content" msg)
  in
  let* details =
    details_of
      (what ^ ".message.reasoning_details")
      (Jsonx.member "reasoning_details" msg)
  in
  let* signature =
    Result.map
      (Option.map Msgx.thought_signature_of_parsed)
      (opt_string
         (what ^ ".message.thought_signature")
         (Jsonx.member "thought_signature" msg))
  in
  let* stop_reason =
    let* s =
      opt_string (what ^ ".stop_reason") (Jsonx.member "stop_reason" j)
    in
    Option.fold ~none:(Ok None)
      ~some:(fun (v : string) ->
        Result.map Option.some
          (Stop_reason.of_string_at (what ^ ".stop_reason") v))
      s
  in
  (* Raw items only; absent and null collapse to [] (the request-side
     schema marks the member nullable). A null or malformed ITEM is
     kept verbatim: item strictness is the typed view's job. *)
  let* tool_calls_raw =
    Option.fold ~none:(Ok [])
      ~some:(fun v ->
        match v with
        | Jsonx.Jnull -> Ok []
        | Jsonx.Jlist items -> Ok items
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
        | Jsonx.Jobj _ ->
          invalid (what ^ ".message.tool_calls: not an array"))
      (Jsonx.member "tool_calls" msg)
  in
  Ok
    { Choice.finish;
      index;
      content;
      reasoning_content;
      reasoning_details = details;
      thought_signature = signature;
      logprobs;
      stop_reason;
      tool_calls_raw;
      path = what }

(* i counts the position for error paths; the wire index member is
   data, not the address of the fault. Tail recursive: the choices
   array is untrusted wire input, so its length must not bound the
   stack. *)
let choices_of (i : int) (items : Jsonx.t list) :
    (Choice.t list, Errx.t) result =
  let rec go (i : int) (acc : Choice.t list) (rest : Jsonx.t list) :
      (Choice.t list, Errx.t) result =
    match rest with
    | [] -> Ok (List.rev acc)
    | item :: tl ->
      let* c = choice_of ("choices[" ^ string_of_int i ^ "]") item in
      go (i + 1) (c :: acc) tl
  in
  go i [] items

(* ---------- cost ---------- *)

let cost_of (o : Jsonx.t option) : (Cost.t option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun v ->
      match v with
      | Jsonx.Jnull -> Ok None
      | Jsonx.Jobj _ ->
        let* usd = req_nonneg_dec "cost.usd" (Jsonx.member "usd" v) in
        let* diem = req_nonneg_dec "cost.diem" (Jsonx.member "diem" v) in
        Ok (Some { Cost.usd; diem })
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jlist _ ->
        invalid "cost: not an object")
    o

(* ---------- the typed response ---------- *)

type t =
  { id : string;
    model : string;
    created : int;
    choices : Choice.t list;
    usage : Usage.t;
    cost : Cost.t option;
    venice_parameters_raw : Jsonx.t option;
    prompt_logprobs_raw : Jsonx.t option }

let id (r : t) : string = r.id
let model (r : t) : string = r.model
let created (r : t) : int = r.created
let choices (r : t) : Choice.t list = r.choices
let usage (r : t) : Usage.t = r.usage
let cost (r : t) : Cost.t option = r.cost
let venice_parameters_raw (r : t) : Jsonx.t option = r.venice_parameters_raw
let prompt_logprobs_raw (r : t) : Jsonx.t option = r.prompt_logprobs_raw

let of_string (s : string) : (t, Errx.t) result =
  let* j = Jsonx.parse s in
  let* (() : unit) =
    Option.fold
      ~none:(invalid "not a JSON object")
      ~some:(fun ((_ : (string * Jsonx.t) list)) -> Ok ())
      (Jsonx.as_obj j)
  in
  let* id = req_string "id" (Jsonx.member "id" j) in
  let* model = req_string "model" (Jsonx.member "model" j) in
  let* created = req_nat "created" (Jsonx.member "created" j) in
  let* obj = req_string "object" (Jsonx.member "object" j) in
  let* (() : unit) =
    if String.equal obj "chat.completion" then Ok ()
    else invalid "object: not chat.completion"
  in
  let* usage = usage_of (Jsonx.member "usage" j) in
  (* Absent choices parses as [] (the swagger marks the member
     optional in so many words); wire null collapses to the same []. *)
  let* choices =
    Option.fold ~none:(Ok [])
      ~some:(fun v ->
        match v with
        | Jsonx.Jnull -> Ok []
        | Jsonx.Jlist items -> choices_of 0 items
        | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
        | Jsonx.Jobj _ ->
          invalid "choices: not an array")
      (Jsonx.member "choices" j)
  in
  let* cost = cost_of (Jsonx.member "cost" j) in
  Ok
    { id;
      model;
      created;
      choices;
      usage;
      cost;
      venice_parameters_raw = Jsonx.member "venice_parameters" j;
      prompt_logprobs_raw = Jsonx.member "prompt_logprobs" j }

(* The usage seam (M11 A8): the ONE usage grammar applied to a
   pre-parsed member value, re-domained through wrap so the streaming
   chunk reading reports its own domain instead of "resp: ".
   Implemented over the existing usage_of + Choice.item_detail, so the
   streaming and non-streaming usage readings cannot drift. *)
let usage_of_json_x ~(wrap : string -> Errx.t) ~(path : string)
    (v : Jsonx.t) : (Usage.t, Errx.t) result =
  Result.map_error
    (fun (e : Errx.t) -> wrap (path ^ ": " ^ Choice.item_detail e))
    (usage_of (Some v))
