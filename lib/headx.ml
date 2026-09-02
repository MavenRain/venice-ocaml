(* M8 response-header domain, sans-io: input is the (name, value)
   pair list and the status/body strings a transport hands over. The
   header roster (rate-limit sextet, balances, x-ratelimit-type) comes
   from FACTS.md "Response headers"; the swagger does not document
   these headers, so every header fact here is a hypothesis until the
   M2/M22 live probes. Names match ASCII-case-insensitively (RFC 9110
   field names); values normalize before any grammar; a repeated
   recognized name, an interior CR/LF, or a comma inside a recognized
   singleton value rejects (smuggling- and duplicate-shaped; edge
   CR/LF strips with the other edge whitespace, as transport noise
   rather than smuggling). Each
   rate-limit triple is all-or-nothing (a half-triple means a mangled
   response, and silently dropping it re-opens the silent-429 threat);
   balances are two independent options (the x402 path documents
   USD-only account shapes). *)

let ( let* ) = Result.bind

let invalid (msg : string) : ('a, Errx.t) result =
  Error (Errx.Head_invalid msg)

(* Jsonx grammar errors re-surface under the header name. *)
let rewrap (name : string) (r : ('a, Errx.t) result) : ('a, Errx.t) result =
  Result.map_error
    (fun (e : Errx.t) -> Errx.Head_invalid (name ^ ": " ^ Errx.to_string e))
    r

(* ---------- value normalization (A2) ---------- *)

let is_strip_ws (c : char) : bool =
  Char.equal c ' ' || Char.equal c '\t' || Char.equal c '\r'
  || Char.equal c '\n'

let rec drop_ws (cs : char list) : char list =
  match cs with
  | c :: rest when is_strip_ws c -> drop_ws rest
  | _ -> cs

(* Strip leading and trailing SP, HTAB, CR, LF; interior bytes stay. *)
let strip_value (v : string) : string =
  let cs = drop_ws (List.of_seq (String.to_seq v)) in
  let cs = List.rev (drop_ws (List.rev cs)) in
  String.of_seq (List.to_seq cs)

(* Normalization before any value grammar: strip the edges (SP,
   HTAB, CR, LF), then reject an interior CR/LF surviving the strip
   (smuggling indicator) and a comma inside a
   recognized singleton value (duplicate-shaped; the digit grammar
   alone must not be the thing that catches "100, 100"). *)
let clean_value (name : string) (v : string) : (string, Errx.t) result =
  let s = strip_value v in
  match () with
  | () when String.contains s '\r' || String.contains s '\n' ->
    invalid ("of_pairs: " ^ name ^ ": embedded CR/LF (smuggling-shaped)")
  | () when String.contains s ',' ->
    invalid ("of_pairs: " ^ name ^ ": comma in singleton (duplicate-shaped)")
  | () -> Ok s

(* ---------- the two header grammars (D4, A5) ---------- *)

let leading_zero (digits : int list) : bool =
  match digits with
  | 0 :: _ :: _ -> true
  | _ -> false

let rec drop_zero_digits (ds : int list) : int list =
  match ds with
  | 0 :: rest -> drop_zero_digits rest
  | _ -> ds

(* Count grammar: digits only, no sign, no dot, no leading zeros,
   value below 10^18 (span_digits caps the run at 18 digits, so the
   fold cannot wrap). Covers limit/remaining counts and the absolute
   Reset_at timestamp. *)
let count_of (name : string) (s : string) : (int, Errx.t) result =
  let* digits, rest =
    rewrap name (Jsonx.span_digits (List.of_seq (String.to_seq s)))
  in
  match digits, rest with
  | [], _ -> invalid (name ^ ": expected digit")
  | _ :: _, _ :: _ -> invalid (name ^ ": digits only")
  | _ :: _, [] ->
    if leading_zero digits then invalid (name ^ ": leading zero")
    else Ok (Jsonx.fold_digits digits)

(* The one headx decimal grammar (A5): an optional '-', then 0 or a
   nonzero-led digit run, then an optional '.' plus digit run; the
   sign only where the field allows it. Trailing fraction zeros
   strip (value-preserving); then post-trim scale <= 18 and post-trim
   mantissa below 10^18 (leading zeros of the combined digit string
   drop before the count), so wei-precision Diem stays representable
   where Jsonx.parse's combined 18-digit cap would reject it. Reuses
   Jsonx.span_digits, so each digit run as written also caps at 18.
   Whitespace never reaches this grammar (A2 stripped it). *)
let dec_of ~(signed : bool) (name : string) (s : string) :
    (Jsonx.dec, Errx.t) result =
  let cs = List.of_seq (String.to_seq s) in
  let negative, cs =
    match cs with
    | '-' :: rest -> (true, rest)
    | _ -> (false, cs)
  in
  let* (() : unit) =
    if negative && not signed then invalid (name ^ ": negative not allowed")
    else Ok ()
  in
  let* int_digits, rest = rewrap name (Jsonx.span_digits cs) in
  let* (() : unit) =
    match int_digits with
    | [] -> invalid (name ^ ": expected digit")
    | _ :: _ ->
      if leading_zero int_digits then invalid (name ^ ": leading zero")
      else Ok ()
  in
  let* frac_digits =
    match rest with
    | [] -> Ok []
    | '.' :: tail ->
      let* fd, rest2 = rewrap name (Jsonx.span_digits tail) in
      (match fd, rest2 with
       | [], _ -> invalid (name ^ ": expected digit after '.'")
       | _ :: _, _ :: _ -> invalid (name ^ ": trailing characters")
       | _ :: _, [] -> Ok fd)
    | _ :: _ -> invalid (name ^ ": not a decimal")
  in
  let trimmed = List.rev (drop_zero_digits (List.rev frac_digits)) in
  let scale = List.length trimmed in
  let significant = drop_zero_digits (int_digits @ trimmed) in
  match () with
  | () when scale > Jsonx.max_digits () ->
    invalid (name ^ ": more than 18 fraction digits")
  | () when List.length significant > Jsonx.max_digits () ->
    invalid (name ^ ": more than 18 significant digits")
  | () ->
    let mantissa = Jsonx.fold_digits significant in
    (* canonical zero carries no sign: "-0" / "-0.0" normalize to the
       unsigned zero (value-preserving, like the trailing-zero trim),
       so a caller reading the record's negative field never sees a
       zero balance as overdrawn *)
    Ok { Jsonx.negative = negative && mantissa > 0; mantissa; scale }

(* ---------- newtypes (A4, A10) ---------- *)

module Reset_at = struct
  (* Absolute unix timestamp from x-ratelimit-reset-requests. A
     distinct newtype from Reset_after so the absolute and the
     relative reset cannot swap at a use site (threat row). *)
  type t = int

  let seconds (t : t) : int = t
end

module Reset_after = struct
  (* Relative duration in seconds from x-ratelimit-reset-tokens.
     Fractional seconds are a live hypothesis, so the value is an
     unsigned headx decimal, not an int. *)
  type t = Jsonx.dec

  let seconds (t : t) : Jsonx.dec = t
end

module Usd = struct
  (* x-venice-balance-usd. Signed: the wire is represented truthfully
     and overdraft is not ours to erase. *)
  type t = Jsonx.dec

  let value (t : t) : Jsonx.dec = t
end

module Diem = struct
  (* x-venice-balance-diem. Signed, wei-precision capable; a distinct
     newtype from Usd so the two balances cannot swap at a use site. *)
  type t = Jsonx.dec

  let value (t : t) : Jsonx.dec = t
end

module Limit_type = struct
  (* x-ratelimit-type. The header is swagger-undocumented (unpinned
     axis), so the open slug precedent applies, not the closed-enum
     one; Other carries the raw token and M2 probes may tighten it. *)
  type t =
    | User
    | Api_key
    | Global
    | Other of string
end

module Requests_limit = struct
  (* The requests triple: all three headers or none (D3). *)
  type t =
    { limit : int;
      remaining : int;
      reset_at : Reset_at.t }

  let limit (t : t) : int = t.limit
  let remaining (t : t) : int = t.remaining
  let reset_at (t : t) : Reset_at.t = t.reset_at
end

module Tokens_limit = struct
  (* The tokens triple: all three headers or none (D3). *)
  type t =
    { limit : int;
      remaining : int;
      reset_after : Reset_after.t }

  let limit (t : t) : int = t.limit
  let remaining (t : t) : int = t.remaining
  let reset_after (t : t) : Reset_after.t = t.reset_after
end

module Tier = struct
  (* Derived, never a wire field (FACTS.md tiers). A positive present
     balance is evidence of Paid; zero balances are NOT evidence of
     Explorer (the daily Diem credit can read 0 on a paid account), so
     Explorer is never minted from headers and the derivation returns
     None without positive evidence. *)
  type t =
    | Explorer
    | Paid

  let of_evidence ~(usd : Usd.t option) ~(diem : Diem.t option) : t option =
    let zero : Jsonx.dec =
      { Jsonx.negative = false; mantissa = 0; scale = 0 }
    in
    let positive (d : Jsonx.dec) : bool = Jsonx.compare_dec d zero > 0 in
    let paid =
      Option.fold ~none:false ~some:positive usd
      || Option.fold ~none:false ~some:positive diem
    in
    if paid then Some Paid else None
end

(* ---------- the typed head ---------- *)

type t =
  { requests : Requests_limit.t option;
    tokens : Tokens_limit.t option;
    limit_type : Limit_type.t option;
    usd : Usd.t option;
    diem : Diem.t option }

let requests (h : t) : Requests_limit.t option = h.requests
let tokens (h : t) : Tokens_limit.t option = h.tokens
let limit_type (h : t) : Limit_type.t option = h.limit_type
let usd (h : t) : Usd.t option = h.usd
let diem (h : t) : Diem.t option = h.diem

(* Recognized names, lowercase (the table is bound locally per
   entrypoint). Everything else the transport carries is ignored. *)
let is_recognized (name : string) : bool =
  let names =
    [ "x-ratelimit-limit-requests";
      "x-ratelimit-remaining-requests";
      "x-ratelimit-reset-requests";
      "x-ratelimit-limit-tokens";
      "x-ratelimit-remaining-tokens";
      "x-ratelimit-reset-tokens";
      "x-ratelimit-type";
      "x-venice-balance-usd";
      "x-venice-balance-diem"
    ]
  in
  List.exists (String.equal name) names

let required (name : string) (parse : string -> string -> ('a, Errx.t) result)
    (o : string option) : ('a, Errx.t) result =
  Option.fold ~none:(invalid (name ^ ": missing")) ~some:(parse name) o

let present_count (xs : bool list) : int =
  List.length (List.filter Fun.id xs)

(* All-or-nothing requests triple: 3 present parses, 0 reads None,
   anything between is a mangled response and rejects. *)
let requests_of (find : string -> string option) :
    (Requests_limit.t option, Errx.t) result =
  let l = find "x-ratelimit-limit-requests" in
  let r = find "x-ratelimit-remaining-requests" in
  let z = find "x-ratelimit-reset-requests" in
  let n =
    present_count [ Option.is_some l; Option.is_some r; Option.is_some z ]
  in
  match () with
  | () when Int.equal n 0 -> Ok None
  | () when Int.equal n 3 ->
    let* limit = required "x-ratelimit-limit-requests" count_of l in
    let* remaining = required "x-ratelimit-remaining-requests" count_of r in
    let* reset_at = required "x-ratelimit-reset-requests" count_of z in
    Ok (Some { Requests_limit.limit; remaining; reset_at })
  | () ->
    invalid "of_pairs: partial requests triple (all three headers or none)"

(* All-or-nothing tokens triple; the reset is a relative unsigned
   decimal, not a timestamp. *)
let tokens_of (find : string -> string option) :
    (Tokens_limit.t option, Errx.t) result =
  let l = find "x-ratelimit-limit-tokens" in
  let r = find "x-ratelimit-remaining-tokens" in
  let z = find "x-ratelimit-reset-tokens" in
  let n =
    present_count [ Option.is_some l; Option.is_some r; Option.is_some z ]
  in
  match () with
  | () when Int.equal n 0 -> Ok None
  | () when Int.equal n 3 ->
    let* limit = required "x-ratelimit-limit-tokens" count_of l in
    let* remaining = required "x-ratelimit-remaining-tokens" count_of r in
    let* reset_after =
      required "x-ratelimit-reset-tokens" (dec_of ~signed:false) z
    in
    Ok (Some { Tokens_limit.limit; remaining; reset_after })
  | () ->
    invalid "of_pairs: partial tokens triple (all three headers or none)"

(* Independent optional balance; present-but-malformed still rejects
   the whole of_pairs. *)
let balance_of (name : string) (find : string -> string option) :
    (Jsonx.dec option, Errx.t) result =
  Option.fold ~none:(Ok None)
    ~some:(fun (v : string) ->
      Result.map Option.some (dec_of ~signed:true name v))
    (find name)

(* Strict tokens map to the FACTS enum; anything else stays Other
   with the raw token (open axis, A6). The empty token never reaches
   here: of_pairs rejects it, as every other recognized header
   rejects an empty value. *)
let limit_type_of (s : string) : Limit_type.t =
  match s with
  | "user" -> Limit_type.User
  | "api_key" -> Limit_type.Api_key
  | "global" -> Limit_type.Global
  | _ -> Limit_type.Other s

(* Parse is the only door: names lowercase, unknown names drop, a
   repeated recognized name rejects regardless of value, every kept
   value normalizes (A2), then each field grammar runs. *)
let of_pairs (pairs : (string * string) list) : (t, Errx.t) result =
  let recognized =
    List.filter
      (fun ((n : string), (_ : string)) -> is_recognized n)
      (List.map
         (fun ((n : string), (v : string)) -> (String.lowercase_ascii n, v))
         pairs)
  in
  let* cleaned =
    List.fold_left
      (fun (acc : ((string * string) list, Errx.t) result)
           ((name : string), (value : string)) ->
        let* seen = acc in
        let* (() : unit) =
          if List.mem_assoc name seen then
            invalid ("of_pairs: repeated header " ^ name)
          else Ok ()
        in
        let* v = clean_value name value in
        Ok ((name, v) :: seen))
      (Ok []) recognized
  in
  let find (name : string) : string option = List.assoc_opt name cleaned in
  let* requests = requests_of find in
  let* tokens = tokens_of find in
  let* usd = balance_of "x-venice-balance-usd" find in
  let* diem = balance_of "x-venice-balance-diem" find in
  let* limit_type =
    Option.fold ~none:(Ok None)
      ~some:(fun (v : string) ->
        if String.equal v "" then
          invalid "of_pairs: x-ratelimit-type: empty token"
        else Ok (Some (limit_type_of v)))
      (find "x-ratelimit-type")
  in
  Ok { requests; tokens; limit_type; usd; diem }

(* ---------- typed error bodies (D8, A8) ---------- *)

(* One product covers StandardError, DetailedError,
   ContentViolationError and PayloadTooLargeError (Plain); the 402
   oneOf adds Payment_required; the provider rejection keeps its own
   shape. details holds the PRINTED member (Jsonx.emit), matching the
   Model.deprecation precedent: no raw Json.t inside a domain value. *)
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
        current_balance_usd : Jsonx.dec option;
        minimum_balance_usd : Jsonx.dec option;
        suggested_top_up_usd : Jsonx.dec option }

(* Assoc lookup that normalizes an explicit JSON null to absence,
   matching the modelx read of every optional field. *)
let member_nn (name : string) (j : Jsonx.t) : Jsonx.t option =
  Option.bind (Jsonx.member name j) (fun v ->
      match (v : Jsonx.t) with
      | Jsonx.Jnull -> None
      | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jstring _
      | Jsonx.Jlist _ | Jsonx.Jobj _ -> Some v)

let str_member (name : string) (j : Jsonx.t) : string option =
  Option.bind (member_nn name j) Jsonx.as_string

(* Both 402 branches land here. No member is required: the discovery
   branch often has no "error" at all. Balance members read via
   as_dec (they are JSON numbers, in-cap); a wrong-typed optional
   member reads as absent. *)
let payment_of (j : Jsonx.t) : (body, Errx.t) result =
  let dec (name : string) : Jsonx.dec option =
    Option.bind (member_nn name j) Jsonx.as_dec
  in
  Ok
    (Payment_required
       { error = str_member "error" j;
         code = str_member "code" j;
         reason = str_member "reason" j;
         current_balance_usd = dec "currentBalanceUsd";
         minimum_balance_usd = dec "minimumBalanceUsd";
         suggested_top_up_usd = dec "suggestedTopUpUsd" })

let plain_of (j : Jsonx.t) : (body, Errx.t) result =
  Option.fold
    ~none:(invalid "body: error member is not a string")
    ~some:(fun (error : string) ->
      Ok
        (Plain
           { error;
             details = Option.map Jsonx.emit (member_nn "details" j);
             code = str_member "code" j;
             suggested_prompt = str_member "suggested_prompt" j }))
    (str_member "error" j)

(* message and credits_refunded are required by the swagger; a
   rejection here is a refused body the caller can still match. *)
let provider_of (e : Jsonx.t) : (body, Errx.t) result =
  let* message =
    Option.fold
      ~none:(invalid "body: provider_content_policy missing message")
      ~some:(fun (s : string) -> Ok s)
      (str_member "message" e)
  in
  let* credits_refunded =
    Option.fold
      ~none:(invalid "body: provider_content_policy missing credits_refunded")
      ~some:(fun (b : bool) -> Ok b)
      (Option.bind (member_nn "credits_refunded" e) Jsonx.as_bool)
  in
  Ok
    (Provider_policy
       { message;
         recommended_model = str_member "recommended_model" e;
         credits_refunded })

(* Keying rule, in order (A8): "x402Version" member ->
   Payment_required; "code" = "PAYMENT_REQUIRED" -> Payment_required;
   "error" string -> Plain; "error" object of type
   "provider_content_policy" -> Provider_policy; else refuse. *)
let body_of_json (j : Jsonx.t) : (body, Errx.t) result =
  let code_is_payment =
    Option.fold ~none:false
      ~some:(String.equal "PAYMENT_REQUIRED")
      (str_member "code" j)
  in
  let error_string = str_member "error" j in
  let provider_error =
    Option.bind (Jsonx.member "error" j) (fun e ->
        Option.bind (str_member "type" e) (fun (ty : string) ->
            if String.equal ty "provider_content_policy" then Some e
            else None))
  in
  match () with
  | () when Option.is_none (Jsonx.as_obj j) ->
    invalid "body: not a JSON object"
  | () when Option.is_some (Jsonx.member "x402Version" j) -> payment_of j
  | () when code_is_payment -> payment_of j
  | () when Option.is_some error_string -> plain_of j
  | () ->
    Option.fold
      ~none:(invalid "body: unrecognized error shape")
      ~some:provider_of provider_error

(* Best-effort body parse; the caller keeps the refusal and the raw
   string side by side, so a JSON failure never masks the HTTP one. *)
let parse_body (raw : string) : (body, Errx.t) result =
  Result.fold ~ok:body_of_json
    ~error:(fun (e : Errx.t) ->
      Error (Errx.Head_invalid ("body: " ^ Errx.to_string e)))
    (Jsonx.parse raw)

(* ---------- typed failures (D8, A8) ---------- *)

(* Every variant carries head + head_error + raw: balances on a
   402/5xx must reach the session layer (M28), and a mangled header
   block must never erase the status class. body is three-state:
   None = empty raw, Some (Ok b) = parsed, Some (Error e) = present
   but refused with raw retained. *)
type failure =
  | Rate_limited of
      { head : t option;
        head_error : Errx.t option;
        body : (body, Errx.t) result option;
        raw : string }
  | Client of
      { status : int;
        head : t option;
        head_error : Errx.t option;
        body : (body, Errx.t) result option;
        raw : string }
  | Server of
      { status : int;
        head : t option;
        head_error : Errx.t option;
        body : (body, Errx.t) result option;
        raw : string }
  | Unexpected_status of
      { status : int;
        head : t option;
        head_error : Errx.t option;
        raw : string }

(* The caller parses headers ONCE via of_pairs for every response and
   passes the result; classify can never lose the status to header
   content, so an Error head demotes to head_error inside the
   failure. The outer Error fires only for a status outside 100..599.
   1xx/3xx are Unexpected_status: the API does not redirect, and
   misclassifying 3xx as a client fault would lie. *)
let classify ~(status : int) ~(head : (t, Errx.t) result) ~(raw : string) :
    (failure option, Errx.t) result =
  let head_opt = Result.to_option head in
  let head_error =
    Result.fold ~ok:(fun (_ : t) -> None) ~error:Option.some head
  in
  let body_of (() : unit) : (body, Errx.t) result option =
    if String.equal raw "" then None else Some (parse_body raw)
  in
  match () with
  | () when status < 100 || status > 599 ->
    invalid
      ("classify: status " ^ string_of_int status ^ " outside 100..599")
  | () when 200 <= status && status <= 299 -> Ok None
  | () when Int.equal status 429 ->
    Ok
      (Some
         (Rate_limited
            { head = head_opt; head_error; body = body_of (); raw }))
  | () when 400 <= status && status <= 499 ->
    Ok
      (Some
         (Client
            { status; head = head_opt; head_error; body = body_of (); raw }))
  | () when 500 <= status && status <= 599 ->
    Ok
      (Some
         (Server
            { status; head = head_opt; head_error; body = body_of (); raw }))
  | () ->
    Ok (Some (Unexpected_status { status; head = head_opt; head_error; raw }))
