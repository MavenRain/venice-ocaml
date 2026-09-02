(* M8 response-header domain: of_pairs normalization, the two header
   grammars, the all-or-nothing triples, independent balances, the
   Tier derivation, typed bodies (all six swagger error shapes) and
   the status classifier. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module J = Venice.Json
module H = Venice.Head

let is_ok (r : ('a, Venice.Error.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> true)
    ~error:(fun (_ : Venice.Error.t) -> false)
    r

let is_err (r : ('a, Venice.Error.t) result) : bool = not (is_ok r)

let err_prefix (p : string) (r : ('a, Venice.Error.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> false)
    ~error:(fun e ->
      Option.fold ~none:false ~some:(String.equal p)
        (Venice.Cursor.take (Venice.Error.to_string e) 0 (String.length p)))
    r

(* Total substring search through the total cursor. *)
let contains_sub (needle : string) (hay : string) : bool =
  let n = String.length needle in
  let rec go (i : int) : bool =
    Option.fold ~none:false
      ~some:(fun (w : string) -> String.equal w needle || go (i + 1))
      (Venice.Cursor.take hay i n)
  in
  go 0

let err_contains (sub : string) (r : ('a, Venice.Error.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> false)
    ~error:(fun e -> contains_sub sub (Venice.Error.to_string e))
    r

let dec_eq ~(neg : bool) ~(m : int) ~(s : int) (d : J.dec) : bool =
  Bool.equal d.J.negative neg && Int.equal d.J.mantissa m
  && Int.equal d.J.scale s

let ostr (w : string) (o : string option) : bool =
  Option.fold ~none:false ~some:(String.equal w) o

let odec ~(neg : bool) ~(m : int) ~(s : int) (o : J.dec option) : bool =
  Option.fold ~none:false ~some:(dec_eq ~neg ~m ~s) o

(* ---------- head helpers ---------- *)

let on_head (pairs : (string * string) list) (f : H.t -> bool) : bool =
  Result.fold ~ok:f
    ~error:(fun (_ : Venice.Error.t) -> false)
    (H.of_pairs pairs)

let on_requests (pairs : (string * string) list)
    (f : Venice.Requests_limit.t -> bool) : bool =
  on_head pairs (fun h -> Option.fold ~none:false ~some:f (H.requests h))

let on_tokens (pairs : (string * string) list)
    (f : Venice.Tokens_limit.t -> bool) : bool =
  on_head pairs (fun h -> Option.fold ~none:false ~some:f (H.tokens h))

let on_usd (pairs : (string * string) list) (f : J.dec -> bool) : bool =
  on_head pairs (fun h ->
      Option.fold ~none:false
        ~some:(fun u -> f (Venice.Usd.value u))
        (H.usd h))

let on_diem (pairs : (string * string) list) (f : J.dec -> bool) : bool =
  on_head pairs (fun h ->
      Option.fold ~none:false
        ~some:(fun d -> f (Venice.Diem.value d))
        (H.diem h))

let lt_token (lt : Venice.Limit_type.t) : string =
  match lt with
  | Venice.Limit_type.User -> "user"
  | Venice.Limit_type.Api_key -> "api_key"
  | Venice.Limit_type.Global -> "global"
  | Venice.Limit_type.Other s -> "other:" ^ s

let limit_type_is (pairs : (string * string) list) (tok : string) : bool =
  on_head pairs (fun h ->
      Option.fold ~none:false
        ~some:(fun lt -> String.equal tok (lt_token lt))
        (H.limit_type h))

let tier_of (h : H.t) : Venice.Tier.t option =
  Venice.Tier.of_evidence ~usd:(H.usd h) ~diem:(H.diem h)

let tier_paid (pairs : (string * string) list) : bool =
  on_head pairs (fun h ->
      Option.fold ~none:false
        ~some:(fun (t : Venice.Tier.t) ->
          match t with
          | Venice.Tier.Paid -> true
          | Venice.Tier.Explorer -> false)
        (tier_of h))

let tier_none (pairs : (string * string) list) : bool =
  on_head pairs (fun h -> Option.is_none (tier_of h))

(* ---------- classify helpers ---------- *)

let classify (status : int) (pairs : (string * string) list) (raw : string) :
    (H.failure option, Venice.Error.t) result =
  H.classify ~status ~head:(H.of_pairs pairs) ~raw

let classify_none (status : int) (pairs : (string * string) list)
    (raw : string) : bool =
  Result.fold ~ok:Option.is_none
    ~error:(fun (_ : Venice.Error.t) -> false)
    (classify status pairs raw)

let on_failure (status : int) (pairs : (string * string) list) (raw : string)
    (f : H.failure -> bool) : bool =
  Result.fold
    ~ok:(fun o -> Option.fold ~none:false ~some:f o)
    ~error:(fun (_ : Venice.Error.t) -> false)
    (classify status pairs raw)

(* One flattened view of any failure so checks stay short. *)
type parts =
  { p_kind : string;
    p_status : int;
    p_head : H.t option;
    p_head_error : Venice.Error.t option;
    p_body : (H.body, Venice.Error.t) result option;
    p_raw : string }

let parts_of (fl : H.failure) : parts =
  match fl with
  | H.Rate_limited { head; head_error; body; raw } ->
    { p_kind = "rate_limited";
      p_status = 429;
      p_head = head;
      p_head_error = head_error;
      p_body = body;
      p_raw = raw }
  | H.Client { status; head; head_error; body; raw } ->
    { p_kind = "client";
      p_status = status;
      p_head = head;
      p_head_error = head_error;
      p_body = body;
      p_raw = raw }
  | H.Server { status; head; head_error; body; raw } ->
    { p_kind = "server";
      p_status = status;
      p_head = head;
      p_head_error = head_error;
      p_body = body;
      p_raw = raw }
  | H.Unexpected_status { status; head; head_error; raw } ->
    { p_kind = "unexpected";
      p_status = status;
      p_head = head;
      p_head_error = head_error;
      p_body = None;
      p_raw = raw }

let on_parts (status : int) (pairs : (string * string) list) (raw : string)
    (f : parts -> bool) : bool =
  on_failure status pairs raw (fun fl -> f (parts_of fl))

let body_ok (p : parts) (f : H.body -> bool) : bool =
  Option.fold ~none:false
    ~some:(fun r ->
      Result.fold ~ok:f ~error:(fun (_ : Venice.Error.t) -> false) r)
    p.p_body

let body_refused (p : parts) : bool =
  Option.fold ~none:false
    ~some:(fun r ->
      Result.fold
        ~ok:(fun (_ : H.body) -> false)
        ~error:(fun (_ : Venice.Error.t) -> true)
        r)
    p.p_body

let as_plain (b : H.body) :
    (string * string option * string option * string option) option =
  match b with
  | H.Plain { error; details; code; suggested_prompt } ->
    Some (error, details, code, suggested_prompt)
  | H.Provider_policy _ -> None
  | H.Payment_required _ -> None

let as_provider (b : H.body) : (string * string option * bool) option =
  match b with
  | H.Provider_policy { message; recommended_model; credits_refunded } ->
    Some (message, recommended_model, credits_refunded)
  | H.Plain _ -> None
  | H.Payment_required _ -> None

let as_payment (b : H.body) :
    (string option
    * string option
    * string option
    * J.dec option
    * J.dec option
    * J.dec option)
    option =
  match b with
  | H.Payment_required
      { error;
        code;
        reason;
        current_balance_usd;
        minimum_balance_usd;
        suggested_top_up_usd
      } ->
    Some
      ( error,
        code,
        reason,
        current_balance_usd,
        minimum_balance_usd,
        suggested_top_up_usd )
  | H.Plain _ -> None
  | H.Provider_policy _ -> None

let plain_is (p : parts)
    (f : string * string option * string option * string option -> bool) :
    bool =
  body_ok p (fun b -> Option.fold ~none:false ~some:f (as_plain b))

let provider_is (p : parts) (f : string * string option * bool -> bool) :
    bool =
  body_ok p (fun b -> Option.fold ~none:false ~some:f (as_provider b))

let payment_is (p : parts)
    (f :
      string option
      * string option
      * string option
      * J.dec option
      * J.dec option
      * J.dec option ->
      bool) : bool =
  body_ok p (fun b -> Option.fold ~none:false ~some:f (as_payment b))

let head_err_prefixed (p : parts) : bool =
  Option.fold ~none:false
    ~some:(fun e ->
      Option.fold ~none:false ~some:(String.equal "head: ")
        (Venice.Cursor.take (Venice.Error.to_string e) 0 6))
    p.p_head_error

(* ---------- fixtures ---------- *)

let req_triple : (string * string) list =
  [ ("x-ratelimit-limit-requests", "100");
    ("x-ratelimit-remaining-requests", "99");
    ("x-ratelimit-reset-requests", "1735689600")
  ]

let tok_triple : (string * string) list =
  [ ("x-ratelimit-limit-tokens", "60000");
    ("x-ratelimit-remaining-tokens", "59900");
    ("x-ratelimit-reset-tokens", "12.5")
  ]

let sextet : (string * string) list = req_triple @ tok_triple

let full : (string * string) list =
  sextet
  @ [ ("x-ratelimit-type", "user");
      ("x-venice-balance-usd", "10.50");
      ("x-venice-balance-diem", "0.000000000000000001")
    ]

let without (name : string) (pairs : (string * string) list) :
    (string * string) list =
  List.filter
    (fun ((n : string), (_ : string)) -> not (String.equal n name))
    pairs

let with_value (name : string) (v : string)
    (pairs : (string * string) list) : (string * string) list =
  List.map
    (fun ((n : string), (w : string)) ->
      if String.equal n name then (n, v) else (n, w))
    pairs

let req_with (v : string) : (string * string) list =
  with_value "x-ratelimit-limit-requests" v req_triple

let usd_only (v : string) : (string * string) list =
  [ ("x-venice-balance-usd", v) ]

let diem_only (v : string) : (string * string) list =
  [ ("x-venice-balance-diem", v) ]

let both_balances (u : string) (d : string) : (string * string) list =
  [ ("x-venice-balance-usd", u); ("x-venice-balance-diem", d) ]

(* Body fixtures: the six swagger error shapes. *)
let b_standard : string = {|{"error":"oops"}|}

let b_detailed : string =
  {|{"error":"bad field","details":{"field":{"_errors":["Field is required"]}}}|}

let b_violation : string =
  {|{"error":"content violation","suggested_prompt":"try this instead"}|}

let b_too_large : string =
  {|{"code":"PAYLOAD_TOO_LARGE","error":"File exceeds the maximum allowed size of 25 MB."}|}

let b_provider : string =
  {|{"error":{"message":"rejected","type":"provider_content_policy","recommended_model":"wan-2-7-text-to-video","credits_refunded":true}}|}

let b_provider_no_model : string =
  {|{"error":{"message":"rejected","type":"provider_content_policy","credits_refunded":false}}|}

let b_provider_missing : string =
  {|{"error":{"message":"rejected","type":"provider_content_policy"}}|}

let b_x402_discovery : string =
  {|{"x402Version":2,"resource":{"url":"https://api.venice.ai/api/v1/chat/completions"}}|}

let b_x402_balance : string =
  {|{"error":"Payment required","code":"PAYMENT_REQUIRED","reason":"insufficient_balance","currentBalanceUsd":0.01,"minimumBalanceUsd":0.1,"suggestedTopUpUsd":10}|}

let b_x402_mixed : string = {|{"x402Version":2,"error":"Payment required"}|}
let b_error_obj_no_type : string = {|{"error":{"message":"m"}}|}
let b_error_number : string = {|{"error":42}|}
let b_foreign : string = {|{"foo":1}|}

let checks : (string * bool) list =
  [ (* of_pairs happy path. *)
    ("full head parses", is_ok (H.of_pairs full));
    ("requests limit", on_requests full (fun r ->
         Int.equal (Venice.Requests_limit.limit r) 100));
    ("requests remaining", on_requests full (fun r ->
         Int.equal (Venice.Requests_limit.remaining r) 99));
    ("requests reset_at absolute", on_requests full (fun r ->
         Int.equal
           (Venice.Reset_at.seconds (Venice.Requests_limit.reset_at r))
           1735689600));
    ("tokens limit", on_tokens full (fun t ->
         Int.equal (Venice.Tokens_limit.limit t) 60000));
    ("tokens remaining", on_tokens full (fun t ->
         Int.equal (Venice.Tokens_limit.remaining t) 59900));
    ("tokens reset_after fractional", on_tokens full (fun t ->
         dec_eq ~neg:false ~m:125 ~s:1
           (Venice.Reset_after.seconds (Venice.Tokens_limit.reset_after t))));
    ("limit type user", limit_type_is full "user");
    ("usd trailing zero trims", on_usd full (dec_eq ~neg:false ~m:105 ~s:1));
    ("diem wei dust", on_diem full (dec_eq ~neg:false ~m:1 ~s:18));
    ("empty pairs all absent",
     on_head [] (fun h ->
         Option.is_none (H.requests h)
         && Option.is_none (H.tokens h)
         && Option.is_none (H.limit_type h)
         && Option.is_none (H.usd h)
         && Option.is_none (H.diem h)));
    ("unknown headers ignored",
     on_head
       [ ("server", "nginx"); ("content-type", "application/json") ]
       (fun h -> Option.is_none (H.requests h) && Option.is_none (H.usd h)));
    ("unknown headers alongside sextet",
     on_requests
       (("via", "proxy, proxy2") :: sextet)
       (fun r -> Int.equal (Venice.Requests_limit.limit r) 100));
    ("requests triple alone ok",
     on_head req_triple (fun h ->
         Option.is_some (H.requests h) && Option.is_none (H.tokens h)));
    ("tokens triple alone ok",
     on_head tok_triple (fun h ->
         Option.is_none (H.requests h) && Option.is_some (H.tokens h)));
    (* Case-insensitive names. *)
    ("uppercase names parse",
     on_requests
       [ ("X-RateLimit-Limit-Requests", "100");
         ("X-RATELIMIT-REMAINING-REQUESTS", "99");
         ("X-RateLimit-Reset-Requests", "1735689600")
       ]
       (fun r -> Int.equal (Venice.Requests_limit.limit r) 100));
    ("mixed-case balance parses",
     on_usd [ ("X-Venice-Balance-Usd", "1.5") ]
       (dec_eq ~neg:false ~m:15 ~s:1));
    ("value case preserved in Other",
     limit_type_is [ ("x-ratelimit-type", "USER") ] "other:USER");
    (* A2 value normalization. *)
    ("edge SP/CR strip accepts",
     on_requests (req_with " 100\r") (fun r ->
         Int.equal (Venice.Requests_limit.limit r) 100));
    ("edge HTAB strip accepts",
     on_usd (usd_only "\t1.5 ") (dec_eq ~neg:false ~m:15 ~s:1));
    ("embedded CR rejects", is_err (H.of_pairs (req_with "10\r0")));
    ("embedded LF rejects", is_err (H.of_pairs (usd_only "1.\n5")));
    ("embedded CR names the check",
     err_contains "smuggling" (H.of_pairs (req_with "10\r0")));
    ("comma 100,99 rejects", is_err (H.of_pairs (req_with "100, 99")));
    ("comma 100,100 rejects", is_err (H.of_pairs (req_with "100, 100")));
    ("comma names the check",
     err_contains "comma" (H.of_pairs (req_with "100, 100")));
    ("repeated name rejects (identical value)",
     is_err
       (H.of_pairs (("x-ratelimit-limit-requests", "100") :: req_triple)));
    ("repeated name rejects (differing value)",
     is_err (H.of_pairs (("x-ratelimit-limit-requests", "7") :: req_triple)));
    ("repeated name rejects across cases",
     is_err
       (H.of_pairs (("X-RateLimit-Limit-Requests", "100") :: req_triple)));
    ("repeated name names the check",
     err_contains "repeated"
       (H.of_pairs (("x-ratelimit-limit-requests", "100") :: req_triple)));
    ("unknown name may repeat",
     is_ok (H.of_pairs [ ("via", "a"); ("via", "b") ]));
    (* Partial triples: all six holes reject. *)
    ("hole limit-requests rejects",
     is_err (H.of_pairs (without "x-ratelimit-limit-requests" sextet)));
    ("hole remaining-requests rejects",
     is_err (H.of_pairs (without "x-ratelimit-remaining-requests" sextet)));
    ("hole reset-requests rejects",
     is_err (H.of_pairs (without "x-ratelimit-reset-requests" sextet)));
    ("hole limit-tokens rejects",
     is_err (H.of_pairs (without "x-ratelimit-limit-tokens" sextet)));
    ("hole remaining-tokens rejects",
     is_err (H.of_pairs (without "x-ratelimit-remaining-tokens" sextet)));
    ("hole reset-tokens rejects",
     is_err (H.of_pairs (without "x-ratelimit-reset-tokens" sextet)));
    ("partial triple names the check",
     err_contains "partial"
       (H.of_pairs (without "x-ratelimit-reset-requests" sextet)));
    (* Balances: two independent options (A3). *)
    ("usd-only parses with diem None",
     on_head (usd_only "3.25") (fun h ->
         Option.is_some (H.usd h) && Option.is_none (H.diem h)));
    ("diem-only parses with usd None",
     on_head (diem_only "0.5") (fun h ->
         Option.is_none (H.usd h) && Option.is_some (H.diem h)));
    ("malformed usd rejects of_pairs",
     is_err (H.of_pairs (usd_only "abc")));
    ("malformed diem rejects of_pairs",
     is_err (H.of_pairs (diem_only "1..2")));
    (* Count grammar (D4). *)
    ("count plus sign rejects", is_err (H.of_pairs (req_with "+100")));
    ("count minus sign rejects", is_err (H.of_pairs (req_with "-100")));
    ("count dot rejects", is_err (H.of_pairs (req_with "1.5")));
    ("count empty rejects", is_err (H.of_pairs (req_with "")));
    ("count 19 digits rejects",
     is_err (H.of_pairs (req_with "1000000000000000000")));
    ("count leading zero rejects", is_err (H.of_pairs (req_with "0100")));
    ("count 10^18-1 accepts",
     on_requests (req_with "999999999999999999") (fun r ->
         Int.equal (Venice.Requests_limit.limit r) 999999999999999999));
    ("count zero accepts",
     on_requests (req_with "0") (fun r ->
         Int.equal (Venice.Requests_limit.limit r) 0));
    ("count error names the header",
     err_contains "limit-requests" (H.of_pairs (req_with "1.5")));
    (* Reset semantics (D4/A4). *)
    ("reset-requests fraction rejects",
     is_err
       (H.of_pairs (with_value "x-ratelimit-reset-requests" "12.5" sextet)));
    ("reset-tokens fraction accepts",
     on_tokens (with_value "x-ratelimit-reset-tokens" "0.5" tok_triple)
       (fun t ->
         dec_eq ~neg:false ~m:5 ~s:1
           (Venice.Reset_after.seconds (Venice.Tokens_limit.reset_after t))));
    ("reset-tokens integer accepts",
     on_tokens (with_value "x-ratelimit-reset-tokens" "60" tok_triple)
       (fun t ->
         dec_eq ~neg:false ~m:60 ~s:0
           (Venice.Reset_after.seconds (Venice.Tokens_limit.reset_after t))));
    ("reset-tokens negative rejects",
     is_err
       (H.of_pairs (with_value "x-ratelimit-reset-tokens" "-1" tok_triple)));
    ("reset-requests zero accepts",
     on_requests (with_value "x-ratelimit-reset-requests" "0" req_triple)
       (fun r ->
         Int.equal
           (Venice.Reset_at.seconds (Venice.Requests_limit.reset_at r))
           0));
    (* The one headx decimal grammar (A5). *)
    ("wei dust accepts (0.000000000000000001)",
     on_diem (diem_only "0.000000000000000001")
       (dec_eq ~neg:false ~m:1 ~s:18));
    ("18 trailing zeros trim (1.000000000000000000)",
     on_diem (diem_only "1.000000000000000000")
       (dec_eq ~neg:false ~m:1 ~s:0));
    ("19 significant digits reject (integer)",
     is_err (H.of_pairs (diem_only "1234567890123456789")));
    ("19 significant digits reject (mixed)",
     is_err (H.of_pairs (diem_only "123456789012345678.9")));
    ("18 significant digits accept (mixed)",
     on_diem (diem_only "12345678901234567.8")
       (dec_eq ~neg:false ~m:123456789012345678 ~s:1));
    ("trailing zeros trim to nonzero scale",
     on_usd (usd_only "10.50") (dec_eq ~neg:false ~m:105 ~s:1));
    ("0.0 normalizes to plain zero",
     on_usd (usd_only "0.0") (dec_eq ~neg:false ~m:0 ~s:0));
    ("negative usd accepts", on_usd (usd_only "-0.5")
       (dec_eq ~neg:true ~m:5 ~s:1));
    ("dot with no fraction rejects", is_err (H.of_pairs (usd_only "1.")));
    ("bare dot lead rejects", is_err (H.of_pairs (usd_only ".5")));
    ("decimal leading zero rejects", is_err (H.of_pairs (usd_only "05.5")));
    ("exponent shape rejects", is_err (H.of_pairs (usd_only "1e5")));
    ("double sign rejects", is_err (H.of_pairs (usd_only "--1")));
    ("second dot rejects", is_err (H.of_pairs (usd_only "1.2.3")));
    ("decimal error names the header",
     err_contains "balance-usd" (H.of_pairs (usd_only "1.2.3")));
    (* Tier derivation (A7). *)
    ("tier 0/0 is None", tier_none (both_balances "0" "0.00"));
    ("tier no balances is None", tier_none sextet);
    ("tier dust-positive diem is Paid",
     tier_paid (both_balances "0" "0.000000000000000001"));
    ("tier negative usd + positive diem is Paid",
     tier_paid (both_balances "-5.00" "1"));
    ("tier negative-only is None", tier_none (both_balances "-5" "-0.1"));
    ("tier positive usd alone is Paid", tier_paid (usd_only "0.01"));
    ("tier zero usd alone is None", tier_none (usd_only "0"));
    (* Limit_type (A6). *)
    ("limit type api_key",
     limit_type_is [ ("x-ratelimit-type", "api_key") ] "api_key");
    ("limit type global",
     limit_type_is [ ("x-ratelimit-type", "global") ] "global");
    ("limit type unknown round-trips as Other",
     limit_type_is [ ("x-ratelimit-type", "workspace") ] "other:workspace");
    ("limit type empty rejects",
     err_contains "empty token" (H.of_pairs [ ("x-ratelimit-type", "  ") ]));
    ("limit type absent is None",
     on_head sextet (fun h -> Option.is_none (H.limit_type h)));
    (* classify per status class (D8/A8). *)
    ("classify 200 is Ok None", classify_none 200 full "");
    ("classify 204 is Ok None", classify_none 204 full "");
    ("classify 429 is Rate_limited",
     on_parts 429 full "" (fun p -> String.equal p.p_kind "rate_limited"));
    ("classify 429 carries parsed resets",
     on_parts 429 full "" (fun p ->
         Option.fold ~none:false
           ~some:(fun h ->
             Option.fold ~none:false
               ~some:(fun r ->
                 Int.equal
                   (Venice.Reset_at.seconds
                      (Venice.Requests_limit.reset_at r))
                   1735689600)
               (H.requests h))
           p.p_head));
    ("classify 404 is Client with status",
     on_parts 404 full "" (fun p ->
         String.equal p.p_kind "client" && Int.equal p.p_status 404));
    ("classify 500 is Server",
     on_parts 500 full "" (fun p ->
         String.equal p.p_kind "server" && Int.equal p.p_status 500));
    ("classify 302 is Unexpected_status",
     on_parts 302 full "" (fun p ->
         String.equal p.p_kind "unexpected" && Int.equal p.p_status 302));
    ("classify 100 is Unexpected_status",
     on_parts 100 full "" (fun p -> String.equal p.p_kind "unexpected"));
    ("classify 600 rejects", is_err (classify 600 full ""));
    ("classify 99 rejects", is_err (classify 99 full ""));
    ("classify status error prefix",
     err_prefix "head: classify" (classify 600 full ""));
    ("classify 5xx carries balances for M28",
     on_parts 502 (usd_only "3.25") "" (fun p ->
         Option.fold ~none:false
           ~some:(fun h ->
             Option.fold ~none:false
               ~some:(fun u ->
                 dec_eq ~neg:false ~m:325 ~s:2 (Venice.Usd.value u))
               (H.usd h))
           p.p_head));
    (* Content mangling: a mangled head never erases the status. *)
    ("mangled 429 still Rate_limited",
     on_parts 429 (without "x-ratelimit-reset-requests" full) "" (fun p ->
         String.equal p.p_kind "rate_limited" && Option.is_none p.p_head));
    ("mangled 429 carries head_error",
     on_parts 429 (without "x-ratelimit-reset-requests" full) "" (fun p ->
         Option.is_some p.p_head_error));
    ("mangled head_error is head-prefixed",
     on_parts 429 (without "x-ratelimit-reset-requests" full) ""
       head_err_prefixed);
    ("mangled 404 still Client",
     on_parts 404 (req_with "0100") "" (fun p ->
         String.equal p.p_kind "client" && Option.is_none p.p_head
         && Option.is_some p.p_head_error));
    (* Body shapes: all six swagger error products. *)
    ("StandardError -> Plain",
     on_parts 404 [] b_standard (fun p ->
         plain_is p (fun (error, details, code, sp) ->
             String.equal error "oops" && Option.is_none details
             && Option.is_none code && Option.is_none sp)));
    ("DetailedError -> Plain with printed details",
     on_parts 400 [] b_detailed (fun p ->
         plain_is p (fun ((_ : string), details, (_ : string option), _sp) ->
             ostr {|{"field":{"_errors":["Field is required"]}}|} details)));
    ("ContentViolationError -> Plain with suggested_prompt",
     on_parts 400 [] b_violation (fun p ->
         plain_is p (fun ((_ : string), _d, (_ : string option), sp) ->
             ostr "try this instead" sp)));
    ("PayloadTooLargeError -> Plain with code",
     on_parts 413 [] b_too_large (fun p ->
         plain_is p (fun ((_ : string), _d, code, _sp) ->
             ostr "PAYLOAD_TOO_LARGE" code)));
    ("ProviderContentPolicyError -> Provider_policy",
     on_parts 400 [] b_provider (fun p ->
         provider_is p (fun (message, model, refunded) ->
             String.equal message "rejected"
             && ostr "wan-2-7-text-to-video" model && refunded)));
    ("provider policy without recommended_model",
     on_parts 400 [] b_provider_no_model (fun p ->
         provider_is p (fun ((_ : string), model, refunded) ->
             Option.is_none model && not refunded)));
    ("provider policy missing credits_refunded is refused, raw kept",
     on_parts 400 [] b_provider_missing (fun p ->
         body_refused p && String.equal p.p_raw b_provider_missing));
    ("x402 discovery branch -> Payment_required",
     on_parts 402 [] b_x402_discovery (fun p ->
         payment_is p (fun (error, code, reason, cur, min_b, top) ->
             Option.is_none error && Option.is_none code
             && Option.is_none reason && Option.is_none cur
             && Option.is_none min_b && Option.is_none top)));
    ("x402 balance branch -> Payment_required",
     on_parts 402 [] b_x402_balance (fun p ->
         payment_is p (fun (error, code, reason, cur, min_b, top) ->
             ostr "Payment required" error && ostr "PAYMENT_REQUIRED" code
             && ostr "insufficient_balance" reason
             && odec ~neg:false ~m:1 ~s:2 cur
             && odec ~neg:false ~m:1 ~s:1 min_b
             && odec ~neg:false ~m:10 ~s:0 top)));
    ("x402Version keys before error string",
     on_parts 402 [] b_x402_mixed (fun p ->
         payment_is p
           (fun (error, (_ : string option), _r, _c, _m, _t) ->
             ostr "Payment required" error)));
    ("PAYLOAD_TOO_LARGE code stays Plain",
     on_parts 413 [] b_too_large (fun p ->
         body_ok p (fun b -> Option.is_some (as_plain b))));
    (* Refused and absent bodies (A8 three-state). *)
    ("error object without type is refused",
     on_parts 400 [] b_error_obj_no_type body_refused);
    ("error member of wrong type is refused",
     on_parts 400 [] b_error_number body_refused);
    ("foreign object is refused, raw kept",
     on_parts 400 [] b_foreign (fun p ->
         body_refused p && String.equal p.p_raw b_foreign));
    ("unparseable body is refused, raw kept",
     on_parts 500 [] "not json" (fun p ->
         body_refused p && String.equal p.p_raw "not json"));
    ("non-object JSON body is refused",
     on_parts 400 [] "[1,2]" body_refused);
    ("empty raw is body None",
     on_parts 500 [] "" (fun p ->
         Option.is_none p.p_body && String.equal p.p_raw ""));
    ("refused body error is head-prefixed",
     on_parts 400 [] b_foreign (fun p ->
         Option.fold ~none:false
           ~some:(fun r ->
             Result.fold
               ~ok:(fun (_ : H.body) -> false)
               ~error:(fun e ->
                 contains_sub "head: body:" (Venice.Error.to_string e))
               r)
           p.p_body));
    (* Public compare_dec (A10). *)
    ("compare_dec public threshold on a balance",
     on_usd (usd_only "10.50") (fun d ->
         J.compare_dec d { J.negative = false; mantissa = 5; scale = 0 } > 0
         && J.compare_dec d { J.negative = false; mantissa = 11; scale = 0 }
            < 0));
    ("compare_dec public zero normalization",
     Int.equal 0
       (J.compare_dec
          { J.negative = true; mantissa = 0; scale = 2 }
          { J.negative = false; mantissa = 0; scale = 0 }));
    ("compare_dec public sign split",
     J.compare_dec
       { J.negative = true; mantissa = 5; scale = 1 }
       { J.negative = false; mantissa = 1; scale = 3 }
     < 0);
    (* Error constructor surface. *)
    ("head error prefix", err_prefix "head: " (H.of_pairs (req_with "-1")))
  ]

let (() : unit) = run checks
