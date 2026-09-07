(* M28 composes the five attestation witnesses. No clock or network
   reaches this unit. See attestx.mli for the order and limitations. *)
type layout = {
  zero : int; one : int; two : int; four : int; hundred : int;
  four_hundred : int; epoch : int; last_second : int; day : int;
  hour : int; minute : int; ordinary_year : int; months : int list;
  prefix : string; quote_member : string; key_member : string;
  address_member : string; nonce_member : string; alternate_nonce : string;
  gpu_member : string; model_member : string; provider_member : string;
  verified_member : string; evidence_member : string; arch_member : string;
  pad : char;
}

let layout (() : unit) : layout = {
  zero = 0; one = 1; two = 2; four = 4; hundred = 100;
  four_hundred = 400; epoch = 1970; last_second = 253402300799;
  day = 86400; hour = 3600; minute = 60; ordinary_year = 365;
  months = [31; 28; 31; 30; 31; 30; 31; 31; 30; 31; 30; 31];
  prefix = "0x"; quote_member = "intel_quote"; key_member = "signing_key";
  address_member = "signing_address"; nonce_member = "nonce";
  alternate_nonce = "request_nonce"; gpu_member = "nvidia_payload";
  model_member = "model"; provider_member = "tee_provider";
  verified_member = "verified"; evidence_member = "evidence_list";
  arch_member = "arch"; pad = '0';
}

let ( let* ) = Result.bind
let fail (word : string) : ('a, Errx.t) result =
  Error (Errx.Attest_invalid word)
let require (word : string) (value : 'a option) : ('a, Errx.t) result =
  Option.fold ~none:(fail word) ~some:(fun x -> Ok x) value
let demand (word : string) (ok : bool) : (unit, Errx.t) result =
  if ok then Ok () else fail word
let member_string (name : string) (json : Jsonx.t) : string option =
  Option.bind (Jsonx.member name json) Jsonx.as_string

module Envelope = struct
  type t = {
    quote : string; key : string; address : string; echo : string;
    gpu : Jsonx.t option; model : string option; provider : string option;
    verified : bool option;
  }

  let parse (l : layout) (text : string) : (t, Errx.t) result =
    let* json = require "envelope" (Result.to_option (Jsonx.parse text)) in
    let* fields = require "envelope" (Jsonx.as_obj json) in
    let object_ = Jsonx.Jobj fields in
    let* quote = require "intel quote member" (member_string l.quote_member object_) in
    let* key = require "signing key member" (member_string l.key_member object_) in
    let* address = require "signing address member" (member_string l.address_member object_) in
    (* The primary spelling wins when present, including a wrong type.
       A second spelling cannot hide a malformed primary member. *)
    let echo_value = Option.fold
      ~none:(Jsonx.member l.alternate_nonce object_)
      ~some:(fun x -> Some x) (Jsonx.member l.nonce_member object_) in
    let* echo = require "nonce member" (Option.bind echo_value Jsonx.as_string) in
    Ok { quote; key; address; echo;
         gpu = Jsonx.member l.gpu_member object_;
         model = member_string l.model_member object_;
         provider = member_string l.provider_member object_;
         verified = Option.bind (Jsonx.member l.verified_member object_) Jsonx.as_bool }

  let of_json (text : string) : (t, Errx.t) result = parse (layout ()) text
  let intel_quote (t : t) : string = t.quote
  let nonce_echo (t : t) : string = t.echo
  let signing_key_hex (t : t) : string = t.key
  let signing_address_hex (t : t) : string = t.address
  let nvidia_payload (t : t) : Jsonx.t option = t.gpu
  let model (t : t) : string option = t.model
end

module Gpu = struct
  module Payload = struct
    type t = { nonce : string; arch : string; count : int }
    let nonce_hex (t : t) : string = t.nonce
    let arch (t : t) : string = t.arch
    let evidence_count (t : t) : int = t.count
  end
  type t = Absent | Present of Payload.t
end

let check_echo ~(echo : string) ~(nonce : Policyx.Nonce.t) : (unit, Errx.t) result =
  demand "nonce echo"
    (String.equal (String.lowercase_ascii echo) (Policyx.Nonce.to_hex nonce))

let candidate (l : layout) (decoded : (string, Errx.t) result) : string option =
  Option.bind (Result.to_option decoded) (fun bytes ->
    Option.bind (Bytesx.u16le bytes l.zero) (fun version ->
      if Int.equal version l.four then Some bytes else None))

let quote_decode (l : layout) (text : string) : (Quotex.t, Errx.t) result =
  let bytes = Option.fold
    ~none:(fun () -> candidate l (Hexx.decode text))
    ~some:(fun bytes () -> Some bytes)
    (candidate l (B64x.decode_std text)) () in
  let* bytes = require "intel quote encoding" bytes in
  Quotex.parse bytes

let decode_quote (text : string) : (Quotex.t, Errx.t) result =
  quote_decode (layout ()) text

let strip_prefix (l : layout) (text : string) : string =
  if String.starts_with ~prefix:l.prefix text then
    Option.value ~default:text
      (Bytesx.take text l.two (String.length text - l.two))
  else text

let signing_check (l : layout) ~(key_hex : string) ~(address_hex : string) :
    (Secpx.Pubkey.t * Keccakx.Address.t, Errx.t) result =
  let* key = require "signing key"
    (Option.bind (Result.to_option (Hexx.decode (strip_prefix l key_hex)))
       Secpx.Pubkey.of_bytes) in
  let* address = require "signing address" (Policyx.address_of_key key) in
  let* supplied = require "signing address" (Keccakx.Address.of_hex address_hex) in
  let* () = demand "signing address" (Keccakx.Address.equal address supplied) in
  Ok (key, address)

let check_signing_key ~(key_hex : string) ~(address_hex : string) :
    (Secpx.Pubkey.t * Keccakx.Address.t, Errx.t) result =
  signing_check (layout ()) ~key_hex ~address_hex

let payload_object (value : Jsonx.t) : (Jsonx.t, Errx.t) result =
  match value with
  | Jsonx.Jstring text ->
      let* json = require "nvidia payload json" (Result.to_option (Jsonx.parse text)) in
      let* fields = require "nvidia payload json" (Jsonx.as_obj json) in
      Ok (Jsonx.Jobj fields)
  | Jsonx.Jobj fields -> Ok (Jsonx.Jobj fields)
  | Jsonx.Jnull | Jsonx.Jbool _ | Jsonx.Jint _ | Jsonx.Jdec _ | Jsonx.Jlist _ ->
      fail "nvidia payload"

let payload_parse (l : layout) ~(nonce : Policyx.Nonce.t) (value : Jsonx.t) :
    (Gpu.Payload.t, Errx.t) result =
  let* json = payload_object value in
  let* echo = require "nvidia payload members" (member_string l.nonce_member json) in
  let* arch = require "nvidia payload members" (member_string l.arch_member json) in
  let* evidence = require "nvidia payload members" (Jsonx.member l.evidence_member json) in
  let normalized = String.lowercase_ascii echo in
  let* () = demand "nvidia payload nonce"
    (String.equal normalized (Policyx.Nonce.to_hex nonce)) in
  let* entries = require "nvidia evidence list" (Jsonx.as_list evidence) in
  let count = List.length entries in
  let* () = demand "nvidia evidence list" (count > l.zero) in
  Ok { Gpu.Payload.nonce = normalized; arch; count }

let parse_payload ~(nonce : Policyx.Nonce.t) (value : Jsonx.t) :
    (Gpu.Payload.t, Errx.t) result = payload_parse (layout ()) ~nonce value

let gpu_check (l : layout) ~(nonce : Policyx.Nonce.t) (value : Jsonx.t option) :
    (Gpu.t, Errx.t) result =
  (* An explicit JSON null counts as absence, as the harness oracle
     live_nvidia reads it; every other non-string, non-object shape
     says "nvidia payload" through payload_object. *)
  Option.fold ~none:(Ok Gpu.Absent)
    ~some:(fun (json : Jsonx.t) ->
      match json with
      | Jsonx.Jnull -> Ok Gpu.Absent
      | Jsonx.Jstring _ | Jsonx.Jobj _ | Jsonx.Jbool _ | Jsonx.Jint _
      | Jsonx.Jdec _ | Jsonx.Jlist _ ->
          Result.map (fun p -> Gpu.Present p) (payload_parse l ~nonce json))
    value

let check_gpu ~(nonce : Policyx.Nonce.t) (value : Jsonx.t option) : (Gpu.t, Errx.t) result =
  gpu_check (layout ()) ~nonce value

(* Each subtraction walk is bounded by the accepted epoch range.
   The largest walk is 8030 years, never one step per second. *)
let rec quotient (l : layout) (n : int) (size : int) (count : int) : int * int =
  if n < size then (count, n)
  else quotient l (n - size) size (count + l.one)

let divisible (l : layout) (n : int) (size : int) : bool =
  let (_count, remainder) = quotient l n size l.zero in
  Int.equal remainder l.zero

let leap (l : layout) (year : int) : bool =
  divisible l year l.four &&
    (not (divisible l year l.hundred) || divisible l year l.four_hundred)

let rec year_walk (l : layout) (year : int) (seconds : int) : int * int =
  let days = l.ordinary_year + (if leap l year then l.one else l.zero) in
  let size = days * l.day in
  if seconds < size then (year, seconds)
  else year_walk l (year + l.one) (seconds - size)

let rec month_walk (l : layout) (is_leap : bool) (month : int) (days : int)
    (months : int list) : int * int =
  match months with
  | [] -> (month, days + l.one)
  | length :: rest ->
      let length = length +
        (if is_leap && Int.equal month l.two then l.one else l.zero) in
      if days < length then (month, days + l.one)
      else month_walk l is_leap (month + l.one) (days - length) rest

let padded (l : layout) (width : int) (value : int) : string =
  let text = string_of_int value in
  String.make (max l.zero (width - String.length text)) l.pad ^ text

let now_of_unix ~(seconds : int) : Derx.Now.t option =
  let l = layout () in
  if seconds < l.zero || seconds > l.last_second then None
  else
    let (year, within_year) = year_walk l l.epoch seconds in
    let (days, within_day) = quotient l within_year l.day l.zero in
    let (month, day) = month_walk l (leap l year) l.one days l.months in
    let (hour, within_hour) = quotient l within_day l.hour l.zero in
    let (minute, second) = quotient l within_hour l.minute l.zero in
    Derx.Now.of_digits
      (padded l l.four year ^ padded l l.two month ^ padded l l.two day ^
       padded l l.two hour ^ padded l l.two minute ^ padded l l.two second)

(* Reusable over real signed evidence even when its REPORTDATA belongs
   to another deployment. This mints no attestation or session witness.
   The signature witness is re-minted from the supplied quote, so the
   signed 632-byte region is re-bound to the QE and ISV signatures on
   every call. A caller cannot pair one quote with a foreign witness. *)
let revalidate_evidence ~(now : Derx.Now.t) ~(collateral : Tcbx.Collateral.t)
    ~(quote : Quotex.t) : (unit, Errx.t) result =
  let* chain = Derx.verify_chain ~now
    (Quotex.Signature_section.pem_chain (Quotex.signature_section quote)) in
  let* signature = Sigx.verify ~pck_key:(Derx.pck_key chain) quote in
  Result.map (fun (_ : Tcbx.t) -> ())
    (Tcbx.verify ~now ~collateral ~chain ~quote ~sig_:signature)

module Attested = struct
  type 'level t = {
    quote : Quotex.t; chain : Derx.t; signature : Sigx.t; tcb : Tcbx.t;
    policy : 'level Policyx.t; signing_key : Secpx.Pubkey.t; gpu : Gpu.t;
    model : string option; provider : string option; verified : bool option;
    collateral : Tcbx.Collateral.t;
  }
  let quote (t : 'l t) : Quotex.t = t.quote
  let chain (t : 'l t) : Derx.t = t.chain
  let signature (t : 'l t) : Sigx.t = t.signature
  let tcb (t : 'l t) : Tcbx.t = t.tcb
  let policy (t : 'l t) : 'l Policyx.t = t.policy
  let nonce (t : 'l t) : Policyx.Nonce.t = Policyx.nonce t.policy
  let signing_key (t : 'l t) : Secpx.Pubkey.t = t.signing_key
  let signing_address (t : 'l t) : Keccakx.Address.t = Policyx.signing_address t.policy
  let gpu (t : 'l t) : Gpu.t = t.gpu
  let model (t : 'l t) : string option = t.model
  let tee_provider (t : 'l t) : string option = t.provider
  let verified_flag (t : 'l t) : bool option = t.verified

  (* A witness can outlive its certificates or collateral. Recheck the
     original signed inputs at the session caller's explicit instant. *)
  let revalidate ~(now : Derx.Now.t) (t : 'l t) : (unit, Errx.t) result =
    revalidate_evidence ~now ~collateral:t.collateral ~quote:t.quote
end

let verify ~(now : Derx.Now.t) ~(expect : 'l Policyx.Expect.t)
    ~(nonce : Policyx.Nonce.t) ~(collateral : Tcbx.Collateral.t)
    ~(response : string) : ('l Attested.t, Errx.t) result =
  let l = layout () in
  let* envelope = Envelope.parse l response in
  let* () = check_echo ~echo:(Envelope.nonce_echo envelope) ~nonce in
  let* quote = quote_decode l (Envelope.intel_quote envelope) in
  let* (signing_key, _address) = signing_check l
    ~key_hex:(Envelope.signing_key_hex envelope)
    ~address_hex:(Envelope.signing_address_hex envelope) in
  let* chain = Derx.verify_chain ~now
    (Quotex.Signature_section.pem_chain (Quotex.signature_section quote)) in
  let* signature = Sigx.verify ~pck_key:(Derx.pck_key chain) quote in
  let* tcb = Tcbx.verify ~now ~collateral ~chain ~quote ~sig_:signature in
  let* policy = Policyx.verify ~expect ~nonce ~signing_key quote in
  let* gpu = gpu_check l ~nonce (Envelope.nvidia_payload envelope) in
  Ok { Attested.quote; chain; signature; tcb; policy; signing_key; gpu;
       model = Envelope.model envelope; provider = envelope.Envelope.provider;
       verified = envelope.Envelope.verified; collateral }
