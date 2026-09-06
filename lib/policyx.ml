(* policyx: the TDX attestation POLICY unit (M24, DESIGN.md:404). It is
   the SECOND module of the attestation tower. It is pure and sans-io:
   no Bytes, no Buffer, no Array, no reference cell, no exception, no
   division and no remainder. Every window comes from Bytesx.take, so a
   short window answers None and never raises, and every integer comes
   from the total quotex accessors.

   THE RULES TABLE, the ONE record below. Every offset in it is
   RELATIVE to the 64-byte report_data window, because this unit reads
   that window through Quotex.Body.report_data and never indexes the
   whole quote. The columns are the report_data offset, the ABSOLUTE
   quote offset, the length and the name.

     0    568   20   address20, the signing address
     20   588   12   zero_pad, the twelve bytes no verifier reads
     32   600   32   nonce32, the RAW nonce
     -    568   64   rd_len, the whole window, which the three above
                     tile exactly
     -    184   48   meas_len, one measurement, and the same length at
                     376, 424, 472 and 520
     -    168   8    td_attributes, whose bit 0 debug_mask selects

   THE CHECK ORDER inside verify, where the reason names the FIRST
   failure:

     0  the signing address exists at all, "signing key"
     1  the DEBUG bit at 168, "debug td"
     2  the address window report_data[0..20], "address mismatch"
     3  the zero pad window report_data[20..32], "pad not zero"
     4  the nonce window report_data[32..64], "nonce mismatch"
     5  the five measurements, "mr_td mismatch" to "rt_mr3 mismatch",
        and only for a full expectation

   THE ZXLINT RULE (trap 2, ZXCAML.md:18-20). rules () builds the
   record ONCE and every helper that needs a constant takes it, so no
   numeric literal and no string constant sits outside the body of
   rules () and the comments, and no top-level alias of a Bytesx, a
   Quotex, a Keccakx, a Secpx or a Hexx binding exists. This unit
   applies no functor and holds no Map, so it stays eligible for the
   M38 omlz artifact.

   The reason vocabulary is CLOSED at TEN words and every rejection is
   one Errx.Policy_rejected, which Errx.to_string prints under
   "policy: ". *)

type rules = {
  addr_off : int;
  addr_len : int;
  pad_off : int;
  pad_len : int;
  nonce_off : int;
  nonce_len : int;
  rd_len : int;
  meas_len : int;
  debug_mask : int64;
  zero_pad : string;
}

(* The ONE record, built once. rd_len is arithmetic HERE and never a
   literal at a use site: the three windows tile the 64-byte report_data
   window exactly, so nonce_off plus nonce_len is its length. zero_pad
   is built HERE too, because a twelve-byte constant inside a helper is
   the same trap 2 finding as a bare number. *)
let rules (() : unit) : rules =
  let addr_off = 0 in
  let addr_len = 20 in
  let pad_off = 20 in
  let pad_len = 12 in
  let nonce_off = 32 in
  let nonce_len = 32 in
  let rd_len = nonce_off + nonce_len in
  let meas_len = 48 in
  let debug_mask = 1L in
  let zero_pad = String.make pad_len '\000' in
  {
    addr_off;
    addr_len;
    pad_off;
    pad_len;
    nonce_off;
    nonce_len;
    rd_len;
    meas_len;
    debug_mask;
    zero_pad;
  }

(* The nonce the caller published in the request and the quote echoes
   back RAW at report_data[32..64]. It is 32 bytes by construction, so
   to_bytes never needs a length test at a use site. *)
module Nonce = struct
  type t = string

  let len (() : unit) : int = (rules ()).nonce_len

  let of_bytes (s : string) : t option =
    if Int.equal (String.length s) (len ()) then Some s else None

  (* Hexx.decode answers a result, which Result.to_option turns into
     the option the length test then consumes, so no match on a result
     and no match on an option happens here. *)
  let of_hex (h : string) : t option =
    Option.bind (Result.to_option (Hexx.decode h)) of_bytes

  let to_bytes (n : t) : string = n
  let to_hex (n : t) : string = Hexx.encode n
  let equal (a : t) (b : t) : bool = String.equal a b
end

(* The five measurements MRTD and RTMR0 to RTMR3, 48 bytes each, at the
   ABSOLUTE quote offsets 184, 376, 424, 472 and 520. mr_seam,
   mrsigner_seam, mr_config_id, mr_owner and mr_owner_config are NOT
   policy inputs, because the M24 row and the threat row DESIGN.md:52
   name these five alone. *)
module Measurements = struct
  type t = {
    mr_td : string;
    rt_mr0 : string;
    rt_mr1 : string;
    rt_mr2 : string;
    rt_mr3 : string;
  }

  let make ~(mr_td : string) ~(rt_mr0 : string) ~(rt_mr1 : string)
      ~(rt_mr2 : string) ~(rt_mr3 : string) : t option =
    let r = rules () in
    let sized (s : string) : bool = Int.equal (String.length s) r.meas_len in
    if List.for_all sized [ mr_td; rt_mr0; rt_mr1; rt_mr2; rt_mr3 ] then
      Some { mr_td; rt_mr0; rt_mr1; rt_mr2; rt_mr3 }
    else None

  let mr_td (m : t) : string = m.mr_td
  let rt_mr0 (m : t) : string = m.rt_mr0
  let rt_mr1 (m : t) : string = m.rt_mr1
  let rt_mr2 (m : t) : string = m.rt_mr2
  let rt_mr3 (m : t) : string = m.rt_mr3

  (* TOTAL: every quotex accessor is total on a parsed body
     (quotex.mli:8-10), so no option and no result appears here. *)
  let of_body (b : Quotex.Body.t) : t =
    {
      mr_td = Quotex.Body.mr_td b;
      rt_mr0 = Quotex.Body.rt_mr0 b;
      rt_mr1 = Quotex.Body.rt_mr1 b;
      rt_mr2 = Quotex.Body.rt_mr2 b;
      rt_mr3 = Quotex.Body.rt_mr3 b;
    }

  (* The FIRST differing field, in the D6 order. The triples are laid
     out in that order and List.find_map walks them once, so the order
     of the answer is the order of this list and nothing else. *)
  let first_mismatch ~(expected : t) ~(observed : t) : string option =
    List.find_map
      (fun ((name : string), (want : string), (got : string)) ->
        if String.equal want got then None else Some name)
      [
        ("mr_td", expected.mr_td, observed.mr_td);
        ("rt_mr0", expected.rt_mr0, observed.rt_mr0);
        ("rt_mr1", expected.rt_mr1, observed.rt_mr1);
        ("rt_mr2", expected.rt_mr2, observed.rt_mr2);
        ("rt_mr3", expected.rt_mr3, observed.rt_mr3);
      ]

  let equal (a : t) (b : t) : bool =
    Option.is_none (first_mismatch ~expected:a ~observed:b)
end

(* The expectation, a GADT whose index the two constructors pin, so the
   level flows into the witness unchanged and tofu can never mint a
   full one. The markers are uninhabited (modelx.ml:14-22) and cost
   nothing at run time. *)
module Expect = struct
  type full = |
  type structural = |

  type _ t =
    | Full : Measurements.t -> full t
    | Tofu : structural t

  let make ~(measurements : Measurements.t) : full t = Full measurements
  let tofu (() : unit) : structural t = Tofu

  (* The ONE-ARM match the index proves exhaustive at type full t: a
     Tofu value cannot reach here, so this arm is the whole match and
     no wildcard is owed. *)
  let measurements (e : full t) : Measurements.t =
    match e with Full m -> m
end

(* The witness a successful verify mints. The record holds what the
   quote proved and never what the caller expected. *)
type witness = {
  measurements : Measurements.t;
  signing_address : Keccakx.Address.t;
  nonce : Nonce.t;
}

(* 'level is phantom: this alias erases it inside the unit and
   policyx.mli re-abstracts the type, which is where the guarantee
   lives (modelx.ml:131-134), so a caller can neither forge a level nor
   cast one. *)
type 'level t = witness

let measurements (w : 'l t) : Measurements.t = w.measurements
let signing_address (w : 'l t) : Keccakx.Address.t = w.signing_address
let nonce (w : 'l t) : Nonce.t = w.nonce

(* Secpx.Pubkey.to_bytes is the 64 bytes X || Y (secpx.mli:62-63) and
   Keccakx.Address.of_pubkey accepts exactly 64 bytes
   (keccakx.mli:42-49), so None is unreachable by construction. The
   option is RETURNED here and consumed ONCE, at the head of verify,
   with the reason "signing key". *)
let address_of_key (k : Secpx.Pubkey.t) : Keccakx.Address.t option =
  Keccakx.Address.of_pubkey (Secpx.Pubkey.to_bytes k)

(* Step 1. The mask comes from the record field debug_mask and the
   comparand from Int64.zero, so neither 1L nor 0L sits in this helper.
   The expression is TRUE when the DEBUG bit is CLEAR, which is why
   0x02 at byte 168 passes and only bit 0 rejects. *)
let check_debug (b : Quotex.Body.t) : (unit, Errx.t) result =
  let r = rules () in
  if
    Int64.equal
      (Int64.logand (Quotex.Body.td_attributes b) r.debug_mask)
      Int64.zero
  then Ok ()
  else Error (Errx.Policy_rejected "debug td")

(* Steps 2 to 4, one Result.bind chain over the 64-byte report_data
   window at ABSOLUTE offset 568. Each Bytesx.take is consumed ONCE by
   an Option.to_result that carries the word of the window it reads.
   All three None arms are unreachable, because Quotex.Body.report_data
   answers 64 bytes by construction (quotex.mli:84-86), so each one
   fails closed on a value it can never see and the vocabulary stays
   CLOSED at ten words. The nonce compare is against the RAW bytes: a
   sha256 of the nonce is a "nonce mismatch" by design. *)
let check_binding ~(nonce : Nonce.t) ~(address : Keccakx.Address.t)
    (b : Quotex.Body.t) : (unit, Errx.t) result =
  let r = rules () in
  let rd = Quotex.Body.report_data b in
  let compared (want : string) (got : string) (reason : string) :
      (unit, Errx.t) result =
    if String.equal want got then Ok () else Error (Errx.Policy_rejected reason)
  in
  Result.bind
    (Option.to_result
       ~none:(Errx.Policy_rejected "address mismatch")
       (Bytesx.take rd r.addr_off r.addr_len))
  @@ fun (seen_address : string) ->
  Result.bind
    (compared (Keccakx.Address.to_bytes address) seen_address
       "address mismatch")
  @@ fun (() : unit) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Policy_rejected "pad not zero")
       (Bytesx.take rd r.pad_off r.pad_len))
  @@ fun (seen_pad : string) ->
  Result.bind (compared r.zero_pad seen_pad "pad not zero")
  @@ fun (() : unit) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Policy_rejected "nonce mismatch")
       (Bytesx.take rd r.nonce_off r.nonce_len))
  @@ fun (seen_nonce : string) ->
  compared (Nonce.to_bytes nonce) seen_nonce "nonce mismatch"

(* Step 5, the exhaustive TWO-ARM match on the expectation sum. It is a
   match on neither an option, a result nor a bool. The locally
   abstract type (type l) is load-bearing: without it the GADT match
   specialises this value to a full expectation and the signature
   inclusion fails. A structural expectation compares NOTHING and
   returns what the body carried, so a tofu witness records what it
   saw. *)
let check_measurements (type l) (e : l Expect.t) (b : Quotex.Body.t) :
    (Measurements.t, Errx.t) result =
  let observed = Measurements.of_body b in
  match e with
  | Expect.Full expected ->
    Option.fold
      ~none:(Ok observed)
      ~some:(fun (name : string) ->
        Error (Errx.Policy_rejected (name ^ " mismatch")))
      (Measurements.first_mismatch ~expected ~observed)
  | Expect.Tofu -> Ok observed

(* The whole order, on a PARSED quote. The signing address is minted
   first, because every window below binds to it, and its option is
   consumed here ONCE with the reason "signing key". Every later step
   is a Result.bind, so the first failure is the reason the caller
   reads and no later check runs. *)
let verify ~(expect : 'l Expect.t) ~(nonce : Nonce.t)
    ~(signing_key : Secpx.Pubkey.t) (q : Quotex.t) : ('l t, Errx.t) result =
  let b = Quotex.body q in
  Result.bind
    (Option.to_result
       ~none:(Errx.Policy_rejected "signing key")
       (address_of_key signing_key))
  @@ fun (address : Keccakx.Address.t) ->
  Result.bind (check_debug b) @@ fun (() : unit) ->
  Result.bind (check_binding ~nonce ~address b) @@ fun (() : unit) ->
  Result.bind (check_measurements expect b) @@ fun (observed : Measurements.t) ->
  Ok { measurements = observed; signing_address = address; nonce }
