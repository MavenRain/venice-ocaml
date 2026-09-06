(* policyx: the TDX attestation POLICY unit (M24, DESIGN.md:404). It is
   the SECOND module of the attestation tower: quotex DECODES the bytes
   and this unit DECIDES on them.

   verify takes a PARSED Quotex.t and never raw bytes, because M28 owns
   the base64 decode and the one Quotex.parse call. This unit verifies
   NO signature (M25), reads no certificate (M26) and no TCB value
   (M27), and it holds no state and no clock.

   THE BINDING on the ECDSA path (FACTS.md:242-249), which is
   report_data = address20 || 0x00 x 12 || nonce32. The 64-byte
   report_data window starts at ABSOLUTE quote offset 568 and ends at
   632. The columns are the report_data offset, the ABSOLUTE quote
   offset, the length and the name.

     0    568   20   address20, the 20 bytes of the signing address
     20   588   12   the zero pad, which no verifier reads and which
                     M24 requires to be zero
     32   600   32   nonce32, RAW: no hash of the nonce, no prefix and
                     no length byte

   The DEBUG bit is bit 0 of td_attributes, the u64 at ABSOLUTE offset
   168, and the test is a MASK and never a "non-zero byte" test.

   THE CHECK ORDER inside verify, where the reason names the FIRST
   failure:

     0  the signing address exists at all, which runs before step 1
        because the address is the identity every window binds to
     1  the DEBUG bit, td_attributes at 168
     2  the address window, report_data[0..20]
     3  the zero pad window, report_data[20..32]
     4  the nonce window, report_data[32..64]
     5  the measurements, in the order mr_td, rt_mr0, rt_mr1, rt_mr2
        and rt_mr3, and only for a full expectation; a structural
        expectation compares nothing and the witness records what it
        saw

   Every rejection is one Errx.Policy_rejected whose text comes from a
   CLOSED vocabulary of TEN words: "debug td", "signing key",
   "address mismatch", "pad not zero", "nonce mismatch",
   "mr_td mismatch", "rt_mr0 mismatch", "rt_mr1 mismatch",
   "rt_mr2 mismatch" and "rt_mr3 mismatch". Errx.to_string prints each
   one under the "policy: " prefix.

   Every value this unit compares is PUBLIC: the address, the nonce
   echo and the expected measurements. So String.equal is used
   throughout and NO constant-time compare is owed
   (keccakx.mli:33-36). The nonce is single-use by the M29 Fresh
   boundary and not by this unit. *)

module Nonce : sig
  (* Exactly 32 bytes. ABSTRACT, so a nonce is minted only by of_bytes
     and of_hex. M29 owns the mint from entropy and the single-use
     rule. *)
  type t

  (* Returns the nonce length, 32, which is the length of the
     report_data window at 600. *)
  val len : unit -> int

  (* Some on exactly 32 bytes, None on every other length. *)
  val of_bytes : string -> t option

  (* Some on exactly 64 hex characters, through Hexx.decode. A byte
     outside the hex alphabet, an odd length and any other length are
     None. *)
  val of_hex : string -> t option

  (* The raw 32 bytes, which are the bytes at report_data[32..64],
     quote 600 to 632. *)
  val to_bytes : t -> string

  (* The 64 lowercase hex characters of those bytes. *)
  val to_hex : t -> string

  (* Byte equality. A nonce echo is PUBLIC, so no constant-time
     compare is owed. *)
  val equal : t -> t -> bool
end

module Measurements : sig
  (* The five TD measurements the policy decides on: MRTD and RTMR0 to
     RTMR3, 48 bytes each. ABSTRACT, so the five lengths hold by
     construction. *)
  type t

  (* Some only when all five fields are exactly 48 bytes, None
     otherwise. *)
  val make :
    mr_td:string ->
    rt_mr0:string ->
    rt_mr1:string ->
    rt_mr2:string ->
    rt_mr3:string ->
    t option

  (* 48 bytes at ABSOLUTE quote offset 184. *)
  val mr_td : t -> string

  (* 48 bytes at ABSOLUTE quote offset 376. *)
  val rt_mr0 : t -> string

  (* 48 bytes at ABSOLUTE quote offset 424. *)
  val rt_mr1 : t -> string

  (* 48 bytes at ABSOLUTE quote offset 472. *)
  val rt_mr2 : t -> string

  (* 48 bytes at ABSOLUTE quote offset 520. *)
  val rt_mr3 : t -> string

  (* Returns the five measurements a parsed body carries. TOTAL,
     because every quotex accessor is total on a parsed value
     (quotex.mli:8-10). *)
  val of_body : Quotex.Body.t -> t

  (* Field equality over the five. Every measurement is PUBLIC, so no
     constant-time compare is owed. *)
  val equal : t -> t -> bool

  (* Returns the name of the FIRST field that differs, in the order
     mr_td, rt_mr0, rt_mr1, rt_mr2, rt_mr3, and None when all five
     agree. *)
  val first_mismatch : expected:t -> observed:t -> string option
end

module Expect : sig
  (* Phantom expectation markers, uninhabited (venice.mli:252-258).
     They cost nothing at run time. *)
  type full
  type structural

  (* The expectation a verify runs against. The level rides the type
     unchanged from here to the witness, so M29 can demand a full
     one. *)
  type 'level t

  (* Returns the FULL expectation over the five measurements, which is
     the only expectation that compares them. *)
  val make : measurements:Measurements.t -> full t

  (* Returns the STRUCTURAL expectation, which compares no
     measurement. It can never mint a full t, so a session that
     demands full refuses a tofu witness. *)
  val tofu : unit -> structural t

  (* Returns the five measurements of a full expectation. A structural
     expectation carries none and cannot be passed here. *)
  val measurements : full t -> Measurements.t
end

(* The WITNESS a successful verify mints. ABSTRACT, so it exists only
   after every check of the order above passed. M28 lifts it into
   Attested.t. It carries no signature fact, because M25 owns the
   signature and the QE binding. *)
type 'level t

(* Returns the measurements as OBSERVED on the body, which are the
   expected ones on a full witness and whatever the body carried on a
   structural one. *)
val measurements : 'l t -> Measurements.t

(* Returns the signing address the binding proved, the 20 bytes at
   report_data[0..20], quote 568 to 588. *)
val signing_address : 'l t -> Keccakx.Address.t

(* Returns the nonce the binding echoed back, the 32 raw bytes at
   report_data[32..64], quote 600 to 632. *)
val nonce : 'l t -> Nonce.t

(* Returns the Ethereum address of a signing key, the last 20 bytes of
   keccak-256 over the 64 bytes X || Y with NO 0x04 prefix. None is
   unreachable by construction, because Secpx.Pubkey.to_bytes is 64
   bytes and Keccakx.Address.of_pubkey accepts 64 bytes, so the caller
   fails closed on a value it can never see (secpx.mli:73-77): verify
   consumes this option ONCE with the reason "signing key". *)
val address_of_key : Secpx.Pubkey.t -> Keccakx.Address.t option

(* Step 1 of the order. Ok when bit 0 of td_attributes, the u64 at
   ABSOLUTE offset 168, is CLEAR. A set bit is "debug td". The test is
   a mask, so 0x02 at byte 168 passes and 0x01 at byte 160, which is
   seam_attributes, passes too. *)
val check_debug : Quotex.Body.t -> (unit, Errx.t) result

(* Steps 2 to 4 of the order over the 64-byte report_data window at
   ABSOLUTE offset 568: the address at [0..20], quote 568 to 588, then
   the zero pad at [20..32], quote 588 to 600, then the RAW nonce at
   [32..64], quote 600 to 632. The reasons are "address mismatch",
   "pad not zero" and "nonce mismatch", in that order. A sha256 of the
   nonce is REJECTED by design: the producer writes the raw bytes. *)
val check_binding :
  nonce:Nonce.t ->
  address:Keccakx.Address.t ->
  Quotex.Body.t ->
  (unit, Errx.t) result

(* Step 5 of the order. Returns the measurements OBSERVED on the body.
   A full expectation compares the five in order and rejects with
   "mr_td mismatch", "rt_mr0 mismatch", "rt_mr1 mismatch",
   "rt_mr2 mismatch" or "rt_mr3 mismatch". A structural expectation
   compares nothing and returns what it saw. *)
val check_measurements :
  'l Expect.t -> Quotex.Body.t -> (Measurements.t, Errx.t) result

(* Runs the whole order on a parsed quote and returns the witness at
   the level of the expectation. The reason names the FIRST failure:
   "signing key", then "debug td", then "address mismatch", then
   "pad not zero", then "nonce mismatch", then the measurement word. *)
val verify :
  expect:'l Expect.t ->
  nonce:Nonce.t ->
  signing_key:Secpx.Pubkey.t ->
  Quotex.t ->
  ('l t, Errx.t) result
