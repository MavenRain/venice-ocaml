(* sigx: the TDX attestation SIGNATURE unit (M25, DESIGN.md:405). It is
   the THIRD module of the attestation tower: quotex DECODES the bytes,
   policyx DECIDES on the body and this unit PROVES the signature
   section. It is pure and sans-io: no mutable byte store, no vector,
   no reference cell, no exception path, no division and no remainder.
   Every window comes from a total quotex accessor or from a total
   bytesx cursor, so a short window answers None and nothing escapes.

   THE RULES TABLE, the ONE record below. Its two fields are the ONLY
   numbers a helper reads, because Quotex.Signature_section hands back
   every other window at its exact length. The offsets are RELATIVE to
   the 64-byte qe_report_data window at ABSOLUTE quote offset 1090.

     0    1090   32   binding_off and binding_len, the QE binding
                      value, which is the first half of qe_report_data

   A key_len, a sig_len or a report_len field would be written and
   never read, which Warning 69 reports under -w +a, so the lengths 64,
   64 and 384 live in the sigx.mli doc comments and in the suite rows
   and never in this record.

   THE CHECK ORDER inside verify, where the reason names the FIRST
   failure and the order follows the TRUST FLOW:

     1  the QE signature PARSE, the 64 bytes at 1154, "qe signature"
     2  the QE signature VERIFY under pck_key over the 384 bytes at
        770, "qe signature mismatch"
     3  the QE BINDING, a raw compare of two public 32-byte strings,
        "qe binding mismatch"
     4  the attestation key POINT parse, the 64 bytes at 700,
        "attestation key"
     5  the ISV signature PARSE, the 64 bytes at 636, "isv signature"
     6  the ISV VERIFY over the signed region, "isv signature mismatch"

   Step 4 is UNREACHABLE through verify on a QE-signed quote: the key
   bytes at 700 sit under the binding hash of step 3, so a paint of the
   key stops at step 3. The arm fails closed and the suite reaches it
   through attestation_key_of_section directly.

   THE ZXLINT RULE (trap 2, ZXCAML.md:18-20). rules () builds the
   record ONCE and every helper that needs a constant binds it first,
   so no numeric literal and no string constant sits outside the body
   of rules () and the comments, and no top-level alias of a Bytesx, a
   Quotex, a P256x or a Sha2 binding exists. This unit applies no
   functor and holds no Map, so it stays eligible as an M38 omlz
   artifact.

   Both ECDSA legs call the p256x message verify, which hashes the
   message itself (p256x.mli:73-74), so this unit hashes exactly ONCE,
   inside binding_digest. Every compare is String.equal on PUBLIC bytes
   and no constant-time compare is owed.

   The reason vocabulary is CLOSED at SIX words and every rejection is
   one Errx.Sig_invalid, which Errx.to_string prints under "sig: ". *)

type rules = { binding_off : int; binding_len : int }

(* The ONE record, built once. binding_off is the start of the QE
   binding value inside qe_report_data and binding_len is its length,
   which is the digest length the compare of step 3 reads. *)
let rules (() : unit) : rules =
  let binding_off = 0 in
  let binding_len = 32 in
  { binding_off; binding_len }

(* The witness a successful verify mints. The record holds what the
   quote PROVED: the two keys the two legs verified under and the QE
   report bytes the QE leg covered. It holds no policy fact, because
   M24 owns those, and no TCB decision, because M27 owns those. *)
type witness = {
  attestation_key : P256x.Pubkey.t;
  pck_key : P256x.Pubkey.t;
  qe_report : string;
}

(* sigx.mli re-abstracts the type, which is where the guarantee lives:
   a caller can neither forge a witness nor read a field this unit did
   not prove (modelx.ml:131-134 shape). *)
type t = witness

let attestation_key (w : t) : P256x.Pubkey.t = w.attestation_key
let pck_key (w : t) : P256x.Pubkey.t = w.pck_key
let qe_report (w : t) : string = w.qe_report

(* The ONE hash call of the unit. Both windows come back from a parsed
   section at their exact length, so the concatenation needs no length
   test and the result is 32 bytes. *)
let binding_digest (s : Quotex.Signature_section.t) : string =
  Sha2.Sha256.digest
    (Quotex.Signature_section.attestation_key s
    ^ Quotex.Signature_section.qe_auth_data s)

(* Steps 1 and 2, one Result.bind chain. The 64 bytes at 1154 are
   parsed FIRST, so a psychic r or s answers "qe signature" before any
   point arithmetic runs, and the verify then reads the 384 QE report
   bytes at 770 under the PCK leaf key the caller hands in. The label
   NAMES the key, because a positional swap with the attestation key
   type-checks in silence. *)
let check_qe_signature ~(pck_key : P256x.Pubkey.t)
    (s : Quotex.Signature_section.t) : (unit, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Sig_invalid "qe signature")
       (P256x.Signature.of_raw
          (Quotex.Signature_section.qe_report_signature s)))
  @@ fun (qe_sig : P256x.Signature.t) ->
  if
    P256x.verify_message pck_key qe_sig (Quotex.Signature_section.qe_report s)
  then Ok ()
  else Error (Errx.Sig_invalid "qe signature mismatch")

(* Step 3, one Result.bind chain over the 64-byte qe_report_data window
   at ABSOLUTE offset 1090. The 32-byte cut is consumed ONCE and its
   None arm is unreachable, because qe_report_data answers 64 bytes by
   construction (quotex.mli:112-116), so the arm fails closed on a
   value it can never see and the vocabulary stays CLOSED at six words.
   The compare is RAW: both sides are public, so String.equal is the
   whole test and no constant-time compare is owed. Intel QVE and
   dcap-qvl compare the first 32 bytes only, and so does this unit; the
   zero tail is under the QE signature anyway. *)
let check_qe_binding (s : Quotex.Signature_section.t) : (unit, Errx.t) result =
  let r = rules () in
  Result.bind
    (Option.to_result
       ~none:(Errx.Sig_invalid "qe binding mismatch")
       (Bytesx.take
          (Quotex.Signature_section.qe_report_data s)
          r.binding_off r.binding_len))
  @@ fun (seen_binding : string) ->
  if String.equal (binding_digest s) seen_binding then Ok ()
  else Error (Errx.Sig_invalid "qe binding mismatch")

(* Step 4, the FAIL-CLOSED arm. P256x.Pubkey.of_bytes reads the 64
   bytes at 700 as X || Y and answers None when a coordinate sits at or
   above the field prime and when the pair is off the curve. On a
   QE-signed quote verify never reaches this arm, because step 3 stops
   every paint of those bytes first; the suite calls this function
   DIRECTLY to prove the arm still rejects. *)
let attestation_key_of_section (s : Quotex.Signature_section.t) :
    (P256x.Pubkey.t, Errx.t) result =
  Option.to_result
    ~none:(Errx.Sig_invalid "attestation key")
    (P256x.Pubkey.of_bytes (Quotex.Signature_section.attestation_key s))

(* Steps 5 and 6, one Result.bind chain. The 64 bytes at 636 are parsed
   FIRST, so a psychic r or s answers "isv signature", and the verify
   then reads Quotex.signed_region, the 632 bytes at 0, which is the
   header followed by the body. The label NAMES the key: att_key is the
   point attestation_key_of_section mints from the 64 bytes at 700. *)
let check_isv_signature ~(att_key : P256x.Pubkey.t) (q : Quotex.t) :
    (unit, Errx.t) result =
  let s = Quotex.signature_section q in
  Result.bind
    (Option.to_result
       ~none:(Errx.Sig_invalid "isv signature")
       (P256x.Signature.of_raw (Quotex.Signature_section.signature s)))
  @@ fun (isv_sig : P256x.Signature.t) ->
  if P256x.verify_message att_key isv_sig (Quotex.signed_region q) then Ok ()
  else Error (Errx.Sig_invalid "isv signature mismatch")

(* The whole order, on a PARSED quote. The Intel leg runs first, so no
   unproven byte of the quote is trusted before the QE signature covers
   it, and the binding compare of step 3 then runs on bytes a signature
   already proved. Every step is a Result.bind, so the first failure is
   the reason the caller reads and no later check runs. *)
let verify ~(pck_key : P256x.Pubkey.t) (q : Quotex.t) : (t, Errx.t) result =
  let s = Quotex.signature_section q in
  Result.bind (check_qe_signature ~pck_key s) @@ fun (() : unit) ->
  Result.bind (check_qe_binding s) @@ fun (() : unit) ->
  Result.bind (attestation_key_of_section s)
  @@ fun (att_key : P256x.Pubkey.t) ->
  Result.bind (check_isv_signature ~att_key q) @@ fun (() : unit) ->
  Ok
    {
      attestation_key = att_key;
      pck_key;
      qe_report = Quotex.Signature_section.qe_report s;
    }
