(* sigx: the TDX attestation SIGNATURE unit (M25, DESIGN.md:405). It is
   the THIRD module of the attestation tower: quotex DECODES the bytes,
   policyx DECIDES on the body and this unit PROVES the signature
   section.

   verify takes a PARSED Quotex.t and never raw bytes, because M28 owns
   the base64 decode and the one Quotex.parse call. This unit parses no
   certificate and no DER (M26), reads no TCB value (M27), holds no
   state and no clock, and it takes the PCK leaf key as a PARAMETER
   that M26 hands in already validated.

   THE WINDOWS this unit reads. Every offset is ABSOLUTE and counts
   from byte zero of the quote. The columns are the offset, the length
   and the name.

     636   64   the ISV signature, r then s, over the signed region
     700   64   the attestation key, X then Y
     770   384  the QE report, which the QE leg covers
     1090  64   qe_report_data, the last 64 bytes of the QE report,
                whose first 32 bytes are the QE binding value
     1154  64   the QE report signature, r then s
     1220  qe_auth_size  the QE auth data, 32 bytes on the fixture

   THE CHECK ORDER inside verify, where the reason names the FIRST
   failure. The order follows the TRUST FLOW, which is the order Intel
   QVE and dcap-qvl run, so no unproven byte of the quote is trusted
   before the Intel leg is proved:

     1  the QE signature PARSE, the 64 bytes at 1154, "qe signature"
     2  the QE signature VERIFY under pck_key over the 384 bytes at
        770, "qe signature mismatch"
     3  the QE BINDING, a raw compare that needs no point,
        "qe binding mismatch"
     4  the attestation key POINT parse, the 64 bytes at 700,
        "attestation key"
     5  the ISV signature PARSE, the 64 bytes at 636, "isv signature"
     6  the ISV VERIFY over the signed region, the 632 bytes at 0,
        "isv signature mismatch"

   Step 4 is UNREACHABLE through verify on a QE-signed quote: the key
   bytes at 700 sit under the binding hash of step 3 and the binding
   value sits inside the QE report of step 2, so any paint of the key
   stops at step 3 with "qe binding mismatch". The arm stays as a
   FAIL-CLOSED arm and the suite reaches it through
   attestation_key_of_section directly.

   Every rejection is one Errx.Sig_invalid whose text comes from a
   CLOSED vocabulary of SIX words: "qe signature", "qe signature
   mismatch", "qe binding mismatch", "attestation key", "isv signature"
   and "isv signature mismatch". Errx.to_string prints each one under
   the "sig: " prefix.

   Every value this unit compares is PUBLIC: the QE report is signed
   and travels in the clear and the attestation key sits in the quote
   at 700. So String.equal is used and NO constant-time compare is owed
   (keccakx.mli:33-36). Both ECDSA legs call P256x.verify_message,
   which hashes the message itself, so this unit calls Sha2.Sha256
   exactly once, inside binding_digest. *)

type t

(* Returns the attestation key the ISV leg verified under, which is the
   validated point of the 64 bytes at 700, X then Y. TOTAL: a witness
   exists only when verify succeeded, which is the quotex.mli:8-10
   invariant-by-construction rule. *)
val attestation_key : t -> P256x.Pubkey.t

(* Returns the PCK leaf key the QE leg verified under, the key M26
   hands in, so M28 records WHICH key proved the quote. TOTAL. *)
val pck_key : t -> P256x.Pubkey.t

(* Returns the QE report the QE leg covered, the 384 bytes at 770. M27
   reads the TCB fields off these bytes and this unit decides nothing
   on them. TOTAL. *)
val qe_report : t -> string

(* Returns the QE binding digest, the sha256 of the attestation key at
   700 followed by the auth data at 1220, always 32 bytes. TOTAL: both
   windows come back from a parsed section at their exact length. *)
val binding_digest : Quotex.Signature_section.t -> string

(* Steps 1 and 2 of the order. It parses the 64 bytes at 1154 as r || s
   and answers "qe signature" when a half falls outside 1 .. n-1, which
   is the CVE-2022-21449 gate of p256x.mli:39-49, then verifies the
   signature under pck_key over the 384 QE report bytes at 770 and
   answers "qe signature mismatch" when the verify is false. *)
val check_qe_signature :
  pck_key:P256x.Pubkey.t -> Quotex.Signature_section.t -> (unit, Errx.t) result

(* Step 3 of the order. It compares binding_digest against the first 32
   bytes of qe_report_data, the window at 1090, and answers "qe binding
   mismatch" on a difference. The compare is RAW and needs no point,
   and both sides are PUBLIC. The 32-byte cut cannot fail on a parsed
   quote, because qe_report_data is 64 bytes by construction
   (quotex.mli:112-116), so its None arm carries the SAME word and
   mints no seventh one. *)
val check_qe_binding : Quotex.Signature_section.t -> (unit, Errx.t) result

(* Step 4 of the order. It parses the 64 bytes at 700 as the affine
   point X || Y and answers "attestation key" when the pair is off the
   curve or a coordinate is at or above the field prime. On a QE-signed
   quote verify never reaches this arm, so the suite calls it here
   DIRECTLY and the arm stays fail-closed. *)
val attestation_key_of_section :
  Quotex.Signature_section.t -> (P256x.Pubkey.t, Errx.t) result

(* Steps 5 and 6 of the order. It parses the 64 bytes at 636 as r || s
   and answers "isv signature" on a psychic half, then verifies under
   att_key over Quotex.signed_region, the 632 bytes at 0, and answers
   "isv signature mismatch" when the verify is false. It takes a
   Quotex.t and not a Signature_section.t, because signed_region lives
   on the outer type (quotex.mli:173). Every leg NAMES its key in the
   label, because attestation_key and pck_key return the SAME type and
   a positional swap type-checks in silence. *)
val check_isv_signature :
  att_key:P256x.Pubkey.t -> Quotex.t -> (unit, Errx.t) result

(* Runs the whole order on a parsed quote and mints the witness. The
   reason names the FIRST failure: "qe signature", then "qe signature
   mismatch", then "qe binding mismatch", then "attestation key", then
   "isv signature", then "isv signature mismatch". This is the ONLY
   minting path of t. *)
val verify : pck_key:P256x.Pubkey.t -> Quotex.t -> (t, Errx.t) result
