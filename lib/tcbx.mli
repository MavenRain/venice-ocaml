(* tcbx: the TDX TCB GRADING unit (M27, DESIGN.md:412). It is the
   FIFTH module of the attestation tower: quotex DECODES the bytes,
   policyx DECIDES on the body, sigx PROVES the signature section,
   derx CHAINS the certification data to Intel and this unit GRADES
   the platform TCB and the QE against Intel's signed collateral.

   It reads NO clock: the caller hands in a Derx.Now.t witness, which
   M28 mints from the host clock. It takes the EARLIER witnesses and
   never raw quote bytes: the four platform values come from the TOTAL
   accessors Derx.cpusvn, Derx.pcesvn, Derx.fmspc and Derx.pce_id, the
   384 QE report bytes come from Sigx.qe_report, and tee_tcb_svn,
   mrsigner_seam and seam_attributes come from Quotex. The two header
   u16 words at quote offsets 8 and 10 are NEVER read (D16 item 7).

   THE CHECK ORDER inside verify, where the reason names the FIRST
   failure:

     0   the witness binding, one P256x.Pubkey.equal over the PCK key
         of the chain and of the signature witness and one String.equal
         over the QE report of the signature witness and of the quote,
         "witness mismatch"
     1   the TCB Info issuer chain: "chain length", the Derx words of
         the block 1 parse and of the pinned root parse, "root pin",
         "signing cert", "signing cert signature", "signing cert not
         yet valid" and "signing cert expired"
     2   "tcb info signature", then "tcb info"
     3   "tcb info id", "tcb info version", "tcb type", "tcb info not
         yet valid", "tcb info expired", "fmspc mismatch" and "pce id
         mismatch"
     4   "tdx module" when tee_tcb_svn byte 1 is 0, else "tdx module
         identity" and "revoked" on the identity that byte selects
     5   "tcb level" and "revoked"
     6   the QE issuer chain and document, as steps 1 and 2, with
         "qe identity signature" and "qe identity"
     7   "qe identity id", "qe identity version", "qe identity not yet
         valid" and "qe identity expired"
     8   the QE report against the identity: "qe miscselect",
         "qe attributes", "qe mrsigner", "qe isvprodid", "qe isvsvn"
         and "revoked"
     9   the witness is minted

   The root's OWN signature is NEVER verified, because Derx.root_pin ()
   is the anchor. Chain block 2 is checked for PRESENCE only, under
   "chain length": trust flows from the pinned root and never from the
   collateral copy of the root (RUL-M27-2).

   Every rejection is one Errx.Tcb_invalid whose text comes from a
   CLOSED vocabulary of THIRTY-ONE words reachable from verify:
   "witness mismatch", "chain length", "root pin", "signing cert",
   "signing cert signature", "signing cert not yet valid", "signing
   cert expired", "tcb info signature", "tcb info", "tcb info id",
   "tcb info version", "tcb type", "tcb info not yet valid", "tcb info
   expired", "fmspc mismatch", "pce id mismatch", "tdx module", "tdx
   module identity", "tcb level", "revoked", "qe identity signature",
   "qe identity", "qe identity id", "qe identity version", "qe identity
   not yet valid", "qe identity expired", "qe miscselect", "qe
   attributes", "qe mrsigner", "qe isvprodid" and "qe isvsvn". The word
   "envelope" is the THIRTY-SECOND word and only Collateral.of_envelope
   says it. Errx.to_string prints each one under the "tcb: " prefix. A
   Derx rejection PASSES THROUGH as its own Errx.Cert_invalid word, so
   this unit mints no synonym for a word derx already owns.

   P256x.verify_message RUNS exactly FOUR times per verify from TWO
   call sites, check_signing_chain and check_document: the signing
   certificate tbsCertificate under the pinned root key once per issuer
   chain, plus the two detached document signatures. It hashes the
   message itself, so this unit names Sha2 never and B64x never.
   Derx.Cert.of_pem sits at ONE call site and runs once per issuer
   chain, Derx.Cert.of_der parses the pinned root, and Derx.verify_chain
   is never called, because the chain witness arrives as a parameter.

   This unit rejects only structure, identity, signature, freshness and
   Revoked. WHICH non-Revoked grade makes a full attestation is M28 and
   M29 policy (D16 item 6), so a grade below UpToDate is a witness
   value here and never a rejection. Every compared value is PUBLIC, so
   String.equal is the whole test and no constant-time compare is
   owed. *)

(* Cuts an issuer chain string into its PEM blocks, one block per
   BEGIN CERTIFICATE marker, through String.split_on_char and
   String.concat, both TOTAL. No unit exports a splitter for a
   collateral chain: Quotex.Signature_section.pem_chain cuts the QUOTE
   window only and Derx.verify_chain takes a list its caller already
   cut. A chain that does not cut to exactly two blocks says "chain
   length" inside check_signing_chain. *)
val blocks_of_chain : string -> string list

(* wire: an Intel instant, the twenty characters YYYY-MM-DDTHH:MM:SSZ
   of issueDate, nextUpdate and tcbDate. It cuts the six digit windows
   at 0, 5, 8, 11, 14 and 17, checks the six fixed non-digit positions
   byte for byte, "-" at 4, "-" at 7, "T" at 10, ":" at 13, ":" at 16
   and "Z" at 19, and hands the fourteen digits to Derx.Now.of_digits.
   Any other length, any other separator and any non-digit is None. *)
val now_of_iso : string -> Derx.Now.t option

module Status : sig
  (* wire: the tcbStatus member of a TCB level and of a QE identity
     level. The seven constructors are the whole Intel status set the
     two documents can carry. *)
  type t =
    | Up_to_date
    | Sw_hardening_needed
    | Configuration_needed
    | Configuration_and_sw_hardening_needed
    | Out_of_date
    | Out_of_date_configuration_needed
    | Revoked

  (* The CLOSED map from the Intel spellings "UpToDate",
     "SWHardeningNeeded", "ConfigurationNeeded",
     "ConfigurationAndSWHardeningNeeded", "OutOfDate",
     "OutOfDateConfigurationNeeded" and "Revoked". Anything else is
     None, which a document parse reports as "tcb info" or as "qe
     identity". *)
  val of_string : string -> t option

  (* The inverse of of_string. TOTAL. *)
  val to_string : t -> string

  (* Constructor equality. *)
  val equal : t -> t -> bool
end

module Level : sig
  (* ONE graded level, the answer of a grade leg. ABSTRACT, so a level
     exists only when a grade leg matched it. *)
  type t

  (* wire: the tcbStatus of the matched level. TOTAL. *)
  val status : t -> Status.t

  (* wire: the tcbDate of the matched level. TOTAL. *)
  val tcb_date : t -> Derx.Now.t

  (* wire: the advisoryIDs of the matched level, the EMPTY list when
     the member is absent (D16 item 5). TOTAL. *)
  val advisories : t -> string list
end

module Collateral : sig
  (* The SIX collateral strings this unit reads. ABSTRACT, so the six
     members travel together and no caller pairs a document with the
     signature of another document. *)
  type t

  (* The TOTAL constructor. The suite paints a collateral string and
     mints a painted value here, because a byte inside a document flips
     its signature and a signature hex digit flips it too. *)
  val make :
    tcb_info:string ->
    tcb_info_signature:string ->
    tcb_info_chain:string ->
    qe_identity:string ->
    qe_identity_signature:string ->
    qe_identity_chain:string ->
    t

  (* Parses the PCS collateral envelope and reads SIX of its nine
     string members: tcb_info_issuer_chain, tcb_info,
     tcb_info_signature, qe_identity_issuer_chain, qe_identity and
     qe_identity_signature. The three CRL members
     pck_crl_issuer_chain, root_ca_crl and pck_crl are IGNORED (D16
     item 1). A non-object, a missing member and a non-string member
     all say "envelope", the ONE word verify never says. *)
  val of_envelope : string -> (t, Errx.t) result

  (* wire: the tcb_info member, the bytes the tcb_info_signature
     covers. TOTAL. *)
  val tcb_info : t -> string

  (* wire: the tcb_info_signature member, 128 hex characters. TOTAL. *)
  val tcb_info_signature : t -> string

  (* wire: the tcb_info_issuer_chain member, two PEM blocks. TOTAL. *)
  val tcb_info_chain : t -> string

  (* wire: the qe_identity member, the bytes the qe_identity_signature
     covers. TOTAL. *)
  val qe_identity : t -> string

  (* wire: the qe_identity_signature member, 128 hex characters.
     TOTAL. *)
  val qe_identity_signature : t -> string

  (* wire: the qe_identity_issuer_chain member, two PEM blocks.
     TOTAL. *)
  val qe_identity_chain : t -> string
end

module Tcb_info : sig
  (* The parsed TCB Info document. ABSTRACT, so a value exists only
     when every member of the D2 shape parsed. *)
  type t

  (* Parses the WHOLE tcb_info document text through Jsonx. It checks
     STRUCTURE only, so every shape failure says "tcb info": a
     non-object, a missing member, a member of the wrong JSON type, an
     instant that is not twenty characters, a status string outside the
     Status set, a hex member that does not decode, and a level whose
     sgxtcbcomponents or tdxtcbcomponents count is not sixteen. The
     tdxModuleIdentities member is OPTIONAL, as Intel marks it: a
     document without it carries no identity. The suite hands
     SYNTHETIC JSON here, because the field checks sit past a
     signature it cannot forge. *)
  val of_json : string -> (t, Errx.t) result

  (* D4 step (3) on the parsed document, against the four TOTAL Derx
     accessors the caller reads off the M26 witness. It says "tcb info
     id" for an id other than "TDX", "tcb info version" for a version
     other than 3, "tcb type" for a tcbType other than 0, "tcb info not
     yet valid" and "tcb info expired" for now outside issueDate <= now
     < nextUpdate, "fmspc mismatch" for a fmspc that is not the six PCK
     bytes and "pce id mismatch" for a pceId that is not the two PCK
     bytes. The two compares are RAW bytes, so the hex case of the
     document does not matter. *)
  val check_platform :
    t -> now:Derx.Now.t -> fmspc:string -> pce_id:string ->
    (unit, Errx.t) result

  (* D4 step (4) on the parsed document, against the three Quotex
     values, in the shape of Intel's QuoteVerifier. When tee_tcb_svn
     byte 1 is 0 it compares the top-level tdxModule and returns None:
     "tdx module" when the tdxModule mrsigner is not mrsigner_seam or
     the masked seam_attributes are not the tdxModule attributes. When
     that byte is not 0 it never reads the top-level tdxModule: it says
     "tdx module identity" when no tdxModuleIdentity carries the id
     "TDX_" plus the two digits of that byte, or the identity fails the
     same two compares under ITS mrsigner, attributes and mask, or no
     identity level is at or below tee_tcb_svn byte 0; it says
     "revoked" when the matched identity level is Revoked; else it
     returns Some status of that level, the input of converge. The
     attributes compare is a NUMBER compare through Bytesx.u64le,
     because Quotex.Body.seam_attributes returns an int64. *)
  val check_tdx_module :
    t -> mrsigner_seam:string -> seam_attributes:int64 ->
    tee_tcb_svn:string -> (Status.t option, Errx.t) result

  (* D4 step (5). In DOCUMENT order it takes the FIRST tcbLevel whose
     sixteen sgxtcbcomponents svn are each at or below cpusvn byte i,
     whose pcesvn is at or below the PCK pcesvn and whose
     tdxtcbcomponents svn are each at or below tee_tcb_svn byte i,
     over all sixteen when tee_tcb_svn byte 1 is 0 and from index 2
     when it is not, because Intel's isTdxTcbHigherOrEqual leaves
     components 0 and 1 to the tdxModuleIdentity. It says "tcb level"
     when no level matches and "revoked" when the matched level carries
     the Revoked status. The raw inputs let the suite lower a CPUSVN
     byte, which it cannot do inside a SIGNED PCK certificate. *)
  val grade :
    t -> cpusvn:string -> pcesvn:int -> tee_tcb_svn:string ->
    (Level.t, Errx.t) result

  (* Intel's convergeTcbStatus over the platform level and the module
     status check_tdx_module returned. A module Out_of_date lowers a
     platform Up_to_date or Sw_hardening_needed to Out_of_date and a
     platform Configuration_needed or
     Configuration_and_sw_hardening_needed to
     Out_of_date_configuration_needed. Every other pair, and None,
     keeps the platform level. TOTAL. *)
  val converge : Level.t -> Status.t option -> Level.t

  (* wire: the id member, "TDX" on the pin. TOTAL. *)
  val id : t -> string

  (* wire: the version member, 3 on the pin. TOTAL. *)
  val version : t -> int

  (* wire: the issueDate member. TOTAL. *)
  val issue_date : t -> Derx.Now.t

  (* wire: the nextUpdate member. TOTAL. *)
  val next_update : t -> Derx.Now.t

  (* wire: the fmspc member as its six RAW bytes. TOTAL. *)
  val fmspc : t -> string

  (* wire: the pceId member as its two RAW bytes. TOTAL. *)
  val pce_id : t -> string

  (* wire: the tcbType member, 0 on the pin. TOTAL. *)
  val tcb_type : t -> int

  (* wire: the tcbEvaluationDataNumber member, 17 on the pin. TOTAL. *)
  val tcb_evaluation_data_number : t -> int

  (* wire: the tdxModule mrsigner member as its 48 RAW bytes. TOTAL. *)
  val tdx_module_mrsigner : t -> string

  (* wire: the tdxModule attributes member as one number. TOTAL. *)
  val tdx_module_attributes : t -> int64

  (* wire: the tdxModule attributesMask member as one number. TOTAL. *)
  val tdx_module_attributes_mask : t -> int64

  (* wire: the id member of each tdxModuleIdentities entry, in document
     order, "TDX_03" then "TDX_01" on the pin. TOTAL. *)
  val identity_ids : t -> string list
end

module Qe_identity : sig
  (* The parsed QE Identity document. ABSTRACT, so a value exists only
     when every member of the D2 shape parsed. *)
  type t

  (* Parses the WHOLE qe_identity document text through Jsonx. It
     checks STRUCTURE only, so every shape failure says "qe identity":
     a non-object, a missing member, a member of the wrong JSON type,
     an instant that is not twenty characters, a status string outside
     the Status set and a hex member that does not decode. The suite
     hands SYNTHETIC JSON here, because the field checks sit past a
     signature it cannot forge. *)
  val of_json : string -> (t, Errx.t) result

  (* D4 step (7) on the parsed document. It says "qe identity id" for
     an id other than "TD_QE", "qe identity version" for a version
     other than 2, and "qe identity not yet valid" and "qe identity
     expired" for now outside issueDate <= now < nextUpdate. *)
  val check_identity : t -> now:Derx.Now.t -> (unit, Errx.t) result

  (* D4 step (8) against the RAW 384 QE report bytes, which the suite
     paints and which a Sigx.t cannot carry in painted form. It says
     "qe miscselect" for the u32le at 16 under miscselectMask, "qe
     attributes" for the 16 bytes at 48 under attributesMask, "qe
     mrsigner" for the 32 bytes at 128, "qe isvprodid" for the u16le at
     256, "qe isvsvn" when no level carries an isvsvn at or below the
     u16le at 258, and "revoked" when the matched level carries the
     Revoked status. The ISVSVN is read from the REPORT BODY and never
     from the quote header (D16 item 7). *)
  val grade : t -> qe_report:string -> (Level.t, Errx.t) result

  (* wire: the id member, "TD_QE" on the pin. TOTAL. *)
  val id : t -> string

  (* wire: the version member, 2 on the pin. TOTAL. *)
  val version : t -> int

  (* wire: the issueDate member. TOTAL. *)
  val issue_date : t -> Derx.Now.t

  (* wire: the nextUpdate member. TOTAL. *)
  val next_update : t -> Derx.Now.t

  (* wire: the tcbEvaluationDataNumber member, 17 on the pin. TOTAL. *)
  val tcb_evaluation_data_number : t -> int

  (* wire: the miscselect member as one number, 0 on the pin. TOTAL. *)
  val miscselect : t -> int

  (* wire: the miscselectMask member as one number. TOTAL. *)
  val miscselect_mask : t -> int

  (* wire: the attributes member as its 16 RAW bytes. TOTAL. *)
  val attributes : t -> string

  (* wire: the attributesMask member as its 16 RAW bytes. TOTAL. *)
  val attributes_mask : t -> string

  (* wire: the mrsigner member as its 32 RAW bytes. TOTAL. *)
  val mrsigner : t -> string

  (* wire: the isvprodid member, 2 on the pin. TOTAL. *)
  val isvprodid : t -> int
end

(* D4 step (1) on the blocks blocks_of_chain cut, and the FIRST of the
   two P256x.verify_message call sites. It says "chain length" unless
   the list holds exactly two blocks, passes a Derx rejection of the
   block 1 parse and of the pinned root parse through as its own
   Errx.Cert_invalid word, says "root pin" when the block 1 issuer TLV
   is not the subject TLV of the pinned root, "signing cert" when the
   block 1 keyUsage carries no digitalSignature bit or its
   basicConstraints carries cA TRUE, "signing cert
   signature" when the block 1 tbsCertificate does not verify under the
   pinned root key, and "signing cert not yet valid" and "signing cert
   expired" when now sits outside notBefore .. notAfter. Block 2 is
   checked for PRESENCE only. It returns the TCB Signing public key,
   the key the two detached document signatures verify under. The
   root_pin label takes the 659 pinned bytes Derx.root_pin () returns,
   so the suite can hand a different anchor. *)
val check_signing_chain :
  now:Derx.Now.t -> root_pin:string -> string list ->
  (P256x.Pubkey.t, Errx.t) result

(* D4 steps (2) and (6), and the SECOND of the two
   P256x.verify_message call sites, which verify RUNS twice. The
   signature is 128 hex characters of 64 raw bytes, r || s, and the
   signed bytes are the WHOLE document member. The word label carries
   the reason, "tcb info signature" for the TCB Info document and "qe
   identity signature" for the QE Identity document, because the closed
   vocabulary names the two documents apart and one leg serves both. A
   hex decode failure, a raw length other than 64, a psychic r or s and
   a false verify all say that one word. *)
val check_document :
  word:string -> key:P256x.Pubkey.t -> signature:string -> string ->
  (unit, Errx.t) result

(* The witness a successful verify mints. ABSTRACT, so a caller can
   neither forge a grade nor read a field this unit did not prove. *)
type t

(* The ONE minting path of t. now is a PARAMETER, so this unit reads no
   clock. The three witnesses are BOUND to ONE platform by step (0),
   because no type ties them together: without that step a caller
   grades the tee_tcb_svn of one quote against the CPUSVN, the PCESVN
   and the FMSPC of a certificate chain from a DIFFERENT platform. The
   reason names the FIRST failure of the order above. *)
val verify :
  now:Derx.Now.t -> collateral:Collateral.t -> chain:Derx.t ->
  quote:Quotex.t -> sig_:Sigx.t -> (t, Errx.t) result

(* Returns the tcbStatus of the matched platform TCB level AFTER
   Tcb_info.converge with the module status, so a module Out_of_date
   reads here as Out_of_date or Out_of_date_configuration_needed.
   TOTAL. *)
val platform_status : t -> Status.t

(* Returns the tcbStatus of the matched tdxModuleIdentity level, None
   when tee_tcb_svn byte 1 is 0 and no identity was graded. TOTAL. *)
val module_status : t -> Status.t option

(* Returns the advisoryIDs of the matched platform TCB level, the
   EMPTY list when the member is absent. TOTAL. *)
val platform_advisories : t -> string list

(* Returns the tcbDate of the matched platform TCB level. TOTAL. *)
val platform_tcb_date : t -> Derx.Now.t

(* Returns the tcbStatus of the matched QE identity level. TOTAL. *)
val qe_status : t -> Status.t

(* Returns the tcbDate of the matched QE identity level. TOTAL. *)
val qe_tcb_date : t -> Derx.Now.t

(* Returns the tcbEvaluationDataNumber of the TCB Info document, 17 on
   the pin. Equality ACROSS the two documents is NOT enforced (D16
   item 3). TOTAL. *)
val tcb_evaluation_data_number : t -> int

(* Returns the six FMSPC bytes both sides agreed on, which are the PCK
   certificate bytes the fmspc compare accepted. TOTAL. *)
val fmspc : t -> string
