(* derx: the TDX attestation CERTIFICATE unit (M26, DESIGN.md:406). It
   is the FOURTH module of the attestation tower: quotex DECODES the
   bytes, policyx DECIDES on the body, sigx PROVES the signature
   section and this unit PROVES the PCK certificate chain.

   verify_chain takes the PEM block list that
   Quotex.Signature_section.pem_chain returns, and never the quote. So
   this unit parses no quote header, reads no absolute quote offset and
   makes no TCB decision (M27). It reads NO clock: the caller hands in
   a Now.t witness, which M28 mints from the host clock.

   THE SUBSET. The DER reader accepts the tags 01, 02, 03, 04, 05, 06,
   0a, 13, 0c, 17, 18, 30, 31, a0 and a3, definite lengths in the short
   form below 128 and in the MINIMAL long form, and nothing else. An
   element never overruns its parent and the nesting depth is bounded.
   An OID is compared as RAW CONTENT BYTES, so no base-128 decode runs.
   The X.509 subset is version 3 only, with an ecdsa-with-SHA256
   algorithm in both the tbsCertificate and the outer SEQUENCE, a
   prime256v1 SubjectPublicKeyInfo, and issuer and subject kept as RAW
   TLV bytes.

   THE CHECK ORDER inside verify_chain, where the reason names the
   FIRST failure:

     1   the list holds exactly three blocks, "chain length"
     2   each block is cut to its PEM body and decoded ONCE through
         B64x.decode_std, "der"
     3   the DER of block 3 equals the pinned Intel SGX Root CA bytes,
         one String.equal over 659 bytes, "root pin"
     4   each block parses under the subset, in list order, which names
         "der", "version", "signature algorithm", "public key" or
         "critical extension"
     5   now sits inside each validity window, in list order,
         "not yet valid" before "expired"
     6   the leaf issuer equals the intermediate subject and the
         intermediate issuer equals the root subject, "issuer"
     7   the two CA certificates carry basicConstraints cA TRUE and the
         leaf does not, "ca"
     8   the two CA certificates carry keyCertSign and the leaf carries
         digitalSignature, "key usage"
     9   the leaf SGX extension reads, "sgx extension"
     10  the leaf tbsCertificate verifies under the intermediate key,
         "leaf signature mismatch", then the intermediate
         tbsCertificate verifies under the root key,
         "ca signature mismatch"

   The root's OWN signature is NEVER verified. Step 3 pins the root
   byte for byte, and a self-signature proves only that the holder of
   the root private key signed the root.

   Every rejection is one Errx.Cert_invalid whose text comes from a
   CLOSED vocabulary of FIFTEEN words: "chain length", "root pin",
   "der", "version", "signature algorithm", "public key", "not yet
   valid", "expired", "issuer", "ca", "key usage", "critical
   extension", "sgx extension", "leaf signature mismatch" and "ca
   signature mismatch". Errx.to_string prints each one under the
   "cert: " prefix.

   P256x.verify_message runs EXACTLY TWICE per chain and hashes the
   message itself, so this unit never names Sha2. B64x.decode_std runs
   EXACTLY ONCE per PEM block. Every compared value is PUBLIC, so
   String.equal is the whole test and no constant-time compare is
   owed. *)

module Now : sig
  (* The validity witness, fourteen ASCII digits YYYYMMDDhhmmss in UTC.
     ABSTRACT, so a witness exists only when every byte is a digit and
     every field sits in its range. Every value has the same length, so
     String.compare orders two witnesses correctly. *)
  type t

  (* The fourteen-digit form, which M28 mints from the host clock. None
     unless the string is fourteen ASCII digits whose month is 01 to
     12, day 01 to 31, hour 00 to 23, and minute and second 00 to 59.
     The calendar is NOT read, so 0229 of any year is accepted. *)
  val of_digits : string -> t option

  (* X.509 UTCTime, the thirteen bytes YYMMDDhhmmssZ. The trailing Z is
     required and any other zone form is None. The two-digit year takes
     the RFC 5280 4.1.2.5.1 pivot: below 50 mints 20YY and 50 or above
     mints 19YY. *)
  val of_utc : string -> t option

  (* X.509 GeneralizedTime, the fifteen bytes YYYYMMDDhhmmssZ. The
     trailing Z is required, so a fractional second and a zone offset
     are both None. *)
  val of_generalized : string -> t option

  (* String.compare over the fourteen digits, which agrees with time
     order because every value has the same length. *)
  val compare : t -> t -> int

  (* Returns the fourteen digits. *)
  val to_string : t -> string
end

module Sgx : sig
  (* The Intel SGX PCK extension values M27 consumes, OID
     1.2.840.113741.1.13.1. ABSTRACT: a value exists only when the
     whole extension parsed. *)
  type t

  (* wire: the .2.18 OCTET STRING of the TCB SEQUENCE, 16 bytes. *)
  val cpusvn : t -> string

  (* wire: the .2.17 INTEGER of the TCB SEQUENCE. *)
  val pcesvn : t -> int

  (* wire: the .4 OCTET STRING, 6 bytes. *)
  val fmspc : t -> string

  (* wire: the .3 OCTET STRING, 2 bytes. *)
  val pce_id : t -> string

  (* wire: the sixteen .2.1 to .2.16 INTEGERs of the TCB SEQUENCE, in
     wire order. *)
  val tcb_components : t -> int list
end

module Cert : sig
  (* One X.509 certificate under the subset above. ABSTRACT, so a
     certificate exists only when every field of the subset parsed. *)
  type t

  (* Parses the DER bytes of one certificate. *)
  val of_der : string -> (t, Errx.t) result

  (* Cuts ONE PEM block to its body, removes CRLF, LF and CR line
     endings, decodes the body ONCE through B64x.decode_std and parses
     the DER. *)
  val of_pem : string -> (t, Errx.t) result

  (* Returns the whole DER of the certificate. *)
  val der : t -> string

  (* wire: the tbsCertificate ELEMENT with its header, which is the
     window both signature legs cover. *)
  val tbs : t -> string

  (* wire: the serialNumber INTEGER content bytes. *)
  val serial : t -> string

  (* wire: the issuer Name as a RAW TLV element, header included. *)
  val issuer : t -> string

  (* wire: the subject Name as a RAW TLV element, header included. *)
  val subject : t -> string

  (* wire: validity notBefore. *)
  val not_before : t -> Now.t

  (* wire: validity notAfter. *)
  val not_after : t -> Now.t

  (* wire: the SubjectPublicKeyInfo point, already validated by
     P256x.Pubkey.of_bytes over its 65 SEC 1 bytes. *)
  val public_key : t -> P256x.Pubkey.t

  (* wire: the non-negative r and s INTEGER CONTENT bytes of the
     signatureValue, BEFORE the DER sign byte is stripped. Negative
     encodings are rejected during certificate parsing. *)
  val signature : t -> string * string

  (* Returns true when basicConstraints carries cA TRUE. *)
  val is_ca : t -> bool

  (* Returns true when keyUsage carries the keyCertSign bit. *)
  val key_cert_sign : t -> bool

  (* Returns true when keyUsage carries the digitalSignature bit. *)
  val digital_signature : t -> bool

  (* wire: the Intel SGX PCK extension. None when the certificate
     carries no such extension and when the extension does not parse,
     which is the "sgx extension" rejection of verify_chain. *)
  val sgx : t -> Sgx.t option
end

(* The witness a successful verify_chain mints. ABSTRACT, so a caller
   can neither forge one nor read a field this unit did not prove. *)
type t

(* The ONE entry. now is a PARAMETER, so this unit reads no clock. The
   blocks are the list Quotex.Signature_section.pem_chain returns, leaf
   first and the pinned Intel SGX Root CA last. *)
val verify_chain : now:Now.t -> string list -> (t, Errx.t) result

(* Returns the PCK leaf certificate, block 1. TOTAL. *)
val leaf : t -> Cert.t

(* Returns the PCK Platform CA certificate, block 2. TOTAL. *)
val intermediate : t -> Cert.t

(* Returns the Intel SGX Root CA certificate, block 3. TOTAL. *)
val root : t -> Cert.t

(* Returns the PCK leaf key the chain proved, the key M25 takes as
   ~pck_key. TOTAL. *)
val pck_key : t -> P256x.Pubkey.t

(* Returns the SGX extension of the leaf. TOTAL. *)
val sgx : t -> Sgx.t

(* Returns the sixteen TCB component INTEGERs of the leaf. TOTAL. *)
val tcb_components : t -> int list

(* Returns the 16 CPUSVN bytes of the leaf. TOTAL. *)
val cpusvn : t -> string

(* Returns the PCE SVN of the leaf. TOTAL. *)
val pcesvn : t -> int

(* Returns the 6 FMSPC bytes of the leaf. TOTAL. *)
val fmspc : t -> string

(* Returns the 2 PCE-ID bytes of the leaf. TOTAL. *)
val pce_id : t -> string

(* Returns the 659 pinned bytes of the Intel SGX Root CA, which are
   fixtures/collateral/TrustedRootCA.der. A unit function, not a
   constant: ZxCaml trap 2 makes a top-level constant invisible inside
   a helper. *)
val root_pin : unit -> string
