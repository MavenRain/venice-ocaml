(* quotex: the TDX version-4 quote decoder (M23, DESIGN.md:402).

   parse takes the RAW quote bytes, never base64: M28 owns the b64x
   decode. It reads the 48-byte header, the 584-byte TD report 1.0 body
   and the signature section, and it rejects with one typed
   Errx.Quote_invalid reason whose text names the check that failed.

   Every accessor below is TOTAL and returns no option, because a value
   of this unit exists only when parse succeeded, which is the
   secpx.mli:31-40 invariant-by-construction rule.

   The unit VERIFIES nothing and DECIDES nothing. M24 reads the DEBUG
   bit and the REPORTDATA binding, M25 verifies the ECDSA signature and
   the QE binding hash, M26 parses the PEM chain, M27 reads the TCB.
   Version 5 is refused at the first check and its body is not decoded.

   Every offset in the comments below is ABSOLUTE and counts from byte
   zero of the quote. Every integer on the wire is little-endian. *)

module Header : sig
  type t

  (* u16 at 0, 2 bytes. Version 4 only; every other value rejects. *)
  val version : t -> int

  (* u16 at 2, 2 bytes. Value 2 only; every other value rejects. *)
  val att_key_type : t -> int

  (* u32 at 4, 4 bytes. Value 0x00000081 only. *)
  val tee_type : t -> int

  (* u16 at 8, 2 bytes. RAW and unlabelled (D16 item 2): dcap-qvl reads
     this word as qe_svn and go-tdx-guest reads it as PceSvn, the byte
     ranges agree and the labels are swapped, so no TCB decision reads
     it here. *)
  val header_u16_at_8 : t -> int

  (* u16 at 10, 2 bytes. RAW and unlabelled for the same reason. *)
  val header_u16_at_10 : t -> int

  (* 16 bytes at 12. *)
  val qe_vendor_id : t -> string

  (* 20 bytes at 28. *)
  val user_data : t -> string
end

module Body : sig
  type t

  (* 16 bytes at 48. *)
  val tee_tcb_svn : t -> string

  (* 48 bytes at 64. *)
  val mr_seam : t -> string

  (* 48 bytes at 112. *)
  val mrsigner_seam : t -> string

  (* 48 bytes at 184. *)
  val mr_td : t -> string

  (* 48 bytes at 232. *)
  val mr_config_id : t -> string

  (* 48 bytes at 280. *)
  val mr_owner : t -> string

  (* 48 bytes at 328. *)
  val mr_owner_config : t -> string

  (* 48 bytes at 376. *)
  val rt_mr0 : t -> string

  (* 48 bytes at 424. *)
  val rt_mr1 : t -> string

  (* 48 bytes at 472. *)
  val rt_mr2 : t -> string

  (* 48 bytes at 520. *)
  val rt_mr3 : t -> string

  (* 64 bytes at 568, ending at 632. M24 reads the nonce and the
     address out of these bytes; M23 only exposes them. *)
  val report_data : t -> string

  (* u64 at 160, 8 bytes. Int64 keeps the top byte, which a 63-bit
     OCaml int would truncate (bytesx.ml:71-73). *)
  val seam_attributes : t -> int64

  (* u64 at 168, 8 bytes. Bit 0 is the DEBUG bit M24 decides on. *)
  val td_attributes : t -> int64

  (* u64 at 176, 8 bytes. *)
  val xfam : t -> int64
end

module Signature_section : sig
  type t

  (* 64 bytes at 636. The ECDSA signature over the signed region. M25
     verifies it. *)
  val signature : t -> string

  (* 64 bytes at 700. The attestation public key, X then Y. *)
  val attestation_key : t -> string

  (* 384 bytes at 770. *)
  val qe_report : t -> string

  (* 64 bytes at 1090, the last 64 bytes of the QE report. The first 32
     bytes are the QE binding value, which M25 checks against
     sha256 of the attestation key and the auth data. M23 exposes it
     and never checks it (D16 item 5). *)
  val qe_report_data : t -> string

  (* 64 bytes at 1154. *)
  val qe_report_signature : t -> string

  (* qe_auth_size bytes at 1220. *)
  val qe_auth_data : t -> string

  (* u16 at 764, 2 bytes. Value 6 only; every other value rejects. *)
  val cert_key_type : t -> int

  (* u32 at 766, 4 bytes. It must equal signature_data_len minus 134. *)
  val cert_size : t -> int

  (* u16 at 1220 plus qe_auth_size, 2 bytes. Value 5 only, which is
     PCK_CERT_CHAIN; every other value rejects. *)
  val inner_cert_type : t -> int

  (* u32 at 1222 plus qe_auth_size, 4 bytes. It must equal cert_size
     minus 456 minus qe_auth_size. *)
  val inner_size : t -> int

  (* u16 at 1218, 2 bytes. *)
  val qe_auth_size : t -> int

  (* inner_size bytes at 1226 plus qe_auth_size. The PEM certificate
     chain as it sits on the wire. *)
  val pem_window : t -> string

  (* The PEM window cut into one block per BEGIN CERTIFICATE marker.
     A block runs from one marker to the next and the last block runs
     to the window end, so every trailing byte stays inside a block.
     The list holds exactly three blocks, which is a FIXTURE pin and
     not a protocol fact (D16 item 3). *)
  val pem_chain : t -> string list
end

type t

(* Decode the raw bytes of a TDX quote. It answers Error with one
   Errx.Quote_invalid whose text names the first check that failed, in
   wire order: the version, the attestation key type, the TEE type, the
   header window, the body window, the length rule, then the signature
   section. The bytes are RAW and never base64. *)
val parse : string -> (t, Errx.t) result

(* The decoded 48-byte header. *)
val header : t -> Header.t

(* The decoded TD report 1.0 body. *)
val body : t -> Body.t

(* The decoded signature section and its certification chain. *)
val signature_section : t -> Signature_section.t

(* The bytes the attestation key signs, which are the header followed
   by the body: 632 bytes at 0. M25 verifies over them. *)
val signed_region : t -> string

(* The declared length of the signature section, the u32 at 632. The
   section starts at 636 and ends at 636 plus this value. *)
val signature_data_len : t -> int

(* The count of trailing bytes after the end of the quote structure.
   Rule 4 is an inequality, so a quote may carry padding; the padding
   is RECORDED here and never consumed. *)
val surplus : t -> int
