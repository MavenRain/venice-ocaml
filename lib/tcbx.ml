(* tcbx: the TDX TCB GRADING unit (M27, DESIGN.md:412), the FIFTH
   module of the attestation tower. quotex DECODES the bytes, policyx
   DECIDES on the body, sigx PROVES the signature section, derx CHAINS
   the certification data to Intel and this unit GRADES the platform
   TCB and the QE against Intel's signed collateral. tcbx.mli states
   the whole check order, the closed vocabulary and the handover rules.

   THE ZXLINT RULE (trap 2, ZXCAML.md:18-20). layout () builds the ONE
   record and every helper that needs a constant takes it FIRST, so no
   offset, no length, no member name, no identity string, no status
   string and no numeric literal sits outside the body of layout (),
   the reason words and the comments. No top-level alias of a Bytesx,
   a Hexx, a Jsonx, a Derx, a Quotex, a Sigx or a P256x binding exists.
   This unit applies no functor and holds no keyed container.

   The P-256 message verify leg RUNS four times per verify from the
   TWO call sites check_signing_chain and check_document, and it
   hashes the message itself, so this unit names no SHA-2 module and
   no base64 module. The derx PEM certificate parser sits at ONE call
   site and runs once per issuer chain, the derx DER parser reads the
   pinned root, and the derx chain walk never runs, because the chain
   witness arrives as a parameter. Every compare is String.equal,
   Int.equal or Int64.equal on PUBLIC bytes and no constant-time
   compare is owed. *)

type layout = {
  (* The QE report body, offsets RELATIVE to the 384 bytes
     Sigx.qe_report returns, where the absolute offset is 770 plus the
     relative one (FACTS.md:291). The map of the whole body is cpusvn
     at 0 for 16, miscselect at 16 for 4, isvExtProdId at 32 for 16,
     attributes at 48 for 16, mrEnclave at 64 for 32, mrSigner at 128
     for 32, configId at 192 for 64, isvProdId at 256, isvSvn at 258,
     configSvn at 260, isvFamilyId at 304 for 16 and reportData at 320
     for 64. This unit READS five windows, at 16, 48, 128, 256 and
     258, so only those five and the total length are pinned here and
     no field of this record is dead. *)
  report_len : int;
  off_miscselect : int;
  off_attributes : int;
  len_attributes : int;
  off_mr_signer : int;
  len_mr_signer : int;
  off_isv_prod_id : int;
  off_isv_svn : int;
  (* The six envelope members this unit reads. The three CRL members
     are read by nobody (D16 item 1). *)
  m_tcb_info_chain : string;
  m_tcb_info : string;
  m_tcb_info_signature : string;
  m_qe_identity_chain : string;
  m_qe_identity : string;
  m_qe_identity_signature : string;
  (* The members of the two inner documents. *)
  m_id : string;
  m_version : string;
  m_issue_date : string;
  m_next_update : string;
  m_fmspc : string;
  m_pce_id : string;
  m_tcb_type : string;
  m_tcb_eval_number : string;
  m_tdx_module : string;
  m_tdx_module_identities : string;
  m_tcb_levels : string;
  m_mrsigner : string;
  m_attributes : string;
  m_attributes_mask : string;
  m_tcb : string;
  m_sgx_components : string;
  m_pcesvn : string;
  m_tdx_components : string;
  m_svn : string;
  m_isvsvn : string;
  m_tcb_date : string;
  m_tcb_status : string;
  m_advisory_ids : string;
  m_miscselect : string;
  m_miscselect_mask : string;
  m_isvprodid : string;
  (* The identity strings and the seven Intel status spellings. *)
  id_tcb_info : string;
  id_qe_identity : string;
  identity_prefix : string;
  st_up_to_date : string;
  st_sw_hardening : string;
  st_configuration : string;
  st_configuration_sw : string;
  st_out_of_date : string;
  st_out_of_date_config : string;
  st_revoked : string;
  (* The scalar pins. components is the sixteen-component count of a
     tcbLevel, on both the sgx and the tdx vector. *)
  components : int;
  tcb_info_version : int;
  qe_identity_version : int;
  tcb_type_pin : int;
  chain_blocks : int;
  raw_signature_len : int;
  sig_half_len : int;
  miscselect_len : int;
  fmspc_len : int;
  pce_id_len : int;
  seam_mrsigner_len : int;
  qe_mrsigner_len : int;
  module_attributes_len : int;
  identity_id_len : int;
  identity_digits : int;
  svn_index_module : int;
  svn_index_major : int;
  (* The count of tdxtcbcomponents the tdxModuleIdentity grades in
     place of the platform walk when the SEAM major version is not 0:
     component 0 is the module isvsvn and component 1 is its major. *)
  tdx_module_components : int;
  (* The Intel instant, twenty characters YYYY-MM-DDTHH:MM:SSZ: the
     six digit windows and the six fixed non-digit positions with the
     byte each one carries. *)
  iso_len : int;
  off_year : int;
  len_year : int;
  off_month : int;
  off_day : int;
  off_hour : int;
  off_minute : int;
  off_second : int;
  len_pair : int;
  pos_dash_one : int;
  pos_dash_two : int;
  pos_t : int;
  pos_colon_one : int;
  pos_colon_two : int;
  pos_z : int;
  byte_dash : int;
  byte_t : int;
  byte_colon : int;
  byte_z : int;
  byte_zero : int;
  byte_nine : int;
  radix : int;
  (* The PEM markers blocks_of_chain cuts on. *)
  pem_begin : string;
  pem_end : string;
  pem_newline : string;
  newline : char;
  zero : int;
  one : int;
}

(* The ONE record, built once and passed FIRST to every helper that
   reads a constant. *)
let layout (() : unit) : layout =
  {
    report_len = 384;
    off_miscselect = 16;
    off_attributes = 48;
    len_attributes = 16;
    off_mr_signer = 128;
    len_mr_signer = 32;
    off_isv_prod_id = 256;
    off_isv_svn = 258;
    m_tcb_info_chain = "tcb_info_issuer_chain";
    m_tcb_info = "tcb_info";
    m_tcb_info_signature = "tcb_info_signature";
    m_qe_identity_chain = "qe_identity_issuer_chain";
    m_qe_identity = "qe_identity";
    m_qe_identity_signature = "qe_identity_signature";
    m_id = "id";
    m_version = "version";
    m_issue_date = "issueDate";
    m_next_update = "nextUpdate";
    m_fmspc = "fmspc";
    m_pce_id = "pceId";
    m_tcb_type = "tcbType";
    m_tcb_eval_number = "tcbEvaluationDataNumber";
    m_tdx_module = "tdxModule";
    m_tdx_module_identities = "tdxModuleIdentities";
    m_tcb_levels = "tcbLevels";
    m_mrsigner = "mrsigner";
    m_attributes = "attributes";
    m_attributes_mask = "attributesMask";
    m_tcb = "tcb";
    m_sgx_components = "sgxtcbcomponents";
    m_pcesvn = "pcesvn";
    m_tdx_components = "tdxtcbcomponents";
    m_svn = "svn";
    m_isvsvn = "isvsvn";
    m_tcb_date = "tcbDate";
    m_tcb_status = "tcbStatus";
    m_advisory_ids = "advisoryIDs";
    m_miscselect = "miscselect";
    m_miscselect_mask = "miscselectMask";
    m_isvprodid = "isvprodid";
    id_tcb_info = "TDX";
    id_qe_identity = "TD_QE";
    identity_prefix = "TDX_";
    st_up_to_date = "UpToDate";
    st_sw_hardening = "SWHardeningNeeded";
    st_configuration = "ConfigurationNeeded";
    st_configuration_sw = "ConfigurationAndSWHardeningNeeded";
    st_out_of_date = "OutOfDate";
    st_out_of_date_config = "OutOfDateConfigurationNeeded";
    st_revoked = "Revoked";
    components = 16;
    tcb_info_version = 3;
    qe_identity_version = 2;
    tcb_type_pin = 0;
    chain_blocks = 2;
    raw_signature_len = 64;
    sig_half_len = 32;
    miscselect_len = 4;
    fmspc_len = 6;
    pce_id_len = 2;
    seam_mrsigner_len = 48;
    qe_mrsigner_len = 32;
    module_attributes_len = 8;
    identity_id_len = 6;
    identity_digits = 2;
    svn_index_module = 0;
    svn_index_major = 1;
    tdx_module_components = 2;
    iso_len = 20;
    off_year = 0;
    len_year = 4;
    off_month = 5;
    off_day = 8;
    off_hour = 11;
    off_minute = 14;
    off_second = 17;
    len_pair = 2;
    pos_dash_one = 4;
    pos_dash_two = 7;
    pos_t = 10;
    pos_colon_one = 13;
    pos_colon_two = 16;
    pos_z = 19;
    byte_dash = 45;
    byte_t = 84;
    byte_colon = 58;
    byte_z = 90;
    byte_zero = 48;
    byte_nine = 57;
    radix = 10;
    pem_begin = "-----BEGIN CERTIFICATE-----";
    pem_end = "-----END CERTIFICATE-----";
    pem_newline = "\n";
    newline = '\n';
    zero = 0;
    one = 1;
  }

(* The TOTAL helpers. Every one that reads a constant takes the layout
   FIRST, and every one that can fail answers an option or a result. *)

(* Some () on true and None on false, so a boolean test joins an
   Option.bind chain without a match on an option. *)
let want (b : bool) : unit option = if b then Some () else None

(* Ok () on true and the reason word on false, the shape every leg of
   verify uses so the FIRST failed check names the rejection. *)
let want_ok (b : bool) (word : string) : (unit, Errx.t) result =
  if b then Ok () else Error (Errx.Tcb_invalid word)

(* The byte codes of a string, through String.to_seq and Char.code,
   both TOTAL. This unit reads no character by index and it builds
   no character from an integer code. *)
let codes (s : string) : int list =
  List.of_seq (Seq.map Char.code (String.to_seq s))

(* True when the two byte lists have the SAME length and the predicate
   holds on every pair. A length difference is false and never a
   silent short compare. *)
let all_pairs (a : int list) (b : int list) (p : int -> int -> bool) : bool =
  Int.equal (List.length a) (List.length b)
  && Seq.fold_left
       (fun (ok : bool) ((x : int), (y : int)) -> ok && p x y)
       true
       (Seq.zip (List.to_seq a) (List.to_seq b))

(* True when seen AND mask equals wanted, byte for byte, on three
   strings of the same length. This is the Intel masked compare of
   the QE attributes and of the SEAM attributes. *)
let masked_bytes_equal (seen : string) (mask : string) (wanted : string) :
    bool =
  let s = codes seen in
  let m = codes mask in
  let w = codes wanted in
  Int.equal (List.length s) (List.length m)
  && Int.equal (List.length s) (List.length w)
  && Seq.fold_left
       (fun (ok : bool) (((x : int), (y : int)), (z : int)) ->
         ok && Int.equal (x land y) z)
       true
       (Seq.zip (Seq.zip (List.to_seq s) (List.to_seq m)) (List.to_seq w))

(* Folds a result-returning reader over a list and keeps the FIRST
   failure, in document order. *)
let collect (f : 'a -> ('b, Errx.t) result) (items : 'a list) :
    ('b list, Errx.t) result =
  Result.bind
    (List.fold_left
       (fun (acc : ('b list, Errx.t) result) (v : 'a) ->
         Result.bind acc @@ fun (xs : 'b list) ->
         Result.bind (f v) @@ fun (x : 'b) -> Ok (x :: xs))
       (Ok []) items)
  @@ fun (xs : 'b list) -> Ok (List.rev xs)

(* Hexx.decode under the caller's reason word. Hexx takes BOTH letter
   cases, so the upper case hex of the Intel documents decodes. *)
let hex_bytes (word : string) (s : string) : (string, Errx.t) result =
  Option.to_result ~none:(Errx.Tcb_invalid word)
    (Result.to_option (Hexx.decode s))

(* Drops the leading DER sign byte of an INTEGER content half, the
   form P256x.Signature.of_rs takes. A half of 32 bytes or fewer
   passes through unchanged. *)
let strip_sign (l : layout) (h : string) : string option =
  if String.length h > l.sig_half_len then
    Option.bind (Bytesx.u8 h l.zero) (fun (b : int) ->
        Option.bind (want (Int.equal b l.zero)) (fun (() : unit) ->
            Bytesx.take h l.one (String.length h - l.one)))
  else Some h

(* The value of a decimal digit string, TOTAL, with no division and no
   Char.code of a literal: the digit bytes are compared to the layout
   bytes of "0" and "9". *)
let digits_value (l : layout) (s : string) : int option =
  List.fold_left
    (fun (acc : int option) (c : int) ->
      Option.bind acc @@ fun (n : int) ->
      Option.bind (want (c >= l.byte_zero && c <= l.byte_nine))
      @@ fun (() : unit) -> Some ((n * l.radix) + (c - l.byte_zero)))
    (Some l.zero) (codes s)

(* One fixed non-digit position of an Intel instant. *)
let iso_byte (s : string) (pos : int) (b : int) : unit option =
  Option.bind (Bytesx.u8 s pos) (fun (c : int) -> want (Int.equal c b))

let now_of_iso (s : string) : Derx.Now.t option =
  let l = layout () in
  Option.bind (want (Int.equal (String.length s) l.iso_len))
  @@ fun (() : unit) ->
  Option.bind (iso_byte s l.pos_dash_one l.byte_dash) @@ fun (() : unit) ->
  Option.bind (iso_byte s l.pos_dash_two l.byte_dash) @@ fun (() : unit) ->
  Option.bind (iso_byte s l.pos_t l.byte_t) @@ fun (() : unit) ->
  Option.bind (iso_byte s l.pos_colon_one l.byte_colon)
  @@ fun (() : unit) ->
  Option.bind (iso_byte s l.pos_colon_two l.byte_colon)
  @@ fun (() : unit) ->
  Option.bind (iso_byte s l.pos_z l.byte_z) @@ fun (() : unit) ->
  Option.bind (Bytesx.take s l.off_year l.len_year) @@ fun (year : string) ->
  Option.bind (Bytesx.take s l.off_month l.len_pair) @@ fun (month : string) ->
  Option.bind (Bytesx.take s l.off_day l.len_pair) @@ fun (day : string) ->
  Option.bind (Bytesx.take s l.off_hour l.len_pair) @@ fun (hour : string) ->
  Option.bind (Bytesx.take s l.off_minute l.len_pair)
  @@ fun (minute : string) ->
  Option.bind (Bytesx.take s l.off_second l.len_pair)
  @@ fun (second : string) ->
  Derx.Now.of_digits (year ^ month ^ day ^ hour ^ minute ^ second)

(* The state of the PEM cut: the finished blocks and the lines of the
   block that is open, both newest first. *)
type cut = { blocks_rev : string list; lines_rev : string list; open_ : bool }

(* One line of an issuer chain. A BEGIN marker OPENS a block and drops
   whatever an unterminated earlier block collected, an END marker
   CLOSES one and text between the two is kept. Every line is trimmed,
   so a CR of a CRLF chain never reaches Derx. *)
let cut_line (l : layout) (st : cut) (line : string) : cut =
  let t = String.trim line in
  match () with
  | () when String.equal t l.pem_begin ->
      { blocks_rev = st.blocks_rev; lines_rev = [ t ]; open_ = true }
  | () when st.open_ && String.equal t l.pem_end ->
      {
        blocks_rev =
          String.concat l.pem_newline (List.rev (t :: st.lines_rev))
          :: st.blocks_rev;
        lines_rev = [];
        open_ = false;
      }
  | () when st.open_ -> { st with lines_rev = t :: st.lines_rev }
  | () -> st

let blocks_of_chain (chain : string) : string list =
  let l = layout () in
  let st =
    List.fold_left (cut_line l)
      { blocks_rev = []; lines_rev = []; open_ = false }
      (String.split_on_char l.newline chain)
  in
  List.rev st.blocks_rev

module Status = struct
  type t =
    | Up_to_date
    | Sw_hardening_needed
    | Configuration_needed
    | Configuration_and_sw_hardening_needed
    | Out_of_date
    | Out_of_date_configuration_needed
    | Revoked

  let to_string (v : t) : string =
    let l = layout () in
    match v with
    | Up_to_date -> l.st_up_to_date
    | Sw_hardening_needed -> l.st_sw_hardening
    | Configuration_needed -> l.st_configuration
    | Configuration_and_sw_hardening_needed -> l.st_configuration_sw
    | Out_of_date -> l.st_out_of_date
    | Out_of_date_configuration_needed -> l.st_out_of_date_config
    | Revoked -> l.st_revoked

  let of_string (s : string) : t option =
    let l = layout () in
    match () with
    | () when String.equal s l.st_up_to_date -> Some Up_to_date
    | () when String.equal s l.st_sw_hardening -> Some Sw_hardening_needed
    | () when String.equal s l.st_configuration -> Some Configuration_needed
    | () when String.equal s l.st_configuration_sw ->
        Some Configuration_and_sw_hardening_needed
    | () when String.equal s l.st_out_of_date -> Some Out_of_date
    | () when String.equal s l.st_out_of_date_config ->
        Some Out_of_date_configuration_needed
    | () when String.equal s l.st_revoked -> Some Revoked
    | () -> None

  let equal (a : t) (b : t) : bool = String.equal (to_string a) (to_string b)
end

module Level = struct
  type t = {
    l_status : Status.t;
    l_tcb_date : Derx.Now.t;
    l_advisories : string list;
  }

  let status (v : t) : Status.t = v.l_status
  let tcb_date (v : t) : Derx.Now.t = v.l_tcb_date
  let advisories (v : t) : string list = v.l_advisories
end

(* The document readers. Every one takes the reason WORD first, so a
   shape failure of the TCB Info document says "tcb info", one of the
   QE Identity document says "qe identity" and one of the envelope
   says "envelope", and no reader mints a word of its own. *)

let json_of (word : string) (text : string) : (Jsonx.t, Errx.t) result =
  Option.to_result ~none:(Errx.Tcb_invalid word)
    (Result.to_option (Jsonx.parse text))

let member_of (word : string) (name : string) (j : Jsonx.t) :
    (Jsonx.t, Errx.t) result =
  Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.member name j)

let string_member (word : string) (name : string) (j : Jsonx.t) :
    (string, Errx.t) result =
  Result.bind (member_of word name j) @@ fun (v : Jsonx.t) ->
  Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.as_string v)

let int_member (word : string) (name : string) (j : Jsonx.t) :
    (int, Errx.t) result =
  Result.bind (member_of word name j) @@ fun (v : Jsonx.t) ->
  Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.as_int v)

let list_member (word : string) (name : string) (j : Jsonx.t) :
    (Jsonx.t list, Errx.t) result =
  Result.bind (member_of word name j) @@ fun (v : Jsonx.t) ->
  Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.as_list v)

(* The member itself, once Jsonx has confirmed it IS an object. *)
let object_member (word : string) (name : string) (j : Jsonx.t) :
    (Jsonx.t, Errx.t) result =
  Result.bind (member_of word name j) @@ fun (v : Jsonx.t) ->
  Result.bind
    (Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.as_obj v))
  @@ fun (_ : (string * Jsonx.t) list) -> Ok v

let instant_member (word : string) (name : string) (j : Jsonx.t) :
    (Derx.Now.t, Errx.t) result =
  Result.bind (string_member word name j) @@ fun (s : string) ->
  Option.to_result ~none:(Errx.Tcb_invalid word) (now_of_iso s)

let status_member (word : string) (name : string) (j : Jsonx.t) :
    (Status.t, Errx.t) result =
  Result.bind (string_member word name j) @@ fun (s : string) ->
  Option.to_result ~none:(Errx.Tcb_invalid word) (Status.of_string s)

(* A hex member of a PINNED raw length. *)
let hex_member (word : string) (name : string) (j : Jsonx.t) (len : int) :
    (string, Errx.t) result =
  Result.bind (string_member word name j) @@ fun (s : string) ->
  Result.bind (hex_bytes word s) @@ fun (b : string) ->
  Result.bind (want_ok (Int.equal (String.length b) len) word)
  @@ fun (() : unit) -> Ok b

(* The eight bytes of a SEAM attributes member, as the little endian
   number Quotex.Body.seam_attributes returns. *)
let hex_u64_member (l : layout) (word : string) (name : string) (j : Jsonx.t)
    : (int64, Errx.t) result =
  Result.bind (hex_member word name j l.module_attributes_len)
  @@ fun (b : string) ->
  Option.to_result ~none:(Errx.Tcb_invalid word) (Bytesx.u64le b l.zero)

(* advisoryIDs is OPTIONAL: a level without it carries no advisory. *)
let advisories_of (word : string) (name : string) (j : Jsonx.t) :
    (string list, Errx.t) result =
  Option.fold ~none:(Ok [])
    ~some:(fun (v : Jsonx.t) ->
      Result.bind
        (Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.as_list v))
      @@ fun (items : Jsonx.t list) ->
      collect
        (fun (a : Jsonx.t) ->
          Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.as_string a))
        items)
    (Jsonx.member name j)

module Collateral = struct
  type t = {
    c_tcb_info : string;
    c_tcb_info_signature : string;
    c_tcb_info_chain : string;
    c_qe_identity : string;
    c_qe_identity_signature : string;
    c_qe_identity_chain : string;
  }

  let make ~(tcb_info : string) ~(tcb_info_signature : string)
      ~(tcb_info_chain : string) ~(qe_identity : string)
      ~(qe_identity_signature : string) ~(qe_identity_chain : string) : t =
    {
      c_tcb_info = tcb_info;
      c_tcb_info_signature = tcb_info_signature;
      c_tcb_info_chain = tcb_info_chain;
      c_qe_identity = qe_identity;
      c_qe_identity_signature = qe_identity_signature;
      c_qe_identity_chain = qe_identity_chain;
    }

  let of_envelope (text : string) : (t, Errx.t) result =
    let l = layout () in
    let word = "envelope" in
    Result.bind (json_of word text) @@ fun (j : Jsonx.t) ->
    Result.bind (string_member word l.m_tcb_info j) @@ fun (info : string) ->
    Result.bind (string_member word l.m_tcb_info_signature j)
    @@ fun (info_sig : string) ->
    Result.bind (string_member word l.m_tcb_info_chain j)
    @@ fun (info_chain : string) ->
    Result.bind (string_member word l.m_qe_identity j) @@ fun (qe : string) ->
    Result.bind (string_member word l.m_qe_identity_signature j)
    @@ fun (qe_sig : string) ->
    Result.bind (string_member word l.m_qe_identity_chain j)
    @@ fun (qe_chain : string) ->
    Ok
      (make ~tcb_info:info ~tcb_info_signature:info_sig
         ~tcb_info_chain:info_chain ~qe_identity:qe
         ~qe_identity_signature:qe_sig ~qe_identity_chain:qe_chain)

  let tcb_info (v : t) : string = v.c_tcb_info
  let tcb_info_signature (v : t) : string = v.c_tcb_info_signature
  let tcb_info_chain (v : t) : string = v.c_tcb_info_chain
  let qe_identity (v : t) : string = v.c_qe_identity
  let qe_identity_signature (v : t) : string = v.c_qe_identity_signature
  let qe_identity_chain (v : t) : string = v.c_qe_identity_chain
end

module Tcb_info = struct
  (* One level of a TDX module identity: the ISVSVN of the module and
     the status. The tcbDate of such a level is PARSED, so a malformed
     instant is a structure failure, and it is kept by nobody, because
     the witness carries the platform date and the QE date only. *)
  type module_level = { mv_isvsvn : int; mv_status : Status.t }

  (* One tdxModuleIdentity, named "TDX_" plus two digits of the SEAM
     major version. *)
  type identity = {
    iv_id : string;
    iv_mrsigner : string;
    iv_attributes : int64;
    iv_mask : int64;
    iv_levels : module_level list;
  }

  (* One platform tcbLevel: the sixteen SGX component svn, the pcesvn,
     the sixteen TDX component svn, the date, the status and the
     advisories. *)
  type tcb_level = {
    tv_sgx : int list;
    tv_pcesvn : int;
    tv_tdx : int list;
    tv_date : Derx.Now.t;
    tv_status : Status.t;
    tv_advisories : string list;
  }

  type t = {
    ti_id : string;
    ti_version : int;
    ti_issue : Derx.Now.t;
    ti_next : Derx.Now.t;
    ti_fmspc : string;
    ti_pce_id : string;
    ti_type : int;
    ti_eval : int;
    ti_mrsigner : string;
    ti_attributes : int64;
    ti_mask : int64;
    ti_identities : identity list;
    ti_levels : tcb_level list;
  }

  let module_level_of (l : layout) (word : string) (v : Jsonx.t) :
      (module_level, Errx.t) result =
    Result.bind (object_member word l.m_tcb v) @@ fun (tcb : Jsonx.t) ->
    Result.bind (int_member word l.m_isvsvn tcb) @@ fun (svn : int) ->
    Result.bind (instant_member word l.m_tcb_date v)
    @@ fun (_ : Derx.Now.t) ->
    Result.bind (status_member word l.m_tcb_status v) @@ fun (st : Status.t) ->
    Ok { mv_isvsvn = svn; mv_status = st }

  let identity_of (l : layout) (word : string) (v : Jsonx.t) :
      (identity, Errx.t) result =
    Result.bind (string_member word l.m_id v) @@ fun (id : string) ->
    Result.bind (hex_member word l.m_mrsigner v l.seam_mrsigner_len)
    @@ fun (ms : string) ->
    Result.bind (hex_u64_member l word l.m_attributes v)
    @@ fun (attributes : int64) ->
    Result.bind (hex_u64_member l word l.m_attributes_mask v)
    @@ fun (mask : int64) ->
    Result.bind (list_member word l.m_tcb_levels v)
    @@ fun (items : Jsonx.t list) ->
    Result.bind (collect (module_level_of l word) items)
    @@ fun (levels : module_level list) ->
    Ok
      {
        iv_id = id;
        iv_mrsigner = ms;
        iv_attributes = attributes;
        iv_mask = mask;
        iv_levels = levels;
      }

  (* The svn of each component of one vector, with the PINNED count of
     sixteen. category and type are read by nobody. *)
  let components_of (l : layout) (word : string) (name : string)
      (tcb : Jsonx.t) : (int list, Errx.t) result =
    Result.bind (list_member word name tcb) @@ fun (items : Jsonx.t list) ->
    Result.bind
      (collect (fun (v : Jsonx.t) -> int_member word l.m_svn v) items)
    @@ fun (svns : int list) ->
    Result.bind (want_ok (Int.equal (List.length svns) l.components) word)
    @@ fun (() : unit) -> Ok svns

  let tcb_level_of (l : layout) (word : string) (v : Jsonx.t) :
      (tcb_level, Errx.t) result =
    Result.bind (object_member word l.m_tcb v) @@ fun (tcb : Jsonx.t) ->
    Result.bind (components_of l word l.m_sgx_components tcb)
    @@ fun (sgx : int list) ->
    Result.bind (int_member word l.m_pcesvn tcb) @@ fun (pcesvn : int) ->
    Result.bind (components_of l word l.m_tdx_components tcb)
    @@ fun (tdx : int list) ->
    Result.bind (instant_member word l.m_tcb_date v)
    @@ fun (date : Derx.Now.t) ->
    Result.bind (status_member word l.m_tcb_status v) @@ fun (st : Status.t) ->
    Result.bind (advisories_of word l.m_advisory_ids v)
    @@ fun (adv : string list) ->
    Ok
      {
        tv_sgx = sgx;
        tv_pcesvn = pcesvn;
        tv_tdx = tdx;
        tv_date = date;
        tv_status = st;
        tv_advisories = adv;
      }

  let of_json (text : string) : (t, Errx.t) result =
    let l = layout () in
    let word = "tcb info" in
    Result.bind (json_of word text) @@ fun (j : Jsonx.t) ->
    Result.bind (string_member word l.m_id j) @@ fun (id : string) ->
    Result.bind (int_member word l.m_version j) @@ fun (version : int) ->
    Result.bind (instant_member word l.m_issue_date j)
    @@ fun (issue : Derx.Now.t) ->
    Result.bind (instant_member word l.m_next_update j)
    @@ fun (next : Derx.Now.t) ->
    Result.bind (hex_member word l.m_fmspc j l.fmspc_len)
    @@ fun (fmspc : string) ->
    Result.bind (hex_member word l.m_pce_id j l.pce_id_len)
    @@ fun (pce_id : string) ->
    Result.bind (int_member word l.m_tcb_type j) @@ fun (tcb_type : int) ->
    Result.bind (int_member word l.m_tcb_eval_number j) @@ fun (eval : int) ->
    Result.bind (object_member word l.m_tdx_module j)
    @@ fun (tdx_module : Jsonx.t) ->
    Result.bind (hex_member word l.m_mrsigner tdx_module l.seam_mrsigner_len)
    @@ fun (ms : string) ->
    Result.bind (hex_u64_member l word l.m_attributes tdx_module)
    @@ fun (attributes : int64) ->
    Result.bind (hex_u64_member l word l.m_attributes_mask tdx_module)
    @@ fun (mask : int64) ->
    (* tdxModuleIdentities is OPTIONAL: a document without it carries
       no identity, and check_tdx_module says "tdx module identity" when
       a non-zero SEAM major version then asks for one. *)
    Result.bind
      (Option.fold ~none:(Ok [])
         ~some:(fun (v : Jsonx.t) ->
           Result.bind
             (Option.to_result ~none:(Errx.Tcb_invalid word) (Jsonx.as_list v))
           @@ fun (id_items : Jsonx.t list) ->
           collect (identity_of l word) id_items)
         (Jsonx.member l.m_tdx_module_identities j))
    @@ fun (identities : identity list) ->
    Result.bind (list_member word l.m_tcb_levels j)
    @@ fun (level_items : Jsonx.t list) ->
    Result.bind (collect (tcb_level_of l word) level_items)
    @@ fun (levels : tcb_level list) ->
    Ok
      {
        ti_id = id;
        ti_version = version;
        ti_issue = issue;
        ti_next = next;
        ti_fmspc = fmspc;
        ti_pce_id = pce_id;
        ti_type = tcb_type;
        ti_eval = eval;
        ti_mrsigner = ms;
        ti_attributes = attributes;
        ti_mask = mask;
        ti_identities = identities;
        ti_levels = levels;
      }

  let check_platform (v : t) ~(now : Derx.Now.t) ~(fmspc : string)
      ~(pce_id : string) : (unit, Errx.t) result =
    let l = layout () in
    match () with
    | () when not (String.equal v.ti_id l.id_tcb_info) ->
        Error (Errx.Tcb_invalid "tcb info id")
    | () when not (Int.equal v.ti_version l.tcb_info_version) ->
        Error (Errx.Tcb_invalid "tcb info version")
    | () when not (Int.equal v.ti_type l.tcb_type_pin) ->
        Error (Errx.Tcb_invalid "tcb type")
    | () when Derx.Now.compare now v.ti_issue < l.zero ->
        Error (Errx.Tcb_invalid "tcb info not yet valid")
    | () when Derx.Now.compare now v.ti_next >= l.zero ->
        Error (Errx.Tcb_invalid "tcb info expired")
    | () when not (String.equal v.ti_fmspc fmspc) ->
        Error (Errx.Tcb_invalid "fmspc mismatch")
    | () when not (String.equal v.ti_pce_id pce_id) ->
        Error (Errx.Tcb_invalid "pce id mismatch")
    | () -> Ok ()

  (* The two compares Intel states on a TDX module: the mrsigner is
     the SEAM mrsigner and the masked SEAM attributes are the module
     attributes. *)
  let module_match (word : string) (mrsigner : string) (attributes : int64)
      (mask : int64) (mrsigner_seam : string) (seam_attributes : int64) :
      (unit, Errx.t) result =
    want_ok
      (String.equal mrsigner mrsigner_seam
      && Int64.equal (Int64.logand seam_attributes mask) attributes)
      word

  (* The SEAM major version an identity id names, "TDX_" plus two
     decimal digits and nothing else. *)
  let identity_major (l : layout) (id : string) : int option =
    Option.bind (want (Int.equal (String.length id) l.identity_id_len))
    @@ fun (() : unit) ->
    Option.bind (Bytesx.take id l.zero (String.length l.identity_prefix))
    @@ fun (prefix : string) ->
    Option.bind (want (String.equal prefix l.identity_prefix))
    @@ fun (() : unit) ->
    Option.bind
      (Bytesx.take id (String.length l.identity_prefix) l.identity_digits)
    @@ fun (digits : string) -> digits_value l digits

  (* The FIRST identity whose id names this major version. *)
  let find_identity (l : layout) (word : string) (major : int)
      (ids : identity list) : (identity, Errx.t) result =
    match
      List.filter
        (fun (i : identity) ->
          Option.fold ~none:false
            ~some:(fun (m : int) -> Int.equal m major)
            (identity_major l i.iv_id))
        ids
    with
    | [] -> Error (Errx.Tcb_invalid word)
    | i :: (_ : identity list) -> Ok i

  (* The status of the FIRST module level at or below the module
     ISVSVN, refused under "revoked" when that status is Revoked. *)
  let grade_module (word : string) (levels : module_level list)
      (isvsvn : int) : (Status.t, Errx.t) result =
    match
      List.filter (fun (lv : module_level) -> lv.mv_isvsvn <= isvsvn) levels
    with
    | [] -> Error (Errx.Tcb_invalid word)
    | lv :: (_ : module_level list) ->
        if Status.equal lv.mv_status Status.Revoked then
          Error (Errx.Tcb_invalid "revoked")
        else Ok lv.mv_status

  (* Intel's QuoteVerifier: a SEAM major version of 0 compares the
     top-level tdxModule and grades no identity, so it yields None. A
     non-zero major version selects the identity "TDX_" plus two digits,
     compares THAT identity's mrsigner and masked attributes, never the
     top-level tdxModule, and grades tee_tcb_svn byte 0 against the
     identity levels, so it yields Some status. *)
  let check_tdx_module (v : t) ~(mrsigner_seam : string)
      ~(seam_attributes : int64) ~(tee_tcb_svn : string) :
      (Status.t option, Errx.t) result =
    let l = layout () in
    let word = "tdx module identity" in
    Result.bind
      (Option.to_result ~none:(Errx.Tcb_invalid word)
         (Bytesx.u8 tee_tcb_svn l.svn_index_major))
    @@ fun (major : int) ->
    if Int.equal major l.zero then
      Result.map
        (fun (() : unit) -> None)
        (module_match "tdx module" v.ti_mrsigner v.ti_attributes v.ti_mask
           mrsigner_seam seam_attributes)
    else
      Result.bind
        (Option.to_result ~none:(Errx.Tcb_invalid word)
           (Bytesx.u8 tee_tcb_svn l.svn_index_module))
      @@ fun (isvsvn : int) ->
      Result.bind (find_identity l word major v.ti_identities)
      @@ fun (i : identity) ->
      Result.bind
        (module_match word i.iv_mrsigner i.iv_attributes i.iv_mask
           mrsigner_seam seam_attributes)
      @@ fun (() : unit) ->
      Result.map Option.some (grade_module word i.iv_levels isvsvn)

  (* The list without its first n elements, through List.filteri. *)
  let drop (n : int) (xs : int list) : int list =
    List.filteri (fun (i : int) ((_ : int)) -> i >= n) xs

  (* True when every component svn of the level is at or below the
     matching platform byte and the pcesvn is at or below the PCK
     pcesvn. The first skip tdxtcbcomponents are left to the
     tdxModuleIdentity. A vector of a different length is false. *)
  let level_matches (lv : tcb_level) (cpu : int list) (tee : int list)
      (skip : int) (pcesvn : int) : bool =
    all_pairs lv.tv_sgx cpu (fun (a : int) (b : int) -> a <= b)
    && lv.tv_pcesvn <= pcesvn
    && all_pairs (drop skip lv.tv_tdx) (drop skip tee)
         (fun (a : int) (b : int) -> a <= b)

  let grade (v : t) ~(cpusvn : string) ~(pcesvn : int)
      ~(tee_tcb_svn : string) : (Level.t, Errx.t) result =
    let l = layout () in
    let cpu = codes cpusvn in
    let tee = codes tee_tcb_svn in
    (* Intel's isTdxTcbHigherOrEqual starts the tdxtcbcomponents walk
       at index 2 when tee_tcb_svn byte 1 is not 0, because components
       0 and 1 are the TDX module SVN the identity grades. *)
    let skip =
      Option.fold ~none:l.zero
        ~some:(fun (major : int) ->
          if Int.equal major l.zero then l.zero else l.tdx_module_components)
        (Bytesx.u8 tee_tcb_svn l.svn_index_major)
    in
    match
      List.filter
        (fun (lv : tcb_level) -> level_matches lv cpu tee skip pcesvn)
        v.ti_levels
    with
    | [] -> Error (Errx.Tcb_invalid "tcb level")
    | lv :: (_ : tcb_level list) ->
        (* Intel signs tcbLevels highest first; the FIRST match is the top. *)
        if Status.equal lv.tv_status Status.Revoked then
          Error (Errx.Tcb_invalid "revoked")
        else
          Ok
            {
              Level.l_status = lv.tv_status;
              Level.l_tcb_date = lv.tv_date;
              Level.l_advisories = lv.tv_advisories;
            }

  (* Intel's convergeTcbStatus. An OutOfDate module lowers an UpToDate
     or SWHardeningNeeded platform to OutOfDate and a ConfigurationNeeded
     or ConfigurationAndSWHardeningNeeded platform to
     OutOfDateConfigurationNeeded. Every other pair keeps the platform
     status. A Revoked module never reaches here, because grade_module
     refuses it under "revoked". *)
  let converge (platform : Level.t) (module_status : Status.t option) :
      Level.t =
    let lowered (s : Status.t) : Status.t =
      match s with
      | Status.Up_to_date | Status.Sw_hardening_needed -> Status.Out_of_date
      | Status.Configuration_needed
      | Status.Configuration_and_sw_hardening_needed ->
          Status.Out_of_date_configuration_needed
      | Status.Out_of_date | Status.Out_of_date_configuration_needed
      | Status.Revoked ->
          s
    in
    Option.fold ~none:platform
      ~some:(fun (m : Status.t) ->
        match m with
        | Status.Out_of_date ->
            { platform with Level.l_status = lowered platform.Level.l_status }
        | Status.Up_to_date | Status.Sw_hardening_needed
        | Status.Configuration_needed
        | Status.Configuration_and_sw_hardening_needed
        | Status.Out_of_date_configuration_needed | Status.Revoked ->
            platform)
      module_status

  let id (v : t) : string = v.ti_id
  let version (v : t) : int = v.ti_version
  let issue_date (v : t) : Derx.Now.t = v.ti_issue
  let next_update (v : t) : Derx.Now.t = v.ti_next
  let fmspc (v : t) : string = v.ti_fmspc
  let pce_id (v : t) : string = v.ti_pce_id
  let tcb_type (v : t) : int = v.ti_type
  let tcb_evaluation_data_number (v : t) : int = v.ti_eval
  let tdx_module_mrsigner (v : t) : string = v.ti_mrsigner
  let tdx_module_attributes (v : t) : int64 = v.ti_attributes
  let tdx_module_attributes_mask (v : t) : int64 = v.ti_mask

  let identity_ids (v : t) : string list =
    List.map (fun (i : identity) -> i.iv_id) v.ti_identities
end

module Qe_identity = struct
  (* One QE level: the ISVSVN, the date and the status, plus the
     advisories the level names. *)
  type qe_level = {
    qv_isvsvn : int;
    qv_date : Derx.Now.t;
    qv_status : Status.t;
    qv_advisories : string list;
  }

  type t = {
    qi_id : string;
    qi_version : int;
    qi_issue : Derx.Now.t;
    qi_next : Derx.Now.t;
    qi_eval : int;
    qi_miscselect : int;
    qi_miscselect_mask : int;
    qi_attributes : string;
    qi_attributes_mask : string;
    qi_mrsigner : string;
    qi_isvprodid : int;
    qi_levels : qe_level list;
  }

  (* The four bytes of a miscselect member, as the little endian
     number the QE report carries at offset 16. *)
  let hex_u32_member (l : layout) (word : string) (name : string)
      (j : Jsonx.t) : (int, Errx.t) result =
    Result.bind (hex_member word name j l.miscselect_len)
    @@ fun (b : string) ->
    Option.to_result ~none:(Errx.Tcb_invalid word) (Bytesx.u32le b l.zero)

  let qe_level_of (l : layout) (word : string) (v : Jsonx.t) :
      (qe_level, Errx.t) result =
    Result.bind (object_member word l.m_tcb v) @@ fun (tcb : Jsonx.t) ->
    Result.bind (int_member word l.m_isvsvn tcb) @@ fun (svn : int) ->
    Result.bind (instant_member word l.m_tcb_date v)
    @@ fun (date : Derx.Now.t) ->
    Result.bind (status_member word l.m_tcb_status v) @@ fun (st : Status.t) ->
    Result.bind (advisories_of word l.m_advisory_ids v)
    @@ fun (adv : string list) ->
    Ok
      {
        qv_isvsvn = svn;
        qv_date = date;
        qv_status = st;
        qv_advisories = adv;
      }

  let of_json (text : string) : (t, Errx.t) result =
    let l = layout () in
    let word = "qe identity" in
    Result.bind (json_of word text) @@ fun (j : Jsonx.t) ->
    Result.bind (string_member word l.m_id j) @@ fun (id : string) ->
    Result.bind (int_member word l.m_version j) @@ fun (version : int) ->
    Result.bind (instant_member word l.m_issue_date j)
    @@ fun (issue : Derx.Now.t) ->
    Result.bind (instant_member word l.m_next_update j)
    @@ fun (next : Derx.Now.t) ->
    Result.bind (int_member word l.m_tcb_eval_number j) @@ fun (eval : int) ->
    Result.bind (hex_u32_member l word l.m_miscselect j)
    @@ fun (misc : int) ->
    Result.bind (hex_u32_member l word l.m_miscselect_mask j)
    @@ fun (misc_mask : int) ->
    Result.bind (hex_member word l.m_attributes j l.len_attributes)
    @@ fun (attributes : string) ->
    Result.bind (hex_member word l.m_attributes_mask j l.len_attributes)
    @@ fun (attributes_mask : string) ->
    Result.bind (hex_member word l.m_mrsigner j l.qe_mrsigner_len)
    @@ fun (ms : string) ->
    Result.bind (int_member word l.m_isvprodid j) @@ fun (isvprodid : int) ->
    Result.bind (list_member word l.m_tcb_levels j)
    @@ fun (items : Jsonx.t list) ->
    Result.bind (collect (qe_level_of l word) items)
    @@ fun (levels : qe_level list) ->
    Ok
      {
        qi_id = id;
        qi_version = version;
        qi_issue = issue;
        qi_next = next;
        qi_eval = eval;
        qi_miscselect = misc;
        qi_miscselect_mask = misc_mask;
        qi_attributes = attributes;
        qi_attributes_mask = attributes_mask;
        qi_mrsigner = ms;
        qi_isvprodid = isvprodid;
        qi_levels = levels;
      }

  let check_identity (v : t) ~(now : Derx.Now.t) : (unit, Errx.t) result =
    let l = layout () in
    match () with
    | () when not (String.equal v.qi_id l.id_qe_identity) ->
        Error (Errx.Tcb_invalid "qe identity id")
    | () when not (Int.equal v.qi_version l.qe_identity_version) ->
        Error (Errx.Tcb_invalid "qe identity version")
    | () when Derx.Now.compare now v.qi_issue < l.zero ->
        Error (Errx.Tcb_invalid "qe identity not yet valid")
    | () when Derx.Now.compare now v.qi_next >= l.zero ->
        Error (Errx.Tcb_invalid "qe identity expired")
    | () -> Ok ()

  let grade (v : t) ~(qe_report : string) : (Level.t, Errx.t) result =
    let l = layout () in
    Result.bind
      (want_ok
         (Int.equal (String.length qe_report) l.report_len)
         "qe miscselect")
    @@ fun (() : unit) ->
    Result.bind
      (Option.to_result ~none:(Errx.Tcb_invalid "qe miscselect")
         (Bytesx.u32le qe_report l.off_miscselect))
    @@ fun (misc : int) ->
    Result.bind
      (want_ok
         (Int.equal (misc land v.qi_miscselect_mask) v.qi_miscselect)
         "qe miscselect")
    @@ fun (() : unit) ->
    Result.bind
      (Option.to_result ~none:(Errx.Tcb_invalid "qe attributes")
         (Bytesx.take qe_report l.off_attributes l.len_attributes))
    @@ fun (attributes : string) ->
    Result.bind
      (want_ok
         (masked_bytes_equal attributes v.qi_attributes_mask v.qi_attributes)
         "qe attributes")
    @@ fun (() : unit) ->
    Result.bind
      (Option.to_result ~none:(Errx.Tcb_invalid "qe mrsigner")
         (Bytesx.take qe_report l.off_mr_signer l.len_mr_signer))
    @@ fun (ms : string) ->
    Result.bind (want_ok (String.equal ms v.qi_mrsigner) "qe mrsigner")
    @@ fun (() : unit) ->
    Result.bind
      (Option.to_result ~none:(Errx.Tcb_invalid "qe isvprodid")
         (Bytesx.u16le qe_report l.off_isv_prod_id))
    @@ fun (prod : int) ->
    Result.bind (want_ok (Int.equal prod v.qi_isvprodid) "qe isvprodid")
    @@ fun (() : unit) ->
    Result.bind
      (Option.to_result ~none:(Errx.Tcb_invalid "qe isvsvn")
         (Bytesx.u16le qe_report l.off_isv_svn))
    @@ fun (svn : int) ->
    match
      List.filter (fun (lv : qe_level) -> lv.qv_isvsvn <= svn) v.qi_levels
    with
    | [] -> Error (Errx.Tcb_invalid "qe isvsvn")
    | lv :: (_ : qe_level list) ->
        if Status.equal lv.qv_status Status.Revoked then
          Error (Errx.Tcb_invalid "revoked")
        else
          Ok
            {
              Level.l_status = lv.qv_status;
              Level.l_tcb_date = lv.qv_date;
              Level.l_advisories = lv.qv_advisories;
            }

  let id (v : t) : string = v.qi_id
  let version (v : t) : int = v.qi_version
  let issue_date (v : t) : Derx.Now.t = v.qi_issue
  let next_update (v : t) : Derx.Now.t = v.qi_next
  let tcb_evaluation_data_number (v : t) : int = v.qi_eval
  let miscselect (v : t) : int = v.qi_miscselect
  let miscselect_mask (v : t) : int = v.qi_miscselect_mask
  let attributes (v : t) : string = v.qi_attributes
  let attributes_mask (v : t) : string = v.qi_attributes_mask
  let mrsigner (v : t) : string = v.qi_mrsigner
  let isvprodid (v : t) : int = v.qi_isvprodid
end

(* The two INTEGER halves of the signatureValue of a certificate, with
   the DER sign byte stripped, the 1 to 32 byte form
   P256x.Signature.of_rs takes. *)
let cert_signature (l : layout) (c : Derx.Cert.t) : P256x.Signature.t option =
  let r, s = Derx.Cert.signature c in
  Option.bind (strip_sign l r) (fun (r : string) ->
      Option.bind (strip_sign l s) (fun (s : string) ->
          P256x.Signature.of_rs ~r ~s))

(* Block 1 of an issuer chain, the Intel TCB Signing certificate. The
   PINNED root is the anchor: the issuer of block 1 must be the
   subject of Derx.root_pin () and the root key must verify the
   tbsCertificate of block 1. The root NEVER verifies itself and block
   2 is never parsed (RUL-M27-2). *)
let signing_key (l : layout) ~(now : Derx.Now.t) ~(root_pin : string)
    (block : string) : (P256x.Pubkey.t, Errx.t) result =
  Result.bind (Derx.Cert.of_pem block) @@ fun (signing : Derx.Cert.t) ->
  Result.bind (Derx.Cert.of_der root_pin) @@ fun (root : Derx.Cert.t) ->
  Result.bind
    (want_ok
       (String.equal (Derx.Cert.issuer signing) (Derx.Cert.subject root))
       "root pin")
  @@ fun (() : unit) ->
  Result.bind
    (want_ok
       (Derx.Cert.digital_signature signing && not (Derx.Cert.is_ca signing))
       "signing cert")
  @@ fun (() : unit) ->
  Result.bind
    (Option.to_result ~none:(Errx.Tcb_invalid "signing cert signature")
       (cert_signature l signing))
  @@ fun (sg : P256x.Signature.t) ->
  Result.bind
    (want_ok
       (P256x.verify_message (Derx.Cert.public_key root) sg
          (Derx.Cert.tbs signing))
       "signing cert signature")
  @@ fun (() : unit) ->
  Result.bind
    (want_ok
       (Derx.Now.compare now (Derx.Cert.not_before signing) >= l.zero)
       "signing cert not yet valid")
  @@ fun (() : unit) ->
  Result.bind
    (want_ok
       (Derx.Now.compare now (Derx.Cert.not_after signing) <= l.zero)
       "signing cert expired")
  @@ fun (() : unit) -> Ok (Derx.Cert.public_key signing)

let check_signing_chain ~(now : Derx.Now.t) ~(root_pin : string)
    (blocks : string list) : (P256x.Pubkey.t, Errx.t) result =
  let l = layout () in
  Result.bind
    (want_ok (Int.equal (List.length blocks) l.chain_blocks) "chain length")
  @@ fun (() : unit) ->
  match blocks with
  | first :: (_ : string list) -> signing_key l ~now ~root_pin first
  | [] -> Error (Errx.Tcb_invalid "chain length")

let check_document ~(word : string) ~(key : P256x.Pubkey.t)
    ~(signature : string) (document : string) : (unit, Errx.t) result =
  let l = layout () in
  Result.bind (hex_bytes word signature) @@ fun (raw : string) ->
  Result.bind
    (want_ok (Int.equal (String.length raw) l.raw_signature_len) word)
  @@ fun (() : unit) ->
  Result.bind
    (Option.to_result ~none:(Errx.Tcb_invalid word)
       (P256x.Signature.of_raw raw))
  @@ fun (sg : P256x.Signature.t) ->
  want_ok (P256x.verify_message key sg document) word

(* The witness of a graded platform and a graded QE. *)
type t = {
  w_platform : Level.t;
  w_module : Status.t option;
  w_qe : Level.t;
  w_eval : int;
  w_fmspc : string;
}

(* D4 step (0), RUL-M27-1: the three witnesses must speak of ONE
   platform and ONE quote, so the PCK key of the certificate chain is
   the PCK key of the signature section and the QE report of the
   signature section is the QE report of the quote. Without this step
   a caller could grade the collateral of one platform against the
   quote of another. *)
let check_binding (chain : Derx.t) (quote : Quotex.t) (sig_ : Sigx.t) :
    (unit, Errx.t) result =
  want_ok
    (P256x.Pubkey.equal (Derx.pck_key chain) (Sigx.pck_key sig_)
    && String.equal (Sigx.qe_report sig_)
         (Quotex.Signature_section.qe_report (Quotex.signature_section quote)))
    "witness mismatch"

let verify ~(now : Derx.Now.t) ~(collateral : Collateral.t) ~(chain : Derx.t)
    ~(quote : Quotex.t) ~(sig_ : Sigx.t) : (t, Errx.t) result =
  let body = Quotex.body quote in
  let root = Derx.root_pin () in
  Result.bind (check_binding chain quote sig_) @@ fun (() : unit) ->
  Result.bind
    (check_signing_chain ~now ~root_pin:root
       (blocks_of_chain (Collateral.tcb_info_chain collateral)))
  @@ fun (tcb_key : P256x.Pubkey.t) ->
  Result.bind
    (check_document ~word:"tcb info signature" ~key:tcb_key
       ~signature:(Collateral.tcb_info_signature collateral)
       (Collateral.tcb_info collateral))
  @@ fun (() : unit) ->
  Result.bind (Tcb_info.of_json (Collateral.tcb_info collateral))
  @@ fun (info : Tcb_info.t) ->
  Result.bind
    (Tcb_info.check_platform info ~now ~fmspc:(Derx.fmspc chain)
       ~pce_id:(Derx.pce_id chain))
  @@ fun (() : unit) ->
  Result.bind
    (Tcb_info.check_tdx_module info
       ~mrsigner_seam:(Quotex.Body.mrsigner_seam body)
       ~seam_attributes:(Quotex.Body.seam_attributes body)
       ~tee_tcb_svn:(Quotex.Body.tee_tcb_svn body))
  @@ fun (module_status : Status.t option) ->
  Result.bind
    (Tcb_info.grade info ~cpusvn:(Derx.cpusvn chain)
       ~pcesvn:(Derx.pcesvn chain)
       ~tee_tcb_svn:(Quotex.Body.tee_tcb_svn body))
  @@ fun (platform : Level.t) ->
  Result.bind
    (check_signing_chain ~now ~root_pin:root
       (blocks_of_chain (Collateral.qe_identity_chain collateral)))
  @@ fun (qe_key : P256x.Pubkey.t) ->
  Result.bind
    (check_document ~word:"qe identity signature" ~key:qe_key
       ~signature:(Collateral.qe_identity_signature collateral)
       (Collateral.qe_identity collateral))
  @@ fun (() : unit) ->
  Result.bind (Qe_identity.of_json (Collateral.qe_identity collateral))
  @@ fun (identity : Qe_identity.t) ->
  Result.bind (Qe_identity.check_identity identity ~now)
  @@ fun (() : unit) ->
  Result.bind (Qe_identity.grade identity ~qe_report:(Sigx.qe_report sig_))
  @@ fun (qe : Level.t) ->
  Ok
    {
      w_platform = Tcb_info.converge platform module_status;
      w_module = module_status;
      w_qe = qe;
      w_eval = Tcb_info.tcb_evaluation_data_number info;
      w_fmspc = Tcb_info.fmspc info;
    }

let platform_status (w : t) : Status.t = Level.status w.w_platform
let platform_advisories (w : t) : string list = Level.advisories w.w_platform
let platform_tcb_date (w : t) : Derx.Now.t = Level.tcb_date w.w_platform
let module_status (w : t) : Status.t option = w.w_module
let qe_status (w : t) : Status.t = Level.status w.w_qe
let qe_tcb_date (w : t) : Derx.Now.t = Level.tcb_date w.w_qe
let tcb_evaluation_data_number (w : t) : int = w.w_eval
let fmspc (w : t) : string = w.w_fmspc
