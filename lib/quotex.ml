(* quotex: the TDX version-4 quote decoder (M23, DESIGN.md:402). It is
   the first module of the attestation tower. It is pure and sans-io:
   no Bytes, no Buffer, no Array, no reference cell, no exception, no
   division and no remainder. Every window comes from Bytesx.take and
   every integer from Bytesx.u8, Bytesx.u16le, Bytesx.u32le or
   Bytesx.u64le, so a short quote answers None and never raises.

   THE LAYOUT, in offset order. Every offset is ABSOLUTE and counts
   from byte zero of the quote. Every integer on the wire is
   little-endian. The columns are offset, length and name.

     0     2    version, 4 only
     2     2    att_key_type, 2 only
     4     4    tee_type, 0x00000081 only
     8     2    header_u16_at_8, RAW and unlabelled
     10    2    header_u16_at_10, RAW and unlabelled
     12    16   qe_vendor_id
     28    20   user_data, the header ends at 48
     48    16   tee_tcb_svn
     64    48   mr_seam
     112   48   mrsigner_seam
     160   8    seam_attributes
     168   8    td_attributes
     176   8    xfam
     184   48   mr_td
     232   48   mr_config_id
     280   48   mr_owner
     328   48   mr_owner_config
     376   48   rt_mr0
     424   48   rt_mr1
     472   48   rt_mr2
     520   48   rt_mr3
     568   64   report_data, the body ends at 632
     0     632  the signed region, the header and the body together
     632   4    signature_data_len, 4300 on the v4 fixture
     636   64   signature
     700   64   attestation_key
     764   2    cert_key_type, 6 only
     766   4    cert_size, signature_data_len minus 134
     770   384  qe_report
     1090  64   qe_report_data, the last 64 bytes of the QE report
     1154  64   qe_report_signature
     1218  2    qe_auth_size, 32 on the v4 fixture
     1220  n    qe_auth_data, qe_auth_size bytes
     1252  2    inner_cert_type, 5 only, at 1220 plus qe_auth_size
     1254  4    inner_size, cert_size minus 456 minus qe_auth_size
     1258  m    the PEM window, inner_size bytes, ending at 4936

   THE EIGHT RULES, by number, which fixtures/README.md states.

     1. version is 4.
     2. att_key_type is 2.
     3. tee_type is 0x00000081.
     4. 636 plus signature_data_len is at most the length, with the
        surplus recorded and never consumed. It is the ONLY inequality
        in this unit.
     5. cert_key_type is 6 with inner type 5 only, and every other type
        is a typed reject.
     6. The PEM chain splits on the certificate markers, which the
        fixture shows to be three certificates.
     7. Version 5 is rejected BY VERSION with a typed reason, before
        any byte past offset 2 is read.
     8. Both fixtures exercise the same decoder, the accept case and
        the reject case.

   THE ONE LAYOUT RECORD is the answer to ZxCaml trap 2, which makes a
   top-level constant invisible inside a helper and which fires CROSS
   MODULE. layout () builds the record ONCE and every helper takes it
   as its FIRST argument, the secpx.ml:66-89 shape. No numeric literal
   sits outside the body of layout (), and no top-level alias of a
   Bytesx binding exists.

   The reason vocabulary is CLOSED. parse answers the FIRST failing
   check and no other, so the check order is part of the contract. *)

type layout = {
  hdr_off : int;
  step : int;
  version_off : int;
  att_key_type_off : int;
  tee_type_off : int;
  hdr8_off : int;
  hdr10_off : int;
  qe_vendor_id_off : int;
  qe_vendor_id_len : int;
  user_data_off : int;
  user_data_len : int;
  hdr_len : int;
  body_off : int;
  body_len : int;
  tee_tcb_svn_off : int;
  tee_tcb_svn_len : int;
  meas_len : int;
  mr_seam_off : int;
  mrsigner_seam_off : int;
  seam_attributes_off : int;
  td_attributes_off : int;
  xfam_off : int;
  mr_td_off : int;
  mr_config_id_off : int;
  mr_owner_off : int;
  mr_owner_config_off : int;
  rt_mr0_off : int;
  rt_mr1_off : int;
  rt_mr2_off : int;
  rt_mr3_off : int;
  report_data_off : int;
  report_data_len : int;
  signed_len : int;
  sdl_off : int;
  section_off : int;
  signature_len : int;
  att_key_rel : int;
  att_key_len : int;
  cert_key_type_rel : int;
  cert_size_rel : int;
  cert_overhead : int;
  qe_report_rel : int;
  qe_report_len : int;
  qe_report_data_rel : int;
  qe_report_data_len : int;
  qe_sig_rel : int;
  qe_sig_len : int;
  auth_size_rel : int;
  auth_data_rel : int;
  inner_hdr_len : int;
  inner_size_rel : int;
  inner_overhead : int;
  version_ok : int;
  att_key_type_ok : int;
  tee_type_ok : int;
  cert_key_type_ok : int;
  inner_cert_type_ok : int;
  pem_marker : string;
  pem_marker_len : int;
  pem_blocks_ok : int;
}

(* The ONE record, built once. Every derived size is arithmetic HERE
   and never a literal at a use site: cert_overhead is 134 and
   inner_overhead is 456, and both come out of the field sizes above
   them. hdr_off is the origin every zero index reuses, and step is the
   one offset the PEM marker scan advances by, because a bare 0 or a
   bare 1 inside a helper would be a literal outside this body. *)
let layout (() : unit) : layout =
  let hdr_off = 0 in
  let step = 1 in
  let version_off = 0 in
  let att_key_type_off = 2 in
  let tee_type_off = 4 in
  let hdr8_off = 8 in
  let hdr10_off = 10 in
  let qe_vendor_id_off = 12 in
  let qe_vendor_id_len = 16 in
  let user_data_off = 28 in
  let user_data_len = 20 in
  let hdr_len = 48 in
  let body_off = 48 in
  let body_len = 584 in
  let tee_tcb_svn_off = 48 in
  let tee_tcb_svn_len = 16 in
  let meas_len = 48 in
  let mr_seam_off = 64 in
  let mrsigner_seam_off = 112 in
  let seam_attributes_off = 160 in
  let td_attributes_off = 168 in
  let xfam_off = 176 in
  let mr_td_off = 184 in
  let mr_config_id_off = 232 in
  let mr_owner_off = 280 in
  let mr_owner_config_off = 328 in
  let rt_mr0_off = 376 in
  let rt_mr1_off = 424 in
  let rt_mr2_off = 472 in
  let rt_mr3_off = 520 in
  let report_data_off = 568 in
  let report_data_len = 64 in
  let signed_len = hdr_len + body_len in
  let sdl_off = signed_len in
  let sdl_len = 4 in
  let section_off = sdl_off + sdl_len in
  let signature_len = 64 in
  let att_key_rel = signature_len in
  let att_key_len = 64 in
  let cert_key_type_rel = att_key_rel + att_key_len in
  let cert_key_type_len = 2 in
  let cert_size_rel = cert_key_type_rel + cert_key_type_len in
  let cert_size_len = 4 in
  let cert_overhead =
    signature_len + att_key_len + cert_key_type_len + cert_size_len
  in
  let qe_report_rel = cert_overhead in
  let qe_report_len = 384 in
  let qe_report_data_len = 64 in
  let qe_report_data_rel = qe_report_len - qe_report_data_len in
  let qe_sig_rel = qe_report_rel + qe_report_len in
  let qe_sig_len = 64 in
  let auth_size_rel = qe_sig_rel + qe_sig_len in
  let auth_size_len = 2 in
  let auth_data_rel = auth_size_rel + auth_size_len in
  let inner_type_len = 2 in
  let inner_size_rel = inner_type_len in
  let inner_size_len = 4 in
  let inner_hdr_len = inner_type_len + inner_size_len in
  let inner_overhead =
    qe_report_len + qe_sig_len + auth_size_len + inner_hdr_len
  in
  let version_ok = 4 in
  let att_key_type_ok = 2 in
  let tee_type_ok = 0x81 in
  let cert_key_type_ok = 6 in
  let inner_cert_type_ok = 5 in
  let pem_marker = "-----BEGIN CERTIFICATE-----" in
  let pem_marker_len = String.length pem_marker in
  let pem_blocks_ok = 3 in
  {
    hdr_off;
    step;
    version_off;
    att_key_type_off;
    tee_type_off;
    hdr8_off;
    hdr10_off;
    qe_vendor_id_off;
    qe_vendor_id_len;
    user_data_off;
    user_data_len;
    hdr_len;
    body_off;
    body_len;
    tee_tcb_svn_off;
    tee_tcb_svn_len;
    meas_len;
    mr_seam_off;
    mrsigner_seam_off;
    seam_attributes_off;
    td_attributes_off;
    xfam_off;
    mr_td_off;
    mr_config_id_off;
    mr_owner_off;
    mr_owner_config_off;
    rt_mr0_off;
    rt_mr1_off;
    rt_mr2_off;
    rt_mr3_off;
    report_data_off;
    report_data_len;
    signed_len;
    sdl_off;
    section_off;
    signature_len;
    att_key_rel;
    att_key_len;
    cert_key_type_rel;
    cert_size_rel;
    cert_overhead;
    qe_report_rel;
    qe_report_len;
    qe_report_data_rel;
    qe_report_data_len;
    qe_sig_rel;
    qe_sig_len;
    auth_size_rel;
    auth_data_rel;
    inner_hdr_len;
    inner_size_rel;
    inner_overhead;
    version_ok;
    att_key_type_ok;
    tee_type_ok;
    cert_key_type_ok;
    inner_cert_type_ok;
    pem_marker;
    pem_marker_len;
    pem_blocks_ok;
  }

(* The three decoded parts. Each type is ABSTRACT in quotex.mli, so a
   value of it exists only when parse succeeded and every accessor
   below is TOTAL. *)

module Header = struct
  type t = {
    version : int;
    att_key_type : int;
    tee_type : int;
    u16_at_8 : int;
    u16_at_10 : int;
    qe_vendor_id : string;
    user_data : string;
  }

  let version (h : t) : int = h.version
  let att_key_type (h : t) : int = h.att_key_type
  let tee_type (h : t) : int = h.tee_type
  let header_u16_at_8 (h : t) : int = h.u16_at_8
  let header_u16_at_10 (h : t) : int = h.u16_at_10
  let qe_vendor_id (h : t) : string = h.qe_vendor_id
  let user_data (h : t) : string = h.user_data
end

module Body = struct
  type t = {
    tee_tcb_svn : string;
    mr_seam : string;
    mrsigner_seam : string;
    mr_td : string;
    mr_config_id : string;
    mr_owner : string;
    mr_owner_config : string;
    rt_mr0 : string;
    rt_mr1 : string;
    rt_mr2 : string;
    rt_mr3 : string;
    report_data : string;
    seam_attributes : int64;
    td_attributes : int64;
    xfam : int64;
  }

  let tee_tcb_svn (b : t) : string = b.tee_tcb_svn
  let mr_seam (b : t) : string = b.mr_seam
  let mrsigner_seam (b : t) : string = b.mrsigner_seam
  let mr_td (b : t) : string = b.mr_td
  let mr_config_id (b : t) : string = b.mr_config_id
  let mr_owner (b : t) : string = b.mr_owner
  let mr_owner_config (b : t) : string = b.mr_owner_config
  let rt_mr0 (b : t) : string = b.rt_mr0
  let rt_mr1 (b : t) : string = b.rt_mr1
  let rt_mr2 (b : t) : string = b.rt_mr2
  let rt_mr3 (b : t) : string = b.rt_mr3
  let report_data (b : t) : string = b.report_data
  let seam_attributes (b : t) : int64 = b.seam_attributes
  let td_attributes (b : t) : int64 = b.td_attributes
  let xfam (b : t) : int64 = b.xfam
end

module Signature_section = struct
  type t = {
    signature : string;
    attestation_key : string;
    qe_report : string;
    qe_report_data : string;
    qe_report_signature : string;
    qe_auth_data : string;
    cert_key_type : int;
    cert_size : int;
    inner_cert_type : int;
    inner_size : int;
    qe_auth_size : int;
    pem_window : string;
    pem_chain : string list;
  }

  let signature (s : t) : string = s.signature
  let attestation_key (s : t) : string = s.attestation_key
  let qe_report (s : t) : string = s.qe_report
  let qe_report_data (s : t) : string = s.qe_report_data
  let qe_report_signature (s : t) : string = s.qe_report_signature
  let qe_auth_data (s : t) : string = s.qe_auth_data
  let cert_key_type (s : t) : int = s.cert_key_type
  let cert_size (s : t) : int = s.cert_size
  let inner_cert_type (s : t) : int = s.inner_cert_type
  let inner_size (s : t) : int = s.inner_size
  let qe_auth_size (s : t) : int = s.qe_auth_size
  let pem_window (s : t) : string = s.pem_window
  let pem_chain (s : t) : string list = s.pem_chain
end

type t = {
  q_header : Header.t;
  q_body : Body.t;
  q_section : Signature_section.t;
  q_signed_region : string;
  q_signature_data_len : int;
  q_surplus : int;
}

(* Rule 1. It runs FIRST, so a version-5 quote is refused before any
   byte past offset 2 is read, whatever else is wrong with it. A read
   that falls outside the buffer is "short: header" and never a version
   verdict, so a one-byte quote and a version-5 quote answer different
   words. *)
let checked_version (l : layout) (quote : string) : (int, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: header")
       (Bytesx.u16le quote l.version_off))
  @@ fun (v : int) ->
  if Int.equal v l.version_ok then Ok v
  else Error (Errx.Quote_invalid ("version " ^ string_of_int v))

(* Rule 2. *)
let checked_att_key_type (l : layout) (quote : string) : (int, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: header")
       (Bytesx.u16le quote l.att_key_type_off))
  @@ fun (v : int) ->
  if Int.equal v l.att_key_type_ok then Ok v
  else Error (Errx.Quote_invalid ("att_key_type " ^ string_of_int v))

(* Rule 3. *)
let checked_tee_type (l : layout) (quote : string) : (int, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: header")
       (Bytesx.u32le quote l.tee_type_off))
  @@ fun (v : int) ->
  if Int.equal v l.tee_type_ok then Ok v
  else Error (Errx.Quote_invalid ("tee_type " ^ string_of_int v))

(* The 48-byte header window. The three checked words come in as
   arguments, because their checks already ran. The window take is the
   BOUND: it proves that every field offset below sits inside the
   quote, and the option chain that follows consumes ONCE. *)
let header_of (l : layout) (quote : string) (version : int)
    (att_key_type : int) (tee_type : int) : (Header.t, Errx.t) result =
  Option.to_result ~none:(Errx.Quote_invalid "short: header")
  @@ Option.bind (Bytesx.take quote l.hdr_off l.hdr_len)
  @@ fun (_ : string) ->
  Option.bind (Bytesx.u16le quote l.hdr8_off) @@ fun (u16_at_8 : int) ->
  Option.bind (Bytesx.u16le quote l.hdr10_off) @@ fun (u16_at_10 : int) ->
  Option.bind (Bytesx.take quote l.qe_vendor_id_off l.qe_vendor_id_len)
  @@ fun (qe_vendor_id : string) ->
  Option.bind (Bytesx.take quote l.user_data_off l.user_data_len)
  @@ fun (user_data : string) ->
  Some
    {
      Header.version;
      att_key_type;
      tee_type;
      u16_at_8;
      u16_at_10;
      qe_vendor_id;
      user_data;
    }

(* The 584-byte TD report 1.0 body window, which ends at 632. The three
   8-byte fields go through Bytesx.u64le, so the top byte of each one
   survives; a 63-bit OCaml int would truncate it. *)
let body_of (l : layout) (quote : string) : (Body.t, Errx.t) result =
  Option.to_result ~none:(Errx.Quote_invalid "short: body")
  @@ Option.bind (Bytesx.take quote l.body_off l.body_len)
  @@ fun (_ : string) ->
  Option.bind (Bytesx.take quote l.tee_tcb_svn_off l.tee_tcb_svn_len)
  @@ fun (tee_tcb_svn : string) ->
  Option.bind (Bytesx.take quote l.mr_seam_off l.meas_len)
  @@ fun (mr_seam : string) ->
  Option.bind (Bytesx.take quote l.mrsigner_seam_off l.meas_len)
  @@ fun (mrsigner_seam : string) ->
  Option.bind (Bytesx.take quote l.mr_td_off l.meas_len)
  @@ fun (mr_td : string) ->
  Option.bind (Bytesx.take quote l.mr_config_id_off l.meas_len)
  @@ fun (mr_config_id : string) ->
  Option.bind (Bytesx.take quote l.mr_owner_off l.meas_len)
  @@ fun (mr_owner : string) ->
  Option.bind (Bytesx.take quote l.mr_owner_config_off l.meas_len)
  @@ fun (mr_owner_config : string) ->
  Option.bind (Bytesx.take quote l.rt_mr0_off l.meas_len)
  @@ fun (rt_mr0 : string) ->
  Option.bind (Bytesx.take quote l.rt_mr1_off l.meas_len)
  @@ fun (rt_mr1 : string) ->
  Option.bind (Bytesx.take quote l.rt_mr2_off l.meas_len)
  @@ fun (rt_mr2 : string) ->
  Option.bind (Bytesx.take quote l.rt_mr3_off l.meas_len)
  @@ fun (rt_mr3 : string) ->
  Option.bind (Bytesx.take quote l.report_data_off l.report_data_len)
  @@ fun (report_data : string) ->
  Option.bind (Bytesx.u64le quote l.seam_attributes_off)
  @@ fun (seam_attributes : int64) ->
  Option.bind (Bytesx.u64le quote l.td_attributes_off)
  @@ fun (td_attributes : int64) ->
  Option.bind (Bytesx.u64le quote l.xfam_off) @@ fun (xfam : int64) ->
  Some
    {
      Body.tee_tcb_svn;
      mr_seam;
      mrsigner_seam;
      mr_td;
      mr_config_id;
      mr_owner;
      mr_owner_config;
      rt_mr0;
      rt_mr1;
      rt_mr2;
      rt_mr3;
      report_data;
      seam_attributes;
      td_attributes;
      xfam;
    }

(* The signed region, the 632 bytes the attestation key signs. The body
   window already proved that these bytes sit inside the quote, so this
   read cannot fail; it keeps the "short: body" word for the case a
   later edit moves the body check. *)
let signed_of (l : layout) (quote : string) : (string, Errx.t) result =
  Option.to_result
    ~none:(Errx.Quote_invalid "short: body")
    (Bytesx.take quote l.hdr_off l.signed_len)

(* The declared length of the signature section, the u32 at 632. *)
let sdl_of (l : layout) (quote : string) : (int, Errx.t) result =
  Option.to_result
    ~none:(Errx.Quote_invalid "short: signature_data_len")
    (Bytesx.u32le quote l.sdl_off)

(* Rule 4, the ONLY inequality in this unit. The window it mints bounds
   every read of the signature section below, so no section read ever
   reaches into the surplus, and a small signature_data_len makes the
   six "short:" section words reachable. *)
let section_window (l : layout) (quote : string) (sdl : int) :
    (string, Errx.t) result =
  let short = Errx.Quote_invalid "short: signature data" in
  if l.section_off + sdl <= String.length quote then
    Option.to_result ~none:short (Bytesx.take quote l.section_off sdl)
  else Error short

(* The PEM split (D8). ONE recursive pass over the window, with no loop
   keyword and no reference cell. It advances one offset at a time and
   cuts a block each time the 27-byte marker matches, so a block runs
   from one marker to the NEXT marker and the last block runs to the
   window end. Every trailing byte therefore stays inside a block, the
   final newline and the one NUL of the fixture included. The caller
   proved the marker at offset 0 first, so prev starts at the origin
   and i starts one marker past it. *)
let rec pem_scan (l : layout) (window : string) (i : int) (prev : int)
    (acc : string list) : string list =
  match () with
  | () when i + l.pem_marker_len > String.length window ->
      List.rev
        (List.append
           (Option.to_list
              (Bytesx.take window prev (String.length window - prev)))
           acc)
  | () when
      Option.fold ~none:false
        ~some:(fun (w : string) -> String.equal w l.pem_marker)
        (Bytesx.take window i l.pem_marker_len) ->
      pem_scan l window (i + l.step) i
        (List.append (Option.to_list (Bytesx.take window prev (i - prev))) acc)
  | () -> pem_scan l window (i + l.step) prev acc

(* Rule 6, the last two checks of the chain. The marker must sit at
   offset 0 of the window, and the block count must be exactly three,
   which is a FIXTURE pin and not a protocol fact (D16 item 3). *)
let pem_chain_of (l : layout) (window : string) :
    (string list, Errx.t) result =
  let at_zero =
    Option.fold ~none:false
      ~some:(fun (w : string) -> String.equal w l.pem_marker)
      (Bytesx.take window l.hdr_off l.pem_marker_len)
  in
  let blocks = pem_scan l window l.pem_marker_len l.hdr_off [] in
  let n = List.length blocks in
  match () with
  | () when not at_zero ->
      Error (Errx.Quote_invalid "pem chain: no marker at 0")
  | () when Int.equal n l.pem_blocks_ok -> Ok blocks
  | () ->
      Error
        (Errx.Quote_invalid ("pem chain: " ^ string_of_int n ^ " certificates"))

(* Rule 5, first half. The cert header window is 134 bytes, so this
   read cannot fail; the window take above owns the short case. *)
let checked_cert_key_type (l : layout) (ch : string) : (int, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: cert header")
       (Bytesx.u16le ch l.cert_key_type_rel))
  @@ fun (v : int) ->
  if Int.equal v l.cert_key_type_ok then Ok v
  else Error (Errx.Quote_invalid ("cert_key_type " ^ string_of_int v))

(* The first D7 equality, ENFORCED and not merely recorded: cert_size
   is signature_data_len minus the 134 bytes of the cert header, which
   are the signature, the attestation key, the cert_key_type word and
   the cert_size word. Without it a quote can carry a
   self-consistent-looking header over a truncated body. *)
let checked_cert_size (l : layout) (ch : string) (sdl : int) :
    (int, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: cert header")
       (Bytesx.u32le ch l.cert_size_rel))
  @@ fun (v : int) ->
  if Int.equal v (sdl - l.cert_overhead) then Ok v
  else Error (Errx.Quote_invalid ("cert_size " ^ string_of_int v))

(* Rule 5, second half. Type 5 is PCK_CERT_CHAIN and no other value is
   accepted. The word sits at offset 0 of the six-byte inner header. *)
let checked_inner_cert_type (l : layout) (ihdr : string) :
    (int, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: inner type")
       (Bytesx.u16le ihdr l.hdr_off))
  @@ fun (v : int) ->
  if Int.equal v l.inner_cert_type_ok then Ok v
  else Error (Errx.Quote_invalid ("inner cert type " ^ string_of_int v))

(* The second D7 equality: inner_size is cert_size minus the 456 bytes
   of the QE report, the QE report signature, the auth size word, the
   inner type word and the inner size word, minus the auth data. *)
let checked_inner_size (l : layout) (ihdr : string) (cert_size : int)
    (auth_size : int) : (int, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: inner type")
       (Bytesx.u32le ihdr l.inner_size_rel))
  @@ fun (v : int) ->
  if Int.equal v (cert_size - l.inner_overhead - auth_size) then Ok v
  else Error (Errx.Quote_invalid ("inner size " ^ string_of_int v))

(* The signature section, in WIRE order. Every read below is bounded by
   the RULE-4 window sec and never by the whole quote, so a small
   signature_data_len makes each "short:" word reachable and no read
   reaches into the surplus. The first window is the 134-byte cert
   header, and the signature, the attestation key, the cert_key_type
   word and the cert_size word come from INSIDE it, where no read can
   fail. The inner type word and the inner size word are ONE six-byte
   window for the same reason. *)
let section_fields (l : layout) (sec : string) (sdl : int) :
    (Signature_section.t, Errx.t) result =
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: cert header")
       (Bytesx.take sec l.hdr_off l.cert_overhead))
  @@ fun (ch : string) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: cert header")
       (Option.bind (Bytesx.take ch l.hdr_off l.signature_len)
          (fun (signature : string) ->
            Option.map
              (fun (attestation_key : string) -> (signature, attestation_key))
              (Bytesx.take ch l.att_key_rel l.att_key_len))))
  @@ fun ((signature : string), (attestation_key : string)) ->
  Result.bind (checked_cert_key_type l ch) @@ fun (cert_key_type : int) ->
  Result.bind (checked_cert_size l ch sdl) @@ fun (cert_size : int) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: qe report")
       (Option.bind (Bytesx.take sec l.qe_report_rel l.qe_report_len)
          (fun (qe_report : string) ->
            Option.map
              (fun (qe_report_data : string) -> (qe_report, qe_report_data))
              (Bytesx.take qe_report l.qe_report_data_rel
                 l.qe_report_data_len))))
  @@ fun ((qe_report : string), (qe_report_data : string)) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: qe signature")
       (Bytesx.take sec l.qe_sig_rel l.qe_sig_len))
  @@ fun (qe_report_signature : string) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: auth size")
       (Bytesx.u16le sec l.auth_size_rel))
  @@ fun (qe_auth_size : int) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: auth data")
       (Bytesx.take sec l.auth_data_rel qe_auth_size))
  @@ fun (qe_auth_data : string) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "short: inner type")
       (Bytesx.take sec (l.auth_data_rel + qe_auth_size) l.inner_hdr_len))
  @@ fun (ihdr : string) ->
  Result.bind (checked_inner_cert_type l ihdr)
  @@ fun (inner_cert_type : int) ->
  Result.bind (checked_inner_size l ihdr cert_size qe_auth_size)
  @@ fun (inner_size : int) ->
  Result.bind
    (Option.to_result
       ~none:(Errx.Quote_invalid "pem chain: no marker at 0")
       (Bytesx.take sec
          (l.auth_data_rel + qe_auth_size + l.inner_hdr_len)
          inner_size))
  @@ fun (pem_window : string) ->
  Result.bind (pem_chain_of l pem_window) @@ fun (pem_chain : string list) ->
  Ok
    {
      Signature_section.signature;
      attestation_key;
      qe_report;
      qe_report_data;
      qe_report_signature;
      qe_auth_data;
      cert_key_type;
      cert_size;
      inner_cert_type;
      inner_size;
      qe_auth_size;
      pem_window;
      pem_chain;
    }

(* ONE Result.bind chain in WIRE order. The FIRST failing check names
   the reason and no later check runs, so the order below is part of
   the contract: version, att_key_type, tee_type, the header window,
   the body window, the signed region, signature_data_len, rule 4, then
   the signature section. Version comes first, so a version-5 quote is
   refused before any byte past offset 2 is read. The surplus is
   RECORDED and never consumed. *)
let parse (quote : string) : (t, Errx.t) result =
  let l = layout () in
  Result.bind (checked_version l quote) @@ fun (version : int) ->
  Result.bind (checked_att_key_type l quote) @@ fun (att_key_type : int) ->
  Result.bind (checked_tee_type l quote) @@ fun (tee_type : int) ->
  Result.bind (header_of l quote version att_key_type tee_type)
  @@ fun (q_header : Header.t) ->
  Result.bind (body_of l quote) @@ fun (q_body : Body.t) ->
  Result.bind (signed_of l quote) @@ fun (q_signed_region : string) ->
  Result.bind (sdl_of l quote) @@ fun (q_signature_data_len : int) ->
  Result.bind (section_window l quote q_signature_data_len)
  @@ fun (sec : string) ->
  Result.bind (section_fields l sec q_signature_data_len)
  @@ fun (q_section : Signature_section.t) ->
  Ok
    {
      q_header;
      q_body;
      q_section;
      q_signed_region;
      q_signature_data_len;
      q_surplus = String.length quote - l.section_off - q_signature_data_len;
    }

let header (q : t) : Header.t = q.q_header
let body (q : t) : Body.t = q.q_body
let signature_section (q : t) : Signature_section.t = q.q_section
let signed_region (q : t) : string = q.q_signed_region
let signature_data_len (q : t) : int = q.q_signature_data_len
let surplus (q : t) : int = q.q_surplus
