(* derx: the TDX attestation CERTIFICATE unit (M26, DESIGN.md:406). It
   is the FOURTH module of the attestation tower: quotex DECODES the
   bytes, policyx DECIDES on the body, sigx PROVES the signature
   section and this unit PROVES the PCK certificate chain. It is pure
   and sans-io: no mutable byte store, no vector, no reference cell, no
   exception path, no division and no remainder. Every window comes
   from Bytesx.take and every byte from Bytesx.u8, so a short window
   answers None and nothing escapes.

   THE LAYOUT RECORD, the ONE record below. It holds every tag byte,
   every OID content string, every bound the reader needs and the 659
   pinned bytes of the Intel SGX Root CA. It is built ONCE by
   layout () and passed FIRST to every helper that reads a literal, so
   no literal sits outside the body of layout () and no helper reads a
   top-level constant (ZxCaml trap 2, ZXCAML.md:18-20). No top-level
   alias of a Bytesx, a B64x, a P256x or an Errx binding exists. This
   unit applies no functor and holds no Map.

   THE CHECK ORDER inside verify_chain, where the reason names the
   FIRST failure:

     1   the list holds exactly three blocks, "chain length"
     2   each block is cut to its PEM body and decoded ONCE through
         the standard base64 unit, "der"
     3   the DER of block 3 equals the pinned root bytes, "root pin"
     4   each block parses under the subset, in list order, which names
         "der", "version", "signature algorithm", "public key" or
         "critical extension"
     5   now sits inside each validity window, in list order,
         "not yet valid" before "expired"
     6   the two Name compares, "issuer"
     7   the basicConstraints cA flags, "ca"
     8   the keyUsage bits, "key usage"
     9   the leaf SGX extension, "sgx extension"
     10  the leaf under the intermediate key, "leaf signature
         mismatch", then the intermediate under the root key, "ca
         signature mismatch"

   The root's OWN signature is NEVER verified. Step 3 pins the root
   byte for byte, which is stronger than a self-verify and needs no
   curve arithmetic.

   The reason vocabulary is CLOSED at FIFTEEN words and every rejection
   is one Errx.Cert_invalid, which Errx.to_string prints under
   "cert: ". The P-256 message verifier runs exactly twice and hashes
   the message itself, so this unit names no hash module at all. Every
   compare is String.equal on PUBLIC bytes. *)

type layout = {
  tag_boolean : int;
  tag_integer : int;
  tag_bit_string : int;
  tag_octet_string : int;
  tag_null : int;
  tag_oid : int;
  tag_enumerated : int;
  tag_printable_string : int;
  tag_utf8_string : int;
  tag_utc_time : int;
  tag_gen_time : int;
  tag_sequence : int;
  tag_set : int;
  tag_ctx0 : int;
  tag_ctx3 : int;
  long_form : int;
  max_len_bytes : int;
  max_depth : int;
  chain_len : int;
  point_len : int;
  point_lead : int;
  utc_len : int;
  gen_len : int;
  digits_len : int;
  year_pivot : int;
  digit_lo : int;
  digit_hi : int;
  zone_byte : int;
  ten : int;
  byte_base : int;
  zero : int;
  one : int;
  two : int;
  idx_issuer : int;
  idx_validity : int;
  idx_subject : int;
  idx_spki : int;
  idx_exts : int;
  off_month : int;
  off_day : int;
  off_hour : int;
  off_min : int;
  off_sec : int;
  month_lo : int;
  month_hi : int;
  day_lo : int;
  day_hi : int;
  hour_hi : int;
  minsec_hi : int;
  century_low : string;
  century_high : string;
  serial_min : int;
  serial_max : int;
  version_v3 : string;
  boolean_true : string;
  ku_digital_signature : int;
  ku_key_cert_sign : int;
  fmspc_len : int;
  pce_id_len : int;
  cpusvn_len : int;
  tcb_count : int;
  begin_marker : string;
  end_marker : string;
  newline : string;
  oid_ecdsa_sha256 : string;
  oid_ec_public_key : string;
  oid_prime256v1 : string;
  oid_basic_constraints : string;
  oid_key_usage : string;
  oid_authority_key_id : string;
  oid_subject_key_id : string;
  oid_crl_distribution : string;
  oid_sgx : string;
  sgx_ppid : string;
  sgx_tcb : string;
  sgx_pce_id : string;
  sgx_fmspc : string;
  sgx_type : string;
  sgx_platform_instance : string;
  sgx_configuration : string;
  sgx_pcesvn : string;
  sgx_cpusvn : string;
  root_der : string;
}

(* One TLV header: the tag byte, the header size and the CONTENT
   length. *)
type header = { h_tag : int; h_size : int; h_len : int }

(* One TLV element inside a buffer: the tag, the ELEMENT offset, the
   ELEMENT size, the CONTENT offset and the CONTENT length. *)
type node = {
  n_tag : int;
  n_off : int;
  n_size : int;
  n_body : int;
  n_len : int;
}

(* One X.509 extension: the OID content bytes, the critical flag and
   the extnValue OCTET STRING content. *)
type ext = { x_oid : string; x_critical : bool; x_value : string }

(* The Intel SGX PCK extension values M27 consumes. *)
type sgx_values = {
  s_cpusvn : string;
  s_pcesvn : int;
  s_fmspc : string;
  s_pce_id : string;
  s_components : int list;
}

(* One parsed certificate. *)
type cert = {
  c_der : string;
  c_tbs : string;
  c_serial : string;
  c_issuer : string;
  c_subject : string;
  c_not_before : string;
  c_not_after : string;
  c_public_key : P256x.Pubkey.t;
  c_sig_r : string;
  c_sig_s : string;
  c_is_ca : bool;
  c_key_cert_sign : bool;
  c_digital_signature : bool;
  c_sgx : sgx_values option;
}

(* The witness a successful verify_chain mints. *)
type witness = {
  w_leaf : cert;
  w_inter : cert;
  w_root : cert;
  w_sgx : sgx_values;
}

type t = witness

(* The ONE record, built once. Every literal of the unit sits inside
   this body: the fifteen accepted tag bytes and the four constructed
   ones, the long-form mask 0x80 which is also the short-form bound,
   the length-byte and depth bounds, the expected chain length, the
   SEC 1 point size and its lead byte, the two time lengths and the
   RFC 5280 pivot, the ASCII digit bounds and the zone byte, the
   header arithmetic constants and the byte base, the two PEM markers
   and the newline, the nine X.509 OID strings, the nine Intel SGX
   sub-OID strings, and the 659 pinned bytes of the Intel SGX Root
   CA. The pin travels as RAW bytes, so it is decoded ZERO times and
   compared ONCE. *)
let layout (() : unit) : layout =
  {
    tag_boolean = 0x01;
    tag_integer = 0x02;
    tag_bit_string = 0x03;
    tag_octet_string = 0x04;
    tag_null = 0x05;
    tag_oid = 0x06;
    tag_enumerated = 0x0a;
    tag_printable_string = 0x13;
    tag_utf8_string = 0x0c;
    tag_utc_time = 0x17;
    tag_gen_time = 0x18;
    tag_sequence = 0x30;
    tag_set = 0x31;
    tag_ctx0 = 0xa0;
    tag_ctx3 = 0xa3;
    long_form = 0x80;
    max_len_bytes = 2;
    max_depth = 16;
    chain_len = 3;
    point_len = 65;
    point_lead = 0x04;
    utc_len = 13;
    gen_len = 15;
    digits_len = 14;
    year_pivot = 50;
    digit_lo = 0x30;
    digit_hi = 0x39;
    zone_byte = 0x5a;
    ten = 10;
    byte_base = 256;
    zero = 0;
    one = 1;
    two = 2;
    idx_issuer = 3;
    idx_validity = 4;
    idx_subject = 5;
    idx_spki = 6;
    idx_exts = 7;
    off_month = 4;
    off_day = 6;
    off_hour = 8;
    off_min = 10;
    off_sec = 12;
    month_lo = 1;
    month_hi = 12;
    day_lo = 1;
    day_hi = 31;
    hour_hi = 23;
    minsec_hi = 59;
    century_low = "19";
    century_high = "20";
    serial_min = 1;
    serial_max = 21;
    version_v3 = "\x02";
    boolean_true = "\xff";
    ku_digital_signature = 0x80;
    ku_key_cert_sign = 0x04;
    fmspc_len = 6;
    pce_id_len = 2;
    cpusvn_len = 16;
    tcb_count = 16;
    begin_marker = "-----BEGIN CERTIFICATE-----";
    end_marker = "-----END CERTIFICATE-----";
    newline = "\r\n";
    oid_ecdsa_sha256 = "\x2a\x86\x48\xce\x3d\x04\x03\x02";
    oid_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01";
    oid_prime256v1 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
    oid_basic_constraints = "\x55\x1d\x13";
    oid_key_usage = "\x55\x1d\x0f";
    oid_authority_key_id = "\x55\x1d\x23";
    oid_subject_key_id = "\x55\x1d\x0e";
    oid_crl_distribution = "\x55\x1d\x1f";
    oid_sgx = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01";
    sgx_ppid = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x01";
    sgx_tcb = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x02";
    sgx_pce_id = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x03";
    sgx_fmspc = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x04";
    sgx_type = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x05";
    sgx_platform_instance = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x06";
    sgx_configuration = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x07";
    sgx_pcesvn = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x02\x11";
    sgx_cpusvn = "\x2a\x86\x48\x86\xf8\x4d\x01\x0d\x01\x02\x12";
    root_der =
      "\x30\x82\x02\x8f\x30\x82\x02\x34\xa0\x03\x02\x01\
     \x02\x02\x14\x22\x65\x0c\xd6\x5a\x9d\x34\x89\xf3\
     \x83\xb4\x95\x52\xbf\x50\x1b\x39\x27\x06\xac\x30\
     \x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x30\
     \x68\x31\x1a\x30\x18\x06\x03\x55\x04\x03\x0c\x11\
     \x49\x6e\x74\x65\x6c\x20\x53\x47\x58\x20\x52\x6f\
     \x6f\x74\x20\x43\x41\x31\x1a\x30\x18\x06\x03\x55\
     \x04\x0a\x0c\x11\x49\x6e\x74\x65\x6c\x20\x43\x6f\
     \x72\x70\x6f\x72\x61\x74\x69\x6f\x6e\x31\x14\x30\
     \x12\x06\x03\x55\x04\x07\x0c\x0b\x53\x61\x6e\x74\
     \x61\x20\x43\x6c\x61\x72\x61\x31\x0b\x30\x09\x06\
     \x03\x55\x04\x08\x0c\x02\x43\x41\x31\x0b\x30\x09\
     \x06\x03\x55\x04\x06\x13\x02\x55\x53\x30\x1e\x17\
     \x0d\x31\x38\x30\x35\x32\x31\x31\x30\x34\x35\x31\
     \x30\x5a\x17\x0d\x34\x39\x31\x32\x33\x31\x32\x33\
     \x35\x39\x35\x39\x5a\x30\x68\x31\x1a\x30\x18\x06\
     \x03\x55\x04\x03\x0c\x11\x49\x6e\x74\x65\x6c\x20\
     \x53\x47\x58\x20\x52\x6f\x6f\x74\x20\x43\x41\x31\
     \x1a\x30\x18\x06\x03\x55\x04\x0a\x0c\x11\x49\x6e\
     \x74\x65\x6c\x20\x43\x6f\x72\x70\x6f\x72\x61\x74\
     \x69\x6f\x6e\x31\x14\x30\x12\x06\x03\x55\x04\x07\
     \x0c\x0b\x53\x61\x6e\x74\x61\x20\x43\x6c\x61\x72\
     \x61\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x0c\x02\
     \x43\x41\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\
     \x02\x55\x53\x30\x59\x30\x13\x06\x07\x2a\x86\x48\
     \xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\
     \x01\x07\x03\x42\x00\x04\x0b\xa9\xc4\xc0\xc0\xc8\
     \x61\x93\xa3\xfe\x23\xd6\xb0\x2c\xda\x10\xa8\xbb\
     \xd4\xe8\x8e\x48\xb4\x45\x85\x61\xa3\x6e\x70\x55\
     \x25\xf5\x67\x91\x8e\x2e\xdc\x88\xe4\x0d\x86\x0b\
     \xd0\xcc\x4e\xe2\x6a\xac\xc9\x88\xe5\x05\xa9\x53\
     \x55\x8c\x45\x3f\x6b\x09\x04\xae\x73\x94\xa3\x81\
     \xbb\x30\x81\xb8\x30\x1f\x06\x03\x55\x1d\x23\x04\
     \x18\x30\x16\x80\x14\x22\x65\x0c\xd6\x5a\x9d\x34\
     \x89\xf3\x83\xb4\x95\x52\xbf\x50\x1b\x39\x27\x06\
     \xac\x30\x52\x06\x03\x55\x1d\x1f\x04\x4b\x30\x49\
     \x30\x47\xa0\x45\xa0\x43\x86\x41\x68\x74\x74\x70\
     \x73\x3a\x2f\x2f\x63\x65\x72\x74\x69\x66\x69\x63\
     \x61\x74\x65\x73\x2e\x74\x72\x75\x73\x74\x65\x64\
     \x73\x65\x72\x76\x69\x63\x65\x73\x2e\x69\x6e\x74\
     \x65\x6c\x2e\x63\x6f\x6d\x2f\x49\x6e\x74\x65\x6c\
     \x53\x47\x58\x52\x6f\x6f\x74\x43\x41\x2e\x64\x65\
     \x72\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\
     \x22\x65\x0c\xd6\x5a\x9d\x34\x89\xf3\x83\xb4\x95\
     \x52\xbf\x50\x1b\x39\x27\x06\xac\x30\x0e\x06\x03\
     \x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x06\
     \x30\x12\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x08\
     \x30\x06\x01\x01\xff\x02\x01\x01\x30\x0a\x06\x08\
     \x2a\x86\x48\xce\x3d\x04\x03\x02\x03\x49\x00\x30\
     \x46\x02\x21\x00\xe5\xbf\xe5\x09\x11\xf9\x2f\x42\
     \x89\x20\xdc\x36\x8a\x30\x2e\xe3\xd1\x2e\xc5\x86\
     \x7f\xf6\x22\xec\x64\x97\xf7\x80\x60\xc1\x3c\x20\
     \x02\x21\x00\xe0\x9d\x25\xac\x7a\x0c\xb3\xe5\xe8\
     \xe6\x8f\xec\x5f\xa3\xbd\x41\x6c\x47\x44\x0b\xd9\
     \x50\x63\x9d\x45\x0e\xdc\xbe\xa4\x57\x6a\xa2";
  }

(* Answers Some () when the test holds, so a test flattens into an
   Option.bind chain and no nested then-branch appears. *)
let want (ok : bool) : unit option = if ok then Some () else None

(* Answers Ok () when the test holds and the reason word otherwise, so
   a test flattens into a Result.bind chain that names its own
   failure. *)
let need (ok : bool) (word : string) : (unit, string) result =
  if ok then Ok () else Error word

(* The fifteen accepted tag bytes, read from the record so no tag
   literal sits outside layout (). *)
let known_tags (l : layout) : int list =
  [
    l.tag_boolean; l.tag_integer; l.tag_bit_string; l.tag_octet_string;
    l.tag_null; l.tag_oid; l.tag_enumerated; l.tag_printable_string;
    l.tag_utf8_string; l.tag_utc_time; l.tag_gen_time; l.tag_sequence;
    l.tag_set; l.tag_ctx0; l.tag_ctx3;
  ]

(* The four tags the walk descends into. *)
let constructed_tags (l : layout) : int list =
  [ l.tag_sequence; l.tag_set; l.tag_ctx0; l.tag_ctx3 ]

(* Membership over a byte list. *)
let has (xs : int list) (v : int) : bool =
  List.exists (fun (x : int) -> Int.equal x v) xs

(* Total list index: None past the end, so no List.nth runs. *)
let rec at (l : layout) (xs : 'a list) (i : int) : 'a option =
  match xs with
  | [] -> None
  | x :: rest -> if Int.equal i l.zero then Some x else at l rest (i - l.one)

(* The first offset at or after i where needle sits inside hay. *)
let rec find_from (l : layout) (hay : string) (needle : string) (i : int) :
    int option =
  match () with
  | () when i + String.length needle > String.length hay -> None
  | ()
    when Option.fold ~none:false
           ~some:(fun (w : string) -> String.equal w needle)
           (Bytesx.take hay i (String.length needle)) ->
      Some i
  | () -> find_from l hay needle (i + l.one)

(* The MINIMAL long form only: one length byte carries 128 or more and
   two length bytes carry 256 or more. Any other count is None, so the
   indefinite form 0x80 and a padded 82 00 05 both fail here. *)
let long_len (l : layout) (s : string) (off : int) (count : int) : int option =
  match () with
  | () when Int.equal count l.one ->
      Option.bind (Bytesx.u8 s (off + l.two)) (fun (b : int) ->
          Option.map (fun (() : unit) -> b) (want (b >= l.long_form)))
  | () when Int.equal count l.two ->
      Option.bind (Bytesx.u8 s (off + l.two)) (fun (hi : int) ->
          Option.bind (Bytesx.u8 s (off + l.two + l.one)) (fun (lo : int) ->
              let v = (hi * l.byte_base) + lo in
              Option.map (fun (() : unit) -> v) (want (v >= l.byte_base))))
  | () -> None

(* One TLV header at off. The tag must be one of the fifteen and the
   length must be definite and minimal. *)
let read_header (l : layout) (s : string) (off : int) : header option =
  Option.bind (Bytesx.u8 s off) (fun (tag : int) ->
      Option.bind (want (has (known_tags l) tag)) (fun (() : unit) ->
          Option.bind (Bytesx.u8 s (off + l.one)) (fun (b : int) ->
              match () with
              | () when b < l.long_form ->
                  Some { h_tag = tag; h_size = l.two; h_len = b }
              | () when b - l.long_form > l.max_len_bytes -> None
              | () ->
                  Option.map
                    (fun (n : int) ->
                      {
                        h_tag = tag;
                        h_size = l.two + (b - l.long_form);
                        h_len = n;
                      })
                    (long_len l s off (b - l.long_form)))))

(* One element at off, header included. *)
let node_at (l : layout) (s : string) (off : int) : node option =
  Option.bind (read_header l s off) (fun (h : header) ->
      Option.map
        (fun (() : unit) ->
          {
            n_tag = h.h_tag;
            n_off = off;
            n_size = h.h_size + h.h_len;
            n_body = off + h.h_size;
            n_len = h.h_len;
          })
        (want (off + h.h_size + h.h_len <= String.length s)))

(* Every element between off and stop, in wire order. An element that
   overruns stop is None, so a child never escapes its parent. *)
let rec siblings (l : layout) (s : string) (off : int) (stop : int)
    (acc : node list) : node list option =
  match () with
  | () when Int.equal off stop -> Some (List.rev acc)
  | () when off > stop -> None
  | () ->
      Option.bind (node_at l s off) (fun (n : node) ->
          Option.bind (want (n.n_off + n.n_size <= stop)) (fun (() : unit) ->
              siblings l s (off + n.n_size) stop (n :: acc)))

(* The children of one constructed element. *)
let children (l : layout) (s : string) (n : node) : node list option =
  siblings l s n.n_body (n.n_body + n.n_len) []

(* INTEGER content is MINIMAL: at least one byte, and a leading 00 or
   ff only when the byte after it needs the sign. *)
let integer_minimal (l : layout) (s : string) (n : node) : bool =
  match () with
  | () when n.n_len < l.one -> false
  | () when Int.equal n.n_len l.one -> true
  | () ->
      Option.fold ~none:false
        ~some:(fun ((b0 : int), (b1 : int)) ->
          match () with
          | () when Int.equal b0 l.zero -> b1 >= l.long_form
          | () when Int.equal b0 (l.byte_base - l.one) -> b1 < l.long_form
          | () -> true)
        (Option.bind (Bytesx.u8 s n.n_body) (fun (b0 : int) ->
             Option.map
               (fun (b1 : int) -> (b0, b1))
               (Bytesx.u8 s (n.n_body + l.one))))

(* The subset walk. It descends into the four constructed tags only,
   bounds the depth, holds INTEGER to the minimal form and holds
   BOOLEAN to one content byte. It never reads a BOOLEAN VALUE, so a
   cA flag flipped from ff to 00 parses and answers "ca" later. *)
let rec walk (l : layout) (s : string) (n : node) (depth : int) : bool =
  match () with
  | () when depth > l.max_depth -> false
  | () when Int.equal n.n_tag l.tag_integer -> integer_minimal l s n
  | () when Int.equal n.n_tag l.tag_boolean -> Int.equal n.n_len l.one
  | () when has (constructed_tags l) n.n_tag ->
      Option.fold ~none:false
        ~some:(fun (kids : node list) ->
          List.for_all
            (fun (k : node) -> walk l s k (depth + l.one))
            kids)
        (children l s n)
  | () -> true

(* The ONE top element of a buffer, which must cover the whole buffer
   and walk clean. *)
let top_node (l : layout) (s : string) : node option =
  Option.bind (node_at l s l.zero) (fun (n : node) ->
      Option.bind (want (Int.equal n.n_size (String.length s)))
        (fun (() : unit) ->
          Option.map (fun (() : unit) -> n) (want (walk l s n l.zero))))

module Now = struct
  (* Fourteen ASCII digits YYYYMMDDhhmmss. Every value has the same
     length, so String.compare orders two of them correctly. *)
  type t = string

  (* The VALUE of one ASCII digit, None for any other byte, which is
     the A8 digit-byte bound. *)
  let digit_val (l : layout) (s : string) (i : int) : int option =
    Option.bind (Bytesx.u8 s i) (fun (c : int) ->
        Option.map
          (fun (() : unit) -> c - l.digit_lo)
          (want (c >= l.digit_lo && c <= l.digit_hi)))

  (* The value of the two digits at i, base ten. *)
  let two_digits (l : layout) (s : string) (i : int) : int option =
    Option.bind (digit_val l s i) (fun (d0 : int) ->
        Option.map
          (fun (d1 : int) -> (d0 * l.ten) + d1)
          (digit_val l s (i + l.one)))

  let in_range (v : int) (lo : int) (hi : int) : bool = v >= lo && v <= hi

  (* Every byte from i up to stop is an ASCII digit. *)
  let rec digits_from (l : layout) (s : string) (i : int) (stop : int) : bool =
    match () with
    | () when i >= stop -> true
    | () ->
        Option.fold ~none:false
          ~some:(fun ((_ : int)) -> digits_from l s (i + l.one) stop)
          (digit_val l s i)

  (* The D7 ranges. The calendar is NOT read, so 0229 of any year is
     accepted and no leap rule runs. *)
  let of_digits (s : string) : t option =
    let l = layout () in
    Option.bind (want (Int.equal (String.length s) l.digits_len))
      (fun (() : unit) ->
        Option.bind (want (digits_from l s l.zero l.digits_len))
          (fun (() : unit) ->
            Option.bind (two_digits l s l.off_month) (fun (mo : int) ->
                Option.bind (two_digits l s l.off_day) (fun (da : int) ->
                    Option.bind (two_digits l s l.off_hour) (fun (ho : int) ->
                        Option.bind (two_digits l s l.off_min) (fun (mi : int) ->
                            Option.bind (two_digits l s l.off_sec)
                              (fun (se : int) ->
                                Option.map
                                  (fun (() : unit) -> s)
                                  (want
                                     (in_range mo l.month_lo l.month_hi
                                     && in_range da l.day_lo l.day_hi
                                     && in_range ho l.zero l.hour_hi
                                     && in_range mi l.zero l.minsec_hi
                                     && in_range se l.zero l.minsec_hi)))))))))

  (* UTCTime YYMMDDhhmmssZ. The RFC 5280 4.1.2.5.1 pivot: a two-digit
     year below 50 mints 20YY and 50 or above mints 19YY. *)
  let of_utc (s : string) : t option =
    let l = layout () in
    Option.bind (want (Int.equal (String.length s) l.utc_len))
      (fun (() : unit) ->
        Option.bind (Bytesx.u8 s (l.utc_len - l.one)) (fun (z : int) ->
            Option.bind (want (Int.equal z l.zone_byte)) (fun (() : unit) ->
                Option.bind (two_digits l s l.zero) (fun (yy : int) ->
                    Option.bind (Bytesx.take s l.zero (l.utc_len - l.one))
                      (fun (body : string) ->
                        let century =
                          if yy < l.year_pivot then l.century_high
                          else l.century_low
                        in
                        of_digits (century ^ body))))))

  (* GeneralizedTime YYYYMMDDhhmmssZ. A fractional second or a zone
     offset changes the length or the last byte, so both are None. *)
  let of_generalized (s : string) : t option =
    let l = layout () in
    Option.bind (want (Int.equal (String.length s) l.gen_len))
      (fun (() : unit) ->
        Option.bind (Bytesx.u8 s (l.gen_len - l.one)) (fun (z : int) ->
            Option.bind (want (Int.equal z l.zone_byte)) (fun (() : unit) ->
                Option.bind (Bytesx.take s l.zero (l.gen_len - l.one))
                  (fun (body : string) -> of_digits body))))

  let compare (a : t) (b : t) : int = String.compare a b
  let to_string (v : t) : string = v
end

(* The whole ELEMENT of a node, header included. *)
let elem_bytes (s : string) (n : node) : string option =
  Bytesx.take s n.n_off n.n_size

(* The CONTENT of a node. *)
let body_bytes (s : string) (n : node) : string option =
  Bytesx.take s n.n_body n.n_len

(* The i-th child, which must carry the expected tag. *)
let tagged (l : layout) (xs : node list) (i : int) (tag : int) : node option =
  Option.bind (at l xs i) (fun (n : node) ->
      Option.map (fun (() : unit) -> n) (want (Int.equal n.n_tag tag)))

(* Membership over a list of OID content strings. *)
let has_str (xs : string list) (v : string) : bool =
  List.exists (fun (x : string) -> String.equal x v) xs

(* The OID content bytes of the first child of an AlgorithmIdentifier.
   The OID is compared as RAW CONTENT, so no base-128 decode runs. *)
let first_oid (l : layout) (s : string) (n : node) : string option =
  Option.bind (children l s n) (fun (kids : node list) ->
      Option.bind (tagged l kids l.zero l.tag_oid) (fun (o : node) ->
          body_bytes s o))

(* A non-negative INTEGER as an int. A first byte at or above the long
   form is a NEGATIVE integer and answers None. *)
let rec int_of_bytes (l : layout) (buf : string) (i : int) (stop : int)
    (acc : int) : int option =
  match () with
  | () when i >= stop -> Some acc
  | () ->
      Option.bind (Bytesx.u8 buf i) (fun (b : int) ->
          int_of_bytes l buf (i + l.one) stop ((acc * l.byte_base) + b))

let int_value (l : layout) (buf : string) (n : node) : int option =
  Option.bind (want (Int.equal n.n_tag l.tag_integer)) (fun (() : unit) ->
      Option.bind (want (integer_minimal l buf n)) (fun (() : unit) ->
          Option.bind (Bytesx.u8 buf n.n_body) (fun (b0 : int) ->
              Option.bind (want (b0 < l.long_form)) (fun (() : unit) ->
                  int_of_bytes l buf n.n_body (n.n_body + n.n_len) l.zero))))

(* An OCTET STRING of an expected content length. *)
let octet_value (l : layout) (buf : string) (n : node) (len : int) :
    string option =
  Option.bind (want (Int.equal n.n_tag l.tag_octet_string)) (fun (() : unit) ->
      Option.bind (want (Int.equal n.n_len len)) (fun (() : unit) ->
          body_bytes buf n))

(* One Extension: the OID, the critical BOOLEAN when it is present, and
   the extnValue OCTET STRING content. *)
let read_ext (l : layout) (s : string) (n : node) : ext option =
  Option.bind (children l s n) (fun (kids : node list) ->
      Option.bind (tagged l kids l.zero l.tag_oid) (fun (o : node) ->
          Option.bind (body_bytes s o) (fun (oid : string) ->
              let crit = tagged l kids l.one l.tag_boolean in
              let flag =
                Option.fold ~none:false
                  ~some:(fun (b : node) ->
                    Option.fold ~none:false
                      ~some:(fun (v : string) -> String.equal v l.boolean_true)
                      (body_bytes s b))
                  crit
              in
              let value_at =
                Option.fold ~none:l.one ~some:(fun ((_ : node)) -> l.two) crit
              in
              Option.bind (tagged l kids value_at l.tag_octet_string)
                (fun (v : node) ->
                  Option.map
                    (fun (bytes : string) ->
                      { x_oid = oid; x_critical = flag; x_value = bytes })
                    (body_bytes s v)))))

(* The extension list of a tbsCertificate, from the a3 wrapper. *)
let read_exts (l : layout) (s : string) (n : node) : ext list option =
  Option.bind (children l s n) (fun (kids : node list) ->
      Option.bind (tagged l kids l.zero l.tag_sequence) (fun (seq : node) ->
          Option.bind (children l s seq) (fun (items : node list) ->
              List.fold_left
                (fun (acc : ext list option) (it : node) ->
                  Option.bind acc (fun (xs : ext list) ->
                      Option.map
                        (fun (x : ext) -> xs @ [ x ])
                        (read_ext l s it)))
                (Some []) items)))

(* The six extension OIDs this unit reads. Any OTHER extension marked
   critical is the "critical extension" rejection. *)
let known_ext_oids (l : layout) : string list =
  [
    l.oid_basic_constraints; l.oid_key_usage; l.oid_authority_key_id;
    l.oid_subject_key_id; l.oid_crl_distribution; l.oid_sgx;
  ]

let find_ext (xs : ext list) (oid : string) : ext option =
  List.find_opt (fun (x : ext) -> String.equal x.x_oid oid) xs

(* basicConstraints cA. The BOOLEAN VALUE is read HERE and not in the
   walk, so a cA flag flipped from ff to 00 parses and answers "ca". *)
let ca_flag (l : layout) (x : ext) : bool =
  Option.fold ~none:false
    ~some:(fun (n : node) ->
      Option.fold ~none:false
        ~some:(fun (kids : node list) ->
          Option.fold ~none:false
            ~some:(fun (b : node) ->
              Option.fold ~none:false
                ~some:(fun (v : string) -> String.equal v l.boolean_true)
                (body_bytes x.x_value b))
            (tagged l kids l.zero l.tag_boolean))
        (children l x.x_value n))
    (top_node l x.x_value)

(* One keyUsage bit. The BIT STRING content starts with the unused-bit
   count, so the mask byte sits one byte after it. *)
let ku_bit (l : layout) (x : ext) (mask : int) : bool =
  Option.fold ~none:false
    ~some:(fun (n : node) ->
      Option.fold ~none:false
        ~some:(fun (b : int) -> Int.equal (b land mask) mask)
        (Bytesx.u8 x.x_value (n.n_body + l.one)))
    (top_node l x.x_value)

(* The seven Intel SGX sub-OIDs of the extension body. An eighth one
   is unknown and the whole extension answers None. *)
let known_sgx_oids (l : layout) : string list =
  [
    l.sgx_ppid; l.sgx_tcb; l.sgx_pce_id; l.sgx_fmspc; l.sgx_type;
    l.sgx_platform_instance; l.sgx_configuration;
  ]

(* One SGX pair: the OID content bytes and the VALUE node beside it. *)
let sgx_pair (l : layout) (buf : string) (n : node) : (string * node) option =
  Option.bind (want (Int.equal n.n_tag l.tag_sequence)) (fun (() : unit) ->
      Option.bind (children l buf n) (fun (kids : node list) ->
          Option.bind (tagged l kids l.zero l.tag_oid) (fun (o : node) ->
              Option.bind (body_bytes buf o) (fun (oid : string) ->
                  Option.map (fun (v : node) -> (oid, v)) (at l kids l.one)))))

(* Every pair under one SGX SEQUENCE, in wire order. *)
let sgx_pairs (l : layout) (buf : string) (n : node) :
    (string * node) list option =
  Option.bind (children l buf n) (fun (kids : node list) ->
      List.fold_left
        (fun (acc : (string * node) list option) (k : node) ->
          Option.bind acc (fun (xs : (string * node) list) ->
              Option.map
                (fun (p : string * node) -> xs @ [ p ])
                (sgx_pair l buf k)))
        (Some []) kids)

(* Lookup BY OID, never by position. *)
let pair_find (xs : (string * node) list) (oid : string) : node option =
  Option.map
    (fun (((_ : string), (v : node)) : string * node) -> v)
    (List.find_opt
       (fun (((o : string), (_ : node)) : string * node) -> String.equal o oid)
       xs)

(* The Intel SGX PCK extension, OID 1.2.840.113741.1.13.1. Every value
   is found BY its OID, so a reordered extension still reads. The TCB
   components are the INTEGER-valued pairs of the .2 SEQUENCE that are
   not the PCESVN, in wire order, and there must be sixteen. *)
let read_sgx (l : layout) (x : ext) : sgx_values option =
  let buf = x.x_value in
  Option.bind (top_node l buf) (fun (n : node) ->
      Option.bind (sgx_pairs l buf n) (fun (top : (string * node) list) ->
          Option.bind
            (want
               (List.for_all
                  (fun (((o : string), (_ : node)) : string * node) ->
                    has_str (known_sgx_oids l) o)
                  top))
            (fun (() : unit) ->
              Option.bind (pair_find top l.sgx_pce_id) (fun (pn : node) ->
                  Option.bind (octet_value l buf pn l.pce_id_len)
                    (fun (pce_id : string) ->
                      Option.bind (pair_find top l.sgx_fmspc) (fun (fn : node) ->
                          Option.bind (octet_value l buf fn l.fmspc_len)
                            (fun (fmspc : string) ->
                              Option.bind (pair_find top l.sgx_tcb)
                                (fun (tn : node) ->
                                  Option.bind (sgx_pairs l buf tn)
                                    (fun (tcb : (string * node) list) ->
                                      Option.bind (pair_find tcb l.sgx_pcesvn)
                                        (fun (sn : node) ->
                                          Option.bind (int_value l buf sn)
                                            (fun (pcesvn : int) ->
                                              Option.bind
                                                (pair_find tcb l.sgx_cpusvn)
                                                (fun (cn : node) ->
                                                  Option.bind
                                                    (octet_value l buf cn
                                                       l.cpusvn_len)
                                                    (fun (cpusvn : string) ->
                                                      let comps =
                                                        List.filter_map
                                                          (fun
                                                            (((o : string),
                                                               (v : node))
                                                              : string * node)
                                                          ->
                                                            Option.bind
                                                              (want
                                                                 (not
                                                                    (String
                                                                     .equal o
                                                                       l.sgx_pcesvn)))
                                                              (fun (() : unit) ->
                                                                Option.bind
                                                                  (want
                                                                     (Int.equal
                                                                        v.n_tag
                                                                        l.tag_integer))
                                                                  (fun
                                                                    (() : unit)
                                                                  ->
                                                                    int_value l
                                                                      buf v)))
                                                          tcb
                                                      in
                                                      Option.map
                                                        (fun (() : unit) ->
                                                          {
                                                            s_cpusvn = cpusvn;
                                                            s_pcesvn = pcesvn;
                                                            s_fmspc = fmspc;
                                                            s_pce_id = pce_id;
                                                            s_components =
                                                              comps;
                                                          })
                                                        (want
                                                           (Int.equal
                                                              (List.length comps)
                                                              l.tcb_count)))))))))))))))

(* One validity time, from its own tag. *)
let read_time (l : layout) (s : string) (n : node) : Now.t option =
  Option.bind (body_bytes s n) (fun (v : string) ->
      match () with
      | () when Int.equal n.n_tag l.tag_utc_time -> Now.of_utc v
      | () when Int.equal n.n_tag l.tag_gen_time -> Now.of_generalized v
      | () -> None)

(* The SEC 1 point of a SubjectPublicKeyInfo BIT STRING: one zero
   unused-bit byte, then 65 bytes that start with 04. *)
let read_point (l : layout) (s : string) (n : node) : string option =
  Option.bind (want (Int.equal n.n_tag l.tag_bit_string)) (fun (() : unit) ->
      Option.bind (want (Int.equal n.n_len (l.point_len + l.one)))
        (fun (() : unit) ->
          Option.bind (Bytesx.u8 s n.n_body) (fun (pad : int) ->
              Option.bind (want (Int.equal pad l.zero)) (fun (() : unit) ->
                  Option.bind (Bytesx.take s (n.n_body + l.one) l.point_len)
                    (fun (pt : string) ->
                      Option.bind (Bytesx.u8 pt l.zero) (fun (lead : int) ->
                          Option.map
                            (fun (() : unit) -> pt)
                            (want (Int.equal lead l.point_lead))))))))

(* A signature INTEGER must be non-negative before its DER sign byte
   is stripped and its magnitude is handed to the unsigned scalar reader.
   The enclosing walk has already checked minimal INTEGER encoding. *)
let signature_integer (l : layout) (s : string) (n : node) : string option =
  Option.bind (Bytesx.u8 s n.n_body) (fun (b0 : int) ->
      Option.bind (want (b0 < l.long_form)) (fun (() : unit) ->
          body_bytes s n))

(* The non-negative r and s INTEGER CONTENT bytes of a signatureValue
   BIT STRING, the sign byte still in place. *)
let read_rs (l : layout) (s : string) (n : node) : (string * string) option =
  Option.bind (want (Int.equal n.n_tag l.tag_bit_string)) (fun (() : unit) ->
      Option.bind (Bytesx.u8 s n.n_body) (fun (pad : int) ->
          Option.bind (want (Int.equal pad l.zero)) (fun (() : unit) ->
              Option.bind
                (Bytesx.take s (n.n_body + l.one) (n.n_len - l.one))
                (fun (inner : string) ->
                  Option.bind (top_node l inner) (fun (seq : node) ->
                      Option.bind (want (Int.equal seq.n_tag l.tag_sequence))
                        (fun (() : unit) ->
                          Option.bind (children l inner seq)
                            (fun (rk : node list) ->
                              Option.bind (tagged l rk l.zero l.tag_integer)
                                (fun (rn : node) ->
                                  Option.bind (tagged l rk l.one l.tag_integer)
                                    (fun (sn : node) ->
                                      Option.bind (signature_integer l inner rn)
                                        (fun (r : string) ->
                                          Option.map
                                            (fun (sv : string) -> (r, sv))
                                            (signature_integer l inner sn)))))))))))

(* Strips the DER sign byte, which P256x.Signature.of_rs refuses. *)
let strip_sign (l : layout) (v : string) : string option =
  Option.fold ~none:(Some v)
    ~some:(fun ((_ : unit)) ->
      Bytesx.take v l.one (String.length v - l.one))
    (Option.bind (Bytesx.u8 v l.zero) (fun (b0 : int) ->
         want (Int.equal b0 l.zero && String.length v > l.one)))

(* Cuts ONE PEM block to its body and decodes it ONCE. The body runs
   from just after the BEGIN marker to the FIRST byte of the END
   marker, so every byte after END is DISCARDED. A block with no
   BEGIN, with no END or with an empty body answers "der", and so does
   a body the base64 decoder refuses. CRLF, LF and CR line endings are
   removed before the strict base64 decode. *)
let pem_der (l : layout) (block : string) : (string, string) result =
  Result.bind
    (Option.to_result ~none:"der" (find_from l block l.begin_marker l.zero))
  @@ fun (b : int) ->
  let start = b + String.length l.begin_marker in
  Result.bind
    (Option.to_result ~none:"der" (find_from l block l.end_marker start))
  @@ fun (e : int) ->
  Result.bind (Option.to_result ~none:"der" (Bytesx.take block start (e - start)))
  @@ fun (raw : string) ->
  let body =
    String.of_seq
      (Seq.filter
         (fun (c : char) -> not (String.contains l.newline c))
         (String.to_seq raw))
  in
  Result.bind (need (String.length body > l.zero) "der") @@ fun (() : unit) ->
  Result.map_error (fun ((_ : Errx.t)) -> "der") (B64x.decode_std body)

(* ONE certificate under the subset. The reason word names the FIRST
   field that refused: a structural failure is "der", the version, the
   two AlgorithmIdentifiers, the SubjectPublicKeyInfo and an unknown
   critical extension each name themselves. *)
let parse_cert (l : layout) (der : string) : (cert, string) result =
  Result.bind (Option.to_result ~none:"der" (top_node l der))
  @@ fun (top : node) ->
  (* A Certificate is a SEQUENCE and nothing else. The walker accepts a
     SET too, so the outer tag is checked HERE, else a certificate whose
     outer 30 is painted to 31 would still parse. *)
  Result.bind (need (Int.equal top.n_tag l.tag_sequence) "der")
  @@ fun (() : unit) ->
  Result.bind (Option.to_result ~none:"der" (children l der top))
  @@ fun (kids : node list) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l kids l.zero l.tag_sequence))
  @@ fun (tbs_n : node) ->
  Result.bind (Option.to_result ~none:"der" (elem_bytes der tbs_n))
  @@ fun (tbs : string) ->
  Result.bind (Option.to_result ~none:"der" (children l der tbs_n))
  @@ fun (tk : node list) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l kids l.one l.tag_sequence))
  @@ fun (alg_out : node) ->
  Result.bind
    (Option.to_result ~none:"signature algorithm" (first_oid l der alg_out))
  @@ fun (oid_out : string) ->
  Result.bind
    (need (String.equal oid_out l.oid_ecdsa_sha256) "signature algorithm")
  @@ fun (() : unit) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l kids l.two l.tag_bit_string))
  @@ fun (sig_n : node) ->
  Result.bind (Option.to_result ~none:"der" (read_rs l der sig_n))
  @@ fun (((sig_r : string), (sig_s : string)) : string * string) ->
  Result.bind (Option.to_result ~none:"version" (tagged l tk l.zero l.tag_ctx0))
  @@ fun (ver_n : node) ->
  Result.bind (Option.to_result ~none:"version" (children l der ver_n))
  @@ fun (vk : node list) ->
  Result.bind
    (Option.to_result ~none:"version" (tagged l vk l.zero l.tag_integer))
  @@ fun (vi : node) ->
  Result.bind (Option.to_result ~none:"version" (body_bytes der vi))
  @@ fun (vb : string) ->
  Result.bind (need (String.equal vb l.version_v3) "version")
  @@ fun (() : unit) ->
  Result.bind (Option.to_result ~none:"der" (tagged l tk l.one l.tag_integer))
  @@ fun (ser_n : node) ->
  Result.bind (Option.to_result ~none:"der" (body_bytes der ser_n))
  @@ fun (serial : string) ->
  Result.bind
    (need
       (String.length serial >= l.serial_min
       && String.length serial <= l.serial_max)
       "der")
  @@ fun (() : unit) ->
  Result.bind (Option.to_result ~none:"der" (tagged l tk l.two l.tag_sequence))
  @@ fun (alg_in : node) ->
  Result.bind
    (Option.to_result ~none:"signature algorithm" (first_oid l der alg_in))
  @@ fun (oid_in : string) ->
  Result.bind
    (need (String.equal oid_in l.oid_ecdsa_sha256) "signature algorithm")
  @@ fun (() : unit) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l tk l.idx_issuer l.tag_sequence))
  @@ fun (iss_n : node) ->
  Result.bind (Option.to_result ~none:"der" (elem_bytes der iss_n))
  @@ fun (issuer : string) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l tk l.idx_subject l.tag_sequence))
  @@ fun (sub_n : node) ->
  Result.bind (Option.to_result ~none:"der" (elem_bytes der sub_n))
  @@ fun (subject : string) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l tk l.idx_validity l.tag_sequence))
  @@ fun (val_n : node) ->
  Result.bind (Option.to_result ~none:"der" (children l der val_n))
  @@ fun (vv : node list) ->
  Result.bind (need (Int.equal (List.length vv) l.two) "der")
  @@ fun (() : unit) ->
  Result.bind (Option.to_result ~none:"der" (at l vv l.zero))
  @@ fun (nb_n : node) ->
  Result.bind (Option.to_result ~none:"der" (at l vv l.one))
  @@ fun (na_n : node) ->
  Result.bind (Option.to_result ~none:"der" (read_time l der nb_n))
  @@ fun (nb : Now.t) ->
  Result.bind (Option.to_result ~none:"der" (read_time l der na_n))
  @@ fun (na : Now.t) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l tk l.idx_spki l.tag_sequence))
  @@ fun (spki : node) ->
  Result.bind (Option.to_result ~none:"public key" (children l der spki))
  @@ fun (sk : node list) ->
  Result.bind
    (Option.to_result ~none:"public key" (tagged l sk l.zero l.tag_sequence))
  @@ fun (kalg : node) ->
  Result.bind (Option.to_result ~none:"public key" (children l der kalg))
  @@ fun (ka : node list) ->
  Result.bind
    (Option.to_result ~none:"public key" (tagged l ka l.zero l.tag_oid))
  @@ fun (ko : node) ->
  Result.bind (Option.to_result ~none:"public key" (body_bytes der ko))
  @@ fun (kob : string) ->
  Result.bind (need (String.equal kob l.oid_ec_public_key) "public key")
  @@ fun (() : unit) ->
  Result.bind
    (Option.to_result ~none:"public key" (tagged l ka l.one l.tag_oid))
  @@ fun (co : node) ->
  Result.bind (Option.to_result ~none:"public key" (body_bytes der co))
  @@ fun (cob : string) ->
  Result.bind (need (String.equal cob l.oid_prime256v1) "public key")
  @@ fun (() : unit) ->
  Result.bind (Option.to_result ~none:"public key" (at l sk l.one))
  @@ fun (bits : node) ->
  Result.bind (Option.to_result ~none:"public key" (read_point l der bits))
  @@ fun (pt : string) ->
  Result.bind (Option.to_result ~none:"public key" (P256x.Pubkey.of_bytes pt))
  @@ fun (pk : P256x.Pubkey.t) ->
  Result.bind
    (Option.to_result ~none:"der" (tagged l tk l.idx_exts l.tag_ctx3))
  @@ fun (ext_n : node) ->
  Result.bind (Option.to_result ~none:"der" (read_exts l der ext_n))
  @@ fun (xs : ext list) ->
  Result.bind
    (need
       (List.for_all
          (fun (x : ext) ->
            (not x.x_critical) || has_str (known_ext_oids l) x.x_oid)
          xs)
       "critical extension")
  @@ fun (() : unit) ->
  let ku = find_ext xs l.oid_key_usage in
  Ok
    {
      c_der = der;
      c_tbs = tbs;
      c_serial = serial;
      c_issuer = issuer;
      c_subject = subject;
      c_not_before = nb;
      c_not_after = na;
      c_public_key = pk;
      c_sig_r = sig_r;
      c_sig_s = sig_s;
      c_is_ca =
        Option.fold ~none:false
          ~some:(fun (x : ext) -> ca_flag l x)
          (find_ext xs l.oid_basic_constraints);
      c_key_cert_sign =
        Option.fold ~none:false
          ~some:(fun (x : ext) -> ku_bit l x l.ku_key_cert_sign)
          ku;
      c_digital_signature =
        Option.fold ~none:false
          ~some:(fun (x : ext) -> ku_bit l x l.ku_digital_signature)
          ku;
      c_sgx =
        Option.bind (find_ext xs l.oid_sgx) (fun (x : ext) -> read_sgx l x);
    }

module Sgx = struct
  type t = sgx_values

  let cpusvn (v : t) : string = v.s_cpusvn
  let pcesvn (v : t) : int = v.s_pcesvn
  let fmspc (v : t) : string = v.s_fmspc
  let pce_id (v : t) : string = v.s_pce_id
  let tcb_components (v : t) : int list = v.s_components
end

module Cert = struct
  type t = cert

  let of_der (bytes : string) : (t, Errx.t) result =
    Result.map_error
      (fun (w : string) -> Errx.Cert_invalid w)
      (parse_cert (layout ()) bytes)

  let of_pem (block : string) : (t, Errx.t) result =
    let l = layout () in
    Result.map_error
      (fun (w : string) -> Errx.Cert_invalid w)
      (Result.bind (pem_der l block) (fun (bytes : string) ->
           parse_cert l bytes))

  let der (c : t) : string = c.c_der
  let tbs (c : t) : string = c.c_tbs
  let serial (c : t) : string = c.c_serial
  let issuer (c : t) : string = c.c_issuer
  let subject (c : t) : string = c.c_subject
  let not_before (c : t) : Now.t = c.c_not_before
  let not_after (c : t) : Now.t = c.c_not_after
  let public_key (c : t) : P256x.Pubkey.t = c.c_public_key
  let signature (c : t) : string * string = (c.c_sig_r, c.c_sig_s)
  let is_ca (c : t) : bool = c.c_is_ca
  let key_cert_sign (c : t) : bool = c.c_key_cert_sign
  let digital_signature (c : t) : bool = c.c_digital_signature
  let sgx (c : t) : Sgx.t option = c.c_sgx
end

(* Returns the 659 pinned bytes of the Intel SGX Root CA, which are the
   bytes of fixtures/collateral/TrustedRootCA.der. A unit function and
   not a top-level constant, because ZxCaml trap 2 makes a top-level
   constant invisible inside a helper. The pin travels as RAW bytes, so
   it is decoded ZERO times and compared ONCE. *)
let root_pin (() : unit) : string = (layout ()).root_der

(* Step 2 of the order: each block is cut to its PEM body and decoded
   ONCE, in list order, so the FIRST block that refuses names "der". *)
let block_ders (l : layout) (blocks : string list) :
    (string list, string) result =
  List.fold_left
    (fun (acc : (string list, string) result) (b : string) ->
      Result.bind acc @@ fun (xs : string list) ->
      Result.map (fun (d : string) -> xs @ [ d ]) (pem_der l b))
    (Ok []) blocks

(* Step 4 of the order: each DER parses under the subset, in list
   order, so the FIRST certificate that refuses names its own word. *)
let parse_all (l : layout) (ders : string list) : (cert list, string) result =
  List.fold_left
    (fun (acc : (cert list, string) result) (d : string) ->
      Result.bind acc @@ fun (xs : cert list) ->
      Result.map (fun (c : cert) -> xs @ [ c ]) (parse_cert l d))
    (Ok []) ders

(* Step 5 of the order for ONE certificate. Both bounds are INCLUSIVE,
   so a now equal to notAfter is valid and one second later is
   "expired". The compare is String.compare over fourteen digits. *)
let in_window (l : layout) (now : Now.t) (c : cert) : (unit, string) result =
  Result.bind (need (Now.compare c.c_not_before now <= l.zero) "not yet valid")
  @@ fun (() : unit) -> need (Now.compare now c.c_not_after <= l.zero) "expired"

(* Step 5 over the whole chain, in list order. *)
let all_windows (l : layout) (now : Now.t) (cs : cert list) :
    (unit, string) result =
  List.fold_left
    (fun (acc : (unit, string) result) (c : cert) ->
      Result.bind acc @@ fun (() : unit) -> in_window l now c)
    (Ok ()) cs

(* The two INTEGER halves of one signatureValue with the DER sign byte
   stripped, which is the 1 to 32 byte form P256x.Signature.of_rs takes.
   A half still longer than 32 bytes answers the leg word and never
   raises, because of_rs returns an option. *)
let signature_of (l : layout) (c : cert) (word : string) :
    (P256x.Signature.t, string) result =
  Option.to_result ~none:word
    (Option.bind (strip_sign l c.c_sig_r) (fun (r : string) ->
         Option.bind (strip_sign l c.c_sig_s) (fun (s : string) ->
             P256x.Signature.of_rs ~r ~s)))

(* The ONE entry, and the ONLY path that mints a witness. Every step is
   a Result.bind, so the reason names the FIRST failure and no later
   step runs. The order is the one the module header states: the count,
   the base64 of each block, the root pin, the parse of each block, the
   validity windows, the two Name compares, the cA flags, the keyUsage
   bits, the leaf SGX extension, and then the two signature legs with
   the LEAF leg first. The message verifier runs EXACTLY TWICE, the
   leaf tbsCertificate under the intermediate key and the intermediate
   tbsCertificate under the root key. The root's OWN signature is NEVER
   verified, because the pin is the anchor. now is a PARAMETER, so this
   unit reads no clock. *)
let verify_chain ~(now : Now.t) (blocks : string list) : (t, Errx.t) result =
  let l = layout () in
  Result.map_error (fun (w : string) -> Errx.Cert_invalid w)
    (Result.bind (need (Int.equal (List.length blocks) l.chain_len) "chain length")
    @@ fun (() : unit) ->
    Result.bind (block_ders l blocks) @@ fun (ders : string list) ->
    Result.bind (Option.to_result ~none:"chain length" (at l ders l.two))
    @@ fun (root_der : string) ->
    Result.bind (need (String.equal root_der l.root_der) "root pin")
    @@ fun (() : unit) ->
    Result.bind (parse_all l ders) @@ fun (cs : cert list) ->
    Result.bind (Option.to_result ~none:"chain length" (at l cs l.zero))
    @@ fun (lf : cert) ->
    Result.bind (Option.to_result ~none:"chain length" (at l cs l.one))
    @@ fun (ca : cert) ->
    Result.bind (Option.to_result ~none:"chain length" (at l cs l.two))
    @@ fun (rt : cert) ->
    Result.bind (all_windows l now cs) @@ fun (() : unit) ->
    Result.bind
      (need
         (String.equal lf.c_issuer ca.c_subject
         && String.equal ca.c_issuer rt.c_subject)
         "issuer")
    @@ fun (() : unit) ->
    Result.bind (need (ca.c_is_ca && rt.c_is_ca && not lf.c_is_ca) "ca")
    @@ fun (() : unit) ->
    Result.bind
      (need
         (ca.c_key_cert_sign && rt.c_key_cert_sign && lf.c_digital_signature)
         "key usage")
    @@ fun (() : unit) ->
    Result.bind (Option.to_result ~none:"sgx extension" lf.c_sgx)
    @@ fun (sv : sgx_values) ->
    Result.bind (signature_of l lf "leaf signature mismatch")
    @@ fun (lf_sig : P256x.Signature.t) ->
    Result.bind
      (need
         (P256x.verify_message ca.c_public_key lf_sig lf.c_tbs)
         "leaf signature mismatch")
    @@ fun (() : unit) ->
    Result.bind (signature_of l ca "ca signature mismatch")
    @@ fun (ca_sig : P256x.Signature.t) ->
    Result.bind
      (need
         (P256x.verify_message rt.c_public_key ca_sig ca.c_tbs)
         "ca signature mismatch")
    @@ fun (() : unit) ->
    Ok { w_leaf = lf; w_inter = ca; w_root = rt; w_sgx = sv })

(* Returns the PCK leaf certificate, block 1. TOTAL. *)
let leaf (w : t) : Cert.t = w.w_leaf

(* Returns the PCK Platform CA certificate, block 2. TOTAL. *)
let intermediate (w : t) : Cert.t = w.w_inter

(* Returns the Intel SGX Root CA certificate, block 3. TOTAL. *)
let root (w : t) : Cert.t = w.w_root

(* Returns the PCK leaf key the chain proved, the key M25 takes as
   ~pck_key. TOTAL. *)
let pck_key (w : t) : P256x.Pubkey.t = w.w_leaf.c_public_key

(* Returns the SGX extension of the leaf. TOTAL. *)
let sgx (w : t) : Sgx.t = w.w_sgx

(* Returns the sixteen TCB component INTEGERs of the leaf. TOTAL. *)
let tcb_components (w : t) : int list = w.w_sgx.s_components

(* Returns the 16 CPUSVN bytes of the leaf. TOTAL. *)
let cpusvn (w : t) : string = w.w_sgx.s_cpusvn

(* Returns the PCE SVN of the leaf. TOTAL. *)
let pcesvn (w : t) : int = w.w_sgx.s_pcesvn

(* Returns the 6 FMSPC bytes of the leaf. TOTAL. *)
let fmspc (w : t) : string = w.w_sgx.s_fmspc

(* Returns the 2 PCE-ID bytes of the leaf. TOTAL. *)
let pce_id (w : t) : string = w.w_sgx.s_pce_id
