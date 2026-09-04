(* M18 keccakx: keccak-256, the SHA3-256 permutation witness and the
   Ethereum address through the PUBLIC surface only. The private lane
   record, the sponge and the padding are reached by the entrypoints
   that use them: the rate boundaries walk the pad through all three of
   its cases, and the multi-block message walks the fold.

   The hex constants below are recomputed by harness/diff_keccak.py from
   the INPUTS this file holds, by a python keccak whose round constants
   and rho offsets are GENERATED and whose sponge is validated against
   hashlib.sha3_256 before any pin is read. That harness requires each
   constant to sit inside a CHECK ROW of this file, not merely somewhere
   in it, and it strips the row LABEL before it searches, so a pin moved
   into a comment, into an unread let or into a row name turns the gate
   RED. The inputs are built here from byte codes, so an input that
   drifts from the harness turns its row false.

   ascending 0 n emits through Bytesx.of_codes, whose chr_in masks every
   code with land 255, so the messages above 256 bytes are the WRAPPED
   sequence and the harness builds the same bytes.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal module by its mangled name, exactly as test_limbsx
   and test_hmacx do. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module K = Venice__Keccakx
module Hx = Venice__Hexx
module B = Venice__Bytesx

(* ---------- readers ---------- *)

let hex (s : string) : string = Hx.encode s

(* n copies of one byte, and n ascending bytes from first: the inputs
   are written as byte codes, never as hex text, so the suite and the
   oracle agree on the INPUTS by construction. *)
let rep (n : int) (code : int) : string =
  B.of_codes (List.init (Int.max n 0) (fun (_ : int) -> code))

let ascending (first : int) (n : int) : string =
  B.of_codes (List.init (Int.max n 0) (fun (i : int) -> first + i))

let addr_hex_is (o : K.Address.t option) (want : string) : bool =
  Option.fold ~none:false
    ~some:(fun (a : K.Address.t) -> String.equal (K.Address.to_hex a) want)
    o

let addr_ck_is (o : K.Address.t option) (want : string) : bool =
  Option.fold ~none:false
    ~some:(fun (a : K.Address.t) ->
      String.equal (K.Address.to_checksum_hex a) want)
    o

let addr_eq (a : K.Address.t option) (b : K.Address.t option) : bool =
  Option.fold ~none:false
    ~some:(fun (x : K.Address.t) ->
      Option.fold ~none:false ~some:(K.Address.equal x) b)
    a

let addr_differs (a : K.Address.t option) (b : K.Address.t option) : bool =
  Option.fold ~none:false
    ~some:(fun (x : K.Address.t) ->
      Option.fold ~none:false
        ~some:(fun (y : K.Address.t) -> not (K.Address.equal x y))
        b)
    a

(* A rejection row is false when the INPUT is missing, so a broken
   builder cannot make a rejection pass for the wrong reason. *)
let pubkey_rejected (o : string option) : bool =
  Option.fold ~none:false
    ~some:(fun (s : string) -> Option.is_none (K.Address.of_pubkey s))
    o

let bytes_rejected (o : string option) : bool =
  Option.fold ~none:false
    ~some:(fun (s : string) -> Option.is_none (K.Address.of_bytes s))
    o

let ck_round (s : string) : bool =
  Option.fold ~none:false
    ~some:(fun (a : K.Address.t) ->
      String.equal (K.Address.to_checksum_hex a) s)
    (K.Address.of_hex s)

let ck_accepts (s : string) : bool =
  addr_eq (K.Address.of_checksum_hex s) (K.Address.of_hex s)

(* ---------- the message inputs ---------- *)

let a200 : string = rep 200 0xa3

let nist56 : string =
  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"

let m135 : string = ascending 0 135
let m136 : string = ascending 0 136
let m137 : string = ascending 0 137
let m271 : string = ascending 0 271
let m272 : string = ascending 0 272
let m273 : string = ascending 0 273
let m1000 : string = ascending 0 1000

(* ---------- the secp256k1 base point, W4 ---------- *)

let gx_hex : string =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

let gy_hex : string =
  "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

let g_pub : string option = Result.to_option (Hx.decode (gx_hex ^ gy_hex))

let g_pub_prefixed (code : int) : string option =
  Option.map (fun (s : string) -> B.of_codes [ code ] ^ s) g_pub

let g_addr : string option -> K.Address.t option =
 fun (o : string option) -> Option.bind o K.Address.of_pubkey

let g64 : K.Address.t option = g_addr g_pub
let g65 : K.Address.t option = g_addr (g_pub_prefixed 0x04)
let g_raw : string option = Option.map K.Address.to_bytes g64

(* ---------- the checks ---------- *)

let kat_checks : (string * bool) list =
  [ ( "keccakx: keccak-256 of the empty string",
      String.equal (hex (K.hash ""))
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" );
    ( "keccakx: keccak-256 of abc",
      String.equal (hex (K.hash "abc"))
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" );
    ( "keccakx: keccak-256 of hello",
      String.equal (hex (K.hash "hello"))
        "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8" );
    ( "keccakx: keccak-256 of 200 bytes of 0xa3",
      String.equal (hex (K.hash a200))
        "3a57666b048777f2c953dc4456f45a2588e1cb6f2da760122d530ac2ce607d4a" );
    ( "keccakx: keccak-256 of the 56-byte message",
      String.equal (hex (K.hash nist56))
        "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371" )
  ]

let boundary_checks : (string * bool) list =
  [ ( "keccakx: the 135-byte message, the single-byte pad case",
      String.equal (hex (K.hash m135))
        "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62" );
    ( "keccakx: the 136-byte message, one whole extra block",
      String.equal (hex (K.hash m136))
        "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e" );
    ( "keccakx: the 137-byte message, one byte into the second block",
      String.equal (hex (K.hash m137))
        "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db" );
    ( "keccakx: the 271-byte message, the pad case one block later",
      String.equal (hex (K.hash m271))
        "7c974895b2a88303ff2dc6b58f438ceb0b298cac91099ac0539cc0f477506191" );
    ( "keccakx: the 272-byte message, two whole blocks",
      String.equal (hex (K.hash m272))
        "fdf2ec49e749960d3c8521a0219af8d03e30e2b3bf19bd16150ee0eaf133d66e" );
    ( "keccakx: the 273-byte message, one byte into the third block",
      String.equal (hex (K.hash m273))
        "4f707289a9c3ccd0c4a51f2f17339f5dd171d371c04ff7783b735b5b22682eaf" );
    ( "keccakx: the 1000-byte message, the multi-block path",
      String.equal (hex (K.hash m1000))
        "aca79e4146e30eb1c733f6d6060d72471c36ea4e01ebf45d7f4916249c2bbd82" )
  ]

let sha3_checks : (string * bool) list =
  [ ( "keccakx: SHA3-256 of the empty string, the permutation witness",
      String.equal (hex (K.sha3_256 ""))
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" );
    ( "keccakx: SHA3-256 of abc",
      String.equal (hex (K.sha3_256 "abc"))
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532" );
    ( "keccakx: SHA3-256 of 200 bytes of 0xa3",
      String.equal (hex (K.sha3_256 a200))
        "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787" )
  ]

let hex_checks : (string * bool) list =
  [ ( "keccakx: hash_hex of abc is the encoding of hash",
      String.equal (K.hash_hex "abc") (hex (K.hash "abc")) );
    ( "keccakx: hash_hex of the empty string is the encoding of hash",
      String.equal (K.hash_hex "") (hex (K.hash "")) );
    ( "keccakx: the digest of the empty string is 32 bytes",
      Int.equal (String.length (K.hash "")) 32 );
    ( "keccakx: the digest of the 1000-byte message is 32 bytes",
      Int.equal (String.length (K.hash m1000)) 32 )
  ]

let shape_checks : (string * bool) list =
  [ ("keccakx: the sponge rate is 136 bytes", Int.equal (K.rate ()) 136);
    ("keccakx: the digest length is 32 bytes", Int.equal (K.hash_len ()) 32);
    ( "keccakx: hash_hex is 64 characters",
      Int.equal (String.length (K.hash_hex "abc")) 64 );
    ( "keccakx: the SHA3-256 digest is 32 bytes",
      Int.equal (String.length (K.sha3_256 "")) 32 )
  ]

let address_checks : (string * bool) list =
  [ ( "keccakx: the address of the base point from the 64-byte key",
      addr_hex_is g64 "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf" );
    ( "keccakx: the EIP-55 address of the base point",
      addr_ck_is g64 "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" );
    ( "keccakx: the 65-byte uncompressed key gives an equal address",
      addr_eq g64 g65 )
  ]

let pubkey_reject_checks : (string * bool) list =
  [ ( "keccakx: of_pubkey rejects a 63-byte key",
      pubkey_rejected (Option.bind g_pub (fun (s : string) -> B.take s 0 63))
    );
    ( "keccakx: of_pubkey rejects a 65-byte key under the 0x02 prefix",
      pubkey_rejected (g_pub_prefixed 0x02) );
    ( "keccakx: of_pubkey rejects a 65-byte key under the 0x03 prefix",
      pubkey_rejected (g_pub_prefixed 0x03) );
    ( "keccakx: of_pubkey rejects a 66-byte key",
      pubkey_rejected
        (Option.map (fun (s : string) -> B.of_codes [ 0x04; 0x04 ] ^ s) g_pub)
    );
    ( "keccakx: of_pubkey rejects the empty string",
      Option.is_none (K.Address.of_pubkey "") )
  ]

let of_bytes_checks : (string * bool) list =
  [ ( "keccakx: of_bytes of the 20 address bytes round-trips",
      Option.fold ~none:false
        ~some:(fun (raw : string) ->
          Option.fold ~none:false
            ~some:(fun (a : K.Address.t) ->
              String.equal (K.Address.to_bytes a) raw)
            (K.Address.of_bytes raw))
        g_raw );
    ( "keccakx: of_bytes rejects 19 bytes",
      bytes_rejected (Option.bind g_raw (fun (s : string) -> B.take s 0 19)) );
    ( "keccakx: of_bytes rejects 21 bytes",
      bytes_rejected
        (Option.map (fun (s : string) -> s ^ B.of_codes [ 0x00 ]) g_raw) );
    ( "keccakx: of_bytes rejects the empty string",
      Option.is_none (K.Address.of_bytes "") )
  ]

let of_hex_checks : (string * bool) list =
  [ ( "keccakx: of_hex reads the 0x-prefixed address",
      addr_eq g64
        (K.Address.of_hex "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") );
    ( "keccakx: of_hex reads the 0X-prefixed address",
      addr_eq g64
        (K.Address.of_hex "0X7e5f4552091a69125d5dfcb7b8c2659029395bdf") );
    ( "keccakx: of_hex reads the bare 40-character address",
      addr_eq g64
        (K.Address.of_hex "7e5f4552091a69125d5dfcb7b8c2659029395bdf") );
    ( "keccakx: of_hex reads the all-uppercase address",
      addr_eq g64
        (K.Address.of_hex "7E5F4552091A69125D5DFCB7B8C2659029395BDF") );
    ( "keccakx: of_hex reads the EIP-55 mixed-case address",
      addr_eq g64
        (K.Address.of_hex "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf") );
    ( "keccakx: of_hex rejects 39 characters",
      Option.is_none
        (K.Address.of_hex "7e5f4552091a69125d5dfcb7b8c2659029395bd") );
    ( "keccakx: of_hex rejects 41 characters",
      Option.is_none
        (K.Address.of_hex "7e5f4552091a69125d5dfcb7b8c2659029395bdff") );
    ( "keccakx: of_hex rejects 42 characters with no prefix",
      Option.is_none
        (K.Address.of_hex "7e5f4552091a69125d5dfcb7b8c2659029395bdfff") );
    ( "keccakx: of_hex rejects a prefix over 38 characters",
      Option.is_none
        (K.Address.of_hex "0x7e5f4552091a69125d5dfcb7b8c2659029395b") );
    ( "keccakx: of_hex rejects a byte outside the alphabet",
      Option.is_none
        (K.Address.of_hex "7e5f4552091a69125d5dfcb7b8c2659029395bdg") );
    ( "keccakx: of_hex rejects the empty string",
      Option.is_none (K.Address.of_hex "") )
  ]

let checksum_checks : (string * bool) list =
  [ ( "keccakx: EIP-55 reference 1 is its own checksum form",
      ck_round "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" );
    ( "keccakx: EIP-55 reference 2 is its own checksum form",
      ck_round "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359" );
    ( "keccakx: EIP-55 reference 3 is its own checksum form",
      ck_round "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB" );
    ( "keccakx: EIP-55 reference 4 is its own checksum form",
      ck_round "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb" );
    ( "keccakx: EIP-55 reference 5 is its own checksum form",
      ck_round "0x52908400098527886E0F7030069857D2E4169EE7" );
    ( "keccakx: EIP-55 reference 6 is its own checksum form",
      ck_round "0x8617E340B3D01FA5F11F306F4090FD50E238070D" );
    ( "keccakx: EIP-55 reference 7 is its own checksum form",
      ck_round "0xde709f2102306220921060314715629080e2fb77" );
    ( "keccakx: EIP-55 reference 8 is its own checksum form",
      ck_round "0x27b1fdb04752bbc536007a920d24acb045561c26" );
    ( "keccakx: of_checksum_hex accepts reference 1",
      ck_accepts "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" );
    ( "keccakx: of_checksum_hex accepts the bare 40-character checksummed body",
      ck_accepts "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" );
    ( "keccakx: of_checksum_hex accepts reference 2",
      ck_accepts "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359" );
    ( "keccakx: of_checksum_hex accepts reference 3",
      ck_accepts "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB" );
    ( "keccakx: of_checksum_hex accepts reference 4",
      ck_accepts "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb" );
    ( "keccakx: of_checksum_hex accepts reference 5",
      ck_accepts "0x52908400098527886E0F7030069857D2E4169EE7" );
    ( "keccakx: of_checksum_hex accepts reference 6",
      ck_accepts "0x8617E340B3D01FA5F11F306F4090FD50E238070D" );
    ( "keccakx: of_checksum_hex accepts reference 7",
      ck_accepts "0xde709f2102306220921060314715629080e2fb77" );
    ( "keccakx: of_checksum_hex accepts reference 8",
      ck_accepts "0x27b1fdb04752bbc536007a920d24acb045561c26" );
    ( "keccakx: of_checksum_hex rejects a flipped first letter",
      Option.is_none
        (K.Address.of_checksum_hex
           "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed") );
    ( "keccakx: of_checksum_hex rejects a flipped last letter",
      Option.is_none
        (K.Address.of_checksum_hex
           "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD") );
    ( "keccakx: of_checksum_hex accepts the all-lowercase form",
      Option.is_some
        (K.Address.of_checksum_hex
           "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed") );
    ( "keccakx: of_checksum_hex accepts the all-uppercase form",
      Option.is_some
        (K.Address.of_checksum_hex
           "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED") )
  ]

let equal_checks : (string * bool) list =
  [ ( "keccakx: two constructions of the base point address are equal",
      addr_eq g64
        (K.Address.of_hex "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf") );
    ( "keccakx: the base point address differs from reference 2",
      addr_differs g64
        (K.Address.of_hex "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359") )
  ]

let () =
  run
    (kat_checks @ boundary_checks @ sha3_checks @ hex_checks @ shape_checks
   @ address_checks @ pubkey_reject_checks @ of_bytes_checks @ of_hex_checks
   @ checksum_checks @ equal_checks)
