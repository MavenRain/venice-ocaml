(* M21 aesx: the FORWARD AES-256 block cipher of FIPS 197, through the
   PUBLIC surface only. The column record, the round steps and the key
   schedule are reached by the entry points that use them: every
   encrypt_block row walks SubBytes, ShiftRows, MixColumns,
   AddRoundKey and the whole Nk = 8 schedule, and every sbox row walks
   the eight masked doublings of gf_mul and the eleven-call inverse
   chain underneath it.

   Every hex constant below is recomputed by harness/diff_gcm.py from
   the INPUTS this file names, by an AES-256 that shares no formula
   with the OCaml unit: the harness builds a log and antilog TABLE over
   the generator 3 and takes the inverse as antilog[255 - log[a]],
   while this unit COMPUTES a^254 through a chain of eleven masked
   multiplications. That harness validates its own S-box and both
   published ciphertexts before it reads a pin, and it requires each
   constant to sit inside a CHECK ROW of this file, not merely
   somewhere in it, and it strips the row LABEL before it searches, so
   a pin moved into a comment, into an unread let or into a row name
   turns the gate RED. Every pin therefore sits INLINE in the boolean
   of its own row.

   The four S-box answers are pinned as OCaml hex literals, 0x63, 0x7c,
   0xed and 0x16, because the surface returns an int and the harness
   writes its needle in that same form.

   The run filter below carries TWO typed wildcards: (_ : string) in
   the filter and (_ : bool) in the printer. No bare wildcard arm
   appears anywhere in this file.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal module by its mangled name, exactly as test_limbsx,
   test_hmacx, test_keccakx, test_p256x and test_secpx do. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module A = Venice__Aesx
module Hx = Venice__Hexx
module B = Venice__Bytesx

(* ---------- readers ---------- *)

(* A strict hex reader: a byte outside the alphabet or an odd length
   gives the empty string, which no length test below accepts. *)
let bytes_of_hex (h : string) : string =
  Option.value ~default:"" (Result.to_option (Hx.decode h))

(* n zero bytes, for the wrong-length rows. of_codes is total. *)
let zeros (n : int) : string = B.of_codes (List.init n (fun (_ : int) -> 0))

(* The one block this unit produces, as lowercase hex. The empty string
   arrives when either surface refuses, and no pinned answer is empty. *)
let enc_hex ~(key : string) ~(block : string) : string =
  Hx.encode
    (Option.value ~default:""
       (Option.bind
          (A.key_of_bytes (bytes_of_hex key))
          (fun (k : A.key) -> A.encrypt_block k (bytes_of_hex block))))

(* A key of n bytes is refused, so key_of_bytes gives None. *)
let key_rejects (n : int) : bool = Option.is_none (A.key_of_bytes (zeros n))

(* A block of n bytes is refused under a WELL FORMED key, so the None
   comes from the block length alone and never from the key. *)
let block_rejects (n : int) : bool =
  Option.fold ~none:false
    ~some:(fun (k : A.key) -> Option.is_none (A.encrypt_block k (zeros n)))
    (A.key_of_bytes (zeros 32))

(* ---------- group (a): the S-box, computed and total ---------- *)

let sbox_checks : (string * bool) list =
  [ ("aesx: the s-box of 0x00 is 0x63", Int.equal (A.sbox 0x00) 0x63);
    ("aesx: the s-box of 0x01 is 0x7c", Int.equal (A.sbox 0x01) 0x7c);
    ("aesx: the s-box of 0x53 is 0xed", Int.equal (A.sbox 0x53) 0xed);
    ("aesx: the s-box of 0xff is 0x16", Int.equal (A.sbox 0xff) 0x16);
    ( "aesx: the s-box masks 0x1ff down to 0xff",
      Int.equal (A.sbox 0x1ff) (A.sbox 0xff) );
    ( "aesx: the s-box masks -1 down to 0xff",
      Int.equal (A.sbox (-1)) (A.sbox 0xff) )
  ]

(* ---------- group (b): the construction lengths ---------- *)

let length_checks : (string * bool) list =
  [ ("aesx: a 16-byte key is None", key_rejects 16);
    ("aesx: a 24-byte key is None", key_rejects 24);
    ("aesx: a 31-byte key is None", key_rejects 31);
    ("aesx: a 33-byte key is None", key_rejects 33);
    ( "aesx: a 32-byte key is Some",
      Option.is_some (A.key_of_bytes (zeros 32)) );
    ("aesx: an empty block is None", block_rejects 0);
    ("aesx: a 15-byte block is None", block_rejects 15);
    ("aesx: a 17-byte block is None", block_rejects 17)
  ]

(* ---------- group (c): the published known answers ---------- *)

let known_answer_checks : (string * bool) list =
  [ ( "aesx: FIPS 197 C.3 encrypts to its published ciphertext",
      String.equal
        (enc_hex
           ~key:
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
           ~block:"00112233445566778899aabbccddeeff")
        "8ea2b7ca516745bfeafc49904b496089" );
    ( "aesx: SP 800-38A F.1.5 block 1 has its published ciphertext",
      String.equal
        (enc_hex
           ~key:
             "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
           ~block:"6bc1bee22e409f96e93d7e117393172a")
        "f3eed1bdb5d2a03c064b5a7e3db181f8" );
    ( "aesx: E_0 of sixteen zero bytes is the GCM case 13 H",
      String.equal
        (enc_hex
           ~key:
             "0000000000000000000000000000000000000000000000000000000000000000"
           ~block:"00000000000000000000000000000000")
        "dc95c078a2408989ad48a21492842087" );
    ( "aesx: the same key and block give the same block twice",
      String.equal
        (enc_hex
           ~key:
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
           ~block:"00112233445566778899aabbccddeeff")
        (enc_hex
           ~key:
             "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
           ~block:"00112233445566778899aabbccddeeff") )
  ]

let () = run (sbox_checks @ length_checks @ known_answer_checks)
