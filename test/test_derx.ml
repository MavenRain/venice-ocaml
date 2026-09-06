(* test_derx: the M26 certificate suite (D8 under A13).  It proves the
   DER and X.509 subset, the PCK chain to the pinned Intel SGX Root CA,
   the SGX PCK extension values M27 consumes, the fifteen-word reject
   vocabulary and the check ORDER of derx.

   Every pin is a LITERAL inside the boolean of its own row, so
   harness/diff_quote.py group (i) can require each one to sit inside a
   check row and recompute it from the fixture bytes.

   The painting discipline of D8 holds.  A painted byte reaches the
   unit ONLY through the DECODED DER: the row paints the DER, base64
   encodes it again, wraps it at the 64-character PEM line width and
   hands the rebuilt block back to derx. The length-encoding and
   signature-sign regressions also resize their enclosing elements.
   A painted byte
   then reaches EXACTLY the leg its row names, in the order the module
   header states: the count, the base64 of each block, the root pin,
   the parse of each block, the validity windows, the two Name
   compares, the cA flags, the keyUsage bits, the leaf SGX extension
   and then the leaf leg before the ca leg.

   The run filter below carries TWO typed wildcards, (_ : string) in
   the filter and (_ : bool) in the printer.  No bare wildcard arm
   appears anywhere in this file. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module D = Venice__Derx
module Q = Venice__Quotex
module Sec = Q.Signature_section
module Errx = Venice__Errx
module P = Venice__P256x
module Pk = P.Pubkey
module Sg = P.Signature
module C = Venice.Cursor

let v4 : string = Fixture_der.bytes ()
let root_file : string = Fixture_root.bytes ()
let hex (s : string) : string = Venice.Hex.encode s
let sha (s : string) : string = Venice.Hex.encode (Sha2.Sha256.digest s)

(* A TOTAL window read.  An out-of-range request answers the empty
   string, which makes its row FALSE and never raises. *)
let win (s : string) (off : int) (len : int) : string =
  Option.value ~default:"" (C.take s off len)

(* A TOTAL splice: the bytes of repl overwrite the same count of bytes
   at off and nothing else moves.  Both pieces are bounded by
   Venice.Cursor.take, so an out-of-range request returns the input
   unchanged instead of raising, and no String.sub and no index
   appears. *)
let patch (s : string) (off : int) (repl : string) : string =
  let n = String.length repl in
  Option.value ~default:s
    (Option.bind (C.take s 0 off) (fun (head : string) ->
         Option.map
           (fun (tail : string) -> head ^ repl ^ tail)
           (C.take s (off + n) (String.length s - off - n))))

(* The count of newline bytes, through a total split. *)
let newlines (s : string) : int =
  List.length (String.split_on_char '\n' s) - 1

(* The PEM window of the fixture, which is the ONE input derx reads. *)
let pem_window (() : unit) : string =
  Option.fold ~none:""
    ~some:(fun (q : Q.t) -> Sec.pem_window (Q.signature_section q))
    (Result.to_option (Q.parse v4))

(* The three PEM blocks, leaf first and the pinned root last. *)
let chain (() : unit) : string list =
  Option.fold ~none:[]
    ~some:(fun (q : Q.t) -> Sec.pem_chain (Q.signature_section q))
    (Result.to_option (Q.parse v4))

(* Block i of the chain, or the empty string, which no row accepts. *)
let bl (i : int) : string =
  Option.value ~default:"" (List.nth_opt (chain ()) i)

(* One certificate of the chain, as an option, so every row below reads
   a value that exists only when of_pem succeeded. *)
let cert (i : int) : D.Cert.t option = Result.to_option (D.Cert.of_pem (bl i))

let cert_str (f : D.Cert.t -> string) (i : int) : string =
  Option.fold ~none:"" ~some:f (cert i)

let cert_bool (f : D.Cert.t -> bool) (i : int) : bool =
  Option.fold ~none:false ~some:f (cert i)

let cert_time (f : D.Cert.t -> D.Now.t) (i : int) : string =
  Option.fold ~none:""
    ~some:(fun (c : D.Cert.t) -> D.Now.to_string (f c))
    (cert i)

(* The DER of block i, which is the buffer every paint row edits. *)
let der_of (i : int) : string = cert_str (fun (c : D.Cert.t) -> D.Cert.der c) i

(* The base64 body of a rebuilt block, wrapped at the 64-character PEM
   line width.  Both cuts are bounded by Venice.Cursor.take. *)
let rec wrap64 (s : string) (i : int) : string =
  let left = String.length s - i in
  if left <= 64 then win s i left
  else win s i 64 ^ "\n" ^ wrap64 s (i + 64)

(* ONE PEM block around raw DER bytes, in the shape the fixture uses:
   the 27-byte BEGIN marker, the wrapped body and the 25-byte END
   marker, each on its own line. *)
let block_of (der : string) : string =
  "-----BEGIN CERTIFICATE-----\n"
  ^ wrap64 (Venice.B64.encode_std der) 0
  ^ "\n-----END CERTIFICATE-----\n"

(* Change only the PEM line endings, preserving every base64 byte. *)
let chain_newlines (ending : string) : string list =
  List.map
    (fun (b : string) -> String.concat ending (String.split_on_char '\n' b))
    (chain ())

(* Block i with the bytes of repl painted over the same count of bytes
   at off of its DECODED DER, rebuilt into a PEM block. *)
let paint (i : int) (off : int) (repl : string) : string =
  block_of (patch (der_of i) off repl)

(* The verdict of the whole order as TEXT, so a row pins the reason
   string and never a constructor shape.  "ok" is the accept. *)
let chain_text ~(now : string) (blocks : string list) : string =
  Option.fold ~none:"no now"
    ~some:(fun (n : D.Now.t) ->
      Result.fold
        ~ok:(fun ((_ : D.t)) -> "ok")
        ~error:(fun (e : Errx.t) -> Errx.to_string e)
        (D.verify_chain ~now:n blocks))
    (D.Now.of_digits now)

(* The verdict over the UNPAINTED chain. *)
let good ~(now : string) : string = chain_text ~now (chain ())

(* The witness the good chain mints at the W7 inside witness, as an
   option, so an accessor row reads a value verify_chain proved. *)
let witness (() : unit) : D.t option =
  Option.bind (D.Now.of_digits "20260906000000") (fun (n : D.Now.t) ->
      Result.to_option (D.verify_chain ~now:n (chain ())))

let w_str (f : D.t -> string) : string =
  Option.fold ~none:"" ~some:f (witness ())

let w_int (f : D.t -> int) : int = Option.fold ~none:(-1) ~some:f (witness ())

let w_ints (f : D.t -> int list) : int list =
  Option.fold ~none:[] ~some:f (witness ())

let w_bytes (f : D.t -> Pk.t) : string =
  Option.fold ~none:""
    ~some:(fun (w : D.t) -> Venice.Hex.encode (Pk.to_bytes (f w)))
    (witness ())

(* The verdict of ONE block through Cert.of_pem, as TEXT. *)
let pem_text (block : string) : string =
  Result.fold
    ~ok:(fun ((_ : D.Cert.t)) -> "ok")
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    (D.Cert.of_pem block)

(* The verdict of raw DER bytes through Cert.of_der, as TEXT. *)
let der_text (der : string) : string =
  Result.fold
    ~ok:(fun ((_ : D.Cert.t)) -> "ok")
    ~error:(fun (e : Errx.t) -> Errx.to_string e)
    (D.Cert.of_der der)

(* The two time parsers as TEXT, "none" for a refusal. *)
let utc (s : string) : string =
  Option.fold ~none:"none"
    ~some:(fun (t : D.Now.t) -> D.Now.to_string t)
    (D.Now.of_utc s)

let gen (s : string) : string =
  Option.fold ~none:"none"
    ~some:(fun (t : D.Now.t) -> D.Now.to_string t)
    (D.Now.of_generalized s)

let digits (s : string) : string =
  Option.fold ~none:"none"
    ~some:(fun (t : D.Now.t) -> D.Now.to_string t)
    (D.Now.of_digits s)

(* One DER INTEGER half with its sign byte stripped, which is the 1 to
   32 byte form P256x.Signature.of_rs takes. *)
let half (v : string) : string =
  if Int.equal (String.length v) 33 then win v 1 32 else v

let sig_of (i : int) : Sg.t option =
  Option.bind (cert i) (fun (c : D.Cert.t) ->
      let ((r : string), (s : string)) = D.Cert.signature c in
      Sg.of_rs ~r:(half r) ~s:(half s))

let sig_hex (i : int) : string =
  Option.fold ~none:""
    ~some:(fun (c : D.Cert.t) ->
      let ((r : string), (s : string)) = D.Cert.signature c in
      hex (half r) ^ hex (half s))
    (cert i)

let sig_lens (i : int) : int * int =
  Option.fold ~none:(0, 0)
    ~some:(fun (c : D.Cert.t) ->
      let ((r : string), (s : string)) = D.Cert.signature c in
      (String.length r, String.length s))
    (cert i)

let key_of (i : int) : Pk.t option =
  Option.map (fun (c : D.Cert.t) -> D.Cert.public_key c) (cert i)

let tbs_of (i : int) : string = cert_str (fun (c : D.Cert.t) -> D.Cert.tbs c) i

(* ONE ECDSA leg, computed here and never quoted: the signature of
   certificate si under the public key of certificate ki over msg. *)
let verifies (ki : int) (si : int) (msg : string) : bool =
  Option.fold ~none:false
    ~some:(fun (k : Pk.t) ->
      Option.fold ~none:false
        ~some:(fun (g : Sg.t) -> P.verify_message k g msg)
        (sig_of si))
    (key_of ki)

(* The sixteen TCB components spelled as the CPUSVN bytes they equal
   under RUL-M26-3. *)
let comps_hex (xs : int list) : string =
  String.concat "" (List.map (fun (v : int) -> Printf.sprintf "%02x" v) xs)

(* Every reason word of the CLOSED vocabulary, printed WHOLE. *)
let printed (word : string) : string = Errx.to_string (Errx.Cert_invalid word)

(* (a) The PEM window and the three blocks of W1. *)
let window_checks : (string * bool) list =
  [
    ( "derx: (a) the embedded quote fixture is 5006 bytes",
      Int.equal (String.length v4) 5006 );
    ( "derx: (a) the embedded root fixture is 659 bytes",
      Int.equal (String.length root_file) 659 );
    ( "derx: (a) the pem_window is 3678 bytes",
      Int.equal (String.length (pem_window ())) 3678 );
    ( "derx: (a) the pem_window starts at quote offset 1258",
      String.equal (pem_window ()) (win v4 1258 3678) );
    ( "derx: (a) the chain holds exactly three blocks",
      Int.equal (List.length (chain ())) 3 );
    ( "derx: (a) the block lengths are 1773, 956 and 949",
      Int.equal (String.length (bl 0)) 1773
      && Int.equal (String.length (bl 1)) 956
      && Int.equal (String.length (bl 2)) 949 );
    ( "derx: (a) the newlines per block are 29, 16 and 16",
      Int.equal (newlines (bl 0)) 29
      && Int.equal (newlines (bl 1)) 16
      && Int.equal (newlines (bl 2)) 16 );
    ( "derx: (a) no block carries a carriage return",
      Int.equal (List.length (String.split_on_char '\r' (pem_window ()))) 1 );
    ( "derx: (a) block 3 ends on the END marker, one newline and one NUL",
      String.equal (hex (win (bl 2) 939 10)) "4154452d2d2d2d2d0a00" );
    ( "derx: (a) block 3 decodes to the embedded root fixture",
      String.equal (der_of 2) root_file );
  ]

(* (b) The three DER certificates of W2 and the PEM body cut. *)
let der_checks : (string * bool) list =
  [
    ( "derx: (b) Cert.of_pem accepts every block of the chain",
      String.equal (pem_text (bl 0)) "ok"
      && String.equal (pem_text (bl 1)) "ok"
      && String.equal (pem_text (bl 2)) "ok" );
    ( "derx: (b) CRLF PEM blocks parse and their chain verifies",
      List.for_all
        (fun (b : string) -> String.equal (pem_text b) "ok")
        (chain_newlines "\r\n")
      && String.equal
           (chain_text ~now:"20260906000000" (chain_newlines "\r\n"))
           "ok" );
    ( "derx: (b) CR PEM blocks parse and their chain verifies",
      List.for_all
        (fun (b : string) -> String.equal (pem_text b) "ok")
        (chain_newlines "\r")
      && String.equal
           (chain_text ~now:"20260906000000" (chain_newlines "\r"))
           "ok" );
    ( "derx: (b) the three der sizes are 1269, 666 and 659",
      Int.equal (String.length (der_of 0)) 1269
      && Int.equal (String.length (der_of 1)) 666
      && Int.equal (String.length (der_of 2)) 659 );
    ( "derx: (b) the leaf der digest",
      String.equal (sha (der_of 0))
        "c2fb4124d84998cc005c38e13766843777e1c47a1e0b89ad720fd70c2e90927e" );
    ( "derx: (b) the intermediate der digest",
      String.equal (sha (der_of 1))
        "22eb770dca215b607b5ccfc21a672b1da5cc660b1ad0365020567979edcaa0e1" );
    ( "derx: (b) the root der digest",
      String.equal (sha (der_of 2))
        "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3" );
    ( "derx: (b) the three tbs element sizes are 1178, 577 and 568",
      Int.equal (String.length (tbs_of 0)) 1178
      && Int.equal (String.length (tbs_of 1)) 577
      && Int.equal (String.length (tbs_of 2)) 568 );
    ( "derx: (b) the leaf tbs digest",
      String.equal (sha (tbs_of 0))
        "504501ea2c2013ec9e2f8b4f78773c63675899d73f2036e0671c4a3e73ed6a9f" );
    ( "derx: (b) the intermediate tbs digest",
      String.equal (sha (tbs_of 1))
        "581d1ff77ba97123a71722be563b50238f861198a174eb3e2d32cd8d5b710e70" );
    ( "derx: (b) the root tbs digest",
      String.equal (sha (tbs_of 2))
        "0e1c8ad1fad9254ad1d0bc362c4c83dad27f32fc903cbb9cda58349ec2a4626a" );
    ( "derx: (b) every tbs element opens at der offset 4",
      String.equal (tbs_of 0) (win (der_of 0) 4 1178)
      && String.equal (tbs_of 1) (win (der_of 1) 4 577)
      && String.equal (tbs_of 2) (win (der_of 2) 4 568) );
    ( "derx: (b) every version element is a003020102, which is v3",
      String.equal (hex (win (der_of 0) 8 5)) "a003020102"
      && String.equal (hex (win (der_of 1) 8 5)) "a003020102"
      && String.equal (hex (win (der_of 2) 8 5)) "a003020102" );
    ( "derx: (b) a carriage return inside the body is der",
      String.equal (pem_text (patch (bl 0) 30 "\r")) "cert: der" );
    ( "derx: (b) a body byte outside the base64 alphabet is der",
      String.equal (pem_text (patch (bl 0) 30 "!")) "cert: der" );
    ( "derx: (b) a block with no END marker is der",
      String.equal
        (pem_text
           ("-----BEGIN CERTIFICATE-----\n"
           ^ Venice.B64.encode_std (der_of 0)))
        "cert: der" );
    ( "derx: (b) a block with no BEGIN marker is der",
      String.equal (pem_text (Venice.B64.encode_std (der_of 0))) "cert: der" );
    ( "derx: (b) a block with an empty body is der",
      String.equal
        (pem_text "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
        "cert: der" );
    ( "derx: (b) a rebuilt block with no paint still parses",
      String.equal (pem_text (block_of (der_of 0))) "ok" );
    ( "derx: (b) Cert.of_der takes the three raw der buffers as they stand",
      String.equal (der_text (der_of 0)) "ok"
      && String.equal (der_text (der_of 1)) "ok"
      && String.equal (der_text (der_of 2)) "ok" );
    ( "derx: (b) Cert.of_der refuses a buffer whose outer length is short",
      String.equal (der_text (patch (der_of 0) 3 "\xf0")) "cert: der" );
    ( "derx: (b) a painted block rebuilds to exactly the painted der",
      String.equal
        (Option.fold ~none:""
           ~some:(fun (c : D.Cert.t) -> D.Cert.der c)
           (Result.to_option (D.Cert.of_pem (paint 0 15 "\x3d"))))
        (patch (der_of 0) 15 "\x3d") );
  ]

(* (c) The root pin of W3, which is the anchor of the whole chain. *)
let pin_checks : (string * bool) list =
  [
    ( "derx: (c) root_pin () holds 659 bytes",
      Int.equal (String.length (D.root_pin ())) 659 );
    ( "derx: (c) the root_pin () digest",
      String.equal (sha (D.root_pin ()))
        "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3" );
    ( "derx: (c) root_pin () equals the embedded root fixture",
      String.equal (D.root_pin ()) root_file );
    ( "derx: (c) root_pin () equals the der of block 3",
      String.equal (D.root_pin ()) (der_of 2) );
    ( "derx: (c) the root is self-issued, issuer TLV equals subject TLV",
      String.equal
        (cert_str (fun (c : D.Cert.t) -> D.Cert.issuer c) 2)
        (cert_str (fun (c : D.Cert.t) -> D.Cert.subject c) 2) );
  ]

(* The raw 64 bytes of one certificate public key, X then Y. *)
let key_hex (i : int) : string =
  Option.fold ~none:""
    ~some:(fun (c : D.Cert.t) -> hex (Pk.to_bytes (D.Cert.public_key c)))
    (cert i)

(* (d) The OIDs as CONTENT bytes, the three public keys and the two
   extension values of W4 and W8. *)
let oid_checks : (string * bool) list =
  [
    ( "derx: (d) the leaf spki bit string is 03 42 00 04 at 330",
      String.equal (hex (win (der_of 0) 330 4)) "03420004" );
    ( "derx: (d) the leaf point halves",
      String.equal (key_hex 0)
        "1720fa04edef8680bfb748fd965af93d61a417a8f1f29910e8b88b3666dfff6d2b2660f3288f203356f90253a7f6f76616e24212c22cfcc3e66d681f971c9769" );
    ( "derx: (d) the intermediate point halves",
      String.equal (key_hex 1)
        "35207feeddb595748ed82bb3a71c3be1e241ef61320c6816e6b5c2b71dad5532eaea12a4eb3f948916429ea47ba6c3af82a15e4b19664e52657939a2d96633de" );
    ( "derx: (d) the root point halves",
      String.equal (key_hex 2)
        "0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394" );
    ( "derx: (d) pck_key returns the leaf point, the W9 tie to M25",
      String.equal
        (w_bytes (fun (w : D.t) -> D.pck_key w))
        "1720fa04edef8680bfb748fd965af93d61a417a8f1f29910e8b88b3666dfff6d2b2660f3288f203356f90253a7f6f76616e24212c22cfcc3e66d681f971c9769" );
    ( "derx: (d) the leaf point sits at der offset 333, 65 bytes",
      String.equal (win (der_of 0) 333 65)
        (Option.fold ~none:"" ~some:Pk.to_bytes (key_of 0) |> fun (b : string) ->
         "\x04" ^ b) );
    ( "derx: (d) the intermediate point sits at der offset 326",
      String.equal (hex (win (der_of 1) 326 1)) "04" );
    ( "derx: (d) the root point sits at der offset 317",
      String.equal (hex (win (der_of 2) 317 1)) "04" );
    ( "derx: (d) the tbs signatureAlgorithm oid content is ecdsa-with-SHA256",
      String.equal (hex (win (der_of 0) 39 8)) "2a8648ce3d040302" );
    ( "derx: (d) the outer signatureAlgorithm oid content is the same one",
      String.equal (hex (win (der_of 0) 1186 8)) "2a8648ce3d040302"
      && String.equal (hex (win (der_of 0) 39 8))
           (hex (win (der_of 0) 1186 8)) );
    ( "derx: (d) the spki curve oid content is prime256v1",
      String.equal (hex (win (der_of 0) 322 8)) "2a8648ce3d030107" );
    ( "derx: (d) the spki algorithm oid content is id-ecPublicKey",
      String.equal (hex (win (der_of 0) 313 7)) "2a8648ce3d0201" );
    ( "derx: (d) the leaf sgx extension oid content",
      String.equal (hex (win (der_of 0) 615 9)) "2a864886f84d010d01" );
    ( "derx: (d) the leaf keyUsage extension value",
      String.equal (hex (win (der_of 0) 591 4)) "030206c0" );
    ( "derx: (d) the two ca keyUsage extension values",
      String.equal (hex (win (der_of 1) 557 4)) "03020106"
      && String.equal (hex (win (der_of 2) 548 4)) "03020106" );
    ( "derx: (d) the leaf basicConstraints extension value",
      String.equal (hex (win (der_of 0) 607 2)) "3000" );
    ( "derx: (d) the intermediate basicConstraints extension value",
      String.equal (hex (win (der_of 1) 573 8)) "30060101ff020100" );
    ( "derx: (d) the root basicConstraints extension value",
      String.equal (hex (win (der_of 2) 564 8)) "30060101ff020101" );
  ]

(* (e) The issuer and subject Names of W6, compared as RAW TLV bytes. *)
let name_checks : (string * bool) list =
  [
    ( "derx: (e) the leaf issuer equals the intermediate subject",
      String.equal
        (cert_str (fun (c : D.Cert.t) -> D.Cert.issuer c) 0)
        (cert_str (fun (c : D.Cert.t) -> D.Cert.subject c) 1) );
    ( "derx: (e) the intermediate issuer equals the root subject",
      String.equal
        (cert_str (fun (c : D.Cert.t) -> D.Cert.issuer c) 1)
        (cert_str (fun (c : D.Cert.t) -> D.Cert.subject c) 2) );
    ( "derx: (e) the leaf subject differs from the intermediate subject",
      not
        (String.equal
           (cert_str (fun (c : D.Cert.t) -> D.Cert.subject c) 0)
           (cert_str (fun (c : D.Cert.t) -> D.Cert.subject c) 1)) );
    ( "derx: (e) the leaf issuer element is 114 bytes at der offset 47",
      String.equal
        (cert_str (fun (c : D.Cert.t) -> D.Cert.issuer c) 0)
        (win (der_of 0) 47 114) );
    ( "derx: (e) the leaf subject element is 114 bytes at der offset 193",
      String.equal
        (cert_str (fun (c : D.Cert.t) -> D.Cert.subject c) 0)
        (win (der_of 0) 193 114) );
    ( "derx: (e) the intermediate issuer element is 106 bytes at 48",
      String.equal
        (cert_str (fun (c : D.Cert.t) -> D.Cert.issuer c) 1)
        (win (der_of 1) 48 106) );
    ( "derx: (e) the intermediate subject element is 114 bytes at 186",
      String.equal
        (cert_str (fun (c : D.Cert.t) -> D.Cert.subject c) 1)
        (win (der_of 1) 186 114) );
    ( "derx: (e) the serial content lengths are 20, 21 and 20",
      Int.equal
        (String.length (cert_str (fun (c : D.Cert.t) -> D.Cert.serial c) 0))
        20
      && Int.equal
           (String.length (cert_str (fun (c : D.Cert.t) -> D.Cert.serial c) 1))
           21
      && Int.equal
           (String.length (cert_str (fun (c : D.Cert.t) -> D.Cert.serial c) 2))
           20 );
  ]

(* (f) The three validity windows of W7, the five answers around the
   inside witness, and the RUL-M26-1 time parsers with the RFC 5280
   4.1.2.5.1 century pivot. *)
let time_checks : (string * bool) list =
  [
    ( "derx: (f) the leaf window is 20250206232551 .. 20320206232551",
      String.equal
        (cert_time (fun (c : D.Cert.t) -> D.Cert.not_before c) 0)
        "20250206232551"
      && String.equal
           (cert_time (fun (c : D.Cert.t) -> D.Cert.not_after c) 0)
           "20320206232551" );
    ( "derx: (f) the intermediate window is 20180521105010 .. 20330521105010",
      String.equal
        (cert_time (fun (c : D.Cert.t) -> D.Cert.not_before c) 1)
        "20180521105010"
      && String.equal
           (cert_time (fun (c : D.Cert.t) -> D.Cert.not_after c) 1)
           "20330521105010" );
    ( "derx: (f) the root window is 20180521104510 .. 20491231235959",
      String.equal
        (cert_time (fun (c : D.Cert.t) -> D.Cert.not_before c) 2)
        "20180521104510"
      && String.equal
           (cert_time (fun (c : D.Cert.t) -> D.Cert.not_after c) 2)
           "20491231235959" );
    ( "derx: (f) the fixture validity strings sit at der offsets 163 and 178",
      String.equal (win (der_of 0) 163 15) "\x17\x0d250206232551Z"
      && String.equal (win (der_of 0) 178 15) "\x17\x0d320206232551Z" );
    ( "derx: (f) the chain is accepted at 20260906000000, inside all three",
      String.equal (good ~now:"20260906000000") "ok" );
    ( "derx: (f) 20240101000000 is before the leaf window: not yet valid",
      String.equal (good ~now:"20240101000000") "cert: not yet valid" );
    ( "derx: (f) 20320206232551 is EXACTLY the leaf notAfter and the chain \
       is accepted, because both validity bounds are INCLUSIVE",
      String.equal (good ~now:"20320206232551") "ok" );
    ( "derx: (f) 20320206232552 is one second past the leaf: expired",
      String.equal (good ~now:"20320206232552") "cert: expired" );
    ( "derx: (f) 20330521105011 is one second past the intermediate: expired",
      String.equal (good ~now:"20330521105011") "cert: expired" );
    ( "derx: (f) 20500101000000 is past the root notAfter: expired",
      String.equal (good ~now:"20500101000000") "cert: expired" );
    ( "derx: (f) not yet valid is answered BEFORE expired at the same cert",
      String.equal (good ~now:"20240101000000") "cert: not yet valid" );
    ( "derx: (f) of_utc 491231235959Z pivots to 20491231235959",
      String.equal (utc "491231235959Z") "20491231235959" );
    ( "derx: (f) of_utc 500101000000Z pivots to 19500101000000",
      String.equal (utc "500101000000Z") "19500101000000" );
    ( "derx: (f) of_utc 000229000000Z is the 2000 leap day, 20000229000000",
      String.equal (utc "000229000000Z") "20000229000000" );
    ( "derx: (f) of_utc refuses a fraction, a missing Z, month 13 and hour 24",
      String.equal (utc "2502062325.1Z") "none"
      && String.equal (utc "250206232551") "none"
      && String.equal (utc "251306232551Z") "none"
      && String.equal (utc "250206242551Z") "none" );
    ( "derx: (f) of_generalized takes the fifteen-character form",
      String.equal (gen "20250206232551Z") "20250206232551"
      && String.equal (gen "20250206232551") "none" );
    ( "derx: (f) of_digits takes the fourteen digits and nothing else",
      String.equal (digits "20260906000000") "20260906000000"
      && String.equal (digits "2026090600000") "none"
      && String.equal (digits "2026090600000Z") "none" );
    ( "derx: (f) compare orders the leaf notBefore before its notAfter",
      Option.fold ~none:false
        ~some:(fun (a : D.Now.t) ->
          Option.fold ~none:false
            ~some:(fun (b : D.Now.t) -> D.Now.compare a b < 0)
            (D.Now.of_digits "20320206232551"))
        (D.Now.of_digits "20250206232551") );
  ]

(* (g) The extension offsets, lengths and critical flags of W8. *)
let ext_checks : (string * bool) list =
  [
    ( "derx: (g) the leaf keyUsage oid content is 551d0f at 583",
      String.equal (hex (win (der_of 0) 583 3)) "551d0f" );
    ( "derx: (g) the leaf keyUsage carries the critical BOOLEAN 0101ff at 586",
      String.equal (hex (win (der_of 0) 586 3)) "0101ff" );
    ( "derx: (g) the leaf basicConstraints oid content is 551d13 at 599",
      String.equal (hex (win (der_of 0) 599 3)) "551d13" );
    ( "derx: (g) the leaf basicConstraints is critical too, 0101ff at 602",
      String.equal (hex (win (der_of 0) 602 3)) "0101ff" );
    ( "derx: (g) the leaf sgx extension value is an OCTET STRING of 554 bytes",
      String.equal (hex (win (der_of 0) 624 4)) "0482022a"
      && Int.equal (String.length (win (der_of 0) 628 554)) 554 );
    ( "derx: (g) the leaf is NOT a ca and cannot sign a certificate",
      (not (cert_bool (fun (c : D.Cert.t) -> D.Cert.is_ca c) 0))
      && not (cert_bool (fun (c : D.Cert.t) -> D.Cert.key_cert_sign c) 0) );
    ( "derx: (g) the leaf keyUsage mask c0 grants digitalSignature",
      cert_bool (fun (c : D.Cert.t) -> D.Cert.digital_signature c) 0 );
    ( "derx: (g) the intermediate is a ca and holds keyCertSign",
      cert_bool (fun (c : D.Cert.t) -> D.Cert.is_ca c) 1
      && cert_bool (fun (c : D.Cert.t) -> D.Cert.key_cert_sign c) 1 );
    ( "derx: (g) the root is a ca and holds keyCertSign",
      cert_bool (fun (c : D.Cert.t) -> D.Cert.is_ca c) 2
      && cert_bool (fun (c : D.Cert.t) -> D.Cert.key_cert_sign c) 2 );
    ( "derx: (g) the ca mask 06 does NOT grant digitalSignature",
      (not (cert_bool (fun (c : D.Cert.t) -> D.Cert.digital_signature c) 1))
      && not (cert_bool (fun (c : D.Cert.t) -> D.Cert.digital_signature c) 2)
    );
    ( "derx: (g) the intermediate cA byte is ff at der offset 577",
      String.equal (hex (win (der_of 1) 577 1)) "ff" );
    ( "derx: (g) the intermediate keyUsage mask byte is 06 at der offset 560",
      String.equal (hex (win (der_of 1) 560 1)) "06" );
    ( "derx: (g) the root pathLen is 1 and the intermediate pathLen is 0",
      String.equal (hex (win (der_of 2) 564 8)) "30060101ff020101"
      && String.equal (hex (win (der_of 1) 573 8)) "30060101ff020100" );
  ]

(* (h) The SGX PCK extension numbers of W8 that M27 consumes. *)
let sgx_checks : (string * bool) list =
  [
    ( "derx: (h) the leaf pcesvn is 11",
      Int.equal (w_int (fun (w : D.t) -> D.pcesvn w)) 11 );
    ( "derx: (h) the pcesvn INTEGER 02010b sits at der offset 987",
      String.equal (hex (win (der_of 0) 986 4)) "1102010b" );
    ( "derx: (h) the cpusvn OCTET STRING 0410 sits at der offset 1005",
      String.equal (hex (win (der_of 0) 1005 2)) "0410"
      && String.equal (hex (win (der_of 0) 1007 16))
           "03030202040100050000000000000000" );
    ( "derx: (h) the fmspc OCTET STRING 0406 sits at der offset 1055",
      String.equal (hex (win (der_of 0) 1055 2)) "0406"
      && String.equal (hex (win (der_of 0) 1057 6)) "b0c06f000000" );
    ( "derx: (h) the pce_id OCTET STRING 0402 sits at der offset 1037",
      String.equal (hex (win (der_of 0) 1037 2)) "0402"
      && String.equal (hex (win (der_of 0) 1039 2)) "0000" );
    ( "derx: (h) the leaf cpusvn is 03030202040100050000000000000000",
      String.equal
        (hex (w_str (fun (w : D.t) -> D.cpusvn w)))
        "03030202040100050000000000000000" );
    ( "derx: (h) the leaf fmspc is b0c06f000000",
      String.equal (hex (w_str (fun (w : D.t) -> D.fmspc w))) "b0c06f000000" );
    ( "derx: (h) the leaf pce_id is 0000",
      String.equal (hex (w_str (fun (w : D.t) -> D.pce_id w))) "0000" );
    ( "derx: (h) the cpusvn is sixteen bytes and the fmspc six",
      Int.equal (String.length (w_str (fun (w : D.t) -> D.cpusvn w))) 16
      && Int.equal (String.length (w_str (fun (w : D.t) -> D.fmspc w))) 6 );
    ( "derx: (h) tcb_components is the sixteen fixture values",
      List.equal Int.equal
        (w_ints (fun (w : D.t) -> D.tcb_components w))
        [ 3; 3; 2; 2; 4; 1; 0; 5; 0; 0; 0; 0; 0; 0; 0; 0 ] );
    ( "derx: (h) tcb_components equals the bytes of cpusvn on the fixture",
      String.equal
        (comps_hex (w_ints (fun (w : D.t) -> D.tcb_components w)))
        (hex (w_str (fun (w : D.t) -> D.cpusvn w))) );
    ( "derx: (h) the sgx accessors read the LEAF, not the intermediate",
      Option.fold ~none:false
        ~some:(fun (c : D.Cert.t) -> Option.is_some (D.Cert.sgx c))
        (cert 0)
      && Option.fold ~none:false
           ~some:(fun (c : D.Cert.t) -> Option.is_none (D.Cert.sgx c))
           (cert 1) );
    ( "derx: (h) the sgx record of the witness equals the leaf sgx record",
      String.equal
        (hex (w_str (fun (w : D.t) -> D.cpusvn w)))
        (hex
           (Option.fold ~none:""
              ~some:(fun (c : D.Cert.t) ->
                Option.fold ~none:"" ~some:D.Sgx.cpusvn (D.Cert.sgx c))
              (cert 0))) );
  ]

(* (i) The two ECDSA legs of W5, each recomputed here from the fixture
   bytes with its own affine P-256 before the row requires it, and the
   four controls that prove each leg reads the key and the message its
   step names. *)
let leg_checks : (string * bool) list =
  [
    ( "derx: (i) the leaf signature halves",
      String.equal (sig_hex 0)
        "c93bd84d51d4b83454cdd50927fb670c706b5eb9bd4036f42fde5bee4a91f56792c287d922000a0e5b36bf25aa068a783b537bd7af6e93b0ce7a9aa604c1d155" );
    ( "derx: (i) the intermediate signature halves",
      String.equal (sig_hex 1)
        "5ec5648b4c3e8ba558196dd417fdb6b9a5ded182438f551e9c0f938c3d5a8b97261bd520260f9c647d3569be8e14a32892631ac358b994478088f4d2b27cf37e" );
    ( "derx: (i) the root signature halves, which derx never verifies",
      String.equal (sig_hex 2)
        "e5bfe50911f92f428920dc368a302ee3d12ec5867ff622ec6497f78060c13c20e09d25ac7a0cb3e5e8e68fec5fa3bd416c47440bd950639d450edcbea4576aa2" );
    ( "derx: (i) the raw halves keep a leading 00 on the leaf and the root",
      (let (a, b) = sig_lens 0 in
       Int.equal a 33 && Int.equal b 33)
      && (let (a, b) = sig_lens 1 in
          Int.equal a 32 && Int.equal b 32)
      && let (a, b) = sig_lens 2 in
         Int.equal a 33 && Int.equal b 33 );
    ( "derx: (i) the leaf signature BIT STRING 034900 sits at der 1194",
      String.equal (hex (win (der_of 0) 1194 3)) "034900" );
    ( "derx: (i) the ca signature BIT STRINGs sit at der 593 and 584",
      String.equal (hex (win (der_of 1) 593 3)) "034700"
      && String.equal (hex (win (der_of 2) 584 3)) "034900" );
    ( "derx: (i) the leaf leg: the intermediate key verifies the leaf tbs",
      verifies 1 0 (tbs_of 0) );
    ( "derx: (i) the ca leg: the root key verifies the intermediate tbs",
      verifies 2 1 (tbs_of 1) );
    ( "derx: (i) control one: the leaf key does NOT verify the leaf tbs",
      not (verifies 0 0 (tbs_of 0)) );
    ( "derx: (i) control two: the root key does NOT verify the leaf tbs",
      not (verifies 2 0 (tbs_of 0)) );
    ( "derx: (i) control three: the leaf leg fails over the WRONG message",
      not (verifies 1 0 (tbs_of 1)) );
    ( "derx: (i) control four: the root self-signature verifies HERE, and \
       derx still never runs that leg",
      verifies 2 2 (tbs_of 2)
      && String.equal (chain_text ~now:"20260906000000" (chain ())) "ok" );
    ( "derx: (i) the witness pck_key is the key of Cert.leaf, not of a ca",
      String.equal
        (w_bytes (fun (w : D.t) -> D.pck_key w))
        (hex (Option.fold ~none:"" ~some:Pk.to_bytes (key_of 0)))
      && not
           (String.equal
              (w_bytes (fun (w : D.t) -> D.pck_key w))
              (hex (Option.fold ~none:"" ~some:Pk.to_bytes (key_of 1)))) );
    ( "derx: (i) the witness keeps the three certificates in chain order",
      String.equal
        (w_str (fun (w : D.t) -> D.Cert.der (D.leaf w)))
        (der_of 0)
      && String.equal
           (w_str (fun (w : D.t) -> D.Cert.der (D.intermediate w)))
           (der_of 1)
      && String.equal
           (w_str (fun (w : D.t) -> D.Cert.der (D.root w)))
           (der_of 2) );
  ]

(* The DER of block i with every paint of ps that names block i applied
   in order, one byte for one byte. *)
let painted_der (i : int) (ps : (int * int * string) list) : string =
  List.fold_left
    (fun (acc : string) ((j : int), (off : int), (repl : string)) ->
      if Int.equal j i then patch acc off repl else acc)
    (der_of i) ps

(* The chain with the painted blocks rebuilt and every other block left
   byte-identical to the fixture. *)
let with_paints (ps : (int * int * string) list) : string list =
  List.mapi
    (fun (i : int) (b : string) ->
      if List.exists (fun ((j : int), (_ : int), (_ : string)) -> Int.equal j i) ps
      then block_of (painted_der i ps)
      else b)
    (chain ())

(* The verdict over a painted chain at the inside witness time. *)
let pt (ps : (int * int * string) list) : string =
  chain_text ~now:"20260906000000" (with_paints ps)

(* The DER of block i with ONE element RE-ENCODED in the NON-MINIMAL
   definite long form.  The two-byte short header at off becomes the
   three bytes of hdr, which spell the same length under the long form
   that a single byte already carries, and the two length bytes of the
   outer SEQUENCE at offset 2 become olen, one more than the fixture
   value, because the element header grew by exactly one byte.  The
   content of the element and every other byte stay as they are, so the
   only fault is the length ENCODING.  Both cuts run through
   Venice.Cursor.take, so an out-of-range request answers the input
   unchanged instead of raising. *)
let long_form_der (i : int) (off : int) (hdr : string) (olen : string) : string
    =
  let der = patch (der_of i) 2 olen in
  Option.value ~default:der
    (Option.bind (C.take der 0 off) (fun (head : string) ->
         Option.map
           (fun (tail : string) -> head ^ hdr ^ tail)
           (C.take der (off + 2) (String.length der - off - 2))))

(* The verdict over a chain whose block i carries that NON-MINIMAL
   header, at the inside witness time.  The block is rebuilt by the SAME
   base64 path every paint row uses, so no base64 character is edited by
   hand. *)
let pt_long (i : int) (off : int) (hdr : string) (olen : string) : string =
  chain_text ~now:"20260906000000"
    (List.mapi
       (fun (j : int) (b : string) ->
         if Int.equal j i then block_of (long_form_der i off hdr olen) else b)
       (chain ()))

(* Rebuild the fixture leaf signature with either sign-padding byte
   removed. The signed tbs and both scalar magnitudes stay unchanged.
   Every enclosing length is recomputed, so the only fault is the
   negative INTEGER encoding. The short TLVs here hold at most 73 bytes. *)
let leaf_sign_encoding ~(negative_r : bool) ~(negative_s : bool) : string =
  let short (tag : int) (body : string) : string =
    Venice__Bytesx.of_codes [ tag; String.length body ] ^ body
  in
  Option.fold ~none:""
    ~some:(fun (c : D.Cert.t) ->
      let ((r : string), (s : string)) = D.Cert.signature c in
      let rv = if negative_r then half r else r in
      let sv = if negative_s then half s else s in
      let sig_der = short 0x30 (short 0x02 rv ^ short 0x02 sv) in
      let body = win (D.Cert.der c) 4 1190 ^ short 0x03 ("\x00" ^ sig_der) in
      let len = String.length body in
      Venice__Bytesx.of_codes [ 0x30; 0x82; len lsr 8; len land 255 ] ^ body)
    (cert 0)

let rejects_negative_signature ~(negative_r : bool) ~(negative_s : bool) : bool =
  let der = leaf_sign_encoding ~negative_r ~negative_s in
  String.equal (der_text der) "cert: der"
  && String.equal
       (chain_text ~now:"20260906000000" [ block_of der; bl 1; bl 2 ])
       "cert: der"

(* (j) The SINGLE-fault paints.  Each row paints ONE byte of ONE
   decoded certificate and names the ONE word that byte reaches. *)
let paint_checks : (string * bool) list =
  [
    ( "derx: (j) rebuilding positive signature integers preserves the leaf",
      String.equal
        (leaf_sign_encoding ~negative_r:false ~negative_s:false)
        (der_of 0) );
    ( "derx: (j) a negative signature r is der",
      rejects_negative_signature ~negative_r:true ~negative_s:false );
    ( "derx: (j) a negative signature s is der",
      rejects_negative_signature ~negative_r:false ~negative_s:true );
    ( "derx: (j) two negative signature integers are der",
      rejects_negative_signature ~negative_r:true ~negative_s:true );
    ( "derx: (j) a two-block chain is answered chain length",
      String.equal
        (chain_text ~now:"20260906000000" [ bl 0; bl 1 ])
        "cert: chain length" );
    ( "derx: (j) a four-block chain is answered chain length",
      String.equal
        (chain_text ~now:"20260906000000" [ bl 0; bl 1; bl 2; bl 2 ])
        "cert: chain length" );
    ( "derx: (j) an empty chain is answered chain length",
      String.equal (chain_text ~now:"20260906000000" []) "cert: chain length" );
    ( "derx: (j) a block with no BEGIN marker is answered der",
      String.equal
        (chain_text ~now:"20260906000000" [ "not a pem block\n"; bl 1; bl 2 ])
        "cert: der" );
    ( "derx: (j) a block with an empty body is answered der",
      String.equal
        (pem_text "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
        "cert: der" );
    ( "derx: (j) a base64 body of one bad character is answered der",
      String.equal
        (pem_text "-----BEGIN CERTIFICATE-----\n*\n-----END CERTIFICATE-----\n")
        "cert: der" );
    ( "derx: (j) the leaf outer tag 30 painted to 31 is answered der",
      String.equal (pt [ (0, 0, "\x31") ]) "cert: der" );
    ( "derx: (j) the leaf outer length byte at 3 painted is answered der",
      String.equal (pt [ (0, 3, "\xf0") ]) "cert: der" );
    ( "derx: (j) the leaf tbs length byte at 6 painted is answered der",
      String.equal (pt [ (0, 6, "\x05") ]) "cert: der" );
    ( "derx: (j) the leaf version value at 12 painted to 01 is version",
      String.equal (pt [ (0, 12, "\x01") ]) "cert: version" );
    ( "derx: (j) the leaf version value at 12 painted to 03 is version",
      String.equal (pt [ (0, 12, "\x03") ]) "cert: version" );
    ( "derx: (j) the leaf tbs sigAlg oid tail at 46 is signature algorithm",
      String.equal (pt [ (0, 46, "\x03") ]) "cert: signature algorithm" );
    ( "derx: (j) the leaf outer sigAlg oid tail at 1193 is signature algorithm",
      String.equal (pt [ (0, 1193, "\x03") ]) "cert: signature algorithm" );
    ( "derx: (j) the leaf curve oid tail at 329 painted is public key",
      String.equal (pt [ (0, 329, "\x08") ]) "cert: public key" );
    ( "derx: (j) the leaf point prefix 04 at 333 painted is public key",
      String.equal (pt [ (0, 333, "\x05") ]) "cert: public key" );
    ( "derx: (j) the leaf signature unused-bits byte at 1196 is der",
      String.equal (pt [ (0, 1196, "\x01") ]) "cert: der" );
    ( "derx: (j) the leaf keyUsage oid tail at 585 painted to 77, an oid \
       this unit does not read, is critical extension",
      String.equal (pt [ (0, 585, "\x77") ]) "cert: critical extension" );
    ( "derx: (j) the same tail painted to 0e is the KNOWN subjectKeyIdentifier \
       oid, so the leaf loses its keyUsage and the answer is key usage",
      String.equal (pt [ (0, 585, "\x0e") ]) "cert: key usage" );
    ( "derx: (j) the root signature byte at 600 painted is root pin, so the \
       root leg is never run",
      String.equal (pt [ (2, 600, "\x00") ]) "cert: root pin" );
    ( "derx: (j) the leaf basicConstraints oid tail at 601 is critical extension",
      String.equal (pt [ (0, 601, "\x14") ]) "cert: critical extension" );
    ( "derx: (j) the leaf sgx oid tail at 623 painted is sgx extension",
      String.equal (pt [ (0, 623, "\x02") ]) "cert: sgx extension" );
    ( "derx: (j) the leaf pcesvn oid tail at 986 painted is sgx extension",
      String.equal (pt [ (0, 986, "\x12") ]) "cert: sgx extension" );
    ( "derx: (j) the leaf issuer SET tag at 49 painted is issuer",
      String.equal (pt [ (0, 49, "\x30") ]) "cert: issuer" );
    ( "derx: (j) the intermediate subject byte at 200 painted is issuer",
      String.equal (pt [ (1, 200, "\x6f") ]) "cert: issuer" );
    ( "derx: (j) the intermediate issuer SET tag at 50 painted is issuer",
      String.equal (pt [ (1, 50, "\x30") ]) "cert: issuer" );
    ( "derx: (j) the intermediate cA flag ff at 577 painted to 00 is ca",
      String.equal (pt [ (1, 577, "\x00") ]) "cert: ca" );
    ( "derx: (j) the intermediate keyUsage mask at 560 painted is key usage",
      String.equal (pt [ (1, 560, "\x00") ]) "cert: key usage" );
    ( "derx: (j) the leaf serial byte at 15 painted is leaf signature mismatch",
      String.equal (pt [ (0, 15, "\x3d") ]) "cert: leaf signature mismatch" );
    ( "derx: (j) the leaf serial byte at 16 painted is leaf signature mismatch",
      String.equal (pt [ (0, 16, "\x17") ]) "cert: leaf signature mismatch" );
    ( "derx: (j) the intermediate serial at 16 is ca signature mismatch",
      String.equal (pt [ (1, 16, "\x96") ]) "cert: ca signature mismatch" );
    ( "derx: (j) the intermediate serial at 20 is ca signature mismatch",
      String.equal (pt [ (1, 20, "\xbe") ]) "cert: ca signature mismatch" );
    ( "derx: (j) the root length byte at 3 painted is root pin",
      String.equal (pt [ (2, 3, "\x8e") ]) "cert: root pin" );
    ( "derx: (j) the root last byte at 658 painted is root pin",
      String.equal (pt [ (2, 658, "\xa3") ]) "cert: root pin" );
    ( "derx: (j) the root tag byte at 2 painted is root pin",
      String.equal (pt [ (2, 2, "\x03") ]) "cert: root pin" );
    ( "derx: (j) the leaf outer signature algorithm at 1182 re-encoded from \
       the short length 30 0a to the NON-MINIMAL long form 30 81 0a, with \
       the outer length grown from 04f1 to 04f2, is answered der",
      String.equal (pt_long 0 1182 "\x30\x81\x0a" "\x04\xf2") "cert: der" );
    ( "derx: (j) the SAME NON-MINIMAL 30 81 0a re-encode of the root outer \
       signature algorithm at 572, with the outer length grown from 028f to \
       0290, is answered root pin",
      String.equal (pt_long 2 572 "\x30\x81\x0a" "\x02\x90") "cert: root pin" );
  ]

(* (k) The TWO-fault precedence rows.  Each row paints two bytes that
   two DIFFERENT steps read and names the EARLIER step, which is the
   only proof that the order of the header is the order of the code. *)
let order_checks : (string * bool) list =
  [
    ( "derx: (k) the root pin is answered before the leaf version",
      String.equal (pt [ (2, 658, "\xa3"); (0, 12, "\x01") ]) "cert: root pin" );
    ( "derx: (k) the version is answered before the issuer compare",
      String.equal (pt [ (0, 12, "\x01"); (0, 49, "\x30") ]) "cert: version" );
    ( "derx: (k) the parse is answered before the validity window",
      String.equal
        (chain_text ~now:"20240101000000" (with_paints [ (0, 12, "\x01") ]))
        "cert: version" );
    ( "derx: (k) not yet valid is answered before the issuer compare",
      String.equal
        (chain_text ~now:"20240101000000" (with_paints [ (1, 200, "\x6f") ]))
        "cert: not yet valid" );
    ( "derx: (k) the issuer compare is answered before the cA flag",
      String.equal (pt [ (1, 200, "\x6f"); (1, 577, "\x00") ]) "cert: issuer" );
    ( "derx: (k) the cA flag is answered before the keyUsage bits",
      String.equal (pt [ (1, 577, "\x00"); (1, 560, "\x00") ]) "cert: ca" );
    ( "derx: (k) the keyUsage bits are answered before the sgx extension",
      String.equal
        (pt [ (1, 560, "\x00"); (0, 623, "\x02") ])
        "cert: key usage" );
    ( "derx: (k) the sgx extension is answered before the leaf leg",
      String.equal
        (pt [ (0, 623, "\x02"); (0, 15, "\x3d") ])
        "cert: sgx extension" );
    ( "derx: (k) the leaf leg is answered before the ca leg",
      String.equal
        (pt [ (0, 15, "\x3d"); (1, 16, "\x96") ])
        "cert: leaf signature mismatch" );
    ( "derx: (k) the chain length is answered before every byte check",
      String.equal
        (chain_text ~now:"20260906000000"
           [ List.nth_opt (with_paints [ (0, 0, "\x31") ]) 0
             |> Option.value ~default:"" ])
        "cert: chain length" );
  ]

(* (l) The CLOSED reason vocabulary of D5 and RUL-M26-2.  Each word is
   printed WHOLE under the "cert: " prefix, so no caller ever reads a
   truncated or a joined reason. *)
let word_checks : (string * bool) list =
  [
    ( "derx: (l) chain length prints whole",
      String.equal (printed "chain length") "cert: chain length" );
    ( "derx: (l) der prints whole", String.equal (printed "der") "cert: der" );
    ( "derx: (l) root pin prints whole",
      String.equal (printed "root pin") "cert: root pin" );
    ( "derx: (l) version prints whole",
      String.equal (printed "version") "cert: version" );
    ( "derx: (l) signature algorithm prints whole",
      String.equal (printed "signature algorithm") "cert: signature algorithm"
    );
    ( "derx: (l) public key prints whole",
      String.equal (printed "public key") "cert: public key" );
    ( "derx: (l) critical extension prints whole",
      String.equal (printed "critical extension") "cert: critical extension" );
    ( "derx: (l) not yet valid prints whole",
      String.equal (printed "not yet valid") "cert: not yet valid" );
    ( "derx: (l) expired prints whole",
      String.equal (printed "expired") "cert: expired" );
    ( "derx: (l) issuer prints whole",
      String.equal (printed "issuer") "cert: issuer" );
    ( "derx: (l) ca prints whole", String.equal (printed "ca") "cert: ca" );
    ( "derx: (l) key usage prints whole",
      String.equal (printed "key usage") "cert: key usage" );
    ( "derx: (l) sgx extension prints whole",
      String.equal (printed "sgx extension") "cert: sgx extension" );
    ( "derx: (l) leaf signature mismatch prints whole",
      String.equal (printed "leaf signature mismatch")
        "cert: leaf signature mismatch" );
    ( "derx: (l) ca signature mismatch prints whole",
      String.equal (printed "ca signature mismatch")
        "cert: ca signature mismatch" );
    ( "derx: (l) the two signature words are DISTINCT",
      not
        (String.equal
           (printed "leaf signature mismatch")
           (printed "ca signature mismatch")) );
    ( "derx: (l) the fifteen words are pairwise distinct",
      Int.equal
        (List.length
           (List.sort_uniq String.compare
              [
                "chain length"; "der"; "root pin"; "version";
                "signature algorithm"; "public key"; "critical extension";
                "not yet valid"; "expired"; "issuer"; "ca"; "key usage";
                "sgx extension"; "leaf signature mismatch";
                "ca signature mismatch";
              ]))
        15 );
    ( "derx: (l) the ca word is never confused with a signature word",
      (not (String.equal (printed "ca") (printed "ca signature mismatch")))
      && not (String.equal (printed "ca") (printed "key usage")) );
  ]

let () =
  run
    (window_checks @ der_checks @ pin_checks @ oid_checks @ name_checks
   @ time_checks @ ext_checks @ sgx_checks @ leg_checks @ paint_checks
   @ order_checks @ word_checks)
