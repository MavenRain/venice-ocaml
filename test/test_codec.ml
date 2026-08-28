(* M3 codecs: strict hex + strict base64 (url and std alphabets). *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let henc = Venice.Hex.encode
let hdec = Venice.Hex.decode
let hdec_fails (s : string) : bool = Result.is_error (hdec s)
let uenc = Venice.B64.encode_url
let udec = Venice.B64.decode_url
let udec_fails (s : string) : bool = Result.is_error (udec s)
let senc = Venice.B64.encode_std
let sdec = Venice.B64.decode_std
let sdec_fails (s : string) : bool = Result.is_error (sdec s)

(* All 256 byte values, as a literal (no Char.chr anywhere). *)
let all_bytes : string =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  ^ "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
  ^ "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
  ^ "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
  ^ "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
  ^ "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
  ^ "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
  ^ "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
  ^ "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
  ^ "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
  ^ "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
  ^ "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
  ^ "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
  ^ "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
  ^ "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
  ^ "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

let hex_checks : (string * bool) list =
  [ ("hex enc empty", String.equal (henc "") "");
    ("hex dec empty", hdec "" = Ok "");
    ("hex enc bytes", String.equal (henc "\x00\x7f\xff") "007fff");
    ("hex dec lower", hdec "007fff" = Ok "\x00\x7f\xff");
    ("hex dec upper", hdec "007FFF" = Ok "\x00\x7f\xff");
    ("hex dec mixed case", hdec "0a0B0c" = Ok "\x0a\x0b\x0c");
    ("hex roundtrip 256", hdec (henc all_bytes) = Ok all_bytes);
    ("hex enc lowercase only",
     String.equal (henc "\xab\xcd\xef") "abcdef");
    ("hex reject odd length", hdec_fails "f");
    ("hex reject odd length 3", hdec_fails "0ff");
    ("hex reject foreign byte", hdec_fails "0g");
    ("hex reject 0x prefix", hdec_fails "0xff");
    ("hex reject space", hdec_fails "00 ff");
    ("hex reject newline", hdec_fails "00\n");
    ("hex odd is typed",
     hdec "abc" = Error (Venice.Error.Hex_invalid "odd length"));
    ("hex foreign is typed",
     hdec "zz" = Error (Venice.Error.Hex_invalid "byte outside alphabet"))
  ]

let url_checks : (string * bool) list =
  [ ("url enc empty", String.equal (uenc "") "");
    ("url dec empty", udec "" = Ok "");
    ("url enc f", String.equal (uenc "f") "Zg");
    ("url enc fo", String.equal (uenc "fo") "Zm8");
    ("url enc foo", String.equal (uenc "foo") "Zm9v");
    ("url enc foob", String.equal (uenc "foob") "Zm9vYg");
    ("url enc fooba", String.equal (uenc "fooba") "Zm9vYmE");
    ("url enc foobar", String.equal (uenc "foobar") "Zm9vYmFy");
    ("url dec foobar", udec "Zm9vYmFy" = Ok "foobar");
    ("url dec foob", udec "Zm9vYg" = Ok "foob");
    ("url alphabet", String.equal (uenc "\xff\xef") "_-8");
    ("url alphabet dec", udec "_-8" = Ok "\xff\xef");
    ("url roundtrip 256", udec (uenc all_bytes) = Ok all_bytes);
    ("url reject padding", udec_fails "Zg==");
    ("url reject std plus", udec_fails "+A");
    ("url reject std slash", udec_fails "/A");
    ("url reject newline", udec_fails "Zm9v\nZg");
    ("url reject len mod 4 = 1", udec_fails "AAAAA");
    ("url reject trailing bits 2char", udec_fails "Zh");
    ("url reject trailing bits 3char", udec_fails "Zm9");
    ("url accept canonical 3char", udec "Zm8" = Ok "fo");
    ("url padding is typed",
     udec "=" = Error (Venice.Error.B64_invalid "byte outside alphabet"))
  ]

let std_checks : (string * bool) list =
  [ ("std enc empty", String.equal (senc "") "");
    ("std dec empty", sdec "" = Ok "");
    ("std enc f", String.equal (senc "f") "Zg==");
    ("std enc fo", String.equal (senc "fo") "Zm8=");
    ("std enc foo", String.equal (senc "foo") "Zm9v");
    ("std enc foob", String.equal (senc "foob") "Zm9vYg==");
    ("std enc fooba", String.equal (senc "fooba") "Zm9vYmE=");
    ("std enc foobar", String.equal (senc "foobar") "Zm9vYmFy");
    ("std dec f", sdec "Zg==" = Ok "f");
    ("std dec fo", sdec "Zm8=" = Ok "fo");
    ("std dec foobar", sdec "Zm9vYmFy" = Ok "foobar");
    ("std alphabet", String.equal (senc "\xfb\xff") "+/8=");
    ("std alphabet dec", sdec "+/8=" = Ok "\xfb\xff");
    ("std roundtrip 256", sdec (senc all_bytes) = Ok all_bytes);
    ("std reject missing padding 2", sdec_fails "Zg");
    ("std reject missing padding 3", sdec_fails "Zm8");
    ("std reject short padding", sdec_fails "Zg=");
    ("std reject long padding", sdec_fails "Zg===");
    ("std reject over padding", sdec_fails "Zm9v=");
    ("std reject interior padding", sdec_fails "Z=g=");
    ("std reject url dash", sdec_fails "_-8=");
    ("std reject newline", sdec_fails "Zm9v\nZg==");
    ("std reject len mod 4 = 1", sdec_fails "AAAAA===");
    ("std reject trailing bits", sdec_fails "Zh==");
    ("std reject trailing bits 3char", sdec_fails "Zm9=");
    ("std missing padding is typed",
     sdec "Zg" = Error (Venice.Error.B64_invalid "missing padding"));
    ("std pad only rejects", sdec_fails "====")
  ]

let () = run (List.concat [ hex_checks; url_checks; std_checks ])
