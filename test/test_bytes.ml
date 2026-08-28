(* M3 total cursor readers. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module C = Venice.Cursor

(* Nine distinct bytes: offsets are recognizable in every read. *)
let buf : string = "\x01\x02\x03\x04\x05\x06\x07\x08\x09"
let all_ff : string = "\xff\xff\xff\xff\xff\xff\xff\xff"

let checks : (string * bool) list =
  [ ("u8 first", C.u8 buf 0 = Some 1);
    ("u8 last", C.u8 buf 8 = Some 9);
    ("u8 past end", C.u8 buf 9 = None);
    ("u8 negative", C.u8 buf (-1) = None);
    ("u8 empty", C.u8 "" 0 = None);
    ("u16le start", C.u16le buf 0 = Some 0x0201);
    ("u16le mid", C.u16le buf 3 = Some 0x0504);
    ("u16le last fit", C.u16le buf 7 = Some 0x0908);
    ("u16le one short", C.u16le buf 8 = None);
    ("u16le negative", C.u16le buf (-1) = None);
    ("u32le start", C.u32le buf 0 = Some 0x04030201);
    ("u32le last fit", C.u32le buf 5 = Some 0x09080706);
    ("u32le one short", C.u32le buf 6 = None);
    ("u32le top bit", C.u32le "\x00\x00\x00\x80" 0 = Some 0x80000000);
    ("u64le start", C.u64le buf 0 = Some 0x0807060504030201L);
    ("u64le shift one", C.u64le buf 1 = Some 0x0908070605040302L);
    ("u64le one short", C.u64le buf 2 = None);
    ("u64le lossless top byte", C.u64le all_ff 0 = Some 0xffffffffffffffffL);
    ("u64le top bit alone",
     C.u64le "\x00\x00\x00\x00\x00\x00\x00\x80" 0 = Some 0x8000000000000000L);
    ("take whole", C.take buf 0 9 = Some buf);
    ("take inner", C.take buf 2 3 = Some "\x03\x04\x05");
    ("take empty at start", C.take buf 0 0 = Some "");
    ("take empty at end", C.take buf 9 0 = Some "");
    ("take offset past end", C.take buf 10 0 = None);
    ("take window past end", C.take buf 7 3 = None);
    ("take len past end", C.take buf 0 10 = None);
    ("take negative offset", C.take buf (-1) 1 = None);
    ("take negative len", C.take buf 3 (-1) = None);
    ("take huge offset", C.take buf max_int 1 = None);
    ("take huge len none", C.take buf 5 max_int = None);
    ("u8 huge offset", C.u8 buf max_int = None)
  ]

let () = run checks
