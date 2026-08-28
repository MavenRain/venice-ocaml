(* M4: strict JSON with the scaled-decimal extension. Numbers are
   exact sign/mantissa/scale ints; strictness rejections (dup keys,
   depth, digit caps, width caps, exponents, control chars) each get a
   vector. \u escape coverage spans all four UTF-8 lengths, both
   letter cases, surrogate pairs, and every lone-surrogate shape. *)

module J = Venice.Json

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let p = J.parse
let e = J.emit
let p_fails (s : string) : bool = Result.is_error (p s)

let dec (negative : bool) (mantissa : int) (scale : int) : J.dec =
  { J.negative; mantissa; scale }

(* n nested arrays around the literal 1. *)
let nest (n : int) : string =
  String.concat "" (List.init n (fun (_ : int) -> "["))
  ^ "1"
  ^ String.concat "" (List.init n (fun (_ : int) -> "]"))

let emit_checks : (string * bool) list =
  [ ("emit null", String.equal (e J.Jnull) "null");
    ("emit true", String.equal (e (J.Jbool true)) "true");
    ("emit false", String.equal (e (J.Jbool false)) "false");
    ("emit int", String.equal (e (J.Jint 42)) "42");
    ("emit neg int", String.equal (e (J.Jint (-17))) "-17");
    ("emit zero", String.equal (e (J.Jint 0)) "0");
    ("emit string plain", String.equal (e (J.Jstring "abc")) "\"abc\"");
    ("emit string quote+backslash",
     String.equal (e (J.Jstring "a\"b\\c")) "\"a\\\"b\\\\c\"");
    ("emit string nl cr tab",
     String.equal (e (J.Jstring "\n\r\t")) "\"\\n\\r\\t\"");
    ("emit string control",
     String.equal (e (J.Jstring "\x01\x1f")) "\"\\u0001\\u001f\"");
    ("emit string high byte raw",
     String.equal (e (J.Jstring "\xc3\xa9")) "\"\xc3\xa9\"");
    ("emit list", String.equal (e (J.Jlist [ J.Jint 1; J.Jint 2 ])) "[1,2]");
    ("emit empty list", String.equal (e (J.Jlist [])) "[]");
    ("emit obj",
     String.equal (e (J.Jobj [ ("a", J.Jint 1) ])) "{\"a\":1}");
    ("emit empty obj", String.equal (e (J.Jobj [])) "{}");
    ("emit nested",
     String.equal
       (e (J.Jobj [ ("a", J.Jlist [ J.Jnull; J.Jbool true ]) ]))
       "{\"a\":[null,true]}");
    ("emit dec 0.35", String.equal (e (J.Jdec (dec false 35 2))) "0.35");
    ("emit dec -0.5", String.equal (e (J.Jdec (dec true 5 1))) "-0.5");
    ("emit dec 10.50", String.equal (e (J.Jdec (dec false 1050 2))) "10.50");
    ("emit dec 0.005", String.equal (e (J.Jdec (dec false 5 3))) "0.005");
    ("emit dec 0.0", String.equal (e (J.Jdec (dec false 0 1))) "0.0");
    ("emit dec 123.456",
     String.equal (e (J.Jdec (dec false 123456 3))) "123.456");
    ("emit dec clamp scale 0",
     String.equal (e (J.Jdec (dec false 5 0))) "5.0");
    ("emit dec clamp big scale",
     String.equal (e (J.Jdec (dec false 5 25))) "0.000000000000000005");
    ("emit dec clamp negative mantissa",
     String.equal (e (J.Jdec (dec false (-1) 1))) "0.0")
  ]

let int_checks : (string * bool) list =
  [ ("parse 0", p "0" = Ok (J.Jint 0));
    ("parse -0", p "-0" = Ok (J.Jint 0));
    ("parse 42", p "42" = Ok (J.Jint 42));
    ("parse -17", p "-17" = Ok (J.Jint (-17)));
    ("parse ws int", p " 7 " = Ok (J.Jint 7));
    ("parse 18 digits",
     p "999999999999999999" = Ok (J.Jint 999999999999999999));
    ("reject 19 digits", p_fails "9999999999999999999");
    ("reject leading zero", p_fails "01");
    ("reject neg leading zero", p_fails "-01");
    ("reject plus", p_fails "+1");
    ("reject empty", p_fails "");
    ("reject bare minus", p_fails "-")
  ]

let dec_checks : (string * bool) list =
  [ ("parse 0.35", p "0.35" = Ok (J.Jdec (dec false 35 2)));
    ("parse -0.5", p "-0.5" = Ok (J.Jdec (dec true 5 1)));
    ("parse 10.50", p "10.50" = Ok (J.Jdec (dec false 1050 2)));
    ("parse 0.005", p "0.005" = Ok (J.Jdec (dec false 5 3)));
    ("parse -0.0", p "-0.0" = Ok (J.Jdec (dec true 0 1)));
    ("parse 123.456", p "123.456" = Ok (J.Jdec (dec false 123456 3)));
    ("scale preserved 1.50 vs 1.5", p "1.50" <> p "1.5");
    ("parse 18 total digits",
     p "1.23456789012345678"
     = Ok (J.Jdec (dec false 123456789012345678 17)));
    ("reject 19 total digits", p_fails "1.234567890123456789");
    ("reject 5.", p_fails "5.");
    ("reject .5", p_fails ".5");
    ("reject -.5", p_fails "-.5");
    ("reject 0..5", p_fails "0..5");
    ("reject 01.5", p_fails "01.5");
    ("exponent 1e5 named",
     p "1e5" = Error (Venice.Error.Json_invalid "exponent not supported"));
    ("exponent 1E5 named",
     p "1E5" = Error (Venice.Error.Json_invalid "exponent not supported"));
    ("exponent 1.5e3 named",
     p "1.5e3" = Error (Venice.Error.Json_invalid "exponent not supported"));
    ("reject 2e-4", p_fails "2e-4");
    ("reject -1.0E+2", p_fails "-1.0E+2")
  ]

let string_checks : (string * bool) list =
  [ ("parse plain string", p "\"abc\"" = Ok (J.Jstring "abc"));
    ("parse escapes",
     p "\"a\\\"b\\\\c\\nd\\re\\tf\\/g\""
     = Ok (J.Jstring "a\"b\\c\nd\re\tf/g"));
    ("parse u0041", p "\"\\u0041\"" = Ok (J.Jstring "A"));
    ("parse u00ff", p "\"\\u00ff\"" = Ok (J.Jstring "\xc3\xbf"));
    ("parse u00FF upper", p "\"\\u00FF\"" = Ok (J.Jstring "\xc3\xbf"));
    ("parse u0000", p "\"\\u0000\"" = Ok (J.Jstring "\x00"));
    ("parse u00e9 two byte", p "\"\\u00e9\"" = Ok (J.Jstring "\xc3\xa9"));
    ("parse u0100 two byte", p "\"\\u0100\"" = Ok (J.Jstring "\xc4\x80"));
    ("parse u4e2d three byte",
     p "\"\\u4e2d\"" = Ok (J.Jstring "\xe4\xb8\xad"));
    ("parse uffff three byte",
     p "\"\\uffff\"" = Ok (J.Jstring "\xef\xbf\xbf"));
    ("parse surrogate pair four byte",
     p "\"\\ud83d\\ude00\"" = Ok (J.Jstring "\xf0\x9f\x98\x80"));
    ("reject lone high surrogate ud834", p_fails "\"\\ud834\"");
    ("reject lone low surrogate udc00", p_fails "\"\\udc00\"");
    ("reject high surrogate then raw char", p_fails "\"\\ud83dx\"");
    ("reject high surrogate then u0041", p_fails "\"\\ud83d\\u0041\"");
    ("reject uzz41", p_fails "\"\\uzz41\"");
    ("reject short unicode", p_fails "\"\\u00\"");
    ("reject unknown escape", p_fails "\"\\q\"");
    ("reject raw control", p_fails "\"a\x01b\"");
    ("reject unterminated", p_fails "\"abc");
    ("parse raw utf8 bytes",
     p "\"\xc3\xa9\"" = Ok (J.Jstring "\xc3\xa9"))
  ]

let container_checks : (string * bool) list =
  [ ("parse empty list", p "[]" = Ok (J.Jlist []));
    ("parse empty obj", p "{}" = Ok (J.Jobj []));
    ("parse list",
     p "[1,2,3]" = Ok (J.Jlist [ J.Jint 1; J.Jint 2; J.Jint 3 ]));
    ("parse mixed list",
     p "[1,\"a\",true,null,0.5]"
     = Ok
         (J.Jlist
            [ J.Jint 1;
              J.Jstring "a";
              J.Jbool true;
              J.Jnull;
              J.Jdec (dec false 5 1)
            ]));
    ("parse nested list",
     p "[[[]]]" = Ok (J.Jlist [ J.Jlist [ J.Jlist [] ] ]));
    ("parse obj order",
     p "{\"a\":1,\"b\":2}"
     = Ok (J.Jobj [ ("a", J.Jint 1); ("b", J.Jint 2) ]));
    ("parse obj ws",
     p "{ \"a\" : 1 , \"b\" : [ 2 ] }"
     = Ok (J.Jobj [ ("a", J.Jint 1); ("b", J.Jlist [ J.Jint 2 ]) ]));
    ("reject trailing comma list", p_fails "[1,]");
    ("reject leading comma list", p_fails "[,1]");
    ("reject trailing comma obj", p_fails "{\"a\":1,}");
    ("reject bare comma obj", p_fails "{,}");
    ("reject missing colon", p_fails "{\"a\" 1}");
    ("reject missing value", p_fails "{\"a\":}");
    ("reject missing comma list", p_fails "[1 2]");
    ("reject unquoted key", p_fails "{a:1}");
    ("dup key named",
     p "{\"a\":1,\"a\":2}"
     = Error (Venice.Error.Json_invalid "duplicate key"));
    ("reject dup key nested", p_fails "{\"x\":{\"a\":1,\"a\":2}}");
    ("same key sibling objs ok",
     p "{\"x\":{\"a\":1},\"y\":{\"a\":2}}"
     = Ok
         (J.Jobj
            [ ("x", J.Jobj [ ("a", J.Jint 1) ]);
              ("y", J.Jobj [ ("a", J.Jint 2) ])
            ]));
    ("depth 32 ok", Result.is_ok (p (nest 32)));
    ("depth 33 reject", p_fails (nest 33));
    ("reject trailing input", p_fails "1 x");
    ("reject two values", p_fails "{} {}");
    ("trailing ws ok", p "null " = Ok J.Jnull);
    ("parse true", p "true" = Ok (J.Jbool true));
    ("parse false", p "false" = Ok (J.Jbool false));
    ("reject tru", p_fails "tru");
    ("reject truex", p_fails "truex");
    ("reject True", p_fails "True")
  ]

let helper_checks : (string * bool) list =
  let obj = J.Jobj [ ("a", J.Jint 1); ("b", J.Jstring "x") ] in
  [ ("member found", J.member "b" obj = Some (J.Jstring "x"));
    ("member missing", J.member "c" obj = None);
    ("member non-obj", J.member "a" (J.Jlist []) = None);
    ("as_string some", J.as_string (J.Jstring "s") = Some "s");
    ("as_string none", J.as_string (J.Jint 1) = None);
    ("as_int some", J.as_int (J.Jint 5) = Some 5);
    ("as_int none on dec", J.as_int (J.Jdec (dec false 5 1)) = None);
    ("as_bool some", J.as_bool (J.Jbool true) = Some true);
    ("as_bool none", J.as_bool J.Jnull = None);
    ("as_list some", J.as_list (J.Jlist [ J.Jnull ]) = Some [ J.Jnull ]);
    ("as_list none", J.as_list (J.Jobj []) = None);
    ("as_obj some", J.as_obj obj = Some [ ("a", J.Jint 1); ("b", J.Jstring "x") ]);
    ("as_obj none", J.as_obj (J.Jint 1) = None);
    ("as_dec on dec",
     J.as_dec (J.Jdec (dec true 35 2)) = Some (dec true 35 2));
    ("as_dec on int", J.as_dec (J.Jint 7) = Some (dec false 7 0));
    ("as_dec on neg int", J.as_dec (J.Jint (-7)) = Some (dec true 7 0));
    ("as_dec none on min_int", J.as_dec (J.Jint Int.min_int) = None);
    ("as_dec none", J.as_dec (J.Jstring "1") = None)
  ]

(* Container width caps: the duplicate-key scan is linear per member,
   so the caps are what keep object parsing out of unbounded
   quadratic time on hostile input. *)
let width_checks : (string * bool) list =
  let obj_of (n : int) : string =
    "{"
    ^ String.concat ","
        (List.init n (fun (i : int) -> "\"k" ^ string_of_int i ^ "\":1"))
    ^ "}"
  in
  let arr_of (n : int) : string =
    "[" ^ String.concat "," (List.init n (fun (_ : int) -> "1")) ^ "]"
  in
  [ ("object 4096 members ok", Result.is_ok (p (obj_of 4096)));
    ("object 4097 members named",
     p (obj_of 4097) = Error (Venice.Error.Json_invalid "object too wide"));
    ("array 65536 items ok", Result.is_ok (p (arr_of 65536)));
    ("array 65537 items named",
     p (arr_of 65537) = Error (Venice.Error.Json_invalid "array too long"))
  ]

let roundtrip_checks : (string * bool) list =
  let canonical = "{\"a\":0.35,\"b\":[1,-2.50,\"x\"],\"c\":null}" in
  let built =
    J.Jobj
      [ ("bal", J.Jdec (dec false 35 2));
        ("n", J.Jint (-3));
        ("row", J.Jlist [ J.Jbool false; J.Jstring "s\n"; J.Jdec (dec true 5 3) ])
      ]
  in
  let ctrl = "\x00\x01\x02\x1e\x1f" in
  [ ("emit.parse canonical",
     Result.map e (p canonical) = Ok canonical);
    ("parse.emit built", p (e built) = Ok built);
    ("control chars round trip",
     p (e (J.Jstring ctrl)) = Ok (J.Jstring ctrl))
  ]

let () =
  run
    (List.concat
       [ emit_checks;
         int_checks;
         dec_checks;
         string_checks;
         container_checks;
         helper_checks;
         width_checks;
         roundtrip_checks
       ])
