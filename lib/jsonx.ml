(* Strict minimal JSON, ported from jose-caml (x402-caml lineage) with
   the scaled-decimal extension DESIGN section 6 requires: a number
   with a fraction part parses to sign/mantissa/scale ints, so no
   float ever crosses the core. Token input is attacker-controlled,
   so: nesting depth cap, digit-count cap (every accepted mantissa
   fits a 63-bit int), duplicate-key rejection at every depth, raw
   control characters rejected in strings, canonical integers only
   (no leading zeros), exponents rejected, object and array width
   caps. \u escapes cover all of Unicode: each escape decodes to a
   16-bit code unit, a high/low surrogate pair combines into one code
   point, and the result is emitted as UTF-8. A lone surrogate (high
   with no valid low escape after it, or a bare low) is rejected.
   ZxCaml trap 2: the scalar limits are unit functions. *)

type dec = { negative : bool; mantissa : int; scale : int }

type t =
  | Jnull
  | Jbool of bool
  | Jint of int
  | Jdec of dec
  | Jstring of string
  | Jlist of t list
  | Jobj of (string * t) list

let ( let* ) = Result.bind

let fail (msg : string) : ('a, Errx.t) result = Error (Errx.Json_invalid msg)

(* Token input is untrusted: cap container nesting so a hostile
   payload cannot exhaust the stack. *)
let max_depth (() : unit) : int = 32

(* At most 18 digits across the integer and fraction parts together:
   every accepted mantissa fits a 63-bit int, so the fold in
   parse_number_body can never wrap. *)
let max_digits (() : unit) : int = 18

(* Container width caps. The duplicate-key test is a linear scan per
   member, so an uncapped member count would make object parsing
   quadratic in attacker-controlled input; the cap bounds that work.
   The array cap bounds the accumulator the same way. *)
let max_members (() : unit) : int = 4096
let max_items (() : unit) : int = 65536

(* ---------- emitter ---------- *)

let escape_char (c : char) : string =
  match c with
  | '"' -> "\\\""
  | '\\' -> "\\\\"
  | '\n' -> "\\n"
  | '\r' -> "\\r"
  | '\t' -> "\\t"
  | _ ->
    if Char.code c < 32 then "\\u00" ^ Hexx.encode (String.make 1 c)
    else String.make 1 c

let escape_string (s : string) : string =
  String.concat "" (List.map escape_char (List.of_seq (String.to_seq s)))

(* Total decimal emitter. Every parser-minted record emits exactly:
   the parser mints only mantissa >= 0 and 1 <= scale < max_digits ().
   A hand-built record may hold anything, so the emitter clamps rather
   than raising: mantissa clamps to [0, max_int] (a negative mantissa,
   min_int included, emits as 0) and scale clamps to
   [0, max_digits ()]. Out-of-range records therefore emit
   best-effort, not exactly. The emitted form always carries a '.', so
   a Jdec never re-parses as a Jint. *)
let emit_dec (d : dec) : string =
  let sign = if d.negative then "-" else "" in
  let m = Int.max 0 d.mantissa in
  let scale = Int.min (max_digits ()) (Int.max 0 d.scale) in
  if Int.equal scale 0 then sign ^ string_of_int m ^ ".0"
  else
    let digits = string_of_int m in
    let pad = Int.max 0 (scale + 1 - String.length digits) in
    let padded = String.make pad '0' ^ digits in
    let cut = String.length padded - scale in
    let int_part = String.of_seq (Seq.take cut (String.to_seq padded)) in
    let frac_part = String.of_seq (Seq.drop cut (String.to_seq padded)) in
    sign ^ int_part ^ "." ^ frac_part

let rec emit (v : t) : string =
  match v with
  | Jnull -> "null"
  | Jbool b -> if b then "true" else "false"
  | Jint n -> string_of_int n
  | Jdec d -> emit_dec d
  | Jstring s -> "\"" ^ escape_string s ^ "\""
  | Jlist items -> "[" ^ String.concat "," (List.map emit items) ^ "]"
  | Jobj fields ->
    "{"
    ^ String.concat ","
        (List.map
           (fun ((k : string), (v : t)) ->
             "\"" ^ escape_string k ^ "\":" ^ emit v)
           fields)
    ^ "}"

(* ---------- parser ---------- *)

let rec skip_ws (cs : char list) : char list =
  match cs with
  | ' ' :: rest | '\n' :: rest | '\r' :: rest | '\t' :: rest -> skip_ws rest
  | _ -> cs

let expect (c : char) (cs : char list) : (char list, Errx.t) result =
  match cs with
  | h :: rest when Char.equal h c -> Ok rest
  | _ -> fail ("expected '" ^ String.make 1 c ^ "'")

let literal (word : string) (value : t) (cs : char list) :
    (t * char list, Errx.t) result =
  let rec eat (want : char list) (have : char list) :
      (t * char list, Errx.t) result =
    match want with
    | [] -> Ok (value, have)
    | w :: ws ->
      (match have with
       | h :: hs when Char.equal h w -> eat ws hs
       | _ -> fail ("expected literal " ^ word))
  in
  eat (List.of_seq (String.to_seq word)) cs

(* \uXXXX resolves through the strict hex decoder (both letter cases):
   the four hex chars decode to two bytes, recombined big-endian into
   one 16-bit code unit. *)
let code_unit (h1 : char) (h2 : char) (h3 : char) (h4 : char) : int option =
  Option.bind
    (Result.to_option
       (Hexx.decode (String.of_seq (List.to_seq [ h1; h2; h3; h4 ]))))
    (fun bytes ->
      Option.bind (Bytesx.u8 bytes 0) (fun hi ->
          Option.map (fun (lo : int) -> (hi * 256) + lo) (Bytesx.u8 bytes 1)))

let high_surrogate (code : int) : bool = 0xD800 <= code && code <= 0xDBFF
let low_surrogate (code : int) : bool = 0xDC00 <= code && code <= 0xDFFF

(* A surrogate pair carries one code point above the BMP. *)
let combine_surrogates (hi : int) (lo : int) : int =
  0x10000 + ((hi - 0xD800) * 0x400) + (lo - 0xDC00)

(* UTF-8 encode one code point through the total byte builder: the
   band-and-or arithmetic keeps every element inside [0, 255]. *)
let utf8_of_code_point (cp : int) : string =
  match () with
  | () when cp < 0x80 -> Bytesx.of_codes [ cp ]
  | () when cp < 0x800 ->
    Bytesx.of_codes [ 0xC0 lor (cp lsr 6); 0x80 lor (cp land 0x3F) ]
  | () when cp <= 0xFFFF ->
    Bytesx.of_codes
      [ 0xE0 lor (cp lsr 12);
        0x80 lor ((cp lsr 6) land 0x3F);
        0x80 lor (cp land 0x3F)
      ]
  | () ->
    Bytesx.of_codes
      [ 0xF0 lor (cp lsr 18);
        0x80 lor ((cp lsr 12) land 0x3F);
        0x80 lor ((cp lsr 6) land 0x3F);
        0x80 lor (cp land 0x3F)
      ]

let parse_string_body (cs : char list) : (string * char list, Errx.t) result =
  let rec go (acc : string list) (rest : char list) :
      (string * char list, Errx.t) result =
    match rest with
    | [] -> fail "unterminated string"
    | '"' :: tail -> Ok (String.concat "" (List.rev acc), tail)
    | '\\' :: '"' :: tail -> go ("\"" :: acc) tail
    | '\\' :: '\\' :: tail -> go ("\\" :: acc) tail
    | '\\' :: 'n' :: tail -> go ("\n" :: acc) tail
    | '\\' :: 'r' :: tail -> go ("\r" :: acc) tail
    | '\\' :: 't' :: tail -> go ("\t" :: acc) tail
    | '\\' :: '/' :: tail -> go ("/" :: acc) tail
    | '\\' :: 'u' :: h1 :: h2 :: h3 :: h4 :: tail ->
      Option.fold (code_unit h1 h2 h3 h4)
        ~none:(fail "unsupported unicode escape")
        ~some:(fun (code : int) -> unit_step acc code tail)
    | '\\' :: _ -> fail "unsupported escape"
    | c :: tail ->
      if Char.code c < 32 then fail "raw control character in string"
      else go (String.make 1 c :: acc) tail
  (* One decoded code unit: a bare low surrogate is never valid, a
     high surrogate must pair, anything else stands alone. *)
  and unit_step (acc : string list) (code : int) (rest : char list) :
      (string * char list, Errx.t) result =
    match () with
    | () when low_surrogate code -> fail "unsupported unicode escape"
    | () when high_surrogate code -> pair_step acc code rest
    | () -> go (utf8_of_code_point code :: acc) rest
  (* The high surrogate must be followed immediately by a second \u
     escape whose code unit is a low surrogate; the pair consumes all
     twelve characters. *)
  and pair_step (acc : string list) (hi : int) (rest : char list) :
      (string * char list, Errx.t) result =
    match rest with
    | '\\' :: 'u' :: l1 :: l2 :: l3 :: l4 :: tail ->
      Option.fold (code_unit l1 l2 l3 l4)
        ~none:(fail "unsupported unicode escape")
        ~some:(fun (lo : int) ->
          if low_surrogate lo then
            go (utf8_of_code_point (combine_surrogates hi lo) :: acc) tail
          else fail "unsupported unicode escape")
    | _ -> fail "unsupported unicode escape"
  in
  go [] cs

let digit_value (c : char) : int option =
  let n = Char.code c - Char.code '0' in
  if 0 <= n && n <= 9 then Some n else None

(* Collect a run of decimal digits, highest first. The count cap
   bounds each run; parse_number_body re-checks the combined
   integer + fraction count before folding a mantissa. The inner loop
   returns the accumulator unreversed because Option.fold ~none: is
   eager: a List.rev there would run once per digit. The single
   reversal happens at the exit. *)
let span_digits (cs : char list) : (int list * char list, Errx.t) result =
  let rec go (acc : int list) (count : int) (rest : char list) :
      (int list * char list, Errx.t) result =
    match rest with
    | c :: tail ->
      Option.fold (digit_value c)
        ~none:(Ok (acc, rest))
        ~some:(fun d ->
          if count >= max_digits () then fail "number out of range"
          else go (d :: acc) (count + 1) tail)
    | [] -> Ok (acc, [])
  in
  Result.map
    (fun ((acc : int list), (rest : char list)) -> (List.rev acc, rest))
    (go [] 0 cs)

let fold_digits (ds : int list) : int =
  List.fold_left (fun acc d -> (acc * 10) + d) 0 ds

let exponent_follows (cs : char list) : bool =
  match cs with
  | ('e' | 'E') :: _ -> true
  | _ -> false

let parse_number_body (cs : char list) : (t * char list, Errx.t) result =
  let negative, cs =
    match cs with
    | '-' :: rest -> (true, rest)
    | _ -> (false, cs)
  in
  let* int_digits, rest = span_digits cs in
  let icount = List.length int_digits in
  let leading_zero =
    match int_digits with
    | 0 :: _ :: _ -> true
    | _ -> false
  in
  match () with
  | () when Int.equal icount 0 -> fail "expected digit"
  | () when leading_zero -> fail "leading zero"
  | () ->
    (match rest with
     | '.' :: tail ->
       let* frac_digits, rest = span_digits tail in
       let fcount = List.length frac_digits in
       (match () with
        | () when Int.equal fcount 0 -> fail "expected digit after '.'"
        | () when icount + fcount > max_digits () ->
          fail "number out of range"
        | () when exponent_follows rest -> fail "exponent not supported"
        | () ->
          Ok
            ( Jdec
                { negative;
                  mantissa = fold_digits (int_digits @ frac_digits);
                  scale = fcount
                },
              rest ))
     | rest when exponent_follows rest -> fail "exponent not supported"
     | _ ->
       let value = fold_digits int_digits in
       Ok (Jint (if negative then -value else value), rest))

let rec parse_value (depth : int) (cs : char list) :
    (t * char list, Errx.t) result =
  match skip_ws cs with
  | [] -> fail "unexpected end of input"
  | '"' :: rest ->
    let* s, rest = parse_string_body rest in
    Ok (Jstring s, rest)
  | 't' :: _ as rest -> literal "true" (Jbool true) rest
  | 'f' :: _ as rest -> literal "false" (Jbool false) rest
  | 'n' :: _ as rest -> literal "null" Jnull rest
  | '[' :: rest ->
    if depth >= max_depth () then fail "too deeply nested"
    else parse_list (depth + 1) [] 0 (skip_ws rest)
  | '{' :: rest ->
    if depth >= max_depth () then fail "too deeply nested"
    else parse_obj (depth + 1) [] 0 (skip_ws rest)
  | rest -> parse_number_body rest

(* count is the number of elements already in acc, carried as an
   accumulator: a List.length per element would itself be quadratic. *)
and parse_list (depth : int) (acc : t list) (count : int) (cs : char list) :
    (t * char list, Errx.t) result =
  match cs with
  | ']' :: rest -> Ok (Jlist (List.rev acc), rest)
  | _ when count >= max_items () -> fail "array too long"
  | _ ->
    let* v, rest = parse_value depth cs in
    (match skip_ws rest with
     | ',' :: tail ->
       (match skip_ws tail with
        | ']' :: _ -> fail "expected value after ','"
        | t2 -> parse_list depth (v :: acc) (count + 1) t2)
     | ']' :: tail -> Ok (Jlist (List.rev (v :: acc)), tail)
     | _ -> fail "expected ',' or ']'")

and parse_obj (depth : int) (acc : (string * t) list) (count : int)
    (cs : char list) : (t * char list, Errx.t) result =
  match cs with
  | '}' :: rest -> Ok (Jobj (List.rev acc), rest)
  | '"' :: rest ->
    let* k, rest = parse_string_body rest in
    (match () with
     | () when count >= max_members () -> fail "object too wide"
     | () when List.mem_assoc k acc -> fail "duplicate key"
     | () ->
       let* rest = expect ':' (skip_ws rest) in
       let* v, rest = parse_value depth rest in
       (match skip_ws rest with
        | ',' :: tail ->
          (match skip_ws tail with
           | '"' :: _ as t2 -> parse_obj depth ((k, v) :: acc) (count + 1) t2
           | _ -> fail "expected key after ','")
        | '}' :: tail -> Ok (Jobj (List.rev ((k, v) :: acc)), tail)
        | _ -> fail "expected ',' or '}'"))
  | _ -> fail "expected key or '}'"

let parse (s : string) : (t, Errx.t) result =
  let* v, rest = parse_value 0 (List.of_seq (String.to_seq s)) in
  match skip_ws rest with
  | [] -> Ok v
  | _ :: _ -> fail "trailing input"

(* ---------- helpers ---------- *)

let member (name : string) (v : t) : t option =
  match v with
  | Jobj fields -> List.assoc_opt name fields
  | Jnull | Jbool _ | Jint _ | Jdec _ | Jstring _ | Jlist _ -> None

let as_string (v : t) : string option =
  match v with
  | Jstring s -> Some s
  | Jnull | Jbool _ | Jint _ | Jdec _ | Jlist _ | Jobj _ -> None

let as_int (v : t) : int option =
  match v with
  | Jint n -> Some n
  | Jnull | Jbool _ | Jdec _ | Jstring _ | Jlist _ | Jobj _ -> None

let as_bool (v : t) : bool option =
  match v with
  | Jbool b -> Some b
  | Jnull | Jint _ | Jdec _ | Jstring _ | Jlist _ | Jobj _ -> None

let as_list (v : t) : t list option =
  match v with
  | Jlist items -> Some items
  | Jnull | Jbool _ | Jint _ | Jdec _ | Jstring _ | Jobj _ -> None

let as_obj (v : t) : (string * t) list option =
  match v with
  | Jobj fields -> Some fields
  | Jnull | Jbool _ | Jint _ | Jdec _ | Jstring _ | Jlist _ -> None

(* Numeric view: an integer reads as a scale-zero decimal, so one case
   consumes any wire number (balance, price, sampling parameter). The
   parser caps mantissas at 18 digits, so the abs cannot overflow.
   Jint min_int is the one unrepresentable case: its magnitude has no
   non-negative int, and Int.abs min_int stays negative, so it reads
   as None rather than breaking the mantissa >= 0 invariant. *)
let as_dec (v : t) : dec option =
  match v with
  | Jint n when Int.equal n Int.min_int -> None
  | Jint n -> Some { negative = n < 0; mantissa = Int.abs n; scale = 0 }
  | Jdec d -> Some d
  | Jnull | Jbool _ | Jstring _ | Jlist _ | Jobj _ -> None

(* ---------- canonical-decimal order ---------- *)

(* The one order on canonical decimals (nonnegative mantissa below
   10^18, scale 0..18, the shape the number parser mints). Moved here
   from paramsx so the repo keeps exactly one definition; public as
   Venice.Json.compare_dec. *)

let zeros (n : int) : string = if n <= 0 then "" else String.make n '0'

(* Magnitude order of two canonical decimals, total over zero: a zero
   mantissa is the least magnitude whatever its scale, so no caller
   ordering can misread a right-padded "0". For nonzero inputs,
   right-pad both digit strings to a common scale; with no leading
   zeros the longer string is the larger number, and equal lengths
   compare byte-wise. *)
let compare_mag (a : dec) (b : dec) : int =
  let s = max a.scale b.scale in
  let da = string_of_int a.mantissa ^ zeros (s - a.scale) in
  let db = string_of_int b.mantissa ^ zeros (s - b.scale) in
  match () with
  | () when a.mantissa = 0 && b.mantissa = 0 -> 0
  | () when a.mantissa = 0 -> -1
  | () when b.mantissa = 0 -> 1
  | () when String.length da < String.length db -> -1
  | () when String.length da > String.length db -> 1
  | () -> String.compare da db

(* Sign with zero normalized: mantissa 0 is zero whatever the printed
   scale or negative flag, so "-0.0" sits with 0. *)
let sign_of (d : dec) : int =
  match () with
  | () when d.mantissa = 0 -> 0
  | () when d.negative -> -1
  | () -> 1

(* Total order on canonical decimals. *)
let compare_dec (a : dec) (b : dec) : int =
  let sa = sign_of a in
  let sb = sign_of b in
  match () with
  | () when sa < sb -> -1
  | () when sa > sb -> 1
  | () when sa = 0 -> 0
  | () when sa > 0 -> compare_mag a b
  | () -> compare_mag b a
