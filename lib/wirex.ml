(* M13 wirex: incremental head reader. Pure, total, bounded, no
   mutation. Byte scanning converts each buffer to a char list ONCE
   per feed and walks it tail-recursively (the ssex A9 rule); pieces
   rejoin through String.of_seq. ZxCaml trap 2: every scalar limit is
   a unit function. *)

type head =
  { version : string;
    status : int;
    reason : string;
    pairs : (string * string) list }

type t =
  { buf : string;
    skipped : int;
    max : int }

type step =
  | More of t
  | Head of head * string

let fail (msg : string) : ('a, Errx.t) result = Error (Errx.Wire_invalid msg)
let chars (s : string) : char list = List.of_seq (String.to_seq s)
let str_of (cs : char list) : string = String.of_seq (List.to_seq cs)
let max_head_default (() : unit) : int = 65536

(* curl prints at most a handful of interim responses; four is
   generous and bounds the work a hostile origin can force. *)
let max_informational (() : unit) : int = 4

(* ---------- line scanning ---------- *)

type scan =
  | Need_more
  | Bare_cr
  | Line of string * char list

(* One line, terminator excluded. CRLF and bare LF both terminate
   (A15), per line. A CR followed by anything but LF is a bare CR and
   rejects; a CR at the very end of the buffer is simply incomplete. *)
let rec scan_line (acc : char list) (cs : char list) : scan =
  match cs with
  | [] -> Need_more
  | '\n' :: rest -> Line (str_of (List.rev acc), rest)
  | '\r' :: '\n' :: rest -> Line (str_of (List.rev acc), rest)
  | '\r' :: [] -> Need_more
  | '\r' :: _ :: _ -> Bare_cr
  | c :: rest -> scan_line (c :: acc) rest

let rec take_while (p : char -> bool) (acc : char list) (cs : char list) :
    string * char list =
  match cs with
  | c :: rest when p c -> take_while p (c :: acc) rest
  | [] -> (str_of (List.rev acc), [])
  | _ :: _ -> (str_of (List.rev acc), cs)

let is_digit (c : char) : bool =
  match c with
  | '0' .. '9' -> true
  | _ -> false

let is_ws (c : char) : bool = Char.equal c ' ' || Char.equal c '\t'

let rec drop_ws (cs : char list) : char list =
  match cs with
  | c :: rest when is_ws c -> drop_ws rest
  | [] -> []
  | _ :: _ -> cs

let trim_ows (s : string) : string =
  str_of (List.rev (drop_ws (List.rev (drop_ws (chars s)))))

(* ---------- status line ---------- *)

(* HTTP-version is DIGIT ["." DIGIT]: "1.1" from HTTP/1.x, "2" from
   the synthesized HTTP/2 line. *)
let version_ok (v : string) : bool =
  match chars v with
  | [ a ] -> is_digit a
  | [ a; '.'; b ] -> is_digit a && is_digit b
  | _ -> false

let parse_reason (r : char list) : (string, Errx.t) result =
  match r with
  | [] -> Ok ""
  | ' ' :: rest -> Ok (str_of rest)
  | _ :: _ -> fail "status line: junk after the status code"

let parse_code (r : char list) : (int * string, Errx.t) result =
  let code, rest = take_while is_digit [] r in
  match String.length code with
  | 3 ->
    Option.fold
      ~none:(fail "status line: unreadable status code")
      ~some:(fun (n : int) ->
        Result.map (fun (rs : string) -> (n, rs)) (parse_reason rest))
      (int_of_string_opt code)
  | _ -> fail "status line: status code is not three digits"

let parse_after_version (ver : string) (r : char list) :
    (string * int * string, Errx.t) result =
  match r with
  | ' ' :: rest ->
    Result.map
      (fun ((n : int), (rs : string)) -> (ver, n, rs))
      (parse_code rest)
  | _ -> fail "status line: no space after the version"

let parse_status (line : string) : (string * int * string, Errx.t) result =
  match chars line with
  | 'H' :: 'T' :: 'T' :: 'P' :: '/' :: rest ->
    let ver, r1 = take_while (fun (c : char) -> not (Char.equal c ' ')) [] rest in
    (match () with
    | () when not (version_ok ver) ->
      fail ("status line: bad HTTP version " ^ ver)
    | () -> parse_after_version ver r1)
  | _ -> fail "status line: does not start with HTTP/"

(* ---------- header lines ---------- *)

let tchar (c : char) : bool =
  match c with
  | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' -> true
  | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_'
  | '`' | '|' | '~' ->
    true
  | _ -> false

(* A response value may hold any byte from SP up, the high range
   included (servers do send Latin-1 in reason-shaped values); a
   control byte other than HTAB rejects. *)
let value_byte (c : char) : bool =
  let n = Char.code c in
  n >= 0x20 || n = 0x09

let parse_value (name : string) (v : char list) :
    (string * string, Errx.t) result =
  let value = trim_ows (str_of v) in
  match () with
  | () when not (List.for_all value_byte (chars value)) ->
    fail ("header line: forbidden byte in the value of " ^ name)
  | () -> Ok (name, value)

let parse_header (line : string) : (string * string, Errx.t) result =
  let name, rest =
    take_while (fun (c : char) -> not (Char.equal c ':')) [] (chars line)
  in
  match rest with
  | ':' :: v ->
    (match () with
    | () when String.length name = 0 -> fail "header line: empty name"
    | () when not (List.for_all tchar (chars name)) ->
      fail ("header line: non-token byte in the name " ^ name)
    | () -> parse_value name v)
  | _ -> fail "header line: no colon"

let obs_fold (line : string) : bool =
  Option.fold ~none:false
    ~some:(fun (n : int) -> n = 0x20 || n = 0x09)
    (Bytesx.u8 line 0)

(* ---------- one head block ---------- *)

type block =
  | Need
  | Done of head * char list

let rec read_headers (ver : string) (code : int) (reason : string)
    (acc : (string * string) list) (cs : char list) : (block, Errx.t) result =
  match scan_line [] cs with
  | Need_more -> Ok Need
  | Bare_cr -> fail "bare CR in the head"
  | Line (line, rest) ->
    (match () with
    | () when String.length line = 0 ->
      Ok
        (Done
           ( { version = ver; status = code; reason; pairs = List.rev acc },
             rest ))
    | () when obs_fold line -> fail "obs-fold continuation line"
    | () ->
      Result.bind (parse_header line) (fun (p : string * string) ->
          read_headers ver code reason (p :: acc) rest))

let read_block (cs : char list) : (block, Errx.t) result =
  match scan_line [] cs with
  | Need_more -> Ok Need
  | Bare_cr -> fail "bare CR in the head"
  | Line (line, rest) ->
    Result.bind (parse_status line)
      (fun ((v : string), (c : int), (r : string)) ->
        read_headers v c r [] rest)

(* ---------- informational skipping ---------- *)

type outcome =
  | Pending of int * char list
  | Complete of head * char list

let informational (h : head) : bool = h.status >= 100 && h.status <= 199

let rec consume (skipped : int) (cs : char list) : (outcome, Errx.t) result =
  Result.bind (read_block cs) (fun (b : block) ->
      match b with
      | Need -> Ok (Pending (skipped, cs))
      | Done (h, rest) ->
        (match () with
        | () when not (informational h) -> Ok (Complete (h, rest))
        | () when skipped >= max_informational () ->
          fail
            ("more than "
            ^ string_of_int (max_informational ())
            ^ " informational blocks")
        | () -> consume (skipped + 1) rest))

(* ---------- interface ---------- *)

let make ?(max_head_bytes : int = max_head_default ()) (() : unit) :
    (t, Errx.t) result =
  match () with
  | () when max_head_bytes < 1 -> fail "make: max_head_bytes must be >= 1"
  | () -> Ok { buf = ""; skipped = 0; max = max_head_bytes }

let grow (t : t) (chunk : string) : (step, Errx.t) result =
  let buf = t.buf ^ chunk in
  Result.bind (consume t.skipped (chars buf)) (fun (o : outcome) ->
      match o with
      | Complete (h, rest) -> Ok (Head (h, str_of rest))
      | Pending (sk, rest) ->
        let kept = str_of rest in
        (match () with
        | () when String.length kept > t.max ->
          fail ("head exceeds " ^ string_of_int t.max ^ " bytes")
        | () -> Ok (More { t with buf = kept; skipped = sk })))

let feed (t : t) (chunk : string) : (step, Errx.t) result =
  Result.bind (consume t.skipped (chars t.buf)) (fun (o : outcome) ->
      match o with
      | Complete (_, _) -> fail "feed: the head is already complete"
      | Pending (_, _) -> grow t chunk)
