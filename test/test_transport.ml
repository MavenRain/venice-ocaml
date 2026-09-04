(* M13 transport, pure half: the key newtype, the endpoint, the route
   index, the request mint with its percent-encoding and header
   tables, the curl config goldens, the incremental head reader with
   its A15 terminators, and the scripted Fake transport. The curl
   subprocess itself is test_curlx.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal modules by their mangled names, exactly as
   test_ssex does. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module K = Venice__Keyx
module H = Venice__Httpx
module C = Venice__Cfgx
module W = Venice__Wirex
module F = Venice__Fakex
module J = Venice__Jsonx
module B = Venice__Bytesx
module E = Venice__Errx

(* ---------- small helpers ---------- *)

let rejects (r : ('a, E.t) result) : bool = Result.is_error r
let accepts (r : ('a, E.t) result) : bool = Result.is_ok r

let err_is (expect : string) (r : ('a, E.t) result) : bool =
  Result.fold
    ~ok:(fun ((_ : 'a)) -> false)
    ~error:(fun (e : E.t) -> String.equal (E.to_string e) expect)
    r

let contains (hay : string) (needle : string) : bool =
  let n = String.length needle in
  let h = String.length hay in
  let rec go (i : int) : bool =
    match () with
    | () when i + n > h -> false
    | () when
        Option.fold ~none:false ~some:(String.equal needle) (B.take hay i n) ->
      true
    | () -> go (i + 1)
  in
  go 0

let ok_str (r : (string, E.t) result) : string =
  Result.fold ~ok:Fun.id ~error:E.to_string r

let repeat (n : int) (c : char) : string = String.make n c

(* The one test key. Every consumer folds over the result, so no
   partial accessor is needed to get a K.t. *)
let test_key (() : unit) : (K.t, E.t) result = K.make "sk-abc"

(* ---------- Api_key ---------- *)

let byte_key (c : char) : (K.t, E.t) result = K.make ("sk" ^ String.make 1 c)

let key_checks : (string * bool) list =
  [ ("key: empty rejects", rejects (K.make ""));
    ("key: one byte passes", accepts (K.make "x"));
    ("key: SP rejects", rejects (byte_key ' '));
    ("key: HTAB rejects", rejects (byte_key '\t'));
    ("key: CR rejects", rejects (byte_key '\r'));
    ("key: LF rejects", rejects (byte_key '\n'));
    ("key: NUL rejects", rejects (byte_key '\000'));
    ("key: DEL rejects", rejects (byte_key '\127'));
    ("key: 0x80 rejects", rejects (byte_key '\128'));
    ("key: 0x21 passes", accepts (byte_key '!'));
    ("key: 0x7E passes", accepts (byte_key '~'));
    ("key: 512 bytes passes", accepts (K.make (repeat 512 'a')));
    ("key: 513 bytes rejects", rejects (K.make (repeat 513 'a')));
    ( "key: empty text names the check",
      err_is "key: make: empty key" (K.make "") );
    ( "key: length text names the cap",
      err_is "key: make: key longer than 512 bytes" (K.make (repeat 513 'a'))
    );
    ( "key: byte text names the range",
      err_is "key: make: key holds a byte outside 0x21..0x7E" (byte_key ' ') );
    ( "key: reveal round-trips",
      Result.fold ~ok:(fun (k : K.t) -> String.equal (K.reveal k) "sk-abc")
        ~error:(fun ((_ : E.t)) -> false)
        (test_key ()) );
    ( "key: from_env with an empty value rejects",
      (Unix.putenv "VENICE_API_KEY" "";
       let unset =
         err_is "key: from_env: VENICE_API_KEY is not set" (K.from_env ())
       in
       let empty = err_is "key: make: empty key" (K.from_env ()) in
       unset || empty) );
    ( "key: from_env set round-trips through make",
      (Unix.putenv "VENICE_API_KEY" "sk-from-env";
       Result.fold
         ~ok:(fun (k : K.t) -> String.equal (K.reveal k) "sk-from-env")
         ~error:(fun ((_ : E.t)) -> false)
         (K.from_env ())) );
    ( "key: from_env applies the byte rule",
      (Unix.putenv "VENICE_API_KEY" "sk with space";
       rejects (K.from_env ())) )
  ]

(* ---------- Endpoint ---------- *)

let ep (s : string) : (H.Endpoint.t, E.t) result = H.Endpoint.of_string s

let bad_ep (c : char) : (H.Endpoint.t, E.t) result =
  ep ("https://a" ^ String.make 1 c ^ "b")

let endpoint_checks : (string * bool) list =
  [ ( "endpoint: default golden",
      String.equal
        (H.Endpoint.to_string H.Endpoint.default)
        "https://api.venice.ai/api/v1" );
    ( "endpoint: default round-trips through of_string",
      Result.fold
        ~ok:(fun (e : H.Endpoint.t) ->
          String.equal (H.Endpoint.to_string e) "https://api.venice.ai/api/v1")
        ~error:(fun ((_ : E.t)) -> false)
        (ep "https://api.venice.ai/api/v1") );
    ("endpoint: http rejects", rejects (ep "http://api.venice.ai"));
    ("endpoint: no scheme rejects", rejects (ep "api.venice.ai"));
    ("endpoint: trailing slash rejects", rejects (ep "https://a/"));
    ("endpoint: empty host rejects", rejects (ep "https://"));
    ("endpoint: slash host rejects", rejects (ep "https:///x"));
    ("endpoint: SP rejects", rejects (bad_ep ' '));
    ("endpoint: HTAB rejects", rejects (bad_ep '\t'));
    ("endpoint: CR rejects", rejects (bad_ep '\r'));
    ("endpoint: LF rejects", rejects (bad_ep '\n'));
    ("endpoint: NUL rejects", rejects (bad_ep '\000'));
    ("endpoint: DEL rejects", rejects (bad_ep '\127'));
    ("endpoint: 0x80 rejects", rejects (bad_ep '\128'));
    ("endpoint: question mark rejects", rejects (bad_ep '?'));
    ("endpoint: hash rejects", rejects (bad_ep '#'));
    ("endpoint: double quote rejects", rejects (bad_ep '"'));
    ("endpoint: backslash rejects", rejects (bad_ep '\\'));
    ("endpoint: path segments pass", accepts (ep "https://a.b/api/v1"));
    ( "endpoint: 2048 bytes passes",
      accepts (ep ("https://" ^ repeat 2040 'a')) );
    ( "endpoint: 2049 bytes rejects",
      rejects (ep ("https://" ^ repeat 2041 'a')) )
  ]

(* ---------- Route ---------- *)

let route_checks : (string * bool) list =
  [ ( "route: chat path",
      String.equal (H.Route.path H.Route.chat_completions) "/chat/completions"
    );
    ("route: models path", String.equal (H.Route.path H.Route.models) "/models");
    ( "route: attestation path",
      String.equal (H.Route.path H.Route.tee_attestation) "/tee/attestation" );
    ( "route: signature path",
      String.equal (H.Route.path H.Route.tee_signature) "/tee/signature" )
  ]

(* ---------- Request ---------- *)

let getq (q : (string * string) list) : (H.Request.t, E.t) result =
  H.Request.get ~query:q H.Route.models

let geth (h : (string * string) list) : (H.Request.t, E.t) result =
  H.Request.get ~headers:h H.Route.models

let url_of (r : (H.Request.t, E.t) result) : string =
  Result.fold
    ~ok:(fun (x : H.Request.t) -> H.Request.url H.Endpoint.default x)
    ~error:E.to_string r

let log_of (r : (H.Request.t, E.t) result) : string =
  Result.fold ~ok:H.Request.to_log ~error:E.to_string r

let body_json : J.t = J.Jobj [ ("a", J.Jstring "b") ]

let post_req : (H.Request.t, E.t) result =
  H.Request.post H.Route.chat_completions ~body:body_json

let reserved_names : string list =
  [ "authorization"; "proxy-authorization"; "cookie"; "content-type";
    "content-length"; "host"; "expect"; "transfer-encoding"; "connection";
    "accept"; "accept-encoding"; "user-agent" ]

let reserved_checks : (string * bool) list =
  List.map
    (fun (n : string) ->
      ( "request: reserved header " ^ n ^ " rejects",
        rejects (geth [ (n, "v") ]) ))
    reserved_names

let many_pairs (n : int) : (string * string) list =
  List.init n (fun (i : int) -> ("k" ^ string_of_int i, "v"))

let many_headers (n : int) : (string * string) list =
  List.init n (fun (i : int) -> ("h" ^ string_of_int i, "v"))

let bad_value (c : char) : (H.Request.t, E.t) result =
  geth [ ("x-a", "a" ^ String.make 1 c ^ "b") ]

let request_checks : (string * bool) list =
  [ ( "request: get on a GET route passes",
      accepts (H.Request.get H.Route.models) );
    ( "request: get meth is Get",
      Result.fold
        ~ok:(fun (r : H.Request.t) ->
          match H.Request.meth r with
          | H.Request.Get -> true
          | H.Request.Post -> false)
        ~error:(fun ((_ : E.t)) -> false)
        (H.Request.get H.Route.models) );
    ( "request: post meth is Post",
      Result.fold
        ~ok:(fun (r : H.Request.t) ->
          match H.Request.meth r with
          | H.Request.Get -> false
          | H.Request.Post -> true)
        ~error:(fun ((_ : E.t)) -> false)
        post_req );
    ( "request: get path is the route path",
      Result.fold
        ~ok:(fun (r : H.Request.t) -> String.equal (H.Request.path r) "/models")
        ~error:(fun ((_ : E.t)) -> false)
        (H.Request.get H.Route.models) );
    ( "request: get carries no body",
      Result.fold
        ~ok:(fun (r : H.Request.t) ->
          Option.is_none (H.Request.body r)
          && Option.is_none (H.Request.rendered r)
          && H.Request.body_bytes r = 0)
        ~error:(fun ((_ : E.t)) -> false)
        (H.Request.get H.Route.models) );
    ( "request: post renders the body once",
      Result.fold
        ~ok:(fun (r : H.Request.t) ->
          Option.equal String.equal (H.Request.rendered r)
            (Some (J.emit body_json))
          && H.Request.body_bytes r = String.length (J.emit body_json))
        ~error:(fun ((_ : E.t)) -> false)
        post_req );
    ( "request: url with no query emits no question mark",
      String.equal
        (url_of (H.Request.get H.Route.models))
        "https://api.venice.ai/api/v1/models" );
    ( "request: attestation query golden",
      String.equal
        (url_of
           (H.Request.get
              ~query:[ ("model", "venice-uncensored"); ("nonce", "ab12") ]
              H.Route.tee_attestation))
        "https://api.venice.ai/api/v1/tee/attestation?model=venice-uncensored&nonce=ab12"
    );
    ( "request: unreserved bytes pass through",
      String.equal
        (url_of (getq [ ("k", "-._~AZaz09") ]))
        "https://api.venice.ai/api/v1/models?k=-._~AZaz09" );
    ( "request: reserved bytes encode uppercase",
      String.equal
        (url_of (getq [ ("k", "a b/c?d=e&f%g#h") ]))
        "https://api.venice.ai/api/v1/models?k=a%20b%2Fc%3Fd%3De%26f%25g%23h"
    );
    ( "request: plus is encoded, not a space",
      String.equal
        (url_of (getq [ ("k", "a+b") ]))
        "https://api.venice.ai/api/v1/models?k=a%2Bb" );
    ( "request: UTF-8 encodes per byte",
      String.equal
        (url_of (getq [ ("k", "\xc3\xa9") ]))
        "https://api.venice.ai/api/v1/models?k=%C3%A9" );
    ( "request: NUL in a value encodes",
      String.equal
        (url_of (getq [ ("k", "\000") ]))
        "https://api.venice.ai/api/v1/models?k=%00" );
    ( "request: DEL in a value encodes",
      String.equal
        (url_of (getq [ ("k", "\127") ]))
        "https://api.venice.ai/api/v1/models?k=%7F" );
    ("request: empty query value passes", accepts (getq [ ("k", "") ]));
    ("request: empty query key rejects", rejects (getq [ ("", "v") ]));
    ("request: reserved byte in a key rejects", rejects (getq [ ("a b", "v") ]));
    ("request: percent in a key rejects", rejects (getq [ ("a%20b", "v") ]));
    ( "request: duplicate query key rejects",
      rejects (getq [ ("k", "1"); ("k", "2") ]) );
    ("request: 16 query pairs pass", accepts (getq (many_pairs 16)));
    ("request: 17 query pairs reject", rejects (getq (many_pairs 17)));
    ( "request: query order is caller order",
      String.equal
        (url_of (getq [ ("b", "1"); ("a", "2") ]))
        "https://api.venice.ai/api/v1/models?b=1&a=2" );
    ( "request: header name lowercases",
      Result.fold
        ~ok:(fun (r : H.Request.t) ->
          List.equal
            (fun ((a : string), (b : string)) ((c : string), (d : string)) ->
              String.equal a c && String.equal b d)
            (H.Request.headers r)
            [ ("x-trace", "abc") ])
        ~error:(fun ((_ : E.t)) -> false)
        (geth [ ("X-Trace", "abc") ]) );
    ( "request: header mint order is kept",
      Result.fold
        ~ok:(fun (r : H.Request.t) ->
          List.equal String.equal
            (List.map
               (fun ((n : string), (_ : string)) -> n)
               (H.Request.headers r))
            [ "b"; "a" ])
        ~error:(fun ((_ : E.t)) -> false)
        (geth [ ("B", "1"); ("A", "2") ]) );
    ( "request: reserved header rejects in mixed case",
      rejects (geth [ ("Authorization", "v") ]) );
    ( "request: reserved header rejects in upper case",
      rejects (geth [ ("AUTHORIZATION", "v") ]) );
    ( "request: duplicate header rejects across casings",
      rejects (geth [ ("X-A", "1"); ("x-a", "2") ]) );
    ("request: empty header name rejects", rejects (geth [ ("", "v") ]));
    ("request: non-token header name rejects", rejects (geth [ ("x a", "v") ]));
    ("request: colon in a header name rejects", rejects (geth [ ("x:a", "v") ]));
    ( "request: 128-byte header name passes",
      accepts (geth [ (repeat 128 'a', "v") ]) );
    ( "request: 129-byte header name rejects",
      rejects (geth [ (repeat 129 'a', "v") ]) );
    ("request: empty header value rejects", rejects (geth [ ("x-a", "") ]));
    ("request: CR in a value rejects", rejects (bad_value '\r'));
    ("request: LF in a value rejects", rejects (bad_value '\n'));
    ("request: NUL in a value rejects", rejects (bad_value '\000'));
    ("request: DEL in a value rejects", rejects (bad_value '\127'));
    ("request: 0x80 in a value rejects", rejects (bad_value '\128'));
    ("request: interior SP in a value passes", accepts (bad_value ' '));
    ("request: interior HTAB in a value passes", accepts (bad_value '\t'));
    ("request: leading SP in a value rejects", rejects (geth [ ("x-a", " v") ]));
    ( "request: trailing SP in a value rejects",
      rejects (geth [ ("x-a", "v ") ]) );
    ( "request: leading HTAB in a value rejects",
      rejects (geth [ ("x-a", "\tv") ]) );
    ( "request: trailing HTAB in a value rejects",
      rejects (geth [ ("x-a", "v\t") ]) );
    ( "request: 8192-byte value passes",
      accepts (geth [ ("x-a", repeat 8192 'v') ]) );
    ( "request: 8193-byte value rejects",
      rejects (geth [ ("x-a", repeat 8193 'v') ]) );
    ("request: 32 headers pass", accepts (geth (many_headers 32)));
    ("request: 33 headers reject", rejects (geth (many_headers 33)));
    ( "request: body at the 4 MiB cap passes",
      accepts
        (H.Request.post H.Route.chat_completions
           ~body:(J.Jstring (repeat 4_194_302 'x'))) );
    ( "request: body one byte over the cap rejects",
      rejects
        (H.Request.post H.Route.chat_completions
           ~body:(J.Jstring (repeat 4_194_303 'x'))) );
    ( "request: post accepts custom headers",
      accepts
        (H.Request.post
           ~headers:[ ("X-Trace", "abc") ]
           H.Route.chat_completions ~body:body_json) );
    ( "request: get to_log golden",
      String.equal
        (log_of
           (H.Request.get
              ~query:[ ("model", "x y") ]
              ~headers:[ ("X-A", "1"); ("B", "2") ]
              H.Route.models))
        "GET /models?model=x%20y headers=[x-a;b] body_bytes=0" );
    ( "request: post to_log golden",
      String.equal (log_of post_req)
        "POST /chat/completions headers=[] body_bytes=9" );
    ( "request: to_log carries no header value",
      not (contains (log_of (geth [ ("X-Secret", "hunter2") ])) "hunter2") )
  ]

(* ---------- Cfgx ---------- *)

let render_of ~(max_time : int option) (r : (H.Request.t, E.t) result) : string
    =
  Result.fold
    ~ok:(fun (k : K.t) ->
      Result.fold
        ~ok:(fun (x : H.Request.t) ->
          C.render ~key:k ~endpoint:H.Endpoint.default ~connect_timeout:30
            ~idle_timeout:300 ~max_time x)
        ~error:E.to_string r)
    ~error:E.to_string (test_key ())

let get_golden : string =
  "no-progress-meter\n\
   show-error\n\
   no-buffer\n\
   include\n\
   globoff\n\
   noproxy = \"*\"\n\
   proto = \"=https\"\n\
   tlsv1.2\n\
   connect-timeout = \"30\"\n\
   speed-limit = \"1\"\n\
   speed-time = \"300\"\n\
   user-agent = \"venice-ocaml/0.1.0\"\n\
   header = \"Authorization: Bearer sk-abc\"\n\
   header = \"Accept: application/json\"\n\
   header = \"Expect:\"\n\
   header = \"x-trace: abc\"\n\
   url = \"https://api.venice.ai/api/v1/models?model=x\"\n"

let post_golden : string =
  "no-progress-meter\n\
   show-error\n\
   no-buffer\n\
   include\n\
   globoff\n\
   noproxy = \"*\"\n\
   proto = \"=https\"\n\
   tlsv1.2\n\
   connect-timeout = \"30\"\n\
   speed-limit = \"1\"\n\
   speed-time = \"300\"\n\
   max-time = \"90\"\n\
   user-agent = \"venice-ocaml/0.1.0\"\n\
   header = \"Authorization: Bearer sk-abc\"\n\
   header = \"Accept: application/json\"\n\
   header = \"Expect:\"\n\
   header = \"Content-Type: application/json\"\n\
   url = \"https://api.venice.ai/api/v1/chat/completions\"\n\
   data-binary = \"{\\\"a\\\":\\\"b\\\"}\"\n"

let argv : string array = C.argv ~binary:"/usr/bin/curl"

let cfg_checks : (string * bool) list =
  [ ("cfgx: argv has four words", Array.length argv = 4);
    ( "cfgx: argv golden",
      List.equal String.equal (Array.to_list argv)
        [ "/usr/bin/curl"; "-q"; "-K"; "-" ] );
    ( "cfgx: GET config golden",
      String.equal
        (render_of ~max_time:None
           (H.Request.get
              ~query:[ ("model", "x") ]
              ~headers:[ ("X-Trace", "abc") ]
              H.Route.models))
        get_golden );
    ( "cfgx: POST config golden",
      String.equal (render_of ~max_time:(Some 90) post_req) post_golden );
    ( "cfgx: no max-time line when unset",
      not (contains (render_of ~max_time:None post_req) "max-time") );
    ( "cfgx: the key reaches exactly one line",
      contains
        (render_of ~max_time:None post_req)
        "header = \"Authorization: Bearer sk-abc\"" );
    ( "cfgx: backslash doubles and quote escapes",
      contains
        (render_of ~max_time:None (geth [ ("X-E", "a\"b\\c") ]))
        "header = \"x-e: a\\\"b\\\\c\"\n" );
    ( "cfgx: GET emits no data-binary line",
      not
        (contains
           (render_of ~max_time:None (getq [ ("k", "1") ]))
           "data-binary") );
    ( "cfgx: GET emits no Content-Type line",
      not
        (contains
           (render_of ~max_time:None (getq [ ("k", "1") ]))
           "Content-Type") );
    ( "cfgx: the user agent tracks Venice.version",
      contains
        (render_of ~max_time:None post_req)
        ("user-agent = \"venice-ocaml/" ^ Venice.version ^ "\"") );
    ( "cfgx: no-progress-meter is the first line",
      String.starts_with ~prefix:"no-progress-meter\n"
        (render_of ~max_time:None post_req) );
    ( "cfgx: show-error is the second line",
      String.starts_with ~prefix:"no-progress-meter\nshow-error\n"
        (render_of ~max_time:None post_req) );
    ( "cfgx: no silent line",
      not (contains (render_of ~max_time:None post_req) "\nsilent\n") );
    ( "cfgx: no suppress-connect-headers line",
      not
        (contains
           (render_of ~max_time:None post_req)
           "suppress-connect-headers") );
    ( "cfgx: data_line_bytes counts the whole line",
      C.data_line_bytes "{}" = String.length "data-binary = \"{}\"\n" );
    ( "cfgx: data_line_bytes counts the escaping",
      C.data_line_bytes "\\" = String.length "data-binary = \"\\\\\"\n" )
  ]

(* ---------- Wirex ---------- *)

let one_shot (s : string) : (W.head * string, E.t) result =
  Result.bind (W.make ()) (fun (m : W.t) ->
      Result.bind (W.feed m s) (fun (st : W.step) ->
          match st with
          | W.More (_ : W.t) -> Error (E.Wire_invalid "incomplete head")
          | W.Head (h, rest) -> Ok (h, rest)))

let split_bytes (s : string) : string list =
  List.map (String.make 1) (List.of_seq (String.to_seq s))

let rec drive (m : W.t) (cs : string list) : (W.head * string, E.t) result =
  match cs with
  | [] -> Error (E.Wire_invalid "incomplete head")
  | c :: tl ->
    Result.bind (W.feed m c) (fun (st : W.step) ->
        match st with
        | W.More m2 -> drive m2 tl
        | W.Head (h, rest) -> Ok (h, rest ^ String.concat "" tl))

let by_byte (s : string) : (W.head * string, E.t) result =
  Result.bind (W.make ()) (fun (m : W.t) -> drive m (split_bytes s))

let head_eq (a : W.head) (b : W.head) : bool =
  String.equal a.W.version b.W.version
  && a.W.status = b.W.status
  && String.equal a.W.reason b.W.reason
  && List.equal
       (fun ((n1 : string), (v1 : string)) ((n2 : string), (v2 : string)) ->
         String.equal n1 n2 && String.equal v1 v2)
       a.W.pairs b.W.pairs

let same_split (s : string) : bool =
  Result.fold
    ~ok:(fun ((ha : W.head), (ra : string)) ->
      Result.fold
        ~ok:(fun ((hb : W.head), (rb : string)) ->
          head_eq ha hb && String.equal ra rb)
        ~error:(fun ((_ : E.t)) -> false)
        (by_byte s))
    ~error:(fun ((_ : E.t)) -> false)
    (one_shot s)

let head_of (s : string) : (W.head, E.t) result =
  Result.map (fun ((h : W.head), (_ : string)) -> h) (one_shot s)

let rest_of (s : string) : (string, E.t) result =
  Result.map (fun ((_ : W.head), (r : string)) -> r) (one_shot s)

let with_head (s : string) (p : W.head -> bool) : bool =
  Result.fold ~ok:p ~error:(fun ((_ : E.t)) -> false) (head_of s)

let is_more (r : (W.step, E.t) result) : bool =
  Result.fold
    ~ok:(fun (st : W.step) ->
      match st with
      | W.More (_ : W.t) -> true
      | W.Head (_, _) -> false)
    ~error:(fun ((_ : E.t)) -> false)
    r

let is_head (r : (W.step, E.t) result) : bool =
  Result.fold
    ~ok:(fun (st : W.step) ->
      match st with
      | W.More (_ : W.t) -> false
      | W.Head (_, _) -> true)
    ~error:(fun ((_ : E.t)) -> false)
    r

let on_machine ?(max_head_bytes : int option) (f : W.t -> bool) : bool =
  Result.fold ~ok:f
    ~error:(fun ((_ : E.t)) -> false)
    (Option.fold
       ~none:(fun (() : unit) -> W.make ())
       ~some:(fun (n : int) (() : unit) -> W.make ~max_head_bytes:n ())
       max_head_bytes ())

let h1 : string =
  "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-n: 1\r\n\r\n"

let h1_lf : string =
  "HTTP/1.1 200 OK\ncontent-type: application/json\nx-n: 1\n\n"

let h1_mixed : string =
  "HTTP/1.1 200 OK\ncontent-type: application/json\r\nx-n: 1\n\r\n"

let continue_then_ok : string = "HTTP/1.1 100 Continue\r\n\r\n" ^ h1

let hints_then_ok : string =
  "HTTP/1.1 103 Early Hints\r\nlink: </a>\r\n\r\n" ^ h1

let n_informational (n : int) : string =
  String.concat ""
    (List.init n (fun ((_ : int)) -> "HTTP/1.1 100 Continue\r\n\r\n"))
  ^ h1

let at_cap : string = "HTTP/1.1 200 OK\r\nx-big: " ^ repeat 200 'a' ^ "\r\n\r\n"

let wire_checks : (string * bool) list =
  [ ("wire: h1 version", with_head h1 (fun h -> String.equal h.W.version "1.1"));
    ("wire: h1 status", with_head h1 (fun h -> h.W.status = 200));
    ("wire: h1 reason", with_head h1 (fun h -> String.equal h.W.reason "OK"));
    ( "wire: h1 pairs in wire order",
      with_head h1 (fun h ->
          List.equal String.equal
            (List.map (fun ((n : string), (_ : string)) -> n) h.W.pairs)
            [ "content-type"; "x-n" ]) );
    ( "wire: h1 values are OWS-trimmed",
      with_head h1 (fun h ->
          List.equal String.equal
            (List.map (fun ((_ : string), (v : string)) -> v) h.W.pairs)
            [ "application/json"; "1" ]) );
    ( "wire: raw header name case is kept",
      with_head "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" (fun h ->
          List.equal String.equal
            (List.map (fun ((n : string), (_ : string)) -> n) h.W.pairs)
            [ "Content-Type" ]) );
    ( "wire: h2 status line has no reason",
      with_head "HTTP/2 200\r\n\r\n" (fun h ->
          String.equal h.W.version "2" && h.W.status = 200
          && String.equal h.W.reason "") );
    ( "wire: h2 status line with a trailing space reads an empty reason",
      with_head "HTTP/2 200 \r\n\r\n" (fun h -> String.equal h.W.reason "") );
    ( "wire: a multi-word reason is kept whole",
      with_head "HTTP/1.1 404 Not Found\r\n\r\n" (fun h ->
          String.equal h.W.reason "Not Found") );
    ("wire: bare LF terminators accept", accepts (head_of h1_lf));
    ( "wire: the bare LF head equals the CRLF head",
      Result.fold
        ~ok:(fun (a : W.head) ->
          Result.fold ~ok:(head_eq a)
            ~error:(fun ((_ : E.t)) -> false)
            (head_of h1_lf))
        ~error:(fun ((_ : E.t)) -> false)
        (head_of h1) );
    ("wire: mixed terminators accept", accepts (head_of h1_mixed));
    ( "wire: bare CR rejects",
      err_is "wire: bare CR in the head"
        (head_of "HTTP/1.1 200 OK\rx-a: 1\r\n\r\n") );
    ( "wire: obs-fold rejects",
      err_is "wire: obs-fold continuation line"
        (head_of "HTTP/1.1 200 OK\r\nx-a: 1\r\n b\r\n\r\n") );
    ( "wire: missing status line rejects",
      err_is "wire: status line: does not start with HTTP/"
        (head_of "200 OK\r\n\r\n") );
    ( "wire: bad version rejects",
      err_is "wire: status line: bad HTTP version 1.1.1"
        (head_of "HTTP/1.1.1 200 OK\r\n\r\n") );
    ( "wire: two-digit code rejects",
      err_is "wire: status line: status code is not three digits"
        (head_of "HTTP/1.1 20 OK\r\n\r\n") );
    ( "wire: four-digit code rejects",
      err_is "wire: status line: status code is not three digits"
        (head_of "HTTP/1.1 2000 OK\r\n\r\n") );
    ( "wire: junk after the code rejects",
      err_is "wire: status line: junk after the status code"
        (head_of "HTTP/1.1 200OK\r\n\r\n") );
    ( "wire: no space after the version rejects",
      err_is "wire: status line: no space after the version"
        (head_of "HTTP/1.1\r\n\r\n") );
    ( "wire: header with no colon rejects",
      err_is "wire: header line: no colon"
        (head_of "HTTP/1.1 200 OK\r\nx-a 1\r\n\r\n") );
    ( "wire: empty header name rejects",
      err_is "wire: header line: empty name"
        (head_of "HTTP/1.1 200 OK\r\n: 1\r\n\r\n") );
    ( "wire: non-token header name rejects",
      err_is "wire: header line: non-token byte in the name x a"
        (head_of "HTTP/1.1 200 OK\r\nx a: 1\r\n\r\n") );
    ( "wire: control byte in a value rejects",
      err_is "wire: header line: forbidden byte in the value of x-a"
        (head_of "HTTP/1.1 200 OK\r\nx-a: \001\r\n\r\n") );
    ( "wire: a high byte in a value passes",
      accepts (head_of "HTTP/1.1 200 OK\r\nx-a: \xc3\xa9\r\n\r\n") );
    ( "wire: HTAB in a value passes",
      accepts (head_of "HTTP/1.1 200 OK\r\nx-a: a\tb\r\n\r\n") );
    ("wire: 100-continue is skipped", accepts (head_of continue_then_ok));
    ( "wire: the skipped block does not leak into the pairs",
      with_head continue_then_ok (fun h ->
          h.W.status = 200 && List.length h.W.pairs = 2) );
    ("wire: 103 early hints is skipped", accepts (head_of hints_then_ok));
    ( "wire: four informational blocks pass",
      accepts (head_of (n_informational 4)) );
    ( "wire: five informational blocks reject",
      err_is "wire: more than 4 informational blocks"
        (head_of (n_informational 5)) );
    ( "wire: leftover bytes are returned",
      Result.fold ~ok:(String.equal "{\"a\":1}")
        ~error:(fun ((_ : E.t)) -> false)
        (rest_of (h1 ^ "{\"a\":1}")) );
    ( "wire: no leftover bytes reads empty",
      Result.fold ~ok:(String.equal "")
        ~error:(fun ((_ : E.t)) -> false)
        (rest_of h1) );
    ( "wire: make rejects a zero cap",
      err_is "wire: make: max_head_bytes must be >= 1"
        (W.make ~max_head_bytes:0 ()) );
    ("wire: make accepts a cap of one", accepts (W.make ~max_head_bytes:1 ()));
    ( "wire: a head at the cap passes",
      on_machine ~max_head_bytes:(String.length at_cap) (fun (m : W.t) ->
          is_head (W.feed m at_cap)) );
    ( "wire: an unterminated head over the cap rejects",
      on_machine ~max_head_bytes:32 (fun (m : W.t) ->
          err_is "wire: head exceeds 32 bytes" (W.feed m (repeat 33 'a'))) );
    ( "wire: an unterminated head at the cap reports More",
      on_machine ~max_head_bytes:32 (fun (m : W.t) ->
          is_more (W.feed m (repeat 32 'a'))) );
    ( "wire: an empty feed reports More",
      on_machine (fun (m : W.t) -> is_more (W.feed m "")) );
    ( "wire: a CR at the buffer end is incomplete, not a bare CR",
      on_machine (fun (m : W.t) -> is_more (W.feed m "HTTP/1.1 200 OK\r")) );
    ( "wire: feeding one machine twice gives the same head",
      on_machine (fun (m : W.t) ->
          Result.fold
            ~ok:(fun (st : W.step) ->
              match st with
              | W.More (_ : W.t) -> false
              | W.Head (ha, _) ->
                Result.fold
                  ~ok:(fun (st2 : W.step) ->
                    match st2 with
                    | W.More (_ : W.t) -> false
                    | W.Head (hb, _) -> head_eq ha hb)
                  ~error:(fun ((_ : E.t)) -> false)
                  (W.feed m h1))
            ~error:(fun ((_ : E.t)) -> false)
            (W.feed m h1)) );
    ("wire: split feed matches one shot for h1", same_split h1);
    ("wire: split feed matches one shot for the LF head", same_split h1_lf);
    ( "wire: split feed matches one shot for the mixed head",
      same_split h1_mixed );
    ("wire: split feed matches one shot for h2", same_split "HTTP/2 200\r\n\r\n");
    ( "wire: split feed matches one shot after a 100-continue",
      same_split continue_then_ok );
    ( "wire: split feed matches one shot after early hints",
      same_split hints_then_ok );
    ( "wire: split feed matches one shot with a body tail",
      same_split (h1 ^ "hello") )
  ]

(* ---------- Fakex ---------- *)

let ok_head : string = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\n"

let script_two : F.t =
  F.make
    [ F.exchange ~head:ok_head ~chunks:[ "a"; "b" ] ();
      F.exchange ~head:"HTTP/1.1 429 Too Many Requests\r\n\r\n"
        ~chunks:[ "c" ] () ]

let fake_send (t : F.t) (r : (H.Request.t, E.t) result) :
    (W.head * F.body, E.t) result =
  Result.bind (test_key ()) (fun (k : K.t) ->
      Result.bind r (fun (req : H.Request.t) -> F.send t ~key:k req))

let listing : (H.Request.t, E.t) result = H.Request.get H.Route.models

let with_body (r : (W.head * F.body, E.t) result) (p : F.body -> bool) : bool =
  Result.fold
    ~ok:(fun ((_ : W.head), (b : F.body)) -> p b)
    ~error:(fun ((_ : E.t)) -> false)
    r

let with_wire_head (r : (W.head * F.body, E.t) result) (p : W.head -> bool) :
    bool =
  Result.fold
    ~ok:(fun ((h : W.head), (_ : F.body)) -> p h)
    ~error:(fun ((_ : E.t)) -> false)
    r

let one_shot_fake (chunks : string list) : (W.head * F.body, E.t) result =
  fake_send (F.make [ F.exchange ~head:ok_head ~chunks () ]) listing

let closing_fake (msg : string) : (W.head * F.body, E.t) result =
  fake_send
    (F.make [ F.exchange ~head:ok_head ~chunks:[] ~close_error:msg () ])
    listing

(* OCaml evaluates list elements right to left, so two checks may
   never share one stateful body: the later element would consume it
   first.  read_seq takes the whole read sequence inside ONE check
   instead.  It reports "<none>" for EOF and the error text for a
   rejection, so both are visible in the compared list. *)
let read_seq (b : F.body) (n : int) : string list =
  let rec go (i : int) (acc : string list) : string list =
    match () with
    | () when i <= 0 -> List.rev acc
    | () ->
      Result.fold
        ~ok:(fun (o : string option) ->
          Option.fold
            ~none:(List.rev ("<none>" :: acc))
            ~some:(fun (s : string) -> go (i - 1) (s :: acc))
            o)
        ~error:(fun (e : E.t) -> List.rev (E.to_string e :: acc))
        (F.read b)
  in
  go n []

let fake_checks : (string * bool) list =
  let first = fake_send script_two listing in
  let second = fake_send script_two post_req in
  let third = fake_send script_two listing in
  [ ( "fake: the first exchange answers first",
      with_wire_head first (fun (h : W.head) -> h.W.status = 200) );
    ( "fake: the second exchange answers second",
      with_wire_head second (fun (h : W.head) -> h.W.status = 429) );
    ( "fake: an exhausted script rejects",
      err_is "transport: fake: script exhausted" third );
    ( "fake: read_all joins the chunks in order",
      with_body
        (one_shot_fake [ "a"; "b" ])
        (fun (b : F.body) -> String.equal (ok_str (F.read_all b)) "ab") );
    ( "fake: read hands the chunks over one at a time, then None",
      with_body
        (one_shot_fake [ "a"; "b" ])
        (fun (b : F.body) ->
          List.equal String.equal (read_seq b 5) [ "a"; "b"; "<none>" ]) );
    ( "fake: requests are recorded in call order",
      List.equal String.equal
        (List.map H.Request.to_log (F.requests script_two))
        [ "GET /models headers=[] body_bytes=0";
          "POST /chat/completions headers=[] body_bytes=9" ] );
    ( "fake: a malformed script head is a wire error",
      err_is "wire: status line: does not start with HTTP/"
        (fake_send
           (F.make [ F.exchange ~head:"garbage\r\n\r\n" ~chunks:[] () ])
           listing) );
    ( "fake: an incomplete script head rejects",
      err_is "wire: fake: the scripted head is incomplete"
        (fake_send
           (F.make [ F.exchange ~head:"HTTP/1.1 200 OK\r\n" ~chunks:[] () ])
           listing) );
    ( "fake: bytes after the blank line become the first read",
      with_body
        (fake_send
           (F.make
              [ F.exchange ~head:(ok_head ^ "lead") ~chunks:[ "tail" ] () ])
           listing)
        (fun (b : F.body) -> String.equal (ok_str (F.read_all b)) "leadtail")
    );
    ( "fake: close is Ok by default",
      with_body second (fun (b : F.body) -> accepts (F.close b)) );
    ( "fake: a scripted close error surfaces",
      with_body
        (closing_fake "curl exit 28")
        (fun (b : F.body) -> err_is "transport: curl exit 28" (F.close b)) );
    ( "fake: close is idempotent",
      with_body
        (closing_fake "curl exit 28")
        (fun (b : F.body) ->
          err_is "transport: curl exit 28" (F.close b) && accepts (F.close b))
    );
    ( "fake: read_all rejects above the cap",
      with_body
        (one_shot_fake [ "ab"; "cd" ])
        (fun (b : F.body) ->
          err_is "transport: read_all: body exceeds 3 bytes"
            (F.read_all ~cap:3 b)) );
    ( "fake: read_all at the cap passes",
      with_body
        (one_shot_fake [ "ab"; "cd" ])
        (fun (b : F.body) -> String.equal (ok_str (F.read_all ~cap:4 b)) "abcd")
    );
    ( "fake: an empty script rejects at once",
      err_is "transport: fake: script exhausted" (fake_send (F.make []) listing)
    );
    ( "fake: no request is recorded when the script is exhausted",
      List.length (F.requests (F.make [])) = 0 )
  ]

(* M15 D10: a refusal slot rejects the send and STILL records the
   request.  That is what lets ONE Fake script a never-sent transport
   failure followed by the answer the retry gets, without a second
   transport and without a mutable hook in the test.

   The three sends are separate top-level lets on purpose: the script
   is stateful and OCaml evaluates list elements right to left, so a
   check list that sent inline would consume the slots backwards. *)
let refusal_script : F.t =
  F.make
    [ F.refusal (E.Transport_unreachable "curl exit 6 (dns): no such host");
      F.exchange ~head:ok_head ~chunks:[ "a" ] () ]

let refused : (W.head * F.body, E.t) result = fake_send refusal_script listing

let after_refusal : (W.head * F.body, E.t) result =
  fake_send refusal_script listing

let refusal_log : H.Request.t list = F.requests refusal_script

let refusal_checks : (string * bool) list =
  [ ("fake: a refusal slot rejects the send", Result.is_error refused);
    ( "fake: the refusal carries the scripted error verbatim",
      err_is "unreachable: curl exit 6 (dns): no such host" refused );
    ( "fake: the slot AFTER a refusal still answers",
      with_wire_head after_refusal (fun (h : W.head) -> h.W.status = 200) );
    ( "fake: a refused send is still recorded in the request log",
      Int.equal (List.length refusal_log) 2 );
    ( "fake: the refused request is the FIRST row of the log",
      match refusal_log with
      | [] -> false
      | r :: (_ : H.Request.t list) ->
        String.equal (H.Request.path r) "/models" );
    ( "fake: the refusal consumed exactly one slot",
      Result.is_error (fake_send refusal_script listing) )
  ]

let () =
  run
    (key_checks @ endpoint_checks @ route_checks @ reserved_checks
   @ request_checks @ cfg_checks @ wire_checks @ fake_checks
   @ refusal_checks)
