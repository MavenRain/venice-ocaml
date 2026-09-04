(* M13 curlx suite: the curl-subprocess transport, driven against the
   FAKE curl binaries in test/fake_curl.  No network is touched and no
   real curl is required.

   Every fake answers "--version" so Curl.make can probe it, and every
   loop inside a fake is bounded (head -c, never while true).

   The suite writes NO file.  The fakes are checked in, the capture
   oracle hands the received config back as the response body, and the
   only state is the child processes.  So parallel gate runs cannot
   collide and there is nothing to clean up.  That also keeps the
   suite free of raising stdlib IO, which the house rules forbid.

   A 60 second alarm is the watchdog.  A hung select pump, a child
   that never exits or a blocked write must turn the gate RED fast
   instead of stalling the whole ladder. *)

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
module Cu = Venice__Curlx
module J = Venice__Jsonx
module B = Venice__Bytesx
module E = Venice__Errx

(* ---------- inherited signal dispositions ---------- *)

(* A signal set to IGNORE survives fork AND exec, so a supervisor that
   launched the gate with SIGTERM ignored hands that disposition to
   every fake curl, and the SIGTERM of an early close does nothing.
   Reset SIGTERM to the default here, so the suite measures curlx and
   not the launcher. *)
let () = Sys.set_signal Sys.sigterm Sys.Signal_default

(* ---------- the watchdog ---------- *)

let () =
  Sys.set_signal Sys.sigalrm
    (Sys.Signal_handle
       (fun ((_ : int)) ->
         print_endline "FAIL watchdog: test_curlx exceeded 60s";
         exit 1));
  ignore (Unix.alarm 60)

(* ---------- small helpers ---------- *)

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

let err_text (r : ('a, E.t) result) : string =
  Result.fold ~ok:(fun ((_ : 'a)) -> "<ok>") ~error:E.to_string r

let err_has (r : ('a, E.t) result) (needle : string) : bool =
  Result.is_error r && contains (err_text r) needle

let ok_str (r : (string, E.t) result) : string =
  Result.fold ~ok:Fun.id ~error:E.to_string r

(* ---------- the fake binaries ---------- *)

(* The exe sits at _build/default/test/, so the source tree is three
   levels up.  gates.sh runs the exe by absolute path. *)
let up (p : string) : string = Filename.concat p Filename.parent_dir_name

let fake_dir : string =
  Filename.concat
    (Filename.concat
       (up (up (up (Filename.dirname Sys.executable_name))))
       "test")
    "fake_curl"

let fake (name : string) : string = Filename.concat fake_dir name

let bin_ok : string = fake "curl_ok"
let bin_capture : string = fake "curl_capture"
let bin_lf : string = fake "curl_lf"
let bin_old : string = fake "curl_7.66.0"
let bin_floor : string = fake "curl_7.67.0"
let bin_781 : string = fake "curl_7.81.0"
let bin_820 : string = fake "curl_8.2.0"
let bin_garbage : string = fake "curl_garbage"
let bin_exit28 : string = fake "curl_exit28"
let bin_leak : string = fake "curl_leak"
let bin_bigerr : string = fake "curl_bigerr"
let bin_bigerr0 : string = fake "curl_bigerr0"
let bin_slow : string = fake "curl_slow"
let bin_nohead : string = fake "curl_nohead"
let bin_missing : string = fake "curl_absent"

(* ---------- driving one exchange ---------- *)

let key : (K.t, E.t) result = K.make "sk-abc"
let listing : (H.Request.t, E.t) result = H.Request.get H.Route.models

let big_post : (H.Request.t, E.t) result =
  H.Request.post H.Route.chat_completions
    ~body:(J.Jstring (String.make 70000 'x'))

let mk (bin : string) : (Cu.t, E.t) result = Cu.make ~binary:bin ()

let attempt (bin : string) (req : (H.Request.t, E.t) result) :
    (W.head * Cu.body, E.t) result =
  Result.bind (mk bin) (fun (t : Cu.t) ->
      Result.bind key (fun (k : K.t) ->
          Result.bind req (fun (r : H.Request.t) -> Cu.send t ~key:k r)))

let with_head (bin : string) (p : W.head -> bool) : bool =
  Result.fold
    ~ok:(fun ((h : W.head), (b : Cu.body)) ->
      let v = p h in
      let (_ : (unit, E.t) result) = Cu.close b in
      v)
    ~error:(fun ((_ : E.t)) -> false)
    (attempt bin listing)

let with_body (bin : string) (p : Cu.body -> bool) : bool =
  Result.fold
    ~ok:(fun ((_ : W.head), (b : Cu.body)) -> p b)
    ~error:(fun ((_ : E.t)) -> false)
    (attempt bin listing)

let with_t (bin : string) (p : Cu.t -> bool) : bool =
  Result.fold ~ok:p ~error:(fun ((_ : E.t)) -> false) (mk bin)

(* drains the body, then closes and reports the close verdict *)
let drain_then_close (bin : string) : (unit, E.t) result =
  Result.fold
    ~ok:(fun ((_ : W.head), (b : Cu.body)) ->
      let (_ : (string, E.t) result) = Cu.read_all b in
      Cu.close b)
    ~error:(fun (e : E.t) -> Error e)
    (attempt bin listing)

let body_text (bin : string) : string =
  Result.fold
    ~ok:(fun ((_ : W.head), (b : Cu.body)) ->
      let s = ok_str (Cu.read_all b) in
      let (_ : (unit, E.t) result) = Cu.close b in
      s)
    ~error:E.to_string (attempt bin listing)

(* the capture oracle: curl_capture hands the config it received back
   as the response body, so the bytes curl really read are comparable
   with the pure renderer *)
let captured (req : (H.Request.t, E.t) result) : string =
  Result.fold
    ~ok:(fun ((_ : W.head), (b : Cu.body)) ->
      let s = ok_str (Cu.read_all b) in
      let (_ : (unit, E.t) result) = Cu.close b in
      s)
    ~error:E.to_string (attempt bin_capture req)

let rendered_for (req : (H.Request.t, E.t) result) : string =
  Result.fold
    ~ok:(fun (k : K.t) ->
      Result.fold
        ~ok:(fun (r : H.Request.t) ->
          C.render ~key:k ~endpoint:H.Endpoint.default ~connect_timeout:30
            ~idle_timeout:300 ~max_time:None r)
        ~error:E.to_string req)
    ~error:E.to_string key

(* a body that exercises both escapes of the curl -K table *)
let escape_post : (H.Request.t, E.t) result =
  H.Request.post H.Route.chat_completions
    ~body:(J.Jobj [ ("a", J.Jstring "b\\c\"d") ])

(* ---------- make ---------- *)

let make_checks : (string * bool) list =
  [ ("make: a missing binary rejects", Result.is_error (mk bin_missing));
    ( "make: a missing binary rejects as a transport error",
      err_has (mk bin_missing) "transport: " );
    ( "make: a non-curl binary rejects on the version line",
      err_has (mk bin_garbage) "version: unreadable curl version line:" );
    ( "make: curl 7.66.0 is below the floor",
      err_has (mk bin_old)
        "version: curl 7.67.0 or newer required, found 7.66.0" );
    ("make: curl 7.67.0 passes the floor", Result.is_ok (mk bin_floor));
    ( "make: version reports the parsed triple",
      with_t bin_floor (fun (t : Cu.t) -> String.equal (Cu.version t) "7.67.0")
    );
    ( "make: 7.67.0 keeps the 64 KiB config-line cap",
      with_t bin_floor (fun (t : Cu.t) -> Cu.max_line t = 65_536) );
    ( "make: 7.81.0 keeps the 64 KiB config-line cap",
      with_t bin_781 (fun (t : Cu.t) -> Cu.max_line t = 65_536) );
    ( "make: 8.2.0 takes the dynbuf config-line cap",
      with_t bin_820 (fun (t : Cu.t) -> Cu.max_line t = 10_485_248) );
    ( "make: 8.5.0 takes the dynbuf config-line cap",
      with_t bin_ok (fun (t : Cu.t) -> Cu.max_line t = 10_485_248) );
    ( "make: connect_timeout 0 rejects",
      err_has
        (Cu.make ~binary:bin_ok ~connect_timeout:0 ())
        "make: connect_timeout must be >= 1" );
    ( "make: idle_timeout 0 rejects",
      err_has
        (Cu.make ~binary:bin_ok ~idle_timeout:0 ())
        "make: idle_timeout must be >= 1" );
    ( "make: max_time 0 rejects",
      err_has
        (Cu.make ~binary:bin_ok ~max_time:0 ())
        "make: max_time must be >= 1" );
    ( "make: an endpoint override is accepted",
      Result.fold
        ~ok:(fun (e : H.Endpoint.t) ->
          Result.is_ok (Cu.make ~binary:bin_ok ~endpoint:e ()))
        ~error:(fun ((_ : E.t)) -> false)
        (H.Endpoint.of_string "https://example.test/v1") )
  ]

(* ---------- send ---------- *)

let send_checks : (string * bool) list =
  [ ( "send: the head status arrives",
      with_head bin_ok (fun (h : W.head) -> h.W.status = 200) );
    ( "send: the head version arrives",
      with_head bin_ok (fun (h : W.head) -> String.equal h.W.version "1.1") );
    ( "send: the head pairs arrive",
      with_head bin_ok (fun (h : W.head) ->
          List.exists
            (fun ((n : string), (v : string)) ->
              String.equal n "content-type" && String.equal v "text/plain")
            h.W.pairs) );
    ("send: read_all drains the body", String.equal (body_text bin_ok) "hello");
    ("send: close on a clean exit is Ok", Result.is_ok (drain_then_close bin_ok));
    ( "send: close is idempotent",
      with_body bin_ok (fun (b : Cu.body) ->
          let (_ : (string, E.t) result) = Cu.read_all b in
          Result.is_ok (Cu.close b) && Result.is_ok (Cu.close b)) );
    ( "send: read reports None at EOF",
      with_body bin_ok (fun (b : Cu.body) ->
          let (_ : (string, E.t) result) = Cu.read_all b in
          let v =
            Result.fold
              ~ok:(fun (o : string option) -> Option.is_none o)
              ~error:(fun ((_ : E.t)) -> false)
              (Cu.read b)
          in
          let (_ : (unit, E.t) result) = Cu.close b in
          v) );
    ( "send: read_all rejects above the cap",
      with_body bin_ok (fun (b : Cu.body) ->
          let v = err_has (Cu.read_all ~cap:2 b) "read_all: body exceeds 2 bytes" in
          let (_ : (unit, E.t) result) = Cu.close b in
          v) );
    ( "send: curl reads the rendered config on stdin",
      String.equal (captured listing) (rendered_for listing) );
    ( "send: the config curl reads starts with no-progress-meter",
      String.starts_with ~prefix:"no-progress-meter\n" (captured listing) );
    ( "send: the config curl reads carries the key exactly once",
      contains (captured listing) "header = \"Authorization: Bearer sk-abc\""
    );
    ( "send: a POST body reaches curl through the escaping table",
      String.equal (captured escape_post) (rendered_for escape_post) );
    ( "send: the escaped body rides on a data-binary line",
      contains (captured escape_post) "\ndata-binary = \"" );
    ( "send: a bare LF head parses",
      with_head bin_lf (fun (h : W.head) -> h.W.status = 200) );
    ( "send: an over-long data line rejects under a 7.81.0 curl",
      err_has (attempt bin_781 big_post) "config-line cap 65536" );
    ( "send: the over-long data line names the measured size",
      err_has (attempt bin_781 big_post) "body: data line " );
    ( "send: the same body passes under an 8.5.0 curl",
      Result.fold
        ~ok:(fun ((_ : W.head), (b : Cu.body)) ->
          let (_ : (unit, E.t) result) = Cu.close b in
          true)
        ~error:(fun ((_ : E.t)) -> false)
        (attempt bin_ok big_post) )
  ]

(* ---------- failure paths ---------- *)

let exit28 : (unit, E.t) result = drain_then_close bin_exit28
let leak_close : (unit, E.t) result = drain_then_close bin_leak
let bigerr_body : string = body_text bin_bigerr
let bigerr_close : (unit, E.t) result = drain_then_close bin_bigerr

(* M14 A17 (D17 residual 2): the exit-0 twin of curl_bigerr.  The
   shipped bigerr fake exits 7, so the exit-0 path behind a FULL
   stderr pipe rested on exit_result alone.  close maps WEXITED 0 to
   Ok on its own, so the close assertion has no false branch by
   itself: the deadlock oracle is the head-and-body read, and the
   wall clock turns a partial stall into a FAIL line instead of a
   watchdog kill. *)
let bigerr0_body : string = body_text bin_bigerr0
let bigerr0_close : (unit, E.t) result = drain_then_close bin_bigerr0

let bigerr0_secs : float =
  let t0 = Unix.gettimeofday () in
  let (_ : (unit, E.t) result) = drain_then_close bin_bigerr0 in
  Unix.gettimeofday () -. t0

let early : float * bool =
  let t0 = Unix.gettimeofday () in
  let ok = with_body bin_slow (fun (b : Cu.body) -> Result.is_ok (Cu.close b)) in
  (Unix.gettimeofday () -. t0, ok)

let failure_checks : (string * bool) list =
  [ ("exit: a nonzero status turns close red", err_has exit28 "curl exit 28");
    ( "exit: 28 carries the timeout meaning",
      err_has exit28 "(timeout: operation timed out)" );
    ( "exit: the stderr tail reaches the message",
      err_has exit28 "Operation timed out" );
    ( "exit: 6 carries the dns meaning",
      err_has leak_close "(dns: could not resolve host)" );
    ( "exit: the key is redacted out of the stderr tail",
      err_has leak_close "[redacted]" );
    ( "exit: the key itself never reaches the message",
      not (contains (err_text leak_close) "sk-abc") );
    ( "stderr: a 200000 byte stderr does not deadlock the head read",
      String.equal bigerr_body "ok" );
    ("stderr: the exit still reaches close", err_has bigerr_close "curl exit 7");
    ( "stderr: 7 carries the connect meaning",
      err_has bigerr_close "(connect: failed to connect to host)" );
    ( "stderr: only the tail is kept",
      String.length (err_text bigerr_close) < 5000 );
    ( "stderr: the tail holds stderr bytes",
      contains (err_text bigerr_close) "EEEEEEEE" );
    ( "stderr0: a 200000 byte stderr does not deadlock the head read",
      String.equal bigerr0_body "ok" );
    ( "stderr0: close is Ok on exit 0 behind a full pipe",
      Result.is_ok bigerr0_close );
    ( "stderr0: send plus read plus close stays under 10 s",
      bigerr0_secs < 10.0 );
    ( "head: a missing head reports the exit, not the wire error",
      err_has (attempt bin_nohead listing) "curl exit 52" );
    ( "head: 52 carries the empty-reply meaning",
      err_has (attempt bin_nohead listing) "(empty reply from server)" );
    ( "close: an early close on a live stream is Ok",
      (fun ((_ : float), (ok : bool)) -> ok) early );
    ( "close: an early close does not wait for the child",
      (fun ((dt : float), (_ : bool)) -> dt < 2.0) early )
  ]

let () = run (make_checks @ send_checks @ failure_checks)
