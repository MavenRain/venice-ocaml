(* M13 curlx: the curl-subprocess transport. HOST unit: Unix, Bytes
   and refs are allowed here and nowhere in the core. Mutation is
   confined to the body record (pending bytes, the stderr ring, and
   the eof / err_eof / closed flags) plus the one module-level flag
   that makes the SIGPIPE ignore idempotent. *)

type t =
  { binary : string;
    endpoint : Httpx.Endpoint.t;
    connect_timeout : int;
    idle_timeout : int;
    max_time : int option;
    version : string;
    max_line : int }

type body =
  { proc : in_channel * out_channel * in_channel;
    out_fd : Unix.file_descr;
    err_fd : Unix.file_descr;
    pid : int;
    key : Keyx.t;
    pending : string ref;
    errbuf : string ref;
    eof : bool ref;
    err_eof : bool ref;
    closed : bool ref }

(* ---------- the one guard ---------- *)

(* The single try-with in the repo. Named constructors only, no
   catch-all arm, no re-raise: every stdlib call that can raise is
   wrapped in its own thunk at the call site, so one guard never
   swallows a second failure. *)
let guard (f : unit -> 'a) : ('a, Errx.t) result =
  try Ok (f ()) with
  | Unix.Unix_error (e, fn, arg) ->
    Error
      (Errx.Transport_failed
         (fn ^ " " ^ arg ^ ": " ^ Unix.error_message e))
  | Sys_error m -> Error (Errx.Transport_failed m)
  | End_of_file -> Error (Errx.Transport_failed "unexpected end of input")

let detail (e : Errx.t) : string =
  match e with
  | Errx.Transport_failed s -> s
  | Errx.Hex_invalid _ | Errx.B64_invalid _ | Errx.Json_invalid _
  | Errx.Model_invalid _ | Errx.Param_invalid _ | Errx.Msg_invalid _
  | Errx.Head_invalid _ | Errx.Chat_invalid _ | Errx.Resp_invalid _
  | Errx.Sse_invalid _ | Errx.Chunk_invalid _ | Errx.Key_invalid _
  | Errx.Req_invalid _ | Errx.Wire_invalid _ ->
    Errx.to_string e

let transport (msg : string) : ('a, Errx.t) result =
  Error (Errx.Transport_failed msg)

(* ---------- scalars ---------- *)

let read_buf_bytes (() : unit) : int = 65536
let err_tail_bytes (() : unit) : int = 4096
let read_all_cap (() : unit) : int = 8_388_608
let default_connect_timeout (() : unit) : int = 30
let default_idle_timeout (() : unit) : int = 300
let default_binary (() : unit) : string = "curl"

(* A13: 10 MiB less 512 bytes of slack below the measured boundary,
   and the pre-8.2.0 regime. *)
let line_cap_new (() : unit) : int = 10_485_248
let line_cap_old (() : unit) : int = 65_536
let floor_version (() : unit) : int * int * int = (7, 67, 0)
let dynbuf_version (() : unit) : int * int * int = (8, 2, 0)

(* ---------- small total helpers ---------- *)

let chars (s : string) : char list = List.of_seq (String.to_seq s)
let str_of (cs : char list) : string = String.of_seq (List.to_seq cs)

let is_digit (c : char) : bool =
  match c with
  | '0' .. '9' -> true
  | _ -> false

let rec digit_run (acc : char list) (cs : char list) : string =
  match cs with
  | c :: tl when is_digit c -> digit_run (c :: acc) tl
  | [] -> str_of (List.rev acc)
  | _ :: _ -> str_of (List.rev acc)

let int_prefix (s : string) : int option =
  int_of_string_opt (digit_run [] (chars s))

let rec starts_with_chars (needle : char list) (cs : char list) : bool =
  match (needle, cs) with
  | [], _ -> true
  | _ :: _, [] -> false
  | a :: nt, b :: ct -> Char.equal a b && starts_with_chars nt ct

let rec drop_n (n : int) (cs : char list) : char list =
  match () with
  | () when n <= 0 -> cs
  | () -> (match cs with [] -> [] | _ :: tl -> drop_n (n - 1) tl)

let rec scrub (needle : char list) (nlen : int) (repl : string)
    (acc : string list) (cs : char list) : string =
  match cs with
  | [] -> String.concat "" (List.rev acc)
  | c :: tl ->
    (match starts_with_chars needle cs with
    | true -> scrub needle nlen repl (repl :: acc) (drop_n nlen cs)
    | false -> scrub needle nlen repl (String.make 1 c :: acc) tl)

(* Every occurrence of the key bytes becomes "[redacted]". The key is
   never empty (Keyx.make rejects ""), and the length guard keeps the
   walk terminating even for a hand-built value. *)
let redact ~(key : Keyx.t) (s : string) : string =
  let k = Keyx.reveal key in
  match String.length k with
  | 0 -> s
  | n -> scrub (chars k) n "[redacted]" [] (chars s)

let ring_add (cur : string) (add : string) : string =
  let s = cur ^ add in
  let n = String.length s in
  match () with
  | () when n <= err_tail_bytes () -> s
  | () ->
    Option.fold ~none:s ~some:Fun.id
      (Bytesx.take s (n - err_tail_bytes ()) (err_tail_bytes ()))

(* ---------- raw descriptor reads ---------- *)

(* Seq.take over Bytes.to_seq keeps the copy total: no sub, no index,
   no partial range to get wrong. *)
let taken (b : Bytes.t) (n : int) : string =
  String.of_seq (Seq.take n (Bytes.to_seq b))

let read_fd (fd : Unix.file_descr) : (string, Errx.t) result =
  guard (fun (() : unit) ->
      let buf = Bytes.create (read_buf_bytes ()) in
      let n = Unix.read fd buf 0 (read_buf_bytes ()) in
      taken buf n)

(* ---------- SIGPIPE ---------- *)

let sigpipe_ignored : bool ref = ref false

let ignore_sigpipe (() : unit) : unit =
  match !sigpipe_ignored with
  | true -> ()
  | false ->
    Sys.set_signal Sys.sigpipe Sys.Signal_ignore;
    sigpipe_ignored := true

(* ---------- spawn ---------- *)

let spawn (binary : string) (args : string array) :
    (in_channel * out_channel * in_channel, Errx.t) result =
  Result.map_error
    (fun (e : Errx.t) -> Errx.Transport_failed ("spawn: " ^ detail e))
    (guard (fun (() : unit) ->
         Unix.open_process_args_full binary args (Unix.environment ())))

(* ---------- version probe (A2, A13, A14) ---------- *)

let rec drain_blocking (fd : Unix.file_descr) (acc : string list) :
    (string, Errx.t) result =
  Result.bind (read_fd fd) (fun (chunk : string) ->
      match String.length chunk with
      | 0 -> Ok (String.concat "" (List.rev acc))
      | _ -> drain_blocking fd (chunk :: acc))

let probe_read (proc : in_channel * out_channel * in_channel) :
    (string, Errx.t) result =
  let ic, oc, ec = proc in
  Result.bind
    (guard (fun (() : unit) -> close_out oc))
    (fun (() : unit) ->
      Result.bind
        (drain_blocking (Unix.descr_of_in_channel ic) [])
        (fun (out : string) ->
          Result.bind
            (drain_blocking (Unix.descr_of_in_channel ec) [])
            (fun ((_ : string)) ->
              Result.map
                (fun ((_ : Unix.process_status)) -> out)
                (guard (fun (() : unit) -> Unix.close_process_full proc)))))

let parse_triple (v : string) : (int * int * int) option =
  match String.split_on_char '.' v with
  | a :: b :: c :: _ ->
    Option.bind (int_prefix a) (fun (x : int) ->
        Option.bind (int_prefix b) (fun (y : int) ->
            Option.map (fun (z : int) -> (x, y, z)) (int_prefix c)))
  | [ a; b ] ->
    Option.bind (int_prefix a) (fun (x : int) ->
        Option.map (fun (y : int) -> (x, y, 0)) (int_prefix b))
  | _ -> None

let first_line (out : string) : string =
  match String.split_on_char '\n' out with
  | first :: _ -> first
  | [] -> ""

let show_triple ((a : int), (b : int), (c : int)) : string =
  string_of_int a ^ "." ^ string_of_int b ^ "." ^ string_of_int c

let parse_version (out : string) : ((int * int * int) * string, Errx.t) result
    =
  let line = first_line out in
  match String.split_on_char ' ' line with
  | name :: v :: _ when String.equal name "curl" ->
    Option.fold
      ~none:(transport ("version: unreadable curl version line: " ^ line))
      ~some:(fun (tr : int * int * int) -> Ok (tr, show_triple tr))
      (parse_triple v)
  | _ -> transport ("version: unreadable curl version line: " ^ line)

let ge ((a : int), (b : int), (c : int)) ((x : int), (y : int), (z : int)) :
    bool =
  match () with
  | () when a <> x -> a > x
  | () when b <> y -> b > y
  | () -> c >= z

let probe (binary : string) : ((int * int * int) * string, Errx.t) result =
  Result.bind
    (spawn binary [| binary; "--version" |])
    (fun (proc : in_channel * out_channel * in_channel) ->
      Result.bind (probe_read proc) parse_version)

(* ---------- make ---------- *)

let positive (name : string) (n : int) : (unit, Errx.t) result =
  match () with
  | () when n < 1 -> transport ("make: " ^ name ^ " must be >= 1")
  | () -> Ok ()

let check_max_time (m : int option) : (unit, Errx.t) result =
  Option.fold ~none:(fun (() : unit) -> Ok ())
    ~some:(fun (n : int) (() : unit) -> positive "max_time" n)
    m ()

let make ?(binary : string = default_binary ())
    ?(endpoint : Httpx.Endpoint.t = Httpx.Endpoint.default)
    ?(connect_timeout : int = default_connect_timeout ())
    ?(idle_timeout : int = default_idle_timeout ()) ?(max_time : int option)
    (() : unit) : (t, Errx.t) result =
  ignore_sigpipe ();
  Result.bind (positive "connect_timeout" connect_timeout) (fun (() : unit) ->
      Result.bind (positive "idle_timeout" idle_timeout) (fun (() : unit) ->
          Result.bind (check_max_time max_time) (fun (() : unit) ->
              Result.bind (probe binary)
                (fun ((tr : int * int * int), (ver : string)) ->
                  match () with
                  | () when not (ge tr (floor_version ())) ->
                    transport
                      ("version: curl "
                      ^ show_triple (floor_version ())
                      ^ " or newer required, found " ^ ver)
                  | () ->
                    Ok
                      { binary;
                        endpoint;
                        connect_timeout;
                        idle_timeout;
                        max_time;
                        version = ver;
                        max_line =
                          (match ge tr (dynbuf_version ()) with
                          | true -> line_cap_new ()
                          | false -> line_cap_old ()) }))))

let version (c : t) : string = c.version
let max_line (c : t) : int = c.max_line

(* ---------- signal and exit naming ---------- *)

(* OCaml signal numbers are negative internal constants (Sys.sigterm
   is -11 on 5.3), so a signal is NEVER printed as an exit code. *)
let signal_name (s : int) : string =
  match () with
  | () when s = Sys.sigterm -> "SIGTERM"
  | () when s = Sys.sigkill -> "SIGKILL"
  | () when s = Sys.sigpipe -> "SIGPIPE"
  | () when s = Sys.sigint -> "SIGINT"
  | () when s = Sys.sighup -> "SIGHUP"
  | () when s = Sys.sigalrm -> "SIGALRM"
  | () when s = Sys.sigsegv -> "SIGSEGV"
  | () when s = Sys.sigabrt -> "SIGABRT"
  | () -> "unknown(" ^ string_of_int s ^ ")"

let meaning (n : int) : string =
  match n with
  | 6 -> " (dns: could not resolve host)"
  | 7 -> " (connect: failed to connect to host)"
  | 23 -> " (write error: the reader closed the pipe)"
  | 26 -> " (config rejected: unknown option or over-long line)"
  | 28 -> " (timeout: operation timed out)"
  | 35 -> " (tls handshake failed)"
  | 52 -> " (empty reply from server)"
  | 56 -> " (recv failure)"
  | 60 -> " (certificate verify failed)"
  | _ -> ""

let exit_result (tail : string) (st : Unix.process_status) :
    (unit, Errx.t) result =
  match st with
  | Unix.WEXITED 0 -> Ok ()
  | Unix.WEXITED n ->
    transport ("curl exit " ^ string_of_int n ^ meaning n ^ ": " ^ tail)
  | Unix.WSIGNALED s ->
    transport ("curl killed by signal " ^ signal_name s ^ ": " ^ tail)
  | Unix.WSTOPPED s -> transport ("curl stopped by signal " ^ signal_name s)

(* ---------- the select pump (A16) ---------- *)

let watched (b : body) : Unix.file_descr list =
  match !(b.err_eof) with
  | true -> [ b.out_fd ]
  | false -> [ b.out_fd; b.err_fd ]

let select_ready (b : body) : (Unix.file_descr list, Errx.t) result =
  Result.map
    (fun ((r : Unix.file_descr list), (_ : Unix.file_descr list),
          (_ : Unix.file_descr list)) -> r)
    (guard (fun (() : unit) -> Unix.select (watched b) [] [] (-1.0)))

let take_err (b : body) (ready : Unix.file_descr list) :
    (unit, Errx.t) result =
  match List.mem b.err_fd ready with
  | false -> Ok ()
  | true ->
    Result.map
      (fun (chunk : string) ->
        match String.length chunk with
        | 0 -> b.err_eof := true
        | _ -> b.errbuf := ring_add !(b.errbuf) chunk)
      (read_fd b.err_fd)

let take_out (b : body) : (string, Errx.t) result =
  Result.map
    (fun (chunk : string) ->
      match String.length chunk with
      | 0 ->
        b.eof := true;
        ""
      | _ -> chunk)
    (read_fd b.out_fd)

(* Returns the next stdout chunk, or "" once stdout is at EOF. Both
   pipes stay in the select set until each reports EOF, so a chatty
   child can never block in write(2) while we wait on the other pipe. *)
let rec pump (b : body) : (string, Errx.t) result =
  match !(b.eof) with
  | true -> Ok ""
  | false ->
    Result.bind (select_ready b) (fun (ready : Unix.file_descr list) ->
        Result.bind (take_err b ready) (fun (() : unit) ->
            match List.mem b.out_fd ready with
            | false -> pump b
            | true -> take_out b))

(* ---------- close ---------- *)

let rec drain_err (b : body) : (unit, Errx.t) result =
  match !(b.err_eof) with
  | true -> Ok ()
  | false ->
    Result.bind (read_fd b.err_fd) (fun (chunk : string) ->
        match String.length chunk with
        | 0 ->
          b.err_eof := true;
          Ok ()
        | _ ->
          b.errbuf := ring_add !(b.errbuf) chunk;
          drain_err b)

let kill_if_live (b : body) : unit =
  match !(b.eof) with
  | true -> ()
  | false ->
    let (_ : (unit, Errx.t) result) =
      guard (fun (() : unit) -> Unix.kill b.pid Sys.sigterm)
    in
    ()

let status_result (b : body) (st : Unix.process_status) :
    (unit, Errx.t) result =
  match !(b.eof) with
  | false -> Ok ()
  | true -> exit_result (redact ~key:b.key !(b.errbuf)) st

let close (b : body) : (unit, Errx.t) result =
  match !(b.closed) with
  | true -> Ok ()
  | false ->
    b.closed := true;
    kill_if_live b;
    Result.bind (drain_err b) (fun (() : unit) ->
        Result.bind
          (guard (fun (() : unit) -> Unix.close_process_full b.proc))
          (status_result b))

(* A nonzero exit WINS over a wire error: the exit code explains the
   truncated head. close returns Ok on exit 0, which hands the
   original error back untouched. *)
let prefer_exit (b : body) (fallback : Errx.t) : Errx.t =
  Result.fold ~ok:(fun (() : unit) -> fallback) ~error:Fun.id (close b)

(* ---------- reads ---------- *)

let chunk_option (c : string) : string option =
  match String.length c with
  | 0 -> None
  | _ -> Some c

let read (b : body) : (string option, Errx.t) result =
  match String.length !(b.pending) with
  | 0 -> Result.map chunk_option (pump b)
  | _ ->
    let held = !(b.pending) in
    b.pending := "";
    Ok (Some held)

let read_all ?(cap : int = read_all_cap ()) (b : body) :
    (string, Errx.t) result =
  let rec go (acc : string list) (n : int) : (string, Errx.t) result =
    Result.bind (read b) (fun (o : string option) ->
        Option.fold
          ~none:(fun (() : unit) -> Ok (String.concat "" (List.rev acc)))
          ~some:(fun (c : string) (() : unit) ->
            let n2 = n + String.length c in
            match () with
            | () when n2 > cap ->
              transport
                ("read_all: body exceeds " ^ string_of_int cap ^ " bytes")
            | () -> go (c :: acc) n2)
          o ())
  in
  go [] 0

(* ---------- send ---------- *)

let check_line (c : t) (req : Httpx.Request.t) : (unit, Errx.t) result =
  Option.fold ~none:(fun (() : unit) -> Ok ())
    ~some:(fun (rendered : string) (() : unit) ->
      let n = Cfgx.data_line_bytes rendered in
      match () with
      | () when n > c.max_line ->
        transport
          ("body: data line " ^ string_of_int n ^ " bytes exceeds the curl "
         ^ c.version ^ " config-line cap "
          ^ string_of_int c.max_line)
      | () -> Ok ())
    (Httpx.Request.rendered req)
    ()

let new_body (proc : in_channel * out_channel * in_channel) (key : Keyx.t) :
    body =
  let ic, (_ : out_channel), ec = proc in
  { proc;
    out_fd = Unix.descr_of_in_channel ic;
    err_fd = Unix.descr_of_in_channel ec;
    pid = Unix.process_full_pid proc;
    key;
    pending = ref "";
    errbuf = ref "";
    eof = ref false;
    err_eof = ref false;
    closed = ref false }

let write_config (b : body) (cfg : string) : (unit, Errx.t) result =
  let (_ : in_channel), oc, (_ : in_channel) = b.proc in
  guard (fun (() : unit) ->
      output_string oc cfg;
      close_out oc)

(* A dead reader means the config never landed. Kill (ESRCH is
   ignored), then wait: the exit code is the better story, and the
   write error stays as the fallback when curl exited 0. *)
let fail_after_write (b : body) (e : Errx.t) : Errx.t =
  let (_ : (unit, Errx.t) result) =
    guard (fun (() : unit) -> Unix.kill b.pid Sys.sigterm)
  in
  b.eof := true;
  Result.fold ~ok:(fun (() : unit) -> e) ~error:Fun.id (close b)

let rec read_head (b : body) (m : Wirex.t) : (Wirex.head, Errx.t) result =
  Result.bind (pump b) (fun (chunk : string) ->
      match String.length chunk with
      | 0 -> Error (Errx.Wire_invalid "stream ended before the response head")
      | _ ->
        Result.bind (Wirex.feed m chunk) (fun (s : Wirex.step) ->
            match s with
            | Wirex.More m2 -> read_head b m2
            | Wirex.Head (h, rest) ->
              b.pending := rest;
              Ok h))

let start_head (b : body) : (Wirex.head, Errx.t) result =
  Result.bind (Wirex.make ()) (read_head b)

let send (c : t) ~(key : Keyx.t) (req : Httpx.Request.t) :
    (Wirex.head * body, Errx.t) result =
  Result.bind (check_line c req) (fun (() : unit) ->
      let cfg =
        Cfgx.render ~key ~endpoint:c.endpoint
          ~connect_timeout:c.connect_timeout ~idle_timeout:c.idle_timeout
          ~max_time:c.max_time req
      in
      Result.bind
        (spawn c.binary (Cfgx.argv ~binary:c.binary))
        (fun (proc : in_channel * out_channel * in_channel) ->
          let b = new_body proc key in
          Result.fold
            ~ok:(fun (() : unit) ->
              Result.fold
                ~ok:(fun (h : Wirex.head) -> Ok (h, b))
                ~error:(fun (e : Errx.t) -> Error (prefer_exit b e))
                (start_head b))
            ~error:(fun (e : Errx.t) -> Error (fail_after_write b e))
            (write_config b cfg)))
