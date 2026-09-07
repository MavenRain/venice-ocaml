(* Exercise the exact production IO boundary against an ordered Unix
   script. Every scenario is finite, including interrupted operations. *)
module F = Entropy_io_fakes
module I = Entropy_io_impl
module E = Venice__Errx
module N = Venice__Policyx.Nonce

type expected = Bytes of string | Unavailable

let check ~(events : F.event list) ~(counts : int * int * int)
    ~(windows : (int * int) list) ?(remaining : int = 0)
    (expected : expected) : bool =
  F.reset events;
  let result = I.Fresh.make ~entropy:(I.system ()) in
  let outcome =
    match expected with
    | Bytes bytes -> Result.fold ~error:(fun _ -> false)
        ~ok:(fun fresh -> String.equal bytes (N.to_bytes (I.Fresh.nonce fresh))) result
    | Unavailable -> Result.fold ~ok:(fun _ -> false)
        ~error:(fun error -> error = E.Session_invalid "entropy unavailable"
          && String.equal (E.to_string error) "session: entropy unavailable") result
  in
  outcome && Atomic.get F.valid && F.counts () = counts
  && F.read_windows () = windows && F.remaining () = remaining

let payload : string = "0123456789abcdefghijklmnopqrstuv"

let checks : (string * bool) list = [
  "IO: exact bytes returned after one read and successful close",
    check ~events:[F.Open_ok; F.Read_bytes payload; F.Close_ok]
      ~counts:(1, 1, 1) ~windows:[0, 32] (Bytes payload);
  "IO: partial reads retain offsets and concatenate all bytes",
    check ~events:[F.Open_ok; F.Read_bytes "0123456";
      F.Read_bytes "789"; F.Read_bytes "abcdefghijklmnopqrstuv"; F.Close_ok]
      ~counts:(1, 3, 1) ~windows:[0, 32; 7, 25; 10, 22] (Bytes payload);
  "IO: interrupted opens retry before any read or close",
    check ~events:[F.Open_error Unix.EINTR; F.Open_error Unix.EINTR;
      F.Open_ok; F.Read_bytes payload; F.Close_ok]
      ~counts:(3, 1, 1) ~windows:[0, 32] (Bytes payload);
  "IO: interrupted read retries the original buffer window",
    check ~events:[F.Open_ok; F.Read_error Unix.EINTR; F.Read_bytes payload; F.Close_ok]
      ~counts:(1, 2, 1) ~windows:[0, 32; 0, 32] (Bytes payload);
  "IO: interrupted partial read retries without losing earlier bytes",
    check ~events:[F.Open_ok; F.Read_bytes "012345678";
      F.Read_error Unix.EINTR; F.Read_bytes "9abcdefghijklmnopqrstuv"; F.Close_ok]
      ~counts:(1, 3, 1) ~windows:[0, 32; 9, 23; 9, 23] (Bytes payload);
  "IO: immediate EOF refuses bytes and closes exactly once",
    check ~events:[F.Open_ok; F.Read_eof; F.Close_ok]
      ~counts:(1, 1, 1) ~windows:[0, 32] Unavailable;
  "IO: EOF after a partial read never returns the partial nonce",
    check ~events:[F.Open_ok; F.Read_bytes "0123456789abc"; F.Read_eof; F.Close_ok]
      ~counts:(1, 2, 1) ~windows:[0, 32; 13, 19] Unavailable;
  "IO: permanent open failure is sanitized and never closes a descriptor",
    check ~events:[F.Open_error Unix.EACCES]
      ~counts:(1, 0, 0) ~windows:[] Unavailable;
  "IO: permanent error after interrupted open terminates retries",
    check ~events:[F.Open_error Unix.EINTR; F.Open_error Unix.EMFILE]
      ~counts:(2, 0, 0) ~windows:[] Unavailable;
  "IO: permanent read failure is sanitized and closes exactly once",
    check ~events:[F.Open_ok; F.Read_error Unix.EIO; F.Close_ok]
      ~counts:(1, 1, 1) ~windows:[0, 32] Unavailable;
  "IO: permanent failure after partial read refuses all bytes",
    check ~events:[F.Open_ok; F.Read_bytes "0123"; F.Read_error Unix.EBADF; F.Close_ok]
      ~counts:(1, 2, 1) ~windows:[0, 32; 4, 28] Unavailable;
  "IO: close failure refuses an otherwise complete nonce",
    check ~events:[F.Open_ok; F.Read_bytes payload; F.Close_error Unix.EIO]
      ~counts:(1, 1, 1) ~windows:[0, 32] Unavailable;
  "IO: interrupted close is attempted once and never retried",
    check ~events:[F.Open_ok; F.Read_bytes payload; F.Close_error Unix.EINTR; F.Close_ok]
      ~counts:(1, 1, 1) ~windows:[0, 32] ~remaining:1 Unavailable;
  "IO: read and close failures remain a sanitized refusal",
    check ~events:[F.Open_ok; F.Read_error Unix.EIO; F.Close_error Unix.EBADF]
      ~counts:(1, 1, 1) ~windows:[0, 32] Unavailable;
  "IO: interrupted close after read failure is never retried",
    check ~events:[F.Open_ok; F.Read_error Unix.EIO; F.Close_error Unix.EINTR; F.Close_ok]
      ~counts:(1, 1, 1) ~windows:[0, 32] ~remaining:1 Unavailable
]

let () =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (name, (_ : bool)) -> print_endline ("FAIL " ^ name)) bad;
  Printf.printf "%d/%d ok\n" (List.length checks - List.length bad) (List.length checks);
  exit (if List.is_empty bad then 0 else 1)
