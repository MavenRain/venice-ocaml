(* M29 entropy is a HOST boundary. Production reads and scripted
   consumption meet at draw, so scalar and nonce construction use the
   same length invariant. Neither rejection text nor public interfaces
   expose a secret scalar, exception detail or descriptor. *)

type t = System | Script of string list Atomic.t
type entropy = t

let draw_length (() : unit) : int = 32
let rejection_limit (() : unit) : int = 128

let invalid (reason : string) : ('a, Errx.t) result =
  Error (Errx.Session_invalid reason)

type io_failure = Interrupted | Unavailable

(* Named exceptions from the Unix boundary only. Raw operation names,
   paths and error payloads never become part of an Errx value. *)
let guard (f : unit -> 'a) : ('a, io_failure) result =
  try Ok (f ()) with
  | Unix.Unix_error (Unix.EINTR, _, _) -> Error Interrupted
  | Unix.Unix_error (_, _, _) | Sys_error _ -> Error Unavailable

let rec retry_io (f : unit -> 'a) : ('a, Errx.t) result =
  Result.fold ~ok:Result.ok
    ~error:(fun failure ->
      match failure with
      | Interrupted -> retry_io f
      | Unavailable -> invalid "entropy unavailable")
    (guard f)

(* A close is attempted exactly once. A host may release a descriptor
   even when close reports EINTR, so retrying could close a descriptor
   that another domain has since opened. Both failure cases fail closed. *)
let close (fd : Unix.file_descr) : (unit, Errx.t) result =
  Result.map_error
    (fun (_ : io_failure) -> Errx.Session_invalid "entropy unavailable")
    (guard (fun () -> Unix.close fd))

let rec read_exact (fd : Unix.file_descr) (buffer : Bytes.t) (offset : int) :
    (unit, Errx.t) result =
  let remaining = Bytes.length buffer - offset in
  if remaining = 0 then Ok ()
  else
    Result.bind
      (retry_io (fun () -> Unix.read fd buffer offset remaining))
      (fun taken ->
        if taken = 0 then invalid "entropy unavailable"
        else read_exact fd buffer (offset + taken))

let read_system (() : unit) : (string, Errx.t) result =
  let buffer = Bytes.create (draw_length ()) in
  Result.bind
    (retry_io (fun () ->
         Unix.openfile "/dev/urandom" [Unix.O_RDONLY; Unix.O_CLOEXEC] 0))
    (fun fd ->
      let read_result = read_exact fd buffer 0 in
      let close_result = close fd in
      Result.bind read_result (fun () ->
          Result.map (fun () -> Bytes.to_string buffer) close_result))

let rec take_script (script : string list Atomic.t) : (string, Errx.t) result =
  let before = Atomic.get script in
  match before with
  | [] -> invalid "entropy exhausted"
  | bytes :: tail ->
    if Atomic.compare_and_set script before tail then Ok bytes
    else take_script script

let draw (source : t) : (string, Errx.t) result =
  let result =
    match source with
    | System -> read_system ()
    | Script script -> take_script script
  in
  Result.bind result (fun bytes ->
      if String.length bytes = draw_length () then Ok bytes
      else invalid "entropy length")

let system (() : unit) : t = System

let scalar (source : t) : (Secpx.Scalar.t, Errx.t) result =
  let rec sample (attempts_left : int) : (Secpx.Scalar.t, Errx.t) result =
    if attempts_left = 0 then invalid "scalar rejection limit"
    else
      Result.bind (draw source) (fun bytes ->
          Result.fold ~ok:Result.ok
            ~error:(fun () -> sample (attempts_left - 1))
            (Option.to_result ~none:() (Secpx.Scalar.of_bytes bytes)))
  in
  sample (rejection_limit ())

module Fresh = struct
  type t = { nonce : Policyx.Nonce.t; consumed : bool Atomic.t }

  let make ~(entropy : entropy) : (t, Errx.t) result =
    Result.bind (draw entropy) (fun bytes ->
        Result.map
          (fun nonce -> { nonce; consumed = Atomic.make false })
          (Option.to_result ~none:(Errx.Session_invalid "entropy length")
             (Policyx.Nonce.of_bytes bytes)))

  let nonce (fresh : t) : Policyx.Nonce.t = fresh.nonce

  let consume (fresh : t) ~(nonce : Policyx.Nonce.t) : (unit, Errx.t) result =
    let acquired = Atomic.compare_and_set fresh.consumed false true in
    match () with
    | () when not acquired -> invalid "fresh consumed"
    | () when not (Policyx.Nonce.equal fresh.nonce nonce) -> invalid "nonce mismatch"
    | () -> Ok ()
end

module Gcm_fresh = struct
  type t = { nonce : Gcmx.Nonce.t; consumed : bool Atomic.t }

  let make ~(entropy : entropy) : (t, Errx.t) result =
    Result.bind (draw entropy) (fun bytes ->
        let nonce =
          Option.bind (Bytesx.take bytes 0 (Gcmx.nonce_len ())) Gcmx.Nonce.of_bytes
        in
        Result.map
          (fun nonce -> { nonce; consumed = Atomic.make false })
          (Option.to_result ~none:(Errx.Session_invalid "entropy length") nonce))

  let nonce (fresh : t) : Gcmx.Nonce.t = fresh.nonce

  let consume (fresh : t) : (unit, Errx.t) result =
    if Atomic.compare_and_set fresh.consumed false true then Ok ()
    else invalid "gcm nonce consumed"
end

module Fake = struct
  let make (chunks : string list) : t = Script (Atomic.make chunks)

  let remaining (source : t) : int =
    match source with
    | System -> 0
    | Script script -> List.length (Atomic.get script)
end
