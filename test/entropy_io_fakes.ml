(* Test-only Unix script. The generated entropy_io_impl copies the
   production entropy unit verbatim and shadows only these IO calls.
   No real descriptor is opened, read or closed by this module.

   This file holds the single sanctioned raise in the repo, at line 49.
   Unix.read and Unix.openfile report a host failure only by raising
   Unix_error, so a fake that never raises cannot drive the production
   guard in entropyx.ml. No lib code raises. *)
module Errx = Venice__Errx
module Secpx = Venice__Secpx
module Policyx = Venice__Policyx
module Real_unix = Unix

type event =
  | Open_ok
  | Open_error of Real_unix.error
  | Read_bytes of string
  | Read_eof
  | Read_error of Real_unix.error
  | Close_ok
  | Close_error of Real_unix.error
  | Exhausted

let script : event list Atomic.t = Atomic.make []
let opens : int Atomic.t = Atomic.make 0
let reads : int Atomic.t = Atomic.make 0
let closes : int Atomic.t = Atomic.make 0
let valid : bool Atomic.t = Atomic.make true
let windows : (int * int) list Atomic.t = Atomic.make []

let reset (events : event list) : unit =
  Atomic.set script events;
  Atomic.set opens 0;
  Atomic.set reads 0;
  Atomic.set closes 0;
  Atomic.set valid true;
  Atomic.set windows []

let counts (() : unit) : int * int * int =
  (Atomic.get opens, Atomic.get reads, Atomic.get closes)

let remaining (() : unit) : int = List.length (Atomic.get script)
let read_windows (() : unit) : (int * int) list = List.rev (Atomic.get windows)

(* Deliberate host failure injection, caught by the production guard in
   entropyx.ml. This is the one raise site in the repo, and it feeds the
   named Unix_error set that the production try guard catches. *)
let unavailable (error : Real_unix.error) : 'a =
  raise (Real_unix.Unix_error (error, "private operation", "secret fake payload"))

let mismatch (() : unit) : 'a =
  Atomic.set valid false;
  unavailable Real_unix.EIO

let take (() : unit) : event =
  match Atomic.get script with
  | [] -> Exhausted
  | event :: tail -> Atomic.set script tail; event

module Unix = struct
  include Real_unix

  let openfile (path : string) (flags : open_flag list) (permission : int) : file_descr =
    Atomic.incr opens;
    if not (String.equal path "/dev/urandom")
       || flags <> [O_RDONLY; O_CLOEXEC] || permission <> 0 then mismatch ()
    else
      match take () with
      | Open_ok -> stdin
      | Open_error error -> unavailable error
      | Read_bytes _ | Read_eof | Read_error _ | Close_ok | Close_error _ | Exhausted ->
        mismatch ()

  let read (fd : file_descr) (buffer : Bytes.t) (offset : int) (length : int) : int =
    Atomic.incr reads;
    Atomic.set windows ((offset, length) :: Atomic.get windows);
    if fd <> stdin || offset < 0 || length < 0
       || offset > Bytes.length buffer - length then mismatch ()
    else
      match take () with
      | Read_bytes bytes ->
        let taken = String.length bytes in
        if taken > length then mismatch ()
        else if offset >= 0 && taken <= Bytes.length buffer - offset then
          (Bytes.blit_string bytes 0 buffer offset taken; taken) (* @total-accessor *)
        else mismatch ()
      | Read_eof -> 0
      | Read_error error -> unavailable error
      | Open_ok | Open_error _ | Close_ok | Close_error _ | Exhausted -> mismatch ()

  let close (fd : file_descr) : unit =
    Atomic.incr closes;
    if fd <> stdin then mismatch ()
    else
      match take () with
      | Close_ok -> ()
      | Close_error error -> unavailable error
      | Open_ok | Open_error _ | Read_bytes _ | Read_eof | Read_error _ | Exhausted ->
        mismatch ()
end
