(* M13 curlx: the curl-subprocess transport. HOST unit.

   This module and fakex are the only ones that name Unix, Bytes or a
   ref; neither is in the gates.sh core= list, and the ONE try-with in
   the repo lives here (guard, over the named constructors
   Unix.Unix_error, Sys_error and End_of_file, never a catch-all,
   never re-raising). Every stdlib call that can raise is wrapped in
   its own guard thunk at the call site.

   Process shape: argv is [binary; "-q"; "-K"; "-"], so `ps` shows no
   secret and no URL; everything else, the key included, arrives on
   stdin as a curl config and dies with the process.

   IO model (A16): stdout and stderr are read as RAW DESCRIPTORS with
   Unix.read, multiplexed by Unix.select, never through the channel
   buffers and never one after the other. A child that writes 1 MiB to
   stderr blocks in write(2) at the 64 KiB pipe capacity, so a reader
   that drains stdout first would hang forever. stderr readiness is
   consumed into a ring that keeps the LAST 4096 bytes; stdout
   readiness yields the next chunk or marks EOF. Only after stdout EOF
   (or after the early-close kill) is stderr drained to EOF with
   blocking reads, which are safe once the child is done writing.

   Redaction: every stderr tail passes through a replacement of the
   key bytes with "[redacted]" before it can reach an error text.

   make has one process-global side effect, documented and taken once:
   it sets SIGPIPE to ignore, without which a dead curl kills the HOST
   process on the config write. *)

type t
type body

val make :
  ?binary:string ->
  ?endpoint:Httpx.Endpoint.t ->
  ?connect_timeout:int ->
  ?idle_timeout:int ->
  ?max_time:int ->
  unit ->
  (t, Errx.t) result
(* Defaults: binary "curl", Httpx.Endpoint.default, connect_timeout
   30, idle_timeout 300, no max_time. Each int must be >= 1.

   make probes the binary ONCE with argv [binary; "--version"] (no
   secret on that command line) and parses the leading
   "curl MAJOR.MINOR.PATCH" line. A spawn failure rejects with
   "spawn: ..."; an unreadable line rejects with "version: ...".
   Below curl 7.67.0 make rejects (A14): no-progress-meter arrived
   there, and an unknown option makes curl abort the WHOLE config
   with exit 26 rather than warn. *)

val version : t -> string
(* the parsed triple as "MAJOR.MINOR.PATCH" *)

val max_line : t -> int
(* The curl config-line cap for this binary: 10_485_248 from 8.2.0
   (10 MiB less 512 bytes of slack below the measured boundary) and
   65_536 below it. send measures the whole rendered data-binary line
   against it BEFORE spawning anything. *)

val send :
  t -> key:Keyx.t -> Httpx.Request.t -> (Wirex.head * body, Errx.t) result
(* Spawns curl, writes the config, closes stdin, and reads stdout
   until the head parses. It does NOT wait for exit: the body streams.
   A nonzero exit WINS over a wire error, because the exit code
   explains the truncated head. *)

val read : body -> (string option, Errx.t) result
(* whatever arrived, partial chunks are normal; None at EOF *)

val read_all : ?cap:int -> body -> (string, Errx.t) result
(* drains to EOF; rejects above cap, default 8_388_608 bytes *)

val close : body -> (unit, Errx.t) result
(* Idempotent (A5): the first call flips the closed flag before
   reaping, and a second call returns Ok without touching the
   channels, because a second close_process_full raises EBADF.

   After EOF: drain stderr, reap, and map the status. WEXITED 0 is Ok;
   any other status carries the redacted stderr tail, with a short
   meaning appended for the documented exit codes (6 dns, 7 connect,
   23 write error, 26 config rejected, 28 timeout, 35 tls handshake,
   52 empty reply, 56 recv failure, 60 certificate verify).

   M15 D9: exit 6, exit 7 and exit 35 are Transport_unreachable,
   because they fire before any request byte can leave and a retry of
   the same request therefore cannot double-bill. Every other nonzero
   status, a signal death and a spawn failure alike, stays
   Transport_failed. Exit 28 and exit 56 stay Transport_failed on
   purpose: a timeout or a reset can strike AFTER the request went
   out.

   Before EOF (caller-initiated early close): SIGTERM (ESRCH
   ignored), drain, reap, and return Ok whatever the status. Exit 23
   and death by SIGTERM are the expected outcomes of hanging up on a
   live stream, not failures. *)
