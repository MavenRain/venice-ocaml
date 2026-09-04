(* M13 fakex: the scripted transport. HOST unit.

   Fake answers a fixed script instead of a process. It matches the
   Curl transport arm for arm, so M14 determinism tests and M15
   end-to-end tests run with no network and no subprocess.

   Fake lives in lib, not in test, for that reason. It is NOT in the
   gates.sh core= list: the script cursor, the recorded requests and
   the per-body chunk cursor are refs, which is host-side mutation.

   The script head is parsed by Wirex at send time, so one head
   grammar serves both transports and a malformed script head fails
   the same way a malformed wire head fails. *)

type t
type body
type exchange

val exchange :
  head:string -> chunks:string list -> ?close_error:string -> unit -> exchange
(* head is the RAW head bytes, terminator included, for example
   "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n". Bytes
   after the blank line become the first read. chunks are handed to
   read in order. close_error makes close reject with that text under
   the "transport: " prefix. *)

val make : exchange list -> t
(* the script, in send order *)

val requests : t -> Httpx.Request.t list
(* every request that send accepted, in call order *)

val send :
  t -> key:Keyx.t -> Httpx.Request.t -> (Wirex.head * body, Errx.t) result
(* Pops the next exchange and records the request. An exhausted
   script rejects with "fake: script exhausted". A malformed script
   head rejects as Wire_invalid. The key is ignored: Fake never
   renders a config. *)

val read : body -> (string option, Errx.t) result
(* the next scripted chunk, None once the script is spent *)

val read_all : ?cap:int -> body -> (string, Errx.t) result
(* drains the remaining chunks; rejects above cap, default 8_388_608 *)

val close : body -> (unit, Errx.t) result
(* Ok, or the scripted close_error. Idempotent, like Curl.close: a
   second call returns Ok. *)

val reads : body -> int
val closes : body -> int
(* M14 A5 test seams: every read call and every close call, the
   idempotent second close included. close is idempotent, so a
   "closed exactly once" claim is unobservable without this counter
   and the close-twice mutant would survive. *)
