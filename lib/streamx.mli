(* M14 PULL streaming (D1-D6): an OCaml 5 effect handler turns the
   M11 SSE machine and the M13 Transport boundary into a cursor the
   CALLER drives. The consumer asks for the next chunk; nothing is
   read until it does, so a consumer that stops reading costs exactly
   the bytes it already asked for.

   Why a handler and not a callback: a push loop owns the stack, so a
   caller that wants one chunk must raise to stop, and this repo has
   no exceptions. The handler suspends the producer instead. The
   Delta effect is SEALED inside streamx.ml: no caller can perform it
   and no caller can handle it, so the suspension can never escape
   the one handler that owns it.

   Ledger (D2-D6, A1, A3, A13), closed.
   - The cursor is one-shot and NOT reentrant. next removes the
     continuation from the state BEFORE it resumes it, so a
     re-entrant next reads None instead of resuming a spent
     continuation twice.
   - run is a bracket. The body closes EXACTLY once, on every exit
     path: a drained stream, a cut, a driver failure and a consumer
     exception alike. On the exception path run closes the body,
     poisons the cursor and re-raises, and no outcome is produced.
   - After the run the cursor is DEAD: next reads None forever and
     touches neither the transport nor the machine (A1).
   - Reading stops at the first outcome. After [DONE] the driver
     drains at most 4096 reads and 1 MiB (A3), so a server that keeps
     a socket open after the terminator cannot pin the consumer.
   - Complete means BOTH closes said Ok. A transport close error WINS
     over an SSE close error (D4), because a broken connection
     explains a truncated stream and the truncation does not explain
     the connection. *)

module type S = sig
  (* streamx's OWN copy of the M13 Transport.S: naming
     Venice.Transport.S here would make lib/venice.ml depend on a
     module that depends on venice. lib/venice.ml carries a drift
     guard that fails to compile the day the two signatures part. *)
  type t
  type body

  val send :
    t -> key:Keyx.t -> Httpx.Request.t -> (Wirex.head * body, Errx.t) result

  val read : body -> (string option, Errx.t) result
  val read_all : ?cap:int -> body -> (string, Errx.t) result
  val close : body -> (unit, Errx.t) result
end

type outcome =
  | Complete
  | Cut
  | Failed of Errx.t

type cursor

val next : cursor -> Ssex.Chunk.t option
(* None means the stream is over OR the run has ended. The outcome
   from run says which. *)

val iter : cursor -> (Ssex.Chunk.t -> unit) -> unit
val fold : cursor -> init:'s -> f:('s -> Ssex.Chunk.t -> 's) -> 's

val collect : cursor -> (Accx.final, Errx.t) result
(* Drain into the M14 accumulator. A rejected chunk stops the drain,
   which leaves the run a Cut. *)

module Make (T : S) : sig
  val run :
    ?closing:Ssex.closing ->
    ?max_line_bytes:int ->
    ?max_event_bytes:int ->
    T.body ->
    (cursor -> 'a) ->
    'a * outcome
  (* The bracket. The optional arguments are the M11 machine's own,
     defaults included. The cursor is valid only inside the
     consumer. *)
end
