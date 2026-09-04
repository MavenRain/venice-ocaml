(* M15 retryx: the bounded retry decision. CORE unit.

   Everything here is pure: no ref, no clock, no float, no exception
   and no IO. The wall clock enters through the [~now] argument that
   clientx reads from a Clockx.S, so a scripted clock and a real clock
   produce the same decisions.

   The five public satellites of Venice.Client (Delay, Policy,
   Obstacle, Stop, Attempt) are DEFINED here (A7), not in clientx:
   clientx depends on retryx and retryx never names clientx, so the
   dune dependency stays acyclic. lib/venice.ml re-exports them.

   The decision is a TABLE, not a search. clientx folds the server
   hints into one optional Delay before it calls [decide], so [decide]
   reads four policy numbers and one obstacle and answers with a wait
   or with the reason it stopped. *)

module Delay : sig
  (* Whole milliseconds inside 0..3_600_000. The window is closed at
     one hour because every hint the wire can carry (a reset instant,
     a reset duration, a retry-after count) is saturated INTO the
     window before it is scaled to milliseconds (A1), so no product
     can pass Int.max_int and no over-window hint can degrade into a
     silent backoff. *)
  type t

  val max_ms : unit -> int
  (* 3_600_000, the closed top of the window *)

  val ms : t -> int
  val zero : unit -> t

  val of_ms : int -> (t, Errx.t) result
  (* The checked mint, for policy fields and for a caller that has an
     exact millisecond count. Outside the window it rejects with
     Client_invalid. It is NOT re-exported by venice.mli (D13): a
     public caller reads a Delay, it never mints one. *)

  val saturate : int -> t
  (* The total mint, for hints. Below 0 gives 0, above the window
     gives the window top. It cannot fail, so hint conversion needs no
     result plumbing, and a saturated hint of 3_600_000 ms is above
     every legal max_delay_ms (600_000), which makes decide answer
     Hint_over_cap for it. *)
end

module Policy : sig
  (* The four bounded numbers that shape a retry. Every window bound
     is a unit thunk in the implementation (D12). *)
  type t

  val default : t
  (* 3 attempts, base 1_000 ms, per-wait cap 30_000 ms, total cap
     120_000 ms *)

  val none : t
  (* one attempt and the defaults otherwise, so decide answers
     Attempts_exhausted at the first obstacle and the caller sees a
     single attempt *)

  val make :
    ?max_attempts:int ->
    ?base_ms:int ->
    ?max_delay_ms:int ->
    ?max_total_ms:int ->
    unit ->
    (t, Errx.t) result
  (* max_attempts 1..8; base_ms 1..60_000; max_delay_ms at least
     base_ms and at most 600_000; max_total_ms at least max_delay_ms
     and at most 3_600_000. A rejection is Client_invalid and NAMES
     the field that failed. *)

  val max_attempts : t -> int
  val base_ms : t -> int
  val max_delay_ms : t -> int
  val max_total_ms : t -> int
end

module Obstacle : sig
  (* What made an attempt fail, as a CLOSED sum: only these three
     retry. Every other failure ends the loop with Stop.Not_retryable,
     so a timeout on a POST is never re-sent and cannot double-bill. *)
  type t =
    | Rate_limited of Delay.t option  (* the folded server hint, if any *)
    | Gateway of int  (* 502, 503 or 504 *)
    | Unreachable of string  (* the Errx.Transport_unreachable payload *)
end

module Stop : sig
  (* Why the loop stopped. Hint_over_cap and Budget_exhausted carry
     the wait that was refused, so a caller can report the number the
     server asked for. *)
  type t =
    | Not_retryable
    | Attempts_exhausted
    | Hint_over_cap of Delay.t
    | Budget_exhausted of Delay.t
end

module Attempt : sig
  (* One RETRIED attempt: the obstacle that ended it and the sleep
     taken before the next send. It carries no body, no header and no
     key byte (D11). *)
  type t

  val make : obstacle:Obstacle.t -> slept:Delay.t -> t
  val obstacle : t -> Obstacle.t
  val slept : t -> Delay.t
end

type hints =
  { reset_at : Delay.t option;
    reset_after : Delay.t option;
    retry_after : Delay.t option }

val hints_of :
  head:(Headx.t, Errx.t) result ->
  now:int ->
  retry_after:string option ->
  hints
(* Reads the three server hints, each already saturated into the
   Delay window (A1).

   reset_at is the requests triple's reset instant, and ONLY when that
   triple is present and its remaining is 0; the value is the instant
   less [now] in SECONDS, dropped when it is not in the future and
   saturated when it is more than an hour ahead. reset_after is the
   tokens triple's reset duration under the same remaining-is-0 rule,
   compared against 3600 SECONDS before it is scaled. An Error head
   gives no triple hint at all, but retry_after is still read, because
   it comes from the raw pair and not from the parse.

   retry_after is the raw value of the first lowercase retry-after
   pair, accepted only as 1..10 ASCII digits with no other byte; an
   HTTP-date is rejected (D18 defers it). *)

val best_hint : hints -> Delay.t option
(* The LARGEST present hint, or None. Waiting the largest is the only
   safe fold: a shorter wait burns an attempt on a certain 429. *)

val decide :
  Policy.t ->
  attempt:int ->
  waited:Delay.t ->
  now:int ->
  Obstacle.t ->
  (Delay.t, Stop.t) result
(* The whole decision, in order:
   1. attempt (1-based) at or above max_attempts stops with
      Attempts_exhausted;
   2. the wait is the folded hint for Rate_limited when present, else
      base_ms doubled attempt-1 times (bounded by a fold, never by an
      unchecked shift) and capped by max_delay_ms;
   3. a wait above max_delay_ms stops with Hint_over_cap, NOT clamped:
      waiting less than the server asked for burns an attempt;
   4. waited plus wait above max_total_ms stops with Budget_exhausted;
   5. otherwise Ok wait.

   [now] is taken for the D4 signature and for a later milestone that
   dates the decision; the hint arithmetic that needs it already ran
   in hints_of (A1), so decide reads no clock and stays a table. *)
