(* M15 clockx: the wall-clock and sleep boundary. HOST unit.

   Runtime assumption, stated here because it is UNVERIFIABLE ON DISK
   (A5): the installed unix.mli states nothing about EINTR or about
   when sleepf raises. The claim is supported by the OCaml runtime
   source, where otherlibs/unix/sleep_unix.c loops nanosleep on EINTR,
   a negative duration returns at once, and only EINVAL raises, which
   a non-negative finite float cannot produce. M15 therefore adds NO
   try-with: the repo keeps exactly one (lib/curlx.ml). FACTS.md
   carries the same claim as an OPEN runtime fact, not a verified one.

   clockx stays out of the gates.sh core= list, like curlx and fakex:
   System names Unix and holds the ONE float of the milestone, and
   Fake holds two refs so a test can script time.

   Every retry decision reads the clock through this boundary, so a
   scripted clock and a real clock drive the same code. *)

module type S = sig
  type t

  val now : t -> int
  (* whole unix seconds *)

  val sleep : t -> Retryx.Delay.t -> unit
  (* blocks for the delay; a Delay is bounded by one hour, so this can
     never block forever *)
end

module System : sig
  (* now is Float.to_int (Unix.gettimeofday ()); sleep is Unix.sleepf
     over the milliseconds divided by 1000., the ONE float in M15. *)
  include S

  val make : unit -> t
end

module Fake : sig
  (* The scripted twin. sleep records the delay and advances now by
     the delay rounded UP to whole seconds, so a caller that sleeps
     1_500 ms sees now advance by 2 s and a reset instant 2 s ahead is
     reached, never missed by a rounding down. *)
  include S

  val make : ?now:int -> unit -> t
  (* default now is 1_700_000_000 *)

  val slept : t -> Retryx.Delay.t list
  (* every sleep, in call order *)
end
