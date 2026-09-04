(* M15 clockx: the wall-clock and sleep boundary. HOST unit: System
   names Unix and holds the one float of the milestone, Fake holds two
   refs. Out of the gates.sh core= list by design. *)

module type S = sig
  type t

  val now : t -> int
  val sleep : t -> Retryx.Delay.t -> unit
end

let ms_per_second (() : unit) : int = 1_000

(* Whole seconds, rounded UP, by a bounded subtraction: a Delay is at
   most 3_600_000 ms, so this takes at most 3_600 steps and needs no
   division. Rounding up matters: a caller that sleeps 1_500 ms must
   see the clock pass a reset instant 2 s away, never stop 1 s short
   of it. *)
let rec ceil_seconds (ms : int) (acc : int) : int =
  match () with
  | () when ms <= 0 -> acc
  | () -> ceil_seconds (ms - ms_per_second ()) (acc + 1)

module System = struct
  type t = unit

  let make (() : unit) : t = ()
  let now (_ : t) : int = Float.to_int (Unix.gettimeofday ())

  let sleep (_ : t) (d : Retryx.Delay.t) : unit =
    Unix.sleepf (Float.of_int (Retryx.Delay.ms d) /. 1000.)
end

module Fake = struct
  type t = { at : int ref; taken : Retryx.Delay.t list ref }

  let default_now (() : unit) : int = 1_700_000_000

  let make ?(now : int = default_now ()) (() : unit) : t =
    { at = ref now; taken = ref [] }

  let now (t : t) : int = !(t.at)

  let sleep (t : t) (d : Retryx.Delay.t) : unit =
    t.taken := d :: !(t.taken);
    t.at := !(t.at) + ceil_seconds (Retryx.Delay.ms d) 0

  let slept (t : t) : Retryx.Delay.t list = List.rev !(t.taken)
end
