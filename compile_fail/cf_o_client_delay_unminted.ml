(* M15 D13: a Delay is MINTED only inside the SDK. A caller reads a
   delay off an Attempt or an Obstacle; it can never build one, so no
   caller can hand the retry loop a wait the policy window never
   approved. Venice.Delay publishes ms and nothing else.

   This must fail with "Unbound value" naming Venice.Delay.of_ms. *)

let unminted : int =
  Venice.Delay.ms (Venice.Delay.of_ms 5)
