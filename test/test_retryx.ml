(* M15 retryx: the pure retry table. No transport, no clock and no
   sleep runs here; every clock value is an argument, so the suite is
   deterministic by construction.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal modules by their mangled names, exactly as
   test_streamx does. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module R = Venice__Retryx
module H = Venice__Headx
module E = Venice__Errx

(* ---------- helpers ---------- *)

let now (() : unit) : int = 1_700_000_000

let stop_text (s : R.Stop.t) : string =
  match s with
  | R.Stop.Not_retryable -> "not_retryable"
  | R.Stop.Attempts_exhausted -> "attempts_exhausted"
  | R.Stop.Hint_over_cap d -> "hint_over_cap " ^ string_of_int (R.Delay.ms d)
  | R.Stop.Budget_exhausted d ->
    "budget_exhausted " ^ string_of_int (R.Delay.ms d)

let verdict (r : (R.Delay.t, R.Stop.t) result) : string =
  Result.fold
    ~ok:(fun (d : R.Delay.t) -> "ok " ^ string_of_int (R.Delay.ms d))
    ~error:stop_text r

let dopt (d : R.Delay.t option) : string =
  Option.fold ~none:"none"
    ~some:(fun (x : R.Delay.t) -> string_of_int (R.Delay.ms x))
    d

let policy_text (r : (R.Policy.t, E.t) result) : string =
  Result.fold ~ok:(fun (_ : R.Policy.t) -> "ok") ~error:E.to_string r

let policy_or_default (r : (R.Policy.t, E.t) result) : R.Policy.t =
  Result.fold
    ~ok:(fun (p : R.Policy.t) -> p)
    ~error:(fun (_ : E.t) -> R.Policy.default)
    r

let delay_text (r : (R.Delay.t, E.t) result) : string =
  Result.fold
    ~ok:(fun (d : R.Delay.t) -> string_of_int (R.Delay.ms d))
    ~error:E.to_string r

let minted (ms : int) : R.Delay.t = R.Delay.saturate ms
let zero (() : unit) : R.Delay.t = R.Delay.zero ()

(* A policy widened to the D12 ceiling, so the whole backoff ladder is
   observable in one table. *)
let wide : R.Policy.t =
  policy_or_default
    (R.Policy.make ~max_attempts:8 ~base_ms:1_000 ~max_delay_ms:30_000
       ~max_total_ms:3_600_000 ())

let gateway : R.Obstacle.t = R.Obstacle.Gateway 503

let step (n : int) : string =
  verdict (R.decide wide ~attempt:n ~waited:(zero ()) ~now:(now ()) gateway)

(* ---------- header fixtures (A8: full triples) ---------- *)

let requests_triple ~(remaining : int) ~(reset : int) :
    (string * string) list =
  [ ("x-ratelimit-limit-requests", "100");
    ("x-ratelimit-remaining-requests", string_of_int remaining);
    ("x-ratelimit-reset-requests", string_of_int reset) ]

let tokens_triple ~(remaining : int) ~(reset : string) :
    (string * string) list =
  [ ("x-ratelimit-limit-tokens", "100000");
    ("x-ratelimit-remaining-tokens", string_of_int remaining);
    ("x-ratelimit-reset-tokens", reset) ]

let head_of (pairs : (string * string) list) : (H.t, E.t) result =
  H.of_pairs pairs

let hints_for ?(pairs : (string * string) list = [])
    ?(retry_after : string option) (() : unit) : R.hints =
  R.hints_of ~head:(head_of pairs) ~now:(now ()) ~retry_after

let after_hint (v : string) : string =
  dopt (hints_for ~retry_after:v ()).R.retry_after

let tokens_hint (reset : string) : string =
  dopt
    (hints_for ~pairs:(tokens_triple ~remaining:0 ~reset) ()).R.reset_after

(* ---------- the checks ---------- *)

let backoff_checks : (string * bool) list =
  [ ("retryx: backoff attempt 1 is the base", String.equal (step 1) "ok 1000");
    ("retryx: backoff attempt 2 doubles", String.equal (step 2) "ok 2000");
    ("retryx: backoff attempt 3 doubles", String.equal (step 3) "ok 4000");
    ("retryx: backoff attempt 4 doubles", String.equal (step 4) "ok 8000");
    ("retryx: backoff attempt 5 doubles", String.equal (step 5) "ok 16000");
    ( "retryx: backoff attempt 6 hits the per-wait cap",
      String.equal (step 6) "ok 30000" );
    ( "retryx: backoff attempt 7 stays at the cap",
      String.equal (step 7) "ok 30000" );
    ( "retryx: attempts exhaust at exactly max_attempts",
      String.equal (step 8) "attempts_exhausted" );
    ( "retryx: the default policy exhausts at attempt 3",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:3 ~waited:(zero ())
              ~now:(now ()) gateway))
        "attempts_exhausted" );
    ( "retryx: the default policy retries attempt 2",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:2 ~waited:(zero ())
              ~now:(now ()) gateway))
        "ok 2000" );
    ( "retryx: an unreachable transport takes the backoff",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:1 ~waited:(zero ())
              ~now:(now ())
              (R.Obstacle.Unreachable "dns")))
        "ok 1000" );
    ( "retryx: a 429 with no hint takes the backoff",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:1 ~waited:(zero ())
              ~now:(now ())
              (R.Obstacle.Rate_limited None)))
        "ok 1000" );
    ( "retryx: a hint under the cap wins over the backoff",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:1 ~waited:(zero ())
              ~now:(now ())
              (R.Obstacle.Rate_limited (Some (minted 5_000)))))
        "ok 5000" );
    ( "retryx: a 45 s hint under the 30 s cap STOPS, it is not clamped",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:1 ~waited:(zero ())
              ~now:(now ())
              (R.Obstacle.Rate_limited (Some (minted 45_000)))))
        "hint_over_cap 45000" ) ]

let budget : R.Policy.t =
  policy_or_default
    (R.Policy.make ~max_attempts:4 ~base_ms:1_000 ~max_delay_ms:1_000
       ~max_total_ms:1_500 ())

let budget_checks : (string * bool) list =
  [ ( "retryx: the budget stops the wait that would cross max_total_ms",
      String.equal
        (verdict
           (R.decide budget ~attempt:2 ~waited:(minted 1_000) ~now:(now ())
              gateway))
        "budget_exhausted 1000" );
    ( "retryx: a wait that lands exactly on max_total_ms is allowed",
      String.equal
        (verdict
           (R.decide budget ~attempt:2 ~waited:(minted 500) ~now:(now ())
              gateway))
        "ok 1000" );
    ( "retryx: Policy.none stops at the first obstacle",
      String.equal
        (verdict
           (R.decide R.Policy.none ~attempt:1 ~waited:(zero ()) ~now:(now ())
              gateway))
        "attempts_exhausted" ) ]

let dec_checks : (string * bool) list =
  [ ("retryx: dec 0.5 s is 500 ms", String.equal (tokens_hint "0.5") "500");
    ( "retryx: dec 1.2345 s ceilings to 1235 ms",
      String.equal (tokens_hint "1.2345") "1235" );
    ("retryx: dec 2 s is 2000 ms", String.equal (tokens_hint "2") "2000");
    ( "retryx: dec 0.0004 s CEILINGS to 1 ms, it does not floor to 0",
      String.equal (tokens_hint "0.0004") "1" );
    ( "retryx: an 18-scale dec still ceilings to 1 ms",
      String.equal (tokens_hint "0.000000000000000001") "1" );
    ( "retryx: dec 1.5 s is 1500 ms",
      String.equal (tokens_hint "1.5") "1500" );
    ( "retryx: a dec above the hour saturates instead of scaling",
      String.equal (tokens_hint "7200") "3600000" );
    ( "retryx: a dec of exactly 3600 s converts, it does not saturate",
      String.equal (tokens_hint "3600") "3600000" );
    ( "retryx: a zero dec is no hint",
      String.equal (tokens_hint "0") "none" );
    ( "retryx: a tokens triple with a negative reset fails the parse, so no \
       triple hint",
      String.equal
        (dopt
           (hints_for
              ~pairs:(tokens_triple ~remaining:0 ~reset:"-1")
              ()).R.reset_after)
        "none" ) ]

let hint_checks : (string * bool) list =
  [ ( "retryx: the requests reset 2 s ahead is a 2000 ms hint",
      String.equal
        (dopt
           (hints_for
              ~pairs:(requests_triple ~remaining:0 ~reset:(now () + 2))
              ()).R.reset_at)
        "2000" );
    ( "retryx: a requests triple with remaining above 0 is no hint",
      String.equal
        (dopt
           (hints_for
              ~pairs:(requests_triple ~remaining:5 ~reset:(now () + 2))
              ()).R.reset_at)
        "none" );
    ( "retryx: a reset already past is no hint",
      String.equal
        (dopt
           (hints_for
              ~pairs:(requests_triple ~remaining:0 ~reset:(now () - 5))
              ()).R.reset_at)
        "none" );
    ( "retryx: a reset at exactly now is no hint",
      String.equal
        (dopt
           (hints_for
              ~pairs:(requests_triple ~remaining:0 ~reset:(now ()))
              ()).R.reset_at)
        "none" );
    ( "retryx: a reset 10^18-1 seconds ahead SATURATES, it does not wrap",
      String.equal
        (dopt
           (hints_for
              ~pairs:(requests_triple ~remaining:0 ~reset:999_999_999_999_999_999)
              ()).R.reset_at)
        "3600000" );
    ( "retryx: a reset whose seconds-to-ms multiply would overflow still \
       saturates to the window top",
      String.equal
        (dopt
           (hints_for
              ~pairs:
                (requests_triple ~remaining:0
                   ~reset:(now () + 9_223_372_036_854_775))
              ()).R.reset_at)
        "3600000" );
    ( "retryx: the saturated reset hint is Hint_over_cap, not a backoff",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:1 ~waited:(zero ())
              ~now:(now ())
              (R.Obstacle.Rate_limited
                 (R.best_hint
                    (hints_for
                       ~pairs:
                         (requests_triple ~remaining:0
                            ~reset:999_999_999_999_999_999)
                       ())))))
        "hint_over_cap 3600000" );
    ( "retryx: the tokens triple alone gives only the reset_after hint",
      String.equal
        (dopt
           (hints_for
              ~pairs:(tokens_triple ~remaining:0 ~reset:"1.5")
              ()).R.reset_at)
        "none" );
    ( "retryx: no triple and no retry-after is no hint at all",
      String.equal (dopt (R.best_hint (hints_for ()))) "none" );
    ( "retryx: both triples exhausted, the LARGER hint wins",
      String.equal
        (dopt
           (R.best_hint
              (hints_for
                 ~pairs:
                   (List.append
                      (requests_triple ~remaining:0 ~reset:(now () + 2))
                      (tokens_triple ~remaining:0 ~reset:"5"))
                 ())))
        "5000" );
    ( "retryx: the larger hint wins whichever triple carries it",
      String.equal
        (dopt
           (R.best_hint
              (hints_for
                 ~pairs:
                   (List.append
                      (requests_triple ~remaining:0 ~reset:(now () + 9))
                      (tokens_triple ~remaining:0 ~reset:"5"))
                 ())))
        "9000" );
    ( "retryx: a half triple fails the head parse, so no triple hint",
      String.equal
        (dopt
           (R.best_hint
              (hints_for
                 ~pairs:[ ("x-ratelimit-remaining-requests", "0") ]
                 ())))
        "none" );
    ( "retryx: a failed head parse still reads retry-after",
      String.equal
        (dopt
           (R.best_hint
              (hints_for
                 ~pairs:[ ("x-ratelimit-remaining-requests", "0") ]
                 ~retry_after:"4" ())))
        "4000" ) ]

let retry_after_checks : (string * bool) list =
  [ ("retryx: retry-after 7 is 7000 ms", String.equal (after_hint "7") "7000");
    ( "retryx: retry-after 007 reads as 7 s",
      String.equal (after_hint "007") "7000" );
    ("retryx: retry-after 0 is no hint", String.equal (after_hint "0") "none");
    ("retryx: an empty retry-after is no hint", String.equal (after_hint "") "none");
    ( "retryx: an HTTP-date retry-after is no hint",
      String.equal (after_hint "Wed, 21 Oct 2015 07:28:00 GMT") "none" );
    ( "retryx: an 11-digit retry-after is no hint",
      String.equal (after_hint "12345678901") "none" );
    ( "retryx: a 10-digit retry-after still parses, and saturates",
      String.equal (after_hint "1234567890") "3600000" );
    ( "retryx: retry-after 3600 converts to the window top",
      String.equal (after_hint "3600") "3600000" );
    ( "retryx: retry-after 7200 SATURATES, it does not become a backoff",
      String.equal (after_hint "7200") "3600000" );
    ( "retryx: the saturated retry-after is Hint_over_cap",
      String.equal
        (verdict
           (R.decide R.Policy.default ~attempt:1 ~waited:(zero ())
              ~now:(now ())
              (R.Obstacle.Rate_limited
                 (R.best_hint (hints_for ~retry_after:"7200" ())))))
        "hint_over_cap 3600000" );
    ( "retryx: a spaced retry-after is no hint",
      String.equal (after_hint " 7") "none" );
    ( "retryx: the largest of three hints wins",
      String.equal
        (dopt
           (R.best_hint
              (hints_for
                 ~pairs:
                   (List.append
                      (requests_triple ~remaining:0 ~reset:(now () + 2))
                      (tokens_triple ~remaining:0 ~reset:"3"))
                 ~retry_after:"7" ())))
        "7000" ) ]

let window_checks : (string * bool) list =
  [ ( "retryx: max_attempts 0 names the field",
      String.equal
        (policy_text (R.Policy.make ~max_attempts:0 ()))
        "client: policy: max_attempts is below 1" );
    ( "retryx: max_attempts 9 names the field",
      String.equal
        (policy_text (R.Policy.make ~max_attempts:9 ()))
        "client: policy: max_attempts is above 8" );
    ( "retryx: base_ms 0 names the field",
      String.equal
        (policy_text (R.Policy.make ~base_ms:0 ()))
        "client: policy: base_ms is below 1" );
    ( "retryx: base_ms 60001 names the field",
      String.equal
        (policy_text (R.Policy.make ~base_ms:60_001 ()))
        "client: policy: base_ms is above 60000" );
    ( "retryx: max_delay_ms below base_ms names the field",
      String.equal
        (policy_text (R.Policy.make ~base_ms:2_000 ~max_delay_ms:1_000 ()))
        "client: policy: max_delay_ms is below base_ms 2000" );
    ( "retryx: max_delay_ms above the ceiling names the field",
      String.equal
        (policy_text
           (R.Policy.make ~max_delay_ms:600_001 ~max_total_ms:3_600_000 ()))
        "client: policy: max_delay_ms is above 600000" );
    ( "retryx: max_total_ms below max_delay_ms names the field",
      String.equal
        (policy_text (R.Policy.make ~max_total_ms:1_000 ()))
        "client: policy: max_total_ms is below max_delay_ms 30000" );
    ( "retryx: max_total_ms above the ceiling names the field",
      String.equal
        (policy_text (R.Policy.make ~max_total_ms:3_600_001 ()))
        "client: policy: max_total_ms is above 3600000" );
    ( "retryx: the widest legal policy is accepted",
      String.equal
        (policy_text
           (R.Policy.make ~max_attempts:8 ~base_ms:60_000
              ~max_delay_ms:600_000 ~max_total_ms:3_600_000 ()))
        "ok" );
    ( "retryx: the default policy attempts",
      Int.equal (R.Policy.max_attempts R.Policy.default) 3 );
    ( "retryx: the default policy base",
      Int.equal (R.Policy.base_ms R.Policy.default) 1_000 );
    ( "retryx: the default policy per-wait cap",
      Int.equal (R.Policy.max_delay_ms R.Policy.default) 30_000 );
    ( "retryx: the default policy total cap",
      Int.equal (R.Policy.max_total_ms R.Policy.default) 120_000 );
    ( "retryx: Policy.none is one attempt",
      Int.equal (R.Policy.max_attempts R.Policy.none) 1 );
    ( "retryx: Policy.none keeps the other defaults",
      Int.equal (R.Policy.base_ms R.Policy.none) 1_000 ) ]

let delay_checks : (string * bool) list =
  [ ( "retryx: Delay.of_ms rejects below the window",
      String.equal
        (delay_text (R.Delay.of_ms (-1)))
        "client: delay: -1 ms is below 0" );
    ("retryx: Delay.of_ms accepts 0", String.equal (delay_text (R.Delay.of_ms 0)) "0");
    ( "retryx: Delay.of_ms accepts the window top",
      String.equal (delay_text (R.Delay.of_ms 3_600_000)) "3600000" );
    ( "retryx: Delay.of_ms rejects above the window",
      String.equal
        (delay_text (R.Delay.of_ms 3_600_001))
        "client: delay: 3600001 ms is above 3600000" );
    ( "retryx: Delay.saturate floors at 0",
      Int.equal (R.Delay.ms (R.Delay.saturate (-5))) 0 );
    ( "retryx: Delay.saturate keeps a value inside the window",
      Int.equal (R.Delay.ms (R.Delay.saturate 10)) 10 );
    ( "retryx: Delay.saturate caps at the window top",
      Int.equal (R.Delay.ms (R.Delay.saturate 99_999_999)) 3_600_000 );
    ("retryx: Delay.zero is 0", Int.equal (R.Delay.ms (R.Delay.zero ())) 0);
    ( "retryx: Delay.max_ms is one hour",
      Int.equal (R.Delay.max_ms ()) 3_600_000 ) ]

let attempt_checks : (string * bool) list =
  let a =
    R.Attempt.make
      ~obstacle:(R.Obstacle.Rate_limited (Some (minted 2_000)))
      ~slept:(minted 2_000)
  in
  [ ( "retryx: an attempt keeps its sleep",
      Int.equal (R.Delay.ms (R.Attempt.slept a)) 2_000 );
    ( "retryx: an attempt keeps its obstacle",
      match R.Attempt.obstacle a with
      | R.Obstacle.Rate_limited hint -> String.equal (dopt hint) "2000"
      | R.Obstacle.Gateway (_ : int) -> false
      | R.Obstacle.Unreachable (_ : string) -> false ) ]

let () =
  run
    (List.concat
       [ backoff_checks;
         budget_checks;
         dec_checks;
         hint_checks;
         retry_after_checks;
         window_checks;
         delay_checks;
         attempt_checks ])
