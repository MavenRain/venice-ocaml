(* M15 retryx: the bounded retry decision. CORE unit: pure, no ref, no
   clock, no float, no exception, no IO. *)

module Delay = struct
  type t = int

  let max_ms (() : unit) : int = 3_600_000
  let ms (t : t) : int = t
  let zero (() : unit) : t = 0

  let of_ms (n : int) : (t, Errx.t) result =
    match () with
    | () when n < 0 ->
      Error
        (Errx.Client_invalid
           ("delay: " ^ string_of_int n ^ " ms is below 0"))
    | () when n > max_ms () ->
      Error
        (Errx.Client_invalid
           ("delay: " ^ string_of_int n ^ " ms is above "
          ^ string_of_int (max_ms ())))
    | () -> Ok n

  let saturate (n : int) : t =
    match () with
    | () when n < 0 -> 0
    | () when n > max_ms () -> max_ms ()
    | () -> n

  let larger (a : t) (b : t) : t = Int.max a b
end

module Policy = struct
  type t =
    { max_attempts : int;
      base_ms : int;
      max_delay_ms : int;
      max_total_ms : int }

  (* D12 window, one unit thunk per bound. *)
  let attempts_floor (() : unit) : int = 1
  let attempts_ceiling (() : unit) : int = 8
  let base_floor (() : unit) : int = 1
  let base_ceiling (() : unit) : int = 60_000
  let delay_ceiling (() : unit) : int = 600_000
  let total_ceiling (() : unit) : int = 3_600_000
  let default_attempts (() : unit) : int = 3
  let default_base (() : unit) : int = 1_000
  let default_delay (() : unit) : int = 30_000
  let default_total (() : unit) : int = 120_000

  let default : t =
    { max_attempts = default_attempts ();
      base_ms = default_base ();
      max_delay_ms = default_delay ();
      max_total_ms = default_total () }

  let none : t =
    { max_attempts = attempts_floor ();
      base_ms = default_base ();
      max_delay_ms = default_delay ();
      max_total_ms = default_total () }

  let reject (field : string) (why : string) : (t, Errx.t) result =
    Error (Errx.Client_invalid ("policy: " ^ field ^ " " ^ why))

  let make ?(max_attempts : int = default_attempts ())
      ?(base_ms : int = default_base ())
      ?(max_delay_ms : int = default_delay ())
      ?(max_total_ms : int = default_total ()) (() : unit) :
      (t, Errx.t) result =
    match () with
    | () when max_attempts < attempts_floor () ->
      reject "max_attempts" ("is below " ^ string_of_int (attempts_floor ()))
    | () when max_attempts > attempts_ceiling () ->
      reject "max_attempts"
        ("is above " ^ string_of_int (attempts_ceiling ()))
    | () when base_ms < base_floor () ->
      reject "base_ms" ("is below " ^ string_of_int (base_floor ()))
    | () when base_ms > base_ceiling () ->
      reject "base_ms" ("is above " ^ string_of_int (base_ceiling ()))
    | () when max_delay_ms < base_ms ->
      reject "max_delay_ms" ("is below base_ms " ^ string_of_int base_ms)
    | () when max_delay_ms > delay_ceiling () ->
      reject "max_delay_ms" ("is above " ^ string_of_int (delay_ceiling ()))
    | () when max_total_ms < max_delay_ms ->
      reject "max_total_ms"
        ("is below max_delay_ms " ^ string_of_int max_delay_ms)
    | () when max_total_ms > total_ceiling () ->
      reject "max_total_ms" ("is above " ^ string_of_int (total_ceiling ()))
    | () -> Ok { max_attempts; base_ms; max_delay_ms; max_total_ms }

  let max_attempts (t : t) : int = t.max_attempts
  let base_ms (t : t) : int = t.base_ms
  let max_delay_ms (t : t) : int = t.max_delay_ms
  let max_total_ms (t : t) : int = t.max_total_ms
end

module Obstacle = struct
  type t =
    | Rate_limited of Delay.t option
    | Gateway of int
    | Unreachable of string
end

module Stop = struct
  type t =
    | Not_retryable
    | Attempts_exhausted
    | Hint_over_cap of Delay.t
    | Budget_exhausted of Delay.t
end

module Attempt = struct
  type t = { obstacle : Obstacle.t; slept : Delay.t }

  let make ~(obstacle : Obstacle.t) ~(slept : Delay.t) : t =
    { obstacle; slept }

  let obstacle (t : t) : Obstacle.t = t.obstacle
  let slept (t : t) : Delay.t = t.slept
end

type hints =
  { reset_at : Delay.t option;
    reset_after : Delay.t option;
    retry_after : Delay.t option }

(* A1: every hint is compared against the window in SECONDS before it
   is scaled to milliseconds, so the product cannot pass Int.max_int
   and an over-window hint saturates instead of wrapping. *)
let hint_seconds_cap (() : unit) : int = 3_600
let retry_after_max_digits (() : unit) : int = 10
let ms_scale_digits (() : unit) : int = 3

let seconds_hint (secs : int) : Delay.t option =
  match () with
  | () when secs <= 0 -> None
  | () when secs > hint_seconds_cap () -> Some (Delay.saturate (Delay.max_ms ()))
  | () -> Some (Delay.saturate (secs * 1_000))

let digit_of (c : char) : int option =
  match () with
  | () when Char.compare c '0' >= 0 && Char.compare c '9' <= 0 ->
    Some (Char.code c - Char.code '0')
  | () -> None

let digits_of_string (s : string) : int list option =
  List.fold_left
    (fun (acc : int list option) (c : char) ->
      Option.bind acc (fun (ds : int list) ->
          Option.map (fun (d : int) -> d :: ds) (digit_of c)))
    (Some []) (List.of_seq (String.to_seq s))

let fold_digits (ds : int list) : int =
  List.fold_left (fun (acc : int) (d : int) -> (acc * 10) + d) 0 ds

let rec zeros (n : int) (acc : int list) : int list =
  match () with
  | () when n <= 0 -> acc
  | () -> zeros (n - 1) (0 :: acc)

(* A TOTAL split: [split_at n xs []] gives the first n elements and
   the rest, with no index and no exception. *)
let rec split_at (n : int) (xs : int list) (acc : int list) :
    int list * int list =
  match xs with
  | [] -> (List.rev acc, [])
  | h :: tl -> (
    match () with
    | () when n <= 0 -> (List.rev acc, xs)
    | () -> split_at (n - 1) tl (h :: acc))

let any_nonzero (ds : int list) : bool =
  List.exists (fun (d : int) -> not (Int.equal d 0)) ds

(* D5: seconds-with-a-scale to whole milliseconds, by digit-string
   arithmetic on the canonical mantissa and never by a division. The
   fraction is padded or cut to exactly three digits, and a cut that
   drops a nonzero digit adds one millisecond, so the conversion is a
   CEILING: a 0.0004 s hint is 1 ms of wait, never 0. *)
let dec_to_ms (d : Jsonx.dec) : int =
  let raw = string_of_int (Int.max 0 d.Jsonx.mantissa) in
  let ds =
    Option.fold ~none:[ 0 ]
      ~some:(fun (xs : int list) -> List.rev xs)
      (digits_of_string raw)
  in
  let scale = Int.max 0 d.Jsonx.scale in
  match () with
  | () when scale <= ms_scale_digits () ->
    fold_digits (List.append ds (zeros (ms_scale_digits () - scale) []))
  | () ->
    let cut = scale - ms_scale_digits () in
    let kept, dropped = split_at (List.length ds - cut) ds [] in
    let floor_ms = fold_digits kept in
    (match any_nonzero dropped with
     | true -> floor_ms + 1
     | false -> floor_ms)

let seconds_cap_dec (() : unit) : Jsonx.dec =
  { Jsonx.negative = false; mantissa = hint_seconds_cap (); scale = 0 }

let dec_hint (d : Jsonx.dec) : Delay.t option =
  match () with
  | () when d.Jsonx.negative -> None
  | () when Int.equal d.Jsonx.mantissa 0 -> None
  | () when Jsonx.compare_dec d (seconds_cap_dec ()) > 0 ->
    Some (Delay.saturate (Delay.max_ms ()))
  | () -> Some (Delay.saturate (dec_to_ms d))

let requests_hint (h : Headx.t) ~(now : int) : Delay.t option =
  Option.bind (Headx.requests h) (fun (r : Headx.Requests_limit.t) ->
      match Int.equal (Headx.Requests_limit.remaining r) 0 with
      | true ->
        seconds_hint
          (Headx.Reset_at.seconds (Headx.Requests_limit.reset_at r) - now)
      | false -> None)

let tokens_hint (h : Headx.t) : Delay.t option =
  Option.bind (Headx.tokens h) (fun (t : Headx.Tokens_limit.t) ->
      match Int.equal (Headx.Tokens_limit.remaining t) 0 with
      | true ->
        dec_hint (Headx.Reset_after.seconds (Headx.Tokens_limit.reset_after t))
      | false -> None)

let retry_after_hint (v : string option) : Delay.t option =
  Option.bind v (fun (s : string) ->
      match () with
      | () when String.length s < 1 -> None
      | () when String.length s > retry_after_max_digits () -> None
      | () ->
        Option.bind (digits_of_string s) (fun (ds : int list) ->
            seconds_hint (fold_digits (List.rev ds))))

let hints_of ~(head : (Headx.t, Errx.t) result) ~(now : int)
    ~(retry_after : string option) : hints =
  let after = retry_after_hint retry_after in
  Result.fold
    ~ok:(fun (h : Headx.t) ->
      { reset_at = requests_hint h ~now;
        reset_after = tokens_hint h;
        retry_after = after })
    ~error:(fun (_ : Errx.t) ->
      { reset_at = None; reset_after = None; retry_after = after })
    head

let pick (a : Delay.t option) (b : Delay.t option) : Delay.t option =
  Option.fold ~none:b
    ~some:(fun (x : Delay.t) ->
      Option.fold ~none:(Some x)
        ~some:(fun (y : Delay.t) -> Some (Delay.larger x y))
        b)
    a

let best_hint (h : hints) : Delay.t option =
  pick h.reset_at (pick h.reset_after h.retry_after)

(* The backoff power, by a BOUNDED fold: max_attempts is at most 8, so
   the exponent is at most 7 and base_ms at most 60_000, which keeps
   every product far below Int.max_int. No shift, checked or not. *)
let backoff_steps_cap (() : unit) : int = 7

let rec doubled (v : int) (times : int) : int =
  match () with
  | () when times <= 0 -> v
  | () -> doubled (v + v) (times - 1)

let backoff (p : Policy.t) (attempt : int) : Delay.t =
  let steps = Int.min (Int.max (attempt - 1) 0) (backoff_steps_cap ()) in
  Delay.saturate
    (Int.min (doubled (Policy.base_ms p) steps) (Policy.max_delay_ms p))

let wait_for (p : Policy.t) (attempt : int) (o : Obstacle.t) : Delay.t =
  match o with
  | Obstacle.Rate_limited hint ->
    Option.fold ~none:(backoff p attempt)
      ~some:(fun (d : Delay.t) -> d)
      hint
  | Obstacle.Gateway (_ : int) -> backoff p attempt
  | Obstacle.Unreachable (_ : string) -> backoff p attempt

let decide (p : Policy.t) ~(attempt : int) ~(waited : Delay.t) ~(now : int)
    (o : Obstacle.t) : (Delay.t, Stop.t) result =
  (* now is taken for the D4 signature; A1 moved every clock-bearing
     conversion into hints_of, so the decision itself is a table. *)
  let (_ : int) = now in
  (* The wait is computed BEFORE the attempts check and is discarded on
     the exhausted branch, so the guards below read as one table in the
     D4 order instead of nesting the backoff inside a live branch. The
     computation is pure and bounded, so the discarded value costs a
     fold over at most max_attempts steps. *)
  let wait = wait_for p attempt o in
  match () with
  | () when attempt >= Policy.max_attempts p -> Error Stop.Attempts_exhausted
  | () when Delay.ms wait > Policy.max_delay_ms p ->
    Error (Stop.Hint_over_cap wait)
  | () when Delay.ms waited + Delay.ms wait > Policy.max_total_ms p ->
    Error (Stop.Budget_exhausted wait)
  | () -> Ok wait
