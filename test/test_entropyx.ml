(* M29 host entropy and one-use nonce suite. Scripted inputs pin exact
   consumption and scalar rejection boundaries. The contention row
   shares one token across domains and demands exactly one winner. *)

module En = Venice__Entropyx
module S = Venice__Secpx
module N = Venice__Policyx.Nonce
module E = Venice__Errx

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let check_ok (result : ('a, E.t) result) (check : 'a -> bool) : bool =
  Result.fold ~ok:check ~error:(fun _ -> false) result

let error_is (reason : string) (result : ('a, E.t) result) : bool =
  Result.fold ~ok:(fun _ -> false)
    ~error:(fun e -> e = E.Session_invalid reason) result

let scalar_is (bytes : string) (result : (S.Scalar.t, E.t) result) : bool =
  check_ok result (fun value -> String.equal (S.Scalar.to_bytes value) bytes)

let one (() : unit) : string = String.make 31 '\000' ^ "\001"
let two (() : unit) : string = String.make 31 '\000' ^ "\002"
let zero (() : unit) : string = String.make 32 '\000'

let scalar_checks : (string * bool) list =
  [ ( "entropy: a valid scalar consumes exactly one draw",
      let source = En.Fake.make [one (); two ()] in
      scalar_is (one ()) (En.scalar source)
      && En.Fake.remaining source = 1
      && scalar_is (two ()) (En.scalar source)
      && En.Fake.remaining source = 0 );
    ( "entropy: an empty scalar source rejects without a draw",
      let source = En.Fake.make [] in
      error_is "entropy exhausted" (En.scalar source)
      && En.Fake.remaining source = 0 );
    ( "entropy: malformed chunks are consumed, never padded or split",
      List.for_all
        (fun length ->
          let source = En.Fake.make [String.make length '\001'; one ()] in
          error_is "entropy length" (En.scalar source)
          && En.Fake.remaining source = 1
          && scalar_is (one ()) (En.scalar source))
        [0; 1; 31; 33; 64] );
    ( "entropy: zero, n, n+1 and 2^256-1 reject before the valid draw",
      check_ok
        (Venice__Hexx.decode
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        (fun n ->
          check_ok
            (Venice__Hexx.decode
               "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142")
            (fun above ->
              let source =
                En.Fake.make
                  [zero (); n; above; String.make 32 '\255'; one (); two ()]
              in
              scalar_is (one ()) (En.scalar source)
              && En.Fake.remaining source = 1)) );
    ( "entropy: n-1 is accepted without reducing it",
      check_ok
        (Venice__Hexx.decode
           "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
        (fun bytes ->
          let source = En.Fake.make [bytes; one ()] in
          scalar_is bytes (En.scalar source) && En.Fake.remaining source = 1) );
    ( "entropy: exhaustion after a rejected scalar preserves the source error",
      let source = En.Fake.make [zero ()] in
      error_is "entropy exhausted" (En.scalar source)
      && En.Fake.remaining source = 0 );
    ( "entropy: a malformed draw after a rejected scalar stops sampling",
      let source = En.Fake.make [zero (); "bad"; one ()] in
      error_is "entropy length" (En.scalar source)
      && En.Fake.remaining source = 1 );
    ( "entropy: attempt 128 can succeed and leaves draw 129 untouched",
      let source =
        En.Fake.make (List.init 127 (fun _ -> zero ()) @ [one (); two ()])
      in
      scalar_is (one ()) (En.scalar source) && En.Fake.remaining source = 1 );
    ( "entropy: 128 rejected draws stop before valid draw 129",
      let source =
        En.Fake.make (List.init 128 (fun _ -> zero ()) @ [one ()])
      in
      error_is "scalar rejection limit" (En.scalar source)
      && En.Fake.remaining source = 1
      && scalar_is (one ()) (En.scalar source) );
    ( "entropy: the rejection bound precedes probing an exhausted source",
      let source = En.Fake.make (List.init 128 (fun _ -> zero ())) in
      error_is "scalar rejection limit" (En.scalar source)
      && En.Fake.remaining source = 0 ) ]

let fresh_checks : (string * bool) list =
  [ ( "entropy: Fresh keeps the exact 32-byte nonce and consumes one draw",
      let bytes = String.init 32 Char.chr in
      let source = En.Fake.make [bytes; one ()] in
      check_ok (En.Fresh.make ~entropy:source) (fun fresh ->
          String.equal (N.to_bytes (En.Fresh.nonce fresh)) bytes
          && String.length (N.to_hex (En.Fresh.nonce fresh)) = 64
          && En.Fake.remaining source = 1) );
    ( "entropy: a zero nonce is valid and does not trigger scalar sampling",
      let source = En.Fake.make [zero (); one ()] in
      check_ok (En.Fresh.make ~entropy:source) (fun fresh ->
          String.equal (N.to_bytes (En.Fresh.nonce fresh)) (zero ())
          && En.Fake.remaining source = 1) );
    ( "entropy: Fresh rejects an exhausted source",
      error_is "entropy exhausted" (En.Fresh.make ~entropy:(En.Fake.make [])) );
    ( "entropy: Fresh refuses malformed nonce sizes and consumes that chunk",
      List.for_all
        (fun length ->
          let source = En.Fake.make [String.make length '\000'; one ()] in
          error_is "entropy length" (En.Fresh.make ~entropy:source)
          && En.Fake.remaining source = 1)
        [0; 1; 31; 33; 64] );
    ( "entropy: the matching nonce consumes exactly once through an alias",
      let source = En.Fake.make [one (); two ()] in
      check_ok (En.Fresh.make ~entropy:source) (fun fresh ->
          let alias = fresh in
          let nonce = En.Fresh.nonce fresh in
          Result.is_ok (En.Fresh.consume fresh ~nonce)
          && error_is "fresh consumed" (En.Fresh.consume alias ~nonce)
          && error_is "fresh consumed" (En.Fresh.consume fresh ~nonce)
          && N.equal nonce (En.Fresh.nonce alias)
          && En.Fake.remaining source = 1) );
    ( "entropy: a wrong nonce burns the token before its matching retry",
      check_ok (En.Fresh.make ~entropy:(En.Fake.make [one ()])) (fun fresh ->
          Option.fold ~none:false
            ~some:(fun wrong ->
              let nonce = En.Fresh.nonce fresh in
              error_is "nonce mismatch" (En.Fresh.consume fresh ~nonce:wrong)
              && error_is "fresh consumed" (En.Fresh.consume fresh ~nonce)
              && error_is "fresh consumed" (En.Fresh.consume fresh ~nonce:wrong))
            (N.of_bytes (two ()))) );
    ( "entropy: independent tokens with identical nonce bytes consume independently",
      let source = En.Fake.make [one (); one ()] in
      check_ok (En.Fresh.make ~entropy:source) (fun first ->
          check_ok (En.Fresh.make ~entropy:source) (fun second ->
              N.equal (En.Fresh.nonce first) (En.Fresh.nonce second)
              && Result.is_ok (En.Fresh.consume first ~nonce:(En.Fresh.nonce first))
              && Result.is_ok (En.Fresh.consume second ~nonce:(En.Fresh.nonce second))
              && En.Fake.remaining source = 0)) ) ]

let rec await_start (started : bool Atomic.t) : unit =
  if Atomic.get started then ()
  else (Domain.cpu_relax (); await_start started)

let concurrent_consume (() : unit) : bool =
  check_ok (En.Fresh.make ~entropy:(En.Fake.make [one ()])) (fun fresh ->
      let started = Atomic.make false in
      let nonce = En.Fresh.nonce fresh in
      let domains =
        List.init 8 (fun _ ->
            Domain.spawn (fun () ->
                await_start started;
                En.Fresh.consume fresh ~nonce))
      in
      Atomic.set started true;
      let results = List.map Domain.join domains in
      List.length (List.filter Result.is_ok results) = 1
      && List.length (List.filter (error_is "fresh consumed") results) = 7
      && error_is "fresh consumed" (En.Fresh.consume fresh ~nonce))

let rendered (result : ('a, E.t) result) : string =
  Result.fold ~ok:(fun (_ : 'a) -> "accepted") ~error:E.to_string result

let fresh_word (made : (En.Fresh.t, E.t) result) (f : En.Fresh.t -> string) :
    string =
  Result.fold ~ok:f ~error:E.to_string made

let second_consume (fresh : En.Fresh.t) : string =
  let nonce = En.Fresh.nonce fresh in
  let (_ : (unit, E.t) result) = En.Fresh.consume fresh ~nonce in
  rendered (En.Fresh.consume fresh ~nonce)

let wrong_consume (fresh : En.Fresh.t) : string =
  Option.fold ~none:"no nonce"
    ~some:(fun nonce -> rendered (En.Fresh.consume fresh ~nonce))
    (N.of_bytes (String.make 32 'x'))

(* Each word below is rendered from a real refusal, never from a
   hand-written constructor, so a changed reason breaks the row. *)
let closed_reasons (() : unit) : (string * string) list =
  [ ("entropy exhausted", rendered (En.scalar (En.Fake.make [])));
    ("entropy length", rendered (En.scalar (En.Fake.make ["bad"])));
    ( "scalar rejection limit",
      rendered
        (En.scalar (En.Fake.make (List.init 128 (fun (_ : int) -> zero ())))) );
    ( "fresh consumed",
      fresh_word (En.Fresh.make ~entropy:(En.Fake.make [one ()])) second_consume );
    ( "nonce mismatch",
      fresh_word (En.Fresh.make ~entropy:(En.Fake.make [two ()])) wrong_consume ) ]

let host_checks : (string * bool) list =
  [ ( "entropy: domain contention has one winner for one shared token",
      List.for_all (fun _ -> concurrent_consume ()) (List.init 8 Fun.id) );
    ( "entropy: the production source supplies a valid scalar and a 32-byte nonce",
      let source = En.system () in
      check_ok (En.scalar source) (fun scalar ->
          check_ok (En.Fresh.make ~entropy:source) (fun fresh ->
              String.length (S.Scalar.to_bytes scalar) = 32
              && String.length (N.to_bytes (En.Fresh.nonce fresh)) = 32
              && Result.is_ok (En.Fresh.consume fresh ~nonce:(En.Fresh.nonce fresh)))) );
    ( "entropy: system sources carry no fake script",
      En.Fake.remaining (En.Fake.make [zero (); one ()]) = 2
      && En.Fake.remaining (En.system ()) = 0 );
    ( "entropy: every closed reason renders with the session prefix",
      List.for_all
        (fun (word, text) -> String.equal text ("session: " ^ word))
        (closed_reasons ()) ) ]

let () = run (scalar_checks @ fresh_checks @ host_checks)
