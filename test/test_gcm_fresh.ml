(* M30 host GCM nonce boundary. Scripted draws pin the exact 96-bit
   prefix, and concurrent aliases must share one successful consume. *)

module En = Venice__Entropyx
module N = Venice__Gcmx.Nonce
module A = Venice__Policyx.Nonce
module E = Venice__Errx

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (name, (_ : bool)) -> print_endline ("FAIL " ^ name)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

let check_ok (result : ('a, E.t) result) (check : 'a -> bool) : bool =
  Result.fold ~ok:check ~error:(fun _ -> false) result

let error_is (reason : string) (result : ('a, E.t) result) : bool =
  Result.fold ~ok:(fun _ -> false)
    ~error:(fun error -> error = E.Session_invalid reason) result

let prefix (() : unit) : string = "0123456789ab"
let draw (() : unit) : string = prefix () ^ "cdefghijklmnopqrstuv"

let nonce_is (expected : string) (fresh : En.Gcm_fresh.t) : bool =
  String.equal expected (N.to_bytes (En.Gcm_fresh.nonce fresh))

let construction_checks : (string * bool) list =
  [ ( "GCM fresh: one 32-byte draw yields its exact 12-byte prefix",
      let source = En.Fake.make [draw (); String.make 32 '\255'] in
      check_ok (En.Gcm_fresh.make ~entropy:source) (fun fresh ->
          nonce_is (prefix ()) fresh
          && En.Fake.remaining source = 1
          && check_ok (En.Gcm_fresh.make ~entropy:source) (fun second ->
              nonce_is (String.make 12 '\255') second
              && En.Fake.remaining source = 0)) );
    ( "GCM fresh: an exhausted source refuses construction",
      let source = En.Fake.make [] in
      error_is "entropy exhausted" (En.Gcm_fresh.make ~entropy:source)
      && En.Fake.remaining source = 0 );
    ( "GCM fresh: invalid draw lengths are consumed and never padded or split",
      List.for_all
        (fun length ->
          let source = En.Fake.make [String.make length '\000'; draw ()] in
          error_is "entropy length" (En.Gcm_fresh.make ~entropy:source)
          && En.Fake.remaining source = 1
          && check_ok (En.Gcm_fresh.make ~entropy:source) (fun fresh ->
              nonce_is (prefix ()) fresh && En.Fake.remaining source = 0))
        [0; 1; 11; 12; 13; 31; 33; 64] );
    ( "GCM fresh: zero draws are accepted without scalar rejection sampling",
      let source = En.Fake.make [String.make 32 '\000'; draw ()] in
      check_ok (En.Gcm_fresh.make ~entropy:source) (fun fresh ->
          nonce_is (String.make 12 '\000') fresh
          && En.Fake.remaining source = 1) );
    ( "GCM fresh: the final 20 draw bytes do not affect the nonce",
      let source =
        En.Fake.make
          [prefix () ^ String.make 20 '\000'; prefix () ^ String.make 20 '\255']
      in
      check_ok (En.Gcm_fresh.make ~entropy:source) (fun first ->
          check_ok (En.Gcm_fresh.make ~entropy:source) (fun second ->
              nonce_is (prefix ()) first && nonce_is (prefix ()) second
              && En.Fake.remaining source = 0)) ) ]

let consumption_checks : (string * bool) list =
  [ ( "GCM fresh: aliases share one use and retain only the nonce projection",
      let source = En.Fake.make [draw (); draw ()] in
      check_ok (En.Gcm_fresh.make ~entropy:source) (fun fresh ->
          let alias = fresh in
          Result.is_ok (En.Gcm_fresh.consume fresh)
          && error_is "gcm nonce consumed" (En.Gcm_fresh.consume alias)
          && error_is "gcm nonce consumed" (En.Gcm_fresh.consume fresh)
          && nonce_is (prefix ()) alias && En.Fake.remaining source = 1) );
    ( "GCM fresh: separate handles with identical nonce bytes burn independently",
      let source = En.Fake.make [draw (); draw ()] in
      check_ok (En.Gcm_fresh.make ~entropy:source) (fun first ->
          check_ok (En.Gcm_fresh.make ~entropy:source) (fun second ->
              nonce_is (prefix ()) first && nonce_is (prefix ()) second
              && Result.is_ok (En.Gcm_fresh.consume first)
              && error_is "gcm nonce consumed" (En.Gcm_fresh.consume first)
              && Result.is_ok (En.Gcm_fresh.consume second)
              && error_is "gcm nonce consumed" (En.Gcm_fresh.consume second)
              && En.Fake.remaining source = 0)) );
    ( "GCM fresh: consuming a GCM handle leaves attestation freshness available",
      let source = En.Fake.make [draw (); draw ()] in
      check_ok (En.Fresh.make ~entropy:source) (fun attest ->
          check_ok (En.Gcm_fresh.make ~entropy:source) (fun gcm ->
              String.equal (A.to_bytes (En.Fresh.nonce attest)) (draw ())
              && Result.is_ok (En.Gcm_fresh.consume gcm)
              && Result.is_ok (En.Fresh.consume attest ~nonce:(En.Fresh.nonce attest))
              && error_is "gcm nonce consumed" (En.Gcm_fresh.consume gcm)
              && En.Fake.remaining source = 0)) );
    ( "GCM fresh: consuming attestation freshness leaves the GCM handle available",
      let source = En.Fake.make [draw (); draw ()] in
      check_ok (En.Gcm_fresh.make ~entropy:source) (fun gcm ->
          check_ok (En.Fresh.make ~entropy:source) (fun attest ->
              Result.is_ok (En.Fresh.consume attest ~nonce:(En.Fresh.nonce attest))
              && Result.is_ok (En.Gcm_fresh.consume gcm)
              && error_is "fresh consumed"
                   (En.Fresh.consume attest ~nonce:(En.Fresh.nonce attest))
              && En.Fake.remaining source = 0)) );
    ( "GCM fresh: the consumed reason renders with the session prefix",
      check_ok (En.Gcm_fresh.make ~entropy:(En.Fake.make [draw ()])) (fun fresh ->
          Result.is_ok (En.Gcm_fresh.consume fresh)
          && Result.fold ~ok:(fun () -> false)
               ~error:(fun error ->
                 String.equal (E.to_string error) "session: gcm nonce consumed")
               (En.Gcm_fresh.consume fresh)) ) ]

let rec await_start (started : bool Atomic.t) : unit =
  if Atomic.get started then ()
  else (Domain.cpu_relax (); await_start started)

let concurrent_consume (() : unit) : bool =
  check_ok (En.Gcm_fresh.make ~entropy:(En.Fake.make [draw ()])) (fun fresh ->
      let started = Atomic.make false in
      let domains =
        List.init 8 (fun _ ->
            Domain.spawn (fun () ->
                await_start started;
                En.Gcm_fresh.consume fresh))
      in
      Atomic.set started true;
      let results = List.map Domain.join domains in
      List.length (List.filter Result.is_ok results) = 1
      && List.length (List.filter (error_is "gcm nonce consumed") results) = 7
      && error_is "gcm nonce consumed" (En.Gcm_fresh.consume fresh))

let host_checks : (string * bool) list =
  [ ( "GCM fresh: shared domain contention produces exactly one winner",
      List.for_all (fun _ -> concurrent_consume ()) (List.init 8 Fun.id) );
    ( "GCM fresh: system entropy supplies a consumable 12-byte nonce",
      check_ok (En.Gcm_fresh.make ~entropy:(En.system ())) (fun fresh ->
          String.length (N.to_bytes (En.Gcm_fresh.nonce fresh)) = 12
          && Result.is_ok (En.Gcm_fresh.consume fresh)
          && error_is "gcm nonce consumed" (En.Gcm_fresh.consume fresh)) ) ]

let () = run (construction_checks @ consumption_checks @ host_checks)
