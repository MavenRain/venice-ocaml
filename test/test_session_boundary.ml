module F = Session_boundary_fakes
module S = Session_boundary_impl
module E = Venice__Entropyx
module P = Venice__Policyx
module D = Venice__Derx
module R = Venice__Errx

let is_error (word : string) (r : ('a, R.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> false)
    ~error:(fun e -> String.equal word (R.to_string e)) r

let case (f : E.t -> E.Fresh.t -> P.Nonce.t -> D.Now.t -> bool) : bool =
  Atomic.set F.Sessx.admissions 0;
  Atomic.set F.Sessx.derivations 0;
  let entropy = E.Fake.make [String.make 32 'n'; String.make 31 '\000' ^ "\001"] in
  Result.fold ~error:(fun (_ : R.t) -> false) ~ok:(fun fresh ->
    Option.fold ~none:false ~some:(fun now -> f entropy fresh (E.Fresh.nonce fresh) now)
      (D.Now.of_digits "20250620103227")) (E.Fresh.make ~entropy)

let witness ?(admission_error : R.t option) ?(derivation_error : R.t option)
    (nonce : P.Nonce.t) : P.Expect.full F.Attestx.Attested.t =
  { F.Attestx.Attested.nonce_value = nonce; admission_error; derivation_error }

let establish entropy fresh now attested =
  S.establish ~entropy ~fresh ~cpu_only:() ~now ~attested ~model:"model"

let checks = [
  "success and alias replay", case (fun entropy fresh nonce now ->
    let attested = witness nonce in
    let first = establish entropy fresh now attested in
    Result.is_ok first && E.Fake.remaining entropy = 0 &&
    is_error "session: fresh consumed" (establish entropy fresh now attested) &&
    Atomic.get F.Sessx.admissions = 1 && Atomic.get F.Sessx.derivations = 1);
  "admission receives the caller's instant", case (fun entropy fresh nonce now ->
    Atomic.set F.Sessx.last_now "";
    Result.is_ok (establish entropy fresh now (witness nonce)) &&
    String.equal (D.Now.to_string now) "20250620103227" &&
    String.equal (Atomic.get F.Sessx.last_now) (D.Now.to_string now));
  "nonce mismatch burns before admission and entropy", case (fun entropy fresh nonce now ->
    Option.fold ~none:false ~some:(fun other ->
      is_error "session: nonce mismatch" (establish entropy fresh now (witness other)) &&
      E.Fake.remaining entropy = 1 && Atomic.get F.Sessx.admissions = 0 &&
      is_error "session: fresh consumed" (establish entropy fresh now (witness nonce)))
      (P.Nonce.of_bytes (String.make 32 'x')));
  "expired admission preserves error and burns before entropy", case (fun entropy fresh nonce now ->
    let attested = witness ~admission_error:(R.Cert_invalid "leaf expired") nonce in
    is_error "cert: leaf expired" (establish entropy fresh now attested) &&
    E.Fake.remaining entropy = 1 && Atomic.get F.Sessx.derivations = 0 &&
    is_error "session: fresh consumed" (establish entropy fresh now (witness nonce)));
  "CPU policy rejection preserves error and burns", case (fun entropy fresh nonce now ->
    let attested = witness ~admission_error:(R.Session_invalid "cpu measurements") nonce in
    is_error "session: cpu measurements" (establish entropy fresh now attested) &&
    E.Fake.remaining entropy = 1 &&
    is_error "session: fresh consumed" (establish entropy fresh now (witness nonce)));
  "entropy failure follows admission and burns", case (fun (_ : E.t) fresh nonce now ->
    let empty = E.Fake.make [] in
    let attested = witness nonce in
    is_error "session: entropy exhausted" (establish empty fresh now attested) &&
    Atomic.get F.Sessx.admissions = 1 && Atomic.get F.Sessx.derivations = 0 &&
    is_error "session: fresh consumed" (establish empty fresh now attested));
  "key derivation failure consumes scalar and burns", case (fun entropy fresh nonce now ->
    let attested = witness ~derivation_error:(R.Session_invalid "shared secret") nonce in
    is_error "session: shared secret" (establish entropy fresh now attested) &&
    E.Fake.remaining entropy = 0 && Atomic.get F.Sessx.derivations = 1 &&
    is_error "session: fresh consumed" (establish entropy fresh now attested));
  "candidate rejection reaches first valid scalar", case (fun (_ : E.t) fresh nonce now ->
    let scalar_entropy = E.Fake.make [String.make 32 '\000'; String.make 31 '\000' ^ "\002"] in
    Result.fold ~error:(fun (_ : R.t) -> false) ~ok:(fun session ->
      String.equal (S.client_pubkey_hex session) (String.make 63 '0' ^ "2") &&
      E.Fake.remaining scalar_entropy = 0 && Atomic.get F.Sessx.derivations = 1)
      (establish scalar_entropy fresh now (witness nonce)));
  "concurrent aliases admit exactly once", case (fun entropy fresh nonce now ->
    let ready = Atomic.make 0 in
    let start = Atomic.make false in
    let invoke () =
      Atomic.incr ready;
      while not (Atomic.get start) do Domain.cpu_relax () done;
      establish entropy fresh now (witness nonce) in
    let a = Domain.spawn invoke in
    let b = Domain.spawn invoke in
    while Atomic.get ready < 2 do Domain.cpu_relax () done;
    Atomic.set start true;
    let ra = Domain.join a in
    let rb = Domain.join b in
    ((Result.is_ok ra && is_error "session: fresh consumed" rb) ||
     (Result.is_ok rb && is_error "session: fresh consumed" ra)) &&
    Atomic.get F.Sessx.admissions = 1 && Atomic.get F.Sessx.derivations = 1)
]

let () =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (name, (_ : bool)) -> print_endline ("FAIL " ^ name)) bad;
  Printf.printf "%d/%d ok\n" (List.length checks - List.length bad) (List.length checks);
  exit (if List.is_empty bad then 0 else 1)
