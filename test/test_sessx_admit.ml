(* M29: the real Sessx.admit against a scripted attestation witness.
   test_sessx calls check_admission and check_cpu_only directly, and
   test_session_boundary replaces admit with a double, so the three legs
   of admit and their order are pinned here. The revalidation call is
   the leg no other suite reaches. *)

module F = Sessx_admit_fakes
module S = Sessx_admit_impl
module E = Venice__Errx
module T = Venice__Tcbx
module P = Venice__Policyx
module D = Venice__Derx
module C = Venice__Secpx
module G = Venice__Attestx.Gpu

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (name, (_ : bool)) -> print_endline ("FAIL " ^ name)) bad;
  Printf.printf "%d/%d ok\n" (List.length checks - List.length bad)
    (List.length checks);
  exit (if List.is_empty bad then 0 else 1)

let error (word : string) (r : ('a, E.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> false)
    ~error:(fun e -> String.equal (E.to_string e) word) r

let measurements (fill : char) : P.Measurements.t option =
  P.Measurements.make ~mr_td:(String.make 48 fill)
    ~rt_mr0:(String.make 48 fill) ~rt_mr1:(String.make 48 fill)
    ~rt_mr2:(String.make 48 fill) ~rt_mr3:(String.make 48 fill)

let signing_key (() : unit) : C.Pubkey.t option =
  Option.bind
    (C.Scalar.of_bytes (String.make 31 '\000' ^ "\001"))
    C.Pubkey.of_scalar

(* One shape for every row: a public key, the caller instant, the
   trusted CPU measurement set and a different observed set. *)
let case (f : C.Pubkey.t -> D.Now.t -> P.Measurements.t -> P.Measurements.t ->
          bool) : bool =
  Option.fold ~none:false
    ~some:(fun key ->
      Option.fold ~none:false
        ~some:(fun now ->
          Option.fold ~none:false
            ~some:(fun trusted ->
              Option.fold ~none:false ~some:(f key now trusted)
                (measurements 'z'))
            (measurements 'a'))
        (D.Now.of_digits "20250620103227"))
    (signing_key ())

let witness ?(revalidation_error : E.t option) ?(model = Some "e2ee-test")
    ?(platform = T.Status.Up_to_date) ?(qe = T.Status.Up_to_date)
    ?(gpu = G.Absent) ~(observed : P.Measurements.t) (key : C.Pubkey.t) :
    P.Expect.full F.Attestx.Attested.t =
  { F.Attestx.Attested.revalidation_error;
    measurement_policy = { F.Policyx.set = observed };
    tcb_grades = F.Tcbx.make ~platform ~qe;
    model_slug = model;
    gpu_evidence = gpu;
    key }

let admit_with ~(trusted : P.Measurements.t) ~(now : D.Now.t)
    (attested : P.Expect.full F.Attestx.Attested.t) =
  S.admit ~cpu_only:(S.Cpu_only.trust ~measurements:trusted) ~now ~attested
    ~model:"e2ee-test"

let reset (() : unit) : unit =
  Atomic.set F.Attestx.Attested.revalidations 0;
  Atomic.set F.Attestx.Attested.last_now ""

let checks : (string * bool) list =
  [ ( "sessx: a clean witness admits and revalidates once at the caller instant",
      case (fun key now trusted (_ : P.Measurements.t) ->
        reset ();
        Result.is_ok (admit_with ~trusted ~now (witness ~observed:trusted key))
        && Atomic.get F.Attestx.Attested.revalidations = 1
        && String.equal
             (Atomic.get F.Attestx.Attested.last_now)
             (D.Now.to_string now)) );
    ( "sessx: a revalidation refusal leaves admit unchanged",
      case (fun key now trusted (_ : P.Measurements.t) ->
        reset ();
        error "cert: expired"
          (admit_with ~trusted ~now
             (witness ~revalidation_error:(E.Cert_invalid "expired")
                ~observed:trusted key))
        && Atomic.get F.Attestx.Attested.revalidations = 1) );
    ( "sessx: revalidation precedes the CPU measurement set",
      case (fun key now trusted other ->
        reset ();
        error "cert: expired"
          (admit_with ~trusted ~now
             (witness ~revalidation_error:(E.Cert_invalid "expired")
                ~observed:other key))) );
    ( "sessx: revalidation precedes every later admission failure",
      case (fun key now trusted other ->
        reset ();
        error "tcb: revoked"
          (admit_with ~trusted ~now
             (witness ~revalidation_error:(E.Tcb_invalid "revoked")
                ~model:None ~platform:T.Status.Revoked ~qe:T.Status.Out_of_date
                ~observed:other key))) );
    ( "sessx: the CPU measurement set precedes model metadata",
      case (fun key now trusted other ->
        reset ();
        error "session: cpu measurements"
          (admit_with ~trusted ~now (witness ~model:None ~observed:other key))
        && Atomic.get F.Attestx.Attested.revalidations = 1) );
    ( "sessx: a single measurement byte refuses the deployment policy",
      case (fun key now trusted (_ : P.Measurements.t) ->
        reset ();
        Option.fold ~none:false
          ~some:(fun observed ->
            error "session: cpu measurements"
              (admit_with ~trusted ~now (witness ~observed key)))
          (P.Measurements.make ~mr_td:(String.make 48 'a')
             ~rt_mr0:(String.make 48 'a') ~rt_mr1:(String.make 48 'a')
             ~rt_mr2:(String.make 48 'a')
             ~rt_mr3:(String.make 47 'a' ^ "b"))) );
    ( "sessx: an admitted witness still refuses a wrong model slug",
      case (fun key now trusted (_ : P.Measurements.t) ->
        reset ();
        error "session: model mismatch"
          (admit_with ~trusted ~now
             (witness ~model:(Some "other") ~observed:trusted key))) );
    ( "sessx: an admitted witness still refuses a lowered platform grade",
      case (fun key now trusted (_ : P.Measurements.t) ->
        reset ();
        error "session: platform tcb"
          (admit_with ~trusted ~now
             (witness ~platform:T.Status.Out_of_date ~observed:trusted key))) ) ]

let () = run checks
