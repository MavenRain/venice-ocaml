(* Test doubles for the M29 admission witness. The pure session core is
   copied verbatim by dune, so this suite runs the real Sessx.admit and
   the real order of its three legs, including the revalidation call
   that the session boundary suite stubs out.

   Only the three opaque records a test cannot mint are scripted: the
   attestation witness, the policy witness and the TCB witness. Their
   real Measurements, Expect, Status and Gpu modules are kept, so
   measurement equality, TCB grading and GPU refusal stay production
   code. No accepting production witness is forged and no constructor is
   added to the library. *)
module Errx = Venice__Errx
module Derx = Venice__Derx
module Secpx = Venice__Secpx
module Hmacx = Venice__Hmacx
module Gcmx = Venice__Gcmx
module Hexx = Venice__Hexx

(* The model row carries routing context only, so a slug stands in. *)
module Modelx = struct
  type e2ee = |
  type 'c t = string
  let id (t : 'c t) : string = t
end

module Policyx = struct
  module Nonce = Venice__Policyx.Nonce
  module Measurements = Venice__Policyx.Measurements
  module Expect = Venice__Policyx.Expect

  (* The real 'level Policyx.t has no public constructor. The phantom
     level is kept, so admit still demands a full expectation. *)
  type 'level t = { set : Measurements.t }
  let measurements (t : 'l t) : Measurements.t = t.set
end

module Tcbx = struct
  module Status = Venice__Tcbx.Status

  (* The real Tcbx.t is minted only by Tcbx.verify. The two graded
     statuses admit reads are scripted here; Status itself is real. *)
  type t = { platform : Status.t; qe : Status.t }
  let make ~(platform : Status.t) ~(qe : Status.t) : t = { platform; qe }
  let platform_status (t : t) : Status.t = t.platform
  let qe_status (t : t) : Status.t = t.qe
end

module Attestx = struct
  module Gpu = Venice__Attestx.Gpu

  module Attested = struct
    type 'level t = {
      revalidation_error : Errx.t option;
      measurement_policy : 'level Policyx.t;
      tcb_grades : Tcbx.t;
      model_slug : string option;
      gpu_evidence : Gpu.t;
      key : Secpx.Pubkey.t;
    }

    (* Call counters, read by the rows that pin the order of admit. *)
    let revalidations : int Atomic.t = Atomic.make 0
    let last_now : string Atomic.t = Atomic.make ""

    let revalidate ~(now : Derx.Now.t) (t : 'l t) : (unit, Errx.t) result =
      Atomic.set last_now (Derx.Now.to_string now);
      Atomic.incr revalidations;
      Result.fold ~ok:(fun (e : Errx.t) -> Error e)
        ~error:(fun (() : unit) -> Ok ())
        (Option.to_result ~none:() t.revalidation_error)

    let policy (t : 'l t) : 'l Policyx.t = t.measurement_policy
    let tcb (t : 'l t) : Tcbx.t = t.tcb_grades
    let model (t : 'l t) : string option = t.model_slug
    let gpu (t : 'l t) : Gpu.t = t.gpu_evidence
    let signing_key (t : 'l t) : Secpx.Pubkey.t = t.key
  end
end
