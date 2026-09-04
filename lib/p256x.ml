(* M19 p256x: ECDSA over the NIST P-256 curve with SHA-256 digests,
   VERIFICATION only. The lineage is jose-caml lib/p256x.ml, which took
   the formulas from tinysvid sig/p256.ml. This is a rewrite, not a
   copy: jose works on raw limb lists, while limbsx.mli here exports an
   ABSTRACT canonical t whose helpers are private, so every formula is
   restated over that surface.

   Jacobian coordinates with a = -3, and the point at infinity encoded
   as z = 0, the jose convention. A projective triple costs no field
   inverse per addition, so one inverse runs at the end of each scalar
   walk and one more inside the scalar inverse.

   Pure and sans-io, like limbsx.ml, hmacx.ml and keccakx.ml: no
   reference cell, no exception, no exception handler, no floating
   point value, no mutable byte buffer and no indexed container. The
   unit holds NO division line and NO remainder operator: every
   reduction runs through Limbsx.mod_red inside reduce_by, and every
   inverse runs through Limbsx.mod_pow inside inv_by, so the modulus is
   always an explicit argument.

   ZxCaml trap 2 makes a top-level constant invisible inside a helper.
   The answer here is the curve RECORD: curve () builds the thirteen
   field values once, and every helper below takes (c : curve) as its
   first parameter, so no helper reads a top-level value. The rule bites
   across module boundaries too: Limbsx.zero and Limbsx.one are top-level
   bindings of a module that sits in the same core list, so this unit
   carries them as record fields as well and names no Limbsx constant
   inside a helper. An alias is
   eta-expanded for the same reason, because a bare alias binding is a
   constant and trap 2 fires on every read of it.

   VARIABLE-TIME by design (DESIGN.md section 2 and section 6, and the
   limbsx stance at M16). Verification reads only PUBLIC inputs:
   attestation quotes, certificates and signatures. Limbsx.mod_red and
   Limbsx.mod_pow branch on limb values, the scalar walk branches on
   the scalar bits, and both scalars here are public.

   Psychic signatures (CVE-2022-21449) die at CONSTRUCTION. A
   Signature.t is minted only when r and s both sit in 1 .. n-1, so
   r = 0, s = 0, r >= n and s >= n never reach the point arithmetic.
   The malleable twin (r, n - s) VERIFIES: FIPS 186-4 carries no low-s
   rule, the suite pins the twin, and a consumer that needs signature
   uniqueness owes its own check. *)

(* The curve, the answer to trap 2. Seven strict hex literals, the four
   small multipliers of the Jacobian formulas, and the two limbsx
   constants this unit needs, built ONCE and then carried as a
   parameter. Limbsx.of_int returns an option (limbsx.mli:22) and
   Limbsx.of_hex returns an option (limbsx.mli:46), so the whole record
   is one Option.bind chain and neither the small multipliers nor the
   two constants cost a default site inside the arithmetic. *)
type curve = {
  p : Limbsx.t;
  p_minus_2 : Limbsx.t;
  n : Limbsx.t;
  n_minus_2 : Limbsx.t;
  b : Limbsx.t;
  gx : Limbsx.t;
  gy : Limbsx.t;
  two : Limbsx.t;
  three : Limbsx.t;
  four : Limbsx.t;
  eight : Limbsx.t;
  zero : Limbsx.t;
  one : Limbsx.t;
}

(* A Jacobian triple. Infinity is z = 0; x and y are then unread, and
   the value one is used for both so the triple stays canonical. *)
type point = { x : Limbsx.t; y : Limbsx.t; z : Limbsx.t }

let curve (() : unit) : curve option =
  Option.bind
    (Limbsx.of_hex
       "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
    (fun (p : Limbsx.t) ->
      Option.bind
        (Limbsx.of_hex
           "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd")
        (fun (p_minus_2 : Limbsx.t) ->
          Option.bind
            (Limbsx.of_hex
               "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
            (fun (n : Limbsx.t) ->
              Option.bind
                (Limbsx.of_hex
                   "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f")
                (fun (n_minus_2 : Limbsx.t) ->
                  Option.bind
                    (Limbsx.of_hex
                       "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
                    (fun (b : Limbsx.t) ->
                      Option.bind
                        (Limbsx.of_hex
                           "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
                        (fun (gx : Limbsx.t) ->
                          Option.bind
                            (Limbsx.of_hex
                               "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
                            (fun (gy : Limbsx.t) ->
                              Option.bind (Limbsx.of_int 2)
                                (fun (two : Limbsx.t) ->
                                  Option.bind (Limbsx.of_int 3)
                                    (fun (three : Limbsx.t) ->
                                      Option.bind (Limbsx.of_int 4)
                                        (fun (four : Limbsx.t) ->
                                          Option.bind (Limbsx.of_int 8)
                                            (fun (eight : Limbsx.t) ->
                                              Option.bind (Limbsx.of_int 0)
                                                (fun (zero : Limbsx.t) ->
                                                  Option.bind (Limbsx.of_int 1)
                                                    (fun (one : Limbsx.t) ->
                                                      Some
                                                        {
                                                          p;
                                                          p_minus_2;
                                                          n;
                                                          n_minus_2;
                                                          b;
                                                          gx;
                                                          gy;
                                                          two;
                                                          three;
                                                          four;
                                                          eight;
                                                          zero;
                                                          one;
                                                        })))))))))))))

(* ---------- field and scalar arithmetic ---------- *)

(* DEFAULT SITE 1 of 4, unreachable. Limbsx.mod_red is None only when
   the modulus is zero (limbsx.mli:67-70), and every modulus handed
   here is c.p or c.n, each decoded from a 32-byte literal by the
   Option.bind chain above, so neither is zero. The default value is
   c.zero, carried on the record for the same trap-2 reason as the curve
   constants themselves. Even a reached default
   cannot mint a false accept: a zero in place of a real residue gives
   an x1 that equals r only by chance. *)
let reduce_by (c : curve) (m : Limbsx.t) (v : Limbsx.t) : Limbsx.t =
  Option.value ~default:c.zero (Limbsx.mod_red ~m v)

let reduce (c : curve) (v : Limbsx.t) : Limbsx.t = reduce_by c c.p v

(* DEFAULT SITE 2 of 4, unreachable. Limbsx.sub is None only when the
   first operand is smaller (limbsx.mli:50-52). The first operand is
   c.p and every second operand is a residue below c.p: the one caller
   is fe_sub, whose second operand is the output of reduce, fe_add,
   fe_mul, fe_sqr or a small curve field under 9. *)
let fe_neg (c : curve) (v : Limbsx.t) : Limbsx.t =
  reduce c (Option.value ~default:c.zero (Limbsx.sub c.p v))

let fe_add (c : curve) (a : Limbsx.t) (v : Limbsx.t) : Limbsx.t =
  reduce c (Limbsx.add a v)

let fe_sub (c : curve) (a : Limbsx.t) (v : Limbsx.t) : Limbsx.t =
  fe_add c a (fe_neg c v)

let fe_mul (c : curve) (a : Limbsx.t) (v : Limbsx.t) : Limbsx.t =
  reduce c (Limbsx.mul a v)

let fe_sqr (c : curve) (a : Limbsx.t) : Limbsx.t = fe_mul c a a

(* DEFAULT SITE 3 of 4, unreachable. Limbsx.mod_pow is None only for a
   zero modulus (limbsx.mli:72-77), and the two moduli are c.p and c.n.
   This is the Fermat inverse, so the exponent is c.p_minus_2 for a
   field value and c.n_minus_2 for a scalar. *)
let inv_by (c : curve) ~(m : Limbsx.t) ~(e : Limbsx.t) (a : Limbsx.t) :
    Limbsx.t =
  Option.value ~default:c.zero (Limbsx.mod_pow ~m a e)

let fe_inv (c : curve) (a : Limbsx.t) : Limbsx.t =
  inv_by c ~m:c.p ~e:c.p_minus_2 a

(* Eta-expanded on purpose: let fe_eq = Limbsx.equal is a top-level
   CONSTANT binding and trap 2 fires on every read of it inside
   on_curve and inside j_add. *)
let fe_eq (a : Limbsx.t) (v : Limbsx.t) : bool = Limbsx.equal a v

(* DEFAULT SITE 4 of 4, unreachable. Limbsx.to_be_string is None only
   when the value needs more than len bytes (limbsx.mli:37-41). The
   only callers are Pubkey.to_bytes and Signature.to_raw; a coordinate
   sits below c.p and a scalar below c.n, so 32 bytes always suffice.
   The surface fixes to_bytes and to_raw at a plain string, so the
   option cannot be threaded to the caller. *)
let be32 (v : Limbsx.t) : string =
  Option.value ~default:"" (Limbsx.to_be_string ~len:32 v)

(* ---------- the curve and its Jacobian arithmetic ---------- *)

(* y^2 = x^3 - 3x + b, both sides reduced. The -3 is built from x
   itself and is never a stored field element. *)
let on_curve (c : curve) (px : Limbsx.t) (py : Limbsx.t) : bool =
  let xx = fe_sqr c px in
  let rhs =
    fe_add c (fe_sub c (fe_mul c xx px) (fe_add c px (fe_add c px px))) c.b
  in
  fe_eq (fe_sqr c py) rhs

(* A NAMED parameter, because the triple reads c.one and c.zero off the
   record: Limbsx.one and Limbsx.zero are top-level bindings of a core
   module, so trap 2 fires on a helper that names them. The parameter is
   read, so warning 27 stays quiet under the dune dev profile. *)
let infinity (c : curve) : point = { x = c.one; y = c.one; z = c.zero }

let is_infinity (q : point) : bool = Limbsx.is_zero q.z

let g (c : curve) : point = { x = c.gx; y = c.gy; z = c.one }

(* Doubling with a = -3. The y = 0 arm has no witness on a curve of
   prime order; it keeps the map total on an arbitrary triple. *)
let j_dbl (c : curve) (q : point) : point =
  match () with
  | () when is_infinity q -> infinity c
  | () when Limbsx.is_zero q.y -> infinity c
  | () ->
    let ysq = fe_sqr c q.y in
    let s = fe_mul c c.four (fe_mul c q.x ysq) in
    let zsq = fe_sqr c q.z in
    let m =
      fe_mul c c.three (fe_mul c (fe_sub c q.x zsq) (fe_add c q.x zsq))
    in
    let x3 = fe_sub c (fe_sqr c m) (fe_add c s s) in
    let y3 =
      fe_sub c (fe_mul c m (fe_sub c s x3)) (fe_mul c c.eight (fe_sqr c ysq))
    in
    let z3 = fe_mul c c.two (fe_mul c q.y q.z) in
    { x = x3; y = y3; z = z3 }

(* Addition. The outer guard splits on an infinite operand and the
   inner one on the doubling and the negation cases, so a nested
   then-branch is a match () guard here and never an if-chain. *)
let j_add (c : curve) (pa : point) (pb : point) : point =
  match () with
  | () when is_infinity pa -> pb
  | () when is_infinity pb -> pa
  | () ->
    let z1sq = fe_sqr c pa.z in
    let z2sq = fe_sqr c pb.z in
    let u1 = fe_mul c pa.x z2sq in
    let u2 = fe_mul c pb.x z1sq in
    let s1 = fe_mul c pa.y (fe_mul c z2sq pb.z) in
    let s2 = fe_mul c pb.y (fe_mul c z1sq pa.z) in
    (match () with
     | () when fe_eq u1 u2 && fe_eq s1 s2 -> j_dbl c pa
     | () when fe_eq u1 u2 -> infinity c
     | () ->
       let h = fe_sub c u2 u1 in
       let r = fe_sub c s2 s1 in
       let hsq = fe_sqr c h in
       let hcu = fe_mul c hsq h in
       let u1hsq = fe_mul c u1 hsq in
       let x3 = fe_sub c (fe_sub c (fe_sqr c r) hcu) (fe_add c u1hsq u1hsq) in
       let y3 = fe_sub c (fe_mul c r (fe_sub c u1hsq x3)) (fe_mul c s1 hcu) in
       let z3 = fe_mul c h (fe_mul c pa.z pb.z) in
       { x = x3; y = y3; z = z3 })

(* Double-and-add, LSB-first over Limbsx.bits. The list is 16 bits per
   limb of the canonical value, so a small scalar gives a SHORT list:
   the high zero bits jose pads with contribute one doubling each and
   no addition, so dropping them changes the running time and not the
   result. *)
let smul (c : curve) (k : Limbsx.t) (q : point) : point =
  fst
    (List.fold_left
       (fun ((acc : point), (dbl : point)) (bit : int) ->
         ((if Int.equal bit 1 then j_add c acc dbl else acc), j_dbl c dbl))
       (infinity c, q) (Limbsx.bits k))

let to_affine (c : curve) (q : point) : (Limbsx.t * Limbsx.t) option =
  if is_infinity q then None
  else
    let zi = fe_inv c q.z in
    let zi2 = fe_sqr c zi in
    Some (fe_mul c q.x zi2, fe_mul c q.y (fe_mul c zi2 zi))

(* ---------- the byte-facing surface ---------- *)

let digest_len (() : unit) : int = 32

module Pubkey = struct
  type t = { kx : Limbsx.t; ky : Limbsx.t }

  (* Consumption site 1 of 4 for the curve record: the below-p test
     reads c.p and the on-curve test reads c.b, so a curve that fails
     to decode mints no key. *)
  let of_xy ~(x : string) ~(y : string) : t option =
    Option.bind (curve ()) (fun (c : curve) ->
        Option.bind (Limbsx.of_be_string x) (fun (vx : Limbsx.t) ->
            Option.bind (Limbsx.of_be_string y) (fun (vy : Limbsx.t) ->
                if
                  Int.equal (String.length x) 32
                  && Int.equal (String.length y) 32
                  && Limbsx.cmp vx c.p < 0 && Limbsx.cmp vy c.p < 0
                  && on_curve c vx vy
                then Some { kx = vx; ky = vy }
                else None)))

  (* 64 bytes are X || Y. 65 bytes under a leading 0x04 are the SEC 1
     uncompressed form that M26 hands over, and the 64-byte tail is
     read. Every other length, and a 65-byte input under any other
     first byte, is None: the compressed 0x02 and 0x03 forms included,
     because this unit decompresses nothing. This reads no curve field
     of its own and reaches the curve through of_xy. *)
  let of_bytes (s : string) : t option =
    match () with
    | () when Int.equal (String.length s) 64 ->
      Option.bind (Bytesx.take s 0 32) (fun (x : string) ->
          Option.bind (Bytesx.take s 32 32) (fun (y : string) ->
              of_xy ~x ~y))
    | ()
      when Int.equal (String.length s) 65
           && Option.fold ~none:false
                ~some:(fun (first : int) -> Int.equal first 4)
                (Bytesx.u8 s 0) ->
      Option.bind (Bytesx.take s 1 32) (fun (x : string) ->
          Option.bind (Bytesx.take s 33 32) (fun (y : string) ->
              of_xy ~x ~y))
    | () -> None

  let to_bytes (k : t) : string = be32 k.kx ^ be32 k.ky

  let equal (a : t) (v : t) : bool =
    Limbsx.equal a.kx v.kx && Limbsx.equal a.ky v.ky
end

module Signature = struct
  type t = { sr : Limbsx.t; ss : Limbsx.t }

  (* The psychic test of CVE-2022-21449, and the whole reason this type
     is abstract: a scalar is acceptable only in 1 .. n-1. *)
  let in_range (c : curve) (v : Limbsx.t) : bool =
    (not (Limbsx.is_zero v)) && Limbsx.cmp v c.n < 0

  (* Consumption site 2 of 4 for the curve record. *)
  let of_raw (raw : string) : t option =
    Option.bind (curve ()) (fun (c : curve) ->
        Option.bind (Bytesx.take raw 0 32) (fun (rb : string) ->
            Option.bind (Bytesx.take raw 32 32) (fun (sb : string) ->
                Option.bind (Limbsx.of_be_string rb) (fun (rv : Limbsx.t) ->
                    Option.bind (Limbsx.of_be_string sb)
                      (fun (sv : Limbsx.t) ->
                        if
                          Int.equal (String.length raw) 64
                          && in_range c rv && in_range c sv
                        then Some { sr = rv; ss = sv }
                        else None)))))

  (* Consumption site 3 of 4 for the curve record. Each half is 1 to 32
     big-endian bytes, the shape M26 hands over once it strips the DER
     sign byte. A two-way test with no nested then-branch, so a plain
     if/else and not a match () guard. *)
  let of_rs ~(r : string) ~(s : string) : t option =
    let half_ok (h : string) : bool =
      String.length h >= 1 && String.length h <= 32
    in
    Option.bind (curve ()) (fun (c : curve) ->
        Option.bind (Limbsx.of_be_string r) (fun (rv : Limbsx.t) ->
            Option.bind (Limbsx.of_be_string s) (fun (sv : Limbsx.t) ->
                if
                  half_ok r && half_ok s && in_range c rv && in_range c sv
                then Some { sr = rv; ss = sv }
                else None)))

  let to_raw (sg : t) : string = be32 sg.sr ^ be32 sg.ss
end

(* Consumption site 4 of 4 for the curve record, through
   Option.fold ~none:false, so a curve that fails to decode rejects
   every signature: the unit fails closed on every path. That branch is
   unreachable, because the literals are fixed and Limbsx.of_hex
   accepts 64 hex characters.

   e is the digest read as a big-endian integer and reduced by the
   group order, w is the Fermat inverse of s, u1 = e w, u2 = r w and
   R = u1 G + u2 Q. False at infinity, and true exactly when the
   residue of x(R) by the group order equals r. Two independent scalar
   walks and one addition: no Shamir trick, because the input is public
   and two walks are simpler to audit.

   A digest of any length other than digest_len () is rejected before
   the arithmetic. That test is load bearing: a 33-byte string whose
   first byte is zero carries the SAME big-endian integer as the
   32-byte digest, so without the test such a string would verify. *)
let verify (q : Pubkey.t) (sg : Signature.t) ~(digest : string) : bool =
  Option.fold ~none:false
    ~some:(fun (c : curve) ->
      Option.fold ~none:false
        ~some:(fun (dv : Limbsx.t) ->
          let ev = reduce_by c c.n dv in
          let w = inv_by c ~m:c.n ~e:c.n_minus_2 sg.Signature.ss in
          let u1 = reduce_by c c.n (Limbsx.mul ev w) in
          let u2 = reduce_by c c.n (Limbsx.mul sg.Signature.sr w) in
          let rp =
            j_add c
              (smul c u1 (g c))
              (smul c u2
                 { x = q.Pubkey.kx; y = q.Pubkey.ky; z = c.one })
          in
          Option.fold ~none:false
            ~some:(fun ((rx : Limbsx.t), (_ : Limbsx.t)) ->
              Limbsx.equal (reduce_by c c.n rx) sg.Signature.sr)
            (to_affine c rp))
        (if Int.equal (String.length digest) (digest_len ()) then
           Limbsx.of_be_string digest
         else None))
    (curve ())

let verify_message (q : Pubkey.t) (sg : Signature.t) (message : string) : bool =
  verify q sg ~digest:(Sha2.Sha256.digest message)
