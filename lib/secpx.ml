(* M20 secpx: secp256k1 ECDSA VERIFICATION and ECDH, over the same
   abstract limbsx surface lib/p256x.ml uses. The lineage is
   lib/p256x.ml at M19: the field helpers, the four-case Jacobian
   addition, the byte-facing surface and the trap-2 curve record are
   ported unchanged, and only the curve constants, the doubling formula
   and the scalar walk differ.

   Jacobian coordinates with a = 0, and the point at infinity encoded
   as z = 0, the p256x convention. A projective triple costs no field
   inverse per addition, so one inverse runs at the end of each scalar
   walk and one more inside the scalar inverse. The doubling is
   dbl-2009-l, which drops the a term entirely; the addition is
   add-2007-bl, the p256x one.

   Pure and sans-io, like limbsx.ml, hmacx.ml, keccakx.ml and p256x.ml:
   no reference cell, no exception, no exception handler, no floating
   point value, no mutable byte buffer and no indexed container. The
   unit holds NO division line and NO remainder operator: every
   reduction runs through Limbsx.mod_red inside reduce_by, and every
   inverse runs through Limbsx.mod_pow inside inv_by, so the modulus is
   always an explicit argument.

   ONE scalar walk, and it is a FIXED-SHAPE Montgomery ladder: verify,
   Pubkey.of_scalar, shared_point and shared_x all run it. The bit list
   is padded to exactly 256 entries and read most significant first, and
   each step CALLS exactly one j_add and one j_dbl whatever the bit, so
   the walk makes 256 addition calls and 256 doubling calls for every
   scalar and the ORDER of the calls never depends on a secret bit.

   The field-operation count is NOT constant, and two residual leaks
   stay. First, limbsx is VARIABLE-TIME underneath: Limbsx.mod_red and
   Limbsx.mod_pow branch on limb values (limbsx.mli:67-69 and 73-76),
   so the values that flow through a step leak through timing even
   though the call shape does not. Second, j_add and j_dbl return early
   on an infinite operand, so a step that runs while r0 is still
   infinity costs no field multiplication at all, and the bit LENGTH of
   the scalar leaks through that case split. M29 mints its scalars by
   rejection sampling from 32 entropy bytes, so a short scalar is a
   2^-32-class event, but the leak is real. A constant-time tower is
   the M39 hardening candidate (DESIGN.md:403).

   ZxCaml trap 2 makes a top-level constant invisible inside a helper.
   The answer here is the curve RECORD: curve () builds the twelve
   field values once, and every helper below takes (c : curve) as its
   first parameter, so no helper reads a top-level value. The rule bites
   across module boundaries too: Limbsx.zero and Limbsx.one are
   top-level bindings of a module that sits in the same core list, so
   this unit carries them as record fields as well and names no Limbsx
   constant inside a helper. An alias is eta-expanded for the same
   reason, because a bare alias binding is a constant and trap 2 fires
   on every read of it.

   Psychic signatures (CVE-2022-21449) die at CONSTRUCTION. A
   Signature.t is minted only when r and s both sit in 1 .. n-1, so
   r = 0, s = 0, r >= n and s >= n never reach the point arithmetic.
   The malleable twin (r, n - s) VERIFIES: the standard carries no
   low-s rule, the suite pins the twin, and a consumer that needs
   signature uniqueness owes its own check.

   The unit HASHES nothing: verify takes a digest, because the signed
   message formula of the /tee/signature route is unpinned until M31.
   It decompresses nothing, so the 0x02 and 0x03 point forms are
   rejections and never inputs, and it recovers no public key, because
   the enclave signing key is an attested field. *)

(* The curve, the answer to trap 2. Six strict hex literals, the three
   small multipliers of the a = 0 Jacobian formulas, the curve
   coefficient b = 7, and the two limbsx constants this unit needs,
   built ONCE and then carried as a parameter. Limbsx.of_int returns an
   option (limbsx.mli:22) and Limbsx.of_hex returns an option
   (limbsx.mli:46), so the whole record is one Option.bind chain and
   neither the small multipliers nor the two constants cost a default
   site inside the arithmetic. The p256x field four is DROPPED: the
   a = 0 doubling reads only two, three and eight, and an unused record
   field is warning 69 under the dune dev profile. *)
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
       "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
    (fun (p : Limbsx.t) ->
      Option.bind
        (Limbsx.of_hex
           "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d")
        (fun (p_minus_2 : Limbsx.t) ->
          Option.bind
            (Limbsx.of_hex
               "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            (fun (n : Limbsx.t) ->
              Option.bind
                (Limbsx.of_hex
                   "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f")
                (fun (n_minus_2 : Limbsx.t) ->
                  Option.bind
                    (Limbsx.of_hex
                       "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    (fun (gx : Limbsx.t) ->
                      Option.bind
                        (Limbsx.of_hex
                           "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
                        (fun (gy : Limbsx.t) ->
                          Option.bind (Limbsx.of_int 7) (fun (b : Limbsx.t) ->
                              Option.bind (Limbsx.of_int 2)
                                (fun (two : Limbsx.t) ->
                                  Option.bind (Limbsx.of_int 3)
                                    (fun (three : Limbsx.t) ->
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
                                                      eight;
                                                      zero;
                                                      one;
                                                    }))))))))))))

(* ---------- field and scalar arithmetic ---------- *)

(* DEFAULT SITE 1 of 4, unreachable. Limbsx.mod_red is None only when
   the modulus is zero (limbsx.mli:67-70), and every modulus handed
   here is c.p or c.n, each decoded from a 64-character hex literal by
   the Option.bind chain above, so neither is zero. The default value is
   c.zero, carried on the record for the same trap-2 reason as the curve
   constants themselves. Even a reached default cannot mint a false
   accept: a zero in place of a real residue gives an x1 that equals r
   only by chance. *)
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
   field value and c.n_minus_2 for a scalar; p and n are both prime, so
   a^(m-2) is the inverse of a modulo m for every a the callers hand
   over. *)
let inv_by (c : curve) ~(m : Limbsx.t) ~(e : Limbsx.t) (a : Limbsx.t) :
    Limbsx.t =
  Option.value ~default:c.zero (Limbsx.mod_pow ~m a e)

let fe_inv (c : curve) (a : Limbsx.t) : Limbsx.t =
  inv_by c ~m:c.p ~e:c.p_minus_2 a

(* Eta-expanded on purpose: let fe_eq = Limbsx.equal is a top-level
   CONSTANT binding and trap 2 fires on every read of it inside
   on_curve and inside j_add. Trap 2 fires ACROSS modules, so the rule
   holds for a Limbsx name exactly as it holds for a local one. *)
let fe_eq (a : Limbsx.t) (v : Limbsx.t) : bool = Limbsx.equal a v

(* DEFAULT SITE 4 of 4, unreachable. Limbsx.to_be_string is None only
   when the value needs more than len bytes (limbsx.mli:37-41). The
   callers are Scalar.to_bytes, Pubkey.to_bytes, Pubkey.to_sec1,
   Signature.to_raw and shared_x; a coordinate and a shared x sit below
   c.p and a scalar below c.n, so 32 bytes always suffice. The surface
   fixes those entries at a plain string, so the option cannot be
   threaded to the caller. *)
let be32 (v : Limbsx.t) : string =
  Option.value ~default:"" (Limbsx.to_be_string ~len:32 v)

(* ---------- the curve and its Jacobian arithmetic ---------- *)

(* y^2 = x^3 + b with b = 7, both sides reduced. This body is SHORTER
   than the p256x one, because a = 0 deletes the -3x term. *)
let on_curve (c : curve) (px : Limbsx.t) (py : Limbsx.t) : bool =
  fe_eq (fe_sqr c py) (fe_add c (fe_mul c (fe_sqr c px) px) c.b)

(* A NAMED parameter, because the triple reads c.one and c.zero off the
   record: Limbsx.one and Limbsx.zero are top-level bindings of a core
   module, so trap 2 fires on a helper that names them. The parameter is
   read, so warning 27 stays quiet under the dune dev profile. *)
let infinity (c : curve) : point = { x = c.one; y = c.one; z = c.zero }

let is_infinity (q : point) : bool = Limbsx.is_zero q.z

let g (c : curve) : point = { x = c.gx; y = c.gy; z = c.one }

(* Doubling with a = 0, the dbl-2009-l formula, and the ONE formula
   that differs from p256x. A = X^2, B = Y^2, C = B^2,
   D = 2((X + B)^2 - A - C), E = 3A, F = E^2, X3 = F - 2D,
   Y3 = E(D - X3) - 8C and Z3 = 2 Y Z, so the only constants it reads
   are c.two, c.three and c.eight. The y = 0 arm has no witness on a
   curve of prime order; it keeps the map total on an arbitrary
   triple. *)
let j_dbl (c : curve) (q : point) : point =
  match () with
  | () when is_infinity q -> infinity c
  | () when Limbsx.is_zero q.y -> infinity c
  | () ->
    let va = fe_sqr c q.x in
    let vb = fe_sqr c q.y in
    let vc = fe_sqr c vb in
    let vd =
      fe_mul c c.two
        (fe_sub c (fe_sub c (fe_sqr c (fe_add c q.x vb)) va) vc)
    in
    let ve = fe_mul c c.three va in
    let vf = fe_sqr c ve in
    let x3 = fe_sub c vf (fe_mul c c.two vd) in
    let y3 = fe_sub c (fe_mul c ve (fe_sub c vd x3)) (fe_mul c c.eight vc) in
    let z3 = fe_mul c c.two (fe_mul c q.y q.z) in
    { x = x3; y = y3; z = z3 }

(* Addition, add-2007-bl, the p256x four-case body UNCHANGED. The outer
   guard splits on an infinite operand and the inner one on the doubling
   and the negation cases, so a nested then-branch is a match () guard
   here and never an if-chain. *)
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

(* The ONE scalar walk, a FIXED-SHAPE Montgomery ladder, shared by
   verify, Pubkey.of_scalar, shared_point and shared_x.

   Limbsx.bits is LSB-first and gives exactly 16 bits per limb
   (limbsx.mli:63-65), so a value below 2^256 carries at most 256
   entries. The walk pads that list on the RIGHT with zeros up to 256
   entries and then reverses it, which puts the padding at the FRONT as
   leading zero bits, so the fold reads the scalar most significant bit
   first and runs 256 steps for every scalar. Int.max 0 keeps the
   padding length non-negative, so a 256-element list pads by nothing.

   The invariant is r1 = r0 + pt at every step. Each step CALLS one
   j_add and one j_dbl whatever the bit, so the CALL shape is fixed;
   the field-operation count is not, because both helpers return early
   on an infinite operand. No Shamir trick, no window and no
   precomputed table: one walk keeps the unit auditable, and it lets
   the public Wycheproof corpus exercise the arithmetic the secret ECDH
   path runs. *)
let ladder (c : curve) (k : Limbsx.t) (pt : point) : point =
  let bs = Limbsx.bits k in
  let padded =
    bs @ List.init (Int.max 0 (256 - List.length bs)) (fun (_ : int) -> 0)
  in
  fst
    (List.fold_left
       (fun ((r0 : point), (r1 : point)) (bit : int) ->
         if Int.equal bit 0 then (j_dbl c r0, j_add c r0 r1)
         else (j_add c r0 r1, j_dbl c r1))
       (infinity c, pt) (List.rev padded))

let to_affine (c : curve) (q : point) : (Limbsx.t * Limbsx.t) option =
  if is_infinity q then None
  else
    let zi = fe_inv c q.z in
    let zi2 = fe_sqr c zi in
    Some (fe_mul c q.x zi2, fe_mul c q.y (fe_mul c zi2 zi))

(* ---------- the byte-facing surface ---------- *)

let digest_len (() : unit) : int = 32

module Scalar = struct
  type t = { sv : Limbsx.t }

  (* Curve consumption site 1 of 7. Exactly 32 big-endian bytes whose
     value sits in 1 .. n-1: zero, n, anything above n and every other
     length are None, which is what M29 rejection sampling needs,
     because it retries on None. *)
  let of_bytes (s : string) : t option =
    Option.bind (curve ()) (fun (c : curve) ->
        Option.bind (Limbsx.of_be_string s) (fun (v : Limbsx.t) ->
            if
              Int.equal (String.length s) 32
              && (not (Limbsx.is_zero v))
              && Limbsx.cmp v c.n < 0
            then Some { sv = v }
            else None))

  let to_bytes (d : t) : string = be32 d.sv
end

module Pubkey = struct
  type t = { kx : Limbsx.t; ky : Limbsx.t }

  (* Curve consumption site 2 of 7: the below-p test reads c.p and the
     on-curve test reads c.b, so a curve that fails to decode mints no
     key. The zero pair falls out of the curve test, because 0 = 7 has
     no solution. *)
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
     uncompressed form the E2EE header and every response chunk carry
     (FACTS.md:241-243 and :246-248), and the 64-byte tail is read.
     Every other length, and a 65-byte input under any other first
     byte, is None: the compressed 0x02 and 0x03 forms included,
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

  (* The 65-byte SEC 1 uncompressed form, 0x04 || X || Y. The prefix is
     a one-character string literal, so no character-code conversion is
     owed. *)
  let to_sec1 (k : t) : string = "\004" ^ be32 k.kx ^ be32 k.ky

  let equal (a : t) (v : t) : bool =
    Limbsx.equal a.kx v.kx && Limbsx.equal a.ky v.ky

  (* Curve consumption site 3 of 7. d G in affine through the ONE
     ladder. None only at infinity, which is unreachable: d sits in
     1 .. n-1 by the Scalar invariant and the group order is prime, so
     d G is never the point at infinity and M29 fails closed on a value
     it can never see. *)
  let of_scalar (d : Scalar.t) : t option =
    Option.bind (curve ()) (fun (c : curve) ->
        Option.map
          (fun ((qx : Limbsx.t), (qy : Limbsx.t)) -> { kx = qx; ky = qy })
          (to_affine c (ladder c d.Scalar.sv (g c))))
end

module Signature = struct
  type t = { sr : Limbsx.t; ss : Limbsx.t }

  (* The psychic test of CVE-2022-21449, and the whole reason this type
     is abstract: a scalar is acceptable only in 1 .. n-1. *)
  let in_range (c : curve) (v : Limbsx.t) : bool =
    (not (Limbsx.is_zero v)) && Limbsx.cmp v c.n < 0

  (* Curve consumption site 4 of 7. *)
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

  (* Curve consumption site 5 of 7. Each half is 1 to 32 big-endian
     bytes, the shape M26 hands over once it strips the DER sign byte.
     A two-way test with no nested then-branch, so a plain if/else and
     not a match () guard. *)
  let of_rs ~(r : string) ~(s : string) : t option =
    let half_ok (h : string) : bool =
      String.length h >= 1 && String.length h <= 32
    in
    Option.bind (curve ()) (fun (c : curve) ->
        Option.bind (Limbsx.of_be_string r) (fun (rv : Limbsx.t) ->
            Option.bind (Limbsx.of_be_string s) (fun (sv : Limbsx.t) ->
                if half_ok r && half_ok s && in_range c rv && in_range c sv
                then Some { sr = rv; ss = sv }
                else None)))

  let to_raw (sg : t) : string = be32 sg.sr ^ be32 sg.ss
end

(* Curve consumption site 6 of 7, through Option.fold ~none:false, so a
   curve that fails to decode rejects every signature: the unit fails
   closed on every path. That branch is unreachable, because the
   literals are fixed and Limbsx.of_hex accepts 64 hex characters.

   e is the digest read as a big-endian integer, with NO reduction of
   its own: u1 = e w is reduced by the group order once, which is the
   same residue. w is the Fermat inverse of s modulo n, u2 = r w and
   R = u1 G + u2 Q, both walks through the ONE ladder. False at
   infinity, and true exactly when the residue of x(R) by the group
   order equals r; the residue is load bearing, because the corpus
   carries a signature whose x(R) is above n.

   A digest of any length other than digest_len () is rejected before
   the arithmetic. That test is load bearing: a 33-byte string whose
   first byte is zero carries the SAME big-endian integer as the
   32-byte digest, so without the test such a string would verify.

   The malleable twin (r, n - s) VERIFIES, and that is the standard
   behaviour: there is no low-s rule here, and EIP-2 is a consumer
   decision. *)
let verify (q : Pubkey.t) (sg : Signature.t) ~(digest : string) : bool =
  Option.fold ~none:false
    ~some:(fun (c : curve) ->
      Option.fold ~none:false
        ~some:(fun (ev : Limbsx.t) ->
          let w = inv_by c ~m:c.n ~e:c.n_minus_2 sg.Signature.ss in
          let u1 = reduce_by c c.n (Limbsx.mul ev w) in
          let u2 = reduce_by c c.n (Limbsx.mul sg.Signature.sr w) in
          let rp =
            j_add c
              (ladder c u1 (g c))
              (ladder c u2 { x = q.Pubkey.kx; y = q.Pubkey.ky; z = c.one })
          in
          Option.fold ~none:false
            ~some:(fun ((rx : Limbsx.t), (_ : Limbsx.t)) ->
              Limbsx.equal (reduce_by c c.n rx) sg.Signature.sr)
            (to_affine c rp))
        (if Int.equal (String.length digest) (digest_len ()) then
           Limbsx.of_be_string digest
         else None))
    (curve ())

(* Curve consumption site 7 of 7. d Q in affine through the same
   ladder, re-validated through Pubkey.of_xy so the result carries the
   same construction invariant every other key carries. None only at
   infinity, which is unreachable for a validated Q: the group has
   prime order n and cofactor 1, and d sits in 1 .. n-1. *)
let shared_point (d : Scalar.t) (q : Pubkey.t) : Pubkey.t option =
  Option.bind (curve ()) (fun (c : curve) ->
      Option.bind
        (to_affine c
           (ladder c d.Scalar.sv
              { x = q.Pubkey.kx; y = q.Pubkey.ky; z = c.one }))
        (fun ((sx : Limbsx.t), (sy : Limbsx.t)) ->
          Pubkey.of_xy ~x:(be32 sx) ~y:(be32 sy)))

(* The 32-byte big-endian x of d Q, the SEC 1 section 3.3.1 shared
   secret value and the Wycheproof shared field. Defined THROUGH
   shared_point, so the two cannot drift, and it reads no curve field
   of its own. *)
let shared_x (d : Scalar.t) (q : Pubkey.t) : string option =
  Option.map (fun (k : Pubkey.t) -> be32 k.Pubkey.kx) (shared_point d q)
