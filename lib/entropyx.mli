(* M29 host entropy boundary. Production values are opaque and read
   exactly 32 bytes from /dev/urandom for each draw. The OS descriptor
   is closed before any bytes leave the boundary. Open and read retry
   EINTR; every other IO failure is the fixed reason "entropy unavailable".

   This is a HOST unit: Unix, Bytes and Atomic stay outside the core.
   The scripted source is internal to the library test surface and is
   not re-exported by Venice.Entropy. *)

type t
type entropy = t

(* Construction performs no IO. Each scalar or Fresh.make call reads
   the source when it needs a draw. *)
val system : unit -> t

(* Rejection sampling of a secp256k1 scalar in 1 .. n-1. Each attempt
   consumes exactly 32 bytes and tests Secpx.Scalar.of_bytes without a
   modulo reduction. At most 128 attempts are made; 128 invalid draws
   reject with "scalar rejection limit" without consuming a 129th. *)
val scalar : t -> (Secpx.Scalar.t, Errx.t) result

module Fresh : sig
  (* A nonce and a shared atomic consumption bit. Aliasing the value,
     including across domains, preserves the one-use rule. *)
  type t

  (* Consumes one 32-byte draw. Every 32-byte string is a valid nonce,
     including all zero bytes; scalar rejection sampling is separate. *)
  val make : entropy:entropy -> (t, Errx.t) result

  (* A public projection. It stays available after consumption but
     does not make another token. *)
  val nonce : t -> Policyx.Nonce.t

  (* The first call atomically burns the token BEFORE comparing the
     public nonce. A mismatch is "nonce mismatch" and still burns it.
     Every later call is "fresh consumed", even with the right nonce. *)
  val consume : t -> nonce:Policyx.Nonce.t -> (unit, Errx.t) result
end

module Fake : sig
  (* Internal deterministic source. A draw pops exactly one chunk;
     an empty script is "entropy exhausted", and a chunk whose length
     differs from 32 is consumed and rejected as "entropy length".
     Concurrent draws share an atomic cursor. *)
  val make : string list -> t

  (* Remaining scripted chunks. A system source has no script and
     reports zero. *)
  val remaining : t -> int
end
