(* M13 keyx: the Venice API key as an opaque value.

   The mint is the only door: a key is 1..512 bytes drawn from
   0x21..0x7E, so SP, HTAB, CR, LF, NUL, DEL and every non-ASCII byte
   reject. Header injection through the key is therefore
   unrepresentable, and the key needs no escaping on its way to an
   Authorization line.

   venice.mli publishes NO projection (no to_string, equal, compare,
   pp, hash or fingerprint), so the key has no printable image THROUGH
   THE PUBLIC API. That is a boundary, not a guarantee: reveal below
   stays reachable as Venice__Keyx.reveal from any executable that
   links the library, exactly as the test suite reaches every other
   internal module (A7). The guarantee that matters is the one the
   type buys: a Request can hold no key field, so no Request
   projection can leak one. *)

type t

val make : string -> (t, Errx.t) result
(* rejects "", any byte outside 0x21..0x7E, and length > 512; 512
   passes *)

val from_env : unit -> (t, Errx.t) result
(* reads VENICE_API_KEY through Sys.getenv_opt; an unset variable
   rejects with text naming the variable, a set one goes through
   make *)

val reveal : t -> string
(* INTERNAL seam, consumed by cfgx alone: the one place the key
   becomes bytes. Never re-exported from venice.mli. *)
