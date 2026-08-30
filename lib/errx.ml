(* The one error type. Every rejection names the check that failed, so a
   caller and the harness can pin the exact reason. Grows with the
   milestones; M3 seeds the codec constructors, M4 adds JSON, M5 the
   model domain. *)

type t =
  | Hex_invalid of string
  | B64_invalid of string
  | Json_invalid of string
  | Model_invalid of string

let to_string (e : t) : string =
  match e with
  | Hex_invalid s -> "hex: " ^ s
  | B64_invalid s -> "base64: " ^ s
  | Json_invalid s -> "json: " ^ s
  | Model_invalid s -> "model: " ^ s
