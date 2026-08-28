(* The public face. venice.mli is the only signature that matters to a
   consumer; the x-suffixed units stay behind it. *)

let version = "0.1.0"

module Error = Errx
module Cursor = Bytesx
module Hex = Hexx
module B64 = B64x
