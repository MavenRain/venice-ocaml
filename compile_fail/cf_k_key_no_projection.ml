(* Battery case k (M13): the API key has no printable image through
   the public API. venice.mli publishes make and from_env only, so no
   projection exists to name. This pins the absence, which no runtime
   test can do. *)

let leak (k : Venice.Api_key.t) : string = Venice.Api_key.to_string k
