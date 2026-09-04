(* M14 D13: the Delta effect is SEALED inside lib/streamx.ml.
   venice.mli publishes the cursor, the outcome and the run bracket,
   and it publishes NO effect constructor, so no caller can perform a
   Delta and no caller can install a second handler for one. The
   suspension therefore never escapes the one handler that owns it.
   The compiler must reject this file with "Unbound constructor". *)

let steal (c : Venice.Sse.Chunk.t) : unit =
  Effect.perform (Venice.Stream.Delta c)
