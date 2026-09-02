(* Battery (c): parts minted from witnesses of TWO different unpacked
   models must NOT share one user message; each Pack match binds a
   fresh existential row. *)

let probe (p : Venice.Model.packed) (q : Venice.Model.packed) =
  match (p, q) with
  | Venice.Model.Pack m1, Venice.Model.Pack m2 ->
    Option.bind (Venice.Model.vision m1) (fun vm1 ->
        Option.map
          (fun vm2 ->
            Result.bind (Venice.Msg.image vm1 ~url:"https://a/1.png")
              (fun i1 ->
                Result.bind
                  (Venice.Msg.image vm2 ~url:"https://b/2.png")
                  (fun i2 -> Venice.Msg.user [ i1; i2 ])))
          (Venice.Model.vision m2))
