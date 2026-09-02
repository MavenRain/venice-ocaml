(* Battery (a): Msg.image demands a vision witness; an unwitnessed
   base model must NOT typecheck. *)

let probe (p : Venice.Model.packed) =
  match p with
  | Venice.Model.Pack m -> Venice.Msg.image m ~url:"https://x/i.png"
