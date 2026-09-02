(* Battery (e): the public Pack constructor is a row-freshening
   primitive; messages minted at the old row must NOT typecheck
   against a re-packed-then-unpacked model. Locally abstract types
   keep the probe non-vacuous ('a/'b annotations would unify into the
   identity). *)

let use (type c) ((_ : c Venice.Model.t)) ((_ : c Venice.Msg.nonempty)) :
    unit =
  ()

let probe (p : Venice.Model.packed) : unit =
  match p with
  | Venice.Model.Pack (type c) (m : c Venice.Model.t) ->
    Result.fold
      ~ok:(fun (msgs : c Venice.Msg.nonempty) ->
        match Venice.Model.Pack m with
        | Venice.Model.Pack m2 -> use m2 msgs)
      ~error:(fun ((_ : Venice.Error.t)) -> ())
      (Result.bind (Venice.Msg.user_text "hi")
         (fun (u : c Venice.Msg.t) -> Venice.Msg.nonempty [ u ]))
