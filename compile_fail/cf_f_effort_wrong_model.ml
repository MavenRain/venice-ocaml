(* Battery case f (M9): an effort witness minted from a DIFFERENT
   model row must not authorize a chat request on this model. Each
   Pack binds its own existential row, so the witness type
   ('other * reasoning_effort) Model.t cannot unify with the
   ('c * reasoning_effort) Model.t the make signature demands. The
   model and messages are applied BEFORE ~effort so the type error
   lands on the witness pair and names the marker. *)

let chat (p : Venice.Model.packed) (q : Venice.Model.packed) :
    (string, Venice.Error.t) result option =
  match (p, q) with
  | Venice.Model.Pack m, Venice.Model.Pack other ->
    Option.map
      (fun w ->
        Result.bind (Venice.Msg.user_text "hi") (fun u ->
            Result.bind (Venice.Msg.nonempty [ u ]) (fun msgs ->
                Result.map Venice.Chat.emit
                  (Venice.Chat.make m msgs
                     ~effort:(w, Venice.Effort.Low) ()))))
      (Venice.Model.reasoning_effort other)
