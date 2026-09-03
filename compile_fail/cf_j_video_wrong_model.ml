(* Battery case j (M12): a video witness minted from a DIFFERENT model
   row must not authorize a video part on this model. Msg.video wants
   ('c * Model.video) Model.t for the row that owns the message, and
   the witness carries another row. *)

let part (p : Venice.Model.packed) (q : Venice.Model.packed) :
    (Venice.Json.t, Venice.Error.t) result option =
  match (p, q) with
  | Venice.Model.Pack m, Venice.Model.Pack other ->
    Option.map
      (fun w ->
        Result.bind (Venice.Msg.video w ~url:"https://a/1.mp4")
          (fun v ->
            Result.bind (Venice.Msg.user [ v ]) (fun u ->
                Result.bind (Venice.Msg.nonempty [ u ]) (fun msgs ->
                    Result.map
                      (fun ((_ : string)) -> Venice.Json.Jnull)
                      (Result.map Venice.Chat.emit
                         (Venice.Chat.make m msgs ()))))))
      (Venice.Model.video other)
