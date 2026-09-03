(* Battery case m (M13): messages minted under one Pack row must not
   feed a Chat.make on another row. Each Pack binds its own
   existential row, so the nonempty message list carries the wrong
   brand. Locally abstract types keep the probe non-vacuous. *)

let chat (p : Venice.Model.packed) (q : Venice.Model.packed) :
    (string, Venice.Error.t) result =
  match (p, q) with
  | ( Venice.Model.Pack (type c) (m : c Venice.Model.t),
      Venice.Model.Pack (type d) ((_ : d Venice.Model.t)) ) ->
    Result.bind (Venice.Msg.user_text "hi") (fun (u : d Venice.Msg.t) ->
        Result.bind (Venice.Msg.nonempty [ u ])
          (fun (msgs : d Venice.Msg.nonempty) ->
            Result.map Venice.Chat.emit (Venice.Chat.make m msgs ())))
