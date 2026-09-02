(* Battery case h (M10a): a response_schema witness minted from a
   DIFFERENT model row must not authorize the json_schema
   response_format arm on this model. Each Pack binds its own
   existential row, so the witness type ('other * response_schema)
   Model.t cannot unify with the ('c * response_schema) Model.t the
   Rf_json_schema payload demands. The model and messages are
   applied BEFORE ~response_format so the type error lands on the
   witness and names the marker. *)

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
                     ~response_format:
                       (Venice.Chat.Rf_json_schema
                          (w, Venice.Json.Jobj []))
                     ()))))
      (Venice.Model.response_schema other)
