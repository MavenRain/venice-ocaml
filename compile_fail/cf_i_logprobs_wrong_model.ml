(* Battery case i (M12): a log_probs witness minted from a DIFFERENT
   model row must not authorize logprobs on this model. The witness
   pair carries ('other * log_probs) Model.t where make demands
   ('c * log_probs) Model.t, so the two existential rows cannot
   unify. The model and messages are applied BEFORE ~logprobs so the
   error lands on the witness pair and names the marker. *)

let chat (p : Venice.Model.packed) (q : Venice.Model.packed) :
    (string, Venice.Error.t) result option =
  match (p, q) with
  | Venice.Model.Pack m, Venice.Model.Pack other ->
    Option.map
      (fun w ->
        Result.bind (Venice.Msg.user_text "hi") (fun u ->
            Result.bind (Venice.Msg.nonempty [ u ]) (fun msgs ->
                Result.map Venice.Chat.emit
                  (Venice.Chat.make m msgs ~logprobs:(w, true) ()))))
      (Venice.Model.log_probs other)
