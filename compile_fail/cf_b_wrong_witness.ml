(* Battery (b): Msg.image on an audio-witnessed model must NOT
   typecheck; the audio marker is not the vision marker. *)

let probe (p : Venice.Model.packed) =
  match p with
  | Venice.Model.Pack m ->
    Option.map
      (fun am -> Venice.Msg.image am ~url:"https://x/i.png")
      (Venice.Model.audio m)
