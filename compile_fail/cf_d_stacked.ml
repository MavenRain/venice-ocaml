(* Battery (d): stacked extraction (audio witness taken from an
   already-vision-witnessed model) erases to the stacked row, so its
   part must NOT share a list with base-row parts. Extract every
   witness from the SAME base model; Model.media is the paved road. *)

let probe (p : Venice.Model.packed) =
  match p with
  | Venice.Model.Pack m ->
    Option.bind (Venice.Model.vision m) (fun vm ->
        Option.map
          (fun avm ->
            Result.bind (Venice.Msg.image vm ~url:"https://a/1.png")
              (fun i ->
                Result.bind (Venice.Msg.audio avm ~data:"aGVsbG8=")
                  (fun a -> Venice.Msg.user [ i; a ])))
          (Venice.Model.audio vm))
