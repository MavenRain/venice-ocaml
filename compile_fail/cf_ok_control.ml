(* Battery control: this file MUST compile against the built library,
   or the battery is vacuous (wrong include path, stale artifacts).
   It exercises the positive multimodal path and structure-level
   payload reuse through the PUBLIC surface only, which also locks the
   venice.mli boundary the runtime suite bypasses. *)

(* Unbranded payloads minted once, no type variable, shared across
   models. *)
let sys : (Venice.Msg.msg, Venice.Error.t) result =
  Venice.Msg.system "you are helpful"

let caption : (Venice.Msg.text_part, Venice.Error.t) result =
  Venice.Msg.text "describe this"

let request (p : Venice.Model.packed) ~(url : string) ~(data : string) :
    (Venice.Json.t, Venice.Error.t) result option =
  match p with
  | Venice.Model.Pack m ->
    let media = Venice.Model.media m in
    Option.bind media.Venice.Model.vision (fun vm ->
        Option.map
          (fun am ->
            Result.bind sys (fun s ->
                Result.bind caption (fun c ->
                    Result.bind (Venice.Msg.image vm ~url) (fun i ->
                        Result.bind (Venice.Msg.audio am ~data) (fun a ->
                            Result.bind
                              (Venice.Msg.user
                                 [ i; a; Venice.Msg.of_text c ])
                              (fun u ->
                                Result.map
                                  (fun ((_ : _ Venice.Msg.nonempty)) ->
                                    Venice.Json.Jnull)
                                  (Venice.Msg.nonempty
                                     [ Venice.Msg.lift s; u ])))))))
          media.Venice.Model.audio)

(* The same structure-level payloads serve two distinct models. *)
let both (p : Venice.Model.packed) (q : Venice.Model.packed) :
    (Venice.Json.t, Venice.Error.t) result option list =
  [ request p ~url:"https://a/1.png" ~data:"aGVsbG8=";
    request q ~url:"https://b/2.png" ~data:"aGVsbG8=" ]
