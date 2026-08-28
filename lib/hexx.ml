(* Strict hex codec. Decode rejects any byte outside the alphabet and
   any odd length; it accepts both letter cases because the wire mixes
   them (EIP-55 addresses checksum with case). Encode emits lowercase.
   ZxCaml trap 2: the alphabets are unit functions and each entrypoint
   binds its lookup map locally. *)

let ( let* ) = Result.bind

let alphabet (() : unit) : string = "0123456789abcdef"
let upper (() : unit) : string = "ABCDEF"

module Imap = Map.Make (Int)
module Cmap = Map.Make (Char)

let enc_map (() : unit) : char Imap.t =
  Seq.fold_left
    (fun m (i, c) -> Imap.add i c m)
    Imap.empty
    (String.to_seqi (alphabet ()))

(* Total: the nibble is masked to [0, 15]. *)
let enc_char (m : char Imap.t) (i : int) : char =
  Option.value (Imap.find_opt (i land 15) m) ~default:'0'

let dec_map (() : unit) : int Cmap.t =
  let low =
    Seq.fold_left
      (fun m (i, c) -> Cmap.add c i m)
      Cmap.empty
      (String.to_seqi (alphabet ()))
  in
  Seq.fold_left
    (fun m (i, c) -> Cmap.add c (i + 10) m)
    low
    (String.to_seqi (upper ()))

let dec_val (m : int Cmap.t) (c : char) : int option = Cmap.find_opt c m

let encode (s : string) : string =
  let m = enc_map () in
  String.of_seq
    (Seq.concat_map
       (fun c ->
         List.to_seq
           [ enc_char m (Char.code c lsr 4); enc_char m (Char.code c) ])
       (String.to_seq s))

let decode (s : string) : (string, Errx.t) result =
  let m = dec_map () in
  (* pending holds the high nibble while its partner is awaited. *)
  let step (st : (int list * int option, Errx.t) result) (c : char) :
      (int list * int option, Errx.t) result =
    let* out_rev, pending = st in
    let* v =
      Option.to_result (dec_val m c)
        ~none:(Errx.Hex_invalid "byte outside alphabet")
    in
    Option.fold pending
      ~none:(Ok (out_rev, Some v))
      ~some:(fun hi -> Ok (((hi lsl 4) lor v) :: out_rev, None))
  in
  let* out_rev, pending =
    List.fold_left step (Ok ([], None)) (List.of_seq (String.to_seq s))
  in
  Option.fold pending
    ~none:(Ok (Bytesx.of_codes (List.rev out_rev)))
    ~some:(fun (_ : int) -> Error (Errx.Hex_invalid "odd length"))
