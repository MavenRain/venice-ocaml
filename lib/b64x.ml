(* Strict base64, both alphabets Venice uses.
   url (RFC 4648 section 5, RFC 7515 flavor): no padding, no line
   breaks, no bytes outside the alphabet, canonical trailing bits, and
   length mod 4 <> 1. A '=' is simply outside this alphabet, so padded
   input is rejected by the same rule as any other foreign byte.
   std (RFC 4648 section 4): the same core plus mandatory canonical '='
   padding; intel_quote arrives in this form.
   ZxCaml trap 2: the alphabets are unit functions and each entrypoint
   binds its lookup map locally. *)

let ( let* ) = Result.bind

let url_alphabet (() : unit) : string =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

let std_alphabet (() : unit) : string =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

module Imap = Map.Make (Int)
module Cmap = Map.Make (Char)

let enc_map_of (alphabet : string) : char Imap.t =
  Seq.fold_left
    (fun m (i, c) -> Imap.add i c m)
    Imap.empty (String.to_seqi alphabet)

let dec_map_of (alphabet : string) : int Cmap.t =
  Seq.fold_left
    (fun m (i, c) -> Cmap.add c i m)
    Cmap.empty (String.to_seqi alphabet)

(* Total: the index is masked to [0, 63]; Maps keep both lookups total
   without an O(n) list scan per character. *)
let enc_char (m : char Imap.t) (i : int) : char =
  Option.value (Imap.find_opt (i land 63) m) ~default:'A'

let dec_val (m : int Cmap.t) (c : char) : int option = Cmap.find_opt c m

let encode_core (m : char Imap.t) (s : string) : string =
  let emit3 (a : int) (b : int) (c : int) : char list =
    [ enc_char m (a lsr 2);
      enc_char m (((a land 3) lsl 4) lor (b lsr 4));
      enc_char m (((b land 15) lsl 2) lor (c lsr 6));
      enc_char m (c land 63) ]
  in
  let rec go (acc : char list list) (codes : int list) : string =
    match codes with
    | [] -> String.of_seq (List.to_seq (List.concat (List.rev acc)))
    | [ a ] ->
      go ([ enc_char m (a lsr 2); enc_char m ((a land 3) lsl 4) ] :: acc) []
    | [ a; b ] ->
      go
        ([ enc_char m (a lsr 2);
           enc_char m (((a land 3) lsl 4) lor (b lsr 4));
           enc_char m ((b land 15) lsl 2) ]
        :: acc)
        []
    | a :: b :: c :: rest -> go (emit3 a b c :: acc) rest
  in
  go [] (List.map Char.code (List.of_seq (String.to_seq s)))

let decode_core (m : int Cmap.t) (chars : char list) :
    (string, Errx.t) result =
  let bad (why : string) : ('a, Errx.t) result =
    Error (Errx.B64_invalid why)
  in
  (* Fold every char to its 6-bit value; group values four at a time. *)
  let step (st : (int list * int list, Errx.t) result) (c : char) :
      (int list * int list, Errx.t) result =
    let* out_rev, group = st in
    let* v =
      Option.to_result (dec_val m c)
        ~none:(Errx.B64_invalid "byte outside alphabet")
    in
    match group with
    | [ y; x; w ] ->
      (* Four 6-bit values w x y v make three bytes. Bytes are pushed most
         significant last, so out_rev stays in reverse output order. *)
      Ok
        ( (((y land 3) lsl 6) lor v)
          :: (((x land 15) lsl 4) lor (y lsr 2))
          :: ((w lsl 2) lor (x lsr 4))
          :: out_rev,
          [] )
    | short -> Ok (out_rev, v :: short)
  in
  let regroup (g_rev : int list) (out_rev : int list) :
      (string, Errx.t) result =
    (* g_rev holds the trailing partial group, most recent value first. *)
    match List.rev g_rev with
    | [] -> Ok (Bytesx.of_codes (List.rev out_rev))
    | [ _ ] -> bad "length mod 4 = 1"
    | [ a; b ] ->
      if Int.equal (b land 15) 0 then
        Ok (Bytesx.of_codes (List.rev (((a lsl 2) lor (b lsr 4)) :: out_rev)))
      else bad "non-zero trailing bits"
    | [ a; b; c ] ->
      if Int.equal (c land 3) 0 then
        Ok
          (Bytesx.of_codes
             (List.rev
                ((((b land 15) lsl 4) lor (c lsr 2))
                :: ((a lsl 2) lor (b lsr 4))
                :: out_rev)))
      else bad "non-zero trailing bits"
    | _ :: _ :: _ :: _ :: _ -> bad "internal group overflow"
  in
  let* out_rev, group = List.fold_left step (Ok ([], [])) chars in
  regroup group out_rev

let encode_url (s : string) : string =
  encode_core (enc_map_of (url_alphabet ())) s

let decode_url (s : string) : (string, Errx.t) result =
  decode_core (dec_map_of (url_alphabet ())) (List.of_seq (String.to_seq s))

let encode_std (s : string) : string =
  let body = encode_core (enc_map_of (std_alphabet ())) s in
  (* The core emits length mod 4 in {0, 2, 3}; land 3 avoids division. *)
  let pad =
    match String.length body land 3 with
    | 2 -> "=="
    | 3 -> "="
    | (_ : int) -> ""
  in
  body ^ pad

let decode_std (s : string) : (string, Errx.t) result =
  let rec split_pads (rev_chars : char list) (p : int) : char list * int =
    match rev_chars with
    | [] -> ([], p)
    | c :: rest ->
      if Char.equal c '=' then split_pads rest (p + 1) else (c :: rest, p)
  in
  let rev_body, pads =
    split_pads (List.rev (List.of_seq (String.to_seq s))) 0
  in
  let body = List.rev rev_body in
  (* An interior '=' survives the split and dies in decode_core as a
     byte outside the alphabet. *)
  match () with
  | () when pads > 2 -> Error (Errx.B64_invalid "padding too long")
  | () when Int.equal pads 0 && not (Int.equal (List.length body land 3) 0) ->
    Error (Errx.B64_invalid "missing padding")
  | () when not (Int.equal ((List.length body + pads) land 3) 0) ->
    Error (Errx.B64_invalid "padding mismatch")
  | () -> decode_core (dec_map_of (std_alphabet ())) body
