(* M13 keyx: the API key mint. Pure and total; the byte window is the
   whole domain check. ZxCaml trap 2: every scalar limit is a unit
   function. *)

type t = Key of string

let invalid (msg : string) : ('a, Errx.t) result = Error (Errx.Key_invalid msg)

(* A Venice key is a short opaque token; 512 bytes is generous and
   bounds the config line the key rides on. *)
let max_key_bytes (() : unit) : int = 512
let env_name (() : unit) : string = "VENICE_API_KEY"

let chars (s : string) : char list = List.of_seq (String.to_seq s)

(* Visible ASCII only: SP, HTAB, CR, LF, NUL, DEL and every byte with
   the high bit set reject, so no key can carry a header terminator or
   a fold into the Authorization line. *)
let printable (c : char) : bool =
  let n = Char.code c in
  n >= 0x21 && n <= 0x7E

let make (s : string) : (t, Errx.t) result =
  match () with
  | () when String.length s = 0 -> invalid "make: empty key"
  | () when String.length s > max_key_bytes () ->
    invalid
      ("make: key longer than " ^ string_of_int (max_key_bytes ()) ^ " bytes")
  | () when not (List.for_all printable (chars s)) ->
    invalid "make: key holds a byte outside 0x21..0x7E"
  | () -> Ok (Key s)

let from_env (() : unit) : (t, Errx.t) result =
  Option.fold
    ~none:(invalid ("from_env: " ^ env_name () ^ " is not set"))
    ~some:make
    (Sys.getenv_opt (env_name ()))

let reveal (Key s : t) : string = s
