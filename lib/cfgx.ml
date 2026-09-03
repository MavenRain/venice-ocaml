(* M13 cfgx: curl config rendering. Pure and total; no IO, no
   mutation. ZxCaml trap 2: every scalar and string constant a helper
   reads is a unit function. *)

let chars (s : string) : char list = List.of_seq (String.to_seq s)

(* curl -K quoting: inside a double-quoted value a backslash doubles
   and a double quote escapes. curl also reads \t \n \r \v, and a
   backslash before any other byte yields that byte, so escaping
   these two is both necessary and sufficient. The emitted JSON body
   holds no raw control byte (Jsonx.emit escapes them), so no other
   escape can ever be needed. *)
let escape_char (c : char) : string =
  match c with
  | '\\' -> "\\\\"
  | '"' -> "\\\""
  | _ -> String.make 1 c

let escape (s : string) : string =
  String.concat "" (List.map escape_char (chars s))

let opt (name : string) (value : string) : string =
  name ^ " = \"" ^ escape value ^ "\"\n"

let flag (name : string) : string = name ^ "\n"

(* Must track Venice.version; test_transport pins the two together so
   the string cannot drift. *)
let user_agent (() : unit) : string = "venice-ocaml/0.1.0"

let data_line (body : string) : string = opt "data-binary" body
let data_line_bytes (body : string) : int = String.length (data_line body)

let argv ~(binary : string) : string array = [| binary; "-q"; "-K"; "-" |]

let post_only (m : Httpx.Request.meth) : string list =
  match m with
  | Httpx.Request.Get -> []
  | Httpx.Request.Post -> [ opt "header" "Content-Type: application/json" ]

let render ~(key : Keyx.t) ~(endpoint : Httpx.Endpoint.t)
    ~(connect_timeout : int) ~(idle_timeout : int) ~(max_time : int option)
    (req : Httpx.Request.t) : string =
  String.concat ""
    (List.concat
       [ [ flag "no-progress-meter";
           flag "show-error";
           flag "no-buffer";
           flag "include";
           flag "globoff";
           opt "noproxy" "*";
           opt "proto" "=https";
           flag "tlsv1.2";
           opt "connect-timeout" (string_of_int connect_timeout);
           opt "speed-limit" "1";
           opt "speed-time" (string_of_int idle_timeout) ];
         Option.fold ~none:[]
           ~some:(fun (n : int) -> [ opt "max-time" (string_of_int n) ])
           max_time;
         [ opt "user-agent" (user_agent ());
           opt "header" ("Authorization: Bearer " ^ Keyx.reveal key);
           opt "header" "Accept: application/json";
           opt "header" "Expect:" ];
         post_only (Httpx.Request.meth req);
         List.map
           (fun ((n : string), (v : string)) -> opt "header" (n ^ ": " ^ v))
           (Httpx.Request.headers req);
         [ opt "url" (Httpx.Request.url endpoint req) ];
         Option.fold ~none:[]
           ~some:(fun (b : string) -> [ data_line b ])
           (Httpx.Request.rendered req) ])
