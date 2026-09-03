(* M13 httpx: endpoint, route index and request mint. Pure, total, no
   mutation. Byte scanning goes through one char-list conversion per
   string (the ssex A9 rule) and pieces join with String.concat.
   ZxCaml trap 2: every scalar limit is a unit function. *)

let ( let* ) = Result.bind
let invalid (msg : string) : ('a, Errx.t) result = Error (Errx.Req_invalid msg)
let chars (s : string) : char list = List.of_seq (String.to_seq s)

module Endpoint = struct
  type t = Endpoint of string

  let max_endpoint_bytes (() : unit) : int = 2048
  let scheme (() : unit) : string = "https://"

  (* Anything that could split the URL into a second target, plus the
     whole non-visible-ASCII range. *)
  let bad_byte (c : char) : bool =
    let n = Char.code c in
    n < 0x21 || n > 0x7E || Char.equal c '?' || Char.equal c '#'
    || Char.equal c '"' || Char.equal c '\\'

  (* Total tail: None when the prefix does not fit. *)
  let after_scheme (s : string) : string option =
    let n = String.length (scheme ()) in
    Bytesx.take s n (String.length s - n)

  let host_ok (s : string) : bool =
    Option.fold ~none:false
      ~some:(fun (h : string) ->
        String.length h > 0 && not (String.starts_with ~prefix:"/" h))
      (after_scheme s)

  let default : t = Endpoint "https://api.venice.ai/api/v1"

  let of_string (s : string) : (t, Errx.t) result =
    match () with
    | () when String.length s > max_endpoint_bytes () ->
      invalid
        ("endpoint: longer than "
        ^ string_of_int (max_endpoint_bytes ())
        ^ " bytes")
    | () when not (String.starts_with ~prefix:(scheme ()) s) ->
      invalid ("endpoint: must start with " ^ scheme ())
    | () when String.ends_with ~suffix:"/" s ->
      invalid "endpoint: trailing slash"
    | () when List.exists bad_byte (chars s) ->
      invalid "endpoint: forbidden byte"
    | () when not (host_ok s) -> invalid "endpoint: empty host segment"
    | () -> Ok (Endpoint s)

  let to_string (Endpoint s : t) : string = s
end

module Route = struct
  (* Uninhabited method markers. *)
  type get
  type post

  type raw =
    | Chat_completions
    | Models
    | Tee_attestation
    | Tee_signature

  (* 'm is phantom: the alias erases it inside the library and
     httpx.mli re-abstracts it, which is where the guarantee lives.
     A consumer can neither forge a marker nor cast one route to the
     other method. *)
  type 'm t = raw

  let chat_completions : post t = Chat_completions
  let models : get t = Models
  let tee_attestation : get t = Tee_attestation
  let tee_signature : get t = Tee_signature

  let path (r : 'm t) : string =
    match r with
    | Chat_completions -> "/chat/completions"
    | Models -> "/models"
    | Tee_attestation -> "/tee/attestation"
    | Tee_signature -> "/tee/signature"
end

module Request = struct
  type meth =
    | Get
    | Post

  type t =
    { meth : meth;
      path : string;
      query : (string * string) list;
      headers : (string * string) list;
      body : Jsonx.t option;
      rendered : string option }

  let max_query_pairs (() : unit) : int = 16
  let max_headers (() : unit) : int = 32
  let max_name_bytes (() : unit) : int = 128
  let max_value_bytes (() : unit) : int = 8192

  (* A13: 4 MiB raw, which is 2x-safe under the 10 MiB curl
     config-line cap even when every body byte escapes to two. *)
  let max_body_bytes (() : unit) : int = 4_194_304

  (* Headers curl owns, headers the transport owns, and headers whose
     duplication changes the request meaning. The check is
     case-insensitive because names lower first. *)
  let reserved (() : unit) : string list =
    [ "authorization"; "proxy-authorization"; "cookie"; "content-type";
      "content-length"; "host"; "expect"; "transfer-encoding"; "connection";
      "accept"; "accept-encoding"; "user-agent" ]

  (* ---------- percent encoding (RFC 3986) ---------- *)

  let unreserved (c : char) : bool =
    match c with
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '.' | '_' | '~' -> true
    | _ -> false

  (* Uppercase hex per RFC 3986 section 2.1; Hexx emits lowercase, so
     the one uppercase step happens here and nowhere else. *)
  let pct_byte (c : char) : string =
    if unreserved c then String.make 1 c
    else "%" ^ String.uppercase_ascii (Hexx.encode (String.make 1 c))

  let pct_encode (s : string) : string =
    String.concat "" (List.map pct_byte (chars s))

  let query_string (q : (string * string) list) : string =
    match q with
    | [] -> ""
    | (_, _) :: _ ->
      "?"
      ^ String.concat "&"
          (List.map
             (fun ((k : string), (v : string)) ->
               pct_encode k ^ "=" ^ pct_encode v)
             q)

  (* ---------- query checks ---------- *)

  let check_pair (seen : string list) ((k : string), (v : string)) :
      (string list, Errx.t) result =
    match () with
    | () when String.length k = 0 -> invalid "query: empty key"
    | () when not (List.for_all unreserved (chars k)) ->
      invalid ("query: key holds a reserved byte: " ^ k)
    | () when List.exists (String.equal k) seen ->
      invalid ("query: duplicate key " ^ k)
    | () ->
      let (_ : string) = v in
      Ok (k :: seen)

  let check_query (q : (string * string) list) :
      ((string * string) list, Errx.t) result =
    match () with
    | () when List.length q > max_query_pairs () ->
      invalid
        ("query: more than "
        ^ string_of_int (max_query_pairs ())
        ^ " pairs")
    | () ->
      Result.map
        (fun ((_ : string list)) -> q)
        (List.fold_left
           (fun (acc : (string list, Errx.t) result) (pair : string * string) ->
             let* seen = acc in
             check_pair seen pair)
           (Ok []) q)

  (* ---------- header checks (A4) ---------- *)

  let tchar (c : char) : bool =
    match c with
    | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' -> true
    | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_'
    | '`' | '|' | '~' ->
      true
    | _ -> false

  let norm_name (n : string) : (string, Errx.t) result =
    match () with
    | () when String.length n = 0 -> invalid "header: empty name"
    | () when String.length n > max_name_bytes () ->
      invalid
        ("header: name longer than "
        ^ string_of_int (max_name_bytes ())
        ^ " bytes")
    | () when not (List.for_all tchar (chars n)) ->
      invalid ("header: name holds a non-token byte: " ^ n)
    | () -> Ok (String.lowercase_ascii n)

  let value_byte (c : char) : bool =
    let n = Char.code c in
    (n >= 0x20 && n <= 0x7E) || n = 0x09

  let ws_code (n : int) : bool = n = 0x20 || n = 0x09

  let edge_ws (v : string) : bool =
    Option.fold ~none:false ~some:ws_code (Bytesx.u8 v 0)
    || Option.fold ~none:false ~some:ws_code
         (Bytesx.u8 v (String.length v - 1))

  let check_value (v : string) : (string, Errx.t) result =
    match () with
    | () when String.length v = 0 -> invalid "header: empty value"
    | () when String.length v > max_value_bytes () ->
      invalid
        ("header: value longer than "
        ^ string_of_int (max_value_bytes ())
        ^ " bytes")
    | () when not (List.for_all value_byte (chars v)) ->
      invalid "header: value byte outside 0x20..0x7E and HTAB"
    | () when edge_ws v ->
      invalid "header: value has leading or trailing whitespace"
    | () -> Ok v

  let add_header (acc : (string * string) list) ((n : string), (v : string)) :
      ((string * string) list, Errx.t) result =
    let* name = norm_name n in
    let* value = check_value v in
    match () with
    | () when List.exists (String.equal name) (reserved ()) ->
      invalid ("header: reserved name " ^ name)
    | () when List.mem_assoc name acc ->
      invalid ("header: duplicate name " ^ name)
    | () -> Ok ((name, value) :: acc)

  let norm_headers (h : (string * string) list) :
      ((string * string) list, Errx.t) result =
    match () with
    | () when List.length h > max_headers () ->
      invalid
        ("header: more than " ^ string_of_int (max_headers ()) ^ " headers")
    | () ->
      Result.map List.rev
        (List.fold_left
           (fun (acc : ((string * string) list, Errx.t) result)
                (pair : string * string) ->
             let* kept = acc in
             add_header kept pair)
           (Ok []) h)

  (* ---------- mints ---------- *)

  let get ?(query : (string * string) list = [])
      ?(headers : (string * string) list = []) (r : Route.get Route.t) :
      (t, Errx.t) result =
    let* q = check_query query in
    let* h = norm_headers headers in
    Ok
      { meth = Get;
        path = Route.path r;
        query = q;
        headers = h;
        body = None;
        rendered = None }

  let post ?(headers : (string * string) list = [])
      (r : Route.post Route.t) ~(body : Jsonx.t) : (t, Errx.t) result =
    let* h = norm_headers headers in
    let emitted = Jsonx.emit body in
    let* (() : unit) =
      match () with
      | () when String.length emitted > max_body_bytes () ->
        invalid
          ("post: body " ^ string_of_int (String.length emitted)
         ^ " bytes exceeds the "
          ^ string_of_int (max_body_bytes ())
          ^ " byte cap")
      | () -> Ok ()
    in
    Ok
      { meth = Post;
        path = Route.path r;
        query = [];
        headers = h;
        body = Some body;
        rendered = Some emitted }

  (* ---------- projections ---------- *)

  let meth (r : t) : meth = r.meth
  let path (r : t) : string = r.path
  let query (r : t) : (string * string) list = r.query
  let headers (r : t) : (string * string) list = r.headers
  let body (r : t) : Jsonx.t option = r.body
  let rendered (r : t) : string option = r.rendered
  let body_bytes (r : t) : int = Option.fold ~none:0 ~some:String.length r.rendered

  let meth_string (m : meth) : string =
    match m with
    | Get -> "GET"
    | Post -> "POST"

  let url (e : Endpoint.t) (r : t) : string =
    Endpoint.to_string e ^ r.path ^ query_string r.query

  let to_log (r : t) : string =
    meth_string r.meth ^ " " ^ r.path ^ query_string r.query ^ " headers=["
    ^ String.concat ";"
        (List.map (fun ((n : string), (_ : string)) -> n) r.headers)
    ^ "] body_bytes="
    ^ string_of_int (body_bytes r)
end
