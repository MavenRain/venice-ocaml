(* M7 message domain. Chat messages come in two families. Branded
   values (media parts, user messages, 'c nonempty) carry the phantom
   base row 'c of the witnessed model, so a media part cannot reach a
   model whose listing never asserted the capability. Unbranded
   payloads (text and file parts, the non-user roles) carry no type
   variable, so one value binds at structure level and is reused
   across models; of_text/of_file/lift instantiate the row per use
   site. The brand is phantom over one concrete repr, the modelx
   erasure idiom; venice.mli's abstract types are the enforcement.
   Total, sans-io. *)

let ( let* ) = Result.bind

let invalid (msg : string) : ('a, Errx.t) result =
  Error (Errx.Msg_invalid msg)

module Audio_format = struct
  (* input_audio.format wire enum. The wire default is wav when the
     member is absent; emission omits an absent format. *)
  type t =
    | Wav
    | Mp3
    | Aiff
    | Aac
    | Ogg
    | Flac
    | M4a
    | Pcm16
    | Pcm24

  let to_string (f : t) : string =
    match f with
    | Wav -> "wav"
    | Mp3 -> "mp3"
    | Aiff -> "aiff"
    | Aac -> "aac"
    | Ogg -> "ogg"
    | Flac -> "flac"
    | M4a -> "m4a"
    | Pcm16 -> "pcm16"
    | Pcm24 -> "pcm24"

  let of_string (s : string) : (t, Errx.t) result =
    match s with
    | "wav" -> Ok Wav
    | "mp3" -> Ok Mp3
    | "aiff" -> Ok Aiff
    | "aac" -> Ok Aac
    | "ogg" -> Ok Ogg
    | "flac" -> Ok Flac
    | "m4a" -> Ok M4a
    | "pcm16" -> Ok Pcm16
    | "pcm24" -> Ok Pcm24
    | other -> invalid ("audio format: unknown value " ^ other)

  let default : t = Wav
end

module Cache = struct
  (* cache_control, type-only in M7: {"type":"ephemeral"}. ttl is a
     beta feature behind a header the swagger does not name (FACTS.md
     open fact), so no ttl argument exists anywhere. *)
  type t = Ephemeral

  let ephemeral : t = Ephemeral
end

module Reasoning_detail = struct
  (* One reasoning_details item, exact by construction: the record
     wraps the raw parsed object, so re-emission preserves the member
     set AND order as received (Jobj is an assoc list in parse order
     and Jsonx.emit is deterministic over it). The item schema does
     not set additionalProperties: false, so unknown members are
     wire-legal and must survive the round trip. Minted only by the
     seam function reasoning_detail_of_json below. *)
  type t =
    { rd_type : string;
      rd_raw : Jsonx.t }

  let str_member (name : string) (d : t) : string option =
    Option.bind (Jsonx.member name d.rd_raw) Jsonx.as_string

  let type_ (d : t) : string = d.rd_type
  let data (d : t) : string option = str_member "data" d
  let format (d : t) : string option = str_member "format" d
  let id (d : t) : string option = str_member "id" d
  let text (d : t) : string option = str_member "text" d

  (* The swagger says number, not integer; no int coercion. *)
  let index (d : t) : Jsonx.t option = Jsonx.member "index" d.rd_raw
end

module Thought_signature = struct
  (* Newtype over the wire string ("pass it back exactly as
     received"). Minted only by the seam function
     thought_signature_of_parsed below. *)
  type t = string
end

(* Unbranded payloads (no type variable). *)
type text_part =
  { tp_text : string;
    tp_cache : Cache.t option }

type file_part =
  { fp_data : string;
    fp_filename : string option;
    fp_cache : Cache.t option }

(* One non-user message; every role keeps the wire's optional name. *)
type msg =
  | Msystem of
      { name : string option;
        parts : text_part list }
  | Mdeveloper of
      { name : string option;
        parts : text_part list }
  | Massistant of
      { name : string option;
        content : string option;
        reasoning_content : string option;
        reasoning_details : Reasoning_detail.t list;
        thought_signature : Thought_signature.t option }
  | Mtool of
      { name : string option;
        tool_call_id : string;
        content : string }

(* Branded content parts. 'c is phantom over this repr, so parts
   minted from different witnesses of the SAME base model share one
   list. *)
type part_repr =
  | Ptext of text_part
  | Pimage of
      { url : string;
        cache : Cache.t option }
  | Paudio of
      { data : string;
        format : Audio_format.t option;
        cache : Cache.t option }
  | Pvideo of
      { url : string;
        cache : Cache.t option }
  | Pfile of file_part

type 'c part = part_repr

(* The two roles sessx may encrypt. *)
type cipher_role =
  | Cuser
  | Csystem

(* One message. Mcipher is the dedicated E2EE content case: only the
   cipher_hex seam constructs it, so the encrypted/plaintext
   distinction is a constructor distinction, not a string test. *)
type repr =
  | Muser of
      { name : string option;
        parts : part_repr list }
  | Mplain of msg
  | Mcipher of
      { role : cipher_role;
        name : string option;
        hex : string }

type 'c t = repr

(* Nonempty by mint: minItems 1 on messages holds by construction. *)
type 'c nonempty = repr list

(* Mint-time checks. *)

let alpha (c : char) : bool =
  (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')

let scheme_char (c : char) : bool =
  alpha c
  || (c >= '0' && c <= '9')
  || Char.equal c '+' || Char.equal c '-' || Char.equal c '.'

(* uri-SHAPE check, matching the schema's format: uri without doing
   the server's work: a nonempty scheme [A-Za-z][A-Za-z0-9+.-]* then
   ':'. data: URLs pass the same test. The server-only checks (64px
   floor, no-redirect, Content-Type, YouTube support) stay server-side
   facts (FACTS.md). *)
let uri_shape (s : string) : bool =
  Option.fold ~none:false
    ~some:(fun (i : int) ->
      Option.fold ~none:false
        ~some:(fun (scheme : string) ->
          Option.fold ~none:false ~some:(String.for_all alpha)
            (Bytesx.take scheme 0 1)
          && String.for_all scheme_char scheme)
        (Bytesx.take s 0 i))
    (String.index_opt s ':')

let require_uri (what : string) (s : string) : (string, Errx.t) result =
  if uri_shape s then Ok s else invalid (what ^ ": not a uri")

let require_text (what : string) (s : string) : (string, Errx.t) result =
  if String.equal s "" then invalid (what ^ ": empty") else Ok s

let nonempty_list (what : string) (items : 'a list) :
    ('a list, Errx.t) result =
  match items with
  | [] -> invalid (what ^ ": empty")
  | _ :: _ -> Ok items

(* Unbranded constructors. minLength 1 is the schema rule for text
   PARTS; the bare-string roles below reject "" as an SDK rule, and
   the empty-parts rejects are SDK-imposed strictness too (the schema
   has no minItems on parts; FACTS.md). *)

let text ?cache (s : string) : (text_part, Errx.t) result =
  let* t = require_text "text part" s in
  Ok { tp_text = t; tp_cache = cache }

let file ?filename ?cache (file_data : string) :
    (file_part, Errx.t) result =
  let* d = require_uri "file.file_data" file_data in
  Ok { fp_data = d; fp_filename = filename; fp_cache = cache }

let system ?name (s : string) : (msg, Errx.t) result =
  let* t = require_text "system content" s in
  Ok (Msystem { name; parts = [ { tp_text = t; tp_cache = None } ] })

let system_parts ?name (parts : text_part list) : (msg, Errx.t) result =
  let* ps = nonempty_list "system parts" parts in
  Ok (Msystem { name; parts = ps })

let developer ?name (s : string) : (msg, Errx.t) result =
  let* t = require_text "developer content" s in
  Ok (Mdeveloper { name; parts = [ { tp_text = t; tp_cache = None } ] })

let developer_parts ?name (parts : text_part list) :
    (msg, Errx.t) result =
  let* ps = nonempty_list "developer parts" parts in
  Ok (Mdeveloper { name; parts = ps })

(* Extensible shape: the tools milestone adds ?tool_calls as an
   optional argument, no API break. Content (or, at M10a, tool_calls)
   is still required: the M10 reasoning passthrough members alone do
   not make a legal assistant message. A passed ?reasoning_details:[]
   is accepted and emits nothing (the label behaves as omitted):
   neither schema sets minItems on reasoning_details, and the respx
   Choice projection collapses absent and [] to the same [], so the
   parse-then-passthrough call must not Error on a wire-legal
   absent-or-empty array. *)
let assistant ?name ?content ?reasoning_content ?reasoning_details
    ?thought_signature (() : unit) : (msg, Errx.t) result =
  let details : Reasoning_detail.t list =
    Option.fold ~none:[] ~some:Fun.id reasoning_details
  in
  Option.fold
    ~none:(invalid "assistant: content or tool_calls required")
    ~some:(fun (s : string) ->
      let* t = require_text "assistant content" s in
      Ok
        (Massistant
           { name;
             content = Some t;
             reasoning_content;
             reasoning_details = details;
             thought_signature }))
    content

let tool ?name ~(tool_call_id : string) (s : string) :
    (msg, Errx.t) result =
  let* t = require_text "tool content" s in
  Ok (Mtool { name; tool_call_id; content = t })

(* Branded constructors. The argument model is the witnessed model;
   the minted part erases to the PRE-extraction base row 'c. Extract
   every witness from the SAME base model (Modelx.media is the paved
   road): a part minted from a stacked witness erases to the stacked
   row and cannot share a list with base-row parts. Optional
   arguments come first: warning 16 (unerasable-optional-argument) is
   an error under the dev profile, and only a later ANONYMOUS
   argument (here the witness) erases an optional; a required
   labelled argument does not. *)

let of_text (p : text_part) : 'c part = Ptext p
let of_file (p : file_part) : 'c part = Pfile p

let image ?cache ((_ : ('c * Modelx.vision) Modelx.t)) ~(url : string) :
    ('c part, Errx.t) result =
  let* u = require_uri "image_url.url" url in
  Ok (Pimage { url = u; cache })

let audio ?format ?cache ((_ : ('c * Modelx.audio) Modelx.t))
    ~(data : string) : ('c part, Errx.t) result =
  let* (_ : string) =
    Result.map_error
      (fun ((_ : Errx.t)) ->
        Errx.Msg_invalid "input_audio.data: not base64")
      (B64x.decode_std data)
  in
  Ok (Paudio { data; format; cache })

let video ?cache ((_ : ('c * Modelx.video) Modelx.t)) ~(url : string) :
    ('c part, Errx.t) result =
  let* u = require_uri "video_url.url" url in
  Ok (Pvideo { url = u; cache })

(* Branded messages. *)

let user ?name (parts : 'c part list) : ('c t, Errx.t) result =
  let* ps = nonempty_list "user parts" parts in
  Ok (Muser { name; parts = ps })

let user_text ?name (s : string) : ('c t, Errx.t) result =
  let* t = require_text "user content" s in
  Ok (Muser { name; parts = [ Ptext { tp_text = t; tp_cache = None } ] })

let lift (m : msg) : 'c t = Mplain m

let nonempty (msgs : 'c t list) : ('c nonempty, Errx.t) result =
  nonempty_list "messages" msgs

(* Emission. Deterministic member order: role, content, tool_call_id
   (tool only), name; parts order type, payload, cache_control. The
   collapse rule is per-message: a single cache-less text part emits
   the bare-string content form, every other shape the array form.
   Tool content is always a bare string (the schema has no anyOf
   there). Assistant emits role, content, name, reasoning_content,
   reasoning_details, thought_signature: the three M10 passthrough
   members APPEND to the frozen M7 order, so every earlier golden
   stays byte-identical, and each present member emits only when
   present (reasoning_details only when nonempty, each item's raw
   Jsonx.t verbatim). *)

let cache_json (c : Cache.t) : Jsonx.t =
  match c with
  | Cache.Ephemeral -> Jsonx.Jobj [ ("type", Jsonx.Jstring "ephemeral") ]

let cache_member (c : Cache.t option) : (string * Jsonx.t) list =
  Option.fold ~none:[]
    ~some:(fun (cc : Cache.t) -> [ ("cache_control", cache_json cc) ])
    c

let opt_string (name : string) (v : string option) :
    (string * Jsonx.t) list =
  Option.fold ~none:[]
    ~some:(fun (s : string) -> [ (name, Jsonx.Jstring s) ])
    v

(* An empty passthrough list emits no member at all (D4: absent and []
   collapse); a nonempty one re-emits each item's raw object
   verbatim. *)
let details_member (ds : Reasoning_detail.t list) :
    (string * Jsonx.t) list =
  match ds with
  | [] -> []
  | _ :: _ ->
    [ ( "reasoning_details",
        Jsonx.Jlist
          (List.map
             (fun (d : Reasoning_detail.t) -> d.Reasoning_detail.rd_raw)
             ds) )
    ]

let emit_text_part (p : text_part) : Jsonx.t =
  Jsonx.Jobj
    ([ ("type", Jsonx.Jstring "text"); ("text", Jsonx.Jstring p.tp_text) ]
     @ cache_member p.tp_cache)

let emit_part (p : part_repr) : Jsonx.t =
  match p with
  | Ptext tp -> emit_text_part tp
  | Pimage { url; cache } ->
    Jsonx.Jobj
      ([ ("type", Jsonx.Jstring "image_url");
         ("image_url", Jsonx.Jobj [ ("url", Jsonx.Jstring url) ]) ]
       @ cache_member cache)
  | Paudio { data; format; cache } ->
    Jsonx.Jobj
      ([ ("type", Jsonx.Jstring "input_audio");
         ( "input_audio",
           Jsonx.Jobj
             (("data", Jsonx.Jstring data)
              :: opt_string "format"
                   (Option.map Audio_format.to_string format)) ) ]
       @ cache_member cache)
  | Pvideo { url; cache } ->
    Jsonx.Jobj
      ([ ("type", Jsonx.Jstring "video_url");
         ("video_url", Jsonx.Jobj [ ("url", Jsonx.Jstring url) ]) ]
       @ cache_member cache)
  | Pfile fp ->
    Jsonx.Jobj
      ([ ("type", Jsonx.Jstring "file");
         ( "file",
           Jsonx.Jobj
             (("file_data", Jsonx.Jstring fp.fp_data)
              :: opt_string "filename" fp.fp_filename) ) ]
       @ cache_member fp.fp_cache)

(* Bare-string content iff exactly one cache-less text part. *)
let collapse_parts (parts : part_repr list) : Jsonx.t =
  match parts with
  | [ Ptext p ] when Option.is_none p.tp_cache -> Jsonx.Jstring p.tp_text
  | [] | [ _ ] | _ :: _ :: _ -> Jsonx.Jlist (List.map emit_part parts)

let collapse_text_parts (parts : text_part list) : Jsonx.t =
  match parts with
  | [ p ] when Option.is_none p.tp_cache -> Jsonx.Jstring p.tp_text
  | [] | [ _ ] | _ :: _ :: _ ->
    Jsonx.Jlist (List.map emit_text_part parts)

let role_member (r : string) : string * Jsonx.t =
  ("role", Jsonx.Jstring r)

let emit_plain (m : msg) : Jsonx.t =
  match m with
  | Msystem { name; parts } ->
    Jsonx.Jobj
      ([ role_member "system"; ("content", collapse_text_parts parts) ]
       @ opt_string "name" name)
  | Mdeveloper { name; parts } ->
    Jsonx.Jobj
      ([ role_member "developer"; ("content", collapse_text_parts parts) ]
       @ opt_string "name" name)
  | Massistant
      { name; content; reasoning_content; reasoning_details;
        thought_signature } ->
    Jsonx.Jobj
      ((role_member "assistant" :: opt_string "content" content)
       @ opt_string "name" name
       @ opt_string "reasoning_content" reasoning_content
       @ details_member reasoning_details
       @ opt_string "thought_signature" thought_signature)
  | Mtool { name; tool_call_id; content } ->
    Jsonx.Jobj
      ([ role_member "tool";
         ("content", Jsonx.Jstring content);
         ("tool_call_id", Jsonx.Jstring tool_call_id) ]
       @ opt_string "name" name)

let cipher_role_string (r : cipher_role) : string =
  match r with
  | Cuser -> "user"
  | Csystem -> "system"

let emit_message (m : 'c t) : Jsonx.t =
  match m with
  | Muser { name; parts } ->
    Jsonx.Jobj
      ([ role_member "user"; ("content", collapse_parts parts) ]
       @ opt_string "name" name)
  | Mplain p -> emit_plain p
  (* E2EE: content is a bare hex string regardless of the original
     part count. *)
  | Mcipher { role; name; hex } ->
    Jsonx.Jobj
      ([ role_member (cipher_role_string role);
         ("content", Jsonx.Jstring hex) ]
       @ opt_string "name" name)

let emit (msgs : 'c nonempty) : Jsonx.t =
  Jsonx.Jlist (List.map emit_message msgs)

(* Internal seam for sessx, chatx and respx (and the tests);
   venice.mli does not re-export it. *)

let part_text (p : part_repr) : string option =
  match p with
  | Ptext tp -> Some tp.tp_text
  | Pimage _ | Paudio _ | Pvideo _ | Pfile _ -> None

let texts_of (parts : part_repr list) : string list option =
  Option.map List.rev
    (List.fold_left
       (fun acc p ->
         Option.bind acc (fun xs ->
             Option.map (fun t -> t :: xs) (part_text p)))
       (Some []) parts)

(* Plaintext projection: the content sessx encrypts. Some only for a
   user message whose parts are all text and for system messages;
   None for every other role and for already-ciphered content. *)
let content_plaintext (m : 'c t) : string option =
  match m with
  | Muser { name = _; parts } ->
    Option.map (String.concat "") (texts_of parts)
  | Mplain (Msystem { name = _; parts }) ->
    Some
      (String.concat ""
         (List.map (fun (p : text_part) -> p.tp_text) parts))
  | Mplain (Mdeveloper _) | Mplain (Massistant _) | Mplain (Mtool _)
  | Mcipher _ ->
    None

(* sessx-only mint for the Mcipher content case: replace user/system
   content with hex ciphertext; every other role is an error. The hex
   bytes are sessx's responsibility. *)
let cipher_hex (m : 'c t) ~(hex : string) : ('c t, Errx.t) result =
  match m with
  | Muser { name; parts = _ } -> Ok (Mcipher { role = Cuser; name; hex })
  | Mplain (Msystem { name; parts = _ }) ->
    Ok (Mcipher { role = Csystem; name; hex })
  | Mcipher { role; name; hex = _ } -> Ok (Mcipher { role; name; hex })
  | Mplain (Mdeveloper _) -> invalid "cipher_hex: developer role"
  | Mplain (Massistant _) -> invalid "cipher_hex: assistant role"
  | Mplain (Mtool _) -> invalid "cipher_hex: tool role"

(* Passthrough mints (D3): parse-only, named seam functions so M11
   ssex / M14 streamx can mint the identical types from delta JSON
   without routing through respx's whole-document parser. Neither
   type gets a public of_string: a Reasoning_detail.t /
   Thought_signature.t that reaches assistant from outside the
   library can only have come from a real parsed response. *)

(* Validates type present and a string; keeps every member verbatim,
   unknown members included (the item schema does not set
   additionalProperties: false). *)
let reasoning_detail_of_json (j : Jsonx.t) :
    (Reasoning_detail.t, Errx.t) result =
  Option.fold
    ~none:(invalid "reasoning_detail: not an object")
    ~some:(fun ((_ : (string * Jsonx.t) list)) ->
      Option.fold
        ~none:(invalid "reasoning_detail: type: missing")
        ~some:(fun ty ->
          Option.fold
            ~none:(invalid "reasoning_detail: type: not a string")
            ~some:(fun (s : string) ->
              Ok { Reasoning_detail.rd_type = s; rd_raw = j })
            (Jsonx.as_string ty))
        (Jsonx.member "type" j))
    (Jsonx.as_obj j)

let thought_signature_of_parsed (s : string) : Thought_signature.t = s
