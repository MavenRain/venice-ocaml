(* M14 accumulator (D1, D7, D8). The ledger lives in accx.mli. Pure,
   total, no mutation: every stage threads a record. *)

let ( let* ) (r : ('a, Errx.t) result) (f : 'a -> ('b, Errx.t) result) :
    ('b, Errx.t) result =
  Result.bind r f

let invalid (what : string) : ('a, Errx.t) result =
  Error (Errx.Stream_invalid what)

(* Caps as unit thunks: a top-level constant is invisible inside a
   helper in the omlz backend (ZXCAML.md trap 2), and both caps count
   DISTINCT KEYS (A8). *)
let max_choices (() : unit) : int = 128
let max_tool_calls (() : unit) : int = 64

let req (what : string) (o : 'a option) : ('a, Errx.t) result =
  Option.fold
    ~none:(fun (() : unit) -> invalid (what ^ " missing"))
    ~some:(fun (v : 'a) (() : unit) -> Ok v)
    o ()

let keep_str (what : string) (cur : string option) (seen : string) :
    (string option, Errx.t) result =
  Option.fold
    ~none:(fun (() : unit) -> Ok (Some seen))
    ~some:(fun (old : string) (() : unit) ->
      match String.equal old seen with
      | true -> Ok (Some old)
      | false -> invalid (what ^ " changed"))
    cur ()

let keep_int (what : string) (cur : int option) (seen : int) :
    (int option, Errx.t) result =
  Option.fold
    ~none:(fun (() : unit) -> Ok (Some seen))
    ~some:(fun (old : int) (() : unit) ->
      match Int.equal old seen with
      | true -> Ok (Some old)
      | false -> invalid (what ^ " changed"))
    cur ()

let prepend (pieces : string list) (o : string option) : string list =
  Option.fold
    ~none:(fun (() : unit) -> pieces)
    ~some:(fun (s : string) (() : unit) -> s :: pieces)
    o ()

(* The pieces join ONCE, in received order. No piece at all reads
   None; a single "" piece reads Some "" (faithful, and
   concatenation-neutral). *)
let join (pieces_rev : string list) : string option =
  match pieces_rev with
  | [] -> None
  | _ :: _ -> Some (String.concat "" (List.rev pieces_rev))

let rec fold_res (f : 'a -> 'b -> ('a, Errx.t) result) (acc : 'a)
    (xs : 'b list) : ('a, Errx.t) result =
  match xs with
  | [] -> Ok acc
  | x :: tl -> Result.bind (f acc x) (fun (a2 : 'a) -> fold_res f a2 tl)

let map_res (f : 'a -> ('b, Errx.t) result) (xs : 'a list) :
    ('b list, Errx.t) result =
  Result.map List.rev
    (fold_res
       (fun (acc : 'b list) (x : 'a) ->
         Result.map (fun (y : 'b) -> y :: acc) (f x))
       [] xs)

let path_of (index : int) : string =
  "choices[" ^ string_of_int index ^ "]"

let frag_path (path : string) (index : int) : string =
  path ^ ".tool_calls[" ^ string_of_int index ^ "]"

(* One open tool call, keyed by the wire fragment index. *)
type frag =
  { f_index : int;
    f_id : string;
    f_name : string option;
    f_args_rev : string list }

(* One choice under accumulation. Newest fragment first; finish
   orders. *)
type ch =
  { c_index : int;
    c_role : string option;
    c_content_rev : string list;
    c_reasoning_rev : string list;
    c_frags : frag list;
    c_finish_raw : string option;
    c_stop_raw : string option }

type t =
  { n : int;
    t_id : string option;
    t_model : string option;
    t_created : int option;
    t_choices : ch list;
    t_usage : Respx.Usage.t option;
    t_usage_raw : Jsonx.t option;
    t_venice_raw : Jsonx.t option }

let empty : t =
  { n = 0;
    t_id = None;
    t_model = None;
    t_created = None;
    t_choices = [];
    t_usage = None;
    t_usage_raw = None;
    t_venice_raw = None }

let chunks (a : t) : int = a.n

let fresh_choice (index : int) : ch =
  { c_index = index;
    c_role = None;
    c_content_rev = [];
    c_reasoning_rev = [];
    c_frags = [];
    c_finish_raw = None;
    c_stop_raw = None }

let find_frag (frags : frag list) (index : int) : frag option =
  List.find_opt (fun (x : frag) -> Int.equal x.f_index index) frags

let put_frag (frags : frag list) (f : frag) : frag list =
  f
  :: List.filter
       (fun (x : frag) -> not (Int.equal x.f_index f.f_index))
       frags

(* A fragment with no open call needs an id: an arguments-only item at
   an unseen index is a lost head, never a new call. *)
let open_frag (fpath : string) (frags : frag list) (index : int)
    (item : Ssex.Chunk.Delta.fragment) : (frag list, Errx.t) result =
  Option.fold
    ~none:(fun (() : unit) ->
      invalid (fpath ^ ": continuation with no open call"))
    ~some:(fun (id : string) (() : unit) ->
      match List.length frags >= max_tool_calls () with
      | true -> invalid (fpath ^ ": too many tool_calls")
      | false ->
        Ok
          ({ f_index = index;
             f_id = id;
             f_name = Ssex.Chunk.Delta.fragment_name item;
             f_args_rev =
               prepend [] (Ssex.Chunk.Delta.fragment_arguments item)
           }
          :: frags))
    (Ssex.Chunk.Delta.fragment_id item) ()

let extend_frag (fpath : string) (frags : frag list) (cur : frag)
    (item : Ssex.Chunk.Delta.fragment) : (frag list, Errx.t) result =
  let* id =
    Option.fold
      ~none:(fun (() : unit) -> Ok cur.f_id)
      ~some:(fun (seen : string) (() : unit) ->
        match String.equal seen cur.f_id with
        | true -> Ok cur.f_id
        | false -> invalid (fpath ^ ": id changed"))
      (Ssex.Chunk.Delta.fragment_id item) ()
  in
  let name =
    Option.fold
      ~none:(fun (() : unit) -> Ssex.Chunk.Delta.fragment_name item)
      ~some:(fun (n : string) (() : unit) -> Some n)
      cur.f_name ()
  in
  Ok
    (put_frag frags
       { cur with
         f_id = id;
         f_name = name;
         f_args_rev =
           prepend cur.f_args_rev
             (Ssex.Chunk.Delta.fragment_arguments item)
       })

let step_frag (path : string) (frags : frag list)
    (item : Ssex.Chunk.Delta.fragment) : (frag list, Errx.t) result =
  let index = Ssex.Chunk.Delta.fragment_index item in
  let fpath = frag_path path index in
  Option.fold
    ~none:(fun (() : unit) -> open_frag fpath frags index item)
    ~some:(fun (cur : frag) (() : unit) ->
      extend_frag fpath frags cur item)
    (find_frag frags index) ()

let step_delta (c : ch) (d : Ssex.Chunk.Delta.t) : (ch, Errx.t) result =
  let path = path_of c.c_index in
  let* role =
    Option.fold
      ~none:(fun (() : unit) -> Ok c.c_role)
      ~some:(fun (r : string) (() : unit) ->
        keep_str (path ^ ".delta.role") c.c_role r)
      (Ssex.Chunk.Delta.role d) ()
  in
  let* items = Ssex.Chunk.Delta.tool_call_fragments d in
  let* frags = fold_res (step_frag path) c.c_frags items in
  Ok
    { c with
      c_role = role;
      c_content_rev = prepend c.c_content_rev (Ssex.Chunk.Delta.content d);
      c_reasoning_rev =
        prepend c.c_reasoning_rev (Ssex.Chunk.Delta.reasoning_content d);
      c_frags = frags
    }

(* finish_reason and stop_reason stay RAW here: the closed enum reads
   them on demand (A7), so a foreign value never destroys the fold. *)
let keep_raw_enum (what : string) (cur : string option)
    (raw : Jsonx.t option) : (string option, Errx.t) result =
  Option.fold
    ~none:(fun (() : unit) -> Ok cur)
    ~some:(fun (v : Jsonx.t) (() : unit) ->
      Option.fold
        ~none:(fun (() : unit) -> invalid (what ^ ": not a string"))
        ~some:(fun (s : string) (() : unit) -> keep_str what cur s)
        (Jsonx.as_string v) ())
    raw ()

let step_choice (a : t) (sc : Ssex.Chunk.Choice.t) : (t, Errx.t) result =
  let index = Ssex.Chunk.Choice.index sc in
  let seen =
    List.find_opt (fun (x : ch) -> Int.equal x.c_index index) a.t_choices
  in
  let* c =
    Option.fold
      ~none:(fun (() : unit) ->
        match List.length a.t_choices >= max_choices () with
        | true -> invalid "too many choices"
        | false -> Ok (fresh_choice index))
      ~some:(fun (cur : ch) (() : unit) -> Ok cur)
      seen ()
  in
  let path = path_of index in
  let* c = step_delta c (Ssex.Chunk.Choice.delta sc) in
  let* finish_raw =
    keep_raw_enum (path ^ ".finish_reason") c.c_finish_raw
      (Ssex.Chunk.Choice.finish_reason_raw sc)
  in
  let* stop_raw =
    keep_raw_enum (path ^ ".stop_reason") c.c_stop_raw
      (Ssex.Chunk.Choice.stop_reason_raw sc)
  in
  Ok
    { a with
      t_choices =
        { c with c_finish_raw = finish_raw; c_stop_raw = stop_raw }
        :: List.filter
             (fun (x : ch) -> not (Int.equal x.c_index index))
             a.t_choices
    }

let step (a : t) (c : Ssex.Chunk.t) : (t, Errx.t) result =
  let* id = keep_str "id" a.t_id (Ssex.Chunk.id c) in
  let* model = keep_str "model" a.t_model (Ssex.Chunk.model c) in
  let* created = keep_int "created" a.t_created (Ssex.Chunk.created c) in
  let usage_raw = Ssex.Chunk.usage_raw c in
  let* a2 =
    fold_res step_choice
      { a with n = a.n + 1; t_id = id; t_model = model; t_created = created }
      (Ssex.Chunk.choices c)
  in
  Ok
    { a2 with
      t_usage =
        Option.fold
          ~none:(fun (() : unit) -> a2.t_usage)
          ~some:(fun (u : Respx.Usage.t) (() : unit) -> Some u)
          (Ssex.Chunk.usage_opt c) ();
      t_usage_raw =
        Option.fold
          ~none:(fun (() : unit) -> a2.t_usage_raw)
          ~some:(fun (v : Jsonx.t) (() : unit) -> Some v)
          usage_raw ();
      t_venice_raw =
        Option.fold
          ~none:(fun (() : unit) -> Ssex.Chunk.venice_parameters_raw c)
          ~some:(fun (v : Jsonx.t) (() : unit) -> Some v)
          a2.t_venice_raw ()
    }

module Choice = struct
  type t =
    { x_index : int;
      x_role : string option;
      x_content : string option;
      x_reasoning : string option;
      x_tools : Msgx.Tool_call.t list;
      x_finish_raw : string;
      x_stop_raw : string option }

  let index (c : t) : int = c.x_index
  let role (c : t) : string option = c.x_role
  let content (c : t) : string option = c.x_content
  let reasoning_content (c : t) : string option = c.x_reasoning
  let tool_calls (c : t) : Msgx.Tool_call.t list = c.x_tools
  let finish_raw (c : t) : string = c.x_finish_raw
  let stop_reason_raw (c : t) : string option = c.x_stop_raw

  let view_enum (what : string) (read : string -> ('a, Errx.t) result)
      (s : string) : ('a, Errx.t) result =
    Result.fold
      ~ok:(fun (x : 'a) -> Ok x)
      ~error:(fun (_ : Errx.t) ->
        invalid (what ^ ": unknown value " ^ s))
      (read s)

  let finish (c : t) : (Respx.Finish.t, Errx.t) result =
    view_enum
      (path_of c.x_index ^ ".finish_reason")
      Respx.Finish.of_string c.x_finish_raw

  let stop_reason (c : t) : (Respx.Stop_reason.t option, Errx.t) result =
    Option.fold
      ~none:(fun (() : unit) -> Ok None)
      ~some:(fun (s : string) (() : unit) ->
        Result.map
          (fun (x : Respx.Stop_reason.t) -> Some x)
          (view_enum
             (path_of c.x_index ^ ".stop_reason")
             Respx.Stop_reason.of_string s))
      c.x_stop_raw ()
end

type final =
  { y_id : string;
    y_model : string;
    y_created : int;
    y_choices : Choice.t list;
    y_usage : Respx.Usage.t option;
    y_usage_raw : Jsonx.t option;
    y_venice_raw : Jsonx.t option }

let mint_tool (path : string) (f : frag) :
    (Msgx.Tool_call.t, Errx.t) result =
  let fpath = frag_path path f.f_index in
  let* name = req (fpath ^ ".function.name") f.f_name in
  Msgx.Tool_call.make ~id:f.f_id ~name
    ~arguments:(String.concat "" (List.rev f.f_args_rev))

let finish_choice (c : ch) : (Choice.t, Errx.t) result =
  let path = path_of c.c_index in
  let* finish_raw = req (path ^ ".finish_reason") c.c_finish_raw in
  let* tools =
    map_res (mint_tool path)
      (List.sort
         (fun (x : frag) (y : frag) -> Int.compare x.f_index y.f_index)
         c.c_frags)
  in
  Ok
    { Choice.x_index = c.c_index;
      x_role = c.c_role;
      x_content = join c.c_content_rev;
      x_reasoning = join c.c_reasoning_rev;
      x_tools = tools;
      x_finish_raw = finish_raw;
      x_stop_raw = c.c_stop_raw
    }

let finish (a : t) : (final, Errx.t) result =
  (* An empty fold has no document to render, and "id missing" would
     blame the wire for a caller mistake. *)
  let* (() : unit) =
    match Int.equal a.n 0 with
    | true -> invalid "no chunks"
    | false -> Ok ()
  in
  let* id = req "id" a.t_id in
  let* model = req "model" a.t_model in
  let* created = req "created" a.t_created in
  let* choices =
    map_res finish_choice
      (List.sort
         (fun (x : ch) (y : ch) -> Int.compare x.c_index y.c_index)
         a.t_choices)
  in
  Ok
    { y_id = id;
      y_model = model;
      y_created = created;
      y_choices = choices;
      y_usage = a.t_usage;
      y_usage_raw = a.t_usage_raw;
      y_venice_raw = a.t_venice_raw
    }

let id (f : final) : string = f.y_id
let model (f : final) : string = f.y_model
let created (f : final) : int = f.y_created
let choices (f : final) : Choice.t list = f.y_choices
let usage_opt (f : final) : Respx.Usage.t option = f.y_usage
let usage_raw (f : final) : Jsonx.t option = f.y_usage_raw
let venice_parameters_raw (f : final) : Jsonx.t option = f.y_venice_raw

let member (name : string) (v : Jsonx.t option) : (string * Jsonx.t) list =
  Option.fold
    ~none:(fun (() : unit) -> [])
    ~some:(fun (j : Jsonx.t) (() : unit) -> [ (name, j) ])
    v ()

let tool_calls_member (calls : Msgx.Tool_call.t list) :
    (string * Jsonx.t) list =
  match calls with
  | [] -> []
  | _ :: _ ->
    [ ("tool_calls", Jsonx.Jlist (List.map Msgx.Tool_call.to_json calls)) ]

(* The accumulated role is emitted verbatim (A7); "assistant" is a
   default for a stream that never sent one, never an override. *)
let message_json (c : Choice.t) : Jsonx.t =
  Jsonx.Jobj
    ([ ("role",
         Jsonx.Jstring
           (Option.value ~default:"assistant" (Choice.role c)));
       ("content",
         Option.fold
           ~none:(fun (() : unit) -> Jsonx.Jnull)
           ~some:(fun (s : string) (() : unit) -> Jsonx.Jstring s)
           (Choice.content c) ())
     ]
    @ member "reasoning_content"
        (Option.map
           (fun (s : string) -> Jsonx.Jstring s)
           (Choice.reasoning_content c))
    @ tool_calls_member (Choice.tool_calls c))

let choice_json (c : Choice.t) : Jsonx.t =
  Jsonx.Jobj
    [ ("index", Jsonx.Jint (Choice.index c));
      ("message", message_json c);
      ("finish_reason", Jsonx.Jstring (Choice.finish_raw c))
    ]

(* venice_parameters renders LAST, after usage (A15). *)
let to_json (f : final) : Jsonx.t =
  Jsonx.Jobj
    ([ ("id", Jsonx.Jstring f.y_id);
       ("object", Jsonx.Jstring "chat.completion");
       ("created", Jsonx.Jint f.y_created);
       ("model", Jsonx.Jstring f.y_model);
       ("choices", Jsonx.Jlist (List.map choice_json f.y_choices))
     ]
    @ member "usage" f.y_usage_raw
    @ member "venice_parameters" f.y_venice_raw)

let to_response (f : final) : (Respx.t, Errx.t) result =
  Respx.of_string (Jsonx.emit (to_json f))
