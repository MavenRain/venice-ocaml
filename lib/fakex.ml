(* M13 fakex: the scripted transport. HOST unit: the script cursor,
   the recorded requests and the per-body chunk cursor are refs. *)

type answer =
  { head_bytes : string; chunks : string list; close_error : string option }

(* M15 D10: a script slot is either a scripted ANSWER or a scripted
   REFUSAL. A refusal records the request and hands the error back, so
   an end-to-end suite can script a transport failure between two
   answers without a second transport. *)
type exchange =
  | Answer of answer
  | Refusal of Errx.t

type t = { script : exchange list ref; recorded : Httpx.Request.t list ref }

type body =
  { pending : string list ref;
    scripted_error : string option;
    closed : bool ref;
    (* M14 A5: read and close counters. Fake close is idempotent, so
       "closed exactly once" is otherwise unobservable and the
       close-twice mutant survives. *)
    reads : int ref;
    closes : int ref }

let read_all_cap (() : unit) : int = 8_388_608

let exchange ~(head : string) ~(chunks : string list)
    ?(close_error : string option) (() : unit) : exchange =
  Answer { head_bytes = head; chunks; close_error }

let refusal (e : Errx.t) : exchange = Refusal e

let make (script : exchange list) : t =
  { script = ref script; recorded = ref [] }

let requests (t : t) : Httpx.Request.t list = List.rev !(t.recorded)

let transport (msg : string) : ('a, Errx.t) result =
  Error (Errx.Transport_failed msg)

let parse_head (raw : string) : (Wirex.head * string, Errx.t) result =
  Result.bind (Wirex.make ()) (fun (m : Wirex.t) ->
      Result.bind (Wirex.feed m raw) (fun (s : Wirex.step) ->
          match s with
          | Wirex.More (_ : Wirex.t) ->
            Error
              (Errx.Wire_invalid "fake: the scripted head is incomplete")
          | Wirex.Head (h, rest) -> Ok (h, rest)))

let leading (rest : string) : string list =
  match String.length rest with
  | 0 -> []
  | _ -> [ rest ]

let pop (t : t) : (exchange, Errx.t) result =
  match !(t.script) with
  | [] -> transport "fake: script exhausted"
  | e :: tl ->
    t.script := tl;
    Ok e

let send (t : t) ~(key : Keyx.t) (req : Httpx.Request.t) :
    (Wirex.head * body, Errx.t) result =
  let (_ : Keyx.t) = key in
  Result.bind (pop t) (fun (e : exchange) ->
      match e with
      | Refusal err ->
        (* The request still counts: requests lists every send, refused
           or not, so a retry ledger can be read off it. *)
        t.recorded := req :: !(t.recorded);
        Error err
      | Answer a ->
        Result.map
          (fun ((h : Wirex.head), (rest : string)) ->
            t.recorded := req :: !(t.recorded);
            ( h,
              { pending = ref (List.append (leading rest) a.chunks);
                scripted_error = a.close_error;
                closed = ref false;
                reads = ref 0;
                closes = ref 0 } ))
          (parse_head a.head_bytes))

let read (b : body) : (string option, Errx.t) result =
  b.reads := !(b.reads) + 1;
  match !(b.pending) with
  | [] -> Ok None
  | c :: tl ->
    b.pending := tl;
    Ok (Some c)

let read_all ?(cap : int = read_all_cap ()) (b : body) :
    (string, Errx.t) result =
  let rec go (acc : string list) (n : int) : (string, Errx.t) result =
    Result.bind (read b) (fun (o : string option) ->
        Option.fold
          ~none:(fun (() : unit) -> Ok (String.concat "" (List.rev acc)))
          ~some:(fun (c : string) (() : unit) ->
            let n2 = n + String.length c in
            match () with
            | () when n2 > cap ->
              transport
                ("read_all: body exceeds " ^ string_of_int cap ^ " bytes")
            | () -> go (c :: acc) n2)
          o ())
  in
  go [] 0

let reads (b : body) : int = !(b.reads)
let closes (b : body) : int = !(b.closes)

let close (b : body) : (unit, Errx.t) result =
  b.closes := !(b.closes) + 1;
  match !(b.closed) with
  | true -> Ok ()
  | false ->
    b.closed := true;
    Option.fold ~none:(Ok ())
      ~some:(fun (m : string) -> Error (Errx.Transport_failed m))
      b.scripted_error
