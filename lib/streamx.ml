(* M14 PULL streaming (D1-D6). The ledger lives in streamx.mli. This
   is a HOST module: it holds the one effect handler, the one ref and
   the one Fun.protect bracket of the repo, so the core modules stay
   pure. *)

module type S = sig
  type t
  type body

  val send :
    t -> key:Keyx.t -> Httpx.Request.t -> (Wirex.head * body, Errx.t) result

  val read : body -> (string option, Errx.t) result
  val read_all : ?cap:int -> body -> (string, Errx.t) result
  val close : body -> (unit, Errx.t) result
end

type outcome =
  | Complete
  | Cut
  | Failed of Errx.t

(* The ONE effect, sealed: streamx.mli publishes no constructor, so
   no caller can perform a Delta and no caller can handle one. *)
type _ Effect.t += Delta : Ssex.Chunk.t -> unit Effect.t

(* The driver step, closed: one yielded chunk with its one-shot
   continuation, or the settled outcome. *)
type step =
  | Yielded of Ssex.Chunk.t * (unit, step) Effect.Deep.continuation
  | Finished of outcome

(* The post-[DONE] phase; a sum type, not a bool flag. *)
type phase =
  | Before_done
  | After_done

(* The whole mutable state of a run, in ONE cell. pending is the
   suspended producer, queued the chunk already produced for the next
   next, closed the exactly-once close latch, and settled the outcome
   the exit routine wrote. The two drain counts ride here too (A3),
   so the run has exactly one mutable cell. *)
type state =
  { pending : (unit, step) Effect.Deep.continuation option;
    queued : Ssex.Chunk.t option;
    closed : bool;
    settled : outcome;
    drain_reads_n : int;
    drain_bytes_n : int }

type cursor = { take : unit -> Ssex.Chunk.t option }

let next (c : cursor) : Ssex.Chunk.t option = c.take ()

let rec iter (c : cursor) (f : Ssex.Chunk.t -> unit) : unit =
  Option.fold
    ~none:(fun (() : unit) -> ())
    ~some:(fun (x : Ssex.Chunk.t) (() : unit) ->
      f x;
      iter c f)
    (next c) ()

let rec fold (c : cursor) ~(init : 's) ~(f : 's -> Ssex.Chunk.t -> 's) : 's =
  Option.fold
    ~none:(fun (() : unit) -> init)
    ~some:(fun (x : Ssex.Chunk.t) (() : unit) -> fold c ~init:(f init x) ~f)
    (next c) ()

let collect (c : cursor) : (Accx.final, Errx.t) result =
  let rec go (a : Accx.t) : (Accx.final, Errx.t) result =
    Option.fold
      ~none:(fun (() : unit) -> Accx.finish a)
      ~some:(fun (x : Ssex.Chunk.t) (() : unit) ->
        Result.bind (Accx.step a x) go)
      (next c) ()
  in
  go Accx.empty

(* The handler is a constant: effc alone, with the implicit identity
   value handler and the implicit re-raising exception handler
   (effect.mli, the 'a effect_handler record). The typed wildcard arm
   is the ONE wildcard this repo allows: Effect.t is an OPEN type, so
   no exhaustive match over it exists, and every effect but our own
   Delta must fall through to the enclosing handler untouched. *)
let handler : step Effect.Deep.effect_handler =
  { Effect.Deep.effc =
      (fun (type c) (e : c Effect.t) ->
        match e with
        | Delta chunk ->
          Some
            (fun (k : (c, step) Effect.Deep.continuation) ->
              Yielded (chunk, k))
        | (_ : c Effect.t) -> None)
  }

module Make (T : S) = struct
  (* Post-[DONE] drain caps (A3), as unit thunks. *)
  let drain_reads (() : unit) : int = 4096
  let drain_bytes (() : unit) : int = 1_048_576

  let run ?closing ?max_line_bytes ?max_event_bytes (body : T.body)
      (consume : cursor -> 'a) : 'a * outcome =
    (* The ONE ref of the unit. *)
    let st =
      ref
        { pending = None;
          queued = None;
          closed = false;
          settled = Cut;
          drain_reads_n = 0;
          drain_bytes_n = 0
        }
    in
    (* The single exit routine (A1 poisoning + A13 release). It writes
       the dead-cursor state, closes the body at most once and returns
       the settled outcome. Every exit path calls it, the Fun.protect
       finally included; a second call keeps the settled outcome and
       never closes again. A close failure WINS over the outcome it
       was given (D4). *)
    let release (o : outcome) : outcome =
      let s = !st in
      match s.closed with
      | true ->
        st := { s with pending = None; queued = None };
        s.settled
      | false ->
        let settled =
          Result.fold
            ~ok:(fun (() : unit) -> o)
            ~error:(fun (e : Errx.t) -> Failed e)
            (T.close body)
        in
        st :=
          { s with pending = None; queued = None; closed = true; settled };
        settled
    in
    (* The producer. It reads, feeds, parses and performs one Delta
       per chunk, in that order (D4); the handler suspends it at the
       perform. *)
    let rec read_step (m : Ssex.t) (ph : phase) : outcome =
      Result.fold
        ~error:(fun (e : Errx.t) -> release (Failed e))
        ~ok:(fun (o : string option) ->
          Option.fold
            ~none:(fun (() : unit) -> at_eof m)
            ~some:(fun (bytes : string) (() : unit) -> got_bytes m ph bytes)
            o ())
        (T.read body)
    and got_bytes (m : Ssex.t) (ph : phase) (bytes : string) : outcome =
      let s = !st in
      let counted =
        match ph with
        | Before_done -> s.drain_bytes_n
        | After_done -> s.drain_bytes_n + String.length bytes
      in
      st := { s with drain_bytes_n = counted };
      Result.fold
        ~error:(fun (e : Errx.t) -> release (Failed e))
        ~ok:(fun ((m2 : Ssex.t), (evs : Ssex.event list)) ->
          dispatch m2 ph evs)
        (Ssex.feed m bytes)
    and dispatch (m : Ssex.t) (ph : phase) (evs : Ssex.event list) : outcome =
      match evs with
      | [] -> pump m ph
      | Ssex.Done :: tl -> dispatch m After_done tl
      | Ssex.Data payload :: tl ->
        Result.fold
          ~error:(fun (e : Errx.t) -> release (Failed e))
          ~ok:(fun (c : Ssex.Chunk.t) ->
            Effect.perform (Delta c);
            dispatch m ph tl)
          (Ssex.Chunk.of_string payload)
    and pump (m : Ssex.t) (ph : phase) : outcome =
      match ph with
      | Before_done -> read_step m Before_done
      | After_done -> drain_step m
    and drain_step (m : Ssex.t) : outcome =
      let s = !st in
      match () with
      | () when s.drain_reads_n >= drain_reads () -> at_eof m
      | () when s.drain_bytes_n >= drain_bytes () -> at_eof m
      | () ->
        st := { s with drain_reads_n = s.drain_reads_n + 1 };
        read_step m After_done
    and at_eof (m : Ssex.t) : outcome =
      (* BOTH closes run and the transport error wins (D4, A9). *)
      release
        (Result.fold
           ~ok:(fun (() : unit) -> Complete)
           ~error:(fun (e : Errx.t) -> Failed e)
           (Ssex.close m))
    in
    (* The first drive parks its chunk: no consumer exists yet. *)
    let park (s : step) : unit =
      match s with
      | Yielded (c, k) ->
        st := { !st with pending = Some k; queued = Some c }
      | Finished o ->
        let (_ : outcome) = release o in
        ()
    in
    let absorb (s : step) : Ssex.Chunk.t option =
      match s with
      | Yielded (c, k) ->
        st := { !st with pending = Some k; queued = None };
        Some c
      | Finished o ->
        let (_ : outcome) = release o in
        None
    in
    let pull (() : unit) : Ssex.Chunk.t option =
      Option.fold
        ~none:(fun (() : unit) -> None)
        ~some:(fun (k : (unit, step) Effect.Deep.continuation) (() : unit) ->
          (* D6: the continuation leaves the ref BEFORE it resumes, so
             a re-entrant next can never resume it twice. *)
          st := { !st with pending = None };
          absorb (Effect.Deep.continue k ()))
        (!st).pending ()
    in
    (* The dead-cursor test comes FIRST (A1): after the run next
       touches neither the transport nor the machine. *)
    let take (() : unit) : Ssex.Chunk.t option =
      let s = !st in
      match s.closed with
      | true -> None
      | false ->
        Option.fold
          ~none:(fun (() : unit) -> pull ())
          ~some:(fun (c : Ssex.Chunk.t) (() : unit) ->
            st := { !st with queued = None };
            Some c)
          s.queued ()
    in
    let cursor = { take } in
    let start (() : unit) : step =
      Result.fold
        ~error:(fun (e : Errx.t) -> Finished (release (Failed e)))
        ~ok:(fun (m : Ssex.t) -> Finished (pump m Before_done))
        (Ssex.make ?closing ?max_line_bytes ?max_event_bytes ())
    in
    let settle (() : unit) : outcome =
      let s = !st in
      match s.closed with
      | true -> s.settled
      | false -> release Cut
    in
    let drive_then_consume (() : unit) : 'a * outcome =
      park (Effect.Deep.try_with start () handler);
      let a = consume cursor in
      (a, settle ())
    in
    Fun.protect
      ~finally:(fun (() : unit) ->
        let (_ : outcome) = release (!st).settled in
        ())
      drive_then_consume
end
