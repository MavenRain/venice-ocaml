(* M15 clientx: the session layer. HOST unit.

   clientx drives IO through two boundaries and owns NO ref and NO
   try-with: the retry loop is a tail-recursive function that threads
   the attempt number, the slept total and the ledger as arguments.
   It is a functor, and the omlz subset has no functors, so it stays
   out of the gates.sh core= list beside curlx, fakex, streamx and
   clockx.

   A9: the parameters are spelled [Make (T : Streamx.S) (C : Clockx.S)]
   and there is NO fourth copy of the transport signature. Naming
   Venice.Transport.S here would make lib/venice.ml depend on a module
   that depends on venice, which is the same cycle streamx.mli
   records. venice.mli spells the same functor
   [Client.Make (T : Transport.S) (C : Clock.S)], and the drift guard
   in lib/venice.ml already proves the two signatures are one.

   The retry policy, the delay newtype and the three closed sums live
   in retryx (A7), which is core and pure. clientx only turns wire
   answers into obstacles and takes the sleep.

   The key reaches T.send and nothing else. No reply and no error
   carries a request body, a key byte or an unbounded server body
   (D11). *)

type error =
  | Http of
      { failure : Headx.failure;
        attempts : Retryx.Attempt.t list;
        stop : Retryx.Stop.t }
  | Failed of
      { error : Errx.t;
        attempts : Retryx.Attempt.t list;
        stop : Retryx.Stop.t }
(* Http is a SERVER verdict that survived the retry loop; Failed is a
   transport rejection or the client's own. Both carry the ledger of
   the attempts that were retried and the reason the loop stopped. *)

type 'a reply =
  { value : 'a;
    head : (Headx.t, Errx.t) result;
    attempts : Retryx.Attempt.t list }
(* head is Headx.of_pairs over the answer that succeeded, run once. It
   is a result, not an option: a rate-limit header block that fails to
   parse never erases a good body. *)

module Make (T : Streamx.S) (C : Clockx.S) : sig
  type t

  val make :
    key:Keyx.t ->
    ?policy:Retryx.Policy.t ->
    ?max_body:int ->
    transport:T.t ->
    clock:C.t ->
    unit ->
    (t, Errx.t) result
  (* Defaults: Retryx.Policy.default and max_body 16_777_216. max_body
     outside 1..268_435_456 rejects with Client_invalid. The error
     body of a NON-2xx answer has its own 1_048_576 byte cap, which no
     caller can widen. *)

  val models :
    ?filter:Modelx.Model_filter.t -> t -> (Modelx.packed list reply, error) result
  (* GET /models. The "type" query parameter is ALWAYS sent (A6): an
     absent ?filter renders "type=all", so the client never depends on
     the server's undocumented default. *)

  val chat : t -> 'c Chatx.t -> (Respx.t reply, error) result
  (* POST /chat/completions, stream false. The request is built ONCE
     before the loop, so every retry sends byte-identical bytes. *)

  val chat_stream :
    t ->
    'c Chatx.t ->
    (Streamx.cursor -> 'a) ->
    (('a * Streamx.outcome) reply, error) result
  (* POST /chat/completions with stream true and usage included. On a
     2xx the media type decides (A3): text/event-stream drives the M14
     puller, application/json refuses with Client_invalid because the
     SSE machine would drop the whole answer, any other present type
     is the same rejection, and an absent type streams.

     A Cut or a Failed outcome is a VALUE in the reply, not an error:
     the consumer already ran and the head was a 2xx, so the retry
     loop is over (D3). The SSE machine caps are not exposed in M15. *)
end
