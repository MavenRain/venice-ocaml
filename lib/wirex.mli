(* M13 wirex: the incremental response-head reader, sans-io.

   curl with --include prints one head block per response: the status
   line, the header lines, a blank line, then the body. A 1xx interim
   response (100 Continue, 103 Early Hints) prints an EXTRA block
   first, so the reader skips informational blocks and stops on the
   first final one.

   Terminators (A15): curl relays HTTP/1.x head bytes VERBATIM, bare
   LF terminators and mixed terminators inside one head included; it
   synthesizes the status line and CRLF terminators only for HTTP/2.
   So every line of the head may end CRLF or bare LF, chosen per
   line. A bare CR still rejects (the ssex smuggling precedent) and
   an obs-fold continuation line still rejects.

   The machine is pure: feed returns the next machine or the finished
   head, never a mutated value, and one head parses identically
   whether it arrives byte at a time or in one piece. *)

type head =
  { version : string;
    (* the token after "HTTP/", so "1.1" or "2" *)
    status : int;
    reason : string;
    (* "" when the status line carries none; both "HTTP/2 200" and
       "HTTP/2 200 " read as an empty reason *)
    pairs : (string * string) list
    (* raw names in wire order; Headx.of_pairs owns lowercasing and
       the rate-limit rules *)
  }

type t

type step =
  | More of t
  | Head of head * string
  (* the string holds the bytes after the terminating blank line, ""
     when none: those are the first pending body bytes *)

val make : ?max_head_bytes:int -> unit -> (t, Errx.t) result
(* default 65536; must be >= 1 or make rejects. The cap is enforced
   DURING accumulation, so a terminator-free flood rejects at the cap
   instead of buffering; at-cap exactly passes and cap+1 rejects.
   Bytes of a skipped informational block leave the buffer with it. *)

val feed : t -> string -> (step, Errx.t) result
(* Empty feed is a no-op that reports More. Feeding after Head is
   impossible by construction: the Head step hands back no machine,
   and a machine handed back by More can never hold a complete head,
   because grow keeps only the unparsed remainder. feed still checks
   that invariant and rejects a machine that violates it, so a future
   edit that stores a completed buffer fails loudly instead of
   yielding the same head twice. Feeding the SAME machine twice with
   the same bytes is pure and gives the same step. *)
