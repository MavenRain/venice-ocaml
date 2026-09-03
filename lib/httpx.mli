(* M13 httpx: the sans-io request layer. Three units behind one file:
   the endpoint newtype, the route index, and the request mint.

   The method is a PHANTOM INDEX on the route, not a run-time field
   (A3): Route.chat_completions has type post Route.t and models has
   type get Route.t, so Request.get on the chat route and Request.post
   on a listing route both fail to TYPECHECK. No meth argument exists
   at the mint; the meth accessor below only reports what the route
   already decided, so cfgx can pick the POST-only lines.

   The request carries no key field of any kind. The key enters the
   wire only through Transport.send ~key, so every Request projection
   (headers, url, to_log) is redaction-safe by construction rather
   than by filtering.

   httpx owns request-header normalization end to end (A4): Headx
   of_pairs is the RESPONSE rate-limit parser and drops unknown names,
   so it cannot serve here. Names normalize through the private
   norm_name (RFC 7230 tchar, 1..128 bytes, lowercased), then the
   reserved-set and duplicate checks run over the lowered names. *)

module Endpoint : sig
  (* https-only by construction. Together with the proto = "=https"
     config line this means no plaintext transport can be configured,
     whatever a caller passes. *)
  type t

  val default : t
  (* https://api.venice.ai/api/v1 *)

  val of_string : string -> (t, Errx.t) result
  (* requires the literal https prefix and a nonempty host segment;
     rejects a trailing slash, rejects question mark, hash, double
     quote, backslash and every byte outside 0x21..0x7E (so SP, HTAB,
     CR, LF and NUL reject), rejects length above 2048 *)

  val to_string : t -> string
end

module Route : sig
  (* Uninhabited method markers, the Model witness idiom. *)
  type get
  type post

  type 'm t
  (* the four routes as one closed variant with a phantom method
     index; 'm is erased inside the library and re-abstracted here *)

  val chat_completions : post t
  val models : get t
  val tee_attestation : get t
  val tee_signature : get t
  val path : 'm t -> string
end

module Request : sig
  type meth =
    | Get
    | Post

  type t

  val get :
    ?query:(string * string) list ->
    ?headers:(string * string) list ->
    Route.get Route.t ->
    (t, Errx.t) result
  (* Query keys: nonempty, unreserved bytes only (ALPHA / DIGIT / - .
     _ ~), byte-equal duplicates reject, at most 16 pairs. Values:
     any bytes, percent-encoded per RFC 3986 with UPPERCASE hex, and
     nothing else is special (no "+" for space). Emission order is
     caller order, so the query string is a golden. *)

  val post :
    ?headers:(string * string) list ->
    Route.post Route.t ->
    body:Jsonx.t ->
    (t, Errx.t) result
  (* The body renders ONCE here through Jsonx.emit; the rendered
     length is capped at 4_194_304 bytes (A13), which is 2x-safe
     under the 10 MiB curl config-line cap even for an all-backslash
     body. Jsonx.emit escapes every control byte, so the rendered
     body can hold no raw CR, LF or NUL, which the cfgx quoting
     relies on. *)

  val meth : t -> meth
  val path : t -> string
  val query : t -> (string * string) list

  val headers : t -> (string * string) list
  (* normalized: names lowercased, mint order kept *)

  val body : t -> Jsonx.t option

  val rendered : t -> string option
  (* INTERNAL seam: the emitted body bytes, minted once by post.
     cfgx reads it for the data-binary line; venice.mli publishes
     body_bytes (the length) instead. *)

  val body_bytes : t -> int
  (* 0 for a GET *)

  val url : Endpoint.t -> t -> string
  (* endpoint ^ path ^ the encoded query string; an empty query emits
     no "?" *)

  val to_log : t -> string
  (* Deterministic single-line projection: method, path, the encoded
     query (keys AND values), header NAMES only (a future header
     could carry a secret) and the body byte LENGTH only (chat
     prompts are user data). Byte-exact golden. *)
end
