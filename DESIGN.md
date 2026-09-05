# venice-ocaml: design

A typed Venice SDK in OCaml. An OpenAI-compatible client is table stakes;
this SDK models what Venice actually sells:

- Model slugs, capabilities, Diem/USD balances, and rate-limit tiers are
  variants and newtypes. A vision message to a non-vision model, a
  temperature outside the model's constraint window, or an E2EE session
  against a model without `supportsE2EE` does not typecheck.
- Chat completions stream through OCaml 5 effect handlers. The consumer
  writes direct-style code; the handler owns the SSE pull loop. This is
  the demo the callback-soup JS/Python SDKs cannot give.
- The headline: the client verifies Venice's TEE attestation quotes
  itself. "Your inference was actually private" becomes a typed witness
  (`full Attested.t`) that the E2EE session constructor requires, not a
  marketing claim and not a `verified: true` field the server asserts
  about itself.

Wire facts live in `FACTS.md` (researched 2026-08-27, re-pinned by live
probes at M2, M22, and M31). Every fact is a hypothesis until a fixture pins it.

## 1. Layering: maximal ZxCaml

Two layers, one repo:

- **Core (ZxCaml subset, pure, sans-io).** Codecs, domain model, SSE state
  machine, the whole crypto tower, the TDX quote verifier, and the E2EE
  session state machine. No IO, no effects, no exceptions, no wall clock,
  no randomness: time enters as a `~now` witness, entropy enters as
  consumed `Fresh.t` values minted at the host boundary. Every core
  module passes `zxlint` and `omlz check`; the flagship artifact (M40)
  compiles the quote parser + policy core with `omlz build --target=bpf`.
- **Host (plain OCaml 5).** The curl-subprocess transport (`curlx`) and
  its scripted twin (`fakex`) behind the `Venice.Transport.S` signature,
  the RNG boundary, the wall clock, and the effect handlers for
  streaming. Effects never cross into the core. Host modules link `unix`,
  may hold refs and `Bytes`, and are exempt from the `zxlint` gate.

The four (plus two) omlz codegen traps and the toolchain pins are in
`ZXCAML.md` (card copied from x402-caml). The curl surface (config
grammar, escaping table, both config-line caps, the exit-code subset,
the version probe and the two-pipe IO trap) is in `CURL.md`.

## 2. Threat model: what the types delete

| Class | Instance in the wild | Where it dies here |
|---|---|---|
| Trust-based privacy | every "we don't log" API | attestation verified client-side; `Session.establish` requires `full Attested.t` |
| Server-asserted verification | `verified: true` in the attestation response | that field is parsed and then ignored for trust decisions; only local checks mint witnesses |
| Stale / replayed attestation | replay of an old quote | caller-minted 32-byte nonce, echo checked, nonce bound into REPORTDATA; `Nonce.t` is single-use |
| Debug enclave | TD with DEBUG attribute | td_attributes DEBUG bit is a typed reject |
| Wrong code identity | reproducible-build gap | `Expect.make ~measurements` (MRTD + RTMR0..3) is mandatory; `Expect.tofu` exists but mints only `structural Attested.t`, which `Session.establish` refuses |
| Forged quote / bogus cert chain | self-signed PCK | ECDSA chain verified to the pinned Intel SGX Root CA public key; QE binding hash checked; TCB Info + QE Identity checked against pinned Intel PCS collateral (CRL / live revocation documented out of scope) |
| Response forgery | MITM after attestation | enclave-signed responses: signed payload must equal the received completion bytes + request_id; secp256k1 verify + keccak address must equal attested `signing_address` |
| E2EE downgrade | plaintext send to a TEE slug | `Session.t` has no plaintext send; encryption is the only path that typechecks |
| AES-GCM nonce reuse | catastrophic key recovery | GCM nonces are generative single-use `Fresh.t`; model spec P3 |
| Illegal request | 400s discovered in prod | capability phantom row + constraint-bounded sampling newtypes + context budget check |
| Rate/balance surprise | silent 429 loops | typed rate-limit sextet, `Tier` variant (Explorer / Paid), typed 429 with reset times, Diem/USD decimal balances |
| Deprecation surprise | slug dies under you | `model_spec.deprecation` parsed to a variant and surfaced |
| Malformed stream | SSE smuggling, unbounded buffers | strict incremental SSE machine, bounded buffers, total |
| Secret leak in logs | API key / session key in traces | redaction at the transport boundary; zeroization sweep at M37 |
| Retry storm / double bill | naive retry of a POST after a timeout | closed `Obstacle` sum: only never-sent transport failures, 429 and the three gateway statuses retry;  attempts, per-wait and total caps are policy fields;  a server hint above the cap stops instead of clamping |
| Timing side channel on client secrets | variable-time bignum under an ephemeral ECDH scalar | limbsx is variable-time by design;  secpx runs ONE fixed-shape ladder for every secret scalar, which makes 256 addition CALLS and 256 doubling CALLS whatever the scalar is, so the CALL shape never depends on a secret bit, but the field-operation count is NOT constant and two residual leaks stay: the limbsx arithmetic underneath is variable-time, and the addition returns early while the accumulator is still the point at infinity, so the bit LENGTH of the scalar leaks;  every other consumer that touches a secret (M29 keygen) states its ladder shape in its brief;  a constant-time tower is a hardening candidate at M39 |
| Tag compare leak | early-exit byte compare on a MAC lets a forger learn the tag prefix by timing | hmacx.equal_ct folds the OR of every byte difference with no early exit;  verify is the only tag check;  HMAC and HKDF branch on lengths only |
| Psychic signatures (r = 0 or s = 0) | CVE-2022-21449 (Java), where a zero pair verified under every key | p256x and secpx each mint a `Signature.t` only when r and s both sit in 1 .. n-1, so r = 0, s = 0, r >= n and s >= n are rejected at CONSTRUCTION, before any point arithmetic runs;  both verifiers are variable-time by design, because they read only PUBLIC inputs (attestation quotes, certificates, signatures) |

## 3. API shape (lib/)

Root module `venice.ml` / `venice.mli` is the only public signature.
Internal units are x-suffixed (errx bytesx hexx b64x jsonx modelx paramsx
msgx headx ssex accx keyx httpx cfgx wirex curlx fakex retryx clockx
limbsx hmacx keccakx
p256x secpx aesx gcmx quotex sigx derx attestx sessx clientx streamx),
hidden behind it.

```ocaml
module Model : sig
  type vision  and tools  and reasoning  and audio  and tee  and e2ee  and video
  (* phantom markers, uninhabited;  video is the video-INPUT capability,
     not the Video model kind *)
  type 'caps t                        (* abstract; 'caps is a product of markers *)
  type packed = Pack : 'c t -> packed (* existential: what a /models parse yields *)
  val of_listing : Json.t -> (packed, Error.t) result
  val vision    : 'c t -> (('c * vision) t) option   (* witness extraction *)
  val tools     : 'c t -> (('c * tools) t) option
  val reasoning : 'c t -> (('c * reasoning) t) option
  val e2ee      : 'c t -> (('c * e2ee) t) option
  val constraints : 'c t -> (Constraints.t, Error.t) result  (* parses on access *)
  val deprecation : 'c t -> Deprecation.t
end

module Chat : sig
  type request                             (* built, not assembled by hand *)
  val make :
    model:'c Model.t -> messages:'c Msg.nonempty ->
    ?temperature:Temp.t -> ?venice:Venice_params.t -> ... ->
    (request, Error.t) result              (* Temp.t minted FROM the model's constraints *)
end

module Tee : sig
  module Nonce : sig
    type t                                 (* 32 bytes, single-use *)
    val mint : Entropy.t -> t              (* host boundary consumes entropy *)
  end
  module Expect : sig
    type full  and structural
    type 'level t
    val make : measurements:Measurements.t -> full t
    val tofu : unit -> structural t        (* explicit, and it shows in the type *)
  end
  module Attested : sig
    type 'level t                          (* level = full | structural *)
    val verify :
      now:Time.t -> expect:'l Expect.t -> nonce:Nonce.t ->
      quote:string -> (('l t) , Error.t) result
    val signing_address : full t -> Eth_address.t
  end
end

module Session : sig
  type 'c t                                (* carries the model's base row *)
  val establish :
    entropy:Entropy.t -> attested:full Tee.Attested.t ->
    model:('c * Model.e2ee) Model.t -> ('c t, Error.t) result
  val send : 'c t -> 'c Msg.nonempty -> (Chat.request * 'c t, Error.t) result
    (* contents leave only as Ciphertext.t hex; no plaintext API exists *)
end

module Api_key : sig
  type t
  val make : string -> (t, Error.t) result   (* no projection is published *)
end

module Http : sig
  module Endpoint : sig type t val default : t end
  module Route : sig
    type get and post                        (* uninhabited method markers *)
    type 'm t                                (* method is a phantom index *)
    val chat_completions : post t
    val models : get t
  end
  module Request : sig
    type t
    val get : ?query:(string * string) list -> ?headers:(string * string) list ->
      Route.get Route.t -> (t, Error.t) result
    val post : ?headers:(string * string) list ->
      Route.post Route.t -> body:Json.t -> (t, Error.t) result
  end
  module Wire : sig
    type head = { version : string;  status : int;  reason : string;
                  pairs : (string * string) list }
    type t and step = More of t | Head of head * string
    val feed : t -> string -> (step, Error.t) result
  end
end

module Transport : sig
  module type S = sig
    type t and body
    val send : t -> key:Api_key.t -> Http.Request.t ->
      (Http.Wire.head * body, Error.t) result
    val read : body -> (string option, Error.t) result
    val read_all : ?cap:int -> body -> (string, Error.t) result
    val close : body -> (unit, Error.t) result
  end
  module Curl : sig include S val make : ?binary:string -> unit -> (t, Error.t) result end
  module Fake : sig include S  type exchange  val make : exchange list -> t end
  (* Curl and Fake are both host layer *)
end

module Stream : sig                       (* host layer: the ONE handler *)
  type outcome = Complete | Cut | Failed of Error.t
  type cursor                             (* dead after run returns *)
  val next : cursor -> Sse.Chunk.t option
  val iter : cursor -> (Sse.Chunk.t -> unit) -> unit
  val fold : cursor -> init:'s -> f:('s -> Sse.Chunk.t -> 's) -> 's
  val collect : cursor -> (Sse.Acc.final, Error.t) result
  module Make (T : Transport.S) : sig
    val run :
      ?closing:Sse.closing -> ?max_line_bytes:int -> ?max_event_bytes:int ->
      T.body -> (cursor -> 'a) -> 'a * outcome
  end
end

module Delay : sig                        (* core: 0 .. 3_600_000 ms *)
  type t                                  (* minted, never negative *)
  val ms : t -> int
end

module Clock : sig                        (* host layer: the ONE wall clock *)
  module type S = sig
    type t
    val now : t -> int                    (* unix seconds *)
    val sleep : t -> Delay.t -> unit
  end
  module System : sig include S val make : unit -> t end
  module Fake : sig
    include S
    val make : ?now:int -> unit -> t
    val slept : t -> Delay.t list         (* the waits, in order *)
  end
end

module Model_filter : sig
  type t = All | Kind of Model.kind       (* renders the `type` query *)
end

module Client : sig                       (* host layer: the retry loop *)
  module Policy : sig
    type t                                (* attempts, base, per-wait, total *)
    val default : t
    val none : t                          (* one attempt, no wait *)
    val make :
      ?max_attempts:int -> ?base_ms:int -> ?max_delay_ms:int ->
      ?max_total_ms:int -> unit -> (t, Error.t) result
  end
  module Obstacle : sig
    type t =                              (* the CLOSED retryable set *)
      | Rate_limited of Delay.t option
      | Gateway of int                    (* 502, 503, 504 only *)
      | Unreachable of string             (* never-sent transport failure *)
  end
  module Stop : sig
    type t =
      | Not_retryable
      | Attempts_exhausted
      | Hint_over_cap of Delay.t
      | Budget_exhausted of Delay.t
  end
  module Attempt : sig
    type t                                (* one ledger row *)
    val obstacle : t -> Obstacle.t
    val slept : t -> Delay.t
  end
  type error =
    | Http of { failure : Head.failure; attempts : Attempt.t list;
                stop : Stop.t }
    | Failed of { error : Error.t; attempts : Attempt.t list; stop : Stop.t }
  type 'a reply =
    { value : 'a; head : (Head.t, Error.t) result;
      attempts : Attempt.t list }
  module Make (T : Transport.S) (C : Clock.S) : sig
    type t
    val make :
      key:Api_key.t -> ?policy:Policy.t -> ?max_body:int ->
      transport:T.t -> clock:C.t -> unit -> (t, Error.t) result
    val models :
      ?filter:Model_filter.t -> t -> (Model.packed list reply, error) result
    val chat : t -> 'c Chat.t -> (Response.t reply, error) result
    val chat_stream :
      t -> 'c Chat.t -> (Stream.cursor -> 'a) ->
      (('a * Stream.outcome) reply, error) result
  end
end
```

## 4. Dependencies

Stdlib-only core plus our own pinned libraries (zxcaml-p1 switch, OCaml 5.2.1):

- `sha2` (git+file pin): SHA-256 for HMAC/HKDF, ECDSA digests, QE binding.
- `ctlk_topos` (git+file pin): joins the opam depends at M35 for `model/`.

Ported in-repo, same author, same conventions: `limbsx` + `p256x`
(jose-caml / tinysvid), `jsonx` codec lineage (x402-caml), strict `b64x`
(jose-caml; extended with the std alphabet because `intel_quote` is
standard base64). New crypto written here: keccak-256, secp256k1
(verify + ECDH), AES-256-GCM, HKDF-SHA256, a total DER/X.509 subset
reader, and the TDX quote parser. No external HTTP dependency: the host
transport shells out to curl behind a signature; tests use a fake
transport.

The host layer links the compiler-distributed `unix` library for
processes, pipes and `select`. `venice_ocaml.opam` needs no new depend,
because `unix` ships with OCaml >= 5.1. That is a decision, not a gap:
an opam depend on `unix` would pin a package that the compiler already
provides.

M15 adds no depend either.  The host clock links that same `unix` for
`gettimeofday` and `sleepf`, the retry table itself is pure core, and
the client drives a transport and a clock through their signatures
only.

The M14 units add no depend either.  Effect handlers ship inside the
OCaml 5 compiler, so `streamx` needs no library for the one handler.
`streamx` also needs no `unix`: it reads and closes through the
`Transport.S` boundary, and the transport owns the file descriptors.
`accx` is pure and stdlib-only.

M16 adds no depend.  The python oracle is a gate-time tool like the
shell of the compile-fail harness, never a build input;  gates.sh calls
it unconditionally.

M17 is the first milestone that LINKS a third-party library into the
build.  `lib/dune` now reads `(libraries unix sha2)` for the SHA-256
compression function under HMAC and HKDF.  `venice_ocaml.opam` already
carries the `sha2` depend (venice_ocaml.opam:11), so no opam change
lands here.  Unlike the python oracle, `sha2` is a BUILD input, not a
gate-time tool.

M18 adds no depend.  `Int64` is stdlib, so the keccak lanes need no
package;  `lib/dune` keeps `(libraries unix sha2)` and
`venice_ocaml.opam` is untouched.  Like the M16 oracle, the new python
keccak is a gate-time tool and never a build input.

M19 adds no depend.  `Sha2.Sha256.digest` arrived with M17, so
`verify_message` needs no new package;  `lib/dune` keeps
`(libraries unix sha2)` and `venice_ocaml.opam` is untouched.  Like the
M16 and M18 oracles, the new python P-256 is a gate-time tool and never
a build input.

M20 adds no depend.  `secpx` hashes nothing and reads only `limbsx`, so
it needs no new package;  `lib/dune` keeps `(libraries unix sha2)` and
`venice_ocaml.opam` is untouched.  Like the M16, M18 and M19 oracles,
the new python secp256k1 is a gate-time tool and never a build input,
and the Wycheproof corpus it reads is a gate-time INPUT of that tool,
never a build input of the library.

## 5. Model plan (model/)

`session_core.ml` is the ONE transition semantics (attest, establish,
encrypt/stream, close; nonce and key lifecycles), shared between `lib/`
and `model/` via dune copy_files (the x402-caml pattern). CTLK specs,
positive and negative, with printed witnesses:

- P1 safety: no plaintext user/system content reaches the transport in
  any state before `full Attested`.
- P2 attestation nonces are single-use across every trace.
- P3 no (key, GCM nonce) pair is ever used twice.
- P4 decrypt fires only after a completed handshake.
- P5 taint is monotone: a failed check never later reads as verified.
- P6 the session key never flows into the transport log projection.
- P7 knowledge: after a valid signed response, the client KNOWS (view
  kernel) the attested enclave produced it.
- P8 liveness: a deprecated model warning is eventually surfaced.

Correspondence gate (its own milestone, M37): lockstep trace replay of `lib/` against the model,
plus a full-edge differential sweep (x402-caml conformance pattern).

## 6. Strictness profile

- Hex and base64 decoders are strict (alphabet, padding, trailing bits).
- JSON: duplicate-key reject at any depth, depth cap 32, 18-digit int
  cap, numbers as scaled decimals (sign/mantissa/scale ints); no float
  crosses the core.
- Attestation nonce exactly 32 bytes. Client pubkeys exactly 65-byte
  uncompressed with leading 0x04. E2EE chunks at least 93 bytes.
- Bounded SSE buffers (max line and max event bytes are constructor
  parameters with defaults).
- Tag and MAC comparison is constant-time (fold XOR).
- The limb bignum is NOT constant-time:  `mod_red` and `mod_pow` branch
  on limb values and on exponent bits, so every secret-bearing caller
  (M20 ECDH, M29 keygen) states its ladder shape in its own brief.
- Cert validity and freshness need an explicit `~now` witness.
- No exceptions, no partial indexing, combinators over match on
  Option/Result, exhaustive matches, effects only in the host layer and
  always discharged by the one handler inside `Stream.Make (T).run`.

## 7. Milestones

| M | What |
|---|---|
| **A: foundation** | |
| M1 | scaffold: dune-project, opam, licenses, gates.sh, ZXCAML.md, DESIGN.md, FACTS.md |
| M2 | live probe I: models list + headers + one SSE stream recorded to fixtures/ (redacted;  pins the M11 chunk-shape hypothesis: delta members, usage placement, chunk finish_reason values, whether a chat stream always ends with [DONE], and the M10a O2 debt: a streamed finish_reason + stop_reason pair from a tool-call turn), plus one request-body capture per M9 chat golden starting with fixtures/chat_minimal.json (activates the skipped test_chatx fixture check); FACTS pins or corrections |
| M3 | errx + bytesx (total cursor readers: u8/u16le/u32le/u64le/take at offset) + hexx strict + b64x (strict std base64 AND base64url) + tests |
| M4 | jsonx port + scaled-decimal extension + tests |
| **B: domain model** | |
| M5 | modelx: capability phantom row + packed existential, known slugs + Unknown, quantization/privacy/deprecation enums, /models parser -> witnesses + tests |
| M6 | paramsx: constraint-bounded sampling newtypes minted from the model's constraints; venice_parameters typed + tests |
| M7 | msgx: roles, nonempty messages, content parts; vision/audio parts require the capability witness + tests |
| M8 | headx: rate-limit sextet + x-ratelimit-type + Diem/USD decimal balances + Tier + typed 429/4xx/5xx + tests |
| M9 | chat request encoder + context budget check (prompt vs availableContextTokens, max_tokens vs maxCompletionTokens, boundary tests); byte-exact golden tests vs fixtures |
| M10 | chat response parser: choices, usage, finish_reason variants + tests;  produces the reasoning_content / reasoning_details / thought_signature values whose request-side passthrough joins `assistant` as optional arguments |
| M10a | tools / function-calling: Msgx.Tool_call (raw-verbatim repr, parser-only mint) + `assistant ?tool_calls`;  Respx raw items always parse, the typed Choice view validates with choices[i].tool_calls[j] paths;  the four request members (tools witness-gated + Tool defs, tool_choice, parallel_tool_calls standalone, response_format with a response_schema-witnessed json_schema arm);  modelx grows the response_schema phantom row + extractor;  server tools (web_search / x_search) deferred: no capability gate exists for them and their venice_parameters interaction is unpinned + tests |
| M11 | ssex: incremental SSE state machine, bounded, data:/[DONE], CRLF and LF + delta parse + tests |
| M12 | compile-fail harness I: domain misuses + compiling control;  the inline battery moves to `harness/compile_fail_i.sh` and gates.sh calls it UNCONDITIONALLY (a missing or non-executable harness is a red gate, never a silent skip);  cases cf_a..cf_m, where cf_k (no key projection) and cf_l (wrong route method) are M13 boundary cases riding in the harness-I extraction |
| **C: transport + effects** | |
| M13 | transport boundary: `keyx` (opaque API key, no published projection), `httpx` (Endpoint, phantom-indexed Route, Request mint with percent-encoded query and a reserved-header table), `cfgx` (the pure curl config renderer, the ONE place the key becomes bytes), `wirex` (incremental head reader, CRLF or bare LF per line, 1xx skipping), `curlx` (curl subprocess over raw fds and `Unix.select`, version probe, config-line cap, stderr ring, key redaction) and `fakex` (scripted twin) behind `Venice.Transport.S`;  test_transport + test_curlx |
| M14 | streamx: a PULL cursor over the M11 SSE machine and the M13 transport boundary, with ONE `Effect.Deep.try_with` per run, ONE state ref and one sealed `Delta` effect;  `Stream.Make (T).run` is a bracket that closes the body exactly once and poisons the cursor on every exit path, the consumer included, and the post-[DONE] drain is bounded;  `next`, `iter`, `fold` and `collect` are transport-independent;  accx: the pure cross-chunk accumulator that folds the M11 chunks (tool_call fragments into `Msgx.Tool_call` included) into one chat.completion document and re-parses it with `Respx.of_string`, so the streaming and the non-streaming path share ONE grammar;  `Venice.Sse.Acc` plus `Venice.Stream` in venice.mli, `Chat.to_json` promoted for a streaming request body, `Errx.Stream_invalid`, the `Ssex.Chunk.usage_raw` seam, fakex read and close counters, `examples/stream_demo.ml`, test_accx + test_streamx + cf_n |
| M15 | clientx: the session layer as `Client.Make (T : Transport.S) (C : Clock.S)`, with `models`, `chat` and `chat_stream` over ONE request built before the loop, so every retry re-sends byte-identical bytes;  the answer is read under a `max_body` cap, a non-2xx keeps its STATUS even when the error body or the close fails, and a 2xx lets a close failure win, because a body that did not close cleanly is not a body that arrived;  retryx: the pure decide table, the doubling backoff, the rate-limit hint folding (the exhausted triple, `retry-after` in seconds, the larger of the two) and the `Policy` window over attempts, base delay, per-wait cap and total budget;  clockx: the `System` and `Fake` wall-clock boundary, so no suite sleeps and no test builds a `System`;  the closed `Obstacle` sum (never-sent transport failure, 429, and 502/503/504 alone) and the closed `Stop` sum, with a server hint above the per-wait cap STOPPING instead of clamping;  `Venice.Delay`, `Venice.Clock`, `Venice.Model_filter` and `Venice.Client` in venice.mli, the M14 drift guard now covering both dependents of the streamx transport copy;  `Errx.Transport_unreachable` for the curl exits that prove no request byte went out (6, 7, 35) and `Errx.Client_invalid` for the client's own rejections;  `Modelx.kind_slug` plus `Model_filter`, so the `type` query parameter is ALWAYS sent and the server default is never relied on;  `Fakex.refusal`, a script slot that rejects the send and still records the request;  the rewritten `examples/stream_demo.ml` over `Client.Make (Transport.Curl) (Clock.System)`;  test_retryx + test_clientx + cf_o |
| **D: crypto tower (core subset)** | |
| M16 | limbsx: the canonical little-endian 16-bit-limb bignum ported from jose-caml, with an ABSTRACT `t` that is canonical by construction, so every limb sits in `0 .. 0xffff`, no most significant zero limb survives and zero is the empty limb list;  every rejection is an option and the one error type grows by nothing, over `of_int`, `of_limbs` (capped on the limb count BEFORE trimming), `of_be_string`, `to_be_string ~len` under the same byte cap, and a strict `of_hex` that refuses a byte outside the alphabet instead of reading it as a zero nibble;  `add`, `sub`, `mul`, `cmp`, `equal`, `bits`, `mod_red` by quotient-estimate subtraction and `mod_pow` by LSB-first square-and-multiply, both VARIABLE-TIME by design and said so in the unit header, in the mli and in the section 2 threat row;  the ONE division of the unit lives in the total helper `div_pos`, whose callers consume its option;  `harness/diff_limbs.py` recomputes every pinned constant with python `pow()` and requires each one to sit inside a CHECK ROW of the suite after the OCaml comments are stripped, with a corrupted twin of the 255-bit result asserted ABSENT so the search is proven to reach the file;  test_limbsx |
| M17 | hmacx: HMAC-SHA256 (RFC 2104) ported from jose-caml over the pinned `sha2` library, and the HKDF-SHA256 of RFC 5869 written here, in ONE internal unit that venice.mli does not re-export;  `sha256 ~key` is total and conditions a key longer than `block_size ()` by hashing it first, `equal_ct` folds the OR of every byte difference with no early exit and `verify` is the only tag check a consumer should write;  the nested `Hkdf` module keeps `prk` ABSTRACT, so `expand` cannot be handed raw keying material, and it carries `extract` (an empty salt IS the HashLen-zeros default of the RFC, so no optional argument exists), `prk_of_string` at exactly `hash_len ()` bytes, `max_len ()` = 8160 and a `derive` that is extract then expand;  every branch of the unit reads a LENGTH and never a key or data byte, and the unit holds no `Bytes`, no `Buffer`, no `Array`, no ref and NO division line at all, because `expand` appends blocks until the accumulator is long enough instead of counting them by a quotient;  `harness/diff_hmac.py` recomputes the RFC 4231 cases 1 to 7 tags, the 0, 63, 64, 65 and 128-byte boundary keys, the RFC 5869 cases 1 to 3 PRK and OKM and the last 32 bytes of an 8160-byte expansion with python `hmac` and `hashlib`, and requires each one to sit inside a CHECK ROW of the suite after the OCaml comments are stripped, with a corrupted twin of case 1's OKM asserted ABSENT so the search is proven to reach the file;  test_hmacx carries 61 checks and the closed mutation list of the M17 brief names 16 mutants |
| M18 | keccakx: keccak-256 under the ORIGINAL Keccak pad (domain byte 0x01), which is what Ethereum hashes with, the FIPS 202 SHA3-256 (domain byte 0x06) as a permutation witness, and the Ethereum address with its EIP-55 checksum, in ONE internal unit that venice.mli does not re-export;  the 25 lanes are `int64` values in named record FIELDS, five to a `row` and five rows to a `state`, so no array, no list index and no index arithmetic ever addresses a lane, `rotl` is called only with literal offsets in 1 .. 63 because a shift of 0 or of 64 is unspecified, and lane (0, 0), whose rho offset is 0, is copied instead of rotated;  `theta`, `rho_pi`, `chi` and `iota` are four total step functions and `keccak_f` is ONE fold over the 24 round constants, so the round count is the LENGTH of that list and never a counter;  the sponge tracks the fill of the current block inside the fold over the input, so the multi-rate pad reaches all three of its cases with NO division line and no remainder anywhere in the unit, and the padding domain is the closed sum `Keccak | Sha3` and never a bare byte flag;  the nested `Address` module keeps `t` ABSTRACT at exactly 20 bytes, `of_pubkey` reads the 64-byte X || Y and the 04-prefixed 65-byte form because no source pins the byte shape of `signing_key` before the M22 fixture, `of_hex` parses with NO checksum enforcement and `of_checksum_hex` applies the EIP-55 acceptance rule (an all-lowercase and an all-uppercase body carry no checksum and are accepted, any other body must equal the checksum form);  no secret enters the unit, so the section 2 table gains no row;  `harness/diff_keccak.py` GENERATES the round constants from the LFSR of FIPS 202 3.2.5 and the rho offsets from the recurrence of 3.2.2, so it shares no table with the OCaml unit, validates its own sponge against `hashlib.sha3_256` before it reads any pin, and requires the five known-answer digests, the seven rate boundaries, the three SHA3-256 witnesses, the address of the secp256k1 base point and the eight EIP-55 reference strings to sit inside a CHECK ROW of the suite after the OCaml comments and the row LABEL are stripped, with a corrupted twin asserted ABSENT and the label stripping proven on a synthetic row held in memory;  `pin()` in `harness/diff_limbs.py` and `harness/diff_hmac.py` strips the row label too, which closes the M17 R3 residual;  test_keccakx carries 69 checks and the closed mutation list of the M18 brief names 17 mutants |
| M19 | p256x: ECDSA over NIST P-256 with SHA-256 digests, VERIFICATION only, ported from jose-caml over the ABSTRACT limbsx `t` and not over raw limb lists, so every formula is restated on a canonical value and no helper reads a limb count;  the seven curve constants and the four small multipliers of the Jacobian formulas live in ONE `curve` record that `curve ()` builds through an `Option.bind` chain, and every helper takes that record as its FIRST parameter, so ZxCaml trap 2 holds inside every helper and no hot loop decodes a hex literal;  the point arithmetic is Jacobian with a = -3 and the point at infinity encoded as z = 0, one field inverse per scalar walk, two independent walks and one addition for the shared point, and NO Shamir trick, because the input is public and two walks are simpler to audit;  the unit holds no division line and no remainder, because every reduction goes through `Limbsx.mod_red` and every inverse through `Limbsx.mod_pow`, and it holds exactly four unreachable default sites, each with its argument in place;  `Pubkey.t` is ABSTRACT and minted only for a pair of 32-byte coordinates below the field prime that sits ON the curve, from the 64-byte X || Y form that M25 hands over and from the 65-byte 0x04-prefixed SEC 1 form that M26 hands over, with the compressed 0x02 and 0x03 forms refused because this unit decompresses nothing;  `Signature.t` is ABSTRACT and carries the psychic rejects of CVE-2022-21449 as a CONSTRUCTION invariant, so r and s both sit in 1 .. n-1 before any point arithmetic runs, over the raw 64-byte r || s form for M25 and the r and s pair for M26 once it strips the DER sign byte;  the verifier is VARIABLE-TIME by design and says so in the unit header, in the mli and in the section 2 row, because it reads only public inputs;  the malleable twin (r, n - s) VERIFIES, because FIPS 186-4 carries no low-s rule, and the suite pins that behaviour so a later reader cannot mistake it for a defect;  `harness/diff_p256.py` runs P-256 in AFFINE coordinates over python integers with three-argument `pow` inverses, so it shares no formula with the Jacobian unit, and it SIGNS the RFC 6979 A.2.5 vector from the published private key and nonce and verifies the result before it reads a pin, then requires the curve constants, both RFC 6979 SHA-256 signatures, the RFC 7515 A.3 ES256 vector, a vector it GENERATES itself and the boundary constants to sit inside a CHECK ROW of the suite, with a corrupted twin asserted ABSENT and the label stripping proven on a synthetic row held in memory;  test_p256x carries 71 checks and the closed mutation list of the M19 brief names 16 mutants |
| M20 | secpx: secp256k1 with ECDSA VERIFICATION over a caller-supplied digest and ECDH, written over the ABSTRACT limbsx `t` in the M19 shape, so every formula is restated on a canonical value and no helper reads a limb count;  the twelve curve constants live in ONE `curve` record that `curve ()` builds through an `Option.bind` chain and every helper takes as its FIRST parameter, which is what ZxCaml trap 2 needs, and the trap fires CROSS-MODULE, so `secpx.ml` is linted beside `limbsx.ml` and never alone;  the point arithmetic is Jacobian with a = 0, the dbl-2009-l doubling and the add-2007-bl addition, and the point at infinity is encoded as z = 0;  ONE fixed-shape Montgomery ladder serves `verify`, `Pubkey.of_scalar`, `shared_point` and `shared_x`, and it makes 256 addition CALLS and 256 doubling CALLS for every scalar, so the CALL shape never depends on a secret bit;  the field-operation count is NOT constant and two residual leaks stay, because the limbsx arithmetic underneath is variable-time and the addition returns early while the accumulator is still the point at infinity, so the bit LENGTH of the scalar leaks, and a constant-time tower is the M39 hardening candidate;  the unit holds no division line and no remainder, because every reduction goes through `Limbsx.mod_red` and every inverse through `Limbsx.mod_pow`, and it holds exactly four unreachable default sites, each with its argument in place;  `Pubkey.t` is ABSTRACT and minted only for a pair of 32-byte coordinates below the field prime that sits ON the curve, from the 64-byte X || Y form and from the 65-byte 0x04-prefixed SEC 1 form the E2EE header carries, with the compressed 0x02 and 0x03 forms refused because this unit decompresses nothing;  `Signature.t` is ABSTRACT and carries the psychic rejects of CVE-2022-21449 as a CONSTRUCTION invariant, so r and s both sit in 1 .. n-1 before any point arithmetic runs;  `verify` takes a DIGEST of exactly 32 bytes and the unit HASHES nothing, because the signed message formula of the `/tee/signature` route is UNPINNED until M31, and a 33-byte digest with a leading zero byte is rejected on its LENGTH although it carries the same integer;  the malleable twin (r, n - s) VERIFIES, because the standard carries no low-s rule, and the suite pins that behaviour so a later reader cannot mistake it for a defect;  `harness/diff_secp.py` runs secp256k1 in AFFINE coordinates over python integers with three-argument `pow` inverses, so it shares no formula with the Jacobian unit, and it VERIFIES every embedded Wycheproof vector and re-signs its own generated vector before it reads a pin, then requires the curve constants, the ECDSA subset (20 vectors plus a computed twin), the ECDH subset (12 vectors), the generated vectors and the boundary constants to sit inside a CHECK ROW of the suite, with a corrupted twin asserted ABSENT and the label stripping proven on a synthetic row held in memory;  test_secpx carries 85 checks |
| M21 | aesx + gcmx: AES-256 (total S-box), GHASH/CTR, seal + open, NIST CAVP pins + tests |
| **E: TDX attestation** | |
| M22 | live probe II: real attestation fixture; pin quote version/layout, REPORTDATA binding formula (vs dstack source), nvidia_payload shape |
| M23 | quotex: TDX quote header + TD report body (mrtd, rtmr0-3, report_data, td_attributes, xfam, tee_tcb_svn) via bytesx cursors + fixture tests |
| M24 | policy: DEBUG reject, nonce + signing_key REPORTDATA binding, Expect.make ~measurements (tofu mints structural only) + tests |
| M25 | sigx: signature section parse, attestation-key ECDSA verify, QE binding hash check + tests |
| M26 | derx: total DER/X.509 subset (tbsCertificate, P-256 SPKI, validity, sig, SGX PCK extension with CPUSVN + PCESVN); PCK chain to pinned Intel root; ~now witness + tests |
| M27 | tcbx: TCB Info + QE Identity checks vs pinned Intel PCS collateral (tee_tcb_svn / CPUSVN / PCESVN vs TCB levels; QE MRSIGNER, ISVPRODID, ISVSVN); CRL / live revocation documented out of scope + tests |
| M28 | attestx: full pipeline -> full/structural Attested.t; nvidia_payload structural parse + nonce check (NRAS network verify documented out of scope); fixture e2e + tests |
| **F: E2EE session** | |
| M29 | sessx establish: Entropy/Fresh boundary, ephemeral secp keygen, ECDH + HKDF vs model pubkey; requires full Attested.t + e2ee witness; KATs |
| M30 | encrypt path: GCM seal, Ciphertext.t hex, E2EE header assembly; no plaintext send exists + tests |
| M31 | live probe III: real E2EE roundtrip capture to fixtures/ (redacted); pin response chunk layout (tag vs ct order) AND the /tee/signature signed-message formula in FACTS |
| M32 | decrypt path: chunk machine (layout per the M31 pin; 93-byte floor), streaming decrypt composed with ssex + effects + tests |
| M33 | response signature: /tee/signature parse; signed payload must equal the received completion bytes + request_id (formula per M31 pin); secp verify + keccak address vs signing_address; cross-request rejection KAT + tests |
| M34 | compile-fail harness II: privacy misuses (send without witness, non-e2ee model, structural where full required) + control |
| **G: model + conformance** | |
| M35 | session_core extraction (copy_files shared lib/model) + CTLK model skeleton: states + transitions |
| M36 | specs P1..P8, positive + negative, printed witnesses |
| M37 | correspondence gate: lockstep trace replay + full-edge differential sweep |
| M38 | differential harness: python recompute of keccak, ECDH, GCM KATs, quote offsets, cert chain; every fixture pin re-derived |
| **H: ship** | |
| M39 | hardening: caps sweep, seeded byte-mutation fuzz (quotes, SSE, chunks, JSON) -> typed errors only; zeroization pass |
| M40 | README + pitch; e2e demo (live gated on VENICE_API_KEY, fixture mode default); zx artifact: omlz bpf build of quotex + policy, size table |

## 8. Gates

`./gates.sh`: dunecho build (0 warnings) + every suite + compile-fail
harnesses + model check + correspondence + `zxlint --errors-only` +
`omlz check` over the core-module list (bpf build gate at M38). Each
milestone lands BUILT + GATED + MUTATION-CONFIRMED (behavioral mutants;
KILLED(compile) is vacuous) + REVIEWED before staging. Nothing is
committed by the assistant.

The python differential harness joins the ladder at M16 (limbs) and
grows toward M38.  It recomputes what a suite pins, from an
implementation that shares no code with the unit under test, and the
gate calls it unconditionally.  From M18 the oracle also validates its
OWN permutation against `hashlib.sha3_256` before it pins anything, so a
python bug cannot certify an OCaml bug.  From M19 the oracle also SIGNS
the RFC 6979 vector and re-verifies every signature in affine
coordinates before it pins anything, so a pin cannot outlive the
arithmetic that produced it.  From M20 the oracle also VERIFIES every
embedded Wycheproof vector and re-signs its own generated vector in
affine secp256k1 coordinates before it pins anything, so the corpus
subset in the suite is a checked quotation and not a copied constant.

Host modules (`curlx`, `fakex`) are exempt from `zxlint` and hold the
one try-with guard in the repo. They stay out of the `core=` list in
`gates.sh` by design, because they own the process, the refs and the
`Bytes` buffers that the core forbids.
