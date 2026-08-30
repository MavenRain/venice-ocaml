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
- **Host (plain OCaml 5).** The curl-subprocess transport behind a
  `TRANSPORT` signature, the RNG boundary, the wall clock, and the effect
  handlers for streaming. Effects never cross into the core.

The four (plus two) omlz codegen traps and the toolchain pins are in
`ZXCAML.md` (card copied from x402-caml).

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

## 3. API shape (lib/)

Root module `venice.ml` / `venice.mli` is the only public signature.
Internal units are x-suffixed (errx bytesx hexx b64x jsonx modelx paramsx
msgx headx ssex limbsx hmacx keccakx p256x secpx aesx gcmx quotex sigx
derx attestx sessx clientx streamx), hidden behind it.

```ocaml
module Model : sig
  type vision  and tools  and reasoning  and e2ee  (* phantom markers, uninhabited *)
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
    model:'c Model.t -> messages:Msg.nonempty ->
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
  type t
  val establish :
    entropy:Entropy.t -> attested:full Tee.Attested.t ->
    model:('c * Model.e2ee) Model.t -> (t, Error.t) result
  val send : t -> Msg.nonempty -> (Chat.request * t, Error.t) result
    (* contents leave only as Ciphertext.t hex; no plaintext API exists *)
end

module Stream : sig
  type _ Effect.t += Delta : Delta.t -> unit Effect.t   (* host layer *)
  val run : (unit -> 'a) -> on_delta:(Delta.t -> unit) -> 'a
end
```

## 4. Dependencies

Stdlib-only core plus our own pinned libraries (karamel-710 switch):

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
- Cert validity and freshness need an explicit `~now` witness.
- No exceptions, no partial indexing, combinators over match on
  Option/Result, exhaustive matches, effects only in the host layer and
  always discharged by `Stream.run`.

## 7. Milestones

| M | What |
|---|---|
| **A: foundation** | |
| M1 | scaffold: dune-project, opam, licenses, gates.sh, ZXCAML.md, DESIGN.md, FACTS.md |
| M2 | live probe I: models list + headers + one SSE stream recorded to fixtures/ (redacted); FACTS pins or corrections |
| M3 | errx + bytesx (total cursor readers: u8/u16le/u32le/u64le/take at offset) + hexx strict + b64x (strict std base64 AND base64url) + tests |
| M4 | jsonx port + scaled-decimal extension + tests |
| **B: domain model** | |
| M5 | modelx: capability phantom row + packed existential, known slugs + Unknown, quantization/privacy/deprecation enums, /models parser -> witnesses + tests |
| M6 | paramsx: constraint-bounded sampling newtypes minted from the model's constraints; venice_parameters typed + tests |
| M7 | msgx: roles, nonempty messages, content parts; vision/audio parts require the capability witness + tests |
| M8 | headx: rate-limit sextet + x-ratelimit-type + Diem/USD decimal balances + Tier + typed 429/4xx/5xx + tests |
| M9 | chat request encoder + context budget check (prompt vs availableContextTokens, max_tokens vs maxCompletionTokens, boundary tests); byte-exact golden tests vs fixtures |
| M10 | chat response parser: choices, usage, finish_reason variants + tests |
| M11 | ssex: incremental SSE state machine, bounded, data:/[DONE], CRLF and LF + delta parse + tests |
| M12 | compile-fail harness I: domain misuses + compiling control |
| **C: transport + effects** | |
| M13 | transport boundary: sans-io Request/Response, curl-subprocess host transport, API-key redaction, fake transport + tests |
| M14 | streamx: effect Delta, handlers (run/iter/fold), direct-style demo, scripted-transport determinism tests |
| M15 | clientx: chat, chat_stream, models; bounded typed retry/backoff honoring reset headers; fake-transport e2e + tests |
| **D: crypto tower (core subset)** | |
| M16 | limbsx port + modexp + tests |
| M17 | hmacx + HKDF-SHA256 (RFC 5869 vectors) + tests |
| M18 | keccakx: keccak-256 + eth address derivation; Ethereum vectors + independent python keccak in harness + tests |
| M19 | p256x port: ECDSA-P256/SHA-256 verify, psychic rejects + tests |
| M20 | secpx: secp256k1 over limbsx, ECDSA verify + ECDH; Wycheproof-subset pins + tests |
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
