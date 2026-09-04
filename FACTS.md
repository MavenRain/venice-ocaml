# Venice wire facts (research digest, 2026-08-27)

Source of truth for the design. Every fact below is a hypothesis until a
live probe confirms it (M2 pins the probe fixtures). Re-verify on SDK bumps.

## Base API
- Base URL `https://api.venice.ai/api/v1`, auth `Authorization: Bearer <key>`.
- OpenAI-compatible: `/chat/completions` (SSE streaming), `/models` (query
  param `type` in {text, code, image, embedding, tts, asr, music, upscale,
  inpaint, video, all}), `/embeddings`, image/audio/video endpoints.
- `venice_parameters` request object (swagger 2026-08-30, saved at
  `~/Documents/venice-swagger.yaml`): `character_slug` (string),
  `strip_thinking_response` (bool, default false), `disable_thinking`
  (bool, default false), `enable_e2ee` (bool, default true; false runs
  an E2EE-capable model TEE-only even when E2EE headers are present, so
  it is a downgrade lever), `enable_web_search` (string enum
  auto | off | on, default off), `enable_web_scraping` (bool, false),
  `enable_web_citations` (bool, false),
  `include_search_results_in_stream` (bool, false),
  `return_search_results_as_documents` (bool, no default),
  `include_venice_system_prompt` (bool, default true),
  `enable_x_search` (bool, false). CORRECTION to the 2026-08-27 digest:
  `prompt_cache_key` (string) and `prompt_cache_retention` (string) are
  TOP-LEVEL chat request members, not venice_parameters members.
- Sampling windows on the chat request (swagger, inclusive edges):
  `temperature` number 0..2, `top_p` number 0..1, `frequency_penalty`
  number -2..2 default 0, `presence_penalty` number -2..2 default 0,
  `repetition_penalty` number >= 0 no maximum (1.0 = no penalty),
  `top_k` integer >= 0, `max_tokens` / `max_completion_tokens` integers
  with no schema bounds (model window is the real cap, M9).

## Response headers
- Rate limits: `x-ratelimit-limit-requests`, `x-ratelimit-remaining-requests`,
  `x-ratelimit-reset-requests` (unix ts), `x-ratelimit-limit-tokens`,
  `x-ratelimit-remaining-tokens`, `x-ratelimit-reset-tokens` (seconds),
  `x-ratelimit-type` (user | api_key | global).
- Balances: `x-venice-balance-usd`, `x-venice-balance-diem`.
- Tiers: Explorer (Pro account, low limits) vs Paid (positive USD/Diem).
  Diem = ERC-20 on Base; 1 Diem staked grants up to $1/day API credit,
  renewing daily; minted by locking sVVV. "VCU" is the legacy name for the
  staking-derived inference unit; the API surfaces Diem + USD.

## Retry
- Landed at M15: a bounded retry loop over a clock boundary.
  `Venice.Client` retries a request only for a closed set of
  obstacles:  a never-sent transport failure, a 429, and the three
  gateway statuses 502, 503 and 504.  The caps (attempts, per-wait
  delay, total waiting time) are policy fields, so the loop is bounded
  by construction and not by a timeout.
- The rate-limit hint comes from the sextet above.  On a 429 the
  client reads the reset field of each EXHAUSTED triple, converts it
  to milliseconds, and waits the larger of the two.  A
  `x-ratelimit-reset-requests` value is a unix timestamp, so the delay
  is that value minus the clock now;  a `x-ratelimit-reset-tokens`
  value is already a duration in seconds.
- `retry-after` is read in its delay-seconds form only (RFC 7231
  section 7.1.3, ASCII digits).  The HTTP-date form is ignored, so a
  server that sends only a date reads as no hint and the client falls
  back to its own backoff.
- OPEN FACTS (pin at the M2 probe).  The M15 client assumes each one
  below, so a capture that refutes one is a client correction and not
  a new module.
  - M15 W1 states that a 2xx answer to POST /chat/completions with
    `stream:false`, and to GET /models, carries `content-type:
    application/json`, with an optional `; charset=utf-8` parameter.
    A 2xx with another media type refutes it.  M15 accepts a subtype
    of `json` or a `+json` structured suffix, and accepts an ABSENT
    content-type;  a present-and-wrong type is rejected as
    `Errx.Client_invalid`.
  - M15 W2 states that a 2xx answer to a `stream:true` request carries
    `content-type: text/event-stream`.  The swagger says
    application/json only, so this hypothesis has a documented
    CONTRADICTION on the wire.  M15 therefore fails closed:
    text/event-stream streams, `application/json` on the stream path
    is REFUSED rather than parsed as one silent empty stream, and any
    third media type is rejected.  A capture of a JSON-bodied stream
    answer refutes it.
  - M15 W3 states that a 429 carries the sextet and that the
    exhausted triple reports `remaining` = 0.  A 429 whose exhausted
    triple has `remaining` > 0, or whose only hint is an HTTP-date
    `retry-after`, refutes it.  A 429 with no usable hint still
    retries on the client's own backoff.
  - M15 W4 states that 502, 503 and 504 are transient gateway answers:
    no completion was produced and no credit was charged.  500 and
    every other 5xx may have executed the request, so M15 does NOT
    retry them.  Venice documentation or a capture that charges for a
    503 refutes it.
  - M15 W5 states that curl exit 6 (DNS), 7 (connect) and 35 (TLS
    handshake) prove that no request byte reached a Venice server.
    Those three exits alone map to `Errx.Transport_unreachable` and
    alone allow a POST re-send.  Exit 28 (timeout) and exit 56 (recv
    failure) stay `Errx.Transport_failed` and never retry, because the
    timeout can strike after the request went out.  The curl man page
    or CURL.md saying that any of 6, 7 or 35 can fire after request
    bytes went out refutes it.
- Runtime fact (not a Venice fact, recorded here because the retry
  loop rests on it):  `Unix.sleepf` loops its own `nanosleep` on
  EINTR and rejects only an invalid duration, and `Unix.gettimeofday`
  does not fail.  The installed `unix.mli` is SILENT on both points,
  so the fact is read from the runtime source.  M15 adds no try-with;
  the repo keeps ONE guard, in curlx.
- The `/models` query parameter `type` is ALWAYS sent by M15, so the
  client never depends on the server default.  That default is
  UNPINNED:  no Venice page states what an absent `type` means.

## Model object (`/models`)
- `id`, `type`, `created`, `name`, `description`, `modelSource`, `offline`,
  `traits` (strings), `uncensored?`, `discount_to_user?`.
- `model_spec`: `privacy` (private | anonymized), `availableContextTokens`,
  `maxCompletionTokens`, `beta`, `regionRestrictions`, `deprecation`
  (dates + replacement).
- `capabilities` (text): `optimizedForCode`, `supportsFunctionCalling`,
  `supportsReasoning`, `supportsReasoningEffort`, `supportsResponseSchema`,
  `supportsVision`, `supportsVideoInput`, `supportsAudioInput`,
  `supportsWebSearch`, `supportsLogProbs`, `supportsTeeAttestation`,
  `supportsE2EE`, `supportsXSearch`, `supportsMultipleImages` (REQUIRED
  bool); `maxImages?`, `maxVideos?` (optional numbers); `quantization`
  (fp4 fp8 fp16 bf16 int8 int4 not-available); `reasoningEffortOptions?`.
- `constraints` (text, swagger "Text Model Constraints"): per-parameter
  objects holding ONLY a required `default` number: `temperature` and
  `top_p` are required members, `frequency_penalty`,
  `presence_penalty`, `repetition_penalty` optional. No per-model
  min/max exists; the request window above is the only bound. Image
  models use a different shape (`promptCharacterLimit`, `steps`
  {default, max}, `widthHeightDivisor`, `maxStyleReferences`, ...) and
  video models another (`aspect_ratios`, `resolutions`, `durations`
  string arrays), so a typed text view must not reject foreign keys.
- `pricing`: input/output usd + diem per million tokens; `cache_input?`,
  `cache_write?`, `extended?` long-context tier.
- Example TEE/E2EE slugs: `e2ee-qwen3-5-122b-a10b`, `e2ee-glm-5`.
  TEE/E2EE is text-models-only today.

## Chat messages (`/chat/completions` request)
- Roles: `system`, `developer`, `user`, `assistant`, `tool`.  Every role
  requires `role` + `content` except `assistant` (content optional:
  content or tool_calls) and `tool` (requires `tool_call_id` too).  Every
  role offers an optional `name`.  `messages` has `minItems: 1`.
- Content is either a bare string or a parts array.  Part shapes:
  `text` {`text`}, `image_url` {`url`}, `input_audio` {`data`,
  `format?`}, `video_url` {`url`}, `file` {`file_data`, `filename?`};
  each part takes an optional `cache_control`.  Tool content is
  string-only (no parts branch).
- Text parts carry `minLength: 1`;  the rule is on PARTS only, not on
  the bare-string content branch.  The SDK rejects "" on the bare-string
  constructors as a deliberate SDK rule.
- User `parts: []` is schema-legal (the parts array has no minItems);
  the SDK's nonempty-parts rule is SDK-imposed strictness.
- `input_audio.format`: wav | mp3 | aiff | aac | ogg | flac | m4a |
  pcm16 | pcm24;  default wav when absent.
- `cache_control`: `{"type": "ephemeral"}` with `type` REQUIRED.  `ttl`
  is a beta feature behind a special header whose name the swagger does
  not give;  OPEN FACT pending a probe.
- Video count cap: the prose says "at most 3" videos while the
  `maxVideos` example is 4;  contradiction is an M2-probe hypothesis;
  fallback 3 when `maxVideos` is absent.
- Video URLs have server-only conditions: no redirects, a permitted
  Content-Type, and provider-dependent YouTube support;  the SDK checks
  uri shape only.
- Single-image vision models (`supportsMultipleImages` false) silently
  DROP all but the last image-bearing message server-side;  the SDK
  exposes `multiple_images` / `max_images` / `max_videos` so a caller
  can warn instead of losing data.

## Tools (`/chat/completions` request + response)
- Four request members in the chat schema: `tools` (swagger 1627-1674),
  `tool_choice` (1610-1626), `parallel_tool_calls` (1549-1553, default
  true), `response_format` (1554-1609).
- `tools` items are an anyOf: a server-tool arm {`type`: web_search |
  x_search} and a function arm {`function`: {`name` REQUIRED,
  `description?`, `parameters?` (object), `strict?` default false},
  `id?`, `type?`} (1631-1671).  The SDK emits the function arm only;
  server tools wait for a capability gate and a pinned
  venice_parameters interaction.
- `tool_choice` is a two-arm anyOf: an OPEN string (no enum, 1626) or
  {`type`, `function`: {`name`}} (1612-1625).  The /responses schema
  pins ITS string arm to an enum (2314-2341); the chat schema does not.
  The SDK emits auto | none | required | the function object.
- `response_format` has three arms: json_schema, json_object
  (deprecated), text (the default).  The json_schema arm takes the
  schema object DIRECTLY under `json_schema` (1558-1567); there is no
  OpenAI {name, schema} wrapper.
- Assistant `tool_calls` items are UNTYPED and nullable in both the
  request (1071-1075) and the response message union (6516-6652).  Two
  candidate item shapes exist:
  - the OpenAI nested shape {`id`, `type`: "function", `function`:
    {`name`, `arguments`: string}} - the hypothesis the SDK
    canonicalizes to;
  - the /responses FLAT shape {`type`: "function_call", `id?`,
    `call_id`, `name`, `arguments`: string} (2043-2067 request,
    2497-2523 output) - a counter-example that proves Venice does not
    always use the nested shape.  It corroborates only `arguments` as
    a JSON-encoded string.
  An M2-style live probe of a chat tool-call turn is the tiebreak; the
  parser accepts the nested shape and keeps every item raw + verbatim,
  so a flat capture cannot lose bytes.
- `stop_reason` on a tool-call turn is an OPEN FACT: the response pins
  a nullable {stop, length} enum (6653-6659) and nothing says which
  value (or null) a `finish_reason: "tool_calls"` turn carries.  The
  M2 probe list gains the finish_reason + stop_reason pair.
- The REQUEST Tool Message (1081-1109) requires only `content`, `role`
  and `tool_call_id`; it also declares `reasoning_content` and its own
  `tool_calls`, both nullable and not required.  Those two are dead
  members: a caller-sent tool RESULT has no producer semantics for
  model reasoning or for nested calls, so `Msg.tool` omits them.
- The response Tool Message arm (role "tool", to 6652) declares content
  parts, reasoning members, and its own `tool_calls`: dead members the
  SDK never reads; the choice parser rejects the role with a
  path-carrying error.
- `venice_parameters.return_search_results_as_documents` INJECTS a
  synthetic tool call named "venice_web_search_documents" into the
  response (1528-1532): a tool_calls consumer can receive a call that
  names no tool it sent.
- E2EE disables function calling (see the E2EE section).

## TEE attestation
- `GET /tee/attestation?model=<id>&nonce=<64 hex>` . nonce MUST be exactly
  32 bytes (64 hex chars); providers reject shorter.
- Response: `verified` (server-side bool: advisory only), `nonce` (echo),
  `model`, `tee_provider` (Intel TDX | NVIDIA), `intel_quote` (base64 TDX
  quote), `nvidia_payload` (GPU attestation for NVIDIA NRAS),
  `signing_key` (pubkey the enclave signs responses with),
  `signing_address` (Ethereum address derived from signing_key).
- Client-side verification (the point of this SDK): parse the TDX quote,
  check nonce binding via REPORTDATA, reject debug TDs, verify the quote
  signature chain to the pinned Intel SGX Root CA, compare measurements
  (MRTD / RTMR0-3) against caller expectations, and bind signing_key into
  REPORTDATA. Exact REPORTDATA binding formula: pin from a live quote +
  the dstack source at the probe milestone (M22).
- Operators: Phala Network + NEAR AI Cloud (dstack stack), Intel TDX CPUs
  + NVIDIA Confidential Computing GPUs.
- `GET /tee/signature?model=<id>&request_id=<id>`: signature over the
  completion, verifies against `signing_address` (secp256k1 + keccak-256
  Ethereum address). The exact signed-message content (hash formula over
  the completion bytes + request_id) is UNPINNED: pin it at M31 and verify
  payload equality against the received bytes, not just signer identity.

## E2EE (encrypted prompts, TEE-terminated)
- Requires `stream: true`. Disables web search, file uploads, function
  calling.
- Crypto: ephemeral secp256k1 ECDH -> HKDF-SHA256 -> AES-256-GCM.
- Request headers: `X-Venice-TEE-Client-Pub-Key` (uncompressed hex,
  130 chars, leading `04`), `X-Venice-TEE-Model-Pub-Key` (from
  attestation), `X-Venice-TEE-Signing-Algo: ecdsa`.
- All `user` and `system` message contents must be encrypted (hex) when
  E2EE headers are present.
- Response chunks: hex, minimum 186 hex chars = 93 bytes:
  65-byte ephemeral pubkey || 12-byte GCM nonce || 16-byte tag || ct
  (tag position vs ct: pin exact layout from the live E2EE capture at M31).

## Streaming (SSE)
- /chat/completions 200 declares application/json only (swagger
  6432-6452);  the file has no text/event-stream, no chunk schema, zero
  `delta` members;  the only streaming prose is 1504-1509, 1522-1527
  and 2377.
- Framing: WHATWG event-stream profile, `data:` fields only.
  Divergences: bare CR terminators reject (the spec accepts CR);
  `event:`/`id:`/`retry:` fields are read and ignored (no dispatch
  types, no reconnect);  EOF with pending bytes rejects instead of the
  spec's silent discard.
- Termination convention: a literal `data: [DONE]` event ends a chat
  stream (OpenAI convention;  not in the swagger file).
- Landed at M14: cross-chunk accumulation of the M11 ssex tool_call
  fragments into Msgx.Tool_call.  `Venice.Sse.Acc` folds the chunks and
  renders one chat.completion document that `Respx.of_string` reads
  back, so the streaming path and the non-streaming path share ONE
  grammar.  The M11 per-chunk fragment view stays as it is.
- OPEN FACTS (pin at the M2 probe).  The M14 accumulator assumes each
  one below, so a capture that refutes one is an accumulator
  correction and not a new module.
  - Chunk schema unpinned;  the OpenAI-compat shape is a hypothesis.
    M14 W1 states that `id`, `model` and `created` hold constant across
    every chunk of one stream.  A second chunk with a different value
    refutes it.  M14 rejects such a stream today with `stream: id
    changed` and its siblings.
  - M14 W2 states that `role` arrives only in the first delta of a
    choice, with the value "assistant".  A later delta with a
    different role refutes it.  Ssex keeps the role verbatim, so a
    foreign role reaches the accumulator intact and fails in the one
    grammar instead of being rewritten.
  - M14 W3 states that a tool_call fragment carries `index` plus `id`
    plus `function.name` first, and `function.arguments` only after
    that.  A continuation fragment that repeats `id`, or a `name` that
    arrives in pieces, refutes it.  Fragment index DENSITY is an
    observation and not a rule:  M14 accepts sparse indices.
  - Usage placement, per-chunk against a usage-only final chunk.  M14
    W5 accumulates usage last-wins, so both shapes read the same and
    the raw usage bytes reach the rendered document.
  - Whether E2EE streams end with [DONE].  M14 W6 states that
    `data: [DONE]` terminates a chat stream, which the M11
    `Require_done` closing enforces.  A stream that ends at clean EOF
    needs `Allow_eof`, which `Stream.Make (T).run` forwards.
  - First-chunk search-results member shape.  M14 keeps
    `venice_parameters` RAW and unpublished, so it pins no shape.
  - Chunk finish_reason values.  M14 W4 states that `finish_reason` is
    non-null exactly once per choice, on that choice's last chunk.
    Two non-null values on one choice, or a choice that ends with
    none, refutes it.  The raw string survives the fold, and only
    `to_response` reads it through the closed Respx enum.
  - M14 W7 is ENFORCED and not open:  every chunk carries `object`
    equal to "chat.completion.chunk", plus `id`, `model`, `created`
    and a per-choice `index`.  A capture with a different object
    string is an M11 correction, not an M14 one.

## Transport
- The curl facts live in CURL.md at the repo root.  This file stays
  the VENICE wire digest, so its sources are Venice URLs only.

## Sources
- https://docs.venice.ai/api-reference/api-spec
- https://docs.venice.ai/guides/features/tee-e2ee-models
- https://docs.venice.ai/api-reference/endpoint/models/list
- https://phala.com/posts/venice-ai-phala-tee-verifiable-private-ai
- https://featurebase.venice.ai/en/help/articles/7782904-how-do-i-access-the-api
- https://venicestats.com/faq (Diem economics)
