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

## Sources
- https://docs.venice.ai/api-reference/api-spec
- https://docs.venice.ai/guides/features/tee-e2ee-models
- https://docs.venice.ai/api-reference/endpoint/models/list
- https://phala.com/posts/venice-ai-phala-tee-verifiable-private-ai
- https://featurebase.venice.ai/en/help/articles/7782904-how-do-i-access-the-api
- https://venicestats.com/faq (Diem economics)
