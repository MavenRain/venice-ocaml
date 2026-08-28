# Venice wire facts (research digest, 2026-08-27)

Source of truth for the design. Every fact below is a hypothesis until a
live probe confirms it (M2 pins the probe fixtures). Re-verify on SDK bumps.

## Base API
- Base URL `https://api.venice.ai/api/v1`, auth `Authorization: Bearer <key>`.
- OpenAI-compatible: `/chat/completions` (SSE streaming), `/models` (query
  param `type` in {text, code, image, embedding, tts, asr, music, upscale,
  inpaint, video, all}), `/embeddings`, image/audio/video endpoints.
- `venice_parameters` request object: `enable_web_search`,
  `enable_web_scraping`, `enable_x_search`, `enable_web_citations`,
  `include_search_results_in_stream`, `return_search_results_as_documents`,
  `include_venice_system_prompt`, `character_slug`,
  `strip_thinking_response`, `disable_thinking`, `prompt_cache_key`.

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
  `supportsE2EE`, `supportsXSearch`; `quantization` (fp4 fp8 fp16 bf16
  int8 int4 not-available); `reasoningEffortOptions?`.
- `constraints` (text): temperature, top_p, frequency_penalty,
  presence_penalty, repetition_penalty, each with defaults.
- `pricing`: input/output usd + diem per million tokens; `cache_input?`,
  `cache_write?`, `extended?` long-context tier.
- Example TEE/E2EE slugs: `e2ee-qwen3-5-122b-a10b`, `e2ee-glm-5`.
  TEE/E2EE is text-models-only today.

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
