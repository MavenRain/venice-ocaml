# venice-ocaml

An independent OCaml SDK for the Venice AI API, with typed model capabilities,
streaming chat through OCaml 5 effect handlers, and bounded retries with
per-attempt reporting. This is a community project, not an official Venice AI
SDK.

## Current capabilities

- Discover models and build requests using capability witnesses derived from
  the model listing. Features such as tools and vision require the matching
  witness, so requests cannot attach those features to an unrelated model.
- Build chat messages and validated sampling parameters, including
  Venice-specific search and reasoning options.
- Send chat requests or consume streaming content through a scoped cursor.
  Streaming distinguishes completion, an interrupted stream, and failure.
- Configure bounded retries and inspect the attempts, delays, and reason the
  client stopped retrying. Ambiguous transport failures are not automatically
  treated as safe to replay.
- Handle failures explicitly through `Result` and `Option` values. The public
  API is documented in [lib/venice.mli](lib/venice.mli).

The shipped client currently exposes model discovery and chat, including
streaming. It does not implement every Venice API endpoint.

## Build from source

Requirements: opam, OCaml 5.1 or newer, Dune 3.0 or newer, and the OCaml `sha2`
package. The shipped transport uses a `curl` executable, version 7.67.0 or newer,
on a Unix-like host.

For a fresh checkout, the following selects OCaml 5.3.0 in a local opam switch:

```sh
git clone https://github.com/MavenRain/venice-ocaml.git
cd venice-ocaml
opam switch create . ocaml-base-compiler.5.3.0
eval "$(opam env)"
opam install . --deps-only
dune build
```

If you already have a suitable switch, activate it and start with the dependency
installation step. To install the library into that switch from this checkout:

```sh
opam install .
```

The package and Dune library name are `venice_ocaml`; the OCaml module is
`Venice`. Add `venice_ocaml` to your application's Dune `libraries` field.

## Run the streaming example

Set `VENICE_API_KEY` in your environment using your usual secret management
method, then run:

```sh
dune exec examples/stream_demo.exe
```

This makes a live Venice API request using your account. The example fetches
text models, selects a preferred available model (or the first listed model),
sends "Say hello in five words.", and prints content as it arrives, followed by
the model, stream outcome, and retry report.

[examples/stream_demo.ml](examples/stream_demo.ml) is a complete example using
only the public API: `Api_key.from_env`, `Client.Make`, `Client.models`,
`Chat.make`, `Client.chat_stream`, and `Stream.iter`.

The curl transport sends the request configuration, including the API key,
through the child process's standard input. It disables the user's `.curlrc`
and redacts the key from captured curl error output. Request contents are sent
to Venice over HTTPS. The example does not establish an E2EE session or verify
the serving environment's attestation. See [CURL.md](CURL.md) for transport
behavior, limits, timeouts, and environment handling.

## Attestation and encryption status

Client-side TDX attestation and E2EE are under development. The repository
contains internal cryptographic primitives, a TDX v4 quote parser, measurement
and REPORTDATA policy checks, quote signature verification, PCK certificate
validation against a pinned Intel root, and signed TCB and QE identity checks.
The public `Tee` API composes these checks while preserving the full or
structural expectation level. Supply trusted measurements, a current instant,
collateral and response bytes. It performs no network request itself.

`Fresh.make` draws a challenge from `Entropy.system ()`. Pass `Fresh.nonce`
to `Tee.verify`, then pass the same handle to `Session.establish`. Establishment
consumes the handle on its first attempt, including failures and concurrent
aliases. It requires a full attestation and an E2EE model capability, rechecks
certificate and collateral validity at the supplied time, requires both TCB
grades to be `UpToDate`, and rejects present GPU evidence. It also requires
`Session.Cpu_only.trust ~measurements`: an explicit caller assertion that the
trusted measurement set confines inference to the CPU TEE. The SDK checks those
measurements against the signed quote. Missing unsigned GPU metadata cannot
establish this deployment property. Matching model
metadata provides routing consistency; the signed measurements and signing
key provide identity. Repeated quote verification is allowed, but session
admission consumes each handle once.

The synthetic response fixture demonstrates rejection paths, not a successful
Venice attestation.  Its real signed quote carries Phala's binding.  GPU payloads
receive structural and nonce checks only;  NRAS authentication and CRL checks
remain outside the pipeline. Session establishment derives an ephemeral
secp256k1 keypair and an opaque AES key through ECDH and HKDF-SHA256.
`Session.request ~entropy session chat` now prepares an encrypted HTTP request.
It validates the complete chat before drawing entropy, encrypts each user or
system text message with its own nonce, and assembles streaming and E2EE
settings and the attested public-key headers. Send the immutable result through
`Transport`. Apply `Session.Stream` to that transport, then call
`run session body consume` to read GCM-checked chunks through the existing
stream cursor. Nonempty content and reasoning frames are authenticated before
each chunk is yielded. The stream requires `[DONE]` by default, rejects
identity changes, and closes the body on completion, failure or an early
consumer exit. Pass `~closing:Sse.Allow_eof` when a stream ends at a clean
EOF.

Always inspect the returned stream outcome. Chunks are provisional: GCM alone
does not establish the attested signer's identity or protect transcript order
and freshness. Receipt verification remains M33 work. An active network
attacker can replace a content or reasoning frame with `""` or `null`, or drop
a whole chunk. The decoder accepts a blanked field as metadata, so deletion and
truncation stay undetectable until M33 receipt verification. A later failure
cannot retract chunks already consumed. The implementation follows the
synthetic M31 fixture; successful live interoperability remains unconfirmed.

This first request path accepts bare-string user/system content without names.
Other roles, multipart content, tools, schemas, stop strings, cache keys,
characters and enabled search reject. Sampling options and routing metadata
remain visible. `Session.encrypt ~fresh session plaintext` also returns an
opaque `Ciphertext.t`; obtain its distinct nonce handle with `Gcm_fresh.make`.
Each attempt burns the handle, including failures. Session aliases share an
atomic registry that rejects duplicate nonce bytes from different handles and
caps reservations at 65,536 per session. A new session is then required.
Nonce and ephemeral-key generation depend on OS entropy; the registry does not
coordinate separate processes or independently established sessions.

No successful live
Venice session is covered by the current fixtures. The cryptographic
implementation does not provide a blanket constant-time guarantee; secret
zeroization remains planned hardening work.

M31 provides a protocol diagnostic for a fixed public prompt:

```sh
python3 -I scripts/probe_e2ee.py MODEL /tmp/venice-e2ee-capture.json
python3 -I harness/diff_e2ee.py /tmp/venice-e2ee-capture.json
```

Set `VENICE_API_KEY` in the environment before running the probe. It checks
model capability, encrypts the public prompt, authenticates encrypted response
frames and checks the receipt against the exact request and SSE bytes. It
writes a capture only after these checks pass. Credentials, private keys and
decrypted output are excluded. The output path must not already exist.

This independent Python diagnostic does not establish an OCaml `Session` or
verify full TDX, TCB, measurement or GPU trust. Its fixture is synthetic, and
live confirmation is still pending. Replaying a live capture verifies receipt
signatures and frame structure; repeating GCM authentication would require the
discarded client scalar. See [validation/m31.md](validation/m31.md) for scope
and [fixtures/README.md](fixtures/README.md) for provenance.

See the milestone roadmap and current limitations in [DESIGN.md](DESIGN.md).
The package metadata describes the intended architecture; this README describes
the capabilities currently available to SDK users.

## Tests and development

Run the OCaml test suites without a Venice API key:

```sh
dune runtest
```

The repository also includes compile-failure checks, fake transports, pinned
cryptographic vectors, and Python differential harnesses. The broader
[gates.sh](gates.sh) workflow requires additional developer tools and external
fixtures described in the script and [DESIGN.md](DESIGN.md); it is not required
to build or use the SDK.

- [FACTS.md](FACTS.md): protocol observations and source references.
- [fixtures/README.md](fixtures/README.md): attestation fixture provenance.
- [CURL.md](CURL.md): subprocess transport contract.
- [DESIGN.md](DESIGN.md): architecture, validation approach, and roadmap.

## License

Dual licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
Third-party attestation fixture attribution is documented in
[fixtures/README.md](fixtures/README.md).
