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
The internal attestation pipeline composes these checks while preserving the
full or structural expectation level.  These modules are not yet a public
attestation API.

The synthetic response fixture demonstrates rejection paths, not a successful
Venice attestation.  Its real signed quote carries Phala's binding.  GPU payloads
receive structural and nonce checks only;  NRAS authentication and CRL checks
remain outside the pipeline.  Public attestation integration, encrypted session
establishment, and encrypted streaming remain planned work.  The cryptographic
implementation does not provide a blanket constant-time guarantee.

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
