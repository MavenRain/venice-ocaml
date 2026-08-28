#!/usr/bin/env bash
# omlz wrapper: ZxCaml (OCaml -> SBF) compiler driver.
# Known-good invocation shape mirrors zxcaml-bench/omlz-run.sh:
# PATH gets zig 0.16.0 + solana-zig, opam switch zxcaml-p1, cwd = zxcaml repo.
# Pass ABSOLUTE paths for source files and -o outputs.
set -euo pipefail
export PATH="$HOME/zig/zig-aarch64-macos-0.16.0:$HOME/.local/bin:$PATH"
eval "$(opam env --switch=zxcaml-p1 --set-switch)"
ZXCAML_ROOT="${ZXCAML_ROOT:-$HOME/Documents/claude1/zxcaml-bench-src}"
cd "$ZXCAML_ROOT"
exec zig-out/bin/omlz "$@"
