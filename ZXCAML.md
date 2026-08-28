# ZXCAML operating card

Read this before omlz work. Do not re-derive the toolchain.

## Toolchain
- Compiler checkout: `~/Documents/claude1/zxcaml-bench-src` (`ZXCAML_ROOT`).
- Build driver: `scripts/omlz.sh` in this repo. It puts zig 0.16.0 and
  `~/.local/bin` on PATH, selects opam switch `zxcaml-p1`, changes to
  `ZXCAML_ROOT`, and execs `zig-out/bin/omlz`.
- Pass ABSOLUTE paths for source files and `-o` outputs.
- Verbs: `check` is the fast parse/type gate. `build --target=bpf` is the
  real codegen gate.

## The four codegen traps
1. A unit conditional around a data write fails bpf codegen
   (UnsupportedExpr at build). Writers must be straight-line. Move the
   guard to the caller.
2. Top-level `let` constants are invisible inside helper functions in the
   emitted Zig. Only the entrypoint sees them. Bind them locally in each
   helper.
3. Account-data writes must go through the witness intrinsics: `read_u8`,
   `read_u64_le`, `write_u64_le`, `set_account_data`. omlz matches them BY
   NAME and discards their bodies. Real `Bytes` operations are for scratch
   buffers only.
4. `omlz check` exit 0 does NOT prove codegen. Only
   `omlz build --target=bpf` does.

## zxlint (enforced)
- `zxlint --errors-only FILE.ml ...` pre-screens traps 1-3. Installed at
  `~/.local/bin/zxlint`. Source: `~/Documents/zxlint`.
- The `zxlint-gate.py` PreToolUse hook runs it on every
  `omlz ... build --target=bpf ... FILE.ml` Bash command and denies on
  blocking findings. Warnings never block. For a DELIBERATE trap probe,
  append `[skip-zxlint]` to the command.
- For a multifile program, pass every file in one call, core module first.

## Session discipline (token cost)
- Batch each build cycle into ONE Bash command:
  `scripts/omlz.sh build --target=bpf F.ml -o F.so && <run test>`.
  One measured session had 42 single-command turns; batching removes ~92%
  of that output bucket.
- Revise files with Edit or `sd`, not full-file Writes. The
  `write-input-size-guard.py` hook denies large high-overlap rewrites.

## Session 3 additions (2026-08-25)
5. CPI is near-unusable: `Cpi.invoke*` compiles ONLY as the bare tail of
   a top-level entrypoint match arm with literal sibling arms. In an
   if branch, in a helper, under a nested match, after in-arm lets,
   before follow-up code, next to a binding arm (`| d -> d`), or with an
   account field access (`a.key`) inside the record literal: all
   UnsupportedExpr. Consequence: the program does not CPI; the client
   creates the treasury account in the same transaction as Init.
6. `Syscall.sol_get_rent_lamports_per_byte_year` returned an unusable
   value under the deployed Agave runtime. The rent constants are frozen
   network-wide; bind lamports_per_byte_year = 3480 locally.
