#!/usr/bin/env bash
# M22 live probe (DESIGN.md row M22, brief D4). The gate NEVER calls
# this script. Run it the day a VENICE_API_KEY exists, and it closes the
# live debt of M22 in one command: it mints a nonce, captures one
# attestation body and CHECKS that body with harness/diff_quote.py, so a
# capture cannot sit on disk unverified.
#
# usage: scripts/probe_attestation.sh MODEL
#
# MODEL is a Venice model id. The ids come from GET /models on the same
# base URL, and the TEE slugs are the ones FACTS.md records for the
# confidential models.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"

# The key guard runs FIRST and reads the variable through the colon-dash
# default. Under set -u a bare reference aborts the shell with exit 1
# and "VENICE_API_KEY: unbound variable" before this guard could run.
if [ -z "${VENICE_API_KEY:-}" ]; then
  echo "probe_attestation: VENICE_API_KEY is unset, the probe needs a key" >&2
  exit 2
fi

if [ "$#" -ne 1 ]; then
  echo "usage: scripts/probe_attestation.sh MODEL (ids from GET /models)" >&2
  exit 2
fi
model="$1"

# The interpreter is resolved exactly as gates.sh lines 41 to 44 do. It
# mints the nonce and it runs the check leg. Nothing on this path
# reaches the network.
py="$(command -v python3 || true)"
if [ -z "$py" ]; then
  py="/opt/homebrew/bin/python3"
fi

curl_bin="$(command -v curl || true)"
if [ -z "$curl_bin" ]; then
  echo "probe_attestation: no curl on PATH" >&2
  exit 2
fi

# 32 bytes, the 64 hex characters the endpoint demands. A shorter nonce
# is rejected by the provider.
nonce="$("$py" -P -c 'import secrets;print(secrets.token_hex(32))')"

utcdate="$(date -u +%Y%m%d)"
slug="${model//\//_}"
capture="$here/fixtures/attestation_${slug}_${utcdate}.json"
url="https://api.venice.ai/api/v1/tee/attestation?model=${model}&nonce=${nonce}"

# The config reaches curl on STDIN, so argv is exactly the four words
# CURL.md pins: the binary, "-q", "-K" and "-". "-q" stays FIRST, which
# skips ~/.curlrc, because a user curlrc that holds -v would echo the
# Authorization header to stderr.
#
# The config is written by the SHELL BUILTIN printf through a pipe, and
# NOT by a here-document. bash spools a here-document through a
# temporary FILE, and CURL.md W2 pins that the config "never touches the
# file system". A builtin forks no process either, so ps never sees the
# key. The option order is the golden order of CURL.md lines 46 to 62,
# with "include" and "no-buffer" dropped: headers are NOT captured,
# because the balance headers FACTS.md records are the user's private
# numbers.
curl_config() {
  printf '%s\n' 'no-progress-meter'
  printf '%s\n' 'silent'
  printf '%s\n' 'show-error'
  printf '%s\n' 'fail-with-body'
  printf '%s\n' 'globoff'
  printf '%s\n' 'noproxy = "*"'
  printf '%s\n' 'proto = "=https"'
  printf '%s\n' 'tlsv1.2'
  printf '%s\n' 'connect-timeout = "10"'
  printf '%s\n' 'max-time = "60"'
  printf '%s\n' 'user-agent = "venice-ocaml/m22-probe"'
  printf '%s\n' "header = \"Authorization: Bearer ${VENICE_API_KEY}\""
  printf '%s\n' 'header = "Accept: application/json"'
  printf '%s\n' 'header = "Expect:"'
  printf '%s\n' "url = \"${url}\""
}

mkdir -p "$here/fixtures"
echo "probe_attestation: model $model, nonce $nonce"
echo "probe_attestation: capture $capture"

# BODY ONLY. The redirect keeps argv at the four pinned words, so no
# output option joins the command line either.
curl_config | "$curl_bin" "-q" "-K" "-" > "$capture"

# The check leg, which is harness/diff_quote.py live FILE --expect-nonce
# NONCE. A capture that does not satisfy the W1 binding, the W3 layout
# or the W10 payload bound makes this script exit non-zero, and the exit
# status of the whole probe is the exit status of the check.
# The status is captured in an if-condition so set -e cannot abort the
# script before the delete command reaches the terminal.
if "$py" -P "$here/harness/diff_quote.py" live "$capture" \
    --expect-nonce "$nonce"; then
  status=0
else
  status=1
fi

echo "probe_attestation: delete the capture with this command when the"
echo "probe_attestation: pins it fed are recorded in FACTS.md:"
echo "  rm $capture"
exit "$status"
