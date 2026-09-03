# curl operating card

Read this before transport work.  Do not re-derive the curl surface.

The card records the curl and OCaml runtime facts the transport
depends on.  Venice wire facts stay in FACTS.md.  Every claim below
was measured against `/usr/bin/curl 8.7.1` and OCaml 5.3.0, or read
from `man curl` and the curl source at the cited anchor.

## Pins

- The transport never puts a secret on the command line.  argv is
  exactly `[binary; "-q"; "-K"; "-"]`.  `ps` shows the binary and two
  flags.
- `-q` (`--disable`) must stay FIRST.  It skips `~/.curlrc`.  A user
  curlrc that holds `-v` would echo the request headers, the API key
  included, to stderr (W1).
- `-K -` (`--config -`) reads the config from stdin.  The config dies
  with the process.  It never touches the file system (W2).
- The version floor is curl 7.67.0.  `Curl.make` probes the binary
  once with argv `[binary; "--version"]` and rejects below the floor.
- Proxies are DISABLED.  The config holds `noproxy = "*"`, which the
  man page calls the wildcard that "effectively disables the proxy"
  (man curl 3039-3042).  Proxy support is a separate milestone and
  needs a real-proxy test.

## The config file

Parsing is line based.  One option per line.  A line whose first
non-blank character is `#` is a comment.  A quoted value supports the
escapes `\\`, `\"`, `\t`, `\n`, `\r` and `\v`.  A backslash before any
other character yields that character (W2).

The renderer touches two bytes and no others:

| source byte | rendered as |
| ----------- | ----------- |
| `\`         | `\\`        |
| `"`         | `\"`        |

Every other byte, control bytes and non-ASCII bytes included, passes
through unchanged inside the quotes.  So an all-backslash body renders
as a line of twice its length.  Plan for that 2x factor when you size a
body against the line cap.

The rendered order is fixed and golden tested:

```
no-progress-meter
show-error
no-buffer
include
globoff
noproxy = "*"
proto = "=https"
tlsv1.2
connect-timeout = "N"
speed-limit = "1"
speed-time = "N"
max-time = "N"            (only when the caller set one)
user-agent = "venice-ocaml/VERSION"
header = "Authorization: Bearer KEY"
header = "Accept: application/json"
header = "Expect:"
header = "Content-Type: application/json"   (POST only)
header = "NAME: VALUE"    (one per custom header, in mint order)
url = "URL"
data-binary = "BODY"      (POST only)
```

`no-progress-meter` leads instead of `silent`.  `silent` suppresses the
one diagnostic that names a config failure.  With `silent` plus
`show-error` an unknown option leaves only "option -K: error
encountered when reading a file".  Without it curl prints
"<stdin>:3: 'bogus-opt' is unknown".  `no-progress-meter` needs curl
7.67.0, which is why the floor is there.

No `request =` line exists.  curl infers POST from `data-binary` and
GET otherwise.  `header = "Expect:"` suppresses curl's own
100-continue request.

## The config-line cap

A config line may be up to 10 megabytes since curl 8.2.0 (man curl
605-607).  Older releases cap far lower in `MAX_CONFIG_LINE_LENGTH`
(`src/tool_parsecfg.c`), so the transport clamps to 65_536 there.

Measured on 8.7.1: a line of 10_485_756 bytes parses.  A line of
10_485_786 bytes fails with exit 26 and makes no request.

`Curl.max_line` reports the cap for the probed binary.  It is
10_485_248 (10 MiB less 512 bytes of slack under the measured
boundary) from 8.2.0, and 65_536 below it.  `Http.Request.post` caps
the RAW body at 4_194_304 bytes, which stays 2x safe under the 10 MiB
line cap even for an all-backslash body.  `Curl.send` measures the
whole rendered data line before it spawns anything.

An over-long line is not a warning.  curl aborts the WHOLE config with
exit 26.  An unknown option does the same.

## The version probe

`Curl.make` runs argv `[binary; "--version"]`, reads stdout and parses
the first line `curl MAJOR.MINOR.PATCH ...` with total combinators.
No secret rides on that command line.

- A spawn failure rejects with `transport: spawn: ...`.
- An unreadable first line rejects with
  `transport: version: unreadable curl version line: ...`.
- A triple below 7.67.0 rejects with
  `transport: version: curl 7.67.0 or newer required, found X.Y.Z`.

## Head bytes on stdout

`include` prints one head block per response: the status line, the
header lines, a blank line, then the body.

curl relays HTTP/1.x head bytes VERBATIM.  Bare LF terminators and
mixed terminators inside one head reach the reader unchanged
(measured against a loopback server: exit 0, head
`HTTP/1.1 200 OK\nContent-Length: 5\n...`).  curl synthesizes the
status line and CRLF terminators only for HTTP/2, where the status
line is `HTTP/2 200` with no reason phrase and the header names are
lowercase.

So Wirex accepts CRLF or bare LF per line.  A bare CR still rejects.
An obs-fold continuation line still rejects.

A 1xx interim response prints an EXTRA head block first.  A 103 Early
Hints block prints separately, before the 200.  Wirex skips up to four
informational blocks and stops on the first final one.

## Exit codes

curl returns 0 for ANY HTTP status while `--fail` is absent, so the
status code comes from the head, never from the exit code.

The transport names this documented subset (W6):

| code | meaning appended by `close` |
| ---- | --------------------------- |
| 6    | dns: could not resolve host |
| 7    | connect: failed to connect to host |
| 23   | write error: the reader closed the pipe |
| 26   | config rejected: unknown option or over-long line |
| 28   | timeout: operation timed out |
| 35   | tls handshake failed |
| 52   | empty reply from server |
| 56   | recv failure |
| 60   | certificate verify failed |

Any other code prints `curl exit N: TAIL` with no meaning.

`speed-limit = "1"` with `speed-time = "N"` is the idle guard.  curl
aborts with exit 28 after N seconds below 1 byte per second.  The
guard fires before the first response byte, so a server that never
answers still times out.

## The IO trap

Never read curl's two pipes one after the other.  A child that writes
1 MiB to stderr before it closes stdout blocks in `write(2)` at the
64 KiB pipe capacity, and the stdout read never reaches EOF.  Stopping
the stderr read at 4096 bytes and then waiting hangs the same way.

The transport reads RAW descriptors with `Unix.read`, multiplexed by
`Unix.select` with no timeout (curl's own timeouts bound the wait).
stderr readiness goes into a ring that keeps the LAST 4096 bytes.
stdout readiness yields the next chunk or marks EOF on a zero read.
Only after stdout EOF, or after the early-close kill, is stderr
drained to EOF with blocking reads.

The config still goes out through the `out_channel`, then
`close_out`.  `close_process_full` owns every other channel close.

`Curl.make` sets SIGPIPE to ignore, once, process wide.  Without it a
dead curl kills the HOST process on the config write.

## Redaction

curl prints option NAMES in its diagnostics, never values.  The
transport still replaces the key bytes with `[redacted]` in every
stderr tail before the tail can reach an error text.  That is defense
in depth, not a fix for a known leak.

## OCaml 5 runtime facts (W7)

- `Unix.open_process_args_full prog args env` searches PATH for prog
  since 4.12 (unix.mli 962-964).
- `Unix.process_full_pid` exposes the pid (unix.mli 1010).
- `Unix.close_process_full` waits and returns the `process_status`
  (unix.mli 1031-1035).
- `In_channel.input` returns 0 at EOF and raises `Sys_error` on
  failure (in_channel.mli 126-131).  The transport reads the raw
  descriptor instead, where `Unix.read` returns 0 at EOF and raises
  `Unix_error` on failure.  Both go through the one guard.
- `Sys.set_signal Sys.sigpipe Sys.Signal_ignore` turns a dead reader
  into `EPIPE` instead of process death (stdlib.mli 1051-1057,
  1175-1179).
- A missing binary raises `Unix_error ENOENT "create_process"` in the
  parent.
- Killing a dead pid raises `ESRCH`.  The transport ignores that one
  case.
- OCaml signal constants are NEGATIVE internal numbers.  `Sys.sigterm`
  is -11 on 5.3.  Never print a signal as an exit code.

## Recorded experiments

- `suppress-connect-headers` DOES suppress a proxy CONNECT block
  without `-p` on 8.7.1 (stdout empty with the option, `HTTP/1.1 200
  Connection established` without it).  The man page documents the
  option for `-p, --proxytunnel` alone, so the wording understates it.
  Proxies stay disabled anyway, because `noproxy = "*"` is
  deterministic and testable through the fake-curl oracle.
- The escaping table round-trips end to end.  The config line
  `data-binary = "{\"a\":\"b\\\\c\\\"d\"}"` puts exactly
  `{"a":"b\\c\"d"}` on the wire.

## Sources

- `man curl`, lines 605-607 (config-line length since 8.2.0)
- `man curl`, lines 3039-3042 (`--noproxy` and the `*` wildcard)
- `man curl`, lines 4973-4976 (`--suppress-connect-headers`)
- `man curl`, EXIT CODES section
- curl source `src/tool_parsecfg.c` (`MAX_CONFIG_LINE_LENGTH`, the
  dynbuf rewrite)
- OCaml 5.3 `unix.mli` 962-964, 1010, 1031-1035
- OCaml 5.3 `in_channel.mli` 126-131
- OCaml 5.3 `stdlib.mli` 1051-1057, 1175-1179
