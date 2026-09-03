(* M13 cfgx: the curl config renderer. This is the ONE place the API
   key becomes bytes.

   The command line carries no secret and no request detail: argv is
   exactly [binary; "-q"; "-K"; "-"], so `ps` shows nothing but the
   binary and two flags. "-q" must stay FIRST, because it disables
   ~/.curlrc, and a user curlrc holding "-v" would echo the request
   headers (the key included) to stderr.

   Everything else arrives on stdin as a config file. Rendering is
   pure, so the exact bytes curl receives are golden-testable without
   a process, and the fake-curl capture oracle proves the same bytes
   end to end. *)

val argv : binary:string -> string array
(* [| binary; "-q"; "-K"; "-" |] and nothing else *)

val render :
  key:Keyx.t ->
  endpoint:Httpx.Endpoint.t ->
  connect_timeout:int ->
  idle_timeout:int ->
  max_time:int option ->
  Httpx.Request.t ->
  string
(* The fixed golden order, one option per LF-terminated line, every
   value double-quoted with the curl -K escaping (backslash doubles,
   double quote escapes, nothing else is touched):

     no-progress-meter / show-error / no-buffer / include / globoff /
     noproxy = "*" / proto = "=https" / tlsv1.2 /
     connect-timeout = "N" / speed-limit = "1" / speed-time = "N" /
     [max-time = "N" only when Some] / user-agent = "venice-ocaml/V" /
     header = "Authorization: Bearer KEY" /
     header = "Accept: application/json" / header = "Expect:" /
     [header = "Content-Type: application/json" on POST] /
     one header = "name: value" per custom header in mint order /
     url = "URL" / [data-binary = "BODY" on POST].

   no-progress-meter leads instead of silent (A17): silent suppresses
   the one diagnostic that names a config failure, and it needs curl
   7.67.0, which is why Curl.make enforces that floor. noproxy = "*"
   disables every proxy (A1), so a CONNECT block can never be handed
   back as the Venice response head. No request = line exists: curl
   infers POST from data-binary and GET otherwise. *)

val data_line_bytes : string -> int
(* The rendered length of the data-binary line for this body: the
   option name, " = \"", the ESCAPED body, the closing quote and the
   LF. Curl.send measures this against the version-dependent curl
   config-line cap before it spawns anything. *)
