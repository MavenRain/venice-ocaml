(* Host orchestration. No secret escapes the public signature. *)
let ( let* ) = Result.bind
module Cpu_only = Sessx.Cpu_only
module Nonce_set = Set.Make (String)
type used = { nonces : Nonce_set.t; count : int }
type 'c t = { core : 'c Sessx.t; used : used Atomic.t }

let nonce_limit (() : unit) : int = 65_536

(* A single CAS reserves both the nonce bytes and the budget slot. Failed
   encryption never releases a reservation. Session aliases share this
   state, including when two domains use independently minted handles. *)
let rec reserve (session : 'c t) (nonce : Gcmx.Nonce.t) : (unit, Errx.t) result =
  let bytes = Gcmx.Nonce.to_bytes nonce in
  let before = Atomic.get session.used in
  match () with
  | () when Nonce_set.mem bytes before.nonces ->
    Error (Errx.Session_invalid "gcm nonce reused")
  | () when before.count >= nonce_limit () ->
    Error (Errx.Session_invalid "gcm nonce limit")
  | () ->
    let after = { nonces = Nonce_set.add bytes before.nonces;
                  count = before.count + 1 } in
    if Atomic.compare_and_set session.used before after then Ok ()
    else reserve session nonce

let establish ~(entropy : Entropyx.t) ~(fresh : Entropyx.Fresh.t)
    ~(cpu_only : Cpu_only.t)
    ~(now : Derx.Now.t) ~(attested : Policyx.Expect.full Attestx.Attested.t)
    ~(model : ('c * Modelx.e2ee) Modelx.t) : ('c t, Errx.t) result =
  let* () = Entropyx.Fresh.consume fresh ~nonce:(Attestx.Attested.nonce attested) in
  let* admitted = Sessx.admit ~cpu_only ~now ~attested ~model in
  let* scalar = Entropyx.scalar entropy in
  let* core = Sessx.establish ~scalar admitted in
  Ok { core; used = Atomic.make { nonces = Nonce_set.empty; count = 0 } }

let client_pubkey_hex (session : 'c t) : string = Sessx.client_pubkey_hex session.core
let model_pubkey_hex (session : 'c t) : string = Sessx.model_pubkey_hex session.core
let model_id (session : 'c t) : string = Sessx.model_id session.core

let encrypt ~(fresh : Entropyx.Gcm_fresh.t) (session : 'c t)
    (plaintext : string) : (Encryptx.Ciphertext.t, Errx.t) result =
  let* () = Entropyx.Gcm_fresh.consume fresh in
  let nonce = Entropyx.Gcm_fresh.nonce fresh in
  let* () = reserve session nonce in
  let* bytes = Hexx.decode (client_pubkey_hex session) in
  let* client_pubkey = Option.to_result
    ~none:(Errx.Session_invalid "client public key") (Secpx.Pubkey.of_bytes bytes) in
  Encryptx.seal ~key:(Sessx.key session.core) ~client_pubkey ~nonce plaintext

(* The whole request is validated before the first draw. Each message
   gets a new handle; no partial request escapes if a later draw fails. *)
let request ~(entropy : Entropyx.t) (session : 'c t) (chat : 'c Chatx.t) :
    (Httpx.Request.t, Errx.t) result =
  let* plan = Encryptx.prepare ~model_id:(model_id session) chat in
  let* reversed = List.fold_left
    (fun result plaintext ->
      let* ciphertexts = result in
      let* fresh = Entropyx.Gcm_fresh.make ~entropy in
      let* ciphertext = encrypt ~fresh session plaintext in
      Ok (ciphertext :: ciphertexts))
    (Ok []) (Encryptx.plaintexts plan) in
  Encryptx.finish ~client_pubkey_hex:(client_pubkey_hex session)
    ~model_pubkey_hex:(model_pubkey_hex session) plan (List.rev reversed)

module Stream (T : Streamx.S) = struct
  module Driver = Streamx.Make (T)
  let run ?closing ?max_line_bytes ?max_event_bytes session body consume =
    let state = ref (Decryptx.make ~scalar:(Sessx.scalar session.core)
      ~model_id:(model_id session)) in
    let decode payload =
      Result.map (fun (next, chunk) -> state := next; chunk)
        (Decryptx.step !state payload) in
    Driver.run_decoded
      ~decode
      ~closing:(Option.value ~default:Ssex.Require_done closing)
      ?max_line_bytes ?max_event_bytes body consume
end
