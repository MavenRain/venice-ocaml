(* The one error type. Every rejection names the check that failed, so a
   caller and the harness can pin the exact reason. Grows with the
   milestones; M3 seeds the codec constructors, M4 adds JSON, M5 the
   model domain, M6 the sampling parameters, M7 the message domain,
   M8 the response-header domain, M9 the chat request domain, M10 the
   chat response domain, M11 the SSE stream and chunk domains, M13
   the key, request, wire-head and transport domains, M14 the stream
   accumulator domain, M15 the never-sent transport failure and the
   client's own rejections, M23 the quote domain, M24 the policy
   domain, M25 the signature domain, M26 the certificate domain, M27
   the TCB grading domain. *)

type t =
  | Hex_invalid of string
  | B64_invalid of string
  | Json_invalid of string
  | Model_invalid of string
  | Param_invalid of string
  | Msg_invalid of string
  | Head_invalid of string
  | Chat_invalid of string
  | Resp_invalid of string
  | Sse_invalid of string
  | Chunk_invalid of string
  | Key_invalid of string
  | Req_invalid of string
  | Wire_invalid of string
  | Transport_failed of string
  | Stream_invalid of string
  (* M15 D9: the transport proved that NO request byte reached a
     Venice server, so a retry of the same request cannot double-bill.
     Every other transport rejection stays Transport_failed. *)
  | Transport_unreachable of string
  (* M15 D9: the client's own rejection (a policy or body window, a
     media type, the total classify arm), never a server verdict. *)
  | Client_invalid of string
  (* M23 D5: the TDX quote decoder refused the bytes. The reason names
     the check that failed and comes from a CLOSED vocabulary, so the
     suite and the harness can pin every rejection text. *)
  | Quote_invalid of string
  (* M24 D5: the attestation policy refused the quote. The reason names
     the FIRST check that failed and comes from a CLOSED vocabulary of
     ten words, so the suite and the harness can pin every rejection
     text. *)
  | Policy_rejected of string
  (* M25 D5: the attestation signature unit refused the quote. The
     reason names the FIRST check that failed and comes from a CLOSED
     vocabulary of six words, so the suite and the harness can pin
     every rejection text. *)
  | Sig_invalid of string
  (* M26 D5: the certificate unit refused the PCK chain. The reason
     names the FIRST check that failed and comes from a CLOSED
     vocabulary of fifteen words, so the suite and the harness can
     pin every rejection text. *)
  | Cert_invalid of string
  (* M27 D5: the TCB unit refused the platform grade or the QE identity.
     The reason names the FIRST check that failed and comes from a
     CLOSED vocabulary of thirty-one words reachable from verify plus
     the word envelope, which only Collateral.of_envelope says, so the
     whole vocabulary is thirty-two words and the suite and the harness
     can pin every rejection text. *)
  | Tcb_invalid of string
  (* M28: the envelope and GPU structural checks. *)
  | Attest_invalid of string
  (* M29: entropy, freshness and session admission. *)
  | Session_invalid of string

let to_string (e : t) : string =
  match e with
  | Hex_invalid s -> "hex: " ^ s
  | B64_invalid s -> "base64: " ^ s
  | Json_invalid s -> "json: " ^ s
  | Model_invalid s -> "model: " ^ s
  | Param_invalid s -> "param: " ^ s
  | Msg_invalid s -> "msg: " ^ s
  | Head_invalid s -> "head: " ^ s
  | Chat_invalid s -> "chat: " ^ s
  | Resp_invalid s -> "resp: " ^ s
  | Sse_invalid s -> "sse: " ^ s
  | Chunk_invalid s -> "chunk: " ^ s
  | Key_invalid s -> "key: " ^ s
  | Req_invalid s -> "req: " ^ s
  | Wire_invalid s -> "wire: " ^ s
  | Transport_failed s -> "transport: " ^ s
  | Stream_invalid s -> "stream: " ^ s
  | Transport_unreachable s -> "unreachable: " ^ s
  | Client_invalid s -> "client: " ^ s
  | Quote_invalid s -> "quote: " ^ s
  | Policy_rejected s -> "policy: " ^ s
  | Sig_invalid s -> "sig: " ^ s
  | Cert_invalid s -> "cert: " ^ s
  | Tcb_invalid s -> "tcb: " ^ s
  | Attest_invalid s -> "attest: " ^ s
  | Session_invalid s -> "session: " ^ s
