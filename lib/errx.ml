(* The one error type. Every rejection names the check that failed, so a
   caller and the harness can pin the exact reason. Grows with the
   milestones; M3 seeds the codec constructors, M4 adds JSON, M5 the
   model domain, M6 the sampling parameters, M7 the message domain,
   M8 the response-header domain, M9 the chat request domain, M10 the
   chat response domain, M11 the SSE stream and chunk domains, M13
   the key, request, wire-head and transport domains. *)

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
