(* The independent M31 synthetic capture supplies these KATs. *)
module D = Venice__Decryptx
module S = Venice__Secpx
module J = Venice__Jsonx
module H = Venice__Hexx
module E = Venice__Errx
module B = Venice__Bytesx
module St = Venice__Streamx
module Sse = Venice__Ssex
module F = Venice__Fakex
module Driver = St.Make (F)
let ( let* ) = Result.bind
let require word v = Option.to_result ~none:(E.Session_invalid word) v
let ok f = Result.fold ~ok:f ~error:(fun (_ : E.t) -> false)
let rejects word = Result.fold ~ok:(fun _ -> false)
  ~error:(fun e -> String.equal (E.to_string e) ("session: " ^ word))
let scalar n = require "scalar" (S.Scalar.of_bytes (String.make 31 '\000' ^ B.of_codes [n]))
let member name json = require name (J.member name json)
let text value = require "text" (J.as_string value)
let fixture () =
  let* json = J.parse (Fixture_decrypt.bytes ()) in
  let* encoded = member "response_body_hex" json in
  let* hex = text encoded in H.decode hex
let payloads wire =
  let* machine = Sse.make () in
  let* _, events = Sse.feed machine wire in
  Ok (List.filter_map (function Sse.Data s -> Some s | Sse.Done -> None) events)
let content_frame payload =
  let* json = J.parse payload in
  let* choices = member "choices" json in
  let* choices = require "choices" (J.as_list choices) in
  let* choice = require "choice" (List.nth_opt choices 0) in
  let* delta = member "delta" choice in
  let* value = member "content" delta in text value
let decode ~scalar = D.chunk ~scalar ~model_id:"SYNTHETIC-model"
let values chunk = List.concat_map (fun choice ->
  let delta = Sse.Chunk.Choice.delta choice in
  List.filter_map Fun.id
    [Sse.Chunk.Delta.content delta; Sse.Chunk.Delta.reasoning_content delta])
  (Sse.Chunk.choices chunk)
let report ~scalar chunks close_error consume =
  let* key = Venice__Keyx.make "test" in
  let* request = Venice__Httpx.Request.get Venice__Httpx.Route.models in
  let fake = F.make [F.exchange
    ~head:"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"
    ~chunks ?close_error ()] in
  let* _, body = F.send fake ~key request in
  let state = ref (D.make ~scalar ~model_id:"SYNTHETIC-model") in
  let decode payload = Result.map (fun (next, chunk) -> state := next; chunk)
    (D.step !state payload) in
  let value, outcome = Driver.run_decoded ~decode body consume in
  Ok (value, outcome, F.closes body)
let collect c = St.fold c ~init:[] ~f:(fun acc chunk -> acc @ values chunk)
let complete expected = function
  | value, St.Complete, 1 -> value = expected
  | _, (St.Complete | St.Cut | St.Failed _), _ -> false
(* Pin both halves of a failure: what the consumer saw and which word
   rejected. A bare "some failure" row cannot show that no plaintext
   escaped. *)
let failed word values = function
  | v, St.Failed e, 1 -> v = values && String.equal (E.to_string e) ("session: " ^ word)
  | _, (St.Complete | St.Cut | St.Failed _), _ -> false
(* The SSE framing words belong to Ssex, so these rows pin the value only. *)
let failed_value values = function
  | v, St.Failed (_ : E.t), 1 -> v = values
  | _, (St.Complete | St.Cut | St.Failed _), _ -> false
let replace source needle replacement =
  let rec loop offset =
    Option.fold ~none:(fun () -> source) ~some:(fun found () ->
      if String.equal found needle then
        Option.value ~default:"" (B.take source 0 offset) ^ replacement ^
        Option.value ~default:"" (B.take source (offset + String.length needle)
          (String.length source - offset - String.length needle))
      else loop (offset + 1))
      (B.take source offset (String.length needle)) () in
  loop 0
(* A chunk with the ordinary identity and a caller-supplied choices value. *)
let shaped choices =
  "{\"id\":\"SYNTHETIC-request-1\",\"model\":\"SYNTHETIC-model\"," ^
  "\"object\":\"chat.completion.chunk\",\"created\":0,\"choices\":" ^ choices ^ "}"
let checks () =
  let* wrong_scalar = scalar 4 in
  let* scalar = scalar 3 in
  let* wire = fixture () in
  let* payloads = payloads wire in
  let* first = require "first" (List.nth_opt payloads 0) in
  let* frame = content_frame first in
  let* raw = H.decode frame in
  let altered offset = H.encode (String.mapi (fun i c ->
    match () with
    | () when i = offset && c = '\000' -> '\001'
    | () when i = offset -> '\000'
    | () -> c) raw) in
  let expected = ["Synthetic answer."; "Synthetic reasoning."] in
  let chunks = List.map (String.make 1) (List.of_seq (String.to_seq wire)) in
  Ok [
    (* Independently sealed and authenticated by harness/diff_e2ee.py,
       client scalar 3, sender scalars 13 and 17, zero nonce. *)
    "93-byte authenticated empty frame", ok (String.equal "") (D.frame ~scalar
      "04f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa80ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81000000000000000000000000e5a1a117673c2a30d70ccb407198e172");
    "different ephemeral peer KAT", ok (String.equal "Rotated peer") (D.frame ~scalar
      "04defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a344211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb770000000000000000000000005bfcd4496804f43166c8ec171aab7439e0bb087bfef49eeb4c07a019");
    "independent frame KAT", ok (String.equal "Synthetic answer.") (D.frame ~scalar frame);
    "wrong scalar", rejects "response authentication" (D.frame ~scalar:wrong_scalar frame);
    "short frame", rejects "response frame length" (D.frame ~scalar (String.make 184 '0'));
    "odd hex", rejects "response frame hex" (D.frame ~scalar "0");
    "bad hex", rejects "response frame hex" (D.frame ~scalar "gg");
    "bounded frame", rejects "response frame length" (D.frame ~scalar (String.make 4_000_187 '0'));
    (* One character below the bound passes the length test and the 93-byte
       floor, then fails on the zero key prefix. This separates > from >=. *)
    "maximum frame accepted", rejects "response public key"
      (D.frame ~scalar (String.make 4_000_186 '0'));
    "invalid key prefix", rejects "response public key" (D.frame ~scalar (altered 0));
    "invalid curve point", rejects "response public key" (D.frame ~scalar (altered 1));
    "nonce tamper", rejects "response authentication" (D.frame ~scalar (altered 65));
    "ciphertext tamper", rejects "response authentication" (D.frame ~scalar (altered 77));
    "tag tamper", rejects "response authentication" (D.frame ~scalar (altered (String.length raw - 1)));
    "chunk KAT", ok (fun c -> values c = ["Synthetic answer."]) (decode ~scalar first);
    "model mismatch", rejects "response model" (D.chunk ~scalar ~model_id:"wrong" first);
    "missing model key", rejects "response model" (decode ~scalar
      "{\"id\":\"SYNTHETIC-request-1\",\"object\":\"chat.completion.chunk\",\"created\":0,\"choices\":[]}");
    "choices not a list", rejects "response choices" (decode ~scalar (shaped "{}"));
    "null choices member", rejects "response choice" (decode ~scalar (shaped "[null]"));
    "choice not an object", rejects "response choice" (decode ~scalar (shaped "[\"delta\"]"));
    "null delta object", rejects "response delta"
      (decode ~scalar (shaped "[{\"index\":0,\"delta\":null}]"));
    "delta not an object", rejects "response delta"
      (decode ~scalar (shaped "[{\"index\":0,\"delta\":\"text\"}]"));
    "first chunk needs object", rejects "response chunk"
      (decode ~scalar (replace first "\"object\":\"chat.completion.chunk\"," ""));
    "first chunk needs created", rejects "response chunk"
      (decode ~scalar (replace first ",\"created\":0" ""));
    "assistant role accepted", ok (fun c -> values c = ["Synthetic answer."])
      (decode ~scalar (replace first "\"delta\":{" "\"delta\":{\"role\":\"assistant\","));
    "other role accepted", ok (fun c -> values c = ["Synthetic answer."])
      (decode ~scalar (replace first "\"delta\":{" "\"delta\":{\"role\":\"model\","));
    "role must be a string", rejects "response delta"
      (decode ~scalar (replace first "\"delta\":{" "\"delta\":{\"role\":null,"));
    "plaintext rejected", rejects "response frame hex" (decode ~scalar (replace first frame "plaintext"));
    "tool delta rejected", rejects "response delta" (decode ~scalar (replace first "\"content\"" "\"tool_calls\""));
    "mixed fields fail atomically", rejects "response frame hex"
      (decode ~scalar (replace first "\"content\":"
        "\"reasoning_content\":\"plaintext\",\"content\":"));
    "tag-first frame rejected", rejects "response authentication"
      (D.frame ~scalar (H.encode
        (Option.value ~default:"" (B.take raw 0 77) ^
         Option.value ~default:"" (B.take raw (String.length raw - 16) 16) ^
         Option.value ~default:"" (B.take raw 77 (String.length raw - 93)))));
    "null delta field", ok (fun c -> values c = [])
      (decode ~scalar (replace first ("\"" ^ frame ^ "\"") "null"));
    "empty delta field", ok (fun c -> values c = [""])
      (decode ~scalar (replace first frame ""));
    "whole SSE", ok (complete expected) (report ~scalar [wire] None collect);
    "byte SSE", ok (complete expected) (report ~scalar chunks None collect);
    "auth failure closes", ok (failed "response frame hex" [])
      (report ~scalar [replace wire frame "plaintext"] None collect);
    "missing DONE", ok (failed_value expected)
      (report ~scalar [replace wire "data: [DONE]\n\n" ""] None collect);
    "duplicate DONE", ok (failed_value expected)
      (report ~scalar [wire; "data: [DONE]\n\n"] None collect);
    "post DONE data", ok (failed_value expected)
      (report ~scalar [wire; "data: {}\n\n"] None collect);
    "request identity change", ok (failed "response identity" ["Synthetic answer."])
      (report ~scalar
        ["data: " ^ first ^ "\n\n"; replace wire "SYNTHETIC-request-1" "other-request"] None collect);
    "created change", ok (failed "response identity" ["Synthetic answer."])
      (report ~scalar
        ["data: " ^ first ^ "\n\n"; replace wire "\"created\":0" "\"created\":1"] None collect);
    (* Only object and created are inherited, so a later chunk without id
       fails the ordinary chunk identity. *)
    "later chunk keeps its own id", ok (failed "response chunk" ["Synthetic answer."])
      (report ~scalar
        ["data: " ^ first ^ "\n\n"; replace wire "\"id\":\"SYNTHETIC-request-1\"," ""] None collect);
    "close failure", ok (failed_value expected)
      (report ~scalar [wire] (Some "close test") collect);
    "consumer cut", ok (function
      | (), St.Cut, 1 -> true
      | (), (St.Complete | St.Cut | St.Failed _), _ -> false)
      (report ~scalar [wire] None (fun _ -> ()));
    "dead cursor", ok (fun (cursor, _, closes) -> St.next cursor = None && closes = 1)
      (report ~scalar [wire] None Fun.id)
  ]
let () = Result.fold
  ~error:(fun e -> print_endline ("FAIL setup: " ^ E.to_string e); exit 1)
  ~ok:(fun checks ->
    let bad = List.filter (fun (_, pass) -> not pass) checks in
    List.iter (fun (name, _) -> print_endline ("FAIL " ^ name)) bad;
    Printf.printf "%d/%d ok\n" (List.length checks - List.length bad) (List.length checks);
    exit (if List.is_empty bad then 0 else 1)) (checks ())
