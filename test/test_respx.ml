(* M10 chat response parser: the swagger example happy path, the
   reasoning passthrough round trip, choice/usage/cost variants, and
   one rejection fixture per D7/D8 guard. The internal seams live
   behind venice.mli, so this suite binds the library-internal
   modules by their mangled names. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module R = Venice__Respx
module Msg = Venice__Msgx
module J = Venice__Jsonx
module E = Venice__Errx

let ( let* ) = Result.bind

let ok_parse (s : string) (f : R.t -> bool) : bool =
  Result.fold ~ok:f ~error:(fun ((_ : E.t)) -> false) (R.of_string s)

let rejects (s : string) (expect : string) : bool =
  Result.fold
    ~ok:(fun ((_ : R.t)) -> false)
    ~error:(fun e -> String.equal (E.to_string e) expect)
    (R.of_string s)

let on_choice (s : string) (f : R.Choice.t -> bool) : bool =
  ok_parse s (fun r ->
      match R.choices r with
      | [ c ] -> f c
      | [] | _ :: _ -> false)

let dec (negative : bool) (mantissa : int) (scale : int) : J.dec =
  { J.negative; mantissa; scale }

let dec_eq (a : J.dec) (b : J.dec) : bool = J.compare_dec a b = 0

(* Fixture builders: a minimal valid document with pluggable choices
   and usage, written without spaces so slices byte-match Jsonx.emit
   output. *)

let ok_usage : string =
  {|{"completion_tokens":1,"prompt_tokens":1,"total_tokens":1}|}

let doc_of (choices : string) (usage : string) : string =
  {|{"id":"i","model":"m","created":1,"object":"chat.completion","choices":|}
  ^ choices ^ {|,"usage":|} ^ usage ^ "}"

let doc (choices : string) : string = doc_of choices ok_usage

let ok_msg : string = {|{"role":"assistant","content":"ok"}|}

let choice_with (message : string) : string =
  {|[{"finish_reason":"stop","index":0,"message":|} ^ message ^ "}]"

let no_choices : string =
  {|{"id":"i","model":"m","created":1,"object":"chat.completion","usage":|}
  ^ ok_usage ^ "}"

(* The swagger example body (sky-blue), assembled from the schema's
   own member examples. *)
let sky_text : string =
  "The sky appears blue because of the way Earth's atmosphere \
   scatters sunlight. When sunlight reaches Earth's atmosphere, it \
   is made up of various colors of the spectrum, but blue light \
   waves are shorter and scatter more easily when they hit the gases \
   and particles in the atmosphere. This scattering occurs in all \
   directions, but from our perspective on the ground, it appears as \
   a blue hue that dominates the sky's color. This phenomenon is \
   known as Rayleigh scattering. During sunrise and sunset, the \
   sunlight has to travel further through the atmosphere, which \
   allows more time for the blue light to scatter away from our \
   direct line of sight, leaving the longer wavelengths, such as \
   red, yellow, and orange, to dominate the sky's color."

let sky_body : string =
  {|{"choices":[{"finish_reason":"stop","index":0,"logprobs":null,"message":{"content":"|}
  ^ sky_text
  ^ {|","reasoning_content":null,"role":"assistant","tool_calls":[]},"stop_reason":null}],"created":1677858240,"cost":{"diem":0,"usd":0.00042},"id":"chatcmpl-abc123","model":"zai-org-glm-5-1","object":"chat.completion","usage":{"completion_tokens":20,"prompt_tokens":10,"total_tokens":30}}|}

(* Reasoning body: reasoning_content + 2 reasoning_details items (the
   second with an UNKNOWN extra member) + thought_signature. The
   slice literal is byte-exact against Jsonx.emit. *)
let details_slice : string =
  {|[{"type":"reasoning.text","text":"step one","format":"anthropic","index":0},{"type":"reasoning.encrypted","data":"xyz","id":"rd_1","zeta":"extra"}]|}

let reasoning_msg : string =
  {|{"role":"assistant","content":"ok","reasoning_content":"thinking","reasoning_details":|}
  ^ details_slice ^ {|,"thought_signature":"sig-abc"}|}

let reasoning_body : string = doc (choice_with reasoning_msg)

(* Parse one choice, feed every passthrough projection back through
   the assistant mint, and hand the emitted message to f. *)
let round_trip (s : string) (f : J.t -> bool) : bool =
  on_choice s (fun c ->
      Result.fold
        ~ok:(fun m -> f (Msg.emit_message (Msg.lift m)))
        ~error:(fun ((_ : E.t)) -> false)
        (Msg.assistant
           ?content:(R.Choice.content c)
           ?reasoning_content:(R.Choice.reasoning_content c)
           ?reasoning_details:(Some (R.Choice.reasoning_details c))
           ?thought_signature:(R.Choice.thought_signature c)
           ()))

let two_choices : string =
  doc
    ({|[{"finish_reason":"length","index":0,"message":|} ^ ok_msg
     ^ {|,"stop_reason":"length"},{"finish_reason":"tool_calls","index":1,"message":|}
     ^ ok_msg ^ "}]")

let logprobs_choice : string =
  doc
    ({|[{"finish_reason":"stop","index":0,"logprobs":{"bytes":[104,101],"logprob":-0.34,"token":"hello","top_logprobs":[{"bytes":[104],"logprob":-0.5,"token":"h"},{"logprob":-1,"token":"x"}]},"message":|}
     ^ ok_msg ^ "}]")

let full_usage : string =
  {|{"completion_tokens":20,"completion_tokens_details":{"reasoning_tokens":32},"prompt_tokens":10,"prompt_tokens_details":{"cached_tokens":128,"cache_creation_input_tokens":64},"total_tokens":30}|}

let checks : (string * bool) list =
  [ (* happy path: the swagger example body, every projection *)
    ("sky id", ok_parse sky_body (fun r -> String.equal (R.id r) "chatcmpl-abc123"));
    ("sky model",
     ok_parse sky_body (fun r -> String.equal (R.model r) "zai-org-glm-5-1"));
    ("sky created", ok_parse sky_body (fun r -> R.created r = 1677858240));
    ("sky one choice", ok_parse sky_body (fun r -> List.length (R.choices r) = 1));
    ("sky finish stop", on_choice sky_body (fun c -> R.Choice.finish c = R.Finish.Stop));
    ("sky index 0", on_choice sky_body (fun c -> R.Choice.index c = 0));
    ("sky content",
     on_choice sky_body (fun c -> R.Choice.content c = Some sky_text));
    ("sky reasoning_content none",
     on_choice sky_body (fun c -> R.Choice.reasoning_content c = None));
    ("sky reasoning_details empty",
     on_choice sky_body (fun c ->
         match R.Choice.reasoning_details c with
         | [] -> true
         | _ :: _ -> false));
    ("sky thought_signature none",
     on_choice sky_body (fun c -> Option.is_none (R.Choice.thought_signature c)));
    ("sky logprobs null reads none",
     on_choice sky_body (fun c -> Option.is_none (R.Choice.logprobs c)));
    ("sky stop_reason null reads none",
     on_choice sky_body (fun c -> R.Choice.stop_reason c = None));
    ("sky usage counts",
     ok_parse sky_body (fun r ->
         let u = R.usage r in
         R.Usage.completion_tokens u = 20
         && R.Usage.prompt_tokens u = 10
         && R.Usage.total_tokens u = 30));
    ("sky usage details none",
     ok_parse sky_body (fun r ->
         let u = R.usage r in
         R.Usage.reasoning_tokens u = None
         && R.Usage.cached_tokens u = None
         && R.Usage.cache_creation_tokens u = None));
    ("sky cost",
     ok_parse sky_body (fun r ->
         Option.fold ~none:false
           ~some:(fun c ->
             dec_eq (R.Cost.usd c) (dec false 42 5)
             && dec_eq (R.Cost.diem c) (dec false 0 0))
           (R.cost r)));
    (* reasoning body + passthrough round trip *)
    ("reasoning content projections",
     on_choice reasoning_body (fun c ->
         R.Choice.reasoning_content c = Some "thinking"
         && List.length (R.Choice.reasoning_details c) = 2));
    ("reasoning detail projections",
     on_choice reasoning_body (fun c ->
         match R.Choice.reasoning_details c with
         | [ d1; d2 ] ->
           String.equal (Msg.Reasoning_detail.type_ d1) "reasoning.text"
           && Msg.Reasoning_detail.text d1 = Some "step one"
           && Msg.Reasoning_detail.format d1 = Some "anthropic"
           && Msg.Reasoning_detail.index d1 = Some (J.Jint 0)
           && Msg.Reasoning_detail.data d1 = None
           && String.equal (Msg.Reasoning_detail.type_ d2)
                "reasoning.encrypted"
           && Msg.Reasoning_detail.data d2 = Some "xyz"
           && Msg.Reasoning_detail.id d2 = Some "rd_1"
           && Msg.Reasoning_detail.index d2 = None
         | [] | [ _ ] | _ :: _ :: _ -> false));
    ("reasoning thought_signature present",
     on_choice reasoning_body (fun c ->
         Option.is_some (R.Choice.thought_signature c)));
    ("round-trip reasoning_details byte-equal",
     round_trip reasoning_body (fun emitted ->
         Option.map J.emit (J.member "reasoning_details" emitted)
         = Some details_slice));
    ("round-trip full emitted message",
     round_trip reasoning_body (fun emitted ->
         String.equal (J.emit emitted)
           ({|{"role":"assistant","content":"ok","reasoning_content":"thinking","reasoning_details":|}
            ^ details_slice ^ {|,"thought_signature":"sig-abc"}|})));
    ("wire [] details round-trips with no member",
     round_trip
       (doc
          (choice_with
             {|{"role":"assistant","content":"ok","reasoning_details":[]}|}))
       (fun emitted -> Option.is_none (J.member "reasoning_details" emitted)));
    ("absent details round-trips with no member",
     round_trip
       (doc (choice_with ok_msg))
       (fun emitted -> Option.is_none (J.member "reasoning_details" emitted)));
    (* choice variants *)
    ("n=2 distinct indexes, length and tool_calls finishes",
     ok_parse two_choices (fun r ->
         match R.choices r with
         | [ c0; c1 ] ->
           R.Choice.index c0 = 0
           && R.Choice.finish c0 = R.Finish.Length
           && R.Choice.stop_reason c0 = Some R.Stop_reason.Length
           && R.Choice.index c1 = 1
           && R.Choice.finish c1 = R.Finish.Tool_calls
           && R.Choice.stop_reason c1 = None
         | [] | [ _ ] | _ :: _ :: _ -> false));
    ("logprobs present: flat record + top_logprobs",
     on_choice logprobs_choice (fun c ->
         Option.fold ~none:false
           ~some:(fun l ->
             String.equal (R.Logprobs.token l) "hello"
             && dec_eq (R.Logprobs.logprob l) (dec true 34 2)
             && R.Logprobs.bytes l = Some [ 104; 101 ]
             && (match R.Logprobs.top_logprobs l with
                 | [ e1; e2 ] ->
                   String.equal (R.Logprobs.entry_token e1) "h"
                   && dec_eq (R.Logprobs.entry_logprob e1) (dec true 5 1)
                   && R.Logprobs.entry_bytes e1 = Some [ 104 ]
                   && String.equal (R.Logprobs.entry_token e2) "x"
                   && dec_eq (R.Logprobs.entry_logprob e2) (dec true 1 0)
                   && R.Logprobs.entry_bytes e2 = None
                 | [] | [ _ ] | _ :: _ :: _ -> false))
           (R.Choice.logprobs c)));
    ("logprobs absent reads none",
     on_choice (doc (choice_with ok_msg)) (fun c ->
         Option.is_none (R.Choice.logprobs c)));
    (* usage / cost / choices variants *)
    ("usage with both details objects",
     ok_parse
       (doc_of (choice_with ok_msg) full_usage)
       (fun r ->
         let u = R.usage r in
         R.Usage.reasoning_tokens u = Some 32
         && R.Usage.cached_tokens u = Some 128
         && R.Usage.cache_creation_tokens u = Some 64));
    ("cost absent reads none",
     ok_parse no_choices (fun r -> Option.is_none (R.cost r)));
    ("choices absent reads []",
     ok_parse no_choices (fun r ->
         match R.choices r with
         | [] -> true
         | _ :: _ -> false));
    (* content projection, positively asserted *)
    ("content null reads none",
     on_choice
       (doc (choice_with {|{"role":"assistant","content":null}|}))
       (fun c -> R.Choice.content c = None));
    ("content absent reads none",
     on_choice
       (doc (choice_with {|{"role":"assistant"}|}))
       (fun c -> R.Choice.content c = None));
    ("text parts join in received order",
     on_choice
       (doc
          (choice_with
             {|{"role":"assistant","content":[{"type":"text","text":"a "},{"type":"text","text":"b"}]}|}))
       (fun c -> R.Choice.content c = Some "a b"));
    (* rejections, one fixture per guard *)
    ("missing id rejects",
     rejects
       ({|{"model":"m","created":1,"object":"chat.completion","usage":|}
        ^ ok_usage ^ "}")
       "resp: id: missing");
    ("missing model rejects",
     rejects
       ({|{"id":"i","created":1,"object":"chat.completion","usage":|}
        ^ ok_usage ^ "}")
       "resp: model: missing");
    ("missing created rejects",
     rejects
       ({|{"id":"i","model":"m","object":"chat.completion","usage":|}
        ^ ok_usage ^ "}")
       "resp: created: missing");
    ("missing usage rejects",
     rejects {|{"id":"i","model":"m","created":1,"object":"chat.completion"}|}
       "resp: usage: missing");
    ("missing finish_reason rejects",
     rejects
       (doc ({|[{"index":0,"message":|} ^ ok_msg ^ "}]"))
       "resp: choices[0].finish_reason: missing");
    ("object not chat.completion rejects",
     rejects
       ({|{"id":"i","model":"m","created":1,"object":"chat.chunk","usage":|}
        ^ ok_usage ^ "}")
       "resp: object: not chat.completion");
    ("Jdec completion_tokens rejects",
     rejects
       (doc_of (choice_with ok_msg)
          {|{"completion_tokens":1.5,"prompt_tokens":1,"total_tokens":1}|})
       "resp: usage.completion_tokens: not an integer");
    ("negative completion_tokens rejects",
     rejects
       (doc_of (choice_with ok_msg)
          {|{"completion_tokens":-1,"prompt_tokens":1,"total_tokens":1}|})
       "resp: usage.completion_tokens: negative");
    ("negative prompt_tokens rejects",
     rejects
       (doc_of (choice_with ok_msg)
          {|{"completion_tokens":1,"prompt_tokens":-1,"total_tokens":1}|})
       "resp: usage.prompt_tokens: negative");
    ("negative total_tokens rejects",
     rejects
       (doc_of (choice_with ok_msg)
          {|{"completion_tokens":1,"prompt_tokens":1,"total_tokens":-1}|})
       "resp: usage.total_tokens: negative");
    ("negative created rejects",
     rejects
       ({|{"id":"i","model":"m","created":-1,"object":"chat.completion","usage":|}
        ^ ok_usage ^ "}")
       "resp: created: negative");
    ("negative choice index rejects",
     rejects
       (doc ({|[{"finish_reason":"stop","index":-1,"message":|} ^ ok_msg ^ "}]"))
       "resp: choices[0].index: negative");
    ("negative cost.usd rejects",
     rejects
       ({|{"id":"i","model":"m","created":1,"object":"chat.completion","usage":|}
        ^ ok_usage ^ {|,"cost":{"usd":-0.1,"diem":0}}|})
       "resp: cost.usd: negative");
    ("negative cost.diem rejects",
     rejects
       ({|{"id":"i","model":"m","created":1,"object":"chat.completion","usage":|}
        ^ ok_usage ^ {|,"cost":{"usd":0,"diem":-1}}|})
       "resp: cost.diem: negative");
    ("negative reasoning_tokens rejects",
     rejects
       (doc_of (choice_with ok_msg)
          {|{"completion_tokens":1,"completion_tokens_details":{"reasoning_tokens":-1},"prompt_tokens":1,"total_tokens":1}|})
       "resp: usage.completion_tokens_details.reasoning_tokens: negative");
    ("negative cached_tokens rejects",
     rejects
       (doc_of (choice_with ok_msg)
          {|{"completion_tokens":1,"prompt_tokens":1,"prompt_tokens_details":{"cached_tokens":-1},"total_tokens":1}|})
       "resp: usage.prompt_tokens_details.cached_tokens: negative");
    ("negative cache_creation_input_tokens rejects",
     rejects
       (doc_of (choice_with ok_msg)
          {|{"completion_tokens":1,"prompt_tokens":1,"prompt_tokens_details":{"cache_creation_input_tokens":-1},"total_tokens":1}|})
       "resp: usage.prompt_tokens_details.cache_creation_input_tokens: negative");
    ("unknown finish_reason rejects",
     rejects
       (doc ({|[{"finish_reason":"halt","index":0,"message":|} ^ ok_msg ^ "}]"))
       "resp: finish_reason: unknown value halt");
    ("unknown stop_reason rejects",
     rejects
       (doc
          ({|[{"finish_reason":"stop","index":0,"message":|} ^ ok_msg
           ^ {|,"stop_reason":"halt"}]|}))
       "resp: stop_reason: unknown value halt");
    ("tool-role choice message rejects",
     rejects
       (doc
          (choice_with
             {|{"role":"tool","content":"42","tool_call_id":"c1"}|}))
       "resp: choice message role");
    ("mixed array rejects the whole document",
     rejects
       (doc
          ({|[{"finish_reason":"stop","index":0,"message":|} ^ ok_msg
           ^ {|},{"finish_reason":"stop","index":1,"message":{"role":"tool","content":"42","tool_call_id":"c1"}}]|}))
       "resp: choice message role");
    ("non-text response part rejects",
     rejects
       (doc
          (choice_with
             {|{"role":"assistant","content":[{"type":"image_url","image_url":{"url":"https://x/i.png"}}]}|}))
       "resp: choices[0].message.content: non-text part");
    ("reasoning_details item without type rejects",
     rejects
       (doc
          (choice_with
             {|{"role":"assistant","content":"ok","reasoning_details":[{"text":"t"}]}|}))
       "msg: reasoning_detail: type: missing");
    ("assistant mint with reasoning members but no content rejects",
     Result.fold
       ~ok:(fun ((_ : Msg.msg)) -> false)
       ~error:(fun e ->
         String.equal (E.to_string e)
           "msg: assistant: content or tool_calls required")
       (let* d =
          Result.bind (J.parse {|{"type":"t"}|}) Msg.reasoning_detail_of_json
        in
        Msg.assistant ~reasoning_content:"rc" ~reasoning_details:[ d ]
          ~thought_signature:(Msg.thought_signature_of_parsed "s") ()))
  ]

let () = run checks
