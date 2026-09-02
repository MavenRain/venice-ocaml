(* M9 chat request domain: the mint gates (kind, completion cap,
   integer floors, witness-gated logprobs/effort), the advisory
   budget, Stop bounds, enum round-trips, and byte-exact emission
   goldens under the frozen A8 member order. Exact emission and the
   seam live behind venice.mli, so this suite binds the
   library-internal modules by their mangled names; the public
   boundary itself is exercised by the compile-fail battery. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module C = Venice__Chatx
module Stop = Venice__Chatx.Stop
module Eff = Venice__Chatx.Effort
module CR = Venice__Chatx.Cache_retention
module M = Venice__Modelx
module Msg = Venice__Msgx
module P = Venice__Paramsx
module J = Venice__Jsonx
module E = Venice__Errx

let ( let* ) = Result.bind

(* A checker carries a polymorphic body so one helper unpacks the
   existential row for every branded probe. *)
type checker = { f : 'c. 'c M.t -> bool }

let on_model (s : string) (c : checker) : bool =
  Result.fold
    ~ok:(fun p -> match p with M.Pack m -> c.f m)
    ~error:(fun ((_ : E.t)) -> false)
    (Result.bind (J.parse s) M.of_json)

let minted (r : ('a, E.t) result) : bool =
  Result.fold
    ~ok:(fun ((_ : 'a)) -> true)
    ~error:(fun ((_ : E.t)) -> false)
    r

let rejects (r : ('a, E.t) result) (expect : string) : bool =
  Result.fold
    ~ok:(fun ((_ : 'a)) -> false)
    ~error:(fun e -> String.equal (E.to_string e) expect)
    r

let chat_emits (r : ('c C.t, E.t) result) (expect : string) : bool =
  Result.fold
    ~ok:(fun t -> String.equal (C.emit t) expect)
    ~error:(fun ((_ : E.t)) -> false)
    r

let chat_json (stream : bool option) (include_usage : bool option)
    (r : ('c C.t, E.t) result) (expect : string) : bool =
  Result.fold
    ~ok:(fun t ->
      String.equal (J.emit (C.to_json ?stream ?include_usage t)) expect)
    ~error:(fun ((_ : E.t)) -> false)
    r

let budget_ok (r : ('c C.t, E.t) result) (pt : int) : bool =
  minted (Result.bind r (fun t -> C.budget t ~prompt_tokens:pt))

let budget_rejects (r : ('c C.t, E.t) result) (pt : int) (expect : string)
    : bool =
  rejects (Result.bind r (fun t -> C.budget t ~prompt_tokens:pt)) expect

let mk_msgs (s : string) : ('c Msg.nonempty, E.t) result =
  Result.bind (Msg.user_text s) (fun u -> Msg.nonempty [ u ])

let with_logprobs (m : 'c M.t) (f : ('c * M.log_probs) M.t -> bool) : bool
    =
  Option.fold ~none:false ~some:f (M.log_probs m)

let with_effort_w (m : 'c M.t) (f : ('c * M.reasoning_effort) M.t -> bool)
    : bool =
  Option.fold ~none:false ~some:f (M.reasoning_effort m)

let with_tools_w (m : 'c M.t) (f : ('c * M.tools) M.t -> bool) : bool =
  Option.fold ~none:false ~some:f (M.tools m)

let with_schema_w (m : 'c M.t) (f : ('c * M.response_schema) M.t -> bool) :
    bool =
  Option.fold ~none:false ~some:f (M.response_schema m)

let mk_tool (name : string) : (C.Tool.t, E.t) result =
  C.Tool.function_ ~name ()

let dec (negative : bool) (mantissa : int) (scale : int) : J.dec =
  { J.negative; mantissa; scale }

(* Fixtures. chatty: text kind, all four request-member capabilities,
   a published effort menu, and both token limits; anyeffort asserts
   the effort capability with NO menu; ctxonly publishes a context
   window but no completion cap; uncapped publishes neither; codey
   and pixel probe the kind gate. *)
let chatty : string =
  {|{"id":"chatty","type":"text","capabilities":{"supportsReasoningEffort":true,"supportsLogProbs":true,"supportsFunctionCalling":true,"supportsResponseSchema":true,"reasoningEffortOptions":["low","medium","high"]},"model_spec":{"availableContextTokens":4096,"maxCompletionTokens":2048}}|}

let anyeffort : string =
  {|{"id":"anyeffort","type":"text","capabilities":{"supportsReasoningEffort":true}}|}

let uncapped : string = {|{"id":"uncapped","type":"text"}|}

let ctxonly : string =
  {|{"id":"ctxonly","type":"text","model_spec":{"availableContextTokens":100}}|}

let codey : string = {|{"id":"codey","type":"code"}|}
let pixel : string = {|{"id":"pixel","type":"image"}|}

(* Byte-exact goldens, hand-authored: Jsonx.emit is deterministic and
   fixtures/ does not exist yet (A9 names the debt; the activation
   check at the bottom watches for it). *)
let golden_minimal : string =
  {|{"model":"chatty","messages":[{"role":"user","content":"hi"}]}|}

let golden_full : string =
  {|{"model":"chatty","messages":[{"role":"user","content":"hi"}],"temperature":1.5,"top_p":0.9,"frequency_penalty":-0.5,"presence_penalty":0.25,"repetition_penalty":1.1,"top_k":40,"venice_parameters":{"include_venice_system_prompt":false},"max_completion_tokens":1000,"stream":true,"stream_options":{"include_usage":true},"stop":["a","b"],"stop_token_ids":[1,2],"seed":7,"n":2,"logprobs":true,"top_logprobs":3,"reasoning_effort":"high","prompt_cache_key":"k1","prompt_cache_retention":"extended"}|}

let golden_permuted : string =
  {|{"model":"chatty","messages":[{"role":"user","content":"hi"}],"temperature":1.5,"top_k":40,"seed":7}|}

(* One toggle golden per member, minimal + that member only; every
   asserted value is NON-default so a dead projection cannot pass. *)
let toggle (tail : string) : string =
  {|{"model":"chatty","messages":[{"role":"user","content":"hi"}],|}
  ^ tail ^ "}"

(* A9 fixtures debt: DESIGN.md's M9 row says "byte-exact golden tests
   vs fixtures", but fixtures/ does not exist until the M2 live
   probes land a request-side capture per golden. gates.sh runs the
   suites from the repo root, so the path below resolves there; until
   the file appears this check passes as skipped. *)
let fixture_minimal_matches : bool =
  if Sys.file_exists "fixtures/chat_minimal.json" then
    String.equal
      (String.trim
         (In_channel.with_open_bin "fixtures/chat_minimal.json"
            In_channel.input_all))
      golden_minimal
  else true

let all_efforts : Eff.t list =
  [ Eff.None_; Eff.Minimal; Eff.Low; Eff.Medium; Eff.High; Eff.Xhigh;
    Eff.Max ]

let all_retentions : CR.t list = [ CR.Default; CR.Extended; CR.H24 ]

let round_trips_effort (e : Eff.t) : bool =
  Result.fold
    ~ok:(fun (e2 : Eff.t) -> e2 = e)
    ~error:(fun ((_ : E.t)) -> false)
    (Eff.of_string (Eff.to_string e))

let round_trips_retention (r : CR.t) : bool =
  Result.fold
    ~ok:(fun (r2 : CR.t) -> r2 = r)
    ~error:(fun ((_ : E.t)) -> false)
    (CR.of_string (CR.to_string r))

let checks : (string * bool) list =
  [ (* goldens *)
    ("golden minimal, zero optionals (A4)",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               golden_minimal) });
    ("golden full request, every M9 member",
     on_model chatty
       { f =
           (fun m ->
             with_logprobs m (fun lw ->
                 with_effort_w m (fun ew ->
                     chat_json (Some true) (Some true)
                       (let* t = P.Temp.make (dec false 15 1) in
                        let* tp = P.Top_p.make (dec false 9 1) in
                        let* fp = P.Frequency_penalty.make (dec true 5 1) in
                        let* pp = P.Presence_penalty.make (dec false 25 2) in
                        let* rp =
                          P.Repetition_penalty.make (dec false 11 1)
                        in
                        let* tk = P.Top_k.make 40 in
                        let* st = Stop.of_list [ "a"; "b" ] in
                        let* msgs = mk_msgs "hi" in
                        C.make ~temperature:t ~top_p:tp
                          ~frequency_penalty:fp ~presence_penalty:pp
                          ~repetition_penalty:rp ~top_k:tk
                          ~venice:
                            (P.Venice_params.make
                               ~include_venice_system_prompt:false ())
                          ~max_completion:1000 ~stop:st
                          ~stop_token_ids:[ 1; 2 ] ~seed:7 ~n:2
                          ~logprobs:(lw, true) ~top_logprobs:3
                          ~effort:(ew, Eff.High) ~prompt_cache_key:"k1"
                          ~cache_retention:CR.Extended m msgs ())
                       golden_full))) });
    ("member order frozen (A8)",
     C.member_order ()
     = [ "model"; "messages"; "temperature"; "top_p"; "frequency_penalty";
         "presence_penalty"; "repetition_penalty"; "top_k";
         "venice_parameters"; "max_completion_tokens"; "stream";
         "stream_options"; "stop"; "stop_token_ids"; "seed"; "n";
         "logprobs"; "top_logprobs"; "reasoning_effort";
         "prompt_cache_key"; "prompt_cache_retention"; "tools";
         "tool_choice"; "parallel_tool_calls"; "response_format" ]);
    ("permuted optional order, reference bytes",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* t = P.Temp.make (dec false 15 1) in
                let* tk = P.Top_k.make 40 in
                let* msgs = mk_msgs "hi" in
                C.make ~temperature:t ~top_k:tk ~seed:7 m msgs ())
               golden_permuted) });
    ("permuted optional order, permuted bytes",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* t = P.Temp.make (dec false 15 1) in
                let* tk = P.Top_k.make 40 in
                let* msgs = mk_msgs "hi" in
                C.make ~seed:7 ~top_k:tk ~temperature:t m msgs ())
               golden_permuted) });
    (* per-member toggles *)
    ("toggle temperature",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* t = P.Temp.make (dec false 5 1) in
                let* msgs = mk_msgs "hi" in
                C.make ~temperature:t m msgs ())
               (toggle {|"temperature":0.5|})) });
    ("toggle top_p",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* tp = P.Top_p.make (dec false 1 1) in
                let* msgs = mk_msgs "hi" in
                C.make ~top_p:tp m msgs ())
               (toggle {|"top_p":0.1|})) });
    ("toggle frequency_penalty",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* fp = P.Frequency_penalty.make (dec false 175 2) in
                let* msgs = mk_msgs "hi" in
                C.make ~frequency_penalty:fp m msgs ())
               (toggle {|"frequency_penalty":1.75|})) });
    ("toggle presence_penalty",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* pp = P.Presence_penalty.make (dec true 15 1) in
                let* msgs = mk_msgs "hi" in
                C.make ~presence_penalty:pp m msgs ())
               (toggle {|"presence_penalty":-1.5|})) });
    ("toggle repetition_penalty",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* rp = P.Repetition_penalty.make (dec false 5 1) in
                let* msgs = mk_msgs "hi" in
                C.make ~repetition_penalty:rp m msgs ())
               (toggle {|"repetition_penalty":0.5|})) });
    ("toggle top_k",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* tk = P.Top_k.make 5 in
                let* msgs = mk_msgs "hi" in
                C.make ~top_k:tk m msgs ())
               (toggle {|"top_k":5|})) });
    ("toggle venice non-empty",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make
                  ~venice:
                    (P.Venice_params.make
                       ~enable_web_search:P.Venice_params.On ())
                  m msgs ())
               (toggle {|"venice_parameters":{"enable_web_search":"on"}|}))
       });
    ("venice empty never emits",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~venice:(P.Venice_params.make ()) m msgs ())
               golden_minimal) });
    ("toggle max_completion",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:64 m msgs ())
               (toggle {|"max_completion_tokens":64|})) });
    ("toggle stream false (A7, non-default emit)",
     on_model chatty
       { f =
           (fun m ->
             chat_json (Some false) None
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               (toggle {|"stream":false|})) });
    ("toggle include_usage without stream (D10)",
     on_model chatty
       { f =
           (fun m ->
             chat_json None (Some false)
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               (toggle {|"stream_options":{"include_usage":false}|})) });
    ("toggle stop single sequence",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* st = Stop.of_string "END" in
                let* msgs = mk_msgs "hi" in
                C.make ~stop:st m msgs ())
               (toggle {|"stop":"END"|})) });
    ("toggle stop four sequences (D7 max)",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* st = Stop.of_list [ "a"; "b"; "c"; "d" ] in
                let* msgs = mk_msgs "hi" in
                C.make ~stop:st m msgs ())
               (toggle {|"stop":["a","b","c","d"]|})) });
    ("toggle stop_token_ids, zero id passes",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~stop_token_ids:[ 0 ] m msgs ())
               (toggle {|"stop_token_ids":[0]|})) });
    ("toggle seed at floor 1",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~seed:1 m msgs ())
               (toggle {|"seed":1|})) });
    ("toggle n",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~n:3 m msgs ())
               (toggle {|"n":3|})) });
    ("toggle logprobs false (witnessed, non-default emit)",
     on_model chatty
       { f =
           (fun m ->
             with_logprobs m (fun lw ->
                 chat_emits
                   (let* msgs = mk_msgs "hi" in
                    C.make ~logprobs:(lw, false) m msgs ())
                   (toggle {|"logprobs":false|}))) });
    ("toggle logprobs with top_logprobs 0 (A3 floor)",
     on_model chatty
       { f =
           (fun m ->
             with_logprobs m (fun lw ->
                 chat_emits
                   (let* msgs = mk_msgs "hi" in
                    C.make ~logprobs:(lw, true) ~top_logprobs:0 m msgs ())
                   (toggle {|"logprobs":true,"top_logprobs":0|}))) });
    ("toggle effort in the published menu (A1)",
     on_model chatty
       { f =
           (fun m ->
             with_effort_w m (fun ew ->
                 chat_emits
                   (let* msgs = mk_msgs "hi" in
                    C.make ~effort:(ew, Eff.Medium) m msgs ())
                   (toggle {|"reasoning_effort":"medium"|}))) });
    ("effort with no published menu accepts any (A1)",
     on_model anyeffort
       { f =
           (fun m ->
             with_effort_w m (fun ew ->
                 chat_emits
                   (let* msgs = mk_msgs "hi" in
                    C.make ~effort:(ew, Eff.None_) m msgs ())
                   {|{"model":"anyeffort","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"none"}|}))
       });
    ("toggle prompt_cache_key",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~prompt_cache_key:"cache-a" m msgs ())
               (toggle {|"prompt_cache_key":"cache-a"|})) });
    ("toggle cache_retention 24h",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~cache_retention:CR.H24 m msgs ())
               (toggle {|"prompt_cache_retention":"24h"|})) });
    ("toggle cache_retention default still emits",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~cache_retention:CR.Default m msgs ())
               (toggle {|"prompt_cache_retention":"default"|})) });
    ("with_messages re-keys the messages (A7 seam)",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                let* t = C.make m msgs () in
                let* swapped = mk_msgs "swapped" in
                Ok (C.with_messages swapped t))
               {|{"model":"chatty","messages":[{"role":"user","content":"swapped"}]}|})
       });
    (* the model-kind gate (A2) *)
    ("kind image rejects at mint",
     on_model pixel
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               "chat: make: model kind image: not a text-like model") });
    ("kind code mints",
     on_model codey
       { f =
           (fun m ->
             minted
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())) });
    (* the capability witnesses refuse models that do not assert the
       capability (A1/A3 None branch) *)
    ("reasoning_effort witness absent without the capability (A1)",
     on_model uncapped { f = (fun m -> Option.is_none (M.reasoning_effort m)) });
    ("log_probs witness absent without the capability (A3)",
     on_model uncapped { f = (fun m -> Option.is_none (M.log_probs m)) });
    (* completion cap boundaries (D4a) *)
    ("max_completion equal to the model cap mints",
     on_model chatty
       { f =
           (fun m ->
             minted
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:2048 m msgs ())) });
    ("max_completion cap+1 rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:2049 m msgs ())
               "chat: make: max_completion 2049: above model cap 2048") });
    ("max_completion 0 rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:0 m msgs ())
               "chat: make: max_completion 0: below 1") });
    ("max_completion on a capless model mints",
     on_model uncapped
       { f =
           (fun m ->
             minted
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:999999 m msgs ())) });
    (* integer floors and member gates *)
    ("seed 0 rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~seed:0 m msgs ())
               "chat: make: seed 0: below 1") });
    ("n 0 rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~n:0 m msgs ())
               "chat: make: n 0: below 1") });
    ("top_logprobs -1 rejects with logprobs",
     on_model chatty
       { f =
           (fun m ->
             with_logprobs m (fun lw ->
                 rejects
                   (let* msgs = mk_msgs "hi" in
                    C.make ~logprobs:(lw, true) ~top_logprobs:(-1) m msgs
                      ())
                   "chat: make: top_logprobs -1: below 0")) });
    ("top_logprobs without logprobs rejects (A3)",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~top_logprobs:3 m msgs ())
               "chat: make: top_logprobs: passed without logprobs") });
    ("top_logprobs with logprobs false rejects (A3)",
     on_model chatty
       { f =
           (fun m ->
             with_logprobs m (fun lw ->
                 rejects
                   (let* msgs = mk_msgs "hi" in
                    C.make ~logprobs:(lw, false) ~top_logprobs:5 m msgs ())
                   "chat: make: top_logprobs: passed without logprobs")) });
    ("stop_token_ids empty rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~stop_token_ids:[] m msgs ())
               "chat: make: stop_token_ids: empty list") });
    ("stop_token_ids negative id rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~stop_token_ids:[ 3; -3 ] m msgs ())
               "chat: make: stop_token_ids -3: below 0") });
    ("prompt_cache_key empty rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~prompt_cache_key:"" m msgs ())
               "chat: make: prompt_cache_key: empty string") });
    ("effort outside the published menu rejects (A1)",
     on_model chatty
       { f =
           (fun m ->
             with_effort_w m (fun ew ->
                 rejects
                   (let* msgs = mk_msgs "hi" in
                    C.make ~effort:(ew, Eff.Xhigh) m msgs ())
                   "chat: make: effort xhigh: not in reasoningEffortOptions"))
       });
    (* Stop bounds (D7) *)
    ("Stop.of_string empty rejects",
     rejects (Stop.of_string "") "chat: stop: empty string");
    ("Stop.of_list empty rejects",
     rejects (Stop.of_list []) "chat: stop: empty list");
    ("Stop.of_list five items rejects",
     rejects
       (Stop.of_list [ "a"; "b"; "c"; "d"; "e" ])
       "chat: stop: 5 items: above max 4");
    ("Stop.of_list embedded empty rejects",
     rejects (Stop.of_list [ "a"; "" ]) "chat: stop: item: empty string");
    ("Stop.of_list one item mints", minted (Stop.of_list [ "x" ]));
    ("Stop.of_list four items mints",
     minted (Stop.of_list [ "a"; "b"; "c"; "d" ]));
    (* budget boundaries (D4b) *)
    ("budget under passes",
     on_model chatty
       { f =
           (fun m ->
             budget_ok
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:96 m msgs ())
               100) });
    ("budget equal passes",
     on_model chatty
       { f =
           (fun m ->
             budget_ok
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:96 m msgs ())
               4000) });
    ("budget over rejects",
     on_model chatty
       { f =
           (fun m ->
             budget_rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~max_completion:96 m msgs ())
               4001
               "chat: budget: prompt 4001 + completion 96: exceeds context 4096")
       });
    ("budget falls back to the model cap, equal passes",
     on_model chatty
       { f =
           (fun m ->
             budget_ok
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               2048) });
    ("budget falls back to the model cap, over rejects",
     on_model chatty
       { f =
           (fun m ->
             budget_rejects
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               2049
               "chat: budget: prompt 2049 + completion 2048: exceeds context 4096")
       });
    ("budget capless completion reads 0, equal passes",
     on_model ctxonly
       { f =
           (fun m ->
             budget_ok
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               100) });
    ("budget capless completion reads 0, over rejects",
     on_model ctxonly
       { f =
           (fun m ->
             budget_rejects
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               101 "chat: budget: prompt 101 + completion 0: exceeds context 100")
       });
    ("budget without a published context window passes",
     on_model uncapped
       { f =
           (fun m ->
             budget_ok
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               1000000000) });
    ("budget negative prompt_tokens rejects",
     on_model chatty
       { f =
           (fun m ->
             budget_rejects
               (let* msgs = mk_msgs "hi" in
                C.make m msgs ())
               (-1) "chat: budget: prompt_tokens -1: below 0") });
    (* enum round-trips *)
    ("Effort round-trips", List.for_all round_trips_effort all_efforts);
    ("Effort.of_string unknown rejects",
     rejects (Eff.of_string "warp") "chat: effort: unknown value warp");
    ("Cache_retention round-trips",
     List.for_all round_trips_retention all_retentions);
    ("Cache_retention.of_string unknown rejects",
     rejects
       (CR.of_string "forever")
       "chat: prompt_cache_retention: unknown value forever");
    (* tools / tool_choice / parallel_tool_calls / response_format
       (M10a) *)
    ("toggle tools minimal function",
     on_model chatty
       { f =
           (fun m ->
             with_tools_w m (fun tw ->
                 chat_emits
                   (let* t = mk_tool "f" in
                    let* msgs = mk_msgs "hi" in
                    C.make ~tools:(tw, [ t ]) m msgs ())
                   (toggle
                      {|"tools":[{"type":"function","function":{"name":"f"}}]|})))
       });
    ("toggle tools full function pair",
     on_model chatty
       { f =
           (fun m ->
             with_tools_w m (fun tw ->
                 chat_emits
                   (let* a =
                      C.Tool.function_ ~name:"f" ~description:"adds"
                        ~parameters:
                          (J.Jobj
                             [ ("type", J.Jstring "object");
                               ("properties", J.Jobj []) ])
                        ~strict:true ()
                    in
                    let* b = mk_tool "g" in
                    let* msgs = mk_msgs "hi" in
                    C.make ~tools:(tw, [ a; b ]) m msgs ())
                   (toggle
                      {|"tools":[{"type":"function","function":{"name":"f","description":"adds","parameters":{"type":"object","properties":{}},"strict":true}},{"type":"function","function":{"name":"g"}}]|})))
       });
    ("toggle tool_choice bare strings without tools (A6)",
     on_model chatty
       { f =
           (fun m ->
             List.for_all
               (fun ((c : C.tool_choice), (w : string)) ->
                 chat_emits
                   (let* msgs = mk_msgs "hi" in
                    C.make ~tool_choice:c m msgs ())
                   (toggle ({|"tool_choice":|} ^ w)))
               [ (C.Tool_auto, {|"auto"|}); (C.Tool_none, {|"none"|});
                 (C.Tool_required, {|"required"|}) ]) });
    ("toggle tool_choice function with tools",
     on_model chatty
       { f =
           (fun m ->
             with_tools_w m (fun tw ->
                 chat_emits
                   (let* t = mk_tool "f" in
                    let* msgs = mk_msgs "hi" in
                    C.make ~tools:(tw, [ t ])
                      ~tool_choice:(C.Tool_function "f") m msgs ())
                   (toggle
                      {|"tools":[{"type":"function","function":{"name":"f"}}],"tool_choice":{"type":"function","function":{"name":"f"}}|})))
       });
    ("toggle parallel_tool_calls standalone (A6)",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~parallel_tool_calls:false m msgs ())
               (toggle {|"parallel_tool_calls":false|})) });
    ("toggle response_format json_object",
     on_model chatty
       { f =
           (fun m ->
             chat_emits
               (let* msgs = mk_msgs "hi" in
                C.make ~response_format:C.Rf_json_object m msgs ())
               (toggle {|"response_format":{"type":"json_object"}|})) });
    ("toggle response_format json_schema",
     on_model chatty
       { f =
           (fun m ->
             with_schema_w m (fun rw ->
                 chat_emits
                   (let* msgs = mk_msgs "hi" in
                    C.make
                      ~response_format:
                        (C.Rf_json_schema
                           (rw, J.Jobj [ ("type", J.Jstring "object") ]))
                      m msgs ())
                   (toggle
                      {|"response_format":{"type":"json_schema","json_schema":{"type":"object"}}|})))
       });
    ("all four M10a members follow prompt_cache_retention",
     on_model chatty
       { f =
           (fun m ->
             with_tools_w m (fun tw ->
                 chat_emits
                   (let* t = mk_tool "f" in
                    let* msgs = mk_msgs "hi" in
                    C.make ~cache_retention:CR.Extended ~tools:(tw, [ t ])
                      ~tool_choice:C.Tool_auto ~parallel_tool_calls:true
                      ~response_format:C.Rf_json_object m msgs ())
                   (toggle
                      {|"prompt_cache_retention":"extended","tools":[{"type":"function","function":{"name":"f"}}],"tool_choice":"auto","parallel_tool_calls":true,"response_format":{"type":"json_object"}|})))
       });
    ("empty tools list rejects",
     on_model chatty
       { f =
           (fun m ->
             with_tools_w m (fun tw ->
                 rejects
                   (let* msgs = mk_msgs "hi" in
                    C.make ~tools:(tw, []) m msgs ())
                   "chat: make: tools: empty list")) });
    ("duplicate tool name rejects",
     on_model chatty
       { f =
           (fun m ->
             with_tools_w m (fun tw ->
                 rejects
                   (let* a = mk_tool "f" in
                    let* b = mk_tool "f" in
                    let* msgs = mk_msgs "hi" in
                    C.make ~tools:(tw, [ a; b ]) m msgs ())
                   "chat: make: tools: duplicate name f")) });
    ("tool_choice function without tools rejects",
     on_model chatty
       { f =
           (fun m ->
             rejects
               (let* msgs = mk_msgs "hi" in
                C.make ~tool_choice:(C.Tool_function "f") m msgs ())
               "chat: make: tool_choice: function without tools") });
    ("tool_choice function not in tools rejects",
     on_model chatty
       { f =
           (fun m ->
             with_tools_w m (fun tw ->
                 rejects
                   (let* t = mk_tool "f" in
                    let* msgs = mk_msgs "hi" in
                    C.make ~tools:(tw, [ t ])
                      ~tool_choice:(C.Tool_function "g") m msgs ())
                   "chat: make: tool_choice: function g: not in tools")) });
    ("json_schema non-object payload rejects",
     on_model chatty
       { f =
           (fun m ->
             with_schema_w m (fun rw ->
                 rejects
                   (let* msgs = mk_msgs "hi" in
                    C.make
                      ~response_format:
                        (C.Rf_json_schema (rw, J.Jlist []))
                      m msgs ())
                   "chat: make: response_format: json_schema: not an object"))
       });
    ("Tool.function_ empty name rejects",
     rejects (C.Tool.function_ ~name:"" ()) "chat: tool: name: empty string");
    ("Tool.function_ empty description rejects",
     rejects
       (C.Tool.function_ ~name:"f" ~description:"" ())
       "chat: tool: description: empty string");
    ("Tool.function_ non-object parameters rejects",
     rejects
       (C.Tool.function_ ~name:"f" ~parameters:(J.Jstring "x") ())
       "chat: tool: parameters: not an object");
    ("tools witness absent without the capability (M10a)",
     on_model uncapped { f = (fun m -> Option.is_none (M.tools m)) });
    ("response_schema witness absent without the capability (M10a)",
     on_model uncapped
       { f = (fun m -> Option.is_none (M.response_schema m)) });
    (* A9 fixture activation *)
    ("fixture golden minimal (A9: skipped until fixtures/ lands)",
     fixture_minimal_matches)
  ]

let () = run checks
