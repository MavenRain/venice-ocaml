(* M5 model domain: parser, enums, and witness extraction. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module M = Venice.Model
module J = Venice.Json

(* A checker carries a polymorphic body so one helper unpacks the
   existential for every scalar and witness probe. *)
type checker = { f : 'c. 'c M.t -> bool }

let on_model (s : string) (c : checker) : bool =
  Result.fold
    ~ok:(fun p -> match p with M.Pack m -> c.f m)
    ~error:(fun ((_ : Venice.Error.t)) -> false)
    (Result.bind (J.parse s) M.of_json)

let parse_err (s : string) : string option =
  Result.fold
    ~ok:(fun ((_ : M.packed)) -> None)
    ~error:(fun e -> Some (Venice.Error.to_string e))
    (Result.bind (J.parse s) M.of_json)

let on_listing (s : string) (f : M.packed list -> bool) : bool =
  Result.fold ~ok:f
    ~error:(fun ((_ : Venice.Error.t)) -> false)
    (Result.bind (J.parse s) M.of_listing)

let listing_err (s : string) : string option =
  Result.fold
    ~ok:(fun ((_ : M.packed list)) -> None)
    ~error:(fun e -> Some (Venice.Error.to_string e))
    (Result.bind (J.parse s) M.of_listing)

(* Fixtures. full exercises every parsed field; minimal only the two
   required members. *)
let full : string =
  {|{"id":"e2ee-glm-5","type":"text","created":1730000000,"traits":["default","fastest"],"offline":false,"model_spec":{"privacy":"private","availableContextTokens":131072,"maxCompletionTokens":8192,"beta":true,"deprecation":{"deprecationDate":"2027-01-01","replacementModel":"e2ee-glm-6"},"capabilities":{"optimizedForCode":false,"supportsFunctionCalling":true,"supportsReasoning":true,"supportsReasoningEffort":true,"supportsResponseSchema":true,"supportsVision":true,"supportsVideoInput":false,"supportsAudioInput":true,"supportsWebSearch":true,"supportsLogProbs":false,"supportsTeeAttestation":true,"supportsE2EE":true,"supportsXSearch":false,"quantization":"fp8","reasoningEffortOptions":["low","medium","high"]},"constraints":{"temperature":{"default":0.7},"top_p":{"default":0.9}}}}|}

let minimal : string = {|{"id":"flux-dev","type":"image"}|}

(* Capabilities asserted but almost all false: negatives must read
   None while the one true flag still mints. *)
let sparse : string =
  {|{"id":"venice-uncensored","type":"text","model_spec":{"privacy":"anonymized","capabilities":{"supportsFunctionCalling":true,"quantization":"not-available"}}}|}

(* capabilities at the top of the entry, no model_spec at all. *)
let top_caps : string =
  {|{"id":"qwen3-4b","type":"text","capabilities":{"supportsVision":true,"quantization":"bf16"}}|}

(* model_spec present but bare; capabilities fall back to top level. *)
let split_caps : string =
  {|{"id":"e2ee-qwen3-5-122b-a10b","type":"text","model_spec":{"privacy":"private"},"capabilities":{"supportsE2EE":true,"quantization":"fp4"}}|}

(* Explicit null on every optional top-level field must parse exactly
   like absence. *)
let nulls : string =
  {|{"id":"m","type":"text","created":null,"traits":null,"offline":null,"capabilities":null,"model_spec":null,"constraints":null}|}

(* Explicit null on every optional model_spec scalar. *)
let spec_nulls : string =
  {|{"id":"m","type":"text","model_spec":{"privacy":null,"beta":null,"availableContextTokens":null,"maxCompletionTokens":null,"deprecation":null,"capabilities":null,"constraints":null}}|}

(* Spec scalars at the top of the entry, no model_spec at all: the
   fallback must read them, not silently default. *)
let top_spec : string =
  {|{"id":"m","type":"text","beta":true,"privacy":"anonymized","availableContextTokens":4096,"maxCompletionTokens":512,"deprecation":{"retiresAt":"2027-06-30","replacement":"m2"}}|}

(* Both locations hold spec scalars: model_spec must win. *)
let spec_wins : string =
  {|{"id":"m","type":"text","beta":false,"privacy":"anonymized","availableContextTokens":1,"deprecation":{"retiresAt":"1999-01-01"},"model_spec":{"beta":true,"privacy":"private","availableContextTokens":2,"deprecation":{"retiresAt":"2028-01-01"}}}|}

let listing : string =
  {|{"object":"list","data":[|} ^ full ^ "," ^ minimal ^ "]}"

let model_of_kind (k : string) : string =
  {|{"id":"m","type":"|} ^ k ^ {|"}|}

let model_of_quant (q : string) : string =
  {|{"id":"m","type":"text","capabilities":{"quantization":"|} ^ q ^ {|"}}|}

let model_of_privacy (p : string) : string =
  {|{"id":"m","type":"text","model_spec":{"privacy":"|} ^ p ^ {|"}}|}

let model_of_dep (d : string) : string =
  {|{"id":"m","type":"text","model_spec":{"deprecation":|} ^ d ^ "}}"

let checks : (string * bool) list =
  [ (* full model scalars *)
    ("full id", on_model full { f = (fun m -> String.equal (M.id m) "e2ee-glm-5") });
    ("full slug", on_model full { f = (fun m -> M.slug m = M.E2ee_glm_5) });
    ("full kind", on_model full { f = (fun m -> M.kind m = M.Text) });
    ("full created", on_model full { f = (fun m -> M.created m = Some 1730000000) });
    ("full traits", on_model full { f = (fun m -> M.traits m = [ "default"; "fastest" ]) });
    ("full offline", on_model full { f = (fun m -> M.offline m = false) });
    ("full beta", on_model full { f = (fun m -> M.beta m = true) });
    ("full privacy", on_model full { f = (fun m -> M.privacy m = Some M.Private) });
    ("full context", on_model full { f = (fun m -> M.context_tokens m = Some 131072) });
    ("full max completion", on_model full { f = (fun m -> M.max_completion_tokens m = Some 8192) });
    ("full quantization", on_model full { f = (fun m -> M.quantization m = Some M.Fp8) });
    ("full effort options", on_model full { f = (fun m -> M.effort_options m = [ "low"; "medium"; "high" ]) });
    ("full deprecation",
     on_model full
       { f =
           (fun m ->
             M.deprecation m
             = M.Deprecated
                 { dates = [ ("deprecationDate", "2027-01-01") ];
                   replacement = Some "e2ee-glm-6" }) });
    (* full model witnesses: every relevant flag is true *)
    ("full vision", on_model full { f = (fun m -> Option.is_some (M.vision m)) });
    ("full tools", on_model full { f = (fun m -> Option.is_some (M.tools m)) });
    ("full reasoning", on_model full { f = (fun m -> Option.is_some (M.reasoning m)) });
    ("full audio", on_model full { f = (fun m -> Option.is_some (M.audio m)) });
    ("full tee", on_model full { f = (fun m -> Option.is_some (M.tee m)) });
    ("full e2ee", on_model full { f = (fun m -> Option.is_some (M.e2ee m)) });
    ("full witness chain",
     on_model full
       { f =
           (fun m ->
             Option.is_some
               (Option.bind (M.vision m) (fun m ->
                    Option.bind (M.tools m) (fun m ->
                        Option.bind (M.reasoning m) (fun m ->
                            Option.bind (M.audio m) (fun m ->
                                Option.bind (M.tee m) M.e2ee)))))) });
    (* minimal model: defaults everywhere *)
    ("minimal kind", on_model minimal { f = (fun m -> M.kind m = M.Image) });
    ("minimal slug", on_model minimal { f = (fun m -> M.slug m = M.Unknown "flux-dev") });
    ("minimal created", on_model minimal { f = (fun m -> M.created m = None) });
    ("minimal traits", on_model minimal { f = (fun m -> M.traits m = []) });
    ("minimal offline", on_model minimal { f = (fun m -> M.offline m = false) });
    ("minimal beta", on_model minimal { f = (fun m -> M.beta m = false) });
    ("minimal privacy", on_model minimal { f = (fun m -> M.privacy m = None) });
    ("minimal context", on_model minimal { f = (fun m -> M.context_tokens m = None) });
    ("minimal max completion", on_model minimal { f = (fun m -> M.max_completion_tokens m = None) });
    ("minimal quantization", on_model minimal { f = (fun m -> M.quantization m = None) });
    ("minimal effort options", on_model minimal { f = (fun m -> M.effort_options m = []) });
    ("minimal deprecation", on_model minimal { f = (fun m -> M.deprecation m = M.Active) });
    ("minimal vision none", on_model minimal { f = (fun m -> Option.is_none (M.vision m)) });
    ("minimal tools none", on_model minimal { f = (fun m -> Option.is_none (M.tools m)) });
    ("minimal e2ee none", on_model minimal { f = (fun m -> Option.is_none (M.e2ee m)) });
    (* sparse: false and absent flags read None, the true one mints *)
    ("sparse privacy", on_model sparse { f = (fun m -> M.privacy m = Some M.Anonymized) });
    ("sparse quantization", on_model sparse { f = (fun m -> M.quantization m = Some M.Not_available) });
    ("sparse tools", on_model sparse { f = (fun m -> Option.is_some (M.tools m)) });
    ("sparse vision none", on_model sparse { f = (fun m -> Option.is_none (M.vision m)) });
    ("sparse reasoning none", on_model sparse { f = (fun m -> Option.is_none (M.reasoning m)) });
    ("sparse audio none", on_model sparse { f = (fun m -> Option.is_none (M.audio m)) });
    ("sparse tee none", on_model sparse { f = (fun m -> Option.is_none (M.tee m)) });
    ("sparse e2ee none", on_model sparse { f = (fun m -> Option.is_none (M.e2ee m)) });
    ("sparse deprecation absent", on_model sparse { f = (fun m -> M.deprecation m = M.Active) });
    (* capabilities location: top level and model_spec fallback *)
    ("top caps vision", on_model top_caps { f = (fun m -> Option.is_some (M.vision m)) });
    ("top caps quantization", on_model top_caps { f = (fun m -> M.quantization m = Some M.Bf16) });
    ("split caps e2ee", on_model split_caps { f = (fun m -> Option.is_some (M.e2ee m)) });
    ("split caps privacy", on_model split_caps { f = (fun m -> M.privacy m = Some M.Private) });
    ("split caps slug", on_model split_caps { f = (fun m -> M.slug m = M.E2ee_qwen3_5_122b_a10b) });
    (* kind table: the ten concrete wire values *)
    ("kind text", on_model (model_of_kind "text") { f = (fun m -> M.kind m = M.Text) });
    ("kind code", on_model (model_of_kind "code") { f = (fun m -> M.kind m = M.Code) });
    ("kind image", on_model (model_of_kind "image") { f = (fun m -> M.kind m = M.Image) });
    ("kind embedding", on_model (model_of_kind "embedding") { f = (fun m -> M.kind m = M.Embedding) });
    ("kind tts", on_model (model_of_kind "tts") { f = (fun m -> M.kind m = M.Tts) });
    ("kind asr", on_model (model_of_kind "asr") { f = (fun m -> M.kind m = M.Asr) });
    ("kind music", on_model (model_of_kind "music") { f = (fun m -> M.kind m = M.Music) });
    ("kind upscale", on_model (model_of_kind "upscale") { f = (fun m -> M.kind m = M.Upscale) });
    ("kind inpaint", on_model (model_of_kind "inpaint") { f = (fun m -> M.kind m = M.Inpaint) });
    ("kind video", on_model (model_of_kind "video") { f = (fun m -> M.kind m = M.Video) });
    (* "all" is a query parameter value, never a model type *)
    ("kind all rejects", parse_err (model_of_kind "all") = Some "model: m.type: unknown value all");
    (* quantization table *)
    ("quant fp4", on_model (model_of_quant "fp4") { f = (fun m -> M.quantization m = Some M.Fp4) });
    ("quant fp8", on_model (model_of_quant "fp8") { f = (fun m -> M.quantization m = Some M.Fp8) });
    ("quant fp16", on_model (model_of_quant "fp16") { f = (fun m -> M.quantization m = Some M.Fp16) });
    ("quant bf16", on_model (model_of_quant "bf16") { f = (fun m -> M.quantization m = Some M.Bf16) });
    ("quant int8", on_model (model_of_quant "int8") { f = (fun m -> M.quantization m = Some M.Int8) });
    ("quant int4", on_model (model_of_quant "int4") { f = (fun m -> M.quantization m = Some M.Int4) });
    ("quant not-available", on_model (model_of_quant "not-available") { f = (fun m -> M.quantization m = Some M.Not_available) });
    ("quant fp6 rejects", parse_err (model_of_quant "fp6") = Some "model: m.capabilities.quantization: unknown value fp6");
    (* absent capability bools default false: quant-only caps mint nothing *)
    ("quant-only no witnesses",
     on_model (model_of_quant "fp8")
       { f =
           (fun m ->
             Option.is_none (M.vision m) && Option.is_none (M.tools m)
             && Option.is_none (M.e2ee m)) });
    (* privacy *)
    ("privacy private", on_model (model_of_privacy "private") { f = (fun m -> M.privacy m = Some M.Private) });
    ("privacy anonymized", on_model (model_of_privacy "anonymized") { f = (fun m -> M.privacy m = Some M.Anonymized) });
    ("privacy public rejects", parse_err (model_of_privacy "public") = Some "model: m.model_spec.privacy: unknown value public");
    ("privacy non-string rejects",
     parse_err {|{"id":"m","type":"text","model_spec":{"privacy":1}}|}
     = Some "model: m.model_spec.privacy: not a string");
    (* deprecation shapes *)
    ("dep null", on_model (model_of_dep "null") { f = (fun m -> M.deprecation m = M.Active) });
    ("dep empty object",
     on_model (model_of_dep "{}") { f = (fun m -> M.deprecation m = M.Active) });
    ("dep int date",
     on_model (model_of_dep {|{"retiresAt":1735689600}|})
       { f =
           (fun m ->
             M.deprecation m
             = M.Deprecated
                 { dates = [ ("retiresAt", "1735689600") ]; replacement = None }) });
    ("dep replacement only",
     on_model (model_of_dep {|{"replacement":"qwen3-next"}|})
       { f =
           (fun m ->
             M.deprecation m
             = M.Deprecated { dates = []; replacement = Some "qwen3-next" }) });
    ("dep bool rejects",
     parse_err (model_of_dep "true") = Some "model: m.model_spec.deprecation: not an object");
    ("dep member bool rejects",
     parse_err (model_of_dep {|{"note":true}|})
     = Some "model: m.model_spec.deprecation.note: not a string or int");
    (* malformed entries *)
    ("entry not object", parse_err {|"hi"|} = Some "model: entry: not an object");
    ("id missing", parse_err {|{"type":"text"}|} = Some "model: id: missing or not a string");
    ("id non-string", parse_err {|{"id":3,"type":"text"}|} = Some "model: id: missing or not a string");
    ("type missing", parse_err {|{"id":"m"}|} = Some "model: m.type: missing or not a string");
    ("offline non-bool",
     parse_err {|{"id":"m","type":"text","offline":"no"}|}
     = Some "model: m.offline: not a bool");
    ("created non-int",
     parse_err {|{"id":"m","type":"text","created":"now"}|}
     = Some "model: m.created: not an int");
    ("context tokens decimal rejects",
     parse_err {|{"id":"m","type":"text","model_spec":{"availableContextTokens":131072.5}}|}
     = Some "model: m.model_spec.availableContextTokens: not an int");
    ("traits non-list",
     parse_err {|{"id":"m","type":"text","traits":"default"}|}
     = Some "model: m.traits: not a list");
    ("traits item non-string",
     parse_err {|{"id":"m","type":"text","traits":[1]}|}
     = Some "model: m.traits: item not a string");
    ("model_spec non-object",
     parse_err {|{"id":"m","type":"text","model_spec":[]}|}
     = Some "model: m.model_spec: not an object");
    ("capabilities non-object",
     parse_err {|{"id":"m","type":"text","capabilities":3}|}
     = Some "model: m.capabilities: not an object");
    ("capability bool non-bool",
     parse_err {|{"id":"m","type":"text","capabilities":{"supportsVision":1,"quantization":"fp8"}}|}
     = Some "model: m.capabilities.supportsVision: not a bool");
    ("quantization absent ok",
     on_model {|{"id":"m","type":"text","capabilities":{}}|}
       { f = (fun m -> M.quantization m = None) });
    ("quantization null ok",
     on_model {|{"id":"m","type":"text","capabilities":{"quantization":null}}|}
       { f = (fun m -> M.quantization m = None) });
    ("quantization absent still mints",
     on_model {|{"id":"m","type":"text","capabilities":{"supportsVision":true}}|}
       { f = (fun m -> Option.is_some (M.vision m) && M.quantization m = None) });
    ("quantization non-string rejects",
     parse_err {|{"id":"m","type":"text","capabilities":{"quantization":3}}|}
     = Some "model: m.capabilities.quantization: not a string");
    ("effort options non-list",
     parse_err {|{"id":"m","type":"text","capabilities":{"quantization":"fp8","reasoningEffortOptions":3}}|}
     = Some "model: m.capabilities.reasoningEffortOptions: not a list");
    ("effort options item non-string",
     parse_err {|{"id":"m","type":"text","capabilities":{"quantization":"fp8","reasoningEffortOptions":["low",5]}}|}
     = Some "model: m.capabilities.reasoningEffortOptions: item not a string");
    ("constraints non-object",
     parse_err {|{"id":"m","type":"text","constraints":5}|}
     = Some "model: m.constraints: not an object");
    (* explicit null on optional fields reads as absence *)
    ("nulls parse ok", on_model nulls { f = (fun m -> String.equal (M.id m) "m") });
    ("nulls created", on_model nulls { f = (fun m -> M.created m = None) });
    ("nulls traits", on_model nulls { f = (fun m -> M.traits m = []) });
    ("nulls offline", on_model nulls { f = (fun m -> M.offline m = false) });
    ("nulls quantization", on_model nulls { f = (fun m -> M.quantization m = None) });
    ("nulls vision none", on_model nulls { f = (fun m -> Option.is_none (M.vision m)) });
    ("nulls beta", on_model nulls { f = (fun m -> M.beta m = false) });
    ("nulls privacy", on_model nulls { f = (fun m -> M.privacy m = None) });
    ("nulls context", on_model nulls { f = (fun m -> M.context_tokens m = None) });
    ("nulls max completion", on_model nulls { f = (fun m -> M.max_completion_tokens m = None) });
    ("nulls deprecation", on_model nulls { f = (fun m -> M.deprecation m = M.Active) });
    ("spec nulls privacy", on_model spec_nulls { f = (fun m -> M.privacy m = None) });
    ("spec nulls beta", on_model spec_nulls { f = (fun m -> M.beta m = false) });
    ("spec nulls context", on_model spec_nulls { f = (fun m -> M.context_tokens m = None) });
    ("spec nulls max completion", on_model spec_nulls { f = (fun m -> M.max_completion_tokens m = None) });
    ("spec nulls deprecation", on_model spec_nulls { f = (fun m -> M.deprecation m = M.Active) });
    ("spec nulls quantization", on_model spec_nulls { f = (fun m -> M.quantization m = None) });
    (* spec scalars at the top level: the fallback reads them *)
    ("top spec beta", on_model top_spec { f = (fun m -> M.beta m = true) });
    ("top spec privacy", on_model top_spec { f = (fun m -> M.privacy m = Some M.Anonymized) });
    ("top spec context", on_model top_spec { f = (fun m -> M.context_tokens m = Some 4096) });
    ("top spec max completion", on_model top_spec { f = (fun m -> M.max_completion_tokens m = Some 512) });
    ("top spec deprecation",
     on_model top_spec
       { f =
           (fun m ->
             M.deprecation m
             = M.Deprecated
                 { dates = [ ("retiresAt", "2027-06-30") ];
                   replacement = Some "m2" }) });
    ("top privacy non-string rejects",
     parse_err {|{"id":"m","type":"text","privacy":1}|}
     = Some "model: m.privacy: not a string");
    (* both locations populated: model_spec wins *)
    ("spec wins beta", on_model spec_wins { f = (fun m -> M.beta m = true) });
    ("spec wins privacy", on_model spec_wins { f = (fun m -> M.privacy m = Some M.Private) });
    ("spec wins context", on_model spec_wins { f = (fun m -> M.context_tokens m = Some 2) });
    ("spec wins deprecation",
     on_model spec_wins
       { f =
           (fun m ->
             M.deprecation m
             = M.Deprecated
                 { dates = [ ("retiresAt", "2028-01-01") ]; replacement = None }) });
    (* listing *)
    ("listing two entries",
     on_listing listing (fun ps ->
         match ps with
         | [ M.Pack a; M.Pack b ] ->
           String.equal (M.id a) "e2ee-glm-5" && String.equal (M.id b) "flux-dev"
         | [] | [ _ ] | _ :: _ :: _ :: _ -> false));
    ("listing empty data", on_listing {|{"object":"list","data":[]}|} (fun ps -> ps = []));
    ("listing data missing", listing_err {|{"object":"list"}|} = Some "model: listing.data: missing or not a list");
    ("listing data non-list", listing_err {|{"data":3}|} = Some "model: listing.data: missing or not a list");
    ("listing bad entry named",
     listing_err {|{"data":[{"id":"m","type":"lava"}]}|}
     = Some "model: m.type: unknown value lava")
  ]

let () = run checks
