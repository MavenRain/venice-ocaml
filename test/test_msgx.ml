(* M7 message domain: constructors, mint-time validation, emission and
   the collapse rule, the media caps view, and the sessx seam. The
   seam and exact emission live behind venice.mli, so this suite binds
   the library-internal modules by their mangled names; the public
   boundary itself is exercised by the compile-fail battery. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module Msg = Venice__Msgx
module AF = Venice__Msgx.Audio_format
module M = Venice__Modelx
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

let parse_err (s : string) : string option =
  Result.fold
    ~ok:(fun ((_ : M.packed)) -> None)
    ~error:(fun e -> Some (E.to_string e))
    (Result.bind (J.parse s) M.of_json)

(* Result helpers over the one error type. *)

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

let emits (r : ('a, E.t) result) (f : 'a -> J.t) (expect : string) : bool =
  Result.fold
    ~ok:(fun v -> String.equal (J.emit (f v)) expect)
    ~error:(fun ((_ : E.t)) -> false)
    r

let emits_str (r : (string, E.t) result) (expect : string) : bool =
  Result.fold
    ~ok:(String.equal expect)
    ~error:(fun ((_ : E.t)) -> false)
    r

let emit_msg (m : Msg.msg) : J.t = Msg.emit_message (Msg.lift m)

let plain (r : ('c Msg.t, E.t) result) (expect : string option) : bool =
  Result.fold
    ~ok:(fun m -> Msg.content_plaintext m = expect)
    ~error:(fun ((_ : E.t)) -> false)
    r

(* Fixtures. trimodal asserts all three media capabilities plus the
   image/video count caps; second asserts vision only; bare has no
   capabilities object at all. *)
let trimodal : string =
  {|{"id":"tri","type":"text","capabilities":{"supportsVision":true,"supportsAudioInput":true,"supportsVideoInput":true,"supportsMultipleImages":true,"maxImages":10,"maxVideos":4}}|}

let second : string =
  {|{"id":"duo","type":"text","capabilities":{"supportsVision":true}}|}

let bare : string = {|{"id":"bare","type":"text"}|}

(* Unbranded payloads bound ONCE at structure level: the
   value-restriction regression. A branded design makes these weak or
   escaping; the unbranded design must let one binding serve two
   models below. *)
let shared_sys : (Msg.msg, E.t) result = Msg.system "you are helpful"
let shared_caption : (Msg.text_part, E.t) result = Msg.text "shared"

(* One request against one vision witness, reusing both shared
   payloads; the injections instantiate the row per call. *)
let send_with (vm : ('c * M.vision) M.t) (url : string) :
    (string, E.t) result =
  let* s = shared_sys in
  let* cap = shared_caption in
  let* img = Msg.image vm ~url in
  let* u = Msg.user [ Msg.of_text cap; img ] in
  let* msgs = Msg.nonempty [ Msg.lift s; u ] in
  Ok (J.emit (Msg.emit msgs))

(* All three witnesses unpacked in parallel from the trimodal model. *)
type media_checker =
  { g :
      'c.
      ('c * M.vision) M.t ->
      ('c * M.audio) M.t ->
      ('c * M.video) M.t ->
      bool }

let on_trimodal (c : media_checker) : bool =
  on_model trimodal
    { f =
        (fun m ->
          let md : _ M.media = M.media m in
          Option.fold ~none:false
            ~some:(fun vm ->
              Option.fold ~none:false
                ~some:(fun am ->
                  Option.fold ~none:false
                    ~some:(fun dm -> c.g vm am dm)
                    md.M.video)
                md.M.audio)
            md.M.vision) }

let good_b64 : string = "aGVsbG8="

let all_formats : AF.t list =
  [ AF.Wav; AF.Mp3; AF.Aiff; AF.Aac; AF.Ogg; AF.Flac; AF.M4a;
    AF.Pcm16; AF.Pcm24 ]

let checks : (string * bool) list =
  [ (* model caps: video witness, media view, count caps *)
    ("video witness some",
     on_model trimodal { f = (fun m -> Option.is_some (M.video m)) });
    ("video witness none",
     on_model second { f = (fun m -> Option.is_none (M.video m)) });
    ("media all three",
     on_trimodal
       { g =
           (fun ((_ : ('c * M.vision) M.t)) ((_ : ('c * M.audio) M.t))
                ((_ : ('c * M.video) M.t)) -> true) });
    ("media none on bare",
     on_model bare
       { f =
           (fun m ->
             let md : _ M.media = M.media m in
             Option.is_none md.M.vision
             && Option.is_none md.M.audio
             && Option.is_none md.M.video) });
    ("multiple_images true",
     on_model trimodal { f = (fun m -> M.multiple_images m) });
    ("multiple_images absent reads false",
     on_model second { f = (fun m -> not (M.multiple_images m)) });
    ("multiple_images no caps false",
     on_model bare { f = (fun m -> not (M.multiple_images m)) });
    ("max_images some",
     on_model trimodal { f = (fun m -> M.max_images m = Some 10) });
    ("max_images none",
     on_model second { f = (fun m -> M.max_images m = None) });
    ("max_videos some",
     on_model trimodal { f = (fun m -> M.max_videos m = Some 4) });
    ("max_videos none",
     on_model second { f = (fun m -> M.max_videos m = None) });
    ("supportsMultipleImages non-bool rejects",
     parse_err
       {|{"id":"tri","type":"text","capabilities":{"supportsMultipleImages":3}}|}
     = Some "model: tri.capabilities.supportsMultipleImages: not a bool");
    ("maxImages non-int rejects",
     parse_err
       {|{"id":"tri","type":"text","capabilities":{"maxImages":true}}|}
     = Some "model: tri.capabilities.maxImages: not an int");
    ("maxVideos non-int rejects",
     parse_err
       {|{"id":"tri","type":"text","capabilities":{"maxVideos":"3"}}|}
     = Some "model: tri.capabilities.maxVideos: not an int");
    (* audio format enum *)
    ("audio format wire names",
     String.equal
       (String.concat "," (List.map AF.to_string all_formats))
       "wav,mp3,aiff,aac,ogg,flac,m4a,pcm16,pcm24");
    ("audio format of_string round-trips",
     List.for_all
       (fun f -> AF.of_string (AF.to_string f) = Ok f)
       all_formats);
    ("audio format unknown rejects",
     rejects (AF.of_string "opus") "msg: audio format: unknown value opus");
    ("audio format default wav", AF.default = AF.Wav);
    (* unbranded payload constructors *)
    ("text mints", minted (Msg.text "hi"));
    ("text empty rejects", rejects (Msg.text "") "msg: text part: empty");
    ("file mints on data url",
     minted (Msg.file "data:application/pdf;base64,AAA="));
    ("file uri shapes accept",
     List.for_all
       (fun u -> minted (Msg.file u))
       [ "https://e.com/a.pdf"; "data:image/png;base64,AAA"; "a:";
         "a+b-c.9:rest" ]);
    ("file uri shapes reject",
     List.for_all
       (fun u ->
         rejects (Msg.file u) "msg: file.file_data: not a uri")
       [ ""; "nope"; ":lead"; "1st://x"; "ht tp://x" ]);
    (* system / developer *)
    ("system collapses to bare string",
     emits (Msg.system "be brief") emit_msg
       {|{"role":"system","content":"be brief"}|});
    ("system empty rejects",
     rejects (Msg.system "") "msg: system content: empty");
    ("system name member last",
     emits (Msg.system ~name:"n" "x") emit_msg
       {|{"role":"system","content":"x","name":"n"}|});
    ("system_parts two parts stay array",
     emits
       (let* a = Msg.text "a" in
        let* b = Msg.text "b" in
        Msg.system_parts [ a; b ])
       emit_msg
       {|{"role":"system","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}|});
    ("system_parts single cached part stays array",
     emits
       (let* a = Msg.text ~cache:Msg.Cache.ephemeral "a" in
        Msg.system_parts [ a ])
       emit_msg
       {|{"role":"system","content":[{"type":"text","text":"a","cache_control":{"type":"ephemeral"}}]}|});
    ("system_parts single plain part collapses",
     emits
       (let* a = Msg.text "solo" in
        Msg.system_parts [ a ])
       emit_msg
       {|{"role":"system","content":"solo"}|});
    ("system_parts empty rejects",
     rejects (Msg.system_parts []) "msg: system parts: empty");
    ("developer collapses to bare string",
     emits (Msg.developer "d") emit_msg
       {|{"role":"developer","content":"d"}|});
    ("developer empty rejects",
     rejects (Msg.developer "") "msg: developer content: empty");
    ("developer_parts empty rejects",
     rejects (Msg.developer_parts []) "msg: developer parts: empty");
    ("developer_parts single plain part collapses",
     emits
       (let* a = Msg.text "solo" in
        Msg.developer_parts [ a ])
       emit_msg
       {|{"role":"developer","content":"solo"}|});
    (* assistant / tool *)
    ("assistant content emits",
     emits (Msg.assistant ~content:"ok" ()) emit_msg
       {|{"role":"assistant","content":"ok"}|});
    ("assistant name member last",
     emits (Msg.assistant ~name:"bot" ~content:"ok" ()) emit_msg
       {|{"role":"assistant","content":"ok","name":"bot"}|});
    ("assistant all absent rejects",
     rejects (Msg.assistant ())
       "msg: assistant: content or tool_calls required");
    ("assistant name only rejects",
     rejects (Msg.assistant ~name:"a" ())
       "msg: assistant: content or tool_calls required");
    ("assistant empty content rejects",
     rejects (Msg.assistant ~content:"" ())
       "msg: assistant content: empty");
    ("assistant reasoning members emit in the frozen order",
     emits
       (let* d =
          Result.bind
            (J.parse {|{"type":"reasoning.text","text":"t1"}|})
            Msg.reasoning_detail_of_json
        in
        Msg.assistant ~name:"bot" ~content:"ok" ~reasoning_content:"rc"
          ~reasoning_details:[ d ]
          ~thought_signature:(Msg.thought_signature_of_parsed "sig") ())
       emit_msg
       {|{"role":"assistant","content":"ok","name":"bot","reasoning_content":"rc","reasoning_details":[{"type":"reasoning.text","text":"t1"}],"thought_signature":"sig"}|});
    ("assistant member names in frozen order",
     Result.fold
       ~ok:(fun m ->
         Option.fold ~none:false
           ~some:(fun members ->
             List.map fst members
             = [ "role"; "content"; "name"; "reasoning_content";
                 "reasoning_details"; "thought_signature" ])
           (J.as_obj (emit_msg m)))
       ~error:(fun ((_ : E.t)) -> false)
       (let* d =
          Result.bind
            (J.parse {|{"type":"t"}|})
            Msg.reasoning_detail_of_json
        in
        Msg.assistant ~name:"bot" ~content:"ok" ~reasoning_content:"rc"
          ~reasoning_details:[ d ]
          ~thought_signature:(Msg.thought_signature_of_parsed "s") ()));
    ("assistant empty reasoning_details omits the member",
     emits
       (Msg.assistant ~content:"ok" ~reasoning_details:[] ())
       emit_msg
       {|{"role":"assistant","content":"ok"}|});
    ("assistant reasoning members without content rejects",
     rejects
       (Msg.assistant ~reasoning_content:"rc" ())
       "msg: assistant: content or tool_calls required");
    ("reasoning_detail non-object rejects",
     rejects
       (Result.bind (J.parse {|"x"|}) Msg.reasoning_detail_of_json)
       "msg: reasoning_detail: not an object");
    ("reasoning_detail missing type rejects",
     rejects
       (Result.bind (J.parse {|{"text":"t"}|}) Msg.reasoning_detail_of_json)
       "msg: reasoning_detail: type: missing");
    ("reasoning_detail non-string type rejects",
     rejects
       (Result.bind (J.parse {|{"type":1}|}) Msg.reasoning_detail_of_json)
       "msg: reasoning_detail: type: not a string");
    ("reasoning_detail projections",
     Result.fold
       ~ok:(fun d ->
         String.equal (Msg.Reasoning_detail.type_ d) "reasoning.text"
         && Msg.Reasoning_detail.text d = None)
       ~error:(fun ((_ : E.t)) -> false)
       (Result.bind
          (J.parse {|{"type":"reasoning.text"}|})
          Msg.reasoning_detail_of_json));
    ("tool content always bare string",
     emits (Msg.tool ~tool_call_id:"call_1" "42") emit_msg
       {|{"role":"tool","content":"42","tool_call_id":"call_1"}|});
    ("tool name member last",
     emits (Msg.tool ~name:"calc" ~tool_call_id:"call_1" "42") emit_msg
       {|{"role":"tool","content":"42","tool_call_id":"call_1","name":"calc"}|});
    ("tool empty content rejects",
     rejects (Msg.tool ~tool_call_id:"c" "") "msg: tool content: empty");
    (* user *)
    ("user_text collapses to bare string",
     emits (Msg.user_text "hi") Msg.emit_message
       {|{"role":"user","content":"hi"}|});
    ("user_text empty rejects",
     rejects (Msg.user_text "") "msg: user content: empty");
    ("user empty rejects",
     rejects (Msg.user []) "msg: user parts: empty");
    ("user single plain text collapses",
     emits
       (let* a = Msg.text "hi" in
        Msg.user [ Msg.of_text a ])
       Msg.emit_message
       {|{"role":"user","content":"hi"}|});
    ("user single cached text stays array",
     emits
       (let* a = Msg.text ~cache:Msg.Cache.ephemeral "hi" in
        Msg.user [ Msg.of_text a ])
       Msg.emit_message
       {|{"role":"user","content":[{"type":"text","text":"hi","cache_control":{"type":"ephemeral"}}]}|});
    ("user two text parts stay array",
     emits
       (let* a = Msg.text "a" in
        let* b = Msg.text "b" in
        Msg.user [ Msg.of_text a; Msg.of_text b ])
       Msg.emit_message
       {|{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}|});
    ("user file part emits",
     emits
       (let* f =
          Msg.file ~filename:"a.pdf"
            "data:application/pdf;base64,AAA="
        in
        Msg.user [ Msg.of_file f ])
       Msg.emit_message
       {|{"role":"user","content":[{"type":"file","file":{"file_data":"data:application/pdf;base64,AAA=","filename":"a.pdf"}}]}|});
    ("user file cache_control member last",
     emits
       (let* f =
          Msg.file ~cache:Msg.Cache.ephemeral "a:"
        in
        Msg.user [ Msg.of_file f ])
       Msg.emit_message
       {|{"role":"user","content":[{"type":"file","file":{"file_data":"a:"},"cache_control":{"type":"ephemeral"}}]}|});
    ("user name member last",
     emits (Msg.user_text ~name:"u" "hi") Msg.emit_message
       {|{"role":"user","content":"hi","name":"u"}|});
    (* branded media parts *)
    ("image emits",
     on_trimodal
       { g =
           (fun vm ((_ : ('c * M.audio) M.t)) ((_ : ('c * M.video) M.t)) ->
             emits
               (let* img = Msg.image vm ~url:"https://x/i.png" in
                Msg.user [ img ])
               Msg.emit_message
               {|{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/i.png"}}]}|}) });
    ("image cache_control member last",
     on_trimodal
       { g =
           (fun vm ((_ : ('c * M.audio) M.t)) ((_ : ('c * M.video) M.t)) ->
             emits
               (let* img =
                  Msg.image vm ~cache:Msg.Cache.ephemeral
                    ~url:"https://x/i.png"
                in
                Msg.user [ img ])
               Msg.emit_message
               {|{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x/i.png"},"cache_control":{"type":"ephemeral"}}]}|}) });
    ("image bad url rejects",
     on_trimodal
       { g =
           (fun vm ((_ : ('c * M.audio) M.t)) ((_ : ('c * M.video) M.t)) ->
             rejects (Msg.image vm ~url:"nope")
               "msg: image_url.url: not a uri") });
    ("audio emits without format member",
     on_trimodal
       { g =
           (fun ((_ : ('c * M.vision) M.t)) am
                ((_ : ('c * M.video) M.t)) ->
             emits
               (let* aud = Msg.audio am ~data:good_b64 in
                Msg.user [ aud ])
               Msg.emit_message
               {|{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"aGVsbG8="}}]}|}) });
    ("audio emits format member",
     on_trimodal
       { g =
           (fun ((_ : ('c * M.vision) M.t)) am
                ((_ : ('c * M.video) M.t)) ->
             emits
               (let* aud = Msg.audio am ~format:AF.M4a ~data:good_b64 in
                Msg.user [ aud ])
               Msg.emit_message
               {|{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"aGVsbG8=","format":"m4a"}}]}|}) });
    ("audio bad base64 rejects",
     on_trimodal
       { g =
           (fun ((_ : ('c * M.vision) M.t)) am
                ((_ : ('c * M.video) M.t)) ->
             rejects
               (Msg.audio am ~data:"not-b64!")
               "msg: input_audio.data: not base64") });
    ("video emits",
     on_trimodal
       { g =
           (fun ((_ : ('c * M.vision) M.t)) ((_ : ('c * M.audio) M.t))
                dm ->
             emits
               (let* vid = Msg.video dm ~url:"https://x/v.mp4" in
                Msg.user [ vid ])
               Msg.emit_message
               {|{"role":"user","content":[{"type":"video_url","video_url":{"url":"https://x/v.mp4"}}]}|}) });
    ("video bad url rejects",
     on_trimodal
       { g =
           (fun ((_ : ('c * M.vision) M.t)) ((_ : ('c * M.audio) M.t))
                dm ->
             rejects (Msg.video dm ~url:"")
               "msg: video_url.url: not a uri") });
    (* the positive multimodal path via Model.media *)
    ("multimodal user emits all four parts",
     on_trimodal
       { g =
           (fun vm am dm ->
             emits
               (let* cap = Msg.text "caption" in
                let* img = Msg.image vm ~url:"https://x/i.png" in
                let* aud = Msg.audio am ~data:good_b64 in
                let* vid = Msg.video dm ~url:"https://x/v.mp4" in
                Msg.user [ Msg.of_text cap; img; aud; vid ])
               Msg.emit_message
               {|{"role":"user","content":[{"type":"text","text":"caption"},{"type":"image_url","image_url":{"url":"https://x/i.png"}},{"type":"input_audio","input_audio":{"data":"aGVsbG8="}},{"type":"video_url","video_url":{"url":"https://x/v.mp4"}}]}|}) });
    (* unbranded payload reuse across two models in one scope *)
    ("shared payloads serve two models",
     on_model trimodal
       { f =
           (fun m1 ->
             on_model second
               { f =
                   (fun m2 ->
                     Option.fold ~none:false
                       ~some:(fun vm1 ->
                         Option.fold ~none:false
                           ~some:(fun vm2 ->
                             emits_str (send_with vm1 "https://a/1.png")
                               {|[{"role":"system","content":"you are helpful"},{"role":"user","content":[{"type":"text","text":"shared"},{"type":"image_url","image_url":{"url":"https://a/1.png"}}]}]|}
                             && emits_str
                                  (send_with vm2 "https://b/2.png")
                                  {|[{"role":"system","content":"you are helpful"},{"role":"user","content":[{"type":"text","text":"shared"},{"type":"image_url","image_url":{"url":"https://b/2.png"}}]}]|})
                           (M.vision m2))
                       (M.vision m1)) }) });
    (* nonempty + emit *)
    ("nonempty empty rejects",
     rejects (Msg.nonempty []) "msg: messages: empty");
    ("emit two messages",
     emits_str
       (let* s = Msg.system "s" in
        let* u = Msg.user_text "hi" in
        let* msgs = Msg.nonempty [ Msg.lift s; u ] in
        Ok (J.emit (Msg.emit msgs)))
       {|[{"role":"system","content":"s"},{"role":"user","content":"hi"}]|});
    (* seam: content_plaintext *)
    ("plaintext user text", plain (Msg.user_text "hi") (Some "hi"));
    ("plaintext user concat",
     plain
       (let* a = Msg.text "a" in
        let* b = Msg.text "b" in
        Msg.user [ Msg.of_text a; Msg.of_text b ])
       (Some "ab"));
    ("plaintext user with image none",
     on_trimodal
       { g =
           (fun vm ((_ : ('c * M.audio) M.t)) ((_ : ('c * M.video) M.t)) ->
             plain
               (let* a = Msg.text "a" in
                let* img = Msg.image vm ~url:"https://x/i.png" in
                Msg.user [ Msg.of_text a; img ])
               None) });
    ("plaintext system",
     plain (Result.map Msg.lift (Msg.system "s")) (Some "s"));
    ("plaintext system parts concat",
     plain
       (Result.map Msg.lift
          (let* a = Msg.text "a" in
           let* b = Msg.text "b" in
           Msg.system_parts [ a; b ]))
       (Some "ab"));
    ("plaintext developer none",
     plain (Result.map Msg.lift (Msg.developer "d")) None);
    ("plaintext assistant none",
     plain (Result.map Msg.lift (Msg.assistant ~content:"ok" ())) None);
    ("plaintext tool none",
     plain (Result.map Msg.lift (Msg.tool ~tool_call_id:"c" "42")) None);
    (* seam: cipher_hex *)
    ("cipher_hex user emits bare hex",
     emits
       (let* u = Msg.user_text "secret" in
        Msg.cipher_hex u ~hex:"deadbeef")
       Msg.emit_message
       {|{"role":"user","content":"deadbeef"}|});
    ("cipher_hex preserves name",
     emits
       (let* u = Msg.user_text ~name:"u" "secret" in
        Msg.cipher_hex u ~hex:"deadbeef")
       Msg.emit_message
       {|{"role":"user","content":"deadbeef","name":"u"}|});
    ("cipher_hex system role",
     emits
       (let* s = Msg.system "secret" in
        Msg.cipher_hex (Msg.lift s) ~hex:"c0ffee")
       Msg.emit_message
       {|{"role":"system","content":"c0ffee"}|});
    ("cipher_hex replaces prior hex",
     emits
       (let* u = Msg.user_text "secret" in
        let* c1 = Msg.cipher_hex u ~hex:"dead" in
        Msg.cipher_hex c1 ~hex:"beef")
       Msg.emit_message
       {|{"role":"user","content":"beef"}|});
    ("cipher_hex multipart user still bare hex",
     emits
       (let* a = Msg.text "a" in
        let* b = Msg.text "b" in
        let* u = Msg.user [ Msg.of_text a; Msg.of_text b ] in
        Msg.cipher_hex u ~hex:"deadbeef")
       Msg.emit_message
       {|{"role":"user","content":"deadbeef"}|});
    ("cipher_hex developer rejects",
     rejects
       (Result.bind
          (Result.map Msg.lift (Msg.developer "d"))
          (fun m -> Msg.cipher_hex m ~hex:"00"))
       "msg: cipher_hex: developer role");
    ("cipher_hex assistant rejects",
     rejects
       (Result.bind
          (Result.map Msg.lift (Msg.assistant ~content:"ok" ()))
          (fun m -> Msg.cipher_hex m ~hex:"00"))
       "msg: cipher_hex: assistant role");
    ("cipher_hex tool rejects",
     rejects
       (Result.bind
          (Result.map Msg.lift (Msg.tool ~tool_call_id:"c" "42"))
          (fun m -> Msg.cipher_hex m ~hex:"00"))
       "msg: cipher_hex: tool role");
    ("plaintext ciphered none",
     plain
       (let* u = Msg.user_text "secret" in
        Msg.cipher_hex u ~hex:"deadbeef")
       None)
  ]

let () = run checks
