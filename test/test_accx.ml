(* M14 accumulator: the cross-chunk fold, the caps, the tool_call
   minting and the rendered document. Pure, so every check is a
   value comparison; the effect-handler half is test_streamx.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal modules by their mangled names, exactly as
   test_ssex does. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module A = Venice__Accx
module S = Venice__Ssex
module E = Venice__Errx
module J = Venice__Jsonx
module R = Venice__Respx
module M = Venice__Msgx

(* ---------- JSON fixture helpers ---------- *)

let str (s : string) : string = "\"" ^ s ^ "\""
let m (name : string) (v : string) : string = str name ^ ":" ^ v
let doc (members : string list) : string = "{" ^ String.concat "," members ^ "}"
let arr (items : string list) : string = "[" ^ String.concat "," items ^ "]"

let chunk (extra : string list) : string =
  doc
    ([ m "id" (str "c1");
       m "object" (str "chat.completion.chunk");
       m "created" "7";
       m "model" (str "m")
     ]
    @ extra)

let choice ?(tail : string list = []) (index : int) (delta : string list) :
    string =
  doc ([ m "index" (string_of_int index); m "delta" (doc delta) ] @ tail)

let choices (items : string list) : string = m "choices" (arr items)

let frag ?(id : string option) ?(name : string option)
    ?(arguments : string option) (index : int) : string =
  let fn =
    List.concat
      [ Option.fold ~none:[] ~some:(fun (n : string) -> [ m "name" (str n) ]) name;
        Option.fold ~none:[]
          ~some:(fun (a : string) -> [ m "arguments" (str a) ])
          arguments
      ]
  in
  doc
    (List.concat
       [ [ m "index" (string_of_int index) ];
         Option.fold ~none:[] ~some:(fun (i : string) -> [ m "id" (str i) ]) id;
         [ m "function" (doc fn) ]
       ])

let tools (items : string list) : string = m "tool_calls" (arr items)

let usage_obj : string =
  doc
    [ m "prompt_tokens" "3"; m "completion_tokens" "2"; m "total_tokens" "5" ]

let usage_obj2 : string =
  doc
    [ m "prompt_tokens" "3"; m "completion_tokens" "9"; m "total_tokens" "12" ]

(* ---------- drivers ---------- *)

let fold_chunks (payloads : string list) : (A.t, E.t) result =
  let rec go (a : A.t) (ps : string list) : (A.t, E.t) result =
    match ps with
    | [] -> Ok a
    | p :: tl ->
      Result.bind (S.Chunk.of_string p) (fun (c : S.Chunk.t) ->
          Result.bind (A.step a c) (fun (a2 : A.t) -> go a2 tl))
  in
  go A.empty payloads

let final_of (payloads : string list) : (A.final, E.t) result =
  Result.bind (fold_chunks payloads) A.finish

let err_is (expect : string) (r : ('a, E.t) result) : bool =
  Result.fold
    ~ok:(fun ((_ : 'a)) -> false)
    ~error:(fun (e : E.t) -> String.equal (E.to_string e) expect)
    r

let says (g : A.final -> string) (r : (A.final, E.t) result) : string =
  Result.fold ~ok:g ~error:E.to_string r

let opt (o : string option) : string = Option.value ~default:"<none>" o

let at (i : int) (g : A.Choice.t -> string) (f : A.final) : string =
  Option.fold ~none:"<no choice>" ~some:g (List.nth_opt (A.choices f) i)

let calls (c : A.Choice.t) : string =
  String.concat ";"
    (List.map
       (fun (tc : M.Tool_call.t) ->
         M.Tool_call.id tc ^ "/" ^ M.Tool_call.name tc ^ "/"
         ^ M.Tool_call.arguments tc)
       (A.Choice.tool_calls c))

let rendered (r : (A.final, E.t) result) : string =
  says (fun (f : A.final) -> J.emit (A.to_json f)) r

let response_text (r : (A.final, E.t) result) : string =
  Result.fold
    ~ok:(fun (f : A.final) ->
      Result.fold
        ~ok:(fun (resp : R.t) ->
          R.id resp ^ "|" ^ R.model resp ^ "|"
          ^ string_of_int (R.created resp)
          ^ "|"
          ^ string_of_int (R.Usage.total_tokens (R.usage resp))
          ^ "|"
          ^ Option.fold ~none:"<no choice>"
              ~some:(fun (c : R.Choice.t) ->
                string_of_int (R.Choice.index c)
                ^ "/"
                ^ opt (R.Choice.content c)
                ^ "/"
                ^ R.Finish.to_string (R.Choice.finish c))
              (List.nth_opt (R.choices resp) 0))
        ~error:E.to_string (A.to_response f))
    ~error:E.to_string r

(* ---------- fixtures ---------- *)

let c_head : string =
  chunk
    [ choices
        [ choice 0 [ m "role" (str "assistant"); m "content" (str "Hel") ] ]
    ]

let c_mid : string = chunk [ choices [ choice 0 [ m "content" (str "lo") ] ] ]

let c_tail : string =
  chunk
    [ choices [ choice ~tail:[ m "finish_reason" (str "stop") ] 0 [] ];
      m "usage" usage_obj
    ]

let three : string list = [ c_head; c_mid; c_tail ]

(* The rendered document, byte for byte (D8, A15): the accumulated
   role, the joined content, the raw finish_reason, then usage, then
   venice_parameters LAST. *)
let golden : string =
  doc
    [ m "id" (str "c1");
      m "object" (str "chat.completion");
      m "created" "7";
      m "model" (str "m");
      m "choices"
        (arr
           [ doc
               [ m "index" "0";
                 m "message"
                   (doc
                      [ m "role" (str "assistant"); m "content" (str "Hello") ]);
                 m "finish_reason" (str "stop")
               ]
           ]);
      m "usage" usage_obj
    ]

(* The same conversation as ONE non-streaming document. *)
let equivalent : string =
  doc
    [ m "id" (str "c1");
      m "object" (str "chat.completion");
      m "created" "7";
      m "model" (str "m");
      m "choices"
        (arr
           [ doc
               [ m "index" "0";
                 m "message"
                   (doc
                      [ m "role" (str "assistant"); m "content" (str "Hello") ]);
                 m "finish_reason" (str "stop")
               ]
           ]);
      m "usage" usage_obj
    ]

let equivalent_text : string =
  Result.fold
    ~ok:(fun (resp : R.t) ->
      R.id resp ^ "|" ^ R.model resp ^ "|"
      ^ string_of_int (R.created resp)
      ^ "|"
      ^ string_of_int (R.Usage.total_tokens (R.usage resp))
      ^ "|"
      ^ Option.fold ~none:"<no choice>"
          ~some:(fun (c : R.Choice.t) ->
            string_of_int (R.Choice.index c)
            ^ "/"
            ^ opt (R.Choice.content c)
            ^ "/"
            ^ R.Finish.to_string (R.Choice.finish c))
          (List.nth_opt (R.choices resp) 0))
    ~error:E.to_string (R.of_string equivalent)

let many_choices (n : int) : string =
  chunk [ choices (List.init n (fun (i : int) -> choice i [])) ]

let many_frags (n : int) : string =
  chunk
    [ choices
        [ choice 0
            [ tools
                (List.init n (fun (i : int) ->
                     frag ~id:"t" ~name:"n" ~arguments:"{}" i))
            ]
        ]
    ]

(* ---------- checks ---------- *)

let ledger_checks : (string * bool) list =
  [ ("empty: chunks reads 0", Int.equal (A.chunks A.empty) 0);
    ( "empty: finish rejects with no chunks",
      err_is "stream: no chunks" (A.finish A.empty) );
    ( "chunks: counts every folded chunk",
      String.equal
        (Result.fold
           ~ok:(fun (a : A.t) -> string_of_int (A.chunks a))
           ~error:E.to_string (fold_chunks three))
        "3" );
    ( "id: first-wins over a repeated id",
      String.equal (says A.id (final_of three)) "c1" );
    ( "id: a changed id rejects",
      err_is "stream: id changed"
        (fold_chunks
           [ c_head;
             doc
               [ m "id" (str "c2");
                 m "object" (str "chat.completion.chunk");
                 m "created" "7";
                 m "model" (str "m")
               ]
           ]) );
    ( "model: a changed model rejects",
      err_is "stream: model changed"
        (fold_chunks
           [ c_head;
             doc
               [ m "id" (str "c1");
                 m "object" (str "chat.completion.chunk");
                 m "created" "7";
                 m "model" (str "other")
               ]
           ]) );
    ( "created: a changed created rejects",
      err_is "stream: created changed"
        (fold_chunks
           [ c_head;
             doc
               [ m "id" (str "c1");
                 m "object" (str "chat.completion.chunk");
                 m "created" "8";
                 m "model" (str "m")
               ]
           ]) );
    ( "model and created project from the fold",
      String.equal
        (says
           (fun (f : A.final) ->
             A.model f ^ "/" ^ string_of_int (A.created f))
           (final_of three))
        "m/7" );
    ( "step is all-or-nothing: a rejected chunk leaves the old fold",
      String.equal
        (Result.fold
           ~ok:(fun (a : A.t) ->
             Result.fold
               ~ok:(fun (c : S.Chunk.t) ->
                 Result.fold
                   ~ok:(fun ((_ : A.t)) -> "accepted")
                   ~error:(fun ((_ : E.t)) ->
                     "rejected/" ^ string_of_int (A.chunks a))
                   (A.step a c))
               ~error:E.to_string
               (S.Chunk.of_string
                  (doc
                     [ m "id" (str "c2");
                       m "object" (str "chat.completion.chunk");
                       m "created" "7";
                       m "model" (str "m")
                     ])))
           ~error:E.to_string (fold_chunks [ c_head ]))
        "rejected/1" )
  ]

let piece_checks : (string * bool) list =
  [ ( "content: pieces join once, in received order",
      String.equal
        (says (at 0 (fun (c : A.Choice.t) -> opt (A.Choice.content c)))
           (final_of three))
        "Hello" );
    ( "content: a stream that never sent content reads None",
      String.equal
        (says (at 0 (fun (c : A.Choice.t) -> opt (A.Choice.content c)))
           (final_of
              [ chunk
                  [ choices
                      [ choice ~tail:[ m "finish_reason" (str "stop") ] 0 [] ]
                  ]
              ]))
        "<none>" );
    ( "content: a null piece is skipped, not joined",
      String.equal
        (says (at 0 (fun (c : A.Choice.t) -> opt (A.Choice.content c)))
           (final_of
              [ chunk [ choices [ choice 0 [ m "content" "null" ] ] ];
                chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "content" (str "x") ]
                      ]
                  ]
              ]))
        "x" );
    ( "content: an empty piece is kept, so \"\" reads Some",
      String.equal
        (says (at 0 (fun (c : A.Choice.t) -> opt (A.Choice.content c)))
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "content" (str "") ]
                      ]
                  ]
              ]))
        "" );
    ( "reasoning_content: pieces join once, in received order",
      String.equal
        (says
           (at 0 (fun (c : A.Choice.t) -> opt (A.Choice.reasoning_content c)))
           (final_of
              [ chunk
                  [ choices [ choice 0 [ m "reasoning_content" (str "th") ] ] ];
                chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "reasoning_content" (str "ink") ]
                      ]
                  ]
              ]))
        "think" );
    ( "role: first-wins across the stream",
      String.equal
        (says (at 0 (fun (c : A.Choice.t) -> opt (A.Choice.role c)))
           (final_of three))
        "assistant" );
    ( "role: a changed role rejects",
      err_is "stream: choices[0].delta.role changed"
        (fold_chunks
           [ c_head; chunk [ choices [ choice 0 [ m "role" (str "system") ] ] ]
           ]) );
    ( "usage: last-wins across two usage-bearing chunks",
      String.equal
        (says
           (fun (f : A.final) ->
             Option.fold ~none:"<none>"
               ~some:(fun (u : R.Usage.t) ->
                 string_of_int (R.Usage.total_tokens u))
               (A.usage_opt f))
           (final_of
              [ c_head;
                chunk [ m "usage" usage_obj ];
                chunk
                  [ choices
                      [ choice ~tail:[ m "finish_reason" (str "stop") ] 0 [] ];
                    m "usage" usage_obj2
                  ]
              ]))
        "12" );
    ( "usage: a stream with no usage member reads None",
      String.equal
        (says
           (fun (f : A.final) ->
             Option.fold ~none:"<none>"
               ~some:(fun (u : R.Usage.t) ->
                 string_of_int (R.Usage.total_tokens u))
               (A.usage_opt f))
           (final_of
              [ chunk
                  [ choices
                      [ choice ~tail:[ m "finish_reason" (str "stop") ] 0 [] ]
                  ]
              ]))
        "<none>" );
    ( "venice_parameters: first-wins and rides raw",
      String.equal
        (says
           (fun (f : A.final) ->
             Option.fold ~none:"<none>" ~some:J.emit
               (A.venice_parameters_raw f))
           (final_of
              [ chunk
                  [ choices [ choice 0 [] ];
                    m "venice_parameters" (doc [ m "a" "1" ])
                  ];
                chunk
                  [ choices
                      [ choice ~tail:[ m "finish_reason" (str "stop") ] 0 [] ];
                    m "venice_parameters" (doc [ m "a" "2" ])
                  ]
              ]))
        (doc [ m "a" "1" ]) )
  ]

let finish_checks : (string * bool) list =
  [ ( "finish_reason: required on every choice at finish",
      err_is "stream: choices[0].finish_reason missing"
        (final_of [ c_head ]) );
    ( "finish_reason: the raw wire string survives",
      String.equal
        (says (at 0 A.Choice.finish_raw) (final_of three))
        "stop" );
    ( "finish_reason: the typed view reads the closed enum",
      String.equal
        (says
           (at 0 (fun (c : A.Choice.t) ->
                Result.fold ~ok:R.Finish.to_string ~error:E.to_string
                  (A.Choice.finish c)))
           (final_of three))
        "stop" );
    ( "finish_reason: a foreign value keeps finish_raw readable",
      String.equal
        (says (at 0 A.Choice.finish_raw)
           (final_of
              [ chunk
                  [ choices
                      [ choice ~tail:[ m "finish_reason" (str "halted") ] 0 [] ]
                  ]
              ]))
        "halted" );
    ( "finish_reason: a foreign value fails the VIEW alone",
      String.equal
        (says
           (at 0 (fun (c : A.Choice.t) ->
                Result.fold ~ok:R.Finish.to_string ~error:E.to_string
                  (A.Choice.finish c)))
           (final_of
              [ chunk
                  [ choices
                      [ choice ~tail:[ m "finish_reason" (str "halted") ] 0 [] ]
                  ]
              ]))
        "stream: choices[0].finish_reason: unknown value halted" );
    ( "finish_reason: a non-string rejects the fold",
      err_is "stream: choices[0].finish_reason: not a string"
        (fold_chunks
           [ chunk [ choices [ choice ~tail:[ m "finish_reason" "7" ] 0 [] ] ] ])
    );
    ( "finish_reason: a changed value rejects",
      err_is "stream: choices[0].finish_reason changed"
        (fold_chunks
           [ chunk
               [ choices
                   [ choice ~tail:[ m "finish_reason" (str "stop") ] 0 [] ]
               ];
             chunk
               [ choices
                   [ choice ~tail:[ m "finish_reason" (str "length") ] 0 [] ]
               ]
           ]) );
    ( "stop_reason: absent reads None in both views",
      String.equal
        (says
           (at 0 (fun (c : A.Choice.t) ->
                opt (A.Choice.stop_reason_raw c)
                ^ "/"
                ^ Result.fold
                    ~ok:(fun (o : R.Stop_reason.t option) ->
                      Option.fold ~none:"<none>" ~some:R.Stop_reason.to_string o)
                    ~error:E.to_string (A.Choice.stop_reason c)))
           (final_of three))
        "<none>/<none>" );
    ( "stop_reason: the typed view reads the closed enum",
      String.equal
        (says
           (at 0 (fun (c : A.Choice.t) ->
                Result.fold
                  ~ok:(fun (o : R.Stop_reason.t option) ->
                    Option.fold ~none:"<none>" ~some:R.Stop_reason.to_string o)
                  ~error:E.to_string (A.Choice.stop_reason c)))
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:
                            [ m "finish_reason" (str "stop");
                              m "stop_reason" (str "length")
                            ]
                          0 []
                      ]
                  ]
              ]))
        "length" )
  ]

let tool_checks : (string * bool) list =
  [ ( "tool_call: one fragment mints one call",
      String.equal
        (says (at 0 calls)
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "tool_calls") ]
                          0
                          [ tools
                              [ frag ~id:"t1" ~name:"lookup"
                                  ~arguments:"{\\\"q\\\":1}" 0
                              ]
                          ]
                      ]
                  ]
              ]))
        "t1/lookup/{\"q\":1}" );
    ( "tool_call: argument pieces join in received order",
      String.equal
        (says (at 0 calls)
           (final_of
              [ chunk
                  [ choices
                      [ choice 0
                          [ tools [ frag ~id:"t1" ~name:"f" ~arguments:"{a" 0 ] ]
                      ]
                  ];
                chunk
                  [ choices
                      [ choice 0 [ tools [ frag ~arguments:"bc" 0 ] ] ]
                  ];
                chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "tool_calls") ]
                          0
                          [ tools [ frag ~arguments:"}" 0 ] ]
                      ]
                  ]
              ]))
        "t1/f/{abc}" );
    ( "tool_call: a fragment with no id and no open call rejects",
      err_is "stream: choices[0].tool_calls[3]: continuation with no open call"
        (fold_chunks
           [ chunk
               [ choices [ choice 0 [ tools [ frag ~arguments:"x" 3 ] ] ] ]
           ]) );
    ( "tool_call: a changed id rejects",
      err_is "stream: choices[0].tool_calls[0]: id changed"
        (fold_chunks
           [ chunk
               [ choices
                   [ choice 0 [ tools [ frag ~id:"t1" ~name:"f" 0 ] ] ]
               ];
             chunk
               [ choices [ choice 0 [ tools [ frag ~id:"t2" 0 ] ] ] ]
           ]) );
    ( "tool_call: a call with no name rejects at finish",
      err_is "stream: choices[0].tool_calls[0].function.name missing"
        (final_of
           [ chunk
               [ choices
                   [ choice
                       ~tail:[ m "finish_reason" (str "tool_calls") ]
                       0
                       [ tools [ frag ~id:"t1" ~arguments:"{}" 0 ] ]
                   ]
               ]
           ]) );
    ( "tool_call: the name is first-wins",
      String.equal
        (says (at 0 calls)
           (final_of
              [ chunk
                  [ choices
                      [ choice 0 [ tools [ frag ~id:"t1" ~name:"first" 0 ] ] ]
                  ];
                chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "tool_calls") ]
                          0
                          [ tools [ frag ~name:"second" 0 ] ]
                      ]
                  ]
              ]))
        "t1/first/" );
    ( "tool_call: sparse fragment indices are legal (A10)",
      String.equal
        (says (at 0 calls)
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "tool_calls") ]
                          0
                          [ tools
                              [ frag ~id:"a" ~name:"one" ~arguments:"1" 0;
                                frag ~id:"b" ~name:"two" ~arguments:"2" 7
                              ]
                          ]
                      ]
                  ]
              ]))
        "a/one/1;b/two/2" );
    ( "tool_call: calls mint in ascending wire-index order",
      String.equal
        (says (at 0 calls)
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "tool_calls") ]
                          0
                          [ tools
                              [ frag ~id:"b" ~name:"two" ~arguments:"2" 5;
                                frag ~id:"a" ~name:"one" ~arguments:"1" 2
                              ]
                          ]
                      ]
                  ]
              ]))
        "a/one/1;b/two/2" );
    ( "tool_call: a malformed item fails the fragment view",
      Result.is_error
        (fold_chunks
           [ chunk [ choices [ choice 0 [ m "tool_calls" (arr [ "7" ]) ] ] ] ])
    )
  ]

let multi_checks : (string * bool) list =
  [ ( "choices: two indices accumulate apart",
      String.equal
        (says
           (fun (f : A.final) ->
             String.concat ";"
               (List.map
                  (fun (c : A.Choice.t) ->
                    string_of_int (A.Choice.index c)
                    ^ ":"
                    ^ opt (A.Choice.content c))
                  (A.choices f)))
           (final_of
              [ chunk
                  [ choices
                      [ choice 0 [ m "content" (str "a") ];
                        choice 1 [ m "content" (str "b") ]
                      ]
                  ];
                chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "content" (str "a2") ];
                        choice
                          ~tail:[ m "finish_reason" (str "length") ]
                          1
                          [ m "content" (str "b2") ]
                      ]
                  ]
              ]))
        "0:aa2;1:bb2" );
    ( "choices: finish orders by wire index, not by arrival",
      String.equal
        (says
           (fun (f : A.final) ->
             String.concat ";"
               (List.map
                  (fun (c : A.Choice.t) -> string_of_int (A.Choice.index c))
                  (A.choices f)))
           (final_of
              [ chunk
                  [ choices
                      [ choice ~tail:[ m "finish_reason" (str "stop") ] 2 [];
                        choice ~tail:[ m "finish_reason" (str "stop") ] 0 []
                      ]
                  ]
              ]))
        "0;2" );
    ( "cap: 128 distinct choice indices accept",
      Result.is_ok (fold_chunks [ many_choices 128 ]) );
    ( "cap: 129 distinct choice indices reject",
      err_is "stream: too many choices" (fold_chunks [ many_choices 129 ]) );
    ( "cap: 64 distinct fragment indices in one choice accept",
      Result.is_ok (fold_chunks [ many_frags 64 ]) );
    ( "cap: 65 distinct fragment indices in one choice reject",
      err_is "stream: choices[0].tool_calls[64]: too many tool_calls"
        (fold_chunks [ many_frags 65 ]) );
    ( "cap: a single choice at index 200 round-trips through to_response",
      String.equal
        (response_text
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          200
                          [ m "role" (str "assistant"); m "content" (str "x") ]
                      ];
                    m "usage" usage_obj
                  ]
              ]))
        "c1|m|7|5|200/x/stop" )
  ]

let render_checks : (string * bool) list =
  [ ( "to_response: the rendered document is byte-exact",
      String.equal (rendered (final_of three)) golden );
    ( "to_response: equal by projection to the non-streaming document",
      String.equal (response_text (final_of three)) equivalent_text );
    ( "to_response: the equivalent document reads what the fold read",
      String.equal equivalent_text "c1|m|7|5|0/Hello/stop" );
    ( "to_response: venice_parameters renders LAST, after usage (A15)",
      String.equal
        (rendered
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "role" (str "assistant"); m "content" (str "x") ]
                      ];
                    m "usage" usage_obj;
                    m "venice_parameters" (doc [ m "a" "1" ])
                  ]
              ]))
        (doc
           [ m "id" (str "c1");
             m "object" (str "chat.completion");
             m "created" "7";
             m "model" (str "m");
             m "choices"
               (arr
                  [ doc
                      [ m "index" "0";
                        m "message"
                          (doc
                             [ m "role" (str "assistant");
                               m "content" (str "x")
                             ]);
                        m "finish_reason" (str "stop")
                      ]
                  ]);
             m "usage" usage_obj;
             m "venice_parameters" (doc [ m "a" "1" ])
           ]) );
    ( "to_response: the accumulated role is emitted, not a default (A7)",
      String.equal
        (rendered
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "role" (str "system"); m "content" (str "x") ]
                      ]
                  ]
              ]))
        (doc
           [ m "id" (str "c1");
             m "object" (str "chat.completion");
             m "created" "7";
             m "model" (str "m");
             m "choices"
               (arr
                  [ doc
                      [ m "index" "0";
                        m "message"
                          (doc
                             [ m "role" (str "system"); m "content" (str "x") ]);
                        m "finish_reason" (str "stop")
                      ]
                  ])
           ]) );
    ( "to_response: a stream with no role renders the assistant default",
      String.equal
        (rendered
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "content" (str "x") ]
                      ]
                  ]
              ]))
        (doc
           [ m "id" (str "c1");
             m "object" (str "chat.completion");
             m "created" "7";
             m "model" (str "m");
             m "choices"
               (arr
                  [ doc
                      [ m "index" "0";
                        m "message"
                          (doc
                             [ m "role" (str "assistant");
                               m "content" (str "x")
                             ]);
                        m "finish_reason" (str "stop")
                      ]
                  ])
           ]) );
    ( "to_response: a foreign finish_reason returns the respx text verbatim",
      String.equal
        (response_text
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "halted") ]
                          0
                          [ m "role" (str "assistant"); m "content" (str "x") ]
                      ];
                    m "usage" usage_obj
                  ]
              ]))
        "resp: choices[0].finish_reason: unknown value halted" );
    ( "to_response: a foreign role rejects through respx",
      String.equal
        (response_text
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "role" (str "system"); m "content" (str "x") ]
                      ];
                    m "usage" usage_obj
                  ]
              ]))
        "resp: choices[0].message.role: unsupported role system" );
    ( "to_response: a stream with no usage rejects through respx",
      Result.is_error
        (Result.bind (final_of [ c_head; c_mid ]) (fun (f : A.final) ->
             Result.map (fun ((_ : R.t)) -> ()) (A.to_response f))) );
    ( "to_response: content \"\" renders and re-parses as Some \"\"",
      String.equal
        (response_text
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "role" (str "assistant"); m "content" (str "") ]
                      ];
                    m "usage" usage_obj
                  ]
              ]))
        "c1|m|7|5|0//stop" );
    ( "to_response: reasoning_content renders and re-parses",
      String.equal
        (Result.fold
           ~ok:(fun (f : A.final) ->
             Result.fold
               ~ok:(fun (resp : R.t) ->
                 Option.fold ~none:"<no choice>"
                   ~some:(fun (c : R.Choice.t) ->
                     opt (R.Choice.reasoning_content c))
                   (List.nth_opt (R.choices resp) 0))
               ~error:E.to_string (A.to_response f))
           ~error:E.to_string
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "stop") ]
                          0
                          [ m "role" (str "assistant");
                            m "content" (str "x");
                            m "reasoning_content" (str "why")
                          ]
                      ];
                    m "usage" usage_obj
                  ]
              ]))
        "why" );
    ( "to_response: tool_calls render and re-parse through the strict mint",
      String.equal
        (Result.fold
           ~ok:(fun (f : A.final) ->
             Result.fold
               ~ok:(fun (resp : R.t) ->
                 Option.fold ~none:"<no choice>"
                   ~some:(fun (c : R.Choice.t) ->
                     Result.fold
                       ~ok:(fun (cs : M.Tool_call.t list) ->
                         String.concat ";"
                           (List.map
                              (fun (tc : M.Tool_call.t) ->
                                M.Tool_call.id tc ^ "/" ^ M.Tool_call.name tc
                                ^ "/" ^ M.Tool_call.arguments tc)
                              cs))
                       ~error:E.to_string (R.Choice.tool_calls c))
                   (List.nth_opt (R.choices resp) 0))
               ~error:E.to_string (A.to_response f))
           ~error:E.to_string
           (final_of
              [ chunk
                  [ choices
                      [ choice
                          ~tail:[ m "finish_reason" (str "tool_calls") ]
                          0
                          [ m "role" (str "assistant");
                            tools
                              [ frag ~id:"t1" ~name:"f" ~arguments:"{}" 0 ]
                          ]
                      ];
                    m "usage" usage_obj
                  ]
              ]))
        "t1/f/{}" );
    ( "to_response: usage renders the server's own bytes (A2)",
      String.equal
        (says
           (fun (f : A.final) ->
             Option.fold ~none:"<none>" ~some:J.emit (A.usage_raw f))
           (final_of three))
        usage_obj )
  ]

let () =
  run
    (List.concat
       [ ledger_checks;
         piece_checks;
         finish_checks;
         tool_checks;
         multi_checks;
         render_checks
       ])
