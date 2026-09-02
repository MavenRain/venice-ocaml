(* M6 sampling domain: window-checked newtypes, the typed constraints
   view, and the venice_parameters emitter. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module J = Venice.Json
module M = Venice.Model
module V = Venice.Venice_params

(* Library-internal modules, reached by their wrapped names: the
   sealed Venice signature routes zeros away from compare_mag at
   every public door, so totality over zero is only observable
   here. *)
module P = Venice__Paramsx
module PJ = Venice__Jsonx

let dec ?(neg = false) (m : int) (s : int) : J.dec =
  { J.negative = neg; mantissa = m; scale = s }

(* The internal dec type; the sealed signature hides its equality
   with J.dec. *)
let pdec ?(neg = false) (m : int) (s : int) : PJ.dec =
  { PJ.negative = neg; mantissa = m; scale = s }

let is_ok (r : ('a, Venice.Error.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> true)
    ~error:(fun (_ : Venice.Error.t) -> false)
    r

let is_err (r : ('a, Venice.Error.t) result) : bool = not (is_ok r)

let err_prefix (p : string) (r : ('a, Venice.Error.t) result) : bool =
  Result.fold ~ok:(fun (_ : 'a) -> false)
    ~error:(fun e ->
      Option.fold ~none:false ~some:(String.equal p)
        (Venice.Cursor.take (Venice.Error.to_string e) 0 (String.length p)))
    r

(* The value behind a minted newtype must be the value given. *)
let round_trip (mk : J.dec -> ('t, Venice.Error.t) result)
    (out : 't -> J.dec) (d : J.dec) : bool =
  Result.fold
    ~ok:(fun t ->
      let o = out t in
      o.J.negative = d.J.negative
      && o.J.mantissa = d.J.mantissa
      && o.J.scale = d.J.scale)
    ~error:(fun (_ : Venice.Error.t) -> false)
    (mk d)

(* Constraints access on a single parsed model entry. *)
let constraints_of (s : string) : (Venice.Constraints.t, Venice.Error.t) result
    =
  Result.bind
    (Result.bind (J.parse s) M.of_json)
    (fun p -> match p with M.Pack m -> M.constraints m)

let on_constraints (s : string) (f : Venice.Constraints.t -> bool) : bool =
  Result.fold ~ok:f
    ~error:(fun (_ : Venice.Error.t) -> false)
    (constraints_of s)

let default_is (o : 't option) (out : 't -> J.dec) (d : J.dec) : bool =
  Option.fold ~none:false
    ~some:(fun t ->
      let v = out t in
      v.J.negative = d.J.negative
      && v.J.mantissa = d.J.mantissa
      && v.J.scale = d.J.scale)
    o

(* Fixtures. *)
let spec_constraints : string =
  {|{"id":"e2ee-glm-5","type":"text","model_spec":{"constraints":{"temperature":{"default":0.7},"top_p":{"default":0.9},"repetition_penalty":{"default":1.05}}}}|}

let top_constraints : string =
  {|{"id":"qwen3-4b","type":"text","constraints":{"temperature":{"default":1},"frequency_penalty":{"default":-0.5}}}|}

let no_constraints : string = {|{"id":"flux-dev","type":"image"}|}

let null_param : string =
  {|{"id":"m","type":"text","constraints":{"temperature":null,"top_p":{"default":0.9}}}|}

let extra_keys : string =
  {|{"id":"m","type":"text","constraints":{"steps":{"default":25,"max":50},"temperature":{"default":0.7,"note":"x"}}}|}

let bad_not_obj : string =
  {|{"id":"m","type":"text","constraints":{"temperature":5}}|}

let bad_missing_default : string =
  {|{"id":"m","type":"text","constraints":{"temperature":{}}}|}

let bad_default_string : string =
  {|{"id":"m","type":"text","constraints":{"temperature":{"default":"hot"}}}|}

let bad_default_null : string =
  {|{"id":"m","type":"text","constraints":{"temperature":{"default":null}}}|}

let bad_out_of_window : string =
  {|{"id":"m","type":"text","constraints":{"temperature":{"default":5}}}|}

let boundary_default : string =
  {|{"id":"m","type":"text","constraints":{"temperature":{"default":2},"top_p":{"default":1}}}|}

(* One listing with three malformed parameters (non-object, object
   without default, out-of-window default) next to two readable
   ones. *)
let degrade_mixed : string =
  {|{"id":"m","type":"text","constraints":{"temperature":5,"frequency_penalty":{},"presence_penalty":{"default":9},"top_p":{"default":0.9},"repetition_penalty":{"default":1.05}}}|}

let bad_constraints_value : string =
  {|{"id":"m","type":"text","constraints":5}|}

let checks : (string * bool) list =
  [ (* Temp window: 0 <= t <= 2, exact decimal compare. *)
    ("temp zero ok", is_ok (Venice.Temp.make (dec 0 0)));
    ("temp two ok", is_ok (Venice.Temp.make (dec 2 0)));
    ("temp 2.00 aligned ok", is_ok (Venice.Temp.make (dec 200 2)));
    ("temp 2.0 aligned ok", is_ok (Venice.Temp.make (dec 20 1)));
    ("temp 0.7 ok", is_ok (Venice.Temp.make (dec 7 1)));
    ("temp 1.99999999999999999 ok",
     is_ok (Venice.Temp.make (dec 199999999999999999 17)));
    ("temp 2.01 rejects", is_err (Venice.Temp.make (dec 201 2)));
    ("temp 2.1 rejects", is_err (Venice.Temp.make (dec 21 1)));
    ("temp 3 rejects", is_err (Venice.Temp.make (dec 3 0)));
    ("temp 20 rejects", is_err (Venice.Temp.make (dec 20 0)));
    ("temp -0.1 rejects", is_err (Venice.Temp.make (dec ~neg:true 1 1)));
    ("temp -0.0 is zero", is_ok (Venice.Temp.make (dec ~neg:true 0 1)));
    ("temp round trip", round_trip Venice.Temp.make Venice.Temp.to_dec (dec 15 1));
    ("temp err path",
     err_prefix "param: temperature" (Venice.Temp.make (dec 3 0)));
    (* Canonicality: a hand-built dec outside the parser's shape
       rejects before any comparison. *)
    ("temp negative mantissa rejects",
     is_err (Venice.Temp.make { J.negative = false; mantissa = -1; scale = 0 }));
    ("temp negative scale rejects",
     is_err (Venice.Temp.make { J.negative = false; mantissa = 1; scale = -1 }));
    ("temp scale 19 rejects",
     is_err (Venice.Temp.make { J.negative = false; mantissa = 1; scale = 19 }));
    ("temp 19-digit mantissa rejects",
     is_err
       (Venice.Temp.make
          { J.negative = false; mantissa = 1000000000000000000; scale = 18 }));
    ("temp scale 18 canonical ok",
     is_ok
       (Venice.Temp.make
          { J.negative = false; mantissa = 999999999999999999; scale = 18 }));
    (* Canonical mantissa cap boundary: 18 nines pass, 10^18 (19
       digits) rejects. The repetition window has no upper bound, so
       only canonicality can reject here. *)
    ("canonical 18-nines mantissa ok",
     is_ok (Venice.Repetition_penalty.make (dec 999999999999999999 0)));
    ("canonical 10^18 mantissa rejects",
     is_err (Venice.Repetition_penalty.make (dec 1000000000000000000 0)));
    (* compare_mag is total over zero: a zero mantissa is the least
       magnitude whatever its scale, with no caller pre-routing. *)
    ("compare_mag zero zero", PJ.compare_mag (pdec 0 0) (pdec 0 3) = 0);
    ("compare_mag zero vs padded nonzero",
     PJ.compare_mag (pdec 0 0) (pdec 5 1) = -1);
    ("compare_mag padded nonzero vs zero",
     PJ.compare_mag (pdec 5 1) (pdec 0 0) = 1);
    ("compare_mag zero vs small nonzero",
     PJ.compare_mag (pdec 0 2) (pdec 1 18) = -1);
    ("compare_mag nonzero pair unchanged",
     PJ.compare_mag (pdec 15 1) (pdec 2 0) = -1);
    (* compare_dec stays total on hand-built canonical zeros. *)
    ("compare_dec zero pair", P.compare_dec (pdec 0 5) (pdec ~neg:true 0 0) = 0);
    ("compare_dec zero below positive",
     P.compare_dec (pdec 0 3) (pdec 5 1) = -1);
    ("compare_dec negative below zero",
     P.compare_dec (pdec ~neg:true 5 1) (pdec 0 4) = -1);
    (* Top_p window: 0 <= p <= 1. *)
    ("top_p zero ok", is_ok (Venice.Top_p.make (dec 0 0)));
    ("top_p one ok", is_ok (Venice.Top_p.make (dec 1 0)));
    ("top_p 1.00 aligned ok", is_ok (Venice.Top_p.make (dec 100 2)));
    ("top_p 0.9 ok", is_ok (Venice.Top_p.make (dec 9 1)));
    ("top_p 1.000001 rejects", is_err (Venice.Top_p.make (dec 1000001 6)));
    ("top_p 1.1 rejects", is_err (Venice.Top_p.make (dec 11 1)));
    ("top_p 2 rejects", is_err (Venice.Top_p.make (dec 2 0)));
    ("top_p -0.5 rejects", is_err (Venice.Top_p.make (dec ~neg:true 5 1)));
    ("top_p err path", err_prefix "param: top_p" (Venice.Top_p.make (dec 2 0)));
    (* Penalties: -2 <= v <= 2. *)
    ("freq -2 ok", is_ok (Venice.Frequency_penalty.make (dec ~neg:true 2 0)));
    ("freq -2.00 aligned ok",
     is_ok (Venice.Frequency_penalty.make (dec ~neg:true 200 2)));
    ("freq 2 ok", is_ok (Venice.Frequency_penalty.make (dec 2 0)));
    ("freq 0 ok", is_ok (Venice.Frequency_penalty.make (dec 0 0)));
    ("freq -1.5 ok", is_ok (Venice.Frequency_penalty.make (dec ~neg:true 15 1)));
    ("freq -2.01 rejects",
     is_err (Venice.Frequency_penalty.make (dec ~neg:true 201 2)));
    ("freq -2.5 rejects",
     is_err (Venice.Frequency_penalty.make (dec ~neg:true 25 1)));
    ("freq 2.5 rejects", is_err (Venice.Frequency_penalty.make (dec 25 1)));
    ("freq err path",
     err_prefix "param: frequency_penalty"
       (Venice.Frequency_penalty.make (dec 25 1)));
    ("pres -2 ok", is_ok (Venice.Presence_penalty.make (dec ~neg:true 2 0)));
    ("pres 2 ok", is_ok (Venice.Presence_penalty.make (dec 2 0)));
    ("pres 2.01 rejects", is_err (Venice.Presence_penalty.make (dec 201 2)));
    ("pres -3 rejects", is_err (Venice.Presence_penalty.make (dec ~neg:true 3 0)));
    ("pres err path",
     err_prefix "param: presence_penalty"
       (Venice.Presence_penalty.make (dec ~neg:true 3 0)));
    (* Repetition penalty: v >= 0, no upper bound. *)
    ("rep 0 ok", is_ok (Venice.Repetition_penalty.make (dec 0 0)));
    ("rep 1.05 ok", is_ok (Venice.Repetition_penalty.make (dec 105 2)));
    ("rep 47.25 ok", is_ok (Venice.Repetition_penalty.make (dec 4725 2)));
    ("rep 999999999999999999 ok",
     is_ok (Venice.Repetition_penalty.make (dec 999999999999999999 0)));
    ("rep -0.01 rejects",
     is_err (Venice.Repetition_penalty.make (dec ~neg:true 1 2)));
    ("rep -0 is zero", is_ok (Venice.Repetition_penalty.make (dec ~neg:true 0 0)));
    ("rep err path",
     err_prefix "param: repetition_penalty"
       (Venice.Repetition_penalty.make (dec ~neg:true 1 2)));
    (* Top_k: integer >= 0. *)
    ("top_k 0 ok", is_ok (Venice.Top_k.make 0));
    ("top_k 40 ok", is_ok (Venice.Top_k.make 40));
    ("top_k -1 rejects", is_err (Venice.Top_k.make (-1)));
    ("top_k value",
     Result.fold ~ok:(fun t -> Venice.Top_k.to_int t = 40)
       ~error:(fun (_ : Venice.Error.t) -> false)
       (Venice.Top_k.make 40));
    ("top_k err path", err_prefix "param: top_k" (Venice.Top_k.make (-1)));
    (* Constraints: model_spec location. *)
    ("spec constraints parse", is_ok (constraints_of spec_constraints));
    ("spec temp default 0.7",
     on_constraints spec_constraints (fun c ->
         default_is (Venice.Temp.default c) Venice.Temp.to_dec (dec 7 1)));
    ("spec top_p default 0.9",
     on_constraints spec_constraints (fun c ->
         default_is (Venice.Top_p.default c) Venice.Top_p.to_dec (dec 9 1)));
    ("spec rep default 1.05",
     on_constraints spec_constraints (fun c ->
         default_is
           (Venice.Repetition_penalty.default c)
           Venice.Repetition_penalty.to_dec (dec 105 2)));
    ("spec freq default absent",
     on_constraints spec_constraints (fun c ->
         Option.is_none (Venice.Frequency_penalty.default c)));
    ("spec pres default absent",
     on_constraints spec_constraints (fun c ->
         Option.is_none (Venice.Presence_penalty.default c)));
    (* Constraints: top-level fallback location. *)
    ("top-level constraints parse", is_ok (constraints_of top_constraints));
    ("top-level int default reads as dec",
     on_constraints top_constraints (fun c ->
         default_is (Venice.Temp.default c) Venice.Temp.to_dec (dec 1 0)));
    ("top-level negative default ok",
     on_constraints top_constraints (fun c ->
         default_is
           (Venice.Frequency_penalty.default c)
           Venice.Frequency_penalty.to_dec (dec ~neg:true 5 1)));
    (* Absent, null, and foreign keys. *)
    ("no constraints member: all absent",
     on_constraints no_constraints (fun c ->
         Option.is_none (Venice.Temp.default c)
         && Option.is_none (Venice.Top_p.default c)
         && Option.is_none (Venice.Frequency_penalty.default c)
         && Option.is_none (Venice.Presence_penalty.default c)
         && Option.is_none (Venice.Repetition_penalty.default c)));
    ("null parameter reads absent",
     on_constraints null_param (fun c ->
         Option.is_none (Venice.Temp.default c)
         && default_is (Venice.Top_p.default c) Venice.Top_p.to_dec (dec 9 1)));
    ("foreign keys ignored",
     on_constraints extra_keys (fun c ->
         default_is (Venice.Temp.default c) Venice.Temp.to_dec (dec 7 1)));
    ("boundary defaults ok",
     on_constraints boundary_default (fun c ->
         default_is (Venice.Temp.default c) Venice.Temp.to_dec (dec 2 0)
         && default_is (Venice.Top_p.default c) Venice.Top_p.to_dec (dec 1 0)));
    (* Malformed advertised metadata degrades that parameter to None;
       the view stays Ok. *)
    ("param not an object degrades to None",
     on_constraints bad_not_obj (fun c ->
         Option.is_none (Venice.Temp.default c)));
    ("missing default degrades to None",
     on_constraints bad_missing_default (fun c ->
         Option.is_none (Venice.Temp.default c)));
    ("string default degrades to None",
     on_constraints bad_default_string (fun c ->
         Option.is_none (Venice.Temp.default c)));
    ("null default degrades to None",
     on_constraints bad_default_null (fun c ->
         Option.is_none (Venice.Temp.default c)));
    ("out-of-window default degrades to None",
     on_constraints bad_out_of_window (fun c ->
         Option.is_none (Venice.Temp.default c)));
    (* Malformed parameters degrade one by one; the readable ones in
       the same listing keep their defaults. *)
    ("mixed listing degrades only the malformed params",
     on_constraints degrade_mixed (fun c ->
         Option.is_none (Venice.Temp.default c)
         && Option.is_none (Venice.Frequency_penalty.default c)
         && Option.is_none (Venice.Presence_penalty.default c)
         && default_is (Venice.Top_p.default c) Venice.Top_p.to_dec (dec 9 1)
         && default_is
              (Venice.Repetition_penalty.default c)
              Venice.Repetition_penalty.to_dec (dec 105 2)));
    (* A constraints value that is not an object still rejects the
       entry at parse. *)
    ("constraints not an object rejects",
     is_err (Result.bind (J.parse bad_constraints_value) M.of_json));
    (* A malformed inner parameter does not fail entry parse itself. *)
    ("entry parse survives bad inner param",
     is_ok (Result.bind (J.parse bad_not_obj) M.of_json));
    (* venice_parameters emitter. *)
    ("empty params is_empty", V.is_empty (V.make ()));
    ("empty params emit {}", String.equal "{}" (J.emit (V.to_json (V.make ()))));
    ("one field not empty", not (V.is_empty (V.make ~disable_thinking:true ())));
    ("web search auto",
     String.equal {|{"enable_web_search":"auto"}|}
       (J.emit (V.to_json (V.make ~enable_web_search:V.Auto ()))));
    ("web search off",
     String.equal {|{"enable_web_search":"off"}|}
       (J.emit (V.to_json (V.make ~enable_web_search:V.Off ()))));
    ("web search on",
     String.equal {|{"enable_web_search":"on"}|}
       (J.emit (V.to_json (V.make ~enable_web_search:V.On ()))));
    ("false emits as false, not absent",
     String.equal {|{"include_venice_system_prompt":false}|}
       (J.emit (V.to_json (V.make ~include_venice_system_prompt:false ()))));
    ("full emit in wire order",
     String.equal
       (String.concat ""
          [ {|{"character_slug":"alan-watts",|};
            {|"strip_thinking_response":false,|};
            {|"disable_thinking":true,|};
            {|"enable_web_search":"auto",|};
            {|"enable_web_scraping":false,|};
            {|"enable_web_citations":true,|};
            {|"include_search_results_in_stream":false,|};
            {|"return_search_results_as_documents":true,|};
            {|"include_venice_system_prompt":false,|};
            {|"enable_x_search":true}|} ])
       (J.emit
          (V.to_json
             (V.make ~character_slug:"alan-watts"
                ~strip_thinking_response:false ~disable_thinking:true
                ~enable_web_search:V.Auto ~enable_web_scraping:false
                ~enable_web_citations:true
                ~include_search_results_in_stream:false
                ~return_search_results_as_documents:true
                ~include_venice_system_prompt:false ~enable_x_search:true ()))));
    ("sparse emit keeps relative order",
     String.equal
       {|{"disable_thinking":true,"enable_x_search":false}|}
       (J.emit
          (V.to_json (V.make ~disable_thinking:true ~enable_x_search:false ()))));
    (* Error constructor surface. *)
    ("param error prefix",
     err_prefix "param: " (Venice.Temp.make (dec 3 0))) ]

let (() : unit) = run checks
