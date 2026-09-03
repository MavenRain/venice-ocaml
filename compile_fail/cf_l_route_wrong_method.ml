(* Battery case l (M13): the route method is a phantom index, not a
   run-time check. chat_completions is a `post Route.t` and
   Request.get demands a `get Route.t`, so a GET on the chat route
   fails to typecheck. There is no run-time rejection to test. *)

let bad : (Venice.Http.Request.t, Venice.Error.t) result =
  Venice.Http.Request.get Venice.Http.Route.chat_completions
