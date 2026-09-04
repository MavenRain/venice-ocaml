(* The public face. venice.mli is the only signature that matters to a
   consumer; the x-suffixed units stay behind it. *)

let version = "0.1.0"

module Error = Errx
module Cursor = Bytesx
module Hex = Hexx
module B64 = B64x
module Json = Jsonx
module Constraints = Paramsx.Constraints
module Temp = Paramsx.Temp
module Top_p = Paramsx.Top_p
module Frequency_penalty = Paramsx.Frequency_penalty
module Presence_penalty = Paramsx.Presence_penalty
module Repetition_penalty = Paramsx.Repetition_penalty
module Top_k = Paramsx.Top_k
module Venice_params = Paramsx.Venice_params
module Model = Modelx
module Audio_format = Msgx.Audio_format
module Cache = Msgx.Cache
module Reasoning_detail = Msgx.Reasoning_detail
module Thought_signature = Msgx.Thought_signature
module Tool_call = Msgx.Tool_call
module Msg = Msgx
module Reset_at = Headx.Reset_at
module Reset_after = Headx.Reset_after
module Requests_limit = Headx.Requests_limit
module Tokens_limit = Headx.Tokens_limit
module Limit_type = Headx.Limit_type
module Usd = Headx.Usd
module Diem = Headx.Diem
module Tier = Headx.Tier
module Head = Headx
module Stop = Chatx.Stop
module Effort = Chatx.Effort
module Cache_retention = Chatx.Cache_retention
module Tool = Chatx.Tool
module Chat = Chatx
module Response = Respx

(* M14: the accumulator sits INSIDE the Sse block, because it reads
   nothing but chunks. *)
module Sse = struct
  include Ssex
  module Acc = Accx
end

module Stream = Streamx
module Api_key = Keyx

module Http = struct
  module Endpoint = Httpx.Endpoint
  module Route = Httpx.Route
  module Request = Httpx.Request
  module Wire = Wirex
end

module Transport = struct
  module type S = sig
    type t
    type body

    val send :
      t -> key:Keyx.t -> Httpx.Request.t -> (Wirex.head * body, Errx.t) result

    val read : body -> (string option, Errx.t) result
    val read_all : ?cap:int -> body -> (string, Errx.t) result
    val close : body -> (unit, Errx.t) result
  end

  module Curl = Curlx
  module Fake = Fakex
end

(* M14 drift guard (A6). streamx carries its OWN copy of the
   transport signature, because naming Venice.Transport.S inside
   streamx.ml would make venice depend on a module that depends on
   venice. This functor application compiles ONLY while every
   Transport.S is a Streamx.S, so the day the two signatures part the
   build fails here instead of at a call site. It is applied to no
   argument and emits no code. *)
module _ (T : Streamx.S) = struct
  module _ : Transport.S = T
end
