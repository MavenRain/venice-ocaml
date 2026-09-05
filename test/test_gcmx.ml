(* M21 gcmx: AES-256-GCM of SP 800-38D, seal and unseal, through the
   PUBLIC surface only.  The GHASH field element, the 128-step masked
   multiplication, the blocking fold and the CTR pass are reached by the
   entry points that use them: every seal row walks the schedule, H, the
   counter blocks and the whole GHASH, the empty-message rows walk GMAC
   over the AAD alone, the 17-byte and longer rows walk a second
   keystream block, and the aad-length rows walk the partial-block pad
   the fill guard emits.

   Every hex constant below is recomputed by harness/diff_gcm.py from
   the INPUTS this file names, by an AES-256-GCM that shares no formula
   with the OCaml unit: the harness runs GHASH over ONE python integer
   with the 0xe1 reduction, while this unit runs it over a pair of Int64
   halves with masked selects.  That harness re-verifies every embedded
   Wycheproof vector, valid and modified, and it SEALS its own generated
   vector before it reads a pin, so a python bug cannot certify an OCaml
   bug.  It also requires each constant to sit inside a CHECK ROW of
   this file, not merely somewhere in it, and it strips the row LABEL
   before it searches, so a pin moved into a comment, into an unread let
   or into a row name turns the gate RED.  Every pin therefore sits
   INLINE in the boolean of its own row.

   The vectors are a subset of the Wycheproof AES-GCM corpus resolved by
   tcId, 21 valid rows, 10 ModifiedTag rows and 5 rows this surface
   rejects on a key or an iv LENGTH alone, plus the four GCM
   specification cases 13 to 16 and the vector the oracle GENERATES at
   gate time from a key, a nonce, an aad and a plaintext that only this
   milestone holds.  Every one of the 36 Wycheproof rows carries its
   tcId in its comment.  Only tcId 315 is a corpus row of result
   "invalid" among the five rejects: tcId 1, 176, 240 and 299 are VALID
   vectors of their own groups, and this unit refuses them on a length
   alone.

   ONE behaviour has no check row and the design brief records it as a
   residual: the max_len () REJECT itself cannot be exercised, because a
   plaintext above 68719476704 bytes is 64 GiB and this host cannot
   allocate it.  The cap is pinned by its VALUE row alone.

   The run filter below carries TWO typed wildcards: (_ : string) in the
   filter and (_ : bool) in the printer.  No bare wildcard arm appears
   anywhere in this file.

   The internal seams live behind venice.mli, so this suite binds the
   library-internal module by its mangled name, exactly as test_limbsx,
   test_hmacx, test_keccakx, test_p256x and test_secpx do. *)

let run (checks : (string * bool) list) : unit =
  let bad = List.filter (fun ((_ : string), ok) -> not ok) checks in
  List.iter (fun (n, (_ : bool)) -> print_endline ("FAIL " ^ n)) bad;
  Printf.printf "%d/%d ok\n"
    (List.length checks - List.length bad)
    (List.length checks);
  exit (match bad with [] -> 0 | (_, _) :: _ -> 1)

module G = Venice__Gcmx
module Hx = Venice__Hexx
module B = Venice__Bytesx

(* ---------- readers ---------- *)

(* A strict hex reader: a byte outside the alphabet or an odd length
   gives the empty string, which every length test below rejects. *)
let bytes_of_hex (h : string) : string =
  Option.value ~default:"" (Result.to_option (Hx.decode h))

(* n zero bytes, for the wrong-length rows.  of_codes is total. *)
let zeros (n : int) : string = B.of_codes (List.init n (fun (_ : int) -> 0))

(* The sealed pair as lowercase hex.  The empty PAIR arrives when any
   surface refuses, and no pinned tag is empty, so a refusal can never
   be read as a match. *)
let seal_hex ~(key : string) ~(iv : string) ~(aad : string) ~(msg : string) :
    string * string =
  Option.value ~default:("", "")
    (Option.bind (G.Key.of_bytes (bytes_of_hex key)) (fun (k : G.Key.t) ->
         Option.bind (G.Nonce.of_bytes (bytes_of_hex iv))
           (fun (n : G.Nonce.t) ->
             Option.map
               (fun ((ct : string), (t : G.Tag.t)) ->
                 (Hx.encode ct, Hx.encode (G.Tag.to_bytes t)))
               (G.seal k n ~aad:(bytes_of_hex aad) (bytes_of_hex msg)))))

let seals ~(key : string) ~(iv : string) ~(aad : string) ~(msg : string)
    ~(ct : string) ~(tag : string) : bool =
  let ((got_ct : string), (got_tag : string)) = seal_hex ~key ~iv ~aad ~msg in
  String.equal got_ct ct && String.equal got_tag tag

let unseal_hex ~(key : string) ~(iv : string) ~(aad : string) ~(ct : string)
    ~(tag : string) : string option =
  Option.bind (G.Key.of_bytes (bytes_of_hex key)) (fun (k : G.Key.t) ->
      Option.bind (G.Nonce.of_bytes (bytes_of_hex iv)) (fun (n : G.Nonce.t) ->
          Option.bind (G.Tag.of_bytes (bytes_of_hex tag)) (fun (t : G.Tag.t) ->
              G.unseal k n ~aad:(bytes_of_hex aad) (bytes_of_hex ct) t)))

let unseals ~(key : string) ~(iv : string) ~(aad : string) ~(ct : string)
    ~(tag : string) ~(msg : string) : bool =
  Option.fold ~none:false
    ~some:(fun (p : string) -> String.equal (Hx.encode p) msg)
    (unseal_hex ~key ~iv ~aad ~ct ~tag)

let unseal_none ~(key : string) ~(iv : string) ~(aad : string) ~(ct : string)
    ~(tag : string) : bool =
  Option.is_none (unseal_hex ~key ~iv ~aad ~ct ~tag)

let nonce_round_trip (h : string) : bool =
  Option.fold ~none:false
    ~some:(fun (n : G.Nonce.t) ->
      String.equal (Hx.encode (G.Nonce.to_bytes n)) h)
    (G.Nonce.of_bytes (bytes_of_hex h))

let tag_round_trip (h : string) : bool =
  Option.fold ~none:false
    ~some:(fun (t : G.Tag.t) -> String.equal (Hx.encode (G.Tag.to_bytes t)) h)
    (G.Tag.of_bytes (bytes_of_hex h))

let tags_equal (a : string) (b : string) : bool =
  Option.fold ~none:false
    ~some:(fun (x : G.Tag.t) ->
      Option.fold ~none:false
        ~some:(fun (y : G.Tag.t) -> G.Tag.equal_ct x y)
        (G.Tag.of_bytes (bytes_of_hex b)))
    (G.Tag.of_bytes (bytes_of_hex a))

(* ---------- group (a): the construction lengths ---------- *)

let construction_checks : (string * bool) list =
  [ ("gcmx: a 31-byte key is None", Option.is_none (G.Key.of_bytes (zeros 31)));
    ("gcmx: a 33-byte key is None", Option.is_none (G.Key.of_bytes (zeros 33)));
    ( "gcmx: a 32-byte key is Some",
      Option.is_some (G.Key.of_bytes (zeros 32)) );
    ( "gcmx: an 11-byte nonce is None",
      Option.is_none (G.Nonce.of_bytes (zeros 11)) );
    ( "gcmx: a 13-byte nonce is None",
      Option.is_none (G.Nonce.of_bytes (zeros 13)) );
    ( "gcmx: a 12-byte nonce is Some",
      Option.is_some (G.Nonce.of_bytes (zeros 12)) );
    ( "gcmx: a nonce round trips through to_bytes",
      nonce_round_trip "d541ece33e951f0bdc43e2fd" );
    ( "gcmx: a 15-byte tag is None",
      Option.is_none (G.Tag.of_bytes (zeros 15)) );
    ( "gcmx: a 17-byte tag is None",
      Option.is_none (G.Tag.of_bytes (zeros 17)) );
    ( "gcmx: a 16-byte tag is Some",
      Option.is_some (G.Tag.of_bytes (zeros 16)) );
    ( "gcmx: a tag round trips through to_bytes",
      tag_round_trip "7a100e3479380bcaa05b779ba56d3999" );
    ( "gcmx: equal_ct is true on one tag against itself",
      tags_equal "c520c21755347c7154ca373f610140f9" "c520c21755347c7154ca373f610140f9" );
    ( "gcmx: equal_ct is false on two tags that differ",
      not (tags_equal "c520c21755347c7154ca373f610140f9" "c520c21755347c7154ca373f610140f8") )
  ]

(* ---------- group (b): the 21 valid Wycheproof rows ---------- *)

let wycheproof_valid_checks : (string * bool) list =
  (* tcId 91: Ktv;  msg 10 bytes, aad 8 bytes, result valid. *)
  [ ( "gcmx: tcId 91 seals to its ciphertext and tag",
      seals
      ~key:"92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20"
      ~iv:"00112233445566778899aabb"
      ~aad:"00000000ffffffff"
      ~msg:"00010203040506070809"
      ~ct:"e27abdd2d2a53d2f136b"
      ~tag:"9a4a2579529301bcfb71c78d4060f52c" );
    ( "gcmx: tcId 91 unseals back to its message",
      unseals
      ~key:"92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20"
      ~iv:"00112233445566778899aabb"
      ~aad:"00000000ffffffff"
      ~ct:"e27abdd2d2a53d2f136b"
      ~tag:"9a4a2579529301bcfb71c78d4060f52c"
      ~msg:"00010203040506070809" );
    (* tcId 92: Ktv;  msg 0 bytes, aad 6 bytes, result valid. *)
    ( "gcmx: tcId 92 seals to its ciphertext and tag",
      seals
      ~key:"29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123"
      ~iv:"00112233445566778899aabb"
      ~aad:"aabbccddeeff"
      ~msg:""
      ~ct:""
      ~tag:"2a7d77fa526b8250cb296078926b5020" );
    ( "gcmx: tcId 92 unseals back to its message",
      unseals
      ~key:"29d3a44f8723dc640239100c365423a312934ac80239212ac3df3421a2098123"
      ~iv:"00112233445566778899aabb"
      ~aad:"aabbccddeeff"
      ~ct:""
      ~tag:"2a7d77fa526b8250cb296078926b5020"
      ~msg:"" );
    (* tcId 93: Pseudorandom, the message-length boundary set;  msg 0 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 93 seals to its ciphertext and tag",
      seals
      ~key:"80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0"
      ~iv:"4da5bf8dfd5852c1ea12379d"
      ~aad:""
      ~msg:""
      ~ct:""
      ~tag:"4771a7c404a472966cea8f73c8bfe17a" );
    ( "gcmx: tcId 93 unseals back to its message",
      unseals
      ~key:"80ba3192c803ce965ea371d5ff073cf0f43b6a2ab576b208426e11409c09b9b0"
      ~iv:"4da5bf8dfd5852c1ea12379d"
      ~aad:""
      ~ct:""
      ~tag:"4771a7c404a472966cea8f73c8bfe17a"
      ~msg:"" );
    (* tcId 94: Pseudorandom, the message-length boundary set;  msg 1 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 94 seals to its ciphertext and tag",
      seals
      ~key:"cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273"
      ~iv:"99e23ec48985bccdeeab60f1"
      ~aad:""
      ~msg:"2a"
      ~ct:"06"
      ~tag:"633c1e9703ef744ffffb40edf9d14355" );
    ( "gcmx: tcId 94 unseals back to its message",
      unseals
      ~key:"cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273"
      ~iv:"99e23ec48985bccdeeab60f1"
      ~aad:""
      ~ct:"06"
      ~tag:"633c1e9703ef744ffffb40edf9d14355"
      ~msg:"2a" );
    (* tcId 96: Pseudorandom, the message-length boundary set;  msg 15 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 96 seals to its ciphertext and tag",
      seals
      ~key:"67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb"
      ~iv:"68ab7fdbf61901dad461d23c"
      ~aad:""
      ~msg:"51f8c1f731ea14acdb210a6d973e07"
      ~ct:"43fc101bff4b32bfadd3daf57a590e"
      ~tag:"ec04aacb7148a8b8be44cb7eaf4efa69" );
    ( "gcmx: tcId 96 unseals back to its message",
      unseals
      ~key:"67119627bd988eda906219e08c0d0d779a07d208ce8a4fe0709af755eeec6dcb"
      ~iv:"68ab7fdbf61901dad461d23c"
      ~aad:""
      ~ct:"43fc101bff4b32bfadd3daf57a590e"
      ~tag:"ec04aacb7148a8b8be44cb7eaf4efa69"
      ~msg:"51f8c1f731ea14acdb210a6d973e07" );
    (* tcId 97: Pseudorandom, the message-length boundary set;  msg 16 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 97 seals to its ciphertext and tag",
      seals
      ~key:"59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a"
      ~iv:"2fcb1b38a99e71b84740ad9b"
      ~aad:""
      ~msg:"549b365af913f3b081131ccb6b825588"
      ~ct:"f58c16690122d75356907fd96b570fca"
      ~tag:"28752c20153092818faba2a334640d6e" );
    ( "gcmx: tcId 97 unseals back to its message",
      unseals
      ~key:"59d4eafb4de0cfc7d3db99a8f54b15d7b39f0acc8da69763b019c1699f87674a"
      ~iv:"2fcb1b38a99e71b84740ad9b"
      ~aad:""
      ~ct:"f58c16690122d75356907fd96b570fca"
      ~tag:"28752c20153092818faba2a334640d6e"
      ~msg:"549b365af913f3b081131ccb6b825588" );
    (* tcId 98: Pseudorandom, the message-length boundary set;  msg 17 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 98 seals to its ciphertext and tag",
      seals
      ~key:"3b2458d8176e1621c0cc24c0c0e24c1e80d72f7ee9149a4b166176629616d011"
      ~iv:"45aaa3e5d16d2d42dc03445d"
      ~aad:""
      ~msg:"3ff1514b1c503915918f0c0c31094a6e1f"
      ~ct:"73a6b6f45f6ccc5131e07f2caa1f2e2f56"
      ~tag:"2d7379ec1db5952d4e95d30c340b1b1d" );
    ( "gcmx: tcId 98 unseals back to its message",
      unseals
      ~key:"3b2458d8176e1621c0cc24c0c0e24c1e80d72f7ee9149a4b166176629616d011"
      ~iv:"45aaa3e5d16d2d42dc03445d"
      ~aad:""
      ~ct:"73a6b6f45f6ccc5131e07f2caa1f2e2f56"
      ~tag:"2d7379ec1db5952d4e95d30c340b1b1d"
      ~msg:"3ff1514b1c503915918f0c0c31094a6e1f" );
    (* tcId 104: Pseudorandom, the message-length boundary set;  msg 63 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 104 seals to its ciphertext and tag",
      seals
      ~key:"6efca98126918ab564d88c6bec02e8998b2be50e3f906ff9adfdd185f373e756"
      ~iv:"4abd6cfc83bd06b11efaa2a7"
      ~aad:""
      ~msg:"bbec79c086d41e602d090f7e40494d6bf3faa1dc6df0ab8a88ea5d35d426b248c2ad880351e223f6170d37cc9655e10459e59cbd6d1c092ed31d72ccc7af20"
      ~ct:"97b4c73a4d8b5b21bc4b50dbb70dfa77b1a7bf0bbe7cf16ecf5bb60ba8070acc5740780435ed145a62a613dd9881b721168fbb3f5af385ee5d4f856cf93cba"
      ~tag:"27ac8c4010d8e81b7051ceb06b30fe2d" );
    ( "gcmx: tcId 104 unseals back to its message",
      unseals
      ~key:"6efca98126918ab564d88c6bec02e8998b2be50e3f906ff9adfdd185f373e756"
      ~iv:"4abd6cfc83bd06b11efaa2a7"
      ~aad:""
      ~ct:"97b4c73a4d8b5b21bc4b50dbb70dfa77b1a7bf0bbe7cf16ecf5bb60ba8070acc5740780435ed145a62a613dd9881b721168fbb3f5af385ee5d4f856cf93cba"
      ~tag:"27ac8c4010d8e81b7051ceb06b30fe2d"
      ~msg:"bbec79c086d41e602d090f7e40494d6bf3faa1dc6df0ab8a88ea5d35d426b248c2ad880351e223f6170d37cc9655e10459e59cbd6d1c092ed31d72ccc7af20" );
    (* tcId 105: Pseudorandom, the message-length boundary set;  msg 64 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 105 seals to its ciphertext and tag",
      seals
      ~key:"5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701"
      ~iv:"d61040a313ed492823cc065b"
      ~aad:""
      ~msg:"d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82"
      ~ct:"c7d191b601f86c28b6a1bdef6a57b4f6ee3ae417bc125c381cdf1c4dac184ed1d84f1196206d62cad112b038845720e02c061179a8836f02b93fa7008379a6bf"
      ~tag:"f15612f6c40f2e0db6dc76fc4822fcfe" );
    ( "gcmx: tcId 105 unseals back to its message",
      unseals
      ~key:"5b1d1035c0b17ee0b0444767f80a25b8c1b741f4b50a4d3052226baa1c6fb701"
      ~iv:"d61040a313ed492823cc065b"
      ~aad:""
      ~ct:"c7d191b601f86c28b6a1bdef6a57b4f6ee3ae417bc125c381cdf1c4dac184ed1d84f1196206d62cad112b038845720e02c061179a8836f02b93fa7008379a6bf"
      ~tag:"f15612f6c40f2e0db6dc76fc4822fcfe"
      ~msg:"d096803181beef9e008ff85d5ddc38ddacf0f09ee5f7e07f1e4079cb64d0dc8f5e6711cd4921a7887de76e2678fdc67618f1185586bfea9d4c685d50e4bb9a82" );
    (* tcId 106: Pseudorandom, the message-length boundary set;  msg 65 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 106 seals to its ciphertext and tag",
      seals
      ~key:"81b6b27e5ed90ab99fe6756d4cb41e3f07269687f5afabdb426e29096b5e4466"
      ~iv:"13e727486031cca21f733375"
      ~aad:""
      ~msg:"9a95a23cfb1e35d89a7597570df0fb0efcbb7429f53bebcbbfa49fa247b251a8508ad497066855d08688576188e4ffb12d1d084dcabec3d57806daf215dcc97edd"
      ~ct:"7ede7368bca3c93d9f1d7f7750d6e44b1cb92c30e3c9834b0b69efd2470911644ae6f6d75715e13aea8781f8da611a13ac6364c406c1a715b7e97acb22b6e6156e"
      ~tag:"74e20a93802f43407c8989a37f013802" );
    ( "gcmx: tcId 106 unseals back to its message",
      unseals
      ~key:"81b6b27e5ed90ab99fe6756d4cb41e3f07269687f5afabdb426e29096b5e4466"
      ~iv:"13e727486031cca21f733375"
      ~aad:""
      ~ct:"7ede7368bca3c93d9f1d7f7750d6e44b1cb92c30e3c9834b0b69efd2470911644ae6f6d75715e13aea8781f8da611a13ac6364c406c1a715b7e97acb22b6e6156e"
      ~tag:"74e20a93802f43407c8989a37f013802"
      ~msg:"9a95a23cfb1e35d89a7597570df0fb0efcbb7429f53bebcbbfa49fa247b251a8508ad497066855d08688576188e4ffb12d1d084dcabec3d57806daf215dcc97edd" );
    (* tcId 110: Pseudorandom, the message-length boundary set;  msg 255 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 110 seals to its ciphertext and tag",
      seals
      ~key:"01e75ae803d3045e6b28b7f67937eee2d8d98f77b4892d48ab1f15f57fa88bbe"
      ~iv:"6902e8f0ef1e9ec60a3e46f0"
      ~aad:""
      ~msg:"32dde3b9bc671fad1265b26cad3d8dd0f099134f6755f98613024e1bd10da9a62bad01a997f973101e855ee1c7e60e6b6aa1df9d80fa567d0ccca0f956680be76ed37c71fdedef560e2523e8c5fdb9516250017304f8ff416b9b8e5d17c1f062ded4616ea9d462ed6ca0dfddb9f5295b7a127c0825ffab56ea4983c01eec867f93e24a18be48ceb540986c530104fd466318eb812eb42fd04355615f92503e53799742cdc71830eaa44aeec914b6ff1cbb4f6f81ab595078331d645c8d083b469731174a706b1666e5e450cb62671067032a566f597b9866b71514a409e38fcabe844964581b3ab5152696b76e49ace66581d21f512e28e077c44948a65260"
      ~ct:"6323ddbf9eb0463714d5857d1841a9f65529516c2f412956bc835f4f252d22a2ce743f21767fcb28859882b570ca053970b72e86f451ff0c77e87f3a03c0536b3859394fce324442ac197874f81a2ce649b99feb442e23123f7ab361d2ce6768a1badb30c509e79bee9277d378fadaa64e77e26f726df86110526530cd439429b017ae2bcec8cc24f994f5885a8a76fab6339c7054df76aa6f450193a635d21d22f71f1ae6856036e6caaeed8840bbfbc8236c25a31e775cba5f6e189fcbc3e96970ca5378fd5c29a712f5dc17641ad88ab566d8c78fff1bb57f9b2f7c9db838b4307c63e04a73d3ef8121f48932ec318dffaead58a83a7f79bc44a1587990"
      ~tag:"0c92bb5291e981bf562293877f4ddb5f" );
    ( "gcmx: tcId 110 unseals back to its message",
      unseals
      ~key:"01e75ae803d3045e6b28b7f67937eee2d8d98f77b4892d48ab1f15f57fa88bbe"
      ~iv:"6902e8f0ef1e9ec60a3e46f0"
      ~aad:""
      ~ct:"6323ddbf9eb0463714d5857d1841a9f65529516c2f412956bc835f4f252d22a2ce743f21767fcb28859882b570ca053970b72e86f451ff0c77e87f3a03c0536b3859394fce324442ac197874f81a2ce649b99feb442e23123f7ab361d2ce6768a1badb30c509e79bee9277d378fadaa64e77e26f726df86110526530cd439429b017ae2bcec8cc24f994f5885a8a76fab6339c7054df76aa6f450193a635d21d22f71f1ae6856036e6caaeed8840bbfbc8236c25a31e775cba5f6e189fcbc3e96970ca5378fd5c29a712f5dc17641ad88ab566d8c78fff1bb57f9b2f7c9db838b4307c63e04a73d3ef8121f48932ec318dffaead58a83a7f79bc44a1587990"
      ~tag:"0c92bb5291e981bf562293877f4ddb5f"
      ~msg:"32dde3b9bc671fad1265b26cad3d8dd0f099134f6755f98613024e1bd10da9a62bad01a997f973101e855ee1c7e60e6b6aa1df9d80fa567d0ccca0f956680be76ed37c71fdedef560e2523e8c5fdb9516250017304f8ff416b9b8e5d17c1f062ded4616ea9d462ed6ca0dfddb9f5295b7a127c0825ffab56ea4983c01eec867f93e24a18be48ceb540986c530104fd466318eb812eb42fd04355615f92503e53799742cdc71830eaa44aeec914b6ff1cbb4f6f81ab595078331d645c8d083b469731174a706b1666e5e450cb62671067032a566f597b9866b71514a409e38fcabe844964581b3ab5152696b76e49ace66581d21f512e28e077c44948a65260" );
    (* tcId 111: Pseudorandom, the message-length boundary set;  msg 256 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 111 seals to its ciphertext and tag",
      seals
      ~key:"dc4dbf811f9509e33a45a8a0743e9391de333f69c56ee4f0fe90ce21c238ee59"
      ~iv:"1859d3ba4710cdd300baa029"
      ~aad:""
      ~msg:"df91c48591f4cae8c4d659d024dfd0a3535981487764bf19b012713e6ac6d578aa0b3a51d7ac97cd503fdc8682cabdb6a5256e9890458356f39b9749f6ab158112fbe4f91acd333477998b9f0d7cc0be2d40acfa5103adc1b0d0a5cc94733d703e0d8c26e09e9d079fa6a65cf35240a16280826ab7c0d8ac5882c89e58444233c2f60aaae0cbd1a7ed850065242a9378c340232fd86f1fd52a92c960a9a86f529f431acf3aa94133785803f4ac1a22378332daa22dea3d34d2fdb7c308fa44ab93b3fb02f428be22fad6c0b10c138af97b92a199296dd947c93fbc40674c34c5623d26d9c90dc6b3357018b9f9250fb4dd5c11518191a236745a2bd42f863766"
      ~ct:"9c511d08f244cb6971a39b70639c4a53ae48254fcb3d2eea4796ecc996f1fe26a8e30932258a48fe4237e5bfb0e1320dc591256dc83cd56dbf5d9b377b7805b7fac0497b2f99e3310e9e2cc8009141a82f26f8a02299d64138bb1fe8a1243df3e9fb37b52bd3c2cc19f543b3f4928e5a73730a7a6e6d75919d117d3dfe10e863a9846b2ca260de5dddba7ceac37019e615b89a2ab94df8d1a790749998cb8531fef1ef5f8a28a8ad60e813f7e78412ca4d95b9604a24a16e4a3ca8ee33bfbb7809048014943e5fd7966a7db214e052d1cc546a6da72ec89d1c3398aefdcb881dfc3d800b7323abcd7583e9c8a31f03b6995d4aeac17c5a56d8af492a2b108fe3"
      ~tag:"17090ce50e35244a59bafc80eba5dae5" );
    ( "gcmx: tcId 111 unseals back to its message",
      unseals
      ~key:"dc4dbf811f9509e33a45a8a0743e9391de333f69c56ee4f0fe90ce21c238ee59"
      ~iv:"1859d3ba4710cdd300baa029"
      ~aad:""
      ~ct:"9c511d08f244cb6971a39b70639c4a53ae48254fcb3d2eea4796ecc996f1fe26a8e30932258a48fe4237e5bfb0e1320dc591256dc83cd56dbf5d9b377b7805b7fac0497b2f99e3310e9e2cc8009141a82f26f8a02299d64138bb1fe8a1243df3e9fb37b52bd3c2cc19f543b3f4928e5a73730a7a6e6d75919d117d3dfe10e863a9846b2ca260de5dddba7ceac37019e615b89a2ab94df8d1a790749998cb8531fef1ef5f8a28a8ad60e813f7e78412ca4d95b9604a24a16e4a3ca8ee33bfbb7809048014943e5fd7966a7db214e052d1cc546a6da72ec89d1c3398aefdcb881dfc3d800b7323abcd7583e9c8a31f03b6995d4aeac17c5a56d8af492a2b108fe3"
      ~tag:"17090ce50e35244a59bafc80eba5dae5"
      ~msg:"df91c48591f4cae8c4d659d024dfd0a3535981487764bf19b012713e6ac6d578aa0b3a51d7ac97cd503fdc8682cabdb6a5256e9890458356f39b9749f6ab158112fbe4f91acd333477998b9f0d7cc0be2d40acfa5103adc1b0d0a5cc94733d703e0d8c26e09e9d079fa6a65cf35240a16280826ab7c0d8ac5882c89e58444233c2f60aaae0cbd1a7ed850065242a9378c340232fd86f1fd52a92c960a9a86f529f431acf3aa94133785803f4ac1a22378332daa22dea3d34d2fdb7c308fa44ab93b3fb02f428be22fad6c0b10c138af97b92a199296dd947c93fbc40674c34c5623d26d9c90dc6b3357018b9f9250fb4dd5c11518191a236745a2bd42f863766" );
    (* tcId 112: Pseudorandom, the message-length boundary set;  msg 257 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 112 seals to its ciphertext and tag",
      seals
      ~key:"317ba331307f3a3d3d82ee1fdab70f62a155af14daf631307a61b187d413e533"
      ~iv:"a6687cf508356b174625deaa"
      ~aad:""
      ~msg:"32c1d09107c599d3cce4e782179c966c6ef963689d45351dbe0f6f881db273e54db76fc48fdc5d30f089da838301a5f924bba3c044e19b3ed5aa6be87118554004ca30e0324337d987839412bf8f8bbdd537205d4b0e2120e965373235d6cbd2fb3776ba0a384ec1d9b7c631a0379ff997c3f974a6f7bbf4fd23016211f5fc10acadb5e400d2ff0fdfd193f5c6fc6d4f7271dfd1349ed80fbedaebb155b9b02fb3074495d55f9a2455f59bf6f113191a029c6b0ba75d97cdc0c84f131836337f29f9d96ca448eec0cc46d1ca8b3735661979d83302fec08fffcf5e58f12b1e7050657b1b97c64a4e07e317f554f8310b6ccb49f36d48c57816d24952aada711d4f"
      ~ct:"d7eebc9587aa21136fa38b41cf0e2db03a7ea2ba9eaddf83d33f781093617bf50f49b2bfe2f7173b113912e2e1775f40edfed8b3b0099b9e1c220dd103be6166210b01029feb24ed9e20614eddc3cebe41b0079a9a8c117b596c90288effd3796fbd0c7e8eab00609a64be3ad9597cdbf3a818c260cd938bdf232e4059ae35a2571a838887fc196912179486e046a62227a4caddce38cbbc37587bb9439ec637602b6818c5cbe3c71a7c4143960533dc74174bd315c8db227b69b55bb7fc30ba1d5213a752ec33925043cefbc1a62943ee5f34d5da01799e69094d732aef52f8e036980d0070e22e173c67c4bbcca61cc1eedbd6016516c592144819df13204dee"
      ~tag:"bf0540d34b20f761101bc608b02458f2" );
    ( "gcmx: tcId 112 unseals back to its message",
      unseals
      ~key:"317ba331307f3a3d3d82ee1fdab70f62a155af14daf631307a61b187d413e533"
      ~iv:"a6687cf508356b174625deaa"
      ~aad:""
      ~ct:"d7eebc9587aa21136fa38b41cf0e2db03a7ea2ba9eaddf83d33f781093617bf50f49b2bfe2f7173b113912e2e1775f40edfed8b3b0099b9e1c220dd103be6166210b01029feb24ed9e20614eddc3cebe41b0079a9a8c117b596c90288effd3796fbd0c7e8eab00609a64be3ad9597cdbf3a818c260cd938bdf232e4059ae35a2571a838887fc196912179486e046a62227a4caddce38cbbc37587bb9439ec637602b6818c5cbe3c71a7c4143960533dc74174bd315c8db227b69b55bb7fc30ba1d5213a752ec33925043cefbc1a62943ee5f34d5da01799e69094d732aef52f8e036980d0070e22e173c67c4bbcca61cc1eedbd6016516c592144819df13204dee"
      ~tag:"bf0540d34b20f761101bc608b02458f2"
      ~msg:"32c1d09107c599d3cce4e782179c966c6ef963689d45351dbe0f6f881db273e54db76fc48fdc5d30f089da838301a5f924bba3c044e19b3ed5aa6be87118554004ca30e0324337d987839412bf8f8bbdd537205d4b0e2120e965373235d6cbd2fb3776ba0a384ec1d9b7c631a0379ff997c3f974a6f7bbf4fd23016211f5fc10acadb5e400d2ff0fdfd193f5c6fc6d4f7271dfd1349ed80fbedaebb155b9b02fb3074495d55f9a2455f59bf6f113191a029c6b0ba75d97cdc0c84f131836337f29f9d96ca448eec0cc46d1ca8b3735661979d83302fec08fffcf5e58f12b1e7050657b1b97c64a4e07e317f554f8310b6ccb49f36d48c57816d24952aada711d4f" );
    (* tcId 100: Pseudorandom, the aad-length set;  msg 20 bytes, aad 1 bytes, result valid. *)
    ( "gcmx: tcId 100 seals to its ciphertext and tag",
      seals
      ~key:"b279f57e19c8f53f2f963f5f2519fdb7c1779be2ca2b3ae8e1128b7d6c627fc4"
      ~iv:"98bc2c7438d5cd7665d76f6e"
      ~aad:"c0"
      ~msg:"fcc515b294408c8645c9183e3f4ecee5127846d1"
      ~ct:"eb5500e3825952866d911253f8de860c00831c81"
      ~tag:"ecb660e1fb0541ec41e8d68a64141b3a" );
    ( "gcmx: tcId 100 unseals back to its message",
      unseals
      ~key:"b279f57e19c8f53f2f963f5f2519fdb7c1779be2ca2b3ae8e1128b7d6c627fc4"
      ~iv:"98bc2c7438d5cd7665d76f6e"
      ~aad:"c0"
      ~ct:"eb5500e3825952866d911253f8de860c00831c81"
      ~tag:"ecb660e1fb0541ec41e8d68a64141b3a"
      ~msg:"fcc515b294408c8645c9183e3f4ecee5127846d1" );
    (* tcId 102: Pseudorandom, the aad-length set;  msg 20 bytes, aad 16 bytes, result valid. *)
    ( "gcmx: tcId 102 seals to its ciphertext and tag",
      seals
      ~key:"f32364b1d339d82e4f132d8f4a0ec1ff7e746517fa07ef1a7f422f4e25a48194"
      ~iv:"5a86a50a0e8a179c734b996d"
      ~aad:"ab2ac7c44c60bdf8228c7884adb20184"
      ~msg:"43891bccb522b1e72a6b53cf31c074e9d6c2df8e"
      ~ct:"43dda832e942e286da314daa99bef5071d9d2c78"
      ~tag:"c3922583476ced575404ddb85dd8cd44" );
    ( "gcmx: tcId 102 unseals back to its message",
      unseals
      ~key:"f32364b1d339d82e4f132d8f4a0ec1ff7e746517fa07ef1a7f422f4e25a48194"
      ~iv:"5a86a50a0e8a179c734b996d"
      ~aad:"ab2ac7c44c60bdf8228c7884adb20184"
      ~ct:"43dda832e942e286da314daa99bef5071d9d2c78"
      ~tag:"c3922583476ced575404ddb85dd8cd44"
      ~msg:"43891bccb522b1e72a6b53cf31c074e9d6c2df8e" );
    (* tcId 116: Pseudorandom, the aad-length set;  msg 20 bytes, aad 63 bytes, result valid. *)
    ( "gcmx: tcId 116 seals to its ciphertext and tag",
      seals
      ~key:"0f112e59cdccd851c3b8e76c9f05a3b7c2e4feca5846afeb351c1cbcace82f04"
      ~iv:"7147973339d86789a2c9a958"
      ~aad:"37128be45f0a7f329546e1492c3c9c2d2534d5b1f5147e49ab91221e7c3edea21bbe47bfe3619437ce3c61e6e946c504f348296918219e51bf2c5598589cff"
      ~msg:"102e5804dda1fb5d656077edb15cadb5d0bdee8c"
      ~ct:"618ac626ae0e8d06c2fd2fb66be253dc26ed6e38"
      ~tag:"d8d93ff975cb988f09174dcd439cb6a4" );
    ( "gcmx: tcId 116 unseals back to its message",
      unseals
      ~key:"0f112e59cdccd851c3b8e76c9f05a3b7c2e4feca5846afeb351c1cbcace82f04"
      ~iv:"7147973339d86789a2c9a958"
      ~aad:"37128be45f0a7f329546e1492c3c9c2d2534d5b1f5147e49ab91221e7c3edea21bbe47bfe3619437ce3c61e6e946c504f348296918219e51bf2c5598589cff"
      ~ct:"618ac626ae0e8d06c2fd2fb66be253dc26ed6e38"
      ~tag:"d8d93ff975cb988f09174dcd439cb6a4"
      ~msg:"102e5804dda1fb5d656077edb15cadb5d0bdee8c" );
    (* tcId 117: Pseudorandom, the aad-length set;  msg 20 bytes, aad 64 bytes, result valid. *)
    ( "gcmx: tcId 117 seals to its ciphertext and tag",
      seals
      ~key:"2ce6b4c15f85fb2da5cc6c269491eef281980309181249ebf2832bd6d0732d0b"
      ~iv:"c064fae9173b173fd6f11f34"
      ~aad:"498d3075b09fed998280583d61bb36b6ce41f130063b80824d1586e143d349b126b16aa10fe57343ed223d6364ee602257fe313a7fc9bf9088f027795b8dc1d3"
      ~msg:"f8a27a4baf00dc0555d222f2fa4fb42dc666ea3c"
      ~ct:"aed58d8a252f740dba4bf6d36773bd5b41234bba"
      ~tag:"01f93d7456aa184ebb49bea472b6d65d" );
    ( "gcmx: tcId 117 unseals back to its message",
      unseals
      ~key:"2ce6b4c15f85fb2da5cc6c269491eef281980309181249ebf2832bd6d0732d0b"
      ~iv:"c064fae9173b173fd6f11f34"
      ~aad:"498d3075b09fed998280583d61bb36b6ce41f130063b80824d1586e143d349b126b16aa10fe57343ed223d6364ee602257fe313a7fc9bf9088f027795b8dc1d3"
      ~ct:"aed58d8a252f740dba4bf6d36773bd5b41234bba"
      ~tag:"01f93d7456aa184ebb49bea472b6d65d"
      ~msg:"f8a27a4baf00dc0555d222f2fa4fb42dc666ea3c" );
    (* tcId 118: Pseudorandom, the aad-length set;  msg 20 bytes, aad 65 bytes, result valid. *)
    ( "gcmx: tcId 118 seals to its ciphertext and tag",
      seals
      ~key:"52350da5a572911ee0e0fcedb115af6f4570fbf9c74a11bc184444d6a621d60f"
      ~iv:"d68ad045c1b9c2923cf5404c"
      ~aad:"03a94b3841292d9bbf72f413c09167c54ee10537c049afe2bbcec43b18f3890b2fcdd3bb31e6d709274e199c0c4648eb3d8b38e0c1bf7f309443bef6937cde4123"
      ~msg:"4e6e6dad2c16cfc6e7cac03636a4a6d88bd6a13e"
      ~ct:"c7764411be13cfeaaece761bd3bb13552f088048"
      ~tag:"bcc2544e79f34ea1076a12b76441d6fa" );
    ( "gcmx: tcId 118 unseals back to its message",
      unseals
      ~key:"52350da5a572911ee0e0fcedb115af6f4570fbf9c74a11bc184444d6a621d60f"
      ~iv:"d68ad045c1b9c2923cf5404c"
      ~aad:"03a94b3841292d9bbf72f413c09167c54ee10537c049afe2bbcec43b18f3890b2fcdd3bb31e6d709274e199c0c4648eb3d8b38e0c1bf7f309443bef6937cde4123"
      ~ct:"c7764411be13cfeaaece761bd3bb13552f088048"
      ~tag:"bcc2544e79f34ea1076a12b76441d6fa"
      ~msg:"4e6e6dad2c16cfc6e7cac03636a4a6d88bd6a13e" );
    (* tcId 123: Pseudorandom, the aad-length set;  msg 20 bytes, aad 256 bytes, result valid. *)
    ( "gcmx: tcId 123 seals to its ciphertext and tag",
      seals
      ~key:"7ec20e38aa1b1f018d79903fc1cf6e260cec3733a19ad9e30f60b54e2ea6ebcc"
      ~iv:"5ccd9cdcf97ac61364687bbb"
      ~aad:"d9d2ee145b5c31a17dce932538c7e45da1c82abb80b0553251e442dbc5af9c126d3a76a24767c39b229bec8976a0df89fa70ea9ad872aa36d6b8b09aaa54698e7f29c2c2d12efb0b301cfb97076473dfa7ec030350e26839fbb7e1612dad93ff08e1119168c5fca56816c62b042f06d89e5a95da6a615e13ba4cad9f942534c539520d00509d0d4ac6d80c59e769d7e1aa7e12987ee05fb6a19b383c3348df6cbdcff604ef218338910a8e275d9a62b802cb07ec9249c9635e2437f8339dff3e21f79e9eb2acc2bbbadd520a84c58f0ddaaf8c32496d173b6b8c0c274352d40d47bfbd93069abdcc3d21c2cd330a8c16847f0e5299beb6a2d33be746de5c71f2"
      ~msg:"bab28e0987509b1d6f9cf3aa90030795f125ee44"
      ~ct:"ce4c58d3c7354d2d27e3bb41a62e5941fb1e39f3"
      ~tag:"e177391d5e2cefa2f7d35e33a76566aa" );
    ( "gcmx: tcId 123 unseals back to its message",
      unseals
      ~key:"7ec20e38aa1b1f018d79903fc1cf6e260cec3733a19ad9e30f60b54e2ea6ebcc"
      ~iv:"5ccd9cdcf97ac61364687bbb"
      ~aad:"d9d2ee145b5c31a17dce932538c7e45da1c82abb80b0553251e442dbc5af9c126d3a76a24767c39b229bec8976a0df89fa70ea9ad872aa36d6b8b09aaa54698e7f29c2c2d12efb0b301cfb97076473dfa7ec030350e26839fbb7e1612dad93ff08e1119168c5fca56816c62b042f06d89e5a95da6a615e13ba4cad9f942534c539520d00509d0d4ac6d80c59e769d7e1aa7e12987ee05fb6a19b383c3348df6cbdcff604ef218338910a8e275d9a62b802cb07ec9249c9635e2437f8339dff3e21f79e9eb2acc2bbbadd520a84c58f0ddaaf8c32496d173b6b8c0c274352d40d47bfbd93069abdcc3d21c2cd330a8c16847f0e5299beb6a2d33be746de5c71f2"
      ~ct:"ce4c58d3c7354d2d27e3bb41a62e5941fb1e39f3"
      ~tag:"e177391d5e2cefa2f7d35e33a76566aa"
      ~msg:"bab28e0987509b1d6f9cf3aa90030795f125ee44" );
    (* tcId 128: SpecialCase, comment "special case";  msg 16 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 128 seals to its ciphertext and tag",
      seals
      ~key:"00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
      ~iv:"000000000000000000000000"
      ~aad:""
      ~msg:"561008fa07a68f5c61285cd013464eaf"
      ~ct:"23293e9b07ca7d1b0cae7cc489a973b3"
      ~tag:"ffffffffffffffffffffffffffffffff" );
    ( "gcmx: tcId 128 unseals back to its message",
      unseals
      ~key:"00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
      ~iv:"000000000000000000000000"
      ~aad:""
      ~ct:"23293e9b07ca7d1b0cae7cc489a973b3"
      ~tag:"ffffffffffffffffffffffffffffffff"
      ~msg:"561008fa07a68f5c61285cd013464eaf" );
    (* tcId 129: SpecialCase, comment "special case";  msg 16 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 129 seals to its ciphertext and tag",
      seals
      ~key:"00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
      ~iv:"ffffffffffffffffffffffff"
      ~aad:""
      ~msg:"c6152244cea1978d3e0bc274cf8c0b3b"
      ~ct:"7cb6fc7c6abc009efe9551a99f36a421"
      ~tag:"00000000000000000000000000000000" );
    ( "gcmx: tcId 129 unseals back to its message",
      unseals
      ~key:"00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
      ~iv:"ffffffffffffffffffffffff"
      ~aad:""
      ~ct:"7cb6fc7c6abc009efe9551a99f36a421"
      ~tag:"00000000000000000000000000000000"
      ~msg:"c6152244cea1978d3e0bc274cf8c0b3b" )
  ]

(* ---------- group (c): the 10 ModifiedTag rows ---------- *)

(* A ModifiedTag row never seals: the corpus tag is not the honest
   tag of its own inputs, so the row unseals the pinned ciphertext
   under the modified tag and requires None.  The message is NOT
   quoted, because no row of this group produces one. *)
let wycheproof_modified_tag_checks : (string * bool) list =
  (* tcId 130: ModifiedTag, "Flipped bit 0 in tag";  msg 16 bytes, aad 0 bytes, result invalid. *)
  [ ( "gcmx: tcId 130 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"9de8fef6d8ab1bf1bf887232eab590dd" );
    (* tcId 137: ModifiedTag, "Flipped bit 63 in tag";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 137 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"9ce8fef6d8ab1b71bf887232eab590dd" );
    (* tcId 138: ModifiedTag, "Flipped bit 64 in tag";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 138 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"9ce8fef6d8ab1bf1be887232eab590dd" );
    (* tcId 148: ModifiedTag, "Flipped bit 127 in tag";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 148 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"9ce8fef6d8ab1bf1bf887232eab5905d" );
    (* tcId 149: ModifiedTag, "Flipped bits 0 and 64 in tag";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 149 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"9de8fef6d8ab1bf1be887232eab590dd" );
    (* tcId 152: ModifiedTag, "all bits of tag flipped";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 152 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"631701092754e40e40778dcd154a6f22" );
    (* tcId 153: ModifiedTag, "Tag changed to all zero";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 153 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"00000000000000000000000000000000" );
    (* tcId 154: ModifiedTag, "tag changed to all 1";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 154 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"ffffffffffffffffffffffffffffffff" );
    (* tcId 155: ModifiedTag, "msbs changed in tag";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 155 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"1c687e76582b9b713f08f2b26a35105d" );
    (* tcId 156: ModifiedTag, "lsbs changed in tag";  msg 16 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 156 unseals to None under its modified tag",
      unseal_none
      ~key:"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      ~iv:"505152535455565758595a5b"
      ~aad:""
      ~ct:"b2061457c0759fc1749f174ee1ccadfa"
      ~tag:"9de9fff7d9aa1af0be897333ebb491dc" )
  ]

(* ---------- group (d): the 5 length rejects ---------- *)

(* Each row stops at the surface that refuses it, so it quotes ONLY
   the field it passes: neither the message nor the ciphertext nor
   the tag of these vectors ever reaches this unit. *)
let wycheproof_length_reject_checks : (string * bool) list =
  (* tcId 1: flag Ktv, keySize 128, a VALID vector of its own group that gcmx rejects on its 16-byte KEY alone;  msg 16 bytes, aad 0 bytes, result valid. *)
  [ ( "gcmx: tcId 1 is refused on its 16-byte key",
      Option.is_none
        (G.Key.of_bytes (bytes_of_hex "5b9604fe14eadba931b0ccf34843dab9")) );
    (* tcId 176: flag SpecialCase, keySize 192, a VALID vector of its own group that gcmx rejects on its 24-byte KEY alone;  msg 16 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 176 is refused on its 24-byte key",
      Option.is_none
        (G.Key.of_bytes (bytes_of_hex "00112233445566778899aabbccddeeff1021324354657687")) );
    (* tcId 240: flag CounterWrap, keySize 256, a VALID vector of its own group that gcmx rejects on its 16-byte IV alone;  msg 40 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 240 is refused on its 16-byte iv",
      Option.is_none
        (G.Nonce.of_bytes (bytes_of_hex "5c2ea9b695fcf6e264b96074d6bfa572")) );
    (* tcId 299: flag SmallIv, keySize 256, a VALID vector of its own group that gcmx rejects on its 1-byte IV alone;  msg 0 bytes, aad 0 bytes, result valid. *)
    ( "gcmx: tcId 299 is refused on its 1-byte iv",
      Option.is_none
        (G.Nonce.of_bytes (bytes_of_hex "a9")) );
    (* tcId 315: flag ZeroLengthIv, keySize 256, result invalid, and gcmx rejects it on its 0-byte IV alone;  msg 0 bytes, aad 0 bytes, result invalid. *)
    ( "gcmx: tcId 315 is refused on its 0-byte iv",
      Option.is_none
        (G.Nonce.of_bytes (bytes_of_hex "")) )
  ]

(* ---------- group (e): the GCM specification cases 13 to 16 ---------- *)

let spec_case_checks : (string * bool) list =
  (* GCM specification case 13:  msg 0 bytes, aad 0 bytes. *)
  [ ( "gcmx: GCM case 13 seals to its ciphertext and tag",
      seals
      ~key:"0000000000000000000000000000000000000000000000000000000000000000"
      ~iv:"000000000000000000000000"
      ~aad:""
      ~msg:""
      ~ct:""
      ~tag:"530f8afbc74536b9a963b4f1c4cb738b" );
    ( "gcmx: GCM case 13 unseals back to its message",
      unseals
      ~key:"0000000000000000000000000000000000000000000000000000000000000000"
      ~iv:"000000000000000000000000"
      ~aad:""
      ~ct:""
      ~tag:"530f8afbc74536b9a963b4f1c4cb738b"
      ~msg:"" );
    (* GCM specification case 14:  msg 16 bytes, aad 0 bytes. *)
    ( "gcmx: GCM case 14 seals to its ciphertext and tag",
      seals
      ~key:"0000000000000000000000000000000000000000000000000000000000000000"
      ~iv:"000000000000000000000000"
      ~aad:""
      ~msg:"00000000000000000000000000000000"
      ~ct:"cea7403d4d606b6e074ec5d3baf39d18"
      ~tag:"d0d1c8a799996bf0265b98b5d48ab919" );
    ( "gcmx: GCM case 14 unseals back to its message",
      unseals
      ~key:"0000000000000000000000000000000000000000000000000000000000000000"
      ~iv:"000000000000000000000000"
      ~aad:""
      ~ct:"cea7403d4d606b6e074ec5d3baf39d18"
      ~tag:"d0d1c8a799996bf0265b98b5d48ab919"
      ~msg:"00000000000000000000000000000000" );
    (* GCM specification case 15:  msg 64 bytes, aad 0 bytes. *)
    ( "gcmx: GCM case 15 seals to its ciphertext and tag",
      seals
      ~key:"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
      ~iv:"cafebabefacedbaddecaf888"
      ~aad:""
      ~msg:"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
      ~ct:"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
      ~tag:"b094dac5d93471bdec1a502270e3cc6c" );
    ( "gcmx: GCM case 15 unseals back to its message",
      unseals
      ~key:"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
      ~iv:"cafebabefacedbaddecaf888"
      ~aad:""
      ~ct:"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
      ~tag:"b094dac5d93471bdec1a502270e3cc6c"
      ~msg:"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255" );
    (* GCM specification case 16:  msg 60 bytes, aad 20 bytes. *)
    ( "gcmx: GCM case 16 seals to its ciphertext and tag",
      seals
      ~key:"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
      ~iv:"cafebabefacedbaddecaf888"
      ~aad:"feedfacedeadbeeffeedfacedeadbeefabaddad2"
      ~msg:"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
      ~ct:"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
      ~tag:"76fc6ece0f4e1768cddf8853bb2d551b" );
    ( "gcmx: GCM case 16 unseals back to its message",
      unseals
      ~key:"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
      ~iv:"cafebabefacedbaddecaf888"
      ~aad:"feedfacedeadbeeffeedfacedeadbeefabaddad2"
      ~ct:"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
      ~tag:"76fc6ece0f4e1768cddf8853bb2d551b"
      ~msg:"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39" )
  ]

(* ---------- group (f): the generated vector and its twins ---------- *)

(* The key is SHA-256 of one ASCII string, the nonce the first 12
   bytes of SHA-256 of another, the aad an ASCII string and the
   plaintext the first 100 bytes of a repeated one, so the oracle
   RECOMPUTES this vector from its derivations and quotes nothing. *)
let generated_checks : (string * bool) list =
  [ ( "gcmx: the generated vector seals to its ciphertext and tag",
      seals
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"d541ece33e951f0bdc43e2fd"
      ~aad:"76656e6963652d6f63616d6c206d323120616164"
      ~msg:"76656e6963652d6f63616d6c206d32312067636d7820706c61696e746578742076656e6963652d6f63616d6c206d32312067636d7820706c61696e746578742076656e6963652d6f63616d6c206d32312067636d7820706c61696e746578742076656e69"
      ~ct:"49a91ef79eb060ce6a5fb9cb6fd67f1bf37a5eefb2fb085a4e06ba6adf993fc67978ad776bd7548fd38b1a922ea6b9d817eaf28cffd5fe76235f90512d5d27a6e448b9f7bb696e4f15ae408d61502d153e231a48ea7c408855267f332daff17ebbb8002c"
      ~tag:"c520c21755347c7154ca373f610140f9" );
    ( "gcmx: the generated vector unseals back to its plaintext",
      unseals
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"d541ece33e951f0bdc43e2fd"
      ~aad:"76656e6963652d6f63616d6c206d323120616164"
      ~ct:"49a91ef79eb060ce6a5fb9cb6fd67f1bf37a5eefb2fb085a4e06ba6adf993fc67978ad776bd7548fd38b1a922ea6b9d817eaf28cffd5fe76235f90512d5d27a6e448b9f7bb696e4f15ae408d61502d153e231a48ea7c408855267f332daff17ebbb8002c"
      ~tag:"c520c21755347c7154ca373f610140f9"
      ~msg:"76656e6963652d6f63616d6c206d32312067636d7820706c61696e746578742076656e6963652d6f63616d6c206d32312067636d7820706c61696e746578742076656e6963652d6f63616d6c206d32312067636d7820706c61696e746578742076656e69" );
    ( "gcmx: the empty twin is GMAC over the aad alone",
      seals
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"d541ece33e951f0bdc43e2fd"
      ~aad:"76656e6963652d6f63616d6c206d323120616164"
      ~msg:""
      ~ct:""
      ~tag:"7a100e3479380bcaa05b779ba56d3999" );
    ( "gcmx: the empty twin unseals to the empty plaintext",
      unseals
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"d541ece33e951f0bdc43e2fd"
      ~aad:"76656e6963652d6f63616d6c206d323120616164"
      ~ct:""
      ~tag:"7a100e3479380bcaa05b779ba56d3999"
      ~msg:"" );
    ( "gcmx: a flipped tag unseals to None",
      unseal_none
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"d541ece33e951f0bdc43e2fd"
      ~aad:"76656e6963652d6f63616d6c206d323120616164"
      ~ct:"49a91ef79eb060ce6a5fb9cb6fd67f1bf37a5eefb2fb085a4e06ba6adf993fc67978ad776bd7548fd38b1a922ea6b9d817eaf28cffd5fe76235f90512d5d27a6e448b9f7bb696e4f15ae408d61502d153e231a48ea7c408855267f332daff17ebbb8002c"
      ~tag:"c520c21755347c7154ca373f610140f8" );
    ( "gcmx: a wrong aad unseals to None",
      unseal_none
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"d541ece33e951f0bdc43e2fd"
      ~aad:"00"
      ~ct:"49a91ef79eb060ce6a5fb9cb6fd67f1bf37a5eefb2fb085a4e06ba6adf993fc67978ad776bd7548fd38b1a922ea6b9d817eaf28cffd5fe76235f90512d5d27a6e448b9f7bb696e4f15ae408d61502d153e231a48ea7c408855267f332daff17ebbb8002c"
      ~tag:"c520c21755347c7154ca373f610140f9" );
    ( "gcmx: a wrong nonce unseals to None",
      unseal_none
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"000000000000000000000000"
      ~aad:"76656e6963652d6f63616d6c206d323120616164"
      ~ct:"49a91ef79eb060ce6a5fb9cb6fd67f1bf37a5eefb2fb085a4e06ba6adf993fc67978ad776bd7548fd38b1a922ea6b9d817eaf28cffd5fe76235f90512d5d27a6e448b9f7bb696e4f15ae408d61502d153e231a48ea7c408855267f332daff17ebbb8002c"
      ~tag:"c520c21755347c7154ca373f610140f9" );
    ( "gcmx: a truncated ciphertext unseals to None",
      unseal_none
      ~key:"94e15a1e66c8bb564199bb26b10ebf38cb06e856a1088f9bf7aedc49495915e3"
      ~iv:"d541ece33e951f0bdc43e2fd"
      ~aad:"76656e6963652d6f63616d6c206d323120616164"
      ~ct:"49a91ef79eb060ce6a5fb9cb6fd67f1bf37a5eefb2fb085a4e06ba6adf993fc67978ad776bd7548fd38b1a922ea6b9d817eaf28cffd5fe76235f90512d5d27a6e448b9f7bb696e4f15ae408d61502d153e231a48ea7c408855267f332daff17ebbb800"
      ~tag:"c520c21755347c7154ca373f610140f9" )
  ]

(* ---------- group (g): the SP 800-38D length cap ---------- *)

(* The REJECT above this cap has no row and the design brief records
   that residual: 68719476704 bytes is 64 GiB and this host cannot
   allocate it, so the cap is pinned by its VALUE alone. *)
let cap_checks : (string * bool) list =
  [ ( "gcmx: max_len is (2^32 - 2) * 16 bytes",
      Int.equal (G.max_len ()) 68719476704 )
  ]

let () =
  run
    (construction_checks @ wycheproof_valid_checks
   @ wycheproof_modified_tag_checks @ wycheproof_length_reject_checks
   @ spec_case_checks @ generated_checks @ cap_checks)
