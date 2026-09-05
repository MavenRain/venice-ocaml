(* embed: the BUILD-time fixture generator of M23 (D2).

   It is a HOST module.  It is not a suite, it joins no core module
   list, and no library module reads it.  dune runs it through the two
   rules of test/dune, once per fixture, and captures its standard
   output as a generated module.

   It prints ONE line, "let bytes (() : unit) : string = ...", where
   Printf %S writes the file bytes as an OCaml string literal and
   escapes every byte, the NUL byte and every byte above 0x7f
   included.  The suite therefore needs no runtime file read and no
   relative fixture path, which matters because gates.sh runs each
   suite executable from the REPOSITORY ROOT while dune test runs it
   from _build/default/test.  A missing or renamed fixture breaks the
   BUILD instead of reddening a suite.

   The path argument comes from Array.to_list Sys.argv through a TOTAL
   two-arm match, never through Sys.argv.(1): a raw array index is an
   exception path and the repository forbids it in every authored
   source (A8).  Option.iter consumes the result, so a call with no
   argument prints nothing and exits 0. *)

let emit (path : string) : unit =
  let bytes = In_channel.with_open_bin path In_channel.input_all in
  Printf.printf "let bytes (() : unit) : string = %S\n" bytes

let arg_path (argv : string list) : string option =
  match argv with
  | (_ : string) :: p :: (_ : string list) -> Some p
  | (_ : string list) -> None

let () = Option.iter emit (arg_path (Array.to_list Sys.argv))
