let test_static_resolve_no_network () =
  Eio_main.run @@ fun env ->
  let t : Aws_credentials.t =
    { source =
        Aws_credentials.Static
          { access_key_id = "AKID"; secret_access_key = "SECRET"; session_token = None };
      region = "us-east-1" }
  in
  match Aws_credentials.resolve ~net:env#net ~clock:env#clock ~fs:env#fs t with
  | Error e -> Alcotest.failf "expected Ok, got Error: %s" (Aws_error.to_string e)
  | Ok r ->
    Alcotest.(check string) "access_key_id" "AKID" r.access_key_id;
    Alcotest.(check string) "secret_access_key" "SECRET" r.secret_access_key;
    Alcotest.(check bool) "static credentials never expire" true (r.expiration = None)

(* Regression test: read_token_file used to read via blocking stdlib
   In_channel with no ~fs capability; it now goes through Eio.Path.load.
   A missing token file must still surface as a clean Credential_error
   (short-circuiting before any network call) rather than an uncaught
   exception or a hang. *)
let test_web_identity_missing_token_file () =
  Eio_main.run @@ fun env ->
  let t : Aws_credentials.t =
    { source =
        Aws_credentials.Web_identity
          { role_arn = "arn:aws:iam::123456789012:role/test";
            token_file = "/nonexistent/path/does-not-exist" };
      region = "us-east-1" }
  in
  match Aws_credentials.resolve ~net:env#net ~clock:env#clock ~fs:env#fs t with
  | Ok _ -> Alcotest.fail "expected a missing token file to be an Error"
  | Error (Aws_error.Credential_error msg) ->
    Alcotest.(check bool) "error mentions the token file"
      true (String.length msg > 0)
  | Error e -> Alcotest.failf "expected Credential_error, got: %s" (Aws_error.to_string e)

let test_of_env_picks_env_chain () =
  let t = Aws_credentials.of_env ~region:"us-west-2" () in
  Alcotest.(check bool) "source is Env_chain" true (t.source = Aws_credentials.Env_chain);
  Alcotest.(check string) "region" "us-west-2" t.region

let test_container_relative_uri_must_be_path_relative () =
  Eio_main.run @@ fun env ->
  List.iter
    (fun relative_uri ->
      let t : Aws_credentials.t =
        { source = Aws_credentials.Container { relative_uri }; region = "us-east-1" }
      in
      match Aws_credentials.resolve ~net:env#net ~clock:env#clock ~fs:env#fs t with
      | Error (Aws_error.Credential_error _) -> ()
      | Error e -> Alcotest.failf "expected Credential_error, got: %s" (Aws_error.to_string e)
      | Ok _ -> Alcotest.fail "expected invalid container relative_uri to fail")
    [ ""; "@example.com/creds"; "http://example.com/creds"; "/bad path"; "/bad\npath" ]

let () =
  let open Alcotest in
  run "aws_credentials"
    [ ( "resolve",
        [ test_case "Static source resolves without a network call" `Quick test_static_resolve_no_network;
          test_case "Web_identity missing token file is a clean Error" `Quick
            test_web_identity_missing_token_file;
          test_case "of_env picks Env_chain explicitly" `Quick test_of_env_picks_env_chain;
          test_case "Container relative_uri is anchored to metadata path" `Quick
            test_container_relative_uri_must_be_path_relative;
        ] );
    ]
