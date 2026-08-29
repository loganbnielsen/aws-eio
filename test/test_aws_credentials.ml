let test_static_resolve_no_network () =
  Eio_main.run @@ fun env ->
  let t : Aws_credentials.t =
    { source =
        Aws_credentials.Static
          { access_key_id = "AKID"; secret_access_key = "SECRET"; session_token = None };
      region = "us-east-1" }
  in
  match Aws_credentials.resolve ~net:env#net ~clock:env#clock t with
  | Error e -> Alcotest.failf "expected Ok, got Error: %s" (Aws_error.to_string e)
  | Ok r ->
    Alcotest.(check string) "access_key_id" "AKID" r.access_key_id;
    Alcotest.(check string) "secret_access_key" "SECRET" r.secret_access_key;
    Alcotest.(check bool) "static credentials never expire" true (r.expiration = None)

let test_of_env_picks_env_chain () =
  let t = Aws_credentials.of_env ~region:"us-west-2" () in
  Alcotest.(check bool) "source is Env_chain" true (t.source = Aws_credentials.Env_chain);
  Alcotest.(check string) "region" "us-west-2" t.region

let () =
  let open Alcotest in
  run "aws_credentials"
    [ ( "resolve",
        [ test_case "Static source resolves without a network call" `Quick test_static_resolve_no_network;
          test_case "of_env picks Env_chain explicitly" `Quick test_of_env_picks_env_chain;
        ] );
    ]
