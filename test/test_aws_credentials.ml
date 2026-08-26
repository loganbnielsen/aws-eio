(* Web_identity/Container/Imdsv2 can't be exercised against real AWS/IMDS
   endpoints from a unit test — these tests validate the response-parsing
   helpers behind them against realistic sample payloads instead (STS's
   AssumeRoleWithWebIdentity response shape is from AWS's own published API
   reference example; the IMDS shape matches its documented security
   -credentials response). *)

let sts_response_xml =
  {|<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE</SessionToken>
      <Expiration>2015-08-30T12:36:00Z</Expiration>
    </Credentials>
    <SubjectFromWebIdentityToken>amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A</SubjectFromWebIdentityToken>
    <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:app1</AssumedRoleId>
    <Provider>www.amazon.com</Provider>
    <Audience>client.5498841531868486423.1548@apps.example.com</Audience>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>|}

let imds_response_json =
  {|{
  "Code": "Success",
  "LastUpdated": "2023-01-01T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "IQoJb3JpZ2luX2VjEXAMPLETOKEN",
  "Expiration": "2023-01-01T06:00:00Z"
}|}

let test_extract_tag_finds_nested_leaf () =
  Alcotest.(check (option string)) "AccessKeyId" (Some "AKIAIOSFODNN7EXAMPLE")
    (Aws_credentials.extract_tag "AccessKeyId" sts_response_xml);
  Alcotest.(check (option string)) "SecretAccessKey"
    (Some "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    (Aws_credentials.extract_tag "SecretAccessKey" sts_response_xml);
  Alcotest.(check (option string)) "Expiration" (Some "2015-08-30T12:36:00Z")
    (Aws_credentials.extract_tag "Expiration" sts_response_xml)

let test_extract_tag_missing () =
  Alcotest.(check (option string)) "missing tag" None
    (Aws_credentials.extract_tag "NotPresent" sts_response_xml)

let test_resolved_of_json_credentials () =
  match Aws_credentials.resolved_of_json_credentials imds_response_json with
  | Error e -> Alcotest.failf "expected Ok, got Error: %s" (Aws_error.to_string e)
  | Ok r ->
    Alcotest.(check string) "access_key_id" "ASIAIOSFODNN7EXAMPLE" r.access_key_id;
    Alcotest.(check string) "secret_access_key" "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      r.secret_access_key;
    Alcotest.(check (option string)) "session_token" (Some "IQoJb3JpZ2luX2VjEXAMPLETOKEN") r.session_token;
    Alcotest.(check bool) "expiration present" true (Option.is_some r.expiration)

let test_resolved_of_json_credentials_malformed () =
  match Aws_credentials.resolved_of_json_credentials "not json at all" with
  | Ok _ -> Alcotest.fail "expected Error for malformed JSON"
  | Error _ -> ()

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
    [ ( "response parsing",
        [ test_case "extract_tag finds nested leaf text" `Quick test_extract_tag_finds_nested_leaf;
          test_case "extract_tag returns None for missing tag" `Quick test_extract_tag_missing;
          test_case "resolved_of_json_credentials (IMDS/ECS shape)" `Quick test_resolved_of_json_credentials;
          test_case "resolved_of_json_credentials rejects malformed JSON" `Quick
            test_resolved_of_json_credentials_malformed;
        ] );
      ( "resolve",
        [ test_case "Static source resolves without a network call" `Quick test_static_resolve_no_network;
          test_case "of_env picks Env_chain explicitly" `Quick test_of_env_picks_env_chain;
        ] );
    ]
