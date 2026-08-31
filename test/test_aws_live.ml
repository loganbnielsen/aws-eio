(* Live AWS smoke test — see project/tickets/READY_FOR_ENGINEERING/AWS-001.md.
   Skipped unless AWS_EIO_LIVE=1 (the default `dune runtest` must never touch
   a real AWS account). Uses STS GetCallerIdentity: free, no IAM permission
   required, and the cheapest proof a real SigV4 signature is accepted by
   AWS itself rather than just this repo's own vectors/mocks. Needs
   AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (+ optional AWS_SESSION_TOKEN);
   AWS_REGION defaults to us-east-1 since the answer doesn't depend on it. *)

let live_enabled () = Sys.getenv_opt "AWS_EIO_LIVE" = Some "1"

let region () = Option.value (Sys.getenv_opt "AWS_REGION") ~default:"us-east-1"

let contains_substring ~needle haystack =
  let nlen = String.length needle and hlen = String.length haystack in
  let rec go i = i + nlen <= hlen && (String.sub haystack i nlen = needle || go (i + 1)) in
  nlen = 0 || go 0

let test_sts_get_caller_identity () =
  if not (live_enabled ()) then
    Printf.printf "[skip] AWS_EIO_LIVE not set to 1 — skipping live STS smoke test\n%!"
  else
    Eio_main.run @@ fun env ->
    let net = env#net and clock = env#clock in
    let region = region () in
    match Aws.Credentials.(resolve ~net ~clock ~fs:env#fs (of_env ~region ())) with
    | Error e -> Alcotest.failf "credential resolution failed: %s" (Aws.Error.to_string e)
    | Ok creds -> (
      let host = Printf.sprintf "sts.%s.amazonaws.com" region in
      match
        Aws.Http.signed_request ~net ~clock
          ~access_key_id:creds.access_key_id
          ~secret_access_key:creds.secret_access_key
          ?session_token:creds.session_token
          ~region ~service:"sts" ~normalize_path:true
          ~meth:`GET ~host ~path:"/"
          ~query:[ ("Action", "GetCallerIdentity"); ("Version", "2011-06-15") ]
          ()
      with
      | Error e -> Alcotest.failf "STS GetCallerIdentity request failed: %s" (Aws.Error.to_string e)
      | Ok (status, _headers, body) ->
        Alcotest.(check int) "HTTP 200" 200 status;
        Alcotest.(check bool) "response contains GetCallerIdentityResult" true
          (contains_substring ~needle:"GetCallerIdentityResult" body);
        Alcotest.(check bool) "response contains an Account element" true
          (contains_substring ~needle:"<Account>" body);
        Printf.printf "[live] STS GetCallerIdentity succeeded: %s\n%!" body)

let () =
  Alcotest.run "aws_live"
    [ ( "sts",
        [ Alcotest.test_case "GetCallerIdentity succeeds against real AWS" `Quick
            test_sts_get_caller_identity;
        ] );
    ]
