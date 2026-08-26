let with_retry_server env f =
  Eio.Switch.run @@ fun sw ->
  let hits = ref 0 in
  let stop, stop_r = Eio.Promise.create () in
  let callback _conn _req body =
    ignore (Eio.Buf_read.(parse_exn take_all) body ~max_size:1024);
    incr hits;
    let status, body =
      if !hits = 1 then (`Too_many_requests, "throttle") else (`OK, "ok")
    in
    Cohttp_eio.Server.respond_string ~status ~body ()
  in
  let server = Cohttp_eio.Server.make ~callback () in
  let socket =
    Eio.Net.listen ~backlog:2 ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, 0))
  in
  let port =
    match Eio.Net.listening_addr socket with
    | `Tcp (_, port) -> port
    | _ -> failwith "unexpected address family"
  in
  Eio.Fiber.fork_daemon ~sw (fun () ->
      Cohttp_eio.Server.run ~stop ~on_error:(fun _ -> ()) socket server;
      `Stop_daemon);
  Fun.protect
    ~finally:(fun () -> Eio.Promise.resolve stop_r ())
    (fun () -> f ~port ~hits)

let test_retries_429_once () =
  Eio_main.run @@ fun env ->
  with_retry_server env @@ fun ~port ~hits ->
  let result =
    Aws_http.request ~max_retries:1 ~net:env#net ~clock:env#clock ~meth:`GET
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[] ()
  in
  let status, body =
    match result with
    | Ok v -> v
    | Error e -> Alcotest.fail (Aws_error.to_string e)
  in
  Alcotest.(check int) "status" 200 status;
  Alcotest.(check string) "body" "ok" body;
  Alcotest.(check int) "retried once" 2 !hits

(* Regression test for the bug an independent reviewer caught: signed_request
   used to build the wire URI via Uri.make/Uri.to_string, a *different*
   encoder than Aws_sigv4 signs with. RFC 3986 permits `!*'();:@$,+` unescaped
   in a URI; SigV4's UriEncode() requires all of them percent-encoded — a
   value containing them would be signed one way and sent another, breaking
   AWS's signature check. wire_resource now reuses Aws_sigv4's own encoders
   directly, so this can no longer drift. *)
let test_wire_resource_matches_strict_sigv4_encoding () =
  let resource =
    Aws_http.wire_resource ~normalize_path:true ~path:"/"
      ~query:[ ("Param", "a!b*c'd(e)f;g:h@i$j,k+l") ]
  in
  Alcotest.(check string) "matches strict SigV4 percent-encoding (not Uri's more permissive rule)"
    "/?Param=a%21b%2Ac%27d%28e%29f%3Bg%3Ah%40i%24j%2Ck%2Bl" resource

let test_wire_resource_consistent_with_aws_sigv4 () =
  (* wire_resource must never independently re-derive encoding — it should be
     built from exactly the same Aws_sigv4 encoders used for signing. *)
  let path = "/example space/" and query = [ ("a", "b c"); ("x", "1 2") ] in
  let expected =
    Aws_sigv4.canonical_uri ~normalize_path:true path ^ "?" ^ Aws_sigv4.canonical_query_string query
  in
  Alcotest.(check string) "wire_resource == Aws_sigv4's own canonical encoders" expected
    (Aws_http.wire_resource ~normalize_path:true ~path ~query)

let test_wire_resource_s3_unnormalized () =
  (* S3 mode: no dot-segment removal/slash-collapsing, still percent-encoded. *)
  let resource = Aws_http.wire_resource ~normalize_path:false ~path:"//example//" ~query:[] in
  Alcotest.(check string) "S3 unnormalized path preserved" "//example//" resource

let () =
  Alcotest.run "aws_http"
    [ ("retry", [ Alcotest.test_case "429 is retried" `Quick test_retries_429_once ]);
      ( "wire_resource",
        [ Alcotest.test_case "matches strict SigV4 encoding, not Uri's" `Quick
            test_wire_resource_matches_strict_sigv4_encoding;
          Alcotest.test_case "stays consistent with Aws_sigv4's own encoders" `Quick
            test_wire_resource_consistent_with_aws_sigv4;
          Alcotest.test_case "S3 unnormalized path mode" `Quick test_wire_resource_s3_unnormalized;
        ] );
    ]
