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

let with_echo_server env f =
  Eio.Switch.run @@ fun sw ->
  let stop, stop_r = Eio.Promise.create () in
  let callback _conn _req body =
    let received = Eio.Buf_read.(parse_exn take_all) body ~max_size:4096 in
    Cohttp_eio.Server.respond_string ~status:`OK ~body:received ()
  in
  let server = Cohttp_eio.Server.make ~callback () in
  let socket = Eio.Net.listen ~backlog:2 ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, 0)) in
  let port =
    match Eio.Net.listening_addr socket with
    | `Tcp (_, port) -> port
    | _ -> failwith "unexpected address family"
  in
  Eio.Fiber.fork_daemon ~sw (fun () ->
      Cohttp_eio.Server.run ~stop ~on_error:(fun _ -> ()) socket server;
      `Stop_daemon);
  Fun.protect ~finally:(fun () -> Eio.Promise.resolve stop_r ()) (fun () -> f ~port)

(* A raw fake server (not cohttp-eio's, which wouldn't let us send a
   deliberately-misleading response) that accepts one connection, reads and
   discards the request, then sends exactly [raw_response] verbatim and
   closes. Used to construct a response that claims a body via
   Content-Length but never actually sends one — the real, legal shape of a
   HEAD response (Content-Length mirrors what GET's body length would be,
   but no body bytes follow) or a 204. If read_response didn't special-case
   these per RFC 7230 3.3.3 rule 1, it would hang reading bytes that will
   never arrive, until the caller's request timeout. *)
let with_raw_server env ~raw_response f =
  Eio.Switch.run @@ fun sw ->
  let socket = Eio.Net.listen ~backlog:2 ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, 0)) in
  let port =
    match Eio.Net.listening_addr socket with
    | `Tcp (_, port) -> port
    | _ -> failwith "unexpected address family"
  in
  Eio.Fiber.fork_daemon ~sw (fun () ->
      Eio.Net.accept_fork ~sw socket
        ~on_error:(fun _ -> ())
        (fun conn _addr ->
          let reader = Eio.Buf_read.of_flow conn ~max_size:65536 in
          let rec drain_headers () =
            match Eio.Buf_read.line reader with "" -> () | _ -> drain_headers ()
          in
          drain_headers ();
          Eio.Flow.copy_string raw_response conn);
      `Stop_daemon);
  f ~port

let test_head_response_never_reads_a_body () =
  Eio_main.run @@ fun env ->
  let raw_response = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" in
  with_raw_server env ~raw_response @@ fun ~port ->
  let result =
    Aws_http.request ~timeout:2.0 ~net:env#net ~clock:env#clock ~meth:`HEAD
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[] ()
  in
  match result with
  | Error e -> Alcotest.fail (Aws_error.to_string e)
  | Ok (status, _headers, body) ->
    Alcotest.(check int) "status" 200 status;
    Alcotest.(check string) "HEAD response body is empty despite Content-Length" "" body

let test_204_response_never_reads_a_body () =
  Eio_main.run @@ fun env ->
  let raw_response = "HTTP/1.1 204 No Content\r\nContent-Length: 50\r\n\r\n" in
  with_raw_server env ~raw_response @@ fun ~port ->
  let result =
    Aws_http.request ~timeout:2.0 ~net:env#net ~clock:env#clock ~meth:`GET
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[] ()
  in
  match result with
  | Error e -> Alcotest.fail (Aws_error.to_string e)
  | Ok (status, _headers, body) ->
    Alcotest.(check int) "status" 204 status;
    Alcotest.(check string) "204 response body is empty despite Content-Length" "" body

(* Regression test for a blocker an independent reviewer caught with a raw
   TCP capture: write_request never sent Content-Length, so a spec-compliant
   server (RFC 7230 3.3.2/3.3.3) treats a request with no Content-Length and
   no Transfer-Encoding as having NO body at all — the bytes still went out
   on the wire, just unattributed to the request. This broke every
   body-carrying call this package makes, including Aws_credentials's own
   EKS IRSA bootstrap (AssumeRoleWithWebIdentity). The server here echoes
   back whatever body it actually received as a request body (via cohttp
   -eio's own request parsing, which strictly follows Content-Length/
   Transfer-Encoding framing) — if this test passes, a real HTTP/1.1 server
   really does see the body. *)
let test_request_body_is_received_by_server () =
  Eio_main.run @@ fun env ->
  with_echo_server env @@ fun ~port ->
  let body = "Action=AssumeRoleWithWebIdentity&RoleArn=foo&WebIdentityToken=bar" in
  let result =
    Aws_http.request ~net:env#net ~clock:env#clock ~meth:`POST
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[ ("Content-Type", "application/x-www-form-urlencoded") ]
      ~body ()
  in
  match result with
  | Error e -> Alcotest.fail (Aws_error.to_string e)
  | Ok (status, _headers, echoed_body) ->
    Alcotest.(check int) "status" 200 status;
    Alcotest.(check string) "server received the exact body sent" body echoed_body

let test_retries_429_once () =
  Eio_main.run @@ fun env ->
  with_retry_server env @@ fun ~port ~hits ->
  let result =
    Aws_http.request ~max_retries:1 ~net:env#net ~clock:env#clock ~meth:`GET
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[] ()
  in
  let status, _headers, body =
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

(* Regression test for a should-fix an independent reviewer caught: AWS's
   restJson1 protocol spec requires clients to accept a service's throttling
   exception type from EITHER the x-amzn-errortype header OR a body field
   named "__type"/"code" — servers are only required to send the header, so
   a client that checks only the header misses throttling responses from
   services/proxies that only put it in the body. This server sends a 400
   with the exception type ONLY in the JSON body, no x-amzn-errortype header
   at all — if retry classification only checked the header, this would
   never be retried. *)
let with_body_only_throttle_server env f =
  Eio.Switch.run @@ fun sw ->
  let hits = ref 0 in
  let stop, stop_r = Eio.Promise.create () in
  let callback _conn _req body =
    ignore (Eio.Buf_read.(parse_exn take_all) body ~max_size:1024);
    incr hits;
    if !hits = 1 then
      Cohttp_eio.Server.respond_string ~status:`Bad_request
        ~body:{|{"__type":"ThrottlingException","message":"Rate exceeded"}|} ()
    else Cohttp_eio.Server.respond_string ~status:`OK ~body:"ok" ()
  in
  let server = Cohttp_eio.Server.make ~callback () in
  let socket = Eio.Net.listen ~backlog:2 ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, 0)) in
  let port =
    match Eio.Net.listening_addr socket with
    | `Tcp (_, port) -> port
    | _ -> failwith "unexpected address family"
  in
  Eio.Fiber.fork_daemon ~sw (fun () ->
      Cohttp_eio.Server.run ~stop ~on_error:(fun _ -> ()) socket server;
      `Stop_daemon);
  Fun.protect ~finally:(fun () -> Eio.Promise.resolve stop_r ()) (fun () -> f ~port ~hits)

let test_retries_body_only_throttling_error () =
  Eio_main.run @@ fun env ->
  with_body_only_throttle_server env @@ fun ~port ~hits ->
  let result =
    Aws_http.request ~max_retries:1 ~net:env#net ~clock:env#clock ~meth:`GET
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[] ()
  in
  let status, _headers, body =
    match result with Ok v -> v | Error e -> Alcotest.fail (Aws_error.to_string e)
  in
  Alcotest.(check int) "status" 200 status;
  Alcotest.(check string) "body" "ok" body;
  Alcotest.(check int) "retried once" 2 !hits

(* Regression test for a gap found while designing s3-eio: read_response has
   always parsed response headers internally (used for retry classification),
   but request/signed_request discarded them before returning to the caller
   — a client that needs Content-Length/ETag/Last-Modified from a HEAD
   response (the entire point of HTTP HEAD) had no way to get them. Fixed by
   threading resp_headers through to the success case; this test pins that
   contract down so it can't silently regress back to (status, body). *)
let test_response_headers_are_returned () =
  Eio_main.run @@ fun env ->
  let raw_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"abc123\"\r\n\r\n" in
  with_raw_server env ~raw_response @@ fun ~port ->
  let result =
    Aws_http.request ~timeout:2.0 ~net:env#net ~clock:env#clock ~meth:`HEAD
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[] ()
  in
  match result with
  | Error e -> Alcotest.fail (Aws_error.to_string e)
  | Ok (_status, headers, _body) ->
    Alcotest.(check (option string)) "ETag header present"
      (Some "\"abc123\"")
      (List.assoc_opt "ETag" headers)

let () =
  Alcotest.run "aws_http"
    [ ( "retry",
        [ Alcotest.test_case "429 is retried" `Quick test_retries_429_once;
          Alcotest.test_case "body-only (no header) throttling error is retried" `Quick
            test_retries_body_only_throttling_error;
        ] );
      ( "request body",
        [ Alcotest.test_case "POST body is received by a spec-compliant server" `Quick
            test_request_body_is_received_by_server;
        ] );
      ( "response body framing",
        [ Alcotest.test_case "HEAD response never reads a body" `Quick
            test_head_response_never_reads_a_body;
          Alcotest.test_case "204 response never reads a body" `Quick test_204_response_never_reads_a_body;
          Alcotest.test_case "response headers are returned to the caller" `Quick
            test_response_headers_are_returned;
        ] );
      ( "wire_resource",
        [ Alcotest.test_case "matches strict SigV4 encoding, not Uri's" `Quick
            test_wire_resource_matches_strict_sigv4_encoding;
          Alcotest.test_case "stays consistent with Aws_sigv4's own encoders" `Quick
            test_wire_resource_consistent_with_aws_sigv4;
          Alcotest.test_case "S3 unnormalized path mode" `Quick test_wire_resource_s3_unnormalized;
        ] );
    ]
