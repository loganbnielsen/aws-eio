let listen_loopback ~sw net =
  try Eio.Net.listen ~backlog:2 ~sw net (`Tcp (Eio.Net.Ipaddr.V4.loopback, 0))
  with
  | Unix.Unix_error ((Unix.EPERM | Unix.EACCES), "bind", _) ->
    Alcotest.skip ()

let with_retry_server net f =
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
  let socket = listen_loopback ~sw net in
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

let with_echo_server net f =
  Eio.Switch.run @@ fun sw ->
  let stop, stop_r = Eio.Promise.create () in
  let callback _conn _req body =
    let received = Eio.Buf_read.(parse_exn take_all) body ~max_size:4096 in
    Cohttp_eio.Server.respond_string ~status:`OK ~body:received ()
  in
  let server = Cohttp_eio.Server.make ~callback () in
  let socket = listen_loopback ~sw net in
  let port =
    match Eio.Net.listening_addr socket with
    | `Tcp (_, port) -> port
    | _ -> failwith "unexpected address family"
  in
  Eio.Fiber.fork_daemon ~sw (fun () ->
      Cohttp_eio.Server.run ~stop ~on_error:(fun _ -> ()) socket server;
      `Stop_daemon);
  Fun.protect ~finally:(fun () -> Eio.Promise.resolve stop_r ()) (fun () -> f ~port)

(* A raw fake server (not cohttp-eio's, which won't send a
   deliberately-misleading response): sends exactly [raw_response] verbatim,
   e.g. a HEAD/204 response whose Content-Length claims a body that never
   follows — the legal shape read_response must special-case per RFC 7230
   3.3.3 rule 1, or it would hang until the caller's timeout. *)
let with_raw_server net ~raw_response f =
  Eio.Switch.run @@ fun sw ->
  let socket = listen_loopback ~sw net in
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

let with_capture_server net f =
  Eio.Switch.run @@ fun sw ->
  let seen, set_seen = Eio.Promise.create () in
  let socket = listen_loopback ~sw net in
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
          let request_line = Eio.Buf_read.line reader in
          let rec read_headers acc =
            match Eio.Buf_read.line reader with
            | "" -> List.rev acc
            | line -> read_headers (line :: acc)
          in
          Eio.Promise.resolve set_seen (request_line, read_headers []);
          Eio.Flow.copy_string "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n" conn);
      `Stop_daemon);
  f ~port ~seen

let test_head_response_never_reads_a_body () =
  Eio_main.run @@ fun env ->
  let raw_response = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" in
  with_raw_server env#net ~raw_response @@ fun ~port ->
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
  with_raw_server env#net ~raw_response @@ fun ~port ->
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

(* Without Content-Length, a spec-compliant server (RFC 7230 3.3.2/3.3.3)
   treats a request as having no body at all. Echoes back the body via
   cohttp-eio's own Content-Length-framed parsing, so a pass means a real
   HTTP/1.1 server actually sees it. *)
let test_request_body_is_received_by_server () =
  Eio_main.run @@ fun env ->
  with_echo_server env#net @@ fun ~port ->
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

let test_request_adds_host_header () =
  Eio_main.run @@ fun env ->
  with_capture_server env#net @@ fun ~port ~seen ->
  let result =
    Aws_http.request ~net:env#net ~clock:env#clock ~meth:`GET
      ~uri:(Printf.sprintf "http://127.0.0.1:%d/" port)
      ~headers:[] ()
  in
  (match result with
   | Ok _ -> ()
   | Error e -> Alcotest.fail (Aws_error.to_string e));
  let _request_line, headers = Eio.Promise.await seen in
  Alcotest.(check bool) "Host header includes non-default port" true
    (List.mem (Printf.sprintf "Host: 127.0.0.1:%d" port) headers)

let test_request_rejects_crlf_header () =
  Eio_main.run @@ fun env ->
  let result =
    Aws_http.request ~max_retries:0 ~net:env#net ~clock:env#clock ~meth:`GET
      ~uri:"http://127.0.0.1/"
      ~headers:[ ("X-Bad\r\nInjected", "x") ] ()
  in
  Alcotest.(check bool) "CRLF rejected" true
    (match result with Error (Aws_error.Network_error _) -> true | _ -> false)

let test_retries_429_once () =
  Eio_main.run @@ fun env ->
  with_retry_server env#net @@ fun ~port ~hits ->
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

(* Sends a 400 with the throttling exception type only in the JSON body, no
   x-amzn-errortype header — retry classification must fall back to the body
   field or this would never be retried. *)
let with_body_only_throttle_server net f =
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
  let socket = listen_loopback ~sw net in
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
  with_body_only_throttle_server env#net @@ fun ~port ~hits ->
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

(* Pins the contract that response headers reach the caller (e.g.
   Content-Length/ETag from a HEAD response), not just status and body. *)
let test_response_headers_are_returned () =
  Eio_main.run @@ fun env ->
  let raw_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nETag: \"abc123\"\r\n\r\n" in
  with_raw_server env#net ~raw_response @@ fun ~port ->
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
      ( "request validation",
        [ Alcotest.test_case "Host header is added" `Quick test_request_adds_host_header;
          Alcotest.test_case "CRLF in headers is rejected" `Quick test_request_rejects_crlf_header;
        ] );
      ( "response body framing",
        [ Alcotest.test_case "HEAD response never reads a body" `Quick
            test_head_response_never_reads_a_body;
          Alcotest.test_case "204 response never reads a body" `Quick test_204_response_never_reads_a_body;
          Alcotest.test_case "response headers are returned to the caller" `Quick
            test_response_headers_are_returned;
        ] );
    ]
