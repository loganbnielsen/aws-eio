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

let test_request_rejects_invalid_uri () =
  Eio_main.run @@ fun env ->
  List.iter
    (fun uri ->
      let result =
        Aws_http.request ~max_retries:0 ~net:env#net ~clock:env#clock ~meth:`GET ~uri ~headers:[] ()
      in
      Alcotest.(check bool) uri true
        (match result with Error (Aws_error.Network_error _) -> true | _ -> false))
    [ "file:///tmp/aws.sock"; "/latest/meta-data" ]

let test_request_rejects_invalid_port () =
  Eio_main.run @@ fun env ->
  List.iter
    (fun port ->
      let result =
        Aws_http.signed_request ~max_retries:0 ~net:env#net ~clock:env#clock
          ~access_key_id:"test" ~secret_access_key:"test" ~region:"us-east-1"
          ~service:"s3" ~normalize_path:false ~meth:`GET ~host:"localhost" ~port ~path:"/" ()
      in
      Alcotest.(check bool) (string_of_int port) true
        (match result with Error (Aws_error.Network_error _) -> true | _ -> false))
    [ 0; -1; 65536 ]

(* Regression test: an unresolvable host used to raise a bare Failure that
   retryable_exception didn't recognize, so a transient DNS hiccup was
   unconditionally classified Permanent instead of Retryable. This doesn't
   assert on retry count (no server to count hits against — DNS resolution
   itself is what's failing) — it just confirms the failure still surfaces
   as a clean Error within a bounded time, not an uncaught exception or a
   hang, now that connect raises a dedicated exception on that path. *)
let test_unresolvable_host_is_a_clean_error () =
  Eio_main.run @@ fun env ->
  match
    Eio.Time.with_timeout env#clock 15.0 (fun () ->
      Ok (Aws_http.request ~max_retries:1 ~net:env#net ~clock:env#clock ~meth:`GET
            ~uri:"http://sun-eio-test-nonexistent-host.invalid/" ~headers:[] ()))
  with
  | Error `Timeout -> Alcotest.fail "unresolvable host should fail fast, not hang"
  | Ok (Error (Aws_error.Network_error _)) -> ()
  | Ok (Error e) -> Alcotest.failf "expected Network_error, got: %s" (Aws_error.to_string e)
  | Ok (Ok _) -> Alcotest.fail "expected an unresolvable host to fail"

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

(* Regression test: is_retryable/is_success classify via Http.Status.t's
   named ~70-code grouping, which falls back to `Code n for anything else
   (529 isn't one of the ~14 5xx codes Http.Status.of_int names). The
   fallback must still classify by number, or an uncommon-but-real 5xx
   would silently stop being retried and an uncommon 2xx would stop being
   treated as success. *)
let with_uncommon_status_retry_server net f =
  Eio.Switch.run @@ fun sw ->
  let hits = ref 0 in
  let stop, stop_r = Eio.Promise.create () in
  let callback _conn _req body =
    ignore (Eio.Buf_read.(parse_exn take_all) body ~max_size:1024);
    incr hits;
    let status = if !hits = 1 then `Code 529 else `OK in
    Cohttp_eio.Server.respond_string ~status ~body:(if !hits = 1 then "overloaded" else "ok") ()
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

let test_retries_uncommon_5xx_code () =
  Eio_main.run @@ fun env ->
  with_uncommon_status_retry_server env#net @@ fun ~port ~hits ->
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
          Alcotest.test_case "uncommon 5xx code (not individually named) is retried" `Quick
            test_retries_uncommon_5xx_code;
          Alcotest.test_case "body-only (no header) throttling error is retried" `Quick
            test_retries_body_only_throttling_error;
          Alcotest.test_case "unresolvable host fails cleanly, not with a bare Failure" `Quick
            test_unresolvable_host_is_a_clean_error;
        ] );
      ( "request body",
        [ Alcotest.test_case "POST body is received by a spec-compliant server" `Quick
            test_request_body_is_received_by_server;
        ] );
      ( "request validation",
        [ Alcotest.test_case "Host header is added" `Quick test_request_adds_host_header;
          Alcotest.test_case "CRLF in headers is rejected" `Quick test_request_rejects_crlf_header;
          Alcotest.test_case "invalid URI is rejected before network I/O" `Quick
            test_request_rejects_invalid_uri;
          Alcotest.test_case "invalid port is rejected before network I/O" `Quick
            test_request_rejects_invalid_port;
        ] );
      ( "response body framing",
        [ Alcotest.test_case "HEAD response never reads a body" `Quick
            test_head_response_never_reads_a_body;
          Alcotest.test_case "204 response never reads a body" `Quick test_204_response_never_reads_a_body;
          Alcotest.test_case "response headers are returned to the caller" `Quick
            test_response_headers_are_returned;
        ] );
    ]
