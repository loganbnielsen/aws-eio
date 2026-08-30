(* Classified via Http.Status.t's own grouping (already a dependency of
   this library) instead of ad hoc numeric-range checks, so "is this a
   success"/"is this retryable" has one shared, correct definition instead
   of the range check being re-derived (and previously duplicated) at each
   call site. Http.Status.of_int only names ~70 well-known codes and falls
   back to `Code n for everything else (e.g. 209, or a 5xx a non-AWS proxy
   invents) — that fallback is handled explicitly by number so an uncommon
   but valid code still classifies the same as the original numeric-range
   check did, not silently as neither success nor retryable. *)
let is_success status =
  match Http.Status.of_int status with
  | #Http.Status.success -> true
  | `Code n -> n >= 200 && n < 300
  | _ -> false

let is_retryable status =
  match Http.Status.of_int status with
  | `Too_many_requests -> true
  | #Http.Status.server_error -> true
  | `Code n -> n >= 500
  | _ -> false

let rng = Random.State.make_self_init ()
let rng_mutex = Mutex.create ()

(* Exponential backoff with full jitter, per AWS's recommended retry strategy:
   sleep = random(0, min(cap, base * 2^attempt)). *)
let backoff_delay ~attempt ~base ~cap =
  let expo = Float.min cap (base *. (2.0 ** float_of_int attempt)) in
  Mutex.lock rng_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock rng_mutex) (fun () -> Random.State.float rng expo)

(* Raw HTTP/1.1 wire I/O, not Cohttp_eio.Client: that client re-derives the
   request line via Uri.path_and_query, which re-encodes with a laxer RFC
   3986 charset than SigV4 requires, so signed and sent bytes could diverge.
   Aws_sigv4's own encoders are used for the wire line instead (see
   signed_request), making them identical by construction.

   Response parsing is correspondingly hand-rolled: status line + headers +
   Content-Length-delimited body (read-until-close if absent). Chunked
   Transfer-Encoding is not supported — fine for small JSON/XML calls, not
   for streaming a large response through this path. *)

(* A distinct exception (not a bare Failure) so retryable_exception can tell
   "DNS didn't resolve, possibly transiently" apart from a genuine programmer
   error — the empty-address-list case is exactly the kind of transient
   connectivity blip the retry loop exists for. *)
exception Dns_resolution_failed of string

let connect ~sw ~net ~scheme ~host ~port =
  let service = match port with Some p -> string_of_int p | None -> scheme in
  match Eio.Net.getaddrinfo_stream ~service net host with
  | addr :: _ -> Eio.Net.connect ~sw net addr
  | [] -> raise (Dns_resolution_failed ("Aws_http: cannot resolve host " ^ host))

let has_crlf s = String.exists (fun c -> c = '\r' || c = '\n') s

let host_header ~scheme ~host ~port =
  let host =
    if String.contains host ':' && not (String.starts_with ~prefix:"[" host) then
      "[" ^ host ^ "]"
    else host
  in
  match (scheme, port) with
  | "http", Some 80 | "https", Some 443 | _, None -> host
  | _, Some port -> Printf.sprintf "%s:%d" host port

let validate_port = function
  | Some port when port <= 0 || port > 65535 ->
    Error (Printf.sprintf "port must be between 1 and 65535, got %d" port)
  | _ -> Ok ()

let validate_wire_inputs ~host ~resource ~headers =
  if has_crlf host then Error "host contains a CR or LF character"
  else if has_crlf resource then Error "request resource contains a CR or LF character"
  else
    match List.find_opt (fun (k, v) -> has_crlf k || has_crlf v) headers with
    | None -> Ok ()
    | Some (k, _) -> Error ("header contains a CR or LF character: " ^ k)

let parse_uri uri =
  let parsed_uri = Uri.of_string uri in
  match Uri.scheme parsed_uri with
  | Some ("http" | "https" as scheme) -> (
    match Uri.host parsed_uri with
    | Some host when host <> "" ->
      let https = scheme = "https" in
      Ok (https, scheme, host, Uri.port parsed_uri, Uri.path_and_query parsed_uri)
    | _ -> Error "URI must include a host")
  | Some scheme -> Error ("unsupported URI scheme: " ^ scheme)
  | None -> Error "URI must include an http or https scheme"

(* A body without Content-Length is treated as bodyless by a spec-compliant
   server (RFC 7230 3.3.2/3.3.3). Added here defensively so every caller
   (including unsigned STS/IMDS calls) gets it; skipped if already present,
   since signed_request must add it to the *signed* header set itself. *)
let write_request flow ~meth ~resource ~headers ~body =
  let has_content_length = List.exists (fun (k, _) -> String.lowercase_ascii k = "content-length") headers in
  let headers =
    match body with
    | Some b when not has_content_length -> headers @ [ ("Content-Length", string_of_int (String.length b)) ]
    | _ -> headers
  in
  let request_line = Printf.sprintf "%s %s HTTP/1.1\r\n" (Http.Method.to_string meth) resource in
  let header_lines = headers |> List.map (fun (k, v) -> Printf.sprintf "%s: %s\r\n" k v) |> String.concat "" in
  Eio.Flow.copy_string (request_line ^ header_lines ^ "\r\n" ^ Option.value body ~default:"") flow

let read_response ~meth flow =
  let reader = Eio.Buf_read.of_flow flow ~max_size:(16 * 1024 * 1024) in
  let status_line = Eio.Buf_read.line reader in
  let status =
    match String.split_on_char ' ' status_line with
    | _proto :: code :: _ -> (
      try int_of_string code with Failure _ -> failwith ("bad status line: " ^ status_line))
    | _ -> failwith ("malformed status line: " ^ status_line)
  in
  let rec read_headers acc =
    match Eio.Buf_read.line reader with
    | "" -> List.rev acc
    | line -> (
      match String.index_opt line ':' with
      | None -> read_headers acc
      | Some i ->
        let k = String.trim (String.sub line 0 i) in
        let v = String.trim (String.sub line (i + 1) (String.length line - i - 1)) in
        read_headers ((k, v) :: acc))
  in
  let headers = read_headers [] in
  let content_length =
    List.find_map
      (fun (k, v) -> if String.lowercase_ascii k = "content-length" then int_of_string_opt v else None)
      headers
  in
  (* RFC 7230 3.3.3 rule 1: HEAD responses and 1xx/204/304 never have a body
     regardless of headers; reading one would misread the next response or
     block waiting for a body that never comes. *)
  let is_bodyless_by_spec = meth = `HEAD || status = 204 || status = 304 || status < 200 in
  let body =
    if is_bodyless_by_spec then ""
    else
      match content_length with
      | Some n -> Eio.Buf_read.take n reader
      | None -> ( try Eio.Buf_read.take_all reader with End_of_file -> "")
  in
  (status, headers, body)

let do_once ~sw ~net ~https ~scheme ~host ~port ~meth ~resource ~headers ~body =
  let flow = connect ~sw ~net ~scheme ~host ~port in
  let flow =
    if not https then (flow :> Eio.Flow.two_way_ty Eio.Std.r)
    else (
      let dummy_uri = Uri.make ~scheme:"https" ~host () in
      match Https_eio.https_for_uri dummy_uri with
      | Error e -> failwith (Https_eio.error_to_string e)
      | Ok None -> failwith "Aws_http: https requested but TLS wrapper unavailable"
      | Ok (Some wrap) ->
        let raw = (flow :> [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r) in
        (wrap dummy_uri raw :> Eio.Flow.two_way_ty Eio.Std.r))
  in
  write_request flow ~meth ~resource ~headers ~body;
  read_response ~meth flow

(* AWS JSON-protocol services (DynamoDB, etc.) signal throttling as HTTP 400
   with the exception type in "x-amzn-errortype", not a 429/5xx — status-only
   retry classification would silently never retry it. *)
let retryable_400_error_types =
  [ "throttlingexception"; "throttling"; "provisionedthroughputexceededexception";
    "requestlimitexceeded"; "toomanyrequestsexception"; "requesttimeout"; "idpcommunicationerror" ]

(* Falls back to a body "__type"/"code" field: some proxies and API Gateway
   passthroughs omit the x-amzn-errortype header. *)
let error_type_from_json_body body =
  match Yojson.Safe.from_string body with
  | exception Yojson.Json_error _ -> None
  | json -> (
    let field name =
      match Yojson.Safe.Util.member name json with
      | `String s -> Some s
      | _ -> None
    in
    match field "__type" with Some _ as v -> v | None -> field "code")

let is_retryable_response ~status ~headers ~body =
  is_retryable status
  ||
  match status with
  | 400 -> (
    let error_type =
      match List.find_opt (fun (k, _) -> String.lowercase_ascii k = "x-amzn-errortype") headers with
      | Some (_, v) -> Some v
      | None -> error_type_from_json_body body
    in
    match error_type with
    | None -> false
    | Some v ->
      let v = String.lowercase_ascii v in
      (* strip an optional "namespace#" prefix some services prepend *)
      let v = match String.index_opt v '#' with Some i -> String.sub v (i + 1) (String.length v - i - 1) | None -> v in
      List.mem v retryable_400_error_types)
  | _ -> false

type request_failure =
  | Retryable of Aws_error.t
  | Permanent of Aws_error.t

let retryable_exception = function
  | Unix.Unix_error _ | Sys_error _ | Dns_resolution_failed _ -> true
  | _ -> false

let error_of_failure = function
  | Retryable e | Permanent e -> e

let request_once ~net ~clock ~timeout ~https ~scheme ~host ~port ~meth ~resource ~headers ~body =
  match validate_port port with
  | Error msg -> Error (Permanent (Aws_error.Network_error msg))
  | Ok () -> (
    match validate_wire_inputs ~host ~resource ~headers with
    | Error msg -> Error (Permanent (Aws_error.Network_error msg))
    | Ok () -> (
      try
        Eio.Time.with_timeout_exn clock timeout (fun () ->
            Eio.Switch.run (fun sw -> Ok (do_once ~sw ~net ~https ~scheme ~host ~port ~meth ~resource ~headers ~body)))
      with
      | Eio.Time.Timeout -> Error (Retryable (Aws_error.Network_error "request timed out"))
      (* Re-raised, never converted to Error: cancellation must unwind the
         caller's structured concurrency, not read as an ordinary failure. *)
      | Eio.Cancel.Cancelled _ as exn -> raise exn
      | (Out_of_memory | Stack_overflow | Sys.Break) as exn -> raise exn
      | exn ->
        let error = Aws_error.Network_error (Printexc.to_string exn) in
        Error (if retryable_exception exn then Retryable error else Permanent error)))

(* Unsigned escape hatch for credential-bootstrap calls (STS
   AssumeRoleWithWebIdentity, IMDSv2) that can't require credentials they
   exist to produce. [uri] is parsed only for scheme/host/port, never
   re-encoded — safe since every caller here uses a fixed literal URL.
   [?timeout] defaults to 10s; IMDSv2 callers pass a short one (SSRF-adjacent,
   see aws-audit.md). *)
let request ?(max_retries = 3) ?(timeout = 10.0) ~net ~clock ~meth ~uri ~headers ?body () =
  match parse_uri uri with
  | Error msg -> Error (Aws_error.Network_error msg)
  | Ok (https, scheme, host, port, resource) ->
    let headers =
      if List.exists (fun (k, _) -> String.lowercase_ascii k = "host") headers then headers
      else ("Host", host_header ~scheme ~host ~port) :: headers
    in
    let rec attempt n =
      match request_once ~net ~clock ~timeout ~https ~scheme ~host ~port ~meth ~resource ~headers ~body with
      | Ok (status, resp_headers, resp_body)
        when is_retryable_response ~status ~headers:resp_headers ~body:resp_body && n < max_retries ->
        Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
        attempt (n + 1)
      | Ok (status, resp_headers, resp_body) when is_success status ->
        Ok (status, resp_headers, resp_body)
      | Ok (status, _, resp_body) -> Error (Aws_error.Http_error (status, resp_body))
      | Error (Retryable _) when n < max_retries ->
        Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
        attempt (n + 1)
      | Error failure -> Error (error_of_failure failure)
    in
    attempt 0

(* Reuses Aws_sigv4's own encoders so the wire request line matches exactly
   what was signed — see the module-top comment. *)
let wire_resource ~normalize_path ~path ~query =
  let uri_path = Aws_sigv4.canonical_uri ~normalize_path path in
  match query with [] -> uri_path | _ -> uri_path ^ "?" ^ Aws_sigv4.canonical_query_string query

let amz_date_now clock =
  match Ptime.of_float_s (Eio.Time.now clock) with
  | None -> invalid_arg "Aws_http.amz_date_now: clock returned an out-of-range time"
  | Some t ->
    let (y, m, d), ((hh, mm, ss), _) = Ptime.to_date_time t in
    Printf.sprintf "%04d%02d%02dT%02d%02d%02dZ" y m d hh mm ss

(* Everything through Aws_sigv4.sign is pure/offline, so a failure here is
   reported as Signature_error, not folded into the I/O try/with below.
   Eio.Cancel.Cancelled is always re-raised, never converted to an Error. *)
let build_signed_headers ~clock ~access_key_id ~secret_access_key ?session_token ~region ~service ~normalize_path
    ~meth ~host_header ~path ~query ~extra_headers ~payload_hash ~body () =
  try
    let amz_date = amz_date_now clock in
    let payload_hash =
      match payload_hash with Some h -> h | None -> Aws_sigv4.sha256_hex (Option.value body ~default:"")
    in
    let headers =
      ("host", host_header) :: ("x-amz-date", amz_date) :: ("x-amz-content-sha256", payload_hash) :: extra_headers
    in
    let headers =
      match session_token with None -> headers | Some t -> headers @ [ ("x-amz-security-token", t) ]
    in
    (* Added here (not left to write_request) so it's part of the header set
       Aws_sigv4.sign covers, matching AWS's SigV4 conformance suite. *)
    let headers =
      match body with
      | Some b -> headers @ [ ("content-length", string_of_int (String.length b)) ]
      | None -> headers
    in
    let sigv4_request : Aws_sigv4.signing_request =
      { meth = Http.Method.to_string meth; path; query; headers; payload_hash; normalize_path }
    in
    match Aws_sigv4.sign ~access_key_id ~secret_access_key ~region ~service ~amz_date sigv4_request with
    | Error msg -> Error (Aws_error.Signature_error msg)
    | Ok authorization -> Ok (headers @ [ ("Authorization", authorization) ])
  with
  | Eio.Cancel.Cancelled _ as exn -> raise exn
  | (Out_of_memory | Stack_overflow | Sys.Break) as exn -> raise exn
  | exn -> Error (Aws_error.Signature_error (Printexc.to_string exn))

let signed_request ?max_retries ?timeout ?(scheme = `Https) ~net ~clock ~access_key_id ~secret_access_key ?session_token ~region
    ~service ~normalize_path ~meth ~host ?port ~path ?(query = []) ?(extra_headers = []) ?payload_hash ?body () =
  let scheme = match scheme with `Http -> "http" | `Https -> "https" in
  let host_header = host_header ~scheme ~host ~port in
  (* Re-signed on every attempt, not just the first — reusing one
     signature across retries risks X-Amz-Date drifting outside AWS's
     clock-skew tolerance by the final retry under a long timeout. Pure
     computation (no I/O), so re-signing is cheap. *)
  let sign () =
    build_signed_headers ~clock ~access_key_id ~secret_access_key ?session_token ~region ~service ~normalize_path
      ~meth ~host_header ~path ~query ~extra_headers ~payload_hash ~body ()
  in
  try
    let resource = wire_resource ~normalize_path ~path ~query in
    let https = scheme = "https" in
    let rec attempt n =
      match sign () with
      | Error _ as e -> e
      | Ok headers -> (
        match
          request_once ~net ~clock ~timeout:(Option.value timeout ~default:10.0) ~https ~scheme ~host ~port ~meth
            ~resource ~headers ~body
        with
        | Ok (status, resp_headers, resp_body)
          when is_retryable_response ~status ~headers:resp_headers ~body:resp_body
               && n < Option.value max_retries ~default:3 ->
          Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
          attempt (n + 1)
        | Ok (status, resp_headers, resp_body) when is_success status ->
          Ok (status, resp_headers, resp_body)
        | Ok (status, _, resp_body) -> Error (Aws_error.Http_error (status, resp_body))
        | Error (Retryable _) when n < Option.value max_retries ~default:3 ->
          Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
          attempt (n + 1)
        | Error failure -> Error (error_of_failure failure))
    in
    attempt 0
  with
  | Eio.Cancel.Cancelled _ as exn -> raise exn
  | (Out_of_memory | Stack_overflow | Sys.Break) as exn -> raise exn
  | exn -> Error (Aws_error.Network_error (Printexc.to_string exn))
