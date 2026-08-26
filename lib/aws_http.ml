let is_retryable status = status = 429 || status >= 500

let rng = Random.State.make_self_init ()
let rng_mutex = Mutex.create ()

(* Exponential backoff with full jitter — AWS's own recommended retry
   strategy (https://docs.aws.amazon.com/general/latest/gr/api-retries.html),
   not a hand-picked scheme. sleep = random(0, min(cap, base * 2^attempt)). *)
let backoff_delay ~attempt ~base ~cap =
  let expo = Float.min cap (base *. (2.0 ** float_of_int attempt)) in
  Mutex.lock rng_mutex;
  Fun.protect ~finally:(fun () -> Mutex.unlock rng_mutex) (fun () -> Random.State.float rng expo)

(* Raw HTTP/1.1 wire I/O — deliberately NOT routed through Cohttp_eio.Client.
   That client always derives the request line's "resource" (path+query) via
   Uri.path_and_query, which decodes then re-encodes using a more permissive
   RFC 3986 "safe character" set than SigV4 requires: Uri leaves
   `! * ' ( ) : @ $ , +` unescaped in a query value, while SigV4's UriEncode()
   requires all of them percent-encoded. Signing one byte sequence and then
   sending a different (Uri-re-encoded) one breaks AWS's server-side
   signature verification for any request whose query contains those
   characters — confirmed by hand: `Uri.of_string "...%21..." |> Uri.to_string`
   comes back with the %21 un-escaped to a literal "!". Aws_sigv4's
   canonical_uri/canonical_query_string are used directly for the wire
   request line below (see signed_request), so what gets signed and what
   gets sent are identical by construction, not by two independent encoders
   agreeing by chance.

   This does mean response parsing is hand-rolled instead of reused from
   cohttp-eio (its low-level Io module isn't part of that library's public
   interface — Cohttp_eio only re-exports Body/Client/Server). Deliberately
   minimal: status line + headers + Content-Length-delimited body, falling
   back to read-until-close if Content-Length is absent. Chunked
   Transfer-Encoding responses are not supported — fine for v1's scope
   (small JSON/XML API calls), not fine if a future caller streams a large
   S3 GetObject response through this path; that's the signal to either
   handle chunked decoding here or reach for a real HTTP/1.1 response parser. *)

let connect ~sw ~net ~scheme ~host ~port =
  let service = match port with Some p -> string_of_int p | None -> scheme in
  match Eio.Net.getaddrinfo_stream ~service net host with
  | addr :: _ -> Eio.Net.connect ~sw net addr
  | [] -> failwith ("Aws_http: cannot resolve host " ^ host)

(* Every HTTP/1.1 request with a body needs Content-Length (or
   Transfer-Encoding, which this client never uses) or a spec-compliant
   server treats it as having no body at all (RFC 7230 3.3.2/3.3.3) — the
   bytes go out on the wire but aren't attributed to the request. Added here
   defensively, not just by signed_request, so every caller through this
   transport (including Aws_credentials's unsigned STS/IMDS calls) gets it
   for free; skipped if the caller already supplied one, to avoid a
   duplicate header when signed_request has already added it (see below —
   signed_request adds it to the *signed* header set too, which must happen
   before Aws_sigv4.sign, so it can't be left to this function alone). *)
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
    | _proto :: code :: _ -> ( try int_of_string code with _ -> failwith ("bad status line: " ^ status_line))
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
  (* RFC 7230 3.3.3 rule 1: a response to HEAD, or any 1xx/204/304, never has
     a body regardless of what the headers say — reading here would either
     misread the next response on a keep-alive connection or, absent
     Content-Length, block until the outer request's timeout for a body that
     was never coming. *)
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
      match Aws_tls.https_for_uri dummy_uri with
      | Error e -> failwith (Aws_tls.error_to_string e)
      | Ok None -> failwith "Aws_http: https requested but TLS wrapper unavailable"
      | Ok (Some wrap) ->
        let raw = (flow :> [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r) in
        (wrap dummy_uri raw :> Eio.Flow.two_way_ty Eio.Std.r))
  in
  write_request flow ~meth ~resource ~headers ~body;
  read_response ~meth flow

(* AWS JSON-protocol services (DynamoDB, etc.) signal throttling as HTTP 400
   with the exception type in the "x-amzn-errortype" response header (e.g.
   "ThrottlingException", "ProvisionedThroughputExceededException") rather
   than a 429/5xx — status-only retry classification silently never retries
   exactly the case retry logic exists for. Per
   https://docs.aws.amazon.com/general/latest/gr/api-retries.html. *)
let retryable_400_error_types =
  [ "throttlingexception"; "throttling"; "provisionedthroughputexceededexception";
    "requestlimitexceeded"; "toomanyrequestsexception"; "requesttimeout"; "idpcommunicationerror" ]

(* AWS's restJson1 protocol spec (smithy.io/2.0/aws/protocols/aws-restjson1-protocol.html)
   requires clients to accept the exception type from EITHER the
   x-amzn-errortype header OR a body field named "__type" or "code" — servers
   are only required to send the header, but older services, proxies, and
   API Gateway passthrough can omit it. Checking the header alone misses
   exactly the throttling responses this retry logic exists to catch. *)
let error_type_from_json_body body =
  match Yojson.Safe.from_string body with
  | exception _ -> None
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

let request_once ~net ~clock ~timeout ~https ~scheme ~host ~port ~meth ~resource ~headers ~body =
  try
    Eio.Time.with_timeout_exn clock timeout (fun () ->
        Eio.Switch.run (fun sw -> Ok (do_once ~sw ~net ~https ~scheme ~host ~port ~meth ~resource ~headers ~body)))
  with
  | Eio.Time.Timeout -> Error (Aws_error.Network_error "request timed out")
  (* Never caught-and-converted, same rule obs-eio documents for its own
     backend calls: a cancellation firing has to unwind the caller's
     structured concurrency correctly, not get reported as an ordinary
     Error result. *)
  | Eio.Cancel.Cancelled _ as exn -> raise exn
  | exn -> Error (Aws_error.Network_error (Printexc.to_string exn))

(* Unsigned request — the escape hatch every credential-bootstrap call needs.
   STS's AssumeRoleWithWebIdentity and the IMDSv2 token/metadata endpoints
   are, by design, not SigV4-signed: signing them would require the
   credentials this call exists to produce. See Aws_credentials.

   [uri] is parsed only for scheme/host/port (never re-encoded into the
   request line) — every caller of this entry point uses a fixed, literal
   URL with no caller-supplied special characters, so Uri's decode/re-encode
   round trip (the thing signed_request avoids) isn't a correctness concern
   here. [?timeout] defaults to 10s; IMDSv2 callers pass a short one — that
   endpoint is SSRF-adjacent (see aws-audit.md) and should fail fast. *)
let request ?(max_retries = 3) ?(timeout = 10.0) ~net ~clock ~meth ~uri ~headers ?body () =
  let u = Uri.of_string uri in
  let https = match Uri.scheme u with Some "https" -> true | _ -> false in
  let scheme = if https then "https" else "http" in
  let host = Uri.host_with_default ~default:"localhost" u in
  let port = Uri.port u in
  let resource = Uri.path_and_query u in
  let rec attempt n =
    match request_once ~net ~clock ~timeout ~https ~scheme ~host ~port ~meth ~resource ~headers ~body with
    | Ok (status, resp_headers, resp_body)
      when is_retryable_response ~status ~headers:resp_headers ~body:resp_body && n < max_retries ->
      Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
      attempt (n + 1)
    | Ok (status, _, resp_body) when status >= 200 && status < 300 -> Ok (status, resp_body)
    | Ok (status, _, resp_body) -> Error (Aws_error.Http_error (status, resp_body))
    | Error _ when n < max_retries ->
      Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
      attempt (n + 1)
    | Error _ as e -> e
  in
  attempt 0

(* Reuses Aws_sigv4's own encoders for the wire request line — see the
   module-top comment for why this must not go through Uri.make/Uri.to_string.
   Exposed for testing: this is the exact function whose earlier absence
   (independently re-deriving the wire URI via Uri.make/Uri.to_string instead
   of reusing these encoders) was the bug. *)
let wire_resource ~normalize_path ~path ~query =
  let uri_path = Aws_sigv4.canonical_uri ~normalize_path path in
  match query with [] -> uri_path | _ -> uri_path ^ "?" ^ Aws_sigv4.canonical_query_string query

let amz_date_now clock =
  match Ptime.of_float_s (Eio.Time.now clock) with
  | None -> invalid_arg "Aws_http.amz_date_now: clock returned an out-of-range time"
  | Some t ->
    let (y, m, d), ((hh, mm, ss), _) = Ptime.to_date_time t in
    Printf.sprintf "%04d%02d%02dT%02d%02d%02dZ" y m d hh mm ss

(* The setup below (amz_date_now, Aws_sigv4.sign) runs before request_once's
   own try/with, which only wraps the actual I/O — so without this outer
   guard, e.g. a clock returning an out-of-range time (amz_date_now's
   Ptime.of_float_s failing) would raise straight out of signed_request,
   contradicting this package's stated "never raises across a public
   boundary" contract for Aws_http specifically (Aws_sigv4, unlike Aws_http,
   is documented as not making that guarantee — see README). Eio.Cancel.Cancelled
   is deliberately excluded from this guarantee and always re-raised, never
   converted to an Error — same rule this author's obs-eio documents for its
   own backend calls: a cancellation has to unwind the caller's structured
   concurrency correctly, not get reported as an ordinary result. *)
let signed_request ?max_retries ?timeout ~net ~clock ~access_key_id ~secret_access_key ?session_token ~region
    ~service ~normalize_path ~meth ~host ?port ~path ?(query = []) ?(extra_headers = []) ?payload_hash ?body () =
  try
    let amz_date = amz_date_now clock in
    let payload_hash =
      match payload_hash with Some h -> h | None -> Aws_sigv4.sha256_hex (Option.value body ~default:"")
    in
    let headers = ("host", host) :: ("x-amz-date", amz_date) :: extra_headers in
    let headers =
      match session_token with None -> headers | Some t -> headers @ [ ("x-amz-security-token", t) ]
    in
    (* Signed here (not left to write_request's defensive add) because it has
       to be part of the header set Aws_sigv4.sign covers, matching every
       POST-with-body case in AWS's own SigV4 conformance suite (e.g.
       post-x-www-form-urlencoded-parameters signs content-length as part of
       SignedHeaders). write_request's own Content-Length handling is a no-op
       here since it's already present, and remains the safety net for the
       unsigned request path (Aws_credentials's STS/IMDS calls), which has no
       signature to keep in sync. *)
    let headers =
      match body with
      | Some b -> headers @ [ ("content-length", string_of_int (String.length b)) ]
      | None -> headers
    in
    let sigv4_request : Aws_sigv4.request =
      { meth = Http.Method.to_string meth; path; query; headers; payload_hash; normalize_path }
    in
    let authorization =
      Aws_sigv4.sign ~access_key_id ~secret_access_key ~region ~service ~amz_date sigv4_request
    in
    let headers = headers @ [ ("Authorization", authorization) ] in
    let resource = wire_resource ~normalize_path ~path ~query in
    let https = true in
    let scheme = "https" in
    let rec attempt n =
      match
        request_once ~net ~clock ~timeout:(Option.value timeout ~default:10.0) ~https ~scheme ~host ~port ~meth
          ~resource ~headers ~body
      with
      | Ok (status, resp_headers, resp_body)
        when is_retryable_response ~status ~headers:resp_headers ~body:resp_body
             && n < Option.value max_retries ~default:3 ->
        Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
        attempt (n + 1)
      | Ok (status, _, resp_body) when status >= 200 && status < 300 -> Ok (status, resp_body)
      | Ok (status, _, resp_body) -> Error (Aws_error.Http_error (status, resp_body))
      | Error _ when n < Option.value max_retries ~default:3 ->
        Eio.Time.sleep clock (backoff_delay ~attempt:n ~base:0.2 ~cap:5.0);
        attempt (n + 1)
      | Error _ as e -> e
    in
    attempt 0
  with
  | Eio.Cancel.Cancelled _ as exn -> raise exn
  | exn -> Error (Aws_error.Network_error (Printexc.to_string exn))
