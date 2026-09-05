(** HTTP transport shared by every aws-eio backend: TLS (via [https-eio]),
    exponential backoff with full jitter on retryable failures, and SigV4
    signing.

    Deliberately does not use [cohttp-eio]'s [Client] for the actual wire
    request: that client derives the request line from [Uri.path_and_query],
    which round-trips through a more permissive character-escaping rule than
    SigV4 requires and would send different bytes than {!signed_request}
    signed — see [aws_http.ml]. *)

val request
  :  ?max_retries:int  (** default 3 *)
  -> ?timeout:float  (** default 10.0s *)
  -> net:_ Eio.Net.t
  -> clock:_ Eio.Time.clock
  -> meth:Http.Method.t
  -> uri:string
  -> headers:(string * string) list
  -> ?body:string
  -> unit
  -> (int * (string * string) list * string, Aws_error.t) result
(** Unsigned escape hatch for credential-bootstrap calls (STS
    AssumeRoleWithWebIdentity, IMDSv2) that happen before any credentials
    exist to sign with. [uri] is always a fixed literal URL at every call
    site, so re-encoding is not a concern here. Retries network failures and
    responses classified retryable by {!Aws_error} status/body inspection
    (429, 5xx, and 400s with a known-retryable [x-amzn-errortype]); once a
    response is received and is not (or is no longer) retryable, [Ok
    (status, headers, body)] is returned regardless of status code — the
    caller owns interpreting a non-2xx status. [Error] means no usable HTTP
    response was ever received: [uri] must be an absolute [http://] or
    [https://] URL with a host, unsupported or relative URIs return [Error
    (Network_error _)], and a signature/network/timeout failure returns the
    corresponding {!Aws_error} variant. Pass a short [?timeout] for
    SSRF-adjacent endpoints like IMDS. *)

val signed_request
  :  ?max_retries:int
  -> ?timeout:float
  -> ?scheme:[ `Http | `Https ]
      (** Default [`Https]. Use [`Http] only for local/S3-compatible custom
          endpoints that require signed requests without TLS. *)
  -> net:_ Eio.Net.t
  -> clock:_ Eio.Time.clock
  -> access_key_id:string
  -> secret_access_key:string
  -> ?session_token:string
  -> region:string
  -> service:string
  -> normalize_path:bool
      (** [true] for most services, [false] for S3 — see {!Aws_sigv4.signing_request.normalize_path}. *)
  -> meth:Http.Method.t
  -> host:string
  -> ?port:int
      (** Used to open the TCP connection and, when non-default, included in
          the signed and sent [Host] header. Must be between 1 and 65535
          when supplied. *)
  -> path:string
  -> ?query:(string * string) list
  -> ?extra_headers:(string * string) list
  -> ?payload_hash:string
      (** Override the computed [sha256_hex body] — pass the literal
          ["UNSIGNED-PAYLOAD"] for S3's streaming-upload mode (still sent as
          the [X-Amz-Content-Sha256] value the caller should also add to
          [extra_headers] if the target service requires that header). *)
  -> ?body:string
  -> unit
  -> (int * (string * string) list * string, Aws_error.t) result
(** SigV4-signs the request (adding [Host], [X-Amz-Date], and
    [X-Amz-Security-Token] if [session_token] is given, then [Authorization])
    before sending it. Defaults to HTTPS; plain HTTP is only for explicitly
    configured local/S3-compatible endpoints. Response headers are returned
    exactly as the server sent them (no case-normalization — compare case-
    insensitively). Same [Ok]/[Error] contract as {!request} above: any
    received response — success or not — comes back as [Ok (status,
    headers, body)], and [Error] means no usable response was received.
    Re-signs (fresh [X-Amz-Date]/[Authorization]) on every retry attempt,
    not just the first — with a long [?timeout] and several retries, reusing
    one signature across the whole sequence could let [X-Amz-Date] drift
    outside AWS's clock-skew tolerance by the final attempt, which would
    surface as an ordinary [Ok] response with no hint the real cause was a
    stale signature. *)
