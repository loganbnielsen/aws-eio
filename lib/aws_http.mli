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

(** The request being signed, as one value: the method, where to send it, and
    what to send. [port] opens the TCP connection and, when non-default, is
    included in the signed and sent [Host] header (1-65535). [payload_hash]
    overrides the computed [sha256_hex body] — pass the literal
    ["UNSIGNED-PAYLOAD"] for S3's streaming-upload mode, still sending it as
    the [X-Amz-Content-Sha256] value. *)
type request =
  { meth : Http.Method.t
  ; host : string
  ; port : int option
  ; path : string
  ; query : (string * string) list
  ; extra_headers : (string * string) list
  ; payload_hash : string option
  ; body : string option
  }

val signed_request
  :  ?max_retries:int
  -> ?timeout:float
  -> ?scheme:[ `Http | `Https ]
      (** Default [`Https]. Use [`Http] only for local/S3-compatible custom
          endpoints that require signed requests without TLS. *)
  -> net:_ Eio.Net.t
  -> clock:_ Eio.Time.clock
  -> credentials:Aws_signing_credentials.t
      (** A resolved credential set — what {!Aws_credentials.resolve} returns. *)
  -> region:string
  -> service:string
      (** Also decides path signing: S3 (and S3-compatible endpoints, which
          use the same service name) signs the path as written, every other
          service signs the normalized form, so there is no [normalize_path]
          argument for a caller to get wrong. *)
  -> request:request
  -> unit
  -> (int * (string * string) list * string, Aws_error.t) result
(** SigV4-signs the request (adding [Host], [X-Amz-Date], and
    [X-Amz-Security-Token] if the credentials carry one, then [Authorization])
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
