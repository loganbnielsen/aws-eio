(** [Aws] is the sole public entry point: use [Aws.Error]/[Aws.Sigv4]/
    [Aws.Http]/[Aws.Credentials]. The flat [Aws_error]/[Aws_sigv4]/
    [Aws_http]/[Aws_credentials]/[Aws_sigv4_core] modules are implementation
    detail ([private_modules] in [lib/dune]) and are not visible to callers
    outside this library. *)

module Error : sig
  (** Shared error type for every aws-eio-family package. Service-specific
      backends (s3-eio, dynamo-eio) extend this with their own variants
      rather than reinventing HTTP/signature/network/credential failure
      cases. *)

  type t =
    | Signature_error of string    (** SigV4 signing failed *)
    | Network_error of string      (** connection/timeout failure *)
    | Credential_error of string   (** credential resolution failed *)

  val to_string : t -> string
end

module Sigv4 : sig
  (** AWS Signature Version 4 request signing.

      Implements the algorithm at
      {{:https://docs.aws.amazon.com/general/latest/gr/create-signed-request.html}
      "Create a signed AWS API request"}. Validated against AWS's own
      published conformance suite (aws-c-auth's
      [tests/aws-signing-test-suite/v4]) — see [test/test_aws_sigv4.ml].
      Header-based signing only (v1 scope); query-string-based presigned-URL
      signing is not implemented. *)

  type signing_request = {
    meth : string;
    path : string;
        (** Raw, unencoded absolute path, e.g. ["/example space/"]. Percent-encoded
            internally — a path segment that is already percent-encoded (e.g.
            forwarded verbatim from an incoming request without decoding first)
            will be double-encoded. Decode before passing it in if it might
            already carry [%XX] sequences. *)
    query : (string * string) list;
        (** Raw, unencoded key/value pairs. Percent-encoded and sorted internally —
            do not pre-encode. *)
    headers : (string * string) list;
        (** Raw header name/value pairs. Must include ["host"] and the request's
            date header (["x-amz-date"]); include ["x-amz-security-token"] here
            too if signing with temporary credentials — it is just another
            header from this module's point of view. *)
    payload_hash : string;
        (** Lowercase hex SHA256 of the request body, or the literal string
            ["UNSIGNED-PAYLOAD"] for S3's streaming-upload mode. *)
    normalize_path : bool;
        (** [true] for most services; [false] for S3. See the field doc in
            [aws_sigv4.ml] for why S3 is the documented exception. *)
  }

  val sha256_hex : string -> string

  val canonical_uri : normalize_path:bool -> string -> string
  (** The exact path bytes used both for signing and for the wire request line.
      [Http] reuses this directly rather than a general-purpose URI
      library, whose more permissive RFC 3986 escaping could byte-for-byte
      disagree with what was signed. *)

  val canonical_query_string : (string * string) list -> string
  (** Same rationale as {!canonical_uri}: reused verbatim for the wire request's
      query string. *)

  val sign
    :  access_key_id:string
    -> secret_access_key:string
    -> region:string
    -> service:string
    -> amz_date:string
    -> signing_request
    -> (string, string) result
  (** End-to-end: derives the signing key and returns the value to send as the
      [Authorization] header. [amz_date] must be an ISO 8601 basic-format
      timestamp, e.g. ["20150830T123600Z"] — the date-only credential scope is
      derived from its first 8 characters. Returns [Error _] if [amz_date] is
      malformed. Does not add [Authorization] to [request.headers] for you; the
      caller sends it separately. *)
end

module Http : sig
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
    -> (int * (string * string) list * string, Error.t) result
  (** Unsigned escape hatch for credential-bootstrap calls (STS
      AssumeRoleWithWebIdentity, IMDSv2) that happen before any credentials
      exist to sign with. [uri] is always a fixed literal URL at every call
      site, so re-encoding is not a concern here. Retries network failures and
      responses classified retryable by {!Error} status/body inspection
      (429, 5xx, and 400s with a known-retryable [x-amzn-errortype]); once a
      response is received and is not (or is no longer) retryable, [Ok
      (status, headers, body)] is returned regardless of status code — the
      caller owns interpreting a non-2xx status. [Error] means no usable HTTP
      response was ever received: [uri] must be an absolute [http://] or
      [https://] URL with a host, unsupported or relative URIs return [Error
      (Network_error _)], and a signature/network/timeout failure returns the
      corresponding {!Error} variant. Pass a short [?timeout] for
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
        (** [true] for most services, [false] for S3 — see {!Sigv4.signing_request.normalize_path}. *)
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
    -> (int * (string * string) list * string, Error.t) result
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
end

module Credentials : sig
  (** AWS credential resolution. Every [t] states its source explicitly — there
      is no implicit default, the same way every Kafka config states its
      security posture explicitly via [Kafka_security.t]. *)

  type static = {
    access_key_id : string;
    secret_access_key : string;
    session_token : string option;
  }

  type source =
    | Static of static
    | Web_identity of { role_arn : string; token_file : string }
        (** EKS IRSA (AssumeRoleWithWebIdentity). Sun's actual production
            credential source. *)
    | Container of { relative_uri : string }  (** ECS/Fargate task role. *)
    | Imdsv2  (** EC2 instance profile. *)
    | Env_chain
        (** Static env vars, then IRSA env vars, then container env var, then
            IMDSv2, in that order. A chosen value, not a fallback default. *)

  type t = {
    source : source;
    region : string;
  }

  type resolved = {
    access_key_id : string;
    secret_access_key : string;
    session_token : string option;
    expiration : float option;  (** Unix timestamp; [None] = does not expire. *)
  }

  val of_env : region:string -> unit -> t
  (** [{ source = Env_chain; region }] — the one place this module picks
      [Env_chain] for you, and it does so as an explicit named choice a caller
      opted into by calling this function, not a silent default. *)

  val resolve
    :  net:_ Eio.Net.t
    -> clock:_ Eio.Time.clock
    -> fs:_ Eio.Path.t
    -> t
    -> (resolved, Error.t) result
  (** Performs whatever network call [t.source] requires (none for [Static]).
      [fs] is used only for [Web_identity] (and [Env_chain] when it resolves to
      [Web_identity]), to read the projected service-account token file through
      Eio's filesystem capability instead of blocking stdlib I/O.
      Callers that hold a [t] across many requests should cache the result and
      re-resolve once [resolved.expiration] approaches — this function does not
      cache or refresh on your behalf. *)
end
