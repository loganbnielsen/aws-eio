(** HTTP transport shared by every aws-eio backend: TLS (via {!Aws_tls}),
    exponential backoff with full jitter on retryable failures, and SigV4
    signing.

    Deliberately does not use [cohttp-eio]'s [Client] for the actual wire
    request: that client derives the request line from [Uri.path_and_query],
    which round-trips through a more permissive character-escaping rule than
    SigV4 requires and would send different bytes than {!signed_request}
    signed — see the comment at the top of [aws_http.ml] for how this was
    found and verified. *)

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
  -> (int * string, Aws_error.t) result
(** Unsigned request. This is the escape hatch every credential-bootstrap
    call needs (STS's AssumeRoleWithWebIdentity, the IMDSv2 token/metadata
    endpoints) — those calls happen *before* any credentials exist to sign
    with, so they must never be routed through {!signed_request}. [uri] is
    only ever a fixed literal URL at every call site in this package, so the
    [Uri.path_and_query] re-encoding concern above does not apply here.
    Retries both network failures and requests classified retryable by
    {!Aws_error} status/body inspection (429, 5xx, and 400 responses that
    carry a known-retryable [x-amzn-errortype] such as [ThrottlingException]
    — see [is_retryable_response] in [aws_http.ml]); a non-2xx, non-retryable
    response is returned as [Error (Http_error (status, body))] rather than
    retried. Pass a short [?timeout] for SSRF-adjacent endpoints like IMDS —
    see aws-audit.md. *)

val signed_request
  :  ?max_retries:int
  -> ?timeout:float
  -> net:_ Eio.Net.t
  -> clock:_ Eio.Time.clock
  -> access_key_id:string
  -> secret_access_key:string
  -> ?session_token:string
  -> region:string
  -> service:string
  -> normalize_path:bool
      (** [true] for most services, [false] for S3 — see {!Aws_sigv4.request.normalize_path}. *)
  -> meth:Http.Method.t
  -> host:string
  -> ?port:int
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
  -> (int * string, Aws_error.t) result
(** SigV4-signs the request (adding [Host], [X-Amz-Date], and
    [X-Amz-Security-Token] if [session_token] is given, then [Authorization])
    before sending it over HTTPS. Always HTTPS — AWS APIs do not offer plain
    HTTP endpoints worth signing for. *)

(** {2 Exposed for testing} *)

val wire_resource : normalize_path:bool -> path:string -> query:(string * string) list -> string
(** The exact request-line resource (path[?query]) {!signed_request} both
    signs and sends. Tested directly against characters RFC 3986 permits
    unescaped in a URI but that SigV4 requires escaped (["!*'();:@$,+"]) —
    the class of character that motivated bypassing a general-purpose URI
    library for this. *)
