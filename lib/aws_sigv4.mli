(** AWS Signature Version 4 request signing.

    Implements the algorithm at
    {{:https://docs.aws.amazon.com/general/latest/gr/create-signed-request.html}
    "Create a signed AWS API request"}. Validated against AWS's own published
    conformance suite (aws-c-auth's [tests/aws-signing-test-suite/v4]) —
    see [test/test_aws_sigv4.ml]. Header-based signing only (v1 scope); query
    -string-based presigned-URL signing is not implemented. *)

type request = {
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

val canonical_request : request -> string
val hashed_canonical_request : request -> string

val canonical_uri : normalize_path:bool -> string -> string
(** The exact path bytes used both for signing and for the wire request line.
    [Aws_http] reuses this directly rather than a general-purpose URI
    library, whose more permissive RFC 3986 escaping could byte-for-byte
    disagree with what was signed. *)

val canonical_query_string : (string * string) list -> string
(** Same rationale as {!canonical_uri}: reused verbatim for the wire request's
    query string. *)

val string_to_sign
  :  algorithm:string
  -> amz_date:string
  -> credential_scope:string
  -> request:request
  -> string

val signing_key : secret_access_key:string -> date:string -> region:string -> service:string -> string
(** Raw bytes (not hex) — feed directly into {!signature}. *)

val signature : signing_key:string -> string_to_sign:string -> string
(** Lowercase hex. *)

val authorization_header
  :  access_key_id:string
  -> credential_scope:string
  -> signed_headers:string list
  -> signature:string
  -> string

val sign
  :  access_key_id:string
  -> secret_access_key:string
  -> region:string
  -> service:string
  -> amz_date:string
  -> request
  -> string
(** End-to-end: derives the signing key and returns the value to send as the
    [Authorization] header. [amz_date] must be an ISO 8601 basic-format
    timestamp, e.g. ["20150830T123600Z"] — the date-only credential scope is
    derived from its first 8 characters. Does not add [Authorization] to
    [request.headers] for you; the caller sends it separately. *)
