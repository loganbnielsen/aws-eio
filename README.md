# aws-eio

Eio-native AWS request signing, credential resolution, and HTTP transport — the
foundation layer for AWS-backed packages (an S3 client, a DynamoDB client, etc. build
on this). Not an AWS SDK: no per-service API bindings live here, only what every AWS
API call needs (SigV4 signing, credentials, a retrying HTTP transport).

Originally developed inside the [Sun](https://github.com/loganbnielsen/sun) platform
as the foundation for its planned AWS integrations. Extracted before any in-tree
consumer existed, to settle the package boundary and get the hard parts (SigV4
correctness, credential resolution) right early — unlike this author's other
extracted packages (`kafka-eio`, `obs-eio`, `pg-eio`), which were pulled out after
being used by real callers for a while.

**Caution:** this package has been validated against AWS's own published SigV4
conformance suite and realistic sample credential-provider responses, but it has not
yet been exercised against a live AWS endpoint (no S3/DynamoDB/STS/IMDS call has
actually been made from an environment with real AWS access). Spec-conformant and
internally consistent is not the same claim as "confirmed working against the real
thing" — treat 0.1.0 accordingly until someone reports a real end-to-end call working.

## Build

```bash
eval $(opam env)
dune build
```

## Test

```bash
dune runtest
```

No external infrastructure required for the SigV4 and credential-parsing tests. The
retry test in `test_aws_http.ml` spins up a local mock HTTP server (no network).

## Public API

### `Aws_error`

```ocaml
type t =
  | Http_error of int * string
  | Signature_error of string
  | Network_error of string
  | Credential_error of string

val to_string : t -> string
```

### `Aws_sigv4`

Pure — no I/O, no Eio dependency. Implements
[Create a signed AWS API request](https://docs.aws.amazon.com/general/latest/gr/create-signed-request.html).
Header-based signing only; query-string presigned-URL signing is not implemented.

```ocaml
type request = {
  meth : string;
  path : string;                       (* raw, unencoded *)
  query : (string * string) list;      (* raw, unencoded *)
  headers : (string * string) list;    (* must include "host" and the date header *)
  payload_hash : string;               (* hex sha256 of the body, or "UNSIGNED-PAYLOAD" *)
  normalize_path : bool;               (* true for most services; false for S3 — see below *)
}

val sign
  :  access_key_id:string
  -> secret_access_key:string
  -> region:string
  -> service:string
  -> amz_date:string                    (* e.g. "20150830T123600Z" *)
  -> request
  -> string                             (* Authorization header value *)
```

`canonical_request`, `string_to_sign`, `signing_key`, `signature`,
`authorization_header`, `sha256_hex`, `canonical_uri`, `canonical_query_string` are
also exposed — used both by `Aws_http` (to guarantee the wire request matches what was
signed, see below) and by `test/test_aws_sigv4.ml`, which checks every one of them
against AWS's own conformance suite (mirrored into `test/vectors/`, Apache-2.0, see
`NOTICE-aws-c-auth`).

**`normalize_path` — the one SigV4 detail most from-scratch implementations get
wrong.** Most services expect the canonical URI to be RFC-3986 normalized (dot
segments removed, consecutive slashes collapsed). S3 is the documented exception: an
object key may legitimately contain `//` or `..` as literal bytes, so S3 requests must
sign the literal path unchanged (still percent-encoded byte-for-byte). There is no
default — every caller states which behavior their service needs. Verified against
`aws-c-auth`'s paired `*-normalized`/`*-unnormalized` fixtures.

### `Aws_credentials`

```ocaml
type source =
  | Static of { access_key_id : string; secret_access_key : string; session_token : string option }
  | Web_identity of { role_arn : string; token_file : string }   (* EKS IRSA *)
  | Container of { relative_uri : string }                        (* ECS/Fargate task role *)
  | Imdsv2                                                        (* EC2 *)
  | Env_chain                                                     (* tries the above, in that order *)

type t = { source : source; region : string }

type resolved = {
  access_key_id : string;
  secret_access_key : string;
  session_token : string option;
  expiration : float option;   (* Unix timestamp; None = does not expire *)
}

val of_env : region:string -> unit -> t
val resolve : net:_ Eio.Net.t -> clock:_ Eio.Time.clock -> t -> (resolved, Aws_error.t) result
```

No implicit default source — every `t` states one explicitly. `of_env` is the one
place this module picks `Env_chain` for you, and it does so because the caller opted
into that convenience by calling it, not because `source` was left unset.

`resolve` does not cache or auto-refresh; a caller holding a `t` across many requests
should track `resolved.expiration` and re-resolve before it lapses.

**IRSA before IMDSv2.** A service running in EKS with IAM Roles for Service Accounts
authenticates via `AssumeRoleWithWebIdentity`, not the EC2 instance metadata service.
`Env_chain` checks for IRSA's env vars (`AWS_ROLE_ARN`/`AWS_WEB_IDENTITY_TOKEN_FILE`)
before falling through to container credentials and finally IMDSv2.

`AssumeRoleWithWebIdentity` and the IMDSv2 token/metadata calls are unsigned by
design — signing them would require the credentials they exist to produce. They go
through `Aws_http.request` (unsigned), never `Aws_http.signed_request`. IMDSv2 calls
use a short (1s), fail-fast timeout — that endpoint is SSRF-adjacent.

### `Aws_http`

```ocaml
val request
  :  ?max_retries:int (* default 3 *) -> ?timeout:float (* default 10.0s *)
  -> net:_ Eio.Net.t -> clock:_ Eio.Time.clock
  -> meth:Http.Method.t -> uri:string -> headers:(string * string) list -> ?body:string
  -> unit -> (int * string, Aws_error.t) result

val signed_request
  :  ?max_retries:int -> ?timeout:float
  -> net:_ Eio.Net.t -> clock:_ Eio.Time.clock
  -> access_key_id:string -> secret_access_key:string -> ?session_token:string
  -> region:string -> service:string -> normalize_path:bool
  -> meth:Http.Method.t -> host:string -> ?port:int -> path:string
  -> ?query:(string * string) list -> ?extra_headers:(string * string) list
  -> ?payload_hash:string (* override the computed hash, e.g. "UNSIGNED-PAYLOAD" *)
  -> ?body:string
  -> unit -> (int * string, Aws_error.t) result
```

**Does not use `cohttp-eio`'s `Client`.** That client always derives the wire request
line from `Uri.path_and_query`, which decodes then re-encodes using a more permissive
RFC 3986 "safe character" set than SigV4 requires — confirmed by hand:
`Uri.of_string "...%21..." |> Uri.to_string` comes back with the `%21` un-escaped to a
literal `!`. A request signed with one encoding and sent with another fails AWS's
signature check for any query value containing `! * ' ( ) : @ $ , +`. `Aws_http`
instead constructs the `Http.Request.t` directly (`resource` set from
`Aws_sigv4.canonical_uri`/`canonical_query_string`, the same functions used for
signing — see `wire_resource`, exposed for testing) and writes/reads the HTTP/1.1
wire format itself.

Response parsing is intentionally minimal: `Content-Length`-delimited bodies (what
every AWS JSON/XML API call in this package's scope returns), falling back to
read-until-close otherwise. Chunked `Transfer-Encoding` responses are not handled —
fine for small API calls, not fine for streaming a large S3 object response.

TLS via a private `Aws_tls` (system CA bundle). Retries network failures and requests
classified retryable by status or response body (429, any 5xx, and 400 responses
carrying a known-retryable `x-amzn-errortype` such as `ThrottlingException` —
DynamoDB's actual throttling signal is a 400, not a 429/5xx) with exponential backoff
and full jitter — AWS's own
[documented retry strategy](https://docs.aws.amazon.com/general/latest/gr/api-retries.html),
using a self-seeded `Random.State.t` (the global `Random` module is deterministic
across fresh processes, which would defeat jitter's purpose across a fleet restarting
together). A non-2xx, non-retryable response is `Error (Http_error (status, body))`,
never retried.

## Design Notes

- `Db`-style naming collision risk: `Aws_error`/`Aws_sigv4`/`Aws_http`/`Aws_credentials`/
  `Aws_tls` are all reasonably specific compound names, lower collision risk than a
  bare single word would be — no `Obs`-style rename needed here.
- All public APIs return `(_, Aws_error.t) result`; nothing raises across a public
  boundary.

## Out of Scope (v1)

- Query-string-based (presigned URL) SigV4 signing — header-based signing only.
- SigV4a (multi-region signing) — single-region SigV4 only.
- Credential caching/auto-refresh — `resolve` is called fresh each time; a caller that
  wants caching wraps it.
- `AWS_STS_REGIONAL_ENDPOINTS=legacy` (opting back into the global `sts.amazonaws.com`
  endpoint) — regional STS endpoints only.
- China-partition STS hosts (`amazonaws.com.cn`) — standard partition only.
- Container credential provider variants beyond `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
  (ECS task roles) — the full-URI and identity-token variants are deferred until
  there's a real caller that needs them.
- Chunked `Transfer-Encoding` on responses.
- A unified `Aws_eio.Config.t` — left to each backend package to compose.
