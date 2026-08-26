# Changes

## 0.1.0

- Initial standalone OPAM package: `Aws_sigv4` (AWS Signature Version 4 request
  signing, validated against AWS's own published conformance suite — 37/37 cases),
  `Aws_credentials` (static keys, EKS IRSA `AssumeRoleWithWebIdentity`, ECS/Fargate
  container credentials, EC2 IMDSv2, and an explicit `Env_chain`), and `Aws_http`
  (retrying HTTP transport with SigV4 signing).
- `Aws_http` builds and sends its own HTTP/1.1 requests rather than using
  `cohttp-eio`'s `Client`, which derives the wire request line via
  `Uri.path_and_query` — a more permissive percent-encoding rule than SigV4
  requires (`! * ' ( ) : @ $ , +` are left unescaped by `Uri`, but SigV4's
  `UriEncode()` requires them escaped). A request signed one way and sent another
  fails AWS's signature check. `Aws_http.wire_resource` reuses `Aws_sigv4`'s own
  encoders directly for the wire request line, so what's signed and what's sent are
  identical by construction.
- Retry classification covers both status-based retries (429, 5xx) and DynamoDB
  -style throttling signaled via HTTP 400 with an `x-amzn-errortype` header
  (`ThrottlingException`, `ProvisionedThroughputExceededException`, etc.) — not
  just status codes. Jitter uses a self-seeded `Random.State.t`, not the global
  `Random` module (which is deterministic across fresh processes).
- IMDSv2 calls use a short (1s), fail-fast timeout — that endpoint is
  SSRF-adjacent.
- Fixed (post-tag, same 0.1.0 line, found by independent review): requests with a
  body never sent `Content-Length`, so a spec-compliant server (RFC 7230 3.3.2/3.3.3)
  read them as having no body at all — bytes went out on the wire but weren't
  attributed to the request. Broke every body-carrying call, including this
  package's own EKS IRSA bootstrap (`AssumeRoleWithWebIdentity`). Fixed in
  `write_request` (added defensively for every caller) and `signed_request` (added
  to the signed header set too, matching AWS's own conformance-suite convention for
  POST-with-body requests). Response reading also now correctly treats `HEAD`
  responses and 1xx/204/304 status codes as always bodyless per RFC 7230 3.3.3 rule
  1, instead of falling back to a full-timeout read-until-close for them.
  `cohttp-eio` removed from the library's runtime dependencies (it was never
  actually used outside a comment — moved to test-only, where the mock server in
  `test_aws_http.ml` still needs it).
