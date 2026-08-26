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
