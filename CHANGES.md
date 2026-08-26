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
- Fixed (round 2 of independent review): retry classification only checked the
  `x-amzn-errortype` response header for a throttling exception type; AWS's
  restJson1 protocol spec requires clients to also accept it from a body field
  named `__type` or `code`, since only the header is required on the server side
  — a throttling response from a service/proxy that omits the header silently
  wasn't retried. Now falls back to the response body. `signed_request` had a
  window before `request_once`'s own exception handling (e.g. `amz_date_now`
  failing on a pathological clock) where an exception would raise straight out of
  a function documented as never raising — wrapped in the same catch-and-convert
  pattern, with `Eio.Cancel.Cancelled` deliberately excluded (always re-raised,
  never swallowed into an `Error`, matching the rule this author's `obs-eio`
  documents for its own backend calls; the same fix applied to `request_once`,
  which had the same gap already). README corrected: the `Aws_credentials.source`
  code sample now matches the `.mli`'s actual named `static` type instead of an
  inlined record.
- Fixed (round 3 of independent review — nit): `Aws_error.Signature_error` was
  declared and documented but never actually constructed anywhere. `signed_request`'s
  pre-request setup (deriving the timestamp, computing the SigV4 signature) is now
  split into its own function (`build_signed_headers`) with its own exception
  boundary, reporting failures there as `Signature_error` — categorically distinct
  from `Network_error`, which now only covers the actual HTTP I/O.
- **Fixed (round 4 of independent review — blocker):** every real HTTPS call this
  package makes (`signed_request`, and `Aws_credentials.resolve_web_identity`'s EKS
  IRSA bootstrap) failed at runtime with "The default generator is not yet
  initialized" — `tls-eio`'s handshake needs `Mirage_crypto_rng.default_generator`
  seeded, and nothing in this package (or its dependency graph) ever did that. Every
  prior test used plain HTTP against local mock servers, so this had zero coverage
  through three review rounds; found by the first test that actually attempted a real
  TLS handshake. Fixed in `Aws_tls`: the same `lazy` that builds the client TLS
  wrapper now also calls `Mirage_crypto_rng_unix.use_default ()` first (one-shot,
  idempotent, and only paid by callers who actually touch HTTPS — pure-SigV4-signing
  use of this package never triggers it). New test (`test_aws_tls.ml`) performs a
  real local TLS handshake against a self-signed cert (checked in under
  `test/tls_fixtures/`, generated with `openssl`, not trusted by the system CA
  bundle) and asserts the failure is a certificate-trust failure, not the
  RNG-not-initialized error — verified to actually fail without the fix before being
  committed. Also (nit): documented that `signed_request`'s `?port` only affects the
  TCP connection, not the signed/sent `Host` header (correct for real AWS traffic,
  worth knowing for anything else).
- **Fixed (round 5 of independent review — should-fix):** the round-4 fix used a bare
  `Stdlib.Lazy.t` to compute `Aws_tls`'s TLS wrapper once. `Lazy`'s own `.mli` states
  plainly that concurrent `Lazy.force` from multiple OCaml 5 domains has "unspecified"
  behavior and can raise `CamlinternalLazy.Undefined` — reproduced by an independent
  reviewer (two domains racing to force the same lazy, 8/8 failures in their
  environment). Any caller spawning multiple domains (e.g. a parallel S3/DynamoDB
  worker pool) whose first-ever HTTPS calls landed close together in time could hit
  this. Fixed with double-checked locking over an `Atomic.t` cache instead of a bare
  `lazy` — `Atomic`'s cross-domain safety is guaranteed by the stdlib, unlike
  `Lazy`'s. New test exercises `Aws_tls.https_for_uri` under real concurrent-domain
  contention (an explicit spin-barrier forces every domain to reach the call at the
  same instant, not just spawned close together) against the fixed code.
- **Fixed (round 6 of independent review — should-fix, on the round-5 test itself):**
  the round-5 concurrency test ran *after* an earlier test that already called
  `Aws_tls.https_for_uri` once, warming `default_https_wrapper_cache` to `Some`
  before the "concurrent domains" test's race even started — every domain was
  hitting the lock-free fast path on an already-populated cache, proving nothing
  about the actual first-use contention the test was named for. An independent
  reviewer confirmed this concretely by forcing the cache to stay cold going into
  the domain race and reproducing the original `CamlinternalLazy.Undefined` crash
  5/5 times against the real code — in an environment where round 5's own fix could
  not reproduce it at all. The library code (round 5's double-checked-locking fix)
  was independently re-verified as correct; only the test needed fixing. Fixed by
  resetting the cache to `None` immediately before the race, making the test
  self-contained regardless of execution order.
- **Extracted (post-tag): `Aws_tls` moved out to the standalone `https-eio` package.**
  The exact same TLS wrapper (rounds 4–6 above, plus the CA-bundle logic) turned out
  to also be duplicated byte-for-byte in obs-loki-eio's `Obs_loki_tls`,
  obs-prometheus-eio's `Obs_prometheus_tls`, and Sun's in-tree `Kafka_service_tls` —
  the round-4 RNG-seeding bug had to be manually ported across all four. `Aws_tls` is
  deleted; `aws_http.ml` now depends on `https-eio` directly. `https-eio` also
  replaces the hand-rolled, Linux/macOS-only CA-bundle path list with the maintained
  `ca-certs` package. The TLS regression tests (real handshake, concurrent-domain
  cache race) moved to `https-eio`'s own test suite.
