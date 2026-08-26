(lang dune 3.0)
(name aws-eio)
(version 0.1.0)
(generate_opam_files true)

(package
 (name aws-eio)
 (synopsis "Eio-native AWS SigV4 request signing, credential resolution, and HTTP transport")
 (description "\
The foundation layer for Eio-native AWS-backed packages (s3-eio, dynamo-eio, and any
future AWS-backed package build on this): AWS Signature Version 4 request signing,
credential resolution (static keys, EKS IRSA, ECS/Fargate container credentials,
EC2 IMDSv2), and a retrying HTTP transport. Not an AWS SDK — no per-service API
bindings live here, only what every AWS API call needs. Header-based SigV4 signing
only (no presigned-URL/query-string signing, no SigV4a); response parsing is
Content-Length-delimited only (no chunked Transfer-Encoding).")
 (maintainers "lbendtlynielsen@gmail.com")
 (authors "lbendtly")
 (license "MIT")
 (homepage "https://github.com/loganbnielsen/aws-eio")
 (bug_reports "https://github.com/loganbnielsen/aws-eio/issues")
 (source (github loganbnielsen/aws-eio))
 (depends
  (ocaml (>= 5.4.0))
  (eio (>= 1.3))
  (digestif (>= 1.3.0))
  (uri (>= 4.4.0))
  (http (>= 6.0.0))
  (tls-eio (>= 2.1.0))
  (x509 (>= 1.0.0))
  (domain-name (>= 0.5.0))
  (ptime (>= 1.2.0))
  (yojson (>= 3.0.0))
  (eio_main (and (>= 1.3) :with-test))
  (cohttp-eio (and (>= 6.2.0) :with-test))
  (alcotest :with-test)
  (odoc :with-doc)))
