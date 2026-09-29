(** [Aws] is the entry point: [Aws.Error], [Aws.Sigv4], [Aws.Http],
    [Aws.Credentials]. Each one is the module that implements it
    ([Aws_error], [Aws_sigv4], [Aws_http], [Aws_credentials]), so every
    interface exists once and nothing has to keep two copies of it in step.

    The modules themselves are public as well, including
    [Aws_signing_credentials] — the credential values a signature needs, which
    lives outside [Aws_credentials] because that module already depends on
    [Aws_http] for its STS and IMDS calls, and a type both it and the signer
    name cannot depend on the other. *)

module Error = Aws_error
module Sigv4 = Aws_sigv4
module Http = Aws_http
module Credentials = Aws_credentials
