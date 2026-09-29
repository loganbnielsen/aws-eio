(** [Aws] is the sole public entry point: use [Aws.Error]/[Aws.Sigv4]/
    [Aws.Http]/[Aws.Credentials]. Each one is an alias for the module that
    implements it ([Aws_error], [Aws_sigv4], [Aws_http], [Aws_credentials]),
    so every interface here exists once: the hand-written copies this file used
    to carry had to be edited in two places for each public change, which is
    what the aliases remove.

    Aliases, not [module type of]: a signature copy gives every datatype a
    *fresh* type, so [Aws.Error.t] would no longer be the [Aws_error.t] the
    library's own functions return -- switching to [module type of] broke the
    test that hands an [Aws_error.t] to [Aws.Error.to_string]. The alias keeps
    the identities, and its cost is that the implementing modules are named
    here rather than hidden behind a copy. *)

module Error = Aws_error
module Sigv4 = Aws_sigv4
module Http = Aws_http
module Credentials = Aws_credentials
