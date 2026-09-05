(** Shared error type for every aws-eio-family package. Service-specific backends
    (s3-eio, dynamo-eio) extend this with their own variants rather than
    reinventing HTTP/signature/network/credential failure cases. *)

type t =
  | Signature_error of string    (** SigV4 signing failed *)
  | Network_error of string      (** connection/timeout failure *)
  | Credential_error of string   (** credential resolution failed *)

val to_string : t -> string
