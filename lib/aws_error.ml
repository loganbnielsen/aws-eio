type t =
  | Signature_error of string
  | Network_error of string
  | Credential_error of string

let to_string = function
  | Signature_error msg        -> "signature error: " ^ msg
  | Network_error msg          -> "network error: " ^ msg
  | Credential_error msg       -> "credential error: " ^ msg
