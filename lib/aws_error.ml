type t =
  | Http_error of int * string
  | Signature_error of string
  | Network_error of string
  | Credential_error of string

let to_string = function
  | Http_error (status, body)  -> Printf.sprintf "http error %d: %s" status body
  | Signature_error msg        -> "signature error: " ^ msg
  | Network_error msg          -> "network error: " ^ msg
  | Credential_error msg       -> "credential error: " ^ msg
