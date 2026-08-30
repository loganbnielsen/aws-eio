let ( let* ) = Result.bind

type static = {
  access_key_id : string;
  secret_access_key : string;
  session_token : string option;
}

type source =
  | Static of static
  | Web_identity of { role_arn : string; token_file : string }
      (** EKS IRSA: AssumeRoleWithWebIdentity using a Kubernetes-projected
          service-account JWT. Sun's actual production credential source. *)
  | Container of { relative_uri : string }  (** ECS/Fargate task role. *)
  | Imdsv2  (** EC2 instance profile. Last resort — see [Env_chain]. *)
  | Env_chain
      (** Static env vars, then IRSA env vars, then container creds env var,
          then IMDSv2, in that order. A named, chosen value: [of_env] is the
          only thing that picks it implicitly, as an explicit opt-in. *)

type t = {
  source : source;
  region : string;
}

type resolved = {
  access_key_id : string;
  secret_access_key : string;
  session_token : string option;
  expiration : float option;  (** Unix timestamp; [None] for non-expiring static credentials. *)
}

let of_env ~region () = { source = Env_chain; region }

(* Deliberately non-general: a substring search for "<Tag>text</Tag>" rather
   than a structural XML parse. Works because none of the four leaf tags this
   module reads carry attributes or a namespace prefix in the real (nested)
   AssumeRoleWithWebIdentity response. If a caller ever needs attributes,
   namespaces, or disambiguating same-named tags, switch to a real parser
   (xmlm) instead of growing this function. *)
let extract_tag tag xml =
  let open_tag = "<" ^ tag ^ ">" and close_tag = "</" ^ tag ^ ">" in
  let hlen = String.length xml and olen = String.length open_tag in
  let rec find needle nlen start =
    let nlen' = nlen in
    if start + nlen' > hlen then None
    else if String.sub xml start nlen' = needle then Some start
    else find needle nlen (start + 1)
  in
  match find open_tag olen 0 with
  | None -> None
  | Some i ->
    let content_start = i + olen in
    (match find close_tag (String.length close_tag) content_start with
     | None -> None
     | Some j -> Some (String.sub xml content_start (j - content_start)))

let parse_iso8601_to_unix s =
  match Ptime.of_rfc3339 s with
  | Ok (t, _, _) -> Some (Ptime.to_float_s t)
  | Error _ -> None

let credential_error msg = Aws_error.Credential_error msg

let truncate ~max_len s =
  if String.length s <= max_len then s
  else String.sub s 0 max_len ^ "... (truncated)"

let read_token_file ~fs path =
  try Ok (String.trim (Eio.Path.load Eio.Path.(fs / path)))
  with
  | Eio.Cancel.Cancelled _ as exn -> raise exn
  | (Out_of_memory | Stack_overflow | Sys.Break) as exn -> raise exn
  | exn -> Error (credential_error ("cannot read web identity token file: " ^ Printexc.to_string exn))

(* Regional STS endpoints only (AWS's documented default); AWS_STS_REGIONAL_ENDPOINTS=legacy
   is not implemented, and China-partition hosts (amazonaws.com.cn) are not handled — Sun's
   deploy target is standard-partition EKS. *)
let sts_host region = Printf.sprintf "sts.%s.amazonaws.com" region

(* Deliberately unsigned (Aws_http.request, not signed_request): this call
   bootstraps the caller's first credentials, so it can't require them. *)
let resolve_web_identity ~net ~clock ~fs ~region ~role_arn ~token_file =
  let* token = read_token_file ~fs token_file in
  let body =
    Printf.sprintf
      "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=%s&RoleSessionName=sun-aws-eio&WebIdentityToken=%s"
      (Uri.pct_encode role_arn) (Uri.pct_encode token)
  in
  let uri = Printf.sprintf "https://%s/" (sts_host region) in
  let headers = [ ("Content-Type", "application/x-www-form-urlencoded") ] in
  match Aws_http.request ~net ~clock ~meth:`POST ~uri ~headers ~body () with
  | Error e -> Error e
  | Ok (_, _, resp_body) -> (
    match
      ( extract_tag "AccessKeyId" resp_body,
        extract_tag "SecretAccessKey" resp_body,
        extract_tag "SessionToken" resp_body )
    with
    | Some access_key_id, Some secret_access_key, Some session_token ->
      let expiration = extract_tag "Expiration" resp_body |> Option.map parse_iso8601_to_unix |> Option.join in
      Ok { access_key_id; secret_access_key; session_token = Some session_token; expiration }
    | _ ->
      Error (credential_error
        (Printf.sprintf
           "AssumeRoleWithWebIdentity response missing AccessKeyId/SecretAccessKey/SessionToken: %s"
           (truncate ~max_len:500 resp_body))))

let resolved_of_json_credentials json_body =
  try
    let json = Yojson.Safe.from_string json_body in
    let open Yojson.Safe.Util in
    let access_key_id = json |> member "AccessKeyId" |> to_string in
    let secret_access_key = json |> member "SecretAccessKey" |> to_string in
    let session_token = json |> member "Token" |> to_string_option in
    let expiration =
      json |> member "Expiration" |> to_string_option |> Option.map parse_iso8601_to_unix |> Option.join
    in
    Ok { access_key_id; secret_access_key; session_token; expiration }
  with Yojson.Json_error _ | Yojson.Safe.Util.Type_error _ ->
    Error (credential_error
      (Printf.sprintf "malformed JSON credentials response: %s" (truncate ~max_len:500 json_body)))

(* Short timeout: IMDSv2 is SSRF-adjacent (see aws-audit.md), so failing fast
   beats tolerating a slow/absent link — real IMDS responses are near-instant. *)
let imdsv2_timeout = 1.0

let resolve_imdsv2 ~net ~clock =
  let base = "http://169.254.169.254" in
  match
    Aws_http.request ~net ~clock ~timeout:imdsv2_timeout ~meth:`PUT ~uri:(base ^ "/latest/api/token")
      ~headers:[ ("X-aws-ec2-metadata-token-ttl-seconds", "21600") ]
      ()
  with
  | Error e -> Error e
  | Ok (_, _, token_resp) -> (
    let token_headers = [ ("X-aws-ec2-metadata-token", String.trim token_resp) ] in
    match
      Aws_http.request ~net ~clock ~timeout:imdsv2_timeout ~meth:`GET
        ~uri:(base ^ "/latest/meta-data/iam/security-credentials/")
        ~headers:token_headers ()
    with
    | Error e -> Error e
    | Ok (_, _, role_name_resp) -> (
      let role_name = String.trim role_name_resp in
      match
        Aws_http.request ~net ~clock ~timeout:imdsv2_timeout ~meth:`GET
          ~uri:(base ^ "/latest/meta-data/iam/security-credentials/" ^ role_name)
          ~headers:token_headers ()
      with
      | Error e -> Error e
      | Ok (_, _, creds_json) -> resolved_of_json_credentials creds_json))

let resolve_container ~net ~clock ~relative_uri =
  (* 169.254.170.2 is the fixed ECS/Fargate task metadata endpoint. *)
  let valid_relative_uri =
    String.length relative_uri > 0
    && relative_uri.[0] = '/'
    && String.for_all (fun c -> Char.code c > 0x20 && Char.code c <> 0x7f) relative_uri
  in
  if not valid_relative_uri then
    Error (credential_error "container credentials relative_uri must be an absolute path")
  else
  match Aws_http.request ~net ~clock ~meth:`GET ~uri:("http://169.254.170.2" ^ relative_uri) ~headers:[] () with
  | Error e -> Error e
  | Ok (_, _, creds_json) -> resolved_of_json_credentials creds_json

let resolve_env_chain ~net ~clock ~fs ~region =
  match (Sys.getenv_opt "AWS_ACCESS_KEY_ID", Sys.getenv_opt "AWS_SECRET_ACCESS_KEY") with
  | Some access_key_id, Some secret_access_key ->
    Ok
      { access_key_id; secret_access_key; session_token = Sys.getenv_opt "AWS_SESSION_TOKEN";
        expiration = None }
  | _ -> (
    match (Sys.getenv_opt "AWS_ROLE_ARN", Sys.getenv_opt "AWS_WEB_IDENTITY_TOKEN_FILE") with
    | Some role_arn, Some token_file -> resolve_web_identity ~net ~clock ~fs ~region ~role_arn ~token_file
    | _ -> (
      match Sys.getenv_opt "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" with
      | Some relative_uri -> resolve_container ~net ~clock ~relative_uri
      | None -> resolve_imdsv2 ~net ~clock))

let resolve ~net ~clock ~fs (t : t) =
  match t.source with
  | Static s ->
    Ok
      { access_key_id = s.access_key_id; secret_access_key = s.secret_access_key;
        session_token = s.session_token; expiration = None }
  | Web_identity { role_arn; token_file } ->
    resolve_web_identity ~net ~clock ~fs ~region:t.region ~role_arn ~token_file
  | Container { relative_uri } -> resolve_container ~net ~clock ~relative_uri
  | Imdsv2 -> resolve_imdsv2 ~net ~clock
  | Env_chain -> resolve_env_chain ~net ~clock ~fs ~region:t.region
