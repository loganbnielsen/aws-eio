(* Validates Aws_sigv4 against AWS's own published SigV4 conformance suite
   (aws-c-auth's tests/aws-signing-test-suite/v4, mirrored under
   test/vectors/ — see test/vectors/../NOTICE-aws-c-auth for attribution).
   Each case directory holds: context.json (credentials/region/service/
   normalize/timestamp), request.txt (raw HTTP request), and the expected
   header-canonical-request.txt / header-string-to-sign.txt /
   header-signature.txt outputs. *)

let vectors_dir = "vectors"

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

(* Trims only a single trailing newline some fixture files have; the AWS
   suite's *.txt files are not newline-consistent, but their significant
   content never has meaningful trailing whitespace. *)
let strip_trailing_newline s =
  let n = String.length s in
  if n > 0 && s.[n - 1] = '\n' then
    if n > 1 && s.[n - 2] = '\r' then String.sub s 0 (n - 2) else String.sub s 0 (n - 1)
  else s

let strip_cr s =
  let n = String.length s in
  if n > 0 && s.[n - 1] = '\r' then String.sub s 0 (n - 1) else s

(* Splits a raw HTTP/1.1 request-line + headers + body. Deliberately does not
   split the request line naively on every space: a request-target may
   itself contain a literal, un-encoded space (see get-space-unnormalized),
   so only the first space (method boundary) and the last space (HTTP
   -version boundary) are treated as delimiters. *)
let parse_request text =
  let lines = String.split_on_char '\n' text |> List.map strip_cr in
  match lines with
  | [] -> failwith "empty request.txt"
  | first_line :: rest ->
    let first_space = String.index first_line ' ' in
    let meth = String.sub first_line 0 first_space in
    let after_meth =
      String.sub first_line (first_space + 1) (String.length first_line - first_space - 1)
    in
    let last_space = String.rindex after_meth ' ' in
    let target = String.sub after_meth 0 last_space in
    let path, query =
      match String.index_opt target '?' with
      | None -> (target, [])
      | Some i ->
        let path = String.sub target 0 i in
        let qs = String.sub target (i + 1) (String.length target - i - 1) in
        let pairs = String.split_on_char '&' qs |> List.filter (fun s -> s <> "") in
        let kv =
          List.map
            (fun pair ->
              match String.index_opt pair '=' with
              | None -> (pair, "")
              | Some j -> (String.sub pair 0 j, String.sub pair (j + 1) (String.length pair - j - 1)))
            pairs
        in
        (path, kv)
    in
    (* Obsolete HTTP/1.1 line folding: a continuation line begins with SP/HT
       and extends the previous header's value, joined by a single space
       (RFC 7230 3.2.4). Verified against get-header-value-multiline. *)
    let is_continuation line = String.length line > 0 && (line.[0] = ' ' || line.[0] = '\t') in
    let rec split_headers acc = function
      | [] -> (List.rev acc, [])
      | "" :: body_lines -> (List.rev acc, body_lines)
      | line :: rest when is_continuation line -> (
        match acc with
        | (k, v) :: acc_rest -> split_headers ((k, v ^ " " ^ String.trim line) :: acc_rest) rest
        | [] -> split_headers acc rest)
      | line :: rest -> (
        match String.index_opt line ':' with
        | None -> split_headers acc rest
        | Some i ->
          let k = String.sub line 0 i in
          let v = String.sub line (i + 1) (String.length line - i - 1) in
          split_headers ((k, v) :: acc) rest)
    in
    let headers, body_lines = split_headers [] rest in
    let body = String.concat "\n" body_lines in
    (meth, path, query, headers, body)

(* "2015-08-30T12:36:00Z" -> "20150830T123600Z" *)
let amz_date_of_iso8601 s =
  String.to_seq s |> Seq.filter (fun c -> c <> '-' && c <> ':') |> String.of_seq

let case_names () =
  Sys.readdir vectors_dir |> Array.to_list
  |> List.filter (fun name -> Sys.is_directory (Filename.concat vectors_dir name))
  |> List.sort compare

let run_case case () =
  let dir = Filename.concat vectors_dir case in
  let ctx = Yojson.Safe.from_file (Filename.concat dir "context.json") in
  let open Yojson.Safe.Util in
  let creds = ctx |> member "credentials" in
  let access_key_id = creds |> member "access_key_id" |> to_string in
  let secret_access_key = creds |> member "secret_access_key" |> to_string in
  let token = creds |> member "token" |> to_string_option in
  (* Some services sign X-Amz-Security-Token as part of the canonical
     request; others add it only after signing. context.json's
     "omit_session_token" (default false = signed) selects which. *)
  let omit_session_token =
    match ctx |> member "omit_session_token" with `Bool b -> b | _ -> false
  in
  let region = ctx |> member "region" |> to_string in
  let service = ctx |> member "service" |> to_string in
  let normalize_path = ctx |> member "normalize" |> to_bool in
  (* Whether the payload hash is also exposed as an explicit
     X-Amz-Content-Sha256 header (required by some services, e.g. S3) versus
     only as the canonical request's trailing hashed-payload line. *)
  let sign_body = ctx |> member "sign_body" |> to_bool in
  let amz_date = ctx |> member "timestamp" |> to_string |> amz_date_of_iso8601 in
  let meth, path, query, headers, body = parse_request (read_file (Filename.concat dir "request.txt")) in
  let payload_hash = Aws_sigv4.sha256_hex body in
  (* X-Amz-Date and X-Amz-Security-Token are added by signing itself, not
     present in request.txt, so they're derived from context.json instead. *)
  let headers = headers @ [ ("X-Amz-Date", amz_date) ] in
  let headers =
    match token with
    | Some t when not omit_session_token -> headers @ [ ("X-Amz-Security-Token", t) ]
    | Some _ | None -> headers
  in
  let headers = if sign_body then headers @ [ ("X-Amz-Content-Sha256", payload_hash) ] else headers in
  let request : Aws_sigv4.signing_request = { meth; path; query; headers; payload_hash; normalize_path } in
  let expected_sig = strip_trailing_newline (read_file (Filename.concat dir "header-signature.txt")) in
  let authz =
    match Aws_sigv4.sign ~access_key_id ~secret_access_key ~region ~service ~amz_date request with
    | Ok authz -> authz
    | Error msg -> Alcotest.fail msg
  in
  let expected_authz_suffix = "Signature=" ^ expected_sig in
  let suffix_len = String.length expected_authz_suffix in
  let has_expected_suffix =
    String.length authz >= suffix_len
    && String.sub authz (String.length authz - suffix_len) suffix_len = expected_authz_suffix
  in
  Alcotest.(check bool)
    (case ^ ": sign() authorization header contains expected signature")
    true has_expected_suffix

let test_sign_rejects_malformed_amz_date () =
  let request : Aws_sigv4.signing_request =
    { meth = "GET";
      path = "/";
      query = [];
      headers = [ ("host", "example.com"); ("x-amz-date", "bad") ];
      payload_hash = Aws_sigv4.sha256_hex "";
      normalize_path = true;
    }
  in
  match
    Aws_sigv4.sign ~access_key_id:"AKID" ~secret_access_key:"SECRET"
      ~region:"us-east-1" ~service:"execute-api" ~amz_date:"bad" request
  with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "expected malformed amz_date to return Error"

let () =
  let cases = case_names () in
  Alcotest.run "aws_sigv4"
    [ ( "aws-c-auth conformance suite",
        List.map (fun case -> Alcotest.test_case case `Quick (run_case case)) cases );
      ( "contract",
        [ Alcotest.test_case "sign rejects malformed amz_date" `Quick
            test_sign_rejects_malformed_amz_date ] );
    ]
