type request = {
  meth : string;
  path : string;
  query : (string * string) list;
  headers : (string * string) list;
  payload_hash : string;
  normalize_path : bool;
      (** Most services expect the canonical URI RFC-3986 normalized (dot
          segments removed, consecutive slashes collapsed). S3 is the
          documented exception — object keys may legitimately contain "//" or
          ".." literally, so S3 requests set this [false] to sign the literal
          path (still percent-encoded, just not collapsed). No default. *)
}

let sha256_hex s = Digestif.SHA256.(to_hex (digest_string s))

let hmac_raw ~key data = Digestif.SHA256.(to_raw_string (hmac_string ~key data))
let hmac_hex ~key data = Digestif.SHA256.(to_hex (hmac_string ~key data))

let is_unreserved = function
  | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '.' | '_' | '~' -> true
  | _ -> false

(* AWS's UriEncode(): percent-encode every byte except unreserved chars, uppercase hex. *)
let uri_encode s =
  let buf = Buffer.create (String.length s * 3) in
  String.iter
    (fun c ->
      if is_unreserved c then Buffer.add_char buf c
      else Buffer.add_string buf (Printf.sprintf "%%%02X" (Char.code c)))
    s;
  Buffer.contents buf

(* S3's documented exception: no dot-segment removal, no slash collapsing —
   an object key may legitimately contain "//" or ".." as literal bytes. Each
   '/'-delimited segment is still percent-encoded byte-for-byte. Verified
   against aws-c-auth's `*-unnormalized` conformance fixtures. *)
let unnormalized_path raw_path =
  raw_path |> String.split_on_char '/' |> List.map uri_encode |> String.concat "/"

(* RFC 3986-style remove_dot_segments, plus AWS's additional collapsing of
   consecutive slashes. Verified against aws-c-auth's `*-normalized` fixtures. *)
let normalized_path raw_path =
  let ends_with_slash =
    String.length raw_path > 1 && raw_path.[String.length raw_path - 1] = '/'
  in
  let segments = String.split_on_char '/' raw_path in
  let stack =
    List.fold_left
      (fun stack seg ->
        match seg with
        | "" | "." -> stack
        | ".." -> ( match stack with _ :: rest -> rest | [] -> [])
        | s -> s :: stack)
      [] segments
  in
  match List.rev stack with
  | [] -> "/"
  | segs ->
    let body = segs |> List.map uri_encode |> String.concat "/" in
    "/" ^ body ^ if ends_with_slash then "/" else ""

let canonical_uri ~normalize_path raw_path =
  if normalize_path then normalized_path raw_path else unnormalized_path raw_path

(* Sort by (encoded key, encoded value) — a plain [compare] on the tuple is
   already lexicographic key-then-value, matching AWS's stated rule ("sort
   the parameters alphabetically by key name after encoding"). *)
let canonical_query_string query =
  query
  |> List.map (fun (k, v) -> (uri_encode k, uri_encode v))
  |> List.sort compare
  |> List.map (fun (k, v) -> k ^ "=" ^ v)
  |> String.concat "&"

let trim_and_collapse_spaces s =
  let s = String.trim s in
  let buf = Buffer.create (String.length s) in
  let in_space = ref false in
  String.iter
    (fun c ->
      if c = ' ' then begin
        if not !in_space then Buffer.add_char buf ' ';
        in_space := true
      end
      else begin
        Buffer.add_char buf c;
        in_space := false
      end)
    s;
  Buffer.contents buf

(* Returns (canonical headers block, sorted lowercase signed-header names).
   Duplicate header names are folded into one comma-joined value, values kept
   in original request order (only the header names are sorted). *)
let canonical_headers headers =
  let lowered =
    List.map (fun (k, v) -> (String.lowercase_ascii k, trim_and_collapse_spaces v)) headers
  in
  let names_in_order =
    List.fold_left (fun acc (k, _) -> if List.mem k acc then acc else acc @ [ k ]) [] lowered
  in
  let grouped =
    List.map
      (fun name ->
        let values = List.filter_map (fun (k, v) -> if k = name then Some v else None) lowered in
        (name, String.concat "," values))
      names_in_order
  in
  let sorted = List.sort (fun (k1, _) (k2, _) -> compare k1 k2) grouped in
  let signed_headers = List.map fst sorted in
  let canonical = sorted |> List.map (fun (k, v) -> k ^ ":" ^ v ^ "\n") |> String.concat "" in
  (canonical, signed_headers)

let canonical_request req =
  let uri = canonical_uri ~normalize_path:req.normalize_path req.path in
  let canonical_query = canonical_query_string req.query in
  let canonical_headers_, signed_headers = canonical_headers req.headers in
  String.concat "\n"
    [ req.meth; uri; canonical_query; canonical_headers_;
      String.concat ";" signed_headers; req.payload_hash ]

let hashed_canonical_request req = sha256_hex (canonical_request req)

let string_to_sign ~algorithm ~amz_date ~credential_scope ~request =
  String.concat "\n" [ algorithm; amz_date; credential_scope; hashed_canonical_request request ]

(* Per "Derive a signing key" (docs.aws.amazon.com/general/latest/gr/create-signed-request.html):
   DateKey = HMAC-SHA256("AWS4"+secret, date)
   DateRegionKey = HMAC-SHA256(DateKey, region)
   DateRegionServiceKey = HMAC-SHA256(DateRegionKey, service)
   SigningKey = HMAC-SHA256(DateRegionServiceKey, "aws4_request")
   Each step's raw (not hex) output becomes the next step's HMAC key. *)
let signing_key ~secret_access_key ~date ~region ~service =
  let k_date = hmac_raw ~key:("AWS4" ^ secret_access_key) date in
  let k_region = hmac_raw ~key:k_date region in
  let k_service = hmac_raw ~key:k_region service in
  hmac_raw ~key:k_service "aws4_request"

let signature ~signing_key ~string_to_sign = hmac_hex ~key:signing_key string_to_sign

let authorization_header ~access_key_id ~credential_scope ~signed_headers ~signature =
  Printf.sprintf "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" access_key_id
    credential_scope
    (String.concat ";" signed_headers)
    signature

let sign ~access_key_id ~secret_access_key ~region ~service ~amz_date request =
  let date = String.sub amz_date 0 8 in
  let credential_scope = Printf.sprintf "%s/%s/%s/aws4_request" date region service in
  let to_sign = string_to_sign ~algorithm:"AWS4-HMAC-SHA256" ~amz_date ~credential_scope ~request in
  let key = signing_key ~secret_access_key ~date ~region ~service in
  let sig_ = signature ~signing_key:key ~string_to_sign:to_sign in
  let _, signed_headers = canonical_headers request.headers in
  authorization_header ~access_key_id ~credential_scope ~signed_headers ~signature:sig_
