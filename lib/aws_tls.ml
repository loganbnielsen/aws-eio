(* Private copy of the same CA-bundle-loading TLS wrapper every other
   HTTPS-calling package in this repo carries privately (kafka-eio-service's
   Kafka_service_tls, obs-loki-eio's Obs_loki_tls, obs-prometheus-eio's
   Obs_prometheus_tls) — established convention, not shared, per the
   obs-eio extraction audit's finding that a shared Obs_tls module caused a
   link clash the moment two backends depending on it were linked together. *)

type error =
  [ `No_system_ca_bundle
  | `Tls_config_error of string
  ]

type https_wrapper =
  Uri.t ->
  [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r ->
  Tls_eio.t

let system_ca_bundle_paths =
  [ "/etc/ssl/certs/ca-certificates.crt"   (* Debian/Ubuntu/WSL *)
  ; "/etc/pki/tls/certs/ca-bundle.crt"     (* RHEL/CentOS/Fedora *)
  ; "/etc/ssl/ca-bundle.pem"               (* OpenSUSE *)
  ; "/etc/ssl/cert.pem"                    (* macOS/Alpine *)
  ]

let read_file path =
  try Some (In_channel.with_open_text path In_channel.input_all)
  with _ -> None

let load_certificates ca_paths =
  ca_paths
  |> List.find_map (fun path ->
       match read_file path with
       | None -> None
       | Some pem ->
         match X509.Certificate.decode_pem_multiple pem with
         | Ok certs when certs <> [] -> Some certs
         | _ -> None)
  |> function
  | Some certs -> Ok certs
  | None -> Error `No_system_ca_bundle

let authenticator ?(ca_paths = system_ca_bundle_paths) () =
  let time () = Ptime.of_float_s (Unix.gettimeofday ()) in
  match load_certificates ca_paths with
  | Ok certs -> Ok (X509.Authenticator.chain_of_trust ~time certs)
  | Error _ as error -> error

let make_https_wrapper ?ca_paths () : (https_wrapper, error) result =
  match authenticator ?ca_paths () with
  | Error _ as error -> error
  | Ok authenticator ->
    match Tls.Config.client ~authenticator () with
    | Error (`Msg msg) -> Error (`Tls_config_error msg)
    | Ok tls_config ->
      Ok
        (fun uri raw ->
          let host =
            Uri.host uri
            |> Option.map (fun h -> Domain_name.(host_exn (of_string_exn h)))
          in
          Tls_eio.client_of_flow ?host tls_config raw)

(* tls-eio's handshake needs Mirage_crypto_rng.default_generator seeded before
   it generates any key/nonce material — without this, every TLS handshake
   raises "The default generator is not yet initialized" at the point of
   first use. Nothing in this package (or its opam dependency graph) did
   this; found by an independent reviewer's first real HTTPS call, since
   every prior test in this repo deliberately used plain-HTTP local mock
   servers. One-shot, idempotent (Lazy.force only ever runs the RHS once),
   tied to the same lazy that builds the TLS wrapper so pure-signing use of
   this package (which never touches Aws_tls) doesn't pay for it. Using the
   synchronous getentropy-based seed (Mirage_crypto_rng_unix.use_default),
   not the Eio-native continuously-reseeding mirage-crypto-rng-eio, to avoid
   requiring env/sw here — a single blocking syscall at first-TLS-use is a
   fine trade for keeping this module's interface as small as it is now
   (Aws_tls.authenticator already makes one blocking Unix call,
   Unix.gettimeofday, for the same reason). *)
let default_https_wrapper =
  lazy (
    Mirage_crypto_rng_unix.use_default ();
    make_https_wrapper ())

let https_for_uri uri =
  match Uri.scheme uri with
  | Some scheme when String.lowercase_ascii scheme = "https" ->
    Result.map (fun https -> Some https) (Lazy.force default_https_wrapper)
  | _ -> Ok None

let error_to_string = function
  | `No_system_ca_bundle ->
    "no system CA bundle found; refusing to connect without certificate verification"
  | `Tls_config_error msg ->
    "TLS config error: " ^ msg
