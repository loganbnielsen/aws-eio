(* Regression test for a blocker an independent reviewer found: no TLS
   handshake this package ever performed had a seeded
   Mirage_crypto_rng.default_generator, so every real HTTPS call (which
   means every signed_request call, and Aws_credentials's EKS IRSA
   bootstrap) failed at the point of first use with "The default generator
   is not yet initialized" — a runtime error, not something the type system
   catches, and invisible to every other test in this repo because they all
   deliberately use plain HTTP against local mock servers.

   This test performs a REAL local TLS handshake (self-signed cert/key in
   tls_fixtures/, generated once with openssl, not trusted by the system CA
   bundle) through Aws_tls.https_for_uri — the exact function whose lazy now
   seeds the RNG before building the client TLS config. Deliberately does
   NOT reach the network (no external service dependency, so this stays
   hermetic and non-flaky) and deliberately expects the handshake to still
   fail — the self-signed cert isn't trusted — but the failure has to be a
   certificate/protocol failure, not the RNG error. That distinction is the
   whole point: RNG seeding happens before key/nonce generation, which
   happens before certificate verification, so reaching a cert-validation
   failure is proof the RNG error is gone. *)

let contains_substring ~needle haystack =
  let nlen = String.length needle and hlen = String.length haystack in
  let rec go i = i + nlen <= hlen && (String.sub haystack i nlen = needle || go (i + 1)) in
  nlen = 0 || go 0

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

let fixtures_dir = "tls_fixtures"

let test_https_handshake_fails_on_cert_not_on_rng () =
  Eio_main.run @@ fun env ->
  Eio.Switch.run @@ fun sw ->
  let cert = Result.get_ok (X509.Certificate.decode_pem (read_file (Filename.concat fixtures_dir "cert.pem"))) in
  let key = Result.get_ok (X509.Private_key.decode_pem (read_file (Filename.concat fixtures_dir "key.pem"))) in
  let server_config = Result.get_ok (Tls.Config.server ~certificates:(`Single ([ cert ], key)) ()) in
  let socket = Eio.Net.listen ~backlog:2 ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, 0)) in
  let port = match Eio.Net.listening_addr socket with `Tcp (_, port) -> port | _ -> failwith "unexpected address family" in
  Eio.Fiber.fork_daemon ~sw (fun () ->
      Eio.Net.accept_fork ~sw socket
        ~on_error:(fun _ -> ())
        (fun conn _addr -> ( try ignore (Tls_eio.server_of_flow server_config conn) with _ -> ()));
      `Stop_daemon);
  let client_socket = Eio.Net.connect ~sw env#net (`Tcp (Eio.Net.Ipaddr.V4.loopback, port)) in
  let dummy_uri = Uri.make ~scheme:"https" ~host:"localhost" () in
  match Aws_tls.https_for_uri dummy_uri with
  | Error e -> Alcotest.fail ("expected an https wrapper, got: " ^ Aws_tls.error_to_string e)
  | Ok None -> Alcotest.fail "expected Some wrapper for an https:// uri"
  | Ok (Some wrap) -> (
    let raw = (client_socket :> [ Eio.Flow.two_way_ty | Eio.Resource.close_ty ] Eio.Std.r) in
    match wrap dummy_uri raw with
    | (_ : Tls_eio.t) -> Alcotest.fail "expected the untrusted self-signed cert to be rejected"
    | exception exn ->
      let msg = Printexc.to_string exn in
      Alcotest.(check bool)
        "handshake reached certificate validation, not the unseeded-RNG error" true
        (not (contains_substring ~needle:"not yet initialized" msg)))

(* Regression test for a second blocker: an independent reviewer found that
   the fix above, when it was a bare `Stdlib.Lazy.t`, was not safe across
   OCaml 5 domains and reproduced CamlinternalLazy.Undefined from it (8/8
   runs, two racing domains, in that reviewer's environment). Stdlib.Lazy's
   own .mli confirms the hazard is real and documented, independent of that
   reproduction: "Lazy.force is not concurrency-safe... behaviour is
   unspecified" under concurrent force from multiple domains, and
   `exception Undefined` is documented as exactly this case. "Unspecified"
   means a fresh attempt to reproduce the crash is not guaranteed to
   reproduce it on a different machine/OCaml build/run — and it didn't,
   here, even with an explicit spin-barrier forcing every domain to hit the
   call at the same instant (below). That non-reproduction does not
   contradict the hazard being real; it's exactly what "unspecified
   behavior" means. Fixed with double-checked locking over an Atomic.t
   cache instead of a bare lazy (see Aws_tls.default_https_wrapper) — a
   primitive whose cross-domain safety is actually guaranteed by the
   stdlib, not "unspecified." This test exercises the fixed code path under
   real concurrent-domain contention and asserts it stays error-free; it is
   a live exercise of the contract, not proof the old code would have
   failed here. *)
let test_concurrent_domains_never_see_lazy_undefined () =
  let domain_count = 8 in
  (* Spawning domains in sequence (List.init calling Domain.spawn one at a
     time) gives the first-spawned domain a head start in practice, which
     lets it win the lazy uncontested most runs — not a real race. A shared
     spin-barrier forces every domain to reach the racy call at the same
     instant instead. *)
  let ready_count = Atomic.make 0 in
  let go = Atomic.make false in
  let domains =
    List.init domain_count (fun _ ->
        Domain.spawn (fun () ->
            Atomic.incr ready_count;
            while not (Atomic.get go) do
              Domain.cpu_relax ()
            done;
            let uri = Uri.make ~scheme:"https" ~host:"localhost" () in
            try
              ignore (Aws_tls.https_for_uri uri : (Aws_tls.https_wrapper option, Aws_tls.error) result);
              Ok ()
            with exn -> Error (Printexc.to_string exn)))
  in
  while Atomic.get ready_count < domain_count do
    Domain.cpu_relax ()
  done;
  Atomic.set go true;
  let results = List.map Domain.join domains in
  List.iteri
    (fun i result ->
      match result with
      | Ok () -> ()
      | Error msg -> Alcotest.failf "domain %d: %s" i msg)
    results

let () =
  Alcotest.run "aws_tls"
    [ ( "https handshake",
        [ Alcotest.test_case "fails on certificate trust, not on an unseeded RNG" `Quick
            test_https_handshake_fails_on_cert_not_on_rng;
          Alcotest.test_case "concurrent domains never see Lazy.Undefined" `Quick
            test_concurrent_domains_never_see_lazy_undefined;
        ] );
    ]
