(** AWS credential resolution. Every [t] states its source explicitly — there
    is no implicit default, the same way every Kafka config states its
    security posture explicitly via [Kafka_security.t]. *)

type static = {
  access_key_id : string;
  secret_access_key : string;
  session_token : string option;
}

type source =
  | Static of static
  | Web_identity of { role_arn : string; token_file : string }
      (** EKS IRSA (AssumeRoleWithWebIdentity). Sun's actual production
          credential source. *)
  | Container of { relative_uri : string }  (** ECS/Fargate task role. *)
  | Imdsv2  (** EC2 instance profile. *)
  | Env_chain
      (** Static env vars, then IRSA env vars, then container env var, then
          IMDSv2, in that order. A chosen value, not a fallback default. *)

type t = {
  source : source;
  region : string;
}

type resolved = {
  access_key_id : string;
  secret_access_key : string;
  session_token : string option;
  expiration : float option;  (** Unix timestamp; [None] = does not expire. *)
}

val of_env : region:string -> unit -> t
(** [{ source = Env_chain; region }] — the one place this module picks
    [Env_chain] for you, and it does so as an explicit named choice a caller
    opted into by calling this function, not a silent default. *)

val resolve : net:_ Eio.Net.t -> clock:_ Eio.Time.clock -> t -> (resolved, Aws_error.t) result
(** Performs whatever network call [t.source] requires (none for [Static]).
    Callers that hold a [t] across many requests should cache the result and
    re-resolve once [resolved.expiration] approaches — this function does not
    cache or refresh on your behalf. *)

(** {2 Exposed for testing}

    The response-parsing helpers behind {!resolve}'s network-backed sources.
    Tested directly against realistic sample payloads, since none of
    Web_identity/Container/Imdsv2 can be exercised against real AWS
    endpoints from a unit test. *)

val extract_tag : string -> string -> string option
(** [extract_tag "AccessKeyId" xml] reads flat [<Tag>text</Tag>] leaf content.
    Deliberately minimal — see the doc comment in [aws_credentials.ml] for
    what it does not handle. *)

val resolved_of_json_credentials : string -> (resolved, Aws_error.t) result
(** Parses the IMDSv2 / ECS container-credentials JSON response shape
    ([AccessKeyId]/[SecretAccessKey]/[Token]/[Expiration]). *)
