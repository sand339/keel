use super::*;
use std::net::Ipv4Addr;

#[test]
#[allow(clippy::too_many_lines)]
fn runtime_model_and_github_credentials_are_exactly_scoped() {
    let (connector, _, _, _) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            git_credential: Some("Basic dormant-git-secret".to_owned()),
            git_host: Some("github.com".to_owned()),
            git_path: Some("/owner/repo.git".to_owned()),
            model: Some("anthropic-real-secret".to_owned()),
            github: Some("github-real-secret".to_owned()),
            github_authorities: GitHubAuthorities::new(true, false),
            ..RuntimeCredentialValues::default()
        })
        .unwrap();
    let public_ip = Ipv4Addr::new(93, 184, 216, 34).into();
    let model = connector
        .vault
        .inject(
            &ConnectionTarget {
                server_name: "api.anthropic.com".to_owned(),
                resolved_ip: public_ip,
                port: 443,
            },
            format!(
                "POST /v1/messages HTTP/1.1\r\nx-api-key: {}\r\n\r\n",
                SystemEgressConnector::MODEL_SENTINEL
            )
            .as_bytes(),
        )
        .unwrap();
    assert!(
        model
            .windows(21)
            .any(|value| value == b"anthropic-real-secret")
    );
    let github_target = ConnectionTarget {
        server_name: "api.github.com".to_owned(),
        resolved_ip: public_ip,
        port: 443,
    };
    let github = connector
        .vault
        .inject(
            &github_target,
            format!(
                "POST /repos/owner/repo/pulls HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                SystemEgressConnector::GITHUB_SENTINEL
            )
            .as_bytes(),
        )
        .unwrap();
    assert!(
        github
            .windows(18)
            .any(|value| value == b"github-real-secret")
    );
    assert!(
        connector
            .vault
            .inject(
                &github_target,
                format!(
                    "GET /repos/owner/repo/issues/42 HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                    SystemEgressConnector::GITHUB_SENTINEL
                )
                .as_bytes(),
            )
            .is_err(),
        "an unscoped PR credential must not become a private-read credential"
    );
    assert!(
        connector
            .vault
            .inject(
                &ConnectionTarget {
                    server_name: "github.com".to_owned(),
                    resolved_ip: public_ip,
                    port: 443,
                },
                format!(
                    "POST /owner/repo.git/git-receive-pack HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                    SystemEgressConnector::GIT_SENTINEL
                )
                .as_bytes(),
            )
            .is_err(),
        "PR authority must not activate the Git push credential"
    );
    let (private_connector, private_git_scope, private_repository, _) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            git_credential: Some("Basic git-secret".to_owned()),
            git_host: Some("github.com".to_owned()),
            git_path: Some("/owner/repo.git".to_owned()),
            github: Some("github-real-secret".to_owned()),
            github_authorities: GitHubAuthorities::new(false, true),
            ..RuntimeCredentialValues::default()
        })
        .unwrap();
    assert!(private_git_scope.is_none());
    assert_eq!(private_repository.as_deref(), Some("owner/repo"));
    let issue = private_connector
        .vault
        .inject(
            &github_target,
            format!(
                "GET /repos/owner/repo/issues/42 HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                SystemEgressConnector::GITHUB_SENTINEL
            )
            .as_bytes(),
        )
        .unwrap();
    assert!(
        issue
            .windows(18)
            .any(|value| value == b"github-real-secret")
    );
    assert!(
        private_connector
            .vault
            .inject(
                &github_target,
                format!(
                    "POST /repos/owner/repo/pulls HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                    SystemEgressConnector::GITHUB_SENTINEL
                )
                .as_bytes(),
            )
            .is_err(),
        "private-issue-read authority must not become PR-write authority"
    );
    assert!(
        private_connector
            .vault
            .inject(
                &ConnectionTarget {
                    server_name: "github.com".to_owned(),
                    resolved_ip: public_ip,
                    port: 443,
                },
                format!(
                    "GET /owner/repo.git/info/refs?service=git-receive-pack HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                    SystemEgressConnector::GIT_SENTINEL
                )
                .as_bytes(),
            )
            .is_err(),
        "private issue authority must not activate the Git push credential"
    );
    let (combined, _, _, _) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            git_credential: Some("Basic git-secret".to_owned()),
            git_host: Some("github.com".to_owned()),
            git_path: Some("/owner/repo.git".to_owned()),
            github: Some("github-real-secret".to_owned()),
            github_authorities: GitHubAuthorities::new(true, true),
            ..RuntimeCredentialValues::default()
        })
        .unwrap();
    for request in [
        "POST /repos/owner/repo/pulls",
        "GET /repos/owner/repo/issues/42",
    ] {
        assert!(
            combined
                .vault
                .inject(
                    &github_target,
                    format!(
                        "{request} HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                        SystemEgressConnector::GITHUB_SENTINEL
                    )
                    .as_bytes(),
                )
                .is_ok(),
            "combined authority must retain its exact binding: {request}"
        );
    }
    for forbidden in [
        "GET /repos/owner/repo/issues/0",
        "GET /repos/owner/repo/issues/42/comments",
        "GET /repos/other/repo/issues/42",
        "GET /repos/owner/repo/contents/README.md",
        "POST /user/keys",
    ] {
        assert!(
            private_connector
                .vault
                .inject(
                    &github_target,
                    format!(
                        "{forbidden} HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                        SystemEgressConnector::GITHUB_SENTINEL
                    )
                    .as_bytes(),
                )
                .is_err(),
            "credential escaped its exact GitHub API shape: {forbidden}"
        );
    }
    assert!(
        connector
            .vault
            .inject(
                &github_target,
                format!(
                    "POST /user/keys HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                    SystemEgressConnector::GITHUB_SENTINEL
                )
                .as_bytes(),
            )
            .is_err()
    );
    assert!(
        CredentialVault::new()
            .inject(
                &github_target,
                format!(
                    "POST /repos/owner/repo/pulls HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n",
                    SystemEgressConnector::GITHUB_SENTINEL
                )
                .as_bytes(),
            )
            .is_err()
    );
}

#[test]
fn push_authority_without_a_configured_credential_binds_no_sentinel() {
    let (connector, scope, private_repository, _) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            allow_git_push: true,
            ..RuntimeCredentialValues::default()
        })
        .expect("credential-less push authority");
    assert!(scope.is_none());
    assert!(private_repository.is_none());
    let target = ConnectionTarget {
        server_name: "github.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    assert!(
        connector
            .vault
            .inject(
                &target,
                format!(
                    "POST /owner/repo.git/git-receive-pack HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
                    SystemEgressConnector::GIT_SENTINEL
                )
                .as_bytes(),
            )
            .is_err()
    );
}

#[test]
fn git_credential_covers_only_private_receive_pack_negotiation_and_write() {
    let (connector, scope, _, _) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            allow_git_push: true,
            git_credential: Some("Basic real-git-credential".to_owned()),
            git_host: Some("github.com".to_owned()),
            git_path: Some("/owner/repo.git".to_owned()),
            ..RuntimeCredentialValues::default()
        })
        .unwrap();
    let scope = scope.expect("Git credential scope");
    let target = ConnectionTarget {
        server_name: "github.com".to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: 443,
    };
    for request in [
        "GET /owner/repo.git/info/refs?service=git-receive-pack HTTP/1.1",
        "POST /owner/repo.git/git-receive-pack HTTP/1.1",
    ] {
        let injected = connector
            .vault
            .inject(
                &target,
                format!("{request}\r\nAuthorization: {}\r\n\r\n", scope.sentinel).as_bytes(),
            )
            .unwrap();
        assert!(
            injected
                .windows(b"Basic real-git-credential".len())
                .any(|value| value == b"Basic real-git-credential")
        );
    }
    for request in [
        "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1",
        "GET /owner/other.git/info/refs?service=git-receive-pack HTTP/1.1",
        "GET /owner/repo.git/attacker/info/refs?service=git-receive-pack HTTP/1.1",
        "POST /owner/repo.git/git-upload-pack HTTP/1.1",
        "POST /owner/repo.git/attacker/git-receive-pack HTTP/1.1",
    ] {
        assert!(
            connector
                .vault
                .inject(
                    &target,
                    format!("{request}\r\nAuthorization: {}\r\n\r\n", scope.sentinel).as_bytes(),
                )
                .is_err(),
            "Git credential escaped its receive-pack scope: {request}"
        );
    }
}

#[test]
fn model_preflight_accepts_global_profiles_and_names_unsupported_models() {
    let provider = ModelProvider {
        host: "bedrock-runtime.us-west-2.amazonaws.com".to_owned(),
        sentinel: SystemEgressConnector::BEDROCK_SENTINEL,
        region: Some("us-west-2".to_owned()),
    };
    validate_model_tariff(&provider, "global.anthropic.claude-sonnet-5-5").expect("global profile");
    let error = validate_model_tariff(&provider, "global.other-vendor.model")
        .expect_err("unpriced model must fail before boot");
    assert!(error.contains("no pinned budget tariff"));
    assert!(error.contains("global.other-vendor.model"));
}

#[test]
fn the_openrouter_key_is_injected_only_as_a_bearer_on_its_messages_endpoint() {
    let (connector, _, _, _) =
        SystemEgressConnector::from_runtime_values_all(RuntimeCredentialValues {
            openrouter: Some("sk-or-real-secret".to_owned()),
            ..RuntimeCredentialValues::default()
        })
        .unwrap();
    let target = |server_name: &str| ConnectionTarget {
        server_name: server_name.to_owned(),
        resolved_ip: Ipv4Addr::new(104, 18, 2, 115).into(),
        port: 443,
    };
    let request = |path: &str| {
        format!(
            "POST {path} HTTP/1.1\r\nAuthorization: Bearer {}\r\n\r\n{{}}",
            SystemEgressConnector::OPENROUTER_SENTINEL
        )
    };
    let injected = connector
        .vault
        .inject(
            &target("openrouter.ai"),
            request("/api/v1/messages").as_bytes(),
        )
        .unwrap();
    let injected = String::from_utf8(injected).unwrap();
    assert!(injected.contains("Authorization: Bearer sk-or-real-secret\r\n"));
    assert!(!injected.contains(SystemEgressConnector::OPENROUTER_SENTINEL));
    for (host, path) in [
        ("openrouter.ai", "/api/v1/chat/completions"),
        ("openrouter.ai", "/api/v1/keys"),
        ("api.anthropic.com", "/v1/messages"),
    ] {
        assert!(
            connector
                .vault
                .inject(&target(host), request(path).as_bytes())
                .is_err(),
            "{host}{path} must not receive the OpenRouter key"
        );
    }
}
