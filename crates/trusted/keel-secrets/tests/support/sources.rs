use super::{CredentialSources, Entry, Source, harden, shell};
use crate::{
    AwsCredentialSource, GitHubAuthorities, basic_authorization, github_repository_from_git_scope,
    repository_credentials, resolve_aws_credentials,
};
use std::{process::Command, sync::Mutex};

fn entry(source: Source, hint: Option<&str>) -> Entry {
    Entry {
        source,
        hint: hint.map(str::to_owned),
    }
}

#[test]
fn the_design_example_parses_and_names_no_secret() {
    let sources = CredentialSources::parse(
        br#"{
          "version": 1,
          "providers": {
            "api-key": {"source": {"kind": "process", "command": "/usr/bin/security find-generic-password -w -s keel-anthropic"}},
            "bedrock": {
              "source": {"kind": "process", "command": "aws configure export-credentials --profile work --format process"},
              "region": "us-west-2"
            },
            "openrouter": {"source": {"kind": "env", "variable": "OPENROUTER_API_KEY"}, "model": "anthropic/claude-sonnet-4.6"}
          },
          "default": "api-key",
          "github": {"source": {"kind": "process", "command": "gh auth token --hostname github.com"}}
        }"#,
    )
    .unwrap();
    assert_eq!(
        sources.providers["api-key"].source.describe(),
        "command `/usr/bin/security find-generic-password -w -s keel-anthropic`"
    );
    assert_eq!(
        sources.providers["bedrock"].source.describe(),
        "command `aws configure export-credentials --profile work --format process`"
    );
    assert_eq!(
        sources.github.unwrap().source,
        Source::Process("gh auth token --hostname github.com".to_owned())
    );
}

#[test]
fn malformed_sources_are_refused() {
    for (text, reason) in [
        ("[]", "not version 1"),
        (r#"{"version":2}"#, "not version 1"),
        (r#"{"version":1,"providers":[]}"#, "not an object"),
        (
            r#"{"version":1,"providers":{"vertex":{"source":{"kind":"env","variable":"X"}}}}"#,
            "unknown provider",
        ),
        (
            r#"{"version":1,"providers":{"api-key":{}}}"#,
            "has no `source`",
        ),
        (
            r#"{"version":1,"github":{"source":{"kind":"vault"}}}"#,
            "is not env or process",
        ),
        (
            r#"{"version":1,"github":{"source":{"kind":"process"}}}"#,
            "needs `command`",
        ),
        (
            r#"{"version":1,"github":{"source":{"kind":"process","command":"a\u001b[2Jb"}}}"#,
            "not short printable text",
        ),
        (
            r#"{"version":1,"github":{"source":{"kind":"env","variable":7}}}"#,
            "not short printable text",
        ),
        // The keyring kinds of the first design are commands now.
        (
            r#"{"version":1,"github":{"source":{"kind":"keychain","service":"keel"}}}"#,
            "is not env or process",
        ),
        (
            r#"{"version":1,"github":{"source":{"kind":"gh"}}}"#,
            "is not env or process",
        ),
        (
            r#"{"version":1,"github":{"source":{"kind":"env","variable":"X"},"hint":"a\nb"}}"#,
            "not short printable text",
        ),
    ] {
        let error = CredentialSources::parse(text.as_bytes()).unwrap_err();
        assert!(error.contains(reason), "{text}: {error}");
    }
    let long = format!(
        r#"{{"version":1,"github":{{"source":{{"kind":"process","command":"{}"}}}}}}"#,
        "a".repeat(513)
    );
    assert!(CredentialSources::parse(long.as_bytes()).is_err());
}

#[test]
fn a_process_source_prints_the_credential() {
    let secret = entry(Source::Process("printf ' key-123\n'".to_owned()), None)
        .resolve()
        .unwrap()
        .unwrap();
    assert_eq!(secret.as_str(), "key-123");
}

/// A stored command searches a fixed path, runs outside the workspace, and
/// is told of no terminal, whatever the operator's environment holds.
#[test]
fn a_stored_command_sees_a_fixed_path_and_no_terminal_hint() {
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            r#"printf '%s|%s|%s|%s' "$PATH" "${GPG_TTY-unset}" "${SSH_ASKPASS-unset}" "$PWD"; test -t 0 || printf '|notty'"#,
        ])
        .env("GPG_TTY", "/dev/ttys001")
        .env("SSH_ASKPASS", "/usr/bin/ssh-askpass")
        .env("PATH", "/workspace/bin");
    harden(&mut command);
    let output = crate::run_credential_command(
        &mut command,
        "test",
        false,
        std::time::Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        std::str::from_utf8(&output).unwrap(),
        "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin|unset|unset|/|notty"
    );
}

#[test]
fn a_locked_source_fails_with_its_unlock_hint() {
    let error = entry(
        Source::Process("echo 'store is locked' >&2; exit 2".to_owned()),
        Some("unlock with `pass show keel/anthropic`"),
    )
    .resolve()
    .unwrap_err();
    assert!(error.contains("store is locked"), "{error}");
    assert!(
        error.ends_with("; unlock with `pass show keel/anthropic`"),
        "{error}"
    );
    let error = entry(Source::Process("true".to_owned()), None)
        .resolve()
        .unwrap_err();
    assert!(error.contains("printed no credential"), "{error}");
}

#[test]
fn a_program_outside_the_fixed_path_is_not_found() {
    let error = entry(Source::Process("keel-no-such-tool lookup".to_owned()), None)
        .resolve()
        .unwrap_err();
    assert!(error.contains("exited with"), "{error}");
}

#[test]
fn an_unset_env_source_is_todays_behavior() {
    let unset = entry(Source::Env("KEEL_TEST_UNSET_VARIABLE".to_owned()), None);
    assert!(unset.resolve().unwrap().is_none());
    let set = entry(Source::Env("PATH".to_owned()), None);
    assert!(set.resolve().unwrap().is_some());
}

/// A stored Bedrock `process` source is kept as a command, so the signer can
/// run it again when the session it printed lapses.
#[test]
fn a_stored_bedrock_command_supplies_signing_credentials() {
    let output = r#"{"Version":1,"AccessKeyId":"AKIDEXAMPLE","SecretAccessKey":"secret","SessionToken":"token"}"#;
    let source = AwsCredentialSource::Stored(Mutex::new(shell(&format!("printf '%s' '{output}'"))));
    for refresh in [false, true] {
        let credentials = resolve_aws_credentials(&source, refresh).unwrap();
        assert_eq!(credentials.access_key_id, "AKIDEXAMPLE");
    }
    let failing = AwsCredentialSource::Stored(Mutex::new(shell("echo leaked >&2; exit 1")));
    let error = resolve_aws_credentials(&failing, true).err().unwrap();
    assert!(!error.contains("leaked"), "{error}");
}

#[test]
fn only_the_selected_providers_source_is_named() {
    let sources = CredentialSources::parse(
        br#"{"version":1,
            "providers":{"openrouter":{"source":{"kind":"process","command":"pass show keel/openrouter"}}},
            "github":{"source":{"kind":"process","command":"gh auth token --hostname github.com"}}}"#,
    )
    .unwrap();
    assert!(sources.describe(Some("api-key"), false).is_empty());
    assert!(sources.describe(None, false).is_empty());
    if std::env::var_os("OPENROUTER_API_KEY").is_none() {
        assert_eq!(
            sources.describe(Some("openrouter"), false),
            ["model credential: command `pass show keel/openrouter`"]
        );
    }
    if std::env::var_os("GH_TOKEN").is_none() && std::env::var_os("GITHUB_TOKEN").is_none() {
        assert_eq!(
            sources.describe(None, true),
            ["GitHub credential: command `gh auth token --hostname github.com`"]
        );
    }
}

#[test]
fn a_github_token_becomes_basic_authorization() {
    assert_eq!(basic_authorization("tok"), "Basic eC1hY2Nlc3MtdG9rZW46dG9r");
}

#[test]
fn a_repository_is_named_with_or_without_the_git_suffix() {
    for path in ["/owner/repo.git", "/owner/repo"] {
        assert_eq!(
            github_repository_from_git_scope("github.com", path).as_deref(),
            Some("owner/repo")
        );
    }
    assert_eq!(
        github_repository_from_git_scope("github.com", "/owner"),
        None
    );
    assert_eq!(
        github_repository_from_git_scope("example.com", "/owner/repo"),
        None
    );
}

/// The derived scope binds the stored GitHub token to the origin's own
/// repository; without a token the run holds no push credential at all.
#[test]
fn a_derived_scope_binds_the_token_or_nothing() {
    if [
        "KEEL_GIT_AUTHORIZATION",
        "KEEL_GIT_CREDENTIAL_HOST",
        "KEEL_GIT_CREDENTIAL_PATH",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    ]
    .iter()
    .any(|variable| std::env::var_os(variable).is_some())
    {
        return;
    }
    let sources = |command: &str| {
        CredentialSources::parse(
            format!(
                r#"{{"version":1,"github":{{"source":{{"kind":"process","command":"{command}"}}}}}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    };
    let derived = || Some(("github.com".to_owned(), "/owner/repo".to_owned()));
    let none = GitHubAuthorities::new(false, false);

    let push = repository_credentials(true, none, &sources("printf tok"), derived()).unwrap();
    assert_eq!(
        push,
        (
            Some("Basic eC1hY2Nlc3MtdG9rZW46dG9r".to_owned()),
            Some("github.com".to_owned()),
            Some("/owner/repo".to_owned()),
            // A push alone declares no GitHub API authority.
            None
        )
    );

    let locked = repository_credentials(true, none, &sources("exit 1"), derived()).unwrap();
    assert_eq!(locked, (None, None, None, None));

    let issues = GitHubAuthorities::new(false, true);
    let read = repository_credentials(false, issues, &sources("printf tok"), derived()).unwrap();
    assert_eq!(
        read,
        (
            None,
            Some("github.com".to_owned()),
            Some("/owner/repo".to_owned()),
            Some("tok".to_owned())
        )
    );

    // A run with no repository authority reads no token and derives nothing.
    let plain = repository_credentials(false, none, &sources("printf tok"), derived()).unwrap();
    assert_eq!(plain, (None, None, None, None));
}
