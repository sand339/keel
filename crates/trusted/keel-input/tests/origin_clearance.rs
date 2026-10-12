#![doc = "Private content is cleared for the workspace's own origin repository only."]

use keel_input::origin_private_sinks;
use keel_kernel::{FlowVerdict, PayloadPolicy};
use keel_provenance::{Confidentiality, PayloadIndex};

const PRIVATE: &str =
    "Quarterly settlement reconciliation notes for the treasury migration, internal only.";

fn policy(origin: &str) -> PayloadPolicy {
    let mut index = PayloadIndex::default();
    index.add(Confidentiality::Private, PRIVATE.as_bytes());
    PayloadPolicy::new(index, origin_private_sinks(origin))
}

fn cleared(policy: &PayloadPolicy, host: &str, path: &str) -> bool {
    matches!(
        policy.judge(host, path, PRIVATE.as_bytes(), "api.anthropic.com"),
        FlowVerdict::Cleared(_)
    )
}

#[test]
fn the_origin_repository_git_and_api_paths_are_cleared() {
    let policy = policy("https://github.com/acme/widget.git\n");
    assert!(cleared(
        &policy,
        "github.com",
        "/acme/widget.git/git-receive-pack"
    ));
    assert!(cleared(&policy, "github.com", "/acme/widget/info/refs"));
    assert!(cleared(
        &policy,
        "api.github.com",
        "/repos/acme/widget/pulls"
    ));
}

#[test]
fn sibling_repositories_and_other_github_sinks_are_not() {
    let policy = policy("https://github.com/acme/widget");
    for (host, path) in [
        ("github.com", "/acme/widget-exfil/git-receive-pack"),
        ("github.com", "/acme/widget2.git/git-receive-pack"),
        ("github.com", "/acme/widgetry/info/refs"),
        ("api.github.com", "/repos/acme/widget-exfil/issues"),
        ("api.github.com", "/gists"),
        ("api.github.com", "/user/repos"),
        ("api.github.com", "/repos/other/widget/issues"),
        ("gist.github.com", "/acme/widget/"),
    ] {
        assert!(
            !cleared(&policy, host, path),
            "{host}{path} must not be cleared"
        );
    }
}

#[test]
fn a_non_github_or_malformed_origin_clears_nothing() {
    for origin in [
        "git@github.com:acme/widget.git",
        "https://gitlab.com/acme/widget",
        "https://github.com/acme",
        "https://github.com/acme/widget/extra",
        "https://github.com/../widget",
        "",
    ] {
        assert!(origin_private_sinks(origin).is_empty(), "{origin:?}");
    }
}
