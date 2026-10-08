#![doc = "Triage scope matches strictly: subdomain wildcards, default ports, exclusions."]

use keel_provenance::Scope;

fn scope(include: &[&str], exclude: &[&str]) -> Result<Scope, String> {
    let owned = |rules: &[&str]| {
        rules
            .iter()
            .map(|rule| (*rule).to_owned())
            .collect::<Vec<_>>()
    };
    Scope::parse(&owned(include), &owned(exclude))
}

#[test]
fn wildcards_cover_subdomains_but_not_the_apex() {
    let scope = scope(&["*.target.example"], &[]).unwrap();
    assert!(scope.contains("app.target.example", 443));
    assert!(scope.contains("a.b.target.example", 80));
    assert!(scope.contains("APP.Target.Example", 443));
    assert!(
        !scope.contains("target.example", 443),
        "apex must be listed"
    );
    assert!(!scope.contains("eviltarget.example", 443));
    assert!(!scope.contains("target.example.evil", 443));
    assert!(
        !scope.contains("app.target.example", 8443),
        "default ports only"
    );
}

#[test]
fn ports_and_exclusions_are_exact() {
    let scope = scope(
        &["*.target.example", "api.target.example:8443"],
        &["admin.target.example"],
    )
    .unwrap();
    assert!(scope.contains("api.target.example", 8443));
    assert!(
        !scope.contains("admin.target.example", 443),
        "exclusion wins"
    );
    assert_eq!(
        scope.describe(),
        [
            "*.target.example:443,80",
            "api.target.example:8443",
            "!admin.target.example:443,80"
        ]
    );
}

#[test]
fn malformed_and_empty_scopes_are_refused() {
    for rule in [
        "*",
        "*.com.",
        "localhost",
        "target..example",
        "-a.example",
        "a.example:99999",
        "https://a.example",
        "a.example/path",
        "**.a.example",
    ] {
        assert!(scope(&[rule], &[]).is_err(), "{rule}");
    }
    assert!(
        scope(&[], &["a.example"]).is_err(),
        "exclusions alone are no scope"
    );
}
