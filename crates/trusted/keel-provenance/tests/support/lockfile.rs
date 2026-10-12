use super::LockfilePins;

const IS_NUMBER: &str = "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==";

fn lockfile(packages: &str) -> Vec<u8> {
    format!(r#"{{"lockfileVersion":3,"packages":{{"":{{"name":"w"}},{packages}}}}}"#).into_bytes()
}

#[test]
fn a_lockfile_pins_each_resolved_tarball_by_its_sha512() {
    let pins = LockfilePins::from_npm_lockfile(&lockfile(&format!(
        r#""node_modules/is-number":{{"resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","integrity":"{IS_NUMBER}"}},
           "node_modules/@scope/pkg":{{"resolved":"https://Registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz","integrity":"sha1-AAAA sha512-{}"}},
           "node_modules/linked":{{"resolved":"../linked","link":true}},
           "node_modules/git":{{"resolved":"git+ssh://git@github.com/a/b.git#abc","integrity":"{IS_NUMBER}"}},
           "node_modules/weak":{{"resolved":"https://registry.npmjs.org/weak/-/weak-1.0.0.tgz","integrity":"sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk="}}"#,
        "A".repeat(86) + "=="
    )))
    .unwrap();
    assert_eq!(pins.len(), 2);
    let digest = pins
        .get("registry.npmjs.org", "/is-number/-/is-number-7.0.0.tgz")
        .unwrap();
    assert_eq!(&digest[..6], &[0xe3, 0x50, 0xa2, 0x7e, 0x48, 0x3a]);
    assert_eq!(
        pins.get("registry.npmjs.org", "/@scope/pkg/-/pkg-1.0.0.tgz"),
        Some(&[0; 64])
    );
    assert!(
        pins.get("registry.npmjs.org", "/weak/-/weak-1.0.0.tgz")
            .is_none()
    );
    assert!(
        pins.get("evil.example", "/is-number/-/is-number-7.0.0.tgz")
            .is_none()
    );
}

#[test]
fn a_lockfile_that_cannot_be_read_exactly_pins_nothing() {
    assert!(
        LockfilePins::from_npm_lockfile(br#"{"lockfileVersion":1,"dependencies":{}}"#).is_err()
    );
    assert!(LockfilePins::from_npm_lockfile(b"not json").is_err());
    let conflicting = lockfile(&format!(
        r#""node_modules/a":{{"resolved":"https://registry.npmjs.org/a/-/a-1.tgz","integrity":"{IS_NUMBER}"}},
           "node_modules/b/node_modules/a":{{"resolved":"https://registry.npmjs.org/a/-/a-1.tgz","integrity":"sha512-{}"}}"#,
        "A".repeat(86) + "=="
    ));
    assert!(LockfilePins::from_npm_lockfile(&conflicting).is_err());
    // A URL with a port, credentials, or a query is not a plain fetch target.
    for url in [
        "https://registry.npmjs.org:8443/a/-/a-1.tgz",
        "https://user@registry.npmjs.org/a/-/a-1.tgz",
        "https://registry.npmjs.org/a/-/a-1.tgz?x=1",
        "http://registry.npmjs.org/a/-/a-1.tgz",
    ] {
        let pins = LockfilePins::from_npm_lockfile(&lockfile(&format!(
            r#""node_modules/a":{{"resolved":"{url}","integrity":"{IS_NUMBER}"}}"#
        )))
        .unwrap();
        assert!(pins.is_empty(), "{url}");
    }
}
