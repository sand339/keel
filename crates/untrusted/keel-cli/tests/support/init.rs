use super::{Host, InitOptions, Session, apply, guide, key_choices, load, parse, write};
use serde_json::{Value, json};
use std::{cell::RefCell, ffi::OsString, fs, os::unix::fs::PermissionsExt as _, path::PathBuf};

/// A host with chosen tools, whose sources all answer unless named in `locked`.
#[derive(Default)]
struct FakeHost {
    macos: bool,
    tools: Vec<&'static str>,
    variables: Vec<&'static str>,
    locked: Vec<&'static str>,
    ran: RefCell<Vec<String>>,
    checked: RefCell<Vec<String>>,
}

impl Host for FakeHost {
    fn macos(&self) -> bool {
        self.macos
    }
    fn user(&self) -> String {
        "operator".to_owned()
    }
    fn has(&self, program: &str) -> bool {
        self.tools.contains(&program)
    }
    fn env(&self, name: &str) -> bool {
        self.variables.contains(&name)
    }
    fn check(&self, command: &str) -> Result<(), String> {
        self.checked.borrow_mut().push(command.to_owned());
        if self.locked.iter().any(|locked| command.starts_with(locked)) {
            Err("exit status: 1: locked".to_owned())
        } else {
            Ok(())
        }
    }
    fn run(&self, argv: &[String]) -> bool {
        self.ran.borrow_mut().push(argv.join(" "));
        true
    }
}

fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("keel-init-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    root.join("keel/sources.json")
}

/// Runs the guided flow with `answers` typed one per line.
fn guided(host: &FakeHost, path: &std::path::Path, answers: &[&str]) -> (bool, String) {
    let mut input = std::io::Cursor::new(answers.join("\n") + "\n");
    let mut output = Vec::new();
    let wrote = guide(
        &mut Session {
            host,
            input: &mut input,
            output: &mut output,
        },
        path,
    )
    .unwrap();
    (wrote, String::from_utf8(output).unwrap())
}

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn flags_record_sources_without_prompting() {
    let options = parse(&arguments(&[
        "--set",
        "api-key=pass show keel/anthropic",
        "--set",
        "bedrock=aws configure export-credentials --profile work --format process",
        "--region",
        "us-west-2",
        "--model",
        "openrouter=anthropic/claude-sonnet-4.6",
        "--github",
        "gh auth token --hostname github.com",
        "--default",
        "api-key",
    ]))
    .unwrap();
    assert!(options.scripted());
    assert!(!InitOptions::default().scripted());
    let mut document = json!({"version": 1});
    apply(&mut document, &options).unwrap();
    assert_eq!(
        document,
        json!({
            "version": 1,
            "providers": {
                "api-key": {"source": {"kind": "process", "command": "pass show keel/anthropic"}},
                "bedrock": {
                    "source": {"kind": "process", "command": "aws configure export-credentials --profile work --format process"},
                    "region": "us-west-2"
                },
                "openrouter": {"model": "anthropic/claude-sonnet-4.6"}
            },
            "github": {"source": {"kind": "process", "command": "gh auth token --hostname github.com"}},
            "default": "api-key"
        })
    );
    for bad in [
        &["--set"][..],
        &["--set", "api-key"],
        &["--unknown", "x"],
        &["--region"],
    ] {
        assert!(parse(&arguments(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn a_rerun_replaces_a_source_and_keeps_its_settings() {
    let mut document = json!({"version": 1, "providers": {"bedrock": {
        "source": {"kind": "process", "command": "old"},
        "hint": "old hint",
        "region": "us-east-1"
    }}});
    let options = InitOptions {
        sets: vec![("bedrock".to_owned(), "new".to_owned())],
        ..InitOptions::default()
    };
    apply(&mut document, &options).unwrap();
    assert_eq!(
        document["providers"]["bedrock"],
        json!({"source": {"kind": "process", "command": "new"}, "region": "us-east-1"})
    );
}

#[test]
fn what_trusted_parsing_would_refuse_is_not_written() {
    for (name, command) in [
        ("vertex", "printf key".to_owned()),
        ("api-key", "printf \u{1b}[2J".to_owned()),
        ("api-key", "a".repeat(513)),
        ("api-key", String::new()),
    ] {
        let options = InitOptions {
            sets: vec![(name.to_owned(), command)],
            ..InitOptions::default()
        };
        assert!(
            apply(&mut json!({"version": 1}), &options).is_err(),
            "{name}"
        );
    }
}

#[test]
fn the_file_is_written_private_and_replaced_whole() {
    let path = scratch("write");
    write(&path, &json!({"version": 1, "github": {"source": {"kind": "process", "command": "gh auth token"}}})).unwrap();
    let mode = |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    write(&path, &json!({"version": 1})).unwrap();
    assert_eq!(load(&path).unwrap(), json!({"version": 1}));
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    // A directory group or others can write, as a default Ubuntu account
    // makes `~/.keel`, would have every run refuse the file: it is tightened.
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o775)).unwrap();
    write(&path, &json!({"version": 1})).unwrap();
    assert_eq!(mode(path.parent().unwrap()), 0o755);
    fs::write(&path, "{}").unwrap();
    assert!(
        load(&path)
            .unwrap_err()
            .to_string()
            .contains("not a version 1")
    );
}

#[test]
fn each_host_is_offered_what_it_has() {
    let labels = |host: &FakeHost| {
        key_choices(host, "anthropic", "ANTHROPIC_API_KEY")
            .into_iter()
            .map(|choice| choice.source)
            .collect::<Vec<Value>>()
    };
    let mac = FakeHost {
        macos: true,
        ..FakeHost::default()
    };
    assert_eq!(
        labels(&mac),
        [
            json!({"kind": "process", "command": "/usr/bin/security find-generic-password -w -s keel-anthropic"}),
            json!({"kind": "env", "variable": "ANTHROPIC_API_KEY"}),
        ]
    );
    let linux = FakeHost {
        tools: vec!["secret-tool", "pass", "op", "bw"],
        variables: vec!["DBUS_SESSION_BUS_ADDRESS"],
        ..FakeHost::default()
    };
    assert_eq!(
        labels(&linux),
        [
            json!({"kind": "process", "command": "secret-tool lookup keel anthropic"}),
            json!({"kind": "process", "command": "pass show keel/anthropic"}),
            json!({"kind": "process", "command": "op read op://Private/keel-anthropic/credential"}),
            json!({"kind": "process", "command": "bw get password keel-anthropic"}),
            json!({"kind": "env", "variable": "ANTHROPIC_API_KEY"}),
        ]
    );
    // A keyring with no session to reach it is not offered.
    let headless = FakeHost {
        tools: vec!["secret-tool"],
        ..FakeHost::default()
    };
    assert_eq!(labels(&headless).len(), 1);
}

#[test]
fn a_mac_goes_from_nothing_to_keychain_and_gh() {
    let path = scratch("mac");
    let host = FakeHost {
        macos: true,
        tools: vec!["gh"],
        ..FakeHost::default()
    };
    // Anthropic, Keychain, store it, no more providers, use gh, write.
    let (wrote, output) = guided(&host, &path, &["1", "1", "y", "", "y", "y"]);
    assert!(wrote, "{output}");
    assert_eq!(
        load(&path).unwrap(),
        json!({
            "version": 1,
            "providers": {"api-key": {"source": {
                "kind": "process",
                "command": "/usr/bin/security find-generic-password -w -s keel-anthropic"
            }}},
            "github": {
                "source": {"kind": "process", "command": "gh auth token --hostname github.com"},
                "hint": "sign in first: `gh auth login`"
            }
        })
    );
    assert_eq!(
        *host.ran.borrow(),
        ["/usr/bin/security add-generic-password -U -s keel-anthropic -a operator -w"]
    );
    assert!(output.contains("[ok] the source answers"), "{output}");
    assert!(
        !output.contains("removes group and other write access"),
        "{output}"
    );
    // Rerunning and changing nothing writes nothing.
    let (wrote, output) = guided(&host, &path, &["", "n"]);
    assert!(!wrote);
    assert!(
        output.contains("Model providers configured: api-key"),
        "{output}"
    );
    assert!(output.contains("Nothing changed."), "{output}");
}

#[test]
fn a_locked_source_is_recorded_with_its_unlock_step() {
    let path = scratch("locked");
    let host = FakeHost {
        tools: vec!["pass"],
        locked: vec!["pass show"],
        ..FakeHost::default()
    };
    // Anthropic, pass, do not store, OpenRouter by custom command with a
    // model, done, default openrouter, write.
    let (wrote, output) = guided(
        &host,
        &path,
        &[
            "1",
            "1",
            "n",
            "3",
            "3",
            "printf key",
            "anthropic/claude-sonnet-4.6",
            "",
            "2",
            "y",
        ],
    );
    assert!(wrote, "{output}");
    assert!(output.contains("does not answer yet"), "{output}");
    assert!(output.contains("unlock the gpg agent first"), "{output}");
    assert!(output.contains("`gh` is not installed"), "{output}");
    let document = load(&path).unwrap();
    assert_eq!(
        document["providers"]["api-key"]["hint"],
        "unlock the gpg agent first: `pass show keel/anthropic >/dev/null`"
    );
    assert_eq!(
        document["providers"]["openrouter"]["model"],
        "anthropic/claude-sonnet-4.6"
    );
    assert_eq!(document["default"], "openrouter");
    assert_eq!(document.get("github"), None);
    assert!(host.ran.borrow().is_empty());
}

#[test]
fn bedrock_is_a_profile_and_a_region_and_declining_writes_nothing() {
    let path = scratch("bedrock");
    let host = FakeHost::default();
    // The directory exists and others can write it: the screen says what
    // writing would change, and declining changes nothing.
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o775)).unwrap();
    let (wrote, output) = guided(&host, &path, &["2", "work", "us-west-2", "", "n"]);
    assert!(!wrote);
    assert!(
        output.contains("removes group and other write access"),
        "{output}"
    );
    assert_eq!(
        fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o775
    );
    assert!(output.contains("\"region\": \"us-west-2\""), "{output}");
    assert!(output.contains("aws configure export-credentials --profile work --format process"));
    assert!(output.contains("Not written."), "{output}");
    assert!(!path.exists());
}
