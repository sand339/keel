#![doc = "Triage runs refuse model providers that are not on the approved list."]

use keel_input::RuntimeIntent;
use std::{
    ffi::OsString,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn only_approved_providers_may_run_triage() {
    // SAFETY: this binary's only test sets the variables before any other
    // thread exists or reads the environment.
    unsafe {
        std::env::set_var("KEEL_MODEL_AUTH", "openrouter");
        std::env::set_var("KEEL_OPENROUTER_TARIFF", "anthropic/claude-sonnet-4.6=7,17");
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-triage-provider-{nonce:x}"));
    fs::create_dir(&root).unwrap();
    let path = root.join("request.json");
    let parse = |profile: &str| {
        fs::write(
            &path,
            format!(
                r#"{{"session_id":"p","allow":[],"provenance":"floor","harness":"claude","harness_args":[],"model":"anthropic/claude-sonnet-4.6"{profile}}}"#
            ),
        )
        .unwrap();
        RuntimeIntent::from_runtime_arguments(&[
            OsString::from("run"),
            OsString::from("--request"),
            path.clone().into_os_string(),
        ])
    };
    let error = parse(r#","profile":"triage","scope":["a.target.example"]"#).unwrap_err();
    assert!(error.contains("approved model providers"), "{error}");
    assert!(parse("").is_ok(), "ordinary runs may use OpenRouter");
    fs::remove_dir_all(root).unwrap();
}
