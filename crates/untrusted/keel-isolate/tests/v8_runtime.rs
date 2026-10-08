#![doc = "Process-level checks for the lower-assurance host V8 launcher."]
#![cfg(feature = "vz-backend")]

use std::{
    fs,
    net::{Ipv4Addr, TcpListener},
    os::{
        fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
        unix::fs::PermissionsExt as _,
    },
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn host_v8_uses_bounded_deno_permissions_and_a_clean_environment() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("keel-host-v8-{nonce:x}"));
    let workspace = root.join("workspace");
    fs::create_dir_all(workspace.join(".git")).unwrap();
    let script = workspace.join("agent.mjs");
    fs::write(&script, "console.log('host-v8')\n").unwrap();
    let sdk = root.join("keel-v8-sdk.ts");
    fs::write(&sdk, "export const keel = {};\n").unwrap();
    let invocation = root.join("invocation");
    let environment = root.join("environment");
    let deno = root.join("deno");
    fs::write(
        &deno,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nenv > '{}'\n",
            invocation.display(),
            environment.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&deno, fs::Permissions::from_mode(0o700)).unwrap();
    let request = root.join("request.json");
    fs::write(
        &request,
        serde_json::to_vec(&serde_json::json!({
            "session_id": "host-v8-test",
            "provenance": "floor",
            "isolation": "v8-sandboxed",
            "allow": ["isolation:v8-sandboxed", "egress:crates.io", "egress:bad,host"],
            "harness": "v8",
            "harness_args": ["agent.mjs", "one"],
        }))
        .unwrap(),
    )
    .unwrap();
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    // SAFETY: `proxy_listener` owns a valid descriptor for the duration of the
    // call. A successful dup returns a distinct descriptor that is transferred
    // exactly once into `proxy_fd` below.
    let raw_proxy_fd = unsafe { libc::dup(proxy_listener.as_raw_fd()) };
    assert!(
        raw_proxy_fd >= 0,
        "dup proxy listener: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful duplicate is owned exclusively by `proxy_fd`.
    let proxy_fd = unsafe { OwnedFd::from_raw_fd(raw_proxy_fd) };
    let status = Command::new(env!("CARGO_BIN_EXE_keel-runtime"))
        .args(["run", "--request"])
        .arg(&request)
        .current_dir(&workspace)
        .env("KEEL_DENO", &deno)
        .env("KEEL_V8_SDK", &sdk)
        .env("KEEL_V8_PROXY_PORT", proxy_port.to_string())
        .env("KEEL_V8_PROXY_FD", proxy_fd.as_raw_fd().to_string())
        .env("KEEL_RUN_CA_PEM", "PUBLIC CERTIFICATE")
        .env("HOST_SECRET_FOR_TEST", "must-not-cross")
        .env_remove("KEEL_KERNEL_SOCKET")
        .status()
        .unwrap();
    assert!(status.success());
    let invocation = fs::read_to_string(invocation).unwrap();
    assert!(invocation.contains("--cached-only"));
    let allow_net = invocation
        .lines()
        .find_map(|line| line.strip_prefix("--allow-net="))
        .expect("net permission");
    let hosts = allow_net.split(',').collect::<Vec<_>>();
    assert!(hosts[0].starts_with("127.0.0.1:"));
    assert_eq!(&hosts[1..], ["api.anthropic.com", "crates.io"]);
    assert!(invocation.contains("runner.ts"));
    assert!(invocation.ends_with("one\n"));
    let environment = fs::read_to_string(environment).unwrap();
    assert!(!environment.contains("HOST_SECRET_FOR_TEST"));
    let proxy = environment
        .lines()
        .find_map(|line| line.strip_prefix("HTTPS_PROXY=http://keel:"))
        .expect("proxy carries its per-run credential");
    let (token, address) = proxy.split_once('@').expect("credential and address");
    assert_eq!(token.len(), 32);
    assert!(address.starts_with("127.0.0.1:"));
    assert!(
        !invocation.contains(token),
        "credential must not appear in Deno arguments"
    );
    fs::remove_dir_all(root).unwrap();
}
