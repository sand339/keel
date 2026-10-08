use super::{
    MAX_DETACHED_OUTPUT, completed_exit_status, launcher_sandbox_profile, persist_exit_status,
    remember_detached_output,
};
use nix::sys::termios::{InputFlags, LocalFlags};
use std::{
    fs::File,
    io::{Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
    os::unix::net::UnixStream,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn admission_pty_echoes_input_and_maps_return_to_newline() {
    let pty = nix::pty::openpty(None, None).unwrap();
    super::prepare_slave_terminal(&pty.slave).unwrap();
    let mode = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
    assert!(mode.input_flags.contains(InputFlags::ICRNL));
    assert!(mode.local_flags.contains(LocalFlags::ECHO));
}

#[test]
fn launcher_sandbox_can_execute_its_renderer() {
    let profile = launcher_sandbox_profile(
        Path::new("/install/bin/keel-render-spike"),
        Path::new("/start"),
        Path::new("/workspaces"),
        Path::new("/state/selection.json"),
    );

    assert!(profile.contains("(literal \"/install/bin/keel-render-spike\")"));
    assert!(profile.contains("(subpath \"/start\")"));
    assert!(!profile.contains("/usr/bin/git"));
    assert!(!profile.contains("/usr/libexec/git-core"));
}

#[test]
fn detached_output_keeps_only_the_newest_bounded_bytes() {
    let mut output = vec![b'a'; MAX_DETACHED_OUTPUT - 2];
    remember_detached_output(&mut output, b"bcde");
    assert_eq!(output.len(), MAX_DETACHED_OUTPUT);
    assert_eq!(&output[output.len() - 4..], b"bcde");

    remember_detached_output(&mut output, &vec![b'z'; MAX_DETACHED_OUTPUT + 1]);
    assert_eq!(output, vec![b'z'; MAX_DETACHED_OUTPUT]);
}

#[test]
fn completed_status_survives_until_a_late_attach_reads_it() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("keel-session-exit-{nonce:x}"));
    let status = Command::new("/usr/bin/false").status().unwrap();

    persist_exit_status(&path, status).unwrap();

    assert_eq!(completed_exit_status(&path).unwrap(), Some(1));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn stop_requests_cooperative_runtime_shutdown() {
    let pty = nix::pty::openpty(None, None).unwrap();
    super::prepare_slave_terminal(&pty.slave).unwrap();
    let mut terminal = File::from(pty.master);
    let mut runtime = File::from(pty.slave);
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(b"STOP\n").unwrap();
    let mut attached = None;
    let mut attached_once = false;
    let mut detached_output = Vec::new();

    assert!(
        super::serve_client(
            server,
            &mut terminal,
            &mut attached,
            &mut attached_once,
            &mut detached_output,
        )
        .unwrap()
    );

    let mut shutdown = [0_u8; 2];
    runtime.read_exact(&mut shutdown).unwrap();
    assert_eq!(shutdown, keel_input::encode_shutdown());
    let mut response = [0_u8; 9];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"STOPPING\n");
}
