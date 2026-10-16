use super::confine::{Confinement, stat_process_groups};
use std::{ffi::OsString, path::PathBuf};

#[test]
fn a_confined_child_sees_only_its_paths_and_no_network() {
    let confinement = Confinement {
        read_only: vec![PathBuf::from("/opt/keel")],
        read_write: vec![PathBuf::from("/work space")],
        devices: vec![PathBuf::from("/dev/kvm")],
        directory: Some(PathBuf::from("/work space")),
    };
    let argv = confinement
        .arguments(
            &PathBuf::from("/opt/keel/bin/keel-runtime"),
            &[OsString::from("run")],
        )
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let window = |needle: &[&str]| argv.windows(needle.len()).any(|window| window == needle);

    assert!(window(&["--unshare-all"]), "every namespace is unshared");
    assert!(window(&["--die-with-parent"]));
    assert!(window(&["--new-session"]), "no controlling terminal");
    assert!(window(&["--cap-drop", "ALL"]));
    assert!(!argv.iter().any(|argument| argument == "--share-net"));
    assert!(window(&["--ro-bind", "/opt/keel", "/opt/keel"]));
    assert!(window(&["--bind", "/work space", "/work space"]));
    assert!(window(&["--dev-bind", "/dev/kvm", "/dev/kvm"]));
    assert!(window(&["--chdir", "/work space"]));
    assert!(
        !argv
            .iter()
            .any(|argument| argument == "/" || argument == "/home"),
        "neither the root nor home directories are bound"
    );
    assert_eq!(
        argv[argv.len() - 3..],
        ["--", "/opt/keel/bin/keel-runtime", "run"],
        "the program and its arguments come last, after the separator"
    );
}

#[test]
fn process_groups_are_read_past_a_hostile_command_name() {
    // pid (comm) state ppid pgrp session tty_nr tpgid ...
    let stat = "4242 (evil) 1 2 3) S 1 4242 4242 34816 4242 4194560 0 0";
    assert_eq!(stat_process_groups(stat), Some((4242, 4242)));
    let background = "77 (sh) S 1 77 77 34816 90 0";
    assert_eq!(stat_process_groups(background), Some((77, 90)));
    assert_eq!(stat_process_groups("77 (sh"), None);
}
