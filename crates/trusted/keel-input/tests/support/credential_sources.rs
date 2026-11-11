use super::{credential_sources_at, derived_push_scope};
use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::PathBuf,
};

const SOURCES: &str = r#"{"version":1,"providers":{"api-key":{"source":{"kind":"process","command":"/usr/bin/security find-generic-password -w -s keel-anthropic"}}}}"#;

/// A private directory holding a sources file, and a workspace beside it.
fn layout(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("keel-sources-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let (home, workspace) = (root.join("home"), root.join("workspace"));
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&workspace).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
    let file = home.join("sources.json");
    fs::write(&file, SOURCES).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    (home, file, workspace)
}

#[test]
fn a_private_sources_file_outside_the_workspace_is_read() {
    let (_, file, workspace) = layout("accepted");
    let sources = credential_sources_at(&file, &workspace).unwrap();
    assert_eq!(
        sources.describe(None, false),
        Vec::<String>::new(),
        "nothing is named for a run that reads no credential"
    );
    assert_ne!(sources, keel_secrets::CredentialSources::default());
}

#[test]
fn a_missing_sources_file_configures_nothing() {
    let (home, _, workspace) = layout("missing");
    let sources = credential_sources_at(&home.join("absent.json"), &workspace).unwrap();
    assert_eq!(sources, keel_secrets::CredentialSources::default());
}

#[test]
fn a_sources_file_others_can_write_is_refused() {
    for mode in [0o620, 0o602, 0o666] {
        let (_, file, workspace) = layout("writable-file");
        fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
        let error = credential_sources_at(&file, &workspace).unwrap_err();
        assert!(error.contains("not writable by group or others"), "{error}");
    }
}

#[test]
fn a_sources_file_in_a_directory_others_can_write_is_refused() {
    let (home, file, workspace) = layout("writable-directory");
    fs::set_permissions(&home, fs::Permissions::from_mode(0o770)).unwrap();
    let error = credential_sources_at(&file, &workspace).unwrap_err();
    assert!(error.contains("not writable by group or others"), "{error}");
}

#[test]
fn a_linked_sources_file_is_refused() {
    let (home, file, workspace) = layout("link");
    let link = home.join("link.json");
    symlink(&file, &link).unwrap();
    let error = credential_sources_at(&link, &workspace).unwrap_err();
    assert!(error.contains("not links"), "{error}");
}

#[test]
fn a_sources_file_inside_the_workspace_is_refused() {
    let (home, file, _) = layout("inside");
    let error = credential_sources_at(&file, &home).unwrap_err();
    assert!(error.contains("inside the workspace"), "{error}");
    // A workspace above the file contains it too.
    let error = credential_sources_at(&file, home.parent().unwrap()).unwrap_err();
    assert!(error.contains("inside the workspace"), "{error}");
}

#[test]
fn a_malformed_sources_file_is_refused_by_name() {
    let (_, file, workspace) = layout("malformed");
    fs::write(&file, r#"{"version":2}"#).unwrap();
    let error = credential_sources_at(&file, &workspace).unwrap_err();
    assert!(error.contains("sources.json refused"), "{error}");
    assert!(error.contains("not version 1"), "{error}");
}

#[test]
fn an_https_github_origin_is_a_scope_as_it_is_spelled() {
    for (origin, path) in [
        ("https://github.com/owner/repo.git", "/owner/repo.git"),
        ("https://github.com/owner/repo", "/owner/repo"),
        ("https://github.com/Owner/Repo.git\n", "/Owner/Repo.git"),
        ("https://github.com/owner/repo/", "/owner/repo"),
        ("https://github.com/o-w.n_r/r.e-p_o", "/o-w.n_r/r.e-p_o"),
    ] {
        assert_eq!(
            derived_push_scope(origin),
            Ok(("github.com".to_owned(), path.to_owned())),
            "{origin}"
        );
    }
}

#[test]
fn every_other_origin_is_refused_with_the_manual_path() {
    for origin in [
        "",
        "git@github.com:owner/repo.git",
        "ssh://git@github.com/owner/repo.git",
        "http://github.com/owner/repo.git",
        "https://gitlab.com/owner/repo.git",
        "https://GitHub.com/owner/repo.git",
        "https://github.com.evil.example/owner/repo.git",
        "https://token@github.com/owner/repo.git",
        "https://user:token@github.com/owner/repo.git",
        "https://github.com:443/owner/repo.git",
        "https://github.com/owner/repo.git?ref=main",
        "https://github.com/owner/repo.git#main",
        "https://github.com/owner",
        "https://github.com/owner/repo/extra",
        "https://github.com/owner/..",
        "https://github.com/../repo",
        "https://github.com//repo",
        "https://github.com/owner/re po",
        "https://github.com/owner/repo%2e",
        "/Users/someone/project",
    ] {
        let error = derived_push_scope(origin).unwrap_err();
        assert!(
            error.contains("KEEL_GIT_CREDENTIAL_PATH"),
            "{origin}: {error}"
        );
    }
}
