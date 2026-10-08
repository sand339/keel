#![doc = "Untrusted microVM backend driver for Keel."]

use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "vz-backend")]
pub mod host_v8;

/// Identifies this crate as outside the trusted computing base.
pub const TRUST_CLASS: &str = "untrusted";

/// Validated host-side inputs required to start one VZ guest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePlan {
    /// Canonical Git workspace shared with the guest.
    pub workspace: PathBuf,
    /// Canonical Linux kernel artifact.
    pub kernel: PathBuf,
    /// Canonical pinned Keel base image.
    pub initramfs: PathBuf,
    /// Read-only root disk the base image mounts, when the image has one.
    pub rootfs: Option<PathBuf>,
}

impl RuntimePlan {
    /// Resolves a runtime plan from the workspace and environment.
    ///
    /// `KEEL_KERNEL` and `KEEL_INITRAMFS` are required; `KEEL_ROOTFS` is used
    /// when set. The workspace must be
    /// a Git worktree so the runtime cannot accidentally expose an unrelated
    /// host directory.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing or invalid workspace or boot artifact.
    pub fn from_environment(workspace: &Path) -> Result<Self, String> {
        let workspace = resolve_workspace(workspace)?;
        let kernel = required_artifact("KEEL_KERNEL")?;
        let initramfs = required_artifact("KEEL_INITRAMFS")?;
        let rootfs = env::var_os("KEEL_ROOTFS")
            .is_some()
            .then(|| required_artifact("KEEL_ROOTFS"))
            .transpose()?;
        Ok(Self {
            workspace,
            kernel,
            initramfs,
            rootfs,
        })
    }
}

/// Resolves and validates a Git workspace without requiring VM boot artifacts.
///
/// # Errors
///
/// Returns an error unless `workspace` is a canonical Git worktree directory.
pub fn resolve_workspace(workspace: &Path) -> Result<PathBuf, String> {
    let workspace = canonical_directory(workspace, "workspace")?;
    if !workspace.join(".git").exists() {
        return Err("workspace is not a Git worktree".to_owned());
    }
    Ok(workspace)
}

fn required_artifact(variable: &str) -> Result<PathBuf, String> {
    let value = env::var_os(variable).ok_or_else(|| format!("{variable} is not set"))?;
    let value = PathBuf::from(value);
    let path = normalized_absolute(&value)
        .then(|| value.clone())
        .map_or_else(|| fs::canonicalize(&value), Ok)
        .map_err(|error| format!("{variable}: {error}"))?;
    if !path.is_file() {
        return Err(format!("{variable} is not a regular file"));
    }
    Ok(path)
}

fn canonical_directory(path: &Path, name: &str) -> Result<PathBuf, String> {
    let path = normalized_absolute(path)
        .then(|| path.to_path_buf())
        .map_or_else(|| fs::canonicalize(path), Ok)
        .map_err(|error| format!("{name}: {error}"))?;
    if !path.is_dir() {
        return Err(format!("{name} is not a directory"));
    }
    Ok(path)
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            !matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{canonical_directory, normalized_absolute};
    use std::{env, fs, path::Path};

    #[test]
    fn only_normalized_absolute_paths_skip_resolution() {
        assert!(normalized_absolute(Path::new("/workspace/project")));
        assert!(!normalized_absolute(Path::new("workspace/project")));
        assert!(!normalized_absolute(Path::new("/workspace/../project")));
        assert!(normalized_absolute(Path::new("/workspace/./project")));
    }

    #[test]
    fn workspace_resolution_rejects_files_and_missing_paths() {
        let root = env::temp_dir().join(format!("keel-runtime-plan-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let file = root.join("file");
        fs::write(&file, b"x").unwrap();
        assert!(canonical_directory(&file, "workspace").is_err());
        assert!(canonical_directory(&root.join("missing"), "workspace").is_err());
        fs::remove_file(file).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
