//! The canonical admission manifest a run records before its workload starts.
//!
//! It binds what the run was admitted with: boot artifacts, policy, workspace,
//! authority, model terms, and run shape. Secrets never enter it. Artifact
//! digests are evidence, not enforcement: the untrusted backend reads the
//! files itself after admission.

use keel_kernel::RunAdmittedEvent;
use keel_provenance::trusted_git_command;
use ring::digest::{Context, SHA256, digest};
use serde_json::Value;
use std::{fmt::Write as _, fs::File, io::Read as _, path::Path};

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The commit at `HEAD` (or `unborn`), whether the worktree differs from it,
/// and the origin URL without any embedded credentials.
pub fn workspace_state(workspace: &Path) -> (String, Option<bool>, Option<String>) {
    let git = |arguments: &[&str]| {
        trusted_git_command()
            .arg("-C")
            .arg(workspace)
            .args(arguments)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let head =
        git(&["rev-parse", "--verify", "--quiet", "HEAD"]).unwrap_or_else(|| "unborn".into());
    let dirty = git(&["status", "--porcelain"]).map(|status| !status.is_empty());
    let origin =
        git(&["config", "--get", "remote.origin.url"]).map(|url| match url.split_once("://") {
            Some((scheme, rest)) => format!(
                "{scheme}://{}",
                rest.rsplit_once('@').map_or(rest, |(_, host)| host)
            ),
            None => url,
        });
    (head, dirty, origin)
}

/// Completes the admission core with boot-artifact digests and canonicalizes
/// it: sorted keys, no whitespace.
///
/// # Errors
///
/// Returns an error when an artifact cannot be read; the run must then refuse.
pub fn finish(
    mut core: Value,
    artifacts: &[(&str, &Path)],
    kernel_release: Option<&str>,
) -> Result<RunAdmittedEvent, String> {
    let mut digests = serde_json::Map::new();
    for (name, path) in artifacts {
        let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut context = Context::new(&SHA256);
        let mut buffer = vec![0_u8; 1 << 16];
        loop {
            let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            context.update(&buffer[..read]);
        }
        digests.insert(
            (*name).to_owned(),
            Value::String(hex(context.finish().as_ref())),
        );
    }
    core["artifacts"] = Value::Object(digests);
    core["kernel_release"] = kernel_release.map_or(Value::Null, Value::from);
    core.sort_all_objects();
    let manifest = core.to_string();
    let mut sha256 = [0_u8; 32];
    sha256.copy_from_slice(digest(&SHA256, manifest.as_bytes()).as_ref());
    Ok(RunAdmittedEvent {
        manifest,
        digest: sha256,
    })
}
