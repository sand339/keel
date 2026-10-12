//! The content of a Git push, derived by trusted host Git from the exact
//! receive-pack bytes the push permit binds (PLAN D81).
//!
//! The pack is indexed in a fresh repository whose only other objects are a
//! private base the guest cannot write, so a thin pack resolves against
//! admitted history and nothing else. Pack parsing stays in Git. Only objects
//! the base lacks count as pushed.

use crate::{
    payload::{is_text, list_blobs, read_objects},
    trusted_git_command,
};
use std::{collections::BTreeSet, fs, io::Write as _, path::Path, process::Stdio};

const MAX_COMMANDS: usize = 256;
const MAX_NEW_BLOBS: usize = 4_096;

/// One ref the push updates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefUpdate {
    /// The remote's current object, or zeroes for a new ref.
    pub old: String,
    /// The pushed object, or zeroes for a deletion.
    pub new: String,
    /// The full ref name.
    pub name: String,
}

/// One blob the push adds, at a path where a pushed commit places it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushedBlob {
    /// Path within the pushed tree.
    pub path: String,
    /// The text, or `None` for binary or oversized content.
    pub text: Option<String>,
}

/// What a receive-pack request updates and adds.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PushedContent {
    /// Every ref command, in request order.
    pub updates: Vec<RefUpdate>,
    /// Every new blob reachable from a pushed commit, at each of its paths.
    pub blobs: Vec<PushedBlob>,
}

/// Splits a receive-pack request into its ref commands and the offset of its
/// pack, which is empty for a push that only deletes.
///
/// # Errors
///
/// Returns an error for a malformed pkt-line, command, or object name.
pub fn receive_pack_commands(body: &[u8]) -> Result<(Vec<RefUpdate>, usize), String> {
    let mut offset = 0;
    let mut updates = Vec::new();
    loop {
        let length = body
            .get(offset..offset + 4)
            .and_then(|length| std::str::from_utf8(length).ok())
            .and_then(|length| usize::from_str_radix(length, 16).ok())
            .ok_or("receive-pack request has a malformed pkt-line length")?;
        if length == 0 {
            offset += 4;
            break;
        }
        let line = body
            .get(offset + 4..offset + length)
            .filter(|_| length > 4)
            .ok_or("receive-pack pkt-line is truncated")?;
        offset += length;
        let line = std::str::from_utf8(line).map_err(|_| "receive-pack command is not UTF-8")?;
        let command = line.split('\0').next().unwrap_or_default().trim_end();
        if command.starts_with("shallow ") {
            continue;
        }
        let mut fields = command.splitn(3, ' ');
        let (Some(old), Some(new), Some(name)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err("receive-pack command is malformed".to_owned());
        };
        if !object_name(old) || !object_name(new) || old.len() != new.len() {
            return Err("receive-pack command names an invalid object".to_owned());
        }
        if updates.len() == MAX_COMMANDS {
            return Err("receive-pack request has too many commands".to_owned());
        }
        updates.push(RefUpdate {
            old: old.to_owned(),
            new: new.to_owned(),
            name: name.to_owned(),
        });
    }
    if updates.is_empty() {
        return Err("receive-pack request updates no ref".to_owned());
    }
    Ok((updates, offset))
}

/// Derives what a push adds. `base` is a private bare repository of admitted
/// history; `scratch` is a fresh, absent directory for the index.
///
/// # Errors
///
/// Returns an error when the request is malformed or the pack does not
/// resolve against `base`, such as a thin pack based on objects only the
/// remote holds. The caller treats that as uninspectable.
pub fn derive_push(body: &[u8], base: &Path, scratch: &Path) -> Result<PushedContent, String> {
    let (updates, offset) = receive_pack_commands(body)?;
    let mut content = PushedContent {
        updates,
        blobs: Vec::new(),
    };
    let pack = &body[offset..];
    if pack.is_empty() {
        return Ok(content);
    }
    let git = |arguments: &[&str]| {
        trusted_git_command()
            .arg("-C")
            .arg(scratch)
            .args(arguments)
            .output()
            .map_err(|error| error.to_string())
    };
    fs::create_dir(scratch).map_err(|error| error.to_string())?;
    if !git(&["init", "--bare", "--quiet"])?.status.success() {
        return Err("cannot initialize the push index".to_owned());
    }
    let objects = base
        .join("objects")
        .canonicalize()
        .map_err(|error| error.to_string())?;
    fs::write(
        scratch.join("objects/info/alternates"),
        format!("{}\n", objects.display()),
    )
    .map_err(|error| error.to_string())?;
    let mut index = trusted_git_command()
        .arg("-C")
        .arg(scratch)
        .args(["index-pack", "--stdin", "--fix-thin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdin = index.stdin.take().ok_or("git index-pack has no stdin")?;
    let bytes = pack.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&bytes));
    let indexed = index
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    let _ = writer.join();
    if !indexed.status.success() {
        return Err("the pushed pack does not resolve against admitted history".to_owned());
    }
    // Objects in the pack that the base lacks are what the push adds;
    // `--fix-thin` also copies in the bases it needed, which are not new.
    let pack_index = fs::read_dir(scratch.join("objects/pack"))
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|extension| extension == "idx"))
        .ok_or("git index-pack wrote no index")?;
    let listing = trusted_git_command()
        .arg("-C")
        .arg(scratch)
        .args(["show-index"])
        .stdin(fs::File::open(&pack_index).map_err(|error| error.to_string())?)
        .output()
        .map_err(|error| error.to_string())?;
    let in_pack = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .collect::<Vec<_>>();
    let new = missing_from(base, &in_pack)?;
    for update in content
        .updates
        .iter()
        .filter(|update| !is_zero(&update.new))
    {
        // Paths come from the pushed commit's full tree, which resolves
        // through the base; only blobs the push adds are kept. A tree that
        // does not resolve would hide its content, so it fails the push.
        let entries = list_blobs(scratch, &update.new)
            .ok_or("a pushed commit's tree does not resolve against admitted history")?;
        let added = entries
            .into_iter()
            .filter(|(object, _)| new.contains(object))
            .collect::<Vec<_>>();
        if content.blobs.len() + added.len() > MAX_NEW_BLOBS {
            return Err("the push adds more files than can be inspected".to_owned());
        }
        let names = added
            .iter()
            .map(|(object, _)| object.as_str())
            .collect::<Vec<_>>();
        for ((_, path), body) in added.iter().zip(read_objects(scratch, &names)?) {
            content.blobs.push(PushedBlob {
                path: path.clone(),
                text: is_text(&body).then(|| String::from_utf8_lossy(&body).into_owned()),
            });
        }
    }
    Ok(content)
}

/// The objects among `objects` that `base` does not hold.
fn missing_from(base: &Path, objects: &[String]) -> Result<BTreeSet<String>, String> {
    let mut child = trusted_git_command()
        .arg("-C")
        .arg(base)
        .args(["cat-file", "--batch-check=%(objectname)"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdin = child.stdin.take().ok_or("git cat-file has no stdin")?;
    let request = objects.iter().fold(String::new(), |mut request, object| {
        request.push_str(object);
        request.push('\n');
        request
    });
    let writer = std::thread::spawn(move || stdin.write_all(request.as_bytes()));
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    let _ = writer.join();
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.strip_suffix(" missing"))
        .map(str::to_owned)
        .collect())
}

/// Dependency manifests and CI configuration: changing either alters what
/// runs with the project's authority, so content pushed there is checked on
/// every branch.
#[must_use]
pub fn is_protected_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    path.starts_with(".github/workflows/")
        || path.starts_with(".circleci/")
        || path.starts_with(".buildkite/")
        || matches!(
            path,
            ".gitlab-ci.yml"
                | "Jenkinsfile"
                | "azure-pipelines.yml"
                | ".travis.yml"
                | "bitbucket-pipelines.yml"
        )
        || name.ends_with(".gemspec")
        || matches!(
            name,
            "Cargo.toml"
                | "Cargo.lock"
                | "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "go.mod"
                | "go.sum"
                | "pyproject.toml"
                | "poetry.lock"
                | "uv.lock"
                | "Pipfile"
                | "Pipfile.lock"
                | "requirements.txt"
                | "Gemfile"
                | "Gemfile.lock"
        )
}

fn is_zero(object: &str) -> bool {
    object.bytes().all(|byte| byte == b'0')
}

fn object_name(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "../tests/support/push.rs"]
mod tests;
