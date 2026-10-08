//! Confidentiality index for payload provenance.
//!
//! At admission the trusted runtime indexes the repository as committed at
//! `HEAD`. Each outgoing request payload is then scanned for verbatim
//! fragments of that content. Fingerprints are winnowed k-gram hashes
//! (Schleimer, Wilkerson, and Aiken, 2003): any shared run of at least
//! `K + W - 1` normalized bytes is guaranteed to share a fingerprint, with
//! memory bounded by about one fingerprint per `W` bytes.
//!
//! Paraphrased, summarized, compressed, or re-encoded content is not detected.
//! A match is evidence that private bytes are leaving, not proof of intent.

use crate::trusted_git_command;
use std::{collections::HashSet, io::Write as _, path::Path, process::Stdio};

const K: usize = 48;
const W: usize = 24;
const BASE: u64 = 0x0000_0100_0000_01B3;
const MAX_BLOB_BYTES: usize = 1 << 20;
const MAX_INDEXED_BYTES: usize = 64 << 20;
const MAX_FINGERPRINTS: usize = 4 << 20;

/// Who may receive content.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Confidentiality {
    /// Anyone.
    Public,
    /// The repository's own remote and the model endpoint.
    Private,
    /// Only the model endpoint.
    Secret,
}

/// Fingerprints of admitted confidential content.
#[derive(Debug, Default)]
pub struct PayloadIndex {
    private: HashSet<u64>,
    secret: HashSet<u64>,
    truncated: bool,
}

/// Fragment counts found in one payload.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FragmentCounts {
    /// Fingerprints matching private content.
    pub private: u32,
    /// Fingerprints matching secret content.
    pub secret: u32,
}

impl FragmentCounts {
    /// The most confidential label present, if any fragment matched.
    #[must_use]
    pub const fn label(self) -> Option<Confidentiality> {
        if self.secret > 0 {
            Some(Confidentiality::Secret)
        } else if self.private > 0 {
            Some(Confidentiality::Private)
        } else {
            None
        }
    }
}

impl PayloadIndex {
    /// Indexes text blobs in the `HEAD` tree with the hardened host Git.
    /// Paths that conventionally hold credentials are labeled secret, and
    /// every other text blob is private.
    ///
    /// # Errors
    ///
    /// Returns an error when the tree cannot be listed or read.
    pub fn from_git_head(workspace: &Path) -> Result<Self, String> {
        let listing = trusted_git_command()
            .arg("-C")
            .arg(workspace)
            .args([
                "ls-tree",
                "-r",
                "-z",
                "--format=%(objecttype) %(objectname) %(path)",
                "HEAD",
            ])
            .output()
            .map_err(|error| error.to_string())?;
        let mut index = Self::default();
        if !listing.status.success() {
            // An unborn branch has nothing committed to protect.
            return Ok(index);
        }
        let entries = listing
            .stdout
            .split(|byte| *byte == 0)
            .filter_map(|entry| {
                // Submodules are commits in another repository; only blobs
                // hold this repository's content.
                let entry = std::str::from_utf8(entry).ok()?.strip_prefix("blob ")?;
                let (object, path) = entry.split_once(' ')?;
                Some((object.to_owned(), path.to_owned()))
            })
            .collect::<Vec<_>>();
        let mut child = trusted_git_command()
            .arg("-C")
            .arg(workspace)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        let mut stdin = child.stdin.take().ok_or("git cat-file has no stdin")?;
        let objects = entries
            .iter()
            .fold(String::new(), |mut objects, (object, _)| {
                objects.push_str(object);
                objects.push('\n');
                objects
            });
        let writer = std::thread::spawn(move || stdin.write_all(objects.as_bytes()));
        let output = child
            .wait_with_output()
            .map_err(|error| error.to_string())?;
        writer
            .join()
            .map_err(|_| "git cat-file writer panicked")?
            .map_err(|error| error.to_string())?;
        let mut rest = output.stdout.as_slice();
        let mut indexed = 0_usize;
        for (_, path) in &entries {
            let header_end = rest
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or("truncated cat-file output")?;
            let header =
                std::str::from_utf8(&rest[..header_end]).map_err(|error| error.to_string())?;
            let size = header
                .rsplit(' ')
                .next()
                .and_then(|size| size.parse::<usize>().ok())
                .ok_or("malformed cat-file header")?;
            let body = rest
                .get(header_end + 1..header_end + 1 + size)
                .ok_or("truncated blob")?;
            rest = rest.get(header_end + 2 + size..).unwrap_or_default();
            let text =
                body.len() <= MAX_BLOB_BYTES && !body.iter().take(8192).any(|byte| *byte == 0);
            if text && indexed + body.len() <= MAX_INDEXED_BYTES {
                indexed += body.len();
                index.add(classify_path(path), body);
            } else if text {
                index.truncated = true;
            }
        }
        Ok(index)
    }

    /// Adds one content item under a label. Public content is not indexed.
    pub fn add(&mut self, label: Confidentiality, content: &[u8]) {
        let set = match label {
            Confidentiality::Public => return,
            Confidentiality::Private => &mut self.private,
            Confidentiality::Secret => &mut self.secret,
        };
        for fingerprint in fingerprints(&normalize(content)) {
            if set.len() >= MAX_FINGERPRINTS {
                self.truncated = true;
                return;
            }
            set.insert(fingerprint);
        }
    }

    /// Whether some admitted content was too large to index fully.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Counts indexed fingerprints in a request target and body, after
    /// undoing percent and JSON string escaping.
    #[must_use]
    pub fn scan(&self, payload: &[u8]) -> FragmentCounts {
        let mut counts = FragmentCounts::default();
        if self.private.is_empty() && self.secret.is_empty() {
            return counts;
        }
        for fingerprint in fingerprints(&normalize(&unescape(payload))) {
            if self.secret.contains(&fingerprint) {
                counts.secret = counts.secret.saturating_add(1);
            } else if self.private.contains(&fingerprint) {
                counts.private = counts.private.saturating_add(1);
            }
        }
        counts
    }
}

/// Labels conventional credential files secret and everything else private.
#[must_use]
pub fn classify_path(path: &str) -> Confidentiality {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let secret = name.starts_with(".env")
        || name.starts_with("id_rsa")
        || name.starts_with("id_ecdsa")
        || name.starts_with("id_ed25519")
        || [".pem", ".key", ".p12", ".pfx"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        || matches!(
            name.as_str(),
            "credentials" | ".netrc" | ".npmrc" | ".pypirc"
        );
    if secret {
        Confidentiality::Secret
    } else {
        Confidentiality::Private
    }
}

/// Collapses every run of ASCII whitespace to one space, so reflowed text
/// still matches.
fn normalize(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut space = false;
    for byte in bytes {
        if byte.is_ascii_whitespace() {
            space = true;
        } else {
            if space && !output.is_empty() {
                output.push(b' ');
            }
            space = false;
            output.push(*byte);
        }
    }
    output
}

/// Decodes percent escapes, `+`, and the JSON string escapes that carry text
/// in request bodies. Unrecognized escapes are kept literally.
fn unescape(bytes: &[u8]) -> Vec<u8> {
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let next = bytes.get(index + 1).copied();
        match (bytes[index], next) {
            (b'%', Some(high)) => match (hex(high), bytes.get(index + 2).and_then(|low| hex(*low)))
            {
                (Some(high), Some(low)) => {
                    output.push(u8::try_from(high * 16 + low).unwrap_or(b'%'));
                    index += 3;
                    continue;
                }
                _ => output.push(b'%'),
            },
            (b'+', _) => output.push(b' '),
            (b'\\', Some(escape @ (b'n' | b't' | b'r' | b'"' | b'\\' | b'/'))) => {
                output.push(match escape {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    other => other,
                });
                index += 2;
                continue;
            }
            (byte, _) => output.push(byte),
        }
        index += 1;
    }
    output
}

/// Winnowed rolling hashes of every `K`-byte window.
fn fingerprints(bytes: &[u8]) -> Vec<u64> {
    if bytes.len() < K {
        return Vec::new();
    }
    let top = (1..K).fold(1_u64, |power, _| power.wrapping_mul(BASE));
    let mut hashes = Vec::with_capacity(bytes.len() - K + 1);
    let mut hash = bytes[..K].iter().fold(0_u64, |hash, byte| {
        hash.wrapping_mul(BASE).wrapping_add(u64::from(*byte))
    });
    hashes.push(hash);
    for index in K..bytes.len() {
        hash = hash
            .wrapping_sub(u64::from(bytes[index - K]).wrapping_mul(top))
            .wrapping_mul(BASE)
            .wrapping_add(u64::from(bytes[index]));
        hashes.push(hash);
    }
    // A monotonic deque yields each window's rightmost minimum in O(n); a
    // position is emitted once, when it first becomes a window's minimum.
    let window = W.min(hashes.len());
    let mut selected = Vec::with_capacity(hashes.len() / W + 1);
    let mut candidates = std::collections::VecDeque::<usize>::new();
    let mut last = None;
    for (position, hash) in hashes.iter().enumerate() {
        while candidates.back().is_some_and(|back| hashes[*back] >= *hash) {
            candidates.pop_back();
        }
        candidates.push_back(position);
        if candidates
            .front()
            .is_some_and(|front| *front + window <= position)
        {
            candidates.pop_front();
        }
        if position + 1 >= window
            && let Some(&minimum) = candidates.front()
            && last != Some(minimum)
        {
            selected.push(hashes[minimum]);
            last = Some(minimum);
        }
    }
    selected
}

/// Lines the model emitted in tool-call arguments during this run: file
/// writes, edits, and shell commands. Pushed content is accounted for when
/// its lines appear here.
#[derive(Debug, Default)]
pub struct ModelOutputIndex {
    lines: HashSet<u64>,
}

impl ModelOutputIndex {
    /// Records every line of one tool-call argument.
    pub fn add(&mut self, text: &str) {
        for fingerprint in text.lines().filter_map(line_fingerprint) {
            if self.lines.len() >= MAX_FINGERPRINTS {
                return;
            }
            self.lines.insert(fingerprint);
        }
    }

    /// Whether the model emitted this line. `None` for a line too short to
    /// say anything about where it came from, such as a lone brace.
    #[must_use]
    pub fn accounts_for(&self, line: &str) -> Option<bool> {
        line_fingerprint(line).map(|fingerprint| self.lines.contains(&fingerprint))
    }
}

/// FNV-1a of a line with surrounding whitespace removed, or `None` when
/// fewer than four characters remain.
fn line_fingerprint(line: &str) -> Option<u64> {
    let line = line.trim();
    (line.chars().count() >= 4).then(|| {
        line.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    })
}
