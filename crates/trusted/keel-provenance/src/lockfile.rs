//! Lockfile pins: the registry artifacts an accepted lockfile names by URL
//! and digest, so a fetch of exactly those bytes keeps the declared rank
//! (PLAN D85). Only trusted code reads the lockfile; an untrusted extractor
//! that lied would be a floor lift.

use std::collections::BTreeMap;

/// The largest lockfile admission reads.
pub const MAX_LOCKFILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PINS: usize = 20_000;

/// Each pinned artifact's SHA-512, keyed by the host and path it is fetched
/// from.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LockfilePins {
    pins: BTreeMap<(String, String), [u8; 64]>,
}

impl LockfilePins {
    /// Reads the pins of an npm `package-lock.json` (lockfile version 2 or
    /// 3): every package with an `https` `resolved` URL and a `sha512`
    /// integrity. Packages without both, such as links and Git
    /// dependencies, are not pinned and lower the floor when fetched.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized or malformed lockfile, an
    /// unsupported version, or a package whose two entries disagree.
    pub fn from_npm_lockfile(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_LOCKFILE_BYTES {
            return Err("package-lock.json exceeds 16 MiB".to_owned());
        }
        let lockfile: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("package-lock.json is not JSON: {error}"))?;
        if !matches!(lockfile["lockfileVersion"].as_u64(), Some(2 | 3)) {
            return Err("package-lock.json must be lockfile version 2 or 3".to_owned());
        }
        let packages = lockfile["packages"]
            .as_object()
            .ok_or("package-lock.json has no packages")?;
        let mut pins = BTreeMap::new();
        for entry in packages.values() {
            let (Some(resolved), Some(integrity)) =
                (entry["resolved"].as_str(), entry["integrity"].as_str())
            else {
                continue;
            };
            let (Some(target), Some(digest)) = (https_target(resolved), sha512(integrity)) else {
                continue;
            };
            if pins
                .insert(target, digest)
                .is_some_and(|other| other != digest)
            {
                return Err(format!("package-lock.json pins {resolved} twice"));
            }
            if pins.len() > MAX_PINS {
                return Err("package-lock.json pins too many packages".to_owned());
            }
        }
        Ok(Self { pins })
    }

    /// The digest pinned for a fetch of `path` from `host`.
    #[must_use]
    pub fn get(&self, host: &str, path: &str) -> Option<&[u8; 64]> {
        self.pins.get(&(host.to_owned(), path.to_owned()))
    }

    /// The number of pinned artifacts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Whether nothing is pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

/// The lowercase host and path of a plain `https` URL on the default port,
/// as the client sends them; anything else is not pinned.
fn https_target(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    let split = rest.find('/')?;
    let (host, path) = rest.split_at(split);
    let plain = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.');
    if host.is_empty() || !host.bytes().all(plain) || path.contains(['?', '#']) {
        return None;
    }
    if !path.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    Some((host.to_ascii_lowercase(), path.to_owned()))
}

/// The SHA-512 of a Subresource Integrity string, ignoring weaker hashes.
fn sha512(integrity: &str) -> Option<[u8; 64]> {
    integrity
        .split_ascii_whitespace()
        .find_map(|hash| hash.strip_prefix("sha512-"))
        .and_then(|encoded| base64(encoded.split('?').next().unwrap_or(encoded)))
        .and_then(|bytes| bytes.try_into().ok())
}

fn base64(encoded: &str) -> Option<Vec<u8>> {
    let value = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let trimmed = encoded.trim_end_matches('=');
    if !encoded.len().is_multiple_of(4) || encoded.len() - trimmed.len() > 2 {
        return None;
    }
    let mut bytes = Vec::with_capacity(trimmed.len() * 3 / 4);
    let (mut buffer, mut bits) = (0_u32, 0);
    for byte in trimmed.bytes() {
        buffer = (buffer << 6) | u32::from(value(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(bytes)
}

#[cfg(test)]
#[path = "../tests/support/lockfile.rs"]
mod tests;
