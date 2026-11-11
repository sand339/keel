//! Credential sources: where the trusted runtime fetches a credential at
//! launch. The sources file names commands and variables, never a secret.
//!
//! There are two kinds. A keyring, a password manager, or the `gh` login is a
//! `process` source whose command the operator can read at admission, so
//! trusted code knows how to run a command and nothing about any one tool.

use serde_json::Value;
use std::{collections::BTreeMap, process::Command};
use zeroize::Zeroizing;

/// Search path for every stored source's command; never the operator's own
/// `PATH`, which a workspace's tooling may have extended.
const SOURCE_PATH: &str = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin";
const MAX_FIELD: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Source {
    Env(String),
    Process(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    source: Source,
    /// What the operator does when the source is locked, shown on failure.
    hint: Option<String>,
}

/// The credential sources an operator stored, keyed by `--auth` name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialSources {
    providers: BTreeMap<String, Entry>,
    github: Option<Entry>,
}

/// Environment variables that outrank a provider's stored source, so a setup
/// that predates the sources file behaves as it always has.
fn overrides(name: &str) -> &'static [&'static str] {
    match name {
        "api-key" => &["ANTHROPIC_API_KEY"],
        "openrouter" => &["OPENROUTER_API_KEY"],
        "bedrock" => &[
            "AWS_BEARER_TOKEN_BEDROCK",
            "KEEL_AWS_CREDENTIAL_PROCESS",
            "AWS_ACCESS_KEY_ID",
        ],
        _ => &["GH_TOKEN", "GITHUB_TOKEN"],
    }
}

fn printable(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_FIELD && !text.chars().any(char::is_control)
}

impl CredentialSources {
    /// Parses a version 1 sources file. Fields the trusted runtime does not
    /// use (`default`, `model`, `region`) are the launcher's and are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, another version, an unknown
    /// provider or kind, and any field that is not short printable text.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("the sources file is not JSON: {error}"))?;
        if value.get("version").and_then(Value::as_u64) != Some(1) {
            return Err("the sources file is not version 1".to_owned());
        }
        let mut sources = Self::default();
        if let Some(providers) = value.get("providers") {
            let providers = providers
                .as_object()
                .ok_or("the sources file's `providers` is not an object")?;
            for (name, entry) in providers {
                if !matches!(name.as_str(), "api-key" | "bedrock" | "openrouter") {
                    return Err(format!(
                        "the sources file names an unknown provider {name:?}"
                    ));
                }
                sources.providers.insert(name.clone(), Entry::parse(entry)?);
            }
        }
        if let Some(entry) = value.get("github") {
            sources.github = Some(Entry::parse(entry)?);
        }
        Ok(sources)
    }

    /// The stored entry a run would use: none when the provider's own
    /// environment variables are set.
    fn stored(&self, name: &str) -> Option<&Entry> {
        if overrides(name)
            .iter()
            .any(|variable| std::env::var_os(variable).is_some())
        {
            return None;
        }
        match name {
            "github" => self.github.as_ref(),
            name => self.providers.get(name),
        }
    }

    /// Names, never values, of the stored sources a run of this provider
    /// would read, for the admission screen and manifest.
    #[must_use]
    pub fn describe(&self, provider: Option<&str>, github: bool) -> Vec<String> {
        let line = |label: &str, name: &str| {
            self.stored(name)
                .map(|entry| format!("{label}: {}", entry.source.describe()))
        };
        provider
            .and_then(|name| line("model credential", name))
            .into_iter()
            .chain(
                github
                    .then(|| line("GitHub credential", "github"))
                    .flatten(),
            )
            .collect()
    }

    /// Resolves one provider's stored secret, when its environment does not
    /// already supply one.
    pub(crate) fn secret(&self, name: &str) -> Result<Option<String>, String> {
        let Some(entry) = self.stored(name) else {
            return Ok(None);
        };
        Ok(entry
            .resolve()?
            .map(|mut secret| std::mem::take(&mut *secret)))
    }

    /// The stored regional credential: a bearer token, or the command that
    /// prints signing credentials, which is kept so a long run can renew.
    pub(crate) fn bedrock(&self) -> Result<(Option<String>, Option<Command>), String> {
        match self.stored("bedrock") {
            Some(Entry {
                source: Source::Process(command),
                ..
            }) => Ok((None, Some(shell(command)))),
            _ => Ok((self.secret("bedrock")?, None)),
        }
    }

    /// Whether the operator stored a GitHub source, which is what lets a run
    /// derive its push scope from the workspace's origin.
    #[must_use]
    pub const fn has_github(&self) -> bool {
        self.github.is_some()
    }

    /// The stored GitHub token, or the fallback's when no source is stored.
    /// A source that fails narrows the run to no token; it never stops it.
    pub(crate) fn github(&self, fallback: impl FnOnce() -> Option<String>) -> Option<String> {
        match self.stored("github") {
            Some(_) => self.secret("github").ok().flatten(),
            None => fallback(),
        }
    }
}

impl Entry {
    fn parse(value: &Value) -> Result<Self, String> {
        let source = value
            .get("source")
            .ok_or("a sources entry has no `source`")?;
        let text = |from: &Value, name: &str| match from.get(name) {
            None => Ok(None),
            Some(field) => field
                .as_str()
                .filter(|text| printable(text))
                .map(|text| Some(text.to_owned()))
                .ok_or_else(|| format!("sources field `{name}` is not short printable text")),
        };
        let required = |name: &str| {
            text(source, name)?.ok_or_else(|| format!("a sources entry needs `{name}`"))
        };
        let source = match source.get("kind").and_then(Value::as_str) {
            Some("env") => Source::Env(required("variable")?),
            Some("process") => Source::Process(required("command")?),
            other => return Err(format!("sources kind {other:?} is not env or process")),
        };
        Ok(Self {
            source,
            hint: text(value, "hint")?,
        })
    }

    /// Reads the secret. An unset `env` variable is `None`, which is today's
    /// behavior; a command that prints nothing is an error.
    fn resolve(&self) -> Result<Option<Zeroizing<String>>, String> {
        let mut command = match &self.source {
            Source::Env(variable) => {
                return Ok(std::env::var(variable)
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(Zeroizing::new));
            }
            Source::Process(command) => shell(command),
        };
        let label = self.source.describe();
        let secret = crate::run_credential_command(
            &mut command,
            &label,
            false,
            crate::CREDENTIAL_PROCESS_TIMEOUT,
        )
        .and_then(|output| {
            std::str::from_utf8(&output)
                .ok()
                .map(str::trim)
                .filter(|secret| !secret.is_empty())
                .map(|secret| Zeroizing::new(secret.to_owned()))
                .ok_or_else(|| format!("{label} printed no credential"))
        })
        .map_err(|error| match &self.hint {
            Some(hint) => format!("{error}; {hint}"),
            None => error,
        })?;
        Ok(Some(secret))
    }
}

impl Source {
    fn describe(&self) -> String {
        match self {
            Self::Env(variable) => format!("environment variable {variable}"),
            Self::Process(command) => format!("command `{command}`"),
        }
    }
}

/// A stored `process` source's command, run by the shell so it reads as the
/// operator wrote it.
fn shell(command: &str) -> Command {
    let mut shell = Command::new("/bin/sh");
    shell.arg("-c").arg(command);
    harden(&mut shell);
    shell
}

/// A stored source's command finds its program on a fixed path, runs outside
/// the workspace, and is told of no terminal to prompt on: a source that
/// would prompt fails instead of drawing on the operator's terminal.
fn harden(command: &mut Command) {
    command
        .env("PATH", SOURCE_PATH)
        .env_remove("GPG_TTY")
        .env_remove("SSH_ASKPASS")
        .current_dir("/");
}

#[cfg(test)]
#[path = "../tests/support/sources.rs"]
mod tests;
