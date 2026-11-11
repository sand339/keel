//! The launcher's view of `~/.keel/sources.json`.
//!
//! The trusted runtime reads the same file and is the side that checks it and
//! resolves a credential from it. The launcher reads only what is
//! configuration: which providers are set up, the default, and each
//! provider's region and model.

use crate::CliError;
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write as _},
    os::unix::fs::MetadataExt as _,
    path::PathBuf,
};

/// One configured provider: its source kind and its non-secret settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoredProvider {
    /// `process` or `env`.
    pub kind: String,
    /// The Bedrock region, when the entry names one.
    pub region: Option<String>,
    /// The model a run of this provider defaults to.
    pub model: Option<String>,
}

/// What the sources file configures, without any credential.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoredSources {
    /// Providers by `--auth` name.
    pub providers: BTreeMap<String, StoredProvider>,
    /// The provider a run uses when several are configured.
    pub default: Option<String>,
    /// The GitHub source kind.
    pub github: Option<String>,
}

/// Where the sources file is: `KEEL_SOURCES`, or `~/.keel/sources.json`.
#[must_use]
pub fn path() -> Option<PathBuf> {
    env::var_os("KEEL_SOURCES")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".keel/sources.json")))
}

/// Reads the sources file. A missing file configures nothing.
///
/// # Errors
///
/// Returns why the trusted runtime would refuse the file: it or its directory
/// is a link, owned by someone else, or writable by group or others, or it
/// does not parse. The runtime makes the binding check; this one lets `keel
/// doctor` and the launcher say so before a run does.
pub fn inspect() -> Result<StoredSources, String> {
    path().map_or_else(|| Ok(StoredSources::default()), |path| inspect_at(&path))
}

pub(crate) fn inspect_at(path: &std::path::Path) -> Result<StoredSources, String> {
    let Ok(file) = fs::symlink_metadata(path) else {
        return Ok(StoredSources::default());
    };
    let directory = path
        .parent()
        .and_then(|directory| fs::symlink_metadata(directory).ok())
        .ok_or("its directory is unreadable")?;
    if !file.is_file() || !directory.is_dir() {
        return Err("it and its directory must not be links".to_owned());
    }
    if file.uid() != directory.uid() || (file.mode() | directory.mode()) & 0o022 != 0 {
        return Err(format!(
            "it and its directory must be owned by you and not writable by group or others; \
run `chmod go-w {} {}`",
            path.display(),
            path.parent().unwrap_or(path).display()
        ));
    }
    parse(&fs::read(path).map_err(|error| error.to_string())?)
}

/// The sources file for a run about to start.
///
/// # Errors
///
/// Returns the refusal the trusted runtime would give, so a run names the
/// file instead of reporting that no credential is configured.
pub fn checked() -> Result<StoredSources, CliError> {
    inspect().map_err(|problem| {
        CliError::new(format!(
            "credential sources {} refused: {problem}",
            path().unwrap_or_default().display()
        ))
    })
}

/// The sources file, or nothing when it is absent or would be refused; the
/// trusted runtime reports a refusal itself when the run starts.
#[must_use]
pub fn load() -> StoredSources {
    inspect().unwrap_or_default()
}

fn parse(bytes: &[u8]) -> Result<StoredSources, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| format!("it is not JSON: {error}"))?;
    if value.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err("it is not version 1".to_owned());
    }
    let text = |value: &serde_json::Value, name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let kind = |entry: &serde_json::Value| {
        entry
            .get("source")
            .and_then(|source| text(source, "kind"))
            .ok_or("an entry has no source kind")
    };
    let mut sources = StoredSources {
        default: text(&value, "default"),
        github: value.get("github").map(kind).transpose()?,
        providers: BTreeMap::new(),
    };
    if let Some(providers) = value
        .get("providers")
        .and_then(serde_json::Value::as_object)
    {
        for (name, entry) in providers {
            sources.providers.insert(
                name.clone(),
                StoredProvider {
                    kind: kind(entry)?,
                    region: text(entry, "region"),
                    model: text(entry, "model"),
                },
            );
        }
    }
    if let Some(default) = &sources.default
        && !sources.providers.contains_key(default)
    {
        return Err(format!(
            "its default `{default}` is not a configured provider"
        ));
    }
    Ok(sources)
}

impl StoredSources {
    /// The provider a run uses when `--auth` and the environment name none:
    /// the only one configured, the default, or the operator's answer.
    ///
    /// # Errors
    ///
    /// Returns an error when several providers are configured with no default
    /// and there is no terminal to ask through, or the answer names none.
    pub fn choose(&self, interactive: bool) -> Result<Option<String>, CliError> {
        let names = self.providers.keys().cloned().collect::<Vec<_>>();
        if let [only] = names.as_slice() {
            return Ok(Some(only.clone()));
        }
        if names.is_empty() || self.default.is_some() {
            return Ok(self.default.clone());
        }
        let choices = names.join("|");
        if !interactive {
            return Err(CliError::new(format!(
                "several model providers are configured with no default; pass --auth {choices}"
            )));
        }
        println!("Several model providers are configured for this host.");
        for (index, name) in names.iter().enumerate() {
            println!("  {}) {name}", index + 1);
        }
        print!("Which should this run use? [1-{}]: ", names.len());
        io::stdout()
            .flush()
            .map_err(|error| CliError::new(error.to_string()))?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|error| CliError::new(error.to_string()))?;
        answer
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|index| names.get(index.checked_sub(1)?))
            .map(|name| Some(name.clone()))
            .ok_or_else(|| {
                CliError::new(format!(
                    "`{}` is not one of the choices; pass --auth {choices} to choose without \
being asked",
                    answer.trim()
                ))
            })
    }

    /// The stored model for a run of `auth`, when it names one.
    #[must_use]
    pub fn model(&self, auth: Option<&str>) -> Option<String> {
        self.providers.get(auth?)?.model.clone()
    }

    /// The stored region for a Bedrock run, when the environment names none.
    #[must_use]
    pub fn region(&self, auth: Option<&str>) -> Option<String> {
        if auth != Some("bedrock") || env::var_os("AWS_REGION").is_some() {
            return None;
        }
        self.providers.get("bedrock")?.region.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{StoredSources, parse};

    const EXAMPLE: &str = r#"{
      "version": 1,
      "providers": {
        "api-key": {"source": {"kind": "process", "command": "/usr/bin/security find-generic-password -w -s keel-anthropic"}},
        "bedrock": {"source": {"kind": "process", "command": "aws …"}, "region": "us-west-2"},
        "openrouter": {"source": {"kind": "env", "variable": "OPENROUTER_API_KEY"}, "model": "anthropic/claude-sonnet-4.6"}
      },
      "default": "api-key",
      "github": {"source": {"kind": "process", "command": "gh auth token --hostname github.com"}}
    }"#;

    #[test]
    fn the_launcher_reads_configuration_only() {
        let sources = parse(EXAMPLE.as_bytes()).unwrap();
        assert_eq!(sources.providers["api-key"].kind, "process");
        assert_eq!(sources.github.as_deref(), Some("process"));
        assert_eq!(
            sources.model(Some("openrouter")).as_deref(),
            Some("anthropic/claude-sonnet-4.6")
        );
        assert_eq!(sources.model(Some("api-key")), None);
        assert_eq!(sources.model(None), None);
        assert_eq!(sources.region(Some("api-key")), None);
        if std::env::var_os("AWS_REGION").is_none() {
            assert_eq!(
                sources.region(Some("bedrock")).as_deref(),
                Some("us-west-2")
            );
        }
    }

    #[test]
    fn a_run_takes_the_only_provider_or_the_default() {
        let sources = parse(EXAMPLE.as_bytes()).unwrap();
        assert_eq!(sources.choose(false).unwrap().as_deref(), Some("api-key"));
        let mut one = StoredSources::default();
        one.providers
            .insert("bedrock".to_owned(), super::StoredProvider::default());
        assert_eq!(one.choose(false).unwrap().as_deref(), Some("bedrock"));
        assert_eq!(StoredSources::default().choose(false).unwrap(), None);
        let mut several = sources;
        several.default = None;
        let error = several.choose(false).unwrap_err().to_string();
        assert!(
            error.contains("--auth api-key|bedrock|openrouter"),
            "{error}"
        );
    }

    #[test]
    fn a_default_must_be_configured() {
        let error = parse(br#"{"version":1,"default":"bedrock"}"#).unwrap_err();
        assert!(error.contains("not a configured provider"), "{error}");
        assert!(parse(br#"{"version":2}"#).is_err());
    }
}
