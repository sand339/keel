//! `keel init`: guided setup that records where each credential comes from.
//!
//! This is untrusted code. It writes `~/.keel/sources.json`, which the trusted
//! runtime checks and reads when a run starts, and it runs the same commands
//! an operator would. It never reads, holds, or stores a credential: storing a
//! key is done by the keyring's own tool on the operator's terminal, and a
//! source is tested by running its command and discarding what it prints.

use crate::{CliError, setup, sources};
use serde_json::{Value, json};
use std::{
    env,
    ffi::OsString,
    fs,
    io::{BufRead, Write},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// The search path the trusted runtime gives a stored command.
const SOURCE_PATH: &str = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin";
const PROVIDERS: [&str; 3] = ["api-key", "bedrock", "openrouter"];
const GH_COMMAND: &str = "gh auth token --hostname github.com";
/// The first session's script. It ships inside the launcher, so a release
/// needs no extra file and the script cannot be swapped on disk.
const DEMO_SCRIPT: &str = include_str!("init-demo.mjs");

/// What `keel init` was asked to record without prompting.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InitOptions {
    /// `(provider, command)` sources to record.
    pub sets: Vec<(String, String)>,
    /// `(provider, model)` defaults to record.
    pub models: Vec<(String, String)>,
    /// The Bedrock region to record.
    pub region: Option<String>,
    /// The GitHub token command to record.
    pub github: Option<String>,
    /// The provider a run uses when several are configured.
    pub default: Option<String>,
}

impl InitOptions {
    /// Whether any answer was given by flag, which makes the run scripted:
    /// no prompt, no test of the sources, and no first session.
    #[must_use]
    pub fn scripted(&self) -> bool {
        *self != Self::default()
    }
}

/// Parses `keel init` arguments.
///
/// # Errors
///
/// Returns a usage error for an unknown flag, a missing value, or a value
/// that is not `NAME=VALUE` where one is required.
pub fn parse(arguments: &[OsString]) -> Result<InitOptions, CliError> {
    const USAGE: &str = "usage: keel init [--set PROVIDER=COMMAND]... [--model PROVIDER=MODEL]... \
[--region REGION] [--github COMMAND] [--default PROVIDER]";
    let mut options = InitOptions::default();
    let mut arguments = arguments.iter().map(|value| value.to_str());
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .flatten()
            .ok_or_else(|| CliError::new(USAGE))?
            .to_owned();
        let pair = |value: &str| {
            value
                .split_once('=')
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .ok_or_else(|| CliError::new(USAGE))
        };
        match flag {
            Some("--set") => options.sets.push(pair(&value)?),
            Some("--model") => options.models.push(pair(&value)?),
            Some("--region") => options.region = Some(value),
            Some("--github") => options.github = Some(value),
            Some("--default") => options.default = Some(value),
            _ => return Err(CliError::new(USAGE)),
        }
    }
    Ok(options)
}

/// What `init` needs from the machine, so the flow can be tested without one.
trait Host {
    fn macos(&self) -> bool;
    fn user(&self) -> String;
    /// Whether a program is on the path stored commands are given.
    fn has(&self, program: &str) -> bool;
    fn env(&self, name: &str) -> bool;
    /// Runs a source's command as the trusted runtime will and reports
    /// whether it printed something, without keeping what it printed.
    fn check(&self, command: &str) -> Result<(), String>;
    /// Runs a command on the operator's terminal.
    fn run(&self, argv: &[String]) -> bool;
}

struct Machine;

impl Host for Machine {
    fn macos(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn user(&self) -> String {
        env::var("USER").unwrap_or_default()
    }

    fn has(&self, program: &str) -> bool {
        SOURCE_PATH
            .split(':')
            .any(|directory| Path::new(directory).join(program).is_file())
    }

    fn env(&self, name: &str) -> bool {
        env::var_os(name).is_some()
    }

    fn check(&self, command: &str) -> Result<(), String> {
        let output = Command::new("/bin/sh")
            .args(["-c", command])
            .env("PATH", SOURCE_PATH)
            .env_remove("GPG_TTY")
            .env_remove("SSH_ASKPASS")
            .current_dir("/")
            .stdin(Stdio::null())
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "{}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        if output.stdout.iter().all(u8::is_ascii_whitespace) {
            return Err("it printed nothing".to_owned());
        }
        Ok(())
    }

    fn run(&self, argv: &[String]) -> bool {
        argv.split_first().is_some_and(|(program, arguments)| {
            Command::new(program)
                .args(arguments)
                .status()
                .is_ok_and(|status| status.success())
        })
    }
}

/// One way this host could supply a credential.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Choice {
    label: String,
    source: Value,
    /// The keyring's own command that stores the item, prompting for it.
    store: Option<Vec<String>>,
    hint: Option<String>,
}

fn process(command: &str) -> Value {
    json!({"kind": "process", "command": command})
}

/// The sources this host can offer for an API key, most integrated first.
fn key_choices(host: &dyn Host, item: &str, variable: &str) -> Vec<Choice> {
    let strings = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
    let mut choices = Vec::new();
    if host.macos() {
        let service = format!("keel-{item}");
        choices.push(Choice {
            label: format!("macOS Keychain item `{service}`"),
            source: process(&format!(
                "/usr/bin/security find-generic-password -w -s {service}"
            )),
            store: Some(strings(&[
                "/usr/bin/security",
                "add-generic-password",
                "-U",
                "-s",
                &service,
                "-a",
                &host.user(),
                "-w",
            ])),
            hint: None,
        });
    }
    if host.has("secret-tool") && host.env("DBUS_SESSION_BUS_ADDRESS") {
        choices.push(Choice {
            label: format!("desktop keyring item `keel {item}` (secret-tool)"),
            source: process(&format!("secret-tool lookup keel {item}")),
            store: Some(strings(&[
                "secret-tool",
                "store",
                &format!("--label=Keel {item}"),
                "keel",
                item,
            ])),
            hint: Some("unlock the desktop keyring by logging in to the desktop".to_owned()),
        });
    }
    if host.has("pass") {
        choices.push(Choice {
            label: format!("pass entry `keel/{item}`"),
            source: process(&format!("pass show keel/{item}")),
            store: Some(strings(&["pass", "insert", &format!("keel/{item}")])),
            hint: Some(format!(
                "unlock the gpg agent first: `pass show keel/{item} >/dev/null`"
            )),
        });
    }
    if host.has("op") {
        choices.push(Choice {
            label: format!("1Password item `keel-{item}` (create it in 1Password first)"),
            source: process(&format!("op read op://Private/keel-{item}/credential")),
            store: None,
            hint: Some(
                "sign in first: `eval $(op signin)`, or enable the app's CLI integration"
                    .to_owned(),
            ),
        });
    }
    if host.has("bw") {
        choices.push(Choice {
            label: format!("Bitwarden item `keel-{item}` (create it in Bitwarden first)"),
            source: process(&format!("bw get password keel-{item}")),
            store: None,
            hint: Some(
                "unlock first: `export BW_SESSION=$(bw unlock --raw)` in the shell that starts Keel"
                    .to_owned(),
            ),
        });
    }
    choices.push(Choice {
        label: format!("the environment variable {variable} (exported in every shell)"),
        source: json!({"kind": "env", "variable": variable}),
        store: None,
        hint: None,
    });
    choices
}

/// Whether trusted parsing will take this text: short and printable.
fn printable(text: &str) -> bool {
    !text.is_empty() && text.len() <= 512 && !text.chars().any(char::is_control)
}

/// Records one entry, keeping what the launcher stored beside it before.
fn set_entry(entry: &mut Value, source: Value, hint: Option<&str>) -> Result<(), CliError> {
    let texts = ["command", "variable"]
        .iter()
        .filter_map(|name| source.get(name).and_then(Value::as_str))
        .chain(hint);
    for text in texts {
        if !printable(text) {
            return Err(CliError::new(
                "a source's command and hint must be printable text of at most 512 bytes",
            ));
        }
    }
    if !entry.is_object() {
        *entry = json!({});
    }
    entry["source"] = source;
    match hint {
        Some(hint) => entry["hint"] = json!(hint),
        None => {
            entry.as_object_mut().map(|entry| entry.remove("hint"));
        }
    }
    Ok(())
}

fn provider<'a>(document: &'a mut Value, name: &str) -> Result<&'a mut Value, CliError> {
    if !PROVIDERS.contains(&name) {
        return Err(CliError::new(format!(
            "`{name}` is not a provider; use api-key, bedrock, or openrouter"
        )));
    }
    if !document["providers"].is_object() {
        document["providers"] = json!({});
    }
    Ok(&mut document["providers"][name])
}

/// Applies the answers given by flag to the sources document.
fn apply(document: &mut Value, options: &InitOptions) -> Result<(), CliError> {
    for (name, command) in &options.sets {
        set_entry(provider(document, name)?, process(command), None)?;
    }
    for (name, model) in &options.models {
        provider(document, name)?["model"] = json!(model);
    }
    if let Some(region) = &options.region {
        provider(document, "bedrock")?["region"] = json!(region);
    }
    if let Some(command) = &options.github {
        set_entry(&mut document["github"], process(command), None)?;
    }
    if let Some(default) = &options.default {
        document["default"] = json!(default);
    }
    Ok(())
}

/// The sources document to start from: the existing file, or an empty one.
fn load(path: &Path) -> Result<Value, CliError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .ok()
            .filter(|value: &Value| value.get("version").and_then(Value::as_u64) == Some(1))
            .ok_or_else(|| {
                CliError::new(format!(
                    "{} is not a version 1 sources file; move it aside and run `keel init` again",
                    path.display()
                ))
            }),
        Err(_) => Ok(json!({"version": 1})),
    }
}

/// The sources directory, when it exists and lets group or others write to
/// it. A run refuses a sources file there, and a default Ubuntu account
/// creates `~/.keel` that way (umask 002).
fn shared_directory(path: &Path) -> Option<(&Path, u32)> {
    let directory = path.parent()?;
    let mode = fs::metadata(directory).ok()?.permissions().mode();
    (mode & 0o022 != 0).then_some((directory, mode))
}

/// Writes the sources file where only the operator can write it: a new
/// directory is private, an existing one loses group and other write access,
/// the file is `0600`, and it replaces the old one whole.
fn write(path: &Path, document: &Value) -> Result<(), CliError> {
    let error = |error: std::io::Error| CliError::new(format!("{}: {error}", path.display()));
    let directory = path
        .parent()
        .ok_or_else(|| CliError::new("the sources file has no directory"))?;
    if !directory.exists() {
        fs::create_dir_all(directory).map_err(error)?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(error)?;
    }
    if let Some((directory, mode)) = shared_directory(path) {
        fs::set_permissions(directory, fs::Permissions::from_mode(mode & !0o022)).map_err(error)?;
    }
    let mut text =
        serde_json::to_string_pretty(document).map_err(|e| CliError::new(e.to_string()))?;
    text.push('\n');
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(error)?;
    fs::rename(&temporary, path).map_err(error)?;
    // What was written must be what a run will accept.
    sources::inspect_at(path)
        .map(|_| ())
        .map_err(|problem| CliError::new(format!("{} would be refused: {problem}", path.display())))
}

fn sources_path() -> Result<PathBuf, CliError> {
    sources::path().ok_or_else(|| CliError::new("HOME and KEEL_SOURCES are unset"))
}

/// Runs `keel init`: records the answers given by flag, or asks at the
/// terminal when there are none.
///
/// # Errors
///
/// Returns an error when there are no answers and no terminal to ask at, and
/// whatever [`record`] or [`guided`] returns.
pub fn run(options: &InitOptions, terminal: bool) -> Result<(), CliError> {
    if options.scripted() {
        println!("{}", record(options)?);
        Ok(())
    } else if terminal {
        guided()
    } else {
        Err(CliError::new(
            "keel init asks its questions at a terminal; pass --set and --github to record \
sources without one",
        ))
    }
}

/// Records the answers given by flag, without prompting.
///
/// # Errors
///
/// Returns an error for an unknown provider, unprintable text, or a file
/// that cannot be written where a run would accept it.
pub fn record(options: &InitOptions) -> Result<String, CliError> {
    let path = sources_path()?;
    let mut document = load(&path)?;
    apply(&mut document, options)?;
    let tightened = shared_directory(&path).map(|(directory, _)| {
        format!(
            "Removed group and other write access from {}\n",
            directory.display()
        )
    });
    write(&path, &document)?;
    Ok(format!(
        "{}Wrote {}\nNext: keel doctor",
        tightened.unwrap_or_default(),
        path.display()
    ))
}

struct Session<'a> {
    host: &'a dyn Host,
    input: &'a mut dyn BufRead,
    output: &'a mut dyn Write,
}

impl Session<'_> {
    fn say(&mut self, text: &str) {
        let _ = writeln!(self.output, "{text}");
    }

    /// Asks one question and returns the trimmed answer; end of input is "".
    fn ask(&mut self, question: &str) -> String {
        let _ = write!(self.output, "{question} ");
        let _ = self.output.flush();
        let mut answer = String::new();
        let _ = self.input.read_line(&mut answer);
        answer.trim().to_owned()
    }

    fn yes(&mut self, question: &str) -> bool {
        matches!(
            self.ask(&format!("{question} [y/N]")).as_str(),
            "y" | "Y" | "yes"
        )
    }

    /// Offers numbered choices; Enter or anything else skips.
    fn pick(&mut self, labels: &[String]) -> Option<usize> {
        for (index, label) in labels.iter().enumerate() {
            self.say(&format!("  {}) {label}", index + 1));
        }
        self.ask("Choose a number, or press Enter to skip:")
            .parse::<usize>()
            .ok()
            .and_then(|choice| choice.checked_sub(1))
            .filter(|index| *index < labels.len())
    }

    /// Runs a source's command as a run will, and says how it went.
    fn test(&mut self, source: &Value, hint: Option<&str>) {
        let Some(command) = source.get("command").and_then(Value::as_str) else {
            return;
        };
        match self.host.check(command) {
            Ok(()) => self.say("  [ok] the source answers"),
            Err(problem) => {
                self.say(&format!(
                    "  [warn] the source does not answer yet: {problem}"
                ));
                if let Some(hint) = hint {
                    self.say(&format!("         {hint}"));
                }
            }
        }
    }

    /// Lets the operator choose where one API key comes from.
    fn key(
        &mut self,
        document: &mut Value,
        name: &str,
        item: &str,
        variable: &str,
    ) -> Result<(), CliError> {
        let mut choices = key_choices(self.host, item, variable);
        let mut labels = choices
            .iter()
            .map(|choice| choice.label.clone())
            .collect::<Vec<_>>();
        labels.push("another command that prints the key".to_owned());
        let Some(index) = self.pick(&labels) else {
            return Ok(());
        };
        let choice = if index < choices.len() {
            choices.swap_remove(index)
        } else {
            let command = self.ask("Command:");
            if command.is_empty() {
                return Ok(());
            }
            Choice {
                label: String::new(),
                source: process(&command),
                store: None,
                hint: None,
            }
        };
        if let Some(store) = &choice.store
            && self.yes(&format!(
                "Store the key now? `{}` will ask for it; Keel never sees it.",
                store.join(" ")
            ))
            && !self.host.run(store)
        {
            self.say("  [warn] the key was not stored");
        }
        set_entry(
            provider(document, name)?,
            choice.source.clone(),
            choice.hint.as_deref(),
        )?;
        self.test(&choice.source, choice.hint.as_deref());
        Ok(())
    }

    fn bedrock(&mut self, document: &mut Value) -> Result<(), CliError> {
        let profile = self.ask("AWS profile (Enter to skip):");
        if profile.is_empty() {
            return Ok(());
        }
        let region = self.ask("AWS region, for example us-west-2:");
        let source = process(&format!(
            "aws configure export-credentials --profile {profile} --format process"
        ));
        let hint = format!("sign in first: `aws sso login --profile {profile}`");
        let entry = provider(document, "bedrock")?;
        set_entry(entry, source.clone(), Some(&hint))?;
        if !region.is_empty() {
            entry["region"] = json!(region);
        }
        self.test(&source, Some(&hint));
        Ok(())
    }

    fn providers(&mut self, document: &mut Value) -> Result<(), CliError> {
        loop {
            let configured = document["providers"]
                .as_object()
                .map(|providers| providers.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            self.say(&format!(
                "\nModel providers configured: {}",
                if configured.is_empty() {
                    "none".to_owned()
                } else {
                    configured.join(", ")
                }
            ));
            let labels = [
                "Anthropic API key (--auth api-key)",
                "Amazon Bedrock through an AWS profile (--auth bedrock)",
                "OpenRouter API key (--auth openrouter)",
            ]
            .map(str::to_owned);
            match self.pick(&labels) {
                Some(0) => self.key(document, "api-key", "anthropic", "ANTHROPIC_API_KEY")?,
                Some(1) => self.bedrock(document)?,
                Some(2) => {
                    self.key(document, "openrouter", "openrouter", "OPENROUTER_API_KEY")?;
                    let model = self.ask("OpenRouter model, for example anthropic/claude-sonnet-4.6 (Enter to skip):");
                    if !model.is_empty() && document["providers"]["openrouter"].is_object() {
                        document["providers"]["openrouter"]["model"] = json!(model);
                    }
                }
                _ => break,
            }
        }
        let names = document["providers"]
            .as_object()
            .map(|providers| providers.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if names.len() > 1 {
            self.say("\nWhich provider should a run use when you pass no --auth?");
            if let Some(index) = self.pick(&names) {
                document["default"] = json!(names[index]);
            }
        } else if let Some(document) = document.as_object_mut() {
            document.remove("default");
        }
        Ok(())
    }

    fn github(&mut self, document: &mut Value) -> Result<(), CliError> {
        self.say("\nGitHub: authenticated push and the GitHub tools use your `gh` login.");
        if !self.host.has("gh") {
            self.say(if self.host.macos() {
                "  `gh` is not installed. Install it with `brew install gh`, run `gh auth login`,\n  then `keel init` again. Until then pushes are refused and GitHub reads are public only."
            } else {
                "  `gh` is not installed. Install it from GitHub's apt repository\n  (https://github.com/cli/cli/blob/trunk/docs/install_linux.md), run `gh auth login`,\n  then `keel init` again. Until then pushes are refused and GitHub reads are public only."
            });
            return Ok(());
        }
        if self.host.check(GH_COMMAND).is_err()
            && !(self.yes("  `gh` is signed out. Run `gh auth login` now?")
                && self
                    .host
                    .run(&["gh".to_owned(), "auth".to_owned(), "login".to_owned()]))
        {
            self.say("  Skipped. Run `gh auth login`, then `keel init` again.");
            return Ok(());
        }
        if self.yes("  Use `gh auth token` for pushes and the GitHub tools? A push is bound to the\n  workspace's own repository, shown at admission.") {
            let hint = "sign in first: `gh auth login`";
            set_entry(&mut document["github"], process(GH_COMMAND), Some(hint))?;
            self.test(&process(GH_COMMAND), Some(hint));
        }
        Ok(())
    }
}

/// The interactive flow up to the written file. Returns whether it wrote.
fn guide(session: &mut Session<'_>, path: &Path) -> Result<bool, CliError> {
    let mut document = load(path)?;
    let before = document.clone();
    session.say(&format!(
        "\nKeel records where each credential comes from in {}.\nIt never stores a key: a source is a command the trusted runtime runs when a run starts.",
        path.display()
    ));
    session.providers(&mut document)?;
    session.github(&mut document)?;
    if document == before {
        session.say("\nNothing changed.");
        return Ok(false);
    }
    let text = serde_json::to_string_pretty(&document).map_err(|e| CliError::new(e.to_string()))?;
    session.say(&format!("\n{} will contain:\n{text}", path.display()));
    if let Some((directory, _)) = shared_directory(path) {
        session.say(&format!(
            "Writing it also removes group and other write access from {}: a run refuses\na sources file in a directory someone else can write.",
            directory.display()
        ));
    }
    if !session.yes("Write it?") {
        session.say("Not written.");
        return Ok(false);
    }
    write(path, &document)?;
    session.say(&format!("Wrote {}", path.display()));
    Ok(true)
}

/// Runs guided setup on the operator's terminal.
///
/// # Errors
///
/// Returns an error when the sources file cannot be read or written, or the
/// first session cannot be started.
pub fn guided() -> Result<(), CliError> {
    let report = setup::doctor();
    print!("Checking this host:\n{}", report.output);
    let stdin = std::io::stdin();
    let (mut input, mut output) = (stdin.lock(), std::io::stdout());
    let mut session = Session {
        host: &Machine,
        input: &mut input,
        output: &mut output,
    };
    let installed = setup::runtime_installed();
    if !installed {
        session.say(
            "\nThe runtime is not installed. From a release, run `keel setup --prebuilt DIR`;\nfrom a source checkout, run `keel setup`. Credentials can be set up now.",
        );
    }
    guide(&mut session, &sources_path()?)?;
    if installed {
        if !setup::reaper_installed()
            && session.yes("\nInstall the hourly crash-recovery job (`keel recover --all`)?")
        {
            session.say(&setup::install_reaper()?);
        }
        if session.yes(
            "\nRun a two-minute first session? It shows the trusted approval screen on two\nharmless requests, calls no model, and touches no repository.",
        ) {
            demo()?;
        }
    }
    session.say(
        "\nNext:\n  keel doctor                      check the setup\n  cd YOUR_REPOSITORY && keel mux   start a session\n  keel run --allow push:branch claude   allow pushes to feature branches",
    );
    Ok(())
}

/// Runs the first session: a script in the V8 microVM, in a throwaway
/// workspace, whose two requests the operator approves and denies.
fn demo() -> Result<(), CliError> {
    let error = |error: std::io::Error| CliError::new(format!("first session: {error}"));
    let root = crate::state_root()?;
    fs::create_dir_all(&root).map_err(error)?;
    // A run needs a Git worktree; this one is Keel's own and holds one file.
    let workspace = if root.join("init-demo").is_dir() {
        root.join("init-demo")
    } else {
        crate::create_managed_workspace(&root, "init-demo")?
    };
    fs::write(workspace.join("demo.mjs"), DEMO_SCRIPT).map_err(error)?;
    let sessions = root.join("sessions");
    let listing = || {
        fs::read_dir(&sessions)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default()
    };
    let before = listing();
    let keel = env::current_exe().map_err(error)?;
    // The script calls no model, but admission wants a provider. A fixed
    // provider, model, and placeholder key keep the lesson the same on every
    // host and read no stored credential.
    let mut command = Command::new(&keel);
    command
        .args(["run", "--isolation", "vm-v8", "--auth", "api-key"])
        .args(["--model", "claude-haiku-4-5", "v8", "demo.mjs"])
        .current_dir(&workspace);
    if env::var_os("ANTHROPIC_API_KEY").is_none() {
        command.env("ANTHROPIC_API_KEY", "keel-init-first-session-placeholder");
    }
    let status = command.status().map_err(error)?;
    for session in listing().difference(&before) {
        let output = Command::new(&keel)
            .args(["status", session])
            .output()
            .map_err(error)?;
        println!("\nThe session's own record (`keel status {session}` shows all of it):");
        // The head of the report: its state, chain, and signed receipt.
        for line in String::from_utf8_lossy(&output.stdout).lines().take(6) {
            println!("  {line}");
        }
    }
    if !status.success() {
        println!("The first session did not finish; `keel doctor` may say why.");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/support/init.rs"]
mod tests;
