#![doc = "Untrusted mediated Git endpoint for Keel."]

use keel_conn::{EgressAuthorization, EgressMethod, request_egress_authorization};
use keel_kernel::{
    ActionClass, Asserted, GIT_ALLOWED, GIT_BROKER_MAGIC, GIT_DENIED, GIT_REPORT_COMPLETED,
    GIT_REPORT_FAILED, GIT_REPORT_MAGIC, Target,
};
use ring::digest::{SHA256, digest};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    env,
    error::Error,
    fmt, fs,
    io::{Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

const MAX_COMMANDS: usize = 256;
const MAX_PACKET: usize = 65_520;
const MAX_HTTP_HEADERS: usize = 64 * 1024;
const MAX_HTTP_BODY: usize = 900 * 1024;
const REMOTE_TEXT_LIMIT: usize = 240;

fn git_command() -> Command {
    let mut command = Command::new(env::var_os("KEEL_GIT").unwrap_or_else(|| "git".into()));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/usr/bin/false")
        .env("GIT_PAGER", "cat")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "credential.helper=",
            "-c",
            "core.sshCommand=false",
        ]);
    command
}

/// A validated Git object identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectId(String);

impl ObjectId {
    fn parse(value: &str) -> Result<Self, GitdError> {
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GitdError::Malformed("invalid object identifier"));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    fn is_zero(&self) -> bool {
        self.0.bytes().all(|byte| byte == b'0')
    }

    /// Returns the hexadecimal object identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One ref command from `git-receive-pack`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefUpdate {
    /// Ref value before the push.
    pub old: ObjectId,
    /// Requested ref value after the push.
    pub new: ObjectId,
    /// Full ref name.
    pub name: String,
}

/// Parses the command pkt-lines at the start of a receive-pack request.
///
/// Packfile bytes after the command-list flush are deliberately ignored here.
///
/// # Errors
///
/// Returns an error for malformed lengths, commands, object identifiers, ref
/// names, missing flush, or excessive command counts.
pub fn parse_receive_pack_commands(body: &[u8]) -> Result<Vec<RefUpdate>, GitdError> {
    parse_receive_pack(body).map(|(updates, _)| updates)
}

fn parse_receive_pack(body: &[u8]) -> Result<(Vec<RefUpdate>, usize), GitdError> {
    let mut cursor = 0;
    let mut updates = Vec::new();
    loop {
        let header = body
            .get(cursor..cursor + 4)
            .ok_or(GitdError::Malformed("truncated pkt-line header"))?;
        let header = std::str::from_utf8(header)
            .map_err(|_| GitdError::Malformed("non-ASCII pkt-line header"))?;
        let length = usize::from_str_radix(header, 16)
            .map_err(|_| GitdError::Malformed("invalid pkt-line length"))?;
        cursor += 4;
        if length == 0 {
            break;
        }
        if !(4..=MAX_PACKET).contains(&length) {
            return Err(GitdError::Malformed("pkt-line length outside bounds"));
        }
        let payload_length = length - 4;
        let payload = body
            .get(cursor..cursor + payload_length)
            .ok_or(GitdError::Malformed("truncated pkt-line payload"))?;
        cursor += payload_length;
        if updates.len() == MAX_COMMANDS {
            return Err(GitdError::TooManyCommands);
        }
        updates.push(parse_update(payload, updates.is_empty())?);
    }
    if updates.is_empty() {
        return Err(GitdError::Malformed("receive-pack command list is empty"));
    }
    Ok((updates, cursor))
}

fn parse_update(payload: &[u8], first: bool) -> Result<RefUpdate, GitdError> {
    let payload = payload.strip_suffix(b"\n").unwrap_or(payload);
    let command = if first {
        payload.split(|byte| *byte == 0).next().unwrap_or(payload)
    } else if payload.contains(&0) {
        return Err(GitdError::Malformed(
            "capabilities are allowed only on the first command",
        ));
    } else {
        payload
    };
    let command = std::str::from_utf8(command)
        .map_err(|_| GitdError::Malformed("receive-pack command is not UTF-8"))?;
    let mut fields = command.split(' ');
    let old = ObjectId::parse(
        fields
            .next()
            .ok_or(GitdError::Malformed("old object is missing"))?,
    )?;
    let new = ObjectId::parse(
        fields
            .next()
            .ok_or(GitdError::Malformed("new object is missing"))?,
    )?;
    let name = fields
        .next()
        .ok_or(GitdError::Malformed("ref name is missing"))?;
    if fields.next().is_some() || !valid_ref(name) {
        return Err(GitdError::Malformed("invalid ref name"));
    }
    Ok(RefUpdate {
        old,
        new,
        name: name.to_owned(),
    })
}

fn valid_ref(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.contains("..")
        && !name.contains("@{")
        && !name.ends_with('.')
        && !name.ends_with('/')
        && !name.contains("//")
        && !name
            .bytes()
            .any(|byte| byte.is_ascii_control() || b" ~^:?*[\\".contains(&byte))
}

/// Read-only operations against the kernel-side mirror after incoming objects
/// have been staged.
pub trait Mirror {
    /// Stages an incoming pack without updating any refs.
    ///
    /// # Errors
    ///
    /// Returns an error when the pack is malformed or cannot be quarantined in
    /// the mirror object store.
    fn stage_pack(&self, pack: &[u8]) -> Result<(), GitdError>;

    /// Returns whether `old` is an ancestor of `new`.
    ///
    /// # Errors
    ///
    /// Returns an error when the mirror cannot inspect the objects.
    fn is_ancestor(&self, old: &ObjectId, new: &ObjectId) -> Result<bool, GitdError>;
    /// Returns paths changed by this update.
    ///
    /// # Errors
    ///
    /// Returns an error when the mirror cannot compute the tree difference.
    fn changed_paths(&self, old: &ObjectId, new: &ObjectId) -> Result<Vec<String>, GitdError>;
    /// Returns the exact diff for the selected manifest paths.
    ///
    /// # Errors
    ///
    /// Returns an error when the mirror cannot render the selected diff.
    fn manifest_diff(
        &self,
        old: &ObjectId,
        new: &ObjectId,
        paths: &[String],
    ) -> Result<String, GitdError>;
}

/// Kernel-side Git mirror inspected through structured `git` arguments.
#[derive(Clone, Debug)]
pub struct CommandMirror {
    path: PathBuf,
    object_directory: PathBuf,
}

impl CommandMirror {
    /// Opens an existing mirror after asking Git to validate it.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be canonicalized or Git cannot
    /// recognize it as a repository.
    pub fn open(path: &Path) -> Result<Self, GitdError> {
        let path = path
            .canonicalize()
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        let git_directory = git_command()
            .arg("-C")
            .arg(&path)
            .args(["rev-parse", "--path-format=absolute", "--git-dir"])
            .output()
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        if !git_directory.status.success() {
            return Err(GitdError::Mirror(
                String::from_utf8_lossy(&git_directory.stderr)
                    .trim()
                    .to_owned(),
            ));
        }
        let git_directory = String::from_utf8(git_directory.stdout)
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        let object_directory = PathBuf::from(git_directory.trim())
            .join("objects")
            .canonicalize()
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        let mirror = Self {
            path,
            object_directory,
        };
        Ok(mirror)
    }

    fn run(&self, arguments: &[&str]) -> Result<String, GitdError> {
        let output = git_command()
            .arg("-C")
            .arg(&self.path)
            .args(arguments)
            .output()
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        if !output.status.success() {
            return Err(GitdError::Mirror(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        String::from_utf8(output.stdout).map_err(|error| GitdError::Mirror(error.to_string()))
    }
}

impl Mirror for CommandMirror {
    fn stage_pack(&self, pack: &[u8]) -> Result<(), GitdError> {
        if pack.is_empty() {
            return Ok(());
        }
        if !pack.starts_with(b"PACK") {
            return Err(GitdError::Malformed(
                "receive-pack payload does not contain a Git pack",
            ));
        }
        let mut child = git_command()
            .arg("index-pack")
            .args(["--stdin", "--fix-thin"])
            .env("GIT_OBJECT_DIRECTORY", &self.object_directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| GitdError::Mirror("git index-pack stdin is unavailable".to_owned()))?
            .write_all(pack)
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        let output = child
            .wait_with_output()
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        if !output.status.success() {
            return Err(GitdError::Mirror(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        Ok(())
    }

    fn is_ancestor(&self, old: &ObjectId, new: &ObjectId) -> Result<bool, GitdError> {
        let status = git_command()
            .arg("-C")
            .arg(&self.path)
            .args(["merge-base", "--is-ancestor", old.as_str(), new.as_str()])
            .status()
            .map_err(|error| GitdError::Mirror(error.to_string()))?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitdError::Mirror(format!(
                "git merge-base exited with {status}"
            ))),
        }
    }

    fn changed_paths(&self, old: &ObjectId, new: &ObjectId) -> Result<Vec<String>, GitdError> {
        // `-z` emits paths verbatim instead of C-quoting non-ASCII names, and
        // `--no-renames` reports a moved manifest's old path as a deletion
        // rather than showing only its new name.
        let output = if old.is_zero() {
            self.run(&[
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "--no-renames",
                "-z",
                "-r",
                new.as_str(),
                "--",
            ])?
        } else {
            self.run(&[
                "diff",
                "--name-only",
                "--no-renames",
                "-z",
                old.as_str(),
                new.as_str(),
                "--",
            ])?
        };
        Ok(output
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .collect())
    }

    fn manifest_diff(
        &self,
        old: &ObjectId,
        new: &ObjectId,
        paths: &[String],
    ) -> Result<String, GitdError> {
        let mut arguments = if old.is_zero() {
            vec![
                "--literal-pathspecs".to_owned(),
                "diff-tree".to_owned(),
                "--root".to_owned(),
                "-p".to_owned(),
                "--no-renames".to_owned(),
                "--binary".to_owned(),
                new.as_str().to_owned(),
                "--".to_owned(),
            ]
        } else {
            vec![
                "--literal-pathspecs".to_owned(),
                "diff".to_owned(),
                "--no-renames".to_owned(),
                "--binary".to_owned(),
                old.as_str().to_owned(),
                new.as_str().to_owned(),
                "--".to_owned(),
            ]
        };
        arguments.extend(paths.iter().cloned());
        let borrowed = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        self.run(&borrowed)
    }
}

/// PDP boundary used by the untrusted Git relay.
pub trait PushAuthorizer {
    /// Submits one fully assessed Git action, returning the audit correlation id
    /// to report the outcome against, or `None` when the PDP refuses it.
    ///
    /// # Errors
    ///
    /// Returns an error when the PDP cannot produce a complete decision.
    fn authorize(
        &mut self,
        action: &Asserted,
        body_digest: [u8; 32],
    ) -> Result<Option<u64>, GitdError>;

    /// Reports what became of an authorized push after forwarding.
    ///
    /// Best-effort by design: a push that reached the remote must not be failed
    /// back to the client because the report could not be delivered. The kernel
    /// closes an authorization it never hears about as `unreported`.
    fn report(&mut self, _action_id: u64, _completed: bool) {}
}

/// Client for the trusted kernel's private Git action channel.
#[derive(Clone, Debug)]
pub struct KernelPushAuthorizer {
    socket_path: PathBuf,
    origin: Option<Vec<u8>>,
}

impl KernelPushAuthorizer {
    /// Targets the private broker socket owned by the current run.
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            origin: None,
        }
    }

    /// Forwards the guest's origin frame with each push authorization.
    #[must_use]
    pub fn with_origin(mut self, origin: Option<Vec<u8>>) -> Self {
        self.origin = origin;
        self
    }
}

impl KernelPushAuthorizer {
    fn connect(&self) -> Result<UnixStream, GitdError> {
        let stream = UnixStream::connect(&self.socket_path)
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        Ok(stream)
    }
}

impl PushAuthorizer for KernelPushAuthorizer {
    fn authorize(
        &mut self,
        action: &Asserted,
        body_digest: [u8; 32],
    ) -> Result<Option<u64>, GitdError> {
        let Target::Git {
            remote,
            refs,
            is_force,
            is_default_branch,
            touches_manifest,
            manifest_diff,
        } = &action.target
        else {
            return Err(GitdError::Kernel(
                "Git authorizer received a non-Git target".to_owned(),
            ));
        };
        if action.class != ActionClass::GitPush {
            return Err(GitdError::Kernel(
                "Git authorizer received a non-push action".to_owned(),
            ));
        }
        let mut stream = self.connect()?;
        if let Some(origin) = &self.origin {
            keel_conn::write_origin_frame(&mut stream, origin)
                .map_err(|error| GitdError::Kernel(error.to_string()))?;
        }
        stream
            .write_all(GIT_BROKER_MAGIC)
            .and_then(|()| write_wire_string(&mut stream, remote))
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        let count = u16::try_from(refs.len())
            .map_err(|_| GitdError::Kernel("too many Git refs for kernel channel".to_owned()))?;
        stream
            .write_all(&count.to_be_bytes())
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        for reference in refs {
            write_wire_string(&mut stream, reference)
                .map_err(|error| GitdError::Kernel(error.to_string()))?;
        }
        stream
            .write_all(&[
                u8::from(*is_force),
                u8::from(*is_default_branch),
                u8::from(*touches_manifest),
            ])
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        match manifest_diff {
            Some(diff) => {
                let length = u32::try_from(diff.len()).map_err(|_| {
                    GitdError::Kernel("manifest diff is too large for kernel channel".to_owned())
                })?;
                stream
                    .write_all(&[1])
                    .and_then(|()| stream.write_all(&length.to_be_bytes()))
                    .and_then(|()| stream.write_all(diff.as_bytes()))
                    .map_err(|error| GitdError::Kernel(error.to_string()))?;
            }
            None => stream
                .write_all(&[0])
                .map_err(|error| GitdError::Kernel(error.to_string()))?,
        }
        stream
            .write_all(&body_digest)
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        stream
            .flush()
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        let mut response = [0_u8; 1];
        stream
            .read_exact(&mut response)
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        match response[0] {
            GIT_ALLOWED => {
                let mut action_id = [0_u8; 8];
                stream
                    .read_exact(&mut action_id)
                    .map_err(|error| GitdError::Kernel(error.to_string()))?;
                Ok(Some(u64::from_be_bytes(action_id)))
            }
            GIT_DENIED => Ok(None),
            _ => Err(GitdError::Kernel(
                "trusted kernel returned an invalid Git decision".to_owned(),
            )),
        }
    }

    fn report(&mut self, action_id: u64, completed: bool) {
        let outcome = if completed {
            GIT_REPORT_COMPLETED
        } else {
            GIT_REPORT_FAILED
        };
        let _ = self.connect().and_then(|mut stream| {
            // The acknowledgement is read, not ignored: it keeps the socket open
            // until the kernel has the report, and it bounds the wait. Nothing is
            // done with a failure here — the kernel closes an unreported push
            // itself, which is the only guarantee that does not depend on a relay.
            let mut ack = [0_u8; 1];
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .and_then(|()| stream.write_all(GIT_REPORT_MAGIC))
                .and_then(|()| stream.write_all(&action_id.to_be_bytes()))
                .and_then(|()| stream.write_all(&[outcome]))
                .and_then(|()| stream.flush())
                .and_then(|()| stream.read_exact(&mut ack))
                .map_err(|error| GitdError::Kernel(error.to_string()))
        });
    }
}

fn write_wire_string(stream: &mut UnixStream, value: &str) -> std::io::Result<()> {
    let length = u16::try_from(value.len())
        .map_err(|_| std::io::Error::other("Git channel string is too long"))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(value.as_bytes())
}

/// One-run smart HTTP service backed by an isolated bare mirror.
#[derive(Clone, Debug)]
pub struct GitHttpService {
    mirror: CommandMirror,
    project_root: PathBuf,
    default_branches: Vec<String>,
    remote: String,
    broker_socket: PathBuf,
    upstream: Option<KernelGitUpstream>,
}

impl GitHttpService {
    /// Creates `ROOT/origin` as a bare mirror of the workspace before the
    /// guest rewrites its own `origin`.
    ///
    /// # Errors
    ///
    /// Returns an error when workspace Git metadata cannot be read or the
    /// isolated mirror cannot be created.
    pub fn initialize(
        workspace: &Path,
        root: &Path,
        broker_socket: impl Into<PathBuf>,
    ) -> Result<Self, GitdError> {
        Self::initialize_with_upstream(workspace, root, broker_socket, None, None)
    }

    /// Creates a mirror with optional inspected HTTPS synchronization to the
    /// workspace's original remote.
    ///
    /// # Errors
    ///
    /// Returns an error for mirror initialization or malformed CA material.
    pub fn initialize_with_upstream(
        workspace: &Path,
        root: &Path,
        broker_socket: impl Into<PathBuf>,
        ca_pem: Option<&str>,
        sentinel: Option<&str>,
    ) -> Result<Self, GitdError> {
        let broker_socket = broker_socket.into();
        fs::create_dir(root).map_err(|error| GitdError::Backend(error.to_string()))?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        // The workspace is guest-writable between runs, so its HEAD alone
        // cannot name the remote default branch: a moved HEAD would make a
        // push to the real default look like an ordinary branch push. Every
        // plausible default is protected; a wrong guess over-gates.
        let mut default_branches =
            vec!["refs/heads/main".to_owned(), "refs/heads/master".to_owned()];
        for candidate in [
            git_optional(workspace, &["symbolic-ref", "--quiet", "HEAD"], "")?,
            git_optional(
                workspace,
                &["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
                "",
            )?
            .replacen("refs/remotes/origin/", "refs/heads/", 1),
        ] {
            if candidate.starts_with("refs/heads/") && !default_branches.contains(&candidate) {
                default_branches.push(candidate);
            }
        }
        let remote = git_optional(
            workspace,
            &["config", "--get", "remote.origin.url"],
            "origin",
        )?;
        let upstream = if remote.starts_with("https://") {
            ca_pem
                .map(|ca| KernelGitUpstream::new(&remote, &broker_socket, ca, sentinel))
                .transpose()?
        } else {
            None
        };
        let repository = root.join("origin");
        let upload_pack =
            env::var_os("KEEL_GIT_UPLOAD_PACK").unwrap_or_else(|| "git-upload-pack".into());
        let output = git_command()
            .args(["clone", "--bare", "--quiet", "--local", "--no-hardlinks"])
            .arg("--upload-pack")
            .arg(upload_pack)
            .arg(workspace)
            .arg(&repository)
            .output()
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        if !output.status.success() {
            return Err(GitdError::Backend(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let receive_pack = git_command()
            .arg("-C")
            .arg(&repository)
            .args(["config", "http.receivepack", "true"])
            .output()
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        if !receive_pack.status.success() {
            return Err(GitdError::Backend(
                String::from_utf8_lossy(&receive_pack.stderr)
                    .trim()
                    .to_owned(),
            ));
        }
        Ok(Self {
            mirror: CommandMirror::open(&repository)?,
            project_root: root.to_path_buf(),
            default_branches,
            remote,
            broker_socket,
            upstream,
        })
    }

    /// Serves one complete HTTP/1.1 request on a guest vsock stream.
    ///
    /// # Errors
    ///
    /// Returns an error when request or response transport fails. Protocol,
    /// policy, and backend errors are converted into explicit HTTP responses.
    pub fn serve(&self, stream: impl std::io::Read + std::io::Write) -> Result<(), GitdError> {
        self.serve_inner(stream, None)
    }

    /// Serves one request from a guest relay that sends its origin frame
    /// first; the origin accompanies any push to the trusted kernel.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin frame is missing or transport fails.
    pub fn serve_with_origin(
        &self,
        mut stream: impl std::io::Read + std::io::Write,
    ) -> Result<(), GitdError> {
        let origin = keel_conn::read_origin_frame(&mut stream)
            .map_err(|error| GitdError::Http(error.to_string()))?;
        self.serve_inner(stream, Some(origin))
    }

    fn serve_inner(
        &self,
        mut stream: impl std::io::Read + std::io::Write,
        origin: Option<Vec<u8>>,
    ) -> Result<(), GitdError> {
        let response = match read_http_request(&mut stream)
            .and_then(|request| self.handle(&request, origin))
        {
            Ok(response) => response,
            Err(GitdError::Denied) => http_error("403 Forbidden", b"Keel denied this Git push.\n"),
            Err(error) => {
                let body = format!("Keel Git relay failed: {error}\n");
                http_error("502 Bad Gateway", body.as_bytes())
            }
        };
        stream
            .write_all(&response)
            .and_then(|()| stream.flush())
            .map_err(|error| GitdError::Http(error.to_string()))
    }

    fn handle(&self, request: &HttpRequest, origin: Option<Vec<u8>>) -> Result<Vec<u8>, GitdError> {
        if request.path == "/origin/git-receive-pack" && request.method == "POST" {
            let mut authorizer = KernelPushAuthorizer::new(&self.broker_socket).with_origin(origin);
            let mut forwarder = GitPushForwarder {
                service: self,
                request,
            };
            return mediate_receive_pack(
                &request.body,
                &self.mirror,
                &self.default_branches,
                &self.remote,
                &mut authorizer,
                &mut forwarder,
            );
        }
        if request.method == "GET"
            && request.path == "/origin/info/refs"
            && request.query.as_deref() == Some("service=git-receive-pack")
            && let Some(upstream) = &self.upstream
        {
            // The client must negotiate its pack against the repository that
            // will actually receive it. Advertising the workspace mirror here
            // can make Git omit objects that exist only in that mirror, after
            // which the real remote rejects the forwarded thin pack as
            // "missing necessary objects". This GET is not a typed push
            // authorization: the trusted TLS relay admits and audits its exact
            // repository path as inspected egress before forwarding it.
            return upstream.forward_receive_pack_advertisement();
        }
        let allowed_read = (request.method == "GET"
            && request.path == "/origin/info/refs"
            && matches!(
                request.query.as_deref(),
                Some("service=git-upload-pack" | "service=git-receive-pack")
            ))
            || (request.method == "POST" && request.path == "/origin/git-upload-pack");
        if !allowed_read {
            return Err(GitdError::Http(
                "unsupported Git smart HTTP operation".to_owned(),
            ));
        }
        self.run_backend(request, &request.body)
    }

    fn run_backend(&self, request: &HttpRequest, body: &[u8]) -> Result<Vec<u8>, GitdError> {
        let mut child = git_command()
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", &self.project_root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("REQUEST_METHOD", &request.method)
            .env("PATH_INFO", &request.path)
            .env("QUERY_STRING", request.query.as_deref().unwrap_or(""))
            .env(
                "CONTENT_TYPE",
                request.content_type.as_deref().unwrap_or(""),
            )
            .env("CONTENT_LENGTH", body.len().to_string())
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| GitdError::Backend("git http-backend stdin is unavailable".to_owned()))?
            .write_all(body)
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        let output = child
            .wait_with_output()
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        if !output.status.success() {
            return Err(GitdError::Backend(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        cgi_to_http(&output.stdout)
    }
}

struct GitPushForwarder<'a> {
    service: &'a GitHttpService,
    request: &'a HttpRequest,
}

impl PushForwarder for GitPushForwarder<'_> {
    fn forward(&mut self, body: &[u8]) -> Result<Forwarded, GitdError> {
        let Some(upstream) = &self.service.upstream else {
            return self
                .service
                .run_backend(self.request, body)
                .map(|response| Forwarded {
                    response,
                    rejection: None,
                });
        };
        let expected_refs = parse_receive_pack_commands(body)?
            .into_iter()
            .map(|update| update.name)
            .collect::<Vec<_>>();
        let response = upstream.forward_receive_pack(self.request, body)?;
        let rejection = assess_remote_receive_pack(&response, &expected_refs).err();
        if rejection.is_none() {
            self.service.run_backend(self.request, body)?;
        }
        Ok(Forwarded {
            response,
            rejection,
        })
    }
}

/// Why the remote's answer to a receive-pack POST is not a success.
///
/// The kernel records only the verdict, and the operator sees only that record,
/// so a rejection that cannot say what the remote said is a dead end: the push
/// fails again identically with nothing new to read. Every refusal below names
/// the remote's own words for it.
fn assess_remote_receive_pack(response: &[u8], expected_refs: &[String]) -> Result<(), String> {
    let body = successful_http_body(response)?;
    let Some(packets) = packet_payloads(&body) else {
        return Err("remote reply is not pkt-line framed".to_owned());
    };
    let mut status = Vec::new();
    let sideband = packets
        .iter()
        .any(|packet| matches!(packet.first(), Some(1..=3)));
    if sideband {
        for packet in packets {
            match packet.split_first() {
                Some((1, payload)) => status.extend_from_slice(payload),
                Some((2, _)) => {}
                Some((3, payload)) => {
                    return Err(format!("remote failed: {}", remote_text(payload)));
                }
                _ => return Err("remote reply used an unknown side-band".to_owned()),
            }
        }
        if let Some(nested) = packet_payloads(&status) {
            status = nested.concat();
        }
    } else {
        status = packets.concat();
    }

    let Ok(status) = std::str::from_utf8(&status) else {
        return Err("remote status report is not UTF-8".to_owned());
    };
    let mut unpack_ok = false;
    let mut accepted_refs = Vec::new();
    for line in status.lines() {
        if line == "unpack ok" {
            unpack_ok = true;
        } else if let Some(reason) = line.strip_prefix("unpack ") {
            return Err(format!("remote could not unpack: {}", remote_text(reason)));
        } else if let Some(rejected) = line.strip_prefix("ng ") {
            return Err(format!("remote rejected {}", remote_text(rejected)));
        } else if let Some(reference) = line.strip_prefix("ok ") {
            accepted_refs.push(reference);
        }
    }
    if !unpack_ok {
        return Err("remote never reported `unpack ok`".to_owned());
    }
    for expected in expected_refs {
        if !accepted_refs.contains(&expected.as_str()) {
            return Err(format!("remote never reported `ok {expected}`"));
        }
    }
    Ok(())
}

/// Renders remote-authored text for an operator's terminal.
///
/// The remote controls every byte here, so control characters and length are
/// the remote's to choose unless they are taken away.
fn remote_text(text: impl AsRef<[u8]>) -> String {
    let text = String::from_utf8_lossy(text.as_ref());
    let rendered = text
        .trim()
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(REMOTE_TEXT_LIMIT)
        .collect::<String>();
    if rendered.is_empty() {
        "(no reason given)".to_owned()
    } else {
        rendered
    }
}

fn successful_http_body(response: &[u8]) -> Result<Vec<u8>, String> {
    let status_end = response
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .ok_or_else(|| "remote reply has no HTTP status line".to_owned())?;
    let status = remote_text(&response[..status_end]);
    if !response.starts_with(b"HTTP/1.1 200 ") {
        return Err(format!("remote returned {status}"));
    }
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| "remote reply has incomplete headers".to_owned())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "remote reply headers are not UTF-8".to_owned())?;
    let body = &response[header_end + 4..];
    if headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        })
    }) {
        decode_http_chunks(body)
            .ok_or_else(|| "remote reply has a truncated chunked body".to_owned())
    } else {
        Ok(body.to_vec())
    }
}

fn decode_http_chunks(body: &[u8]) -> Option<Vec<u8>> {
    let mut cursor = 0;
    let mut decoded = Vec::new();
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|bytes| bytes == b"\r\n")?
            + cursor;
        let length = std::str::from_utf8(&body[cursor..line_end])
            .ok()?
            .split(';')
            .next()?;
        let length = usize::from_str_radix(length, 16).ok()?;
        cursor = line_end + 2;
        if length == 0 {
            return Some(decoded);
        }
        let end = cursor.checked_add(length)?;
        decoded.extend_from_slice(body.get(cursor..end)?);
        if body.get(end..end + 2)? != b"\r\n" {
            return None;
        }
        cursor = end + 2;
    }
}

fn packet_payloads(stream: &[u8]) -> Option<Vec<&[u8]>> {
    let mut cursor = 0;
    let mut packets = Vec::new();
    loop {
        let header = stream.get(cursor..cursor + 4)?;
        let header = std::str::from_utf8(header).ok()?;
        let length = usize::from_str_radix(header, 16).ok()?;
        cursor += 4;
        if length == 0 {
            return (cursor == stream.len()).then_some(packets);
        }
        if !(4..=MAX_PACKET).contains(&length) {
            return None;
        }
        let end = cursor.checked_add(length - 4)?;
        packets.push(stream.get(cursor..end)?);
        cursor = end;
    }
}

#[derive(Clone, Debug)]
struct KernelGitUpstream {
    host: String,
    repository_path: String,
    broker_socket: PathBuf,
    tls: Arc<ClientConfig>,
    sentinel: Option<String>,
}

impl KernelGitUpstream {
    fn new(
        remote: &str,
        broker_socket: &Path,
        ca_pem: &str,
        sentinel: Option<&str>,
    ) -> Result<Self, GitdError> {
        let remote = remote.strip_prefix("https://").ok_or_else(|| {
            GitdError::Backend("real Git synchronization requires an HTTPS origin".to_owned())
        })?;
        let (host, path) = remote.split_once('/').ok_or_else(|| {
            GitdError::Backend("real Git origin must include a repository path".to_owned())
        })?;
        if host.is_empty()
            || host.contains(':')
            || host != host.to_ascii_lowercase()
            || host.chars().any(char::is_control)
            || path.is_empty()
            || path.contains('?')
            || path.contains('#')
        {
            return Err(GitdError::Backend(
                "real Git origin is not a normalized HTTPS URL".to_owned(),
            ));
        }
        let certificate =
            pem::parse(ca_pem).map_err(|error| GitdError::Backend(error.to_string()))?;
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificate.into_contents()))
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        let tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            host: host.to_owned(),
            repository_path: format!("/{path}").trim_end_matches('/').to_owned(),
            broker_socket: broker_socket.to_path_buf(),
            tls: Arc::new(tls),
            sentinel: sentinel.map(str::to_owned),
        })
    }

    fn forward_receive_pack(
        &self,
        request: &HttpRequest,
        body: &[u8],
    ) -> Result<Vec<u8>, GitdError> {
        self.forward_http(
            "POST",
            "git-receive-pack",
            None,
            request
                .content_type
                .as_deref()
                .unwrap_or("application/x-git-receive-pack-request"),
            "application/x-git-receive-pack-result",
            body,
        )
    }

    fn forward_receive_pack_advertisement(&self) -> Result<Vec<u8>, GitdError> {
        self.forward_http(
            "GET",
            "info/refs",
            Some("service=git-receive-pack"),
            "",
            "application/x-git-receive-pack-advertisement",
            &[],
        )
    }

    fn forward_http(
        &self,
        method: &str,
        endpoint: &str,
        query: Option<&str>,
        content_type: &str,
        accept: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, GitdError> {
        let broker = match request_egress_authorization(
            &self.broker_socket,
            &self.host,
            443,
            EgressMethod::Tls,
        )
        .map_err(|error| GitdError::Kernel(error.to_string()))?
        {
            EgressAuthorization::Allowed(broker) => broker,
            EgressAuthorization::Denied => return Err(GitdError::Denied),
            EgressAuthorization::ExecutionFailed => {
                return Err(GitdError::Backend(
                    "trusted Git forwarding failed".to_owned(),
                ));
            }
        };
        broker
            .set_write_timeout(None)
            .map_err(|error| GitdError::Kernel(error.to_string()))?;
        let server_name = ServerName::try_from(self.host.clone())
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        let connection = ClientConnection::new(Arc::clone(&self.tls), server_name)
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        let mut tls = StreamOwned::new(connection, broker);
        let mut path = format!("{}/{endpoint}", self.repository_path);
        if let Some(query) = query {
            path.push('?');
            path.push_str(query);
        }
        let mut outbound = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nAccept: {accept}\r\n",
            self.host
        )
        .into_bytes();
        if !content_type.is_empty() {
            write!(outbound, "Content-Type: {content_type}\r\n")
                .map_err(|error| GitdError::Backend(error.to_string()))?;
        }
        let credential_bearing =
            (method == "POST" && endpoint == "git-receive-pack" && query.is_none())
                || (method == "GET"
                    && endpoint == "info/refs"
                    && query == Some("service=git-receive-pack"));
        if credential_bearing && let Some(sentinel) = &self.sentinel {
            write!(outbound, "Authorization: {sentinel}\r\n")
                .map_err(|error| GitdError::Backend(error.to_string()))?;
        }
        write!(
            outbound,
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .map_err(|error| GitdError::Backend(error.to_string()))?;
        outbound.extend_from_slice(body);
        tls.write_all(&outbound)
            .and_then(|()| tls.flush())
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response)
            .map_err(|error| GitdError::Backend(error.to_string()))?;
        Ok(response)
    }
}

#[derive(Clone, Debug)]
struct HttpRequest {
    method: String,
    path: String,
    query: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

struct HttpHead {
    method: String,
    path: String,
    query: Option<String>,
    content_type: Option<String>,
    content_length: usize,
}

fn read_http_request(stream: &mut impl std::io::Read) -> Result<HttpRequest, GitdError> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8192];
    let header_end = loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| GitdError::Http(error.to_string()))?;
        if count == 0 {
            return Err(GitdError::Http("Git HTTP request ended early".to_owned()));
        }
        request.extend_from_slice(&buffer[..count]);
        if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break offset + 4;
        }
        if request.len() > MAX_HTTP_HEADERS {
            return Err(GitdError::Http("Git HTTP headers exceed 64 KiB".to_owned()));
        }
    };
    if header_end > MAX_HTTP_HEADERS {
        return Err(GitdError::Http("Git HTTP headers exceed 64 KiB".to_owned()));
    }
    let headers = std::str::from_utf8(&request[..header_end - 4])
        .map_err(|error| GitdError::Http(error.to_string()))?;
    let head = parse_http_head(headers)?;
    let total = header_end
        .checked_add(head.content_length)
        .ok_or_else(|| GitdError::Http("Git HTTP request length overflowed".to_owned()))?;
    while request.len() < total {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| GitdError::Http(error.to_string()))?;
        if count == 0 {
            return Err(GitdError::Http("Git HTTP body ended early".to_owned()));
        }
        request.extend_from_slice(&buffer[..count]);
        if request.len() > total {
            return Err(GitdError::Http(
                "Git HTTP request contains pipelined bytes".to_owned(),
            ));
        }
    }
    if request.len() != total {
        return Err(GitdError::Http(
            "Git HTTP request length is inconsistent".to_owned(),
        ));
    }
    Ok(HttpRequest {
        method: head.method,
        path: head.path,
        query: head.query,
        content_type: head.content_type,
        body: request[header_end..].to_vec(),
    })
}

fn parse_http_head(headers: &str) -> Result<HttpHead, GitdError> {
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| GitdError::Http("Git HTTP request line is missing".to_owned()))?;
    let mut fields = request_line.split(' ');
    let method = fields
        .next()
        .ok_or_else(|| GitdError::Http("Git HTTP method is missing".to_owned()))?;
    let target = fields
        .next()
        .ok_or_else(|| GitdError::Http("Git HTTP target is missing".to_owned()))?;
    if fields.next() != Some("HTTP/1.1") || fields.next().is_some() {
        return Err(GitdError::Http(
            "Git relay requires an HTTP/1.1 request".to_owned(),
        ));
    }
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let method = method.to_owned();
    let path = path.to_owned();
    let query = query.map(str::to_owned);
    let mut content_length = None;
    let mut content_type = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| GitdError::Http("malformed Git HTTP header".to_owned()))?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(GitdError::Http(
                    "duplicate Git HTTP content length".to_owned(),
                ));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|error| GitdError::Http(error.to_string()))?,
            );
        } else if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(GitdError::Http(
                "Git HTTP transfer encoding is unsupported".to_owned(),
            ));
        }
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_HTTP_BODY {
        return Err(GitdError::Http("Git HTTP body exceeds 900 KiB".to_owned()));
    }
    Ok(HttpHead {
        method,
        path,
        query,
        content_type,
        content_length,
    })
}

fn cgi_to_http(output: &[u8]) -> Result<Vec<u8>, GitdError> {
    let header_end = output
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| GitdError::Backend("git http-backend omitted CGI headers".to_owned()))?;
    let headers = std::str::from_utf8(&output[..header_end])
        .map_err(|error| GitdError::Backend(error.to_string()))?;
    let body = &output[header_end + 4..];
    let mut status = "200 OK";
    let mut forwarded = Vec::new();
    let mut has_content_length = false;
    for line in headers.split("\r\n") {
        if let Some(value) = line.strip_prefix("Status: ") {
            status = value;
            continue;
        }
        let name = line.split_once(':').map_or(line, |(name, _)| name);
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        forwarded.extend_from_slice(line.as_bytes());
        forwarded.extend_from_slice(b"\r\n");
    }
    let mut response = format!("HTTP/1.1 {status}\r\n").into_bytes();
    response.extend_from_slice(&forwarded);
    if !has_content_length {
        write!(response, "Content-Length: {}\r\n", body.len())
            .map_err(|error| GitdError::Backend(error.to_string()))?;
    }
    response.extend_from_slice(b"Connection: close\r\n\r\n");
    response.extend_from_slice(body);
    Ok(response)
}

fn http_error(status: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn git_optional(
    repository: &Path,
    arguments: &[&str],
    fallback: &str,
) -> Result<String, GitdError> {
    let output = git_command()
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(|error| GitdError::Backend(error.to_string()))?;
    if !output.status.success() {
        return Ok(fallback.to_owned());
    }
    let value =
        String::from_utf8(output.stdout).map_err(|error| GitdError::Backend(error.to_string()))?;
    let value = value.trim();
    Ok(if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    })
}

/// Credential-bearing remote operation available only after authorization.
pub trait PushForwarder {
    /// Forwards the original receive-pack body to the real remote.
    ///
    /// # Errors
    ///
    /// Returns an error when the remote operation fails.
    fn forward(&mut self, body: &[u8]) -> Result<Forwarded, GitdError>;
}

/// What forwarding one receive-pack body actually achieved.
///
/// A remote can return a well-formed response that rejects every ref, so the
/// bytes to relay and the question "did the push land" are separate answers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Forwarded {
    /// Response to return to the Git client verbatim.
    pub response: Vec<u8>,
    /// Why the remote did not report success for every ref in the push.
    pub rejection: Option<String>,
}

impl Forwarded {
    /// Whether the remote reported success for every ref in the push.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        self.rejection.is_none()
    }
}

/// Parses, assesses, authorizes, and only then forwards a receive-pack request.
///
/// # Errors
///
/// Returns an error for malformed commands, mirror failures, PDP denial, or
/// remote forwarding failure.
pub fn mediate_receive_pack(
    body: &[u8],
    mirror: &impl Mirror,
    default_branches: &[impl AsRef<str>],
    remote: &str,
    authorizer: &mut impl PushAuthorizer,
    forwarder: &mut impl PushForwarder,
) -> Result<Vec<u8>, GitdError> {
    let (updates, pack_offset) = parse_receive_pack(body)?;
    mirror.stage_pack(&body[pack_offset..])?;
    let assessment = assess_push(mirror, updates, default_branches)?;
    let action = assessment.asserted_action(remote);
    let hash = digest(&SHA256, body);
    let mut body_digest = [0_u8; 32];
    body_digest.copy_from_slice(hash.as_ref());
    let Some(action_id) = authorizer.authorize(&action, body_digest)? else {
        return Err(GitdError::Denied);
    };
    // The forward is the leg that can still fail — the remote may refuse the push,
    // or the connection may not survive it. Reporting afterwards is what keeps the
    // audit from claiming a push landed when only the authorization did.
    let result = forwarder.forward(body);
    if let Some(rejection) = result
        .as_ref()
        .ok()
        .and_then(|sent| sent.rejection.as_ref())
    {
        // The audit records that the push failed; only this says why, and the
        // operator needs the remote's reason to know whether to retry, fix the
        // branch, or stop trusting the relay.
        eprintln!("keel-gitd: the remote did not accept the push: {rejection}");
    }
    authorizer.report(action_id, result.as_ref().is_ok_and(Forwarded::accepted));
    result.map(|sent| sent.response)
}

/// Flags and exact gate content computed from receive-pack commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushAssessment {
    /// Parsed ref updates.
    pub updates: Vec<RefUpdate>,
    /// Any update is non-fast-forward.
    pub is_force: bool,
    /// A default-branch candidate is updated.
    pub is_default_branch: bool,
    /// A dependency manifest, lockfile, or CI configuration file changes.
    pub touches_manifest: bool,
    /// Exact diff of every protected change: the protected files of any
    /// update, and every file of a default-branch update. Shown by the trusted
    /// gate and inspected line by line by the kernel.
    pub manifest_diff: Option<String>,
}

impl PushAssessment {
    /// Converts this remote-derived assessment to the kernel's mediated action.
    #[must_use]
    pub fn asserted_action(&self, remote: impl Into<String>) -> Asserted {
        Asserted {
            class: ActionClass::GitPush,
            target: Target::Git {
                remote: remote.into(),
                refs: self
                    .updates
                    .iter()
                    .map(|update| update.name.clone())
                    .collect(),
                is_force: self.is_force,
                is_default_branch: self.is_default_branch,
                touches_manifest: self.touches_manifest,
                manifest_diff: self.manifest_diff.clone(),
            },
            declared_cost: None,
        }
    }
}

/// Computes policy flags from staged objects in the kernel-side mirror.
///
/// # Errors
///
/// Returns an error when mirror ancestry, changed-path, or exact-diff
/// inspection fails.
pub fn assess_push(
    mirror: &impl Mirror,
    updates: Vec<RefUpdate>,
    default_branches: &[impl AsRef<str>],
) -> Result<PushAssessment, GitdError> {
    let mut is_force = false;
    let mut is_default_branch = false;
    let mut touches_manifest = false;
    let mut manifest_sections = Vec::new();
    for update in &updates {
        let default_update = default_branches
            .iter()
            .any(|branch| update.name == branch.as_ref());
        is_default_branch |= default_update;
        if !update.old.is_zero() && !update.new.is_zero() {
            is_force |= !mirror.is_ancestor(&update.old, &update.new)?;
        }
        if update.new.is_zero() {
            // Deleting a ref discards history exactly as a force push does.
            is_force |= !update.old.is_zero();
            continue;
        }
        let changed = mirror.changed_paths(&update.old, &update.new)?;
        touches_manifest |= changed.iter().any(|path| is_protected_path(path));
        // The kernel inspects every line added to a protected place: all of a
        // default-branch update, and the protected files of any other.
        let paths = changed
            .into_iter()
            .filter(|path| default_update || is_protected_path(path))
            .collect::<Vec<_>>();
        if !paths.is_empty() {
            manifest_sections.push(mirror.manifest_diff(&update.old, &update.new, &paths)?);
        }
    }
    let diff = (!manifest_sections.is_empty()).then(|| bounded_diff(manifest_sections.join("\n")));
    Ok(PushAssessment {
        updates,
        is_force,
        is_default_branch,
        touches_manifest,
        manifest_diff: diff,
    })
}

/// Marker the kernel reads as an uninspectable diff.
pub const DIFF_TRUNCATED_MARKER: &str = "\n# keel: diff truncated\n";
/// Kept below the kernel's 1 MiB bound with room for the marker.
const MAX_INSPECTED_DIFF: usize = 1_000_000;

fn bounded_diff(diff: String) -> String {
    if diff.len() <= MAX_INSPECTED_DIFF {
        return diff;
    }
    let mut end = MAX_INSPECTED_DIFF;
    while !diff.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{DIFF_TRUNCATED_MARKER}", &diff[..end])
}

/// Dependency manifests and CI configuration: changing either alters what
/// runs with the project's authority.
fn is_protected_path(path: &str) -> bool {
    is_manifest_path(path)
        || path.starts_with(".github/workflows/")
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
}

fn is_manifest_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
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
    ) || name.ends_with(".gemspec")
}

/// Receive-pack parsing or mirror inspection error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitdError {
    /// Untrusted receive-pack input was malformed.
    Malformed(&'static str),
    /// Receive-pack exceeded the command bound.
    TooManyCommands,
    /// Kernel-side mirror inspection failed.
    Mirror(String),
    /// Trusted kernel channel failed.
    Kernel(String),
    /// Smart HTTP request or transport failed.
    Http(String),
    /// Local Git smart HTTP backend failed.
    Backend(String),
    /// PDP denied the structured push.
    Denied,
}

impl fmt::Display for GitdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => {
                write!(formatter, "malformed receive-pack request: {reason}")
            }
            Self::TooManyCommands => formatter.write_str("too many receive-pack commands"),
            Self::Mirror(error) => {
                write!(formatter, "kernel-side mirror inspection failed: {error}")
            }
            Self::Kernel(error) => write!(formatter, "trusted kernel channel failed: {error}"),
            Self::Http(error) => write!(formatter, "Git smart HTTP failed: {error}"),
            Self::Backend(error) => write!(formatter, "Git backend failed: {error}"),
            Self::Denied => formatter.write_str("Git push denied by policy"),
        }
    }
}

impl Error for GitdError {}

#[cfg(test)]
mod tests {
    use super::{
        CommandMirror, Forwarded, GitHttpService, GitdError, HttpRequest, KernelGitUpstream,
        KernelPushAuthorizer, Mirror, ObjectId, PushAuthorizer, PushForwarder, RefUpdate,
        assess_push, assess_remote_receive_pack, git_command, mediate_receive_pack,
        parse_receive_pack_commands,
    };
    use keel_audit::{AuditPayload, AuditWriter, Redactor, RunKey, verify_file};
    use keel_kernel::{
        ActionClass, AuditEvent, AuditSink, EgressConnector, EgressSession, Gate, GateDecision,
        GatePayload, GateRequest, KernelBroker, ProvenanceMode, ReportedOutcomeEvent, Target,
    };
    use keel_mcp::{PullRequestAction, pull_request_round_trip};
    use keel_policy::{SessionFacts, StatefulPolicy};
    use keel_secrets::TestMitmCa;
    use rustls::{ServerConnection, StreamOwned};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener},
        os::unix::net::{UnixListener, UnixStream},
        path::Path,
        process::{Command, Stdio},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    const ZERO: &str = "0000000000000000000000000000000000000000";
    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";

    struct FakeMirror {
        ancestor: bool,
        paths: Vec<String>,
    }

    impl Mirror for FakeMirror {
        fn stage_pack(&self, _pack: &[u8]) -> Result<(), GitdError> {
            Ok(())
        }

        fn is_ancestor(&self, _old: &ObjectId, _new: &ObjectId) -> Result<bool, GitdError> {
            Ok(self.ancestor)
        }

        fn changed_paths(
            &self,
            _old: &ObjectId,
            _new: &ObjectId,
        ) -> Result<Vec<String>, GitdError> {
            Ok(self.paths.clone())
        }

        fn manifest_diff(
            &self,
            _old: &ObjectId,
            _new: &ObjectId,
            paths: &[String],
        ) -> Result<String, GitdError> {
            Ok(format!("diff -- {}", paths.join(" ")))
        }
    }

    fn packet(payload: &str) -> Vec<u8> {
        format!("{:04x}{payload}", payload.len() + 4).into_bytes()
    }

    fn band(channel: u8, payload: &[u8]) -> Vec<u8> {
        packet_bytes(&[&[channel][..], payload].concat())
    }

    fn packet_bytes(payload: &[u8]) -> Vec<u8> {
        let mut packet = format!("{:04x}", payload.len() + 4).into_bytes();
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn parses_remote_ref_commands_independent_of_client_syntax() {
        let mut body = packet(&format!("{OLD} {NEW} refs/heads/main\0report-status\n"));
        body.extend(packet(&format!("{ZERO} {NEW} refs/heads/topic\n")));
        body.extend_from_slice(b"0000PACKignored");

        let updates = parse_receive_pack_commands(&body).expect("valid commands");

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].name, "refs/heads/main");
        assert_eq!(updates[1].old.as_str(), ZERO);
    }

    #[test]
    fn force_default_and_manifest_flags_reach_one_kernel_action() {
        let updates = vec![RefUpdate {
            old: ObjectId::parse(OLD).expect("old"),
            new: ObjectId::parse(NEW).expect("new"),
            name: "refs/heads/main".to_owned(),
        }];
        let assessment = assess_push(
            &FakeMirror {
                ancestor: false,
                paths: vec!["src/lib.rs".to_owned(), "Cargo.toml".to_owned()],
            },
            updates,
            &["refs/heads/main"],
        )
        .expect("assessment");

        assert!(assessment.is_force);
        assert!(assessment.is_default_branch);
        assert!(assessment.touches_manifest);
        let action = assessment.asserted_action("origin");
        assert_eq!(action.class, ActionClass::GitPush);
        let Target::Git {
            is_force,
            is_default_branch,
            touches_manifest,
            manifest_diff,
            ..
        } = action.target
        else {
            panic!("Git target expected");
        };
        assert!(is_force && is_default_branch && touches_manifest);
        // A default-branch update carries every changed file for inspection.
        assert_eq!(
            manifest_diff.as_deref(),
            Some("diff -- src/lib.rs Cargo.toml")
        );
    }

    #[test]
    fn ci_configuration_is_protected_and_large_diffs_are_marked() {
        let assessment = assess_push(
            &FakeMirror {
                ancestor: true,
                paths: vec![
                    ".github/workflows/ci.yml".to_owned(),
                    "src/lib.rs".to_owned(),
                ],
            },
            vec![RefUpdate {
                old: ObjectId::parse(OLD).expect("old"),
                new: ObjectId::parse(NEW).expect("new"),
                name: "refs/heads/topic".to_owned(),
            }],
            &["refs/heads/main"],
        )
        .expect("assessment");
        assert!(assessment.touches_manifest);
        assert_eq!(
            assessment.manifest_diff.as_deref(),
            Some("diff -- .github/workflows/ci.yml")
        );
        let bounded = super::bounded_diff("+x\n".repeat(600_000));
        assert!(bounded.ends_with(super::DIFF_TRUNCATED_MARKER));
        assert!(bounded.len() < 1024 * 1024);
    }

    #[test]
    fn fast_forward_update_is_not_classified_as_force() {
        let assessment = assess_push(
            &FakeMirror {
                ancestor: true,
                paths: vec!["src/lib.rs".to_owned()],
            },
            vec![RefUpdate {
                old: ObjectId::parse(OLD).expect("old"),
                new: ObjectId::parse(NEW).expect("new"),
                name: "refs/heads/topic".to_owned(),
            }],
            &["refs/heads/main"],
        )
        .expect("assessment");

        assert!(!assessment.is_force);
    }

    #[test]
    fn ref_deletion_is_classified_as_force() {
        let assessment = assess_push(
            &FakeMirror {
                ancestor: true,
                paths: Vec::new(),
            },
            vec![RefUpdate {
                old: ObjectId::parse(OLD).expect("old"),
                new: ObjectId::parse(ZERO).expect("zero"),
                name: "refs/heads/topic".to_owned(),
            }],
            &["refs/heads/main"],
        )
        .expect("assessment");

        assert!(assessment.is_force);
        assert!(!assessment.is_default_branch);
    }

    #[test]
    fn every_default_branch_candidate_is_protected() {
        let candidates = ["refs/heads/main", "refs/heads/master", "refs/heads/trunk"];
        for name in candidates {
            let assessment = assess_push(
                &FakeMirror {
                    ancestor: true,
                    paths: vec!["src/lib.rs".to_owned()],
                },
                vec![RefUpdate {
                    old: ObjectId::parse(OLD).expect("old"),
                    new: ObjectId::parse(NEW).expect("new"),
                    name: name.to_owned(),
                }],
                &candidates,
            )
            .expect("assessment");
            assert!(assessment.is_default_branch, "{name}");
        }
    }

    #[test]
    fn moved_workspace_head_does_not_unprotect_main() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let workspace =
            std::env::temp_dir().join(format!("keel-gitd-head-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&workspace).expect("workspace directory");
        git(&workspace, &["init", "-q", "--initial-branch=main"]);
        git(&workspace, &["config", "user.name", "Keel Test"]);
        git(&workspace, &["config", "user.email", "keel@example.test"]);
        git(
            &workspace,
            &["commit", "-q", "--allow-empty", "-m", "initial"],
        );
        git(&workspace, &["checkout", "-q", "-b", "feature"]);
        let root = workspace.with_extension("gitd");

        let service = GitHttpService::initialize(&workspace, &root, root.join("broker.sock"))
            .expect("service");

        for branch in ["refs/heads/main", "refs/heads/master", "refs/heads/feature"] {
            assert!(
                service.default_branches.iter().any(|name| name == branch),
                "{branch}"
            );
        }
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn malformed_ref_and_truncated_packet_fail_closed() {
        let invalid = packet(&format!("{OLD} {NEW} main\n"));
        assert!(parse_receive_pack_commands(&[invalid, b"0000".to_vec()].concat()).is_err());
        assert!(parse_receive_pack_commands(b"0010short").is_err());
    }

    #[test]
    fn mirror_update_requires_unpack_and_every_ref_to_succeed() {
        let expected = vec!["refs/heads/main".to_owned(), "refs/heads/topic".to_owned()];
        let accepted = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 71\r\n\r\n".as_slice(),
            &packet("unpack ok\n"),
            &packet("ok refs/heads/main\n"),
            &packet("ok refs/heads/topic\n"),
            b"0000",
        ]
        .concat();
        assert_eq!(assess_remote_receive_pack(&accepted, &expected), Ok(()));

        let rejected = [
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            &packet("unpack ok\n"),
            &packet("ok refs/heads/main\n"),
            &packet("ng refs/heads/topic protected branch\n"),
            b"0000",
        ]
        .concat();
        assert_eq!(
            assess_remote_receive_pack(&rejected, &expected),
            Err("remote rejected refs/heads/topic protected branch".to_owned())
        );

        let incomplete = [
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            &packet("unpack ok\n"),
            &packet("ok refs/heads/main\n"),
            b"0000",
        ]
        .concat();
        assert_eq!(
            assess_remote_receive_pack(&incomplete, &expected),
            Err("remote never reported `ok refs/heads/topic`".to_owned())
        );
    }

    #[test]
    fn a_rejection_names_the_remote_status_the_relay_read() {
        // Every one of these failed a live push and left `failed` in the audit as
        // the entire explanation. A reason an operator can act on is the whole
        // point of reading the remote's reply rather than counting bytes.
        let expected = vec!["refs/heads/topic".to_owned()];
        for (response, reason) in [
            (
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec(),
                "remote returned HTTP/1.1 401 Unauthorized",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nnot a whole chunk"
                    .to_vec(),
                "remote reply has a truncated chunked body",
            ),
            (
                [
                    b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
                    &packet("unpack index-pack failed\n"),
                    b"0000",
                ]
                .concat(),
                "remote could not unpack: index-pack failed",
            ),
        ] {
            assert_eq!(
                assess_remote_receive_pack(&response, &expected),
                Err(reason.to_owned())
            );
        }
    }

    #[test]
    fn a_side_band_report_with_a_trailing_flush_is_a_success() {
        // Captured from GitHub: progress on band 2, the status report on band 1,
        // and the report's own flush packet arriving as a band-1 payload before
        // the stream's flush. A parser that reads the first `0000` it sees as the
        // end of the stream scores this real success as a failure.
        let status = [packet("unpack ok\n"), packet("ok refs/heads/topic\n")].concat();
        let mut body = band(2, b"\x00");
        body.extend_from_slice(&band(2, b"Resolving deltas: 100% (1/1), done.\n"));
        for chunk in [&status[..], b"0000"] {
            body.extend_from_slice(&band(1, chunk));
        }
        body.extend_from_slice(&band(2, b"\nCreate a pull request by visiting:\n"));
        body.extend_from_slice(b"0000");
        let response = [
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes(),
            body,
        ]
        .concat();
        assert_eq!(
            assess_remote_receive_pack(&response, &["refs/heads/topic".to_owned()]),
            Ok(())
        );
    }

    #[test]
    fn mirror_update_accepts_chunked_sideband_status() {
        let nested = [
            packet("unpack ok\n"),
            packet("ok refs/heads/main\n"),
            b"0000".to_vec(),
        ]
        .concat();
        let mut channel = vec![1];
        channel.extend_from_slice(&nested);
        let report = [packet_bytes(&channel), b"0000".to_vec()].concat();
        let response = [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
            format!("{:x}\r\n", report.len()).as_bytes(),
            &report,
            b"\r\n0\r\n\r\n",
        ]
        .concat();

        assert_eq!(
            assess_remote_receive_pack(&response, &["refs/heads/main".to_owned()]),
            Ok(())
        );
    }

    #[test]
    fn remote_forwarding_cannot_run_before_pdp_allow() {
        struct Authorizer {
            allow: bool,
            reports: Vec<(u64, bool)>,
        }
        impl PushAuthorizer for Authorizer {
            fn authorize(
                &mut self,
                _action: &keel_kernel::Asserted,
                _body_digest: [u8; 32],
            ) -> Result<Option<u64>, GitdError> {
                Ok(self.allow.then_some(7))
            }
            fn report(&mut self, action_id: u64, completed: bool) {
                self.reports.push((action_id, completed));
            }
        }
        struct Forwarder {
            calls: u64,
            accepted: bool,
        }
        impl PushForwarder for Forwarder {
            fn forward(&mut self, _body: &[u8]) -> Result<Forwarded, GitdError> {
                self.calls += 1;
                Ok(Forwarded {
                    response: b"remote-ok".to_vec(),
                    rejection: (!self.accepted).then(|| "remote said no".to_owned()),
                })
            }
        }

        let mut body = packet(&format!("{OLD} {NEW} refs/heads/topic\n"));
        body.extend_from_slice(b"0000PACK");
        let mirror = FakeMirror {
            ancestor: true,
            paths: vec!["src/lib.rs".to_owned()],
        };
        let mut denied = Authorizer {
            allow: false,
            reports: Vec::new(),
        };
        let mut forwarder = Forwarder {
            calls: 0,
            accepted: true,
        };
        assert_eq!(
            mediate_receive_pack(
                &body,
                &mirror,
                &["refs/heads/main"],
                "origin",
                &mut denied,
                &mut forwarder,
            ),
            Err(GitdError::Denied)
        );
        assert_eq!(forwarder.calls, 0);
        assert!(denied.reports.is_empty());

        let mut allowed = Authorizer {
            allow: true,
            reports: Vec::new(),
        };
        assert_eq!(
            mediate_receive_pack(
                &body,
                &mirror,
                &["refs/heads/main"],
                "origin",
                &mut allowed,
                &mut forwarder,
            )
            .expect("allowed push"),
            b"remote-ok"
        );
        assert_eq!(forwarder.calls, 1);
        assert_eq!(allowed.reports, [(7, true)]);
    }

    /// The defect this guards: a remote that answers but rejects the ref left the
    /// audit asserting the push executed, because the outcome was recorded at
    /// authorization time and forwarding was never reported on.
    #[test]
    fn a_rejected_push_is_reported_as_failed_not_executed() {
        struct Authorizer(Vec<(u64, bool)>);
        impl PushAuthorizer for Authorizer {
            fn authorize(
                &mut self,
                _action: &keel_kernel::Asserted,
                _body_digest: [u8; 32],
            ) -> Result<Option<u64>, GitdError> {
                Ok(Some(11))
            }
            fn report(&mut self, action_id: u64, completed: bool) {
                self.0.push((action_id, completed));
            }
        }
        struct Rejecting;
        impl PushForwarder for Rejecting {
            fn forward(&mut self, _body: &[u8]) -> Result<Forwarded, GitdError> {
                Ok(Forwarded {
                    response: b"ng refs/heads/topic non-fast-forward".to_vec(),
                    rejection: Some("remote rejected refs/heads/topic".to_owned()),
                })
            }
        }
        struct Dropping;
        impl PushForwarder for Dropping {
            fn forward(&mut self, _body: &[u8]) -> Result<Forwarded, GitdError> {
                Err(GitdError::Kernel("connection dropped".to_owned()))
            }
        }

        let mut body = packet(&format!("{OLD} {NEW} refs/heads/topic\n"));
        body.extend_from_slice(b"0000PACK");
        let mirror = FakeMirror {
            ancestor: true,
            paths: vec!["src/lib.rs".to_owned()],
        };

        let mut authorizer = Authorizer(Vec::new());
        let response = mediate_receive_pack(
            &body,
            &mirror,
            &["refs/heads/main"],
            "origin",
            &mut authorizer,
            &mut Rejecting,
        )
        .expect("the remote's refusal is relayed to the client");
        assert_eq!(response, b"ng refs/heads/topic non-fast-forward");
        assert_eq!(authorizer.0, [(11, false)]);

        let mut authorizer = Authorizer(Vec::new());
        assert!(
            mediate_receive_pack(
                &body,
                &mirror,
                &["refs/heads/main"],
                "origin",
                &mut authorizer,
                &mut Dropping,
            )
            .is_err()
        );
        assert_eq!(authorizer.0, [(11, false)]);
    }

    struct NoEgress;

    impl EgressConnector for NoEgress {
        fn connect(
            &mut self,
            _host: &str,
            _port: u16,
            _method: &str,
        ) -> Result<Box<dyn EgressSession>, String> {
            Err("test connector must not receive Git actions".to_owned())
        }
    }

    struct RecordingGate {
        payloads: Arc<Mutex<Vec<GatePayload>>>,
    }

    impl Gate for RecordingGate {
        fn decide(&mut self, request: GateRequest<'_>) -> GateDecision {
            self.payloads.lock().unwrap().push(request.to_payload());
            GateDecision::Approve
        }
    }

    struct NoAudit;

    impl AuditSink for NoAudit {
        fn record(&mut self, _event: AuditEvent) -> Result<(), String> {
            Ok(())
        }
    }

    fn stateful_broker(
        session_id: &str,
        capabilities: BTreeSet<String>,
        audit: Box<dyn AuditSink>,
        gate: Box<dyn Gate>,
    ) -> KernelBroker {
        let mut facts = SessionFacts::default();
        facts.intent.allow_push_branch = capabilities.contains("push:branch");
        facts.intent.allow_pr_create = capabilities.contains("pr:create");
        KernelBroker::spawn_with_session_policy(
            session_id.to_owned(),
            BTreeSet::new(),
            capabilities,
            facts,
            ProvenanceMode::Floor,
            Box::new(StatefulPolicy::new().expect("stateful policy")),
            Box::new(NoEgress),
            audit,
            Some(gate),
        )
        .expect("broker")
    }

    struct DurableAudit(Option<AuditWriter>);

    impl AuditSink for DurableAudit {
        fn record(&mut self, event: AuditEvent) -> Result<(), String> {
            let fields = BTreeMap::from([
                ("action_class".to_owned(), event.class.as_str().to_owned()),
                ("outcome".to_owned(), event.outcome.as_str().to_owned()),
                ("target_kind".to_owned(), event.target_kind.to_owned()),
                ("target_hash".to_owned(), hex(&event.target_hash)),
            ]);
            self.0
                .as_ref()
                .ok_or_else(|| "audit writer is closed".to_owned())?
                .record(AuditPayload {
                    timestamp_ms: event.action_id,
                    event: "kernel.action".to_owned(),
                    action_id: Some(event.action_id),
                    fields,
                })
                .map_err(|error| error.to_string())
        }

        fn record_reported_outcome(&mut self, event: ReportedOutcomeEvent) -> Result<(), String> {
            self.0
                .as_ref()
                .ok_or_else(|| "audit writer is closed".to_owned())?
                .record(AuditPayload {
                    timestamp_ms: event.action_id,
                    event: "kernel.reported-outcome".to_owned(),
                    action_id: Some(event.action_id),
                    fields: BTreeMap::from([
                        ("reporter".to_owned(), event.reporter.to_owned()),
                        ("reported_outcome".to_owned(), event.outcome),
                    ]),
                })
                .map_err(|error| error.to_string())
        }

        fn shutdown(&mut self) -> Result<(), String> {
            self.0
                .take()
                .ok_or_else(|| "audit writer is closed".to_owned())?
                .shutdown()
                .map_err(|error| error.to_string())
        }
    }

    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn start_git_server(
        service: Arc<GitHttpService>,
    ) -> (SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("listener address");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = thread::spawn(move || {
            while !server_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking Git client");
                        service.serve(stream).expect("serve Git client");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("Git listener failed: {error}"),
                }
            }
        });
        (address, stop, server)
    }

    #[test]
    fn assessed_push_reaches_live_kernel_before_forwarding() {
        struct Forwarder(u64);

        impl PushForwarder for Forwarder {
            fn forward(&mut self, _body: &[u8]) -> Result<Forwarded, GitdError> {
                self.0 += 1;
                Ok(Forwarded {
                    response: b"forwarded".to_vec(),
                    rejection: None,
                })
            }
        }

        let payloads = Arc::new(Mutex::new(Vec::new()));
        let broker = stateful_broker(
            "gitd-kernel-channel",
            ["push:branch".to_owned()].into_iter().collect(),
            Box::new(NoAudit),
            Box::new(RecordingGate {
                payloads: Arc::clone(&payloads),
            }),
        );
        let mut authorizer = KernelPushAuthorizer::new(broker.socket_path());
        let mut body = packet(&format!("{OLD} {NEW} refs/heads/topic\n"));
        body.extend_from_slice(b"0000PACK");
        let mut forwarder = Forwarder(0);

        let response = mediate_receive_pack(
            &body,
            &FakeMirror {
                ancestor: true,
                paths: vec!["src/lib.rs".to_owned()],
            },
            &["refs/heads/main"],
            "origin",
            &mut authorizer,
            &mut forwarder,
        )
        .expect("safe branch push");
        assert_eq!(response, b"forwarded");
        assert_eq!(forwarder.0, 1);

        mediate_receive_pack(
            &body,
            &FakeMirror {
                ancestor: false,
                paths: vec!["Cargo.toml".to_owned()],
            },
            &["refs/heads/main"],
            "origin",
            &mut authorizer,
            &mut forwarder,
        )
        .expect("approved manifest push");
        assert_eq!(forwarder.0, 2);
        let payloads = payloads.lock().unwrap();
        assert_eq!(payloads.len(), 2);
        let exact_target = String::from_utf8(payloads[1].exact_target.clone()).unwrap();
        assert!(exact_target.contains("force: true"));
        assert!(exact_target.contains("touches manifest or CI: true"));
        assert!(exact_target.contains("diff -- Cargo.toml"));
        drop(payloads);

        let report = broker.shutdown().expect("broker shutdown");
        // Two authorizations and two reported outcomes: the kernel records what it
        // decided and, separately, what the relay says came of it.
        assert_eq!(report.audit_events, 6);
        assert_eq!(report.denied_actions, 0);
    }

    #[test]
    fn command_mirror_computes_ancestry_paths_and_exact_diff() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let repository =
            std::env::temp_dir().join(format!("keel-gitd-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&repository).expect("repository directory");
        git(&repository, &["init", "-q"]);
        git(&repository, &["config", "user.name", "Keel Test"]);
        git(&repository, &["config", "user.email", "keel@example.test"]);
        fs::write(repository.join("README.md"), "first\n").expect("first file");
        git(&repository, &["add", "README.md"]);
        git(&repository, &["commit", "-q", "-m", "first"]);
        let old = ObjectId::parse(&git(&repository, &["rev-parse", "HEAD"])).expect("old object");

        fs::write(repository.join("Cargo.toml"), "[package]\nname='demo'\n").expect("manifest");
        git(&repository, &["add", "Cargo.toml"]);
        git(&repository, &["commit", "-q", "-m", "manifest"]);
        let new = ObjectId::parse(&git(&repository, &["rev-parse", "HEAD"])).expect("new object");
        let mirror = CommandMirror::open(&repository).expect("mirror");

        assert!(mirror.is_ancestor(&old, &new).expect("ancestry"));
        assert!(!mirror.is_ancestor(&new, &old).expect("reverse ancestry"));
        assert_eq!(
            mirror.changed_paths(&old, &new).expect("paths"),
            ["Cargo.toml"]
        );
        assert!(
            mirror
                .manifest_diff(&old, &new, &["Cargo.toml".to_owned()])
                .expect("diff")
                .contains("+name='demo'")
        );
        fs::remove_dir_all(repository).expect("remove repository");
    }

    #[test]
    fn manifest_detection_survives_quoting_and_renames() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let repository =
            std::env::temp_dir().join(format!("keel-gitd-quote-{}-{nonce}", std::process::id()));
        fs::create_dir_all(repository.join("é")).expect("repository directory");
        git(&repository, &["init", "-q"]);
        git(&repository, &["config", "user.name", "Keel Test"]);
        git(&repository, &["config", "user.email", "keel@example.test"]);
        fs::write(
            repository.join("Gemfile"),
            "source 'https://rubygems.org'\n",
        )
        .expect("gemfile");
        git(&repository, &["add", "Gemfile"]);
        git(&repository, &["commit", "-q", "-m", "first"]);
        let first = ObjectId::parse(&git(&repository, &["rev-parse", "HEAD"])).expect("first");

        fs::write(repository.join("é/package.json"), "{}\n").expect("quoted manifest");
        git(&repository, &["mv", "Gemfile", "notes.txt"]);
        git(&repository, &["add", "é/package.json"]);
        git(&repository, &["commit", "-q", "-m", "second"]);
        let second = ObjectId::parse(&git(&repository, &["rev-parse", "HEAD"])).expect("second");
        let mirror = CommandMirror::open(&repository).expect("mirror");

        let manifests = mirror
            .changed_paths(&first, &second)
            .expect("paths")
            .into_iter()
            .filter(|path| super::is_manifest_path(path))
            .collect::<Vec<_>>();
        assert_eq!(manifests, ["Gemfile", "é/package.json"]);
        assert!(
            mirror
                .manifest_diff(&first, &second, &manifests)
                .expect("diff")
                .contains("-source 'https://rubygems.org'")
        );
        fs::remove_dir_all(repository).expect("remove repository");
    }

    #[test]
    fn command_mirror_stages_incoming_objects_before_assessment() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("keel-gitd-stage-{}-{nonce}", std::process::id()));
        let source = root.join("source");
        let mirror_path = root.join("mirror.git");
        fs::create_dir_all(&source).expect("source directory");
        git(&source, &["init", "-q"]);
        git(&source, &["config", "user.name", "Keel Test"]);
        git(&source, &["config", "user.email", "keel@example.test"]);
        fs::write(source.join("README.md"), "first\n").expect("first file");
        git(&source, &["add", "README.md"]);
        git(&source, &["commit", "-q", "-m", "first"]);
        let old = git(&source, &["rev-parse", "HEAD"]);
        let clone = git_command()
            .args(["clone", "--bare", "--quiet"])
            .arg(&source)
            .arg(&mirror_path)
            .output()
            .expect("clone mirror");
        assert!(
            clone.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&clone.stderr)
        );

        fs::write(source.join("Cargo.toml"), "[package]\nname='staged'\n").expect("manifest");
        git(&source, &["add", "Cargo.toml"]);
        git(&source, &["commit", "-q", "-m", "manifest"]);
        let new = git(&source, &["rev-parse", "HEAD"]);
        let mut packer = git_command()
            .arg("-C")
            .arg(&source)
            .args(["pack-objects", "--stdout", "--revs"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("pack objects");
        write!(
            packer.stdin.take().expect("packer stdin"),
            "{new}\n^{old}\n"
        )
        .expect("pack revisions");
        let pack = packer.wait_with_output().expect("pack output");
        assert!(pack.status.success(), "git pack-objects failed");

        let mirror = CommandMirror::open(&mirror_path).expect("open mirror");
        let old = ObjectId::parse(&old).expect("old object");
        let new = ObjectId::parse(&new).expect("new object");
        assert!(mirror.changed_paths(&old, &new).is_err());
        mirror
            .stage_pack(&pack.stdout)
            .expect("stage incoming pack");
        assert!(mirror.is_ancestor(&old, &new).expect("ancestry"));
        assert_eq!(
            mirror.changed_paths(&old, &new).expect("changed paths"),
            ["Cargo.toml"]
        );
        assert!(
            mirror
                .manifest_diff(&old, &new, &["Cargo.toml".to_owned()])
                .expect("manifest diff")
                .contains("+name='staged'")
        );
        fs::remove_dir_all(root).expect("remove repositories");
    }

    #[test]
    fn smart_http_service_advertises_the_isolated_mirror() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("keel-git-http-{}-{nonce}", std::process::id()));
        let source = root.join("source");
        fs::create_dir_all(&source).expect("source directory");
        git(&source, &["init", "-q"]);
        git(&source, &["config", "user.name", "Keel Test"]);
        git(&source, &["config", "user.email", "keel@example.test"]);
        fs::write(source.join("README.md"), "smart HTTP\n").expect("file");
        git(&source, &["add", "README.md"]);
        git(&source, &["commit", "-q", "-m", "initial"]);
        let service = GitHttpService::initialize(
            &source,
            &root.join("service"),
            root.join("missing-kernel.sock"),
        )
        .expect("Git service");
        let (mut client, server) = UnixStream::pair().expect("stream pair");
        client
            .write_all(
                b"GET /origin/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: 10.0.0.1:9418\r\n\r\n",
            )
            .expect("HTTP request");
        service.serve(server).expect("serve request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("HTTP response");
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let content_type = b"Content-Type: application/x-git-upload-pack";
        assert!(
            response
                .windows(content_type.len())
                .any(|window| window == content_type)
        );
        let service_header = b"# service=git-upload";
        assert!(
            response
                .windows(service_header.len())
                .any(|window| window == service_header)
        );
        fs::remove_dir_all(root).expect("remove service");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn phase_one_node_contract_pushes_opens_pr_and_verifies_audit() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("keel-git-push-{}-{nonce}", std::process::id()));
        let source = root.join("source");
        let client = root.join("client");
        fs::create_dir_all(&source).expect("source directory");
        git(&source, &["init", "-q"]);
        git(&source, &["config", "user.name", "Keel Test"]);
        git(&source, &["config", "user.email", "keel@example.test"]);
        fs::write(source.join("README.md"), "initial\n").expect("file");
        fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"keel-test\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::create_dir(source.join("src")).expect("source tree");
        fs::write(
            source.join("src/lib.rs"),
            "#[must_use]\npub fn answer() -> u8 { 42 }\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn answer_is_stable() { assert_eq!(super::answer(), 42); }\n}\n",
        )
        .expect("source file");
        git(&source, &["add", "README.md", "Cargo.toml", "src/lib.rs"]);
        git(&source, &["commit", "-q", "-m", "initial"]);
        let audit_path = root.join("audit.ndjson");
        let tampered_path = root.join("audit-tampered.ndjson");
        let audit = AuditWriter::spawn(
            &audit_path,
            "phase-one-node-contract",
            RunKey::new([23; 32]),
            Redactor::new(Vec::<String>::new()).expect("redactor"),
        )
        .expect("audit writer");

        let payloads = Arc::new(Mutex::new(Vec::new()));
        let broker = stateful_broker(
            "phase-one-node-contract",
            ["pr:create".to_owned(), "push:branch".to_owned()]
                .into_iter()
                .collect(),
            Box::new(DurableAudit(Some(audit))),
            Box::new(RecordingGate {
                payloads: Arc::clone(&payloads),
            }),
        );
        let service = Arc::new(
            GitHttpService::initialize(&source, &root.join("service"), broker.socket_path())
                .expect("Git service"),
        );
        let (address, stop, server) = start_git_server(Arc::clone(&service));

        let clone = git_command()
            .args(["clone", "--quiet"])
            .arg(format!("http://{address}/origin"))
            .arg(&client)
            .output()
            .expect("clone client");
        assert!(
            clone.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&clone.stderr)
        );
        git(&client, &["config", "user.name", "Keel Test"]);
        git(&client, &["config", "user.email", "keel@example.test"]);
        assert_eq!(
            fs::read_to_string(client.join("README.md")).expect("read repository"),
            "initial\n"
        );
        let tests = Command::new("cargo")
            .arg("test")
            .arg("--quiet")
            .current_dir(&client)
            .output()
            .expect("run repository tests");
        assert!(
            tests.status.success(),
            "repository tests failed: {}",
            String::from_utf8_lossy(&tests.stderr)
        );
        git(&client, &["checkout", "-q", "-b", "keel-e2e"]);
        fs::write(client.join("README.md"), "approved update\n").expect("update");
        git(&client, &["add", "README.md"]);
        git(&client, &["commit", "-q", "-m", "update"]);
        let push = git_command()
            .arg("-C")
            .arg(&client)
            .args(["push", "--quiet", "origin", "HEAD:refs/heads/keel-e2e"])
            .output()
            .expect("push client");
        assert!(
            push.status.success(),
            "git push failed: {}",
            String::from_utf8_lossy(&push.stderr)
        );
        assert_eq!(
            git(&client, &["rev-parse", "HEAD"]),
            git(
                &service.project_root.join("origin"),
                &["rev-parse", "refs/heads/keel-e2e"]
            )
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("MCP runtime");
        let pull_request = runtime
            .block_on(pull_request_round_trip(
                broker.socket_path().to_path_buf(),
                PullRequestAction {
                    repository: "owner/repo".to_owned(),
                    head: "keel-e2e".to_owned(),
                    base: "main".to_owned(),
                    title: "Keel Phase 1 acceptance".to_owned(),
                    body: "Exercises the mediated pull-request path.".to_owned(),
                },
                |_| Ok("https://github.example/owner/repo/pull/1".to_owned()),
            ))
            .expect("approved pull request");
        assert_eq!(pull_request, "https://github.example/owner/repo/pull/1");

        stop.store(true, Ordering::Release);
        server.join().expect("Git server");
        let payloads = payloads.lock().expect("gate payloads");
        assert_eq!(payloads.len(), 2);
        let pull_request_payload = payloads
            .iter()
            .find(|payload| payload.action_class == "pull-request")
            .expect("pull-request gate payload");
        let target =
            String::from_utf8(pull_request_payload.exact_target.clone()).expect("target text");
        assert!(target.contains(r#"recipient: "owner/repo""#));
        assert!(target.contains(r#""head":"keel-e2e""#));
        assert!(target.contains(r#""title":"Keel Phase 1 acceptance""#));
        drop(payloads);
        let report = broker.shutdown().expect("broker shutdown");
        assert_eq!(report.audit_events, 5);
        assert_eq!(
            verify_file(&audit_path, &RunKey::new([23; 32])).expect("valid audit"),
            5
        );
        let audit_text = fs::read_to_string(&audit_path).expect("audit text");
        assert!(audit_text.contains(r#""action_class":"git-push""#));
        assert!(audit_text.contains(r#""action_class":"pull-request""#));
        // The push landed, and the audit says so as a relay report rather than as a
        // kernel assertion about something the kernel did not observe.
        assert!(audit_text.contains(r#""event":"kernel.reported-outcome""#));
        assert!(audit_text.contains(r#""reported_outcome":"completed""#));
        fs::write(
            &tampered_path,
            audit_text.replacen("git-push", "git-push-tampered", 1),
        )
        .expect("tampered audit");
        assert!(verify_file(&tampered_path, &RunKey::new([23; 32])).is_err());
        fs::remove_dir_all(root).expect("remove service");
    }

    #[derive(Clone, Copy)]
    enum ForceSyntax {
        Flag,
        ForceWithLease,
        ForceWithLeaseRef,
        ForceWithLeaseExact,
        RefPrefix,
        Alias,
    }

    impl ForceSyntax {
        fn label(self) -> &'static str {
            match self {
                Self::Flag => "flag",
                Self::ForceWithLease => "force-with-lease",
                Self::ForceWithLeaseRef => "force-with-lease-ref",
                Self::ForceWithLeaseExact => "force-with-lease-exact",
                Self::RefPrefix => "ref-prefix",
                Self::Alias => "alias",
            }
        }
    }

    fn run_force_push(client: &Path, syntax: ForceSyntax) -> std::process::Output {
        let mut force = git_command();
        force.arg("-C").arg(client);
        match syntax {
            ForceSyntax::Flag => {
                force.args([
                    "push",
                    "--quiet",
                    "--force",
                    "origin",
                    "HEAD:refs/heads/topic",
                ]);
            }
            ForceSyntax::ForceWithLease => {
                force.args([
                    "push",
                    "--quiet",
                    "--force-with-lease",
                    "origin",
                    "HEAD:refs/heads/topic",
                ]);
            }
            ForceSyntax::ForceWithLeaseRef => {
                force.args([
                    "push",
                    "--quiet",
                    "--force-with-lease=refs/heads/topic",
                    "origin",
                    "HEAD:refs/heads/topic",
                ]);
            }
            ForceSyntax::ForceWithLeaseExact => {
                let expected = git(client, &["rev-parse", "refs/remotes/origin/topic"]);
                force
                    .args(["push", "--quiet"])
                    .arg(format!("--force-with-lease=refs/heads/topic:{expected}"))
                    .args(["origin", "HEAD:refs/heads/topic"]);
            }
            ForceSyntax::RefPrefix => {
                force.args(["push", "--quiet", "origin", "+HEAD:refs/heads/topic"]);
            }
            ForceSyntax::Alias => {
                git(
                    client,
                    &[
                        "config",
                        "alias.force-topic",
                        "push --quiet --force origin HEAD:refs/heads/topic",
                    ],
                );
                force.arg("force-topic");
            }
        }
        force.output().expect("force push")
    }

    fn force_push_gate_target(syntax: ForceSyntax) -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "keel-git-force-{}-{}-{nonce}",
            syntax.label(),
            std::process::id()
        ));
        let source = root.join("source");
        let client = root.join("client");
        fs::create_dir_all(&source).expect("source directory");
        git(&source, &["init", "-q"]);
        git(&source, &["config", "user.name", "Keel Test"]);
        git(&source, &["config", "user.email", "keel@example.test"]);
        fs::write(source.join("README.md"), "base\n").expect("base file");
        git(&source, &["add", "README.md"]);
        git(&source, &["commit", "-q", "-m", "base"]);

        let payloads = Arc::new(Mutex::new(Vec::new()));
        let broker = stateful_broker(
            &format!("force-push-{}", syntax.label()),
            ["push:branch".to_owned()].into_iter().collect(),
            Box::new(NoAudit),
            Box::new(RecordingGate {
                payloads: Arc::clone(&payloads),
            }),
        );
        let service = Arc::new(
            GitHttpService::initialize(&source, &root.join("service"), broker.socket_path())
                .expect("Git service"),
        );
        let (address, stop, server) = start_git_server(service);
        let clone = git_command()
            .args(["clone", "--quiet"])
            .arg(format!("http://{address}/origin"))
            .arg(&client)
            .output()
            .expect("clone client");
        assert!(
            clone.status.success(),
            "git clone failed: {}",
            String::from_utf8_lossy(&clone.stderr)
        );
        git(&client, &["config", "user.name", "Keel Test"]);
        git(&client, &["config", "user.email", "keel@example.test"]);
        let base = git(&client, &["rev-parse", "HEAD"]);

        fs::write(client.join("README.md"), "first topic tip\n").expect("first topic file");
        git(&client, &["add", "README.md"]);
        git(&client, &["commit", "-q", "-m", "first topic tip"]);
        git(
            &client,
            &["push", "--quiet", "origin", "HEAD:refs/heads/topic"],
        );
        git(
            &client,
            &[
                "fetch",
                "--quiet",
                "origin",
                "topic:refs/remotes/origin/topic",
            ],
        );
        // Git does not transmit the caller's force option. Every syntax below
        // therefore has to produce the same genuinely divergent ref update;
        // the relay's security fact is old/new ancestry on the wire, not argv.
        git(&client, &["reset", "--hard", &base]);
        fs::write(client.join("README.md"), "replacement topic tip\n")
            .expect("replacement topic file");
        git(&client, &["add", "README.md"]);
        git(&client, &["commit", "-q", "-m", "replacement topic tip"]);

        let force = run_force_push(&client, syntax);
        stop.store(true, Ordering::Release);
        server.join().expect("Git server");
        assert!(
            force.status.success(),
            "git force push failed: {}",
            String::from_utf8_lossy(&force.stderr)
        );

        let payloads = payloads.lock().expect("gate payloads");
        assert_eq!(payloads.len(), 2);
        let target = String::from_utf8(payloads[1].exact_target.clone()).expect("target text");
        drop(payloads);
        let report = broker.shutdown().expect("broker shutdown");
        // Per push: one kernel authorization and one relay-reported outcome.
        assert_eq!(report.audit_events, 6);
        fs::remove_dir_all(root).expect("remove service");
        target
    }

    #[test]
    fn force_flag_reaches_wire_parser_and_kernel_gate() {
        assert!(force_push_gate_target(ForceSyntax::Flag).contains("force: true"));
    }

    #[test]
    fn force_with_lease_reaches_wire_parser_and_kernel_gate() {
        assert!(force_push_gate_target(ForceSyntax::ForceWithLease).contains("force: true"));
    }

    #[test]
    fn force_with_lease_ref_reaches_wire_parser_and_kernel_gate() {
        assert!(force_push_gate_target(ForceSyntax::ForceWithLeaseRef).contains("force: true"));
    }

    #[test]
    fn force_with_lease_exact_reaches_wire_parser_and_kernel_gate() {
        assert!(force_push_gate_target(ForceSyntax::ForceWithLeaseExact).contains("force: true"));
    }

    #[test]
    fn force_ref_prefix_reaches_wire_parser_and_kernel_gate() {
        assert!(force_push_gate_target(ForceSyntax::RefPrefix).contains("force: true"));
    }

    #[test]
    fn force_alias_reaches_wire_parser_and_kernel_gate() {
        assert!(force_push_gate_target(ForceSyntax::Alias).contains("force: true"));
    }

    #[test]
    fn remote_push_preflight_uses_the_sentinel_only_for_exact_receive_pack_scope() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = Path::new("/tmp").join(format!("kg-{}-{nonce:x}", std::process::id()));
        fs::create_dir(&root).expect("test root");
        let socket = root.join("broker.sock");
        let listener = UnixListener::bind(&socket).expect("broker listener");
        let ca = TestMitmCa::generate().expect("test CA");
        let server_config = ca.server_config("git.example").expect("server config");
        let server = thread::spawn(move || {
            for (expected, credential_bearing) in [
                (
                    "GET /owner/repo.git/info/refs?service=git-receive-pack HTTP/1.1\r\n",
                    true,
                ),
                (
                    "GET /owner/repo.git/info/refs?service=git-upload-pack HTTP/1.1\r\n",
                    false,
                ),
                ("GET /owner/repo.git/HEAD HTTP/1.1\r\n", false),
                ("POST /owner/repo.git/git-receive-pack HTTP/1.1\r\n", true),
            ] {
                let (mut stream, _) = listener.accept().expect("broker accept");
                let mut marker = [0_u8; 15];
                stream.read_exact(&mut marker).expect("egress marker");
                assert_eq!(&marker, b"KEEL-EGRESS-V2\0");
                let mut length = [0_u8; 2];
                stream.read_exact(&mut length).expect("host length");
                let mut host = vec![0_u8; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut host).expect("host");
                assert_eq!(host, b"git.example");
                let mut suffix = [0_u8; 3];
                stream.read_exact(&mut suffix).expect("port and method");
                assert_eq!(suffix, [1, 187, 1]);
                stream.write_all(b"PA").expect("pending then allow");
                stream.flush().expect("allow flush");

                let connection = ServerConnection::new(Arc::clone(&server_config))
                    .expect("server TLS connection");
                let mut tls = StreamOwned::new(connection, stream);
                let mut request = vec![0_u8; 4096];
                let count = tls.read(&mut request).expect("TLS HTTP request");
                request.truncate(count);
                let text = String::from_utf8_lossy(&request);
                assert!(text.starts_with(expected));
                assert_eq!(
                    text.contains("Authorization: sentinel-only\r\n"),
                    credential_bearing
                );
                assert!(!text.contains("real-token"));
                tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .expect("HTTP response");
                tls.conn.send_close_notify();
                tls.flush().expect("TLS response flush");
            }
        });
        let upstream = KernelGitUpstream::new(
            "https://git.example/owner/repo.git",
            &socket,
            &ca.certificate_pem(),
            Some("sentinel-only"),
        )
        .expect("upstream");
        let advertisement = upstream
            .forward_receive_pack_advertisement()
            .expect("remote receive-pack advertisement");
        assert!(advertisement.starts_with(b"HTTP/1.1 200 OK\r\n"));
        for (endpoint, query) in [
            ("info/refs", Some("service=git-upload-pack")),
            ("HEAD", None),
        ] {
            let response = upstream
                .forward_http("GET", endpoint, query, "", "application/octet-stream", &[])
                .expect("unauthenticated repository read");
            assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        }
        let response = upstream
            .forward_receive_pack(
                &HttpRequest {
                    method: "POST".to_owned(),
                    path: "/origin/git-receive-pack".to_owned(),
                    query: None,
                    content_type: Some("application/x-git-receive-pack-request".to_owned()),
                    body: b"PACK".to_vec(),
                },
                b"PACK",
            )
            .expect("remote push");
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        server.join().expect("server");
        fs::remove_dir_all(root).expect("remove test root");
    }

    fn git(repository: &Path, arguments: &[&str]) -> String {
        let output = git_command()
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git UTF-8")
            .trim()
            .to_owned()
    }
}
