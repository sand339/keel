#![forbid(unsafe_code)]
#![doc = "Trusted credential and TLS custody for Keel."]

use keel_audit::Redactor;
use keel_kernel::{
    ContextBlock, EgressConnector, EgressRequestAuthorizer, EgressSession, ModelBudgetRequest,
    ModelUsage,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use ring::{
    digest::{SHA256, digest},
    hmac,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    io::Write as _,
    net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs as _},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

/// Identifies this crate as part of the trusted computing base.
pub const TRUSTED_CRATE: &str = "keel-secrets";

const MAX_HTTP_REQUEST: usize = 1024 * 1024;
const MAX_HTTP_RESPONSE: u64 = 16 * 1024 * 1024;
const MAX_RESOLVED_ADDRESSES: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REUSE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// A large model request can take minutes before its first streamed event,
/// and some providers send no keepalive meanwhile. A short timeout here turned
/// slow responses into ambiguous failures charged at the full reservation.
/// This matches the harness's own API timeout.
const MODEL_READ_IDLE_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_REUSED_REQUESTS: usize = 32;
const EVENT_STREAM_CONTENT_TYPE: &str = "application/vnd.amazon.eventstream";

/// The validated scope of the Git credential configured for one run.
///
/// The host is returned so the caller allows egress to exactly the host the
/// credential is bound to. Two readers of `KEEL_GIT_CREDENTIAL_HOST` could
/// disagree about what counts as a valid host; one validated value cannot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitCredentialScope {
    /// Sentinel handed to the untrusted Git relay in place of the credential.
    pub sentinel: String,
    /// Host the credential is scoped to, lowercase and control-free.
    pub host: String,
}

/// Explicit GitHub API authorities accepted for one run.
///
/// Keeping these authorities together prevents a growing list of booleans from
/// obscuring which credential surfaces the caller intended to enable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitHubAuthorities {
    create_pull_requests: bool,
    read_private_issues: bool,
}

impl GitHubAuthorities {
    /// Constructs the exact GitHub API authority set for a run.
    #[must_use]
    pub const fn new(create_pull_requests: bool, read_private_issues: bool) -> Self {
        Self {
            create_pull_requests,
            read_private_issues,
        }
    }

    const fn any(self) -> bool {
        self.create_pull_requests || self.read_private_issues
    }
}

#[derive(Default)]
struct RuntimeCredentialValues {
    allow_git_push: bool,
    git_credential: Option<String>,
    git_host: Option<String>,
    git_path: Option<String>,
    model: Option<String>,
    github: Option<String>,
    github_authorities: GitHubAuthorities,
    bedrock: Option<(String, String)>,
    signer: Option<SigV4Signer>,
    openrouter: Option<String>,
}

/// System resolver and TCP connector guarded by structural address checks.
pub struct SystemEgressConnector {
    ca: Arc<MitmCa>,
    upstream_tls: Arc<ClientConfig>,
    vault: Arc<CredentialVault>,
    reuse_connections: bool,
}

impl SystemEgressConnector {
    /// Sentinel exposed to the untrusted Git relay when a scoped token exists.
    pub const GIT_SENTINEL: &'static str = "keel-git-credential-sentinel-v1";
    /// Sentinel presented by Claude Code and swapped only for model messages.
    pub const MODEL_SENTINEL: &'static str = "keel-anthropic-credential-sentinel-v1";
    /// Sentinel used by the broker-backed GitHub pull-request client.
    pub const GITHUB_SENTINEL: &'static str = "keel-github-credential-sentinel-v1";
    /// Sentinel presented as a bearer token for a regional model endpoint.
    pub const BEDROCK_SENTINEL: &'static str = "keel-bedrock-credential-sentinel-v1";
    /// Sentinel presented as a bearer token for the `OpenRouter` endpoint.
    pub const OPENROUTER_SENTINEL: &'static str = "keel-openrouter-credential-sentinel-v1";

    /// Creates a connector with an ephemeral per-run CA and public `WebPKI`
    /// upstream roots.
    ///
    /// # Errors
    ///
    /// Returns an error when the run CA cannot be generated.
    pub fn new() -> Result<Self, String> {
        Self::with_vault(CredentialVault::new())
    }

    /// Creates a connector with a trusted credential vault.
    ///
    /// # Errors
    ///
    /// Returns an error when the run CA cannot be generated.
    pub fn with_vault(vault: CredentialVault) -> Result<Self, String> {
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        let upstream_tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            ca: Arc::new(MitmCa::generate().map_err(|error| error.to_string())?),
            upstream_tls: Arc::new(upstream_tls),
            vault: Arc::new(vault),
            reuse_connections: false,
        })
    }

    /// Describes every credential this run holds by scope, never by value:
    /// `METHODS host path` per binding and `SIGV4 host` for a signer.
    #[must_use]
    pub fn credential_scopes(&self) -> Vec<String> {
        let mut scopes = self
            .vault
            .bindings
            .iter()
            .map(|binding| {
                let methods = binding.scope.methods.iter().cloned().collect::<Vec<_>>();
                let scope = &binding.scope;
                format!(
                    "{} {}{}",
                    methods.join(","),
                    scope.server_name,
                    scope.path_prefix
                )
            })
            .collect::<Vec<_>>();
        scopes.extend(
            self.vault
                .signer
                .iter()
                .map(|signer| format!("SIGV4 {}", signer.host)),
        );
        scopes.sort();
        scopes
    }

    /// Enables bounded sequential connection reuse for the Anthropic API.
    ///
    /// Reuse remains disabled for every other destination.
    #[must_use]
    pub fn with_connection_reuse(mut self, enabled: bool) -> Self {
        self.reuse_connections = enabled;
        self
    }

    /// Builds the run connector and scoped credentials from the trusted
    /// process environment and the active GitHub CLI keyring entry.
    ///
    /// Only push authority reads `KEEL_GIT_AUTHORIZATION`; private issue reads
    /// use the host/path as repository identity without activating that secret.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete or malformed credential scope.
    pub fn from_runtime_environment(
        allow_git_push: bool,
        github_authorities: GitHubAuthorities,
        include_model_provider: bool,
    ) -> Result<(Self, Option<GitCredentialScope>, Option<String>, Redactor), String> {
        let repository_scope = allow_git_push || github_authorities.read_private_issues;
        let (credential, host, path) = if repository_scope {
            (
                allow_git_push
                    .then(|| std::env::var("KEEL_GIT_AUTHORIZATION").ok())
                    .flatten(),
                std::env::var("KEEL_GIT_CREDENTIAL_HOST").ok(),
                std::env::var("KEEL_GIT_CREDENTIAL_PATH").ok(),
            )
        } else {
            (None, None, None)
        };
        // Reading the operator's GitHub credential is itself authority-bearing.
        // Do it only for a run whose accepted capability declares a GitHub
        // effect; ordinary model and V8 runs must not silently harvest it.
        let github = if github_authorities.any() {
            match (
                std::env::var("GH_TOKEN").ok(),
                std::env::var("GITHUB_TOKEN").ok(),
            ) {
                (Some(left), Some(right)) if left != right => {
                    return Err(
                        "GH_TOKEN and GITHUB_TOKEN contain different credentials".to_owned()
                    );
                }
                (Some(token), _) | (_, Some(token)) => Some(token),
                (None, None) => std::process::Command::new("gh")
                    .args(["auth", "token", "--hostname", "github.com"])
                    .output()
                    .ok()
                    .filter(|output| output.status.success())
                    .and_then(|output| String::from_utf8(output.stdout).ok())
                    .map(|token| token.trim().to_owned())
                    .filter(|token| !token.is_empty()),
            }
        } else {
            None
        };
        // One provider per run. The credential for the provider this run did not
        // select is left unbound rather than bound and unreachable: a run that
        // holds a live key for a host outside its own egress intent is one
        // allowlist mistake away from having two budgets and one log.
        let (model, bedrock, signer, openrouter) = if include_model_provider {
            let provider = runtime_model_provider()?;
            let bedrock = provider
                .region
                .is_some()
                .then_some(std::env::var("AWS_BEARER_TOKEN_BEDROCK").ok())
                .flatten()
                .map(|token| (provider.host.clone(), token));
            let openrouter = (provider.host == OPENROUTER_HOST)
                .then(|| std::env::var("OPENROUTER_API_KEY").ok())
                .flatten();
            let model = if provider.region.is_some() || provider.host == OPENROUTER_HOST {
                None
            } else {
                std::env::var("ANTHROPIC_API_KEY").ok()
            };
            // A regional provider without a bearer token authenticates by signing.
            // Resolving the credentials here rather than at first request means a
            // missing or unusable session is a refusal before the VM boots, not a
            // dropped model call an hour into a run.
            let signer = match &provider.region {
                Some(region) if bedrock.is_none() => Some(SigV4Signer::from_runtime_environment(
                    provider.host.clone(),
                    region.clone(),
                )?),
                _ => None,
            };
            (model, bedrock, signer, openrouter)
        } else {
            // Harnesses without model egress must not even resolve model credentials.
            // Besides shrinking ambient authority, this keeps non-model tests and
            // tools independent of an operator's current SSO login state.
            (None, None, None, None)
        };
        Self::from_runtime_values_all(RuntimeCredentialValues {
            allow_git_push,
            git_credential: credential,
            git_host: host,
            git_path: path,
            model,
            github,
            github_authorities,
            bedrock,
            signer,
            openrouter,
        })
    }

    fn from_runtime_values_all(
        values: RuntimeCredentialValues,
    ) -> Result<(Self, Option<GitCredentialScope>, Option<String>, Redactor), String> {
        let RuntimeCredentialValues {
            allow_git_push,
            git_credential,
            git_host,
            git_path,
            model,
            github,
            github_authorities,
            bedrock,
            signer,
            openrouter,
        } = values;
        // Tell the guest to present the GitHub sentinel only when this run
        // actually loaded a corresponding GitHub credential. A Git-only run
        // must keep public issue reads anonymous rather than presenting an
        // unbound sentinel that trusted custody will correctly reject.
        let github_repository = github_authorities
            .read_private_issues
            .then_some(github.as_ref())
            .flatten()
            .and_then(|_| {
                git_host
                    .as_deref()
                    .zip(git_path.as_deref())
                    .and_then(|(host, path)| github_repository_from_git_scope(host, path))
            });
        let mut vault = CredentialVault::new();
        vault.signer = signer;
        let mut redactions = Vec::new();
        let git_scope = configure_git_binding(
            &mut vault,
            &mut redactions,
            allow_git_push,
            git_credential,
            git_host,
            git_path,
        )?;
        let (bedrock_host, bedrock_token) =
            bedrock.map_or((String::new(), None), |(host, token)| (host, Some(token)));
        for (credential, sentinel, host, path, methods) in [
            (
                model,
                Self::MODEL_SENTINEL,
                "api.anthropic.com",
                "/v1/messages",
                &["POST"][..],
            ),
            (
                bedrock_token,
                Self::BEDROCK_SENTINEL,
                bedrock_host.as_str(),
                "/model",
                &["POST"][..],
            ),
            (
                openrouter,
                Self::OPENROUTER_SENTINEL,
                OPENROUTER_HOST,
                "/api/v1/messages",
                &["POST"][..],
            ),
        ] {
            let Some(credential) = credential else {
                continue;
            };
            if credential.is_empty() || credential.chars().any(char::is_control) {
                return Err(format!("{host} credential is malformed"));
            }
            redactions.extend([credential.clone(), sentinel.to_owned()]);
            vault.insert(
                CredentialBinding::new(
                    CredentialScope {
                        server_name: host.to_owned(),
                        methods: methods.iter().map(|method| (*method).to_owned()).collect(),
                        path_prefix: path.to_owned(),
                    },
                    SecretBytes::new(sentinel.as_bytes().to_vec()),
                    SecretBytes::new(credential.into_bytes()),
                )
                .map_err(|error| error.to_string())?,
            );
        }
        configure_github_bindings(
            &mut vault,
            &mut redactions,
            github,
            github_authorities,
            github_repository.as_deref(),
        )?;
        let redactor = Redactor::new(redactions).map_err(|error| error.to_string())?;
        Self::with_vault(vault).map(|connector| (connector, git_scope, github_repository, redactor))
    }
}

fn configure_git_binding(
    vault: &mut CredentialVault,
    redactions: &mut Vec<String>,
    enabled: bool,
    credential: Option<String>,
    host: Option<String>,
    path: Option<String>,
) -> Result<Option<GitCredentialScope>, String> {
    if !enabled || (credential.is_none() && host.is_none() && path.is_none()) {
        return Ok(None);
    }
    let (Some(credential), Some(host), Some(path)) = (credential, host, path) else {
        return Err("Git authorization, host, and path must be configured together".into());
    };
    if credential.is_empty()
        || host.is_empty()
        || host != host.to_ascii_lowercase()
        || host.chars().any(char::is_control)
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
    {
        return Err("Git credential scope is malformed".to_owned());
    }
    let sentinel = SystemEgressConnector::GIT_SENTINEL.to_owned();
    redactions.extend([credential.clone(), sentinel.clone()]);
    vault.insert(
        CredentialBinding::new(
            CredentialScope {
                server_name: host.clone(),
                // Private smart-HTTP pushes authenticate both the
                // receive-pack advertisement and the later write. The
                // endpoint-shape check still excludes every fetch and other
                // repository operation.
                methods: ["GET".to_owned(), "POST".to_owned()].into_iter().collect(),
                path_prefix: path,
            },
            SecretBytes::new(sentinel.as_bytes().to_vec()),
            SecretBytes::new(credential.into_bytes()),
        )
        .map_err(|error| error.to_string())?,
    );
    Ok(Some(GitCredentialScope { sentinel, host }))
}

fn configure_github_bindings(
    vault: &mut CredentialVault,
    redactions: &mut Vec<String>,
    credential: Option<String>,
    authorities: GitHubAuthorities,
    repository: Option<&str>,
) -> Result<(), String> {
    let Some(credential) = credential else {
        return Ok(());
    };
    if credential.is_empty() || credential.chars().any(char::is_control) {
        return Err("api.github.com credential is malformed".to_owned());
    }
    redactions.extend([
        credential.clone(),
        SystemEgressConnector::GITHUB_SENTINEL.to_owned(),
    ]);
    let mut insert = |methods: &[&str], path_prefix: String| -> Result<(), String> {
        vault.insert(
            CredentialBinding::new(
                CredentialScope {
                    server_name: "api.github.com".to_owned(),
                    methods: methods.iter().map(|method| (*method).to_owned()).collect(),
                    path_prefix,
                },
                SecretBytes::new(SystemEgressConnector::GITHUB_SENTINEL.as_bytes().to_vec()),
                SecretBytes::new(credential.as_bytes().to_vec()),
            )
            .map_err(|error| error.to_string())?,
        );
        Ok(())
    };
    if authorities.create_pull_requests {
        insert(&["POST"], "/repos".to_owned())?;
    }
    if let Some(repository) = repository {
        insert(&["GET"], format!("/repos/{repository}"))?;
    }
    Ok(())
}

impl EgressConnector for SystemEgressConnector {
    fn structurally_denied(&self, host: &str, port: u16, method: &str) -> bool {
        (method == "CONNECT" && port != 443)
            || host.parse::<IpAddr>().ok().is_some_and(is_forbidden_ip)
    }

    fn connect(
        &mut self,
        host: &str,
        port: u16,
        method: &str,
    ) -> Result<Box<dyn EgressSession>, String> {
        if method == "CONNECT" && port != 443 {
            return Err("CONNECT egress is restricted to inspected TLS on port 443".to_owned());
        }
        if host.parse::<IpAddr>().ok().is_some_and(is_forbidden_ip) {
            return Err("egress target is a forbidden address".to_owned());
        }
        let tls = method == "TLS" || (method == "CONNECT" && port == 443);
        let front_tls = tls
            .then(|| self.ca.server_config(host))
            .transpose()
            .map_err(|error| error.to_string())?;
        // This is deliberately local setup only. DNS and TCP happen in
        // `forward`, after the terminating proxy has decrypted and authorized
        // the exact HTTP method/path. Otherwise an unapproved CONNECT can still
        // be used as a DNS/port-probing oracle.
        Ok(Box::new(SystemEgressSession {
            destination: EgressDestination {
                server_name: host.to_owned(),
                port,
            },
            front_tls,
            upstream_tls: Arc::clone(&self.upstream_tls),
            vault: Arc::clone(&self.vault),
            reuse_connections: self.reuse_connections && host == "api.anthropic.com",
        }))
    }

    fn ca_certificate_pem(&self) -> Option<String> {
        Some(self.ca.certificate_pem())
    }
}

struct SystemEgressSession {
    destination: EgressDestination,
    front_tls: Option<Arc<ServerConfig>>,
    upstream_tls: Arc<ClientConfig>,
    vault: Arc<CredentialVault>,
    reuse_connections: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EgressDestination {
    server_name: String,
    port: u16,
}

impl EgressSession for SystemEgressSession {
    fn forward(
        self: Box<Self>,
        guest: UnixStream,
        authorizer: &mut dyn EgressRequestAuthorizer,
    ) -> Result<(), String> {
        if let Some(front_tls) = self.front_tls {
            if self.reuse_connections {
                guest
                    .set_read_timeout(Some(REUSE_IDLE_TIMEOUT))
                    .map_err(|error| error.to_string())?;
            }
            proxy_tls_http(
                guest,
                front_tls,
                self.upstream_tls,
                &self.destination,
                &self.vault,
                authorizer,
                self.reuse_connections,
                || connect_system_target(&self.destination),
            )
            .map_err(|error| error.to_string())
        } else {
            proxy_plain_http_once(guest, &self.destination, &self.vault, authorizer, || {
                connect_system_target(&self.destination)
            })
            .map_err(|error| error.to_string())
        }
    }
}

fn connect_system_target(
    destination: &EgressDestination,
) -> Result<(TcpStream, ConnectionTarget), TlsError> {
    let addresses = (destination.server_name.as_str(), destination.port)
        .to_socket_addrs()
        .map_err(|error| TlsError::new("egress DNS resolution", error))?
        .take(MAX_RESOLVED_ADDRESSES + 1)
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(TlsError(
            "egress DNS resolution returned no addresses".to_owned(),
        ));
    }
    if addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(TlsError(
            "egress DNS resolution returned too many addresses".to_owned(),
        ));
    }
    if addresses
        .iter()
        .any(|address| is_forbidden_ip(address.ip()))
    {
        return Err(TlsError(
            "egress DNS resolution included a forbidden address".to_owned(),
        ));
    }

    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                return Ok((
                    stream,
                    ConnectionTarget {
                        server_name: destination.server_name.clone(),
                        resolved_ip: address.ip(),
                        port: destination.port,
                    },
                ));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(TlsError(format!(
        "egress connection failed: {}",
        last_error.map_or_else(
            || "no address was attempted".to_owned(),
            |error| error.to_string(),
        )
    )))
}

fn proxy_plain_http_once<S, C>(
    mut guest: S,
    destination: &EgressDestination,
    vault: &CredentialVault,
    authorizer: &mut dyn EgressRequestAuthorizer,
    connect: C,
) -> Result<(), TlsError>
where
    S: std::io::Read + std::io::Write,
    C: FnOnce() -> Result<(TcpStream, ConnectionTarget), TlsError>,
{
    let request = read_http_request(&mut guest)?;
    let request_plan = authorize_http_request(destination, &request, authorizer)?;
    commit_external_send(authorizer, request_plan.model)?;
    let (mut upstream, target) = connect()
        .map_err(|error| release_authorized_unsent(authorizer, request_plan.model, error))?;
    upstream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| {
            release_authorized_unsent(
                authorizer,
                request_plan.model,
                TlsError::new("upstream read timeout", error),
            )
        })?;
    upstream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| {
            release_authorized_unsent(
                authorizer,
                request_plan.model,
                TlsError::new("upstream write timeout", error),
            )
        })?;
    let prepared = finish_authorized_request(
        &target,
        vault,
        &request,
        request_plan,
        authorizer,
        false,
        false,
    )?;
    begin_model_send(authorizer, prepared.model)?;
    if let Err(error) = upstream.write_all(&prepared.bytes) {
        return Err(commit_after_possible_send(
            authorizer,
            prepared.model,
            TlsError::new("upstream request", error),
        ));
    }
    if let Err(error) = upstream.flush() {
        return Err(commit_after_possible_send(
            authorizer,
            prepared.model,
            TlsError::new("upstream request flush", error),
        ));
    }
    let response = match relay_http_response_with_observation(
        &mut upstream,
        &mut guest,
        "guest HTTP response",
        || {
            authorizer
                .record_response()
                .map_err(|error| TlsError::new("kernel response provenance", error))
        },
    ) {
        Ok(response) => response,
        Err(failure) => {
            return Err(commit_after_interrupted_response(
                authorizer,
                prepared.model,
                failure,
            ));
        }
    };
    if prepared.model {
        settle_complete_model_response(authorizer, &response.bytes)?;
    }
    if let Some(error) = response.guest_error {
        return Err(error);
    }
    guest
        .flush()
        .map_err(|error| TlsError::new("guest HTTP response flush", error))
}

fn commit_external_send(
    authorizer: &mut dyn EgressRequestAuthorizer,
    model: bool,
) -> Result<(), TlsError> {
    authorizer.commit_request_send().map_err(|error| {
        release_authorized_unsent(
            authorizer,
            model,
            TlsError::new("kernel external-send handoff", error),
        )
    })
}

fn begin_model_send(
    authorizer: &mut dyn EgressRequestAuthorizer,
    model: bool,
) -> Result<(), TlsError> {
    if !model {
        return Ok(());
    }
    if let Err(error) = authorizer.mark_model_request_send_attempted() {
        return Err(release_definitely_unsent(
            authorizer,
            TlsError::new("kernel model send transition", error),
        ));
    }
    Ok(())
}

fn release_definitely_unsent(
    authorizer: &mut dyn EgressRequestAuthorizer,
    error: TlsError,
) -> TlsError {
    match authorizer.release_model_reservation() {
        Ok(()) => error,
        Err(release_error) => TlsError(format!(
            "{error}; model reservation release also failed: {release_error}"
        )),
    }
}

fn commit_after_possible_send(
    authorizer: &mut dyn EgressRequestAuthorizer,
    model: bool,
    error: TlsError,
) -> TlsError {
    if !model {
        return error;
    }
    match commit_model_conservatively(authorizer) {
        Ok(()) => error,
        Err(commit_error) => TlsError(format!("{error}; {commit_error}")),
    }
}

/// Settles a model response that failed part way. When the provider's
/// opening usage event arrived, the charge is a trusted upper bound on what
/// the request could have cost; otherwise the full reservation is kept.
fn commit_after_interrupted_response(
    authorizer: &mut dyn EgressRequestAuthorizer,
    model: bool,
    failure: RelayFailure,
) -> TlsError {
    let RelayFailure { error, partial } = failure;
    if !model {
        return error;
    }
    match interrupted_usage_bound(&partial) {
        Some(usage) => match authorizer.commit_model_reservation_observed(usage) {
            Ok(()) => error,
            Err(commit_error) => TlsError(format!(
                "{error}; observed model reservation commit also failed: {commit_error}"
            )),
        },
        None => commit_after_possible_send(authorizer, true, error),
    }
}

fn commit_model_conservatively(
    authorizer: &mut dyn EgressRequestAuthorizer,
) -> Result<(), TlsError> {
    authorizer
        .commit_model_reservation_conservatively()
        .map_err(|error| TlsError::new("conservative model reservation commit also failed", error))
}

fn settle_complete_model_response(
    authorizer: &mut dyn EgressRequestAuthorizer,
    response: &[u8],
) -> Result<(), TlsError> {
    let status = response_status(response)
        .map_err(|error| commit_after_possible_send(authorizer, true, error))?;
    if !(200..300).contains(&status) {
        // Provider error bodies are not a billing contract. Even if one happens
        // to contain a field named `usage`, retain the admitted reservation:
        // only a successful response with the complete trusted usage shape can
        // prove the lower actual charge.
        return commit_model_conservatively(authorizer);
    }
    match parse_model_usage(response) {
        Ok(usage) => {
            authorizer.record_model_usage(usage).map_err(|error| {
                commit_after_possible_send(
                    authorizer,
                    true,
                    TlsError::new("kernel model usage", error),
                )
            })?;
            let blocks = model_response_blocks(response);
            let arguments = tool_arguments(&blocks);
            if !arguments.is_empty() {
                authorizer.observe_model_output(&arguments);
            }
            authorizer.observe_model_context(
                true,
                blocks
                    .iter()
                    .map(|block| context_block("response", None, block))
                    .collect(),
            );
            Ok(())
        }
        Err(usage_error) => match commit_model_conservatively(authorizer) {
            Ok(()) => Err(usage_error),
            Err(commit_error) => Err(TlsError(format!("{usage_error}; {commit_error}"))),
        },
    }
}

/// Credential bytes that zero their allocation on drop and cannot be
/// serialized or formatted through `Debug`.
///
/// ```compile_fail
/// let secret = keel_secrets::SecretBytes::new(b"secret".to_vec());
/// let _ = serde_json::to_string(&secret);
/// ```
///
/// ```compile_fail
/// let secret = keel_secrets::SecretBytes::new(b"secret".to_vec());
/// let _ = format!("{secret:?}");
/// ```
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Takes custody of secret bytes.
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Exposes a secret only for the duration of a trusted operation.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(&self.0)
    }

    const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Destination authenticated independently from the guest's HTTP headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionTarget {
    /// TLS server name parsed before termination.
    pub server_name: String,
    /// Kernel-resolved address used for this connection.
    pub resolved_ip: IpAddr,
    /// Destination port.
    pub port: u16,
}

/// Host, method, and path constraints for one credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialScope {
    /// Exact normalized TLS server name.
    pub server_name: String,
    /// Allowed uppercase HTTP methods.
    pub methods: BTreeSet<String>,
    /// Required request-path prefix.
    pub path_prefix: String,
}

/// Sentinel and real credential held only by the trusted proxy.
pub struct CredentialBinding {
    scope: CredentialScope,
    sentinel: SecretBytes,
    credential: SecretBytes,
}

impl CredentialBinding {
    /// Creates a scoped sentinel replacement.
    /// # Errors
    /// Returns an error when the sentinel is empty.
    pub fn new(
        scope: CredentialScope,
        sentinel: SecretBytes,
        credential: SecretBytes,
    ) -> Result<Self, TlsError> {
        if sentinel.is_empty() {
            return Err(TlsError("credential sentinel cannot be empty".to_owned()));
        }
        Ok(Self {
            scope,
            sentinel,
            credential,
        })
    }
}

/// Trusted credential store used by the terminating proxy.
#[derive(Default)]
pub struct CredentialVault {
    bindings: Vec<CredentialBinding>,
    signer: Option<SigV4Signer>,
}

impl CredentialVault {
    /// Creates an empty vault.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bindings: Vec::new(),
            signer: None,
        }
    }

    /// Adds one credential binding.
    pub fn insert(&mut self, binding: CredentialBinding) {
        self.bindings.push(binding);
    }

    /// Replaces sentinels only when the authenticated connection target,
    /// method, and path satisfy the credential's scope.
    ///
    /// Guest-controlled `Host` headers are not consulted.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed requests or any sentinel presented
    /// outside its scope.
    pub fn inject(&self, target: &ConnectionTarget, request: &[u8]) -> Result<Vec<u8>, TlsError> {
        if is_forbidden_ip(target.resolved_ip) {
            return Err(TlsError(
                "credential target resolves to a structurally forbidden address".to_owned(),
            ));
        }
        let (method, path) = request_line(request)?;
        // A signed provider authenticates by computing a header, not by holding
        // one. The sentinel the guest presented is dropped with the header it
        // arrived in, which is why the residual check below still passes.
        let mut output = match &self.signer {
            Some(signer) if signer.matches(target) => signer.sign(target, request)?,
            _ => request.to_vec(),
        };
        for binding in &self.bindings {
            let contains = binding
                .sentinel
                .expose(|sentinel| find_subslice(&output, sentinel).is_some());
            if !contains {
                continue;
            }
            let endpoint_shape_allowed = binding.sentinel.expose(|sentinel| {
                if sentinel == SystemEgressConnector::GITHUB_SENTINEL.as_bytes() {
                    github_api_path(method, path, &binding.scope.path_prefix)
                } else if sentinel == SystemEgressConnector::GIT_SENTINEL.as_bytes() {
                    git_smart_http_path(method, path, &binding.scope.path_prefix)
                } else {
                    true
                }
            });
            let allowed = target.server_name == binding.scope.server_name
                && target.port == 443
                && binding.scope.methods.contains(method)
                && path_matches(path, &binding.scope.path_prefix)
                && endpoint_shape_allowed;
            if !allowed {
                // Multiple separately admitted capabilities may intentionally
                // use the same public sentinel while retaining disjoint exact
                // bindings. Try every binding; the residual-sentinel check
                // below fails closed when none of them matches.
                continue;
            }
            output = binding.sentinel.expose(|sentinel| {
                binding
                    .credential
                    .expose(|credential| replace_credential_header(&output, sentinel, credential))
            })?;
        }
        self.refuse_sentinels(output)
    }

    /// Passes a request through only if it carries no credential sentinel.
    /// Plaintext transports use this instead of [`Self::inject`], so no
    /// credential is ever written to an unencrypted upstream connection.
    ///
    /// # Errors
    ///
    /// Returns an error if any bound or built-in sentinel remains.
    pub fn refuse_sentinels(&self, output: Vec<u8>) -> Result<Vec<u8>, TlsError> {
        let bound_sentinel_remains = self.bindings.iter().any(|binding| {
            binding
                .sentinel
                .expose(|sentinel| find_subslice(&output, sentinel).is_some())
        });
        if bound_sentinel_remains
            || [
                SystemEgressConnector::GIT_SENTINEL,
                SystemEgressConnector::MODEL_SENTINEL,
                SystemEgressConnector::GITHUB_SENTINEL,
                SystemEgressConnector::BEDROCK_SENTINEL,
                SystemEgressConnector::OPENROUTER_SENTINEL,
            ]
            .iter()
            .any(|sentinel| find_subslice(&output, sentinel.as_bytes()).is_some())
        {
            return Err(TlsError(
                "credential sentinel has no binding for this request".to_owned(),
            ));
        }
        Ok(output)
    }
}

fn github_api_path(method: &str, path: &str, scope_prefix: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let fields = path.trim_matches('/').split('/').collect::<Vec<_>>();
    match (method, fields.as_slice()) {
        ("POST", ["repos", owner, repository, "pulls"]) => {
            !owner.is_empty() && !repository.is_empty()
        }
        ("GET", ["repos", owner, repository, "issues", number]) => {
            scope_prefix != "/repos"
                && !owner.is_empty()
                && !repository.is_empty()
                && number.parse::<u64>().is_ok_and(|number| number > 0)
        }
        _ => false,
    }
}

fn github_repository_from_git_scope(host: &str, path: &str) -> Option<String> {
    if host != "github.com" {
        return None;
    }
    let repository = path
        .strip_prefix('/')?
        .strip_suffix(".git")?
        .trim_end_matches('/');
    let mut fields = repository.split('/');
    let owner = fields.next()?;
    let name = fields.next()?;
    let valid = |field: &str| {
        !field.is_empty()
            && field != "."
            && field != ".."
            && field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    };
    (valid(owner) && valid(name) && fields.next().is_none()).then(|| format!("{owner}/{name}"))
}

fn git_smart_http_path(method: &str, path: &str, repository: &str) -> bool {
    let (path, query) = path
        .split_once('?')
        .map_or((path, None), |(path, query)| (path, Some(query)));
    (method == "POST" && query.is_none() && path == format!("{repository}/git-receive-pack"))
        || (method == "GET"
            && path == format!("{repository}/info/refs")
            && query == Some("service=git-receive-pack"))
}

/// Replaces one credential sentinel only when it is the complete credential
/// carried by an authentication header. Sentinels are public bearer values, so
/// allowing them in a request body would turn substitution into a credential
/// disclosure primitive.
fn replace_credential_header(
    request: &[u8],
    sentinel: &[u8],
    credential: &[u8],
) -> Result<Vec<u8>, TlsError> {
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| TlsError("HTTP request headers are incomplete".to_owned()))?;
    if find_subslice(&request[header_end + 4..], sentinel).is_some() {
        return Err(TlsError(
            "credential sentinel is forbidden in the HTTP request body".to_owned(),
        ));
    }
    let headers = std::str::from_utf8(&request[..header_end])
        .map_err(|error| TlsError::new("HTTP request headers", error))?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| TlsError("HTTP request line is missing".to_owned()))?;
    if find_subslice(request_line.as_bytes(), sentinel).is_some() {
        return Err(TlsError(
            "credential sentinel is forbidden in the HTTP request line".to_owned(),
        ));
    }

    let sentinel_text = std::str::from_utf8(sentinel)
        .map_err(|error| TlsError::new("credential sentinel", error))?;
    let credential_text =
        std::str::from_utf8(credential).map_err(|error| TlsError::new("credential", error))?;
    let mut matched = false;
    let mut output = Vec::with_capacity(request.len() + credential.len());
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\r\n");
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| TlsError("HTTP header is malformed".to_owned()))?;
        let allowed_header =
            name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-api-key");
        let trimmed = value.trim();
        let replacement = if trimmed == sentinel_text {
            Some(credential_text.to_owned())
        } else if let Some(token) = trimmed.strip_prefix("Bearer ") {
            (token == sentinel_text).then(|| format!("Bearer {credential_text}"))
        } else {
            None
        };
        let contains = find_subslice(value.as_bytes(), sentinel).is_some();
        if contains && (!allowed_header || replacement.is_none() || matched) {
            return Err(TlsError(
                "credential sentinel must appear exactly once in an authorization header"
                    .to_owned(),
            ));
        }
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        if let Some(replacement) = replacement {
            matched = true;
            output.extend_from_slice(replacement.as_bytes());
        } else {
            output.extend_from_slice(trimmed.as_bytes());
        }
        output.extend_from_slice(b"\r\n");
    }
    if !matched {
        return Err(TlsError(
            "credential sentinel is missing from an authorization header".to_owned(),
        ));
    }
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&request[header_end + 4..]);
    Ok(output)
}

fn request_line(request: &[u8]) -> Result<(&str, &str), TlsError> {
    let end = request
        .windows(2)
        .position(|bytes| bytes == b"\r\n")
        .ok_or_else(|| TlsError("HTTP request line is incomplete".to_owned()))?;
    let line = std::str::from_utf8(&request[..end])
        .map_err(|error| TlsError::new("HTTP request line", error))?;
    let mut fields = line.split_ascii_whitespace();
    let method = fields
        .next()
        .ok_or_else(|| TlsError("HTTP method is missing".to_owned()))?;
    let path = fields
        .next()
        .ok_or_else(|| TlsError("HTTP path is missing".to_owned()))?;
    let version = fields
        .next()
        .ok_or_else(|| TlsError("HTTP version is missing".to_owned()))?;
    if fields.next().is_some() || !version.starts_with("HTTP/") {
        return Err(TlsError("HTTP request line is malformed".to_owned()));
    }
    Ok((method, path))
}

fn sha256_bytes(value: &[u8]) -> [u8; 32] {
    let hash = digest(&SHA256, value);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(hash.as_ref());
    bytes
}

fn path_matches(request_path: &str, scope: &str) -> bool {
    let request_path = request_path.split('?').next().unwrap_or(request_path);
    request_path == scope
        || (request_path.starts_with(scope)
            && (scope.ends_with('/')
                || request_path
                    .as_bytes()
                    .get(scope.len())
                    .is_some_and(|byte| *byte == b'/')))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Result of stripping server-side tools from a model request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SanitizedModelRequest {
    /// Sanitized JSON body.
    pub body: Vec<u8>,
    /// Removed root keys or tool types.
    pub stripped: Vec<String>,
}

/// One admitted model endpoint. The set is closed: a host that is not named here
/// is not a model endpoint, and a path shape this table does not describe is
/// refused before any application byte reaches upstream.
enum ModelEndpoint {
    /// `POST /v1/messages`, with the model identifier in the body.
    AnthropicMessages,
    /// `POST /model/{id}/invoke[-with-response-stream]` in one region, with the
    /// model identifier in the path.
    BedrockInvoke { region: String },
    /// `OpenRouter`'s Anthropic-compatible `POST /api/v1/messages`, priced from
    /// the operator-admitted snapshot.
    OpenRouterMessages,
}

/// The `OpenRouter` endpoint host.
pub const OPENROUTER_HOST: &str = "openrouter.ai";

const BEDROCK_ANTHROPIC_VERSION: &str = "bedrock-2023-05-31";

/// The model provider one run uses, chosen host-side before the guest starts.
pub struct ModelProvider {
    /// The single model host this run's egress intent admits.
    pub host: String,
    /// Non-secret string the guest presents in place of the credential.
    pub sentinel: &'static str,
    /// Region the endpoint is pinned to, when the provider has one.
    pub region: Option<String>,
}

impl ModelProvider {
    /// `anthropic`, `bedrock`, or `openrouter`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.host.as_str() {
            OPENROUTER_HOST => "openrouter",
            _ if self.region.is_some() => "bedrock",
            _ => "anthropic",
        }
    }
}

/// Selects this run's model provider from the trusted process environment.
///
/// `AWS_BEARER_TOKEN_BEDROCK` selects the regional provider and requires
/// `AWS_REGION`; without it the provider is the first-party API.
///
/// # Errors
///
/// Returns an error when the regional provider is selected without a
/// well-formed region.
pub fn runtime_model_provider() -> Result<ModelProvider, String> {
    if std::env::var("KEEL_MODEL_AUTH").as_deref() == Ok("openrouter") {
        return Ok(ModelProvider {
            host: OPENROUTER_HOST.to_owned(),
            sentinel: SystemEgressConnector::OPENROUTER_SENTINEL,
            region: None,
        });
    }
    let bedrock = bedrock_selected(
        std::env::var("KEEL_MODEL_AUTH").ok().as_deref(),
        std::env::var_os("AWS_BEARER_TOKEN_BEDROCK").is_some(),
        std::env::var("KEEL_MODEL_PROVIDER").ok().as_deref(),
    )?;
    runtime_model_provider_from(bedrock, std::env::var("AWS_REGION").ok())
}

/// Verifies that one configured model has a pinned budget tariff for the
/// selected provider before the guest starts.
///
/// # Errors
///
/// Returns an actionable error when the model family, inference-profile form,
/// or Bedrock region has no pinned tariff.
pub fn validate_model_tariff(provider: &ModelProvider, model: &str) -> Result<(), String> {
    model_tariff(provider, model).map(|_| ()).ok_or_else(|| {
        format!(
            "model `{model}` has no pinned budget tariff for `{}`; choose a supported Anthropic model or update Keel's reviewed tariff table",
            provider.host
        )
    })
}

/// The `(input, output)` micro-USD per-token price this run charges `model`
/// at, and whether it comes from Keel's reviewed table or an admitted
/// `OpenRouter` snapshot.
#[must_use]
pub fn model_tariff(provider: &ModelProvider, model: &str) -> Option<(u64, u64, &'static str)> {
    if provider.host == OPENROUTER_HOST {
        return openrouter_tariff(model)
            .map(|(input, output)| (input, output, "admitted-snapshot"));
    }
    provider
        .region
        .as_deref()
        .map_or_else(
            || anthropic_tariff(model),
            |region| bedrock_tariff(region, model),
        )
        .map(|(input, output)| (input, output, "reviewed-table"))
}

/// Whether this run's configuration selects the regional provider.
///
/// A named choice outranks inference: an operator holding both credentials has
/// said nothing by holding them, and reading the answer off whichever variable
/// happens to be set spends the wrong budget against the wrong account.
///
/// # Errors
///
/// Returns an error when the named choice is not one of the two providers.
pub fn bedrock_selected(
    auth: Option<&str>,
    bearer_token: bool,
    provider: Option<&str>,
) -> Result<bool, String> {
    match auth {
        Some("bedrock") => Ok(true),
        Some("api-key") => Ok(false),
        Some(other) => Err(format!(
            "KEEL_MODEL_AUTH `{other}` is not `api-key`, `bedrock`, or `openrouter`"
        )),
        // The bearer token selects the regional provider on its own because that
        // variable exists for nothing else. SigV4 credentials do not: an operator
        // may hold them for unrelated reasons, and silently routing this run's
        // model traffic somewhere else on that basis would be a provider switch
        // nobody asked for. So the signed path is opted into by name.
        None => Ok(bearer_token || provider == Some("bedrock")),
    }
}

fn runtime_model_provider_from(
    bedrock: bool,
    region: Option<String>,
) -> Result<ModelProvider, String> {
    if !bedrock {
        return Ok(ModelProvider {
            host: "api.anthropic.com".to_owned(),
            sentinel: SystemEgressConnector::MODEL_SENTINEL,
            region: None,
        });
    }
    // A region is an endpoint. It is required here, in trusted configuration,
    // rather than defaulted, so that the host the guest's traffic is admitted to
    // is always something the operator named.
    let region = region.ok_or_else(|| {
        "the regional model provider requires AWS_REGION: a region selects an endpoint, \
         so it is configuration rather than a default"
            .to_owned()
    })?;
    let host = format!("bedrock-runtime.{region}.amazonaws.com");
    if !matches!(
        model_endpoint(&host),
        Some(ModelEndpoint::BedrockInvoke { .. })
    ) {
        return Err(format!("AWS_REGION `{region}` is not a well-formed region"));
    }
    Ok(ModelProvider {
        host,
        sentinel: SystemEgressConnector::BEDROCK_SENTINEL,
        region: Some(region),
    })
}

fn model_endpoint(server_name: &str) -> Option<ModelEndpoint> {
    if server_name == "api.anthropic.com" {
        return Some(ModelEndpoint::AnthropicMessages);
    }
    if server_name == OPENROUTER_HOST {
        return Some(ModelEndpoint::OpenRouterMessages);
    }
    // `{region}` is a wildcard inside a hostname, and this function is the wrong
    // place to resolve it. The name checked here was authenticated by the TLS
    // session and reached this proxy only because the run's trusted egress
    // allowlist already named it, so the region is configuration that arrived
    // from the host side; a guest cannot introduce one by asking.
    let region = server_name
        .strip_prefix("bedrock-runtime.")?
        .strip_suffix(".amazonaws.com")?;
    well_formed_region(region).then(|| ModelEndpoint::BedrockInvoke {
        region: region.to_owned(),
    })
}

fn bedrock_control_endpoint(server_name: &str) -> bool {
    server_name
        .strip_prefix("bedrock.")
        .and_then(|region| region.strip_suffix(".amazonaws.com"))
        .is_some_and(well_formed_region)
}

fn well_formed_region(region: &str) -> bool {
    region.len() >= 5
        && region.contains('-')
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn bedrock_model_id(path: &str) -> Option<String> {
    let (model, action) = path
        .split('?')
        .next()?
        .strip_prefix("/model/")?
        .rsplit_once('/')?;
    if !matches!(action, "invoke" | "invoke-with-response-stream") {
        return None;
    }
    // One identifier, one spelling. A model id carries a colon, which a harness
    // may send literally or escaped, and a tariff key with two spellings is a
    // tariff key that can be missed. Every other escape stays refused.
    let model = decode_escaped_colons(model)?;
    (!model.is_empty()).then_some(model)
}

/// Decodes `%3A` and rejects every other percent escape.
fn decode_escaped_colons(value: &str) -> Option<String> {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find('%') {
        if !matches!(rest.get(index..index + 3), Some("%3A" | "%3a")) {
            return None;
        }
        output.push_str(rest.get(..index)?);
        output.push(':');
        rest = rest.get(index + 3..)?;
    }
    output.push_str(rest);
    Some(output)
}

// ---------------------------------------------------------------------------
// SigV4 request signing (D17)
// ---------------------------------------------------------------------------

const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SIGV4_SERVICE: &str = "bedrock";
const SIGV4_CONTENT_TYPE: &str = "application/json";
/// Credentials are replaced this far ahead of their expiry. A request signed a
/// second before the boundary is still in flight when it lapses.
const CREDENTIAL_REFRESH_MARGIN: u64 = 120;

/// AWS credentials held only in this process, for the lifetime of one run.
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: SecretBytes,
    session_token: Option<SecretBytes>,
    /// Unix seconds after which these are refused. `None` for a long-lived key,
    /// which does not rotate on its own.
    expires_at: Option<u64>,
}

impl AwsCredentials {
    fn stale(&self, now: u64) -> bool {
        self.expires_at
            .is_some_and(|at| at <= now.saturating_add(CREDENTIAL_REFRESH_MARGIN))
    }
}

/// Where this run's `SigV4` credentials come from, and where a replacement comes
/// from when they lapse.
enum AwsCredentialSource {
    /// Static values from the trusted process environment. Nothing to refresh
    /// from, so an expiry ends the run.
    Environment,
    /// An operator-named command printing the AWS `credential_process` JSON.
    ///
    /// This is how Identity Center support is bought without putting an SSO
    /// implementation in the TCB: the command owns the login cache, the portal
    /// call, and the rotation, and Keel only re-runs it. Keel therefore holds no
    /// SSO state and cannot be wrong about the cache format.
    Process(String),
}

/// Signs model requests for a regional endpoint that authenticates with `SigV4`.
///
/// The guest still presents a sentinel, and the sentinel is *discarded* rather
/// than swapped: what travels upstream is a signature over the sanitized body,
/// so the guest holds nothing that works anywhere, even through this proxy.
struct SigV4Signer {
    host: String,
    region: String,
    source: AwsCredentialSource,
    credentials: Mutex<AwsCredentials>,
}

impl SigV4Signer {
    /// Resolves credentials for a signed regional provider.
    fn from_runtime_environment(host: String, region: String) -> Result<Self, String> {
        let source = match std::env::var("KEEL_AWS_CREDENTIAL_PROCESS") {
            Ok(command) if !command.trim().is_empty() => AwsCredentialSource::Process(command),
            _ => AwsCredentialSource::Environment,
        };
        let credentials = resolve_aws_credentials(&source)?;
        Ok(Self {
            host,
            region,
            source,
            credentials: Mutex::new(credentials),
        })
    }

    /// Whether this signer authenticates the authenticated connection target.
    fn matches(&self, target: &ConnectionTarget) -> bool {
        target.server_name == self.host
    }

    /// Replaces the request's authorization with a `SigV4` signature.
    ///
    /// The bytes passed here are the ones that go upstream, after sanitizing and
    /// after `Content-Length` is settled: a signature over anything else is a
    /// signature over a request that was never sent.
    fn sign(&self, target: &ConnectionTarget, request: &[u8]) -> Result<Vec<u8>, TlsError> {
        let header_end = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .ok_or_else(|| TlsError("HTTP headers are incomplete".to_owned()))?;
        let body = &request[header_end + 4..];
        let headers = std::str::from_utf8(&request[..header_end])
            .map_err(|error| TlsError::new("HTTP headers", error))?;
        let (method, path) = request_line(request)?;
        let canonical_uri = canonical_request_uri(path)?;
        let (amz_date, date_stamp) = sigv4_timestamps(unix_now()?);
        let payload_hash = encode_lower_hex(digest(&SHA256, body).as_ref());
        // The host is the name the TLS session authenticated, never the guest's
        // `Host` header; the rebuilt request carries the same value, so the
        // signature covers the destination this proxy actually opened.
        let authority = if target.port == 443 {
            target.server_name.clone()
        } else {
            format!("{}:{}", target.server_name, target.port)
        };
        let authorization = self.authorization(
            method,
            &canonical_uri,
            &authority,
            &amz_date,
            &date_stamp,
            &payload_hash,
        )?;
        let mut output = Vec::with_capacity(request.len() + authorization.value.len() + 256);
        let mut lines = headers.lines();
        let request_line = lines
            .next()
            .ok_or_else(|| TlsError("HTTP request line is missing".to_owned()))?;
        output.extend_from_slice(request_line.as_bytes());
        output.extend_from_slice(b"\r\n");
        for line in lines {
            let name = line.split_once(':').map_or(line, |(name, _)| name);
            // Every header the signature covers is written below from the value
            // that was signed. Passing a guest copy through as well would let the
            // request disagree with its own signature.
            if SIGNED_HEADER_NAMES
                .iter()
                .any(|signed| name.eq_ignore_ascii_case(signed))
                || name.eq_ignore_ascii_case("x-amz-content-sha256")
            {
                continue;
            }
            output.extend_from_slice(line.as_bytes());
            output.extend_from_slice(b"\r\n");
        }
        write!(
            output,
            "Content-Type: {SIGV4_CONTENT_TYPE}\r\nX-Amz-Date: {amz_date}\r\n"
        )
        .map_err(|error| TlsError::new("signed request headers", error))?;
        if let Some(token) = &authorization.session_token {
            write!(output, "X-Amz-Security-Token: {token}\r\n")
                .map_err(|error| TlsError::new("signed request headers", error))?;
        }
        write!(output, "Authorization: {}\r\n\r\n", authorization.value)
            .map_err(|error| TlsError::new("signed request headers", error))?;
        output.extend_from_slice(body);
        Ok(output)
    }

    /// Builds the `Authorization` value, refreshing credentials that are close
    /// enough to expiry that this request could outlive them.
    fn authorization(
        &self,
        method: &str,
        canonical_uri: &str,
        authority: &str,
        amz_date: &str,
        date_stamp: &str,
        payload_hash: &str,
    ) -> Result<SignedAuthorization, TlsError> {
        let mut held = self
            .credentials
            .lock()
            .map_err(|_| TlsError("AWS credential custody is unavailable".to_owned()))?;
        let now = unix_now()?;
        if held.stale(now) {
            let AwsCredentialSource::Process(command) = &self.source else {
                return Err(TlsError(
                    "AWS session credentials have expired and no KEEL_AWS_CREDENTIAL_PROCESS is \
                     configured to renew them"
                        .to_owned(),
                ));
            };
            *held = resolve_credential_process(command).map_err(TlsError)?;
            if held.stale(now) {
                return Err(TlsError(
                    "KEEL_AWS_CREDENTIAL_PROCESS returned credentials that are already expiring; \
                     renew the session login"
                        .to_owned(),
                ));
            }
        }
        let scope = format!("{date_stamp}/{}/{SIGV4_SERVICE}/aws4_request", self.region);
        let session_token = held
            .session_token
            .as_ref()
            .map(|token| token.expose(|bytes| String::from_utf8_lossy(bytes).into_owned()));
        let mut signed_headers = "content-type;host;x-amz-date".to_owned();
        let mut canonical_headers =
            format!("content-type:{SIGV4_CONTENT_TYPE}\nhost:{authority}\nx-amz-date:{amz_date}\n");
        if let Some(token) = &session_token {
            signed_headers.push_str(";x-amz-security-token");
            canonical_headers.push_str("x-amz-security-token:");
            canonical_headers.push_str(token);
            canonical_headers.push('\n');
        }
        // The empty line is the canonical query string: no admitted operation
        // takes parameters, and `canonical_request_uri` refuses one outright.
        let canonical_request = format!(
            "{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        );
        let string_to_sign = format!(
            "{SIGV4_ALGORITHM}\n{amz_date}\n{scope}\n{}",
            encode_lower_hex(digest(&SHA256, canonical_request.as_bytes()).as_ref())
        );
        let signature = held.secret_access_key.expose(|secret| {
            sigv4_signature(
                secret,
                date_stamp,
                &self.region,
                SIGV4_SERVICE,
                string_to_sign.as_bytes(),
            )
        });
        Ok(SignedAuthorization {
            value: format!(
                "{SIGV4_ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, \
                 Signature={signature}",
                held.access_key_id
            ),
            session_token,
        })
    }
}

/// Header names whose values the signature covers.
const SIGNED_HEADER_NAMES: [&str; 4] = [
    "authorization",
    "content-type",
    "x-amz-date",
    "x-amz-security-token",
];

struct SignedAuthorization {
    value: String,
    session_token: Option<String>,
}

/// Derives the `SigV4` signing key and signs the string to sign.
///
/// The service is a parameter rather than the pinned constant so that this
/// derivation can be checked against AWS's published vectors, which are written
/// for other services. It is the only part of signing that a test can prove
/// without a live endpoint.
fn sigv4_signature(
    secret: &[u8],
    date_stamp: &str,
    region: &str,
    service: &str,
    message: &[u8],
) -> String {
    let mut seed = Vec::with_capacity(secret.len() + 4);
    seed.extend_from_slice(b"AWS4");
    seed.extend_from_slice(secret);
    let date_key = hmac_sha256(&seed, date_stamp.as_bytes());
    seed.zeroize();
    let region_key = hmac_sha256(date_key.as_ref(), region.as_bytes());
    let service_key = hmac_sha256(region_key.as_ref(), service.as_bytes());
    let signing_key = hmac_sha256(service_key.as_ref(), b"aws4_request");
    encode_lower_hex(hmac_sha256(signing_key.as_ref(), message).as_ref())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> hmac::Tag {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Canonicalizes the request path for signing.
///
/// **Unverified against a live endpoint.** Path encoding is the likeliest thing
/// in this file to be wrong on first contact, because it is the one input a
/// signature mismatch cannot distinguish from a bad key: each segment is encoded
/// once, with `/` left alone, which is `SigV4`'s rule for every service except S3.
fn canonical_request_uri(path: &str) -> Result<String, TlsError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    if !query.is_empty() {
        return Err(TlsError(
            "model request path carries a query string, which no admitted operation takes"
                .to_owned(),
        ));
    }
    let decoded = decode_escaped_colons(path).ok_or_else(|| {
        TlsError("model request path carries an unsupported percent escape".to_owned())
    })?;
    let mut output = String::with_capacity(decoded.len());
    for byte in decoded.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    Ok(output)
}

fn unix_now() -> Result<u64, TlsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| TlsError::new("system clock", error))
}

/// Splits a Unix timestamp into `SigV4`'s two date forms.
fn sigv4_timestamps(seconds: u64) -> (String, String) {
    let time = seconds % 86_400;
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let date = format!("{year:04}{month:02}{day:02}");
    (
        format!(
            "{date}T{:02}{:02}{:02}Z",
            time / 3600,
            (time % 3600) / 60,
            time % 60
        ),
        date,
    )
}

/// Hinnant's civil-from-days, over an era beginning on 0000-03-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    };
    let year = year_of_era + era * 400;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Hinnant's days-from-civil, the inverse used to read a credential expiry.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let month_position = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_position + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Reads the `Expiration` field's RFC 3339 instant, normalized to UTC.
///
/// An offset is subtracted rather than assumed away. This first accepted `Z` only,
/// which is what the format's examples show and not what the AWS CLI writes: it
/// emits `+00:00`, so every real `credential_process` expiry was unreadable and
/// every signed run refused. Reading an expiry an hour wrong is the failure worth
/// avoiding — it means signing with a lapsed credential or refreshing in a loop —
/// and that argues for doing the arithmetic, not for rejecting the input.
fn parse_utc_timestamp(value: &str) -> Option<u64> {
    let (value, offset) = if let Some(value) = value.strip_suffix('Z') {
        (value, 0)
    } else {
        // Only a sign after the time can be a zone; the date's own separators
        // sit at fixed positions ahead of the `T`.
        let sign = value.rfind(['+', '-']).filter(|sign| *sign > 10)?;
        let (rest, zone) = value.split_at(sign);
        let (hours, minutes) = zone.get(1..)?.split_once(':')?;
        let magnitude = i64::from(hours.parse::<u8>().ok()?) * 3600
            + i64::from(minutes.parse::<u8>().ok()?) * 60;
        if magnitude > 14 * 3600 {
            return None;
        }
        (
            rest,
            if zone.starts_with('-') {
                -magnitude
            } else {
                magnitude
            },
        )
    };
    let (date, time) = value.split_once('T')?;
    let mut date = date.split('-');
    let year = date.next()?.parse::<u64>().ok()?;
    let month = date.next()?.parse::<u64>().ok()?;
    let day = date.next()?.parse::<u64>().ok()?;
    if date.next().is_some() || !(1970..=9999).contains(&year) {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Fractional seconds carry no information this comparison needs.
    let mut time = time.split('.').next()?.split(':');
    let hour = time.next()?.parse::<u64>().ok()?;
    let minute = time.next()?.parse::<u64>().ok()?;
    let second = time.next()?.parse::<u64>().ok()?;
    if time.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let local = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    local.checked_add_signed(-offset)
}

fn resolve_aws_credentials(source: &AwsCredentialSource) -> Result<AwsCredentials, String> {
    match source {
        AwsCredentialSource::Environment => {
            let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    "a signed regional model provider needs AWS_ACCESS_KEY_ID and \
                     AWS_SECRET_ACCESS_KEY, or KEEL_AWS_CREDENTIAL_PROCESS"
                        .to_owned()
                })?;
            let secret = std::env::var("AWS_SECRET_ACCESS_KEY")
                .ok()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    "AWS_ACCESS_KEY_ID is set without AWS_SECRET_ACCESS_KEY".to_owned()
                })?;
            Ok(AwsCredentials {
                access_key_id,
                secret_access_key: SecretBytes::new(secret.into_bytes()),
                session_token: std::env::var("AWS_SESSION_TOKEN")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .map(|token| SecretBytes::new(token.into_bytes())),
                // Environment credentials carry no expiry, so Keel cannot tell a
                // long-lived key from a session that lapses in five minutes. The
                // lapse then surfaces as an upstream refusal naming the
                // credential, which is why the process source exists.
                expires_at: None,
            })
        }
        AwsCredentialSource::Process(command) => resolve_credential_process(command),
    }
}

/// Runs the operator-named credential command and reads its JSON.
fn resolve_credential_process(command: &str) -> Result<AwsCredentials, String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|error| format!("KEEL_AWS_CREDENTIAL_PROCESS could not be run: {error}"))?;
    if !output.status.success() {
        // The command's stderr is the operator's own tooling talking about the
        // operator's own session, and it is where "run aws sso login" appears.
        return Err(format!(
            "KEEL_AWS_CREDENTIAL_PROCESS exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse_credential_process_output(&output.stdout)
}

fn parse_credential_process_output(output: &[u8]) -> Result<AwsCredentials, String> {
    let value: Value = serde_json::from_slice(output)
        .map_err(|error| format!("credential process output is not JSON: {error}"))?;
    if value.get("Version").and_then(Value::as_u64) != Some(1) {
        return Err("credential process output is not Version 1".to_owned());
    }
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .filter(|field| !field.is_empty())
    };
    let access_key_id = field("AccessKeyId")
        .ok_or_else(|| "credential process output has no AccessKeyId".to_owned())?;
    let secret = field("SecretAccessKey")
        .ok_or_else(|| "credential process output has no SecretAccessKey".to_owned())?;
    let expires_at = match field("Expiration") {
        Some(expiration) => Some(parse_utc_timestamp(expiration).ok_or_else(|| {
            format!("credential process reported an unreadable Expiration `{expiration}`")
        })?),
        // No expiry means a long-lived key, which is what an Identity Center
        // session is not. Absent is accepted; unreadable is not.
        None => None,
    };
    Ok(AwsCredentials {
        access_key_id: access_key_id.to_owned(),
        secret_access_key: SecretBytes::new(secret.as_bytes()),
        session_token: field("SessionToken").map(|token| SecretBytes::new(token.as_bytes())),
        expires_at,
    })
}

/// Allows only an admitted model endpoint and strips server-side execution
/// capabilities before forwarding.
///
/// # Errors
///
/// Returns an error unless the authenticated target is an admitted model host
/// over TLS, for any path that endpoint does not describe, for a Bedrock request
/// that declares a different wire contract, and for malformed JSON or a
/// non-object request body.
pub fn sanitize_model_request(
    target: &ConnectionTarget,
    path: &str,
    body: &[u8],
) -> Result<SanitizedModelRequest, TlsError> {
    if is_forbidden_ip(target.resolved_ip) {
        return Err(TlsError(
            "model request is not bound to the approved API target".to_owned(),
        ));
    }
    sanitize_model_request_for_destination(&target.server_name, target.port, path, body)
}

fn sanitize_model_request_for_destination(
    server_name: &str,
    port: u16,
    path: &str,
    body: &[u8],
) -> Result<SanitizedModelRequest, TlsError> {
    let endpoint = model_endpoint(server_name)
        .filter(|_| port == 443)
        .ok_or_else(|| {
            TlsError("model request is not bound to the approved API target".to_owned())
        })?;
    let admitted = match &endpoint {
        ModelEndpoint::AnthropicMessages => path.split('?').next() == Some("/v1/messages"),
        ModelEndpoint::BedrockInvoke { .. } => bedrock_model_id(path).is_some(),
        ModelEndpoint::OpenRouterMessages => path.split('?').next() == Some("/api/v1/messages"),
    };
    if !admitted {
        return Err(TlsError(format!("model endpoint `{path}` is not allowed")));
    }
    let mut value: Value =
        serde_json::from_slice(body).map_err(|error| TlsError::new("model request JSON", error))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| TlsError("model request must be a JSON object".to_owned()))?;
    if matches!(endpoint, ModelEndpoint::BedrockInvoke { .. }) {
        // The wire contract surfaces here rather than as an upstream 400, because
        // both the strip list below and the tariff are written against one payload
        // shape. A body announcing a different one is not a request this code has
        // read the rules for.
        let version = object.get("anthropic_version").and_then(Value::as_str);
        if version != Some(BEDROCK_ANTHROPIC_VERSION) {
            return Err(TlsError(format!(
                "model request declares anthropic_version `{}`, not `{BEDROCK_ANTHROPIC_VERSION}`",
                version.unwrap_or("absent")
            )));
        }
    }
    let mut stripped = Vec::new();
    // OpenRouter's routing fields could fall back to another model or provider,
    // or add paid plugins, outside the admitted price snapshot.
    for key in [
        "mcp_servers",
        "container",
        "models",
        "route",
        "provider",
        "plugins",
        "web_search_options",
    ] {
        if object.remove(key).is_some() {
            stripped.push(key.to_owned());
        }
    }
    if let Some(tools) = object.get_mut("tools").and_then(Value::as_array_mut) {
        tools.retain(|tool| {
            let tool_type = tool.get("type").and_then(Value::as_str).unwrap_or("");
            let remove = ["web_search", "web_fetch", "computer", "bash", "text_editor"]
                .iter()
                .any(|prefix| tool_type.starts_with(prefix));
            if remove {
                stripped.push(format!("tools:{tool_type}"));
            }
            !remove
        });
    }
    stripped.sort();
    let body = serde_json::to_vec(&value)
        .map_err(|error| TlsError::new("serialize model request", error))?;
    Ok(SanitizedModelRequest { body, stripped })
}

fn model_budget_request(
    endpoint: &ModelEndpoint,
    path: &str,
    body: &[u8],
) -> Result<ModelBudgetRequest, TlsError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|error| TlsError::new("model budget JSON", error))?;
    let (model, tariff) = match endpoint {
        ModelEndpoint::AnthropicMessages => {
            let model = value.get("model").and_then(Value::as_str).ok_or_else(|| {
                TlsError("model request is missing a model identifier".to_owned())
            })?;
            (model.to_owned(), anthropic_tariff(model))
        }
        ModelEndpoint::BedrockInvoke { region } => {
            // Here the key comes from the path, which makes path parsing the
            // source of a price. That is the likeliest new route to an unpinned
            // key, and it fails closed for exactly the same reason an unpinned
            // model does: an unpriced request is an unbounded charge.
            let model = bedrock_model_id(path).ok_or_else(|| {
                TlsError(format!(
                    "model endpoint `{path}` carries no model identifier"
                ))
            })?;
            let tariff = bedrock_tariff(region, &model);
            (format!("{region}/{model}"), tariff)
        }
        ModelEndpoint::OpenRouterMessages => {
            let model = value.get("model").and_then(Value::as_str).ok_or_else(|| {
                TlsError("model request is missing a model identifier".to_owned())
            })?;
            (model.to_owned(), openrouter_tariff(model))
        }
    };
    let max_output_tokens = value
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|tokens| *tokens > 0)
        .ok_or_else(|| TlsError("model request has an invalid max_tokens".to_owned()))?;
    let (input_microusd_per_token, output_microusd_per_token) =
        tariff.ok_or_else(|| TlsError(format!("model `{model}` has no pinned budget tariff")))?;
    Ok(ModelBudgetRequest {
        input_tokens_upper_bound: u64::try_from(body.len())
            .map_err(|error| TlsError::new("model request size", error))?,
        max_output_tokens,
        input_microusd_per_token,
        output_microusd_per_token,
    })
}

/// The admitted `OpenRouter` price snapshot, `MODEL=INPUT,OUTPUT` in micro-USD
/// per token, from `KEEL_OPENROUTER_TARIFF`. The untrusted launcher fetches
/// it and trusted admission shows it to the operator before the run starts.
#[must_use]
pub fn openrouter_snapshot() -> Option<(String, u64, u64)> {
    static SNAPSHOT: std::sync::OnceLock<Option<(String, u64, u64)>> = std::sync::OnceLock::new();
    SNAPSHOT
        .get_or_init(|| {
            let value = std::env::var("KEEL_OPENROUTER_TARIFF").ok()?;
            let (model, prices) = value.split_once('=')?;
            let (input, output) = prices.split_once(',')?;
            // Auto-routing and web-search variants are priced per routed model
            // or per search, which no per-token snapshot can bound.
            let routed = model.starts_with("openrouter/") || model.contains(":online");
            (!model.is_empty() && !routed && model.chars().all(|c| c.is_ascii_graphic()))
                .then(|| Some((model.to_owned(), input.parse().ok()?, output.parse().ok()?)))
                .flatten()
        })
        .clone()
}

fn openrouter_tariff(model: &str) -> Option<(u64, u64)> {
    // Claude Code marks long-context use with a `[1m]` suffix, which OpenRouter
    // strips; the snapshot already prices the long-context tier.
    let model = model.strip_suffix("[1m]").unwrap_or(model);
    openrouter_snapshot()
        .filter(|(pinned, _, _)| pinned == model)
        .map(|(_, input, output)| (input, output))
}

fn anthropic_tariff(model: &str) -> Option<(u64, u64)> {
    if model.starts_with("claude-opus-") {
        Some((20, 75))
    } else if model.starts_with("claude-sonnet-") || model.starts_with("claude-3-7-sonnet-") {
        Some((5, 15))
    } else if model.starts_with("claude-haiku-") || model.starts_with("claude-3-5-haiku-") {
        Some((2, 5))
    } else {
        None
    }
}

fn bedrock_tariff(region: &str, model: &str) -> Option<(u64, u64)> {
    // Bedrock prices per region, so the region is half the key and an unpinned
    // region is an unpinned price. Only the US regions are pinned; anywhere else
    // fails closed rather than borrowing a number from a region it was not quoted
    // for.
    if !matches!(region, "us-east-1" | "us-east-2" | "us-west-2") {
        return None;
    }
    // The inference-profile prefix is examined rather than normalised away:
    // `global.anthropic.…`, `us.anthropic.…`, and `anthropic.…` are distinct
    // identifiers that AWS may price apart, and if it does, these arms are where
    // they diverge. Today all three resolve to the pinned conservative tariff.
    //
    // Unverified against live Bedrock pricing — see `docs/design/bedrock-sigv4.md`.
    let family = model
        .strip_prefix("global.anthropic.")
        .or_else(|| model.strip_prefix("us.anthropic."))
        .or_else(|| model.strip_prefix("anthropic."))?;
    anthropic_tariff(family)
}

fn parse_model_usage(response: &[u8]) -> Result<ModelUsage, TlsError> {
    let body = response_body(response)?;
    let mut usage = UsageFields::default();
    if is_event_stream(response) {
        for event in decode_event_stream(&body)? {
            usage.observe(&event)?;
        }
    } else if let Ok(value) = serde_json::from_slice::<Value>(&body) {
        usage.observe(&value)?;
    } else {
        for line in body.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let Some(data) = line.strip_prefix(b"data: ") else {
                continue;
            };
            if data == b"[DONE]" {
                continue;
            }
            let value: Value = serde_json::from_slice(data)
                .map_err(|error| TlsError::new("model usage event", error))?;
            usage.observe(&value)?;
        }
    }
    usage.finish(response_status(response)?)
}

/// Most tool-argument text recorded from one model response.
const MAX_TOOL_ARGUMENT_BYTES: usize = 4 << 20;

/// The content blocks of one complete model response. Streamed text,
/// thinking, and tool input arrive as deltas per block and are reassembled.
fn model_response_blocks(response: &[u8]) -> Vec<Value> {
    let Ok(body) = response_body(response) else {
        return Vec::new();
    };
    let events = if is_event_stream(response) {
        decode_event_stream(&body).unwrap_or_default()
    } else if let Ok(message) = serde_json::from_slice::<Value>(&body) {
        return message
            .get("content")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
    } else {
        complete_server_sent_events(&body).unwrap_or_default()
    };
    let mut blocks = std::collections::BTreeMap::<u64, (Value, String)>::new();
    let mut total = 0_usize;
    for event in &events {
        let index = event
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        match event.get("type").and_then(Value::as_str) {
            Some("content_block_start") => {
                if let Some(block) = event.get("content_block") {
                    blocks.insert(index, (block.clone(), String::new()));
                }
            }
            Some("content_block_delta") => {
                let (Some((block, input)), Some(delta)) =
                    (blocks.get_mut(&index), event.get("delta"))
                else {
                    continue;
                };
                let field = match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => "text",
                    Some("thinking_delta") => "thinking",
                    Some("input_json_delta") => "partial_json",
                    _ => continue,
                };
                let Some(fragment) = delta.get(field).and_then(Value::as_str) else {
                    continue;
                };
                if total + fragment.len() > MAX_TOOL_ARGUMENT_BYTES {
                    continue;
                }
                total += fragment.len();
                if field == "partial_json" {
                    input.push_str(fragment);
                } else if let Some(Value::String(text)) = block.get_mut(field) {
                    text.push_str(fragment);
                }
            }
            _ => {}
        }
    }
    blocks
        .into_values()
        .map(|(mut block, input)| {
            if let (Ok(input), Some(fields)) =
                (serde_json::from_str::<Value>(&input), block.as_object_mut())
            {
                fields.insert("input".to_owned(), input);
            }
            block
        })
        .collect()
}

/// Every string the model placed in a tool call of one complete response:
/// file contents, edits, and shell commands.
fn tool_arguments(blocks: &[Value]) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut total = 0_usize;
    let mut pending = blocks
        .iter()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
        .filter_map(|block| block.get("input").cloned())
        .collect::<Vec<_>>();
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) if total + text.len() <= MAX_TOOL_ARGUMENT_BYTES => {
                total += text.len();
                arguments.push(text);
            }
            Value::Array(items) => pending.extend(items),
            Value::Object(fields) => pending.extend(fields.into_iter().map(|(_, value)| value)),
            _ => {}
        }
    }
    arguments
}

/// Block types the context digest log names; anything else is `other`.
const CONTEXT_KINDS: &[&str] = &[
    "text",
    "thinking",
    "redacted_thinking",
    "tool_use",
    "tool_result",
    "server_tool_use",
    "image",
    "document",
];
const MAX_CONTEXT_BLOCKS: usize = 4096;

/// Every content block of a model request, in order: system, tools, then
/// messages. Shadow data for per-turn context provenance.
fn model_request_context(body: &[u8]) -> Vec<ContextBlock> {
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let text = |text: &Value| serde_json::json!({ "type": "text", "text": text });
    let mut blocks = Vec::new();
    match request.get("system") {
        Some(Value::Array(items)) => {
            blocks.extend(
                items
                    .iter()
                    .map(|block| context_block("system", None, block)),
            );
        }
        Some(system @ Value::String(_)) => {
            blocks.push(context_block("system", None, &text(system)));
        }
        _ => {}
    }
    for tool in request
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        blocks.push(context_block("tools", Some("tool"), tool));
    }
    let messages = request.get("messages").and_then(Value::as_array);
    for (index, message) in messages.into_iter().flatten().enumerate() {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .filter(|role| matches!(*role, "user" | "assistant"))
            .unwrap_or("other");
        let place = format!("messages.{index}.{role}");
        match message.get("content") {
            Some(Value::Array(items)) => {
                blocks.extend(items.iter().map(|block| context_block(&place, None, block)));
            }
            Some(content) => blocks.push(context_block(&place, None, &text(content))),
            None => {}
        }
    }
    blocks.truncate(MAX_CONTEXT_BLOCKS);
    blocks
}

/// Describes one block by its identity-bearing fields. Cache markers and
/// thinking signatures move or vary between requests, so they are excluded;
/// a block the model emitted then digests the same when carried back.
fn context_block(place: &str, kind: Option<&'static str>, block: &Value) -> ContextBlock {
    let name = block
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = kind
        .or_else(|| CONTEXT_KINDS.iter().find(|kind| **kind == name).copied())
        .unwrap_or("other");
    let field = |name: &str| block.get(name).cloned().unwrap_or(Value::Null);
    let mut identity = match kind {
        "text" => serde_json::json!([kind, field("text")]),
        "thinking" => serde_json::json!([kind, field("thinking")]),
        "redacted_thinking" => serde_json::json!([kind, field("data")]),
        "tool_use" | "server_tool_use" => {
            serde_json::json!([kind, field("id"), field("name"), field("input")])
        }
        "tool_result" => serde_json::json!([
            kind,
            field("tool_use_id"),
            field("content"),
            block
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        ]),
        _ => serde_json::json!([kind, block]),
    };
    strip_cache_control(&mut identity);
    // Objects keep insertion order in this build, so sort for a digest that
    // does not depend on how a harness re-serializes a tool input.
    identity.sort_all_objects();
    let canonical = identity.to_string();
    let mut digest = [0_u8; 8];
    digest.copy_from_slice(&sha256_bytes(canonical.as_bytes())[..8]);
    let tool_use = block
        .get(if kind == "tool_result" {
            "tool_use_id"
        } else {
            "id"
        })
        .and_then(Value::as_str)
        .filter(|id| {
            kind != "tool"
                && id.len() <= 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .map(str::to_owned);
    ContextBlock {
        place: place.to_owned(),
        kind,
        bytes: canonical.len(),
        digest,
        tool_use,
    }
}

fn strip_cache_control(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.remove("cache_control");
            fields.values_mut().for_each(strip_cache_control);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_cache_control),
        _ => {}
    }
}

/// Output tokens charged beyond what an interrupted stream delivered. The
/// provider may have generated tokens that never reached Keel before it saw
/// the connection end; this bounds that tail.
const INTERRUPTED_OUTPUT_MARGIN_TOKENS: u64 = 4_096;

/// Upper bound on the usage of a successful model stream that ended early.
///
/// `None` unless the provider's opening usage event arrived, because that is
/// the only exact statement of input. Output is bounded by the bytes of text,
/// thinking, and tool input already streamed (a token is at least one byte)
/// plus [`INTERRUPTED_OUTPUT_MARGIN_TOKENS`].
fn interrupted_usage_bound(partial: &[u8]) -> Option<ModelUsage> {
    if !(200..300).contains(&response_status(partial).ok()?) {
        return None;
    }
    let body = partial_body(partial)?;
    let events = if is_event_stream(partial) {
        complete_event_stream_events(&body)?
    } else {
        complete_server_sent_events(&body)?
    };
    let mut usage = UsageFields::default();
    let mut streamed = 0_u64;
    for event in &events {
        usage.observe(event).ok()?;
        let delta = event.get("delta");
        for field in ["text", "thinking", "partial_json"] {
            if let Some(text) = delta
                .and_then(|delta| delta.get(field))
                .and_then(Value::as_str)
            {
                streamed = streamed.saturating_add(u64::try_from(text.len()).ok()?);
            }
        }
    }
    let input_tokens = usage.input_total()?;
    let output_tokens = usage
        .output
        .unwrap_or_default()
        .max(usage.provider_output.unwrap_or_default())
        .max(streamed)
        .saturating_add(INTERRUPTED_OUTPUT_MARGIN_TOKENS);
    Some(ModelUsage {
        input_tokens,
        output_tokens,
    })
}

/// The body received so far, decoding only complete chunks.
fn partial_body(response: &[u8]) -> Option<Vec<u8>> {
    let header_end = response.windows(4).position(|bytes| bytes == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&response[..header_end]).ok()?;
    let mut input = &response[header_end + 4..];
    let chunked = headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        })
    });
    if !chunked {
        return Some(input.to_vec());
    }
    let mut output = Vec::new();
    while let Some(line_end) = input.windows(2).position(|bytes| bytes == b"\r\n") {
        let size = std::str::from_utf8(&input[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())?;
        let rest = &input[line_end + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        output.extend_from_slice(&rest[..size]);
        input = rest.get(size + 2..).unwrap_or_default();
    }
    Some(output)
}

/// Decodes every complete event-stream frame, ignoring a truncated last one.
fn complete_event_stream_events(body: &[u8]) -> Option<Vec<Value>> {
    let mut end = 0;
    while let Some(length) = be_u32(&body[end..], 0)
        .ok()
        .and_then(|length| usize::try_from(length).ok())
        .filter(|length| end + length <= body.len() && *length > 0)
    {
        end += length;
    }
    decode_event_stream(&body[..end]).ok()
}

/// Parses every complete `data:` line, ignoring a truncated last one.
fn complete_server_sent_events(body: &[u8]) -> Option<Vec<Value>> {
    let complete = &body[..body
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |end| end + 1)];
    complete
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            line.strip_suffix(b"\r")
                .unwrap_or(line)
                .strip_prefix(b"data: ")
        })
        .filter(|data| *data != b"[DONE]")
        .map(|data| serde_json::from_slice(data).ok())
        .collect()
}

#[derive(Default)]
struct UsageFields {
    input: Option<u64>,
    cache_creation_input: u64,
    cache_read_input: u64,
    output: Option<u64>,
    provider_input: Option<u64>,
    provider_output: Option<u64>,
}

impl UsageFields {
    fn observe(&mut self, value: &Value) -> Result<(), TlsError> {
        // A SigV4 provider restates the same two numbers under its own names on
        // the terminal event, and its input count is already a total rather than
        // a figure the cache fields add to. They are therefore accumulated
        // separately and reconciled once, in `finish`; adding them to the
        // per-event fields would charge the cached tokens twice.
        if let Some(metrics) = value.get("amazon-bedrock-invocationMetrics") {
            if let Some(tokens) = usage_u64(metrics, "inputTokenCount")? {
                self.provider_input = Some(self.provider_input.unwrap_or_default().max(tokens));
            }
            if let Some(tokens) = usage_u64(metrics, "outputTokenCount")? {
                self.provider_output = Some(self.provider_output.unwrap_or_default().max(tokens));
            }
        }
        let usage = value.get("usage").or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("usage"))
        });
        let Some(usage) = usage else {
            return Ok(());
        };
        if let Some(tokens) = usage_u64(usage, "input_tokens")? {
            self.input = Some(self.input.unwrap_or_default().max(tokens));
        }
        if let Some(tokens) = usage_u64(usage, "cache_creation_input_tokens")? {
            self.cache_creation_input = self.cache_creation_input.max(tokens);
        }
        if let Some(tokens) = usage_u64(usage, "cache_read_input_tokens")? {
            self.cache_read_input = self.cache_read_input.max(tokens);
        }
        if let Some(tokens) = usage_u64(usage, "output_tokens")? {
            self.output = Some(self.output.unwrap_or_default().max(tokens));
        }
        Ok(())
    }

    /// Billed input, once any trusted account of it has been seen.
    fn input_total(&self) -> Option<u64> {
        if self.input.is_none() && self.provider_input.is_none() {
            return None;
        }
        let input = self
            .input
            .unwrap_or_default()
            .checked_add(self.cache_creation_input)?
            .checked_add(self.cache_read_input)?;
        Some(input.max(self.provider_input.unwrap_or_default()))
    }

    fn finish(self, status: u16) -> Result<ModelUsage, TlsError> {
        if (self.input.is_none() && self.provider_input.is_none())
            || (self.output.is_none() && self.provider_output.is_none())
        {
            return Err(TlsError(format!(
                "model response {status} contains incomplete trusted usage"
            )));
        }
        let input_tokens = self
            .input_total()
            .ok_or_else(|| TlsError("model input usage overflowed".to_owned()))?;
        // Two accounts of one response settle at the larger. If a provider and
        // the events it relays disagree, the run is charged for the worse of the
        // two rather than the more convenient one.
        Ok(ModelUsage {
            input_tokens,
            output_tokens: self
                .output
                .unwrap_or_default()
                .max(self.provider_output.unwrap_or_default()),
        })
    }
}

fn usage_u64(usage: &Value, field: &str) -> Result<Option<u64>, TlsError> {
    usage.get(field).map_or(Ok(None), |value| {
        value
            .as_u64()
            .map(Some)
            .ok_or_else(|| TlsError(format!("model usage field `{field}` is invalid")))
    })
}

fn response_body(response: &[u8]) -> Result<Vec<u8>, TlsError> {
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| TlsError("model response headers are incomplete".to_owned()))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| TlsError::new("model response headers", error))?;
    let body = &response[header_end + 4..];
    if headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        })
    }) {
        decode_chunked(body)
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, TlsError> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
            .ok_or_else(|| TlsError("chunk size is incomplete".to_owned()))?;
        let size = std::str::from_utf8(&input[..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or_else(|| TlsError("chunk size is invalid".to_owned()))?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        let end = size
            .checked_add(2)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| TlsError("chunk body is incomplete".to_owned()))?;
        if &input[size..end] != b"\r\n" {
            return Err(TlsError("chunk body terminator is invalid".to_owned()));
        }
        output.extend_from_slice(&input[..size]);
        if output.len() as u64 > MAX_HTTP_RESPONSE {
            return Err(TlsError("decoded response exceeds 16 MiB".to_owned()));
        }
        input = &input[end..];
    }
}

fn is_event_stream(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return false;
    };
    std::str::from_utf8(&response[..header_end]).is_ok_and(|headers| {
        headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("content-type")
                    && value.split(';').next().is_some_and(|media| {
                        media.trim().eq_ignore_ascii_case(EVENT_STREAM_CONTENT_TYPE)
                    })
            })
        })
    })
}

/// Decodes a binary eventstream body into the JSON events it carries.
///
/// The framing CRCs are deliberately not verified. The bytes arrived over a TLS
/// session this crate authenticated itself, so a checksum adds no authority the
/// stream does not already have, and no CRC implementation is on this crate's
/// dependency allowlist. Framing is a different matter: a declared length that
/// does not fit what was received means the stream is not the stream it claims
/// to be, and every such disagreement fails closed rather than being repaired.
fn decode_event_stream(body: &[u8]) -> Result<Vec<Value>, TlsError> {
    const PRELUDE: usize = 12;
    const FRAMING: usize = PRELUDE + 4;
    let mut events = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let total_length = usize::try_from(be_u32(rest, 0)?)
            .map_err(|error| TlsError::new("event stream frame length", error))?;
        let headers_length = usize::try_from(be_u32(rest, 4)?)
            .map_err(|error| TlsError::new("event stream headers length", error))?;
        if total_length > rest.len()
            || total_length < FRAMING
            || headers_length > total_length - FRAMING
        {
            return Err(TlsError(
                "event stream frame length is inconsistent".to_owned(),
            ));
        }
        events.push(event_stream_event(
            &rest[PRELUDE..PRELUDE + headers_length],
            &rest[PRELUDE + headers_length..total_length - 4],
        )?);
        rest = &rest[total_length..];
    }
    Ok(events)
}

fn be_u32(bytes: &[u8], offset: usize) -> Result<u32, TlsError> {
    bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| TlsError("event stream frame ends early".to_owned()))
}

fn event_stream_event(headers: &[u8], payload: &[u8]) -> Result<Value, TlsError> {
    let headers = event_stream_headers(headers)?;
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    match header(":message-type") {
        Some("event") => {}
        // An exception is a message the stream itself declares malformed or
        // refused. Reporting it as zero usage would settle a reservation
        // against a response that never arrived.
        Some("exception") => {
            return Err(TlsError(format!(
                "model stream raised `{}`",
                header(":exception-type").unwrap_or("an unnamed exception")
            )));
        }
        message_type => {
            return Err(TlsError(format!(
                "event stream message type `{}` is not admitted",
                message_type.unwrap_or("absent")
            )));
        }
    }
    let event_type = header(":event-type").unwrap_or("absent");
    if event_type != "chunk" {
        return Err(TlsError(format!(
            "event stream event `{event_type}` is not admitted"
        )));
    }
    let envelope: Value = serde_json::from_slice(payload)
        .map_err(|error| TlsError::new("event stream payload", error))?;
    let encoded = envelope
        .get("bytes")
        .and_then(Value::as_str)
        .ok_or_else(|| TlsError("event stream chunk carries no payload bytes".to_owned()))?;
    serde_json::from_slice(&decode_base64(encoded)?)
        .map_err(|error| TlsError::new("event stream chunk", error))
}

fn event_stream_headers(mut headers: &[u8]) -> Result<Vec<(String, String)>, TlsError> {
    let malformed = || TlsError("event stream headers are malformed".to_owned());
    // Only string-valued headers are read; the rest are stepped over by their
    // declared width. A width this function does not know is a framing
    // disagreement, not a header to skip.
    let mut parsed = Vec::new();
    while !headers.is_empty() {
        let name_length = usize::from(headers[0]);
        let name = headers.get(1..1 + name_length).ok_or_else(malformed)?;
        let value_type = *headers.get(1 + name_length).ok_or_else(malformed)?;
        let name = std::str::from_utf8(name)
            .map_err(|_| malformed())?
            .to_owned();
        headers = &headers[2 + name_length..];
        let length = match value_type {
            0 | 1 => 0,
            2 => 1,
            3 => 2,
            4 => 4,
            5 | 8 => 8,
            9 => 16,
            6 | 7 => {
                let declared = headers.get(..2).ok_or_else(malformed)?;
                headers = &headers[2..];
                usize::from(u16::from_be_bytes([declared[0], declared[1]]))
            }
            _ => return Err(malformed()),
        };
        let value = headers.get(..length).ok_or_else(malformed)?;
        if value_type == 7 {
            let value = std::str::from_utf8(value).map_err(|_| malformed())?;
            parsed.push((name, value.to_owned()));
        }
        headers = &headers[length..];
    }
    Ok(parsed)
}

fn decode_base64(input: &str) -> Result<Vec<u8>, TlsError> {
    let invalid = || TlsError("event stream chunk is not valid base64".to_owned());
    let padded = input.as_bytes();
    let body = padded
        .strip_suffix(b"==")
        .or_else(|| padded.strip_suffix(b"="))
        .unwrap_or(padded);
    if !padded.len().is_multiple_of(4) || body.len() % 4 == 1 {
        return Err(invalid());
    }
    let mut output = Vec::with_capacity(body.len() / 4 * 3);
    let mut bits = 0_u32;
    let mut pending = 0_u32;
    for byte in body {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(invalid()),
        };
        bits = (bits << 6) | u32::from(sextet);
        pending += 6;
        if pending >= 8 {
            pending -= 8;
            let byte = (bits >> pending) & 0xff;
            output.push(u8::try_from(byte).map_err(|_| invalid())?);
        }
    }
    // Leftover sextet bits belong to a byte that was never sent, so they must be
    // zero. Anything else is data this decoder would silently drop.
    if bits & ((1 << pending) - 1) != 0 {
        return Err(invalid());
    }
    Ok(output)
}

/// Fresh OAuth access token returned by a trusted refresh client.
pub struct RefreshedToken {
    /// Access-token bytes.
    pub access_token: SecretBytes,
    /// Absolute expiry time in caller-defined seconds.
    pub expires_at: u64,
}

/// Trusted OAuth refresh transport.
pub trait OAuthRefresher {
    /// Exchanges a refresh token for a new access token.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh exchange fails.
    fn refresh(&mut self, refresh_token: &[u8]) -> Result<RefreshedToken, TlsError>;
}

/// OAuth credential pair retained in trusted memory.
pub struct OAuthCredential {
    access_token: SecretBytes,
    refresh_token: SecretBytes,
    expires_at: u64,
}

impl OAuthCredential {
    /// Creates an OAuth credential pair.
    #[must_use]
    pub const fn new(
        access_token: SecretBytes,
        refresh_token: SecretBytes,
        expires_at: u64,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_at,
        }
    }

    /// Exposes a current access token, refreshing within the requested skew.
    ///
    /// # Errors
    ///
    /// Returns an error when refresh is required and fails.
    pub fn with_access_token<R>(
        &mut self,
        now: u64,
        refresh_skew: u64,
        refresher: &mut impl OAuthRefresher,
        operation: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, TlsError> {
        if self.expires_at <= now.saturating_add(refresh_skew) {
            let new_token = self
                .refresh_token
                .expose(|token| refresher.refresh(token))?;
            self.access_token = new_token.access_token;
            self.expires_at = new_token.expires_at;
        }
        Ok(self.access_token.expose(operation))
    }
}

/// Ephemeral certificate authority generated for one isolated run.
pub struct MitmCa {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

/// Backward-compatible name used by the Phase 0 compatibility spike.
pub type TestMitmCa = MitmCa;

/// Certificate generation, TLS configuration, or connection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsError(String);

impl TlsError {
    fn new(context: &str, error: impl fmt::Display) -> Self {
        Self(format!("{context}: {error}"))
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for TlsError {}

impl MitmCa {
    /// Generates an ephemeral CA for one isolated run.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic provider cannot generate the key
    /// or certificate.
    pub fn generate() -> Result<Self, TlsError> {
        let mut params = CertificateParams::new(Vec::new())
            .map_err(|error| TlsError::new("CA parameters", error))?;
        params
            .distinguished_name
            .push(DnType::CommonName, "Keel Phase 0 Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().map_err(|error| TlsError::new("CA key", error))?;
        let certificate = params
            .self_signed(&key)
            .map_err(|error| TlsError::new("CA certificate", error))?;
        Ok(Self {
            certificate,
            issuer: Issuer::new(params, key),
        })
    }

    /// Returns the CA certificate in PEM form for a guest trust store.
    #[must_use]
    pub fn certificate_pem(&self) -> String {
        self.certificate.pem()
    }

    /// Returns the CA certificate in DER form.
    #[must_use]
    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.certificate.der().clone()
    }

    /// Mints a host-bound leaf certificate and creates a `rustls` server.
    ///
    /// # Errors
    ///
    /// Returns an error when the DNS name is invalid, leaf generation fails,
    /// or `rustls` rejects the certificate/key pair.
    pub fn server_config(&self, dns_name: &str) -> Result<Arc<ServerConfig>, TlsError> {
        let mut params = CertificateParams::new(vec![dns_name.to_owned()])
            .map_err(|error| TlsError::new("leaf parameters", error))?;
        params.distinguished_name.push(DnType::CommonName, dns_name);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let key = KeyPair::generate().map_err(|error| TlsError::new("leaf key", error))?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| TlsError::new("leaf certificate", error))?;
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())).clone_key();
        let chain = vec![certificate.der().clone(), self.certificate_der()];
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, private_key)
            .map_err(|error| TlsError::new("rustls server config", error))?;
        Ok(Arc::new(config))
    }
}

/// Terminates one TLS HTTP/1.1 connection and writes the handler's response.
///
/// The caller parses the untrusted connection prefix and selects policy before
/// invoking this trusted function. Plaintext remains inside this crate until
/// it is passed to the supplied request handler.
///
/// # Errors
///
/// Returns an error if the handshake, bounded request read, or response write
/// fails.
pub fn terminate_http_once(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    handler: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<(), TlsError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| TlsError::new("TLS read timeout", error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| TlsError::new("TLS write timeout", error))?;
    terminate_stream_once(stream, config, handler)
}

/// Terminates one TLS HTTP/1.1 connection over a byte-preserving handoff
/// stream.
///
/// This variant accepts the replay stream returned by the untrusted connection
/// classifier. Transport-specific timeouts must be configured before handoff.
///
/// # Errors
///
/// Returns an error if the handshake, bounded request read, or response write
/// fails.
pub fn terminate_stream_once<S>(
    stream: S,
    config: Arc<ServerConfig>,
    handler: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Result<(), TlsError>
where
    S: std::io::Read + std::io::Write,
{
    let connection = ServerConnection::new(config)
        .map_err(|error| TlsError::new("rustls server connection", error))?;
    let mut tls = StreamOwned::new(connection, stream);
    let request = read_http_request(&mut tls)?;
    let response = handler(&request);
    tls.write_all(&response)
        .map_err(|error| TlsError::new("TLS response", error))?;
    tls.flush()
        .map_err(|error| TlsError::new("TLS response flush", error))?;
    tls.conn.send_close_notify();
    tls.flush()
        .map_err(|error| TlsError::new("TLS close notification", error))?;
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn proxy_tls_http<S, C>(
    guest: S,
    front_config: Arc<ServerConfig>,
    upstream_config: Arc<ClientConfig>,
    destination: &EgressDestination,
    vault: &CredentialVault,
    authorizer: &mut dyn EgressRequestAuthorizer,
    reuse_connections: bool,
    connect: C,
) -> Result<(), TlsError>
where
    S: std::io::Read + std::io::Write,
    C: FnOnce() -> Result<(TcpStream, ConnectionTarget), TlsError>,
{
    let connection = ServerConnection::new(front_config)
        .map_err(|error| TlsError::new("rustls server connection", error))?;
    let mut front = StreamOwned::new(connection, guest);
    let mut connect = Some(connect);
    let mut upstream_config = Some(upstream_config);
    let mut upstream = None;
    let request_limit = if reuse_connections {
        MAX_REUSED_REQUESTS
    } else {
        1
    };
    for request_index in 0..request_limit {
        let request = match read_http_request_optional(&mut front)? {
            Some(request) => request,
            None if request_index == 0 => {
                return Err(TlsError("TLS request is empty".to_owned()));
            }
            None => break,
        };
        let keep_alive = reuse_connections
            && request_index + 1 < request_limit
            && request_supports_keep_alive(&request)?;
        let request_plan = match authorize_http_request(destination, &request, authorizer) {
            Ok(request_plan) => request_plan,
            Err(error) => {
                // A refusal is an answer, not a transport fault. Dropping the
                // connection instead would reach the harness as a reset and
                // start a retry storm against a decision that will not change.
                let _ = write_refusal(&mut front);
                front.conn.send_close_notify();
                let _ = front.flush();
                return Err(error);
            }
        };
        commit_external_send(authorizer, request_plan.model)?;
        if upstream.is_none() {
            let connector = connect
                .take()
                .ok_or_else(|| TlsError("upstream connector was already consumed".to_owned()))?;
            upstream = Some(connect_tls_after_authorization(
                destination,
                upstream_config.take().ok_or_else(|| {
                    TlsError("upstream TLS configuration was already consumed".to_owned())
                })?,
                connector,
                authorizer,
                request_plan.model,
            )?);
        }
        let (tls, target) = upstream
            .as_mut()
            .ok_or_else(|| TlsError("upstream TLS session is unavailable".to_owned()))?;
        let prepared = match finish_authorized_request(
            target,
            vault,
            &request,
            request_plan,
            authorizer,
            keep_alive,
            true,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = write_refusal(&mut front);
                front.conn.send_close_notify();
                let _ = front.flush();
                return Err(error);
            }
        };
        begin_model_send(authorizer, prepared.model)?;
        if let Err(error) = tls.write_all(&prepared.bytes) {
            return Err(commit_after_possible_send(
                authorizer,
                prepared.model,
                TlsError::new("upstream request", error),
            ));
        }
        if let Err(error) = tls.flush() {
            return Err(commit_after_possible_send(
                authorizer,
                prepared.model,
                TlsError::new("upstream request flush", error),
            ));
        }
        let response =
            match relay_http_response_with_observation(tls, &mut front, "TLS response", || {
                authorizer
                    .record_response()
                    .map_err(|error| TlsError::new("kernel response provenance", error))
            }) {
                Ok(response) => response,
                Err(failure) => {
                    return Err(commit_after_interrupted_response(
                        authorizer,
                        prepared.model,
                        failure,
                    ));
                }
            };
        if prepared.model {
            settle_complete_model_response(authorizer, &response.bytes)?;
        }
        if let Some(error) = response.guest_error {
            return Err(error);
        }
        if !keep_alive || response_closes_connection(&response.bytes)? {
            break;
        }
    }
    front
        .flush()
        .map_err(|error| TlsError::new("TLS response flush", error))?;
    front.conn.send_close_notify();
    front
        .flush()
        .map_err(|error| TlsError::new("TLS close notification", error))
}

fn connect_tls_after_authorization<C>(
    destination: &EgressDestination,
    upstream_config: Arc<ClientConfig>,
    connect: C,
    authorizer: &mut dyn EgressRequestAuthorizer,
    model: bool,
) -> Result<(StreamOwned<ClientConnection, TcpStream>, ConnectionTarget), TlsError>
where
    C: FnOnce() -> Result<(TcpStream, ConnectionTarget), TlsError>,
{
    let (stream, target) =
        connect().map_err(|error| release_authorized_unsent(authorizer, model, error))?;
    if target.server_name != destination.server_name || target.port != destination.port {
        return Err(release_authorized_unsent(
            authorizer,
            model,
            TlsError("upstream connector changed the authorized destination".to_owned()),
        ));
    }
    stream
        .set_read_timeout(Some(if model {
            MODEL_READ_IDLE_TIMEOUT
        } else {
            Duration::from_secs(10)
        }))
        .map_err(|error| {
            release_authorized_unsent(
                authorizer,
                model,
                TlsError::new("upstream read timeout", error),
            )
        })?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| {
            release_authorized_unsent(
                authorizer,
                model,
                TlsError::new("upstream write timeout", error),
            )
        })?;
    let server_name = ServerName::try_from(target.server_name.clone()).map_err(|error| {
        release_authorized_unsent(authorizer, model, TlsError::new("upstream DNS name", error))
    })?;
    let connection = ClientConnection::new(upstream_config, server_name).map_err(|error| {
        release_authorized_unsent(
            authorizer,
            model,
            TlsError::new("rustls upstream connection", error),
        )
    })?;
    Ok((StreamOwned::new(connection, stream), target))
}

/// Sends a decrypted request over a separately authenticated upstream TLS leg.
///
/// The caller supplies a connected socket after kernel-side resolution and
/// structural address checks. The DNS name is verified against the upstream
/// certificate using the supplied trust anchor.
///
/// # Errors
///
/// Returns an error if trust-store setup, hostname validation, the upstream
/// handshake, or request/response I/O fails.
pub fn forward_http_once(
    request: &[u8],
    stream: TcpStream,
    dns_name: &str,
    trusted_ca: CertificateDer<'static>,
) -> Result<Vec<u8>, TlsError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| TlsError::new("upstream read timeout", error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| TlsError::new("upstream write timeout", error))?;
    let mut roots = RootCertStore::empty();
    roots
        .add(trusted_ca)
        .map_err(|error| TlsError::new("upstream trust anchor", error))?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    forward_http_with_config(request, stream, dns_name, Arc::new(config))
}

fn forward_http_with_config(
    request: &[u8],
    stream: TcpStream,
    dns_name: &str,
    config: Arc<ClientConfig>,
) -> Result<Vec<u8>, TlsError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| TlsError::new("upstream read timeout", error))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| TlsError::new("upstream write timeout", error))?;
    let server_name = ServerName::try_from(dns_name.to_owned())
        .map_err(|error| TlsError::new("upstream DNS name", error))?;
    let connection = ClientConnection::new(config, server_name)
        .map_err(|error| TlsError::new("rustls upstream connection", error))?;
    let mut tls = StreamOwned::new(connection, stream);
    tls.write_all(request)
        .map_err(|error| TlsError::new("upstream request", error))?;
    tls.flush()
        .map_err(|error| TlsError::new("upstream request flush", error))?;
    relay_http_response(&mut tls, &mut std::io::sink(), "response buffer")?.finish_guest_delivery()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpResponseState {
    Incomplete,
    Complete(usize),
    CloseDelimited,
}

fn relay_http_response<R, W>(
    upstream: &mut R,
    guest: &mut W,
    guest_context: &'static str,
) -> Result<RelayedHttpResponse, TlsError>
where
    R: std::io::Read,
    W: std::io::Write,
{
    relay_http_response_with_observation(upstream, guest, guest_context, || Ok(()))
        .map_err(|failure| failure.error)
}

fn relay_http_response_with_observation<R, W, F>(
    upstream: &mut R,
    guest: &mut W,
    guest_context: &'static str,
    before_first_delivery: F,
) -> Result<RelayedHttpResponse, RelayFailure>
where
    R: std::io::Read,
    W: std::io::Write,
    F: FnOnce() -> Result<(), TlsError>,
{
    // Bytes received before a failure are kept: an interrupted model stream
    // may already state the usage that bounds its charge.
    let mut response = Vec::new();
    match relay_into(
        &mut response,
        upstream,
        guest,
        guest_context,
        before_first_delivery,
    ) {
        Ok(guest_error) => Ok(RelayedHttpResponse {
            bytes: response,
            guest_error,
        }),
        Err(error) => Err(RelayFailure {
            error,
            partial: response,
        }),
    }
}

fn relay_into<R, W, F>(
    response: &mut Vec<u8>,
    upstream: &mut R,
    guest: &mut W,
    guest_context: &'static str,
    before_first_delivery: F,
) -> Result<Option<TlsError>, TlsError>
where
    R: std::io::Read,
    W: std::io::Write,
    F: FnOnce() -> Result<(), TlsError>,
{
    let mut guest_error = None;
    let mut before_first_delivery = Some(before_first_delivery);
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = upstream
            .read(&mut chunk)
            .map_err(|error| TlsError::new("upstream response", error))?;
        if read == 0 {
            return match http_response_state(response)? {
                HttpResponseState::Complete(length) if length == response.len() => Ok(guest_error),
                HttpResponseState::CloseDelimited => Ok(guest_error),
                _ => Err(TlsError("upstream response ended early".to_owned())),
            };
        }
        let previous_length = response.len();
        let new_length = previous_length
            .checked_add(read)
            .ok_or_else(|| TlsError("upstream response size overflowed".to_owned()))?;
        if new_length as u64 > MAX_HTTP_RESPONSE {
            return Err(TlsError("upstream response exceeds 16 MiB".to_owned()));
        }
        response.extend_from_slice(&chunk[..read]);
        let state = http_response_state(response)?;
        let forwarded_length = match state {
            HttpResponseState::Complete(length) => length,
            HttpResponseState::Incomplete | HttpResponseState::CloseDelimited => response.len(),
        };
        if guest_error.is_none() {
            if previous_length < forwarded_length
                && let Some(observe) = before_first_delivery.take()
            {
                observe()?;
            }
            if let Err(error) = guest.write_all(&response[previous_length..forwarded_length]) {
                guest_error = Some(TlsError::new(guest_context, error));
            } else if let Err(error) = guest.flush() {
                guest_error = Some(TlsError::new(guest_context, error));
            }
        }
        if let HttpResponseState::Complete(length) = state {
            response.truncate(length);
            return Ok(guest_error);
        }
    }
}

/// A response relay that failed, with every byte received before it did.
#[derive(Debug)]
struct RelayFailure {
    error: TlsError,
    partial: Vec<u8>,
}

struct RelayedHttpResponse {
    bytes: Vec<u8>,
    guest_error: Option<TlsError>,
}

impl RelayedHttpResponse {
    fn finish_guest_delivery(self) -> Result<Vec<u8>, TlsError> {
        match self.guest_error {
            Some(error) => Err(error),
            None => Ok(self.bytes),
        }
    }
}

/// Refusal body sent to the guest in place of a dropped connection.
///
/// The reason stays inside the trusted process. The guest learns only that
/// this request was refused, in the shape its own API client already handles.
const REFUSAL_BODY: &str = concat!(
    r#"{"type":"error","error":{"type":"permission_error","#,
    r#""message":"Keel refused this request"}}"#
);

fn write_refusal(guest: &mut impl std::io::Write) -> Result<(), TlsError> {
    let response = format!(
        "HTTP/1.1 403 Forbidden\r\n\
Content-Type: application/json\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{REFUSAL_BODY}",
        REFUSAL_BODY.len()
    );
    guest
        .write_all(response.as_bytes())
        .map_err(|error| TlsError::new("TLS refusal", error))?;
    guest
        .flush()
        .map_err(|error| TlsError::new("TLS refusal flush", error))
}

fn response_status(response: &[u8]) -> Result<u16, TlsError> {
    std::str::from_utf8(
        response
            .split(|byte| *byte == b'\r')
            .next()
            .unwrap_or_default(),
    )
    .ok()
    .and_then(|line| line.split_ascii_whitespace().nth(1))
    .and_then(|status| status.parse::<u16>().ok())
    .ok_or_else(|| TlsError("upstream response status is malformed".to_owned()))
}

fn http_response_state(response: &[u8]) -> Result<HttpResponseState, TlsError> {
    let Some(header_end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return Ok(HttpResponseState::Incomplete);
    };
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| TlsError::new("upstream response headers", error))?;
    let body_start = header_end + 4;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| TlsError("upstream response status is malformed".to_owned()))?;
    if status == 204 || status == 304 {
        return Ok(HttpResponseState::Complete(body_start));
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(TlsError("upstream response header is malformed".to_owned()));
        };
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|error| TlsError::new("upstream Content-Length", error))?;
            if content_length
                .replace(parsed)
                .is_some_and(|prior| prior != parsed)
            {
                return Err(TlsError(
                    "upstream response has conflicting Content-Length headers".to_owned(),
                ));
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"));
        }
    }
    if chunked {
        return chunked_message_length(&response[body_start..]).map(|length| {
            length.map_or(HttpResponseState::Incomplete, |length| {
                HttpResponseState::Complete(body_start + length)
            })
        });
    }
    if let Some(content_length) = content_length {
        let message_length = body_start
            .checked_add(content_length)
            .ok_or_else(|| TlsError("upstream response size overflowed".to_owned()))?;
        return Ok(if response.len() >= message_length {
            HttpResponseState::Complete(message_length)
        } else {
            HttpResponseState::Incomplete
        });
    }
    Ok(HttpResponseState::CloseDelimited)
}

fn chunked_message_length(body: &[u8]) -> Result<Option<usize>, TlsError> {
    let mut position = 0;
    loop {
        let Some(relative_line_end) = body[position..]
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
        else {
            return Ok(None);
        };
        let line_end = position + relative_line_end;
        let size = std::str::from_utf8(&body[position..line_end])
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or_else(|| TlsError("upstream chunk size is invalid".to_owned()))?;
        let data_start = line_end + 2;
        if size == 0 {
            if body[data_start..].starts_with(b"\r\n") {
                return Ok(Some(data_start + 2));
            }
            return Ok(body[data_start..]
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .map(|trailer_end| data_start + trailer_end + 4));
        }
        let Some(data_end) = data_start.checked_add(size) else {
            return Err(TlsError("upstream chunk size overflowed".to_owned()));
        };
        let Some(chunk_end) = data_end.checked_add(2) else {
            return Err(TlsError("upstream chunk size overflowed".to_owned()));
        };
        if chunk_end > body.len() {
            return Ok(None);
        }
        if &body[data_end..chunk_end] != b"\r\n" {
            return Err(TlsError("upstream chunk terminator is invalid".to_owned()));
        }
        position = chunk_end;
    }
}

fn request_supports_keep_alive(request: &[u8]) -> Result<bool, TlsError> {
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| TlsError("HTTP headers are incomplete".to_owned()))?;
    let headers = std::str::from_utf8(&request[..header_end])
        .map_err(|error| TlsError::new("HTTP headers", error))?;
    let version = headers
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(2))
        .ok_or_else(|| TlsError("HTTP request line is malformed".to_owned()))?;
    Ok(version == "HTTP/1.1" && !headers_request_connection_close(headers))
}

fn response_closes_connection(response: &[u8]) -> Result<bool, TlsError> {
    if http_response_state(response)? == HttpResponseState::CloseDelimited {
        return Ok(true);
    }
    let header_end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| TlsError("upstream response headers are incomplete".to_owned()))?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|error| TlsError::new("upstream response headers", error))?;
    let version = headers
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().next())
        .ok_or_else(|| TlsError("upstream response status is malformed".to_owned()))?;
    let close = headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
    });
    let keep_alive = headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("keep-alive"))
        })
    });
    Ok(close || (version == "HTTP/1.0" && !keep_alive))
}

fn headers_request_connection_close(headers: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("connection")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
    })
}

struct PreparedHttpRequest {
    bytes: Vec<u8>,
    model: bool,
}

struct AuthorizedHttpRequest {
    body: Vec<u8>,
    destination: EgressDestination,
    model: bool,
}

#[cfg(test)]
fn prepare_upstream_request_with_authorizer(
    target: &ConnectionTarget,
    vault: &CredentialVault,
    request: &[u8],
    authorizer: &mut dyn EgressRequestAuthorizer,
    keep_alive: bool,
) -> Result<PreparedHttpRequest, TlsError> {
    let destination = EgressDestination {
        server_name: target.server_name.clone(),
        port: target.port,
    };
    let request_plan = authorize_http_request(&destination, request, authorizer)?;
    finish_authorized_request(
        target,
        vault,
        request,
        request_plan,
        authorizer,
        keep_alive,
        true,
    )
}

fn authorize_http_request(
    destination: &EgressDestination,
    request: &[u8],
    authorizer: &mut dyn EgressRequestAuthorizer,
) -> Result<AuthorizedHttpRequest, TlsError> {
    let (method, path) = request_line(request)?;
    if bedrock_control_endpoint(&destination.server_name) {
        // Claude Code uses the Bedrock control client to discover inference
        // profiles. Keel intentionally has authority only for the model-runtime
        // API: admitting the TLS connection avoids a transport reset, while a
        // local HTTP refusal ensures no control-plane request or credential ever
        // reaches AWS.
        return Err(TlsError(format!(
            "Bedrock control-plane request `{method} {path}` is not admitted"
        )));
    }
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| TlsError("HTTP headers are incomplete".to_owned()))?;
    let body = &request[header_end + 4..];
    let endpoint = model_endpoint(&destination.server_name);
    let body = if endpoint.is_some() {
        if method != "POST" {
            return Err(TlsError(format!(
                "model endpoint accepts only POST requests, not `{method} {path}`"
            )));
        }
        let sanitized = sanitize_model_request_for_destination(
            &destination.server_name,
            destination.port,
            path,
            body,
        )?;
        if !sanitized.stripped.is_empty() {
            eprintln!(
                "keel-secrets: stripped model request capabilities: {}",
                sanitized.stripped.join(",")
            );
        }
        sanitized.body
    } else {
        body.to_vec()
    };
    let model_budget = endpoint
        .as_ref()
        .map(|endpoint| model_budget_request(endpoint, path, &body))
        .transpose()?;
    if endpoint.is_none() {
        authorizer.observe_payload(path, &body);
    } else {
        authorizer.observe_model_context(false, model_request_context(&body));
    }
    authorizer
        .authorize(method, path, sha256_bytes(&body), model_budget)
        .map_err(|error| TlsError::new("kernel HTTP authorization", error))?;
    Ok(AuthorizedHttpRequest {
        body,
        destination: destination.clone(),
        model: endpoint.is_some(),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn finish_authorized_request(
    target: &ConnectionTarget,
    vault: &CredentialVault,
    request: &[u8],
    request_plan: AuthorizedHttpRequest,
    authorizer: &mut dyn EgressRequestAuthorizer,
    keep_alive: bool,
    encrypted: bool,
) -> Result<PreparedHttpRequest, TlsError> {
    if target.server_name != request_plan.destination.server_name
        || target.port != request_plan.destination.port
        || is_forbidden_ip(target.resolved_ip)
    {
        return Err(release_authorized_unsent(
            authorizer,
            request_plan.model,
            TlsError("resolved target does not match the authorized destination".to_owned()),
        ));
    }
    let request = rebuild_http_request(request, &request_plan.body, target, keep_alive)
        .map_err(|error| release_authorized_unsent(authorizer, request_plan.model, error))?;
    let bytes = if encrypted {
        vault.inject(target, &request)
    } else {
        vault.refuse_sentinels(request)
    }
    .map_err(|error| release_authorized_unsent(authorizer, request_plan.model, error))?;
    Ok(PreparedHttpRequest {
        bytes,
        model: request_plan.model,
    })
}

fn release_authorized_unsent(
    authorizer: &mut dyn EgressRequestAuthorizer,
    model: bool,
    error: TlsError,
) -> TlsError {
    if model {
        release_definitely_unsent(authorizer, error)
    } else {
        error
    }
}

fn rebuild_http_request(
    request: &[u8],
    body: &[u8],
    target: &ConnectionTarget,
    keep_alive: bool,
) -> Result<Vec<u8>, TlsError> {
    let header_end = request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or_else(|| TlsError("HTTP headers are incomplete".to_owned()))?;
    let headers = std::str::from_utf8(&request[..header_end])
        .map_err(|error| TlsError::new("HTTP headers", error))?;
    let mut lines = headers.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| TlsError("HTTP request line is missing".to_owned()))?;
    let mut output = Vec::with_capacity(request.len() + 19);
    output.extend_from_slice(request_line.as_bytes());
    output.extend_from_slice(b"\r\n");
    for line in lines {
        let name = line.split_once(':').map_or(line, |(name, _)| name);
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("accept-encoding")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(TlsError(
                "HTTP transfer encoding is not supported".to_owned(),
            ));
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    if target.port == 443 {
        write!(output, "Host: {}\r\n", target.server_name)
            .map_err(|error| TlsError::new("HTTP request host", error))?;
    } else {
        write!(output, "Host: {}:{}\r\n", target.server_name, target.port)
            .map_err(|error| TlsError::new("HTTP request host", error))?;
    }
    write!(
        output,
        "Accept-Encoding: identity\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        body.len(),
        if keep_alive { "keep-alive" } else { "close" }
    )
    .map_err(|error| TlsError::new("HTTP request rebuild", error))?;
    output.extend_from_slice(body);
    Ok(output)
}

fn read_http_request(stream: &mut impl std::io::Read) -> Result<Vec<u8>, TlsError> {
    read_http_request_optional(stream)?.ok_or_else(|| TlsError("TLS request is empty".to_owned()))
}

fn read_http_request_optional(
    stream: &mut impl std::io::Read,
) -> Result<Option<Vec<u8>>, TlsError> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = match stream.read(&mut buffer) {
            Ok(count) => count,
            // A reusable connection that goes quiet before sending anything has
            // simply finished. Only a partial request makes silence an error.
            Err(error) if request.is_empty() && is_idle_timeout(&error) => return Ok(None),
            Err(error) => return Err(TlsError::new("TLS request", error)),
        };
        if count == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..count]);
        if request.len() > MAX_HTTP_REQUEST {
            return Err(TlsError("TLS request exceeds 1 MiB".to_owned()));
        }
        if let Some(message_length) = request_message_length(&request)? {
            if request.len() > message_length {
                return Err(TlsError(
                    "HTTP pipelining and trailing request bytes are not supported".to_owned(),
                ));
            }
            if request.len() == message_length {
                return Ok(Some(request));
            }
        }
    }
    if request.is_empty() {
        return Ok(None);
    }
    Err(TlsError("TLS request ended early".to_owned()))
}

fn is_idle_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn request_message_length(request: &[u8]) -> Result<Option<usize>, TlsError> {
    let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
        return Ok(None);
    };
    let body_start = header_end + 4;
    let headers = std::str::from_utf8(&request[..header_end])
        .map_err(|error| TlsError::new("HTTP headers", error))?;
    let mut content_length = None;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(TlsError("HTTP header is malformed".to_owned()));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(TlsError(
                "HTTP transfer encoding is not supported".to_owned(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|error| TlsError::new("HTTP content-length", error))?;
            if content_length.replace(parsed).is_some() {
                return Err(TlsError(
                    "HTTP request has multiple Content-Length headers".to_owned(),
                ));
            }
        }
    }
    body_start
        .checked_add(content_length.unwrap_or(0))
        .map(Some)
        .ok_or_else(|| TlsError("HTTP request size overflowed".to_owned()))
}

/// Returns whether an address is structurally forbidden as an egress target.
///
/// IPv6 forms that embed an IPv4 address (mapped, compatible, NAT64, and
/// 6to4) are judged by the embedded address, so an AAAA record cannot reach
/// a range the IPv4 check forbids.
#[must_use]
pub const fn is_forbidden_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_forbidden_ipv4(address),
        IpAddr::V6(address) => {
            let segments = address.segments();
            let bytes = address.octets();
            let embedded = if segments[0] == 0x2002 {
                Some(Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]))
            } else if matches!(segments, [0x64, 0xff9b, 0, 0, 0, 0, _, _]) {
                Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
            } else {
                address.to_ipv4()
            };
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || matches!(embedded, Some(v4) if is_forbidden_ipv4(v4))
        }
    }
}

const fn is_forbidden_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, ..] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && b & 0xc0 == 64)
        || (a == 198 && b & 0xfe == 18)
}

#[cfg(test)]
#[path = "../tests/support/credential_scope.rs"]
mod credential_scope_tests;
#[cfg(test)]
#[path = "../tests/support/model_lifecycle.rs"]
mod model_lifecycle_tests;
#[cfg(test)]
#[path = "../tests/support/unit.rs"]
mod tests;
#[cfg(test)]
#[path = "../tests/support/transport_ordering.rs"]
mod transport_ordering_tests;
