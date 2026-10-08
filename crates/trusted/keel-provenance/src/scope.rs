//! Triage scope: the hosts a reproduction may reach, declared by the operator.
//!
//! `*.example.com` matches subdomains only, never the apex, which must be
//! listed on its own. A rule without a port matches 443 and 80. An exclusion
//! beats any match.

/// One host rule.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Rule {
    host: String,
    subdomains: bool,
    port: Option<u16>,
}

impl Rule {
    fn parse(text: &str) -> Result<Self, String> {
        let invalid = || format!("invalid scope rule `{text}`");
        let lower = text.trim().to_ascii_lowercase();
        let (host, port) = match lower.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().map_err(|_| invalid())?)),
            None => (lower.as_str(), None),
        };
        let (host, subdomains) = host
            .strip_prefix("*.")
            .map_or((host, false), |rest| (rest, true));
        let label = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        };
        if host.len() > 253 || !host.contains('.') || !host.split('.').all(label) {
            return Err(invalid());
        }
        Ok(Self {
            host: host.to_owned(),
            subdomains,
            port,
        })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        let named = if self.subdomains {
            host.strip_suffix(&self.host)
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
        } else {
            host == self.host
        };
        named
            && self
                .port
                .map_or(matches!(port, 443 | 80), |rule| rule == port)
    }

    fn describe(&self) -> String {
        let wildcard = if self.subdomains { "*." } else { "" };
        let port = self
            .port
            .map_or_else(|| ":443,80".to_owned(), |port| format!(":{port}"));
        format!("{wildcard}{}{port}", self.host)
    }
}

/// The hosts a triage run may reach.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Scope {
    include: Vec<Rule>,
    exclude: Vec<Rule>,
}

impl Scope {
    /// Parses operator-declared rules.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed rule or an empty scope.
    pub fn parse(include: &[String], exclude: &[String]) -> Result<Self, String> {
        let rules = |texts: &[String]| {
            texts
                .iter()
                .map(|text| Rule::parse(text))
                .collect::<Result<Vec<_>, _>>()
        };
        let scope = Self {
            include: rules(include)?,
            exclude: rules(exclude)?,
        };
        if scope.include.is_empty() {
            return Err("a triage run needs at least one --scope rule".to_owned());
        }
        Ok(scope)
    }

    /// Whether a connection to `host:port` is in scope.
    #[must_use]
    pub fn contains(&self, host: &str, port: u16) -> bool {
        self.include.iter().any(|rule| rule.matches(host, port))
            && !self.exclude.iter().any(|rule| rule.matches(host, port))
    }

    /// The normalized rules: included, then `!`-prefixed exclusions.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let excluded = self
            .exclude
            .iter()
            .map(|rule| format!("!{}", rule.describe()));
        self.include
            .iter()
            .map(Rule::describe)
            .chain(excluded)
            .collect()
    }
}
