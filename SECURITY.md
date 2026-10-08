# Security policy

Keel is a research prototype that executes potentially hostile AI workloads. Please read the [threat model](docs/THREAT-MODEL.md) before treating unexpected behavior as a vulnerability.

Keel is not yet a production security product. Its current limitations are documented rather than hidden, but bypasses of a stated security objective are still important and should be reported privately.

## Supported versions

Keel has no stable release series yet.

| Version | Security support |
| --- | --- |
| Current default branch | Best-effort fixes |
| Older commits, forks, and locally modified builds | Not supported |
| Unreleased roadmap or design-note behavior | Not implemented and therefore not supported |

Security fixes may require updating the default branch, rebuilding runtime artifacts, and rerunning keel setup. There is currently no promise of patch releases for older revisions.

## Report a vulnerability

Use GitHub's private vulnerability reporting:

1. Open this repository's **Security** tab.
2. Select **Advisories**.
3. Choose **Report a vulnerability**.

Do not include vulnerability details in a public issue, pull request, discussion, commit message, or shared audit log.

If private vulnerability reporting is unavailable, open a public issue containing only a request for a private reporting channel. Do not identify the affected component or include reproduction details in that issue.

Repository maintainers should enable **Private vulnerability reporting** under **Settings → Code security and analysis** before the first public release.

## What to include

Provide enough information to reproduce and assess the issue:

- affected commit, branch, or release;
- macOS version, hardware architecture, and Keel isolation profile;
- whether the workload used the microVM or host V8 sandbox;
- expected security decision and observed result;
- minimal reproduction steps or proof of concept;
- relevant policy, capabilities, provenance mode, and provider;
- redacted audit events, logs, or screenshots;
- whether real credentials or third-party systems were exposed;
- any suggested mitigation or disclosure deadline.

Never send live API keys, AWS credentials, Git credentials, unredacted secrets, or private repository contents. Replace them with synthetic values.

## Security-sensitive findings

Examples include:

- escape from a Keel microVM into the host;
- host V8 sandbox escape or undeclared host access;
- credential disclosure to the workload;
- arbitrary egress that bypasses the trusted authorization path;
- policy, provenance, capability, budget, or structural-denial bypass;
- forged or replayed trusted approval;
- confusion between an asserted action and trusted stamped facts;
- downgrade from a stronger isolation profile to a weaker one;
- audit-chain forgery or undetected modification under the documented assumptions;
- a trusted crate depending on or delegating authority to untrusted code;
- unsafe parsing that changes the destination, method, path, principal, or authorized effect.

The following are generally not vulnerabilities unless they contradict a documented claim:

- harmful model output without a boundary bypass;
- an operator approving an accurately displayed dangerous action;
- exfiltration through output explicitly allowed by policy;
- denial of service within configured resource limits;
- failure to protect against a compromised host OS, hypervisor, trusted dependency, or admitted runtime artifact;
- limitations already listed in the threat model;
- setup, usability, or rendering defects with no security impact.

When uncertain, report privately and let the maintainers classify it.

## Response process

This is a best-effort research project. Maintainers aim to:

- acknowledge a complete report within three business days;
- provide an initial assessment within fourteen days;
- keep the reporter informed when the assessment materially changes;
- coordinate a fix and disclosure date according to severity and exploitability;
- credit the reporter when requested and safe to do so.

These are targets, not a service-level agreement.

Maintainers may ask for additional evidence, create a private fork, prepare a coordinated patch, request a CVE, or publish an advisory. A report may be closed as out of scope when it relies on assumptions Keel explicitly does not make.

## Disclosure

Please allow a reasonable remediation period before public disclosure. After a fix or coordinated disclosure date, the project may publish:

- affected versions or commits;
- impact and prerequisites;
- the violated security objective;
- remediation and upgrade instructions;
- credit and timeline;
- any changes to the threat model.

## Safe-harbor intent

Good-faith research is welcome when it:

- targets systems and data you own or have explicit permission to test;
- avoids privacy violations, service disruption, persistence, and unnecessary data access;
- uses the minimum access needed to demonstrate the issue;
- stops and reports when real secrets or third-party data are encountered;
- complies with applicable law.

The project cannot authorize testing against third-party providers, repositories, accounts, or infrastructure.
