#!/usr/bin/env python3
"""Check the Phase 1 trust-boundary invariants I1-I12."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parent.parent
TRUSTED_ROOT = ROOT / "crates" / "trusted"
UNTRUSTED_ROOT = ROOT / "crates" / "untrusted"
# Per-crate budgets plus an explicitly unallocated reserve sum to exactly
# TOTAL_BUDGET. Reallocating between crates or assigning reserve is a recorded
# decision. D39 raised the hard ceiling for the measured implementation of
# staged approval waits, scoped denial history, and conservative model-charge
# settlement; future work still cannot consume its reserve by accident.
CRATE_BUDGETS = {
    # D15 moved 200 lines here from keel-provenance for the enforcement-state
    # record. Provenance's budget was sized for the vertex-fork comparison that
    # Phase 4 measures rather than builds, so those lines were unclaimed.
    # D22 moved 175 lines here for risk-classified approvals and bounded,
    # exact-host session grants. The total did not move.
    # D28 moved the final 2 lines of headroom to lifecycle status.
    # D31: exact effect permits and bounded concurrent broker handling.
    # D32 removes the in-process approval signature and reallocates its 73-line
    # reduction to audit completeness and Git/input hardening.
    # D37 moves live floor-lift authority into the kernel that owns the session
    # instead of constructing an unrelated kernel around unsigned floor.json.
    # Its 49 lines come from deleting that obsolete trusted-input path.
    # D39 adds the gate lifetime, scoped-denial, and reservation state machines.
    # D40 moved regression-only lifecycle and model-budget coverage out of
    # production `src`; D41 reset the ratchet to the measured source count.
    # D42 assigns 83 reserve lines to atomic grant revocation and FIN/EOF
    # detection at the broker's external-send handoff.
    # D44 assigns 312 reserve lines: the pipeline splits at the gate so the
    # operator's wait holds only the adjudication slot, approvals are
    # re-derived against the session after the wait, reusable grants bind
    # method, reasons, and floor, and loop detection is a burst window.
    # D45: task-envelope verdicts stamped on every action and branch-scoped push and PR narrowing.
    # D47: admission-time confidentiality index and shadow payload-flow verdicts on decrypted egress.
    # D48: a model-only upstream idle timeout and charging interrupted model streams their observed usage bound.
    # D49: waiting for in-flight model reservations instead of refusing a request that will fit.
    # D50: marking connection-setup legs not-applicable in the task-envelope verdict.
    # D51: guest-reported process origins carried on every mediated channel, stamped, audited, shown at the gate, and used to gate pushes and pull requests from workspace code.
    # D52: recording model tool-call output and judging lines pushed into protected places against it.
    "keel-kernel": 5_266,
    # D22, D23, D25, and D28 moved 211 unclaimed lines from this evaluator-only
    # crate.
    # D31: immutable built-in restrictions beneath accepted policy.
    # D39 changes the repeated-denial rule to consume exact-scope window facts.
    "keel-policy": 852,
    # D18 moved 100 lines from here to keel-secrets for explicit provider
    # selection, D20 another 100 to keel-input, D23 another 25, and D25 another
    # 30, and D28 another 3. The surplus is still the one D15 named: sized for the vertex-fork
    # comparison Phase 4 measures rather than builds.
    # D32 adds the sole hardened host-Git constructor.
    # D39 stores typed, time-bounded, opaque denial observations.
    # D45: task-envelope verdicts stamped on every action and branch-scoped push and PR narrowing.
    # D47: admission-time confidentiality index and shadow payload-flow verdicts on decrypted egress.
    # D52: recording model tool-call output and judging lines pushed into protected places against it.
    "keel-provenance": 1_321,
    # D22-D25 moved 160 lines of unused headroom to the kernel and input path;
    # D28 moved the remaining 3.
    # D31: public-key audit verification without persisted signing material.
    # D32 adds durable terminal sealing, structural rejection records, and
    # encoded-secret redaction variants.
    # D39 records typed denials and terminal model-reservation outcomes.
    # D45: task-envelope verdicts stamped on every action and branch-scoped push and PR narrowing.
    # D47: admission-time confidentiality index and shadow payload-flow verdicts on decrypted egress.
    # D51: guest-reported process origins carried on every mediated channel, stamped, audited, shown at the gate, and used to gate pushes and pull requests from workspace code.
    # D52: recording model tool-call output and judging lines pushed into protected places against it.
    "keel-audit": 1_228,
    # D16 moved 200 lines here from keel-input for the eventstream usage decoder.
    # The trusted input path is complete, so its surplus was sized for work that
    # Phase 2 has since finished. D17 then added 700 with no donor at all: SigV4
    # signing and credential refresh do not fit behind any crate's surplus, so the
    # total moved instead of a per-crate line.
    # D18 added 100 from keel-provenance so a run can name its provider rather
    # than have one inferred from whichever credential happens to be exported.
    # D22, D24, and D25 moved 80 lines of unused headroom without changing it.
    # D31: structural credential-header injection and endpoint binding.
    # D32 makes GitHub credential acquisition conditional on declared intent.
    # D39 marks the upstream send boundary, drains complete responses, and
    # settles every reservation conservatively on ambiguous post-send failure.
    # D40 moved endpoint and credential-scope regressions to integration
    # support; D41 resets the ratchet after splitting GitHub authorities.
    # D43 assigns 38 reserve lines: credentials substitute only over TLS to
    # port 443, and IPv6 forms embedding a forbidden IPv4 address are denied.
    # D44 assigns 1 line to strip the host V8 proxy credential upstream.
    # D47: admission-time confidentiality index and shadow payload-flow verdicts on decrypted egress.
    # D48: a model-only upstream idle timeout and charging interrupted model streams their observed usage bound.
    # D52: recording model tool-call output and judging lines pushed into protected places against it.
    "keel-secrets": 3_338,
    # D20 added 100 from keel-provenance for the display seam tracker: the trusted
    # terminal owner has to know where a sequence or character ends before it
    # writes a notice into the guest's stream or resumes one after a takeover.
    # D22 added 125 lines for one-key confirmation and the bounded mux framing
    # bridge. The VT parser, screen model, and compositor remain untrusted.
    # D25 added 70 lines for the pre-VM launcher relay. Its menu, filesystem
    # browser, and workspace decisions remain in untrusted processes.
    # D28 added 9 lines for lifecycle detach codes and read-only session status.
    # D30 assigns 25 reserve lines to trusted isolation-mode admission. The
    # engines, launchers, proxies, and SDKs remain untrusted.
    # D31: sandboxed child launch and fail-closed approval/continuation input.
    # D32 adds fail-closed input provenance, exact loopback proxy scoping, and
    # admission/teardown hashing for repository-controlled Git configuration.
    # D33 consumes the remaining reserve for foreground-terminal authenticated
    # mux attachment, restoring secure-attention approvals without trusting a
    # raw same-UID attach socket.
    # D36 moves terminal state into the sandboxed untrusted renderer. Trusted
    # input relays only bounded complete snapshots and requests a fresh one
    # after approval takeover; no terminal model enters the TCB.
    # D39 expires stale pending UI state and ignores late approval input.
    # D40 assigns 113 lines for cooperative sealed stop, persistent-runtime
    # completion status, V8 late-reply handling, and canonical terminal-margin
    # cleanup. Regression-only helpers remain outside production `src`.
    # D41 admits and exposes private-issue authority independently.
    # D45: task-envelope verdicts stamped on every action and branch-scoped push and PR narrowing.
    # D47: admission-time confidentiality index and shadow payload-flow verdicts on decrypted egress.
    "keel-input": 3_326,
}
UNALLOCATED_RESERVE = 669
TOTAL_BUDGET = 16_000
SENSITIVE_TYPES = {
    "keel-secrets": [
        "SecretBytes",
        "CredentialBinding",
        "CredentialVault",
        "OAuthCredential",
        "MitmCa",
    ],
}


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def rust_files(crate: Path) -> list[Path]:
    return sorted((crate / "src").rglob("*.rs"))


def _skip_literal(source: str, index: int) -> int:
    """Return the index just past a comment or literal starting at `index`,
    or `index` itself when none starts there."""
    if source.startswith("//", index):
        end = source.find("\n", index)
        return len(source) if end < 0 else end
    if source.startswith("/*", index):
        depth, index = 1, index + 2
        while index < len(source) and depth:
            if source.startswith("/*", index):
                depth, index = depth + 1, index + 2
            elif source.startswith("*/", index):
                depth, index = depth - 1, index + 2
            else:
                index += 1
        return index
    raw = re.match(r'b?r(#*)"', source[index:])
    if raw:
        closing = '"' + raw.group(1)
        end = source.find(closing, index + raw.end())
        return len(source) if end < 0 else end + len(closing)
    if source[index] == '"' or source.startswith('b"', index):
        index += 2 if source[index] == "b" else 1
        while index < len(source) and source[index] != '"':
            index += 2 if source[index] == "\\" else 1
        return index + 1
    char = re.match(r"b?'(?:\\.[^']*|[^\\'])'", source[index:])
    if char:
        return index + char.end()
    return index


def _item_end(source: str, index: int) -> int:
    """Return the end of the Rust item beginning at `index`: through its
    terminating `;` or its balanced top-level brace block."""
    braces = nesting = 0
    while index < len(source):
        skipped = _skip_literal(source, index)
        if skipped != index:
            index = skipped
            continue
        character = source[index]
        if character in "([":
            nesting += 1
        elif character in ")]":
            nesting -= 1
        elif character == "{":
            braces += 1
        elif character == "}":
            braces -= 1
            if braces == 0 and nesting == 0:
                return index + 1
        elif character == ";" and braces == 0 and nesting == 0:
            return index + 1
        index += 1
    return index


def production_source(path: Path) -> str:
    """Return source with every `#[cfg(test)]` item removed, wherever it sits.

    Cutting at the first attribute would hide all production code after an
    inline test-only helper from the source-pattern invariants."""
    source = path.read_text(encoding="utf-8")
    output = []
    index = 0
    while True:
        start = source.find("#[cfg(test)]", index)
        if start < 0:
            output.append(source[index:])
            return "".join(output)
        output.append(source[index:start])
        index = _item_end(source, start + len("#[cfg(test)]"))


def tokei_line_count(crate: Path) -> int:
    result = subprocess.run(
        ["tokei", "--output", "json", str(crate / "src")],
        check=True,
        capture_output=True,
        text=True,
    )
    report = json.loads(result.stdout)
    return int(report["Total"]["code"])


def check_loc() -> None:
    # One counter everywhere. An approximate local fallback is worse than no local
    # check: it disagrees with CI at the margin, so it fails on crates that are
    # comfortably under budget while the crates that are actually over go unnoticed.
    if shutil.which("tokei") is None:
        fail(
            "I1: tokei is required to count first-party LOC. "
            "Install the pinned version with: cargo install tokei --version 15.0.0"
        )
    allocated = sum(CRATE_BUDGETS.values())
    if allocated + UNALLOCATED_RESERVE != TOTAL_BUDGET:
        fail(
            f"I1: per-crate budgets ({allocated}) plus unallocated reserve "
            f"({UNALLOCATED_RESERVE}) must equal the total budget of {TOTAL_BUDGET}"
        )

    violations = []
    total = 0
    for name, budget in CRATE_BUDGETS.items():
        actual = tokei_line_count(TRUSTED_ROOT / name)
        total += actual
        over = "" if actual <= budget else f"  OVER by {actual - budget}"
        if actual > budget:
            violations.append(f"I1: {name} has {actual} first-party LOC; budget is {budget}")
        print(f"I1: {name}: {actual}/{budget} LOC{over}")
    if total > TOTAL_BUDGET:
        violations.append(
            f"I1: trusted crates have {total} first-party LOC; budget is {TOTAL_BUDGET}"
        )
    # Report every violation. Exiting on the first one hides the rest, which is how
    # a second crate stayed over budget unnoticed for fourteen commits.
    if violations:
        for violation in violations:
            print(f"error: {violation}", file=sys.stderr)
        raise SystemExit(1)
    print(
        f"I1: trusted total: {total}/{TOTAL_BUDGET} LOC "
        f"({allocated} allocated + {UNALLOCATED_RESERVE} reserved; tokei)"
    )


def check_forbid_unsafe() -> None:
    for name in CRATE_BUDGETS:
        crate = TRUSTED_ROOT / name
        roots = [path for path in (crate / "src" / "lib.rs", crate / "src" / "main.rs") if path.exists()]
        if not roots:
            fail(f"I2: {name} has no crate root")
        for root in roots:
            text = root.read_text(encoding="utf-8")
            if "#![forbid(unsafe_code)]" not in text:
                fail(f"I2: {root.relative_to(ROOT)} does not forbid unsafe code")
    print("I2: every trusted crate root forbids unsafe code")


def cargo_metadata() -> dict[str, object]:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def check_dependencies() -> None:
    metadata = cargo_metadata()
    packages = metadata["packages"]
    workspace_names = {package["name"] for package in packages}
    trusted = set(CRATE_BUDGETS)
    untrusted = {
        package["name"]
        for package in packages
        if Path(package["manifest_path"]).is_relative_to(UNTRUSTED_ROOT)
    }
    allow_path = ROOT / "ci" / "trusted-dependencies.toml"
    allowed = tomllib.loads(allow_path.read_text(encoding="utf-8"))["allow"]

    if set(allowed) != trusted:
        fail("I4: trusted dependency allowlist must name every trusted crate exactly once")

    for package in packages:
        name = package["name"]
        if name not in trusted:
            continue
        direct = {dependency["name"] for dependency in package["dependencies"]}
        bad_direction = direct & untrusted
        if bad_direction:
            fail(f"I3: {name} depends on untrusted crate(s): {sorted(bad_direction)}")
        external = direct - workspace_names
        unapproved = external - set(allowed[name])
        stale = set(allowed[name]) - external
        if unapproved:
            fail(f"I4: {name} has unapproved direct dependencies: {sorted(unapproved)}")
        if stale:
            fail(f"I4: {name} allowlist has stale dependencies: {sorted(stale)}")

    print("I3: trusted crates do not depend on untrusted crates")
    print("I4: trusted direct dependencies match the per-crate allowlist")


def check_no_runtime_loading() -> None:
    banned = re.compile(r"\b(libloading|dlopen|dlsym)\b")
    for name in CRATE_BUDGETS:
        for path in rust_files(TRUSTED_ROOT / name):
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if banned.search(line):
                    fail(f"I4: runtime loading marker in {path.relative_to(ROOT)}:{line_number}")
    print("I4: no runtime-loading markers in trusted first-party code")


def check_stamped_visibility() -> None:
    source = (TRUSTED_ROOT / "keel-kernel" / "src" / "lib.rs").read_text(encoding="utf-8")
    declaration = re.search(r"pub struct Stamped\s*\{(?P<body>.*?)\n\}", source, re.DOTALL)
    if declaration is None:
        fail("I5: keel-kernel must declare Stamped")
    public_field = re.search(r"^\s*pub(?:\([^)]*\))?\s+\w+\s*:", declaration["body"], re.MULTILINE)
    if public_field is not None:
        fail("I5: Stamped fields must remain private")
    preceding = source[max(0, declaration.start() - 500) : declaration.start()]
    if "```compile_fail" not in preceding:
        fail("I5: Stamped privacy must have a compile-fail doctest")
    print("I5: Stamped has private fields and a compile-fail construction test")


def check_authorization_boundary() -> None:
    forbidden_dependencies = {"cedar-policy", "regorus", "opa"}
    offline_compiler_dependencies = {"keel-compile": {"cedar-policy", "regorus"}}
    forbidden_source = {
        r"\bimpl\s+(?:keel_kernel::)?Policy\s+for\b": "implements the trusted Policy trait",
        r"\bimpl\s+(?:keel_kernel::)?Gate\s+for\b": "implements the trusted Gate trait",
        r"\bGateDecision::(?:Approve|Deny)\b": "creates a trusted gate decision",
        r"\bChannelRegistry::new\b": "constructs an authorization channel registry",
    }
    for manifest_path in sorted(UNTRUSTED_ROOT.glob("*/Cargo.toml")):
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        dependencies = set(manifest.get("dependencies", {}))
        allowed_offline = offline_compiler_dependencies.get(manifest_path.parent.name, set())
        forbidden = (dependencies & forbidden_dependencies) - allowed_offline
        if forbidden:
            fail(
                f"I6: {manifest_path.parent.name} depends on authorization engine(s): "
                f"{sorted(forbidden)}"
            )
    for path in sorted(UNTRUSTED_ROOT.rglob("*")):
        if path.suffix in {".cedar", ".cedarschema"}:
            fail(f"I6: policy artifact exists outside the TCB: {path.relative_to(ROOT)}")
    for crate in sorted(UNTRUSTED_ROOT.iterdir()):
        if not crate.is_dir():
            continue
        for path in rust_files(crate):
            source = production_source(path)
            for pattern, reason in forbidden_source.items():
                if re.search(pattern, source):
                    fail(f"I6: {path.relative_to(ROOT)} {reason}")
    print("I6: only the offline compiler carries policy oracles; no untrusted live decision path")


def check_secret_custody() -> None:
    forbidden_traits = {"Clone", "Debug", "Deserialize", "Serialize"}
    for crate_name, type_names in SENSITIVE_TYPES.items():
        source = (TRUSTED_ROOT / crate_name / "src" / "lib.rs").read_text(encoding="utf-8")
        for type_name in type_names:
            declaration = re.search(
                rf"(?P<derives>(?:#\[derive\([^]]*\)\]\s*)*)pub struct {type_name}\b",
                source,
            )
            if declaration is None:
                fail(f"I7: sensitive type {type_name} must remain in {crate_name}")
            derives = set(re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", declaration["derives"]))
            exposed = derives & forbidden_traits
            if exposed:
                fail(f"I7: sensitive type {type_name} derives {sorted(exposed)}")
            trait_impl = re.search(
                rf"\bimpl(?:<[^>]*>)?\s+(?:serde::)?"
                rf"(?:Serialize|Deserialize|Debug|Clone)\b[^{{]*\bfor\s+{type_name}\b",
                source,
            )
            if trait_impl is not None:
                fail(f"I7: sensitive type {type_name} implements an exposing trait")
    secrets = (TRUSTED_ROOT / "keel-secrets" / "src" / "lib.rs").read_text(encoding="utf-8")
    drop_impl = re.search(r"impl Drop for SecretBytes\s*\{(?P<body>.*?)\n\}", secrets, re.DOTALL)
    if drop_impl is None or ".zeroize()" not in drop_impl["body"]:
        fail("I7: SecretBytes must zero its allocation on drop")
    if secrets.count("```compile_fail") < 2:
        fail("I7: secret serialization and formatting must have compile-fail doctests")
    print("I7: credential and signing-key types are opaque, non-serializable, and zeroized")


def check_channel_registry() -> None:
    source = (TRUSTED_ROOT / "keel-kernel" / "src" / "lib.rs").read_text(encoding="utf-8")
    support = TRUSTED_ROOT / "keel-kernel" / "tests" / "support"
    evidence = source + "\n" + "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(support.rglob("*.rs"))
    )
    required = [
        "pub gate_class: GateClass",
        "KernelError::MissingChannel",
        "KernelError::UnexpectedChannel",
        "KernelError::DuplicateChannel",
        "startup_rejects_a_missing_channel_declaration",
    ]
    missing = [marker for marker in required if marker not in evidence]
    if missing:
        fail(f"I8: channel-registry enforcement is incomplete: {missing}")
    print("I8: startup-validated channels require exactly one declared gate class")


def check_operator_input_boundary() -> None:
    metadata = cargo_metadata()
    packages = {package["name"]: package for package in metadata["packages"]}
    direct = {dependency["name"] for dependency in packages["keel-input"]["dependencies"]}
    untrusted = {
        package["name"]
        for package in packages.values()
        if Path(package["manifest_path"]).is_relative_to(UNTRUSTED_ROOT)
    }
    if direct & untrusted:
        fail(f"I9: keel-input depends on untrusted crate(s): {sorted(direct & untrusted)}")

    # The guest confinement module names the *guest's* /dev/tty in its Landlock
    # rules. It is compiled only into the Linux guest binary, so it can never
    # open the host operator's terminal; the gate below keeps that true.
    guest_only = UNTRUSTED_ROOT / "keel-mcp" / "src" / "bin" / "keel-mcp-guest" / "confine.rs"
    guest_binary = (UNTRUSTED_ROOT / "keel-mcp" / "src" / "bin" / "keel-mcp-guest.rs").read_text(
        encoding="utf-8"
    )
    if '#[cfg(target_os = "linux")]\n#[path = "keel-mcp-guest/confine.rs"]' not in guest_binary:
        fail("I9: the guest confinement module must be compiled only for the Linux guest")
    for crate in sorted(UNTRUSTED_ROOT.iterdir()):
        if not crate.is_dir():
            continue
        for path in rust_files(crate):
            if path == guest_only:
                continue
            if '"/dev/tty"' in production_source(path):
                fail(f"I9: untrusted code opens the operator tty: {path.relative_to(ROOT)}")

    runtime = (TRUSTED_ROOT / "keel-input" / "src" / "bin" / "keel-input-runtime.rs").read_text(
        encoding="utf-8"
    )
    renderer = (
        UNTRUSTED_ROOT / "keel-render" / "src" / "bin" / "keel-render-spike.rs"
    ).read_text(encoding="utf-8")
    acceptance = (
        TRUSTED_ROOT / "keel-input" / "tests" / "secure_attention.rs"
    ).read_text(encoding="utf-8")
    if "io::stdin().lock()" not in runtime or "route_input(" not in runtime:
        fail("I9: trusted input runtime must exclusively classify operator stdin")
    if "is_terminal()" not in renderer or "renderer inherited a tty" not in renderer:
        fail("I9: untrusted renderer must fail when it inherits a tty")
    for test_name in [
        "normal_keys_and_fake_prompts_cannot_approve",
        "escape_denies_and_renderer_frames_are_suspended_in_trusted_mode",
        "terminal_gate_renders_the_kernel_action_and_returns_operator_approval",
    ]:
        if test_name not in acceptance:
            fail(f"I9: secure-attention acceptance test is missing: {test_name}")
    print("I9: only keel-input owns operator stdin; the renderer rejects tty inheritance")


def check_policy_artifact() -> None:
    source = (TRUSTED_ROOT / "keel-policy" / "src" / "lib.rs").read_text(encoding="utf-8")
    tests = (
        TRUSTED_ROOT / "keel-policy" / "tests" / "stateful_rules.rs"
    ).read_text(encoding="utf-8")
    required = [
        'directory.join("bundle.sha256")',
        "declared != expected",
        "actual != expected",
    ]
    missing = [marker for marker in required if marker not in source]
    if missing or "loader_requires_the_pinned_content_hash" not in tests:
        fail("I10: policy loader is not pinned to a tested content hash")
    print("I10: policy bundles require matching caller, manifest, and content hashes")


def check_structural_invariants() -> None:
    source = (TRUSTED_ROOT / "keel-kernel" / "src" / "lib.rs").read_text(encoding="utf-8")
    support = TRUSTED_ROOT / "keel-kernel" / "tests" / "support"
    evidence = source + "\n" + "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(support.rglob("*.rs"))
    )
    required = [
        "matches!(asserted.target, Target::Protected(_))",
        "KernelError::ProtectedStateMutation",
        "all_protected_kernel_state_is_never_policy_reachable",
    ]
    missing = [marker for marker in required if marker not in evidence]
    if missing:
        fail(f"I11: protected-state enforcement is incomplete: {missing}")
    print("I11: every protected kernel state is rejected before policy and gate evaluation")


def check_git_invocations() -> None:
    raw_git = re.compile(r"(?:Process)?Command::new\(\s*\"git\"\s*\)")
    for root in (TRUSTED_ROOT, UNTRUSTED_ROOT):
        for path in sorted(root.rglob("*.rs")):
            if "tests" in path.relative_to(root).parts:
                continue
            if raw_git.search(production_source(path)):
                fail(
                    "I12: production Git invocation bypasses the hardened constructor: "
                    f"{path.relative_to(ROOT)}"
                )
    provenance = (TRUSTED_ROOT / "keel-provenance" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    gitd = (UNTRUSTED_ROOT / "keel-gitd" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    hardening = [
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "core.fsmonitor=false",
        "core.hooksPath=/dev/null",
        "credential.helper=",
        "GIT_TERMINAL_PROMPT",
    ]
    for name, source in (("trusted_git_command", provenance), ("keel-gitd", gitd)):
        missing = [marker for marker in hardening if marker not in source]
        if missing:
            fail(f"I12: {name} Git hardening is incomplete: {missing}")
    print("I12: production Git invocations use hardened, non-interactive configuration")


def main() -> None:
    check_loc()
    check_forbid_unsafe()
    check_dependencies()
    check_no_runtime_loading()
    check_stamped_visibility()
    check_authorization_boundary()
    check_secret_custody()
    check_channel_registry()
    check_operator_input_boundary()
    check_policy_artifact()
    check_structural_invariants()
    check_git_invocations()
    print("Phase 1 invariants I1-I12: PASS")


if __name__ == "__main__":
    main()
