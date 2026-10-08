#!/usr/bin/env python3
"""Headless end-to-end suite for Keel on an Apple silicon Mac.

Runs every workflow that needs no operator answer against the installed
runtime, checks each case's output and audit records, then verifies every
audit chain and runs the reports.

    python3 ci/e2e.py              # every case whose credentials are present
    python3 ci/e2e.py --list
    python3 ci/e2e.py --case claude-reply --case build-offline

The suite never answers the trusted terminal. Each run's input is /dev/null,
so a case that raises an approval or admission screen cannot proceed, and the
suite counts that as a failure. Workflows that need an operator decision
(approvals, grants, admission screens, the host V8 confirmation) are in the
manual runbook, docs/E2E.md.

Credentials come from the environment, as for a normal run. Cases whose
credentials are absent are reported as SKIP.

Results go to ~/.keel/e2e-results/<UTC time>/: summary.md, summary.json, one
transcript per case, and an isolated state directory with every session.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78]")
PENDING = "KEEL APPROVAL PENDING"
ADMISSION = ("KEEL TASK ADMISSION", "KEEL TRUSTED ADMISSION")


def clean(raw: bytes) -> str:
    return ANSI.sub("", raw.decode("utf-8", "replace")).replace("\r", "")


@dataclass
class Result:
    name: str
    status: str = "PASS"
    checks: list[tuple[str, bool, str]] = field(default_factory=list)
    sessions: list[str] = field(default_factory=list)
    seconds: float = 0.0
    note: str = ""

    def check(self, label: str, passed: bool, detail: str = "") -> None:
        self.checks.append((label, passed, detail))
        if not passed:
            self.status = "FAIL"


class Suite:
    def __init__(self, keel: Path, root: Path) -> None:
        self.keel = keel
        self.root = root
        self.state = root / "state"
        self.workspaces = root / "workspaces"
        self.transcripts = root / "transcripts"
        for directory in (self.state, self.workspaces, self.transcripts):
            directory.mkdir(parents=True, exist_ok=True)
        self.environment = dict(os.environ, KEEL_STATE_DIR=str(self.state))

    # -- helpers -----------------------------------------------------------

    def workspace(self, name: str, files: dict[str, str]) -> Path:
        path = self.workspaces / name
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(parents=True)
        for relative, content in {"README.md": f"# {name}\n", **files}.items():
            (path / relative).write_text(content)
        git = ["git", "-c", "user.name=keel-e2e", "-c", "user.email=e2e@example.invalid"]
        subprocess.run(["git", "init", "-q"], cwd=path, check=True)
        subprocess.run([*git, "add", "."], cwd=path, check=True)
        subprocess.run([*git, "commit", "-qm", "e2e fixture"], cwd=path, check=True)
        return path

    def run(
        self,
        name: str,
        arguments: list[str],
        cwd: Path,
        timeout: int = 420,
        extra_env: dict[str, str] | None = None,
    ) -> tuple[int | None, str]:
        """Runs `keel ARGUMENTS` under script(1) with no operator input."""
        transcript = self.transcripts / f"{name}.typescript"
        environment = dict(self.environment, **(extra_env or {}))
        try:
            completed = subprocess.run(
                ["script", "-q", str(transcript), str(self.keel), *arguments],
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
            )
            code: int | None = completed.returncode
        except subprocess.TimeoutExpired:
            code = None
        text = clean(transcript.read_bytes()) if transcript.exists() else ""
        return code, text

    def sessions_since(self, before: set[str]) -> list[str]:
        root = self.state / "sessions"
        current = {entry.name for entry in root.iterdir()} if root.exists() else set()
        return sorted(current - before)

    def session_names(self) -> set[str]:
        root = self.state / "sessions"
        return {entry.name for entry in root.iterdir()} if root.exists() else set()

    def records(self, session: str) -> list[dict]:
        directory = self.state / "sessions" / session
        chains = sorted(directory.glob("audit-*.ndjson"))
        if not chains:
            return []
        return [json.loads(line)["payload"] for line in chains[-1].read_text().splitlines() if line]

    def manifest(self, session: str) -> dict | None:
        for record in self.records(session):
            if record["event"] == "kernel.run-admitted":
                return json.loads(record["fields"]["manifest"])
        return None

    def run_case(
        self,
        result: Result,
        arguments: list[str],
        cwd: Path,
        expect: list[str],
        timeout: int = 420,
        extra_env: dict[str, str] | None = None,
    ) -> str:
        """Runs one session-producing case and applies the common checks."""
        before = self.session_names()
        started = time.monotonic()
        code, text = self.run(result.name, arguments, cwd, timeout, extra_env)
        result.seconds += time.monotonic() - started
        result.sessions += self.sessions_since(before)
        result.check("finished before the timeout", code is not None, f"exit {code}")
        result.check("no approval was raised", PENDING not in text)
        result.check(
            "no admission screen was raised",
            not any(marker in text for marker in ADMISSION),
        )
        for marker in expect:
            result.check(f"output contains {marker!r}", marker in text)
        for session in result.sessions:
            manifest = self.manifest(session)
            result.check(f"{session} recorded an admission manifest", manifest is not None)
            presented = [
                record
                for record in self.records(session)
                if record["fields"].get("prompt_presented") == "true"
            ]
            result.check(f"{session} presented no operator prompt", not presented)
        return text


# ---------------------------------------------------------------------------
# Cases. Each returns a Result; `requires` names the environment it needs.

V8_SCRIPT = 'console.log("E2E-V8-OK");\n'

CONFINEMENT_SCRIPT = """\
uname -r
if kill -0 1 2>/dev/null; then echo E2E-SIGNAL-ALLOWED; else echo E2E-SIGNAL-DENIED; fi
keel-mcp-guest confine-check
"""

BROWSER_CLI_SCRIPT = """\
agent-browser open "data:text/html,<title>E2E-BROWSER-CLI-OK</title><h1>hi</h1>" >/dev/null
agent-browser get title
agent-browser screenshot >/dev/null && echo E2E-SCREENSHOT-OK
"""

BUILD_SCRIPT = """\
set -e
# A fresh directory per run, so running the script twice still works.
work=$(mktemp -d /tmp/e2e-build.XXXXXX)
printf '#include <stdio.h>\\nint main(void){puts("E2E-C-OK");return 0;}\\n' > "$work/h.c"
gcc "$work/h.c" -o "$work/h" && "$work/h"
cd "$work" && cargo new -q rhello && cd rhello && cargo build -q --offline
./target/debug/rhello | sed 's/Hello, world!/E2E-RUST-OK/'
mkdir -p "$work/ghello" && cd "$work/ghello"
printf 'package main\\nimport "fmt"\\nfunc main(){fmt.Println("E2E-GO-OK")}\\n' > main.go
go mod init ghello >/dev/null 2>&1 && go build -o g . && ./g
python3 -m venv "$work/venv" && "$work/venv/bin/pip" --version >/dev/null && echo E2E-PIP-OK
npm --version >/dev/null && echo E2E-NPM-OK
free -m | awk '/Mem:/{print "E2E-MEM-MIB", $2}'
"""


def run_script_prompt(script: str) -> str:
    return (
        f"Run `bash {script}` with the Bash tool and reply with its complete output verbatim."
    )


def case_doctor(suite: Suite) -> Result:
    result = Result("doctor")
    started = time.monotonic()
    completed = subprocess.run(
        [str(suite.keel), "doctor"], env=suite.environment, capture_output=True, text=True
    )
    result.seconds = time.monotonic() - started
    output = completed.stdout + completed.stderr
    (suite.transcripts / "doctor.txt").write_text(output)
    result.check("doctor exits 0", completed.returncode == 0, f"exit {completed.returncode}")
    for line in ("guest root disk", "supports Landlock scoping", "VZ backend has virtualization"):
        result.check(f"doctor reports {line!r}", line in output)
    return result


def case_v8_vm(suite: Suite) -> Result:
    result = Result("v8-vm")
    workspace = suite.workspace("v8-vm", {"hello.mjs": V8_SCRIPT})
    suite.run_case(result, ["run", "--isolation", "vm-v8", "v8", "hello.mjs"], workspace, ["E2E-V8-OK"])
    for session in result.sessions:
        manifest = suite.manifest(session) or {}
        result.check("manifest names the vm-v8 isolation", manifest.get("run", {}).get("isolation") == "vm-v8")
        result.check("manifest records the root disk digest", bool(manifest.get("artifacts", {}).get("rootfs")))
    return result


def case_claude_reply(suite: Suite) -> Result:
    result = Result("claude-reply")
    workspace = suite.workspace("claude-reply", {})
    suite.run_case(result, ["run", "claude", "-p", "Reply with exactly: E2E-CLAUDE-OK"], workspace, ["E2E-CLAUDE-OK"])
    for session in result.sessions:
        settled = [
            record
            for record in suite.records(session)
            if record["event"] == "kernel.model-reservation"
            and record["fields"].get("outcome") == "settled-actual"
        ]
        result.check("model usage was settled from trusted usage", bool(settled))
        context = [record for record in suite.records(session) if record["event"] == "kernel.model-context"]
        result.check("the context digest log recorded requests", bool(context))
    return result


def case_guest_confinement(suite: Suite) -> Result:
    result = Result("guest-confinement")
    workspace = suite.workspace("guest-confinement", {"check.sh": CONFINEMENT_SCRIPT})
    text = suite.run_case(
        result,
        ["run", "claude", "-p", run_script_prompt("check.sh"), "--allowedTools", "Bash"],
        workspace,
        ["E2E-SIGNAL-DENIED", "6.12."],
    )
    result.check("Landlock ABI 6 is active", re.search(r'"landlock_abi"\s*:\s*6', text) is not None)
    return result


def case_browser_mcp(suite: Suite) -> Result:
    result = Result("browser-mcp")
    workspace = suite.workspace("browser-mcp", {})
    prompt = (
        "Use the browser MCP tools: open data:text/html,<title>E2E-BROWSER-MCP-OK</title><h1>hi</h1>, "
        "take a screenshot, then reply with only the page title."
    )
    suite.run_case(result, ["run", "claude", "-p", prompt, "--allowedTools", "mcp__browser"], workspace, ["E2E-BROWSER-MCP-OK"])
    shots = list((workspace / ".keel-browser" / "screenshots").glob("*.png"))
    result.check("a screenshot landed in the workspace", bool(shots))
    status = subprocess.run(["git", "status", "--porcelain"], cwd=workspace, capture_output=True, text=True).stdout
    result.check("the browser output directory is ignored by Git", status.strip() == "", status.strip())
    return result


def case_browser_cli(suite: Suite) -> Result:
    result = Result("browser-cli")
    workspace = suite.workspace("browser-cli", {"browse.sh": BROWSER_CLI_SCRIPT})
    suite.run_case(
        result,
        ["run", "claude", "-p", run_script_prompt("browse.sh"), "--allowedTools", "Bash"],
        workspace,
        ["E2E-BROWSER-CLI-OK", "E2E-SCREENSHOT-OK"],
    )
    return result


def case_build_offline(suite: Suite) -> Result:
    result = Result("build-offline")
    workspace = suite.workspace("build-offline", {"build.sh": BUILD_SCRIPT})
    text = suite.run_case(
        result,
        ["run", "--memory", "4", "claude", "-p", run_script_prompt("build.sh"), "--allowedTools", "Bash"],
        workspace,
        ["E2E-C-OK", "E2E-RUST-OK", "E2E-GO-OK", "E2E-PIP-OK", "E2E-NPM-OK"],
        timeout=600,
    )
    memory = re.search(r"E2E-MEM-MIB (\d+)", text)
    result.check("--memory 4 reached the guest", bool(memory) and int(memory.group(1)) > 3500, memory.group(0) if memory else "")
    for session in result.sessions:
        result.check("manifest records memory_gib 4", (suite.manifest(session) or {}).get("run", {}).get("memory_gib") == 4)
    return result


def case_refusals(suite: Suite) -> Result:
    """Configurations Keel must refuse before any VM boots."""
    result = Result("refusals")
    workspace = suite.workspace("refusals", {})
    cases = [
        ("unknown profile", ["run", "--profile", "recon", "claude"], {}, "profile"),
        ("malformed triage scope", ["run", "--profile", "triage", "--scope", "*", "claude"], {}, "scope"),
        (
            "triage with an unapproved provider",
            ["run", "--profile", "triage", "--scope", "example.com", "claude"],
            {"KEEL_TRIAGE_PROVIDERS": "openrouter"},
            "approved model providers",
        ),
        ("zero memory", ["run", "--memory", "0", "claude"], {}, "--memory"),
        ("unknown auth", ["run", "--auth", "guess", "claude"], {}, "--auth"),
    ]
    before = suite.session_names()
    for label, arguments, extra, message in cases:
        started = time.monotonic()
        code, text = suite.run(f"refusals-{label.replace(' ', '-')}", arguments, workspace, 120, extra)
        result.seconds += time.monotonic() - started
        result.check(f"{label}: refused", code not in (0, None), f"exit {code}")
        result.check(f"{label}: names the reason", message in text, message)
    booted = [
        session
        for session in suite.sessions_since(before)
        if any(record["event"] == "kernel.run-admitted" for record in suite.records(session))
    ]
    result.check("no refused run reached admission", not booted, ", ".join(booted))
    return result


def case_interrupted(suite: Suite) -> Result:
    """A session whose trusted runtime dies is reported as interrupted."""
    result = Result("interrupted")
    workspace = suite.workspace("interrupted", {})
    before = suite.session_names()
    transcript = suite.transcripts / "interrupted.typescript"
    started = time.monotonic()
    process = subprocess.Popen(
        [
            "script", "-q", str(transcript), str(suite.keel), "run", "claude", "-p",
            "Run `sleep 300` with the Bash tool, then reply DONE.", "--allowedTools", "Bash",
        ],
        cwd=workspace,
        env=suite.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    chain = None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and chain is None:
        for session in suite.sessions_since(before):
            chains = list((suite.state / "sessions" / session).glob("audit-*.ndjson"))
            if chains and any("settled-actual" in line for line in chains[0].read_text().splitlines()):
                chain = chains[0]
        time.sleep(2)
    result.check("the session started and called the model", chain is not None)
    if chain is not None:
        writer = int(chain.name.split("-")[1])
        # Nothing yet tears down the runtime and VM below a trusted runtime
        # that dies (verified teardown is unbuilt). Record whether they stop
        # on their own, then clean up so the case leaves nothing running.
        descendants = descendants_of(writer)
        os.kill(writer, signal.SIGKILL)
        time.sleep(20)
        survivors = [pid for pid in descendants if alive(pid)]
        result.note = (
            f"{len(survivors)} of {len(descendants)} processes below the trusted runtime "
            "outlived it by 20s and were killed by the suite (known gap: no verified teardown)"
            if survivors
            else "the runtime and VM stopped with the trusted runtime"
        )
        for pid in survivors:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        result.sessions.append(chain.parent.name)
    try:
        process.wait(timeout=120)
    except subprocess.TimeoutExpired:
        process.kill()
    result.seconds = time.monotonic() - started
    if chain is not None:
        status = subprocess.run(
            [str(suite.keel), "status", chain.parent.name], env=suite.environment, capture_output=True, text=True
        )
        result.check("keel status reports state: interrupted", "state: interrupted" in status.stdout, status.stdout.splitlines()[1] if status.stdout else status.stderr)
    return result


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def descendants_of(pid: int) -> list[int]:
    found, pending = [], [pid]
    while pending:
        children = subprocess.run(["pgrep", "-P", str(pending.pop())], capture_output=True, text=True).stdout.split()
        found += [int(child) for child in children]
        pending += [int(child) for child in children]
    return found


def case_provider_anthropic(suite: Suite) -> Result:
    result = Result("provider-anthropic")
    workspace = suite.workspace("provider-anthropic", {})
    suite.run_case(
        result,
        ["run", "--auth", "api-key", "--model", "claude-sonnet-4-6", "claude", "-p", "Reply with exactly: E2E-ANTHROPIC-OK"],
        workspace,
        ["E2E-ANTHROPIC-OK"],
    )
    for session in result.sessions:
        result.check("manifest names the anthropic provider", (suite.manifest(session) or {}).get("model", {}).get("provider") == "anthropic")
    return result


CASES: dict[str, tuple[Callable[[Suite], Result], list[str]]] = {
    "doctor": (case_doctor, []),
    "v8-vm": (case_v8_vm, []),
    "claude-reply": (case_claude_reply, []),
    "guest-confinement": (case_guest_confinement, []),
    "browser-mcp": (case_browser_mcp, []),
    "browser-cli": (case_browser_cli, []),
    "build-offline": (case_build_offline, []),
    "refusals": (case_refusals, []),
    "interrupted": (case_interrupted, []),
    "provider-anthropic": (case_provider_anthropic, ["ANTHROPIC_API_KEY"]),
}


# ---------------------------------------------------------------------------
# Verification and reports


def verify_and_report(suite: Suite, results: list[Result]) -> dict:
    verification = {}
    interrupted = {session for result in results if result.name == "interrupted" for session in result.sessions}
    for result in results:
        for session in result.sessions:
            directory = suite.state / "sessions" / session
            chains = sorted(directory.glob("audit-*.ndjson"))
            if not chains:
                continue
            completed = subprocess.run(
                [str(suite.keel), "audit", "verify", str(chains[-1]), str(chains[-1].with_suffix(".key"))],
                env=suite.environment, capture_output=True, text=True,
            )
            line = (completed.stdout or completed.stderr).strip().splitlines()[-1:] or [""]
            verification[session] = line[0]
            expected = "VERIFIED PREFIX" if session in interrupted else "VERIFIED AND SEALED"
            result.check(f"{session} audit verifies ({expected})", expected in line[0], line[0])
    sessions = sorted(verification)
    reports = {}
    for flag in ("--axes", "--context"):
        completed = subprocess.run(
            [str(suite.keel), "report", flag, *sessions], env=suite.environment, capture_output=True, text=True
        )
        reports[flag] = completed.stdout + completed.stderr
        (suite.root / f"report{flag.replace('--', '-')}.txt").write_text(reports[flag])
    return {"verification": verification, "reports": reports}


def write_summary(suite: Suite, results: list[Result], extra: dict) -> None:
    lines = [
        f"# Keel headless end-to-end run — {suite.root.name}",
        "",
        "| Case | Status | Time | Sessions | Note |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for result in results:
        lines.append(
            f"| {result.name} | **{result.status}** | {result.seconds:.0f}s | {', '.join(result.sessions) or '-'} | {result.note} |"
        )
    lines += ["", "## Checks", ""]
    for result in results:
        lines.append(f"### {result.name} — {result.status}")
        for label, passed, detail in result.checks:
            mark = "PASS" if passed else "FAIL"
            lines.append(f"- {mark}: {label}" + (f" — `{detail}`" if detail and not passed else ""))
        lines.append("")
    lines += ["## Audit verification", ""]
    lines += [f"- `{session}`: {line}" for session, line in extra["verification"].items()]
    for flag, output in extra["reports"].items():
        lines += ["", f"## keel report {flag}", "", "```text", output.strip(), "```"]
    (suite.root / "summary.md").write_text("\n".join(lines) + "\n")
    (suite.root / "summary.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "name": result.name,
                        "status": result.status,
                        "seconds": round(result.seconds, 1),
                        "sessions": result.sessions,
                        "note": result.note,
                        "checks": [{"label": l, "passed": p, "detail": d} for l, p, d in result.checks],
                    }
                    for result in results
                ],
                **extra,
            },
            indent=2,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", action="append", choices=sorted(CASES), help="run only these cases")
    parser.add_argument("--list", action="store_true", help="list cases and exit")
    parser.add_argument("--keel", default=str(Path.home() / ".local/bin/keel"), help="installed keel launcher")
    parser.add_argument("--out", help="result directory")
    arguments = parser.parse_args()
    if arguments.list:
        for name, (_, requires) in CASES.items():
            print(f"{name}{'  (needs ' + ', '.join(requires) + ')' if requires else ''}")
        return 0
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = Path(arguments.out) if arguments.out else Path.home() / ".keel" / "e2e-results" / stamp
    suite = Suite(Path(arguments.keel), root)
    results = []
    for name in arguments.case or list(CASES):
        function, requires = CASES[name]
        missing = [variable for variable in requires if not os.environ.get(variable)]
        if missing:
            results.append(Result(name, status="SKIP", note=f"needs {', '.join(missing)}"))
            print(f"SKIP  {name}: needs {', '.join(missing)}", flush=True)
            continue
        print(f"RUN   {name} ...", flush=True)
        result = function(suite)
        results.append(result)
        print(f"{result.status:5} {name} ({result.seconds:.0f}s)", flush=True)
    extra = verify_and_report(suite, results)
    write_summary(suite, results, extra)
    print(f"\nSummary: {root / 'summary.md'}")
    return 0 if all(result.status in ("PASS", "SKIP") for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
