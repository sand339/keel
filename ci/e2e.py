#!/usr/bin/env python3
"""Headless end-to-end suite for Keel on an Apple silicon Mac or a Linux KVM host.

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
import shlex
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


# Slow hosts, such as a nested VM, set KEEL_E2E_TIMEOUT_SCALE to stretch every
# wait, so the suite tests correctness rather than speed.
TIMEOUT_SCALE = float(os.environ.get("KEEL_E2E_TIMEOUT_SCALE", "1"))


def scaled(seconds: float) -> float:
    return seconds * TIMEOUT_SCALE


def under_script(transcript: Path, command: list[str]) -> list[str]:
    """Runs COMMAND on a pseudo-terminal, recording it to TRANSCRIPT. BSD
    script(1) takes the command as arguments; util-linux takes one shell line."""
    if sys.platform == "darwin":
        return ["script", "-q", str(transcript), *command]
    return ["script", "-q", "-e", "-c", shlex.join(command), str(transcript)]


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
                under_script(transcript, [str(self.keel), *arguments]),
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=scaled(timeout),
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
    backend = "bubblewrap can create" if sys.platform == "linux" else "VZ backend has virtualization"
    for line in ("guest root disk", "supports Landlock scoping", backend):
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
        timeout=scaled(600),
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
        ("malformed scope", ["run", "--profile", "scoped", "--scope", "*", "claude"], {}, "scope"),
        ("retired triage name", ["run", "--profile", "triage", "--scope", "example.com", "claude"], {}, "--profile scoped"),
        (
            "scoped run with an unapproved provider",
            ["run", "--profile", "scoped", "--scope", "example.com", "claude"],
            {"KEEL_SCOPED_PROVIDERS": "openrouter"},
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
    """A session whose trusted runtime dies is stale until `keel recover`
    releases what its chain records, and nothing below it survives."""
    result = Result("interrupted")
    workspace = suite.workspace("interrupted", {})
    before = suite.session_names()
    transcript = suite.transcripts / "interrupted.typescript"
    started = time.monotonic()
    process = subprocess.Popen(
        under_script(transcript, [
            str(suite.keel), "run", "claude", "-p",
            "Run `sleep 300` with the Bash tool, then reply DONE.", "--allowedTools", "Bash",
        ]),
        cwd=workspace,
        env=suite.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    chain = None
    deadline = time.monotonic() + scaled(120)
    while time.monotonic() < deadline and chain is None:
        for session in suite.sessions_since(before):
            chains = list((suite.state / "sessions" / session).glob("audit-*.ndjson"))
            if chains and any("settled-actual" in line for line in chains[0].read_text().splitlines()):
                chain = chains[0]
        time.sleep(2)
    result.check("the session started and called the model", chain is not None)
    if chain is not None:
        writer = int(chain.name.split("-")[1])
        descendants = descendants_of(writer)
        os.kill(writer, signal.SIGKILL)
        time.sleep(5)
    try:
        process.wait(timeout=scaled(120))
    except subprocess.TimeoutExpired:
        process.kill()
    if chain is not None:
        session = chain.parent.name
        result.sessions.append(session)
        stale = subprocess.run(
            [str(suite.keel), "status", session], env=suite.environment, capture_output=True, text=True
        )
        result.check("keel status reports state: stale", "state: stale" in stale.stdout, first_line_after_session(stale))
        orphaned = [pid for pid in descendants if alive(pid)]
        result.note = f"{len(orphaned)} of {len(descendants)} processes below the killed runtime were still running when recovery began"
        recover = subprocess.run(
            [str(suite.keel), "recover", session], env=suite.environment, capture_output=True, text=True
        )
        result.check("keel recover releases what the chain records", recover.returncode == 0, (recover.stdout + recover.stderr).strip())
        survivors = [pid for pid in descendants if alive(pid)]
        result.check(
            "nothing below the killed trusted runtime survives recovery",
            not survivors,
            f"{len(survivors)} of {len(descendants)} still running; the suite kills them",
        )
        for pid in survivors:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        recovered = subprocess.run(
            [str(suite.keel), "status", session], env=suite.environment, capture_output=True, text=True
        )
        result.check("keel status then reports state: recovered", "state: recovered\n" in recovered.stdout, first_line_after_session(recovered))
    result.seconds = time.monotonic() - started
    return result


def case_persistent_stop(suite: Suite) -> Result:
    """`keel stop` on a persistent session returns only after a verified
    teardown receipt, and leaves no supervisor file or runtime process."""
    result = Result("persistent-stop")
    workspace = suite.workspace("persistent-stop", {})
    before = suite.session_names()
    transcript = suite.transcripts / "persistent-stop.typescript"
    started = time.monotonic()
    process = subprocess.Popen(
        under_script(transcript, [
            str(suite.keel), "run", "--keep-alive", "claude", "-p",
            "Run `sleep 300` with the Bash tool, then reply DONE.", "--allowedTools", "Bash",
        ]),
        cwd=workspace,
        env=suite.environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    chain = None
    deadline = time.monotonic() + scaled(120)
    while time.monotonic() < deadline and chain is None:
        for session in suite.sessions_since(before):
            chains = list((suite.state / "sessions" / session).glob("audit-*.ndjson"))
            if chains and any("settled-actual" in line for line in chains[0].read_text().splitlines()):
                chain = chains[0]
        time.sleep(2)
    result.check("the persistent session started and called the model", chain is not None)
    if chain is not None:
        session = chain.parent.name
        result.sessions.append(session)
        descendants = descendants_of(int(chain.name.split("-")[1]))
        stop = subprocess.run(
            [str(suite.keel), "stop", session], env=suite.environment, capture_output=True, text=True, timeout=scaled(60)
        )
        result.check("keel stop succeeds and names its receipt", stop.returncode == 0 and "teardown receipt" in stop.stdout, (stop.stdout + stop.stderr).strip())
        directory = chain.parent
        result.check("the receipt sits beside the chain", chain.with_suffix(".receipt.json").exists())
        leftovers = [name for name in ("attach.sock", "attach.pid") if (directory / name).exists()]
        result.check("no supervisor file remains", not leftovers, ", ".join(leftovers))
        survivors = [pid for pid in descendants if alive(pid)]
        result.check("no runtime process survives the stop", not survivors, f"{len(survivors)} of {len(descendants)} still running")
        for pid in survivors:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        status = subprocess.run(
            [str(suite.keel), "status", session], env=suite.environment, capture_output=True, text=True
        )
        result.check("keel status reports closed with a verified receipt", "state: closed\n" in status.stdout and "receipt: verified after stop" in status.stdout, status.stdout.strip() or status.stderr.strip())
        again = subprocess.run(
            [str(suite.keel), "stop", session], env=suite.environment, capture_output=True, text=True, timeout=scaled(30)
        )
        result.check("a repeated stop reports the existing receipt", again.returncode == 0 and "already stopped" in again.stdout, (again.stdout + again.stderr).strip())
    try:
        process.wait(timeout=scaled(60))
    except subprocess.TimeoutExpired:
        process.kill()
    result.seconds = time.monotonic() - started
    return result


def case_idle_timeout(suite: Suite) -> Result:
    """A detached persistent session that stays silent past its idle limit
    stops itself through the normal path and records why in its receipt."""
    result = Result("idle-timeout")
    workspace = suite.workspace("idle-timeout", {})
    before = suite.session_names()
    transcript = suite.transcripts / "idle-timeout.typescript"
    started = time.monotonic()
    process = subprocess.Popen(
        under_script(transcript, [
            str(suite.keel), "run", "--keep-alive", "claude", "-p",
            "Run `sleep 300` with the Bash tool, then reply DONE.", "--allowedTools", "Bash",
        ]),
        cwd=workspace,
        env=dict(suite.environment, KEEL_IDLE_TIMEOUT_SECS="15"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    chain = None
    deadline = time.monotonic() + scaled(120)
    while time.monotonic() < deadline and chain is None:
        for session in suite.sessions_since(before):
            chains = list((suite.state / "sessions" / session).glob("audit-*.ndjson"))
            if chains and any("settled-actual" in line for line in chains[0].read_text().splitlines()):
                chain = chains[0]
        time.sleep(2)
    result.check("the persistent session started and called the model", chain is not None)
    # Ending the attached client detaches the session; the supervisor and
    # its run are in their own sessions and keep running.
    os.killpg(process.pid, signal.SIGKILL)
    process.wait()
    if chain is not None:
        session = chain.parent.name
        result.sessions.append(session)
        receipt = chain.with_suffix(".receipt.json")
        deadline = time.monotonic() + scaled(90)
        while time.monotonic() < deadline and not receipt.exists():
            time.sleep(2)
        result.check("the detached session stopped itself", receipt.exists())
        if receipt.exists():
            body = json.loads(receipt.read_text())
            result.check("its receipt records stop_reason idle", body.get("stop_reason") == "idle", str(body.get("stop_reason")))
            result.check("and every teardown check passed", body.get("ok") is True)
        status = subprocess.run(
            [str(suite.keel), "status", session], env=suite.environment, capture_output=True, text=True
        )
        result.check("keel status reports closed after idle", "state: closed\n" in status.stdout and "receipt: verified after idle" in status.stdout, status.stdout.strip() or status.stderr.strip())
    result.seconds = time.monotonic() - started
    return result


def case_workspace_own(suite: Suite) -> Result:
    """`workspace:own`, approved at the trusted admission screen, starts the
    floor at 2 from a clean clone of the accepted HEAD, and reading the
    repository inside the guest does not lower it."""
    result = Result("workspace-own")
    workspace = suite.workspace("workspace-own", {"NOTE.md": "E2E-OWN-NOTE\n"})
    (workspace / "untracked-secret.txt").write_text("E2E-UNTRACKED\n")
    started = time.monotonic()
    texts = []
    for attempt in ("first", "again"):
        before = suite.session_names()
        transcript = suite.transcripts / f"workspace-own-{attempt}.typescript"
        process = subprocess.Popen(
            under_script(transcript, [
                str(suite.keel), "run", "--allow", "workspace:own", "claude", "-p",
                "Use the Read tool on NOTE.md and on untracked-secret.txt, then reply with what each contains.",
                "--allowedTools", "Read",
            ]),
            cwd=workspace,
            env=suite.environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Input typed before the trusted screen appears is discarded, so the
        # approval is typed only once the prompt is on the terminal.
        deadline = time.monotonic() + scaled(60)
        while time.monotonic() < deadline and not (
            transcript.exists() and b"Type APPROVE" in transcript.read_bytes()
        ):
            time.sleep(0.2)
        assert process.stdin is not None
        process.stdin.write(b"APPROVE\r")
        process.stdin.flush()
        try:
            code = process.wait(timeout=scaled(420))
        except subprocess.TimeoutExpired:
            process.kill()
            code = None
        text = clean(transcript.read_bytes()) if transcript.exists() else ""
        texts.append(text)
        sessions = suite.sessions_since(before)
        result.sessions.extend(sessions)
        result.check(f"{attempt}: the run completed", code == 0, text[-400:])
        for session in sessions:
            if not (suite.state / "sessions" / session / "floor.json").exists():
                result.check(f"{attempt}: {session} reached shutdown", False)
                continue
            manifest = suite.manifest(session) or {}
            declared = manifest.get("workspace", {})
            result.check(f"{attempt}: the manifest declares rank 2", declared.get("declared_rank") == 2, str(declared))
            result.check(
                f"{attempt}: the guest worked in the clone",
                str(declared.get("root", "")).endswith(f"/sessions/{session}/workspace"),
                str(declared.get("root")),
            )
            floor = json.loads((suite.state / "sessions" / session / "floor.json").read_text())
            result.check(f"{attempt}: reading the repository left the floor at 2", floor.get("floor") == 2, str(floor.get("floor")))
    result.check("the tracked note was read", "E2E-OWN-NOTE" in texts[0])
    result.check("the untracked file was not in the clone", "E2E-UNTRACKED" not in texts[0])
    result.check("the first admission was a first acceptance", "first acceptance of this workspace" in texts[0])
    result.check("the second admission saw the same HEAD", "unchanged since last accepted" in texts[1])
    result.check("the run printed how to fetch the agent's commits", "git fetch" in texts[0])
    result.seconds = time.monotonic() - started
    return result


NPM_PACKAGE = json.dumps({"name": "w4b", "version": "1.0.0", "private": True, "dependencies": {"is-number": "7.0.0"}})
NPM_LOCKFILE = json.dumps({
    "name": "w4b",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {"name": "w4b", "version": "1.0.0", "dependencies": {"is-number": "7.0.0"}},
        "node_modules/is-number": {
            "version": "7.0.0",
            "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz",
            "integrity": "sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==",
        },
    },
})


def case_npm_ci_pinned(suite: Suite) -> Result:
    """W4b: `npm ci` in an own workspace fetches only what the accepted
    lockfile pins, so the floor stays at the declared rank 2."""
    result = Result("npm-ci-pinned")
    workspace = suite.workspace("npm-ci-pinned", {"package.json": NPM_PACKAGE, "package-lock.json": NPM_LOCKFILE})
    started = time.monotonic()
    before = suite.session_names()
    transcript = suite.transcripts / "npm-ci-pinned.typescript"
    process = subprocess.Popen(
        under_script(transcript, [
            str(suite.keel), "run",
            "--allow", "workspace:own", "--allow", "egress:registry.npmjs.org", "claude", "-p",
            "Use the Bash tool to run exactly `npm ci --no-audit --no-fund` and then "
            "`cat node_modules/is-number/package.json`, then reply with the package's version.",
            "--allowedTools", "Bash",
        ]),
        cwd=workspace,
        env=suite.environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + scaled(60)
    while time.monotonic() < deadline and not (transcript.exists() and b"Type APPROVE" in transcript.read_bytes()):
        time.sleep(0.2)
    assert process.stdin is not None
    process.stdin.write(b"APPROVE\r")
    process.stdin.flush()
    try:
        code = process.wait(timeout=scaled(420))
    except subprocess.TimeoutExpired:
        process.kill()
        code = None
    text = clean(transcript.read_bytes()) if transcript.exists() else ""
    sessions = suite.sessions_since(before)
    result.sessions.extend(sessions)
    result.check("the run completed", code == 0, text[-400:])
    result.check("admission named the pinned package", "1 npm package(s) pinned by package-lock.json" in text, text[:1200])
    result.check("the agent read the installed package", "7.0.0" in text, text[-400:])
    for session in sessions:
        floor_path = suite.state / "sessions" / session / "floor.json"
        if not floor_path.exists():
            result.check(f"{session} reached shutdown", False)
            continue
        manifest = suite.manifest(session) or {}
        result.check("the manifest records one pin", manifest.get("workspace", {}).get("lockfile_pins") == 1, str(manifest.get("workspace")))
        floor = json.loads(floor_path.read_text())
        result.check("the pinned install left the floor at 2", floor.get("floor") == 2, json.dumps(floor.get("floor_history", []))[:600])
        npm_egress = [
            record["fields"] for record in suite.records(session)
            if record["event"] == "kernel.action"
            and record["fields"].get("action_class") == "egress" and record["fields"].get("outcome") == "executed"
            and str(record["fields"].get("origin", "")).startswith("node ")
        ]
        result.check("npm's fetch went through Keel", bool(npm_egress), str(len(npm_egress)))
    result.seconds = time.monotonic() - started
    return result


PAGE_SCHEMAS = json.dumps([{
    "version": 1,
    "name": "page-kind",
    "fields": {
        "kind": {"enum": ["documentation", "example", "login", "news", "other"]},
        "has_links": {"boolean": True},
    },
}])


def case_extract_url(suite: Suite) -> Result:
    """`keel_extract` reads an untrusted page through the quarantine helper:
    the agent gets only the schema's fields, the floor does not drop, and the
    audit records the extraction."""
    result = Result("extract-url")
    workspace = suite.workspace("extract-url", {})
    schemas = suite.root / "page-schemas.json"
    schemas.write_text(PAGE_SCHEMAS)
    before = suite.session_names()
    transcript = suite.transcripts / "extract-url.typescript"
    started = time.monotonic()
    process = subprocess.Popen(
        under_script(transcript, [
            str(suite.keel), "run", "--schemas", str(schemas),
            "--allow", "egress:example.com", "--allow", "workspace:own", "claude", "-p",
            "Call the keel_extract MCP tool with source url:https://example.com/ and schema page-kind, "
            "then reply with exactly the JSON result it returns and nothing else.",
            "--allowedTools", "mcp__keel__keel_extract",
        ]),
        cwd=workspace,
        env=suite.environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + scaled(60)
    while time.monotonic() < deadline and not (
        transcript.exists() and b"Type APPROVE" in transcript.read_bytes()
    ):
        time.sleep(0.2)
    assert process.stdin is not None
    process.stdin.write(b"APPROVE\r")
    process.stdin.flush()
    try:
        code = process.wait(timeout=scaled(420))
    except subprocess.TimeoutExpired:
        process.kill()
        code = None
    text = clean(transcript.read_bytes()) if transcript.exists() else ""
    sessions = suite.sessions_since(before)
    result.sessions.extend(sessions)
    result.check("the run completed", code == 0, text[-600:])
    result.check("the admission screen showed the schema and its bandwidth", "extract:page-kind (" in text)
    result.check("the agent relayed a schema-shaped result", '"kind"' in text and '"has_links"' in text, text[-600:])
    result.check("no page text reached the agent", "Example Domain" not in text.split("Type APPROVE")[-1])
    for session in sessions:
        records = suite.records(session)
        extractions = [r for r in records if r["event"] == "kernel.extraction"]
        result.check("the audit records the extraction", any(r["fields"].get("outcome") == "ok" for r in extractions), str(extractions))
        floor_file = suite.state / "sessions" / session / "floor.json"
        floor = json.loads(floor_file.read_text()).get("floor") if floor_file.exists() else None
        provenance = [r for r in records if r["event"] == "kernel.provenance" and "example.com" in r["fields"].get("source", "")]
        result.check("the page never entered the guest's provenance", not provenance, str(provenance))
        result.check("an own workspace's floor stays at 2 through the extraction", floor == 2, str(floor))
    result.seconds = time.monotonic() - started
    return result


def first_line_after_session(completed: subprocess.CompletedProcess) -> str:
    lines = completed.stdout.splitlines()
    return lines[1] if len(lines) > 1 else completed.stderr.strip()


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
    "persistent-stop": (case_persistent_stop, []),
    "idle-timeout": (case_idle_timeout, []),
    "workspace-own": (case_workspace_own, []),
    "npm-ci-pinned": (case_npm_ci_pinned, []),
    "extract-url": (case_extract_url, []),
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
