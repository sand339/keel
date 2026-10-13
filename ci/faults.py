#!/usr/bin/env python3
"""Lifecycle fault injection for Keel's teardown, receipt, and recovery.

Each case starts a real trusted runtime (a debug `keel-input-runtime`, the only
build that honours development overrides) in front of a fake `keel-runtime`
backend that misbehaves on purpose, injects one fault, and checks what Keel
recorded and what it left running. No model is called and no VM boots.

A failed audit write at teardown is not injected here: on macOS an append to
an already-open chain survives both the immutable flag and a full volume, so
it is covered in-process by `broker_shutdown_propagates_durable_audit_failure`.

    python3 ci/faults.py                 # every case
    python3 ci/faults.py --case stop-escalates
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from e2e import under_script

REPO = Path(__file__).resolve().parent.parent
# On Linux the backend runs in bubblewrap's PID namespace with
# --die-with-parent: it dies with bubblewrap, and bubblewrap dies with the
# trusted runtime or its own command. The orphan faults below cannot happen
# there, so each Linux case checks that nothing outlives the run instead.
LINUX = sys.platform == "linux"
INSTALLED = Path.home() / ".local/share/keel"

# Ignores the signals teardown sends first. The orphan-member variant forks a
# member and lets the leader exit once launchd has adopted it, that is, once
# the trusted runtime is gone, so only a member remains in the group.
FAKE_BACKEND = r"""
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    char ready[1024];
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    snprintf(ready, sizeof ready, "%s/ready", getenv("TMPDIR"));
    close(open(ready, O_CREAT | O_WRONLY, 0600));
#ifdef ORPHAN_MEMBER
    if (fork() == 0) {
        for (;;) pause();
    }
    while (getppid() != 1) sleep(1);
    return 0;
#else
    for (;;) pause();
#endif
}
"""


# Lists every descriptor above stderr it inherited, and whether each is a
# character device other than /dev/null, into its scratch directory.
DESCRIPTOR_PROBE = r"""
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
int main(void) {
    char path[1024], line[64];
    struct stat null_device, entry;
    stat("/dev/null", &null_device);
    snprintf(path, sizeof path, "%s/descriptors.txt", getenv("TMPDIR"));
    int out = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    for (int fd = 3; fd < 256; fd++) {
        if (fd == out || fstat(fd, &entry) != 0) continue;
        int terminal = S_ISCHR(entry.st_mode) && entry.st_rdev != null_device.st_rdev;
        snprintf(line, sizeof line, "%d %s\n", fd, terminal ? "terminal" : "other");
        write(out, line, strlen(line));
    }
    write(out, "done\n", 5);
    close(out);
    for (;;) pause();
}
"""


@dataclass
class Result:
    name: str
    status: str = "PASS"
    checks: list[tuple[str, bool, str]] = field(default_factory=list)
    note: str = ""

    def check(self, label: str, passed: bool, detail: str = "") -> bool:
        self.checks.append((label, passed, detail))
        if not passed:
            self.status = "FAIL"
        return passed


def group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_for(predicate: Callable[[], bool], seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.5)
    return predicate()


class Faults:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.state = root / "state"
        self.state.mkdir(parents=True)
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        for command in (
            ["git", "init", "-q"],
            ["git", "-c", "user.name=keel-faults", "-c", "user.email=faults@example.invalid",
             "commit", "-q", "--allow-empty", "-m", "fault fixture"],
        ):
            subprocess.run(command, cwd=self.workspace, check=True)
        subprocess.run(
            ["cargo", "build", "-q", "-p", "keel-cli", "--bin", "keel", "-p", "keel-input", "--bin", "keel-input-runtime"],
            cwd=REPO,
            check=True,
        )
        self.keel = REPO / "target/debug/keel"
        self.backends = {mode: self.backend(mode) for mode in ("stubborn", "orphan-member", "descriptor-probe")}

    def backend(self, mode: str) -> Path:
        """Builds a fake backend in a directory that mirrors the install, since
        the runtime finds its siblings and images relative to the backend."""
        directory = self.root / mode
        (directory / "bin").mkdir(parents=True)
        source = directory / "fake.c"
        source.write_text(DESCRIPTOR_PROBE if mode == "descriptor-probe" else FAKE_BACKEND)
        flags = ["-DORPHAN_MEMBER"] if mode == "orphan-member" else []
        backend = directory / "bin" / "keel-runtime"
        subprocess.run(["clang", "-O2", *flags, "-o", str(backend), str(source)], check=True)
        backend_siblings = (
            ("keel-ch", "cloud-hypervisor", "virtiofsd") if sys.platform == "linux" else ("keel-vz-spike",)
        )
        for sibling in (*backend_siblings, "deno", "keel-v8-sdk.ts"):
            (directory / "bin" / sibling).symlink_to(INSTALLED / "bin" / sibling)
        (directory / "images").symlink_to(INSTALLED / "images")
        return backend

    def environment(self, mode: str) -> dict[str, str]:
        return dict(
            os.environ,
            KEEL_STATE_DIR=str(self.state),
            KEEL_INPUT_RUNTIME=str(REPO / "target/debug/keel-input-runtime"),
            KEEL_UNSAFE_DEVELOPMENT_OVERRIDES="1",
            KEEL_RUNTIME_BACKEND=str(self.backends[mode]),
            KEEL_XTERM_RENDERER=str(INSTALLED / "bin/keel-xterm-renderer"),
            KEEL_RENDERER=str(INSTALLED / "bin/keel-render-spike"),
            KEEL_AUTO_RECOVER="off",
        )

    def sessions(self) -> set[str]:
        root = self.state / "sessions"
        return {entry.name for entry in root.iterdir()} if root.exists() else set()

    def start(
        self, name: str, mode: str, keep_alive: bool, ready: bool = True
    ) -> tuple[subprocess.Popen, Path, int]:
        """Starts a run and returns it once its chain records the backend group."""
        before = self.sessions()
        arguments = [str(self.keel), "run", *(["--keep-alive"] if keep_alive else []), "claude"]
        process = subprocess.Popen(
            under_script(self.root / f"{name}.typescript", arguments),
            cwd=self.workspace,
            env=self.environment(mode),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        found: list[tuple[Path, int]] = []

        def recorded() -> bool:
            for session in self.sessions() - before:
                for chain in (self.state / "sessions" / session).glob("audit-*.ndjson"):
                    for line in chain.read_text().splitlines():
                        payload = json.loads(line)["payload"]
                        if payload["event"] == "kernel.run-resource" and payload["fields"]["kind"] == "backend-group":
                            found.append((chain, int(payload["fields"]["detail"].removeprefix("pgid "))))
                            return True
            return False

        if not wait_for(recorded, 60):
            process.kill()
            raise RuntimeError(f"{name}: the run never recorded its backend group")
        chain, pgid = found[0]
        if not ready:
            return process, chain, pgid

        # The group is recorded as soon as sandbox-exec is spawned; inject
        # nothing until the fake backend has installed its signal handlers,
        # or a stop just ends sandbox-exec or the loader with an ordinary
        # SIGTERM. The descriptor probe signals readiness with its listing.
        scratch = next(
            Path(r["fields"]["detail"]) for r in self.records(chain)
            if r["event"] == "kernel.run-resource" and r["fields"]["kind"] == "scratch"
        )
        marker = scratch / ("descriptors.txt" if mode == "descriptor-probe" else "ready")
        if not wait_for(marker.exists, 10):
            process.kill()
            raise RuntimeError(f"{name}: the fake backend never started")
        return process, chain, pgid

    def keel_command(self, mode: str, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.keel), *arguments], env=self.environment(mode), capture_output=True, text=True, timeout=90
        )

    def status(self, mode: str, session: str) -> str:
        return self.keel_command(mode, "status", session).stdout

    @staticmethod
    def records(chain: Path) -> list[dict]:
        return [json.loads(line)["payload"] for line in chain.read_text().splitlines() if line]

    @staticmethod
    def finish(process: subprocess.Popen, *groups: int) -> None:
        for pgid in groups:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.wait()


def case_stop_escalates(faults: Faults) -> Result:
    """A backend that ignores SIGTERM is killed, and both records say so."""
    result = Result("stop-escalates")
    process, chain, pgid = faults.start("stop-escalates", "stubborn", keep_alive=True)
    try:
        stop = faults.keel_command("stubborn", "stop", chain.parent.name)
        result.check("keel stop succeeds", stop.returncode == 0, (stop.stdout + stop.stderr).strip())
        teardown = [r for r in faults.records(chain) if r["event"] == "kernel.run-teardown"]
        fields = teardown[0]["fields"] if teardown else {}
        if LINUX:
            # SIGTERM ends bubblewrap, and its namespace takes the stubborn
            # backend with it, so there is nothing left to escalate against.
            result.check("the in-chain teardown records a clean stop", fields.get("ok") == "true", str(fields))
        else:
            result.check("the in-chain teardown records SIGKILL escalation", fields.get("escalated") == "true", str(fields))
        result.check("and the backend group check passed", fields.get("ok") == "true")
        receipt = chain.with_suffix(".receipt.json")
        body = json.loads(receipt.read_text()) if receipt.exists() else {}
        result.check("the supervisor receipt passed", body.get("ok") is True, str(body.get("checks")))
        result.check("the backend group is gone", not group_alive(pgid))
    finally:
        faults.finish(process, pgid)
    return result


def crash_case(faults: Faults, name: str, mode: str, member_only: bool) -> Result:
    result = Result(name)
    process, chain, pgid = faults.start(name, mode, keep_alive=False)
    session = chain.parent.name
    try:
        writer = int(chain.name.split("-")[1])
        os.kill(writer, signal.SIGKILL)
        wait_for(lambda: not pid_alive(writer), 10)
        if member_only:
            wait_for(lambda: not pid_alive(pgid), 10)
            result.check(
                "the fault holds: the leader exited and a member survives",
                not pid_alive(pgid) and group_alive(pgid),
                f"leader alive: {pid_alive(pgid)}, group alive: {group_alive(pgid)}, leader: "
                + subprocess.run(["ps", "-o", "stat=,ppid=", "-p", str(pgid)], capture_output=True, text=True).stdout.strip(),
            )
        elif LINUX:
            result.check(
                "the backend dies with the killed runtime",
                wait_for(lambda: not group_alive(pgid), 10),
            )
        else:
            result.check("the fault holds: the backend outlives the killed runtime", pid_alive(pgid))
        result.check("status reports stale", "state: stale\n" in faults.status(mode, session))
        recover = faults.keel_command(mode, "recover", session)
        result.check("keel recover succeeds", recover.returncode == 0, (recover.stdout + recover.stderr).strip())
        result.check("recovery ended the recorded group", wait_for(lambda: not group_alive(pgid), 5))
        record = chain.with_suffix(".recovery.json")
        body = json.loads(record.read_text()) if record.exists() else {}
        checks = body.get("checks", {})
        group = [outcome for kind, outcome in checks.items() if kind.endswith("backend-group")]
        result.check("its record names the group as released", bool(group) and group[0].startswith("ok"), str(checks))
        result.check("status then reports recovered", "state: recovered\n" in faults.status(mode, session))
    finally:
        faults.finish(process, pgid)
    return result


def case_crash_orphan_leader(faults: Faults) -> Result:
    """SIGKILL of the trusted runtime leaves its backend running; recovery ends it."""
    return crash_case(faults, "crash-orphan-leader", "stubborn", member_only=False)


def case_crash_orphan_member(faults: Faults) -> Result:
    """Only a member of the backend group survives; recovery ends it without a live leader."""
    if LINUX:
        return member_dies_with_leader(faults)
    return crash_case(faults, "crash-orphan-member", "orphan-member", member_only=True)


def member_dies_with_leader(faults: Faults) -> Result:
    """On Linux a member cannot outlive its leader: when the backend's command
    exits, its PID namespace ends, and the run stops in order."""
    result = Result("crash-orphan-member")
    process, chain, pgid = faults.start("crash-orphan-member", "orphan-member", keep_alive=False, ready=False)
    try:
        result.check("the run ends when the backend leader exits", wait_for(lambda: process.poll() is not None, 30))
        result.check("no member of the backend group survives", wait_for(lambda: not group_alive(pgid), 10))
        teardown = [r for r in faults.records(chain) if r["event"] == "kernel.run-teardown"]
        fields = teardown[0]["fields"] if teardown else {}
        result.check("the in-chain teardown passed", fields.get("ok") == "true", str(fields))
        result.check("status does not report stale", "state: stale\n" not in faults.status("orphan-member", chain.parent.name))
    finally:
        faults.finish(process, pgid)
    return result


def case_supervisor_killed(faults: Faults) -> Result:
    """SIGKILL of `serve`: the run must still end its backend and seal, and
    recovery must clean the supervisor's files."""
    result = Result("supervisor-killed")
    process, chain, pgid = faults.start("supervisor-killed", "stubborn", keep_alive=True)
    directory = chain.parent
    try:
        serve = int((directory / "attach.pid").read_text())
        os.kill(serve, signal.SIGKILL)
        sealed = wait_for(lambda: '"audit.sealed"' in chain.read_text(), 30)
        result.check("the run seals its chain without its supervisor", sealed)
        result.check("the backend group is gone", wait_for(lambda: not group_alive(pgid), 10))
        result.check("no receipt is claimed", not chain.with_suffix(".receipt.json").exists())
        stop = faults.keel_command("stubborn", "stop", directory.name)
        result.check(
            "keel stop reports a supervisor gone without a receipt",
            stop.returncode != 0 and "without a teardown receipt" in stop.stderr,
            (stop.stdout + stop.stderr).strip(),
        )
        recover = faults.keel_command("stubborn", "recover", directory.name)
        result.check("keel recover succeeds", recover.returncode == 0, (recover.stdout + recover.stderr).strip())
        leftovers = [name for name in ("attach.sock", "attach.pid") if (directory / name).exists()]
        result.check("the supervisor's files are removed", not leftovers, ", ".join(leftovers))
    finally:
        faults.finish(process, pgid)
    return result


def case_backend_descriptors(faults: Faults) -> Result:
    """The untrusted backend inherits no terminal: not the persistent
    supervisor's pty master or slave, and not one from a foreground launch."""
    result = Result("backend-descriptors")
    for keep_alive in (True, False):
        label = "persistent" if keep_alive else "foreground"
        process, chain, pgid = faults.start(f"descriptors-{label}", "descriptor-probe", keep_alive=keep_alive)
        try:
            scratch = next(
                Path(r["fields"]["detail"]) for r in faults.records(chain)
                if r["event"] == "kernel.run-resource" and r["fields"]["kind"] == "scratch"
            )
            listing = scratch / "descriptors.txt"
            wait_for(lambda: listing.exists() and listing.read_text().endswith("done\n"), 10)
            lines = listing.read_text().splitlines() if listing.exists() else []
            result.check(f"{label}: the probe ran", lines[-1:] == ["done"])
            terminals = [line for line in lines if line.endswith(" terminal")]
            result.check(f"{label}: no terminal descriptor reaches the backend", not terminals, ", ".join(terminals))
        finally:
            faults.finish(process, pgid)
            writer = int(chain.name.split("-")[1])
            pid_file = chain.parent / "attach.pid"
            for pid in (writer, int(pid_file.read_text()) if pid_file.exists() else None):
                if pid:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
    return result


CASES: dict[str, Callable[[Faults], Result]] = {
    "backend-descriptors": case_backend_descriptors,
    "stop-escalates": case_stop_escalates,
    "crash-orphan-leader": case_crash_orphan_leader,
    "crash-orphan-member": case_crash_orphan_member,
    "supervisor-killed": case_supervisor_killed,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--case", action="append", choices=sorted(CASES))
    parser.add_argument("--keep", action="store_true", help="keep the scratch root for inspection")
    arguments = parser.parse_args()
    # Attach sockets live in the state directory, and macOS caps a socket
    # path at 104 bytes, so the root must be short.
    root = Path(tempfile.mkdtemp(prefix="kf-", dir="/tmp"))
    faults = Faults(root)
    results = []
    for name in arguments.case or list(CASES):
        print(f"RUN   {name} ...", flush=True)
        try:
            result = CASES[name](faults)
        except Exception as error:  # a broken harness is a failed case, not a crash
            result = Result(name, status="FAIL", checks=[("harness", False, str(error))])
        results.append(result)
        print(f"{result.status:5} {name}{'  — ' + result.note if result.note else ''}")
        for label, passed, detail in result.checks:
            if not passed:
                print(f"      FAIL: {label}{': ' + detail if detail else ''}")
    if arguments.keep:
        print(f"Scratch root: {root}")
    else:
        shutil.rmtree(root, ignore_errors=True)
    return 0 if all(result.status == "PASS" for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
