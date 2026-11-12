#!/usr/bin/env python3
"""Check the claims ledger, ci/claims.toml, against the tree.

Every security objective in docs/THREAT-MODEL.md §5 must have at least one
claim. Every claim must name at least one positive test (the permitted thing
works) and one negative test (the forbidden thing fails), or carry a waiver
that says why a side is missing. A waiver is a known gap, and so is each entry of
a claim's optional `gaps` list, which records where the evidence is weaker
than the statement. Gaps are printed on every run and counted, and the goal
is none.

Each reference must resolve to a test that exists:

    test:NAME        a Rust `#[test] fn NAME` anywhere under crates/
    file:PATH        a Rust test file holding at least one `#[test]`
    e2e:CASE         a case in ci/e2e.py
    faults:CASE      a case in ci/faults.py
    eval:CASE        a case in ci/eval.py
    invariant:In     an invariant ci/check_invariants.py reports
    script:PATH      a check script that ci/phase0.sh runs

The tests the threat model's control map (§6) names must also exist and be
referenced by a claim, so the document cannot cite a test that is gone.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "ci" / "claims.toml"
THREAT_MODEL = ROOT / "docs" / "THREAT-MODEL.md"
SIDES = ("positive", "negative")


def fail(messages: list[str]) -> None:
    for message in messages:
        print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def rust_tests() -> dict[str, set[str]]:
    """Every `#[test]` function under crates/, with the files that define it."""
    pattern = re.compile(r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*(?:pub\s+)?fn\s+([a-z0-9_]+)\s*\(")
    names: dict[str, set[str]] = {}
    for path in (ROOT / "crates").rglob("*.rs"):
        if "target" in path.parts:
            continue
        for name in pattern.findall(path.read_text(encoding="utf-8")):
            names.setdefault(name, set()).add(path.name)
    return names


def harness_cases(script: str) -> set[str]:
    """Case names in a harness's CASES table."""
    path = ROOT / "ci" / script
    if not path.exists():
        return set()
    source = path.read_text(encoding="utf-8")
    table = source[source.find("\nCASES") :]
    table = table[: table.find("\n}\n") + 1] if "\n}\n" in table else table
    return set(re.findall(r'^\s+"([a-z0-9-]+)":\s*\(?\s*case_', table, re.MULTILINE))


def invariants() -> set[str]:
    source = (ROOT / "ci" / "check_invariants.py").read_text(encoding="utf-8")
    return set(re.findall(r'"(I\d+):', source))


def objectives() -> dict[int, str]:
    """The numbered objectives of THREAT-MODEL §5."""
    text = THREAT_MODEL.read_text(encoding="utf-8")
    section = text[text.index("## 5. Security objectives") : text.index("## 6. Control map")]
    found = re.findall(r"^(\d+)\. (.+?)(?=\n\d+\. |\n\n)", section, re.MULTILINE | re.DOTALL)
    return {int(number): " ".join(body.split()) for number, body in found}


def control_map_tests() -> tuple[set[str], set[str]]:
    """Test function names and test file names in §6's evidence column."""
    text = THREAT_MODEL.read_text(encoding="utf-8")
    section = text[text.index("## 6. Control map") : text.index("## 7. Decision boundary")]
    names: set[str] = set()
    files: set[str] = set()
    for row in section.splitlines():
        cells = row.split("|")
        if len(cells) < 6 or cells[1].strip() in ("Threat", "---"):
            continue
        for token in re.findall(r"`([^`]+)`", cells[4]):
            if token.endswith(".rs"):
                files.add(token)
            elif re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+){2,}", token):
                names.add(token)
    return names, files


class Resolver:
    def __init__(self) -> None:
        self.tests = rust_tests()
        self.cases = {kind: harness_cases(f"{kind}.py") for kind in ("e2e", "faults", "eval")}
        self.invariants = invariants()

    def problem(self, reference: str) -> str | None:
        kind, _, name = reference.partition(":")
        if not name:
            return f"`{reference}` is not KIND:NAME"
        if kind == "test":
            return None if name in self.tests else f"no #[test] fn named `{name}`"
        if kind == "file":
            path = ROOT / name
            if not path.is_file():
                return f"no file `{name}`"
            return None if "#[test]" in path.read_text(encoding="utf-8") else f"`{name}` holds no test"
        if kind in self.cases:
            return None if name in self.cases[kind] else f"no {kind} case `{name}`"
        if kind == "invariant":
            return None if name in self.invariants else f"no invariant `{name}`"
        if kind == "script":
            if not (ROOT / name).is_file():
                return f"no script `{name}`"
            runs = (ROOT / "ci" / "phase0.sh").read_text(encoding="utf-8")
            return None if name in runs else f"ci/phase0.sh does not run `{name}`"
        return f"`{kind}` is not a reference kind"


def main() -> None:
    # `--ledger PATH` checks another ledger against this tree; the checker's
    # own test uses it to feed in ledgers that must be refused.
    path = Path(sys.argv[2]) if sys.argv[1:2] == ["--ledger"] else LEDGER
    ledger = tomllib.loads(path.read_text(encoding="utf-8"))
    claims = ledger.get("claim", [])
    wanted = objectives()
    resolver = Resolver()
    errors: list[str] = []
    waivers: list[str] = []
    seen: set[str] = set()
    covered: dict[int, list[str]] = {number: [] for number in wanted}
    referenced: set[str] = set()

    for claim in claims:
        identifier = claim.get("id", "")
        if not re.fullmatch(r"O\d+-[a-z0-9-]+", identifier):
            errors.append(f"claim id `{identifier}` is not O<objective>-<name>")
            continue
        if identifier in seen:
            errors.append(f"claim `{identifier}` appears twice")
        seen.add(identifier)
        objective = claim.get("objective")
        if objective not in wanted:
            errors.append(f"{identifier}: objective {objective!r} is not in THREAT-MODEL §5")
        elif not identifier.startswith(f"O{objective}-"):
            errors.append(f"{identifier}: its id does not match objective {objective}")
        else:
            covered[objective].append(identifier)
        for field in ("statement", "limit"):
            if not str(claim.get(field, "")).strip():
                errors.append(f"{identifier}: `{field}` is empty")
        if not claim.get("environment"):
            errors.append(f"{identifier}: `environment` is empty")
        for gap in claim.get("gaps", []):
            if not str(gap).strip():
                errors.append(f"{identifier}: an entry of `gaps` is empty")
            waivers.append(f"{identifier}: {gap}")
        for side in SIDES:
            references = claim.get(side, [])
            waiver = str(claim.get(f"waiver_{side}", "")).strip()
            if references and waiver:
                errors.append(f"{identifier}: has {side} tests and a {side} waiver")
            elif not references and not waiver:
                errors.append(f"{identifier}: no {side} test and no waiver")
            elif waiver:
                waivers.append(f"{identifier}: no {side} test: {waiver}")
            for reference in references:
                problem = resolver.problem(reference)
                if problem:
                    errors.append(f"{identifier}: {side} `{reference}`: {problem}")
                referenced.add(reference)

    for number, body in sorted(wanted.items()):
        if not covered[number]:
            errors.append(f"objective {number} has no claim: {body[:70]}")

    # The control map may only cite tests that exist, and the ledger carries
    # every one of them, so the two cannot drift apart silently.
    names, files = control_map_tests()
    ledger_tests = {r.partition(":")[2] for r in referenced if r.startswith("test:")}
    # A file is carried by naming it or by naming a test it defines.
    ledger_files = {Path(r.partition(":")[2]).name for r in referenced if r.startswith("file:")}
    for name in ledger_tests:
        ledger_files |= resolver.tests.get(name, set())
    for name in sorted(names):
        if name not in resolver.tests:
            errors.append(f"THREAT-MODEL §6 cites `{name}`, which is not a test")
        elif name not in ledger_tests:
            errors.append(f"THREAT-MODEL §6 cites `{name}`, which no claim references")
    for name in sorted(files):
        if not any((ROOT / "crates").rglob(name)):
            errors.append(f"THREAT-MODEL §6 cites `{name}`, which is not a file")
        elif name not in ledger_files:
            errors.append(f"THREAT-MODEL §6 cites `{name}`, which no claim references")

    if errors:
        fail(errors)
    for number in sorted(wanted):
        print(f"claims: objective {number}: {', '.join(covered[number])}")
    for waiver in waivers:
        print(f"claims: GAP {waiver}")
    print(
        f"claims: {len(claims)} claims cover {len(wanted)} objectives with "
        f"{len(referenced)} tests; {len(waivers)} known gaps"
    )


if __name__ == "__main__":
    main()
