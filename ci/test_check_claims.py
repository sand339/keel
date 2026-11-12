#!/usr/bin/env python3
"""Checks that ci/check_claims.py refuses a ledger that should be refused.

A checker that accepts everything passes on a good ledger too, so each case
here breaks the real ledger in one way and expects the named error.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
LEDGER = (ROOT / "ci" / "claims.toml").read_text(encoding="utf-8")


def run(ledger: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as file:
        file.write(ledger)
    try:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "ci" / "check_claims.py"), "--ledger", file.name],
            capture_output=True,
            text=True,
        )
    finally:
        Path(file.name).unlink()
    return completed.returncode, completed.stdout + completed.stderr


def without_claim(identifier: str) -> str:
    """The ledger with one claim removed."""
    blocks = LEDGER.split("[[claim]]")
    kept = [block for block in blocks if f'id = "{identifier}"' not in block]
    assert len(kept) == len(blocks) - 1, identifier
    return "[[claim]]".join(kept)


def replace(old: str, new: str) -> str:
    assert LEDGER.count(old) == 1, old
    return LEDGER.replace(old, new)


CASES = [
    ("the real ledger passes", LEDGER, 0, "known gaps"),
    (
        "a test that does not exist",
        replace('"test:budget_exhaustion_is_not_gate_overridable"', '"test:no_such_test_anywhere"'),
        1,
        "no #[test] fn named `no_such_test_anywhere`",
    ),
    (
        "a harness case that does not exist",
        replace('positive = ["e2e:v8-fetch", "e2e:npm-ci-pinned"]', 'positive = ["e2e:no-such-case"]'),
        1,
        "no e2e case `no-such-case`",
    ),
    (
        "a file that holds no test",
        replace(
            '"file:crates/trusted/keel-audit/tests/verification_status.rs"',
            '"file:crates/trusted/keel-audit/Cargo.toml"',
        ),
        1,
        "holds no test",
    ),
    (
        "an unknown invariant",
        replace('positive = ["invariant:I1", "invariant:I2", "invariant:I3", "invariant:I4"]', 'positive = ["invariant:I99"]'),
        1,
        "no invariant `I99`",
    ),
    (
        "an unknown reference kind",
        replace('positive = ["e2e:v8-fetch", "e2e:npm-ci-pinned"]', 'positive = ["manual:looked-at-it"]'),
        1,
        "`manual` is not a reference kind",
    ),
    (
        "a claim with no negative test and no waiver",
        replace('negative = ["script:ci/test_check_invariants.py"]', ""),
        1,
        "no negative test and no waiver",
    ),
    (
        "a side with both tests and a waiver",
        replace(
            'positive = ["invariant:I1", "invariant:I2", "invariant:I3", "invariant:I4"]',
            'positive = ["invariant:I1"]\nwaiver_positive = "and also a waiver"',
        ),
        1,
        "has positive tests and a positive waiver",
    ),
    ("an objective with no claim", without_claim("O7-exact-approval"), 1, "objective 7 has no claim"),
    (
        "an id that names another objective",
        replace('id = "O8-audit-chain"\nobjective = 8', 'id = "O8-audit-chain"\nobjective = 7'),
        1,
        "its id does not match objective 7",
    ),
    (
        "a control-map test no claim carries",
        without_claim("O3-policy-artifact"),
        1,
        "which no claim references",
    ),
    (
        "an eval case that does not exist",
        replace('"eval:audit-tamper"', '"eval:no-such-attack"'),
        1,
        "no eval case `no-such-attack`",
    ),
    (
        "a script the verification run does not run",
        replace('"script:ci/test_check_invariants.py"', '"script:ci/e2e.py"'),
        1,
        "ci/phase0.sh does not run `ci/e2e.py`",
    ),
    (
        "an empty limit",
        replace(
            'limit = "A crash leaves an intentionally unsealed stream. A host compromised during the run is out of scope."',
            'limit = ""',
        ),
        1,
        "`limit` is empty",
    ),
]


def main() -> None:
    failed = 0
    for label, ledger, expected_code, expected_text in CASES:
        code, output = run(ledger)
        passed = code == expected_code and expected_text in output
        failed += not passed
        print(f"{'ok  ' if passed else 'FAIL'} {label}")
        if not passed:
            print(f"     wanted exit {expected_code} with {expected_text!r}; got exit {code}:\n{output}")
    if failed:
        raise SystemExit(1)
    print(f"check_claims refuses {len(CASES) - 1} broken ledgers and accepts the real one")


if __name__ == "__main__":
    main()
