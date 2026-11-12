#!/usr/bin/env python3
"""Checks that the trusted line budget of ci/check_invariants.py is enforced.

A checker that only prints a number passes on any tree. Each case hands the
budget check line counts that must be refused, and one that must not be.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_invariants as invariants  # noqa: E402

BUDGETS = {"keel-kernel": 600, "keel-input": 300}
CASES = [
    ("counts at their ratchets, under the ceiling", {"keel-kernel": 600, "keel-input": 300}, BUDGETS, 1_000, []),
    ("a crate over its ratchet", {"keel-kernel": 601, "keel-input": 300}, BUDGETS, 1_000, ["keel-kernel has 601"]),
    (
        "every crate over its ratchet is named",
        {"keel-kernel": 601, "keel-input": 301},
        BUDGETS,
        1_000,
        ["keel-kernel has 601", "keel-input has 301"],
    ),
    (
        "the total over the ceiling",
        {"keel-kernel": 600, "keel-input": 300},
        BUDGETS,
        899,
        ["total 900 first-party LOC; the ceiling is 899", "ratchets sum to 900, above the ceiling of 899"],
    ),
    (
        "ratchets raised past the ceiling, before any code is",
        {"keel-kernel": 100, "keel-input": 100},
        {"keel-kernel": 700, "keel-input": 400},
        1_000,
        ["ratchets sum to 1100, above the ceiling of 1000"],
    ),
    ("a total exactly at the ceiling", {"keel-kernel": 600, "keel-input": 300}, BUDGETS, 900, []),
]


def main() -> None:
    failed = 0
    for label, counts, budgets, ceiling, expected in CASES:
        violations = invariants.loc_violations(counts, budgets, ceiling)
        passed = len(violations) == len(expected) and all(
            any(text in violation for violation in violations) for text in expected
        )
        failed += not passed
        print(f"{'ok  ' if passed else 'FAIL'} {label}")
        if not passed:
            print(f"     wanted {expected}; got {violations}")
    # The shipped numbers themselves: the ceiling is the recorded one, and
    # the ratchets as committed fit under it.
    shipped = [
        ("the ceiling is 30,000 lines", invariants.TRUSTED_TOTAL_BUDGET == 30_000),
        (
            "the committed ratchets fit under the ceiling",
            sum(invariants.CRATE_BUDGETS.values()) <= invariants.TRUSTED_TOTAL_BUDGET,
        ),
        (
            "check_loc applies the ceiling",
            "loc_violations(counts, CRATE_BUDGETS, TRUSTED_TOTAL_BUDGET)"
            in Path(invariants.__file__).read_text(encoding="utf-8"),
        ),
    ]
    # End to end, against this tree: with the ceiling set below what the
    # trusted crates measure today, the real check exits with an error.
    measured = sum(invariants.tokei_line_count(invariants.TRUSTED_ROOT / name) for name in invariants.CRATE_BUDGETS)
    invariants.TRUSTED_TOTAL_BUDGET = measured - 1
    try:
        # The refusal's own error lines would read as a failure in a CI log.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            invariants.check_loc()
        refused = False
    except SystemExit as exit:
        refused = exit.code == 1
    finally:
        invariants.TRUSTED_TOTAL_BUDGET = 30_000
    shipped.append((f"the real check fails this tree ({measured} lines) under a ceiling of {measured - 1}", refused))
    for label, passed in shipped:
        failed += not passed
        print(f"{'ok  ' if passed else 'FAIL'} {label}")
    if failed:
        raise SystemExit(1)
    print(f"the trusted line budget refuses {sum(bool(case[4]) for case in CASES)} violations and accepts the rest")


if __name__ == "__main__":
    main()
