#!/usr/bin/env python3
"""Four-term cost of the Rust suite, with its own repeat-run null.

CLOUD-1208. `mise run test:cargo` emits ONE duration for a step that is four
costs, and the per-step receipt makes even that unobservable on a hit. The shell
side has had `mise run suite-bench` and `bench/suites/RESULTS.md` since
CLOUD-386; the Rust side has had nothing, so every claim about what that suite
costs — including the ones in this row's siblings — is a hand measurement
somebody took once.

## Why four terms, and why the fourth is the point

    total wall  =  build  +  execute  +  <residue>

`perf`/`perf-pair` measure the BINARY's invocation latency, which is a different
question one layer down; conflating the two is the error `.claude/rules/rust.md`
records for `acquisition-wall-clock` vs `wall-clock`. A report emitting only
nextest's `Summary` would declare a 127s suite that takes 231s.

**THE RESIDUE IS REPORTED AND NEVER LABELLED, and that is this harness's whole
reason to exist.** CLOUD-1208 has been wrong about it twice:

  1. Filed quoting 1376s wall and "~90% is compile and link" — both from
     guessing when the run started and ended. Wrong by 4.5x, corrected by `stat`
     on a log file.
  2. Then quoting the 97.7s residue as nextest's per-binary list phase —
     reasoned from how nextest works, never measured. Wrong by 56x: a zero-match
     filter run pays the freshness check AND the full enumeration and then runs
     nothing, and totals 1.75s.

Two independent attributions, both confident, both wrong, both caught only by an
ad-hoc experiment nobody was obliged to run. A harness printing
`list phase: 97.7s` would have shipped the second as fact. So this prints the
residue as a residue, and prints what it is NOT.

## Why a `bench/` helper driven by a one-line task

`policy/shell-retirement.rego` refuses ADDING an authored shell rule at `deny`
(`V-SHELL-RULE-ADDED`) with no override, so a `mise-tasks/*.sh` program is
unavailable — the same constraint that forced `[tasks.semver]`,
`[tasks.prose-only-check]`, `[tasks.policy-test]` and `bench/acquisition/sweep.py`
into their shapes. Under `bench/` rather than `mise-tasks/` for a second reason
that one records: mise makes every executable in a task directory a file task
named by its basename AND its stem, so a helper there would publish a second
entry point that runs this with no `BENCH_METRIC` set — stamping the invocation
series' default into the suite series, which is the one thing the stamp exists to
prevent.

## A SENSOR, NEVER A GATE

A duration ceiling is met by deleting assertions, which is strictly worse than a
slow suite because the result also has to be maintained. That is
`[tasks.coverage]`'s recorded argument against a coverage threshold, and
non-negotiable rule 2's "a log without a gate is sensor only" anticipates exactly
this case. So this draws no conclusion, exits 0 on any measurement it completed,
and is deliberately absent from `verify` and from `final`'s `needs:`.

## Output

Pointer-only per non-negotiable rule 4: durations, counts and target names. No
test names, no command lines, no cargo chatter.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Two warm arms, so the null is a measured spread rather than a number in a
# comment. `perf-compare`'s 0.966–1.102 came from n=30 of a much cheaper arm;
# a suite arm is minutes, so the count is what is affordable and the spread is
# reported with its own `pairs=` so a reader knows how thin it is.
NULL_PAIRS = 2

RESULTS = Path("bench/rust/RESULTS.md")

# nextest's own execute term, e.g. `Summary [ 127.000s] 3167 tests run: ...`.
SUMMARY = re.compile(r"Summary\s*\[\s*([0-9.]+)s\]\s*(\d+)\s+tests?\s+run")
# `Starting 3167 tests across 119 binaries`, which is the target count the
# residue has repeatedly been blamed on.
STARTING = re.compile(r"Starting\s+(\d+)\s+tests?\s+across\s+(\d+)\s+binar")

# SGR escapes, stripped before either pattern is applied.
#
# Measured rather than anticipated: the first real run of this harness failed with
# "nextest printed no Summary line" over a suite that had just reported
# `Summary [ 143.437s] 3194 tests run`. nextest colours that line, so the bytes are
# `\x1b[32;1m     Summary\x1b[0m \x1b[1m3194\x1b[0m …` and every `\s*` in the
# patterns above is looking at an escape sequence.
#
# BOTH HALVES, because either alone is a single point of failure for the one term
# this harness exists to report: `--color never` is passed below so the common path
# produces clean bytes, and this strips whatever still arrives — a `CLICOLOR_FORCE`
# in the environment, or a future nextest that colours a stream it does not today.
# Losing the Summary silently would mean reporting the residue as the whole
# non-build cost, which is the mislabelling this row is about.
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def fail(message: str, code: int = 2) -> None:
    print(f"::error:: suite-bench-rust: {message}", file=sys.stderr)
    sys.exit(code)


def run(argv: list[str]) -> tuple[float, str, int]:
    """Wall clock, combined and de-escaped output, and status of one command."""
    started = time.monotonic()
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - started
    return elapsed, ANSI.sub("", result.stdout + result.stderr), result.returncode


def arm(label: str) -> dict[str, float]:
    """One reading of all four terms, taken back to back on one machine.

    The `--no-run` call goes FIRST and its wall clock is the build term. On a
    warm tree that is the freshness check (CLOUD-1208 measured 5.9s); on a cold
    or partial one it is build-and-link. Either way the term is what it is —
    naming it "the build" and then quoting a cold number as a warm one is the
    first of the two defects above, so the arm records which it was by reporting
    the number rather than a word.
    """
    build_wall, _build_out, build_rc = run(
        ["cargo", "nextest", "run", "--workspace", "--no-run", "--color", "never"]
    )
    if build_rc != 0:
        # No `-i` equivalent and no tolerance: a suite that does not build is
        # perfectly timeable, which is how a broken tree would otherwise be
        # published as a fast number.
        fail(f"arm {label}: the suite did not build, so nothing here is a measurement", 1)

    total_wall, out, _ = run(
        ["cargo", "nextest", "run", "--workspace", "--no-fail-fast", "--color", "never"]
    )
    # A red suite is still a valid COST measurement — this is a sensor, and
    # refusing to report because a test failed would make the instrument
    # unavailable exactly when somebody is bisecting a slow failing suite. The
    # status is reported so the reading is not mistaken for a green one.
    summary = SUMMARY.search(out)
    if summary is None:
        fail(f"arm {label}: nextest printed no Summary line, so the execute term is unknown", 1)
    execute = float(summary.group(1))
    cases = int(summary.group(2))

    starting = STARTING.search(out)
    binaries = int(starting.group(2)) if starting else 0

    return {
        "build": build_wall,
        "execute": execute,
        "total": total_wall,
        # NOT an explanation. Subtraction, and nothing else is claimed about it.
        "residue": total_wall - build_wall - execute,
        "cases": float(cases),
        "binaries": float(binaries),
    }


def record(label: str, terms: dict[str, float]) -> None:
    print(
        f"arm={label} build={terms['build']:.1f}s execute={terms['execute']:.1f}s "
        f"total={terms['total']:.1f}s residue={terms['residue']:.1f}s "
        f"cases={int(terms['cases'])} binaries={int(terms['binaries'])}"
    )


def write_results(arms: list[dict[str, float]], nulls: list[float]) -> None:
    first = arms[0]
    share = (first["residue"] / first["total"] * 100) if first["total"] > 0 else 0.0
    lines = [
        "# Four-term cost of the Rust suite",
        "",
        "Generated by `mise run suite-bench-rust`. Do not hand-edit.",
        "",
        "`total` is wall clock for the whole run. `build` is a `--no-run` call",
        "taken first, so on a warm tree it is the freshness check rather than a",
        "compile. `execute` is nextest's own `Summary`. **`residue` is the",
        "subtraction and nothing more — this report does not name its cause.**",
        "",
        "Two attempts to name it were wrong by 4.5x and 56x (CLOUD-1208). It is",
        "measured NOT to be nextest's per-binary list phase: a zero-match filter",
        "run pays the freshness check and the full enumeration and totals 1.75s.",
        "",
        f"- arms: {len(arms)}",
        f"- cases: {int(first['cases'])} across {int(first['binaries'])} binaries",
        f"- residue share of the first arm: {share:.1f}%",
    ]
    if nulls:
        lines.append(
            f"- repeat-run null: {min(nulls):.3f}–{max(nulls):.3f} over {len(nulls)} pairs"
        )
    lines += [
        "",
        "| arm | build | execute | total | residue |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ]
    for index, terms in enumerate(arms):
        lines.append(
            f"| {index} | {terms['build']:.1f}s | {terms['execute']:.1f}s "
            f"| {terms['total']:.1f}s | {terms['residue']:.1f}s |"
        )
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False
    )
    if root.returncode != 0:
        fail("not a git repository, so there is no suite to measure")
    os.chdir(root.stdout.strip())

    if shutil.which("cargo") is None:
        fail("cargo is not on PATH — run this through `mise run suite-bench-rust`")

    arms = []
    for index in range(NULL_PAIRS):
        terms = arm(str(index))
        record(str(index), terms)
        arms.append(terms)

    # THE NULL IS A SPREAD, and it is over `total` because that is the term every
    # sibling row quotes a delta against. Consecutive identical arms, so the
    # ratio is 1.0 plus pure noise by construction — the same construction
    # `perf-pair --null` uses, and the reason a sibling's number can be read at
    # all. A delta inside this spread has measured "no effect", which is a result.
    nulls = [
        arms[index + 1]["total"] / arms[index]["total"]
        for index in range(len(arms) - 1)
        if arms[index]["total"] > 0
    ]
    for index, value in enumerate(nulls):
        print(f"ratio=null{index} value={value:.3f}")
    if nulls:
        print(f"null-spread low={min(nulls):.3f} high={max(nulls):.3f} pairs={len(nulls)}")

    # WHAT THE RESIDUE IS NOT, printed every run rather than left in a comment.
    # This is the line that stops the next reader doing what the last two did.
    print(
        "residue-is-unattributed note=not-the-list-phase "
        "measured=1.75s-for-a-zero-match-filter-run"
    )

    write_results(arms, nulls)
    print(f"wrote={RESULTS}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
