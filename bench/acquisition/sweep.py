#!/usr/bin/env python3
"""Tree-surface acquisition cost as a function of declared-document count.

CLOUD-935. `.claude/rules/rust.md`'s concurrency table carries one row whose
verdict is conditional and unmet — tree-surface fact ACQUISITION "stays serial
until a number says otherwise" — and states the condition: *"To move it now,
bring a number showing resolution — not projection — is the cost."* CLOUD-834
measured PROJECTION and disclaims this half. This is that number.

## Why a second harness rather than an arm in `perf`

`mise-tasks/perf.sh` measures fixed paths over fixed fixtures, and its arms
bracket INVOCATION cost. This sweeps a variable, which is a different experiment
with a different independent axis, and it needs to generate a fixture family per
run rather than materialise two committed ones. Adding a swept arm to `perf`
would also have meant editing an authored shell rule, which
`policy/shell-retirement.rego` refuses at `deny` with no override route
(`V-SHELL-RULE-EDITED`) — so the shape here is a Python helper driven by an
inline `mise.toml` task, the same inline-task shape `semver` and `policy-test`
were forced into for that identical reason.

Under `bench/` beside `bench/gates/classify.py` rather than under `mise-tasks/`:
mise makes every executable in that directory a file task named by its basename
AND its stem, so a helper there would publish a second entry point that runs this
sweep with no `BENCH_METRIC` set — stamping the invocation series' default into
the acquisition series, which is the one thing §5 exists to prevent.

## The experiment, and the confound it is built to avoid

ONE rule, ONE bundle, ONE module — and the row's `documents` array is what
grows. A row PER document would have made every step of the sweep add a module
compile and an evaluation beside each read, so the curve would price four things
and get reported as one. Holding everything but the declared path count fixed is
what leaves acquisition as the only term that moves.
`crates/batten/tests/document_read_count.rs::one_row_declaring_n_paths_acquires_n_documents`
pins that the engine really does acquire once per declared path under exactly
this shape, because a sweep over a variable the engine ignores would still draw a
tidy curve.

## Ratios, never absolutes

Machine noise is common-mode across arms measured seconds apart on one machine,
so it divides out — the same reason `perf-compare` decides a ratio and
`.claude/rules/rust.md` records why wall clock is usable at all here. Every arm
is reported, and the verdict is read off `ratio=` lines against the N=0 floor.

## The null is not optional

Two IDENTICAL trees at the largest N, measured as a separate pair. Its ratio is
1.0 plus pure noise by construction, which is what makes the spread a measured
quantity rather than a number in a comment — exactly how `perf-pair --null`
derived the 0.966–1.102 spread `perf-compare`'s 1.30 threshold clears. A sweep
number that sits inside the null spread has measured "no effect", and that is a
result rather than a failure to deliver.

## Output

Pointer-only per non-negotiable rule 4: one `path=` record per arm in `perf.sh`'s
byte-stable shape, then one `ratio=` line per comparison. No fixture contents, no
command lines, no hyperfine chatter — the raw JSON stays under the output
directory for a human.

Exit 0 measured / 1 a measurement failed / 2 could not look.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# `perf.sh`'s names and defaults, deliberately: a caller who already knows how to
# turn that task down should not have to learn a second vocabulary.
RUNS = int(os.environ.get("BENCH_RUNS", "100"))
WARMUP = int(os.environ.get("BENCH_WARMUP", "10"))
# ABSOLUTE, and that is load-bearing rather than tidy. Every arm runs hyperfine
# with the FIXTURE tree as its working directory, so a relative export path
# resolves against the fixture and hyperfine dies with "No such file or
# directory" before it times anything. `mise-tasks/perf.sh`'s header records the
# identical lesson for its own check arm; this is the same trap one harness over.
# `resolve()` is happy on a path that does not exist yet, which is why it can sit
# here rather than after the mkdir.
OUT_DIR = Path(os.environ.get("BENCH_OUT_DIR", "target/acquisition-bench")).resolve()
BIN = Path(os.environ.get("BENCH_BIN", "target/release/batten"))

# The sweep, and its FIRST entry is the ratio base.
#
# ONE, NOT ZERO, and that correction is the difference between measuring
# acquisition and measuring "does this tree have a policy row at all". A zero arm
# carries no rule, so the step from it to any other arm bundles the fixed cost of
# registering a bundle, compiling a module and evaluating it in with the reads —
# measured, that step alone read 1.367 at N=16, which would have been published as
# a per-document cost it is mostly not. Basing the ratios on a tree that already
# has exactly one rule and one document holds every fixed term constant, so the
# only thing differing between arms is how many paths that one row declares.
#
# 256 is chosen to be past the point where a per-document term, if there is one,
# has to be visible above a ~5 ms process start: at 256 even a 10 µs read is
# 2.5 ms. `BENCH_NS=0,...` still works and gives the no-policy reference, which is
# a different question and is not what the verdict is read off.
NS = [int(n) for n in os.environ.get("BENCH_NS", "1,16,64,256").split(",") if n]

# How many identical pairs the null is taken over. Five rather than one, because
# a single ratio is a point and the sweep has to be read against a WIDTH.
NULL_PAIRS = int(os.environ.get("BENCH_NULL_PAIRS", "5"))

# One module, whose body reads whatever was declared. Iterating `documents`
# rather than naming a path keeps the module identical across every arm, so the
# only thing differing between arms is the row's declaration.
MODULE = """package batten.acquisition

import rego.v1

rules contains "acquisition-bench"

violation contains {
\t"rule": "acquisition-bench",
\t"verdict": "V-ACQUISITION-BENCH",
\t"subjects": [{"path": path}],
} if {
\tsome path, doc in input.tree.documents
\tdoc.stray
}
"""

AUTHORITY_HEAD = """version = 1

[[verdict]]
id = "V-ACQUISITION-BENCH"
gloss = "the bench fixture declared a document carrying the sentinel key"
class = \"\"\"
A generated fixture for CLOUD-935's acquisition sweep. It is never raised: the
documents carry no sentinel, so the run is clean and the number is about reading
rather than about rendering findings.
\"\"\"

[[verdict.route]]
id = "R-REGENERATE-THE-FIXTURE"
kind = "document"
target = "batten.toml"
"""


def fail(message: str, code: int = 2) -> None:
    print(f"::error:: acquisition-bench: {message}", file=sys.stderr)
    raise SystemExit(code)


def build_tree(root: Path, n: int) -> None:
    """A repository with one policy row declaring `n` distinct documents."""
    if root.exists():
        shutil.rmtree(root)
    (root / "policy-acquisition").mkdir(parents=True)
    (root / "policy-acquisition" / "gate.rego").write_text(MODULE, encoding="utf-8")

    paths = [f"config{i}.toml" for i in range(n)]
    for path in paths:
        # Small and uniform. The cost being priced is the fixed per-document term
        # — open, read, parse, cache — rather than a per-byte one, and a large
        # file would measure the parser instead. Said out loud so the fixture does
        # not grow by accretion, the way `perf.sh` says the same thing about its
        # post-tool payload.
        (root / path).write_text("quiet = true\n", encoding="utf-8")

    # THE FLOOR ARM CARRIES NO ROW AND NO VERDICT, which is what makes it the
    # floor: config load, trust resolution and the walk, and not one acquisition.
    # A row declaring zero documents would still compile a module and put that
    # cost into the baseline every ratio is taken against.
    #
    # The verdict row goes with it, and that is the REGISTRY's requirement rather
    # than a choice: `[[verdict]]` runs in both directions, so a declared class
    # nothing raises fails the load outright ("a class no gate reaches reads as
    # coverage"). With no rule there is no module, so the token is unraised and a
    # floor arm carrying it would not run at all. The residual difference is a few
    # lines of TOML the other arms also parse, which is orders below the noise the
    # null measures.
    if n:
        declared = ", ".join(f'"{p}"' for p in paths)
        authority = (
            AUTHORITY_HEAD
            + "\n[[rule]]\n"
            'id = "acquisition-bench"\n'
            'kind = "policy"\n'
            'scope = "tree"\n'
            'bundle = "policy-acquisition/"\n'
            f"documents = [{declared}]\n"
            'severity = "deny"\n'
        )
    else:
        authority = "version = 1\n"
    (root / "batten.toml").write_text(authority, encoding="utf-8")

    # `git init` so the walk is a repository walk, matching every other fixture in
    # this tree. No global or system config: a contributor's own git settings must
    # not be able to change what is measured (CLOUD-282).
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    subprocess.run(
        ["git", "init", "-q", "-b", "main"],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
    )


def measure(arm: str, root: Path, binary: Path) -> dict[str, float]:
    """One hyperfine run of `batten check` in `root`, as a record."""
    out = OUT_DIR / f"{arm}.json"
    result = subprocess.run(
        [
            "hyperfine",
            "--warmup",
            str(WARMUP),
            "--runs",
            str(RUNS),
            "--shell=none",
            "--export-json",
            str(out),
            "--style",
            "none",
            f"{binary} check",
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # NO `-i`. Every arm's fixture is clean, so a non-zero exit means the
        # binary started failing rather than that the measurement is awkward —
        # and a broken path is still perfectly timeable, which is how it would
        # otherwise be published as a fast number.
        (OUT_DIR / f"{arm}.err").write_text(result.stderr, encoding="utf-8")
        fail(f"measuring arm {arm} failed — see {OUT_DIR / f'{arm}.err'}. No records.", 1)

    times = sorted(json.loads(out.read_text(encoding="utf-8"))["results"][0]["times"])
    count = len(times)
    # p95 from the sorted per-run times rather than mean+2sd, for `perf.sh`'s
    # reason: startup latency is right-skewed, so a normal assumption understates
    # exactly the tail a budget would be about.
    return {
        "p50": times[int((count - 1) * 0.5)] * 1000,
        "p95": times[-(-int((count - 1) * 95) // 100)] * 1000,
        "mean": sum(times) / count * 1000,
        "runs": count,
    }


def record(arm: str, stats: dict[str, float]) -> None:
    print(
        f"path={arm} p50={stats['p50']:.2f} p95={stats['p95']:.2f} "
        f"mean={stats['mean']:.2f} runs={int(stats['runs'])}"
    )


def main() -> int:
    root = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if root.returncode != 0:
        fail("not a git repository, so there is no tree to measure over")
    os.chdir(root.stdout.strip())

    if shutil.which("hyperfine") is None:
        fail("hyperfine is not installed — run `mise install`; it is pinned in mise.toml")
    binary = BIN.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        fail(f"{BIN} is missing — run `mise run build:release`. Nothing measured.")

    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    OUT_DIR.mkdir(parents=True)

    # THE SWEEP, measured back to back on one machine so the noise the ratios
    # divide out is the same noise.
    stats: dict[int, dict[str, float]] = {}
    for n in NS:
        tree = OUT_DIR / f"tree-{n}"
        build_tree(tree, n)
        stats[n] = measure(f"acquire-{n}", tree, binary)
        record(f"acquire-{n}", stats[n])

    # THE NULL, AND IT IS A SPREAD RATHER THAN A NUMBER. Two identical trees at
    # the largest N, built separately so each comparison is between two arms
    # rather than an arm against itself — repeated, because ONE null ratio says
    # nothing about how wide the noise is and a sweep ratio can only be read
    # against a width. `perf-compare`'s 0.966–1.102 came from n=30 for exactly
    # this reason; the pairs here are longer, so fewer of them bound it.
    nulls: list[float] = []
    largest = max(NS)
    for pair in range(NULL_PAIRS):
        sides = {}
        for side in ("a", "b"):
            tree = OUT_DIR / f"null{pair}-{side}"
            build_tree(tree, largest)
            arm = f"null{pair}-{side}"
            sides[side] = measure(arm, tree, binary)
            record(arm, sides[side])
        nulls.append(sides["b"]["p50"] / sides["a"]["p50"])

    base = stats[NS[0]]["p50"]
    if base <= 0:
        fail("the base arm measured zero, so no ratio can be taken", 1)
    for n in NS[1:]:
        print(f"ratio=acquire-{n}/acquire-{NS[0]} value={stats[n]['p50'] / base:.3f}")
    for pair, value in enumerate(nulls):
        print(f"ratio=null{pair} value={value:.3f}")
    print(f"null-spread low={min(nulls):.3f} high={max(nulls):.3f} pairs={len(nulls)}")

    # THE PER-DOCUMENT TERM, which is the number the verdict is actually about.
    # Reported rather than left to a reader with a calculator, and taken across
    # the widest span in the sweep because that is where the fixed terms matter
    # least. Microseconds, since milliseconds would round it to nothing.
    span = max(NS) - NS[0]
    if span > 0:
        per_doc = (stats[max(NS)]["p50"] - base) * 1000 / span
        print(f"per-document us={per_doc:.2f} over={span} documents")
    return 0


if __name__ == "__main__":
    sys.exit(main())
