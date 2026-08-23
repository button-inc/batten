"""Classify the gate-described `mise-tasks/` programs by what each INVOKES.

CLOUD-907's first deliverable, and it gates the rest of that row: the bucket
sizes the bash-retirement campaign, and an estimate cannot schedule it.

# Why this is not a `grep`

`.claude/rules/scanning.md` row two. The question — "is this token in command
position, inside a comment, or inside a string" — is a SYNTAX question, and the
two instruments give different answers. CLOUD-843 ran both an hour apart: a
substring pass gave 11 tree / 24 git / 31 tracker / 16 forge, and a
command-position pass over the same files gave 22 / 50 / 3 / 7, because
`ci-local-parity` and `pipefail-grep-check` carried the token in a COMMENT. The
substring reading was nearly published as the campaign's scoping.

So this walks tree-sitter-bash's parse and reads `command_name` nodes. A comment
is its own node kind and is never a command head, so "comments stripped" is a
property of the grammar rather than a preprocessing step that can be got wrong.

# Why it is not wired into `hk`

Deliberately an INTERACTIVE instrument, run with the language pinned, exactly as
`scanning.md` scopes row two. CLOUD-310's rejection of a matcher CLI *as a gate*
is measured and stands: the programs under `mise-tasks/` carry no extension, so a
run pointed at that directory scans nothing and still exits 0 — a gate that found
nothing looks exactly like a gate that passed. A standing gate over command
position needs the general fix, which is CLOUD-914's row, not a second copy of
this script behind a `#MISE description`.

# Running it

    python3 -m venv .venv && .venv/bin/pip install tree_sitter tree_sitter_bash
    .venv/bin/python bench/gates/classify.py > bench/gates/RESULTS.md
    mise exec -- prettier --write bench/gates/RESULTS.md

The `prettier` pass is part of generation, not a hand-edit: `hk` formats every
tracked markdown file, so a generator whose output it would rewrite produces a
file the tree cannot hold. Column alignment is the whole of what it changes. It
goes through `mise exec` because prettier IS a pinned tool here (`npm:prettier`
in `mise.toml`), so a bare call would format with whatever version happened to
be on PATH and could produce bytes the gate then rewrites.

The two tree-sitter packages are NOT pinned, and the reason is a property of what
they are rather than of where the script sits (CLOUD-480, raised on review).
mise's backends install executables; these are import-only Python libraries with
no CLI, so there is nothing for it to put on PATH — and `python` itself is not a
`[tools]` entry, so adding one would download a toolchain into every clone for a
script nothing on the landing path runs. The venv is the narrowest thing that
works. If CLOUD-914 makes command-position scanning a standing gate, its inputs
become landing-path inputs and get pinned like any other.
"""

import collections
import pathlib
import re
import sys

import tree_sitter_bash
from tree_sitter import Language, Parser

PARSER = Parser(Language(tree_sitter_bash.language()))

TASKS = pathlib.Path(__file__).resolve().parents[2] / "mise-tasks"

# A task is gate-described when its `#MISE description=` OPENS with Gate.
#
# `Gate\b` rather than `Gate:`, and the difference is exactly one row:
# `signing-posture` opens `"Gate (and, with --repair, the write): ..."`. A
# colon-anchored predicate counts 84 and silently drops the one task that
# describes a gate with a caveat — the off-by-one this file exists to not make.
GATE_DESCRIPTION = re.compile(r'^#MISE description="Gate\b')

# Which external program puts a task in which bucket, in PRECEDENCE order: the
# first bucket a task's command heads touch wins. A task that shells out to the
# forge is a forge task even when it also reads git, because the forge read is
# what blocks its migration.
BUCKETS: list[tuple[str, frozenset[str]]] = [
    ("forge", frozenset({"gh"})),
    ("git", frozenset({"git"})),
    ("build", frozenset({"cargo", "rustc", "hyperfine", "cargo-nextest"})),
]

# Which git fact variant an invocation needs, decided from the subcommand and
# its flags rather than from the subcommand alone. `rev-parse` is 65 of the
# invocations and is NOT one question: `--git-dir` and `--show-toplevel` locate
# the repository, `HEAD` reads the current commit, and `<ref>^{commit}` resolves
# a declared ref. Collapsing them would put the whole corpus in one variant and
# tell the fact model nothing.
LOCATION_FLAGS = ("--git-dir", "--show-toplevel", "--is-inside-work-tree", "--absolute-git-dir")
ANCESTRY_FLAGS = ("--is-ancestor", "--count", "--merge-base")


def described_as_gate(text: str) -> bool:
    for line in text.splitlines():
        if line.startswith("#MISE description="):
            return GATE_DESCRIPTION.match(line) is not None
    return False


def commands(source: bytes):
    """Every `command` node, as (head, [argument words]).

    Words are the literal text of each argument; one built from an expansion
    (`"$ref"`) is kept verbatim rather than guessed at, so a variant is never
    inferred from a value this pass cannot see.
    """
    tree = PARSER.parse(source)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "command":
            head = None
            args = []
            for child in node.children:
                if child.type == "command_name":
                    head = child.text.decode("utf-8", "replace")
                elif head is not None and child.type not in ("file_redirect", "herestring_redirect"):
                    args.append(child.text.decode("utf-8", "replace"))
            if head is not None:
                yield head, args
        stack.extend(node.children)


# Global options git accepts BEFORE the subcommand that take their value as a
# SEPARATE word. Skipping the value is what keeps `git -C "$root" rev-parse` from
# reading `"$root"` as the subcommand (CLOUD-480, found on review of #660): it
# resolved to no variant at all, so the task silently understated the git surface
# — and that count is what the retirement campaign is scheduled against.
GLOBAL_OPTS_WITH_VALUE = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path")


def subcommand(words: list[str]) -> str:
    """The subcommand, past any leading global options and their values."""
    index = 0
    while index < len(words):
        word = words[index]
        if not word.startswith("-"):
            return word
        # `--git-dir=x` carries its value inline, so only the separate-word form
        # consumes the next element.
        if word in GLOBAL_OPTS_WITH_VALUE:
            index += 2
        else:
            index += 1
    return ""


def variant(args: list[str]) -> str | None:
    """Which git fact variant one `git ...` invocation needs."""
    words = [a for a in args if a]
    sub = subcommand(words)
    flags = [w for w in words if w.startswith("-")]

    if sub in ("fetch", "remote", "ls-remote", "push"):
        return "remote"
    if sub == "config":
        return "remote" if any("remote." in w or "branch." in w for w in words) else "head"
    if sub in ("status", "diff", "diff-index", "diff-files", "stash"):
        return "status"
    if sub in ("log", "show", "cat-file", "hash-object", "tag", "describe", "shortlog"):
        return "log"
    if sub == "merge-base":
        return "ancestry"
    if sub == "rev-list":
        return "ancestry" if any(f.startswith(ANCESTRY_FLAGS) for f in flags) else "log"
    if sub == "ls-files":
        return "status" if any(f in ("-m", "-o", "--others", "--modified") for f in flags) else "tracked"
    if sub in ("rev-parse", "symbolic-ref", "show-ref", "branch", "for-each-ref"):
        if any(f in LOCATION_FLAGS for f in flags):
            return "location"
        return "head"
    if sub in ("submodule", "worktree"):
        return "location"
    return None


def main() -> int:
    rows = []
    for path in sorted(TASKS.iterdir()):
        if not path.is_file():
            continue
        source = path.read_bytes()
        if not described_as_gate(source.decode("utf-8", "replace")):
            continue

        heads: set[str] = set()
        variants: set[str] = set()
        for head, args in commands(source):
            heads.add(head)
            if head == "git":
                found = variant(args)
                if found:
                    variants.add(found)

        bucket = "tree"
        for name, programs in BUCKETS:
            if heads & programs:
                bucket = name
                break

        rows.append(
            {
                "task": path.name,
                "bucket": bucket,
                "variants": sorted(variants),
            }
        )

    counts = collections.Counter(row["bucket"] for row in rows)
    variant_counts: collections.Counter[str] = collections.Counter()
    for row in rows:
        if row["bucket"] == "git":
            variant_counts.update(row["variants"])

    out = sys.stdout
    out.write("# What each gate-described `mise-tasks/` program invokes\n\n")
    out.write(
        "Generated by `bench/gates/classify.py`. Do not hand-edit.\n"
        "Classified by COMMAND-POSITION invocation over a tree-sitter-bash parse,\n"
        "so a token inside a comment or a string is not a hit\n"
        "(`.claude/rules/scanning.md` row two; CLOUD-843's two passes disagreed\n"
        "11/24/31/16 against 22/50/3/7 for exactly that reason).\n\n"
    )
    out.write(f"- gate-described tasks: {len(rows)}\n")
    for name in ("tree", "git", "build", "forge"):
        out.write(f"- {name}: {counts.get(name, 0)}\n")
    out.write("\n## The git bucket, by the fact variant each task needs\n\n")
    out.write(
        "A task appears once per variant it reads. The variant is decided from the\n"
        "subcommand AND its flags: `rev-parse` is most of the corpus and is not one\n"
        "question — `--git-dir` locates the repository, `HEAD` reads the current\n"
        "commit, and a named ref resolves a declared one.\n\n"
    )
    out.write("| variant | tasks |\n| --- | ---: |\n")
    for name, count in sorted(variant_counts.items()):
        out.write(f"| `{name}` | {count} |\n")
    # WHICH TASKS NEED A FACT THAT DOES NOT EXIST YET, which is the number the
    # campaign is actually scheduled against. `location` is the repository's own
    # git dir and toplevel — the engine already resolves both before any rule
    # runs — and `tracked` is `Fact::Tracked`, landed by CLOUD-846. A task whose
    # whole git usage is those two needs no new fact at all, and counting it in
    # the git bucket overstates the surface the fact model owes.
    already = frozenset({"location", "tracked"})
    git_rows = [row for row in rows if row["bucket"] == "git"]
    served = [row for row in git_rows if set(row["variants"]) <= already]
    out.write("\n## What the git bucket actually owes the fact model\n\n")
    out.write(f"- git-bucket tasks: {len(git_rows)}\n")
    out.write(
        f"- of those, served by facts that already exist "
        f"(`location` + `Fact::Tracked`): {len(served)}\n"
    )
    out.write(f"- needing a variant the engine cannot emit today: {len(git_rows) - len(served)}\n\n")
    out.write("| git usage | tasks |\n| --- | ---: |\n")
    shapes = collections.Counter(
        ", ".join(f"`{v}`" for v in row["variants"]) or "—" for row in git_rows
    )
    for shape, count in shapes.most_common():
        out.write(f"| {shape} | {count} |\n")

    out.write("\n## Every task\n\n")
    out.write("| task | bucket | git variants |\n| --- | --- | --- |\n")
    for row in rows:
        variants = ", ".join(f"`{v}`" for v in row["variants"]) or "—"
        out.write(f"| `{row['task']}` | {row['bucket']} | {variants} |\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
