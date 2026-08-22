#!/usr/bin/env bash
#MISE description="Gate: the working tree is the bytes at HEAD, so a receipt keyed to HEAD names what was actually validated"
#
# CLOUD-193 moved `verify`'s verdict off the exit code and onto a receipt "keyed
# to the exact HEAD it validated". The mechanism is sound and it rests on an
# assumption nothing enforced: that the bytes verified ARE the bytes at HEAD.
# They need not be. `cargo`, `hk` and `zizmor` all read the WORKING TREE;
# `receipt record verify` keys the claim to HEAD.
#
# Measured 2026-08-09 landing CLOUD-269. `mise run land` was backgrounded, the
# session began editing `crates/batten/src/rules.rs` in the same worktree, and
# the lap's `verify` compiled a mid-edit snapshot:
#
#   error[E0004]: non-exhaustive patterns: `RuleKind::Shape` not covered
#   ::error:: land: verify failed on c5bfe05
#
# `c5bfe05` contains none of that code. That direction is loud and
# self-correcting. The mirror is silent and is the one this gate exists for: a
# dirty tree that PASSES writes a receipt for HEAD, `verified` matches it,
# `ready-guard` accepts it, the PR is readied, and CI runs the commit alone —
# which was never the thing that passed. Uncommitted work is not exotic here:
# backgrounding the slow path is mandated (AGENTS.md), so a long `verify` while
# the session edits the next ticket in the same worktree is the DESIGNED
# workflow.
#
# UNTRACKED FILES ARE DIRTY, decided rather than omitted. `git diff --quiet HEAD
# --` — the obvious predicate — cannot see them, and the gap is not theoretical:
# `cargo test` auto-discovers `crates/batten/tests/*.rs` and the bats suite globs
# `tests/*.bats`, so a brand-new untracked file is compiled and run by `verify`
# with ZERO tracked-file change. A receipt written after that attests a pass over
# bytes no commit contains, which is the whole failure. Staged-but-uncommitted is
# dirty for the same reason: the index is not HEAD. Ignored paths are excluded
# STRUCTURALLY — `git status` never reports them — so `target/`, `.serena/cache/`,
# `batten.local.toml` and the worktree dirs are outside the judgement rather than
# tuned out of it, the same structural exclusion the claim receipt uses for scratch
# (`receipt::judgeable`).
#
# Output is a pointer (non-negotiable rule 4): a count and the porcelain
# status/path lines, never a diff body.
#
# Exit 1 for a dirty tree — a usage error about this invocation, not a policy
# verdict, so never 2. Exit 2 is reserved for "could not look" (no repository, no
# HEAD), matching `mise-tasks/verified.sh`'s environment refusals.
#
# NOT wired into the hk gate, deliberately: `pre-commit` runs over a tree that is
# dirty by definition, so a step there would refuse every commit. Its one home is
# `[tasks.verify]`, which is what `land` inherits it through.
set -euo pipefail

# Resolved in two steps rather than `cd "$(git rev-parse --show-toplevel)"`: a
# failed substitution there yields `cd ""`, which bash treats as a SUCCESS and
# leaves the gate judging whatever directory it happened to start in.
root="${TREE_CLEAN_ROOT:-}"
if [[ -z "$root" ]] && ! root=$(git rev-parse --show-toplevel 2>/dev/null); then
	echo "::error:: tree-clean: not inside a git repository, so there is no HEAD to compare against" >&2
	exit 2
fi
cd "$root" 2>/dev/null || {
	echo "::error:: tree-clean: $root is not a directory this gate can enter" >&2
	exit 2
}

head=$(git rev-parse HEAD 2>/dev/null) || {
	echo "::error:: tree-clean: HEAD does not resolve, so there is no commit for a receipt to name" >&2
	exit 2
}

# `--no-optional-locks` so a gate never writes the index stat cache — this can
# run while another task holds the repository. `--untracked-files=normal` is
# named explicitly because `status.showUntrackedFiles` is user config, and a gate
# that a config setting can silently halve is not a gate.
dirty=$(git --no-optional-locks status --porcelain --untracked-files=normal) || {
	echo "::error:: tree-clean: could not read the working tree state" >&2
	exit 2
}

if [[ -z "$dirty" ]]; then
	echo "tree-clean: working tree matches HEAD ${head:0:8}"
	exit 0
fi

count=$(printf '%s\n' "$dirty" | wc -l | tr -d ' ')
echo "::error:: tree-clean: the working tree differs from HEAD ${head:0:8} in $count path(s), so a receipt keyed to that commit would attest bytes no commit contains:" >&2
printf '%s\n' "$dirty" >&2
echo "  Commit the work (you are pre-authorised to), stash it, or run the long task in a separate worktree — then re-run. No receipt is written." >&2
exit 1
