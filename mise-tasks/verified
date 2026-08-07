#!/usr/bin/env bash
#MISE description="Gate: is HEAD verified? Answers from the receipts, so no shell idiom can mask the verdict"
#
# `verify` already writes a receipt keyed to HEAD, and writes it only after its
# guarded steps pass — the mechanism was sound and nothing read it. Every
# consumer read the exit CODE instead, and an exit code is destroyed by an
# ordinary idiom: `mise run verify 2>&1 | tail -60` exits 0 whether verify passed
# or failed. That produced a real false green in this repo — `linear-check`
# rejected the branch, no receipt was written, and the zero the session acted on
# was `tail`'s.
#
# `run-shape-guard` denies the idioms observed so far, which is a fast path with
# a good error message and inherently incomplete: `| grep -c`, `| wc -l`,
# `; true`, or a wrapper script all escape shape recognition. This is the
# invariant underneath it. It never consults a remembered exit code, so no idiom
# — present or future — can fool it.
#
# The predicate, all of it a pure function of the receipts and the git refs:
#
#   verify-receipt-missing   no verify receipt for this exact HEAD
#   linear-receipt-missing   no linear-check receipt for this exact HEAD
#   main-moved               the linear-check receipt records an origin/main that
#                            is no longer the current one
#
# An amend or a rebase produces a new HEAD and therefore no receipt, which is the
# point. Receipts live under `--git-dir`, so they resolve per-worktree and one
# worktree's receipt cannot vouch for another's.
#
# Output is a pointer: which predicate failed and what to run, never the contents
# of a run.
set -euo pipefail

git_dir=$(git rev-parse --git-dir 2>/dev/null) || {
	echo "::error:: not a git repository, so there is no HEAD to verify" >&2
	exit 2
}
head=$(git rev-parse HEAD 2>/dev/null) || {
	echo "::error:: HEAD does not resolve" >&2
	exit 2
}
receipts="$git_dir/batten-receipts"

fail() {
	echo "::error:: HEAD ${head:0:8} is NOT verified — $1" >&2
	echo "  Run \`mise run verify\` and read its exit status directly; never through a pipe, which reports the pipe's status. Then re-run \`mise run verified\`." >&2
	exit 1
}

[ -f "$receipts/verify.$head" ] ||
	fail "no verify receipt for this commit. A verify that failed, or whose exit status was swallowed by a pipe, leaves no receipt — which is exactly what this gate exists to catch."

recorded_main=$(cat "$receipts/linear-check.$head" 2>/dev/null) ||
	fail "no linear-check receipt for this commit."

current_main=$(git rev-parse origin/main 2>/dev/null) || {
	echo "::error:: origin/main does not resolve, so currency cannot be judged. This is a checkout problem, not a verification failure." >&2
	exit 2
}

[ "$recorded_main" = "$current_main" ] ||
	fail "the linear-check receipt was taken against origin/main ${recorded_main:0:8}, but origin/main is now ${current_main:0:8}. Rebase, then verify again."

echo "verified: HEAD ${head:0:8} has verify + linear-check receipts, linear on origin/main ${current_main:0:8}"
