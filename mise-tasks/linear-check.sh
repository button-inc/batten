#!/usr/bin/env bash
#MISE description="Gate: HEAD is linear on the current origin/main, so the PR can fast-forward-land"
#
# Re-asserted twice — inside `verify`, and again immediately before `gh pr ready`,
# because `main` moves constantly and a verify green a minute ago may be stale
# (AGENTS.md, workflow step 5). One definition, called from both places, instead
# of the fetch/merge-base snippet retyped per session.
#
# Lives here rather than inline in mise.toml for two reasons. It is testable:
# `tests/linear-check.bats` stubs `git` and asserts the fail-closed path below,
# which an inline `run =` body cannot express. And it gets `set -euo pipefail`,
# which mise's `shell = "bash -c"` bodies do NOT have — a task body there runs
# every line regardless of the previous one's exit status.
#
# That missing `set -e` is exactly what made the fetch below load-bearing. The
# fetch refreshes the `origin/main` ref that every line after it reads. When it
# failed silently, `git rev-parse origin/main` still succeeded against the ref
# already on disk, the merge-base comparison compared a stale main to itself,
# the gate passed, and a receipt was written attesting a linearity that had not
# been checked. `ready-guard` then compares that receipt to the same stale ref
# (mise-tasks/ready-guard.sh:82) and matches, so `gh pr ready` was allowed and CI
# ran on a branch that was not actually rebased. A gate that silently passes on
# a broken precondition is worse than no gate, so the fetch now fails closed.
set -euo pipefail

# `git fetch origin main` is not enough, and it fails in the direction the
# fail-closed check above cannot see: in a single-branch clone it exits 0 while
# updating no remote-tracking ref at all. Measured on a fresh `git clone --depth
# 1`: fetch exits 0, `git rev-parse origin/main` exits 128. The clone configures
# a fetch refspec covering only its own branch, so `main` is never written; a
# shallow clone additionally rejects the update ("shallow roots are not allowed
# to be updated"). Depth is not the cause — `--depth 1 --no-single-branch` has
# `origin/main`. Deepen first, then name the refspec explicitly so the ref every
# line below reads is the one just fetched.
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
	git fetch -q --no-tags --unshallow origin 2>/dev/null ||
		git fetch -q --no-tags --deepen=1000 origin 2>/dev/null || true
fi
if ! git fetch -q --no-tags origin "+refs/heads/main:refs/remotes/origin/main"; then
	echo "::error:: could not fetch origin/main, so linearity is unverifiable. Refusing to pass on a stale ref — re-run when the network is back." >&2
	exit 1
fi

if ! main=$(git rev-parse origin/main 2>/dev/null); then
	echo "::error:: fetched, but origin/main still does not resolve. That is a checkout problem, not a rebase problem — do not read it as 'not rebased'." >&2
	exit 1
fi
# Exit 2, and the distinction is load-bearing for the caller (CLOUD-318). The
# two refusals above are about the environment: the ref could not be fetched, or
# the checkout has no `origin/main` — a branch may well be fine and there is
# nothing here that says otherwise. This one is different in kind: the branch is
# measured and found behind, which is the shell tasks' "the input moved" answer
# rather than a verdict about its content. `land` runs `verify` for ~150s while
# `main` advances underneath it, and the only way it can tell "rebase and lap"
# from "stop, something is broken" is by which code came back. Collapsing all
# three into 1 is what made a lap that loses a race it is designed to lose end
# the run instead of starting the next one.
if [ "$(git merge-base origin/main HEAD)" != "$main" ]; then
	echo "::error:: not rebased on latest main ($main). Run: git rebase origin/main" >&2
	exit 2
fi

# The receipt write is the binary's job (CLOUD-203). It records WHICH main we
# were linear against, so a main that moves afterwards invalidates it instead
# of silently still counting (see ready-guard), and it maintains the
# grandfathered $GIT_DIR/batten-receipts/ compatibility layout — resolved
# per-worktree, so a receipt taken in one worktree cannot authorise
# `gh pr ready` in another. `set -e` above makes a failed record fail this
# gate and leave no receipt. BATTEN_BIN exists so the bats suite can stub the
# binary (bats must never build the workspace — the cargo target-dir lock is
# deliberately serialised in hk) and so a caller with a prebuilt batten skips
# the cargo round trip; the default does add workspace compilation to this
# gate's failure domain.
read -r -a batten_bin <<<"${BATTEN_BIN:-cargo run --quiet -p batten --}"
"${batten_bin[@]}" receipt record linear-check
echo "linear-check: HEAD is linear on origin/main ($main)"
