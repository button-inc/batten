# A gate that could not look reads exactly like a gate that passed

Load this when a gate is **green locally and red in CI on the same SHA**, before
re-running anything, and before concluding a CI failure is a flake or that CI is
wrong.

## The class

Every gate here fails open on what it cannot reach — no `gh`, no network, an
unparseable answer. That is correct: a verdict about the environment must not be
spoken as a verdict about the tree. The cost is that **exit 0 has two meanings**
and the human channel does not always distinguish them.

So "it passes locally" is not evidence the gate agrees with CI. It may be
evidence the gate never ran.

## Measured, 2026-09-04 (CLOUD-1422)

`claim-race-check` gave three different answers about ONE commit:

| how it was run                | answer                                 | exit |
| ----------------------------- | -------------------------------------- | ---- |
| bare, outside the task runner | `gh is not available — could not look` | 0    |
| under `mise exec`             | `no open PR races this branch's claim` | 0    |
| in CI                         | `claim-not-raced`                      | 1    |

Two green readings on the SHA CI refused. The first is could-not-look wearing a
pass; the second is a real pass over a _different input_ than CI had.

The cause was an input, not the code: `actions/checkout` on a `pull_request`
event leaves a DETACHED HEAD, `gh pr view` with no argument resolves the PR from
the current branch, and there is none — so the script's `self` was empty and the
branch was compared against its own PR.

## The technique that works

**Reproduce the gate's CONDITION, never re-run the gate.** A re-run tests whether
the failure is deterministic; it cannot tell you why. Recreating the condition
tells you why on the first try.

Here that was three commands and no CI minutes:

```sh
git worktree add --detach "$SCRATCH/wt" HEAD   # the condition: no current branch
cd "$SCRATCH/wt" && mise exec -- ./mise-tasks/<gate>.sh
git worktree remove --force "$SCRATCH/wt"      # clean up, or `git worktree prune`
```

It reproduced the CI error verbatim, named the raced key, and cost nothing.

## What to ask, in order

1. **What input does this gate read that differs between here and CI?** Checkout
   shape (detached vs branch), credentials and their scopes, which binaries are
   on `PATH`, whether `origin/main` exists in a shallow clone.
2. **Was the local pass a reading or an abstention?** Re-read the gate's own
   stdout. `could not look`, `not available`, `configured but not readable` are
   abstentions. Silence is usually a pass; a sentence about the environment is
   not.
3. **Only then** consider a re-run, and only to establish determinism.

## The cost of skipping it

One re-run was spent on a failure that was deterministic by construction, on the
theory that an edited PR body had changed the answer. The condition — a detached
checkout — was unchanged, so the second attempt failed identically. The worktree
reproduction, done first, would have said so for free.

## Related

`mem:github-access` before concluding the toolchain cannot reach GitHub — a
scope failure and an outage look alike here too, and both fail open.
