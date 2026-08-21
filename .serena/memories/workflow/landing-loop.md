# The landing loop, and why its shape looks like breakage from an old clone

Read this **before** changing anything under `mise-tasks/land.sh*`, `ci-wait`,
`main-watch`, `checks-green`, or `tests/land*.bats`. Three things here read as
defects to an agent on a clone that predates them, and each is the change:

- **a lease held by a live process**, not a file the tree owns;
- **a raced wait with no wall clock anywhere** — no timeout, no cap, no deadline;
- **verdicts that refuse to answer** rather than guessing (exit 3 is a real answer).

Repairing any of them back is the regression. Four gates now refuse the repair,
listed at the bottom with their bypasses so a refusal can be told from a defect.

## The lap

fetch → rebase → `verify` → `verified` → push → `ci-wait` ∥ `main-watch` →
`/fast-forward` → read the answer → lap.

A refusal is **the design working**, not a failure. Each lap rebases onto a
little more landed work, so conflicts arrive one small resolvable increment at a
time; batching laps removes no refusal and only makes each one bigger. An agent
that infers "a race I keep losing" and wraps the loop in bespoke retry is
optimising against the design — measured, CLOUD-238.

`LAND_MAX_LAPS` is a **count** of laps, `LAND_LOCK_MAX_WAITS` a count of lease
turns lost, `LAND_ANSWER_MAX_UNKNOWNS` a count of unreadable bot answers. None is
a clock. A hang is fixed by an exit condition that can fire; a wall-clock cap
reintroduces the VM-reap gap it was meant to close and lands as a false
"refused" on a slow bot.

**`LAND_LOCK_STALL_BEATS`/`LAND_LOCK_HANG_BEATS` are not the exception, and the
difference is worth reading before "repairing" them out** (CLOUD-499). They are
counts of beats **since the last advance**, and the count RESETS on every
advance — a phase transition, a check-run turning, a poll going round. So they
bound nothing about how long a legitimate landing may take: one that keeps
producing state changes never reaches either, however slow it is. What they bound
is how long we keep believing a holder that has stopped producing evidence, which
is what the rolling TTL above already does one signal shallower. The TTL notices a
holder that stopped **beating**; these notice one that stopped **landing** — the
case liveness cannot see, where the lease renews forever and `status` reports a
healthy hold. A deadline on the whole wait would still be the banned thing.

`land`'s closing `could not delete origin/<branch>` is **expected output, not a
failure.** GitHub's auto-delete-on-merge wins the race, so the branch is already
absent by the time `land` asks. Observed on four consecutive lands, each merged
with the branch gone (`git ls-remote` confirms). There is nothing to repair here
— a `land` that deleted successfully would be the one doing redundant work.

## The lease

`land-lock` is a compare-and-swap on `refs/heads/batten-land-lock` — one
operation, no service, no API. Four things the design was pressure-tested into,
each of which cost an incident:

- **It is a BRANCH.** The agent proxy 403s a push outside `refs/heads`, and
  GitHub does not enforce the fast-forward rule off `refs/heads` either — a
  parentless orphan `PATCH` with `force:false` was _accepted_ on a custom
  namespace. The atomicity the design rests on exists only on `refs/heads`.
- **Renewal is `--force-with-lease=<ref>:<observed>`**, a true CAS. `PATCH` with
  `force:false` does not give one. Create stays a plain push, so acquire is an
  atomic test-and-set.
- **The body carries a nonce.** Git addresses by content, so two mints agreeing
  on holder and expiry produce the same sha, and pushing a sha the ref already
  holds is an "up to date" no-op reporting success — a rejected claim reading as
  a win.
- **Rolling TTL (120s) with a 30s heartbeat**, not a static `p95 x 3`. A static
  TTL must bound how long a hold might legitimately take, which is a guess wrong
  in both directions; a rolling one bounds only how long until we notice a holder
  stopped beating. Three missed beats is the Raft/etcd margin.

Enforced at three points, deliberately: `ready-guard` (free, local, a receipt),
`ci-lease-precondition` (server-side, costs a cancelled matrix), and `land`
itself. The first is a fail-fast convenience — a hook can be unloaded — so the
CI-side check is the load-bearing half. Every one of them **fails open**: a gate
that cannot look must never become a gate that blocks everything, because the
cost of failing open is one matrix and the cost of failing closed is the fleet.

## Why there is no clock, anywhere

`ci-wait` is unbounded by design and `tests/land.bats` asserts the task carries
no wall-clock timeout. The tests are held to the same bar, and the shape to copy
when a case genuinely needs a precondition the runner might not create is
CLOUD-448's, in `tests/land-lock.bats`: **retry the SETUP, never the
MEASUREMENT** (retrying the measurement is drive-to-green), and `skip` with a
diagnostic naming the ticket when N attempts fail to establish it.

The failure this prevents is subtler than a flake: a guessed `sleep` standing in
for "the background thing has happened" makes a case pass **vacuously** on a
loaded box — the process is alive because it never ran, so a regression is
invisible on exactly the runs where the suite is slowest.

## Verdicts

- One roster, `CI_REQUIRED_CHECKS` in `mise.toml [env]`, read by `checks-green`
  and by `land`'s `graded_runs`. Two copies drifted once and that was CLOUD-327.
- **Each name is judged by its LATEST run** — a sha accumulates a check-run per
  event, and a draft-created head carries its `opened` skip set forever.
- `skipped` and `cancelled` are **not** bad conclusions; they are the absence of
  an answer, and reading either as red wedges a branch with no exit. `absent` is
  different again and is tolerated only where a workflow is path-filtered.
- Exit **3** is "no answer yet" and is a first-class outcome, not a failure to
  decide. Exit **2** is "could not look", and it must never be reachable from a
  path that would otherwise spend a matrix.
- The fast-forward verdict is keyed to the PR's own comment id via the
  workflow's `run-name`, because an `issue_comment` run attaches to the
  default-branch tip and carries nothing else that identifies the PR. Reading it
  by timestamp alone means reading strangers' refusals as your own.

## The gates that refuse a repair

| Gate              | Refuses                                                                                        | Bypass                           |
| ----------------- | ---------------------------------------------------------------------------------------------- | -------------------------------- |
| `ci-local-parity` | a `pull_request` job with no lease precondition; a precondition body run without `\|\| exit 0` | — (gate, not a hook)             |
| `ready-guard`     | `gh pr ready` without verify + linear-check receipts for this exact HEAD, or without the lease | `BATTEN_READY_GUARD_BYPASS=1`    |
| `run-shape-guard` | discarding a verdict-bearing command's exit status                                             | `BATTEN_RUN_SHAPE_BYPASS=1`      |
| `contract-drift`  | nothing — it reports, once, that the surface moved under a running session                     | `BATTEN_CONTRACT_DRIFT_BYPASS=1` |

## Rollout posture

Every mechanism here fails open on a clone that predates it, so none of them
binds an agent that never fetches. `branch-age-check` is the backstop: a branch
old enough to be dangerous is already failing a gate for being old.
