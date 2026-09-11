# The landing system: what it is for, and the decisions that follow

Read when: touching `land.rs`, `lease.rs`, `speculation.rs`, `pipeline.rs`, the
land/lease region of `lib.rs`, the landing workflows, or any `CLOUD-*` row about
the lease, the lap, speculation, eviction or landing throughput.

This file is a DECISION RECORD under `mem:decision/adr-process`: it is rewritten
in place to the current truth, carries no supersession markers, and `git blame`
is its amendment history.

## The guarantee everything hangs off

**Fast-forward-only linearized trunk. Landing PRESERVES the sha.**

> CI goes green on head `H`; trunk fast-forwards to `H`; the runs on `H` **are**
> the runs on trunk. **CI never runs twice.**

**The holder does NOT land by rebase.** PR #934's body and commit `3a18fb5`'s
message both say it does ("minting new ones for the same patches") and both are
wrong; a 2026-09-10 session quoted that approvingly and built a whole fencing
argument on it. A waiter that speculates on `H_A` and sees the holder land `H_A`
unchanged was **exactly right** — speculation converges, it does not churn.

## What the lock is for

**The lock is the LINEARIZATION mechanism, not a spend limiter.** Its purpose is
to eliminate contention and keep CI **maximally saturated with only green
matrices on the critical path.**

The two resources are asymmetric, and this is the whole design pressure:

- **The trunk is serial and metered.** One branch lands at a time and each
  occupies a CI matrix that costs money. (Free public runners today; paid before,
  when private; paid again on the bigger runners coming.)
- **Agents are parallel and free.** In-process agent work has no monetary cost,
  so **agents are the parallelization lever** precisely because trunk
  linearization is the bottleneck.

So: push the maximum work into the free parallel phase, the minimum into the
metered serial one. An agent must prove — with receipts for everything CI will
run — that its tree is already green **before** admission to a matrix. The matrix
VERIFIES a claim; it does not discover. Agent local prep being ≥ half the landing
wall clock, usually much more, is the design working.

**Speculation is the pipelining mechanism, not a workaround.** While the holder
occupies the slot with `H_A` in CI, a waiter rebases onto `H_A` — the trunk that
is about to exist — and spends its free local prep there, so the instant the
holder lands, the waiter's matrix starts against an already-proven tree.

**k = 1, and a semaphore is not the lever.** Widening the slot means k heads
racing for one fast-forward target; every loser's matrix is spent on a head that
can no longer land. Throughput comes from pipelining the slot, not widening it.

## The metrics that do not exist, and must

None of the three quantities that define the objective are instrumented:

1. **Skew** — last green matrix end → next green matrix start. The primary
   metric; speculation done right drives it toward zero.
2. **Cost per run in BOTH currencies** — CI minutes (monetary) and wall clock.
   They diverge and are optimised differently.
3. **Agent local prep wall clock** — free in money, dominant in time, the phase
   the design deliberately loads. Unmeasured, so nobody can tell exhaustive
   proving from spinning.

CLOUD-492 measures divergence-from-linear, which is adjacent and not this. **You
cannot tune a pipeline you cannot see** — every design argument here is a guess
until these exist.

## The poison cascade, sized correctly

Because speculation is pipelining, a poisoned holder is not one branch's problem:
**every waiter that prepped against `H_A` spent its slow-but-free phase against a
base that will never exist.** The cost is an emptied pipeline plus N agents' prep
discarded — not a wasted matrix. Hence: detect poison with the fastest oracle,
broadcast it, and make the cooldown proportionate.

**CI is the oracle for poison, not a waiter's local verify.** A waiter's own red
cannot distinguish "the borrowed base is bad" from "my change is bad" without a
second run. That is why the pre-2026-09-10 design needed a two-lap discrimination
dance, a suspicion surviving a process, and a promotion step — all of it working
around asking the wrong oracle.

## Consensus: we already have it — do NOT implement Paxos or Raft

**We are not in the message-passing model.** Each ref is a register,
`--force-with-lease` is an atomic compare-and-swap, fetch is a read.

- **CAS has consensus number ∞** (Herlihy, _Wait-Free Synchronization_). A single
  CAS register solves consensus for any number of processes, wait-free. **The
  remote already IS our consensus.** Paxos on top would be a second source of
  truth that can disagree with the first.
- **There is no peer transport.** Agents have no inbound addresses; every
  "message" is a write to the remote another agent reads. "Gossip" here _is_ the
  remote, which is already the serialization point — an eventually-consistent
  overlay on a linearizable store trades away the strongest property we have.
- **Quorum members are reclaimable containers**, so quorum loss would be routine
  rather than exceptional. Raft over ephemeral agents is a liveness liability.

This is the Chubby argument (Burrows, OSDI'06): most systems want a
lock/consensus **service** their clients call, not an embedded consensus library.
The forge is our Chubby. `openraft` and TiKV's `raft-rs` were considered and
declined — the reason is the substrate, not their quality.

## What to build instead: a replicated log on the register

The missing primitive is not agreement but **total order**. **The log is a branch
whose commits are its entries**; appending is commit-then-CAS-the-tip, retrying on
conflict (lock-free, correct for a fleet this size).

One construction pays for four things:

1. **A real monotonic epoch** — the log index. Better than the trunk tip, which
   only advances when something lands; the index advances on every fleet event,
   so bets, evictions and cooldowns can be fenced against activity too.
2. **The queue, with agreement by construction.** Everyone reads the same
   sequence, so everyone computes the same order. No votes, no round trips.
3. **Front-of-queue skips as a declared priority class.** `release` and `human`
   (the manual no-agent fast-forward) sort ahead of `agent`; FIFO by log index
   within a class. The release path stops being a special case that races the
   fleet. **Starvation must be designed against** — strict class priority starves
   `agent` under sustained release load, so this needs aging or a reserved share,
   declared rather than discovered.
4. **An audit trail** — ordered, attributable entries.

## Eviction: fencing, not voting

**No failure detector is accurate in an asynchronous system.** FLP kills
consensus with one crash fault under message passing; the CAS register sidesteps
that for _agreement_, but nothing sidesteps _detection_. Every suspicion of a
dead holder is a heuristic, and a vote does not make a wrong suspicion right — it
makes several agents confidently wrong together.

So the design must be **safe under a false suspicion**, which fencing gives and
voting does not: eviction is a CAS advancing the lease's fencing token. The
evicted holder is not asked and need not be reachable; its next write presents a
stale token and is refused, so **a wrongly-evicted holder cannot corrupt anything
— it loses and re-laps.** (Kleppmann's fencing argument.)

Therefore the eviction notice is **advisory** (a peer's request the holder may
honour early and cheaply) while the eviction itself is **unilateral and fenced**
(the referee's CAS). Both halves, each doing the job it is sound for.

## The referee is a declared ROLE, not a named platform

Non-negotiable rule 1: batten adjudicates for six harnesses (`Harness`,
`crates/batten/src/hook.rs`) and runs on agent containers, CI runners and
developer machines. So **"a GitHub Action" must not appear in `crates/batten`.**
The core defines _an executor whose binary version is attested_ and _which
decisions require one_; a consumer's `batten.toml` names the instantiation.

In this repository that instantiation already half-exists: five workflows run
`batten lease guard` from a binary installed **from trunk**, not from the PR. It
reads shared state and cancels unauthorised matrices; it never writes. Extending
it to write is the referee.

**A consumer with no such executor must degrade honestly** — fall back to
epoch-and-TTL expiry, weaker but not wrong. A mandatory referee in the core is a
consumer fact smuggled into the agnostic half.

Same discipline: the epoch is the **declared trunk's** tip, not `main`'s; the CAS
address is a ref on the declared remote; and the forge behaviours the lock leans
on (atomic ref update, fast-forward enforcement) are **declared capabilities, not
assumptions compiled in.**

## Identity: the tuple, because a branch name is not an identity

`host-pid-nonce` dies with the process, and **branch names get reused**. The
stable identity carried IN each entry — never derived from live state that may
have moved — is:

```
{account, session-id, session-name, session-url, pr-number, branch,
 batten-version, epoch}
```

Why each: **pr-number** because a branch name alone cannot be matched to its pull
request after the fact, and an audit trail is about what was true then;
**session-url** so something clickable leads to the harness session that wrote
the entry; **session-name** so it is findable in the GUI; **account** so you know
**which human to hold responsible for a misbehaving agent cluster** — on a fleet
with a world-writable lock, the operationally important question;
**batten-version** so skew is visible rather than inferred.

**Unresolved and must be settled before designing this in:** which commit-metadata
surface may carry it. `[attribution] identity_deny` governs committer/author and
non-negotiable rule 8 refuses a harness identity request there; `trailer_deny`
forbids `^Claude-Session:` and `claude.ai/code` outright. Neutrality is about _who
is credited_; blame attribution is a different requirement and may need its own
declared surface. Settle against `rules/commits.md` and
`no-denied-identity-prescribed`, not after a gate refuses it.

## Transcript preservation: `refs/sessions/<sha>`

A redacted transcript per session, from every harness, so agents can investigate
**clusters of repo misbehaviour** without touching code or the landing refs.

**Shape: a parentless orphan per transcript, content-addressed.** No parent, no
children, created by a plain push — the same test-and-set the lock uses, except
the address IS the content hash, so there is one writer per address by
construction and no contention at all.

**Inertness is structural, not conventional.** A parentless commit can never
_become_ an ancestor of trunk: it cannot be fast-forwarded into anything and
nothing can descend from it. Keeping it out of the lap's fetch path is then a
performance concern, not a correctness one.

**Recanting is cheap**: delete the ref and the object is unreachable and
collectable, with nothing orphaned. So **the risk is what has already been read,
not permanence** — which is why fail-closed redaction is a strong default rather
than an absolute bar.

**Residual risk is not uniform**, and this is the part to design to:

- **A GitHub credential leaked through GitHub is the safest case** — GitHub scans
  its own token formats and auto-revokes its own disclosed credentials. It is
  self-defending.
- **Third-party credentials are the actual residual**, because nothing revokes
  them. Near-zero in this environment by construction (MCP is credentialless, no
  other system access) — but **batten runs across many environments**, so the
  core must not assume one where the only credential self-revokes. The redactor's
  patterns are a consumer fact; failing closed is the agnostic rule.

Already built: CLOUD-651 (Done) is the collector; `ripsecrets` is provisioned;
CLOUD-59 (Done) added the `secrets` rule kind. **Durable publication is the
missing half.**

## The open questions, stated rather than assumed

1. Which commit-metadata surface carries the blame identity (above).
2. **Log compaction** — an append-only branch grows without bound and every agent
   fetches it. Needs snapshot-and-truncate with a measured ceiling, or it becomes
   the bandwidth defect the design already warns about.
3. **Starvation policy** for the priority queue — aging, or a reserved share.
4. **Whether CAS addresses must live under `refs/heads`** — untested, and the
   claim traces to a misdiagnosed credential failure. See
   `mem:evidence-hierarchy` and CLOUD-416.

## Deutsch's fallacies, as commitments to check against

| Fallacy                       | Commitment                                                                                                                                                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The network is reliable       | Every read fails open; no fleet-binding decision rests on one failed read; every write is CAS-or-retry.                                                                                                             |
| Latency is zero               | **No wall clocks anywhere** — counts and supplied instants only. The epoch design keeps this by making expiry an EVENT, not a duration.                                                                             |
| Bandwidth / transport is free | The sharded and log designs make this WORSE and must pay for it: ref advertisement is O(refs), and a 79,973-byte advertisement is already on record. Reaper plus a measured ceiling, or the fix is the next defect. |
| The network is secure         | World-writable by construction; the threat is accident, not malice. Trunk stays sacred: the referee re-derives rather than trusting a request.                                                                      |
| Topology doesn't change       | Agents vanish without deregistering. Membership is derived from observation with expiry, never from a registry needing clean exit.                                                                                  |
| There is one administrator    | **False by construction** — agents run different binary versions. Every ref body carries a schema major; readers ignore unknown keys, reject an unknown major, and ship a release before writers.                   |
| The network is homogeneous    | Six harnesses, three environment classes. No environment's quirk may reach `crates/batten` (rule 1).                                                                                                                |
