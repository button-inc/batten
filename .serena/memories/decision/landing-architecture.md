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

## The record layer: what we rent from the forge, and what we must provide

World-writable means **shared address space**, and the honest question is which
security properties we are renting and which we only assumed.

- **Rented**: CAS atomicity on ref update; rollback protection on protected refs;
  admission control (who may write the repo at all).
- **NOT rented, and currently absent**: any binding between a **body** and the
  **writer who wrote it**. The forge authenticates the PUSH, never the RECORD. Its
  ACL says "can write this repo" and we have been reading it as "can write this
  agent's ref."

**"Accident, not malice" was the wrong frame** and it is worth naming as an error
rather than quietly dropping. At the record layer a stale agent writing a wrong
body and an attacker writing a wrong body are the SAME EVENT: a verifier cannot
tell them apart and does not need to. The split does no work, and it was being
used to justify less mechanism.

### DHTs solve exactly this, and they split on mutability

Vanilla Kademlia has no authentication and is open to storage poisoning. What
shipped in real systems is two constructions:

1. **Immutable → self-certifying address.** `key = H(value)` (BitTorrent
   info-hash, IPFS CID). Fetch from `K`, hash what came back, discard on
   mismatch. Tamper-evident with **zero key material**.
2. **Mutable → the address is derived from a public key.** BEP 44 mutable items,
   IPNS: `addr = H(pubkey [+ salt])`, body signed, plus a monotonic `seq`;
   readers reject a bad signature or a non-increasing sequence. **No PKI, no CA,
   no key distribution** — the address IS the identity. That is the whole trick.
3. S/Kademlia adds Sybil resistance (crypto puzzles on node ids, disjoint lookup
   paths). **We do not need that half**: the writer population is not open, the
   forge ACL already bounds it. This is the precise content of the "no Byzantine
   fault" advantage — we need DHT **data authentication**, not DHT **admission
   control**.

### Mapping — git gives construction 1 for free and construction 2 nowhere

| structure             | mutability             | have                                       | gap                      |
| --------------------- | ---------------------- | ------------------------------------------ | ------------------------ |
| `refs/sessions/<sha>` | immutable              | **self-certifying** — ref name IS the hash | none                     |
| the log branch        | append-only            | **Merkle chain** — entries name parents    | rewind                   |
| per-agent ref         | mutable, single-writer | nothing                                    | **the whole BEP 44 gap** |
| the lease             | mutable, multi-writer  | CAS                                        | attribution              |

Per-agent refs are BEP 44 verbatim: an ephemeral keypair per session, ref at
`refs/batten/agent/<H(pubkey)>`, body signed over `(seq, payload)`, readers
verify-or-discard — and a discarded record folds into the membership rule already
committed (_derived from observation with expiry_), so an unverifiable agent reads
as absent. **Fail-closed on content, fail-open on availability.** It also kills a
defect class for free: two agents cannot collide on an id and none can squat
another's address.

For the **lease**, signing changes nothing about eviction — that stays a fenced
CAS, safe under false suspicion. What it buys is that **you cannot write a body
falsely naming another session as holder**, and the fencing token becomes
attributable.

### Where the analogy runs out: replay

**Signatures do not stop rollback.** An old signed body is perfectly valid;
force-pushing a ref back to it passes every check. BEP 44 stops this with a `seq`
**readers remember** — DHTs can because many nodes do, which is precisely the
quorum rejected above (no peer transport, ephemeral containers). Our readers are
reclaimable containers with no memory.

So monotonicity must anchor in **a ref with server-side rollback protection**
(branch protection forbidding force-push), and ultimately trunk. We borrow the
forge's rollback protection for monotonicity the same way we borrow its CAS for
consensus — and that dependency is a **declared forge capability**, because forge
behaviour demonstrably varies by namespace.

CLOUD-877 already asks for this construction (_"give it a portable signed form"_).
CLOUD-591 decided not to sign COMMITS — a different surface, orthogonal, the way
rule 8 splits trailer from committer.

## Deutsch's fallacies, as commitments to check against

**Eight, not seven.** An earlier version merged _bandwidth is infinite_ with
_transport cost is zero_. They are different, and merging them hid the one this
project is most directly a response to: transport cost is the entire economic
premise (serial metered trunk, parallel free agents).

| #   | Fallacy                    | Commitment                                                                                                                                                                  | Mechanism                                                       |
| --- | -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| 1   | The network is reliable    | **Name both errors and fail toward the cheaper one, per (read, decision) pair.** Never a blanket direction — see below.                                                     | partial, per call site                                          |
| 2   | Latency is zero            | No wall clock is READ inside a decision; instants are supplied. **But expiry IS a clock, and cross-agent skew is assumed and unmeasured.**                                  | `clippy.toml` sleep ban, `tests/sleep_ban.rs`; skew: **none**   |
| 3   | Bandwidth is infinite      | Ref advertisement is O(total refs); 79,973 bytes already on record. Per-agent refs and transcripts must not ride it.                                                        | **none** — needs `ls-refs` `ref-prefix` scoping                 |
| 4   | The network is secure      | Every mutable record carries a signature verifiable against its own address, plus a sequence anchored in a rollback-protected ref; a reader discards what it cannot verify. | **none yet** — CLOUD-877                                        |
| 5   | Topology doesn't change    | Membership derived from observation, never a registry needing clean exit — **and a vanished agent's leavings are recoverable.**                                             | `Bet::recovered`; orphan refs **CLOUD-1747, open**              |
| 6   | There is one administrator | Every body carries a schema major; readers reject an unknown one and ignore unknown keys.                                                                                   | `Body::schema` **landed**; "readers before writers" **no gate** |
| 7   | Transport cost is zero     | **The premise, not a caveat.** Trunk serial and metered, agents parallel and free; speculation is pipelining, the lock is linearization.                                    | the speculation design; metrics **none**                        |
| 8   | The network is homogeneous | No host's quirk reaches `crates/batten` — **and no forge's either.**                                                                                                        | rule 1 **enforced**; forge capabilities **prose only**          |

### 1 was actively wrong, and the wrong version would license a real bug

It read _"every read fails open."_ The tree contradicts that where it matters.
`Live::decide` fails **closed** — _"failing open there would make a network blip
the thing that lands somebody else's work"_ — while `authorises` fails **open** —
_"a lease it cannot read stops EVERY job in the fleet, where waving one matrix
through costs one matrix."_

Same read, opposite directions, because the **question** differs. The direction is
a property of the (read, decision) pair, structurally the same argument
`rules/scanning.md` makes for decider-vs-floor being relational and therefore not
expressible as a column. So: at every could-not-look, state the two errors and
their costs and fail toward the cheaper — and a new call site owes that sentence.

The old second clause — _"no fleet-binding decision rests on one failed read"_ —
**is not implemented.** `authorises` reads once. A gap, not a property.

### 2's real gap is clocks, and it is worse than skew

The sleep ban is real and enforced. The clock underneath is not.

**`now_unix()` is `SystemTime::now()` — `CLOCK_REALTIME`, not monotonic.** NTP
step, VM resume and container migration all move it backwards, so a holder that
beats across a backward step re-mints an EARLIER `expires` than the one already
published. **And it answers `0` when the clock will not read**, which makes
`expired(now)` (`now >= expires`) say nothing is ever expired — a clock failure
wedges the whole fleet rather than degrading. `expires == 0` is separately the
tombstone sentinel (`released()`), so zero carries two meanings.

**But no clock choice fixes the real defect.** `expired(now)` compares MY `now`
against YOUR `expires` — an absolute timestamp crossing the wire — and monotonic
clocks are not comparable across machines either. **Expiry must never cross the
wire.** The correct shape is observer-local staleness: B observes the lease at its
own monotonic instant with progress token `P`; if after B's own elapsed ΔT the
token is still `P`, B may judge the holder stalled. B never reads A's clock.

**That mechanism already exists beside it.** `progress` is opaque and compared
_"for EQUALITY OVER TIME… so no clock crosses the wire"_. So `expires` is largely
redundant with its neighbour and is the half carrying every hazard. The change:
**promote the progress token to the primary liveness signal, demote expiry to a
backstop, and if a timeout is kept make it an `Instant` measured locally** — never
a timestamp shipped in a body.

### Clocks do two jobs and only one needs real time

- **Ordering and validity** — "is this record newer", "is my bet against the
  current epoch" → **logical clock: the log index.** No real time at all.
- **Failure detection** — "is the holder dead" → **irreducibly needs a timeout.**
  FLP: a crash cannot be detected without one, and no logical clock answers
  liveness. This part cannot be designed away, only confined.

### Why NOT vector clocks

Considered and declined, so nobody reopens it cold — and recorded because the
first version of this file did not consider them at all.

1. **They reconstruct a partial order where there is no serialization point. We
   have one.** Every fleet event goes through a CAS on a single ref. Same shape as
   the Paxos argument above: a vector relates events across independent replicas,
   and we deliberately have one totally-ordered log. **The log index is already a
   Lamport clock and the total order makes a vector strictly redundant.**
2. **O(N) entries with unbounded, churning N.** Agents are reclaimable containers;
   vector-clock GC for departed processes is unsolved, so entries for dead agents
   accumulate in every body forever — straight into fallacy 3.
3. **They DETECT concurrency; the lease must PREVENT it.** Learning after the fact
   that two writes were concurrent gives no mutual exclusion. `--force-with-lease`
   refuses the loser; CAS is strictly stronger than detection for this job.
4. **On single-writer sharded refs a vector degenerates to a scalar** — no
   concurrency to relate, so a per-writer sequence is exactly sufficient, which is
   what BEP 44 uses.

**The case where a vector IS required, stated as a constraint on the multi-address
design:** N independent CAS addresses means N independent logs and no single total
order, and relating events across them genuinely needs a vector with its GC cost.
So: **one log → a scalar index suffices; multiple independent logs → vector clocks
and their costs.** An argument for one log, or for declaring separate logs
causally independent and never compared.

The sleep ban is real and enforced. But `Body::expires` is an absolute instant and
`expired(now)` compares against one, so the liveness model **is** a wall clock —
merely supplied across the boundary rather than read inside. It assumes bounded
skew and nothing measures it: a holder with a slow clock holds past TTL while a
rival with a fast clock steals mid-matrix, which is **two landers** — the exact
failure the lease exists to prevent.

The skew-free primitive already exists: `progress` is opaque and compared for
EQUALITY OVER TIME, so no clock crosses the wire. That is a logical clock.
**Promote it to the primary liveness signal and demote expiry to a backstop**, and
meanwhile advertise each agent's clock beside its version so skew is measured
rather than assumed.

### 3 — and the transcript design above violates it

"Keep it out of the lap's fetch path" is not enough: **ref advertisement is not
fetch.** The v0/v1 handshake lists every ref whatever you fetch, so transcripts —
the largest objects in the system — would bloat every lease read. The fix is
protocol v2 `ls-refs` with `ref-prefix`, scoping the advertisement server-side.

### 5, 6, 8 each have a named unbuilt half

A reclaimed container leaves a held lease, a readied PR, a burning matrix and
stranded `refs/batten-spec/*` (CLOUD-1747). _Readers ship before writers_ is a
process promise with no gate, which rule 2 calls half a change — `Body::writer` is
the mechanism, refusing to raise the major until the observed fleet minimum is
high enough. And rule 1 governs hosts, not **forges**: fast-forward enforcement was
measured differing by namespace on one forge, so declared forge capabilities need
to be a table.
