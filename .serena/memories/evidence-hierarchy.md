# What counts as evidence, and what is only a claim

Read when: about to act on anything a doc comment, a `CLOUD-*` row, a PR body, a
previous session's handoff, `AGENTS.md` or another memory asserts — and ALWAYS
before citing one as the reason for a design decision. Also read it before
writing a claim into any of those surfaces yourself.

## The ranking

1. **Code and tests as they execute right now**, and **the output of a command
   you ran and read yourself.**
2. **Everything else is a CLAIM**: doc comments, the board, PR bodies, commit
   messages, `AGENTS.md`, these memories. Comments are written by the same agents
   who write the board, reviewed no harder, and go stale the same way.
3. **Even (1) goes stale.** A command's output describes the moment it ran, and
   the remote is shared and mutable.

**The operational rule: if a claim is load-bearing, re-derive it from something
executable. If nothing executable exists, THAT ABSENCE IS THE FINDING.** A
constraint worth designing around is worth a test.

`rules/scanning.md` row five is the same rule one level down: to know what a gate
DECIDES, run it and read the exit code. Reading source to predict a verdict "is
worse than guessing, because it looks like rigour."

## The board's measured error rate

**5 of 13** speculation/lease rows audited against the tree on 2026-09-10 were
STALE or REFUTED — ~38%. Rows are written by agents, many running a stale binary
that only ever saw a half-implementation.

**A cheap discriminator, worth keeping:** a row or comment that cites a **retired
artefact** — a shell variable (`spec_undo`, `spec_base`, `LAND_LOCK_HOLDER_PID`),
a line number in `mise-tasks/land.sh` or `land-lock.sh` — was wrong **4 times in
5**. A row citing live Rust paths was usually at least partly live. It is triage,
not a substitute for reading the tree.

## Worked examples, so the shape is recognisable

- **A doc comment that is the foundation of a design and has no test.**
  `lease.rs:1310-1315` asserts the agent proxy 403s a push outside `refs/heads`,
  and concludes the landing lock must therefore be a branch. No test anywhere
  asserts it; `git ls-remote origin` shows `refs/notes` DOES exist on the remote;
  and `mem:github-access` measures the real mechanism — proxied, `git`
  authenticates with the INJECTED token, which 403s writes it is not scoped for.
  Same symptom, different cause. **CLOUD-416 records that this misdiagnosis cost
  the lease being implemented four times.**
- **A Done row whose landing claim is false.** CLOUD-1399 (Done) says commit
  `46530200` landed the `egress-is-unproxied` `[[startup]]` row.
  `git log -S'egress-is-unproxied' --all -- batten.toml` is EMPTY and `46530200`
  is not a valid object. The detector (`doctor egress`) landed; the repair never
  did.
- **A false premise propagating from a PR body into pushed history and then into
  a plan.** PR #934's body and commit `3a18fb5`'s message both state "the holder
  lands by rebase, minting new ones for the same patches." **False** — landing is
  fast-forward and PRESERVES the sha (`mem:decision/landing-architecture`). A
  later session quoted it approvingly and built a fencing argument on it.
- **Two Urgent rows refuted by inspection.** CLOUD-240 reasons over
  `mise-tasks/land.sh:162`, a deleted file; CLOUD-1423 says `batten land` has zero
  callers, but `land lap` is `mise.toml:3494`.

## When you find one

A row the tree refutes goes **back to Backlog with a comment saying what the tree
says instead** — never a note edited into its body, which leaves the false claim
in place above the correction. Then it is not worked until re-filed against
reality. `mem:workflow/board-states`: a state is a claim about the tree, and the
tree wins.
