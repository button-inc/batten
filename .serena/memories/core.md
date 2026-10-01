# Top-level source map

Single workspace crate: `crates/batten` (bin `batten` + lib `batten`). Root
`Cargo.toml` holds workspace lints/profiles; see `.claude/rules/rust.md` for
style rules (thin `main`, no `unwrap`/`expect`/`panic`, exit-code branching).
This memory is the router: it names every other memory and when to read it,
and it stays small enough to read whole in one call — `[budget.memories]` in
`batten.toml` holds every memory under the per-file ceiling (CLOUD-1934).

## Where the rest lives — read the right one at its trigger

This memory is the graph root: every other memory is reached from here, and the
trigger for each is stated here rather than inside it (`mem:memory_maintenance`).
Read on demand, never all of them.

- `mem:evidence-hierarchy` — **before acting on anything a doc comment, a
  `CLOUD-*` row, a PR body or a handoff asserts**, and before citing one as the
  reason for a decision. The board audited at ~38% wrong; comments are no better.
- `mem:decision/adr-process` — recording a decision; about to add a `status:`,
  `superseded-by:` or version suffix to any document.
- `mem:decision/landing-architecture` — touching `land.rs`, `lease.rs`,
  `speculation.rs`, `pipeline.rs` or the landing workflows; any row about the
  lease, the lap, speculation, eviction or landing throughput.
- `mem:workflow/board-states` — starting or finishing a `CLOUD-*` issue;
  reasoning about what is in flight.
- `mem:workflow/agent-fanout` — spawning a subagent, or running more than one
  session against this repo.
- `mem:workflow/landing-loop` — landing a branch; before "repairing" `land`, the
  lease, the CI wait or their suites; porting a lifecycle (a trap, a lock, a
  reaper) out of a retired program.
- `mem:workflow/sonar-scope` — Sonar refuses your branch; reading or changing
  `sonar-gate`; a Sonar verdict looks wrong on a SHA; before treating a `final`
  failure as trunk's, or a check-run's annotations as the whole finding list.
- `mem:session-transcript-access` — asked to read chat history or another
  session; before probing a session API or credential.
- `mem:github-access` — any GitHub op; before claiming the toolchain or CI
  "can't reach GitHub".
- `mem:gate-could-not-look` — a gate is green locally and red in CI on the same
  SHA; before re-running a gate, calling a CI failure a flake, or reading exit 0
  as a pass.
- `mem:github-rest-etiquette` — writing a task that calls the GitHub API;
  diagnosing a 403/429/abuse response.
- `mem:toolchain-and-hooks` — pinning a tool, adding a task, touching `hk.pkl`
  or the gate. **Before editing a `mise-tasks/*.sh` or a `tests/**/\*.bats`, the
  binding rule is `.claude/rules/toolchain.md`'s two shapes\*\* — retire it whole
  or leave it — not this memory, which describes the layer being retired.
- `mem:serena-setup` — a Serena worktree or index misbehaves; changing
  `.serena/` config.
- `mem:prior-art-and-issue-hygiene` — surveying outside practice; adopting a
  tool or pattern; writing an issue or PR body.
- `mem:connector-allowlist-recovery` — **any** `MCP tool call requires approval`,
  including `create_session`/`list_sessions`/`get_session` (each answers after an
  approval; no user-facing setting clears that prompt, and Claude Code Remote
  is not listed at claude.ai/customize/connectors — CLOUD-1946); a connector's
  tools start prompting or denying,
  reappear under a different name, or are **absent entirely** ("No such tool
  available"); before telling anyone a connector is unattached or needs
  authorizing; and when `claim-check` has no payload to read, since a missing
  receipt stops `verify` and strands the branch.
  **Read it BEFORE the first probe, not after it fails** — this has been
  re-derived by experiment in at least three sessions, each time ending in advice
  to change a setting that does not exist.
- `mem:memory_maintenance` — writing, renaming or splitting a memory; the
  shipped convention template.
- `mem:engineering/module-map` — finding which `crates/batten/src/` module owns
  a responsibility, or adding a module (its line is gated).
- `skills/groom/SKILL.md` — grooming, refining or promoting any row toward
  Todo. A procedure, not a memory: `ready lint` exit 0 is its floor, never its
  verdict (CLOUD-1968).

## `crates/batten/src/` module map

One line per module lives in `mem:engineering/module-map` — read it when you
need to know WHICH module owns a responsibility. Each module's own `//!` doc
comment carries the why; the map carries only the where.

## Tests

`crates/batten/tests/cli.rs` — end-to-end over the _compiled_ binary
(`CARGO_BIN_EXE_batten`), asserting exit codes and output shape consumers
depend on. Prefer adding here over unit tests for anything behavioral
(`.claude/rules/rust.md`).

`crates/batten/tests/pointer_only.rs` — non-negotiable rule 4 given an exit code
(CLOUD-92). A corpus in which every byte a check can read is a distinct canary,
crossed with a **census over every leaf verb of `surface::SURFACE`**, asserted
total in both directions — so a verb joining the surface fails the suite until
somebody classifies it. Two canary classes, because the law is about content and
not about config: content bytes (a matched line, a counted body, a transcript's
free text, a child's stream, a mediated operand) may reach no verb's output,
while declaration bytes (a rule's `pattern`, a waiver's `reason`, a ledger's
`evidence`) are what `config show` and `generate schema` exist to echo —
collapsing the two makes the gate either vacuous or false. `exec` is held to a
COUNT rather than to absence: its child's streams are inherited by contract, so
the defect is Batten's report adding a copy. It sits at the **process boundary**
rather than at the emitters because there is no shared emission path to put it
in (CLOUD-371); the bytes the process wrote is where all ~30 `writeln!` sites and
ten differently-named renderers already converge, so no new emitter can route
around it. Every verb passed as landed — the engine held the law and only the
proof was missing.

`crates/batten/tests/primitives.rs` — the CLOUD-9 core primitives over the
_library_ surface, since they mint no subcommand and the fixture suite is their
gate (Option A). Carries the hermetic git fixture builder and the keystone: a
rebased-and-landed branch is merged though `--is-ancestor` says otherwise. The
former bats suites moved onto compiled tiers under `crates/batten/tests/it` as
the shell retired (CLOUD-843); `test:bats` and the vendored runner are gone.

## Self-consumption

Root `batten.toml` is Batten's own policy config — "consumer #1" (AGENTS.md
rule 1) — gated by `batten check` against this repo. The template for external
consumers is `crates/batten/src/starter.toml`, emitted by `batten init`; it
lives in-crate because `crates/batten` is the published package and
`include_str!` cannot reach outside it. `batten.example.toml` is still here and
is a different artifact — a teaching document, gated separately — and retiring it
in favour of the starter is CLOUD-206's follow-up. `.taplo.toml` binds all three
to `schema/batten.schema.json`.
