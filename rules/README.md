# The instruction surface, and what each rule in it is

Batten adjudicates for six harnesses — `Harness` in `crates/batten/src/hook.rs`
names `ClaudeCode`, `Cursor`, `CopilotCli`, `GeminiCli`, `CodexCli` and the
neutral `ExitCode` contract. Its doctrine used to live in `.claude/rules/`, which
five of the six cannot read. A completion gate shipping as a consumer-installable
product cannot have its own rules readable by one vendor's host: that is
non-negotiable rule 1's argument, applied to the instruction surface instead of
to the core (CLOUD-1152).

`AGENTS.md` is the routing table and is already neutral — `CLAUDE.md` is a
symlink to it. This directory is what that table now points at.

## The home, decided

**A root `rules/` directory, with `.claude/rules/*.md` kept as pointer stubs.**
The alternatives and why they lost:

- **Expand `AGENTS.md`.** It is budgeted on purpose (CLOUD-683), and
  `batten policy budget` gates it. The routing table exists _because_ the budget
  does; folding five files back in is what the budget was set to refuse.
- **Push each rule down into its mechanism's header.** Where a rule is genuinely
  mechanism-owned this is right, and the (a) rows below do exactly that. It fails
  as a general answer because a reader looking for doctrine has nowhere to start:
  a header is discoverable only once you already know which module owns it.
- **Copy the directory per vendor.** Five stale copies is worse than one, and
  `rules-drift` would then police a cartesian product.

**The trigger question, answered rather than deferred.** A rule nothing routes to
is read by nobody. Two things route to these files now:

1. `AGENTS.md`'s table, in **one hop**, for every harness that reads it — which
   is all six, since it is the neutral root document.
2. Claude Code's frontmatter `paths:` trigger, which stays in `.claude/rules/`
   as a stub. That is the one genuinely vendor-specific affordance in the whole
   surface, so it is the one thing left in the vendor directory.

**What this does not claim.** Relocation is not reach. Batten's own neutral
channel — a `[[rule]]` row's `glob` as the trigger, `severity = "warn"` as the
advisory, the `[[verdict]]` registry as the text — delivers at the act rather
than at session start, and `AdvisoryReach.delivered_on` is non-empty for
**2 of 6** hosts (`ClaudeCode`, `GeminiCli`) since CLOUD-1362 closed the Gemini
half. Moving prose ahead of that channel was what CLOUD-1152 forbade; moving it
now that the channel carries more than one host is what it asked for. Taking the
remaining four is CLOUD-209's probe and CLOUD-44's shim, not this file's.

## The classification

Each rule is exactly one of: **(a) mechanism-owned** — the authority is a module,
task header or source comment, and the prose is a pointer; **(b) vendor-specific**
— it describes one host's own affordance and belongs in that host's directory;
**(c) neutral doctrine with no mechanism** — rule 2's _half a change_, which owes
a gate or a filed gap.

| file                | class              | the authority it points at, or the gap                                                                                                                                                                                                                                                                                                                                          |
| ------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rust.md`           | (a)                | `clippy.toml` (lint and spawn census), `Cargo.toml` workspace lints, `crates/batten/src/exit.rs` for the exit table. `crates/batten/tests/it/ambient_authority.rs` holds the client closure; `mem:core` holds the module map.                                                                                                                                                   |
| `toolchain.md`      | (a)                | `policy/shell-retirement.rego` owns the two shapes and every admission arm; `mise.toml` task bodies own the lifecycle; `mise-tasks/step-receipt.sh` owns the receipt spec. The prose restates none of the arm counts any more — CLOUD-1150 is what a restated count cost.                                                                                                       |
| `commits.md`        | (a)                | `batten.toml`'s `[attribution]` table and `crates/batten/src/commit.rs`; `release-plz.toml` for the bump arrows.                                                                                                                                                                                                                                                                |
| `scanning.md`       | (a) + a stated gap | `batten.toml`'s `no-tool-substitution` gates the substitution axis. **Instrument suitability is (c) and is declared unowned in the file itself** — there is no honest exit code over "was this the right class of instrument", and non-negotiable rule 3 refuses a gate over a judgement. `crates/batten/tests/it/scanner_taxonomy.rs` gates the prose's shape, not its advice. |
| `policy-modules.md` | (a)                | `policy/rules-drift.rego` holds its `input.*` key lists to the generated schemas in both directions; `crates/batten/src/policy.rs` owns the load-time refusals. Its own §"What this file does not gate" states the residue.                                                                                                                                                     |

**No rule is class (b).** That is the finding rather than an omission: nothing in
these five files described a Claude Code affordance. The only vendor-specific
thing in the surface was the _loading mechanism_, which is why the stubs keep
their frontmatter and carry nothing else.

**No rule was dropped in the move.** The five files are `git mv`'d, so the diff
shows renames rather than deletions and additions; the only content change is
that each moved file's frontmatter went to its stub, where the trigger lives.

## What stayed in `.claude/`

`.claude/settings.json` (hook wiring), `.claude/hooks/git-hook.sh`,
`.claude/commands/`, and the five pointer stubs. `.serena/memories/**` is a
second vendor surface with its own loading contract and is **inherited debt named
rather than folded in** — CLOUD-1152 §2 puts it out of scope, and it needs a row
of its own.
