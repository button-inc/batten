# Top-level source map

Single workspace crate: `crates/batten` (bin `batten` + lib `batten`). Root
`Cargo.toml` holds workspace lints/profiles; see `.claude/rules/rust.md` for
style rules (thin `main`, no `unwrap`/`expect`/`panic`, exit-code branching) —
this memory only maps what each module does, since nothing else does.

## `crates/batten/src/` module map

Each module carries a dense rationale doc comment (`//!` at file top) — read the
file itself for the "why", this is only the "where":

- `main.rs` — binary boundary: parse → `lib::run` → exit status. Only place
  `print*!`/stderr writes are allowed.
- `lib.rs` — library entry point (`run`), declares the module tree.
- `surface.rs` — house-style §11, CLOUD-27: the command tree declared **once**,
  as data (`ROOT` + `SURFACE`) — path, summary, effect, and flags (with each
  flag's env equivalent, so §8 precedence is inspectable data). `command()`
  builds the live `clap::Command` from it, and `effect_for` resolves the §5
  effect model off the same rows, so the parser, the emitted spec, the derived
  allowlist and the completions cannot disagree. Absence = `Ask`, never `Read`.
- `cli.rs` — the other half of the surface: turns parsed `ArgMatches` into the
  typed `Cli`/`Command` enums `lib::run` dispatches on, so dispatch stays an
  exhaustive `match` rather than a lookup on strings. Verbs today: `check`,
  `enforce`, `config show`, `spec`, `generate completions`, `hook`,
  `receipt record|status`. Adding a verb is a `surface.rs` row plus the arm
  here; a row without an arm fails `cli.rs`'s `every_leaf_verb_dispatches`.
- `effect.rs` — the house-style §5 effect _vocabulary_ (`read`/`write`/
  `destructive`/`unclassified`/`ask`) and its stable tokens. The classification
  itself lives on each `surface.rs` row, not in a second table keyed by the
  same paths.
- `spec.rs` — house-style §11: introspects the live `clap::Command` tree plus
  the `surface.rs` effect rows at runtime into byte-stable JSON (`batten spec`),
  and derives the read-only allowlist from the same walk. Completions derive
  from this too — `batten generate completions` emits them on stdout and
  `completions-check` diffs the committed copy byte-for-byte (DoR §4).
- `exit.rs` — the `ExitCode` contract (stable numeric values); branch on named
  variants, never integer literals. One table, no per-verb exception (CLOUD-226):
  `0` clean/allow, `1` usage, `2` the policy verdict — a `check` violation and a
  `hook` deny alike — `3` internal. The numbering makes fail-open structural, and
  a unit test asserts no failure code equals the deny code.
- `error.rs` — two typed carriers the binary boundary downcasts on: `UsageError`
  → `ExitCode::Usage` (1) for expected bad-input vs. an internal failure, and
  `Denial` → `ExitCode::Violation` (2), the mediation verdict travelling to the
  one place allowed to write stderr. A `Denial` prints _unprefixed_: a host hands
  that text to the model as the deny reason, where `batten: ` reads as a crash.
- `config.rs` — loads/validates one `batten.toml` (typed, no unknown keys,
  required `version`). Layering across sources is `resolve.rs`, not here.
- `trust.rs` — house-style §8 config trust (CLOUD-31): `load_base` reads the
  committed authority from a git ref via `git::show`, so `--config-from` loads
  policy out of band of the change under review and a branch cannot lower the
  bar it is judged by. `weakenings` is the base-vs-working comparison — the same
  monotonicity the raise-only clamp uses, so narrowing `scope` is tightening and
  is not reported. Pointer-only `Weakening`s (key path + two verdict tokens),
  sorted so the report is byte-stable. `config lint` (CLOUD-87) reuses both
  rather than growing a second trusted-load path.
- `resolve.rs` — house-style §8 precedence resolver: `flag > env > local file >
repo config > default`, declared as data in `SETTINGS` (per-key env var/flag),
  not hard-coded per field.
- `git.rs` — the one repo-root primitive (CLOUD-34): the parent of git's
  _common_ directory, so linked worktrees resolve to the main repository root.
  Discovery env is scrubbed; outside-a-repo, bare, and submodule-interior
  layouts raise `UsageError` rather than mis-root. All git plumbing flows
  through here — the single-implementation assertion in its tests is the gate.
- `state.rs` — out-of-tree state dir (`<data-dir>/<app>/<repo-name>/`, CLOUD-23),
  via `etcetera`; repo-name derived at runtime, never baked in (rule 1).
- `rules.rs` — the rule/check engine (CLOUD-12): glob-selected, `kind`-typed
  predicates over the repo. `run_static` (read-effect, no process spawn) backs
  `check`; `run_all` (every kind) backs `enforce`. `check` refuses a
  command-executing rule rather than silently skipping it. Each rule pins a
  required `severity` (`RuleSeverity`, no implicit fallback) and a separate
  `scope` (`RuleScope`, pinned default `tree`) — two axes that never conflate
  (CLOUD-61); `any_blocking` is where severity meets the exit contract.
- `hook.rs` — the `hook` adjudicator (CLOUD-202): the normalized envelope, the
  wrapper-lookthrough command parser, and the policy tables, ported from the
  shell guards. Harness adapters decode/encode at the edges; the core is
  harness-blind and fail-open. What varies per harness is the _channel_ a deny
  travels over, never the number: the exit-code adapter denies with `2`, the
  claude-code adapter with a `permissionDecision` document and exit `0`.
- `identity.rs` — finding-identity fingerprints (CLOUD-123): SHA-256 over a
  normalized, kind-discriminated tuple — never raw `file:line` — so line
  insertion doesn't re-mint a finding; content changes correctly do.
- `receipt.rs` — verification receipts (CLOUD-203): SHA-keyed in-toto
  statements that a named check passed, stored out-of-tree (first caller of
  `state.rs` and `identity.rs`) plus the grandfathered
  `$GIT_DIR/batten-receipts/` compat layout the shell readers consume;
  validity (`valid`/`stale-head`/`stale-main`/`missing`) is a pure function
  of receipt + git facts — amend, rebase, or a moved main invalidate, never
  a clock.
- `severity.rs` — the severity taxonomy (CLOUD-168): one rank table plus the
  adapter across the three axes — `RuleSeverity` (config, CLOUD-61),
  `AdvisoryTier` (the one _stored_ severity, CLOUD-80/78), `ReportLevel`
  (render, CLOUD-130). Mapping is by **rank, never by name**: config `warn` is
  tier `caution`, tier `warning` is config `deny`. Lookups are exhaustive
  matches into the table, so they are total with no panic path. A leaf module —
  consumers attach as they land.

## Tests

`crates/batten/tests/cli.rs` — the only integration suite: end-to-end over the
_compiled_ binary (`CARGO_BIN_EXE_batten`), asserting exit codes and output
shape consumers depend on. Prefer adding here over unit tests for anything
behavioral (`.claude/rules/rust.md`). Non-Rust tests (`mise-tasks/*` scripts,
gates) live under `tests/*.bats`, run via `mise run test:bats`.

## Self-consumption

Root `batten.toml` is Batten's own policy config — "consumer #1" (AGENTS.md
rule 1) — gated by `batten check` against this repo. `batten.example.toml` is
the documented template for external consumers.
