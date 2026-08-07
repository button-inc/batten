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
- `cli.rs` — the `clap` command surface (`Cli`, `Command`, `ConfigCommand`,
  `SpecFormat`). Verbs today: `check`, `enforce`, `config show`, `spec`. Adding
  a verb requires an `effect.rs` table entry in the same change (enforced by a
  completeness test in `spec.rs`).
- `effect.rs` — the house-style §5 effect table (`read`/`write`/`destructive`/
  `unclassified`), keyed by full command path. Absence = `Ask`, never `Read`.
- `spec.rs` — house-style §11: introspects the live `clap::Command` tree +
  `effect.rs` at runtime into byte-stable JSON (`batten spec`); completions/docs
  derive from this, never hand-duplicated.
- `exit.rs` — the `ExitCode` contract (stable numeric values); branch on named
  variants, never integer literals. `hook` subcommand inverts part of this —
  documented there, not here.
- `error.rs` — `UsageError`, the typed error that maps to `ExitCode::Usage` (2)
  for expected bad-input vs. an internal failure.
- `config.rs` — loads/validates one `batten.toml` (typed, no unknown keys,
  required `version`). Layering across sources is `resolve.rs`, not here.
- `resolve.rs` — house-style §8 precedence resolver: `flag > env > local file >
repo config > default`, declared as data in `SETTINGS` (per-key env var/flag),
  not hard-coded per field.
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
  harness-blind and fail-open, and the §7 exit-2-denies inversion lives in the
  exit-code adapter only.
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
