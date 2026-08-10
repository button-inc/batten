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
  Since CLOUD-42 a row also carries `data_channel` (does this verb answer through
  `-J`?), and a flag carries `hidden` plus `Rung` — which §3 ladder rung it
  selects — so "is this a ladder flag" is a column rather than a naming
  convention, and the ladder's totality is a census test.
- `cli.rs` — the other half of the surface: turns parsed `ArgMatches` into the
  typed `Cli`/`Command` enums `lib::run` dispatches on, so dispatch stays an
  exhaustive `match` rather than a lookup on strings. Verbs today: `check`,
  `enforce`, `config show`, `spec`, `generate completions`, `hook`,
  `receipt record|status`. Adding a verb is a `surface.rs` row plus the arm
  here; a row without an arm fails `cli.rs`'s `every_leaf_verb_dispatches`.
  It does **not** carry the §3/§4 presentation flags: those are read from raw
  argument order by `output.rs`, because clap's recorded indices are not
  comparable across the subcommand boundary.
- `output.rs` — house-style §3/§4 (CLOUD-42): the `Verbosity` ladder
  (`silent…trace`, a derived `Ord`, so `admits` is a comparison), the §4
  attended/unattended resolution (`SIGNALS`, `resolve_with` taking the TTY
  booleans explicitly so CLOUD-107 can drive them), and the three stderr writers.
  Verbosity shapes **stderr only** — the data-emitting functions take
  `out: &mut dyn Write` and have no `Mode` to consult, which is what makes `-J`
  structurally ungatable. `verdict` and `error` are ungated: exit `1` is
  fail-loud, so `--silent` must not empty it.
- `exec.rs` — `batten exec -- <cmd>` (CLOUD-285): the transparent passthrough two
  Phase 2 issues were waiting on. Three things pass through untouched — the
  child's argv (`ValueDecl::Trailing`, with `allow_hyphen_values` so a child's own
  `-v` is not read as Batten's rung), its inherited streams, and **its exit
  code**. That last is the one deliberate exception to the §7 table: the code is
  the child's, so it travels as `error::Passthrough` rather than widening
  `ExitCode`, which stays total over the four codes Batten _chooses_. Batten never
  mints a `2` here — an unspawnable program is exit 1 — and `hook` is not
  reachable from this path, so no host can read a wrapped code as a deny.
  Capturing the streams is CLOUD-162's, not this module's.
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
- `doctor.rs` — `batten doctor` (CLOUD-66), house-style §12's post-install
  self-check: can Batten do its job in this repository? Diagnoses only — it
  **never returns exit 2**, because every failure it can report (config absent,
  invalid, unresolvable; not a repository) is the config-or-usage class, and a
  harness must not read "this checkout is misconfigured" as a deny. That is why
  `config lint` is deliberately _not_ a diagnostic: a smell is exit 2 there, and
  folding it in would answer the same question two ways. Checks report a stable
  reason id, never the error text, so `--json` is byte-stable and carries no
  filesystem path. Distinct from `mise-tasks/doctor`, which gates this repo's own
  provisioning.
- `epoch.rs` — `config_epoch` (CLOUD-32): a SHA-256 over the governing config
  surface, so two records carrying the same epoch were produced under provably
  the same rules. The tracked set is **config** (`[epoch] tracked`), not code —
  which files govern a repo is that repo's business, so the core carries only the
  default (`batten.toml`) and Batten's own list lives in Batten's own config
  (rule 1) — and true as a _grep_, not merely in spirit: no consumer's
  identifiers appear anywhere in `crates/batten`, doc comments included.
  Built on `identity::surface_fingerprint` — the one length-prefixed SHA-256
  construction, shared with findings rather than a second hash of the same
  bytes — so a rename cannot be hidden by choosing names, authoring order never
  reaches the value (paths sorted + deduped), and a CRLF checkout attributes
  identically (NFC/`LF` canonicalization). Follows `--config-from`: under a base
  ref both the tracked list _and_ the bytes come from the ref, never the working
  tree, so the epoch attributes the config that actually governed. An unreadable
  tracked path is **exit 1, naming the path** — the tracked set _is_ config, so
  an unreadable one is unreadable config (§7); `3` stays for I/O not
  attributable to the config. Never a skip: that would compute a _stable_ epoch
  over a changed surface, which looks exactly like a valid answer. Surfaced by
  `config epoch` and in `doctor --json`; stamping onto guard records is
  CLOUD-133's, the cache/etag revalidation CLOUD-232's.
- `error.rs` — two typed carriers the binary boundary downcasts on: `UsageError`
  → `ExitCode::Usage` (1) for expected bad-input vs. an internal failure, and
  `Denial` → `ExitCode::Violation` (2), the mediation verdict travelling to the
  one place allowed to write stderr. A `Denial` prints _unprefixed_: a host hands
  that text to the model as the deny reason, where `batten: ` reads as a crash.
- `config.rs` — loads/validates one `batten.toml` (typed, no unknown keys,
  required `version`). Layering across sources is `resolve.rs`, not here.
- `lint.rs` — `batten config lint` (CLOUD-87): the policy smells a _valid_
  config can still carry. Complements `trust.rs` rather than replacing it —
  `--config-from` makes a weakening ineffective, this makes it visible. Two
  classes: single-tree (a set declared and empty, a rule at `severity = "allow"`)
  located by `toml::Spanned` so each smell carries a line, and base-ref smells
  that reuse `trust::weakenings` and its `WeakeningKind` ids, so there is one
  definition of "weakened". **Absent is not empty**: a key the config never
  mentions is not a smell, or the lint would fire on every minimal config; the
  deletion of a populated set is caught by the base-ref class instead. Any smell
  is exit 2; an unparseable config is exit 1.
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
- `git.rs` — the one repo-root primitive (CLOUD-34) and the one merged-ness
  answer (CLOUD-36). `repo_root` is the parent of git's _common_ directory, so
  linked worktrees resolve to the main repository root; outside-a-repo, bare,
  and submodule-interior layouts raise `UsageError` rather than mis-root.
  `landing` decides whether work landed by **patch identity, never
  reachability** — a rebased, squashed, or cherry-picked branch is recognised,
  which no ancestry test manages — and a negative is `NotLandedWithinWindow`
  carrying the scan it did, never a bare no. All git plumbing flows through
  `query`/`query_bytes` here; three source-level gates in its tests hold the
  line (one repo-root resolver, no reachability verdict in `src/`, no second
  literal `git` invoker).
- `state.rs` — out-of-tree state dir (`<data-dir>/<app>/<repo-name>/`, CLOUD-23),
  via `etcetera`; repo-name derived at runtime, never baked in (rule 1).
- `rules.rs` — the rule/check engine (CLOUD-12): glob-selected, `kind`-typed
  predicates over the repo. `run_static` (read-effect, no process spawn) backs
  `check`; `run_all` (every kind) backs `enforce`. `check` refuses a
  command-executing rule rather than silently skipping it. Each rule pins a
  required `severity` (`RuleSeverity`, no implicit fallback) and a separate
  `scope` (`RuleScope`, pinned default `tree`) — two axes that never conflate
  (CLOUD-61); `any_blocking` is where severity meets the exit contract. `scope`
  is also the surface router (CLOUD-48): `tree` rules are the tree engine's,
  `mediated_call` rules are `hook`'s, and `RuleKind::scopes` refuses a pairing no
  surface would evaluate. Per-kind column agreement is a **census**
  (`Rule::columns` × `requires`/`permits`), not a per-kind match — the match
  named fields, so a new column landed in no arm and every kind accepted it.
- `hook.rs` — the `hook` adjudicator (CLOUD-202): the normalized envelope, the
  wrapper-lookthrough command parser, and the matcher. **The policy is config,
  not code** (CLOUD-48): `Policy` is the `mediated_call`-scoped rows of the
  _resolved_ config, so a `batten.local.toml` that adds a row is applied and
  `--config-from` is inherited. The parser is quote-aware (CLOUD-269) — a quoted
  operand survives as a word, which is what a path gate needs and what the old
  `QUOTED` sentinel destroyed. Harness adapters decode/encode at the edges; the
  core is harness-blind and fail-open. What varies per harness is the _channel_ a
  deny travels over, never the number: the exit-code adapter denies with `2`, the
  claude-code adapter with a `permissionDecision` document and exit `0`;
  `Harness::ALL` is what keeps CLOUD-40's channel matrix total. Absent authority
  is the empty policy (allow, silently); an authority that exists and cannot be
  read is exit `1`, loud, never a deny. Two gates run per call: the explicit
  `[[rule]]` shape rows first, then the derived protected-path gate (CLOUD-96) —
  `{program ∈ [[verb]]} × {path ∈ protected}`, an intersection of two config
  tables rather than rows, since rows would need one per verb × path pair. A
  truncating redirect has no mutating program, so `>`/`>>` are surfaced as
  pseudo-programs (`REDIRECT_VERBS`) a consumer declares like any verb — a
  crate↔config contract, hence the constant. Stated limits: no `cwd`, so an
  absolute or `..` path is compared as written, and expansion/substitution hide
  operands. Both under-deny, the sanctioned direction.
- `markers.rs` — counted suppression markers (CLOUD-36): how many times policy
  was waved through, and where. Tokens are config, never crate constants (rule
  1); hits are pointer-only (`path:line` + marker id, rule 4) and `counts`
  reports every configured marker including zero, so "none now" stays
  distinguishable from "not measured". Reuses `rules::tree_files`.
- `verbs.rs` — the mutating-verb table (CLOUD-36): which programs change the
  world, config-driven (rule 1) and typed by `effect.rs`'s one §5 vocabulary
  rather than a second severity axis. Each verb carries its own redirect for the
  refusal contract. Table and lookup only — crossing it with the protected path
  set is CLOUD-96's gate, and the sets are CLOUD-37's.
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

`crates/batten/tests/cli.rs` — end-to-end over the _compiled_ binary
(`CARGO_BIN_EXE_batten`), asserting exit codes and output shape consumers
depend on. Prefer adding here over unit tests for anything behavioral
(`.claude/rules/rust.md`).

`crates/batten/tests/primitives.rs` — the CLOUD-9 core primitives over the
_library_ surface, since they mint no subcommand and the fixture suite is their
gate (Option A). Carries the hermetic git fixture builder and the keystone: a
rebased-and-landed branch is merged though `--is-ancestor` says otherwise. Non-Rust tests (`mise-tasks/*` scripts,
gates) live under `tests/*.bats`, run via `mise run test:bats`.

## Self-consumption

Root `batten.toml` is Batten's own policy config — "consumer #1" (AGENTS.md
rule 1) — gated by `batten check` against this repo. `batten.example.toml` is
the documented template for external consumers.
