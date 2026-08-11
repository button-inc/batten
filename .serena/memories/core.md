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
- `lib.rs` — library entry point, declares the module tree. `run(cli, mode, out,
err)` takes **both** channels and the resolved `Mode`, so a verb can write a
  ladder-gated message itself instead of that being `main.rs`'s privilege
  (CLOUD-208; it closed CLOUD-42's G10, "nothing emits at `Verbose` or above
  yet"). `out` is the answer, `err` the messaging — `batten exec` reports its
  output matches through `err` for that reason.
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
  structurally ungatable. That holds at the _emitter_ layer and is what the
  guarantee rests on; the _verb_ layer does carry a `Mode` (see `lib.rs`), so a
  gated message is written through `message` and can never reach `out`. `verdict` and `error` are ungated: exit `1` is
  fail-loud, so `--silent` must not empty it.
- `outputs.rs` — `exec` output predicates (CLOUD-117): declared literals that,
  found in a wrapped command's captured stream, promote a lying exit `0` to a
  failure. **A match always fails** — no severity field, no `fail_on_warning`
  dependence, because a finding that exits `0` is invisible to the only surface an
  agent reads. Literal substring, not regex: the crate carries no regex dependency
  and `forbid` sets the precedent. Report is pointer-only (`stream:line <id>` plus
  a count and each reason once), never the matched line — a wrapped command's
  output is the likeliest place in the engine for a secret to appear. Batten only
  ever **adds** failure: a non-zero child passes its code through untouched.
  Raise-only from a local file (add yes, redefine no).
- `budget.rs` — the instruction-set token budget (CLOUD-50), surfaced as `policy
budget`. The successor to `mise-tasks/context-budget`, deleted in the same
  change: two gates counting one surface by different rules is the drift this
  engine exists to refuse. The estimate is bytes/4 over what actually **loads** —
  YAML frontmatter and block-level HTML comments stripped first, by a byte scan
  rather than a regex (the crate carries none; `outputs.rs` set that precedent).
  Deliberately an approximation: an exact count needs a tokenizer, a vocabulary
  and a network fetch, and a budget gate that fails because a download failed is
  worse than one 10% out. What it must be is **stable, offline and monotone**,
  which is what puts it in house-style §0.3's decidable fragment — a count against
  a constant guard. Both boundaries are `<=`, so exactly at budget passes, and a
  clean run prints nothing. The load-bearing refusal is per-entry: **a configured
  glob matching no file is exit 1**, even when its siblings match, because the
  whole-set reading let one dead glob contribute nothing while the rest counted
  and still reported green (CLOUD-298). A config declaring no budget is exit 1
  too — a budget verb that measured nothing must not report `0`.
- `capture.rs` — captured child output, content-addressed in out-of-tree state
  (CLOUD-162): the shared substrate CLOUD-117's output predicate and CLOUD-121's
  handles both read, built once so neither grows its own copy. The digest **is**
  the key (`captures/<stream>-<digest>` under `state::repo_state_dir`), so
  identical bytes are one record and the record carries no timestamp — a
  content-keyed capture must be a pure function of its content. Addressing goes
  through `identity::capture_fingerprint`, which has its own domain tag beside
  `SURFACE_TAG` rather than a `FindingKind`: a capture is not a finding. Bytes are
  hashed **verbatim**, unlike `surface_fingerprint`, because a capture identifies
  what a program actually wrote. It renders no verdict and emits nothing.
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
  classes: single-tree (a set declared and empty, a rule at `severity = "allow"`,
  a waiver naming no declared rule, a waiver past its expiry — CLOUD-208, which
  is why `smells`/`run` take a `waiver::Date`: the verdict is a function of
  (bytes, date), never of when the process started)
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
  is not reported. **Which direction is weakening is a property of the key, not of
  the module**: `removed_entries` covers `protected`/`unlanded`/`rule`, where more
  entries mean a higher bar, and `added_entries` + `WaiverAdded` cover the one
  entity whose _presence_ lowers it (CLOUD-208) — reported whether or not it has
  expired, since the diff is a fact about two files and the lapse is the run's.
  Pointer-only `Weakening`s (key path + two verdict tokens),
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
  literal `git` invoker). `query_optional` is the fourth entry point (CLOUD-51):
  non-zero exit is `None`, for the one question whose answer may legitimately be
  "there is none" — `@{upstream}` on a branch that tracks nothing. A caller that
  would read absent as _safe_ must not use it.
  **The `--end-of-options` trap, measured on CLOUD-51:** every query here carries
  that flag, and in `rev-parse`'s ref-PRINTING modes (`--abbrev-ref`,
  `--symbolic-full-name`) it must not — `rev-parse` does not consume the flag
  there, it **echoes it as an output line**, so the answer comes back as
  `"--end-of-options\nrefs/remotes/origin/main"` and every downstream ref lookup
  fails on a target nobody configured. Copying the house pattern is what produces
  the bug. `upstream_of_head` therefore asks about a bare `@{upstream}` with no
  branch name interpolated, so there is no caller-influenced token in the argv
  and omitting the flag costs nothing.
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
  wrapper-lookthrough command parser, and the matcher. The envelope is seven
  fields since CLOUD-43 — a typed `Event` (`const ALL` + `as_str`, the vocabulary
  idiom `Harness`/`Stream`/`RuleKind` use) plus the host's own `raw_event`, which
  is not a second authority: one is what policy dispatches on, the other is the
  token echoed back, and normalizing inward and echoing outward are different
  directions. `input` carries the whole tool-input object for the tools that are
  not shell-shaped and is never emitted (rule 4); `command` stays as its shell
  projection so the parser reads one decoded string. `session` is
  `Option<String>` with empty normalized to `None`, because
  `identity::sequence_fingerprint` already hashes `None` and `Some("")`
  distinctly — that signature IS the degradation contract, not a second rule.
  **`adjudicate` dispatches on the event and only pre-tool is adjudicated**: the
  field was decoded and never read, so a `PostToolUse` payload carrying a banned
  command was denied after the fact, at an event no host offers a deny channel
  for. `cwd` is decoded but not consumed, so an absolute path operand is still
  compared as written. An absent `hook_event_name` is assumed pre-tool
  (`ASSUMED_EVENT`) rather than unrecognized: guessing the adjudicated event can
  only over-adjudicate, where guessing the other turns a missing key into a
  silent bypass. **The policy is config,
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
- `waiver.rs` — the designed escape hatch (CLOUD-208): a `[[waiver]]` names a
  rule, a required reason and a required expiry, and `apply` filters findings in
  `lib.rs`'s `run_rules` — the one funnel both `check` and `enforce` pass through
  — before rendering and before `any_blocking`. **Never a fourth severity**
  (`severity.rs`'s three axes are a bijection): "waived" says whether a finding is
  counted. Expiry is load-bearing rather than paperwork — it is the only
  mechanism that makes lapsing the default when nobody looks — so it is evaluated
  in the gate, with **today injected as a `Date` input** (`resolve_with`'s idiom),
  which is how §6 byte-stability survives a clock: same commit + same date → same
  bytes. `today()` is the one boundary reader. Carries the tree's single
  civil-from-days conversion, which `receipt.rs` now reads its date half from;
  `receipt.rs`'s "expiry is a git fact, never a clock" is right there and does not
  generalise, because a receipt's claim is about a SHA and a waiver's warrant
  decays in calendar time. Each application writes a pointer-only audit line to
  stderr through `output::message`. Scope bound: a `shape` rule cannot be waived
  (`adjudicate` returns `Decision`, not `Finding`). A local file may add a waiver
  for a rule the authority does not declare and is refused outright for one it
  does — the one direction where the local layer lowers the bar, and `trust.rs`'s
  `added_entries`/`WaiverAdded` is the first _added_-direction weakening in the
  tree. Dead-waiver diagnostics are `lint.rs`'s `waiver-names-no-rule` and
  `waiver-expired`; the runtime one (a waiver matching nothing) is deliberately
  out of scope — it would put `rules::run_all`'s spawning path behind a `read` verb.
- `worktree.rs` — at-risk work detection (CLOUD-51), surfaced as `worktree
status`. Three categories as one read gate: **uncommitted** (the tree is not
  porcelain-clean), **unpushed** (commits with no patch-equivalent on the
  upstream — and a branch with **no upstream** is judged against the target
  instead, because absence of an upstream is not safety), **unlanded** (no
  patch-equivalent on `must_land_on`). It re-derives no merged-ness: every
  verdict is `git::landing`, so the rebase and squash shapes come for free and
  ancestry is never consulted — which is the whole point, since these consumers
  land by rebase and a landed branch is therefore never an ancestor of the trunk.
  A negative carries `TRUNCATED` when the scan filled its window, so an unproven
  absence never renders as a proven one. `is_landed()` is the test rather than
  `Verdict::Landed`, or a branch with nothing to land would read at-risk forever.
  Config is one key, `must_land_on` — deliberately NOT the landed `unlanded`
  key, which is path membership over tree content; VCS state and path membership
  are orthogonal and one key meaning both is the conflation CLOUD-37 avoided.
  An absent key is exit 1, never a pass over nothing.
- `identity.rs` — finding-identity fingerprints (CLOUD-123): SHA-256 over a
  normalized, kind-discriminated tuple — never raw `file:line` — so line
  insertion doesn't re-mint a finding; content changes correctly do. The module
  doc is the landed spec (tuples, canonicalization, exclusions, count semantics,
  migration, interaction laws), so read it rather than re-deriving from the
  issue. Three things beyond the plain fingerprints: `secret_code_fingerprint`
  HMAC-keys the span for secret-class findings, because an unkeyed digest of a
  low-entropy secret is an offline-guessing oracle a journal cannot expunge —
  the key comes from the caller, custody is the store's; `override_fingerprint`
  hashes the default identity as a field, which makes a per-rule override
  split-only _by construction_ rather than by validation; and the key-id sits
  inside the preimage while an `identity_version` stays outside it, which looks
  contradictory and is not — a version must not re-mint (the migration
  equality-join needs comparable hashes), a rotation must (its join is
  dual-HMAC). Behavioural churn fixtures live in
  `crates/batten/tests/identity_churn.rs` (CLOUD-169); they compose the matcher
  with this module because a `Finding` carries no fingerprint yet (CLOUD-164).
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
