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
- `budget.rs` — declared file-set token budgets (CLOUD-50), surfaced as `policy
budget` and **enforced on `check`**. `[budget.<name>]` is a MAP, not a struct with
  a field per set: the set name is the consumer's, and an engine field called
  `instructions` would be a consumer-specific identifier in the crate (rule 1) —
  a second consumer now declares `[budget.<their-name>]` with no engine change.
  Enforcement is an ordinary `Finding` (`FindingKind::Scope`, id `budget.<name>`,
  identity over the SET so a bigger overrun is the same finding), appended in
  `run_rules` before the waiver filter — which is what makes a budget waivable
  and puts it in `-J`, the exit contract and the store for free, none of which a
  private verdict path would have inherited. `policy budget` is introspection
  only; it was the sole surface until the DoD audit, and a budget that reported
  only when asked is a gate nobody runs. The absent `[budget]` table reads two
  ways ON PURPOSE: `check` measures nothing (a repo declaring no budget has none
  to fail), `policy budget` is exit 1 (a report that measured nothing must not
  print `0`) — two callers, two honest readings. The successor to `mise-tasks/context-budget`, deleted in the same
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
- `ci.rs` — the merge contract derived from the host ruleset (CLOUD-54). The HOST
  is the authority; `[ci]` in `batten.toml` is a projection a gate polices, never
  the reverse. Committed rather than fetched per run because a gate that can fail
  when a token expires is not a gate — so `derive` is a pure function of a payload
  the CALLER supplies (`config lint --host-rules <path|->`), keeping the gate
  offline, credential-free and byte-stable. Required checks are the UNION over
  `required_status_checks` rules (each adds an obligation); merge methods are the
  INTERSECTION over `pull_request` rules that carry the key (each NARROWS what may
  be used — union would widen the contract past what one rule allows, the
  dangerous direction). No such rule = `None`, "the host constrains none", which
  is a different claim from an empty set and only agrees with `None`. Unknown rule
  types are ignored: the host adds them over time and failing on one would break
  the gate on a change nobody made. A non-array payload is exit 1, never an empty
  contract — that would read as agreement against an absent `[ci]` and as drift
  against a real one. Drift is SYMMETRIC and signed (`+` host, `-` config): a
  stale name the config claims is what a downstream reader waits on forever.
  Consumer #1's row is `required_checks = ["final"]` with no method key, matching
  the live ruleset. The fetch lives in `mise-tasks/ci-drift` on a SCHEDULE
  (`.github/workflows/ci-drift.yml`), not the landing path — `lock-currency`'s
  recorded lesson: a remote round trip there fails whichever PR is in flight for a
  change it did not cause.
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
  and derives the read-only allowlist from the same walk, emitting it beside the
  tree as `read_only_allowlist` (CLOUD-217 (39)) — flattened, so the tree's own
  root keys do not move, and the filter has one implementation rather than one
  per consumer. Completions derive
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
- `defects.rs` — the in-tree append-only defect ledger (CLOUD-52): `[defects]`
  (`path` + `classes`, both consumer facts), one `deny_unknown_fields` `Record`,
  `defects add [-n]` / `defects query`, and the built-in gate `check` runs
  whenever the table is declared. The **lesson** layer, deliberately not
  `findings.rs`'s signal layer: curated, permanent, taxonomy-classified,
  committed and PR-reviewed, where a finding is machine-emitted, identity-hashed
  and self-clearing. Neither absorbs the other — fold lessons into findings and
  they self-clear, which is the one thing a lesson must never do. Append-only is
  a **byte prefix**, not a growing id set: a prefix also freezes past rows'
  bytes, so a correction appends with `supersedes` and the quiet revision (same
  id, rewritten evidence) an id-set check waves through is caught. Two bases —
  `HEAD` and the remote default when it resolves — because either alone has a
  hole; an unresolvable base is DROPPED, never a pass, so a repo with no remote
  is still guarded by `HEAD`. A malformed row is a `Finding`, not a usage error:
  one bad line must not stop `check` reporting everything else, and the byte
  comparison deliberately runs even when the parse failed so a rewrite cannot
  hide behind a breakage. Gate findings are ordinary `Finding`s (`Scope`, keyed
  on the problem id, never the line — a ledger only grows, so a position-keyed
  identity would re-mint on every unrelated append), which is what gets them
  waivers, `-J`, the exit contract and the store for free. Consumer #1 adoption
  is deliberately NOT here (the issue's own stated assumption 2).
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
- `brief.rs` — the delegation-brief handoff schema (CLOUD-84), surfaced as `lint
brief`. `lint.rs`'s sibling and deliberately not part of it: that verb lints the
  one committed authority, this one lints an artifact the CALLER names, so they
  share the house-style `lint <kind>` shape and no code. `SCHEMA` is the
  required-section set as DATA — identifiers, period, instructions, read, check —
  and `problems` is a pure function of the bytes: no clock, no filesystem, no
  config, because the schema is engine structure and there is no key a
  `batten.local.toml` could weaken. Presence only, never prose quality; a judge is
  permanently out of scope (CLOUD-93). The ONE shape requirement is `check`'s
  `runnable` column — its body must carry a fenced, non-blank line — and that is
  what **retires a separate reply scanner**: a brief handing over a runnable
  command needs no second gate reading the reply for one. It never reads what the
  command is, so `rm -rf /` satisfies it too. Recognition is a label-line
  normalizer, not a heading rule: briefs in use spell a label four ways (`## Check`,
  `**Check:**`, `- Check:`, `Check:`), so the scan takes the text before the first
  `:`, strips markers, lowercases, and compares for EQUALITY — `contains` would make
  a brief that discusses its own structure self-satisfying. **Fence state is
  computed over the whole document BEFORE labels are read**, so a quoted transcript
  containing `# Check` declares nothing; without that ordering the more faithfully a
  brief quotes its evidence the more sections it appears to satisfy. Two problem
  classes because they are two different repairs (`missing` = write the section,
  `unrunnable` = put a command in one that exists), rendered `missing: check,
period (2)` in SCHEMA order — so the report never depends on the order the author
  wrote. A clean brief is SILENT (the issue's §7(a) overriding the house "state the
  count even at zero"), while `-J` answers unconditionally. Exit `0`/`2`/`1`, and
  the `2`-for-a-missing-section is CLOUD-307's correction landing: the issue's own
  Ready block had shipped the `mise-tasks/*-check` convention, whose inverse would
  make a policy verdict read to every mediating harness as a config error.
  Pointer-only is load-bearing rather than formal here — a brief is the likeliest
  document in the tree to carry a name, an entity path or a pasted credential — so
  ids and counts only, asserted on both channels.
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
- `store.rs` — _which_ store belongs to this checkout (CLOUD-164); it holds
  nothing, and CLOUD-78 extends the contents without touching identity. The id
  is MINTED at first write and seeded with a clock, so it cannot be recomputed
  from a path — that irreproducibility is what lets a store survive the repo
  moving. Common dir, remotes and root commits are recorded as `KeyMaterial`
  metadata, never keyed on: each changes under ordinary work, and a store keyed
  on one orphans itself, silently resurrecting every `rejected-by-design`
  finding. So a key-material change is a MIGRATION event, never a fresh store.
  Basename decides only _where to look first_ (`state.rs`'s path, unchanged);
  the repo->store direction is a marker in the common git dir, beside
  `receipt.rs`'s `batten-receipts`. `resolve` reads and never writes, which is
  what keeps `check`'s `read` effect honest; `commit` is the write half. Only
  `Opened::Fresh` mints, and it is reachable only after every criterion has been
  asked. A root commit or remote URL is identity-bearing and auto-adopts; a
  matching common dir ALONE is not (a path can be reused by a stranger) and
  yields `Candidate`, bound only by `batten state adopt`.
- `findings.rs` — what the store HOLDS (CLOUD-164), split from `store.rs`'s
  _which store_: identity is stable for a repo's life, contents change per scan,
  and CLOUD-78 extends only this half. One `FindingRecord` per identity, one file
  each, with `Instance`s INSIDE it — "one finding" is structural, not a join two
  worktrees could disagree about. Instances key on **ref**, never worktree path
  (ephemeral, randomly named); the path is metadata. `Observation` is the
  load-bearing type: `Observed(0)` resolves, `NotObserved` HOLDS — a skipped or
  errored rule reports nothing, and reading that silence as zero is how
  fail-closed becomes fail-open. Every comparison is per (identity × context), so
  interleaved scans from different refs never read as change. GC is by ref
  EXISTENCE, never reachability — these repos land by fast-forward, so a landed
  branch is an ancestor of nothing. CLOUD-78 added the disposition half:
  `Disposition` is declared weakest-first so derived `Ord` IS the precedence
  `acted > rejected-by-design > rejected-wrong`, and `merge` is `max` — a join on
  a total order, so it commutes, associates and is idempotent by construction
  rather than by a policy each call site could get subtly wrong. `Presentation`
  is the second axis: a finding the ENGINE withheld (drain-suppressed, over the
  cardinality cap, capability-absent) never had the chance to be acted on, so
  `effective_fp_rates` excludes it from BOTH sides of the ratio — otherwise the
  suppression machinery inflates the number it exists to measure. Not-acted is a
  false positive _including_ `rejected-by-design`; exempting the agent's own
  by-design call is what would make the measurement worthless. A zero denominator
  is no rate rather than a perfect one. `tier` is the ONE stored severity axis,
  derived through the rank table at mint and never recomputed: an Nth occurrence
  moves the count and never the tier (CLOUD-80's no-escalation law, testable for
  the first time here because this is what counts duplicates).
  `rejected-by-design` is GC-exempt — the decision outlives the branch it was made
  on, and the unbounded retention that buys is accepted and stated.
- `rules.rs` — the rule/check engine (CLOUD-12): glob-selected, `kind`-typed
  predicates over the repo. **`Ratchet`** (CLOUD-55) is the fourth kind: a count
  of `pattern` over `glob`, at a `base` rev vs the working tree, that may only
  move the declared `direction`. It exists because a test suite cannot be a
  `protected` path — tests are edited daily — so the computable property is
  DIRECTION of change, the shape `trust.rs` already uses for config. Counted in
  AGGREGATE per rule, never per file: a test moved between two matching files
  changes nothing, so renames are clean with no rename tracking, and the price is
  that the finding names counts (`glob 2->1`) while `git diff` names locations.
  The finding's `rule` field stays the plain id — decorating it would make a
  ratchet the one finding no waiver could suppress, and the waiver is the designed
  hatch for a legitimate reduction. It is evaluated BEFORE the empty-match early
  return, which is load-bearing: for every other kind an empty match set is
  "nothing to inspect", but for a ratchet it is the maximal deletion.
  `spawns_processes` stays false — it reaches git plumbing, which is a process,
  but CLOUD-170's invariant is about USER-SUPPLIED CODE (`receipt status` reads
  the same way), and the strict reading would make the kind enforce-only and cost
  it `check`. Two traps measured while adopting it: an unanchored literal counts
  PROSE (a bare `#[ignore]` matched 5 mentions in a tree with zero disabled
  tests, so the row would have failed on its own documentation — anchor to a
  newline), and a glob spanning a SUBMODULE counts one side only (`ls-tree` sees a
  gitlink, the walker sees 228 files: base 637 vs working 1404, a gate that
  cannot fail — CLOUD-328). `run_static` (read-effect, no process spawn) backs
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
  wrapper-lookthrough command parser, the matcher, and the **per-host shims**
  (CLOUD-44). Five hosts plus the neutral `exit-code`: claude-code, cursor,
  copilot-cli, gemini-cli, codex-cli. The survey (CLOUD-209) is why the shim is
  small — the industry converged on Claude's wire format, so the adapter is a
  rename table plus three special cases, NOT a moat. What differs: Gemini's event
  names (`BeforeTool`→pre-tool); Cursor's four pre-tool spellings, its specialized
  events that carry the operand at top level with NO `tool_name` (the tool is
  DERIVED from the event, or every specialized call reads as the same anonymous
  one), and `conversation_id` for session; Copilot's `toolArgs` typed `unknown`
  and shown stringified in its own docs, so the parser takes object OR string —
  assuming object would read a real payload as command-less, i.e. a silent allow.
  A leading UTF-8 BOM is stripped on EVERY host: Cursor's Windows stdin emits one,
  it broke strict parsers, and (staff-confirmed) degraded guards to allow-all.
  Emitter: `encode_deny` returns `None` where the exit code is the whole channel.
  Since CLOUD-122 `Decision::Deny` carries a `refusal::Refusal`, not a string, so
  neither deny path can ship a bare "no"; `deny_text` is the projection every
  channel carries and is the one place the bypass hatch is appended (a mediation
  fact, not a refusal field, which is why `check`'s refusal carries none).
  Two hosts read a body, for DIFFERENT reasons — Claude discards stdout on exit 2
  so the channels are exclusive; Cursor assigns stderr no meaning at all, so
  CLOUD-122's "every deny points to the fix" is unsatisfiable there without JSON.
  Fixtures live in `tests/fixtures/hooks/`, checked in rather than reconstructed
  because the survey measured that model memory of this space is badly stale.
  **Capabilities** (CLOUD-45) is the host × capability row the dispatcher consults
  before anything keys on an event — NOT a list of Claude-only events, because the
  survey measured the asymmetry running both ways (Gemini rewrites model traffic;
  Cursor sees file contents pre-read; neither is a Claude power). An undeclared
  event allows and fires nothing, with a Verbose-rung note — never an error and
  never a deny, since an absent capability is a fact about the host. `TaskCompleted`
  is the one load-bearing Claude-only event (exit 2 prevents completion, the machine
  form of the completion-signal thesis) and `degrade` maps it to the Stop family
  elsewhere; `ConfigChange` degrades to NOTHING, because inventing a stand-in is
  worse than admitting the gap. Two uniform facts the table pins so nobody assumes
  otherwise: **no host vetoes completion from Stop** (all five only force
  continuation — "Stop blocks" is wrong everywhere, not degraded somewhere), and
  `ask` is unavailable on Gemini and Codex, so a policy wanting confirmation must
  hard-deny there — degrading `ask` to ALLOW would turn "check with a human" into
  "go ahead". Fail-open edges are capabilities too (Copilot timeouts always fail
  open, Cursor needs `failClosed`, Gemini reads unparseable stdout as Allow). Two
  clippy lints are allowed with stated reasons: a matrix row is not a state machine
  (`struct_excessive_bools`) and rows that coincide today are still separate hosts
  (`match_same_arms`). The envelope is seven
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
- `refusal.rs` — the refusal contract (CLOUD-122): ONE `Refusal` value —
  `{rule, reason, fix}` — constructed at every deny site and projected onto
  whatever channel a host reads, so the shape is never re-typed per harness.
  **Completeness is structural, not tested**: `Refusal::new` is the only
  constructor and takes a `Fix` positionally with no default and no `Option`, so
  a deny that declares no disposition does not compile; a deny with no safe
  remedy spells `Fix::None`, which serializes as an explicit `"fix": null` rather
  than a dropped key (a consumer cannot tell an omitted field from one the
  producer forgot). `render()` is the one text projection — `Refused by <rule>:
<reason> Fix: <fix>.` — with the terminator normalised once so a config
  author's paragraph and a bare command splice into the same slot byte-stably
  (§6). Three deny sites feed it: `hook.rs`'s `shape_refusal` (the row's REQUIRED
  `reason` column is the fix, since `RuleKind::requires` mandates it and its doc
  is "what to do instead" — CLOUD-215 owns splitting it into `reason` + `fix` and
  the `--fix` affordance, deliberately not pre-empted), `hook.rs`'s
  `protected_refusal` (the verb's `redirect`, `Fix::None` where none is declared
  — the tier CLOUD-280 re-sources per path class), and `rules::run_static`'s
  refusal of a spawning kind under `check` (`Fix::Run("batten enforce")`, exit 1).
  A leaf module rather than a field of `hook.rs` — where the issue's Ready block
  put it — because `hook` already imports `rules` and `rules` is a deny site, so
  housing it there would close a module cycle. Bound (CLOUD-211): a mediated deny
  comes only from a computable predicate, never a judge verdict, so the shape
  models no advisory output — no confidence, no severity, no "maybe".
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
  An absent key resolves the remote's recorded default (`refs/remotes/<remote>/HEAD`,
  read not guessed — a hardcoded `main` that happens to exist answers against the
  wrong trunk silently). Where NO target resolves the verdict is `Unlanded::
NotComputable`, a third answer `Option` cannot express because it cannot tell
  "asked and clean" from "never asked"; it is at-risk and never suppresses the
  other facts. That last part is what the DoD audit demoted this for: an absent
  key used to be exit 1, so a repo with no target got NO report — not the dirty
  tree, not the branch tracking nothing — and the configuration likeliest to be a
  fresh at-risk checkout was the one the gate stayed silent about. A target the
  author NAMED and got wrong is still exit 1; that is a config error, a different
  mistake from naming none. `no-upstream` is its own line, not a flavour of
  `unpushed` (different fixes: push vs. set a tracking branch), and fires only
  when the target cannot account for the work — a landed branch loses nothing by
  tracking nothing, and flagging it would mark every finished local branch forever.
- `journal.rs` — the store's durable plumbing (CLOUD-78): append shards, a merged
  log with `(generation, seqno)` cursors, and the store-format version. Writers
  append to their **own** shard, so the concurrent path shares no mutable file and
  needs no lock; only the shard->record fold is single-writer, under an **OS
  advisory lock** (`fs4`, the one reason that crate is in the tree). Advisory,
  never a bare lockfile: the kernel releases it on process death, and the ambient
  ~2-minute foreground kill would otherwise strand a lockfile and brick the store
  for every worktree from one timeout. A lost race is `Merge::Busy` — an outcome,
  not an error and never a deny, since the entry is already durable in its shard
  and the next merge folds it; the §7 table stays total over `0/1/2/3` (rule 5),
  so busy maps to allow at the boundary rather than minting a fifth code.
  `append` fsyncs before returning (persist-before-emit). GC does not rewrite
  history, it **rotates the generation**, invalidating every outstanding cursor by
  construction — so `since` answers `FullResync` rather than computing a delta
  against records that are gone; a cursor past the end resyncs too, never
  underflows. Versioning is **write-old/read-both**: a binary writes the store's
  recorded version and reads a window around it, and `state migrate` is the ONLY
  upgrade — an implicit one on a read path would rewrite a store an older sibling
  worktree is still using. A store newer than the binary is `DegradedReadOnly`:
  dedupe still works, emissions carry `persisted:false`, and it maps to
  allow-with-warning, because an out-of-date binary is an operator problem and
  refusing the agent's work does not fix it.
- `judge.rs` — the judge's payload-privacy boundary (CLOUD-135): what may be sent
  to a model. Config types plus one pure function; **no command, no effect-table
  row, no egress** — enforcement of the config half rides `config lint`'s landed
  `read` row. Landed BEFORE the judge that reads it (CLOUD-56), because a
  boundary written after the code it bounds is one that code has already crossed.
  `[judge] raw` names which content classes may ever cross (default none).
  **One protected member refuses the WHOLE invocation** (`Refusal::Protected`,
  exit 1 at the caller) — not the span. The `over_protected` key that used to
  withhold spans individually is GONE: it was verbatim the issue's own rejected
  alternative ("a committed opt-in key for protected egress … not a latent key"),
  and per-span withholding also made the verdict be about content the config
  never described. `assemble` decides protection BEFORE any byte enters a payload
  value. The cap (`max_payload_bytes`, default 16 KiB) refuses whole and never
  truncates — a truncated payload judges a prefix while the record claims the
  row; `effective_cap` is tighten-only, and for a budget that means "may not
  RAISE" (the §8 direction reads backwards here). Three payload classes: `rule`
  (the row's own committed id+criteria — config author's words, always crosses,
  not repo content), `content`, `pointer`. `InvocationRecord` is pointer-only
  (rule, byte count, sha256, matched-file count, disposition) and is asserted to
  carry no payload bytes. `lint.rs`'s `judge-over-protected-unstated` went with
  the key — a smell over a decision the engine now makes structurally could never
  fire.
  A span is protected when its path matches the committed `protected` globs — a
  structural match, never an inference — **or when it carries no path provenance
  at all**, the fail-closed half: cannot-show-it-is-safe resolves to withheld.
  A withheld span still leaves a pointer and a hash (`identity::
judge_fingerprint`, its own domain tag), so a caller can reference content it
  did not send. `PayloadEntry::text` is the only field that can carry bytes, so a
  caller cannot leak by accident, only by configuration. The justification bar is
  high because the verdict bought is advisory-only (house style §0.3) — egress
  that cannot even block argues for a refusing default, not a balanced one.
  Absent `over_protected` is safe (builds pointer-only) AND smelled by
  `lint.rs`'s `judge-over-protected-unstated`: a silent safe default is
  indistinguishable from a decision nobody made, and the next diff widening `raw`
  inherits the omission unseen.
- `transcript.rs` — completed-session transcripts as an optional `check` input
  (CLOUD-95): a serde parse from a host-provided path to a typed event stream
  (turn boundary, tool call + args, tool result, hook decision). Every event comes
  from a **typed field**, never from prose — a denial is the host's recorded
  `exitCode` compared against `ExitCode::Violation`, read from the other side of
  the same §7 table, not a substring match on an error message. Free text is never
  interpreted and never emitted: `Counts` carries numbers, `Record` a line.
  Forward-compatible on purpose — the format is a **host's** and it moves, so an
  unrecognized line yields no events rather than an error (one captured session
  carried six top-level `type` values and eleven `attachment.type` values); a line
  that is not JSON is the one refusal. Three states, and the first two are the
  design: **unconfigured** (the repository does not use it — absent is not empty,
  `lint.rs`'s principle) is silent; **absent** (configured, nothing there) is
  reported and exits `0`; **present-but-undecodable** is `UsageError` (exit `1`,
  never `2` — a parse failure must not reach a harness as a deny). The absent
  report rides **both** channels because the stderr half is ladder-gated: `-J` has
  no `Mode` to consult, so `--silent -J` still carries it, which is what stops a
  skipped gate from exiting 0 in silence. Emits no findings itself — `FindingKind::Sequence`
  and `findings::Observation::NotObserved` stay the reserved seam CLOUD-97/98/219
  occupy. `session` is `Option<String>` with empty normalized to `None`, the same
  degradation `identity::sequence_fingerprint`'s signature already encodes.
  `Event::Turn` carries an **`Origin` beside its `Role`** (CLOUD-267), because the
  role alone cannot answer who spoke: a host renders tool results in the _user_
  role, so a role-only reading finds a user message where nobody typed one, and
  "a turn carrying no user message" would never fire. Three values plus
  `Assistant` — `Authored`, `Synthetic` (a host-set `isMeta`/`isSynthetic`, or a
  block array that is all `tool_result`), and `Unknown`, which is a real answer
  per §10 rather than a guess in either direction.
- `selfwrite.rs` — unprompted agent self-persistence (CLOUD-267): a memory write
  in a turn no genuine user message opened, as a conjunction of two exact
  structural matches over `transcript.rs`'s stream. **Memory-write event**: exact
  membership in `MEMORY_TOOLS` after normalizing a host's MCP namespace
  (`mcp__serena__write_memory` → `write_memory`, so it stays membership and not a
  substring match), OR a named generic write verb whose `file_path` falls under
  the declared memory root. **No-user-message turn**: an _exchange_ is delimited
  by user-role boundaries, not by every turn boundary — tool calls live in the
  model's own turns, so keying on "the most recent boundary" would raise on every
  call ever made. A turn a person opened never raises however many calls follow;
  a host-marked synthetic opener does, because an injected message is not
  authorization. `Unknown` authorship registers `Disposition::Unresolved`.
  Advisory and **structurally unable to block**: it rides the transcript view in
  `-J`, never the `findings` vec, so no `--fail-on-warning` promotion can route it
  to an exit code. Output is counts plus bare line numbers — the memory key and
  target are payload, not pointers. The intent question is permanently out of
  scope (CLOUD-93), not deferred. Store/tier/drain integration waits on
  CLOUD-81/82.
- `session.rs` — session lineage and the durable resume point (CLOUD-83): the
  fourth question `store`/`findings`/`journal` leave open — **who is reading, and
  how far have they got**. A warm fork keeps everything that is out of process
  for free (that inheritance is the restart "procedure", written as rustdoc on
  `state.rs`/`store.rs` per the issue's §1); the two things it loses are a
  reader's `(generation, seqno)` position and the session key an open
  sequence-kind finding was minted under. Both live in one record per session
  under `sessions/`. The cursor is keyed on the **lineage root**, so a fork reads
  its parent's position, and sub-keyed by `holder` — load-bearing, not defensive:
  a shared cursor would let `state record` (holder `record`) mark entries seen
  that never reached an agent, and CLOUD-79's drain would then skip exactly what
  it exists to emit. `root` walks the chain bounded at 64 and reports
  `truncated` rather than spinning; a cycle is unreachable through `observe`
  anyway, whose parent edge is **write-once** (relinking would move already-
  resolved identities and cursors under readers holding the old root). The parent
  is DECLARED through `BATTEN_SESSION_PARENT`, never inferred: two sessions run
  back-to-back in one worktree are indistinguishable from a fork by anything the
  store can observe, and chaining them would carry an open incident into an
  unrelated trajectory — the direction that hides an alert. A warm fork inherits
  its parent's environment, which is what makes env the honest channel and costs
  no new command, flag, or envelope field (§3). Bare consts rather than a
  `resolve.rs` `SETTINGS` row (`hook::BYPASS_ENV`'s shape): ambient context has no
  config spelling, so no precedence ladder to declare. Absent is unconfigured and
  silent, and the record file is named by a FINGERPRINT of the key — a host
  session id is somebody else's arbitrary string and must not name this crate's
  files — with the raw key inside, where `sequence_fingerprint` needs it. Reads
  never write, so resolving a session on a `read` verb does not make it a writer.
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
- `provision.rs` — the `[[provision]]` manifest (CLOUD-90): pinned tools fetched
  and cached out of tree. §9's check/fix pair — `provision status` (read) is
  freshness, `provision apply [-n]` (write) is the fix. **The provisioned binary
  is never executed by either half**: the whole equality test is a checksum, which
  is what keeps a `read` verb from running an artifact fetched from the internet.
  `apply` fetches into memory, verifies, THEN writes — a mismatched artifact never
  reaches the cache, so there is no partial install. Mismatch is exit 2 (a verdict
  about the pin); unreachable is exit 3 (could not complete — a different claim).
  The cache stores the artifact bytes as well as the binary, so freshness
  re-verifies the pin against what was installed rather than a receipt it wrote
  about itself; `version` is a path segment so two pins coexist. A malformed
  `sha256` is refused at load, or every apply would blame the artifact for a typo.
  **The https fetch shells out to `curl`** — measured, not preferred: no
  TLS-capable Rust client links here, because `macos-link-check` fails any crate
  declaring `links` or linking an Apple framework (native-tls and
  rustls-native-certs pull `security-framework`; rustls with bundled roots still
  fails on `ring`'s `links` key). curl IS the host's default TLS stack, which is
  the acceptance's proxy-CA property in its strongest reading, and §9's own
  posture. Debt tracked in CLOUD-320, not absorbed.
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
