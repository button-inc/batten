# Top-level source map

Single workspace crate: `crates/batten` (bin `batten` + lib `batten`). Root
`Cargo.toml` holds workspace lints/profiles; see `.claude/rules/rust.md` for
style rules (thin `main`, no `unwrap`/`expect`/`panic`, exit-code branching) —
this memory only maps what each module does, since nothing else does.

## Where the rest lives — read the right one at its trigger

This memory is the graph root: every other memory is reached from here, and the
trigger for each is stated here rather than inside it (`mem:memory_maintenance`).
Read on demand, never all of them.

- `mem:workflow/board-states` — starting or finishing a `CLOUD-*` issue;
  reasoning about what is in flight.
- `mem:workflow/agent-fanout` — spawning a subagent, or running more than one
  session against this repo.
- `mem:workflow/landing-loop` — landing a branch; before "repairing" `land`, the
  lease, the CI wait or their suites.
- `mem:workflow/sonar-gate-race` — Sonar refuses your branch; before treating a
  `final` failure on `sonar-gate` as yours, or reading a check-run's annotations
  as the whole finding list.
- `mem:session-transcript-access` — asked to read chat history or another
  session; before probing a session API or credential.
- `mem:github-access` — any GitHub op; before claiming the toolchain or CI
  "can't reach GitHub".
- `mem:github-rest-etiquette` — writing a task that calls the GitHub API;
  diagnosing a 403/429/abuse response.
- `mem:toolchain-and-hooks` — pinning a tool, adding a task, touching `hk.pkl`
  or the gate.
- `mem:serena-setup` — a Serena worktree or index misbehaves; changing
  `.serena/` config.
- `mem:prior-art-and-issue-hygiene` — surveying outside practice; adopting a
  tool or pattern; writing an issue or PR body.
- `mem:connector-allowlist-recovery` — **any** `MCP tool call requires approval`,
  including `create_session`/`list_sessions`/`get_session` (that one is upstream
  and ungrantable — read the STOP section before answering, and never send anyone
  to a settings screen for it); a connector's tools start prompting or denying,
  reappear under a different name, or are **absent entirely** ("No such tool
  available"); before telling anyone a connector is unattached or needs
  authorizing; and when `claim-check` has no payload to read, since a missing
  receipt stops `verify` and strands the branch.
  **Read it BEFORE the first probe, not after it fails** — this has been
  re-derived by experiment in at least three sessions, each time ending in advice
  to change a setting that does not exist.
- `mem:memory_maintenance` — writing, renaming or splitting a memory; the
  shipped convention template.

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
- `action.rs` — the `[[hook.action]]` plugin surface (CLOUD-91), house-style §9's
  "repo-specific cleanup or keepalive is reconstructed here, not hardcoded". A row
  names an event and argv already on the operator's PATH. **`fire` returns
  NOTHING**, which is how "an action cannot change the answer" is structural
  rather than promised: there is no value a decision path could branch on, so the
  §7 table and CLOUD-40's per-harness channel hold whatever the command does. The
  child's streams are DISCARDED, never forwarded — stdout because two hosts parse
  a decision document there, stderr because two others read a deny reason from it,
  and an action is the likeliest place in the surface for a secret to appear (rule
  4); a failure is the pointer `hook.action <id>: exit N`, with could-not-spawn
  kept distinguishable from ran-and-failed. `on` takes a NORMALIZED token, so one
  row fires on every host offering the moment. **`pre-tool` and `unrecognized` are
  refused at load**, for different reasons: a side effect at the adjudicated event
  would run before a deny that may be about to refuse the very call (and would put
  a config load back on the hottest path in the binary, which `fire_actions`
  returns early to protect), while `unrecognized` names no moment at all — only
  that the host said something this build cannot normalize. Firing is EXACT, never
  degraded: `Capabilities::degrade` is right for a policy that merely _observes_ a
  moment, and wrong for one that _does_ something at a moment nobody named. argv,
  not a shell string, so no quoting layer sits between what an operator wrote and
  what runs; `{event}/{tool}/{path}/{session}` expand, an absent fact collapses to
  empty, and an UNKNOWN placeholder is left verbatim rather than emptied — a
  typo'd `{pathh}` silently shortening argv is unbounded in a way failing on the
  literal is not. Authority-only, and here that is a security property rather than
  a consistency one: a `batten.local.toml` able to add a row could run anything
  under the agent's own hook.
- `baseline.rs` — the adoption path for an already-dirty repository (CLOUD-67),
  surfaced as `baseline [--prune]`: the persisted set of finding identities that
  already existed, so `check` stops failing on them and still fails on anything
  new. A bulk waiver by another name, which is why the load-bearing part is not
  the filter but the **minting predicate**: only landed, committed state may be
  baselined, and it is spelled `worktree::status` — patch identity through
  `git::landing` — because `git.rs`'s `no_ancestry_decides_merged_ness` forbids
  a reachability verdict crate-wide and a rebased landing is invisible to
  ancestry anyway. `Unlanded::NotComputable` refuses too: unproven is not clean.
  The artifact is one JSON document under the **bound store** (`store::bound_dir`,
  beside `findings/` and `journal/`), not a plain `repo_state_dir` join like every
  other store here — it keys on finding identities, so a baseline that survived a
  `state adopt` would describe a store the checkout no longer owns, the second
  answer `store.rs` exists to refuse. Drift reuses CLOUD-123's direction-aware
  semantics wholesale (`identity::compare_to_anchor`): increase re-raises (new
  evidence fails), decrease ratchets and surfaces only as prune staleness,
  zero resolves. **Count drift never moves a tier** — `severity.rs`'s deferred
  invariant, landed here and structural rather than promised, since `apply` only
  ever removes elements and never builds or mutates a `Finding`. Staleness is an
  ordinary `Finding` (`Scope`, `baseline.stale`) joined where `budget` and
  `defects` join, inheriting waivers, `-J`, the exit contract and the store; the
  filter sits immediately BEFORE the waiver filter, and that order is
  load-bearing — waivers first would make a live entry read as unmatched. Two
  fail-closed holds that are never pruned: a rule in `Scan::not_evaluated` holds
  its entries (silence is not evidence), and an entry minted under a superseded
  `identity_version` holds as `baseline.version-drift` rather than silently
  unmatching, which is the issue's "a bump must not invalidate every adopter's
  baseline". The clock is an input (`waiver::today`'s idiom) and no predicate
  reads it: `minted_at` is provenance beside the ref and two SHAs, which are git
  facts. Output is pointer-only — `rule <digest12>`, never a baselined line.
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
  print `0`) — two callers, two honest readings. The successor to `mise-tasks/context-budget.sh`, deleted in the same
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
- `attribution.rs` — what produced commits may carry about the tooling that made
  them (CLOUD-274), the mechanism for the attribution decision record
  (CLOUD-268). Judges author/committer identity, every trailer and the message
  body against `[attribution]` patterns, over a commit range or one pending
  message — the commit-msg seam, where a refusal means the offending commit is
  never created. A GATE OVER THE ARTIFACT, never a setting: the vendor identity
  is injected at the environment level and the host's own suppression setting
  does not govern every path, so the invariant is only checkable on the produced
  commit. Deny is the default and `trailer_allow` is the carve-out, so one pair
  of lists expresses every posture from silent to disclosing; an EMPTY allow-set
  exempts nothing, which is a branch rather than an empty pattern because an
  empty regex matches everything and would invert the gate. Findings are pointers
  (`<sha8> author`, `<sha8> trailer:<key>`) and never the matched text — this
  module reads exactly the content someone wanted suppressed. `set_identity` is
  the one write, repo-local only, and it leaves a compliant identity alone.
- `commit.rs` — the commit-subject convention (CLOUD-701): one configured regex
  over `%s`, judged across a range or over one pending message file. Lives in the
  engine because "is this subject conventional" is a rule about what a commit may
  BE, and this repo lands by fast-forward — every commit reaches `main` with its
  own message and drives release-plz's semver, so each one is judged rather than
  just the PR title. It replaced `CONVENTIONAL_RE` in `mise.toml [env]`; that file
  configures how tools run, which is the same correction `attribution.rs` is the
  precedent for. NOT a classifier: the vocabulary of types is `[commit]`'s, and
  the crate carries no notion of Conventional Commits. Findings are pointers
  (`<sha8> subject`) and never the subject text — a deliberate tightening over the
  shell task, which printed it. `--no-merges`, because a merge subject is git's
  wording rather than an author's. A sibling of `attribution` rather than a verb
  under it: same object, different question, and one verdict answering both would
  be unattributable to either.
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
  the live ruleset. The fetch lives in `mise-tasks/ci-drift.sh` on a SCHEDULE
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
  mints a `2` here — the only two codes it mints are exit 1: an unspawnable
  program, and an `exec_pattern` matching on an otherwise-clean exit 0 (CLOUD-117).
  Both are statements about the INVOCATION, which is what 1 means, so neither is a
  §7 exception; CLOUD-292 decided that against renumbering the second to 2, because
  "never a `2` here" is the property that makes the channel readable at all. `hook`
  is not reachable from this path, so no host can read a wrapped code as a deny.
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
  `derived-check` diffs the committed copy byte-for-byte (DoR §4).
- `render.rs` — the two _human_ renderings of the same tree (CLOUD-69), the
  other half of what §11 has always claimed: `man` builds one roff page per
  command via `clap_mangen`, `markdown` walks `spec.rs`'s `CommandSpec` into the
  whole-surface reference. Both return a `String` and write nothing, which is
  what keeps `generate` an `Effect::Read` verb — the redirect is the caller's
  (`mise run man`), never the binary's. Three name fields carry the qualified
  path because `clap_mangen` reads a different one for each (page title,
  SYNOPSIS, `.TH` source), and the `.TH` date is left empty: a dated page would
  differ on every regeneration and no byte-for-byte gate could hold it. The man
  pages are committed and gated by `derived-check`; the markdown is **not**
  committed — it is the CLI reference, rendered at publish time (CLOUD-171), so
  there is no second copy to drift from.
- `exit.rs` — the `ExitCode` contract (stable numeric values); branch on named
  variants, never integer literals. One table, no per-verb exception (CLOUD-226):
  `0` clean/allow, `1` usage, `2` the policy verdict — a `check` violation and a
  `hook` deny alike — `3` internal. The numbering makes fail-open structural, and
  a unit test asserts no failure code equals the deny code.
- `facts.rs` — the fact model (CLOUD-757): what a fact **costs** and where it may
  be **resolved**, as two independent axes rather than one ladder. `Cost`
  (free/read/effect/stateful) prices resolution; `Surface` (hook/check/
  verify-only) names the NARROWEST surface it may be resolved on. Independent
  because the bound that bars forge state from the mediated path is CLOUD-747's
  no-runtime assertion, not the price — forge facts are `read` x `verify-only`,
  the pair a one-axis model cannot express. `Class::meet` composes on BOTH axes
  (CLOUD-773): a derived fact is at most as cheap as its most expensive input and
  at most as wide as its narrowest, so a `read`-class rule cannot silently
  inherit an `effect`-class dependency. Every match is exhaustive with no
  wildcard arm — the compiler gives totality, `tests/facts.rs`'s source scan
  gives no-wildcard, because `_ => Cost::Free` compiles happily and classifies
  every future fact as cheap. Each fact's class is a stated `const` beside it and
  `Fact::class` returns that const rather than recomputing. `Look` states the
  three-valued contract once — is / is-not / **could not look** — which is what
  `hook::ReceiptFacts`'s `None` has meant since it shipped. `Surface::Check` is
  the tree-surface boundary NAMED WHILE STILL EMPTY: everything `adjudicate`
  consumes today is hook-resolvable, and the second axis exists for the facts
  that are not landed yet. CLOUD-772 put the first fact there: `Format` +
  `Node` + `Format::read` are the DOCUMENT fact — TOML/YAML/JSON/JSON5 parsed
  into one canonical tree (`BTreeMap`, so key order is the keys' and never the
  file's; numbers carried as source text so a version pin round-trips). PKL is a
  DECLARABLE variant that never parses: an absent variant would answer a
  consumer's declaration with "no rows", which is the vacuous pass. A file that
  does not parse is `CouldNotLook`, never `IsNot` — the live failure mode of the
  73 awk readers in `mise-tasks/`, where an empty extraction reads as agreement.
  `Node::at` walks a dotted path and answers `IsNot` for a node that is not
  there, which is the OTHER absence and must stay a different value.
  CLOUD-776 added the second fact class and the first that is not the engine's
  to resolve: `Sourced` + `sourced` + `rows_in` are the AGENT-SOURCED fact — a
  gate denies with `Fix::Run`, the AGENT's own tool runs the command, and the
  harness hands the bytes back as `Envelope::result`. Batten executes nothing, so
  the same answer that is `read` x `verify-only` when the ENGINE would fetch it
  is `read` x `hook` here: the table is about who resolves, not about what is
  known, which is the second axis earning itself twice. Two disciplines hold it
  up. The recorded command is compared to the asked one by BYTE EQUALITY — the
  agent picks which command runs and any normalisation is a gap between asked and
  accepted, so a near miss is `CouldNotLook`, sharing that arm with never-ran
  because both call for the same remedy. And `rows_in` reduces the buffer to a
  COUNT at the boundary, so no byte of a tool's stdout — the likeliest field in
  the envelope to hold a secret — reaches disk, a deny message or a `-J`
  document. An unrecognised buffer shape is `CouldNotLook`, never zero: the
  shapes read are the two this tree has evidence for, and guessing a third would
  make a mis-parse a silent fact.
- `doctor.rs` — `batten doctor` (CLOUD-66), house-style §12's post-install
  self-check: can Batten do its job in this repository? Diagnoses only — it
  **never returns exit 2**, because every failure it can report (config absent,
  invalid, unresolvable; not a repository) is the config-or-usage class, and a
  harness must not read "this checkout is misconfigured" as a deny. That is why
  `config lint` is deliberately _not_ a diagnostic: a smell is exit 2 there, and
  folding it in would answer the same question two ways. Checks report a stable
  reason id, never the error text, so `--json` is byte-stable and carries no
  filesystem path. Distinct from `mise-tasks/doctor.sh`, which gates this repo's own
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
  rather than growing a second trusted-load path. **What is compared is a census,
  not a habit (CLOUD-721)**: `CENSUS` carries a verdict per `Config` field —
  compared (with its kinds), no monotone reading, or not policy-bearing, the last
  two with the reason — and its test reads the field list off `config.rs`'s own
  source, so a key added to the struct fails until somebody decides. `Rule`'s
  predicate columns work the same way one level down: every column is compared as
  a byte change (`RulePredicateChanged`, digest tokens, never a ranking of two
  globs) unless `RULE_NON_PREDICATE` exempts it with a reason. `WaiverExpiryExtended`
  is the pairing `Waiver::key` cannot see — same rule and path, expiry pushed out —
  and stays date-independent by comparing one file's `expires` against the other's.
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
  **Two backends, and the line between them is a DECISION, not an unfinished
  migration (CLOUD-320's `git.rs` row).** `gix_is_confined_to_this_module` keeps
  the in-process half from spreading across the crate. Read the module doc for
  the full split; the rule is: **in-process only where a library makes a defect
  unrepresentable.** Two qualified — `show`, whose argv carried a caller's ref so
  `--config-from --output=<path>` made a `read` verb write a file (CLOUD-718),
  and `count_at_rev`, which parsed `ls-tree` under the host's `core.quotePath` so
  a ratchet spanning a non-ASCII path reported clean while a test was deleted
  (CLOUD-749, CLOUD-328's class on a second axis). `show` also closed the
  `<ref>:<dir>` tree listing and split "unresolvable ref" from "path absent at
  that ref", which is what CLOUD-720 builds last-known-good on.
  **Everything else stays shelled out, measured rather than deferred**, and
  CLOUD-738/739/740 are closed on these grounds rather than pending: the other
  reads take fixed argv with no caller token; `landing`'s two admitted defects
  are INERT (a `PatchId` is only compared against one from the same binary in the
  same run, and the whitespace collision biases safe), so rewriting what
  `worktree`/`baseline`/`stop`/`receipt` rest on is risk with no return; and
  **nothing is kept here because gix cannot do it** — two primitives were, and
  CLOUD-780 deleted them rather than keep a spawn path with no expiry date, so
  every remaining spawn is _unported_ and never _unportable_ (the property
  CLOUD-737's re-decision needs). `no_gix_gap_primitive_survives` is the gate.
  The latency case was measured and does not carry it: `key_facts` is the
  only mediated-path spawn site, measured at 6.7ms on two command shapes against
  the budget `perf-assert` owns (CLOUD-770 — the measurement is this note's, the
  budget is not).
  `git2` is excluded by `macos-link-check` rule 1 — a COST, not a constraint:
  cross-linking Darwin frameworks needs an SDK the build declines because macOS
  runners bill at 10x on a **private** repo, which CLOUD-737 revisits when the
  repo goes public.
- `state.rs` — out-of-tree state dir (`<data-dir>/<app>/<segment>/`, CLOUD-23), via
  `etcetera`; the segment derived at runtime, never baked in (rule 1). Since
  CLOUD-296 the segment is `<dir-name>-<12 hex>`, not the bare directory name: the
  name alone put `~/work/batten` and `~/scratch/batten` in ONE store, survivable for
  SHA-keyed receipts and not for the capture store, where a handle could expand to
  output from a different tree. The digest is `identity::checkout_fingerprint` of
  the canonical absolute root — the mirror image of `canonical_repo_path`, which
  refuses an absolute path because a FINDING's identity must not depend on checkout
  location, where a CHECKOUT's identity is exactly that. A moved checkout derives a
  new segment and orphans its records, chosen over a marker file or a registry
  because either is a second answer to "which repository is this". Worktree siblings
  are unaffected: `git::repo_root` already routes them to the main checkout's root
  (CLOUD-164) before this function sees anything.
- `stop.rs` — the end-of-turn gate (CLOUD-85), house-style §10's "the stop hook is
  the reconciliation point". `deny-stop ⇔ at-risk work ∨ an undischarged denial`,
  and **both inputs are consumed, never re-derived**: `worktree::status` is the
  at-risk half, a store record with `disposition == None` the other. Undischarged
  means NO disposition — the store's own three-valued reading — so every settled
  answer including `rejected-by-design` discharges; a gate that blocked on a
  rejection would refuse an answer the agent already gave. Only `deny`-severity
  findings count, or the severity axis means nothing. A finding the ENGINE
  withheld still counts: the stop event is where a withheld finding is finally
  due. Split like `receipts`: `facts` is the I/O half at the boundary, the verdict
  is pure over values, which is what makes it testable without a world. It **forces
  continuation, never vetoes completion** — `stop_vetoes_completion` is false on
  every surveyed host — which is why the refusal names a command to run rather
  than only reporting a state, taking the first discharging argv a pending denial
  declares and falling back to the at-risk remedy. Distinct from a pre-tool deny
  by EVENT, never by code: §7 has no per-verb exception, so both are exit 2, and
  the `tests/cli.rs` event census gained a `state_decided` column rather than
  losing its "only pre-tool denies" assertion. Dispatched from `adjudicate` BEFORE
  the bypass check — the hook bypass says "do not adjudicate this call", and what
  is judged here is not a call but whether the turn's work is finished. Absent is
  never a deny: outside a repository, or with no bound store, both inputs are
  "not asked" rather than "clean", while a store that exists and cannot be read
  propagates (exit 3, fail loud) rather than guessing either verdict.
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
  CLOUD-97 added the **third door**, `record_sequence`, and one exemption inside
  `record`. The door differs from `record_advisory` in exactly two ways, both
  because a sequence detector RE-EVALUATES rather than only raising: the caller
  supplies the `Observation` (which is what makes the finding self-clearing —
  `Observed(0)` next time resolves it with no ack), and it mints ONLY on a
  positive one, since a record whose only instance says "zero" describes a
  finding nobody raised. The exemption is the load-bearing half: `record`'s
  blanket-resolve pass now SKIPS `FindingKind::Sequence` records, because a rule
  scan has no producer for one and its silence is therefore not evidence — the
  same fail-open `Observation::NotObserved` exists to prevent, one level up.
  Skipped rather than held, or an unrelated scan would overwrite a live raise
  with "nobody looked"; an UNCLASSIFIABLE kind is not skipped, since guessing
  `Sequence` for a future kind would exempt it from resolution forever. `Advisory`
  is now the one value type for both doors, which is why its name is the general
  one and not the judge's.
- `rules.rs` — the rule/check engine (CLOUD-12): glob-selected, `kind`-typed
  predicates over the repo. **`Document`** (CLOUD-772) addresses a node in a
  parsed document — `glob` + `format` + `node` + `pattern`; the parse itself is
  `facts::Format::read`, so the core knows formats and never artifacts.
  **Derived values** (CLOUD-773) are the composition half: a row may `derives` a
  name and another may `reads` it, resolved ONCE per run by `resolve_derived`
  instead of per consumer — which is the defect the shell layer has, where 57 of
  126 tasks compose over an exit code and re-derive what the producer already
  knew. `RuleKind::fact_class` is what makes composition checkable: the meet on
  BOTH CLOUD-757 axes, and a reference that moves the reader's class is refused
  AT LOAD (`validate_composition`), as are a cycle, a duplicate name and a
  reference nothing derives. `validate_in` is the located form the two loaders
  call, so a refusal points at `batten.toml:<line>` rather than only at an id.
  The four-stage `adjudicated` chain deliberately stays code: referenceable
  VALUES are in scope, configurable ORDERING is out, because a chain a consumer
  can misorder puts the protected-mutation gate behind a shape rule that allows
  and the failure is silent. **`Authority`** (CLOUD-763) is the axis `scopes`
  actually pairs on, renamed from `spawns_processes` and corrected: not
  "consumer-authored" and not "spawns", but AMBIENT AUTHORITY — can this kind
  acquire anything its inputs did not carry? Three values, because the boolean
  could not express the case the fact model creates: `Acquires` (reaches the
  network without starting a program) passes "does it spawn?" and fails this,
  which is what makes `no_mediated_call_kind_carries_ambient_authority` STRICTLY
  STRONGER than the pin it replaces rather than a rename. No kind carries
  `Acquires` today; naming the value is what lets a test prove the pin refuses
  it (CLOUD-418). `admissible_at_mediated_call` is the predicate as a free
  function over the authority, so that proof does not need a fixture kind. **`Ratchet`** (CLOUD-55) is the fourth kind: a count
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
  `carries_ambient_authority` stays false — it reaches git plumbing, which is a process,
  but CLOUD-170's invariant is about USER-SUPPLIED CODE (`receipt status` reads
  the same way), and the strict reading would make the kind enforce-only and cost
  it `check`. Two traps measured while adopting it: an unanchored literal counts
  PROSE (a bare `#[ignore]` matched 5 mentions in a tree with zero disabled
  tests, so the row would have failed on its own documentation — anchor to a
  newline), and a glob spanning a SUBMODULE counts one side only (`ls-tree` sees a
  gitlink, the walker sees 228 files: base 637 vs working 1404, a gate that
  cannot fail — CLOUD-328). **Three scan surfaces, and the third is the one
  people miss.** `run_static` (read-effect, no process spawn) backs `check` and
  REFUSES a command-executing rule rather than silently skipping it; `run_all`
  (every kind) backs `enforce`; `run_recorded` backs `state record` and WITHHOLDS
  a spawning kind into `Scan::not_evaluated`, where its findings hold. Skipping is
  honest on the third and dishonest on the first for one structural reason — the
  recorder folds `not_evaluated` into the store and `check` has only an exit code
  — and the third exists because `run_static`'s refusal returns _before any work_,
  so one `command` or `secrets` row cost the whole verb its store write, its GC
  and its transcript detectors. That is why CLOUD-97 had never evaluated once in
  this repository, which declares sixteen such rules. Each rule pins a
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
- `redirect.rs` — the per-path-class redirect table (CLOUD-280): what to run
  instead, keyed by **what is protected** rather than by the verb reaching for
  it. `[[redirect]]` is `{glob, mutation}`, and `hook::protected_refusal`
  consults it BEFORE the verb's own `redirect` — three tiers, table then verb
  then `Fix::None`, where the last two are CLOUD-96's behaviour untouched, so the
  floor is structural rather than careful (`Fix::declared(Option<&str>)` was
  built for this seam). Matching is `rules::glob_match` — one glob semantics for
  the engine — over the SAME normalised path `protected.contains` was asked
  about, or the two tables would disagree about which path is under discussion.
  **Declaration order decides, first match wins**, the tie-break `shape_rules`
  already uses and for its stated reason: a reviewer reads a table top to bottom,
  and any cleverer precedence is a rule about rules the config does not state.
  A **sibling** table rather than a wider `protected`, which keeps `Vec<String>`
  so `trust::removed_entries`'s `protected[<entry>]` weakening keys are
  byte-identical (asserted). Not policy-bearing — it changes what a refusal says,
  never whether it fires — so no raise-only clamp applies; the local layer may
  add a class and may not redefine a committed one, and since local rows append
  after committed ones, first-match-wins means an uncommitted file can never
  change what a committed row says. **The boundary worth knowing**: consumer #1
  declares `.github/workflows/**` and `batten.toml`, and deliberately NOT
  `.serena/memories/**` — that class's remedy depends on the ACTION
  (`write_memory` / `edit_memory` / `rename_memory` / `delete_memory`), so a path
  row would override four correct per-verb answers with one weaker sentence.
  Per-path beats per-verb only where the path fact dominates. It makes a message
  specific; it does not make the named surface reachable (CLOUD-663).
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
  stderr through `output::message`. Scope bound: `reaches` is the authority on
  which kinds a waiver covers — `apply` filters `Finding`s, so `shape`/`receipt`
  (adjudicated to a `Decision`) and `judge` (refused `severity`, so `run_rule`
  skips it) are all out of reach, and its match is exhaustive so a new kind
  cannot default to reachable. A local file may add a waiver
  for a rule the authority does not declare and is refused outright for one it
  does — the one direction where the local layer lowers the bar, and `trust.rs`'s
  `added_entries`/`WaiverAdded` is the first _added_-direction weakening in the
  tree. Dead-waiver diagnostics are `lint.rs`'s `waiver-names-no-rule`,
  `waiver-expired` and `waiver-unreachable-kind` (the rule exists and its kind
  mints no `Finding`, so the row survives the other two and still suppresses
  nothing — read through `waiver::reaches`, never a second list here);
  the runtime one (a waiver matching nothing) is deliberately
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
  **CLOUD-46's pileup half is GONE (CLOUD-780, 2026-08-20)** — the count over the
  OTHER worktrees on the machine, `worktree reclaim`, the `[worktree]` table and
  the four `git.rs` primitives they rested on. A deliberate capability loss, not a
  refactor: the standing strategy is _gix for everything gix can do; where it
  cannot, implement LESS rather than keep a spawn path_, and those two primitives
  were the only ones kept for the other reason. What survives is every fact about
  the work in front of the reader; what is gone is Batten answering the one about
  the machine around it. Read CLOUD-780 for why a PARTIAL drop was refused —
  `reclaim` was the crate's only destructive path and its safety WAS the interlock
  a partial drop removes, so it was all four symbols or none.
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
- `decision.rs` — the guard-decision telemetry record (CLOUD-133): what a gate or
  hook decision emits, and its append-only home in out-of-tree state. The
  **observability** plane, not the enforcement one — recording who called is
  provenance, never judgement, so CLOUD-93/131 are untouched and nothing here
  participates in a verdict. It is what CLOUD-32 descoped stamping onto, because
  no decision record existed: `hook.rs` adjudicates and emits nothing,
  `receipt.rs` records a verification claim, `findings.rs` holds findings.
  **Rule 4 is structural, not editorial**: no constructor accepts bytes or free
  text, so `Subject` is a `StoredIdentity` and `ContextPointer` a `Fingerprint`
  plus a count, both minted by `identity.rs` before they arrive — `judge.rs`'s
  posture with the one bytes-bearing field removed rather than guarded. The
  subject **is** the finding identity where one corresponds (CLOUD-123, never a
  second divergent hash) with `identity_version` beside it, or
  `Subject::Unattributed`, a real answer rather than a hash minted here.
  `identity::context_fingerprint` is the sanctioned context pointer and lives
  there for exactly that reason. Byte-stability survives a timestamp because the
  clock is an INPUT (`RecordedAt`, `waiver::today`'s idiom). Provenance degrades
  in its VALUE, never by dropping a field (`unknown`, CLOUD-275) — with the
  stated limit that a host declaring the literal `unknown` is indistinguishable,
  which under-attributes, the safe direction. `Outcome::Skipped` maps to **no**
  exit code rather than `Success`: reading a skipped gate's silence as a pass is
  `findings::Observation`'s fail-open at the verdict layer. Storage reuses
  `journal::shard_id` (one shard per writer, no lock, fsync before returning)
  and `defects::first_divergence` (append-only is a byte PREFIX, one definition
  in the tree). No CLI verb: surfacing the join is CLOUD-275's, the
  context-as-embedding capture CLOUD-134's.
- `drain.rs` — the advisory drain (CLOUD-79): the first thing that reads the
  store back TO the agent, and the producer `NotShown::DrainSuppressed` had been
  waiting for. **The batch boundary is a window, not an event**: `hook::Event`
  carries no batch variant, so N verifiers in one batch are N separate processes,
  and a drain per process IS the once-per-verifier behaviour the issue removes.
  (Claude Code DOES emit `PostToolBatch` — CLOUD-187 wires a hook on it — and the
  other four surveyed hosts do not; riding it where it exists is CLOUD-389, and
  it changes delivery rather than the invariant below.)
  The first wake past the window drains, every wake inside it is `Coalesced` and
  records that a follow-up is owed — so the MASK, not the event, enforces
  once-per-batch, which is why a host that never grows a batch event still gets
  batch behaviour. Each wake being its own process is also why the window is
  persisted per session under the bound store (`drain/<hash>.json`, the session
  id HASHED — it is a host-chosen string and must not choose a path). Two
  short-circuits that are deliberately not one: `resultId` (CLOUD-166) declines
  to repeat a byte-identical payload, the empty-poll give-up stops paying for a
  drain AT ALL until the merged log moves — collapsing them loses one, since a
  resultId that also stopped looking could never notice the store had changed.
  `pending` suppresses the give-up: a masked wake was promised a follow-up, and
  giving up instead is the window silently becoming a loss. The scope filter is
  **per kind and the exception is the point** — only `Code` is filtered against
  `git::changed_paths`; sequence/log/scope bypass unconditionally because the
  flagship wrong-completion class (done-not-landed, deny-then-bypass) attaches to
  no changed file BY CONSTRUCTION, so filtering on "no changed file" would drop
  exactly what the engine exists to raise. An unclassifiable kind bypasses too:
  showing costs a line, filtering is a silent false negative. Not built on
  `findings::pointer_lines` — that renders per INSTANCE (right for `state list`),
  where the drain's contract is one line per IDENTITY with a repeat suppressed
  and counted. `[drain]` absent means the DEFAULTS, unlike every other optional
  table (a budget nobody declared is not a budget of zero): this is engine
  pacing, not consumer policy, and it is unlayered because an interval has no
  monotone direction for a raise-only clamp to read. Rides `hook` at the
  post-tool event — an event no host offers a deny channel for — so it is
  structurally unable to block (§0.3). A record with no `check` or no
  `remediation` is never emitted (CLOUD-81's `is_emittable`) and is NOT counted
  as a suppression — the engine did not choose to withhold it.
  **Emission is bounded twice, and the two bounds are not interchangeable**
  (CLOUD-82, which is why `cycle` selects before it renders): the per-rule
  `cardinality_cap` collapses a rule over K distinct identities to one
  `rule R: K+ findings` line and journals the rest as `OverCardinalityCap` — a
  statement about the RULE, and the counter rule-health telemetry reads — where
  the `token_budget` clamps the payload as a whole (via `budget::estimate_tokens`,
  never a second estimator) and journals what it drops as `DrainSuppressed`, a
  statement about THIS boundary that the next drain reconsiders. Lines are
  ordered salient-first by tier, then rule, then fingerprint, and the count is
  deliberately NOT a sort key: that is CLOUD-80's no-escalation law made
  structural rather than remembered. A group re-raise renders `old->new` against
  `WakeState::counts` — what this session's last drain actually SAID, since the
  store carries no count anchor — and only for emitted identities, so a capped
  rule anchors nothing. A count that fell renders plainly: a ratchet is not a
  re-raise, because re-raising on incremental fixing punishes the fix.
  CLOUD-165 adds a **fourth** withholding reason, and the four now measure four
  different things: the scope filter is about the TREE, the cap about the RULE, the
  budget about THIS PAYLOAD, and `FlapSuppressed` about the identity's own SIGNAL.
  The filter sits inside `select`, after `in_scope` and before the instance pick —
  the last point a withheld identity is still a record that can be journalled,
  since `cap` folds it into a summary and `state_lines` has already digested it. Its
  count joins `result_fingerprint`'s withheld tuple, and the omission would have
  been the worse bug: a flap suppression is invisible in the lines, so a cycle
  withholding a newly-flapping identity would digest identically to the last one and
  `resultId` would report `unchanged` about a payload that changed. The drain also
  journals its EMISSIONS now (`record_emissions`, `Origin::Drain` + `Shown`): only
  suppressions were ever recorded, because `Shown` is a record's default — so the
  log carried a suppression history and no emission history, and a cap counted in
  evaluation boundaries had nothing to count. Written only when the payload actually
  reaches the agent, since an `unchanged` boundary showed nothing and must not spend
  the cap. It also repairs a smaller asymmetry: a record suppressed once kept the
  `NotShown` reason forever, because only a suppression ever wrote the field.
  `[drain]` gains `flap_window`/`flap_percent`/`emit_cap`, engine pacing like the
  rest of the table; `flap_window` under 2 turns the policy off for both halves,
  which is why there is no separate `enabled` key to disagree with it.
- `emission.rs` — the emission policy (CLOUD-165): hysteresis and a re-emit cap on
  the notification channel, and NOTHING on the state plane. The plane split is the
  whole issue — hysteresis on finding _state_ would contradict CLOUD-81's law, since
  an open finding whose own check exits 0 is a broken invariant, not a debounced
  one — and it is **structural rather than remembered**: the module takes the
  journal by reference and returns values, so it holds no store handle to write
  through. Flapping is an ANNOTATION feeding per-rule health, never a gate on
  clearing and never an exit code. The window is counted in **evaluation
  boundaries** (the last N entries for one subject), never wall-clock, because a
  clock makes the same oscillation read as flapping on a busy box and steady on an
  idle one, and makes the verdict unreproducible from the log — where `drain.rs`'s
  coalescing interval genuinely IS a clock, pacing being a question about time. The
  subject is **(identity × context)**, `findings.rs`'s comparison law applied to the
  journal: read per identity alone, two worktrees at two refs are indistinguishable
  from one identity oscillating. An entry naming no context is its OWN subject, not
  a member of a default ref — the "cannot classify, do not default" reading, which
  is also how a secret-class record (whose `kind()` is `None`) travels through
  unclassified rather than guessed. Emissions are per IDENTITY, since a drain entry
  carries no ref. The cap biting only a FLAPPING identity is the hysteresis: a steady
  finding re-raised repeatedly is working output, so capping it unconditionally
  would make this a rate limiter on the drain — a different feature with a different
  failure mode. Too few evaluations is `Steady`, never `Flapping` (cost of believing
  a steady identity is one emission; of disbelieving a real one, a finding nobody
  sees), and the threshold divides by adjacent PAIRS rather than evaluations, or a
  perfectly alternating window could never reach 100. Only observations that LOOKED
  count on either side: reading `NotObserved` as a clear manufactures a transition
  out of a rule that never ran.
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
  **The execution half landed with CLOUD-56**, in the same module: `[judge] run`
  (command template, first token a program on PATH, run DIRECTLY — never a shell)
  and `model` (opaque to the engine, substituted at `{{model}}`; the placeholder
  with no model set is refused rather than passed through as a literal argv
  token). `argv()` resolves the two; `invoke()` spawns with the payload on
  **stdin** and stdout/stderr to `/dev/null`, which is what makes "reads the exit
  code only" true rather than aspirational — a judge's prose can never re-enter
  the engine as a decision input (CLOUD-93). `Verdict::of`: `0` clean, `2` raised,
  **anything else (and a signal) unresolved**. That third arm is load-bearing —
  reading any non-zero as a raise, or any non-two as clean, converts a plumbing
  failure into a verdict.
  The `judge` RULE KIND (CLOUD-56) is `rules.rs` vocabulary only —
  `carries_ambient_authority() == true`, so `run_static` already refuses it on `check`
  naming `batten enforce`, with no new code. Columns: `criteria` (required, the
  committed question), `tier` (`AdvisoryTier`, default `advisory`), and
  `no_fix_reason` **required** — a judge finding reaches the store and CLOUD-81
  refuses a stored finding nothing can close, and a model's opinion has no
  mechanical fix. `settling_argv` is the judge's answer to CLOUD-81's settling
  question: neither `Reevaluate` (the engine cannot re-decide a model's verdict)
  nor `None` (that means "never reaches the store"), but the judge's own argv.
  **Blocking is unrepresentable, not forbidden.** A judge outcome is a
  `findings::Advisory`, never a `rules::Finding`, so `any_blocking` and
  `--fail-on-warning` have nothing to see; `findings::record_advisory` is its own
  door because the tier comes off the ROW (there is no severity to derive one
  from) and because a judge invocation is one row's answer, so it must not
  resolve findings it never looked at. The walker reaches the same place by its
  own route: a judge row's severity is `allow` — refused as a config key and
  injected by `config::parse` before deserialization — so `run_rule` returns
  before any kind dispatch. The injection exists because `Rule::severity` is
  required and non-`Option` by an equally deliberate decision; the faithful fix
  (per-kind presence, so the derived SCHEMA stops flagging a correct judge row)
  is CLOUD-445.
- `design.rs` — design-evidence integrity gates (CLOUD-53): is the RECORD behind a
  decision sound, whatever the decision was? Input is a JSONL claim stream on
  **stdin and nothing else** (CLOUD-324) — stdin SUBSUMES a config path (a corpus
  that is a file reaches the gate as `< corpus.jsonl`, no key and no credential),
  so there is no second source and therefore no precedence question, and the
  module stays a pure function of a string. Nine gates, each an exact comparison
  over typed fields; the load-bearing consequence of rule 3 is that "the claim
  asserts an absence" is computable ONLY as a declared `polarity` field —
  classifying claim text would be a judge, and judges cannot block (§0.3). Five
  violations (duplicate id, `verified ∧ absence`, digest mismatch, a status past
  `claimed` with no verifier, declared `byte_count` vs the bytes carried) and four
  advisories (no claimant, verifier == claimant, binding not computable, capture
  over the ceiling). `claimant`/`verifier` are OPTIONAL on purpose: their absence
  is what two gates decide over, and a required field would turn each of those
  findings into a parse error that refuses the whole corpus. `byte_count` is
  DECLARED rather than derived, which is what keeps the budget checkable for a
  record carrying no bytes — and makes the declaration itself falsifiable. A
  malformed row is exit **1**, not 2, and unlike `defects.rs` it is not a finding:
  the corpus IS the input, so a row that does not parse leaves the audit with no
  object. `blocks` is the FIRST consumer of `config::Strictness` and reads all
  three ranks rather than special-casing `strict`; promotion runs through
  `rules::any_blocking`, so `--fail-on-warning` and `strict` share one definition
  of what advisory costs and no bespoke flag exists. `Permissive` is unreachable
  from an override (resolve clamps raise-only). Findings are ordinary `Finding`s
  (`Scope`, keyed on gate id + CLAIM id, never the line — a corpus is regenerated
  wholesale, so a position-keyed identity would re-mint on every unrelated edit).
  Digest binding reuses `receipt::hex_sha256`, made public rather than respelled:
  the plain in-toto `sha256` an external attestation tool wrote, deliberately not
  `identity.rs`'s domain-tagged construction. The one config key is
  `[design].max_capture_bytes` (default 16 KiB, tighten-only — `judge.rs`'s shape,
  where §8's "may not weaken" reads as "may not RAISE"). Clean prints NOTHING on
  the plain channel while `-J` answers unconditionally: the two channels disagree
  on purpose. `design attest` (write) is not built.
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
  and `findings::Observation::NotObserved` are the reserved seam CLOUD-98/219 still
  occupy, and `completion.rs` (CLOUD-97) is the first to take it.
  `Event::TurnEnd(StopReason)` is CLOUD-97's widening of it: the host's
  `stop_reason` normalized to a typed vocabulary
  (`EndTurn`/`StopSequence`/`ToolUse`/`Other`) whose raw string never leaves the
  module, emitted on PRESENCE of the typed field and never gated on the role —
  reading a role to decide whether to trust a typed field is the inference this
  module refuses. Its own event rather than a third field on `Event::Turn`, so
  the turn boundary's consumers carry no `Option` none of them asked for, and it
  is pushed AFTER its boundary because a marker scan depends on that order.
  `Counts` deliberately gains no field for it: a turn-end reason is a
  predicate's input, not a fact the capability report's reader needs, and adding
  one would move a `-J` document four landed assertions read. `session` is `Option<String>` with empty normalized to `None`, the same
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
- `bypass.rs` — guardrail bypass (CLOUD-98): a refused operation retried with
  enforcement off, the THIRD detector over `transcript.rs`'s stream and the
  second occupant of the `Sequence` seam. Neither half is visible to a
  synchronous hook — the sandbox toggle does not route through Batten — so only
  the completed record sees both, which is why this is a post-hoc audit and not
  a reference monitor (the scope reminder still holds). **Both halves alone are
  deliberately silent**: a refusal raises nothing, and flagging every
  enforcement-disable is the alternative the issue rejects, since turning the
  sandbox off is a declared affordance. Only the ordered pair raises, and the
  ORDER is the predicate — one forward pass, so a call that disables enforcement
  before anything refused the same operation pairs with nothing. A refusal has
  two producers joined by the host's `tool_use` id: a hook record at the §7
  verdict code (`Mediated`) and the typed `is_error` boolean (`Failed`, which is
  what covers the sandbox denial no hook ever sees). `Refusal` is declared
  weakest-first so derived `Ord` IS the precedence and merging is `max` —
  `Disposition`'s construction, and for the same reason: byte-stability must not
  depend on the order a host wrote two records about one call. Equivalence is
  EXACT (verb + normalized target, trim and `\`->`/` only — no case folding, no
  path resolution, no shell parsing, each of which would decide two different
  operations are one); a call declaring none of `TARGET_FIELDS` is SKIPPED, since
  "same operation" over a field nobody declared is a guess.
  `ENFORCEMENT_OFF_ARGS` is a crate const on `selfwrite::MEMORY_TOOLS`'s
  precedent — a host's own escape-hatch name is host-adapter data, and a
  repository does not get to redefine what disables enforcement (rule 6) — and
  the match is an exact JSON `true`, never a truthy string. One finding per
  bypassed OPERATION (the identity hashes verb+target beside the session), so two
  operations are two findings and a repeat is a count. Tier `Warning`
  (answer-now, above `completion.rs`'s `Caution`), still unable to block.
  **It never self-clears, and that is a property of its subject**: it anchors to
  an immutable transcript event, so the observation is always positive and a
  clean scan writes NOTHING rather than a clear — a later transcript saying
  nothing about an earlier bypass is not evidence it did not happen. It settles
  by disposition (CLOUD-78), which is the issue's assumption 1 landed as written
  — and the verb that would mint one does not exist yet (CLOUD-587).
- `completion.rs` — declared done with work not landed (CLOUD-97), the second
  detector over `transcript.rs`'s stream and the FIRST occupant of the
  `FindingKind::Sequence` seam that module reserved. A conjunction, both halves
  structural: **completion-signaled** is the last completion marker with no tool
  call after it — two producers, an exact token set over `StopReason`
  (`end_turn`/`stop_sequence`; `tool_use` is the model CONTINUING and `Other`
  absorbs truncation and any future token) and a hook record whose event
  normalizes through `hook::Event` to `Stop`/`TaskCompleted`, reused rather than
  re-tabled so the two ends of that vocabulary cannot drift. The "no tool call
  after it" half is what separates a completed session from one captured
  mid-turn, and without it the rule fires on every session that ever paused —
  the false-positive rate that gets a detector switched off. **¬landed** is
  `git::landing`, so patch identity and never ancestry: the rebased-and-landed
  acceptance case needs no code here at all, it is a property of the primitive.
  Four outcomes, and the fourth is the point — `NotComputable` (no landing
  target) writes `Observation::NotObserved`, which HOLDS an open finding, where
  a pass would clear it. `NotSignaled` writes NOTHING rather than clearing: a
  session still running has declared no stopping point, and resolving on that
  silence would let a mid-flight scan close an incident nobody addressed.
  `stop.rs`'s split — `signal` reads the stream, `assess` is pure over values —
  so every branch is testable with no repository, clock or store. Registered
  from `state record` through `findings::record_sequence`, never as a
  `rules::Finding`: blocking is unrepresentable, not declined (§0.3), the judge
  precedent exactly. Tier `Caution` (CLOUD-80), `Check::Reevaluate` — the
  engine's own next evaluation IS the self-clearing mechanism — and
  `Remediation::NoFix` naming the target ref, because the fix is "land it" and
  the command that does that is a consumer's (rule 1). Output is a transcript
  line, a marker token and a count; the raw session id reaches the store only
  inside `identity::sequence_fingerprint`.
  **It first evaluated in this repository on 2026-08-20, and the gap is worth
  remembering** because none of the four causes was visible from inside: no
  `[transcript]` table (so the capability resolved `Unconfigured` and returned
  silently), nothing invoking `state record`, `run_static` refusing that verb
  outright over a spawning rule (see `rules.rs`), and nothing reading the store
  back to an agent. A detector can be complete, tested and shipped and still
  never run; "is it wired for consumer #1" is a separate question from "does it
  work", and only the second one had an answer. It is wired now through
  `mise-tasks/stop-guard.sh`, which refreshes the transcript symlink from the Stop
  payload, runs the recorder, and reports the finding via
  `mise-tasks/unlanded-check.sh`.
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
- `init.rs` — `batten init` (CLOUD-206), house style §12's scaffolding half: the
  starter `batten.toml` embedded as `src/starter.toml` plus the three-valued
  `apply` (`Created`/`WouldCreate`/`Exists`). The FIRST verb whose write target is
  inside the repository — every other writer is out-of-tree state — so two things
  are pinned rather than inferred. It writes the **working directory**, never
  `git::repo_root`: §8 defines the authority with no upward walk and `resolve`/
  `lint` read it from the working directory, so scaffolding to the repo root would
  write a file the loader ignores; it also means `init` needs no repository, which
  is what makes the empty-directory case honest. And an existing config is exit
  **2**, not 1 — `batten.toml` is the committed authority §8 makes the trust
  boundary, so declining to overwrite it is a policy answer about the repository
  rather than a claim the invocation was malformed. Carried as a returned
  `ExitCode::Violation` (what `check` does), never a `Denial`, whose scope is a
  mediated call; the reason rides stderr unprefixed per §7. Existence is decided
  BEFORE `--dry-run`, mirroring `provision::apply`: a preview of a write that
  would never happen is not a preview. The template is deliberately NOT
  `batten.example.toml`: that file had drifted into `unlanded = []`, a smell
  `lint.rs` reports, and its conflict-marker rule is now a `command` kind
  delegating to `hk` — which `check` refuses and a fresh consumer has no binary
  for — so a repository started from it fails its own first command. A scaffold
  must run clean under the read-effect verb with nothing else installed, so the
  two answer different questions. Retiring the example is a follow-up, kept out of
  the landing change because that file takes a commit from nearly every feature
  adding config surface, and deleting it puts a hand-resolved conflict on every
  lap. Its rule globs `**/*/*` rather
  than `**/*` for a reason worth keeping: a `forbid` pattern is a literal, so a
  repo-wide glob makes the rule fire on the config that declares it.
- `identity.rs` — finding-identity fingerprints (CLOUD-123): SHA-256 over a
  normalized, kind-discriminated tuple — never raw `file:line` — so line
  insertion doesn't re-mint a finding; content changes correctly do. The module
  doc is the landed spec (tuples, canonicalization, exclusions, count semantics,
  migration, interaction laws), so read it rather than re-deriving from the
  issue. Three things beyond the plain fingerprints: `secret_code_fingerprint`
  HMAC-keys the span for secret-class findings, because an unkeyed digest of a
  low-entropy secret is an offline-guessing oracle a journal cannot expunge —
  the key comes from the caller and custody is `secrets.rs`'s, and since
  CLOUD-59 WHICH span is keyed is a type rather than recall: it takes an opaque
  `SecretSpan` with no route back to `&str`, so the mis-route to
  `code_fingerprint` is a compile error. The secret class carries its own
  date-styled version (`StoredIdentity::secret`) and deliberately no
  `FindingKind` variant — that enum's one consumer is the changed-scope filter,
  whose honest answer here is `None`/cannot-classify; `override_fingerprint`
  hashes the default identity as a field, which makes a per-rule override
  split-only _by construction_ rather than by validation; and the key-id sits
  inside the preimage while an `identity_version` stays outside it, which looks
  contradictory and is not — a version must not re-mint (the migration
  equality-join needs comparable hashes), a rotation must (its join is
  dual-HMAC). Behavioural churn fixtures live in
  `crates/batten/tests/identity_churn.rs` (CLOUD-169); they compose the matcher
  with this module because a `Finding` carries no fingerprint yet (CLOUD-164).
- `secrets.rs` — secret-class scanning: key custody and the scanner adapter
  (CLOUD-59). Detection is adopted (a pinned ripsecrets, run as a child); the
  module exists for CONTAINMENT, because the scanner prints the byte it matched
  and Batten copies what it sees into channels that retain it. Two controls,
  neither a rule anyone remembers: each match is wrapped into
  `identity::SecretSpan` at the parse boundary, and that type has no route back
  to `&str`, so handing one to the unkeyed `code_fingerprint` does not compile;
  and `rules::Finding` has no field a span could occupy, so pointer-only is
  structural in text and `-J` alike rather than a property of the renderer.
  Wave-one custody: 32 bytes from the OS CSPRNG under `state::repo_state_dir`,
  mode 0600 set AT CREATION (a chmod afterwards leaves a world-readable window,
  and the key is what gets written into it), `create_new` so the loser of a mint
  race READS the winner rather than overwriting — a truncating write there
  silently re-identifies everything already emitted under the replaced key, which
  is also why a malformed key file is refused rather than repaired. The key is
  machine-scoped, the stated trade absent a secret channel. `today` and the key
  path are both injected: the key id is a hash input (so a self-read clock would
  bound §6 byte-stability to a day), and the path is ambient env-selected state
  that only `set_var` could move, which `unsafe_code = "forbid"` rules out
  entirely.
  CLOUD-529 landed the custody remainder, and the shape is a **split, not a new
  module**: this side owns the keys and the append-only ledger beside them
  (`identity/custody.jsonl`, ids + fingerprints + counts, never bytes) and reads NO
  store — the whole keyed-identity invariant is that the key is unreachable from
  the digests it protects, and a module that opened the store would be one edit
  from breaking it. `lib.rs`'s `reconcile_secret_custody` owns the store and never
  sees a key byte. The ledger exists because the key id lives INSIDE the HMAC
  preimage: self-describing is not readable, so no stored fingerprint can be asked
  which generation minted it, which is the exact question rotation and loss turn
  on. Rotation holds **two** generations in the key file (never three: a third
  needs a rule for which pair a join names, and rotating twice would orphan the
  middle one, so `rotate` refuses while a window is open) and is an operation with
  a WINDOW rather than a write — the new fingerprint is an HMAC over a span, no
  span is stored anywhere, so the dual-HMAC pair is computable only inside a scan
  while both keys are held, and each pair is written to the ledger as it is
  computed. Applying a pair MOVES the record (disposition, tier and instances
  travel; `findings::forget` drops the old file) rather than re-minting one — a
  rotation that dropped a `rejected-by-design` would resurrect every dismissal.
  Key loss is the other branch and never a degraded rotation: the predicate is
  ledger-against-file (a generation that once existed and is no longer held), NOT
  "the key file is missing", which is indistinguishable from a repo that never
  scanned; the affected findings are re-opened through `findings::reopen` — the one
  deliberate bypass of the disposition join, since an orphan is not a new
  observation the `max` join could absorb but the loss of the ability to compare —
  and the event is loud, unladdered, and recorded once per lost generation.
  Rewrites go through the key file's own TEXT (`generation_lines`), because
  `IdentityKey` exposes no byte accessor and widening it for a file rewrite is the
  containment claim's own property being spent. One bug surfaced by journaling:
  `scan` hardcoded `remediation: None` where every other kind reads
  `rule.remediation()`, invisible while nothing secret-class could reach a store
  that refuses a remediation-less finding, and silently fatal to §7(a) the moment
  it could.
- `policy.rs` — the policy evaluator (CLOUD-647, CLOUD-689): a `[[rule]]` of
  kind `policy` names a **registered** Rego module, and the module decides over
  the resolved fact set. It exists because `run` is a flat loop where no row
  consumes another's verdict, so a predicate over relationships between facts is
  not expressible as a row — which is why 57 of 126 tasks compose over a
  sibling's exit code and re-derive what the producer already knew.
  **`MediatedCall`-scoped on `Authority::Supplied`, not by exception**: a
  `command` row spawns a process that can read any file and reach the network,
  while a module is a pure function over the input document, so the fact set is
  its whole world. That bound is only statable because the fact model exists,
  which is the real reason facts came first. **Deny-only structurally** — only
  the module's `deny` set is read and there is no spelling for an allow, so §8's
  raise-only invariant holds and the allow/deny contradiction class cannot be
  authored. **Registration, never discovery**: §8 forbids the upward walk and
  the `conf.d` merge, and naming each module in the one committed authority is
  the opposite of both. `load` compiles and drives a smoke query AT LOAD because
  regorus reports conflicts and recursion at _evaluation_, which on the mediated
  path is the worst time and the wrong exit class. A faulting module is
  `Look::CouldNotLook`, never an empty deny set — CLOUD-251's vacuous pass is
  exactly what this surface could rebuild. `Module` holds no `source` field and
  hand-writes `Debug`, so a policy body has nowhere to live past compilation
  (rule 4).
- `pattern.rs` — the `[[pattern]]` table (CLOUD-885): named regular expressions a
  policy module references by id, never writes inline. **The lever is cost, not
  prohibition** — "do not regex things that are not regular" is a judgement and
  rule 3 refuses a gate over one, but _where a pattern lives_ is decidable. So a
  regex costs a config row and an id while the same question over an
  already-parsed document costs a field access, and the cheap path becomes the
  correct one without a translator reasoning about regularity. Consumer-owned for
  `verbs`' stated reason (rule 1): a tracker-key expression is a consumer
  identifier. Two consequences fall out rather than being designed in —
  duplication becomes _unwritable_ (measured: one concept, 19 spellings across 17
  shell programs), and the inventory becomes reviewable data (§11). `policy.rs`
  closes it at both ends: an inline literal is refused, and so is a reference no
  row declares, because that resolves to UNDEFINED and Rego reads undefined as
  "does not hold" — a silent gate. The same failure by deletion is
  `trust::WeakeningKind::PatternRemoved`. Two defects here were found by an AST
  probe rather than a reading: a backtick literal is a `RawString` node and not a
  `String`, and a REFERENCE contains a literal (`patterns["x"]` is a `RefBrack`
  indexed by a string), so a naive sweep refuses the sanctioned form.
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
rebased-and-landed branch is merged though `--is-ancestor` says otherwise. Non-Rust tests (`mise-tasks/*` scripts,
gates) live under `tests/*.bats`, run via `mise run test:bats`.

## Self-consumption

Root `batten.toml` is Batten's own policy config — "consumer #1" (AGENTS.md
rule 1) — gated by `batten check` against this repo. The template for external
consumers is `crates/batten/src/starter.toml`, emitted by `batten init`; it
lives in-crate because `crates/batten` is the published package and
`include_str!` cannot reach outside it. `batten.example.toml` is still here and
is a different artifact — a teaching document, gated separately — and retiring it
in favour of the starter is CLOUD-206's follow-up. `.taplo.toml` binds all three
to `schema/batten.schema.json`.
