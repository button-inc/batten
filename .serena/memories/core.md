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
- `mem:workflow/sonar-scope` — Sonar refuses your branch; reading or changing
  `sonar-gate`; a Sonar verdict looks wrong on a SHA; before treating a `final`
  failure as trunk's, or a check-run's annotations as the whole finding list.
- `mem:session-transcript-access` — asked to read chat history or another
  session; before probing a session API or credential.
- `mem:github-access` — any GitHub op; before claiming the toolchain or CI
  "can't reach GitHub".
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
- `bot.rs` — the bot lane, retired off `mise-tasks/bot-issue.sh` (CLOUD-1295).
  Two halves in one module: the PREDICATES — is this PR one of the lane's, which
  manifests it touched, what Conventional type its subject declares, whether a
  body still CLOSES a key rather than merely naming one — are pure functions with
  no network at all, and the `forge` submodule is the only thing that talks to
  anybody. It reads through `gh` rather than `fetch.rs` for `pr_watch`'s reason
  (CLOUD-1143): the client resolves the credential OUTSIDE this crate, where the
  transport would put token resolution inside it next to no config row declaring
  one. Every consumer fact — repository, bot logins, owned manifests, the marker
  strings, the tracker's key prefix, the branch prefix, the body template's path
  — is `[bot_lane]` in `batten.toml`, so a grep of `crates/batten` for a bot's
  name or a manifest path returns nothing (rule 1); `document_facts` caught the
  first draft's doc comment naming one as an example. The verbs are `batten pr
derive|file|link|ensure|closes` plus `claim bot`, and neither forge-reading one
  declares `-J`: the `-J` census's byte-stability term would be a claim about the
  forge's answer rather than about the verb, which is the same call `pr watch`
  makes. `claim bot` is the SECOND receipt kind and `carry.rs` below is the
  third; they are separate because they attest different things (CLOUD-431).
- `carry.rs` — whether a licence-carry branch's diff is DERIVABLE, and the
  receipt that records it (CLOUD-1295). `sbom-actions-currency` (CLOUD-1213)
  opens its PRs on `sbom-actions/carry-<timestamp>`, which neither receipt
  `verify` accepts would fit — so the first one landed on a `--takeover` claim
  asserting a refinement nobody performed. **Nothing here reads the branch
  name**: a prefix exemption would be a password wearing one, and anything able
  to name itself so would pass. What is attested is checkable against the merge
  base — one path differs and it is the licence table, every added row names a
  repo the BASE already carries with an identical licence and holder so only the
  sha moved, and nothing is removed or rewritten. Two choices are the whole
  predicate: append-only is a PREFIX comparison, because a line-set difference
  reads a rewritten row as a removal plus an addition and could admit the
  addition; and the known verdicts come from the base side ONLY, or two unmapped
  repos vouch for each other and the branch carries a licence nobody judged.
  Byte-identity of the upstream files is the workflow's half, stated as such —
  this bounds what the diff may say, not what upstream holds.
- `claim.rs` — whether an issue is pullable, and the receipt that records the
  pull (CLOUD-272, CLOUD-431; ported off `mise-tasks/claim-check.sh` by
  CLOUD-1121). The tracker's automation fires on the PR event — the END of the
  work — so nothing reserves an issue when somebody starts it; measured on
  CLOUD-49, a second session began writing it six minutes after the first and the
  result was thrown away. **Two questions, and `Kind` is what stops them being
  one.** COMPETITOR rules (not-todo, assigned, has-pr) detect somebody else and
  every one reads clear when nobody else is involved, so all three are blind by
  construction to a sole agent moving too fast; SEQUENCE rules ask whether the
  story was refined before the session implementing it. They shared a counter in
  the shell, so `--takeover` — documented for "the competitor is this branch" —
  also cleared `refined-this-session` (CLOUD-816, measured on a payload with no
  competitor at all). `Verdict::pullable` can only clear `Kind::Competitor`, so
  the collapse is unexpressible rather than merely repaired. Carries CLOUD-520's
  live-PR narrowing with its bias intact (a merged PR is a predecessor; absent
  and malformed still refuse, so it can only turn a false refusal into a pull)
  and CLOUD-526's projection (the body is demanded by the one rule that reads it,
  at its own site, which is also what keeps the cheap refusals reachable on a
  bodyless payload). Readiness delegates to `ready::lint` rather than re-reading
  a grammar whose anchors were found by experiment.
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
- `admission.rs` — issued admissions (CLOUD-1051): an override stops being
  knowledge and becomes a record. A content-addressed capability over
  `{rule, verdict, subject, head, epoch, answers, prev, author}`, canonicalized
  by JCS rather than concatenated — raw `a ‖ b` is ambiguous across field
  boundaries, so two field splits can hash alike and the address would not be
  well-defined. **The address is INTEGRITY, never authentication**: anyone
  holding the answers can compute it, so what restricts who may mint one is the
  store's write path and nothing else. Under a local store that means anyone who
  can write it can mint one, which is acceptable against honest error and is
  written down so a later reader does not mistake the hash for a signature. The
  store has an `fs4` compare-and-set this row introduced — `receipt.rs` carried
  no locking at all — and the questions come off a class's declared
  `override.precondition` in `verdict.rs`. The gate never grades an answer;
  presence and non-emptiness are the whole predicate (rule 3).
- `advisory.rs` — the advisory CHANNEL and what it may cost (CLOUD-896). A LEAF
  beside `refusal.rs`, and the pairing is the whole placement: `refusal` bounds
  ONE emitted deny line, this bounds ONE emission of the whole channel, so the two
  answer the same question over the two documents a boundary can produce.
  CLOUD-461 coalesced the FRAMING — one `additionalContext` object per call — and
  bounded nothing about volume: three producers (`drain::render`,
  `contract::render`, the dispatched handler) shared no rate budget, and
  `[drain] token_budget` bounds only one of them, so the channel's real ceiling
  was whatever the set summed to. `[advisory] max_tokens` supersedes it — one
  fact, one authority. `admit` sorts by `AdvisoryTier` (CLOUD-80's severity as
  required response latency, `Reverse` because the derive is weakest-first) and
  fills until the ceiling is spent; the tier is carried from the PUSH SITE in
  `lib.rs` rather than inferred here, because "how soon must this be answered" is
  a property of what is said and the boundary has only a string. **The remainder
  is dropped AND COUNTED** — a truncated report that reads as complete is the
  false green in advisory form — and the count line is a count and a ceiling,
  never the dropped text. **The first entry is always admitted**, even alone over
  budget, so the count line can never be the only thing said. An UNDECLARED
  ceiling emits exactly what it emitted before, in the boundary's own order: that
  is the anti-vacuity half, and it is what keeps this consumer's number out of
  every other consumer's engine (rule 1). `validate` refuses `max_tokens = 0` at
  load — a channel switched off wearing a budget's clothes. `trust.rs` carries
  `AdvisoryCeilingRaised`: smaller is stricter, absent is unenforced rather than
  zero. It reaches `budget` for the estimator `refusal` already reaches, because a
  second one would be a second authority over what a token costs.
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
- `handler.rs` — the `[[hook.handler]]` dispatch surface (CLOUD-898), the door
  that lets `batten hook` be the ONLY registration on every surface while a
  repository still runs whatever it likes behind it. A **second noun beside
  `action`, never a widening of it**: an action cannot change the answer and its
  streams are discarded; a handler participates in the decision and its streams
  are the channel. The reader's question is "may this change the answer" and the
  kind is the answer. `pre-tool` IS declarable here — `action`'s first objection
  (a side effect running before a deny) does not transfer to something that IS
  the decision, while its second (a config load on the hottest path) does, so
  `selects` is CLOUD-460's narrowing and a call no handler selects for does less
  work than `--help`. Four contract properties no dispatched program can give
  itself: a parent-imposed **bound** (the retired `stop-guard` hand-rolled
  `timeout 1s cat` for this; the rest had none), central **fail-open** (spawn failure, timeout and
  an undefined exit are all could-not-look, which allows), a stated **output
  shape** (stdout on exit 0 is advisory text, a reason is on stderr, §7's
  `0/1/2` unchanged), and **one reply per call** via `Dispatched`. stdout is
  INTERPRETED, never forwarded — the rule-4 answer and the portability answer at
  once: a handler speaks to Batten in Batten's vocabulary and Batten re-renders
  per harness, so a host decision document written here is
  `Violation::ImpersonatedHost` rather than bytes nobody passes on. Violations
  are pointers carrying the handler id and never a byte the handler wrote.
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
- `checks_green.rs` — is this SHA green over the required check set (CLOUD-1143,
  ported off `mise-tasks/checks-green.sh`). A pure function of a READING the
  caller already holds, never of the network: the fetch stays with the poller,
  which is the agents-fetch-gates-decide split, and it is what lets every case
  run offline. Conserves three rules and re-decides none of them — latest run
  per name (CLOUD-436), absent-is-not-skipped with an unset tolerated set as the
  STRICT direction (CLOUD-337), and the fan-in split where an unnamed fan-in
  leaves every failure manufacturable (CLOUD-900 over CLOUD-363). `Red` and
  `Pending` share one exit code deliberately: they differ in whether to ask
  again, never in whether the head may land, so a reader that ignores stdout
  holds rather than fast-forwarding a head nothing judged.
- `pr_watch.rs` — the poll around that verdict (CLOUD-1143, ported off
  `mise-tasks/ci-wait.sh`; renamed off the singleton `ci` noun onto §2's declared
  `pr watch` by CLOUD-1214, which is why the module and the retired program no
  longer share a name). Owns the REQUEST — the conditional read, the ETag,
  the interval — and nothing about what green means, which is CLOUD-346's split
  and why a second, weaker copy of the predicate could not survive in a
  workflow. The poll is CONDITIONAL: a `304` costs no rate limit and KEEPS the
  previous reading, since re-parsing an absent body as an empty check set would
  restart the wait on every unchanged poll. Deliberately unbounded — the exit
  condition is "the required checks answered", and a wall-clock timeout would
  only reintroduce the reap gap it closed. Two progress signals (CLOUD-499), a
  tick per poll and a signature that moves only when the reading does, so a
  heartbeat can tell a healthy wait from a wedged one; WHICH program records
  them is a flag, because a recorder's path in the core is rule 1's violation.
  `Effect::Unclassified` and so out of the read-only allowlist, stated rather
  than guessed: it runs two programs the caller named. "Not yet" never reaches
  the caller — that is the state the loop exists to sit in, and it is the whole
  difference between this verb and `checks green`.
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
- `environment.rs` — what KIND of machine this is (CLOUD-1383), read from the
  environment because it is the one fact a committed file cannot hold: the same
  commit is checked out by a disposable container and by a developer's laptop and
  the honest answer differs. `BATTEN_ENVIRONMENT=disposable` licenses a repair to
  REMOVE what it finds on the surfaces batten already owns; absent — the default,
  and every misspelling — reports and never removes. It replaced a committed
  exemption table that was a second authority over the same subject and drifted
  from the repair within a day.
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
- `contract.rs` — the contract-drift predicate (CLOUD-461, CLOUD-525): hash the
  `[contract] tracked` surface, compare against this session's snapshot under
  `$GIT_DIR/batten-contract/<session>`, and report the change-set **once** on the
  advisory channel. Reports, never refuses — `PreToolUse`'s only model-facing
  channel is exit 2, which blocks, and CLOUD-97/CLOUD-219 each ruled a deny out.
  **Deliberately not a `facts.rs` row**: a fact is what `adjudicate` consumes and
  `Fact::ALL` drives the policy-input projection, so classifying this would oblige
  a projection no rule could read; it obeys the fact model's disciplines (`Look`,
  pointer-only, resolved at the boundary) without claiming a row in a table about
  something else. **Not `[epoch] tracked`** either, and the module doc carries
  why: an epoch must be a function of a _stated_ set, so `epoch.rs` is literal
  paths read one file each — where here a newly added file IS the drift, which
  only globs can see. The write is the rate limit; there is no second state file.
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
- `fetch.rs` — one HTTPS request, in process (CLOUD-745). The client is **hyper
  plus hyper-rustls, not `reqwest`**, and that substitution is a measurement
  rather than a preference: every reqwest configuration hits one of the two
  chokepoints CLOUD-320 died at, because it selects the verifier and the crypto
  provider through FEATURES and unification then puts `ring` or
  `security-framework` in the graph from a crate this workspace does not control.
  Below reqwest both are constructor arguments, which is the whole of why it
  links on an SDK-free macOS build. Measured on four configurations; the
  instructive one is reqwest 0.13's private `__rustls`, which RESOLVES AND DOES
  NOT COMPILE — its source needs `rustls_platform_verifier` unconditionally — so
  `macos-link-check` was green over a graph that cannot build and only
  `darwin-link` saw it. The module states what a link gate structurally cannot
  ask: with no provider in the graph the binary links clean and dies at the first
  handshake, so `graviola`'s presence is asserted by a test. Keeps CLOUD-745's
  fetch-side hardening — connect AND total timeouts, buffer-then-return so a
  caller's verify-before-write order survives, one scoped current-thread runtime
  (never `#[tokio::main]`), and a status as a typed value so a 404 cannot digest
  as a checksum mismatch. `hook` never reaches here, so CLOUD-689's ceiling is
  untouched.
- `gitwrite.rs` — the LOCAL git writes: a loose object into the odb, and a ref
  moved (CLOUD-1274's D2). Placed by EFFECT rather than by subject, which is the
  whole reason it is not part of `git.rs`: that module is read-only over gix and
  says so, and the only REMOTE write in the crate is `lease::swap`. Deciding
  which objects a push must carry stays `git::objects_to_send`, because that is a
  read. Writes go through the odb handle rather than `Repository::write_object`,
  which re-serialises a typed value — the handle takes the payload and the kind it
  was hashed as, so what lands is what the pack reader produced, and the returned
  id is checked against the derived one because a disagreement is a delta applied
  wrongly. Loose rather than a pack: `gix-pack`'s bundle writer is behind
  `streaming-input`, which is off and would pull `parking_lot` and `gix-tempfile`,
  and a lap's fetch is a handful of commits. `module-layering` forbids
  `hook -> gitwrite` and `check -> gitwrite`.
- `land.rs` — the landing lap's REPLAY half, and the first consumer of the two
  modules above (CLOUD-1335). `replay` advances the base (`lease::fetch`, then
  `gitwrite::write_objects`, then `gitwrite::set_ref` — that order, because a ref
  moved before its objects landed names a commit the clone cannot read), replays
  the branch onto it with `gitwrite::rebase`, and APPENDS what happened to a `lap`
  record. **It decides nothing**: whether a lap may continue past a conflicted
  replay is `rebase-conflict-stops-the-lap`'s verdict over that record, which is
  CLOUD-1148's split — mechanics to the engine, decisions to Rego — and what
  keeps this from becoming a second authority on its own subject. A conflict is
  carried outward unchanged rather than resolved; `gitwrite::rebase` refuses
  instead of taking a strategy, and that refusal is the loop's one human stop.
  The record is the only `VERB_WRITTEN` store that is a HISTORY rather than a
  current state, because the module reads its last line so a conflict a later lap
  resolved stops refusing.
- `lease.rs` — the landing lease's compare-and-swap, spoken as git smart-HTTP
  over `fetch.rs` (CLOUD-1274). The CAS is the PROTOCOL'S OWN: receive-pack takes
  `<old> <new> <ref>` and applies it only while the ref still reads `<old>`,
  decided under the server's lock — strictly stronger than `--force-with-lease`,
  which compares against what the CLIENT last observed and races anything that
  moved in between. **No new closure and no git binary**: the framing is
  `gix-packetline/blocking-io` — the same thing `gix-transport`'s
  `blocking-client` resolves to, taken directly, since the transport it would
  supply is not one this crate can use — so there is no HTTP client, no TLS
  backend and no credential helper, and the bytes go over the hyper + rustls
  client `fetch.rs` already bounds. The framing is gix's rather than this
  module's for the reason `.claude/rules/policy-modules.md` gives one domain
  over: a second parser is a second AUTHORITY. What the module adds is the
  BOUNDARY between the framed section and the raw packfile that follows a `NAK`,
  plus a pack writer and reader over `flate2` and a lease commit minted through
  `gix::objs` — parentless, over the empty tree, and salted, because git
  addresses by content and two agreeing mints produce one id whose push is an
  "up to date" no-op that reports success. The three routes that could not be taken are recorded there rather than
  re-derived: gix ships no push at all, gix's own transports resolve `reqwest`
  plus two `FRAMEWORK_CRATES` names, and every git2 configuration that reaches
  HTTPS resolves `openssl-sys`, which `macos-link-check` refuses BY NAME with no
  vendored exemption — and that gate is `governed_at_head`, so adopting git2 would
  have meant retiring the gate protecting the SDK-free macOS build. **The failure
  directions are the design**, because each loses the fleet rather than a test: a
  proxy error page must not parse as an empty ref set (that reads as "the lease is
  unheld" and hands the matrix to everyone at once), a truncated pkt-line is
  could-not-look rather than a short read, a lost race is `Rejected` and NOT an
  error (reporting it as one makes a caller fail OPEN on a rival's win), and a
  report carrying no unpack status is could-not-look. `module-layering.rego`
  forbids BOTH `hook -> lease` and `check -> lease`; `check` is listed explicitly
  rather than left to follow from `hook`, since a tree-scoped gate is declared
  `read` and the read-only allowlist is DERIVED from that declaration.
- `forge.rs` — the forge's verdict for a commit, read back from a record
  something else wrote (CLOUD-1154). **The engine opens no socket, and that is
  the design rather than a constraint**: house style §5 forbids an HTTP client on
  the `check` surface and CLOUD-689's budget forbids one on the mediated path, so
  ~22 governed gates that read the forge had no expressible successor. The answer
  is not to widen the engine but to move WHO RESOLVES — the producer fetches once
  outside and writes a keyed record this reads back, which is `AGENT_SOURCED`'s
  own argument moved from the hook surface to the tree one. `evaluator-io-check`
  stays the gate on the engine opening nothing. **Keyed by SHA, and the keying is
  the safety property**: a verdict taken against a different commit is not
  evidence about this one, so a record under any other key is invisible — without
  it a gate could inherit a green reading from a commit nobody asked about, a
  judgement that was never made reported as one that was. Three answers stay
  apart: a declared sha with no record is ABSENT (nothing has judged this commit),
  a record holding no checks is present and EMPTY (the forge looked and said
  nothing), and no store at all is `None` → `null`. Pointer-only at the boundary
  — a check's name and its conclusion, both tokens, never a check-run body or an
  annotation, which is where rule 4 is decided rather than at the report. The
  polling never moves in (CLOUD-1177): only the decision does, so `ci-wait` and
  `main-watch` get the fact and not a home for their loop.
- `tools.rs` — a third-party tool's verdict, read back from a record keyed to
  (tool, pinned version, input digest) (CLOUD-1171). **`forge.rs`'s mechanism
  with a different key**, and that is the whole row: `check` is `read` and
  structurally cannot run a validator, so ~five governed programs that run one
  and then adjudicate what it said had no successor. The producer runs it once
  outside — a `mise` task, a CI step — and writes a keyed record. **The key is a
  triple and each component refuses a different lie**: the TOOL, because one
  validator's record is not another's; its PINNED VERSION, because an answer at
  one version is not an answer at the next, which closes CLOUD-646's shape for
  this path by putting the pin IN THE KEY rather than in a field a module must
  remember to compare; and the INPUT DIGEST, taken here rather than declared, so
  a verdict goes stale by construction — edit the subject and the key moves, so
  the old record is not found rather than found and wrong. **One parser, not
  two**: `forge::parse` is `pub(crate)` and this reads the same line shape,
  because two parsers over one byte format are two authorities that can disagree
  about a torn line. Three answers stay apart, as `forge.rs`'s do. Pointer-only
  at the boundary — a finding's name and a `path:line`, never a tool's report,
  which is the likeliest place in this family for a secret to appear. **The
  benchmark half is deliberately absent**, by CLOUD-1171's own correction:
  `batten perf` already ships and already spawns, so a measurement was never
  blocked on a record family, and a benchmark key would owe a machine identity
  and a declared null spread besides.
- `captured.rs` — declared REDUCTIONS over responses the agent already captured
  (CLOUD-1188). Ten board gates are pure predicates that exist as CLI verbs only
  because they have nowhere to read from — `.claude/rules/toolchain.md` calls
  them "a pure function of stdin" — and every one becomes a policy module once
  this channel exists. **The store, never stdin, on three independent refusals**:
  a stdin-fed fact declared `Surface::Check` is not admitted, so the module
  silently sees nothing; a payload on stdin is context re-sent every turn, the
  channel `ready lint` and `claim check` were both moved off; and the
  step-receipt key does not include stdin, so two runs over different payloads on
  one tree hit one receipt and skip. `capture::list` is sorted by handle rather
  than by time, so a reduction is a pure function of the store's bytes — the byte
  stability `Surface::Check` requires. **The reduction is part of the FACT**: a
  row declares `present`, `count` or `token`, the set is closed so no row can ask
  for prose, and a `token` over a value carrying whitespace or longer than
  `facts::TOKEN_MAX` is REFUSED rather than truncated, because a prefix of an
  issue body is still an issue body. That is non-negotiable rule 4 decided by the
  declaration's shape. **`None` means the store could not be addressed**, and
  returning an empty map for it was a live defect in the first draft: the state
  directory is derived from an ABSOLUTE root and `check` does not promise one, so
  every declared row resolved to nothing and the module read a clean empty object
  instead of could-not-look — the vacuous pass, inside the function written to
  prevent it. The root is canonicalized here rather than trusted.
- `task.rs` — CLOUD-425's READER: which long-running tasks are running right
  now, and what phase each is in, ported off `mise-tasks/alive.sh` (CLOUD-843).
  Three answers stay distinct and conflating any two is the defect it exists to
  fix — _running_, _crashed_ (a STATE, not an absence), and _nothing registered_
  (which is not could-not-look). **It reads a format ANOTHER PROGRAM OWNS**, and
  that is CLOUD-1283 rather than an oversight: the writer half
  (`mise-tasks/task-registry.sh`) was ported too and could not land, because
  `land-lock.sh` binds it to a variable and spends it with arguments, and
  `shell-retirement` admits a repointing at the binding and none at the spend.
  Shipping engine writers beside it would have put two implementations of one
  stamp rule over one file format. **Reaping is licensed by `kill -0` ALONE**,
  never by a failed corroboration (CLOUD-901): the probe collapses "gone" and
  "not this task" into one `false`, and reaping on the second made a read verb
  destroy the state it reads. **`--program-root` is required, never defaulted** —
  where a consumer keeps its programs is that consumer's fact (rule 1), and a
  wrong root fails SILENTLY because an unmatched corroboration reads as alive.
  Sends no signal at all: `SIGUSR1`'s default disposition is Term, so a reader
  that signalled would kill what it came to inspect.
- `taskset.rs` — the task runner's own argv, from a receipt minted OUTSIDE the
  mediated call (CLOUD-856). `hook::call_document` projects `Fact::Document` as
  `None` and rightly — a document is unbounded there — so
  `cargo-substitutes-for-a-task` stayed in bash while the rest of its guard
  moved. **The answer is shape (c): move the acquisition, not the arm.** The
  manifest is parsed once at SESSION START, where a read of that size is
  admissible, and the call reads one small keyed record. `Fact::Document`'s arm
  is unchanged and now carries the reason it can stay that way. **It files under
  `pinned.rs`'s store and reuses `pinned::key` deliberately**: both are memoised
  readings of the same manifest, so two key derivations would be two answers to
  "has the manifest moved" that can disagree — and the one saying "no" wins by
  being read first. **Staleness is structural**: the key is recomputed at read
  time from the manifest's bytes, so a record about a manifest that has changed
  is not found. That means the read DIGESTS the manifest and never PARSES it —
  a distinction that took a correction, because the first test asserted the
  manifest need not exist, which the design deliberately does not provide; the
  case that discriminates records over a manifest that is not valid TOML.
  A task with no single-command body is present with a `null` argv rather than
  absent: "not a single command" and "not defined" are different answers, and
  reducing a compound body to a word list would let a guard refuse a call by
  naming a command the task never runs. **Aliases are deliberately NOT recorded
  here** — resolving them is an effect, `pinned.rs` already asks and already
  records, and a second recorder would be the second authority this module's own
  key-sharing exists to avoid.

`Fact::Extracted` (CLOUD-1172) has no module of its own — it is resolved by
`lib.rs`'s `extracted_facts` over `transcript.rs`, which already types every
event it reads. **The row asked for the transcript's contents and the answer is
COUNTS**: `facts::Extraction` is a closed set whose every member returns an
integer over a typed field — a hook run's exit code, a result's own `is_error`
— so no span of session text can reach the policy input by construction rather
than by a projection remembering to drop one. A transcript is worse than the
commit body CLOUD-1168 declines to carry, because a body is authored and a
transcript is captured. **Could-not-look is the COMMON case** (CLOUD-388:
transcripts die with their container): no path on the envelope, a host that
keeps none, one that will not parse, and nobody having declared an extractor are
all `null`, and every one differs from an extractor that ran and counted zero —
reading the first four as the fifth is the false green CLOUD-990 measured
costing a session an hour. **CLOUD-1029 is not a precondition here**, recorded
rather than assumed: that row makes the transcript tamper-EVIDENT and is a
precondition for any gate whose verdict is ABOUT the record's integrity; this
one grades neither the record nor its author. A consumer that later grades
transcript CONTENT needs 1029 first, and nothing landed authorises one.

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
- `invocation.rs` — Rust call sites, parsed (CLOUD-914). Answers WHERE a token
  sits, which no line predicate can: a literal in a call's ARGUMENT list is an
  invocation argument, one in an array initialiser or a method call's receiver is
  not, and a comment never reaches the walk at all. That split is the whole
  discriminator — five of `git.rs`'s seven source-scan gates assemble their
  needles by concatenation so they do not match their own source, and the two
  that do not obfuscate are exactly the two that never read their own module.
  A file the parser refuses is `Look::CouldNotLook`, never an empty node set.
  Separate from `facts.rs` because that file forbids a wildcard match arm and the
  walk over the parser's expression enum needs one — two matches with opposite
  right answers do not share a file.
- `uses.rs` — the `use` graph (CLOUD-762). Which module reaches which, resolved
  through the crate root's own re-export table. **The measurement is the point:**
  over `crates/batten/src/**` the syntactic tier diverges at exactly FOUR sites in
  two classes, both re-exports — `trust.rs` and `output.rs` reach `error` through
  `crate::UsageError` (a hidden edge a line predicate reads as nothing), and
  `policy.rs` and `sink.rs` read as internal where `crate::Result` is really
  `anyhow` (a phantom edge it invents). Aliases and globs move NO top-level edge
  in this tree. Four is bounded and nameable, so the fact is `Read × Check` and
  needs no delegated analyser — and the deeper reason is that the re-export table
  is itself syntax, so a parser resolves it with no name resolution at all.
  Two things the tree corrected and the code now states: a bare first segment at
  the root is a module OR another crate, told apart only by the root's own `mod`
  declarations; and `use crate::{a, b}` imports modules directly, so every
  declared module is its own table entry. `via_root` marks the edges resolution
  CHANGED, because judging by the item's case counts all 88 ordinary edges as
  divergences.
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
- `recorder.rs` — a post-tool record whose SHAPE is the consumer's and whose
  columns may carry a value another gate decided (CLOUD-1051). Sits beside
  `mint.rs` rather than inside it: a mint renders a closed template over a path,
  which is right for a receipt and cannot express an exit status. A closed value
  language — `literal | result | input | object | wrap | section | program` —
  plus per-column `minus`/`without`/`counted-with`/`zero-is-a-count`. `result`
  and `input` are separate variants because they differ in TRUST, which is what
  makes the record unforgeable by its own author. Refusal is at LOAD (an
  undeclared program or pattern), never a column that renders `-` forever, since
  the gate downstream passes on `-` by design. `section` takes `[[pattern]]` ids
  and refuses an inline regex, `policy-modules.md`'s rule one layer over.
  `run_program` is an annotated spawn — the censused program is the single
  authority on a grammar 19 files share, so it is run rather than reimplemented.
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
- `review.rs` — the vendored-prompt dispatch tier (CLOUD-472): the SECOND
  occupant of `Cost::Effect` and the third adopter of `secrets.rs`'
  delegated-analyser shape, after `symbols.rs`. It answers one narrow question —
  **did a particular vendored prompt run over these exact bytes** — and that
  narrowness is the mechanism rather than a limitation: a gate over it refuses
  ABSENCE, which is a comparison of two digests, so no model verdict reaches an
  exit code (rule 3). The findings reach a module as `{path, line, clause}`
  pointers with no field an agent's prose could occupy, so rule 4 holds
  structurally rather than by the parser remembering to strip.
  **It is what the cheaper tiers cannot be.** `ready-lint` gates the SHAPE of a
  refinement block, and shape is what an author optimises against once the gate
  exists — the measured failure that opened CLOUD-472, where every clause was
  present and none had been pressure-tested. `obligations-bound` binds a §7 entry
  to a killer mutation, but only at implementation time; at refinement there is
  no code, no case file and no `#MUTANT` row to reach. A hash comparison is what
  better-shaped prose cannot satisfy, because the prose is the input to the hash.
  **Spawn on miss, read on hit**, keyed by (prompt digest, subject digest) —
  `step-receipt`'s pattern, so the agent runs once per unique subject rather than
  once per landing lap, and editing the ticket body or pushing a commit leaves
  the record under a name nothing looks up. The keying is the anti-staleness
  property, not an optimisation.
  **The dispatch is the ENGINE's**, which is the whole difference from
  `tool-verdict`'s producer-writes-outside store — identical read shape, measured
  dead, because somebody has to remember to run the tool and pipe its output
  (CLOUD-1265). The prompt is compiled in the way `policy/presets/**` are, so its
  digest is a constant of the build and a consumer cannot satisfy the gate by
  pointing it at an easier prompt. Every failure path — runner missing, non-zero
  exit, unparseable stream — leaves NO record, so a broken agent and one that
  never ran are indistinguishable and both refuse.
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
- `hookcost.rs` — what this repository's own hooks cost the session that runs
  them (CLOUD-417). Rule 4 is stated per-CHECK and enforced per-CHECK, so nobody
  had measured the hooks IN AGGREGATE, where one compliant line is emitted
  hundreds of times and every copy stays in context forever. Measured on one
  captured transcript (758 turns, 5.83 MB): `hook_success` 1181 KB +
  `hook_additional_context` 42 KB — **hook output alone is 20% of the
  transcript**, the largest contributor saying one identical true thing every
  turn. Same shape CLOUD-896 found one layer down, and the same answer: put the
  ceiling on the aggregate, because the aggregate is what is spent. Two
  predicates on `[hook_output]`, and the second is most of the win —
  `max_tokens` bounds the session, `max_repeats` makes **"silence on success is
  the default"** and **"a repeat is a pointer to the first, not a copy"**
  DECIDABLE rather than prose, because a hook saying the same thing every turn is
  a digest repeated. Floor on `max_repeats` is 1, never 0: saying it once is the
  report, and refusing the first emission would silence the finding rather than
  its restatement — which the row puts explicitly out of scope. Pointer-only
  structurally: `transcript.rs` hashes the emitted text
  (`identity::context_fingerprint`) and DROPS it at the parse, so a measurement
  of an over-wide channel cannot itself carry what the channel said; the report
  keeps eight hex characters, a count and the first copy's line. Grouping key is
  (producer, digest) — two hooks emitting one string are two producers, not a
  repeat. `Event::HookOutput` is APPENDED to the transcript vocabulary and gated
  on the host's `hook_*` tag PREFIX rather than an enumerated set, because an
  unrecognized tag counted as zero is the silent under-report this row ends.
  Empty output is not an emission, which is what keeps three silent records from
  hashing alike and manufacturing a violation out of the behaviour being asked
  for. `Reading::line` is ONE line and `batten policy hooks` prints nothing
  around it — the self-applying property, asserted in both tiers. Not in
  `verify` and not in the hk gate: a transcript is a property of the WORLD, not
  of the commit (`lock-complete` vs `lock-currency`), so `mise run hook-cost` is
  a hand run — which is also the row's acceptance clause, the 20% figure shipped
  as a re-runnable command rather than a number in an issue body.
- `markers.rs` — counted suppression markers (CLOUD-36): how many times policy
  was waved through, and where. Tokens are config, never crate constants (rule
  1); hits are pointer-only (`path:line` + marker id, rule 4) and `counts`
  reports every configured marker including zero, so "none now" stays
  distinguishable from "not measured". Reuses `rules::tree_files`.
- `mcp.rs` — Batten as an MCP **client** (CLOUD-1260): the `[mcp]` table, wiring
  resolution over declared `[[mcp.source]]` rows, the JSON-RPC session
  (`initialize` → initialized → `tools/call`, SSE-framed or not), and the
  `[[mcp.result]]` reductions. `project` keeps declared fields as the payload
  carries them; `acknowledge` holds each to a bounded token and drops what is not
  one, so the write-side arm cannot emit prose however a row is written. `payload`
  takes the PROTOCOL's own content-block framing off — that is MCP's vocabulary,
  not a tracker's — and is three-valued, so an unrecognised shape keeps its bytes.
  What it unframes is what `capture::store` files, because `capture::find` looks
  for its key at the top level and the board gates read the store that way.
  Every tracker identifier is the consumer's, in `batten.toml` (rule 1); the crate
  knows only _dispatch a declared method, reduce by a declared projection_.
  Network goes through `fetch::spend`, one current-thread runtime per sequence.
- `minted.rs` — one declared FIELD of a receipt `mint.rs` already wrote, read on
  the TREE surface and bounded by age (CLOUD-1310). **`tools.rs`'s mechanism a
  family over**: the fetch happened at the mediated boundary, in a session that
  had a credential, so what remains here is a line off disk and a clock
  comparison and `check` stays `read`. Answers the question `hooks-wiring-check`
  decided from piped-in payloads — _has the issue owning this exemption CLOSED_ —
  which CLOUD-1160 retired with no successor because a tree-scoped module has no
  stdin. **The age bound is why this is not `captured.rs`**: that store is keyed
  by content and carries no clock, so a MUTABLE field answers from whichever read
  sorts first in digest order, which `batten.toml`'s `claim-before-code` row
  records being refused from as a pre-claim capture. Positional, because
  `claim.rs` already reads this store with `nth(3)`; `field` and `recency` are
  separate indices and the load refuses them equal, since collapsing them projects
  the timestamp as the value while the bound compares it against itself.
  **Could-not-look is the ORDINARY answer** — the store is under the git
  directory, never committed, empty on every CI runner — so `None` covers both of
  its conditions and a readable store holding nothing is present and EMPTY, a
  different answer.
- `mint.rs` — receipts minted from the tool result that earned them
  (CLOUD-1024): the `[[mint]]` table, the closed six-form body template
  (`{path}`, `{now}`, `{digest:}`, `{slug:}`, `{join:}`, `{git:}`), the dotted
  path selector whose `[]` segment iterates, and `satisfied` — which is **the
  success predicate**, not a convenience, since a mint firing on an errored or
  empty response would forge a read receipt for a read that never happened.
  Written by `lib.rs`'s `record_mints` on the post-tool event, beside
  `record_agent_fact` whose shape it copies down to the silent-failure posture.
  **Not `sink.rs`'s production axis**: `validate_sink` refuses `produces` on any
  non-Tree scoped row at load, both consumer rows are `mediated_call`, and only
  the pre-tool event is adjudicated — so there is no decision on the event the
  mint happens on and no `Requested` to carry, which is also what dissolved the
  question of carrying a status VALUE. Tracker vocabulary is all config (rule 1);
  the table is authority-only, on a stronger form of `facts.rs`'s reason — a
  local row would not point a gate at chosen output, it would write the receipt
  the gate honours. Shares `rules::selects_tool_name` with `Rule::selects_tool`
  so the matcher choosing which rows adjudicate and the one choosing which
  results mint cannot drift into a gate nobody can satisfy (CLOUD-178), and
  `receipt::safe_subject` so writer and reader refuse the same filenames.
- `mutate.rs` — mutation coverage over the declared gate set (CLOUD-418),
  retired out of `mise-tasks/mutant.sh` and `mise-tasks/mutant-census.sh` under
  CLOUD-1267. **The one behavioural change is the DECLARED suite**: the
  predecessor resolved a gate's source with a Rego fallback and its suite as
  `tests/$gate.bats` unconditionally, so a mutation applied to a `.rego` module
  had no suite that could turn red — 32 modules, 32 `#MUTANT-EXEMPT` rows and
  141 compiled-binary tiers it could not see. `#MUTANT-SUITE <path>` beside the
  `#MUTANT` rows names the tier instead, and `Suite` resolves a `.bats` through
  the vendored runner or a `crates/batten/tests/*.rs` through `cargo test
--test`. Two more arms the predecessor lacked: a gate name resolves to a
  PRESET directory as well as a task or a module, and `#MUTANT-OWNER` echoes the
  row owning a known-dead predicate on its survivor line while **changing no
  exit code** — annotation, never an exemption. Conserved whole: the anti-vacuity
  term (a listed gate with no declaration FAILS), three-fields-before-the-split,
  green-before-mutation, the inert and self-mutating diff tests, both directions
  of the too-wide/too-narrow filter, restore-between-rows, and a staged tree that
  is a real repository. `Verdict::could_not_look` is what splits exit `3` from
  the `2` a survivor answers, which is the acceptance rather than a nicety.
  Spawning side per CLOUD-1171 (`perf.rs`'s disposition), so `mutate sweep` is
  `write` and only `mutate census` reaches the read-only allowlist.
- `verbs.rs` — the mutating-verb table (CLOUD-36): which programs change the
  world, config-driven (rule 1) and typed by `effect.rs`'s one §5 vocabulary
  rather than a second severity axis. Each verb carries its own redirect for the
  refusal contract. Table and lookup only — crossing it with the protected path
  set is CLOUD-96's gate, and the sets are CLOUD-37's.
- `verdict.rs` — the refusal vocabulary (CLOUD-1050): the `[[verdict]]` table,
  its `Subject` pointers and its closed `Route` list. A refusal stopped being a
  free string here — `{rule, verdict, subjects}` replaces `{rule, msg}`, the
  prose moves into the one declared class definition, and every remedy defect
  CLOUD-122 named becomes decidable instead of merely expressible. **One table
  for both emitters**, Rego and native alike, which is the drift CLOUD-1050
  reversed its own first review over. Well-formedness is validated at parse
  beside `pattern.rs`'s; registry EQUALITY against what the modules emit needs
  the compiled bundles and lives in `policy::load`; route TARGET resolution is a
  policy module, because a task runner is a consumer fact (rule 1). Tombstone
  chains live here too, and are the same chain predicate CLOUD-1051's `prev`
  needs.
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
- `wiring.rs` — the one WRITE path over a host's hook registrations (CLOUD-893),
  surfaced as `wiring reclaim`: `destructive`, `-y` required, subject is this
  host's merged `$HOME` surfaces and never the committed file (the `same_file`
  arm). It also owns the three wiring-file readers `doctor.rs` used to hold —
  `committed_events`, `entries_under`, `same_file` — so the census and the repair
  cannot disagree about what a registration IS, which is the defect
  `merged_under`'s own comment warns about. **Records before it repairs**: a
  harness reads its wiring once at session start, so a repair changes the disk and
  not the running host, and a census taken after one reports `merged_siblings: 0`
  over a runtime still dispatching what was deleted. The at-load record under
  `$GIT_DIR/batten-wiring/` is what keeps those two states distinguishable;
  `doctor hooks` reports its total as `at_load_siblings` (`None` = no repair
  recorded, which is read-the-disk) and `hooks-wiring-check` turns a non-zero into
  `wiring-repair-unloaded`, naming the restart. The record has exactly ONE writer
  and ONE expiry — `reclaim` writes it if absent, `batten hook` on `SessionStart`
  drops it — which is why the repair is not run from a session-start handler at
  all: both acts inside one unordered batch would be a coin toss between the
  honest red and the false green the record exists to refuse. `wiring apply` over
  the committed surface is deliberately unbuilt, and the reason got STRONGER
  rather than weaker: it was "the one committed violation left is
  `session-start.sh`, whose remedy is a handler row rather than a deletion", and
  that row landed — so there is now no committed violation at all for such a
  writer to be right about. `hooks-wiring-check`'s `DECLARED` table is
  correspondingly empty, and the two launcher rows it used to carry are what this
  verb removes.
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
- `patch.rs` — the in-process patch identity (CLOUD-739), and `git::landing`'s
  sole supplier of one. It replaced `git log -p | git patch-id --stable` and, with
  it, the twenty-six settings pinned around that pipeline — twenty `git config`
  keys, six flags, two environment variables — whose whole purpose was stopping a
  host's configuration from changing the answer. In process there is nothing to
  pin, so all twenty-six are deleted and NOTHING replaces them.
  **The deliverable is the normalisation being DECIDED, not the spawn being gone.**
  A `PatchId` is only ever compared against one this same binary made in this same
  run, so the requirement is _a_ canonical deterministic identity, never git's
  (CLOUD-320 ruled that in writing) — and that licence is what turns four side
  effects of tool choice into four choices with reasons. Line numbers stay
  excluded, the one behaviour inherited deliberately, because hunk positions are
  exactly what shift under the replay the primitive exists to recognise.
  **Whitespace becomes SIGNIFICANT, diverging from git**: `patch-id` folds it, so
  a whitespace-only difference collides, and the doc this replaced called that
  collision _"the safe direction for a primitive whose failure class is a false not
  landed"_ — backwards here, because a false LANDED is what suppresses
  `completion.unlanded`'s finding. A spurious not-landed is noise, a spurious
  landed is a lie. Binary content is identified by blob ids, which RETIRES the
  `--binary` caveat (a zlib body _"deterministic for a given zlib but not
  guaranteed across zlib builds"_) rather than restating it. Renames stay
  undetected, now as a choice rather than as two flags that had to agree.
  `imara-diff` is taken DIRECT and `gix-diff/blob` refused: `blob` is monolithic,
  and its eight non-imara deps exist to run external diff drivers, clean/smudge
  filters, and materialise blobs to disk — honouring `diff.<driver>.command` would
  hand back the very host-configuration input the twenty keys removed.
  **The rename case is the CLOUD-418 lesson worth carrying**: rename detection is a
  pure function of the two trees, so no fixture built out of trees can tell a
  detecting build from a non-detecting one, and the test that claimed to gate it
  could not go red. It is gated on the SHAPE instead
  (`patch::tests::renames_are_not_a_shape_this_identity_can_take`), where the
  mutation — a fourth `Kind` — fails the build with E0004.
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
  `lib.rs`'s `stop_nudges` (CLOUD-1051, which retired `mise-tasks/stop-guard.sh`):
  the boundary refreshes the transcript symlink from the Stop payload, runs the
  recorder, and reports the finding via `mise-tasks/unlanded-check.sh`, which is
  spawned unchanged.
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
- `sink.rs` — production, the boundary half (CLOUD-851): a `[[rule]]` may declare
  what it PRODUCES, and this is what writes it. The split is the whole design —
  `rules::run` computes `Scan.requested` purely from the rule table and the
  sorted findings, and this module turns that into bytes under
  `$GIT_DIR/batten-sinks`, so `adjudicate` stays pure with three of the four
  writing hook bodies on the mediated path. Three kinds, distinguished by what
  READS the record: a journal nothing reads back, a keyed baseline a later run
  reads back through `Fact::Produced`, and a marker whose only content is its
  existence. Only the spawning surface performs — `check` computes the identical
  request set and writes nothing (§5). Rule 4 is structural: `Requested` has no
  field a matched byte can occupy, and byte-stability is a property of the
  request SET rather than of the schedule, which is what makes it safe under
  CLOUD-850's concurrent acquisition.
- `semver.rs` — the API-compatibility gate as a delegated-analyser adapter
  (CLOUD-1050), ported off `mise-tasks/semver.sh` when CLOUD-1059 made editing a
  shell rule refusable. Same shape as `symbols.rs` and `secrets.rs` — a pinned
  binary, its flags beside the parser, an exit status reconciled against what the
  output says — plus one thing neither needed: **a baseline the committed lock
  can build**. `cargo-semver-checks` runs `cargo update` in a scratch crate, so it
  discards `Cargo.lock` and its verdict is a function of the registry index at the
  moment it runs. Measured 2026-08-26: green in CI at 19:18:19Z, `bisync 0.3.0`
  yanked at 19:25:45Z, every commit from v0.0.89 on unresolvable seven minutes
  later. `baseline_rustdoc` builds it with `--locked` instead and hands it over
  through `--baseline-rustdoc` — MORE of the gate applied, not less. The rev route
  stays primary and `Route` is reported, so a green never hides its baseline.
- `symbols.rs` — the first `Cost::Effect` fact's acquisition (CLOUD-760). Where
  a **name** resolves, asked of the compiler rather than of the text: the census
  `.claude/rules/scanning.md` records three answers for — `grep` 14, a syntax
  matcher 11, name resolution 9 — because `surface.rs` imports `clap::Command`
  bare and no scanner can tell the two types apart. So this module delegates to
  `cargo clippy --message-format=json`, with `--force-warn` overriding
  `allow`/`expect` so an ENFORCEMENT lint reports as an INVENTORY without the
  tree's annotations deciding what is counted.
  It generalises `secrets.rs`'s adapter shape rather than copying it — binary
  pinned, flags beside the parser, exit reconciled against the parse — and
  carries that module's invariant verbatim: **clean is never inferred from a
  stream that failed to parse**, so an unreadable stream is `CouldNotLook` and
  never an empty census. `Provenance` (tool, version, invocation) travels inside
  the fact because §6 byte-stability is a claim about a named producer; `Site`
  is pointer-only per rule 4, a path, a line and the lint, with the path made
  repository-relative so the answer does not depend on where the checkout sits.
  Acquisition is the CALLER's: `rules::symbols_fact` resolves it once at the
  boundary and only when a row declared it, and the projection is pure — a
  projection that spawned would be the class's whole point undone. `Surface::Hook`
  is refused (`tests/facts.rs`'s `no_effect_fact_is_hook_resolvable`), as a
  census over `Fact::ALL` rather than an assertion about this one variant.
- `preset.rs` — one manifest per vendored preset (CLOUD-1181): identity, the
  `scope` its modules decide, the modules themselves, and the refusal classes
  they raise. It exists because a preset used to be three unrelated `const`s that
  nothing tied together — the name-to-modules table here, the verdict rows inside
  `verdict.rs`'s `VENDORED` under a comment, and a branch exempting it from the
  `[[pattern]]` refusal — so a preset carried no identity beyond its name, no
  version, and no declared scope. **Below `policy` and `verdict`, and it reads
  neither**: both project the one declaration rather than three tables knowing
  about each other, which is what `module-layering` pins. `scope` is the field
  the row was written for, and the honest reading of what it buys is in the load
  site's own comment: a mismatch was ALREADY refused by the module input-key
  check, so this refuses earlier and names the preset a consumer enabled rather
  than a module inside the binary. **A manifest is not permission to fetch one**
  — CLOUD-129's no-network verdict is unchanged, `include_str!` at build time,
  and what the manifest buys CLOUD-970 is that the trust question becomes
  askable at all.
- `policy.rs` — the policy evaluator (CLOUD-647, CLOUD-689): a `[[rule]]` of
  kind `policy` names a **registered** Rego module, and the module decides over
  the resolved fact set. It exists because `run` is a flat loop where no row
  consumes another's verdict, so a predicate over relationships between facts is
  not expressible as a row — which is why 57 of 126 tasks compose over a
  sibling's exit code and re-derive what the producer already knew.
  **Scoped on `Authority::Supplied`, not by exception**: a
  `command` row spawns a process that can read any file and reach the network,
  while a module is a pure function over the input document, so the fact set is
  its whole world. That bound is only statable because the fact model exists,
  which is the real reason facts came first. It is also what admits a policy row
  to the read-only `check` surface where a `command` row is barred.
  **BOTH SCOPES, not mediated-call only** (CLOUD-833): a row is
  `scope = "mediated_call"` (the hook, reading `input.call.*`) or `scope = "tree"`
  (`batten check`, reading `input.tree.*`), and the two documents are different
  shapes — a key from the wrong one resolves to undefined, which Rego reads as
  "does not hold", so the gate is silently dead (CLOUD-845). The emittable key set
  per surface is the two GENERATED schemas, `schema/policy-input.schema.json` and
  `schema/policy-call.schema.json`; `rules-drift` holds the prose that names them
  to those files. A row selects a **bundle** rather than a single file, and
  `presets = [...]` enables the vendored bundles compiled into the binary
  (CLOUD-836) — `Bundle` is the unit, and bundles stay isolated from one another
  so a preset cannot silently supply a consumer module's helper. One
  `Engine::new()` per bundle rather than per module (CLOUD-837), because N
  isolated evaluators is the duplication this file's own doc opens by decrying,
  rebuilt in a second language. `batten policy test` runs a module's own `test_`
  rules; `mise run policy-test` is what invokes it in the gate (CLOUD-931), and it
  is the LOAD-TIME tier only — `tests/<gate>.bats` over the compiled binary is the
  tier that proves the engine builds the shape a predicate reads, which a
  `with input as` case cannot. **Authoring contract: `.claude/rules/policy-modules.md`**,
  loaded when writing a `.rego` module or preset. **Deny-only structurally** — only
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
- `perf.rs` — the paired latency measurement (CLOUD-875), retired out of
  `mise-tasks/perf-pair.sh` under CLOUD-1059. Two halves with a deliberate seam:
  `select` is the pure SKIP predicate — a diff that cannot change what gets
  invoked cannot have made the invocation slower — and `pair` is the measurement,
  `Cost::Effect` on `Surface::VerifyOnly`. The seam keeps the decision
  exercisable without a build, the same split `perf`/`perf-assert` keeps. **The
  skip's set is DERIVED, never restated**: crate source and the manifests bound
  four arms, but `wired` adjudicates against the committed config, so the
  authority and every path a `policy` row registers are consulted too — measured,
  one policy row moved `wired` 5.8ms → 9.3ms while the gate reported "nothing
  measured". Wiring paths come from `Harness::wiring` rather than being spelled,
  which is what keeps a consumer's artifact name out of the core. It reaches
  `git` for `merge_base` (range selection through gix — a spawned reachability
  verb is `ancestry-decides-nothing`'s subject), `base_delta` and
  `materialize_rev`, the last of which retires the worktree-wedging defect rather
  than guarding it. The exit contract belongs to a frozen caller: `perf-gate.sh`
  tells a skip from a measurement by grepping `^arm=`, never by a second code.
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
- `pinned.rs` — the programs the project's pin puts on `PATH` (CLOUD-1028), and
  the record that lets a mediated call read them. **The set is the DIFFERENCE
  between the composed `PATH` and the ambient one**, not the pin's install list:
  the runner from the incident (`./tests/bats/bin/bats`, 60 runs killed by an
  unset variable rather than by the assertion) is a submodule the manifest puts
  on `PATH` and not a tool the pin installs, so an install-list reading would
  have missed the exact defect. Executable regular files only — six of the 49
  names here are an extracted archive's `LICENSE`/`README.md`. Resolving is
  `Cost::Effect`, so `refresh` spawns at `SessionStart` only and `cached` reads
  the record on every call. **THE KEY IS ASKED FOR, NEVER WRITTEN DOWN**: naming
  the manifest and lockfile in the crate is refused by rule 1's gate, and naming
  them as a row's `sources` is refused at LOAD (that column is a tree row's), so
  `configs` asks the pin which files configure it and `keyed_paths` adds every
  sibling agreeing up to the first `.` — computed at read time, so a lockfile
  appearing after the record moves the key instead of being invisible. Every
  failure is could-not-look, which allows; a fact naming every program in a
  project must never refuse on a failure to see.
- `prune.rs` — the build tree's reclaim and its disk floor (CLOUD-766/861/1030),
  retired out of `mise-tasks/target-prune.sh` under CLOUD-1059.
  `Effect::Destructive` on `Surface::VerifyOnly`, beside `capture prune` — §5's
  read-only promise is about the MEDIATED CALL, and `VerifyOnly` is the surface
  that exists for an effectful verb the hook can never reach. Backlogging this
  row on "the effect cannot move into a read-only engine" was a punt: the
  precedent predated the claim by months and `perf.rs` did the identical port in
  the same session. **TWO FLOORS, and the second one IS the ticket.** The reclaim
  takes superseded artifacts under `deps` only — caches regrow, so deleting one
  costs a rebuild, which is how two hand-remedies re-consumed the space they
  freed — and escalates to dropping `incremental` when the warm floor is
  breached. That escalation GUARANTEES the next build is cold, so re-reading free
  space and comparing it against the warm floor again certifies a lap against a
  basis the reclaim has just destroyed; `Basis` moves with the reclaim and the
  cold floor is what then applies. Both floors live in `[prune]` with the date
  they were measured, because how many megabytes a rebuild writes is a consumer
  fact (rule 1) — `Prune::validate` decides `mb == worst_mb * multiplier` at
  config LOAD, which is what the predecessor's regex over its own source was
  reaching for one tier earlier. Its one spawn is `df`, for `symbols`' reason:
  what the volume has left is not a property of the tree. `TARGET_PRUNE_FREE_MB`
  is CLOUD-778's seam widened to a SEQUENCE — the readings a run takes, in order,
  last repeating — because the discriminating case needs the second reading to
  differ from the first.
- `startup.rs` — the `[[startup]]` table (CLOUD-1324): what a container must be
  and how it is repaired. Sibling to `provision.rs` and the split is the SUBJECT —
  that one answers _is this artifact the one we pinned_, this one _is this
  container the one we declared_. Same §9 check/fix pair, as one verb and a flag
  (`batten startup`, `--repair`) rather than two sub-verbs, because both halves
  decide the same rows and the fix half's report IS the check re-run. A row is
  `id`/`gloss`/`check` argv/optional `repair` argv; nothing in it names a harness
  or a platform, which is what makes the table the harness-agnostic answer to
  "what does this box need". After a repair the check is RE-DECIDED, so a repair
  that exits zero having fixed nothing reports `repair-failed`; a check that
  cannot be spawned is could-not-look — never a pass, and never a licence to
  mutate. The declared repairs also run at `SessionStart` without a flag, because
  writing a `repair` in the committed authority IS the authorisation; `--repair`
  is the out-of-band surface `setup.sh` uses. Replaced `[hook]
reclaim_at_session_start`, a boolean about one harness-shaped repair in a table
  about hook events.
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
- `ready.rs` — the Definition-of-Ready grammar as a predicate over a tracker
  payload (CLOUD-179, ported off `mise-tasks/ready-lint.sh` by CLOUD-1121 when
  `shell-retirement` made editing a shell rule refusable). **Rust rather than
  Rego, and the reason is the input**: the predicate reads a PAYLOAD, which is
  not tree state, and a module reads `input.tree.*` with no issue-payload fact to
  read — which is why `shell-retirement` accepts `crates/batten/src/*.rs` as a
  policy surface. Validates the clauses PRESENT and says nothing about absence
  (the gate document forbids restating all eight, and CLOUD-33 omits §4 while
  correctly Ready), with a FLOOR under that: a block carrying no clause at all is
  refused, the parent dialect exempt by opener and never by count (CLOUD-299).
  Four grammar facts are each recoverable only by experiment and each cost an
  incident: the commit type is a whole code span and not a prefix (CLOUD-290),
  the `!` is read off that token and never off the line so "Not `!`" denies
  rather than declares (CLOUD-852), a break denial must name the surface it
  denies about and must ATTACH to the denial rather than share its line
  (CLOUD-842), and an absent `relations` key is could-not-look rather than an
  empty edge set (CLOUD-679) — which is why a violation outranks a gap here,
  the opposite of CLOUD-251's ordering and deliberately so. `Finding` carries a
  line and a rule id with no field a body can occupy, so rule 4 is structural.
- `receipt.rs` — verification receipts (CLOUD-203): SHA-keyed in-toto
  statements that a named check passed, stored out-of-tree (first caller of
  `state.rs` and `identity.rs`) plus the grandfathered
  `$GIT_DIR/batten-receipts/` compat layout the shell readers consume;
  validity (`valid`/`stale-head`/`stale-main`/`missing`) is a pure function
  of receipt + git facts — amend, rebase, or a moved main invalidate, never
  a clock.
- `record.rs` — the WRITE half of the two out-of-tree verdict stores
  (CLOUD-1265). `tools.rs` and `forge.rs` both shipped a correct reader with no
  writer but a test, so `validator-verdict-clean` and `forge-verdict-required`
  resolved `null` on every real checkout and decided nothing — CLOUD-845's dead
  gate, twice. Two leaves (`record tool <id>`, `record forge <ref>`) rather than
  one verb with a mode flag, because the stores share the `<name> <token>` line
  shape and nothing else, and a flag choosing which KEY gets composed would be a
  second authority over it. **It ingests a verdict and spawns nothing** — the run
  stays outside (§5, §9's prior art), `mise run record-verdicts` is the caller.
  **The anti-staleness property is argv shape, not discipline**: there is no
  `--digest`/`--tool`/`--version`/`--input`, so the row id is the only handle and
  the verb digests the subject itself through `tools::digest`/`record_key` — the
  same two functions the reader calls. A record for a tool nobody declared is
  therefore unspellable. Stricter than `forge::parse` in one place: a line with no
  token is refused rather than skipped, because a producer emitting one has a bug.
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
gates) live under `tests/**/*.bats`, run via `mise run test:bats`.

## Self-consumption

Root `batten.toml` is Batten's own policy config — "consumer #1" (AGENTS.md
rule 1) — gated by `batten check` against this repo. The template for external
consumers is `crates/batten/src/starter.toml`, emitted by `batten init`; it
lives in-crate because `crates/batten` is the published package and
`include_str!` cannot reach outside it. `batten.example.toml` is still here and
is a different artifact — a teaching document, gated separately — and retiring it
in favour of the starter is CLOUD-206's follow-up. `.taplo.toml` binds all three
to `schema/batten.schema.json`.
