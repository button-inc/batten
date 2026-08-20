# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.92](https://github.com/button-inc/batten/compare/v0.0.91...v0.0.92) - 2026-08-20

### Added

- *(facts)* state what a fact costs and where it may be resolved

## [0.0.91](https://github.com/button-inc/batten/compare/v0.0.90...v0.0.91) - 2026-08-20

### Other

- *(deps)* reach the constructor where it lives, and gate the pin that lied

## [0.0.90](https://github.com/button-inc/batten/compare/v0.0.89...v0.0.90) - 2026-08-20

### Fixed

- *(git)* carry --end-of-options in resolve_ref, whose name comes from config
- *(ratchet)* count the base side from tree bytes, not quoted ls-tree output

### Other

- *(git)* record which half of the module is in-process, and why

## [0.0.89](https://github.com/button-inc/batten/compare/v0.0.88...v0.0.89) - 2026-08-20

### Added

- *(receipt)* [**breaking**] judge the claim receipt with one predicate, not two
- *(trust)* compare every config key the census demanded a verdict for

### Fixed

- *(tests)* gate the StateHome import to unix, where its only callers are
- *(config)* consult --config-from before the working file on every surface
- *(git)* read the config ref in-process, so the ref is not argv

### Other

- *(receipt)* pin the -J document to the keying it judged
- *(receipt)* pin both readers to one verdict, and the stale row that was green
- *(trust)* split the comparison in two so each half stays readable
- *(trust)* a both-directions case per compared key, and one that reaches the verb
- *(trust)* fail on any config field with no weakening verdict
- *(deps)* land the bot's PRs unattended, and retire the second bot

## [0.0.88](https://github.com/button-inc/batten/compare/v0.0.87...v0.0.88) - 2026-08-19

### Added

- *(config)* [**breaking**] name every layer that set a key, not only the winner

## [0.0.87](https://github.com/button-inc/batten/compare/v0.0.86...v0.0.87) - 2026-08-19

### Added

- *(check)* tell a first reader what a clean run just did

### Other

- *(check)* split the clean-run notice's write half from its decision

## [0.0.86](https://github.com/button-inc/batten/compare/v0.0.85...v0.0.86) - 2026-08-19

### Other

- *(git)* keep two cargo test runs out of one fixture directory

## [0.0.85](https://github.com/button-inc/batten/compare/v0.0.84...v0.0.85) - 2026-08-19

### Added

- *(redirect)* declare the two path classes whose remedy the verb cannot know
- *(redirect)* [**breaking**] key the sanctioned mutation to the protected path, not the verb

### Other

- *(config-lint)* arm --config-from against the PR's base ref (CLOUD-236)

## [0.0.84](https://github.com/button-inc/batten/compare/v0.0.83...v0.0.84) - 2026-08-19

### Fixed

- *(claim-check)* void a claim receipt whose branch was restarted

### Other

- *(receipt)* build the fixture body by push, not by format-push-string
- *(claim-receipt)* drive the restart through the real hook, not just the predicate

## [0.0.83](https://github.com/button-inc/batten/compare/v0.0.82...v0.0.83) - 2026-08-19

### Added

- *(exec)* [**breaking**] keep the group predicate live on Windows, and re-measure the tokens
- *(exec)* dispatch a `:::` bundle, and make a live capture readable
- *(exec)* charge the caller a record, not the bytes it already stored
- *(exec)* own the dispatched process tree, or decline to mise's protocol
- *(hook)* give the payload allowlist the spawn prompt it had no member for
- *(commit)* [**breaking**] read the subject convention from batten.toml, not from a mise variable
- *(capture)* navigate a frozen capture instead of re-running the command

### Fixed

- *(exec)* finish reconciling with the capture surface main grew
- *(rules)* dedup rule-scoped findings so a batched command rule reports once
- *(capture)* [**breaking**] reconcile with the surface main grew while this branch was out
- *(cross-check)* gate the dead-helper class, not just its one instance

### Other

- *(process-group)* scrub the marker the suite runs under
- *(census)* decide the shape-row obligation instead of stating it
- *(capture)* route the handle suite's store through state_home
- *(capture)* one function per sub-verb, so the dispatcher clears the length lint
- *(capture)* sort by key, and take the formatters' shape

## [0.0.82](https://github.com/button-inc/batten/compare/v0.0.81...v0.0.82) - 2026-08-19

### Other

- update Cargo.toml dependencies

## [0.0.81](https://github.com/button-inc/batten/compare/v0.0.80...v0.0.81) - 2026-08-18

### Fixed

- *(lint)* the crate satisfies the clippy the raised pin brings with it

### Other

- *(deps)* the MSRV floor tracks the toolchain pin, and two gates hold it

## [0.0.80](https://github.com/button-inc/batten/compare/v0.0.79...v0.0.80) - 2026-08-18

### Added

- *(rules)* run a shebang program through its interpreter

### Fixed

- *(gates)* keep the PATH audit's own fixtures inside the gates it runs beside
- *(tests)* compose the judge fixture's PATH with join_paths, not an interpolated colon
- *(spawn)* read an absolute program's shebang from the program itself
- *(spawn)* one resolution ladder for every kind that spawns a program
- *(doctor)* probe PATH the way the spawn does, not with a second answer
- *(rules)* look up a program under PATHEXT, not only its bare name
- *(rules)* find a program PATH holds under a bare, extensionless name
- *(secrets)* resolve a shebang scanner the way command rules do
- *(identity)* one checkout, one fingerprint, however the path is spelled

### Other

- *(harness)* route every suite's state isolation through one helper
- *(gates)* a path-valued TOML key is interpolated as a literal string, and a gate says so
- *(gates)* a state-dir override must be mirrored for Windows, or it isolates nothing
- *(tests)* interpolate the provisioned url as a TOML literal string
- *(doctor)* interpolate the script path as a TOML literal string
- *(cli)* name the cause when a committed-config case fails
- *(harness)* mirror every XDG_DATA_HOME with APPDATA
- *(harness)* isolate the capability-table hook helper too
- *(harness)* point the state root at the fixture on every platform
- *(gates)* bound the source-introspection slice instead of widening it

## [0.0.79](https://github.com/button-inc/batten/compare/v0.0.78...v0.0.79) - 2026-08-17

### Added

- *(hook)* ride the batch event where the host emits one

## [0.0.78](https://github.com/button-inc/batten/compare/v0.0.77...v0.0.78) - 2026-08-15

### Added

- *(hook)* [**breaking**] adjudicate consumes the boundary-resolved waiver facts
- *(hook)* [**breaking**] refuse publishing work that names no tracker key

### Fixed

- *(hook)* a shallow clone cannot answer the key question, so it allows

## [0.0.77](https://github.com/button-inc/batten/compare/v0.0.76...v0.0.77) - 2026-08-14

### Added

- *(policy)* declare the verdict shapes, and shrink run-shape-guard to two
- *(hook)* [**breaking**] a pipeline kind — deny a verdict the structure throws away
- *(waiver)* resolve a waiver's liveness at the mediation boundary
- *(config)* [**breaking**] an absent batten.toml is the default layer, not an error
- *(receipt)* [**breaking**] honour a branch-keyed receipt, and let a row fire on a write

### Fixed

- *(hook)* add the pipeline kind's corpus fixture, and drop the banned word
- *(config)* give the default rule the pipeline kind's two columns

### Other

- *(lint)* borrow the path, forward the method, and allow expect in tests

## [0.0.76](https://github.com/button-inc/batten/compare/v0.0.75...v0.0.76) - 2026-08-14

### Added

- *(baseline)* record the findings that already exist, so only new ones fail
- *(policy)* declare the five unported write shapes, and delete memory-guard
- *(verbs)* [**breaking**] let a row narrow to a destination, a flag, or a subcommand

### Other

- *(baseline)* keep the store resolution off check's hot path
- *(baseline)* stop the module header naming the tokens its own gate forbids
- *(baseline)* lift the check-time filter out of run_rules

## [0.0.75](https://github.com/button-inc/batten/compare/v0.0.74...v0.0.75) - 2026-08-14

### Added

- *(lint)* report a waiver over a rule kind it cannot reach
- *(waiver)* name the rule kinds a waiver cannot reach

### Other

- *(lint)* pass the method itself where the closure only forwards

## [0.0.74](https://github.com/button-inc/batten/compare/v0.0.73...v0.0.74) - 2026-08-14

### Added

- *(drain)* withhold a flapping identity's repeats, and nothing else
- *(store)* [**breaking**] journal enforce-surface scans, and give the secret key rotation and loss custody

### Other

- *(store)* drive the enforce-surface journal and key custody over the binary
- *(store)* pin the journal, custody and emission-policy laws in-module

## [0.0.73](https://github.com/button-inc/batten/compare/v0.0.72...v0.0.73) - 2026-08-14

### Added

- *(hook)* [**breaking**] make the host capability axis data, and declare per-host attribution rows

### Fixed

- *(test)* write the fixture's git identity into the repo, not through `-c`

## [0.0.72](https://github.com/button-inc/batten/compare/v0.0.71...v0.0.72) - 2026-08-14

### Added

- *(hook)* derive per-harness hook wiring, and gate the committed copy against it
- *(drain)* [**breaking**] answer an unchanged cycle with a marker, and never skip its record
- *(drain)* [**breaking**] bound the advisory payload by a per-rule cap and a token budget

### Fixed

- *(state)* key the out-of-tree state root on the checkout, not its directory name
- *(release)* publish the override schema, and gate the drift glob it moved
- *(exec)* record the decision on an output match's exit code, and drop the rough edge

### Other

- *(pointer-only)* classify `payload field`, whose answer IS the payload
- *(hooks)* [**breaking**] register the surviving hooks by path, and pay for it with a gate

## [0.0.71](https://github.com/button-inc/batten/compare/v0.0.70...v0.0.71) - 2026-08-14

### Added

- *(rules)* [**breaking**] add the `secrets` rule kind and its pointer-only adapter
- *(receipt)* record what was acting, bounded by what it cannot see
- *(transcript)* type the agent's own composition
- *(receipt)* [**breaking**] bind the governing surface, not only the policy

### Fixed

- *(test)* make batten.toml an input of the step whose tests read it
- *(resolve)* drop the expect whose lint exemption cited a test that never existed
- *(test)* build the stub's token without a format! iterator chain

### Other

- *(perf)* [**breaking**] move the latency family into the perf namespace and gate it in CI
- *(secrets)* prove the containment claim end to end over the compiled binary

## [0.0.70](https://github.com/button-inc/batten/compare/v0.0.69...v0.0.70) - 2026-08-14

### Added

- *(bypass)* flag a refused operation retried with enforcement off
- *(provision)* [**breaking**] pin one artifact per platform, and resolve the binary's path
- *(completion)* flag a session that signalled done with work not landed
- *(identity)* [**breaking**] route secret spans to the keyed path by type, and mint the key

### Fixed

- *(completion)* land the rebased fixture behind a moved trunk

## [0.0.69](https://github.com/button-inc/batten/compare/v0.0.68...v0.0.69) - 2026-08-13

### Added

- *(attribution)* [**breaking**] refuse vendor authorship, branding and session links on produced commits
- *(action)* assert every exit code the Action can return, not just the one that means yes

### Fixed

- *(identity)* correct four claims the last correction got wrong

## [0.0.68](https://github.com/button-inc/batten/compare/v0.0.67...v0.0.68) - 2026-08-13

### Added

- *(init)* scaffold a starter batten.toml, refusing to overwrite one

## [0.0.67](https://github.com/button-inc/batten/compare/v0.0.66...v0.0.67) - 2026-08-13

### Fixed

- *(tests)* ask git whether the reference is committed, not the filesystem

## [0.0.66](https://github.com/button-inc/batten/compare/v0.0.65...v0.0.66) - 2026-08-13

### Added

- *(rules)* [**breaking**] wrap the walker in ignore + globset, and anchor a run at the repo root

## [0.0.65](https://github.com/button-inc/batten/compare/v0.0.64...v0.0.65) - 2026-08-13

### Added

- *(hook)* [**breaking**] refuse to end a turn whose work is not finished
- *(generate)* derive man pages and a markdown reference from the command surface
- *(hook)* [**breaking**] let a repository attach its own side effects to hook events

### Fixed

- *(man)* reset the version on the cloned node, not merely leave it unset
- *(cli)* append the new generate variants rather than inserting them
- *(man)* make a committed page a pure function of the surface, not of the version
- *(tests)* stop the suites depending on GNU tools and on git's default branch

### Other

- *(pointer-only)* classify the two new generate verbs
- *(spec)* admit the two new derivations to the pinned row set and allowlist
- *(generate)* gate the man pages and the reference the way the completions are gated
- *(cli)* run the portability rows under enforce, like every committed-config sibling

## [0.0.64](https://github.com/button-inc/batten/compare/v0.0.63...v0.0.64) - 2026-08-13

### Added

- *(drain)* [**breaking**] refuse to emit a finding the agent cannot close
- *(drain)* wake the advisory drain once per batch, not once per verifier
- *(config)* delegate the shipped conflict-marker rule to hk's own checker

### Fixed

- *(pointer-only)* namespace the sweep's fixtures away from the hand-written ones
- *(pointer-only)* drop a format! that interpolates nothing
- *(drain)* a suppression the record already carries is not news

### Other

- *(pointer-only)* classify `worktree reclaim`, and run it dry
- *(pointer-only)* say "vouched for itself" where the gate reads a consumer name
- *(pointer-only)* classify `design audit`, the sharpest content case yet
- *(pointer-only)* follow the command kind's `run` column to `check`
- *(pointer-only)* classify `lint brief`, the first verb the census caught
- *(pointer-only)* make a canary's provenance a field, not a trailing comment
- *(pointer-only)* state the law where a consumer writes a check, and name its gate
- *(pointer-only)* decide rule 4 over every leaf verb, not one adapter
- *(drain)* the batch event exists on one host — say so, and name what still holds
- *(drain)* assert the state-file key is hex, not merely the right length
- *(drain)* state the failure posture the code actually has
- *(drain)* apply the tree's fixers, and fold the ladder run into one helper

## [0.0.63](https://github.com/button-inc/batten/compare/v0.0.62...v0.0.63) - 2026-08-13

### Added

- *(worktree)* [**breaking**] count the dirty unreapable pileup, and give it a way down
- *(decision)* define the guard-decision telemetry record and its append-only store

## [0.0.62](https://github.com/button-inc/batten/compare/v0.0.61...v0.0.62) - 2026-08-12

### Added

- *(bench)* measure and gate the path that is actually wired
- *(judge)* add the advisory-only judge rule kind, unable to block by type
- *(hook)* gate a mediated call on a receipt, retiring ready-guard's predicate
- *(hook)* adjudicate write tools, so the write matcher stops being unjudged
- *(findings)* settle a finding with a check, and never clear one nothing looked at
- *(design)* audit a design-evidence claim stream for record integrity
- *(install)* ship a single-binary-first install path with a verified download
- *(action)* ship a GitHub Action whose empty `with:` block is the whole configuration
- *(refusal)* one refusal type, so no deny can ship a bare "no"
- *(config)* gate the predecessor consumer's repo name
- *(rules)* [**breaking**] rename the command kind's `run` column to `check`, reserve `fix`
- *(lint)* gate a delegation brief on the facts that do not inherit
- *(bench)* measure the invocation cost, publish it, and gate it
- *(state)* record where a session left the journal
- *(session)* give a warm fork somewhere to resume from
- *(spec)* emit the derived read-only allowlist beside the tree
- *(rules)* give forbid a regex alternative and an exclude column
- *(config)* give the override layer its own type, schema, and honoured keys
- *(epoch)* cache the config epoch and revalidate it stat-style
- *(budget)* count Serena's always-given prompt against the instruction set
- *(budget)* count a string embedded in a host's config file
- *(check)* emit a finding's identity on the -J channel
- *(selfwrite)* flag a memory write in a turn no user message opened

### Fixed

- *(hook)* [**breaking**] resolve receipts for the command, not for the whole policy
- *(rules)* reconcile the judge kind with the receipt kind after the rebase
- *(rules)* [**breaking**] make severity a per-kind column, so a judge row can omit it
- *(rules)* stop the tree walk at a nested repository, so both halves of a ratchet select the same set
- *(lint)* add the lint rows to the two committed surface lists, and fix the census's clippy denial
- *(bench)* keep the workflow's summary block off shellcheck's SC2016
- *(budget)* give the validate fixture the new embedded field
- *(spec)* pin the four surface rows house-style §2 disagreed with

### Other

- *(fuzz)* fuzz the hook envelope and the config parsers, and gate the corpus on every landing
- *(rules)* keep the census arm a one-liner, so clippy and rustfmt agree
- *(judge)* rustfmt the module, the kind and their suites
- *(judge)* satisfy the workspace lints on the new module and its suite
- *(rules)* classify the judge kind's two required columns in the pairing census
- *(judge)* drive every acceptance bullet through the compiled binary
- *(submodule)* rustfmt the new acceptance fixture
- *(design)* rustfmt the module and its suite
- *(design)* drive every acceptance bullet through the compiled binary
- *(markers)* assert the permission drop landed, and audit every site that needs one
- *(readme)* lead with the completion gate, not the policy-engine category
- *(deps)* drop dev-dependencies that duplicate the normal ones
- *(resolve)* mark §5's max_effect as specified, not implemented
- *(session)* compare the whole store across a restart, not a subset
- *(session)* pin what a warm fork must keep
- *(findings)* hold the no-escalation law over the bytes, not over a struct
- *(resolve)* carry the layered tables and path sets as values
- *(budget)* seed the committed budget's surfaces in the config fixtures
- *(config)* the epoch dispatch comment claimed exit 3 too
- widen the gate bar from computable to deciding
- *(store)* state the store id's construction, not a disagreement with the spec

## [0.0.61](https://github.com/button-inc/batten/compare/v0.0.60...v0.0.61) - 2026-08-11

### Added

- *(defects)* append-only defect ledger with a check-enforced gate
- *(rules)* let a count move only one way, and catch the tree that emptied

### Fixed

- *(defects)* satisfy the output-contract census and the items-after-statements lint
- *(ci)* supply the ratchet base the runner does not fetch, and isolate the fixtures that read it

### Other

- apply rustfmt to the defect-ledger module and its suite
- *(spec)* admit `defects query` to the derived read-only allowlist

## [0.0.60](https://github.com/button-inc/batten/compare/v0.0.59...v0.0.60) - 2026-08-11

### Added

- *(ci)* derive the merge contract from the host, and gate the copy against it
- *(hook)* make a host's event set a declared capability, not an assumption
- *(hook)* speak five hosts' payloads into one envelope
- *(judge)* refuse the invocation a protected span appears in, and cap what crosses
- *(budget)* name a budget set after its consumer, and make check enforce it
- *(journal)* fold shards under an advisory lock, and never upgrade a store implicitly
- *(findings)* give a finding a disposition that merges without adjudication
- *(transcript)* read a completed session transcript as an optional check input
- *(provision)* pin, verify, and cache tools out of tree

### Fixed

- *(worktree)* report the facts it can compute when the target resolves to nothing
- *(identity)* stop the keyed path claiming a guarantee it does not give

### Other

- *(fixtures)* format the host-payload README
- *(config)* rename the budget key in the every-key fixture
- *(worktree)* backtick DoD so the doc lint passes
- *(journal)* let the merged-log read say it cannot fail

## [0.0.59](https://github.com/button-inc/batten/compare/v0.0.58...v0.0.59) - 2026-08-11

### Added

- *(findings)* mint a finding's identity in the engine, and hold it per ref

## [0.0.58](https://github.com/button-inc/batten/compare/v0.0.57...v0.0.58) - 2026-08-11

### Added

- *(judge)* govern what may be sent to a model, before the judge exists

## [0.0.57](https://github.com/button-inc/batten/compare/v0.0.56...v0.0.57) - 2026-08-11

### Added

- *(store)* identify a findings store by a minted id, never by where it sits

### Fixed

- *(store)* observe the repository where it is now, not where it was recorded

### Other

- *(git)* write the empty-listing fallbacks as let...else

## [0.0.56](https://github.com/button-inc/batten/compare/v0.0.55...v0.0.56) - 2026-08-11

### Added

- *(worktree)* detect at-risk work by content, never by ancestry

## [0.0.55](https://github.com/button-inc/batten/compare/v0.0.54...v0.0.55) - 2026-08-11

### Added

- *(policy)* gate the always-loaded context from the engine, not a shell task

## [0.0.54](https://github.com/button-inc/batten/compare/v0.0.53...v0.0.54) - 2026-08-11

### Added

- *(identity)* key secret-class identity, and make an override split-only

## [0.0.53](https://github.com/button-inc/batten/compare/v0.0.52...v0.0.53) - 2026-08-11

### Added

- *(hook)* dispatch on the normalized event, and widen the envelope to carry it

## [0.0.52](https://github.com/button-inc/batten/compare/v0.0.51...v0.0.52) - 2026-08-11

### Other

- *(identity)* drive the identity-churn pack from real tree edits

## [0.0.51](https://github.com/button-inc/batten/compare/v0.0.50...v0.0.51) - 2026-08-10

### Added

- *(waiver)* add per-rule waivers that lapse on their own date

## [0.0.50](https://github.com/button-inc/batten/compare/v0.0.49...v0.0.50) - 2026-08-10

### Other

- *(readme)* document the three extension surfaces, with executed examples

## [0.0.49](https://github.com/button-inc/batten/compare/v0.0.48...v0.0.49) - 2026-08-10

### Added

- *(outputs)* promote a wrapped command's lying exit 0 to a failure

## [0.0.48](https://github.com/button-inc/batten/compare/v0.0.47...v0.0.48) - 2026-08-10

### Added

- *(capture)* tee `exec` output to a content-addressed out-of-tree store

## [0.0.47](https://github.com/button-inc/batten/compare/v0.0.46...v0.0.47) - 2026-08-10

### Added

- *(exec)* add the transparent passthrough verb the surface always declared

## [0.0.46](https://github.com/button-inc/batten/compare/v0.0.45...v0.0.46) - 2026-08-10

### Other

- *(cli)* derive the machine-output contract from the data_channel column

## [0.0.45](https://github.com/button-inc/batten/compare/v0.0.44...v0.0.45) - 2026-08-10

### Added

- *(cli)* add the standard flag ladder and the attended/unattended layer

## [0.0.44](https://github.com/button-inc/batten/compare/v0.0.43...v0.0.44) - 2026-08-10

### Added

- *(hook)* deny a mutating verb against a protected path, and name the mutation

## [0.0.43](https://github.com/button-inc/batten/compare/v0.0.42...v0.0.43) - 2026-08-09

### Added

- *(hook)* adjudicate mediated calls from a declarative rule table

## [0.0.42](https://github.com/button-inc/batten/compare/v0.0.41...v0.0.42) - 2026-08-09

### Fixed

- *(hook)* parse quoted spans into words instead of a sentinel

## [0.0.41](https://github.com/button-inc/batten/compare/v0.0.40...v0.0.41) - 2026-08-09

### Other

- *(hook)* pin the decision channel per harness with a fixture matrix

## [0.0.40](https://github.com/button-inc/batten/compare/v0.0.39...v0.0.40) - 2026-08-09

### Added

- *(config)* attribute every emitted config key, and put the full table behind --json

## [0.0.39](https://github.com/button-inc/batten/compare/v0.0.38...v0.0.39) - 2026-08-09

### Other

- *(corpus)* translate the predecessor acceptance corpus into a de-identified rule fixture

## [0.0.38](https://github.com/button-inc/batten/compare/v0.0.37...v0.0.38) - 2026-08-09

### Added

- *(gate)* discover a fixture-repo corpus, and collapse nine copies of the materializer

## [0.0.37](https://github.com/button-inc/batten/compare/v0.0.36...v0.0.37) - 2026-08-09

### Added

- *(rules)* re-run rule 1's grep on every gate, not once by hand

## [0.0.36](https://github.com/button-inc/batten/compare/v0.0.35...v0.0.36) - 2026-08-08

### Fixed

- *(config)* validate the marker table at load, and gate the class that hid it

## [0.0.35](https://github.com/button-inc/batten/compare/v0.0.34...v0.0.35) - 2026-08-08

### Fixed

- *(config)* validate the verb table at load, where nothing validated it at all
- *(markers)* tell "not UTF-8" apart from "cannot be read", as the contract says

## [0.0.34](https://github.com/button-inc/batten/compare/v0.0.33...v0.0.34) - 2026-08-08

### Fixed

- *(check)* an unreadable working authority is the maximal weakening, not an abort
- *(lint)* keep the key trust located a weakening by, so dedup cannot swallow one

## [0.0.33](https://github.com/button-inc/batten/compare/v0.0.32...v0.0.33) - 2026-08-08

### Added

- *(config)* hash the governing config surface into a config_epoch (CLOUD-32)

## [0.0.32](https://github.com/button-inc/batten/compare/v0.0.31...v0.0.32) - 2026-08-08

### Other

- *(fail-on-warning)* start each fixture from an empty directory

## [0.0.31](https://github.com/button-inc/batten/compare/v0.0.30...v0.0.31) - 2026-08-08

### Added

- *(doctor)* add the post-install self-check and render the exit table (CLOUD-66)

## [0.0.30](https://github.com/button-inc/batten/compare/v0.0.29...v0.0.30) - 2026-08-08

### Added

- *(config)* publish the two new tables in the JSON Schema
- *(tables)* count suppression markers and type mutating verbs, from config
- *(git)* decide merged-ness by patch identity, never by reachability

### Other

- *(git)* pin what cumulative evidence claims, and the fast-forward shape

## [0.0.29](https://github.com/button-inc/batten/compare/v0.0.28...v0.0.29) - 2026-08-08

### Added

- *(config)* name policy smells with `batten config lint` (CLOUD-87)

## [0.0.28](https://github.com/button-inc/batten/compare/v0.0.27...v0.0.28) - 2026-08-08

### Added

- *(config)* judge by a trusted base ref with --config-from (CLOUD-31)

## [0.0.27](https://github.com/button-inc/batten/compare/v0.0.26...v0.0.27) - 2026-08-08

### Added

- *(config)* derive and publish the batten.toml JSON Schema, gate min_batten_version (CLOUD-33)

## [0.0.26](https://github.com/button-inc/batten/compare/v0.0.25...v0.0.26) - 2026-08-08

### Added

- *(cli)* declare the command surface once, as data (CLOUD-27)

## [0.0.25](https://github.com/button-inc/batten/compare/v0.0.24...v0.0.25) - 2026-08-08

### Added

- *(check)* promote warn findings with one resolved fail_on_warning setting

### Other

- *(resolve)* lift the env and flag layer lookups out of the resolver

## [0.0.24](https://github.com/button-inc/batten/compare/v0.0.23...v0.0.24) - 2026-08-08

### Added

- *(rules)* three independent config-driven path sets

## [0.0.23](https://github.com/button-inc/batten/compare/v0.0.22...v0.0.23) - 2026-08-08

### Added

- [**breaking**] one exit table — 2 is the policy verdict, so hook has nothing to invert

### Other

- keep the always-loaded exit-contract rule inside the context budget

## [0.0.22](https://github.com/button-inc/batten/compare/v0.0.21...v0.0.22) - 2026-08-08

### Added

- *(git)* resolve the repo root via the common-dir finder

### Fixed

- *(receipt)* derive the state dir from the common-dir root, not the worktree

## [0.0.21](https://github.com/button-inc/batten/compare/v0.0.20...v0.0.21) - 2026-08-08

### Other

- *(readme)* claim the surveyed property, not the falsified one

## [0.0.20](https://github.com/button-inc/batten/compare/v0.0.19...v0.0.20) - 2026-08-07

### Added

- *(receipt)* SHA-keyed verification receipts, written and judged by the binary

## [0.0.19](https://github.com/button-inc/batten/compare/v0.0.18...v0.0.19) - 2026-08-07

### Added

- *(rules)* adopt cargo-deny's severity model — deny/warn/allow per rule

## [0.0.18](https://github.com/button-inc/batten/compare/v0.0.17...v0.0.18) - 2026-08-07

### Other

- *(scope)* a boundary that survives the roadmap, and the misuse cost named

## [0.0.17](https://github.com/button-inc/batten/compare/v0.0.16...v0.0.17) - 2026-08-07

### Added

- *(hook)* the adjudicator's first slice — envelope, parser, gh policy

## [0.0.16](https://github.com/button-inc/batten/compare/v0.0.15...v0.0.16) - 2026-08-07

### Added

- *(gate)* wire consumer #1 — batten check runs against its own repository

### Fixed

- *(cli)* bare invocation lists subcommands instead of exiting silently

### Other

- *(graph)* one authority per fact across the agent-facing doc graph
- *(contract)* the public contract states what ships, and plans the rest

## [0.0.15](https://github.com/button-inc/batten/compare/v0.0.14...v0.0.15) - 2026-08-07

### Added

- *(severity)* map the three severity axes through one rank table

## [0.0.14](https://github.com/button-inc/batten/compare/v0.0.13...v0.0.14) - 2026-08-07

### Fixed

- *(config)* treat an empty env override as unset and refuse authority-only local keys

## [0.0.13](https://github.com/button-inc/batten/compare/v0.0.12...v0.0.13) - 2026-08-07

### Other

- *(hooks)* format and validate every config format in the gate

## [0.0.12](https://github.com/button-inc/batten/compare/v0.0.11...v0.0.12) - 2026-08-07

### Other

- *(config)* drop the unread raise_only flag from SETTINGS

## [0.0.11](https://github.com/button-inc/batten/compare/v0.0.10...v0.0.11) - 2026-08-07

### Added

- *(config)* resolve batten.toml layers with a raise-only clamp

## [0.0.10](https://github.com/button-inc/batten/compare/v0.0.9...v0.0.10) - 2026-08-07

### Added

- *(identity)* add the finding-identity fingerprint kernel (CLOUD-123)

## [0.0.9](https://github.com/button-inc/batten/compare/v0.0.8...v0.0.9) - 2026-08-07

### Added

- *(rules)* add a command rule kind for dynamic checks

## [0.0.8](https://github.com/button-inc/batten/compare/v0.0.7...v0.0.8) - 2026-08-07

### Added

- *(check)* split process-spawning rules onto a non-read verb

## [0.0.7](https://github.com/button-inc/batten/compare/v0.0.6...v0.0.7) - 2026-08-07

### Other

- update Cargo.toml dependencies

## [0.0.6](https://github.com/button-inc/batten/compare/v0.0.5...v0.0.6) - 2026-08-06

### Other

- *(deps)* auto-land Dependabot PRs on green CI

## [0.0.5](https://github.com/button-inc/batten/compare/v0.0.4...v0.0.5) - 2026-08-06

### Added

- *(check)* add rule and check engine with a static forbid kind
- *(state)* derive the out-of-tree state path from the repo name

### Other

- *(check)* derive unit-test scratch dir at runtime
- *(exit)* assert the exit-code contract as a table

## [0.0.4](https://github.com/button-inc/batten/compare/v0.0.3...v0.0.4) - 2026-08-06

### Added

- *(config)* add the batten.toml loader and `config show`

## [0.0.3](https://github.com/button-inc/batten/compare/v0.0.2...v0.0.3) - 2026-08-06

### Added

- *(cli)* emit the command surface as data via `batten spec`

## [0.0.2](https://github.com/button-inc/batten/compare/v0.0.1...v0.0.2) - 2026-08-06

### Fixed

- *(exit)* set internal-error exit code to 3

### Other

- relicense Batten to Apache-2.0 only

## [0.0.1](https://github.com/button-inc/batten/compare/v0.0.0...v0.0.1) - 2026-08-06

### Fixed

- tie exit-code fallback to Internal instead of a bare literal

### Other

- release v0.0.0

## [0.0.0](https://github.com/button-inc/batten/releases/tag/v0.0.0) - 2026-08-05

### Other

- scaffold Batten repo-agnostic policy engine
