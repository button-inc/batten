# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.217](https://github.com/button-inc/batten/compare/v0.0.216...v0.0.217) - 2026-10-24

### Added

- *(mutate)* [**breaking**] the changed diff's mutants run at admission, cargo-mutants included, sharded in CI
- *(preset)* [**breaking**] refuse a session's first plan once, with the operator's correction
- *(hook)* [**breaking**] refuse an interpreter running a script outside the repository
- *(engine)* [**breaking**] tell a consumer its pin is behind, and move every copy with it
- *(doctor)* count what plan mode refused, by program
- *(red-head)* [**breaking**] a push may not supersede a red head whose failed checks are unread
- *(dist)* Chocolatey and nix channels, and the channel test (CLOUD-2298)
- *(dist)* release and prove the package channels (CLOUD-2298)
- *(dist)* generate the Homebrew, MSI, npm, deb, rpm and apk channels (CLOUD-2298)
- *(dist)* cargo-dist builds each release leg and generates the installers (CLOUD-2297)
- *(rules)* the reset, singleton and history gates are native rows
- *(engine)* [**breaking**] engine install follows the pin; install.sh bakes the latest release
- *(ready)* a feat row's claims carry the prior-art search it ran
- *(mint)* a mint keys from the call's input, held to a declared shape; no row is born in Todo
- *(land)* readying owes simplify and both reviews, on both ready routes
- *(preset)* except a preset's modules and eject them into policy/
- *(trunk-based)* [**breaking**] refuse a merge at the call and hold land linear to the trunk's ruleset
- *(mutate)* a row seen caught is not run again until its inputs change
- *(mutate)* the sweep prints its row count and each row's verdict and time
- *(policy)* a turn that defers work names the row holding it
- *(collect)* every compile unit passes the disk collector, as RUSTC_WRAPPER
- *(disk)* one watcher spans the run; the prune floor model retires
- *(release)* [**breaking**] main pins only a published, immutable, verified release
- *(land)* collect toward max_free_mb in the lap and the sweep
- *(hook)* collect disk before admitting under the declared band
- *(collect)* collect superseded, then least-recently-used, cargo units under disk pressure
- *(o200k)* the pre-tokenizer as a build-time DFA, read in place
- *(o200k)* the o200k vocabulary as a compile-time table in every binary
- *(capture)* a streamed store and a streaming hook-input reader
- *(capture)* store every tool result, and bound what the model reads in o200k tokens
- *(mutate)* a command runner, its argv committed and its exit the contract
- *(hook)* judge by the session repo, register its root, point at views
- *(mutate)* [**breaking**] one runner registry, the declared runner and cargo-mutants registered beside it (WIP)
- *(refusal)* every line a pointer the legend resolves — routes, subjects and heads where they were missing
- *(refusal)* remedy lines are headed remedy, the legend is one sentence, the drain speaks its rule's own word
- *(refusal)* one finding format for check, waiver and repair lines
- *(refusal)* [**breaking**] batten <severity> <class> heads every finding, and the repeat keeps its routes
- *(refusal)* [**breaking**] a repeat is the address, and a finding names its gate once
- *(drain)* a per-rule delta small by shape, the budget a relief valve
- *(drain)* cut the response at the token budget and journal the cut
- *(refusal)* class every agent-facing emitter through the finding grammar
- *(verdict)* every live class carries its interaction doc, and none may land without one
- *(config)* a rule's reason is a remedy of at most 240 characters, and 188 rows carry docs
- *(history)* one --history call walks the authority once and prints a shared commit once
- *(verdict)* every vendored class carries its interaction doc
- *(verdict)* a first sighting carries the class's doc, and a config row needs its history read before it changes
- *(preset)* a backgrounded call that names no timeout runs with the host's maximum
- *(policy)* [**breaking**] one explain resolves every name a finding prints, and the line names it once
- *(mint)* [**breaking**] mint the review receipt on completion, and let land ask for it

### Fixed

- *(test)* a receipt's mtime may trail its stamp by the coarse clock's second
- *(mutants)* an empty piece counts the rest whole, a sweep case writes only its scratch build
- *(lock)* judge the staged mise.lock, not a checkout a CI job may write
- *(mutate)* no sweep on the failed wait, whose one reachable failure is ECHILD
- *(mutate)* keep the sweep off a failed wait whose leader was reaped elsewhere
- *(mutate)* sweep a failed wait's group whatever the failure
- *(mutate)* no sweep after a failed wait that says the leader was reaped
- *(mutate)* sweep the failed wait's exit too, since only the final wait reaps
- *(mutate)* no repeat kill where a failed wait leaves the group id unreserved
- *(mutate)* sweep before the leader is reaped, on both of the wait's exits
- *(mutate)* sweep a suite's group until it no longer answers
- *(git)* /code-review — no memo work outside a hook call, every write opens fresh, and the common config and nested scope are gated
- *(git)* /code-review — a write opens fresh, the hit path is tested, and a nested scope keeps the outer memo
- *(git)* scope the repository-open memo to one hook call, so a long-lived process never reads a shared snapshot stale
- *(git)* believe a remembered open by its config files' bytes, so a first call's cost does not depend on the clock
- *(release)* [**breaking**] retire release settings --probe with the ruleset it proved
- *(mutate)* carry the hunk-header row at column 0, where mutate reads it
- *(mutate)* group the in-diff hunks with chunk_by and pin the grouping
- *(mutate)* write the in-diff hunks from the ranges they print
- *(release)* owe no release-path ruleset, so the guard can go green
- *(ci)* map the refusal of every wrapped release verb, and simplify
- *(perf)* accept identical arms when the head was built clean
- *(provision)* install the locked toolchain with no attestation read
- *(ci)* map the release gate's not-green exit 2, not 1
- *(tokens)* name each arm's own byte-stability in the not-measured line
- *(policy)* state what a step is, instead of excluding one shape at a time
- *(policy)* an empty string is not a step, so arm E stops accusing one
- *(policy)* arm E accused a manifest whose fetch task yields no step
- *(toolchain)* the fix-selection gate resolves the package too, so it fetches first
- *(policy)* arm E counted the union, so a floating fragment stayed clean
- *(policy)* arm A2 was masking arm A, and arm D had no "names none"
- *(policy)* keep arm B's reach, and never commit a source engine pin
- *(policy)* read the tag half of hk.pkl's URL too, and spell the CA selection once
- *(policy)* read both halves of the fetch URL, and factor what the tiers repeat
- *(toolchain)* fetch the pkl package before the validator runs
- *(verdict)* token_enum! refuses a duplicate token at compile time
- *(capture)* call the keeping seam directly, so no wrapper's count goes unread
- *(capture)* a call never evicts the response it just stored
- keep the network wrappers' bodies and the lint inventory as main has them
- *(mutate)* the MUTANT-SUITE line after the profile row is its own line again
- *(mutate)* the profile pin's comments claim only what it does, and a unit case asserts it
- *(mutate)* the sweep runs nextest's default profile again, never the caller's
- *(mutate)* keep an inherited nextest profile the staged tree declares, else default
- *(mutate)* the sweep's Cargo arm runs nextest's default profile, whatever the caller selected
- *(mutate)* a nextest result line counts only when it names a case; TERMINAL's doc says what mutate adds
- *(replay)* every attempt decides replay; only the mutate count dedupes cases
- *(replay)* a retried case's result is read, and counted once
- *(replay)* a result line's status word is its first, and the case count stops at the summary
- *(mutate)* kill_group keeps the direct group signal suite-reap-leader-only mutates
- *(mutate)* /code-review — nextest's LEAK and retried lines count, both shard numbers come from strategy
- *(mutate)* the pinned cargo-mutants is applied for every registered runner
- *(mutate)* declared Cargo rows run under nextest, and a timed-out runner is asked before it is killed
- *(engine)* engine update leaves a digest the gate accepts
- *(engine)* /code-review round 3 of CLOUD-2418
- *(engine)* stamp-trusted-when-absent targets check's source arm again
- *(engine)* /code-review of CLOUD-2418 after the rebase
- *(policy)* /security-review of CLOUD-2418 — every spelling of git grep's pager
- *(engine)* source-pin-admitted targets the gate's source arm again
- *(engine)* /code-review of CLOUD-2418
- *(policy)* /security-review of CLOUD-2418 — a git read form never writes
- *(engine)* /simplify over CLOUD-2418 — git's program-running options are never reads
- *(engine)* close the findings CLOUD-2279 left, and read git's global options
- *(land)* name no consumer in the CLOUD-2189 case (CLOUD-2189)
- *(land)* a dead end is confirmed only by the masked names' own new runs (CLOUD-2189)
- *(claim-race)* a body closing an unrelated key settles nothing, so read its commits
- *(claim-race)* a speculative lap judges this branch on its own commits
- *(claim-race)* an unconfirmed collision refuses and says so, rather than declining
- *(claim-race)* a competitor whose body closes the key is settled, not distrusted
- *(claim-race)* decline the unconfirmed race, not the confirmed one beside it
- *(claim-race)* a race nobody could confirm is not a refusal, and two arms owed a case
- *(claim-race)* a competitor that could refuse this branch is worth the round trip
- *(claim-race)* the guard asks its question once, above the match
- *(claim-race)* a claim set short of its own commits cannot report a clean board
- *(claim-race)* a closing body answers without the log, so only a silent one is could-not-look
- *(claim-race)* the branch's own log read owes the same `.ok()` as the competitors'
- *(claim-race)* a read that failed is not a competitor that claims nothing
- *(claim-race)* judge before declining to judge, and price the fan-out on a reproduced count
- *(claim-race)* an unanswered competitor exits Internal, not clean
- *(claim-race)* a fill that lost a worker is could-not-look, not a verdict
- *(claim-race)* a panicked worker costs one fetch, and the skip names the source it is unsound for
- *(closes)* a cleared body and a created body are closing sets too
- *(closes)* one reading of pr-closes, and an edited body is recorded
- *(ci)* name the mise action by its own name, not its owner's (CLOUD-2388)
- *(ci)* the suite census reads every --rule, argv checks and mise's value flags (CLOUD-2388)
- *(ci)* a pinned tool spawned by name is refused; node and jq are required where cases reach them (CLOUD-2388)
- *(ci)* batten enforce runs the rules' checks, and batten-check installs cargo-dist (CLOUD-2388)
- *(ci)* batten test replay and land lap run cases; one reading of mise run's flags (CLOUD-2388)
- *(ci)* the suite gate reads templates, flag values, here-docs and resolver bodies (CLOUD-2388)
- *(ci)* the suite gate reads cargo, mise, hk and scripts as their CLIs do (CLOUD-2388)
- *(ci)* the suite gate reads every resolving call and parses commands, not lines (CLOUD-2388)
- *(ci)* the suite-job gate reads require_tool calls, and cache-warm-musl installs pkl (CLOUD-2388)
- *(land)* a raced gate's cancel reads the group note where verify wrote it
- *(land)* the stall watches the registration this run made, never an unregistered pid
- *(land)* the entry reconcile defers to a live lease; the gate claims the race too; alive is a read
- *(land)* the stall arm wins once, before its cancel, and sees a same-second step
- *(land)* a gate that never reports is no evidence of a stall
- *(land)* a lap that never returned has its ready head's runs reconciled at the next entry
- *(land)* a verify whose task stops advancing cancels its gate and stops the landing
- *(task)* alive reads the registry and deletes nothing; the next land forgets the dead
- *(stop)* excuse only a backgrounded land, and re-arm the excuse with the rest
- *(stop)* earn the land excuse after the call, spend it only where it excuses
- *(stop)* excuse the Stop after a land is started, and sweep the new receipts
- *(stop)* judge the Stop refusal on this Stop's own verdict
- *(stop)* refuse the Stop after an ignored unlanded pointer while no land runs
- *(land)* a branch the lookup finds no pull request for still asks at push
- *(land)* a branch with no pull request buys no run, so its push owes nothing
- *(land)* only a push that buys a run owes its reviews
- *(land)* a ready pull request's push owes the reviews its ready did
- *(receipt)* a subject one row cannot read is could-not-look for that row alone
- *(hook)* leave an absolute path as sent; strip only a drive in the case
- *(hook)* resolve a rooted path without a drive at the boundary
- *(handler)* a tree_only row skips a rooted path, not only an absolute one
- *(hook)* follow a dangling link in relative_to's tail replay
- *(hook)* walk from the path itself so relative_to stays at its canonicalize ceiling
- *(hook)* canonicalize a tail component that resolves after a `..`
- *(hook)* resolve a tail `..` against the canonical base, not lexically
- *(hook)* resolve `..` before relativising a path through a missing directory
- *(handler)* keep dispatch's six-argument form and add dispatch_writing
- *(preset)* enroll claude-code-plan where every shipped preset is named
- *(preset)* [**breaking**] ship the first-plan refusal as its own preset, claude-code-plan
- *(preset)* give the plan-mode row a neutral id and the new class its doc
- *(handler)* [**breaking**] let a row except the paths that are not its subject
- *(hook)* attached values, --opt=value and versioned interpreters read right
- *(hook)* a bundle's valued option and trailing inline options read right
- *(hook)* read each interpreter family's own option grammar
- *(preset)* a Serena memory write is pre-approved outside plan mode
- *(mcp)* the connector guard applies a committed rule under the literal name too
- *(filed-here)* parse the trimmed line the filter measured, and pin both guards at load time
- *(filed-here)* a blocked fetch never outranks a measured one, and every guard has its mutant
- *(filed-here)* a measured nothing carries no key, and the unread filter has its mutant
- *(filed-here)* exempt only rows the newest measured PR body closes
- *(engine)* the update's failed install is the install's own error
- *(engine)* fifth /code-review of CLOUD-2279 — a failed install says the write stood
- *(engine)* fourth /code-review of CLOUD-2279 — an update never puts the pin back
- *(engine)* an update's doc says it rolls back, and a failed restore is said
- *(engine)* third /code-review of CLOUD-2279 — failures leave nothing half done
- *(engine)* second /code-review of CLOUD-2279 — the notice fails open
- *(engine)* /code-review of CLOUD-2279 — the gate's remedies clear it
- *(land)* keep a declined record while its group lives; refuse a member whose pid cannot be read
- *(land)* a group is an orphan only with its leader and registrant gone
- *(land)* the reaper's own group is excluded by number, not by spelling
- *(land)* date an abandoned group against its record instead of probing its leader
- *(land)* signal only leaderless groups when reaping abandoned tasks
- *(preset)* clamp the host maximum rather than max-then-min
- *(preset)* pin a backgrounded call to the host's real maximum, not two hours
- *(toolchain)* declare the program root once, so land's reap of abandoned groups runs
- *(preset)* plan mode reads the guide subagent, printenv and ps
- *(test)* session_drain's transcript cases state their platform with cfg!
- *(doctor)* the sessionless-template mutant row parses
- *(doctor)* a tail torn inside a character is still torn
- *(test)* the transcript fixtures are unix-only, like every test that reads them
- *(doctor)* a torn transcript tail never falls back to a zero
- *(doctor)* re-check the store after reading the transcript
- *(hook)* the TodoWrite mutant keeps hook.rs's other rows on their suites
- *(doctor)* every task call counts, and a relative link resolves against the link
- *(doctor)* only a hook denial unwrites a task call, and TodoWrite is a task tool
- *(doctor)* a half-written or refused task call never decides the zero
- *(doctor)* the transcript speaks only for its own session, over an absent store, from complete lines
- *(doctor)* an absent task store reads zero when the transcript shows no task call
- *(capture)* /code-review — an advisory overflow takes no row, and the grace is a minute
- *(capture)* /code-review — a fresh row-less record is not an orphan, and a part of a result is ranked, never selected
- *(capture)* every hook-side store records its row, and a row-less record is evicted first
- *(durable)* /code-review — the use mark is made in durable, the one place this crate mutates a file
- *(cache)* /code-review — touch through collect's open_handle, so a refresh moves the directory on Windows too; cover the refresh and the no-prune rule
- *(cache)* /code-review — the mark needs no hard link, refreshes the directory too, and touches read-only first
- *(cache)* mark a partition used through a file, so every platform ranks by last use
- *(doctor)* gaps prints no empty pointer and absorb keeps counted apart
- *(obligations-bound)* a newest unread fetch keeps the earlier reading
- *(obligations-bound)* judge only the newest PR-body fetch
- *(red-head)* the hand-driven `land push` owes the same read
- *(red-head)* the landing owes the same read, and a check with no job has its own
- /code-review of #1189 — the suite comment and CI bullet say only what holds
- /code-review of #1189 — restore what the neutral comment and the CI bullet dropped
- /code-review findings on #1189
- *(ci)* find suite jobs through mise's task graph and install cargo-dist for coverage (CLOUD-2381)
- *(ci)* mutant rows at column 0 and archiver_argv without Option<Option> (CLOUD-2381)
- *(dist)* zip the Windows archive with bsdtar on a Windows host (CLOUD-2297)
- *(dist)* refuse a stale lockfile and stale outputs before dist builds (CLOUD-2297)
- *(dist)* read dist's staging under the workspace target and widen the proof's paths (CLOUD-2298)
- *(dist)* keep the build-tool refusal's wording and name cargo-dist after it (CLOUD-2297)
- *(dist)* generate the MSI template before each dist build (CLOUD-2298)
- *(dist)* clear verify's refusals over the channel bundle (CLOUD-2298)
- *(dist)* meet the gates the release wiring tripped (CLOUD-2297)
- *(dist)* keep the dist API patch-compatible and lock cargo-dist (CLOUD-2297)
- /code-review — the eviction-order row targets its line, and the Windows rank is named exactly
- /code-review — the partition bound's docs say what it guarantees, and mutants pin it
- /code-review — the partition bound is one least-recently-used count
- /code-review of the partition bound, the answer memo and the epoch's state
- /code-review of the caches — a missing cache is a whole read, a partition in use is never the oldest
- address /code-review of this branch's caches and memos
- *(clippy)* name the cited-patterns parameter of check_loaded
- clear verify's refusals of this branch — a lint escape, a cfg-gated test, an unplaced module
- *(build)* link mimalloc on Linux glibc only
- *(clippy)* clear this branch's 15 lint refusals; hold the authority by reference in the parse memo
- *(mutate)* every Rust mutation row is three fields and changes its own source
- *(build)* link mimalloc on Linux only, without transparent huge pages
- *(cache)* put this branch's mutation rows where `mutate` reads them, and enforce them
- *(cache)* partition the cache directory by binary, so two binaries stop evicting each other
- *(exec)* a forwarder leaves the count before it stops answering signals
- *(land)* a signal unwinds only the tree the bet left
- *(land)* the signal unwind keeps its record when it cannot finish, and leaves a published bet to the lap
- *(hook)* a remedy names an action, never words in the turn
- *(land)* a terminating signal unwinds a live speculation
- *(hook)* the unlanded pointer speaks once per claim until the operator speaks
- *(ci)* the required fan-in can never be skipped, so a draft run no longer satisfies protect-main
- *(hook)* the strongest native row for a gate decides, and removing one lowers nothing
- *(hook)* a native gate with no row stays at deny
- *(rules)* the native kind has its README row and fixture, and the chain its budget
- *(mcp)* a failure record is its last field, and unix ledger cases skip nothing
- /code-review findings on the second simplification
- /code-review findings on the mutation-runner bundle
- *(mutate)* suite_for hands back a reference again; each row carries its resolved suite
- *(mutate)* the census refuses rows that cannot apply, and the dead rows are repaired
- *(mutate)* [**breaking**] judge each row under the MUTANT-SUITE above it, and sweep on every one
- *(mutate)* [**breaking**] the census refuses a row whose script changes nothing
- *(mcp)* spawn provisions a launch program PATH lacks; posture reads a failed exec
- *(surface)* engine install is reached now, by session:batten and deps-install
- *(release)* grade the land where it now runs, and the bake where it now ends
- *(exec)* the reaper KILLs and waits only a child not yet waited
- *(exec)* the reaper waits for the child it signalled
- *(mint)* a key_shape is judged as a rule's is, compiled and nothing more
- *(mint)* a padded key_shape loads; a stray one is told to go first
- *(mint)* a key_shape that narrows nothing or admits nothing is refused
- *(mint)* a blank key_shape is refused at load
- *(land)* an asked receipt stops the unattended lap; a verdict reads like commit_type
- *(land)* a fact in a receipt row withholds only itself from the lap
- prior art owed from a declared cutover; land asks receipts only when it readies
- *(preset)* preset eject's census row, class doc, pages and completions
- *(preset)* preset eject is declared unreached, and the golden schema carries it
- *(verify)* run perf-gate alone and last, after every other step has exited
- *(collect)* the singleton wait bound is spelled in minutes
- *(collect)* rank the staged copy and every build tree's scratch, and wait out batten's own background build
- *(preset)* ReadNotifications is a read in plan mode
- *(preset)* a batten mcp call whose method only reads is read-only in plan mode
- *(mutate)* touched() calls changed_by again, as before the rebase onto main
- *(land)* linear-check refuses a merge commit, and a resolution keeps its mode
- *(land)* a replay merges a `merge=union` path as the union of both sides
- *(collect)* keep the profiles a lap builds, take unreachable artifacts first
- *(land)* flatten a merge-carrying branch, never merge the trunk into it
- *(mutate)* the cargo-mutants globs own each crate's tests again
- *(mutate)* stream cargo-mutants' output as it is written
- *(mutate)* shard the change's mutants evenly, not each source's
- *(release)* verify reads the asset module's report as it is written
- *(collect)* count Windows hardlinks before calling a removal freed
- *(collect)* open trees and stamp times the way Windows allows
- *(land)* the red-head undo says what it did, not what will happen
- *(collect)* read macOS processes by name, as XNU allows
- *(replay)* a body that will not compile is charged to itself, never to the union
- *(mutate)* the sweep writes through durable; this branch's tests pass the tree gates
- *(policy)* the runner glob is split on its double star, not swapped for a sentinel
- *(engine)* a release pin is repaired by the release, never by a build
- *(test)* gate the state-home import with the Linux-only cases that use it
- *(hook)* the post-tool recorders read a spilled response, not its marker
- *(verify)* the lap's findings after the main merge
- *(install)* merge origin/main; the generated bootstrap installs the pin
- *(exec)* the branch adds no spawn escape the inventory does not already hold
- *(exec)* an error or an unwind never abandons the supervised child
- *(mutate)* a spawned step's outcome is one enum; a sed timeout is not the row's refusal
- *(mutate)* re-anchor the rows whose target line moved
- *(forge)* a pull request's state is parsed once, unknown never closed
- *(capture)* a held response is as old as its latest call row
- *(policy)* a descriptor duplication is not a file write
- *(release)* how a commit relates to main is one Relation from both producers
- *(verify)* clear the lap's own clippy, spelling and census findings
- *(collect)* the compiler is spawned through exec, the placed boundary
- *(collect)* cargo's lock roots compile inputs; the clock roots only what a run reads
- *(collect)* every `step run` build runs under the disk watcher
- *(collect)* the collector arms at its default band when none is declared
- *(pipeline)* a commit's status is a verdict a trailing line replaces
- *(policy)* the bytecode cache is hit on the live hook path
- *(release)* land on the released engine; the gate sees wrapped released calls
- *(hook)* spill at the result bound; handlers read the host's own bytes
- *(install)* stamp the installed engine, and test follow_pin on its own
- *(collect)* a live build is the root, never a 10-minute window
- *(engine)* the floor's repair replaces the stale copy; the hook hands off from its own root
- *(layering)* place this branch's eight modules; durable or marked writes
- *(collect)* name what held a pass back, and never rank scratch units
- *(collect)* each platform's own answer to "is this binary running"
- *(collect)* see running programs and file identity on every shipped target
- *(engine)* a test run uses the engine it built — BATTEN_ENGINE=local
- *(disk)* the collector reaches incremental caches and test scratch
- *(engine)* a branch's own build is the engine its source pin names
- *(release)* load the release-path modules and close the suite on CLOUD-2033
- name held roots, keep an unread wait's head, point at the gate's log
- five defects measured on this PR, each with its test and mutant
- *(recorder)* follow a backgrounded call to its output instead of recording its placeholder
- clear verify's five failures and restore the collector band
- *(collect)* index each profile's artifacts once, not once per unit
- *(handler)* pass the unit tests' payloads as handler::Payload
- *(prune)* take a basis-moving root only when its drop can reach the cold floor
- *(capture)* evict built-in tool results before tracker reads
- *(stop)* look a filed row's status up under the root the writer stored it
- *(semver)* balance the backticks in cause_line's doc
- *(prune)* read a profile without its build scripts as cold
- *(semver)* report the build's first error, not cargo's summary line
- *(engine)* tell a stale build of the checkout to rebuild, not update
- *(cli)* end quietly when the reader closes stdout
- *(engine)* name and admit the engine repair rooted at the judged authority
- *(handler)* run every hook handler from the declaring repository's root
- enforce the three new mutation sources, and clear clippy over the bundle
- *(hook)* collapse only the output of a call that ran the engine
- *(recorder)* a row can refuse a result by path
- *(check)* a policy finding's other subjects ride its line
- *(policy)* claim mint absent selects its row by id and names it
- *(durable)* name each temp by a per-process sequence, not the clock alone
- *(test)* build the replay under the checkout's target, where the prune reaches it
- *(prune)* declare the `build` root basis-moving
- *(mutate)* shard the declared sweep beside the registered runner, off the ci job
- *(mutate)* pass the runner's work directory by reference at its one caller
- *(mutate)* install cargo-mutants in CI the way its publisher does, resolve it only where it runs
- *(mutate)* pin cargo-mutants from crates.io, and keep the runner cases unix-only
- *(stop)* restore the publisher filter a mutation run left in 38acade5
- *(stop)* the filed-row rung scans over its selection, so registry equality no longer silences it
- *(hook)* settle a filed row before the next edit, and find the Stop rung's row by what it publishes
- [**breaking**] retire spawn count wrong, which refused splits and never bounded the fan-out it was filed for
- clear clippy, and make CLOUD-2185's mutant and cases discriminate what the row says
- *(hook)* a silent repair's record opens its window's legend like any first finding
- *(hook)* a silent repair's record reaches the model, and a could-not-look lint says its gap once
- clear clippy on the address change
- *(drain)* no line is exempt from the budget, the first included
- *(advisory)* an undeclared ceiling leaves the boundary's order alone
- *(drain)* the told total is two counts, never a list of rules
- clear verify after the replay onto main
- *(cli)* a usage refusal carries no backtrace
- clear verify on the gate-prose branch
- *(hookcost)* a refusal is followed when the next call takes a route its own line printed
- clippy, a history cap that starved long rows, engine update's toolchain, the probed rewrite
- what the full suite caught on this branch's earlier commits
- *(refusal)* the delivery-marks-on-emit mutant names a line rustfmt keeps whole
- *(refusal)* once-per-window delivery is lazy, delivery-marked, atomic, with a legend
- *(history)* a message the cap cut is not pointed at, and one too long to fit still lists its subject
- *(verdict)* register the doc and history modules, and regenerate what the new field and flag move
- *(hook)* the grant's rewrite stays inside run_hook's line budget, and the new tests pass clippy
- *(mint)* run writer rows first, and let exclusive selectors share a prerequisite
- *(mint)* refuse a prerequisite this call wrote, and return a claim a failed write could not spend
- *(mint)* claim the prerequisite, judge it against the store before the call
- *(mint)* spend the dispatch on its completion, and refuse what the review found
- *(mint)* split the after check out of validate, and regenerate the surface
- *(mutate)* a Kyverno case's verdict is a function of its set, and generated results are told apart by their shape

### Other

- *(mutants)* the receipt case's message names the bound it checks
- *(mutants)* keep the stop case's runtime cfg arm, which cfg-gated-test prefers
- *(mutants)* the stop case is unix-only by attribute, not by an early return
- *(mutants)* an unhung pack header, the base's own pause waiver, a fixed orphan stamp
- *(lease)* [**breaking**] terms_from_environment reads through the caller's lookup
- *(mutants)* an idempotent seed unguarded, one clean-tree read in measure
- *(mutants)* kill an unstopped holder before failing
- *(mutants)* bound the stop wait, isolate inherited env, quote stub paths
- *(mutants)* a range of asks and an unnegated rest, so no mutant hangs
- *(mutants)* review fixes over the residue seams
- *(mutants)* restore guards in operator-free form, share test fixtures
- *(mutants)* clippy over the residue seams and suites
- *(mutants)* perf rows over stubbed instruments, acquire checks the build first
- *(mutants)* stand-in transport, lease and mcp seams, forge and orphan suites
- *(mutants)* close G1/G2 residue rows in hook, rules, task, cache, transcript, pack
- *(rust)* scope MISE_LOCKFILE to the install steps, and check the lock after the suite
- *(lock)* read the working-copy lock again
- *(lock)* keep the inline spelling as a row, and give the doubled name its own
- *(lock)* label each fixture spelling and add the near-miss key and the doubled name
- *(lock)* the fixture shows the inline, renamed and near-miss spellings
- *(lock)* name github-attestations wherever the lock records it, and show it
- *(lock)* read attestation provenance from the parsed lock, every spelling
- *(lock)* name each lock table that carries attestation provenance
- *(mutate)* the sweep's safety rests on group membership, on both exits
- *(mutate)* the sweep case claims only the miss it can see
- *(mutate)* the survivor diagnostic signals nothing
- *(mutate)* end only listed survivors, by matches no reused pid can make
- *(mutate)* end only the job and its children, whatever ps answers
- *(mutate)* end every survivor the listing names, and skip an unwritten pid
- *(mutate)* probe and end the surviving job through the module's own spawn
- *(mutate)* name what outlives the group kill when the suite's job survives
- *(git)* /simplify — a repository without a commondir reads its config once
- *(git)* /simplify — the memo holds the thread-local handle and its stamps whole
- *(git)* open a repository once per thread while its config files are unchanged
- *(git)* build the hunk fixture without format-collect
- *(git)* pin unified_hunks' near-top header in its own module
- *(release)* read a ruleset's rules in place, and point at owed
- *(release)* G4 no longer runs --probe, so say what it does check
- *(mutate)* print the in-diff hunks with gix-diff's unified printer
- *(store)* the blocked-store case is its own, and says Windows reads it as absent
- the watch wait keeps its exact count, and the clock census names its closure blind spot
- only a local bound to a closure escapes the clock census, and the waits keep their margins
- a closure is not a clock reading, and the new cases share their helpers
- *(perf)* a refusal that closes stdin first is not a failed write
- *(record)* an unknown family is refused before any config is read
- *(recorder)* the declared-program case says off unix there is no sh
- the new cases pass verify's gates and fail fast under their mutants
- *(tokens)* keep Arm's public accessors and the case that pins them
- *(exec)* the off-unix dead-code expectation excludes the test build
- no new spawn, a premise checked before the signal, a budget boundary that discriminates
- share the scratch and executable helpers in the new mutant cases
- kill historical mutants in mutate and testing
- kill historical mutants in mcp and collect
- kill historical mutants in capture, store and the recorders
- kill historical mutants in exec and drain
- kill historical mutants in perf, tokens, budget and o200k
- *(background)* kill the stale-bound and task-id charset survivors
- read the declared forge without declaring one
- say which half of the forge case another case can see
- name the default the forge case expects
- read the winning forge's list off its own field
- declare a graded list the default cannot answer
- pin the declared path to the default it reads
- drop the forge case's order-dependent inequality
- hold the declared-forge readers to whichever forge won
- keep the replay fixture and environment out of the lint allowance
- clear the gates over G6's sweep cases
- hold claim's readiness to the ready lint's own answer
- hold every repeatable flag to keeping each occurrence
- kill the survivors the first measurement left
- state each case's platform and keep its fixture undated
- declare the one forge every case in the binary declares
- keep the hot path's own spelling and share the test helpers
- kill historical mutants in G6's ready and doctor modules
- kill historical mutants in G6's board, hk, engine, surface, history and rest
- kill historical mutants in G6's reclaim, lint, output, claim and verdict
- kill historical mutants in G6's store and ledger modules
- kill historical mutants in G6's small modules
- *(rules)* name a non-NotFound spawn failure every platform produces
- *(rules)* keep the non-executable spawn case to Unix
- *(rules)* build the history queries once and append the fingerprint newline directly
- satisfy clippy, the canonical spelling ceiling and the core vocabulary in the sweep cases
- *(rules)* refuse an edge naming an undeclared register
- *(rules)* kill the verification-run survivors in selectors, history dedup and the recorded partition
- *(hook)* drop a read route no declared source resolves
- *(hook)* fix vacuous protected-gate cases and remove two equivalent mutants
- keep the exact census and ceiling derivation the review asked back
- share the scratch fixture and tighten census reads in the sweep cases
- *(hook)* kill sweep survivors in the shell parse walk
- *(hook)* kill sweep survivors in verdict discard and interpreter grammar
- *(hook)* kill precedence survivors in the receipt command walk
- *(rules)* kill sweep survivors in ratchets, conservation, references and fact projections
- *(hook)* kill sweep survivors in receipt keying and declared tables
- *(hook)* kill sweep survivors in shell classification and protected operands
- kill sweep survivors in hook policy gates and rules fact families
- kill sweep survivors in rules validators, entry points and hook receipt selection
- *(hook)* kill sweep survivors in policy accessors, native gates and edit spans
- *(hook)* kill sweep survivors in host tables, decode and relativize
- *(test)* finish the correction on the mutant's Rust twin
- *(policy)* drop three figures and an attribution that do not hold
- *(test)* package_manifest serves the no-version family, not the no-URL one
- *(policy)* declare the mutation the array-blank case was standing in for
- *(policy)* the blank case was named for the spelling it does not use
- *(policy)* one home per claim in the arm E block
- *(toolchain)* the fix-selection `depends` does not buy what the validator's does
- *(policy)* reflow two comments, and stop the array `run` undercutting its own claim
- *(policy)* correct four statements, and give the package builder the task body
- *(policy)* declare the merge defect as a mutation, and record the tag-half gap
- *(rules)* build NativeGate's expected token once
- *(rules)* NativeGate's token parses back to its gate
- *(verdict)* fold token_enum!'s @impl arm into the plain arm
- *(verdict)* token_enum!'s serde arm delegates to the plain one
- *(verdict)* assert_unique compares each token with the earlier ones
- *(verdict)* show token_enum's duplicate guard can fail
- *(verdict)* drop the runtime duplicate-token checks the build now makes
- *(verdict)* one token_enum! macro serves every tokened enum
- *(verdict)* declare each native class and native gate once
- *(capture)* /simplify — the keeping seam is crate-private and borrows the row's digest
- assert the unresolved captured root addresses another store
- resolve the captured root on every platform, and scratch prune's missing path
- hand reduce the unresolved root, and name prune's case for its platform
- canonicalise the captured fixture's root and state the volume read off unix
- name which gix ref edit needs an identity, in the fixture's comment
- write the git fixture's refs as loose files, needing no identity
- check the epoch entry against the contained root itself
- check the epoch entry is contained, and say which platform pins the inode
- skip a nameless remote before reading it, and share the fixture helpers
- state the off-unix contract in place of two platform-gated cases
- satisfy the gate: lints, consumer-neutral fixture names, a live hookcost row
- rewrite the head-probe session in place, so only its first line differs
- assert nothing on the clock and keep the blank-name remote out
- state each off-unix outcome and drop the live free-space premise
- pin the lease terms to the configured remote
- pin the size bounds as spelled, the recheck pause and the session boundary
- pin git's index divergence, signatures, worktrees and materialised trees
- pin lease re-mints, successor slot, delta lengths and prune's executables
- pin lease capabilities, pack kinds and the band-width refusal
- pin git's upstream and a HEAD its remote carries
- kill historical mutants in the task registry, the singleton lock, prune's reclaim and disk_watch
- kill historical mutants across git's reads and lease's pure helpers
- kill historical mutants in refusal, and drop parse_labelled's unreachable arm
- kill historical mutants in journal and transcript, and pin captured's containment order
- close the remaining unit-scope survivors in eleven G2 modules
- kill historical mutants in cache, handler and lease's delta reader
- kill historical mutants in ten small G2 modules
- drop the released suite case no mutant needs
- take the sourced record's clock from now_unix
- name the sourced record uniquely rather than sweep for it
- match the swept record's name with its delimiter
- sweep the sourced record by name before and after its case
- read the sourced record through the store it was located by
- remove the sourced record even when its case fails
- tighten the second sweep's cases after review
- kill the remaining landed and sbom survivors
- kill the landing and CI-signal mutants the second sweep found
- kill the mutants the second sweep found surviving
- drop interval_for cases the floor suite already pins
- tighten the mutant-killing cases after review
- kill historical mutants in the landing's records and pure readers
- kill historical mutants in the check-run poll and the git writer
- kill historical mutants in release state, receipts and producers
- kill historical mutants in release, receipt and land
- kill historical mutants in the forge, CI and trunk readers
- *(g4)* drop the mediator case rather than narrow it to unix
- *(g4)* cite only the issue on the unix-only mediator case
- *(g4)* lift the unix-only gate on a fix, not a diagnosis
- *(g4)* say why the mediator case is unix-only, correctly
- *(g4)* name the Windows provisioning gap the unix-only case waits on
- *(g4)* ask the mediator only where the runner provides one
- *(g4)* leave the rules doc check's scope as it was
- *(g4)* apply the code review of the simplify pass
- *(g4)* apply the second simplify review
- *(g4)* pin which trust bundle the host's tools read
- *(g4)* satisfy clippy and keep a consumer's file name out of the core
- *(g4)* pin a bytecode bundle's empty description and a helper's coverage
- *(g4)* cover config's prune, parse-cache, text-memo and load-site survivors
- *(g4)* cover the policy, config and lane-C survivors the lib tier still missed
- *(g4)* contain the new state-store cases and correct three claims
- *(g4)* apply the simplify review to the new cases
- *(g4)* give the new filesystem fixtures a per-process directory
- *(g4)* cover provision, preset, config and policy survivors
- *(g4)* kill historical cargo-mutants survivors across config, policy and trust helpers
- *(mutate)* one row binds the profile pin; the helper comment names no subset
- *(mutate)* a second row drops the profile pin; the case claims only what it checks
- *(mutate)* a row binds the profile pin to its case, which reads the last entry
- *(mutate)* /simplify — nextest_profile parses the config with toml, not a line scan
- *(mutate)* /simplify — the default nextest profile lives in suite_env, for both runners that run nextest
- *(mutate)* judge LEAK and SLOW lines alone, so their misreadings cannot cancel
- *(replay)* replay is back as main had it; mutate counts its own cases off the shared word list
- *(replay)* one result-line parser returns the word and the case; each case is judged by its last attempt
- *(replay)* one parser of a nextest result line, shared by replay and the mutate count
- *(mutate)* /simplify — one list of nextest's status words, one group signal, one shard count
- *(engine)* /simplify of CLOUD-2418's review fixes
- *(engine)* /simplify of CLOUD-2418 after the rebase
- *(engine)* second /simplify over CLOUD-2418
- *(land)* pin each masked name, not one, as the dead end's confirmation (CLOUD-2189)
- *(claim-race)* "only the unconfirmed one" is a count, and asserting the first line never checked it
- *(claim-race)* two figures that never matched anything, and the count that made one of them
- *(claim-race)* the mutation section was a heading rustdoc never saw
- *(claim-race)* one spelling of collision, and the case that tells `any` from `first`
- *(claim-race)* the predicate gets a case, and the fixture stops holding its invariant by string identity
- *(claim-race)* the speculative case pins the read it names, not only the one it refuses
- *(claim-race)* which commits speak for this branch is its own function
- *(claim-race)* the unconfirmed mark goes on the row it qualifies
- *(claim-race)* the unconfirmed mark is read off its own line, not the whole stream
- *(claim-race)* the judge-first rationale argued from an invariant that stopped being true
- *(claim-race)* the fixture-seam rule outlived its own census too
- *(claim-race)* a conditional rule keeps where a census of call sites does not
- *(claim-race)* each item owns its own summary, and the helper says what it converted
- *(claim-race)* source 1 over one text gets a name, and the filter factors
- *(claim-race)* the filter states one predicate, and the case asserts the fix rather than its ingredients
- *(claim-race)* the skip's misjudgement runs both ways, and the worse way is a false refusal
- *(claim-race)* the self read's two halves become the Option the module already spells
- *(claim-race)* a missing self log inverts precedence rather than shortening the claim
- *(claim-race)* the Internal exit buys less at the gate than the comment claimed
- *(claim-race)* the case keeps its own rationale, the helper keeps the fixture's
- *(claim-race)* the listing the concurrency case drives is its own function
- *(claim-race)* the panic bound and the fixture seam both said less than they cost
- *(claim-race)* a channel carries the answers, and the case reads the width it asserts
- *(claim-race)* each fetch carries its destination, and the doc stops asserting a law
- *(claim-race)* fetch the competitors' logs concurrently, bounded at eight
- *(closes)* a cleared body supersedes a set, and the any-body selector has its mutant
- *(ci)* the suite gate reads shell with the hooks' parser and calls with syn (CLOUD-2388)
- *(land)* resolve the cancel's root once, for both arms
- *(land)* [**breaking**] verify_raced names its stall terms
- *(land)* anchor the entry-reconcile mutants on the guard
- *(spec)* the task noun has five writers beside its two readers
- *(land)* one lease reading; the entry asks it last; durable owns its temp mark
- *(task)* write_entry is durable::replace, whose temp is already per writer
- *(land)* reconcile inside the census window, docs follow the stall
- *(land)* a verify stall is its own signal; the arms win one way; one abandon helper
- *(stop)* word the dispatch excuse without the term source-name-other bans
- *(stop)* read the land call's background flag through Field::RunInBackground
- *(land)* a branch with no pull request owes its push nothing again
- *(land)* the push asks its receipts with no forge read
- *(test)* restore the link cases' cfg! early return off unix
- *(hook)* run the link cases on Windows too, without an early return
- *(test)* say the link cases' platform contract once, in the module doc
- *(hook)* enter the dangling loop through an ungoverned link
- *(hook)* state the link cases' platform contract inside each case
- *(test)* park the session_drain link through common::link_dir
- *(test)* make the portable link helpers common
- *(hook)* run the link cases on every platform, not only unix
- *(hook)* pin an absolute dangling target and a dangling loop
- *(hook)* hold relative_to's pending tail as a reversed stack
- *(hook)* say the tail replay's symlink invariant covers only its first component
- *(hook)* replay a missing tail through receipt::lexically_normal
- *(handler)* [**breaking**] a handler's subject is the tree, said by `tree_only` rather than a path regex
- *(hook)* one version rule for interpreter membership and grammar
- *(hook)* one decisive-option reading for both bundle walkers
- *(hook)* one interpreter grammar for both readers of a program
- *(preset)* the memory-write grant reads a consumer's pattern row
- *(preset)* opa fmt over the memory-write arm
- *(engine)* the fixture filters this build's target out of one platform list
- *(engine)* the fixture's provision platforms are never this build's
- *(engine)* --record clears on every run with no distance to give
- *(engine)* the notice asks git whether HEAD is detached
- *(engine)* the notice stamp reuses the one branch slug
- *(engine)* the notice stamp is per branch, like the record it guards
- *(engine)* one predicate decides when the notice looks again
- *(engine)* the notice stamp carries its pin; one ahead-of-pin rule
- *(engine)* one tag parser, one key reader, one manifest cache
- *(land)* the one-look comment names the row that owns records
- *(land)* the one-look comment names its mechanics and the rows that own the gap
- *(land)* one look at an abandoned record, stated as the design
- *(land)* one stat-line test builder; the keep rule said once
- *(land)* the orphan predicate's reasons live once, beside it
- *(land)* one /proc walk and one stamp reading behind the reap guard
- *(land)* the reap guard reads collect's /proc parsers; the caller's group is the reaper's call
- *(land)* the reap guard lives in a /proc leaf, not in exec
- *(preset)* the host's adapter reports the background ceiling, not the core
- long-run guidance matches the measured host and the tree
- *(test)* session_drain's header names the transcript cases' platform contract
- *(doctor)* one config resolution per `doctor session`
- *(durable)* /code-review — the scratch helper fails where the fixture fails, and its doc claims only what the reaper does
- *(durable)* /code-review — durable's cases take the crate's reaped scratch, not a /tmp directory per run
- *(durable)* /code-review — create_empty's AlreadyExists is pinned in durable's own suite; the no-prune mutant keeps the mark
- *(durable)* /simplify — create_empty returns the error, not a bool no caller reads
- *(durable)* /simplify — the module doc points at open_handle rather than restating it
- *(durable)* /simplify — the module doc names its third mutation, the handle opened for a lock or times
- *(durable)* /code-review — the file-or-directory opener lives in durable, the crate's std::fs leaf, not a new unplaced module
- *(handle)* /simplify — the file-or-directory handle lives in its own module, not in collect
- *(cache)* /code-review — a refresh writes two times, and an own partition lacks a mark only when marking failed
- *(cache)* /code-review — the bound case's off-unix note blames std, not Windows, and the mark step counts the list it walks
- *(cache)* /code-review — the bound case says it tells the rankings apart on unix only, and counts creation once
- *(cache)* /simplify — the step helper is `stepped`, not shadowed by a test's `at` closure
- *(cache)* /simplify — one step-to-time helper, and the test ages directories through `touch`
- *(cache)* /code-review — age the partition directories against their marks, so the directory-ranking mutant dies on any clock
- *(cache)* /simplify — the mark is one `File::create_new`, and the directory shim says when it can go
- *(cache)* /simplify — the use mark is written durably, and a partition that cannot be marked does not prune
- *(doctor)* [**breaking**] the rule opts into counting, not the engine
- *(red-head)* the job-log read names `return_content`, and `land push` keeps its doc
- *(red-head)* one typed record for the fact and the landing
- *(red-head)* one record path, a push-only lookup, and a reading passed whole
- /simplify of #1189 — name the checks-green task, and a neutral suite comment
- *(mcp)* the spawn rows name their own suite, and the failure reader has rows
- *(ci)* read the suite's requirements through rust_sources and hold them to [tools] (CLOUD-2381)
- *(ci)* gate suite-job tool installs, host libc and the Windows archiver locally (CLOUD-2381)
- *(dist)* stage the archive dist's installer picks for this host (CLOUD-2297)
- *(dist)* give the archive-name case its doc comment back (CLOUD-2297)
- *(dist)* check the lock with cargo fetch and pin the MSI's WiX table (CLOUD-2297)
- *(dist)* name dist's checksum and staging once, read its config once (CLOUD-2297)
- *(dist)* one home for the MSI template and dist's file names (CLOUD-2297)
- *(dist)* regenerate the CLI surface for --build-tool cargo-dist (CLOUD-2297)
- *(dist)* run cargo-dist's generator in a scratch workspace (CLOUD-2297)
- *(cache)* state the Windows ranking once, without claiming more than the filesystem keeps
- /simplify — each input holds its own answers; the parse cache is switched by argument
- /simplify — a partition in use is kept past the bound, the epoch retires from the state it already holds
- /simplify — one VM per bundle per input, a stamp that names its file everywhere
- simplify this branch's caches and memos per /simplify
- perf(pinned): digest the toolchain manifest once per process
- *(config)* read the authority once per process while it is unchanged
- *(pinned)* digest the toolchain manifest once per process while nothing moved
- *(hook)* one shared resolve per call, for the handler table too
- *(policy)* key each bundle by the pattern table's digest, taken once per load
- link mimalloc as the global allocator
- *(policy)* serialise the pattern table and resolve the cache directory once per load
- *(rules)* compile a glob's matcher at its first match, not at load
- *(cli)* build the command tree in one move per node, without a backward search per row
- *(hook)* build only the invoked verb's command subtree
- *(hook)* policy load parses its data document once and builds no check-only tables
- *(hook)* one authority decode per call, one input parse, BLAKE3 cache keys
- *(hook)* tally the session transcript incrementally, not whole per call
- *(hook)* evaluate each policy bundle once per call, not once per question
- *(cache)* the epoch cache and the pinned key onto the shared construction
- *(hook)* one cache module, and the validated authority cached on it
- *(hook)* one config load per hook call, and no fsync on its per-call records
- *(exec)* the forwarder count field states both release points
- *(land)* the bet head comes from the replay, and the closure derives its ref
- *(land)* a pushed bet is disarmed, not flagged
- one marker path, one re-raise, one signal set
- *(land)* the signal child fails when nobody spawned it, rather than passing over nothing
- *(hook)* run_hook hands PostTool to its own function, so it fits its line budget
- *(renovate)* Renovate carries an action's licence row in its own bump
- *(rules)* NativeGate::ALL is every gate, and its tokens are the parser's
- *(rules)* one native grade function, compared per gate by the weakening diff
- *(hook)* each native gate's predicate is written once
- *(mcp)* pin the failure marker to the last field
- *(mcp)* one predicate names a failure record — is_exec_failure
- *(mcp)* the ledger cases count launch records, not a refused exec's record
- *(mcp)* the exec-failure row sits at column 0, above its impl
- /simplify — optional target selectors, the spawn record carried to its failure
- /simplify — one scope read per source, one provisioning site, a ledger record for a failed exec
- *(mcp)* compose the provisioned-launch case's PATH with join_paths
- *(mutate)* mutants build without debug info, and a later suite's rule is pinned
- *(mutate)* build the targets fixture without an indented suite marker
- *(mutate)* build only the test targets that cover a mutated file
- *(exec)* the Reaper's doc passes doc_markdown
- *(exec)* the Reaper's doc names the direct-child KILL and reap
- *(review)* the existing cases keep main's `status` call; the owner admits two replayed bodies
- *(census)* plan file loose owes a case; validate's subject columns are one helper
- *(mint)* the optional-shape case names no consumer key; both stray rows stay
- *(mint)* [**breaking**] a tight optional key_shape loads; a stray one on a branch row is refused
- *(mint)* the named-row refusals read as their siblings, branch and blank cases included
- *(mint)* a named row takes one subject source and a shape that compiles
- *(ready)* one reading of a cutover, for all three ratchets
- read the fact table in place; the prior-art doc names who decides presence
- one reading of each claim, shape and fact set across the bundle
- *(land)* the lap's ready case asserts at a fixed instant, not the clock
- *(verify)* answer the base-test replay and four tree-pure hk steps from their receipts
- a declared retiring set lets `bats` leave the roster while it still runs
- *(mutate)* take mutation admission off until it runs fast locally first
- *(mutate)* a sharded cargo-mutants run skips the baseline
- *(collect)* read the host's own process table, step by step
- *(merge)* carry origin/main into claude/admiring-shannon-zxyn81
- *(mutate)* every changed row's case discriminates; a module's own test judges its row
- *(action)* the action installs its ref's pin, the case its mutation row names
- *(mutate)* the in-diff patch is written in process; a spawn is never admitted by its own reason
- *(mutate)* a row is applied in process, and a runner-owned file names its runner
- *(lease)* a lease is in exactly one state, decided once
- *(forge)* a run's state is classified once, from both fields
- *(git)* a landing fact carries its verdict, not a string and a bool
- *(agents)* land is the one step after pushing
- *(policy)* cache each mediated bundle as RVM bytecode
- template-copy fixture repos; a cfg! guard, never a cfg attribute, on new cases
- *(stream_input)* a tee that drops the host's bytes is caught
- *(prune)* run the two POSIX-executable cases on unix only
- *(mise)* retire the lap's reclaim step and the build's prune edge
- *(engine)* the staleness decision takes BATTEN_ENGINE=local as an argument
- *(hook)* bench the compile-time o200k table's cold start
- *(hook)* time the o200k pre-tokenizer regex alone in hook-read-bench
- *(hook)* bench bpe-openai's o200k load against tiktoken-rs
- *(hook)* measure the longest o200k token in hook-read-bench
- *(hook)* measure the o200k table load in hook-read-bench
- *(hook)* bench reading a hook payload buffered vs streamed
- *(capture)* run the --field cases on every platform
- build the wiring fixture from the template, and let released read carried subjects
- *(mutate)* scrub the sweep's selection from every case, and kill this branch's surviving mutants
- *(replay)* replay every modified test in one nextest run, judged by its own result lines
- build the Stop-rung case with init_repo, and pin the runner-absent case to a PATH without cargo-mutants
- *(mutate)* clear clippy over the runner registry
- *(mutate)* a whole sweep with a runner registered leaves that runner's rows alone
- *(stop)* show the hook's stderr when the filed-row rung stays silent
- *(mutate)* restore drain-cut-unreported on the line that now renders the cut
- *(mutate)* four rows the touched-gate sweep proved dead now discriminate
- *(refusal)* make every finding-grammar mutant row apply and die
- *(refusal)* route every agent-facing writer through the finding grammar (wip)
- *(config)* withhold the declared class docs until a release reads `doc`
- *(mutate)* keep generate_sweep, so the two generating cases read as they did
- *(mutate)* declare the fixture constants before the statements
- *(mint)* hold the cross-row refusals in one helper
- *(mutate)* baseline recordings for the hand-made Kyverno fixtures

## [0.0.216](https://github.com/button-inc/batten/compare/v0.0.215...v0.0.216) - 2026-10-13

### Fixed

- *(mutate)* generated-case-any-pass sits above kyverno_verdict, where rustfmt leaves it at column zero
- *(mutate)* the generated-case-any-pass row sits at column zero
- *(mutate)* select a GeneratingPolicy case by its trigger and fail it on any generated object

## [0.0.215](https://github.com/button-inc/batten/compare/v0.0.214...v0.0.215) - 2026-10-13

### Fixed

- *(lease)* keep cooling's signature; the holder-aware reading is cooling_for
- *(lease)* a poison cooldown never waits on this clone or a dead holder
- *(capture)* publish every live spool commit
- *(verify)* repair the hook surface before the gate set judges it (CLOUD-2233)
- *(wiring)* a merged-$HOME registration is reported as hook wire stray and never refuses landing (CLOUD-2233)
- *(asked)* record an answer given above the checkout into the checkout (CLOUD-2203)
- *(install)* the installer cases compile on every target and pass clippy (CLOUD-2203)
- *(install)* carry every surviving installer behaviour into tested Rust (CLOUD-2203)
- *(install)* take install.sh off the shell census exemption (CLOUD-2203)
- *(release)* read the installable targets from the bootstrap's table (CLOUD-2203)

### Other

- *(lease)* declare the cooldown's two rival-clause mutants
- *(capture)* declare the skipped-publish mutant
- *(config-lint)* build the workspace fixtures in place
- *(verify)* declare task-verify's mutant and read only the steps (CLOUD-2233)
- *(install)* a TLS fixture that survives the full suite's load; a workspace fixture built through Fixture (CLOUD-2203)
- *(install)* build the SHA256SUMS and matrix bodies with write!, not format!-collect (CLOUD-2203)
- *(install)* pack the fixture stub executable, as a release archive's binary is (CLOUD-2203)
- *(install)* drive the generated bootstrap end to end and pin its bytes (CLOUD-2203)

## [0.0.214](https://github.com/button-inc/batten/compare/v0.0.213...v0.0.214) - 2026-10-11

### Fixed

- *(install)* register engine install and generate installer with the surface gates
- *(install)* add `engine install` and `generate installer` for a generated bootstrap

### Other

- *(install)* build the per-user directory from components (CLOUD-2203)
- *(install)* name the placed binary with the platform's executable suffix (CLOUD-2203)
- *(install)* drop the generate installer verb (CLOUD-2203)
- *(install)* borrow the PATH entry rather than cloning it

## [0.0.213](https://github.com/button-inc/batten/compare/v0.0.212...v0.0.213) - 2026-10-11

### Fixed

- *(hook)* apply the host's mode policy where no authority governs

### Other

- *(hook)* drive the no-authority mode cases through adjudicate

## [0.0.212](https://github.com/button-inc/batten/compare/v0.0.211...v0.0.212) - 2026-10-10

### Fixed

- *(mutate)* declare the tofu init row at column zero
- *(mutate)* initialise the staged tree before a tofu suite runs

## [0.0.211](https://github.com/button-inc/batten/compare/v0.0.210...v0.0.211) - 2026-10-10

### Added

- *(mutate)* [**breaking**] read the enforced set from a committed [mutate] table
- *(mutate)* [**breaking**] retire the bats arm and add tofu, kyverno, conftest and pytest suites

### Fixed

- *(worktree)* resolve the consumer's trunk instead of assuming `main`
- *(mutate)* put two declared mutation rows at column zero

### Other

- *(trunk)* opt config-subject fixtures out of the trunk declaration
- *(trunk)* declare the trunk in fixtures and regenerate the surface
- *(mutate)* read the committed [mutate] table outside run_mutate

## [0.0.210](https://github.com/button-inc/batten/compare/v0.0.209...v0.0.210) - 2026-10-09

### Added

- *(mutate)* sweep only touched gates at admission

### Fixed

- *(captured)* [**breaking**] select the record the key is the subject of, not one that mentions it
- *(provision)* hand a launched tool the name it was called by
- *(mutate)* leave Rust rows to cargo-mutants at admission
- *(mutate)* count a deleted preset module as touched
- *(mutate)* read the sweep base from the environment
- *(handler)* a timed-out handler's whole process group dies with it
- *(drain)* bound the advisory payload to its budget and cap
- *(engine)* a failed fetch on the hook path falls through to the floor
- *(mutate)* gate the re-raise on unix instead of waiving a stub
- *(engine)* pass the followed engine's output through
- *(engine)* follow a release pin from the cache, on the hook path too
- *(exec)* expect the escalation reasons unbuilt where nothing forwards
- *(symbols)* let a launcher carry the analyser's environment
- *(mutate)* end a timed-out suite's whole process group, not its direct child

### Other

- *(policy)* drive claim-before-code's mutation through the shipped module
- *(captured)* build the subject fixture from the template, not a fork
- *(captured)* pin the subject match, and contain the stop-posture fixture
- *(provision)* waive the unix-only argv[0] case, and fail where bash is absent
- *(mutate)* move change narrowing into its own function
- *(suite)* restore the coverage the clock rewrites dropped
- *(engine)* run the followed case's engine from outside the checkout
- *(exec)* withdraw the two exec-lock rows that could not be shown red
- *(suite)* analyse a toy crate, measure the binary under test
- *(suite)* a case that cannot run fails, or is a cfg! arm; never retried
- *(suite)* assert recorded outcomes, never wall clocks
- *(mutate)* repair the three exec-lock rows, none of which had ever run

## [0.0.209](https://github.com/button-inc/batten/compare/v0.0.208...v0.0.209) - 2026-10-08

### Fixed

- *(ready)* stop reading the §8 sentence; cites-blockers names the edges

### Other

- *(harness)* stop mise's config search at the fixture root on every spawn
- *(ready)* read changed: ledger rows as declared; waive CLOUD-1771's count drop
- *(refusal-ceiling)* stage no session provisioning for the SessionStart cases

## [0.0.208](https://github.com/button-inc/batten/compare/v0.0.207...v0.0.208) - 2026-10-08

### Fixed

- *(perf)* identical arms are suspect only when the binary's sources differ
- *(config)* clear pr-open when a pull request is closed unmerged

### Other

- *(one_pr)* keep the close cases' bodies, empty their fixture row

## [0.0.207](https://github.com/button-inc/batten/compare/v0.0.206...v0.0.207) - 2026-10-08

### Added

- *(test)* replay each modified test's base form against HEAD

### Fixed

- *(engine)* aim the draft-wait mutation row at the line inside its loop
- *(engine)* wait out a pinned release that is still a draft, never refuse it
- *(release)* dispatch the artifacts of a draft release, and read a draft by list
- *(land)* keep the default lease waits inside one background lifetime
- *(ready)* read the §6 type before the answer, and an empty column as no claim
- *(test)* a replay that could not run is could-not-look, never a finding
- *(test)* `test replay` emits its findings as one JSON document under -J

### Other

- *(hookcost)* measure distinct gates per window and what follows a deny
- *(replay)* the scratch crate runs under nextest's default profile
- *(snapshots)* the golden JSON schema carries `test replay`

## [0.0.206](https://github.com/button-inc/batten/compare/v0.0.205...v0.0.206) - 2026-10-07

### Added

- *(refusal)* [**breaking**] one projection, labelled, every pointer on every firing, full once per context per compaction cycle (CLOUD-2075)
- *(hook)* [**breaking**] carry every route and every non-blocking advisory on an allowed call (CLOUD-1470)
- *(verdict)* admit a shape deny through a recorded override (CLOUD-1806)
- *(hook)* enumerate the four hook sources and their event vocabularies (CLOUD-1728)
- *(mint)* [**breaking**] a clear mode, so a pull request closed unmerged can free its branch
- *(wiring)* register batten where any session root loads it

### Fixed

- *(admission)* a fingerprint selects one of twin findings on a path (CLOUD-2126)
- *(provision)* no task calls the installer; a fixture holds the rule (CLOUD-2123)
- *(provision)* only an installed engine links the host (CLOUD-2124)
- *(hook)* admit the engine's own repair verb over a pin skew (CLOUD-2116)
- *(refusal)* declare the adjudicate echo columns and read a route flag as no label (CLOUD-2075)
- *(patch)* build the identity test's filler without format-collect (CLOUD-2098)
- *(patch)* a replayed edit keeps its identity when the base moved elsewhere (CLOUD-2098)
- *(refusal)* satisfy clippy over the projection and record the ceiling admission (CLOUD-2075)
- *(override)* refuse a request whose subject no refusal of the rule binds (CLOUD-1996)
- *(refusal)* [**breaking**] bind the pointers a mediated refusal prints (CLOUD-1826)
- *(provision)* fence GitHub off the proxy only with a live credential
- *(provision)* drop the proxy- placeholder on the fenced route even with no PAT
- *(land)* lift the lease-loss mutation row to column 0
- *(land)* a lap lost to the lease no longer spends the lap budget
- *(wiring)* declare and render the register verb everywhere
- *(wiring)* append the register variant after gate
- *(wiring)* register on the session root, not the user surface
- *(wiring)* complete the register check flag declaration

### Other

- *(admission)* decide the anchor in its own function (CLOUD-2126)
- *(provision)* redden the committed installer row, not a fixture copy (CLOUD-2123)
- *(refusal)* read the reference and traversal verbs' findings in the labelled grammar (CLOUD-2075)
- *(verdict)* pin the admission that keeps classes routed into protected paths reachable (CLOUD-1893)
- carry the auto-mode grant and the credential-gated fence into the suites

## [0.0.205](https://github.com/button-inc/batten/compare/v0.0.204...v0.0.205) - 2026-10-06

### Fixed

- *(released)* peel each revision to its commit before walking history

### Other

- *(released)* an annotated tag reports what it shipped

## [0.0.204](https://github.com/button-inc/batten/compare/v0.0.203...v0.0.204) - 2026-10-06

### Fixed

- *(register)* a cited register column reads only the rows the register keys

## [0.0.203](https://github.com/button-inc/batten/compare/v0.0.202...v0.0.203) - 2026-10-06

### Added

- *(register)* [**breaking**] append the register refusal last, and declare the API break
- *(traversal)* walk each declared traversal once per run into input.tree.traversals
- *(facts)* project traversals into the tree document (wip)
- *(facts)* declare the traversals tree fact (wip)
- *(traversal)* document edges, seeds, a register terminal and where a chain broke (wip)
- *(register)* dispatch the reference kind and resolve citations (wip)
- *(register)* the reference kind, the cites spec and per-column patterns (wip)
- *(register)* carry registers and traversals to the runner, and the reference join
- *(register)* declare [[register]] in config, trust and the verdict table
- *(register)* a declared key set and the one GFM row grammar

### Fixed

- *(land)* ready and re-draft through the proxy's REST route when GraphQL is refused
- *(land)* never pause after a race arm's final ask
- *(register)* refuse the four review findings' cases
- *(verdict)* declare the register refusal class in the vendored table
- *(traversal)* labels are optional beside declared edges, and the graph is Debug
- *(register)* a flattened source cannot sit under deny_unknown_fields

### Other

- register the reference kind, its refusal class and the traversals fact in every census
- regenerate the schema, register its module and input key, and stay inside clippy's line budget
- *(register)* a tracked citer deleted from the worktree is absent, not a finding
- *(traversal)* close the cargo-mutants survivors; build each walk's registers once
- keep consumer vocabulary out of crates/batten (rule 1)
- *(traversal)* the 04 -> 02 -> 01 chain through the compiled binary, a break at each hop
- *(facts)* classify traversals in the fact census
- *(traversal)* the document graph breaks at each hop and closes at a registered capture
- *(register)* close the cargo-mutants survivors over register.rs
- *(register)* retire the //MUTANT rows; Rust mutation is cargo-mutants
- *(register)* the four mutants the reference kind owes
- *(register)* the reference kind through the compiled binary
- *(register)* classify cites and the reference kind in the censuses
- *(register)* widen the column census for cites
- *(register)* cover the reference kind in the kind census and column list
- name registers in the two remaining Vocabulary literals

## [0.0.202](https://github.com/button-inc/batten/compare/v0.0.201...v0.0.202) - 2026-10-04

### Added

- *(forge)* record forge's nothing-graded statuses are config, and widening them is a weakening
- *(preset)* pre-approve every write batten allows in auto mode
- *(engine)* [**breaking**] gate the engine pin on the landing path, and keep a source pin current

### Fixed

- *(perf)* suspect identical arms only when this run built the base
- *(forge)* append the nothing-graded weakening rather than insert it
- *(forge)* an absent nothing_graded is the documented default, so the key needs no release to land
- *(engine)* the pin gate asks the pinned release to lint the config, not merely to load it
- *(config)* collapse the schema walk's nested reference guard
- *(commit)* route the commit-msg classes to commands the gate admits
- *(config)* cap every config prose column at load and in both schemas
- *(commit)* [**breaking**] lead every commit-msg refusal with a declared verdict class
- *(git)* escape the pipes in the identity-less-commit mutation row
- *(land)* admit a remote whose every commit the head already carries
- *(policy)* a class the binary ships no longer bricks the mediated boundary
- *(prune)* put the examples mutation row at column 0
- *(hk)* run the root clippy once, not once per Cargo workspace
- *(prune)* reclaim superseded example generations like deps
- *(step)* tee a step's own output so a failing gate names its failure
- *(gitwrite)* declare drop_set's mutant at column 0
- keep the three gate fixes within clippy and the fixture template
- *(gitwrite)* drop the lease holder's republished commits on a bet's unwind
- *(land)* point the trunk's tracking ref at the landed head on retirement
- *(hook)* the unloadable-config floor admits tools that mutate nothing
- *(land)* retire the single-partition lap reader the lease replaced
- *(land)* the push lease follows replays across a chain and a re-claim
- *(policy)* dropping a PR subscription is granted in every mode
- *(hook)* a newline after a verdict-bearing command replaces its status
- *(engine)* never self-update a build of the checkout, and re-exec by the path read before the swap
- *(engine)* cache a pinned release in the repository's state, never inside the checkout

### Other

- *(test)* read the bypass hatches without the validated config load
- *(prune)* reclaim a live unit's superseded .dwo generations
- *(prune)* keep an earlier row out of a later row's root
- *(config)* parse one authority once per process
- *(identity)* borrow already-canonical text instead of rewriting it
- *(semver)* keep the lock route's rustdoc targets warm
- *(pointer-only)* hold every echoed config column to a declared, capped leaf
- *(perf)* keep the head arm as the next lap's base
- *(config)* read only [forge] in the prologue, never the whole authority
- *(preapprove)* grant cases write outside the checkout
- *(preset)* judge write-is-preapproved over compound lines
- *(engine)* regenerate completions, man pages, the hk contract and the schema snapshot for engine pin and gate

## [0.0.201](https://github.com/button-inc/batten/compare/v0.0.200...v0.0.201) - 2026-10-03

### Added

- *(engine)* update the engine to its pin at startup, off the hook path

### Fixed

- *(land)* unwind a speculation the gate refused, and never stop carrying one
- *(engine)* fetch a pinned release from the engine module, rows at column 0
- *(testing)* judge fall-through in the resolver's spelling, not canonicalize's
- *(mutate)* count a mutation's changed lines as a multiset, not a set
- *(test)* a subset gate no longer overwrites the full suite's JUnit report
- *(config)* a duplicate close of a filed row records the tracker's status
- *(record)* one record decide at a time, so none clears another's reading
- *(lease)* a ref the remote does not advertise is bad input, exit 1
- *(git)* an unrelated ceiling no longer refuses a valid repository
- *(suites)* a nextest table labels its rows as modules, not suites
- *(record)* a retired bats lane's last report no longer shadows the nextest table
- *(suites)* a setup script is not a module row
- *(record)* a subdirectory abstention clears the stale record a root run left
- *(record)* a turn decided from a directory with no authority abstains
- *(suites)* a nextest table keeps nested modules apart and says its figures are summed

### Other

- *(engine)* regenerate completions, man pages and the schema snapshot for engine update
- *(test)* document the functions this branch adds or touches
- *(suite)* every nextest report lands where record suites reads it
- *(harness)* the task and piped doors refuse at spawn, on any target layout
- *(harness)* the task door refuses a fall-through as the binary's door does
- *(mutate)* repair the 19 rows the first sweep of the revived gates refused
- *(mutate)* move the indented row main's perf-pair fix brought in
- *(config)* withdraw the duplicate-close recorder until a human admits it
- *(mutate)* a Rust mutation row sits at column 0, and 36 dead ones come alive
- *(harness)* a full run writes nothing to the real state store, and every door pins the home
- *(harness)* refuse a fall-through before the spawn, judged by the resolver the binary uses
- *(harness)* main's git preset suite and the last two fixtures run in a repository of their own
- *(harness)* every fixture the binary runs in is a repository of its own
- *(harness)* every spawn writes the case's own state root, and a fixture that falls through to the checkout is refused
- *(suite)* every nextest run leaves per-case times, and record suites reads them

## [0.0.200](https://github.com/button-inc/batten/compare/v0.0.199...v0.0.200) - 2026-10-02

### Added

- *(engine)* an exact engine pin, checked before the parse

### Fixed

- *(perf)* count a base arm as built only for the key it was built for

### Other

- *(engine)* [**breaking**] register the engine noun and key in every surface ledger

## [0.0.199](https://github.com/button-inc/batten/compare/v0.0.198...v0.0.199) - 2026-10-02

### Added

- *(preset)* grant every git call batten allows, and prove no refusal is a dead end

### Fixed

- *(perf)* record the last arm through durable::replace
- *(perf)* build each pair arm from its own tree, and refuse two identical arms
- *(land)* [**breaking**] push only over a remote value this clone has seen

### Other

- *(preset)* register the git preset's surface and give each scratch call its own name
- *(portability)* hold every set_len to an inline write handle without a waiver
- *(portability)* hold executed test stubs and Windows truncation to local gates

## [0.0.198](https://github.com/button-inc/batten/compare/v0.0.197...v0.0.198) - 2026-10-02

### Fixed

- *(preset)* pre-approve declared mise lifecycle tasks

### Other

- *(prune)* stop the escalation at the first row that recovers the floor
- *(perf-gate)* return Result from the shared-arms case
- *(preset)* opa fmt the lifecycle-task grant
- *(perf-gate)* build both pair arms in one shared target dir
- *(journal)* write each folded record once per merge, not once per entry

## [0.0.197](https://github.com/button-inc/batten/compare/v0.0.196...v0.0.197) - 2026-10-02

### Fixed

- *(land)* catch a merge-carrying branch up with a merge instead of refusing it

## [0.0.196](https://github.com/button-inc/batten/compare/v0.0.195...v0.0.196) - 2026-10-01

### Added

- [**breaking**] retire the repository's bash into engine verbs, rego and presets

### Fixed

- *(durable)* truncate a torn tail through a write handle of its own
- *(tests)* make the drifting syft stub portable to BSD sed and wc
- *(record)* read a commit the forge has never seen as nothing graded

## [0.0.195](https://github.com/button-inc/batten/compare/v0.0.194...v0.0.195) - 2026-10-01

### Fixed

- *(hook)* keep a load fault's cause in the refusal, and pin the deny
- *(hook)* refuse the call over any config that will not load

## [0.0.194](https://github.com/button-inc/batten/compare/v0.0.193...v0.0.194) - 2026-10-01

### Other

- *(it)* judge a scratch name threaded through a helper, and end five races
- *(it)* test the vocabulary file's extension through Path
- *(it)* read the declared vocabulary from the file set the gates see

## [0.0.193](https://github.com/button-inc/batten/compare/v0.0.192...v0.0.193) - 2026-09-30

### Added

- *(rules)* every rule declares its remedy, fix or a classed no_fix_reason

### Fixed

- *(lint)* hold only kinds that permit no_fix_reason to a declared remedy

## [0.0.192](https://github.com/button-inc/batten/compare/v0.0.191...v0.0.192) - 2026-09-30

### Added

- *(codemod)* lossless Rust rewrites through ra_ap_syntax, pinned =0.0.331

### Fixed

- *(codemod)* declare the mutations at column zero, where the sweep reads them

## [0.0.191](https://github.com/button-inc/batten/compare/v0.0.190...v0.0.191) - 2026-09-29

### Added

- *(memories)* [**breaking**] bound every memory to what one read returns, and split the ones over it
- *(policy)* subagents and workflows never prompt in auto mode; only worktrees are refused

### Fixed

- *(hook)* the unreadable-config refusal names the floor it admits
- *(policy)* bats-invocation reads the selector test:bats actually runs
- *(policy)* keep a consumer filename out of the core, and fork no fixture repo
- *(policy)* read rule members only at the packages the modules declared
- *(refusal)* accept an admission subject as the refusal line prints it
- *(prune)* reclaim a .dwo whose owning unit has no fingerprint
- *(perf)* build the repository being measured, never an enclosing workspace
- *(hook)* a leading `/` in a followed `cd` is absolute on every host
- *(prune)* measure the warm floor instead of rescaling it by test-file count
- *(doctor)* register `doctor config` in the read allowlist, row set and pointer-only table
- *(doctor)* a `[[startup]]` row fails when the engine on PATH drops config rows
- *(hook)* a memory `Read` refuses under its own class and names its read route
- *(ready)* a docs or commitless row may declare no tests in its claims object
- *(tasks)* `record-verdicts` records only conclusions in the declared answered set
- *(hook)* `tool select other` follows a leading `cd` before judging an operand's containment

### Other

- *(perf)* keep the confinement case compiled on every target
- *(hook)* quote the repository root in the followed-`cd` deny cases

## [0.0.190](https://github.com/button-inc/batten/compare/v0.0.189...v0.0.190) - 2026-09-29

### Other

- *(shell-retirement)* bound the cost case in allocations, not wall time
- *(harness)* a state redirect no longer moves mise's installs
- *(lease)* assert the push economy over a fixture, not the checkout's history

## [0.0.189](https://github.com/button-inc/batten/compare/v0.0.188...v0.0.189) - 2026-09-29

### Added

- *(land)* [**breaking**] propose candidate resolutions on a conflicted replay, never apply them
- *(hook)* [**breaking**] pre-approve an owner-approved dispatch in auto mode, by receipt
- *(config_edit)* a format-preserving config edit seam with a toml_edit backend

### Fixed

- *(verdict)* declare the stale-receipt route on receipt read missing
- *(land)* keep gix in gitwrite and regenerate replay's pages
- *(land)* clear propose's clippy, durable-write, and layering refusals
- *(nextest)* keep the collector's mutation row out of doc comments
- *(nextest)* collect every target triple's scratch parent, not only target/tmp
- *(config_edit)* write through durable::replace and drop the format_collect
- *(prune)* supersede by cargo unit identity, not by stem
- *(finding-sink)* name the read that records a row's column

### Other

- *(verdict)* one stale-receipt route const, with its declared mutation
- *(hook)* sample the missing-receipt refusal for the route binding case
- *(closure)* report the distribution on stderr
- *(closure)* record the four modules #962 added to the plumbing
- *(closure)* name the plumbing set, because a count cannot see a swap
- *(closure)* gate the real distribution, and delete the vacuous one
- *(closure)* the cliff premise is refuted by the resolved graph
- *(closure)* ratchet the module dependency distribution
- *(shell-retirement)* bound the six-deletion arm at 30x the floor

## [0.0.188](https://github.com/button-inc/batten/compare/v0.0.187...v0.0.188) - 2026-09-28

### Added

- *(skills)* a groom skill that forces what `ready lint` cannot decide
- *(land)* [**breaking**] the lap watches its volume while the gate runs, and reclaims before the floor
- *(policy)* [**breaking**] plan mode reads or refuses, and a read is never put to the operator
- *(policy)* [**breaking**] a module can pre-approve a call the engine already allowed
- *(policy)* refuse a tool call while the operator's message has no answer
- *(policy)* one open pull request per branch, refused rather than asked
- *(policy)* name a decision offered back to the human at turn end

### Fixed

- *(mcp)* retract the Claude Code Remote tool-permissions remedy
- *(harness)* read the settings document inline so its deny list is not collected
- *(harness)* refuse the committed autoMode grant the classifier never reads
- *(land)* closing-key-record reads every key of a list, not every other one
- *(land)* the disk arm judges a running lap by its reserve, and never overrides a verdict
- *(verify)* two runs of one step both record, and the new surfaces are placed
- *(perf)* define the pair profile on the command line for the base arm
- *(verify)* repair the five reds this branch's own gates found
- *(tasks)* refuse a suite run that changes a tracked file in the checkout
- *(land)* a replay whose base deletes a directory removes it and everything after it
- *(hook)* report the attach check at session start too
- *(hook)* surface the connector-ask finding at session start and gate plan-mode reads
- *(tasks)* make test:cargo's PATH shadow absolute
- *(tasks)* run test:cargo with no batten resolvable by name, as on CI

### Other

- *(tasks)* a task body runs with mise's timings off, so byte-stable cases compare output, not clocks
- *(land)* a head the gate already proved is not proved again
- *(perf)* stage the pair's base arm under its own profile
- *(gate)* build both pair arms under perf-arm, key the base on crate content
- *(tasks)* annotate test_cargo_path's sh spawn and meet clippy

## [0.0.187](https://github.com/button-inc/batten/compare/v0.0.186...v0.0.187) - 2026-09-28

### Fixed

- address the code review on #962
- *(spawn)* bind every spawn's reason to its site, and gate the factory that launders it
- *(ci)* record on a detached HEAD, portable task bodies, and the gates CI measured
- *(engine)* [**breaking**] route every file write through a crash-only durable path
- *(tasks)* meet main's new test, schema and budget after the replay

### Other

- port lint-deno.bats to a Rust tier over a scratch repository
- *(tasks)* [**breaking**] retire step-receipt onto the keyed record store, 44 of 44
- *(tasks)* [**breaking**] retire 43 wave-2 bash programs into inline mise tasks

## [0.0.186](https://github.com/button-inc/batten/compare/v0.0.185...v0.0.186) - 2026-09-26

### Fixed

- *(darwin-link)* take the target argument, and refuse a bare body that reads one
- *(task)* reclaim a singleton lock that never got a pid
- *(hook)* a loaded deny-all rule can be escaped by a ripcord sentinel

### Other

- *(run-arg-shape)* backtick the target triples in a doc comment
- *(policy)* describe each bundle's AST once per load
- *(config)* read the committed schema before deriving one, and derive once
- *(claude)* no tracker or harness step ever stops for a prompt
- *(perf-gate)* open the sibling directory with backup semantics on Windows
- *(perf-gate)* the seeding cases declare their expect() like the crate's other tests
- *(perf-gate)* warm-start a missed base build from the newest previous one

## [0.0.185](https://github.com/button-inc/batten/compare/v0.0.184...v0.0.185) - 2026-09-26

### Added

- *(bench)* the token benchmark and its honesty gate move into the engine
- *(perf)* the measurement and its series move into the engine
- *(release)* the install contract is asked of its authorities, not scraped
- *(policy)* a startup budget nobody chose is boilerplate, and now it is gated
- *(ready)* the paths a row names are the crate's question too
- *(ci)* which suites a diff can move is a deny-list the engine reads
- *(doctor)* [**breaking**] six programs were two capabilities, and they are now two verbs
- *(record)* the per-suite cost corpus splits into a producer and a membership gate
- *(receipt)* the tree-clean precondition moves inside the verb that writes the receipt
- *(mcp)* retire the MCP launcher shim onto a verb that cannot become a supervisor
- *(doctor)* retire the egress pair onto the verb that already outranked it
- *(perf)* generalise the declared-arm harness both instances now use
- *(exit)* one authority folds findings and blind spots into an exit code
- *(policy)* retire ci-tools-check onto the engine
- *(policy)* retire timeout-check onto the engine
- *(policy)* retire publish-credential-check onto the engine
- *(policy)* retire coderabbit-config-check onto the engine
- *(policy)* retire cap-drift onto the engine
- *(policy)* retire digest-major-agreement onto the engine
- *(policy)* retire rust-paths-check onto the engine
- *(policy)* retire msrv-pin-agreement onto the engine
- *(policy)* retire hook-pin-check onto the engine
- *(policy)* retire mise-action-floor onto the engine
- *(policy)* retire batten-glob-check onto glob-containment
- *(policy)* [**breaking**] retire six shell gates onto the engine and give `exec` a lock

### Fixed

- *(harness)* take main's collector and fail-fast posture after the replay
- *(land)* a red head's other runs finish instead of being cancelled
- *(bench)* find the binary under test by its platform name
- *(prune)* a prune inside verify's open lap touches nothing
- *(land)* a fresh ready's wait does not read the draft-era skips as a dead end
- *(prune)* a running build's tree is never reclaimed
- *(surface)* drop the unreached declaration the reach needle refutes
- *(policy)* only a hook command in harness JSON reaches a verb
- *(refusal)* defer to the trunk's class-token binding, and carry the two cases it lacks
- *(prune)* a reclaimed artifact takes its cargo fingerprint with it
- *(harness)* the collector cases state their platform contract instead of hiding it
- *(harness)* the collector's command reader is Unix-only with its callers
- *(harness)* the scratch collector no longer deletes a concurrent run's fixtures
- *(lint)* a claim arms the repository root's authority and nothing below it
- *(lint)* a claimed branch's weakenings are adjudicated at the edit, not a lap later
- *(harness)* every scratch directory is one case's own, and a gate says so
- *(toolchain)* declare the fail-fast posture instead of inheriting one
- *(land)* restore the sentence that stops a reader reaching for --continue
- *(bench)* two runs at once measured each other
- *(config)* [**breaking**] the two consumer facts the ports wrote into the core
- *(spec)* the nine rows this campaign added, and the two lints the split raised
- *(spawn)* every spawn this branch added goes through the placed adapter
- *(lint)* every clippy escape this branch added, removed rather than annotated
- *(exec)* a lock key cannot leave its directory, and a lock option needs a lock
- *(policy)* five boundary reads that fired on text nobody wrote
- *(policy)* four ways a gate read clean over what it never judged
- *(surface)* exec and verdict declare the exit codes they actually return
- *(refusal)* every pointer shape binds, so no declared route can ship inert
- *(refusal)* an admission binds to an artifact subject, so a receipt refusal is escapable
- *(tests)* a case about which column moves must not also be about the clock
- *(handler)* a row naming the mediator runs the running image
- *(arm)* take the order from the caller, so a percentile needs no cast
- *(mcp)* withdraw a retirement whose caller resolves a release
- *(config)* a split keeps its id, so the weakening check reads it as one
- *(surface)* re-derive what the branch's new base changed under it
- *(git)* the working-tree walk answers about the checkout in front of it
- *(lints)* clear what the branch's own new code owed clippy and the vocabulary gate
- *(git)* a submodule is not an uncommitted path
- *(config)* repair what the replay dropped and rename the ported rows to three-word names
- *(spec)* the `verdict` verb takes its two ledger rows
- *(gate)* place `arm`, and make its rank arithmetic need no lint escape
- *(test)* qualify the four ledger arms whose case titles collide
- *(test)* fold the fixture builders instead of collecting a format! per entry
- *(policy)* give the first six ported rules verdicts that mean what they emit
- *(policy)* give the five ported rules verdicts that mean what they emit
- *(test)* drop the tracker key from the awk-regex inline fixture

### Other

- *(mcp-spawn)* the windows refusal case names a server
- *(platform)* state the unix contract of eleven cases the windows leg ran
- *(bench-tokens)* byte-exact reproduction is the publishing platform's
- *(bench-tokens)* perturb a copy of the table, never the committed one
- *(config-schema)* a config fixture is its own repository
- *(prune)* declare the fingerprint mutation where the obligation gate reads
- *(pointer)* the seven ports had no rule-4 disposition
- *(ledger)* the 129 deleted cases this branch never accounted for
- *(policy)* three assertions that could not tell right from wrong
- *(policy)* place the modules this branch added, and unbreak a module header
- *(landed)* retire the program its successor already replaced
- *(pointer-only)* the `verdict` verb takes its census row
- *(land)* drive a real conflict through the writer the module reads

## [0.0.184](https://github.com/button-inc/batten/compare/v0.0.183...v0.0.184) - 2026-09-26

### Fixed

- *(config)* name the ancestor sweep, so the prune loop stays under the line lint
- *(config)* an action row's unknown key costs the row, named rather than silent
- *(config)* a dotted array row is droppable, so a handler outlives its schema

## [0.0.183](https://github.com/button-inc/batten/compare/v0.0.182...v0.0.183) - 2026-09-26

### Added

- *(mutate)* give inline mise tasks a mutation route, scoped to their own table

### Fixed

- *(land)* a speculative lap is judged against the base it borrowed
- *(test)* every nextest run reports every failure, not the first two
- *(test)* the scratch collector waits for every other nextest run to finish
- *(admission)* bind the artifacts, so a class that advertises an override has one
- *(mutate)* clear verify's refusals on the task route and the prune cases
- *(target-prune)* refuse a short disk without building the engine to ask

### Other

- *(admission)* read the receipt refusal's subject off the refusal
- *(target-prune)* state the two spawns the shipped-body cases make
- *(common)* every task-body extractor reads through the sweep's boundary

## [0.0.182](https://github.com/button-inc/batten/compare/v0.0.181...v0.0.182) - 2026-09-25

### Added

- *(traversal)* [**breaking**] declare the walk in config, not in a module
- *(graph)* a bounded, call-by-need walk that stops on a node property

### Fixed

- *(prune)* skip a zero refusal count without a lint escape
- *(prune)* a learned floor the volume has refused twice re-bases
- *(admission)* a path-less class's admission binds to the head
- *(graph)* a test helper that always returns Some is not an Option

## [0.0.181](https://github.com/button-inc/batten/compare/v0.0.180...v0.0.181) - 2026-09-25

### Added

- *(policy)* refuse a new call that launders this engine's could-not-look

## [0.0.180](https://github.com/button-inc/batten/compare/v0.0.179...v0.0.180) - 2026-09-20

### Fixed

- *(harness)* publish the scratch count without BSD wc's padding

### Other

- *(harness)* collect the scratch parent once per run
- reserve an update slot a frozen pull request cannot consume

## [0.0.179](https://github.com/button-inc/batten/compare/v0.0.178...v0.0.179) - 2026-09-20

### Fixed

- *(facts)* read the frontmatter fence a generator actually wrote, not only `---`

### Other

- *(facts)* pin every frontmatter dialect, and declare the mutations that kill the table

## [0.0.178](https://github.com/button-inc/batten/compare/v0.0.177...v0.0.178) - 2026-09-20

### Fixed

- *(land)* walk the check-runs pages, so a live matrix is not read as absent
- *(mutate)* [**breaking**] bound a Rust suite by what it must do, and never call a timeout a filter fault
- *(gitwrite)* one UTC stamp for both committer signatures, in git.rs
- *(gitwrite)* withdraw the UTC stamp until it has a git-module home
- *(land)* the conflict stop names the route out of it
- *(gitwrite)* one UTC stamp for both committer signatures

### Other

- *(land)* bind both of CLOUD-1537's obligations to cases

## [0.0.177](https://github.com/button-inc/batten/compare/v0.0.176...v0.0.177) - 2026-09-20

### Other

- *(policy)* drive the depth and cycle cases over the compiled binary
- *(setup)* supersede the consumer artifact with this clone's own build

## [0.0.176](https://github.com/button-inc/batten/compare/v0.0.175...v0.0.176) - 2026-09-19

### Fixed

- *(land)* [**breaking**] a closed check set with a masked name stops the wait instead of polling it

### Other

- *(verify)* admit an approximated lane, and take musl off the pre-ready gate

## [0.0.175](https://github.com/button-inc/batten/compare/v0.0.174...v0.0.175) - 2026-09-19

### Fixed

- *(admission)* a spent block rides the merge ref's second parent, where CI looks
- *(hook)* a config that will not parse no longer denies the read that would show it

## [0.0.174](https://github.com/button-inc/batten/compare/v0.0.173...v0.0.174) - 2026-09-19

### Fixed

- *(policy)* give the stale-receipt class an exit that is not the password
- *(policy)* a skipped fan-in is a non-answer, not a red verdict

## [0.0.173](https://github.com/button-inc/batten/compare/v0.0.172...v0.0.173) - 2026-09-19

### Fixed

- *(ci)* the first build runs the disk precondition the rest already do

### Other

- *(ci)* assert the build's disk precondition as a dependency, not a mention

## [0.0.172](https://github.com/button-inc/batten/compare/v0.0.171...v0.0.172) - 2026-09-18

### Added

- *(policy)* refuse a verb a branch adds and nothing reaches

## [0.0.171](https://github.com/button-inc/batten/compare/v0.0.170...v0.0.171) - 2026-09-18

### Fixed

- *(tests)* a template is what git opens, not the two files an archiver keeps
- *(hook)* a read is not a mutation, and our own subcommand is not a path

## [0.0.170](https://github.com/button-inc/batten/compare/v0.0.169...v0.0.170) - 2026-09-18

### Fixed

- *(tests)* a template that cannot be established is a cost, not a failure
- *(tests)* the fixture template is verified before it is handed out
- *(tests)* the refusal cases own their repository, and so their store
- *(tests)* a fixture must not resolve the repository it runs inside

## [0.0.169](https://github.com/button-inc/batten/compare/v0.0.168...v0.0.169) - 2026-09-17

### Fixed

- *(hook)* the singleton scan reads mise's subcommand, not its first argument

## [0.0.168](https://github.com/button-inc/batten/compare/v0.0.167...v0.0.168) - 2026-09-17

### Fixed

- *(admission)* a mint addressing no finding of a rule that fired refuses
- *(harness-wiring)* name the surface a could-not-look could not read
- *(ci)* a provisioning run that failed must not report 0
- *(store)* [**breaking**] give the merged journal the order `assess` already assumes
- *(admission)* read a spent block from HEAD so CI honours an override
- *(doctor)* report a session-start fact a registered rule reads and nothing minted

### Other

- *(store)* the journal's order is asserted on both sides of the draw
- *(harness-wiring)* the could-not-look clause gets a compiled-binary tier

## [0.0.167](https://github.com/button-inc/batten/compare/v0.0.166...v0.0.167) - 2026-09-16

### Added

- *(record)* one producer door for the nine measurements, keyed by branch
- *(cli)* retire claimed-keys and merged-pr-keys onto claim keys and claim merged
- *(cli)* claim keys, the leaf claimed-keys retires onto
- *(race)* the source selector and the ancestor bound claimed-keys carries
- *(record)* two store families a task can reach, reusing the journal
- *(forge)* one windowed forge read, where truncation is a verdict

### Fixed

- *(ledger)* port the drain's two gather cases, because their subject survives
- *(tests)* restore the door tier's allow case, which asserts the door and not the rule
- *(mise)* merge the manifest against the real base, and re-point two run-shape mirrors
- *(lint)* clear the clippy denials this branch's new code introduced
- *(tests)* assert the record fixtures' setup writes instead of discarding them
- *(policy)* invert the last four cases asserting the sleep-loop exemption
- *(policy)* withdraw the sleep-loop exemption and correct every remedy it left behind
- *(test)* the hk fixture's fixer is portable, which Darwin just proved it wasn't
- *(ci)* a required macOS check that never runs must be absent-ok
- *(checks-green)* [**breaking**] order a name's runs by when they concluded

### Other

- *(gate)* [**breaking**] retire stop-posture-check onto the module that already decides it
- *(fixtures)* copy the git template instead of forking, per main's ratchet
- *(surface)* regenerate the derived artifacts for the record leaves
- stop asserting a repository visibility that has already changed

## [0.0.166](https://github.com/button-inc/batten/compare/v0.0.165...v0.0.166) - 2026-09-16

### Added

- *(rules)* [**breaking**] refuse the next write after a turn stopped with work unlanded
- *(attribution)* [**breaking**] judge who cut a tag, from the tag object rather than its commit

### Fixed

- *(attribution)* join the no-identity arms instead of escaping the lint
- *(land)* report the bot's own refusal instead of mapping it to remedies
- *(land)* sweep the fourth branch-keyed receipt family on retirement
- *(land)* read why the bot refused instead of asserting non-descent
- *(ci)* a release leg provisions what it needs, not every pinned tool

## [0.0.165](https://github.com/button-inc/batten/compare/v0.0.164...v0.0.165) - 2026-09-15

### Added

- *(tests)* a comment reporting a scan came back clean names what re-runs it

### Fixed

- *(land)* declare the forge for the process, not for a verb that loads policy
- *(rest)* name the credential this consumer holds, not the one its host injects
- *(tests)* the assertion gate stops spelling the name it exists to keep out
- *(prune)* move the floor basis to the tree this bundle leaves behind
- *(rest)* [**breaking**] the forge credential is the consumer's to name, not the engine's
- *(provision)* [**breaking**] the credential mechanism stops naming one forge, and a gate says so
- *(preset)* gate the provider declaration, and stop ci-hygiene passing a workflow it never read
- *(preset)* [**breaking**] declare which CI provider a module reads, and refuse where it reads none
- *(transcript)* [**breaking**] parse by a declared grammar, so an unsurveyed host abstains
- *(landed)* the sweep refuses an undeclared board instead of reporting it clean
- *(board)* the module owns its table, and the censuses know it
- *(board)* [**breaking**] refuse the next column literal, not just this one
- *(board)* the column vocabulary stops being an engine constant

### Other

- *(cli)* the census fixture declares the board `claim check` reads
- *(claim)* the fixture declares the board it is judged against

## [0.0.164](https://github.com/button-inc/batten/compare/v0.0.163...v0.0.164) - 2026-09-12

### Added

- *(facts)* read a markdown file's frontmatter, and say which non-answer it is

### Fixed

- *(perf)* raise the sample to what this comparison's own null needs to decide
- *(lease)* give the stand-down notice its sender, so a stale holder can be asked
- *(lease)* give the poison cooldown its writer, so a clone that reddened CI takes no further turn
- *(rules)* count the reads `acquire` makes, so the rule-cost census stops lying

### Other

- *(rules)* extract the measured acquisition so `run` stays under its cap
- *(config)* [**breaking**] carry this branch's two gates onto the new trunk

## [0.0.163](https://github.com/button-inc/batten/compare/v0.0.162...v0.0.163) - 2026-09-12

### Added

- *(policy)* [**breaking**] put the module finding ids in the grammar too
- *(refusal)* [**breaking**] render the rule id only where it differs from the class
- *(config)* [**breaking**] enforce the id grammar at load, and collapse where two names are one
- *(config)* [**breaking**] put all 136 rule ids in the three-word grammar
- *(verdict)* a rule id parses through the class grammar

### Fixed

- *(lease)* a present-but-empty schema field is refused, not read as the oldest
- *(cli)* match a rule id by its stored spelling before normalising
- *(cli)* normalise a rule id at the argument boundary, where it was not
- *(config)* keep `validate_tables` inside the line budget
- *(config)* a config read from a ref is compared, not judged by this grammar
- *(commit)* an unreadable parent config leaves the commit unjudged
- *(policy)* finish the grammar over what main added, tests and prose too
- *(policy)* carry the grammar to what main added under the branch
- *(tests)* stop forking the repo setup, and finish the bats migration
- *(policy)* carry the finding-id migration to every surface that names one
- *(policy)* keep `load` under its line budget, and migrate the rego test ids
- *(tests)* carry the migration through every surface that names a rule

### Other

- *(preset)* hold a preset's finding ids to the vendor's grammar

## [0.0.162](https://github.com/button-inc/batten/compare/v0.0.161...v0.0.162) - 2026-09-11

### Fixed

- *(mise)* let the job's own credential outrank the one mise-action sets

## [0.0.161](https://github.com/button-inc/batten/compare/v0.0.160...v0.0.161) - 2026-09-11

### Added

- *(lease)* an agent that poisoned CI takes no turn until the trunk moves or the pool idles
- *(lease)* [**breaking**] a peer can ask the holder to stand down, and the holder decides
- *(lease)* the body carries a refusable major and advertises its writer

### Fixed

- *(semver)* route every spawn through the resolution ladder
- *(land)* a gate refusal over a borrowed base laps instead of blaming this branch
- *(lease)* the ref-namespace premise was a misdiagnosed credential failure
- *(commit)* a path with a sanctioned mutation owes no articulation
- *(land)* [**breaking**] refuse the publish while a bet is outstanding, and lap instead
- *(land)* [**breaking**] publish the borrowed base to every body gate
- *(verdict)* append the new class rather than grouping it, since position is API
- *(hook)* refuse only a declaration nothing could read, and say why
- *(hook)* extract the refusal, and move four asserted codes off the fail-open
- *(hook)* deny a call this build cannot adjudicate, rather than exiting non-zero

### Other

- *(hook)* name the two fail-open boundaries, and let the raw payload travel
- *(hook)* give the adjudicable predicate a name, and the fifth code its reason
- *(hook)* show the fail-open arm can fail, and that its fix is not an outage

## [0.0.160](https://github.com/button-inc/batten/compare/v0.0.159...v0.0.160) - 2026-09-11

### Fixed

- *(land)* a hold is bettable only if it is another AGENT's, not another branch's

## [0.0.159](https://github.com/button-inc/batten/compare/v0.0.158...v0.0.159) - 2026-09-09

### Added

- *(hook)* [**breaking**] a handler may select on the command, not only the tool name
- *(bench)* the report answers the question it was built to ask
- *(bench)* the post-CLOUD-1637 numbers, and prose derived from them
- *(bench)* price refusal rendering by strategy and explicit residency
- *(wiring)* [**breaking**] disarm declared launcher scripts, not just their registrations
- *(run-shape)* every mise call is backgrounded, and a backgrounded call keeps its own output

### Fixed

- *(rules)* hoist the order key out of run, where it was a statement
- *(rules)* make the finding order a function of the set, not of the walk
- *(bench)* the report drops the crate version, which no release could leave stable
- *(mutate)* a second sweep over the persisted staged tree is not a broken harness
- *(land)* fetch the trunk before the speculation reads it
- *(test)* ask the portable question, and drop the waiver it needed
- *(test)* open the shim spawn's annotation with its verdict
- *(test)* build the disarm fixture's paths as literal TOML strings
- *(hook)* make the cross-turn pointers survive a coloured log
- *(policy)* a task-output poll is the same duplicate as a process poll
- *(trust)* give the wiring table a weakening verdict, and the suite its shapes
- *(wiring)* refuse an unloadable config, and label a conservative disarm honestly
- *(verdict)* the discard family stops prescribing the form background-redirect refuses
- *(pipeline-shapes)* move the prescribed form to backgrounded-and-unredirected, since two rows now refuse the old one
- *(tests)* move the live-root mise cases to the backgrounded form, and follow the commit-msg call site
- *(run-shape)* exercise both new predicates, and stop asserting a foreground mise call is allowed
- *(checks-green)* the winner is a function of the set, not the slice order
- *(mutate)* the bound blocks on a channel, so no delay waiver is needed
- *(mutate)* the watchdog signalled a group it did not own
- *(tests)* the hoisted vocabulary is already a reference
- *(core)* keep the consumer's artifact names out of the core's comments
- *(mutate)* the sweep owns its suite bound, and the row that proves it
- *(checks)* a run that completed without judging cannot erase a verdict

### Other

- *(ci-parity)* the engine fixture declares the two lanes the cover names
- *(snapshots)* accept the spec snapshot the `--issue` help-text change moves
- stop caching another system's facts in prose, and point at the one dated authority
- *(hook)* build the fixture from the template rather than forking git
- *(hook)* assert the door's real channels, not the assumed ones
- *(bench)* the projection loses its lint escape, and the tier its new gated test
- *(bench)* the projection keeps its rows, and the report splits its halves
- *(rebase)* build a twin git will not collapse, and a trunk that moved
- rustfmt the disarm pass and its suite
- *(hooks)* the commit-msg steps stay on the task, because respelling them requires an edit shell-retirement refuses
- *(mutate)* the runner's bound is a sleep it never reaps on a red case
- *(tests)* replay the record gate in-process instead of over 78 spawns
- *(tests)* split the record replay per trial block and build its repo once

## [0.0.158](https://github.com/button-inc/batten/compare/v0.0.157...v0.0.158) - 2026-09-09

### Added

- *(gate)* refuse an added absolute that cites nothing

### Fixed

- *(land)* take the wait callback's argument in its own unit case
- *(land)* [**breaking**] advance the lease token when the checks move, not when the poll does
- *(lease)* publish the progress token a beat was never carrying

### Other

- *(land)* ask a step's prechecks once, and keep the core repo-agnostic

## [0.0.157](https://github.com/button-inc/batten/compare/v0.0.156...v0.0.157) - 2026-09-09

### Added

- *(hook)* run the declared repair, and take the arm the class declares
- *(rules)* admit a repair on the kinds that reach the boundary
- *(verdict)* declare what the boundary may DO about a class

### Fixed

- *(rules)* carry both census columns the rebase merged
- *(hook)* name every allowing event in one arm rather than six
- *(hook)* declare why the event arms repeat rather than merging them
- *(rules)* [**breaking**] say what `no_retry_reason` declares

### Other

- *(hook)* split the command-line gates out of the call chain
- *(hook)* split the event dispatch out of the gate chain

## [0.0.156](https://github.com/button-inc/batten/compare/v0.0.155...v0.0.156) - 2026-09-09

### Added

- *(surface)* declare `doctor gate`'s exit set
- *(surface)* declare `policy rule`'s exit set
- *(surface)* every leaf verb declares the exit codes it may produce

### Fixed

- *(mcp)* a failed tool result is not a successful call

### Other

- *(mutant)* enforce the two engine gates, and declare the landing verbs' exits

## [0.0.155](https://github.com/button-inc/batten/compare/v0.0.154...v0.0.155) - 2026-09-09

### Fixed

- *(rules)* classify `unless_contains` in the column census
- *(policy)* a range move is not a landing lap
- *(preset)* write the action as a coordinate, not a bare vendor name
- *(preset)* the manifest census reads a module's named fields
- *(policy)* gate the mise pin against the version workflows install
- *(ci)* give the x64 `ci-` family a warm writer, and gate the orphaning
- *(session)* install the release at session start, never a compile
- *(doctor)* drop the exit-set declaration, written against a borrowed base
- *(doctor)* declare the new verb's exit set
- *(doctor)* state the Windows hook contract instead of gating the case away
- *(doctor)* the exec-bit reading is unix's, so the case that asserts it is too
- *(doctor)* the commit-gate predicate is a sub-verb, not a report row
- *(doctor)* the commit path becomes a checked precondition

### Other

- *(preset)* [**breaking**] the module header says scope is per module now

## [0.0.154](https://github.com/button-inc/batten/compare/v0.0.153...v0.0.154) - 2026-09-08

### Fixed

- *(hook)* [**breaking**] deliver the class definition on a first sighting

## [0.0.153](https://github.com/button-inc/batten/compare/v0.0.152...v0.0.153) - 2026-09-08

### Added

- *(land)* give the loop's one human stop a route to take it
- *(land)* race the gate against its base and cancel the loser
- *(land)* a gate refusal says WHICH kind of refusal it was
- *(land)* the entry gates and the retirement of a landed branch
- *(land)* the lap places the speculation it settles
- *(land)* the lap settles an outstanding speculation
- *(lease)* the fast-forward carve-out, and the lane the shell missed
- *(land)* the ready event, and pr_watch's last gh spawn retired
- *(land)* the driver runs the undos a lap owes
- *(pipeline)* the landing composition as a declared list
- *(lease)* release notes the reclaim census, as the consumer declares it
- *(land)* the prune, conserving what `--prune` was load-bearing for
- *(land)* the tap, the transient re-run, and the rate-limit backoff
- *(land)* abandon the matrix a red check made worthless
- *(lease)* `guard` — the step-0 precondition as one composite write
- *(lease)* `carries` — the staleness row that was about to go silently dead
- *(land)* the lap's ready step, and the two orphaned gates it calls
- *(land)* the lap ledger — spend is counted, never inferred
- *(land)* speculation — the bet on the base that is about to exist
- *(land)* [**breaking**] the stale arm is main-watch's conditional poll, raced
- *(land)* a freshness probe between the gate and the push
- *(land)* `lap` — the driver, and the table that says what each answer means
- *(land)* `fast-forward` as a verb, and one exhaustive match to slot it into
- *(land)* the fast-forward protocol, keyed to the comment that asked

### Fixed

- *(test)* the entry-gate stub is a program on both targets, not a shebang
- *(gitwrite)* [**breaking**] a resolution is spent per entry, so a path may conflict twice
- *(test)* two cases narrowed to unix that hold on both targets
- *(test)* a corpse is unreachable off unix, so both arms get asserted
- *(test)* the scratch reaper's case asserted only one arm of its own cfg split
- *(test)* declare the reinstall fixture's const before the statements
- *(test)* restore the provision-fence fixture main's module needs
- *(provision)* replace the cached binary rather than writing through it
- *(land)* spend each resolution PATH once, not the whole offer at once
- *(land)* drop a commit whose change is already on the base
- *(receipt)* committed config is the working tree's, on both anchors
- *(land)* the raced gate was two dead mechanisms, and this makes both live
- *(land)* refund the lap whose gate the race reclaimed
- *(scratch)* place the module and let its tests use expect
- *(test)* clear $LAND_VERIFY from the census corpus, it was running verify
- *(scratch)* one owner for out-of-tree test scratch, reaped by liveness
- *(land)* the lock's binding is used now, so it loses its underscore
- *(land)* a registration that never moves reads as a stall
- *(land)* verify's exit 2 means main moved, and the port stopped on it
- *(land)* the lap takes the singleton, registers, and reaps
- *(config)* the load-time census reads three loader bodies, not two
- *(config)* a warn shape row is silent, and the comment claimed otherwise
- *(trust)* the lane weakening priced INTRODUCING a gate, not widening one
- *(lease)* git-over-HTTP takes Basic, and the smart-HTTP client sent Bearer
- *(provision)* the busy-target case is Unix-only, because its subject is
- *(provision)* a re-link cannot write through the binary it is replacing
- *(land)* the lap held a 120s lease across a whole matrix, and thirteen more
- *(engine)* nine could-not-look collapses, each reported as a clean answer
- *(hook)* a newline inside a quoted argument was a line boundary, and six more
- *(exec)* `reraise` did not type-check on the Windows target
- *(lease)* the pre-checkout guard had no lease to read, and six more
- *(lease)* the guard skipped the lease it exists to read, and six more
- *(land)* a destructive prune keyed to the wrong remote, and three readings
- *(land)* the last lap's deferred undos, and a bet flag that outlived its bet
- *(land)* six findings, and four were a mechanism written and never reached
- *(land)* thirteen findings, and three of them were gates deciding nothing
- *(rest)* a dead clock is not an instant, and four more unreachable arms
- *(land)* a merged pull request is CLOSED, so the merge gate could never pass
- *(land)* the losing arm of the race stops holding a finished landing
- *(land)* the lease is handed back, the backoff is honoured, the refund fires
- *(land)* a skipped bot run is not a merge, and six regressions of my own
- *(rest)* the retirement dropped a header the forge requires, and two pointers
- *(land)* the lap takes the lease, so the tap it declares can close
- *(land)* the lander could not complete a single lap as shipped
- *(land)* a could-not-look trunk is not a moved trunk, and the fan-in binds
- *(land)* close the outstanding review findings on #848
- *(land)* [**breaking**] retire abandon-matrix, and the fan-in it was cancelling
- *(receipt)* verified_by takes a default rather than refusing
- *(lease)* the guard read no config at all, and CodeRabbit's ten others
- *(land)* a red wait stops the lap instead of waiting out the hour
- *(lease)* every health state names the admitted successor
- *(land)* an unset fan-in cancels nothing rather than guessing
- *(main-watch)* an empty base is never reported as movement
- *(test)* `rest` joins the declared network callers
- *(land)* the abandon fixtures name no consumer's workflow
- *(rest)* the forge REST tier moves in process, and a gate over the escapes
- *(lease)* the status verdict, and the two columns that read it
- *(surface)* the three new verbs carry a pointer-only disposition
- *(land)* speculation reads ancestry through gitwrite rather than opening gix
- *(spec)* the committed surface set carries the three verbs this branch added
- *(land)* resolve the clone's root, so the configured gate is actually run

### Other

- *(gate)* the compiled tier cfg-gated-test's #MUTANT-SUITE names
- *(surface)* record --resolve in the golden schema snapshot
- *(landing)* restore main's landing-roster rows after the replay
- *(policy)* withdraw the provision fence, it is CLOUD-1550's row
- *(hook)* main landed CLOUD-1287 too, so the hand-rolled splitter goes
- *(provision)* close the doc comment the cfg gate split in two
- *(trust)* the new weakening kind ships with the case its census demands
- *(ci-parity)* both tiers pin the fan-in binding, in both directions
- *(shell)* retire the lander, and 146 titles dispositioned one by one
- *(lease)* [**breaking**] retire land-lock, the cluster's largest program
- *(lease)* [**breaking**] retire ci-lease-precondition onto `batten lease guard`
- *(land)* [**breaking**] retire main-watch onto the lap's staleness precheck
- *(lease)* retire land-lock-check.sh onto `batten lease check`
- *(shell)* retire verified.sh onto `batten receipt verified`

## [0.0.152](https://github.com/button-inc/batten/compare/v0.0.151...v0.0.152) - 2026-09-08

### Added

- *(nextest)* ban slow tests in the runner, and gate the declaration

### Fixed

- *(nextest)* bound a hang from the job budget, not from this box
- *(nextest)* gate the kill threshold, and start it as a runaway guard
- *(test)* drop the unused fixture constant the Windows cross-check denied
- *(test)* resolve the committed config through the Overrides the signature takes
- *(admission)* narrow a mint's scan to the bundle that publishes the predicate

## [0.0.151](https://github.com/button-inc/batten/compare/v0.0.150...v0.0.151) - 2026-09-08

### Fixed

- *(doctor)* [**breaking**] the mediator check asks whether the build is behind the source

## [0.0.150](https://github.com/button-inc/batten/compare/v0.0.149...v0.0.150) - 2026-09-07

### Fixed

- *(landing)* anchor the guard on the invocation, not the mention
- *(landing)* declare the directory, so deleting the guard is not invisible
- *(landing)* consult the required-check roster before moving main

### Other

- *(test)* drop the needless hashes from the unguarded fixture

## [0.0.149](https://github.com/button-inc/batten/compare/v0.0.148...v0.0.149) - 2026-09-07

### Added

- *(secret)* [**breaking**] a credential that cannot be printed by accident
- *(provision)* prove a credential before stripping the host's wiring on its strength

### Fixed

- *(config)* a stale binary starts and says so, and each release publishes its schema
- *(config)* tell a stale binary apart from a bad config, and start
- *(fetch)* send a User-Agent, and stop collapsing could-not-look into refused
- *(policy)* gate the egress fence on the surface that actually runs

### Other

- *(config)* the skew check is the failure arm's, not every invocation's
- *(secret)* a canary that is not itself a credential
- *(config)* the additions window disarms the hook, it does not only blur it
- *(policy)* add the compiled tier the gate commit claimed and did not carry

## [0.0.148](https://github.com/button-inc/batten/compare/v0.0.147...v0.0.148) - 2026-09-07

### Added

- *(bench)* declare the agentic trials, and gate the records that carry them
- *(tests)* score a rule's cases as reported / validated / noisy / missing
- *(decision)* answer `sha -> {model, harness, session}` over the decision log

### Fixed

- *(policy)* ask the presence question of every backend, not only the locked ones

### Other

- *(rules)* move the doctrine to a neutral home five more harnesses can read
- *(facts)* hold every consumer to one conformance set for an issue key

## [0.0.147](https://github.com/button-inc/batten/compare/v0.0.146...v0.0.147) - 2026-09-07

### Added

- *(policy)* price the code review at the ready transition, not per commit
- *(receipt)* key a receipt to the branch's change, so a review can be owed at a transition
- *(mint)* [**breaking**] key a receipt to the branch's change, so a code review can be owed

### Fixed

- *(receipt)* resolve the delta identity from the repo root, not the cwd
- *(lint)* a waiver may name a predicate id, which is the spelling that suppresses
- *(mint)* the guard added last round was unreachable, so it deleted the filter
- *(mint)* the null-result guard made the gate unclearable, and the tier could not see it
- *(mint)* repair the four correctness defects the third review found
- *(gate)* repair the five defects the gate's second review found
- *(gate)* repair the four defects the gate's own code review found

### Other

- *(trust)* the outcome census rationale carried collapsed-line whitespace
- *(lint)* extract the waiver diagnostics, which put smells over the line ceiling
- *(receipt)* the delta arm's comment described the code before the hoist
- *(receipt)* resolve the delta identity once per check, not three times
- *(receipt)* build the delta-keying fixture through the builder, not a git init chain
- *(mint)* let the test module use expect, as its siblings do
- *(mint)* wrap the selector binding as rustfmt wants it

## [0.0.146](https://github.com/button-inc/batten/compare/v0.0.145...v0.0.146) - 2026-09-06

### Fixed

- *(override)* anchor a policy predicate's mint on its finding, not the HEAD
- *(hook)* let the detectors speak when another writer holds the store
- *(hook)* hold rule findings the skipped scan never looked at
- *(hook)* never let the mediated path wait on the drain's lock
- *(hook)* keep the transcript detectors synchronous, detach only the scan
- *(hook)* start the state record instead of awaiting it
- *(rules)* withhold a rule whose declared fact this surface cannot resolve
- *(rules)* [**breaking**] gate the effect facts on Surface, not on the dispatch enum
- *(rules)* gate the two Cost::Effect facts on the effect surface, not declaration

### Other

- *(hook)* assert the skipped scan does not RESOLVE, not which arm it takes
- *(exec)* place the drain's spawn at the child-process boundary
- *(rules)* let the mediated caller choose its config-fault checks

## [0.0.145](https://github.com/button-inc/batten/compare/v0.0.144...v0.0.145) - 2026-09-06

### Added

- *(hook)* decide a loop from its node, not from a keyword
- *(hook)* parse bash with rable instead of scanning it
- *(preset)* mise preset, receipt-backed execution integrity
- *(policy)* advise on recognized shell tool failures
- *(hk)* define hk execution-evidence capability and conformance fixtures
- *(hk)* record a bounded hk runtime-observation receipt
- *(hk)* make hk's effective plan a pre-admission fact
- *(hk)* generate and drift-check the adopted hk surface contract
- *(hook)* [**breaking**] `severity = "ask"` reaches the escalation the engine already had
- *(hook)* refuse a second start of a task this clone already holds
- *(hook)* refuse a reset that would leave work referenced by nothing
- *(hook)* [**breaking**] the hatch stops answering for any class with a real way out
- *(landed)* say so when the claimed arm is unsupplied, and carry the derived artifacts
- *(landed)* sweep a board for claims nobody is serving

### Fixed

- *(outcome)* the anti-vacuity case measures the matcher, not the host
- *(hk)* the contract is the config's plan, not the caller's
- *(outcome)* let the signature fixture declare the host's own family
- *(hook)* read the shape and receipt walks per line, with their own spans
- *(hook)* read the pipeline walk per line, through one reading
- *(hook)* judge every element of a substitution scan, per line and resolved
- *(hook)* close two bypasses and two wrong verdicts
- *(hk)* [**breaking**] a version skew is could-not-look, not drift
- *(spec)* rebuild the committed row set from main, plus the hk rows
- *(hook)* the per-line consume drained on a mismatch it called abstention
- *(hook)* repair three gates, one of them mine
- *(hook)* two expressions that read as decisions and were not
- *(tests)* stop the reclaim census cases hanging on a network they do not use
- *(hook)* keep env assignments as words; stop walking control-flow bodies
- *(hk)* refuse colliding plan ids at load, and show drift able to fire
- *(taskset)* decide a task's argv by parse, and stop the preset
- *(hook)* a newline splits the program, not the segment
- *(config)* [**breaking**] close the six review findings on the forward-compatible loader
- *(config)* [**breaking**] a key in a plain section costs the key, and the report names the release
- *(config)* a header may carry a trailing comment, and that was a fail-open
- *(config)* lex strings properly, and check the prune against the parser
- *(config)* a quoted header is not a section boundary, and the tier that says so
- *(config)* [**breaking**] a row from a newer schema costs its row, not the whole file
- *(task)* EPERM is a live process, and reading it as dead fails open
- *(hook)* a live-root case must not name the one task a lock guards
- *(hook)* land's allow is a fact about the world, not about the commit
- *(prune)* a lap is not charged for the cleanup that outran it
- *(landed)* clear the four gates verify raised on the rebased head

### Other

- *(hook)* split the parse walk under the line ceiling
- *(generated)* regenerate the derived artifacts on the new base
- *(preset)* the compiled tier's envelope had drifted from the predicate
- *(facts)* the census counts 39 after the rebase
- *(cli)* document the three functions this branch adds, and regenerate
- *(hook)* put unquote's rationale back on unquote
- *(install)* the fixture names its own repository rather than this one
- *(agents)* stop promising that a task count answers "safe to end?"
- *(hook)* a corpse is unexpressible off unix, so the case that needs one is gated
- *(prune)* the fixture moves to the generation that repaired the arithmetic
- *(landed)* enrol the module in the mutation sweep and make its rows readable

## [0.0.144](https://github.com/button-inc/batten/compare/v0.0.143...v0.0.144) - 2026-09-06

### Added

- *(identity)* the payload contract is a type, and both its arms name one document
- *(store)* a chunk is storage bookkeeping, never a second canonical identity
- *(capture)* [**breaking**] choose inline or addressed transport from a measured threshold
- *(capture)* locators find a payload, addresses name one, and freshness costs no bytes
- *(store)* resolve a content address by rehashing before anything decodes it
- *(identity)* a versioned, domain-separated BLAKE3 content address
- *(store)* a lost secret-identity key is the verdict, not a log line
- *(mcp)* census a connector's tools against the grants that reach them
- *(mcp)* [**breaking**] project each element of an array result
- *(facts)* collapse the Rust parse to one call site
- *(facts)* make a deferral's reversal condition data a gate can read
- *(ci-drift)* project the host settings whose change weakens a control
- *(config)* compute the version floor a release owes
- *(contract)* report an added path apart from a changed one
- *(policy)* refuse a landing lap taken off the task

### Fixed

- *(capture)* clear the gates verify raised, and articulate the one split-out
- *(capture)* four review findings, each a could-not-look or an undeclared emission
- *(capture)* the index writer must not destroy what it could not read
- *(mcp)* drop the redundant continue on the unreachable arm
- *(policy)* place the two modules this bundle added, and cite two rows by key
- *(engine)* [**breaking**] anchor an admission to the finding, not to the commit
- *(hook)* normalise the operand window and the substitution target
- *(hook)* stop the substitution scan failing open on a program-less element
- *(hook)* read every mediated walk per line and by resolved program
- *(hook)* resolve a program per line, so a force push cannot ride a newline
- *(hook)* decide a shape row per line, so a newline stops being a bypass
- *(landed)* [**breaking**] wire the evidence arm the port declared and never filled

### Other

- *(snapshot)* accept the golden schema the new flag moves
- *(pipeline)* move a fixture the new row now decides
- *(census)* the shape row a new gate owes an entry in

## [0.0.143](https://github.com/button-inc/batten/compare/v0.0.142...v0.0.143) - 2026-09-05

### Added

- *(cli)* [**breaking**] rename the mediation entrypoint `hook` to `adjudicate`
- *(cli)* place `show agent` in the three censuses that judge it
- *(cli)* recover the agent subtree as `show agent`
- *(hook)* [**breaking**] no Stop advisory names a write a plan-mode turn may not make (CLOUD-895)
- *(transcript)* [**breaking**] a tool result carries a keyed observation identity (CLOUD-1348)
- *(transcript)* split truncation out of StopReason::Other (CLOUD-1464)
- *(provision)* [**breaking**] name the resolver a row is turned into a binary by
- *(recorder)* [**breaking**] a row that could not answer says so, instead of writing nothing
- *(config)* name the rebuild when a config key this build cannot know fails the parse
- *(provision)* condition a bypass on the interceptor, not on a refusal
- *(startup)* [**breaking**] the container came up with no tools, and both rows said fine

### Fixed

- *(agent)* refuse to speak for a config that will not load
- *(perf)* ask each paired binary which mediation verb it declares
- *(surface)* repair four assertions the bundle's own rows inverted
- *(hook)* the unlanded nudge keys on the claim, not on a SHA its remedy moves (CLOUD-890)
- *(policy)* the infinitive hedge is the same tell, one word shorter (CLOUD-487)
- *(config)* balance the backticks and hoist the items clippy refuses
- *(config)* balance the backticks clippy reads in the skew note
- *(trust)* rank a declared arrival so a narrowing is not a weakening
- *(provision)* satisfy the lints the launcher's own code tripped
- *(policy)* strip a group's punctuation from both ends, not just the front
- *(policy)* anchor a program on `programs`, not on the first word

### Other

- *(surface)* regenerate completions, man pages and the suite cost corpus
- *(surface)* assert what a positional argument may do
- *(output)* render through the inherent method, not a clone of it
- *(output)* give the data channel one emission path
- *(authority-replay)* give the verdict axis a threshold it can read
- *(scanning)* hold row four's cell to the no-bare-product rule it claimed
- *(rules)* route a claim about what is filed to the board, as a fourth question class
- *(provision)* open each launcher spawn's annotation with its verdict
- *(policy)* the registry case reads the key its preset now anchors on
- *(policy)* give the preset fixture the key its presets now read

## [0.0.142](https://github.com/button-inc/batten/compare/v0.0.141...v0.0.142) - 2026-09-05

### Fixed

- *(policy)* unfreeze the one suite this campaign can never retire
- *(install)* bypass a proxy only when it is the thing refusing

## [0.0.141](https://github.com/button-inc/batten/compare/v0.0.140...v0.0.141) - 2026-09-05

### Added

- *(mutate)* [**breaking**] let an engine predicate declare a mutation, so "able to fail" is a command
- *(landed)* the verb, and the one exit table it takes on the way
- *(landed)* the predicate half of the board sweep, both directions
- *(startup)* [**breaking**] provision the task runner, so the setup script is one line

### Fixed

- *(doctor)* discard the store path explicitly where no symlink exists
- *(doctor)* read a pointer at an unwritten task store as zero, not could-not-look
- *(landed)* withdraw the data channel this verb could not honestly serve
- *(landed)* the four gates the new verb owed, and one vacuous assertion
- *(policy)* make seven declared mutations able to fail
- *(test)* quote the fixture's paths so a native Windows path parses
- *(test)* hoist the fmt::Write import out of the function body
- *(test)* meet the fixture-fork ratchet main landed under this branch
- *(startup)* the runner row was dead twice, both silently
- *(git)* merge the comment-marker arms clippy refuses to see twice
- *(git)* classify declaration-language comments so prose-only can see them
- *(test)* the suite's largest term is a lock wait billed three times

### Other

- *(landed)* name the module the error type lives in
- *(pointer-only)* the census entry the new verb owes
- *(surface)* the derived artifacts a new verb moves
- *(landed)* the compiled tier, over the engine rather than the predicate
- *(symbols)* gate the corrected prose, because prose-only refused it

## [0.0.140](https://github.com/button-inc/batten/compare/v0.0.139...v0.0.140) - 2026-09-04

### Added

- *(check)* a worktree registration that outlives its checkout is a finding
- *(commit)* an escape hatch is not spent by the commit that creates it
- *(doctor)* [**breaking**] read the container's own proxy values, not the ones mise fixed
- *(policy)* compare what we publish against what a provision row can serve
- *(claim)* [**breaking**] retire claim-race-check onto `batten claim race`
- *(race)* decide a claim race by head SHA, not by a branch name
- *(facts)* [**breaking**] supply the instant a declared max_age is read against
- *(facts)* a supplied instant, so a lease predicate is expressible
- *(policy)* refuse an unreadable cache key and an uncached cargo job

### Fixed

- *(policy)* correct two stale predictions and drive the missing channel for real
- *(policy)* name a real case in every test-targets mutation row
- *(policy)* refuse the second shape cargo autodiscovers, and ratchet fixture forks
- *(test)* give each advisory case its own bench
- *(test)* make the advisory bench its own repository root
- *(test)* own the premise these advisory cases were inheriting from the session
- *(check)* spell the worktree verdicts from a word the dictionary declares
- *(mcp)* a JSON-RPC refusal carries the message the server is required to send
- *(policy)* obligations-bound reads the separator its own recorder writes
- *(commit)* the mutation row goes where the gate reads it, and no consumer artifact reaches the core
- *(semver)* the lock route replaces both sides, so a moved registry cannot silence the gate
- *(policy)* the module pins its own predicate, and the allowlist literal sorts
- *(policy)* the commit that deletes the fence is refused, and the shell gate is left alone
- *(policy)* demand a cache guard only where a cache exists
- *(capture)* carry `project` through the get_issue projection
- *(claim)* answer claim-not-raced from the tree, not the installed binary
- *(ci)* five land-blocking defects CI could see and no local gate could
- *(hook)* drop the line-count expectation main's move made unfulfilled
- *(task)* assert the Windows reclaim contract instead of the unix one
- *(cli)* regenerate the completions and corpus the rebases deferred
- *(spec)* declare the eleven new rows, and move the fact census count
- *(rules)* merge the rebase's three list regions instead of concatenating them
- *(rules)* hand the boundary's clock in, rather than reading one in the projection
- *(cli)* give the task and singleton rows the stable id main now requires
- *(ci)* qualify the one case title two retiring suites shared
- *(policy)* name the renamed verdict token, and move the arm count's third authority
- *(ci)* keep batten-check on x64, and key the warmed family by architecture
- *(policy)* revive ci-parity, which was silent over this repository's own tree

### Other

- *(suite)* copy a git template per fixture instead of forking init
- *(pointer-only)* classify `claim race` in the verb census
- *(ci)* [**breaking**] retire singleton onto the task noun's lock verbs
- *(ci)* [**breaking**] retire task-registry onto the task noun's writer verbs
- *(ci)* [**breaking**] retire alive onto the task noun, and record why its writer cannot follow
- *(ci)* [**breaking**] retire ready-guard onto the ready-needs-receipts row
- apply the formatters to this branch's own new and changed files

## [0.0.139](https://github.com/button-inc/batten/compare/v0.0.138...v0.0.139) - 2026-09-03

### Added

- *(wiring)* delete the exemption table, and the three directions that policed it
- *(environment)* let the environment say whose $HOME this is
- *(policy)* report a presence probe that asks the bare PATH about a pinned program
- *(doctor)* report the declared evidence capability
- *(spec)* admit `doctor mediator` to the read-only allowlist and the row set
- *(doctor)* add `doctor mediator` — which engine the registrations reach
- *(policy)* switching a gate off for a call is a decision, not a flag
- *(config)* declare where this host keeps the session task store
- *(doctor)* [**breaking**] give "is this session safe to end" a verb, so it stops being estimated
- *(facts)* [**breaking**] an extraction the host cannot answer says so, instead of answering zero
- *(facts)* price a call the session has already made, as a maximum not a total

### Fixed

- *(refusal)* the census annotation opens with its verdict
- *(resolve)* attribute the refusal ceiling, which every resolved key owes
- *(hook)* the declared ceiling bounds a first sighting, not only a repeat
- *(hook)* a first sighting carries every route, not the first one declared
- *(hook)* [**breaking**] a declared refusal explains itself once per session
- *(rules)* keep the analyser on the eager door, and pin the zero-spawn bound
- *(rules)* reach the analyser through the LAZY door too
- *(pinned)* recover a record that stops existing mid-session
- *(cli)* [**breaking**] a narrowed `enforce` still answers for the defect ledger
- *(doctor)* state the blind spot `doctor mediator` has, and pin it
- *(test)* the perf-assert tier reports a dead gate instead of passing over it
- *(test)* the cost bound is a step-change detector, not a machine reading
- *(test)* read the perf budgets from the module the gate retired onto
- *(test)* name the retired bats cases exactly, and record the one this row inverts
- *(test)* seed the README the committed perf-assert row declares, and use write!
- *(transcript)* the tilde expands by substitution, not by a platform path join
- *(test)* the posture cases read the real session's findings store
- *(policy)* the claim-order row judged a tree that never made the split
- *(claim)* state the order the receipt already required, and stop inviting the second claim
- *(ci)* cache the perf base arm on a path that holds still across a rebase

### Other

- *(hook)* bundle what a refusal line needs, rather than widening a limit
- *(hook)* measure the ceiling on prose, which is what actually reaches it
- *(snapshot)* accept the golden schema carrying both new doctor sub-verbs
- *(stop-posture)* isolate every case, not only the one asserting silence
- *(test)* assert one rule with one rule — the third and largest of the family
- *(stop-posture)* isolate the one case that asserts silence
- *(snapshot)* accept the golden schema for `doctor mediator`
- *(pointer-only)* classify `doctor mediator` as pointer-only
- *(doctor)* pin `doctor mediator`, including the arm that refutes its old placement
- *(hook)* a refused write says what the engine did, not just that it did not
- *(cost)* the cost reading's rung and answer channel are gated, not argued
- *(ci)* the perf budget is a rule, not a shell program
- *(policy)* build the ledger index only when a deletion needs it, and gate the term
- *(transcript)* the test helper stops hiding which cases are about an absent home
- *(pointer-only)* the session verb reads real prose, then declines to print it
- *(spec)* state the new sub-verb in the two lists that must be stated
- *(surface)* regenerate the derived artifacts for the new sub-verb
- *(doctor)* pin the session verb, and prove the could-not-look arm can fail
- *(facts)* the recorded kinds are a set, not four booleans
- *(facts)* [**breaking**] land the loop predicate as the family's own, on trailing-run adjacency

## [0.0.138](https://github.com/button-inc/batten/compare/v0.0.137...v0.0.138) - 2026-09-03

### Added

- *(land)* the lap runs the consumer's own gate, and spawns nothing to do it
- *(land)* the lap pushes its own branch under receive-pack's compare-and-swap
- *(land)* the lap asks its two questions in one loop and acts on one answer
- *(policy)* a lap acts on one answer from its race, never on both
- *(land)* `batten land replay` and the tier that joins the writer to the reader
- *(land)* the lap's replay half, in process and deciding nothing
- *(policy)* a lap whose replay conflicted does not continue
- *(hook)* the advisory channel reaches a second harness
- *(policy)* a backgrounded wait that polls a local process is refused
- *(ready)* a refinement block owes a dispatched pressure test
- *(policy)* the declared review becomes a gate, and an absent runner is not guilt
- *(facts)* [**breaking**] a vendored prompt's dispatch becomes a fact the tree can read
- *(startup)* declare what a container must be, and repair it
- *(mcp)* [**breaking**] refuse the raw tracker read, and give its remedy a name that resolves
- *(mcp)* the dispatch boundary mints the receipts the hook path mints
- *(enforce)* narrow the spawning verb too, for the caller `check` cannot serve
- *(gitwrite)* replay a branch onto a moved base, and refuse the conflict
- *(gitwrite)* put a fetched object in the odb and move a ref, in a module that admits it writes
- *(lease)* resolve pack deltas and fetch a ref, which the lease path never needed
- *(git)* enumerate a branch's objects, and push one over receive-pack
- *(lease)* garbage stops being indistinguishable from a hold, and the gate that reads it
- *(lease)* the heartbeat learns the two ways a holder stops being one
- *(lease)* the nine arms as a verb, and the exit table they now answer to
- *(lease)* observe, swap, and the four bodies a lease is ever minted as
- *(lease)* the lease body and the one question a runner can ask
- *(lease)* read the lease body, mint one, and take gix's framing rather than a second one
- *(lease)* speak the CAS over the client already in the closure
- *(policy)* wire the lease record, so consumer #1 eats this food too
- *(policy)* a blind push is the bare lease, not the flag
- *(policy)* the leased push is the spelling that destroys a sibling's commit
- *(record)* a verb writes the closes record, so the exemption can fire
- *(policy)* a declared obligation names a case, or it is not landing
- *(facts)* one definition of an issue key, and a gate on the twenty-first
- *(ready)* a test obligation's mutation names a slug, not a sentence
- *(hook)* a host's plan surface is surveyed, unsurveyed, or measured none
- *(policy)* the plan a branch declared, held to its own end
- *(ready)* the prose dialect becomes a legacy, on a declared cutover
- *(policy)* the punt sweep gets an exit code
- *(rules)* let a receipt row accept any one of several receipts
- *(claim)* attest a licence-carry branch, so the lane needs no fake claim
- *(carry)* decide whether a licence-carry branch is derivable, offline
- *(fetch)* pair the HTTP method with its body, so PATCH becomes expressible
- *(policy)* remove the two launcher hooks, and refuse their return
- *(policy)* a declared exemption whose owning issue has closed is now refusable
- *(facts)* [**breaking**] project one field of an already-minted receipt onto the tree
- *(policy)* the could-not-look channel carries WHY, not just which
- *(preset)* one manifest per preset, instead of three tables and four exemptions
- *(spec)* [**breaking**] version the emitted spec and give every command a stable id
- *(state)* an event-anchored finding can finally be answered
- *(policy)* a remedy resolves to a declared command or rule
- *(hook)* one budget for the advisory channel, not per producer
- *(hook)* a generic read of a memory names the tool that answers it
- *(policy)* read a bats suite's lines, and admit the case that dies with its subject
- *(hook)* retire session-start.sh into ten declared handler rows
- *(mutate)* regenerate the derived artifacts across the mcp rebase
- *(mutate)* regenerate the golden schema and correct the noun's effect in prose
- *(mutate)* state the new surface rows where the spec is declared by hand
- *(mutate)* a spawning-side verb whose gate suite is a DECLARED path
- *(recorder)* [**breaking**] the lease judgement, and the one primitive it needed
- *(policy)* the second landing judgement, named for the fact that answers it
- *(policy)* the file-granularity half of the port-without-retirement arm
- *(policy)* a fifth conserves arm for a port without a retirement
- *(facts)* build the producer the two verdict stores never had
- *(policy)* the generic third of a landing loop, as a vendored preset
- *(mcp)* [**breaking**] expand `${VAR}` in a source path, and declare the session wiring (CLOUD-1251)
- *(mcp)* [**breaking**] give the engine a credential it can spend (CLOUD-1261)
- *(commit)* carry the articulation in the commit message, so an override leaves a trail
- *(hook)* [**breaking**] the bypass variable no longer opens the protected-path gate
- *(hook)* make a mediated refusal admissible, so the password can stop being the only way through
- *(mcp)* reduce a write to an acknowledgement instead of the echoed body
- *(mcp)* [**breaking**] dispatch a declared MCP call and hand back a reduction

### Fixed

- *(cli)* restore what a whole-file conflict resolution discarded
- *(policy)* a declared mutation names a case its suite has, asked where a contributor sees it
- *(policy)* the wait predicate was a dead gate, and only the compiled tier could see it
- *(land)* the fixture config declares its version, and the census classifies the new leaf
- *(hook)* mint the completion verdict before any rule can return, and rank it first
- *(config)* the merged-sibling refusal names the verb that clears it
- *(policy)* repoint the could-not-look clause at the cause it can reach
- *(policy)* gate AGENTS.md's branch clause against restatement in tree prose
- *(test)* a Windows path is not a TOML escape, and a stub that cannot run is not a pass
- *(policy)* the stale guard's case took the arm its mutation does not touch
- *(policy)* two harness-wiring mutations reached nothing, for two reasons
- *(facts)* the census count and the module's placement, both missed by a replay
- *(review)* the prompt went down a channel a real runner ignores
- *(review)* the dispatch sent a prompt and no subject
- *(rules)* bound the pin rung to names PATH cannot resolve
- *(symbols)* [**breaking**] reach the analyser through the pin, not through bare PATH
- *(obligations-bound)* judge the rows the pull request lands
- *(obligations-bound)* decide over the latest recorded line, not the history
- *(startup)* [**breaking**] check that the engine READS the authority, and retire the two spent declarations
- *(hook)* withdraw `exclusive`, whose zero count was an artifact of the measurer
- *(surface)* the golden's `rule` flag was one field short of the binary
- *(surface)* accept the golden schema for `enforce --rule`
- *(ready)* read a plain clause label as the clause it is
- *(perf)* keep the consumer's CI paths out of the core's doc comment
- *(recorder)* partition the verb-written records too, and never the claim itself
- *(lease)* the liveness probe is /proc's, and Windows CI is what said so
- *(surface)* the lease rows carry the stable id main added, and the snapshot is regenerated
- *(lease)* a clone with no remote is an answer, not a failure to look
- *(gitwrite)* the worktree write assumed Unix, and the whole library stopped compiling for Windows
- *(semver)* [**breaking**] the refusal names a lint class, and the author needs the instance
- *(gitwrite)* the unfiltered path is the common one, and it was being refused
- *(lease)* a pack member is not always a commit, and only a live run said so
- *(recorder)* partition a record by the claim, not by the branch name alone
- *(surface)* the new rows carry the id main gave every CommandDecl
- *(claim)* the prose-dialect cutover reaches the gate that starts the work
- *(claim)* a carried row keeps the weakening it groomed
- *(claim)* one branch carries as many claims as it has rows
- *(rules)* declare `checks_any`'s fact, and split the two long assertions
- *(ci)* keep the reclaim body inline-shaped and annotate its spawns
- *(ci)* report the reclaim verdict once per boot, not once per session
- *(mutate)* the sweep's cargo cache is its own, never the repository's
- *(policy)* recombine the wiring halves, and withdraw the defect that split them
- *(verdict)* a lane refusal names which head it could not see tested
- *(config)* [**breaking**] a config fault names the table that would not load
- *(policy)* explain a class when the config cannot be read
- *(policy)* a module's finding takes its remedy from the class it raises
- *(hook)* ask Path whether a spill is absolute, rather than one platform's spelling
- *(hook)* recover an intercepted read so the receipt it owes can mint
- *(test)* declare the grouped module whose three cases never ran, and gate it
- *(trust)* a verdict rename is not a hatch newly added
- *(config)* restore the pattern id the rename sweep hit, and declare two renames
- *(verdict)* convert fixture registry ids to the three-word grammar
- *(verdict)* convert the classes main added after the grammar landed
- *(hook)* bound what a session's hooks cost it, and make a repeat decidable
- *(receipt)* a branch behind its own receipt is not a restart
- *(rules)* derive the mediated column refusal from the fact model
- *(hook)* [**breaking**] a bare directory destination is inside the protected set
- *(hook)* resolve a relative operand against the caller's cwd, and stop asserting tracked-ness
- *(hook)* verb and operand attribution stops at a newline
- *(hook)* the hot path emits a class and its pointers, and stops
- *(hook)* every mediated deny carries a declared class
- *(policy)* make the stays-bash route clear the verdict that offers it
- *(verdict)* convert every refusal class to the declared three-word grammar
- *(verdict)* measure the single-token dictionary the verdict grammar needs
- *(policy)* declare the third ported mutation, and drop two numbers that drift
- *(test)* two defects this branch's own verify found, and both were mine
- *(policy)* hold a restated arm count and the schema key set to their mechanisms
- *(prune)* a capped floor measures the volume, so it re-measures
- *(rules)* let a row declare the format its extension cannot name
- *(rules)* let a module say what it could not look at
- *(ci)* a comment quoting the ratchet's pattern incremented the ratchet
- *(gate)* decide a weakening's admission in the verb, on three states not two
- *(board)* mint the weakens line the claim port dropped
- *(test)* write the fixture config through fmt::Write
- *(mutate)* resolve a declared suite without naming a cargo target
- *(mutate)* gate the bats fixture constants with the arm that reads them
- *(mutate)* gate the bats arm on unix, where the vendored runner can run
- *(mutate)* count could-not-look apart from uncaught in the sweep summary
- *(mutate)* place the new module, carry the fixture arms, and leave graph-check alone
- *(mutate)* resolve the lent runner inside the arm that can use it
- *(mutate)* repair seven declared mutations the first reachable sweep found broken
- *(test)* repoint the ported ledger arms at the it/ test home
- *(test)* bound the ported cases to the platform their subject runs on
- *(test)* open each ported spawn annotation with its inventory verdict
- *(exec)* give the two pipe drains one shared deadline budget, not one each
- *(ci)* the pending-snapshot gate was blind to half its own subject
- *(spec)* state the record verbs in the committed row set and the golden schema
- *(policy)* refuse a wrong-surface read in both directions, and stop the fixtures leaning on the hole
- *(policy)* judge a mediated module's tree reads too, closing CLOUD-845's class
- *(ci)* collapse the deps tasks to one-line shims and clear two lint slips
- *(hook)* report a session whose SessionStart registration never ran
- *(hook)* stop advertising a hatch that no longer opens this class

### Other

- *(gh-guard)* ask about the row, not the aggregate, for `gh pr create`
- *(perf)* [**breaking**] retire perf-compare and perf-gate onto the perf verb
- *(provisioning)* declare session-wiring in the roster that enumerates it
- *(harness)* isolate the state root for the suites whose subject is the real repository
- *(hook)* derive the mediation path in the two tests that pinned it
- *(hook)* derive the mediation argv from the SURFACE row
- *(tools)* the validator row stops advertising a gap that was closed
- *(review)* the untouched-subject case could not see the narrowing it names
- *(toolchain)* withdraw the replay harness, which never had a consumer
- *(test)* name the two narrowed rule sets once rather than at four sites
- *(surface)* regenerate the derived artifacts for the repeatable --rule
- *(test)* assert six rules with six rules, not with all 103 — twice over
- *(ci)* retire sbom-check onto the tool-verdict family
- *(ci)* retire hook-latency-drift onto the workflow step it always was
- *(cli)* [**breaking**] give `enforce` a flags struct, so its next flag is additive
- *(test)* assert one rule with one rule, not with all 103
- *(perf)* key the base arm on its merge base and carry it between runs
- *(git)* the backend belongs to three named modules, and the resolver gate stops standing in for that
- *(policy)* the engine tier cannot build an empty delta, so say so
- *(ci)* admit a task-name span in the retirement repointing arm
- *(rules)* drive the receipt alternation over the compiled binary
- *(bot)* gate the bot lane suite on unix, where its stub can run
- *(ci)* [**breaking**] retire bot-issue onto the engine, and wire the carry receipt
- *(fetch)* drop the PATCH payload, whose premise did not survive the port
- *(ci)* conserve the 42 cases inside unit 9's retired suites
- *(ci)* write unit 9's retirement ledger, and drop a now-unused import
- *(policy)* exercise the empty exemption table, which nothing reached
- *(ci)* retire run-shape-guard, and declare the hook surface exclusive
- *(verdict)* measure the condition word the table now declares
- *(policy)* one receipt closes both rows that name its owner, not the first
- *(ci)* retire ci-drift onto the verb it was already calling
- the extension guide names all ten rule kinds and how to reach a preset
- *(verdict)* prove a native class is raised rather than exempting it
- *(findings)* the acceptance clauses I skipped while calling three rows done
- *(rules)* [**breaking**] a finding records its owner instead of being looked up
- *(hook)* pin the second interpreter residue, which had no case at all
- *(ci)* retire hooks-wiring-check onto the two authorities it was the seam between
- *(tests)* retire the fact-record-keying suite onto the compiled binary
- *(agents)* a board state is a claim about the tree, and the tree wins
- *(ci)* [**breaking**] retire lock-complete onto the index it always meant to read
- *(ci)* retire unlanded-check onto the engine that mints its verdict
- *(ci)* retire config-lint into the verb it already called
- *(policy)* bind the case fixture the way a suite actually binds it
- *(policy)* declare the landing-loop preset's mutation, which main added under the widened census
- *(ci)* [**breaking**] retire the mutation runner onto `batten mutate`, and put the Rego layer into the enforced set
- *(ci)* [**breaking**] port helpers and pre-commit-staging off the bats lane
- *(harness)* group 144 integration test targets into two, and ratchet the count
- *(harness)* fold Fixture::git to one process and drop a rename that already held
- *(test)* memoize the harness's three re-reads of the committed config
- *(build)* store dev debuginfo unpacked, and pin the opt-level that was unpinned
- *(ci)* retire rules-drift onto the policy engine
- *(ci)* retire gh-guard and memories-check onto the policy engine
- *(ci)* retire three validator wrappers into the rows meant to decide
- *(hook)* assert session isolation directly, not the absence of every advisory
- *(hook)* pin that a registered module's refusal names a route, not a memory tool
- *(hook)* prove a spent admission opens the gate, over the compiled binary
- *(facts)* decide the runtime-discovered out-of-root set, and correct its premise

## [0.0.137](https://github.com/button-inc/batten/compare/v0.0.136...v0.0.137) - 2026-08-31

### Added

- *(policy)* make a retirement declare whether engine source is a verb or mechanism

### Fixed

- *(deps)* drop the three bumps this repository has already decided against
- *(test)* the vendor-symlink arm is could-not-look off unix
- *(test)* carry the pid in the declared lane, not on every scratch path
- *(test)* make the shared scratch root per-process, not just per-case
- *(ci)* give the four retired-gate tiers a process-unique scratch root
- *(policy)* let a retirement name the DRY home, and say which home is which
- *(prune)* the escalation spends the undo hedge before it takes the basis
- *(prune)* [**breaking**] Outcome grows report flags, so declare it non-exhaustive
- *(prune)* retire the observations a superseded reading took
- *(prune)* the escalation opens on the floor in force, not the declaration
- *(prune)* reclaim a nested cargo build tree, which no consumer can name

### Other

- reformat under the prettier and shfmt the same change bumps
- *(ci)* declare kind:mechanism on the eight retirement arms
- *(ci)* satisfy the workspace lints in the skill contract tier
- *(ci)* retire config-deprecations, reference-check, schema-check and skill-check
- *(prune)* the superseded-reading discard, over the compiled binary

## [0.0.136](https://github.com/button-inc/batten/compare/v0.0.135...v0.0.136) - 2026-08-31

### Added

- *(rules)* [**breaking**] decidability is the bar to block, not computability
- *(cli)* [**breaking**] close `resolve::Overrides` to outside construction
- *(cli)* say which repository supplies the committed authority
- *(policy)* admit dropping a retired name from a list
- *(ready)* say when a clause label lost the emphasis its anchor needs

### Fixed

- *(harness)* grant the auto-mode classifier what permissions.allow cannot
- *(tests)* annotate the spawn the hatch fixture needs
- *(prune)* the basis reads cargo's own profiles, not every nested tree
- *(prune)* a lap's closing floor is the basis of the tree it left
- *(prune)* a built profile with no `deps` left is cold, whichever others survive
- *(prune)* name the journal when the floor in force is one the tool learned
- *(ci-hygiene)* inline the preset's patterns — a preset cannot read the registry
- *(ci)* scope the concurrency-group rule to triggers that race one subject
- *(rules)* apply the default the previous commit only described
- *(rules)* the fail-safe is an unclassified KIND, not an unattributable finding
- *(design)* keep the decidability bound off findings that carry no rule kind
- *(hook)* carry the root through the policy-module fixture too
- *(hook)* judge a Bash operand by the path the repository names
- *(cli)* build `Overrides` the way an outside crate now has to
- *(hook)* let a hand-written row outrank a module over the same call
- *(test)* keep the replay corpus under the line limit and off Windows
- *(test)* gate the divergence inventory on the platform that can observe one
- *(build)* keep line tables for workspace code — `debug = 0` sold the wrong thing

### Other

- *(hook)* a child that exits before reading stdin is not a write failure
- *(hook)* let the serializer render the fixture's path
- *(hook)* the suite's own environment cannot disarm the engine it tests
- *(prune)* the escalation is its own function
- *(ci)* port the foreign-cargo spelling predicate onto the policy engine
- *(ci)* retire ci-local-parity, with 101 conserved cases
- *(ci)* port the lease, green-predicate and bot-watcher properties
- *(ci)* add the ci-hygiene wiring module, seven more ported properties
- *(ci)* land ci-parity, the consumer half of ci-local-parity
- *(ci)* land the ci-hygiene preset, the generic half of ci-local-parity
- *(ci)* retire derived-check and man-pages onto the Rust tier
- *(rules)* move the approximating bound where it can be reached
- *(rules)* classify against the real table, and pin the fail-safe on purpose
- *(rules)* assert the contained failure on the data channel too
- *(hook)* spell an absolute operand the way a caller types one
- *(transcript)* key the injection fixture on the process, not just the seat
- *(cli)* accept the spec snapshot for `--config-in`
- *(policy)* discriminate the list-drop join with a declared mutation
- *(ready)* pin the unanchored-clause rule against the corpus it must not widen
- *(ready)* compare the emission its consumer reads, and inventory the divergence
- *(toolchain)* take back the Ready-grammar retirement, whose successor cannot spell a sibling
- *(toolchain)* retire the replay arm with the program it compared against
- *(toolchain)* retire the second Ready grammar so the split token reaches its consumer
- *(bench)* retire 596 lines of Python out of `bench/` — the ratchet's scope is shell, the rule is no spaghetti
- *(bench)* drop the four-term harness — its premise did not reproduce
- *(build)* drop dev debuginfo — 9.4x off the linked test artifacts, measured
- *(bench)* report the Rust suite in four terms, and refuse to name the fourth
- *(rules)* take the cost census off `Scan`, where `semver` was right to refuse it
- *(rules)* gate the per-rule cost census, and show it able to fail
- *(policy)* memoize two per-path scans that were being re-run once per line
- *(rules)* compile a forbid row's matcher once per rule, and report what each rule cost

## [0.0.135](https://github.com/button-inc/batten/compare/v0.0.134...v0.0.135) - 2026-08-31

### Added

- *(rules)* [**breaking**] contain an erroring gate, and let a rule declare its inputs
- *(policy)* let a retirement declare what its callers now run
- *(facts)* [**breaking**] declare the API break ten fact families make
- *(facts)* count typed transcript events, never a byte of the session
- *(hook)* move the manifest read to session start, and keep `Document` None
- *(policy)* reduce the capture store, so a board predicate can be a module
- *(facts)* read a third-party tool's verdict from a triple-keyed record
- *(facts)* read the forge's verdict from a keyed record, never a socket
- *(facts)* resolve a declared history PATTERN, not just a named ref
- *(facts)* the git index bytes, and the engine's own finding store
- *(policy)* project a declared range's commit identity fields, never its body
- *(facts)* project a declared, bounded file outside the repository root
- *(cli)* [**breaking**] let the caller's known change-set narrow `check`
- *(config)* ratchet the two shell surfaces the census never counted
- *(policy)* give rule 1 a mechanism for the class, not four literals
- *(ready-lint)* read the checkable half as data, and refuse a claim that is absent

### Fixed

- *(policy)* drive the suite-subject tier through the engine, and correct 18 to 19
- *(policy)* report a bats suite whose subject no retirement can delete
- *(rules)* let a contained failure still say what went wrong
- *(prune)* cap the ratchet at what the lap that set it left free
- *(exec)* name the sweep's bound so the delay inventory can resolve it
- *(exec)* annotate the forwarder's polls under the new delay inventory
- *(exec)* declare `received` dead on windows rather than warned
- *(exec)* escalate on a second signal, arm before the spawn, die of it
- *(hook)* a refusal outranks advice about the same call
- *(ci)* name the suite where verify can see it, and derive the fixture's job
- *(ready)* declare the grammar in CLOUD-453's fixture, so its cases judge a block
- *(policy)* keep CLOUD-453's structured claims path alive across the grammar move
- *(policy)* carry CLOUD-1113's widened claim opener into the registry row
- *(policy)* thread the resolved grammar through the boundary CLOUD-1100 landed
- *(pattern)* assemble the known-bad expression, so clippy can still read the file
- *(prune)* escalate in two tiers, and reach for the basis only if still short
- *(prune)* [**breaking**] report the escalation from the basis it created, not the one judged
- *(prune)* [**breaking**] refuse an undeclared basis on the verify surface, not at load
- *(prune)* read the basis from the tree, not only from this run's escalation
- *(prune)* judge a closed lap on the basis it ran under, not one its own close created
- *(prune)* [**breaking**] record the basis each floor was measured against, not only the date
- *(prune)* close the lap the floor was read at the start of, and ratchet it
- *(prune)* group artifacts by (stem, kind) and declare the escalation's roots
- *(ready-lint)* split the bump fact, so a non-releasing type can still land a commit
- *(rules)* count a ratchet at the merge base, not at the declared tip
- *(ci)* qualify the two ledger arms both dying suites claimed
- *(ready-lint)* read every spelling of a blocker claim, not just the one with no space

### Other

- format the new rego and test cases
- *(policy)* pin the sibling and invocation arms in both tiers
- *(contract)* take the spec's reordering from main
- *(contract)* take the spec's growth, and stop the accept task leaving residue
- *(contract)* freeze the machine surface as bytes, and give it an accept task
- *(exit)* assert the disposition to exit-code mapping is total, by enumeration
- *(exit)* pin exit 3 in the one table, and retire the comments that said it was unreachable
- *(cli)* [**breaking**] rename `ci wait` to the declared `pr watch`, and keep Unclassified
- *(transcript)* give each fixture read its own scratch directory
- *(exec)* wait for the group note before killing the Batten that wrote it
- *(exec)* pin the signal contract, and record the clause that cannot hold
- *(lint)* ban a sleep, and make every delay in the crate name its bound
- *(gate)* retire prebuilt-lint's bats tier onto the engine
- *(ci)* give the shell suite its own runner, and gate the carve-out that lets it
- *(pattern)* validate a declaration by parsing it, not by building its matcher
- *(policy)* [**breaking**] move the Ready grammar out of the core into the pattern registry
- *(prune)* state the profile bound on the tree's basis reading
- *(ci)* [**breaking**] retire ci-wait, the one reader that could not be repointed
- *(ci)* [**breaking**] retire checks-green, with an arm for every case it pinned
- *(ci)* conserve every case the dying suite pinned, and declare the verb
- *(ci)* give the green verdict a verb, and an exit table that fails safe
- *(ci)* port the green-verdict decision to the engine

## [0.0.134](https://github.com/button-inc/batten/compare/v0.0.133...v0.0.134) - 2026-08-30

### Added

- *(config)* [**breaking**] let a tombstone name a reason instead of a successor
- *(policy)* [**breaking**] decide the Todo promotion at the boundary, from a verdict already in hand

## [0.0.133](https://github.com/button-inc/batten/compare/v0.0.132...v0.0.133) - 2026-08-30

### Fixed

- *(rules)* stop asserting which regorus builtins this build carries

## [0.0.132](https://github.com/button-inc/batten/compare/v0.0.131...v0.0.132) - 2026-08-29

### Fixed

- *(hook)* render a normalised write target in git's separator
- *(hook)* [**breaking**] an unclassified program on a protected path fails closed
- *(hook)* a PreToolUse advisory reaches the agent, measured rather than assumed

### Other

- *(config)* make "never a silently-wrong value" decidable
- *(policy)* prove the engine builds the input the advisory reads

## [0.0.131](https://github.com/button-inc/batten/compare/v0.0.130...v0.0.131) - 2026-08-29

### Fixed

- *(fetch)* honour the proxy, the host CA, and redirects, as curl did
- *(fetch)* let the test module panic loudly, as provision's already does
- *(provision)* a timed-out fetch is exit 3, not a usage error
- *(provision)* fetch over https in process, and bound the wait

### Other

- *(provision)* extract the fixture's key material into its own helper
- *(provision)* restore the host-CA clause, on SSL_CERT_FILE

## [0.0.130](https://github.com/button-inc/batten/compare/v0.0.129...v0.0.130) - 2026-08-29

### Added

- *(config)* [**breaking**] carry a source class beside every resolved contributor
- *(board)* put the two board verbs on every census the surface carries
- *(board)* resolve a captured payload by the key it carries

### Fixed

- *(cli)* append the two new enum variants rather than placing them by meaning

### Other

- *(config)* pin the class, the boundary, and the base-ref reading
- *(receipt)* assert the claim contract over minted bytes, not over a shell grep
- *(board)* restore ready-lint's shell arm, and say why its retirement stops here
- *(board)* retire claim-check into the engine
- *(board)* carry claim-check's 76 cases onto the compiled binary
- *(board)* carry ready-lint's 82 cases onto the compiled binary
- *(board)* port the claim predicate to Rust, and re-point two census bounds
- *(deps)* resolve a links-free HTTP client, below reqwest rather than with it
- *(board)* port the Ready-block grammar to Rust, and vendor the HTTP client

## [0.0.129](https://github.com/button-inc/batten/compare/v0.0.128...v0.0.129) - 2026-08-29

### Added

- *(wiring)* [**breaking**] the repair that cannot eat its own evidence
- *(hook)* [**breaking**] a handler may spend a grant the operator already wrote
- *(handler)* a dispatched program is a debt, and now it names its creditor
- *(hook)* [**breaking**] a consumer may declare its hook surfaces exclusively batten's
- *(doctor)* [**breaking**] the merged census answers "is there a hook here that is not mine"

### Fixed

- *(tests)* the fixture's dispatched helper reads the binary under test
- *(tests)* the isolation guard reads the real home in both spellings too
- *(tests)* the fixture home is set on Windows too, not only on POSIX
- *(tests)* backtick `SessionStart` in the run_hook doc
- *(tests)* `run_hook` writes its own authority instead of inheriting the repo's
- *(test)* the two door suites stop defining a second repo-root resolver
- *(test)* hoist the door helper's import, which `-D warnings` reads as an item after statements
- *(test)* the two door tiers type-check on Windows, where there is no executable bit
- *(policy)* place `wiring` in the layer table, and un-cross two rules in one fixture
- *(wiring)* four review findings, two of them the defect this branch removes
- *(hook)* the strongest matching policy row decides, not the first
- *(hook)* read a write target as the repository reads it
- *(hook)* a mediated policy row's severity column decides whether it refuses
- *(policy)* a complete ledger is an additional obligation, not a substitute

### Other

- *(door)* gate both door suites on unix, where their handler can run
- *(door)* the same treatment for `run-shape-guard`'s tier — the defect asserted, the hop stubbed
- *(door)* assert the connector guard's measured defect, and stub the cases that are about the door
- *(hook)* the guards this branch cannot retire, it does not touch
- *(door)* the three door tiers move to Rust, and the corpus falls instead of growing
- *(rules)* the two-shapes retirement rule binds where a reader meets it

## [0.0.128](https://github.com/button-inc/batten/compare/v0.0.127...v0.0.128) - 2026-08-29

### Added

- *(prune)* [**breaking**] judge the disk floor against the build the reclaim just created

### Fixed

- *(prune)* stop the walk at a symlink, and close five review findings
- *(prune)* escalate on the cache being gone, not on how large it was

### Other

- *(prune)* map_or in the suite's survivor count
- *(prune)* pin the calendar branch, and stop the ledger overclaiming

## [0.0.127](https://github.com/button-inc/batten/compare/v0.0.126...v0.0.127) - 2026-08-29

### Fixed

- *(perf)* retire perf-pair into the engine, and let its skip see the config
- *(tasks)* make `mise run fmt` the formatters-only subset it is documented as
- *(hook)* [**breaking**] report a pinned program reached around the pin

### Other

- *(perf)* measure tree-surface acquisition and move the row it gates
- *(ci)* re-sweep the pole at the runner's width, and retire its gate onto the engine

## [0.0.126](https://github.com/button-inc/batten/compare/v0.0.125...v0.0.126) - 2026-08-28

### Fixed

- *(engine)* [**breaking**] consult the admission store, so a spent override actually admits

### Other

- *(toolchain)* hold the fmt description to its task body, and revert the shell-gate edit

## [0.0.125](https://github.com/button-inc/batten/compare/v0.0.124...v0.0.125) - 2026-08-28

### Added

- *(hook)* model heredoc binding, and decide the three shapes it unblocks

### Fixed

- *(test)* a replay row named a pre-rebase sha, so replay refused every row
- *(hook)* carry `run_in_background` into the policy input, as CLOUD-834 said it would

### Other

- *(gate)* retire mise-pin-agreement's shell tier
- *(policy)* assert what the engine emits, not what a renderer might
- *(policy)* migrate mise-pin-agreement onto the tree surface

## [0.0.124](https://github.com/button-inc/batten/compare/v0.0.123...v0.0.124) - 2026-08-28

### Fixed

- *(policy)* [**breaking**] project the segmentation the engine already computes
- *(test)* assert rather than panic in the replacing-guard case
- *(mise)* propagate the engine's verdict out of batten-check

## [0.0.123](https://github.com/button-inc/batten/compare/v0.0.122...v0.0.123) - 2026-08-28

### Added

- *(policy)* [**breaking**] the withdrawal arm at file granularity, because one ledger has two readers
- *(rules)* a fourth conserves arm for a withdrawal, and delete the wrapper it unblocks

### Fixed

- *(rules)* [**breaking**] a row's sink counts the findings its own module reported

## [0.0.122](https://github.com/button-inc/batten/compare/v0.0.121...v0.0.122) - 2026-08-28

### Added

- *(facts)* [**breaking**] count a tool result's matching elements, and the conditions beside them

### Fixed

- *(facts)* [**breaking**] a fact names the call it answers, not only the tool

### Other

- *(config)* the tool-sourced review checks are added rows, not an edit

## [0.0.121](https://github.com/button-inc/batten/compare/v0.0.120...v0.0.121) - 2026-08-27

### Added

- *(policy)* [**breaking**] semver.sh retires, and the gate it leaves behind reads the lock
- *(cli)* [**breaking**] `batten semver check`, and the gate answers again
- *(semver)* the compatibility gate becomes an adapter, with a baseline the lock can build
- *(policy)* [**breaking**] the review-answered suite retires, and the edit arm learns truncation
- *(hook)* [**breaking**] the end of turn becomes the engine's, and stop-guard.sh retires
- *(policy)* [**breaking**] CLOUD-514's two refusals become a module, and the shell pair retires
- *(facts)* the recorder's record becomes a tree fact, so a gate can read it
- *(cli)* [**breaking**] an admission is spent, which is what makes the bare variable stop working
- *(policy)* the Stop moment reaches a module, so its rules can be Rego
- *(recorder)* [**breaking**] the board-write record becomes a declaration, and three defects it hid
- *(recorder)* a record's shape is the consumer's, and its column may be a gate's verdict
- *(policy)* [**breaking**] prose-only-check becomes a rego row, and check learns --rule
- *(receipt)* [**breaking**] an override becomes an issued record, not a variable somebody knows
- *(policy)* [**breaking**] a refusal is {rule, verdict, subjects}, and there is no msg
- *(transcript)* the host's rule-injection event, and the census over it
- *(policy)* a migration that touches a shell rule retires it

### Fixed

- *(tests)* the shell-stub cases are unix-only, which is what Windows was saying
- *(semver)* five censuses name the new verb, and every one of them found it
- *(semver)* the toolchain read moves into the adapter `spawn-adapters` places
- *(semver)* the baseline tree is materialized through gix, not a git spawn
- *(tests)* the Windows shebang the ladder can read, and the third precondition row
- *(exec)* a shebang program reaches the ladder, which is what Windows needed
- *(policy)* the retirement ledger's own arms, and the module the layering table had not placed
- *(rebase)* three line ceilings the merge crossed, resolved along existing seams
- *(hook)* the transcript symlink loses its only writer when stop-guard.sh retires
- *(hook)* the end-of-turn module was a dead gate, and this is what proves it is not

### Other

- *(policy)* the module read splits out, at the seam the I/O already had
- *(policy)* [**breaking**] a module's own test rules stop riding the hot path
- *(exec)* the two new spawns move to the placed adapter
- *(git)* base_delta classifies by blob id, and reads only what moved
- *(policy)* the two lints the shell-retirement row landed with

## [0.0.120](https://github.com/button-inc/batten/compare/v0.0.119...v0.0.120) - 2026-08-26

### Added

- *(install)* one line, every environment — harden the installer itself
- *(facts)* [**breaking**] file an agent-sourced record under the key its row declares

## [0.0.119](https://github.com/button-inc/batten/compare/v0.0.118...v0.0.119) - 2026-08-26

### Fixed

- *(handler)* a matcher's server segment is judged by what it accepts

### Other

- *(hook)* [**breaking**] row 5 of the shell-guard wave retires into a handler
- *(hook)* row 4 of the shell-guard wave retires into three deny rows
- *(hook)* row 6 of the shell-guard wave retires into two ceilings

## [0.0.118](https://github.com/button-inc/batten/compare/v0.0.117...v0.0.118) - 2026-08-25

### Added

- *(facts)* [**breaking**] a declared fact states what its command returns
- *(facts)* add the first Cost::Effect fact
- *(config)* the schema-removal gate, and the verb that decides it
- *(config)* the deprecation grammar's predicates — a migration window, and the removal gate that needs one

### Fixed

- *(facts)* opaque declares a shape too, and a loosened one is a weakening
- *(facts)* read the declared shape at the site that records it
- *(git)* a canonicalised repository root is comparable again on Windows
- *(facts)* the symbol fact's schema admits the null its projection emits
- *(git)* patch identity is computed in process, and its normalisation is decided

### Other

- *(git)* [**breaking**] nothing in the crate spawns `git`, and the one-invoker gate becomes a no-invoker one
- *(git)* nine git questions answered in process, and a CLOUD-739 fixture repaired
- *(hook)* a host's decision channel is a Capabilities row, not a name switch

## [0.0.117](https://github.com/button-inc/batten/compare/v0.0.116...v0.0.117) - 2026-08-25

### Added

- *(policy)* gate that a gate's remedy reaches its reader and has one author

### Fixed

- *(transcript)* state the parse fact once, not the consequence twice

## [0.0.116](https://github.com/button-inc/batten/compare/v0.0.115...v0.0.116) - 2026-08-25

### Added

- *(hooks)* [**breaking**] delete the hand-run minters, so a receipt has one writer
- *(config)* [**breaking**] mint the two read-shaped receipts from the result that earned them
- *(rules)* [**breaking**] a ratchet admits an increase by declaration

### Fixed

- *(hook)* the mint reads the envelope the host actually sends, from the repository it belongs to
- *(receipt)* read a branch receipt at its newest base, not its oldest
- *(rules)* pair each ratchet admission column with the direction it governs

### Other

- *(hook)* place every retired minter case, and assert the four with no successor
- *(hook)* the minted receipts are shown to fail before they are shown to pass
- *(rego)* gate Rego formatting, the one config format with no formatter

## [0.0.115](https://github.com/button-inc/batten/compare/v0.0.114...v0.0.115) - 2026-08-25

### Fixed

- *(tasks)* a clause the test could not observe is gone, and two arms say why

### Other

- *(hook)* row 3 of the shell-guard wave retires into a config row

## [0.0.114](https://github.com/button-inc/batten/compare/v0.0.113...v0.0.114) - 2026-08-25

### Fixed

- *(rules)* the ledger's two readers share one grammar
- *(transcript)* [**breaking**] an unreadable transcript is reported, never a veto
- *(receipt)* [**breaking**] a transcript this verb cannot read is reported, not refused

### Other

- *(facts)* the no-storage clause names the path it is true of
- *(hook)* row 2 of the shell-guard wave retires into a config row

## [0.0.113](https://github.com/button-inc/batten/compare/v0.0.112...v0.0.113) - 2026-08-25

### Added

- *(config)* [**breaking**] row 1 retires — a filing owes a search, as config

### Fixed

- *(rules)* the root table's empty case names its own type
- *(hook)* one selector applies the modifier, so a second caller cannot miss it
- *(hook)* a narrowing that holds on one path is not a narrowing
- *(rules)* the value qualifier is validated on every kind that carries it
- *(hook)* the modifier narrows every receipt selection, not one loop

## [0.0.112](https://github.com/button-inc/batten/compare/v0.0.111...v0.0.112) - 2026-08-24

### Added

- *(hook)* a deny names the hatch that suppresses it, and no other
- *(gate)* module layering is a gate, over the resolved use graph
- *(facts)* Fact::Uses reaches Rego, resolved across the declared set
- *(facts)* the use graph, resolved through the crate root's own re-export table
- *(facts)* a call site's program and arguments, so a token's POSITION is a fact

### Fixed

- *(rules)* one path can be acquired as more than one fact

### Other

- *(facts)* hoist the two syn visitors to module scope, and lift the suite's lint
- *(identity)* pin the emitted bytes, so a substrate bump cannot re-key silently
- *(invocation)* the discriminator, and could-not-look told from an empty set
- *(hook)* the two receipt non-answers are told apart, and pinned as one document
- *(hook)* ReceiptFacts and KeyFacts are three-valued on facts::Look

## [0.0.111](https://github.com/button-inc/batten/compare/v0.0.110...v0.0.111) - 2026-08-24

### Other

- *(gates)* record where three inverted board-gate cases went

## [0.0.110](https://github.com/button-inc/batten/compare/v0.0.109...v0.0.110) - 2026-08-23

### Fixed

- *(facts)* count a shell tool's buffer, which is a MEMBER of its envelope
- *(facts)* a content block needs a string text, and one dark block condemns the envelope
- *(facts)* an array is an envelope only if EVERY item is a content block
- *(facts)* normalise a tool buffer to an array instead of refusing it
- *(rules)* name the capability, not the product, on the substitution axis

## [0.0.109](https://github.com/button-inc/batten/compare/v0.0.108...v0.0.109) - 2026-08-23

### Added

- *(rules)* a receipt row can bound how old its receipt may be
- *(hook)* [**breaking**] a receipt row keyed on a tool is reached at all
- *(rules)* the mirror polarity, so a move is distinguishable from an edit
- *(rules)* a mediated row can condition on the arguments a call names
- *(rules)* the reading manifest as a per-call ceiling
- *(rules)* a ceiling whose subject is one call, not a file set
- *(rules)* a mediated row can name the tool it is about

### Fixed

- *(sbom)* key the action table the way the pin exemption already spells it
- *(sbom)* a portable roots reader, and a coordinate the exclusion could not spell

## [0.0.108](https://github.com/button-inc/batten/compare/v0.0.107...v0.0.108) - 2026-08-23

### Added

- *(facts)* landing is a fact a rule can ask, not an exit code to archaeologise
- *(rules)* a deletion declares where every case it dropped went
- *(facts)* the checkout's git state is five facts, each bounded by declaration
- *(rules)* a broad rule can carve out the paths a precise one owns
- *(rules)* a rule can declare what it produces, and the boundary writes it
- *(policy)* [**breaking**] derive both policy-input schemas from the fact model
- *(policy)* describe the mediated-call surface too, and keep the two apart
- *(policy)* describe the tree-surface input, and gate the description
- *(hook)* record an absent response, and assert the capture end to end

### Fixed

- *(git)* could-not-look is null, never a fabricated fact
- *(rules)* apply the exclusions and the contracts the reviews found missing
- *(facts)* the extracted family names its non-members instead of wildcarding
- *(sink)* an unreadable declared record is could-not-look, never absent
- *(rules)* the write-only kind is unreadable, and the escape is injective
- *(rules)* a produced record is addressed by its rule, so two cannot collide
- *(hook)* bound the absent-response path, and pin what the tests read

### Other

- *(rules)* the mapping's three inputs are one thing, so pass them as one
- *(rules)* map the one completed retirement, and close the two gaps it found
- *(rules)* the ratchet, and the arm that proves it is one
- *(hook)* the aliases, the block shape, an unreadable one, and a dead store

## [0.0.107](https://github.com/button-inc/batten/compare/v0.0.106...v0.0.107) - 2026-08-23

### Added

- *(hook)* capture every PostToolUse response
- *(capture)* a per-call provenance log and a bounded response store
- *(capture)* mint the store owner-only
- *(capture)* read a capture's bytes verbatim through `--raw`
- *(capture)* a response stream and a byte-exact read
- declare each host's response-capture fidelity
- *(attribution)* record which authority governs commit identity, and gate the prescription

### Fixed

- *(capture)* [**breaking**] evict by the log's append order, and pair the perf arms apart
- *(capture)* bound the call log ahead of the blob budget, under its lock
- *(surface)* the root about is the crate description, not a second copy of it

### Other

- state the post-tool arm's real margin instead of a magnitude
- accept the post-tool arm's write-vs-no-write pairing, with an expiry
- price the PostToolUse capture with its own arm
- the front door stops claiming a private repository and citing links a reader cannot open

## [0.0.106](https://github.com/button-inc/batten/compare/v0.0.105...v0.0.106) - 2026-08-22

### Added

- *(hook)* the first handler, and the door proved end to end on real wiring
- *(hook)* wire the handler dispatch, and drain the advisory channel at one site
- *(hook)* `[[hook.handler]]`, so one door can carry a contract the scripts behind it cannot
- *(hook)* [**breaking**] decide over what a write would land, not just where it lands
- *(doctor)* [**breaking**] read the surfaces a host MERGES, so an undeclared hook is visible
- *(hook)* [**breaking**] the contract-drift predicate, and the shell task retires
- *(hook)* [**breaking**] an advisory channel, so a notice can reach the model without denying

### Fixed

- *(trust)* the `hook` field has a monotone reading now, because a handler is a bar
- *(hook)* [**breaking**] a handler cannot refuse on a moment the engine may not refuse on
- *(rules)* a content-keyed shape row cannot carry a command's columns
- *(hook)* [**breaking**] bound every handler pipe, and refuse a verdict that names nothing
- *(completion)* [**breaking**] a hook run is not the model declaring done
- *(hook)* [**breaking**] the end-of-turn gate reports, and can no longer refuse
- *(hook)* one advisory document per call, and a content row that cannot read as configured and decide nothing
- *(facts)* state where the tree surface stands on a prospective fact
- *(doctor)* count a merged surface once its shape is valid, and skip a same file

### Other

- *(hook)* stop resolving end-of-turn facts nothing can observe
- *(hook)* make two handler assertions able to fail
- *(rebase)* carry #632 onto main's shell style and its lint tier
- *(hook)* render a decision rather than reaching one twice, and clear the lint tier

## [0.0.105](https://github.com/button-inc/batten/compare/v0.0.104...v0.0.105) - 2026-08-22

### Added

- *(policy)* [**breaking**] a regex costs a declaration, so the cheap path is the correct one
- *(policy)* refuse a regex over the command line, so the capability ships with its bound
- *(policy)* a substitution predicate on the pipeline kind, so tool choice has a gate

### Fixed

- *(policy)* three wrongly-refusing verdicts in the two new rules
- *(policy)* qualify the sed substitute by -n, and three more rename casualties
- *(tasks)* name main's two new gates .sh, and fix the test the substitutes column broke
- *(test)* lift `cause` out of one test so both families can assert a pointer
- *(tasks)* the sibling paths, globs and anchors a textual rename cannot see

### Other

- *(policy)* the module checks are config faults, so they leave the hot path
- NOT_REGULAR gates the rarer disease and blesses the common one
- *(hook)* load only the policy modules this surface can evaluate
- *(tasks)* [**breaking**] name a shell program .sh, and gate it with the engine

## [0.0.104](https://github.com/button-inc/batten/compare/v0.0.103...v0.0.104) - 2026-08-22

### Other

- *(gate)* the appeal fixture named a real surveyed project, so it reported itself
- *(gate)* replace the coverage the retired suite carried

## [0.0.103](https://github.com/button-inc/batten/compare/v0.0.102...v0.0.103) - 2026-08-22

### Fixed

- *(trust)* [**breaking**] make the no-pin-no-degrade guarantee structural, not a doc comment

### Other

- *(policy)* mirror the policy directory into every committed-config fixture

## [0.0.102](https://github.com/button-inc/batten/compare/v0.0.101...v0.0.102) - 2026-08-21

### Added

- *(rules)* a lines fact, so the 12 tree-scoped gates with no fact to decide over have one
- *(rules)* bound the declared read set, on a count rather than a clock
- *(rules)* a policy row can declare a glob, and the whole rule set reads each path once
- *(trust)* [**breaking**] make the base-ref load a lifecycle, with a last-known-good pin

### Fixed

- *(policy)* a declared document this build cannot parse is a config fault, not a skip
- *(policy)* refuse a module that reads a tree key the engine cannot emit
- *(policy)* build `input.tree.tracked`, and project the tree document from the fact model

### Other

- *(rules)* group the once-per-run inputs, so run_rule states them as one
- *(pointer-only)* [**breaking**] a lines canary, so §5's teeth are structural rather than reviewed
- *(rust)* split the concurrency verdict PR #620 wrote as one, and scope the narrowing test to the path it measured
- *(facts)* collapse three document acquisitions into one, and assert all seven pairings
- *(tests)* drop a `format!` with nothing to interpolate
- *(trust)* decide the offline lifecycle from the binary's exit and its stderr
- *(rules)* name the instrument for each class of whole-tree question

## [0.0.101](https://github.com/button-inc/batten/compare/v0.0.100...v0.0.101) - 2026-08-21

### Added

- *(hook)* [**breaking**] project the resolved fact set into the policy input

### Fixed

- *(hook)* take CodeRabbit's two findings on the projection

## [0.0.100](https://github.com/button-inc/batten/compare/v0.0.99...v0.0.100) - 2026-08-21

### Added

- *(policy)* give the vendored presets their own tests, and measure what that costs the hook path
- *(policy)* run a module's own test_ rules, and prove a test made each predicate fire

## [0.0.99](https://github.com/button-inc/batten/compare/v0.0.98...v0.0.99) - 2026-08-21

### Added

- *(policy)* [**breaking**] analyse a composed rule set as a whole, and prove the sweep reached it
- *(policy)* ship vendored preset bundles, compiled in and enabled by name
- *(rules)* let a policy row decide on the tree, not only on the mediated call
- *(policy)* compose a bundle into one engine, and pin the rule names not the package
- *(policy)* give a module's predicates their own ids, severities and waivers
- *(rules)* gate the evaluator's IO-free pin instead of asserting it
- *(doctor)* [**breaking**] `doctor hooks`, so the wiring check ships and stops being bash
- *(hook)* Event::UserPromptSubmit, so the surface clause stops being vacuous

### Fixed

- *(policy)* assert the preset path by component, not by string prefix
- *(policy)* take the five clippy findings on their merits
- *(hook)* resolve the authority root in the binary, and delete the launcher

## [0.0.98](https://github.com/button-inc/batten/compare/v0.0.97...v0.0.98) - 2026-08-21

### Added

- *(gate)* declare every suite's subject and delete the waiver
- *(rules)* [**breaking**] let a ratchet admit a decrease when the subject died

### Other

- *(rules)* pin retires_with on the case a blanket waiver cannot express
- *(rules)* decide the concurrency posture, and measure the number it rested on
- *(lint)* gate a new shell-out arriving, with the verdict on the line

## [0.0.97](https://github.com/button-inc/batten/compare/v0.0.96...v0.0.97) - 2026-08-21

### Added

- *(hook)* the policy gate decides a mediated call from the fact set
- *(rules)* [**breaking**] a policy kind, so a rule can be a predicate over the fact set
- *(hook)* name the call's background posture as a readable field

### Fixed

- *(git)* name what the remaining spawns cost, and gate that the doc keeps saying it
- *(test)* satisfy the clippy gate, not my approximation of it
- *(policy)* the gate was unreachable, and five other defects the unit tests could not see
- *(git)* [**breaking**] refuse a short attribution record instead of answering with blanks
- *(git)* name and type the receipt's repository facts
- *(git)* name and type the ledger's base reads
- *(git)* name and type the commit-subject read

### Other

- *(hook)* drop the half of `HookEventName`'s reason that stopped being true

## [0.0.96](https://github.com/button-inc/batten/compare/v0.0.95...v0.0.96) - 2026-08-21

### Added

- *(config)* tolerate a retired key in a config read from a git ref
- *(git)* [**breaking**] drop the two primitives kept only because gix cannot do them

## [0.0.95](https://github.com/button-inc/batten/compare/v0.0.94...v0.0.95) - 2026-08-20

### Added

- *(config)* [**breaking**] declare agent-sourced facts, and resolve a check from one
- *(hook)* [**breaking**] carry the tool result, and the fact an agent's command sourced
- *(state)* withhold a spawning rule instead of losing the whole record

### Fixed

- *(receipt)* mark `rfc3339_utc` `#[must_use]`, as publishing it requires

### Other

- *(hook)* close the agent-sourced fact loop over the compiled binary

## [0.0.94](https://github.com/button-inc/batten/compare/v0.0.93...v0.0.94) - 2026-08-20

### Added

- *(perf)* budget the pass-through path match-all made the common case
- *(hook)* register batten on every hook surface of every harness
- *(rules)* [**breaking**] referenceable derived values, refused at load when they cannot compose

### Other

- *(rules)* [**breaking**] the axis `scopes` pairs on is ambient authority, not spawning

## [0.0.93](https://github.com/button-inc/batten/compare/v0.0.92...v0.0.93) - 2026-08-20

### Added

- *(rules)* [**breaking**] require_via, so "never a bare cargo" is a gate rather than prose
- *(rules)* [**breaking**] a document fact — TOML, YAML, JSON and JSON5, three-valued
- *(hook)* [**breaking**] dispatch the protected-write gate on a neutral Operation

### Fixed

- *(hook)* give this branch's test policies the harness field
- *(hook)* a program-only pattern fires, on both matchers

### Other

- *(pointer-only)* spell the corpus shape row so the matcher can honour it

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
