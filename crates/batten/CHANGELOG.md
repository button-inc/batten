# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
