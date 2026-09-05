# Authoring a policy module

These load when you write or edit a `.rego` module — `policy/*.rego` in this
repository, or a vendored preset under `crates/batten/src/policy/presets/**`.

**Two kinds of statement live here and they are not interchangeable.** The
**shape** rules and the `[[pattern]]` rule are refused at **load time** rather
than at adjudication, which is the point: a module that breaks one fails to load
and says why, instead of loading and deciding nothing. Everything after them —
which `input.*` keys exist, module-or-preset, the two test tiers, choosing a
mutation that discriminates — is authoring judgement with a partial mechanism
behind it at best, and the preset exemption is a named gap rather than a rule.
Each section says which it is; §"What this file does not gate" is the summary. An
opening that claimed load-time refusal for all of it was the defect this file
exists to warn about, one level up, and review of #694 is what caught it.

## The shape

Three rule names are fixed, under the `data.batten` prefix, with the sub-package
the consumer's:

| name                    | what it is                                                |
| ----------------------- | --------------------------------------------------------- |
| `data.batten.rules`     | the predicate ids this module declares — a `contains` set |
| `data.batten.violation` | the findings, each carrying the `rule` id it belongs to   |
| `data.batten.deny`      | the composed set the engine reads                         |

Those three names are the query root, so a module publishing `denies` instead of
`deny` contributes nothing and fails nothing. `rules-drift` holds the names above
to `policy.rs`'s own constants.

**Deny-only, structurally — there is no allow spelling.** That is what preserves
house-style §8's raise-only invariant: a module can only ever add refusals, so
enabling a bundle cannot weaken policy and the contradiction class is removed by
construction rather than by review.

**A predicate id is a string literal INSIDE its `violation` rule**, never derived
from the rule's name. `policy test`'s coverage binds on that literal, because a
`test_<id>` naming convention would be satisfied by a test that never touches the
predicate.

## A refusal is `{rule, verdict, subjects}` — there is no `msg`

Refused at **load**, in both directions, so this belongs with the shape rules
above rather than with the authoring judgement below.

```rego
violation contains {
	"rule": "shell-rule-retired",
	"verdict": "shell edit refused",
	"subjects": [{"path": path}],
} if { ... }
```

`verdict` is a **token** the `[[verdict]]` registry declares; the prose that used
to live in `msg` lives there, once, where a gate can read it. A module binding
`msg` fails to load and says which key; so does one raising a token no row
declares, one raising a token declared as a tombstone, and one that **composes**
its verdict with `sprintf` — a class a reader cannot look up is not a class. The
other direction is refused too: a `[[verdict]]` row nothing raises fails the load,
because a class no gate reaches reads as coverage while its routes have never been
walked.

The measured reason (CLOUD-1050): `msg` was a `String`, so a refusal naming no
remedy, naming a task that does not exist, or offering an override with no
precondition were all _expressible and none checkable_. Two of those were live in
this repository when the row was written.

`subjects` is optional and ordered, and every member is a **tagged pointer** —
`{path}`, `{path, line}`, `{count}`, `{artifact}` — never prose, which is what
makes non-negotiable rule 4 structural here rather than a habit each module keeps.
The **first path-bearing subject becomes the finding's own pointer**, so the order
is a statement about which one a reader should follow first; a class with nothing
to point at omits the key rather than inventing one. The bare-string `deny`
channel carries a token too, and is held to the same registry.

## Patterns come from `[[pattern]]`, never inline

An inline regex is **refused at load**. A pattern is a `[[pattern]]` row read as
`data.batten.patterns["<id>"]`, so one concept has one spelling and duplication
becomes unwritable rather than merely detectable.

The measured reason: one concept was spelled 19 different ways across 17 shell
programs before the registry existed. A convention would not have stopped that; a
load-time refusal does.

**NEVER BUILD A PREDICATE ON TEXT A ROUND TRIP REWRITES, and never spell a
threshold as a pattern.** Two failures, one root: reaching for the registry
because it is the nearest declaration surface rather than because the thing being
declared is a concept with one spelling.

A tracker sanitises what it stores. This consumer already declares
`ready-issue-mention-markup` **because** a bare issue key comes back wrapped in
`<issue …>` markup — so a rule matching key text is matching the one thing the
round trip is known to mangle, and it will pass in a fixture and fail in
production. Measured 2026-09-01: a prose-dialect ratchet was drafted as
`^CLOUD-([0-9]{1,3}|1[0-3][0-9]{2})$`, a key range in alternation. Wrong twice —
arithmetic is not a concept, so a range is unreadable and unmovable in a regex,
and the decision turned on rewritten text. It is a **value** now, in `[ready]`.

Its replacement carried a subtler form of the same error and is worth the
sentence: a key ORDINAL — trailing digits, no separator assumed — reaches no
consumer literal and passes `no-tracker-key-in-core`, yet still requires keys
that are numeric AND monotonic with creation order. Three popular trackers give
that and a slug- or UUID-keyed one does not, where it would resolve to nothing
and **fail silently**. Prefer a fact every tracker actually stamps: the row's
creation instant, compared as fixed-width ISO-8601, which is what
`filed-here.rego`'s `predates_the_branch` already does.

**A PRESET IS EXEMPT, AND IN A PRESET YOU WRITE THE LITERAL INLINE.** This
paragraph told authors the opposite — that the exemption was "a hole rather than
a design" and to "write the row" anyway — and following it produces a **dead
gate**, which is strictly worse than the duplication the registry exists to stop.

A `[[pattern]]` row is CONSUMER config. A preset is compiled in and reaches a
consumer who wrote no rows, so `data.batten.patterns["x"]` resolves to undefined
there, Rego reads undefined as _does not hold_, and the rule decides nothing while
loading clean. `policy.rs` states it at the exemption's own site: the demand is
"unsatisfiable… a consumer cannot add a `[[pattern]]` row on its behalf, and the
preset cannot read one." CLOUD-934 predicted the failure in those words before it
happened; CLOUD-1161's `ci-hygiene` preset is it happening, two predicates dead.

Rule 1 still binds the literal, and that is what makes inline safe here rather
than merely necessary: a preset ships everywhere, so its pattern could not name a
consumer even if you wanted it to.

**The load-time tier cannot see this** — `policy test` reported 330 passed over
the dead version. `crates/batten/tests/it/policy_presets.rs` is what catches it,
because it runs a preset's suite the way a consumer gets it. Give your own
compiled tier the same empty vocabulary (`patterns: &[]`) for the same reason: a
harness that declares the ids is supplying input no consumer supplies, and its
deny cases then pass for the wrong reason.

Whether presets should get a vendored inventory of their own is CLOUD-934's open
question. Until it lands, inline is the answer and not a compromise.

## Which `input.*` keys exist, per surface

**The two surfaces are different shapes, and a key from the wrong one is a silent
dead gate.** Rego reads an undefined path as undefined, so the body never holds,
so the `violation` set is empty — and a dead gate and a clean tree are
byte-identical on the decision surface. That is not hypothetical: a module copied
from `policy.rs`'s own doc iterated a tree key the engine never built, passed its
own suite green, and enforced nothing.

**The class is not ours, which is the reason to expect it rather than to guard
against it once.** Surveying registry tooling for CLOUD-1107 reproduced it in the
field, in the most mature instrument in that space: run without `--v2`, OpenTelemetry's
`weaver` evaluated a Rego policy over a knowingly-broken registry and printed
`✔ No 'after_resolution' policy violation`, **exit 0** — because the module reads
`input.registry.attributes`, a key the v1 schema never builds. Same shape, same
silence, same green. A policy engine plus a schema that can disagree about which keys
exist produces this defect by construction, so the second tier below is the only thing
that distinguishes a passing gate from an absent one.

A **tree**-scoped module (`scope = "tree"`, run by `batten check`) reads
`input.tree.documents`, `input.tree.lines`, `input.tree.invocations`,
`input.tree.uses`, `input.tree.tracked`, `input.tree.missing`,
`input.tree.produced`, `input.tree.records`, `input.tree["records-blocked"]`,
`input.tree.landing`, and the git
family —
`input.tree.git-head`, `input.tree.git-refs`, `input.tree.git-ranges`,
`input.tree.git-remote`, `input.tree.git-status`, `input.tree.git-worktrees`.

**`git-worktrees` is the one whose EMPTY value is an answer, so it is worth the
sentence the rest of the family does not need** (CLOUD-1424). Everywhere else here
an empty collection is the could-not-look shape one level down — an unresolvable
ref is absent from `git-refs`, a range that would not read is absent from
`git-ranges`. Here the main checkout keeps no registration at all, so `linked: []`
is a repository that genuinely has no linked worktrees, `null` is the registry
that could not be read, and a predicate collapsing the two reports clean over a
checkout it never looked at. Each entry is `{id, present, locked}` and carries no
path: a linked worktree may live anywhere on the machine, so its base is read to
decide `present` and dropped at the boundary — rule 4 held in the fact's TYPE, the
same way `commit-meta` has no body field.

**`records-blocked` is the recorder surface's could-not-look, and its EMPTY value
is an answer** (CLOUD-1126). `records` already distinguishes a record that could
not be read (absent from the map) from one that was read and is short; neither
says that a row's SELECTOR matched a call which then failed to produce what the
row reads. That third arm is the one nothing downstream can re-derive, because
the call is gone by the time a gate reads the store — measured where
`pr-body-closes` selects a `gh pr view` on a host with no `gh`, so `filed-here`'s
closes-the-row exemption was unreachable rather than unsatisfied. The store is
written only when a row is blocked, so its absence and its emptiness are one
fact: read a PRESENT entry, and never infer one from an absence.

**Eleven of those keys are DECLARED READS whose subject is not the working tree**,
and grouping them is worth a sentence because each answers a question no walk
can: `input.tree["base-delta"]` is how the declared globs' paths differ from a
declared base rev — `added`, `edited`, `deleted`, `code-changed` and the base side
of every EDITED path's lines, which is what lets a module decide a CHANGE rather
than a state (CLOUD-1059); `input.tree.symbols` is where a delegated analyser
resolved a named type, by NAME rather than by spelling, and carries the
`provenance` of the tool that produced it — the first `Cost::Effect` fact
(CLOUD-760); `input.tree.external` is a file outside the repository root, resolved
against a launcher root the row names (CLOUD-1167); `input.tree.staged` is a
path's INDEX bytes, which `tracked` explicitly is not (CLOUD-1203);
`input.tree["git-history"]` resolves a declared PATTERN rather than a named ref,
so a tag glob answers where `git-refs` cannot (CLOUD-1200);
`input.tree["commit-meta"]` is a range's identity fields and carries no message
body (CLOUD-1187); `input.tree.state` is the engine's own finding store per
declared ref (CLOUD-1203); `input.tree.forge` is the forge's verdict for a
declared SHA, from a record a producer wrote outside the engine (CLOUD-1154);
`input.tree["tool-verdict"]` is a third-party tool's verdict keyed to
(tool, pinned version, input digest), so a differently-pinned or stale record
does not answer (CLOUD-1171); `input.tree.minted` is one declared FIELD of a
receipt the MEDIATED boundary already wrote, bounded by how old the reading is —
which is what makes it a different family from `captured`, whose store is keyed
by content, carries no clock, and would answer a question about a mutable field
from whichever read sorts first in digest order (CLOUD-1310); and
`input.tree.captured` is a declared REDUCTION
over the capture store — `present`, `count` or a bounded token, never a payload
(CLOUD-1188); and `input.tree.review` is whether a VENDORED agent prompt was
dispatched over a declared subject, keyed by (prompt digest, subject digest) so
editing the subject leaves the record under a name nothing looks up (CLOUD-472).

**`review` is the one key whose ARM a module must get right rather than merely
its spelling, so it is worth the extra sentence.** A declared id ABSENT from the
map was never dispatched, and that absence is the ONLY thing a predicate over it
may refuse on. Its `findings` are pointers — `{path, line, clause}`, with no
field an agent's prose could occupy — and a module refusing on what the agent
CONCLUDED would be a model verdict wearing an exit code, which non-negotiable
rule 3 forbids. `forge-verdict-required` refuses the opposite arm for a reason
that does not carry: the forge is a third party that may legitimately not have
judged yet, where a review this branch was supposed to dispatch and did not is
the branch's own conduct.

**THERE IS NO INSTANT KEY, AND THAT IS A DECISION RATHER THAN A GAP**
(CLOUD-1170). A module never sees a timestamp to compare, so do not go looking for
one: what reaches a decision is an already-resolved verdict — `receipt::Validity`
is `Valid` / `Expired` / `Missing`, which is fresh, expired and could-not-look.

The reason is the same one `waiver.rs` states for a waiver's expiry and
`rules.rs`'s `max_age` states for a receipt's age: **the clock is the boundary's,
never the decision's.** A row declares the bound, the boundary compares where the
record is already being read, and the core is handed the answer. `hook --instant`
supplies the instant that comparison uses, so the same instant over the same tree
yields the same verdict — which a clock READ can never do, and which §6's
byte-stable output requires.

Projecting the raw integer instead would cost two things worth naming. Every
module would compare in its own spelling, which is a second authority over time —
the disagreement class this file already records for parsers. And byte-stability
would break by construction, because a value that differs per invocation makes one
tree produce different bytes. If some later predicate genuinely needs arithmetic
over an arbitrary timestamp, that is its own row with its own argument to make.

A **mediated-call** module (`scope = "mediated_call"`, run by `batten hook`)
reads `input.call.command`, `input.call.segments`, `input.call.programs`,
`input.call.event`, `input.call.operation`, `input.call.writes`,
`input.call["run-in-background"]`, `input.call["final-message"]`,
`input.call.transcript` and `input.call["stop-repeat"]`, plus the `facts` object.

**The `facts` object is where the hook-surface FACTS live, and it is not
`input.call`.** That distinction is the one this file's own reader gets wrong
first: `input.call.*` is the envelope — what the harness handed over — and
`input.facts.*` is what the boundary RESOLVED about it. Measured while landing
CLOUD-856, where a module that reached for its fact under the `call` object
instead of `facts` evaluated, read undefined, and refused nothing, with its own
suite green throughout. Spelled that way deliberately: `rules-drift` holds every
backticked, fully-qualified key in this file to the generated schema, so naming
the wrong one even as a warning is itself the defect — a reader copies it, and
the gate is right to refuse.
`input.facts["pinned-programs"]` is the landed example; `input.facts.tasks` is
the task runner's own argv, read from a receipt minted at session start so the
mediated path parses no manifest (CLOUD-856); and `input.facts.extracted` is a
declared extractor's COUNT over this session's transcript — an integer over
typed events, never a byte of the session (CLOUD-1172).

`programs` is the ARGV ALREADY READ (CLOUD-1028), and it is NOT `segments` under
another name: one entry per segment, each carrying the EFFECTIVE program, the
`arguments` that program was handed, and whether a mediator selected it.
`segments[_].words[0]` is the first word as written; `programs[_].program` is
what will actually run once the boundary has looked through wrappers,
environment assignments, every spelling of the mediator's own invocation, and —
since CLOUD-1382 — the shell grammar that can stand where a program is written.
Reach for it rather than deriving one from the other: a module re-deriving that
is a second authority over an argv reading the engine already owns, and the six
constructs the table below measures are what the derivation misses.

**`arguments` is the half that makes the anchor usable, and its absence was a
trap rather than an inconvenience.** The list is `filter_map`ed — a segment with
no program at all yields no entry — so `programs` and `segments` do not share an
index, and a module anchoring on the program had nothing to correlate its own
flags ON. Every one that tried joined back by value (`program.program ==
segment.words[0]`), which is the same first-word anchor wearing a second
reading, and it stops agreeing the moment the two readings differ. Read
`arguments` instead.

`input.call["run-in-background"]` is a property of the CALL rather than of the
command (CLOUD-1094), and it is three-valued: `true`, `false`, or `null` where
the host said nothing. Compare it with `== true`, never for truthiness — most
hosts send no such key, so reading absent as `false` is a claim about all of
them. It is `Field::RunInBackground`'s answer rather than a raw key, so a module
never has to know whether its host spells it `run_in_background` or
`runInBackground`.

**Anchor a program on `programs`, never on `command` and never on a segment's
first WORD.** This passage has been wrong twice in the same direction, and both
corrections are kept because the second one is what the first taught.

`input.call.command` is the line exactly as written, so
`split(input.call.command, " ")[0] == "git"` asks about the first word of the
whole LINE — and a real agent command is compound most of the time. Measured on
the vendored preset that spelled it that way: `git push --force origin main`
denied while `cd /tmp && git push --force origin main` was allowed, with a green
suite over it (CLOUD-857).

**The remedy this file then taught was `segment.words[0] == "git"`, and it is one
construct short of the program** (CLOUD-1382). `words[0]` is the first WORD, and
six shell constructs occupy that position in their own right. Measured over the
compiled binary, adjudication only, one preset:

| command                                          | exit |
| ------------------------------------------------ | ---- |
| `git push --force origin main`                   | 2    |
| `(git push --force origin main)`                 | 0    |
| `time git push --force origin main`              | 0    |
| `! git push --force origin main`                 | 0    |
| `{ git push --force origin main; }`              | 0    |
| `command git push --force origin main`           | 0    |
| `if true; then git push --force origin main; fi` | 0    |

Every one runs the force push, and every one is one keystroke. The reason the
table is here rather than only on the row is that ~80 modules were about to copy
whatever this paragraph said.

`input.call.programs` is the argv the engine already read — the effective
program per segment, resolved through environment assignments, wrapper programs
and the shell grammar above — with `name` for the program reached through a
path, `arguments` for what THAT program was handed, and `mediated` for whether
the pin selected it. So the correct predicate is still short, and it correlates:

```rego
some program in input.call.programs
program.name == "git"
"push" in program.arguments
```

Reach for `arguments` rather than the segment's words whenever a flag has to be
the program's own: a `git status` beside an `hg push --force` is two facts, and
reading the whole segment merges them into a refusal nobody can act on.

`input.call.segments` is still `hook::segments` projected — the same quote-aware
tokenizer `shape` and `pipeline` rows are decided by — one entry per list
element, each carrying `words`, `raw`, the `terminator` that followed it
(`"&&"`, `";"`, `"||"`, `"|"`, `"&"`, or `null` where the command ended), and
`input-redirect`. Read it for the SPAN's own structure, which is what those
fields are: what the element's status is handed to, whether it binds stdin, what
was literally written. A program is not one of them.

**The engine half of CLOUD-1382 is a declared STOPGAP and that row stays open.**
`hook.rs`'s `SHELL_GRAMMAR` is a list, a list cannot enumerate a grammar, and
`effective_program`'s own posture — _"Known wrappers only; anything
unrecognised keeps the fail-open posture"_ — says how the next token stays
silent. The fix is a parsed command line, which is CLOUD-1381.

**`input-redirect` is per SEGMENT and that is the whole of it** (CLOUD-613):
whether THIS element binds stdin, by `<`, `<<` or `<<<`, outside a quoted span.
A heredoc binds to the element that writes it, so
`git commit -F - && mise run land <<'EOF'` gives `land` the message and git
`/dev/null` — and the command STRING carries an opener either way, which is why
no predicate over `command` can tell that from `git commit -F - <<'EOF'`.
Compare it with `== false`, never as `not segment["input-redirect"]`: Rego reads
an absent key as undefined and `not undefined` HOLDS, so the negated spelling
denies everything on an engine that stopped emitting the field, where the
comparison allows — the direction a miss is supposed to fail in.

Segments arrive with heredoc **bodies already dropped**, which is the same
change read forwards. A body is data, not shell, so a `;` in a commit message no
longer splits the list and a `nohup` in a documentation paragraph is no longer an
invocation (CLOUD-723, measured twice in one session on the commands that were
documenting the rule). A module therefore does **not** scrub for heredocs, and a
new one copying `run-shape.rego`'s hand-rolled `openers`/`body` comprehensions is
copying the era before this projection.

A **newline is whitespace, not a separator** — bash disagrees, and the bound is
deliberate rather than an oversight: promoting it would change every landed
`pipeline` verdict. So the shell following a heredoc's terminator joins the
segment its opener was written in, and a two-command call written across lines is
judged as one segment.

**AND "it under-denies, which is the sanctioned direction" IS MEASURED
BACKWARDS** (CLOUD-1287). That sentence stood here and was false of the arm that
matters most: one segment means `effective_program` resolves the FIRST line's
program for every operand on every line, so a declared `protected_readers` entry
was unreachable from any script. Measured over the shipped binary, one protected
path, the same read twice: `stat -c %s batten.toml` allowed, and the identical
`stat` written on line two after `cd /tmp` REFUSED, naming `cd`. That is an
OVER-deny, on a read, which is the direction that gets a guard switched off
rather than the sanctioned one.

The bound above still holds for segment identity — `terminator` is unmoved and no
landed `pipeline` verdict changed. What changed is narrower and lives in the
engine rather than in a module: `hook::line_bounded_words` splits a segment's own
`raw` at newlines and re-enters `segments` per line, and only the mutation walk
and the unknown-program walk read it. Both ask "which program was handed this
operand", a question a line answers and a segment does not. So a module reading
`input.call.segments` sees exactly what it saw before, and must not grow its own
line splitting to compensate — that would be the second authority two sections
up already refuses.

There is **one parser**, and a module must not grow a second: no `split` of the
command line, in Rego or in Rust. **The reason is not effort, and giving it as
effort was this file's own defect** (CLOUD-1104): the cost was stated as ~60
lines of hand-rolled string work forced by builtins this build supposedly lacks,
which sent every author toward exactly the duplication the `[[pattern]]`
registry two sections up exists to make unwritable — and `Cargo.toml`'s feature
list is the one authority on what regorus carries, never a sentence here.

The real reason is that **a second parser is a second AUTHORITY, and the two can
disagree.** `hook::segments` is what `shape` and `pipeline` rows are already
decided by, so a module reading the same call through its own tokenizer can deny
a command the engine allows, or allow one the engine denies, over a quoting or
terminator case neither author had in mind. CLOUD-857 is that disagreement
measured rather than imagined — `git push --force origin main` denied while
`cd /tmp && git push --force origin main` was allowed, with a green suite over
it — and CLOUD-843's wave 1 copies this template ~80 times, so the second
authority would arrive ~80 times with it. `batten policy test` **fails** a
mediated-call module whose every `test_` rule passes a bare command, so a suite
blind to this class cannot ship green.

The last three are the **Stop** projections (CLOUD-1051) and every one is `null`
on every other event, which is the three-valued read working rather than a gap: a
module asking for them at `pre-tool` gets undefined, Rego reads undefined as
_does not hold_, and a Stop predicate therefore cannot fire on a tool call. They
are `call` fields rather than facts because nothing resolves them — the harness
hands them over. `transcript` is the **path**, never a byte of the session; a
module wanting the contents asks for a fact the engine resolves.

`schema/policy-input.schema.json` and `schema/policy-call.schema.json` are the
authority and are generated — do not hand-edit either, and do not restate the key
set anywhere else. `rules-drift` holds the lists above to those two files, **as a
set equality in both directions** — so a key named here that the engine cannot
emit is a finding rather than a trap for the next author, and a key the engine
DOES emit that this file does not name is a finding too.

**The second direction was claimed here before it was held, which is the reason
it is now spelled out** (CLOUD-1206). This paragraph said the lists were held and
only the first direction was checked; measured 2026-08-30, the schema declared
`base-delta` and `symbols` and this file named neither — `base-delta` being the
projection a Todo row was about to re-derive a diff for. A false assurance is
worse than an unclaimed gap, and the sentence above is the anchor
`schema-key-undocumented` keys on: it fires over the file that makes this claim
and is silent over every file that does not, which is what keeps it from
demanding that 25 keys be enumerated everywhere.

**`input.tree.missing` is the could-not-look channel, not a fact.** A declared
source that will not parse belongs there rather than being silently absent, and a
module that iterates only `documents` reports green over a file it never read.
Write the `missing` clause.

**AND IT FIRES — since CLOUD-1049, which this file has now been wrong about in
both directions.** It first carried a parenthetical saying the engine half did
not populate; that was replaced by a claim the row had shipped when it had not;
that was replaced by a measured table saying the channel was dead. The channel is
live now, and the reason the history is worth keeping is that every one of those
revisions was written confidently and two of them were false.

**What the defect was, because it decides where you look if it recurs.** The
projection was never the problem — `tree_document` built a correct
`input.tree.missing` all along. `policy_rule` then discarded the whole document
one line later whenever anything failed to acquire, so the clause could not fire
and neither could any OTHER predicate in the same module, including one whose
body is `true`. A gate switched off by the state of one of its own inputs, at
exit 0. One guard, downstream of every push into the channel.

**Confirm a channel with an UNCONDITIONAL arm, never with an arm over the channel
itself.** A probe whose only clause reads `missing` cannot tell an empty channel
from a module that never ran, and that is precisely why two measurements on
CLOUD-1049 missed the larger half and reported it as an unfilled channel. Add a
`violation` with body `true` and see whether it speaks.

**The two causes stay distinct and a module may rely on that**: a path that never
entered the acquisition set is `Absent`, one that was read and would not parse is
`Unparsed`, and `NotAcquired` keeps them apart deliberately so a policy cannot
mistake "could not parse" for "not there".
`crates/batten/tests/it/rules_drift.rs` carries one case per cause, reaching one
class by two routes, which is what proves the distinction survives projection.

**A module that carries no `missing` clause still abstains.** The engine reports
`RuleSkipped` for it rather than a clean tree, so CLOUD-251's "never an empty
deny set" is intact — but abstention is not a finding and nobody reads it.
Write the clause; it is the difference between the engine recording that it could
not look and your gate saying so.

Assert it in the second tier over the compiled binary, never with `with input
as` — that fabricates the very shape the engine may be unable to produce, which
is how the dead clause survived this long.

## Module or preset

**An in-repo module by default.** A preset only when the predicate stays generic
once the consumer's facts are pulled out into `batten.toml`.

Forcing a consumer-specific gate into a preset is how non-negotiable rule 1 gets
violated by a well-meaning migration — and it makes fidelity unanswerable, because
a split deliberately sheds content, so "identical behaviour" is the wrong test for
the preset half alone.

## Two test tiers, and the second is not optional

The module's own `test_` rules are the **load-time** tier. They pin the predicate.

`tests/<gate>.bats` over the **compiled binary** is the tier that proves the
ENGINE builds the input the predicate reads. A `with input as` case cannot do
this: it fabricates the very shape the engine may be unable to produce, so it
passes over a key nothing fills and over a channel nothing populates. Both live
instances of that class were found by adding the second tier, not by reading.

`mise run policy-test` runs the first tier for every registered module and enabled
preset. **A module in `$MUTANT_GATES` DECLARES the suite its mutations must
redden** — `#MUTANT-SUITE crates/batten/tests/<x>.rs`, beside its `#MUTANT` rows —
and a declared mutation whose named case does not exist is reported rather than
silently counted.

**That is CLOUD-1267's change, and the sentence here used to say the opposite.**
It read _"a gate that remains registered also needs `tests/<gate>.bats` to exist,
because `mutant` resolves a gate's suite by that name"_ — which was true, and was
the reason 32 of 32 modules carried a `#MUTANT-EXEMPT`: the runner hardcoded a
path no module may have, `V-SHELL-RULE-ADDED` refuses adding one, and 141
compiled-binary tiers were therefore unreachable. `batten mutate` resolves the
DECLARED path instead, so a `.rego` module names the tier that actually drives
the engine and the exemption is withdrawn rather than renewed. A new module's
second tier is still `crates/batten/tests/*.rs` and never a `.bats`.

**Naming a tier is not the same as being covered by it, and the sweep is what
tells them apart.** A tier that drives the FACT a predicate reads — the
`*_facts.rs` family — never installs the module, so no case in it can turn red
under a mutation of the predicate: the row is declared, it SURVIVES, and the
survivor is the finding. `#MUTANT-OWNER <KEY>|<why>` names the row that owes the
missing tier and **changes no exit code**; a declaration that suppressed the
finding would be the laundering the runner exists to refuse.

**Choose a mutation that discriminates.** A mutation over a conjunct that some
other conjunct already excludes will survive, and surviving is the only way you
find out. That happened here: a declared mutation on `privileged-lane`'s third
conjunct survived because the input it named was excluded by the first.

## What this file does not gate

`rules-drift` holds the key lists above to the generated schemas **in both
directions since CLOUD-1206**, and nothing here holds anything else. Currency is
now bought and it is still not compliance: the gate cannot catch an author who
does not read this file, and a §7 claiming otherwise would be the defect
`.claude/rules/scanning.md` already records for its own case. The previous
revision said this bought "currency, not compliance" while only one direction was
checked, so it was overstating the first half and understating nothing — which is
the shape worth remembering, because a paragraph disclaiming the ambitious
guarantee reads as honest while the modest one it does claim is unheld.
