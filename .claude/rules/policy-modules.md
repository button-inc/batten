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
	"verdict": "V-SHELL-RULE-EDITED",
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

Presets are currently **exempt** from that refusal, which is a hole rather than a
design — a preset ships to every consumer while a consumer module reaches one, so
the exemption is inverted. Don't take the exemption as licence; write the row.

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
`input.tree.produced`, `input.tree.records`, `input.tree.landing`, and the git
family —
`input.tree.git-head`, `input.tree.git-refs`, `input.tree.git-ranges`,
`input.tree.git-remote`, `input.tree.git-status`.

**Seven of those keys are DECLARED READS whose subject is not the working tree**,
and grouping them is worth a sentence because each answers a question no walk
can: `input.tree.external` is a file outside the repository root, resolved
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
does not answer (CLOUD-1171); and `input.tree.captured` is a declared REDUCTION
over the capture store — `present`, `count` or a bounded token, never a payload
(CLOUD-1188).

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
another name: one entry per segment, each carrying the EFFECTIVE program and
whether a mediator selected it. `segments[_].words[0]` is the first word as
written; `programs[_].program` is what will actually run once the boundary has
looked through wrappers, environment assignments and every spelling of the
mediator's own invocation. Reach for it rather than deriving one from the other —
a module re-deriving that is a second authority over an argv reading the engine
already owns.

`input.call["run-in-background"]` is a property of the CALL rather than of the
command (CLOUD-1094), and it is three-valued: `true`, `false`, or `null` where
the host said nothing. Compare it with `== true`, never for truthiness — most
hosts send no such key, so reading absent as `false` is a claim about all of
them. It is `Field::RunInBackground`'s answer rather than a raw key, so a module
never has to know whether its host spells it `run_in_background` or
`runInBackground`.

**Anchor a program on `segments`, never on `command`** (CLOUD-857).
`input.call.command` is the line exactly as written, so
`split(input.call.command, " ")[0] == "git"` asks about the first word of the
whole LINE — and a real agent command is compound most of the time. Measured on
the vendored preset that spelled it that way: `git push --force origin main`
denied while `cd /tmp && git push --force origin main` was allowed, with a green
suite over it. `input.call.segments` is `hook::segments` projected — the same
quote-aware tokenizer `shape` and `pipeline` rows are decided by — one entry per
list element, each carrying `words`, `raw`, the `terminator` that followed
it (`"&&"`, `";"`, `"||"`, `"|"`, `"&"`, or `null` where the command ended), and
`input-redirect`. So
the correct predicate is the short one:

```rego
some segment in input.call.segments
segment.words[0] == "git"
```

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
judged as one. It under-denies, which is the sanctioned direction.

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
set anywhere else. `rules-drift` holds the lists above to those two files, so a
key named here that the engine cannot emit is a finding rather than a trap for
the next author.

**`input.tree.missing` is the could-not-look channel, not a fact.** A declared
source that will not parse belongs there rather than being silently absent, and a
module that iterates only `documents` reports green over a file it never read.
Write the `missing` clause. (This used to add that the engine half did not
populate for a parse failure, so the clause was right and the channel empty.
CLOUD-1049 shipped on 2026-08-25 and that parenthetical is stale — do not read it
as licence to leave the clause untested. Its own acceptance requires the cause to
be distinguishable from `Absent`, and to prove it in the second tier over the
compiled binary rather than with `with input as`, which is the only way to tell a
populated channel from one nothing fills.)

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
preset. A gate that **remains registered** in `$MUTANT_GATES` also needs
`tests/<gate>.bats` to exist, because `mutant` resolves a gate's suite by that
name — and a declared mutation whose named case does not exist is reported rather
than silently counted.

**That clause binds a gate that stays, and says nothing about one being retired**,
which the unscoped wording invited a reader to get backwards (CLOUD-1132,
measured: it was read as a demand for a bats suite beside a new module, and then
as a direct conflict with `shell-retirement`, which refuses adding one). A
retirement LEAVES `$MUTANT_GATES` and takes its suite with it — that is step four
of the two-shapes rule in `.claude/rules/toolchain.md` — so there is no gate left
for this sentence to be about. A new `.rego` module's second tier is
`crates/batten/tests/*.rs` and never a `.bats`.

**Choose a mutation that discriminates.** A mutation over a conjunct that some
other conjunct already excludes will survive, and surviving is the only way you
find out. That happened here: a declared mutation on `privileged-lane`'s third
conjunct survived because the input it named was excluded by the first.

## What this file does not gate

`rules-drift` holds the key lists above to the generated schemas, and nothing
here holds anything else. It cannot catch an author who does not read this file,
and a §7 claiming otherwise would be the defect `.claude/rules/scanning.md`
already records for its own case. This buys currency, not compliance.
