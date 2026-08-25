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

A **tree**-scoped module (`scope = "tree"`, run by `batten check`) reads
`input.tree.documents`, `input.tree.lines`, `input.tree.invocations`,
`input.tree.uses`, `input.tree.tracked`, `input.tree.missing`,
`input.tree.produced`, `input.tree.landing`, and the git family —
`input.tree.git-head`, `input.tree.git-refs`, `input.tree.git-ranges`,
`input.tree.git-remote`, `input.tree.git-status`.

A **mediated-call** module (`scope = "mediated_call"`, run by `batten hook`)
reads `input.call.command`, `input.call.event`, `input.call.operation` and
`input.call.writes`, plus the `facts` object.

`schema/policy-input.schema.json` and `schema/policy-call.schema.json` are the
authority and are generated — do not hand-edit either, and do not restate the key
set anywhere else. `rules-drift` holds the lists above to those two files, so a
key named here that the engine cannot emit is a finding rather than a trap for
the next author.

**`input.tree.missing` is the could-not-look channel, not a fact.** A declared
source that will not parse belongs there rather than being silently absent, and a
module that iterates only `documents` reports green over a file it never read.
Write the `missing` clause. (Its engine half does not currently populate for a
parse failure — CLOUD-1049 — so the clause is right and the channel is not yet
filled.)

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
preset. A gate in `$MUTANT_GATES` also needs `tests/<gate>.bats` to exist, because
`mutant` resolves a gate's suite by that name — and a declared mutation whose
named case does not exist is reported rather than silently counted.

**Choose a mutation that discriminates.** A mutation over a conjunct that some
other conjunct already excludes will survive, and surviving is the only way you
find out. That happened here: a declared mutation on `privileged-lane`'s third
conjunct survived because the input it named was excluded by the first.

## What this file does not gate

`rules-drift` holds the key lists above to the generated schemas, and nothing
here holds anything else. It cannot catch an author who does not read this file,
and a §7 claiming otherwise would be the defect `.claude/rules/scanning.md`
already records for its own case. This buys currency, not compliance.
