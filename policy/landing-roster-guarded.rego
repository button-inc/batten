# CLOUD-1570's ratchet: the landing workflow consults the required-check roster
# before it moves `main`.
#
# WHAT IT IS FOR, MEASURED RATHER THAN ASSERTED. `$CI_REQUIRED_CHECKS`
# (`mise.toml`) names 20 checks. `final` — the ONE context `protect-main`
# requires — declares `needs: [ci, batten-check, bats, perf]`, so branch
# protection fans in over **4 of the 20**. On PR #880 head `6eb08e14`, `final`
# concluded at 02:57:30 and `windows` at 03:01:50: 4m20s in which the required
# context was green while a required check was still running. A `/fast-forward`
# posted in that window is admitted by the host.
#
# THE HOST CANNOT CLOSE THIS AND THAT IS STRUCTURAL, not an omission. A
# `paths:`-filtered check must be ABSENT rather than `skipped` — `skipped` is not
# in `CI_ANSWERED_CONCLUSIONS`, so a skipping required check wedges `land` at
# exit 3 — and a ruleset cannot require a context that is legitimately absent. So
# the roster is enforceable only where the landing decision is made, which is
# `fast-forward.yml`, and this module is what stops that guard being deleted.
#
# THIS IS NOT "THE FAN-IN COVERS THE ROSTER". That predicate is false by design
# here and a gate asserting it would refuse the tree forever — the shape
# `fixture-forks.rego` records as the one that gets an exception written for it,
# "and the exception is what rots". What is checkable, and what actually
# regresses silently, is whether the landing path asks the question at all.
#
# WHY THE ROW DECLARES THE WHOLE WORKFLOW DIRECTORY AND THE MODULE READS ONE KEY.
# The narrow spelling — `line_sources` naming only the landing workflow — was
# tried and is WRONG, measured by the compiled tier: a rule whose declared
# sources match no file is SKIPPED rather than evaluated over an empty document,
# so deleting the landing workflow made this gate not run at all and the branch
# passed clean. Declaring the directory guarantees the rule always has a source
# (there are 28 workflows), so `not guarded` fires on a DELETED landing workflow
# exactly as it does on an unguarded one. The module still reads one key, so the
# narrowing that matters — which file answers the question — is unchanged.
#
# WHY A `contains` AND NOT A `[[pattern]]` ROW. The registry exists so one
# CONCEPT has one spelling, and this is not a concept with variants — it is one
# literal invocation of one task in one declared file. `fixture-forks.rego` takes
# a row because `git init` has two live spellings in the tree; this has one.
# `contains` is a string builtin, so no inline regex is being smuggled past the
# load-time refusal.
#
# WHAT IT DELIBERATELY DOES NOT DECIDE. Whether the guard is CORRECT — whether
# the adapter's exit codes are read the right way round, whether the step runs
# before the push. That is a judgement, and a gate resolving to it would be the
# model verdict non-negotiable rule 3 forbids. `crates/batten/tests/it/landing_roster.rs`
# is the tier that drives the engine over the real committed file; the adapter's
# own behaviour is `tests/checks-green.bats`'s and is not restated here.
#MUTANT-SUITE crates/batten/tests/it/landing_roster.rs
#MUTANT guard-unread|s@^\tsome line in input.tree.lines\[landing_workflow\]$@\tsome line in []@|the_committed_landing_workflow_is_guarded
#MUTANT guard-matches-anything|s@^\tcontains(line, "checks-green")$@\ttrue@|a_landing_workflow_that_does_not_consult_the_roster_is_refused
#
# THE FIRST MUTATION EMPTIES THE LINE WALK rather than negating `contains`.
# Negating the match would make `guarded` hold over any file at all, so the
# REFUSAL cases would still pass and the mutation would survive on them; emptying
# the walk makes `guarded` unreachable, which reddens the PASS case — the one
# asserting the committed file is guarded. A gate that refuses its own mechanism
# is the shape that gets switched off, and that case is what says it does not.
#
# THE SECOND MAKES THE GUARD MATCH ANY LINE, so `guarded` holds over a workflow
# that consults nothing and the REFUSAL case is the one that reddens. The two
# mutations therefore redden different cases — the pass side and the refuse side
# — which is what makes neither of them shadowed by the other.

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.landing_roster

import rego.v1

rules contains "landing-roster-unguarded"

# The one workflow that moves `main`. A consumer path in a consumer module, which
# is where non-negotiable rule 1 puts it: `crates/batten` may not name it and
# `batten.toml` is what declares the file this rule reads.
landing_workflow := ".github/workflows/fast-forward.yml"

# The roster predicate, by the name the landing path invokes it under. `land`
# decides on the same adapter, so this is the one authority over "is this SHA
# green" being consulted rather than a second one being written.
guarded if {
	some line in input.tree.lines[landing_workflow]
	contains(line, "checks-green")
}

# THE REFUSAL, AND ITS BODY IS `not guarded` WITH NO PRESENCE CONJUNCT — which
# is a MEASURED shape rather than a shortcut, and the first draft got it wrong.
#
# That draft guarded this arm on `input.tree.lines[landing_workflow]` and carried
# a second arm over `input.tree.missing` for the could-not-look case, on the
# reading that a declared source which cannot be read lands there. It does not.
# `line_sources` is a GLOB LIST, and a glob matching zero files is not an
# unreadable source — it is no source at all, so nothing enters `documents`,
# `lines` OR `missing`. Measured by the compiled tier
# (`an_absent_landing_workflow_is_reported_rather_than_read_as_clean`), which
# returned `[]` where a finding was owed: a branch DELETING the landing workflow
# passed the gate silently, which is the exact dead-gate shape this module exists
# to refuse, reached through this module's own could-not-look clause.
#
# THE UNCONDITIONAL-ARM PROBE COULD NOT HAVE CAUGHT IT, and that is worth writing
# down beside the rule that prescribes the probe. A `violation` whose body is
# `true` confirms the MODULE evaluates; it says nothing about whether a
# particular arm is reachable. Only the tier that drives the engine over a tree
# with the file removed can tell, which is `.claude/rules/policy-modules.md`'s
# own reason for the second tier stated one level down.
#
# So absence and presence-without-the-guard are ONE class here, and they should
# be: both mean the landing path does not consult the roster before it moves
# `main`. Refusing on a whole-tree acquisition failure too is the safe direction
# — a landing workflow that cannot be read is not one that has been checked.
violation contains {
	"rule": "landing-roster-unguarded",
	"verdict": "check read never",
	"subjects": [{"path": landing_workflow}],
} if {
	not guarded
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------
#
# These pin the PREDICATE. What they cannot pin is that the engine BUILDS the
# input the predicate reads — `with input as` fabricates the very shape the
# engine may be unable to produce — so `crates/batten/tests/it/landing_roster.rs`
# runs the same questions over the compiled binary against the real committed
# workflow. Both tiers, per `.claude/rules/policy-modules.md`, and the second is
# not optional.

tree(lines, missing) := {"tree": {"lines": lines, "missing": missing}}

guarded_file := [
	"      - name: refuse a head whose required checks have not all answered",
	"          SHA=\"$head_sha\" mise run checks-green || rc=$?",
]

unguarded_file := [
	"      - uses: sequoia-pgp/fast-forward@ea7628b # v1.0.0",
	"        with:",
	"          merge: true",
]

# THE PASS SIDE FIRST: without it every refusal below is satisfied by a module
# that refuses everything. `#MUTANT guard-unread` reddens exactly here.
test_a_landing_workflow_that_consults_the_roster_is_clean if {
	count(violation) == 0 with input as tree(
		{".github/workflows/fast-forward.yml": guarded_file},
		{},
	)
}

test_a_landing_workflow_that_does_not_is_refused if {
	count(violation) == 1 with input as tree(
		{".github/workflows/fast-forward.yml": unguarded_file},
		{},
	)
}

# THE POINTER IS THE FILE a reader opens (rule 4), and the class is the one the
# registry declares for it.
test_the_refusal_points_at_the_landing_workflow if {
	some v in violation with input as tree(
		{".github/workflows/fast-forward.yml": unguarded_file},
		{},
	)
	v.subjects[0].path == ".github/workflows/fast-forward.yml"
	v.verdict == "check read never"
}

# ABSENCE IS THE SAME CLASS. A branch that DELETES the landing workflow has
# removed the guard just as surely as one that edits it, and the compiled tier is
# what proved this arm was unreachable in the first draft.
test_an_absent_landing_workflow_is_refused if {
	count(violation) == 1 with input as tree({}, {})
}

# ANTI-VACUITY ON THE ANCHOR, and it is the STRONG form: another workflow
# carrying the guard's own text does not satisfy this rule. With a wrong anchor —
# or with the walk reading every path rather than the declared one — this passes
# while every case above still passes, which is exactly how an anchored rule goes
# quietly wrong.
test_the_guard_is_not_satisfied_from_another_file if {
	count(violation) == 1 with input as tree(
		{
			".github/workflows/ci.yml": guarded_file,
			".github/workflows/fast-forward.yml": unguarded_file,
		},
		{},
	)
}
