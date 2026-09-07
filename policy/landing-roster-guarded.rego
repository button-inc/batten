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
#MUTANT missing-arm-silent|s@^\tsome path, _cause in input.tree.missing$@\tsome path, _cause in {}@|an_unreadable_landing_workflow_is_reported_rather_than_skipped
#
# THE FIRST MUTATION EMPTIES THE LINE WALK rather than negating `contains`.
# Negating the match would make `guarded` hold over any file at all, so the
# REFUSAL cases would still pass and the mutation would survive on them; emptying
# the walk makes `guarded` unreachable, which reddens the PASS case — the one
# asserting the committed file is guarded. A gate that refuses its own mechanism
# is the shape that gets switched off, and that case is what says it does not.
#
# THE SECOND NEUTERS THE COULD-NOT-LOOK ARM, whose case is the only one that can
# redden for it: every other case supplies a readable file.

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

# THE REFUSAL. The file was read and does not consult the roster, so branch
# protection is the only thing between a `/fast-forward` comment and `main` —
# and branch protection sees 4 of 20.
violation contains {
	"rule": "landing-roster-unguarded",
	"verdict": "check read never",
	"subjects": [{"path": landing_workflow}],
} if {
	input.tree.lines[landing_workflow]
	not guarded
}

# COULD NOT LOOK IS A FINDING, NOT A PASS. A declared source that will not parse
# or is not there belongs in `missing` rather than being silently absent, and a
# module that iterates only `lines` reports green over a file it never read.
violation contains {
	"rule": "landing-roster-unguarded",
	"verdict": "source read unread",
	"subjects": [{"path": path}],
} if {
	some path, _cause in input.tree.missing
	path == landing_workflow
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

# ANTI-VACUITY ON THE ANCHOR. Another workflow with the same content is not this
# rule's business — without the anchor the rule would refuse every workflow in
# the tree, and with a WRONG anchor it would refuse nothing at all while still
# passing the refusal case above.
test_another_workflow_is_not_this_rules_business if {
	count(violation) == 0 with input as tree(
		{".github/workflows/ci.yml": unguarded_file},
		{},
	)
}

# AND A SOURCE THAT COULD NOT BE READ IS A FINDING RATHER THAN A CLEAN TREE.
# `#MUTANT missing-arm-silent` reddens exactly here.
test_an_unreadable_landing_workflow_is_reported_rather_than_skipped if {
	some v in violation with input as tree(
		{},
		{".github/workflows/fast-forward.yml": "Unparsed"},
	)
	v.verdict == "source read unread"
}

# A DIFFERENT PATH IN `missing` IS SOMEBODY ELSE'S COULD-NOT-LOOK, so the arm is
# anchored too rather than firing on any unreadable file in the tree.
test_another_unreadable_path_is_not_this_rules_could_not_look if {
	count(violation) == 0 with input as tree(
		{},
		{".github/workflows/ci.yml": "Unparsed"},
	)
}
