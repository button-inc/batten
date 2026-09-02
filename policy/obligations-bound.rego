# A §7 obligation is bound to a case, or it is not landing (CLOUD-472).
#
# THE DEFECT, MEASURED. `ready-lint` gates the SHAPE of a Ready block and
# `verify` gates the CODE, and nothing compared them — so an obligation could be
# written into an issue, pass the refinement gate, and land with no test behind
# it, with every gate in the loop green while it happened. CLOUD-369 is the
# instance: an acceptance bullet describing when a second matrix may be bought
# did not describe the code that buys it, and it merged to `main` by fast-forward,
# CI-confirmed green.
#
# The reconstruction is what makes this structural rather than inattention. The
# acceptance was written first and correctly; a collision forced a mid-implementation
# redesign; the redesign was derived from the problem again rather than from the
# acceptance and silently dropped one condition; and THE TESTS WERE WRITTEN FROM
# THE IMPLEMENTATION, so they assert what the code does. Tests written that way
# can only ever confirm it — they are structurally incapable of catching an
# obligation that was dropped, because a missing behaviour has no code to write a
# test against. The Ready block is the only artifact that still remembers what was
# promised, and nothing read it at implementation time. This does.
#
# WHAT IT CHECKS AND WHAT THE SWEEP CHECKS, because the pair is the obligation
# and neither half alone is. Here: the declared FILE is tracked, and the declared
# SLUG is a `#MUTANT` row in it. `mise run mutant` then applies that row and runs
# its named case, and a SURVIVOR is the finding. So this answers *is there
# something bound to the promise* and the sweep answers *does it discriminate* —
# which is the difference between coverage and a test that cannot fail, the whole
# of CLOUD-418.
#
# IT SCORES NO PROSE (rule 3). It compares a recorded `<file>:<slug>` against
# tracked paths and against lines that begin with a fixed marker. Whether the
# obligation was worth making, and whether the case is a good one, are judgements
# no gate here makes.
#
# THE SET IS THE TRACKER'S, NOT THE AUTHOR'S. `board-issue-groomed`'s
# `obligations` column runs the Ready grammar over the description the tracker
# RETURNED, so an author cannot hand this rule a set it assembled — the same
# forgery control the `verdict` column has, earned when `ready-lint` over a
# self-assembled payload was measured green three times against text in a local
# file, once under an id no row carried.
#MUTANT-SUITE crates/batten/tests/it/obligations_bound.rs
#MUTANT unbound-file-unread|s@^\tnot obligation.file in input.tree.tracked$@\tfalse@|an_obligation_naming_no_tracked_file_is_refused
#MUTANT undeclared-slug-unread|s@^\tnot declares_slug(obligation)$@\tfalse@|an_obligation_whose_slug_no_row_declares_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.obligations_bound

import rego.v1

rules contains "obligation-unbound"

# The board record, or nothing. ABSENT IS NOT EMPTY: a branch whose recorder
# never ran has no key here, Rego reads that as *does not hold*, and this module
# is silent — which is a different claim from a branch that recorded rows
# declaring no obligations.
lines := input.tree.records["board-writes"]

column(columns, at) := value if {
	value := columns[at]
} else := "-"

# Every `<file>:<slug>` this branch's rows declared.
#
# THE `-` IS COULD-NOT-LOOK AND IS SKIPPED, which is the distinction the
# recorder's `stdout-line` read exists to preserve: a prose-dialect block emits
# no line at all, and reading that as "declares no obligations" would exempt
# precisely the rows this gate is for. A row recorded by an older recorder, with
# no column at all, reads the same way and is judged as it was before this
# module existed.
obligation contains entry if {
	some raw in lines
	columns := split(raw, " ")
	columns[0] == "issue"
	packed := column(columns, 7)
	packed != "-"
	some pair in split(substring(packed, indexof(packed, ",") + 1, -1), ",")
	at := indexof(pair, ":")
	at > 0
	entry := {
		"id": columns[1],
		"file": substring(pair, 0, at),
		"slug": substring(pair, at + 1, -1),
	}
}

# Whether the named file declares the named slug as a `#MUTANT` row.
#
# The marker and the field separator are `mutate`'s own three-field format, and
# matching the PREFIX rather than the whole row is deliberate: the expression and
# the case name are the sweep's business, and a module re-parsing them would be a
# second authority over a format the runner already owns.
declares_slug(entry) if {
	some line in input.tree.lines[entry.file]
	startswith(line, sprintf("#MUTANT %v|", [entry.slug]))
}

# An obligation whose file this repository does not track.
#
# ONE FINDING PER OBLIGATION, so a reviewer sees which promise is unbound rather
# than a count they have to reconstruct. The path leads, because that is what a
# reader opens; the row's id follows it, carried rather than as the pointer.
violation contains {
	"rule": "obligation-unbound",
	"verdict": "test name undefined",
	"subjects": [{"path": obligation_row.file}, {"artifact": obligation_row.id}],
} if {
	some obligation_row in obligation
	not obligation_row.file in input.tree.tracked
}

# An obligation whose file exists and whose slug nothing in it declares.
#
# SEPARATE FROM THE ARM ABOVE because the two are different remedies: a missing
# file means the case was never written, and a missing slug means it was written
# and never given a mutation that could kill it. Collapsing them would hand the
# author one message for two problems.
violation contains {
	"rule": "obligation-unbound",
	"verdict": "test name undefined",
	"subjects": [{"path": obligation_row.file}, {"artifact": obligation_row.id}],
} if {
	some obligation_row in obligation
	obligation_row.file in input.tree.tracked
	not declares_slug(obligation_row)
}

# The predicate's own tests. The SILENT cases carry the weight: every
# could-not-look above is a pass-side property, and a rule that fired on every
# recorded row would satisfy the denies while deciding nothing.

board(record, tracked, lines_by_file) := {"tree": {
	"records": {"board-writes": record},
	"tracked": tracked,
	"lines": lines_by_file,
}}

bound := "issue CLOUD-1 2026-01-01T00:00:00Z ready - - - 1,tests/a.rs:slug-one"

test_a_bound_obligation_is_clean if {
	count(violation) == 0 with input as board(
		[bound],
		["tests/a.rs"],
		{"tests/a.rs": ["#MUTANT slug-one|s@a@b@|the_case"]},
	)
}

test_an_obligation_naming_no_tracked_file_is_refused if {
	some v in violation with input as board([bound], [], {})
	v.verdict == "test name undefined"
}

# THE FILE EXISTS AND THE PROMISE IS STILL UNKEPT. A case with no mutation is a
# case nothing has shown can fail, which is CLOUD-418's whole finding.
test_an_obligation_whose_slug_no_row_declares_is_refused if {
	some v in violation with input as board(
		[bound],
		["tests/a.rs"],
		{"tests/a.rs": ["#MUTANT other-slug|s@a@b@|the_case"]},
	)
	v.verdict == "test name undefined"
}

# COULD NOT LOOK IS NOT A REFUSAL. A prose-dialect block emits no obligations
# line, so the column records `-`, and reading that as "declares none" would
# exempt exactly the rows this gate exists for.
test_a_row_with_no_obligations_column_is_not_judged if {
	count(violation) == 0 with input as board(
		["issue CLOUD-1 2026-01-01T00:00:00Z ready - - - -"],
		[],
		{},
	)
}

# A MEASURED ZERO IS AN ANSWER AND PASSES: the object was read and declares no
# obligations, which is a legitimate Ready block.
test_a_row_declaring_no_obligations_passes if {
	count(violation) == 0 with input as board(
		["issue CLOUD-1 2026-01-01T00:00:00Z ready - - - 0"],
		[],
		{},
	)
}

test_an_absent_record_is_silent if {
	count(violation) == 0 with input as {"tree": {"records": {}, "tracked": [], "lines": {}}}
}

test_a_comment_line_declares_no_obligations if {
	count(violation) == 0 with input as board(
		["comment CLOUD-1 2026-01-01T00:00:00Z - - - 1,tests/a.rs:slug-one"],
		[],
		{},
	)
}

# ONE FINDING PER OBLIGATION, and the pointer leads with the path a reader opens.
test_every_unbound_obligation_is_named if {
	paths := {v.subjects[0].path | some v in violation} with input as board(
		["issue CLOUD-1 2026-01-01T00:00:00Z ready - - - 2,tests/a.rs:one,tests/b.rs:two"],
		[],
		{},
	)
	paths == {"tests/a.rs", "tests/b.rs"}
}
