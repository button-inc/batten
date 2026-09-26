# A duplicate close decided in the same operation as its target's own close
# (CLOUD-829, ported off `mise-tasks/duplicate-close-check.sh` under CLOUD-1752).
#
# Measured: CLOUD-777 was marked Done and CLOUD-817 closed as a Duplicate OF it
# in one operation, `2026-08-21T02:37:51.492Z` — and CLOUD-817's own text was the
# finding that CLOUD-777's acceptance passed vacuously. A duplicate close makes
# the closed row unreachable from the survivor, so the finding stopped being
# readable, not merely lost.
#
# WHAT THIS DECIDES, AND WHAT IT REFUSES TO PRETEND TO DECIDE. Whether two rows
# contradict is not computable. A duplicate close whose target entered a
# completed state in the same second is: two decisions taken as one, and one of
# them never argued. The refusal demands the argument; it never says which row
# was right, and it moves nothing.
#
# ONE POINTER NAMES THE PAIR, `<duplicate>><target>`: a refusal naming only
# the closed row leaves a reader unable to find the decision taken beside it.
#
# THE SPLIT. `[tasks.duplicate-close-record]` reads the piped payloads and
# records one `dup` line per duplicate close with both stamps already truncated
# to the window, and refuses — writing nothing — on every could-not-look the
# program had: no payload carrying `duplicateOf` at all, a close with no stamp, a
# target outside the piped set. So a violation here is only ever a refusal,
# which keeps `board-sweep`'s refusal lane apart from its could-not-look lane.
#
# The census closes the record, as `done`'s does: a record missing it, or
# disagreeing with its line count, was torn and is refused rather than judged.
#
#MUTANT-SUITE crates/batten/tests/it/duplicate_close.rs
#MUTANT window-never-compares|s@^\tentry.closed == entry.target_at$@\tfalse@|a_duplicate_close_in_its_targets_operation_is_refused
#MUTANT different-seconds-refused|s@^\tentry.closed == entry.target_at$@\ttrue@|closes_in_different_seconds_pass
#MUTANT torn-record-passes|s@^\tcount(census) != 1$@\tfalse@|a_record_without_its_census_is_torn

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.duplicate_close

import rego.v1

rules contains "issue answer other"

lines := input.tree.records["duplicate-close"]

# `dup\t<id>\t<closed>\t<target>\t<target completed>`, both stamps truncated to
# the window by the producer.
entries contains {"id": c[1], "closed": c[2], "target": c[3], "target_at": c[4]} if {
	some line in lines
	c := split(line, "\t")
	count(c) == 5
	c[0] == "dup"
}

dup_lines contains line if {
	some line in lines
	startswith(line, "dup\t")
}

census contains to_number(raw) if {
	some line in lines
	startswith(line, "census\tduplicates=")
	raw := substring(line, count("census\tduplicates="), -1)
	regex.match(data.batten.patterns["whole-number"], raw)
}

torn if {
	lines
	count(census) != 1
}

torn if {
	some n in census
	n != count(dup_lines)
}

violation contains {
	"rule": "issue answer other",
	"verdict": "issue grade twice",
	"subjects": [{"artifact": sprintf("%s>%s", [entry.id, entry.target])}],
} if {
	not torn
	some entry in entries
	entry.closed == entry.target_at
}

violation contains {
	"rule": "issue answer other",
	"verdict": "issue count partial",
	"subjects": [{"count": count(census)}],
} if {
	torn
}

# --- cases -------------------------------------------------------------------

tree(lines) := {"tree": {"records": {"duplicate-close": lines}}}

test_same_second_is_refused if {
	found := violation with input as tree([
		"dup\tCLOUD-817\t2026-08-21T02:37:51\tCLOUD-777\t2026-08-21T02:37:51",
		"census\tduplicates=1",
	])
	{v.verdict | some v in found} == {"issue grade twice"}
}

test_different_seconds_pass if {
	count(violation) == 0 with input as tree([
		"dup\tCLOUD-817\t2026-08-21T02:37:52\tCLOUD-777\t2026-08-21T02:37:51",
		"census\tduplicates=1",
	])
}

test_a_missing_or_wrong_census_is_torn if {
	missing := violation with input as tree(["dup\tCLOUD-817\ta\tCLOUD-777\ta"])
	{v.verdict | some v in missing} == {"issue count partial"}
	wrong := violation with input as tree(["census\tduplicates=1"])
	{v.verdict | some v in wrong} == {"issue count partial"}
}

test_an_absent_record_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}
