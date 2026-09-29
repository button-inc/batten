# METADATA
# description: |
#   A duplicate close decided in the same operation as its target's own close
#   (CLOUD-829; moved into this preset from a consumer module under CLOUD-843).
#
#   Measured on consumer #1: one row was marked Done and another closed as a
#   duplicate OF it in one operation, and the closed row's own text was the
#   finding that the survivor's acceptance passed vacuously. A duplicate close
#   makes the closed row unreachable from the survivor, so the finding stopped
#   being readable, not merely lost.
#
#   WHAT THIS DECIDES, AND WHAT IT REFUSES TO PRETEND TO DECIDE. Whether two rows
#   contradict is not computable. A duplicate close whose target entered a
#   completed state in the same window is: two decisions taken as one, and one of
#   them never argued. The refusal demands the argument; it never says which row
#   was right.
#
#   ONE POINTER NAMES THE PAIR, `<duplicate>><target>`: a refusal naming only the
#   closed row leaves a reader unable to find the decision taken beside it.
#
#   `record derive duplicate-close` truncates both stamps to the window and
#   refuses — writing nothing — on every could-not-look, so a violation here is
#   only ever a refusal. The census closes the record.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/tracker_hygiene.rs
#MUTANT window-never-compares|s@^\tentry.closed == entry.target_at$@\tfalse@|a_duplicate_close_in_its_targets_operation_is_refused
#MUTANT different-seconds-refused|s@^\tentry.closed == entry.target_at$@\ttrue@|closes_in_different_seconds_pass
#MUTANT duplicate-close-torn-record-passes|s@^\tcount(duplicate_census) != 1$@\tfalse@|a_duplicate_close_record_without_its_census_is_torn

rules contains "issue answer other"

# EVERY NAME HERE IS PREFIXED `duplicate_`, for the shared package's reason.
duplicate_lines := input.tree.records["duplicate-close"]

# `dup\t<id>\t<closed>\t<target>\t<target completed>`, both stamps truncated to
# the window by the producer.
duplicate_entries contains {"id": c[1], "closed": c[2], "target": c[3], "target_at": c[4]} if {
	some line in duplicate_lines
	c := split(line, "\t")
	count(c) == 5
	c[0] == "dup"
}

duplicate_dup_lines contains line if {
	some line in duplicate_lines
	startswith(line, "dup\t")
}

duplicate_census contains to_number(raw) if {
	some line in duplicate_lines
	startswith(line, "census\tduplicates=")
	raw := substring(line, count("census\tduplicates="), -1)
	regex.match(`^[0-9]+$`, raw)
}

duplicate_torn if {
	duplicate_lines
	count(duplicate_census) != 1
}

duplicate_torn if {
	some n in duplicate_census
	n != count(duplicate_dup_lines)
}

violation contains {
	"rule": "issue answer other",
	"verdict": "issue grade twice",
	"subjects": [{"artifact": sprintf("%s>%s", [entry.id, entry.target])}],
} if {
	not duplicate_torn
	some entry in duplicate_entries
	entry.closed == entry.target_at
}

violation contains {
	"rule": "issue answer other",
	"verdict": "issue count partial",
	"subjects": [{"count": count(duplicate_census)}],
} if {
	duplicate_torn
}

# --- cases -------------------------------------------------------------------

duplicate_tree(lines) := {"tree": {"records": {"duplicate-close": lines}}}

test_duplicate_same_second_is_refused if {
	found := violation with input as duplicate_tree([
		"dup\tACME-817\t2026-08-21T02:37:51\tACME-777\t2026-08-21T02:37:51",
		"census\tduplicates=1",
	])
	{v.verdict | some v in found} == {"issue grade twice"}
}

test_duplicate_different_seconds_pass if {
	count(violation) == 0 with input as duplicate_tree([
		"dup\tACME-817\t2026-08-21T02:37:52\tACME-777\t2026-08-21T02:37:51",
		"census\tduplicates=1",
	])
}

test_duplicate_a_missing_or_wrong_census_is_torn if {
	missing := violation with input as duplicate_tree(["dup\tACME-817\ta\tACME-777\ta"])
	{v.verdict | some v in missing} == {"issue count partial"}
	wrong := violation with input as duplicate_tree(["census\tduplicates=1"])
	{v.verdict | some v in wrong} == {"issue count partial"}
}

test_duplicate_an_absent_record_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}
