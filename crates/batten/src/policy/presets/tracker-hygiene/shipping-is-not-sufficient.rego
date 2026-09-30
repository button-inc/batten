# METADATA
# description: |
#   A release tag shipping a row is NECESSARY for Done and not sufficient
#   (CLOUD-174, CLOUD-257, CLOUD-309; retired off `[tasks.released]`'s inline
#   body under CLOUD-843).
#
#   Done means released, and no tracker integration fires on "a tag now contains
#   this commit", so the move from review to Done is the caller's. Before it
#   moves a shipped row, two refusals stand, and both are reported so one never
#   hides the other:
#
#   HELD: the row carries the consumer's hold marker in its own description.
#   REFUSED: the board gate, composed by the producer rather than copied here,
#   raised a rule for the row. A held row is reported as held and not also as
#   refused — the hold is the row's own word, and it outranks the gate's.
#
#   A DANGLING BLOCKER IS NOT A REFUSAL. It is a property of the piped SET — a
#   blocker the caller did not fetch — and says nothing about the row.
#
#   ONLY THE REVIEW COLUMN IS JUDGED. A row already past it is not moved by
#   this, and a row before it is not asking to be.
#
#   `record derive released` writes the record, normalising the column to the
#   engine's token, so this names no tracker's vocabulary. THE CENSUS CLOSES THE
#   RECORD, for the siblings' reason.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/released.rs
#MUTANT hold-ignored|s@^\tentry.hold == "held"$@\tfalse@|an_issue_holding_itself_open_is_held
#MUTANT gate-verdict-dropped|s@^\tcount(released_refusals(entry.id)) > 0$@\tfalse@|an_in_review_issue_with_no_pr_is_refused_by_rule
#MUTANT released-torn-record-passes|s@^\tcount(released_census) != 1$@\tfalse@|a_released_record_without_its_census_is_torn

rules contains "issue ship other"

# EVERY NAME HERE IS PREFIXED `released_`, for the shared package's reason.
released_lines := input.tree.records.released

# `issue\t<id>\t<review|other>\t<held|free>`.
released_entries contains {"id": columns[1], "column": columns[2], "hold": columns[3]} if {
	some line in released_lines
	columns := split(line, "\t")
	count(columns) == 4
	columns[0] == "issue"
}

released_issue_lines contains line if {
	some line in released_lines
	startswith(line, "issue\t")
}

# `refusal\t<id>\t<rule>`: every rule the composed board gate raised for a row.
released_refusals(id) := [rule |
	some line in released_lines
	columns := split(line, "\t")
	count(columns) == 3
	columns[0] == "refusal"
	columns[1] == id
	rule := columns[2]
	rule != "dangling-blocker"
]

released_census contains to_number(raw) if {
	some line in released_lines
	startswith(line, "census\tissues=")
	raw := substring(line, count("census\tissues="), -1)
	regex.match(`^[0-9]+$`, raw)
}

released_torn if {
	released_lines
	count(released_census) != 1
}

released_torn if {
	some n in released_census
	n != count(released_issue_lines)
}

violation contains {
	"rule": "issue ship other",
	"verdict": "issue ship held",
	"subjects": [{"artifact": entry.id}],
} if {
	not released_torn
	some entry in released_entries
	entry.column == "review"
	entry.hold == "held"
}

violation contains {
	"rule": "issue ship other",
	"verdict": "issue ship refused",
	"subjects": [{"artifact": entry.id}, {"artifact": sort(released_refusals(entry.id))[0]}],
} if {
	not released_torn
	some entry in released_entries
	entry.column == "review"
	entry.hold != "held"
	count(released_refusals(entry.id)) > 0
}

violation contains {
	"rule": "issue ship other",
	"verdict": "tag read partial",
	"subjects": [{"count": count(released_census)}],
} if {
	released_torn
}

# --- cases -------------------------------------------------------------------

released_tree(lines) := {"tree": {"records": {"released": lines}}}

test_released_a_free_review_row_moves if {
	found := violation with input as released_tree(["range\tv1..v2", "shipped\tACME-2", "issue\tACME-2\treview\tfree", "census\tissues=1"])
	count(found) == 0
}

test_released_a_held_review_row_is_held if {
	found := violation with input as released_tree(["issue\tACME-2\treview\theld", "census\tissues=1"])
	{entry.verdict | some entry in found} == {"issue ship held"}
}

test_released_a_refused_review_row_names_its_rule if {
	found := violation with input as released_tree([
		"issue\tACME-2\treview\tfree",
		"refusal\tACME-2\tin-review-no-pr",
		"census\tissues=1",
	])
	{entry.subjects[1].artifact | some entry in found} == {"in-review-no-pr"}
}

test_released_a_held_row_is_not_also_refused if {
	found := violation with input as released_tree([
		"issue\tACME-2\treview\theld",
		"refusal\tACME-2\tin-review-no-pr",
		"census\tissues=1",
	])
	{entry.verdict | some entry in found} == {"issue ship held"}
}

test_released_a_dangling_blocker_is_not_a_refusal if {
	found := violation with input as released_tree([
		"issue\tACME-2\treview\tfree",
		"refusal\tACME-2\tdangling-blocker",
		"census\tissues=1",
	])
	count(found) == 0
}

test_released_another_column_is_not_judged if {
	found := violation with input as released_tree([
		"issue\tACME-2\tother\theld",
		"refusal\tACME-2\tin-review-no-pr",
		"census\tissues=1",
	])
	count(found) == 0
}

test_released_a_missing_or_wrong_census_is_torn if {
	missing := violation with input as released_tree(["issue\tACME-2\treview\theld"])
	{entry.verdict | some entry in missing} == {"tag read partial"}
	wrong := violation with input as released_tree(["issue\tACME-2\treview\theld", "census\tissues=2"])
	{entry.verdict | some entry in wrong} == {"tag read partial"}
}

test_released_an_absent_record_says_nothing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}
