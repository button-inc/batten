# METADATA
# description: |
#   No issue reads Done while no release contains its commits (CLOUD-192;
#   moved into this preset from a consumer module under CLOUD-843).
#
#   Done means RELEASED, and a tracker's forge integration keys it on the merge.
#   A release cycle sits between those two events, so an issue can read Done
#   while shipped in nothing — measured on consumer #1, an issue read Done at
#   merge time with the trunk 50 commits past the last release tag.
#   Landed-but-unreleased is review, and this module refutes the Done.
#
#   REFUTES, NEVER CONFIRMS. Refs come from commit MESSAGES, which cite and defer
#   as well as complete, so a ref inside a release is weak evidence and a ref
#   nowhere near one is conclusive. `record derive done` resolves each issue to
#   one of three readings, and only `landed` — on the trunk, reached by no
#   release tag — refuses. An issue carrying several refs is judged by its
#   most-released one.
#
#   THE STATUS COLUMN IS THE ENGINE'S TOKEN, NOT THE TRACKER'S. Which column
#   name means Done is a consumer fact, so the producer takes it as an input and
#   records `done` or `other`; this module compares the token and names no
#   tracker's vocabulary.
#
#   THE CENSUS CLOSES THE RECORD. `census\tissues=<n>` is written last, so a
#   record missing it or disagreeing with its lines was torn and is refused
#   rather than judged over part of a board.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/tracker_hygiene.rs
#MUTANT landed-done-passes|s@^\tentry.shipped == "landed"$@\tfalse@|a_done_issue_landed_past_the_last_tag_is_refused
#MUTANT other-columns-judged|s@^\tentry.status == "done"$@\ttrue@|an_issue_in_another_column_is_not_judged
#MUTANT torn-record-passes|s@^\tcount(done_census) != 1$@\tfalse@|a_record_without_its_census_is_torn_rather_than_clean

rules contains "issue grade other"

# EVERY NAME HERE IS PREFIXED `done_`: the preset's modules share one package,
# and a second binding of an unprefixed name COLLIDES rather than shadowing.
#
# The producer's lines, or nothing. Absent is could-not-look and every rule
# below is silent: the producer writes nothing when it refuses.
done_lines := input.tree.records.done

# `issue\t<id>\t<done|other>\t<shipped|landed|unlanded>`.
done_entries contains {"id": columns[1], "status": columns[2], "shipped": columns[3]} if {
	some line in done_lines
	columns := split(line, "\t")
	count(columns) == 4
	columns[0] == "issue"
}

done_issue_lines contains line if {
	some line in done_lines
	startswith(line, "issue\t")
}

# The whole-number guard runs before `to_number`, which FAULTS in regorus on a
# non-numeric string rather than going undefined. Inline, because a preset
# cannot read a consumer's `[[pattern]]` row.
done_census contains to_number(raw) if {
	some line in done_lines
	startswith(line, "census\tissues=")
	raw := substring(line, count("census\tissues="), -1)
	regex.match(`^[0-9]+$`, raw)
}

done_torn if {
	done_lines
	count(done_census) != 1
}

done_torn if {
	some n in done_census
	n != count(done_issue_lines)
}

violation contains {
	"rule": "issue grade other",
	"verdict": "issue ship ahead",
	"subjects": [{"artifact": entry.id}],
} if {
	not done_torn
	some entry in done_entries
	entry.status == "done"
	entry.shipped == "landed"
}

violation contains {
	"rule": "issue grade other",
	"verdict": "issue read partial",
	"subjects": [{"count": count(done_census)}],
} if {
	done_torn
}

# --- cases -------------------------------------------------------------------

done_tree(lines) := {"tree": {"records": {"done": lines}}}

test_done_a_landed_done_is_refused if {
	found := violation with input as done_tree(["issue\tACME-499\tdone\tlanded", "census\tissues=1"])
	{entry.verdict | some entry in found} == {"issue ship ahead"}
}

test_done_a_shipped_done_and_an_unlanded_done_pass if {
	found := violation with input as done_tree([
		"issue\tACME-168\tdone\tshipped",
		"issue\tACME-99999\tdone\tunlanded",
		"census\tissues=2",
	])
	count(found) == 0
}

test_done_another_column_is_not_judged if {
	found := violation with input as done_tree(["issue\tACME-5\tother\tlanded", "census\tissues=1"])
	count(found) == 0
}

test_done_a_missing_or_wrong_census_is_torn if {
	missing := violation with input as done_tree(["issue\tACME-499\tdone\tlanded"])
	{entry.verdict | some entry in missing} == {"issue read partial"}
	wrong := violation with input as done_tree(["issue\tACME-499\tdone\tlanded", "census\tissues=2"])
	{entry.verdict | some entry in wrong} == {"issue read partial"}
}

test_done_an_absent_record_says_nothing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}
