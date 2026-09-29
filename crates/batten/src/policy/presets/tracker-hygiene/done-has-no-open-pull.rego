# METADATA
# description: |
#   An issue may become Done only if none of its own pull requests is still
#   open (CLOUD-468; the decision half of the retired `done-pr-check` body,
#   moved into this preset under CLOUD-843).
#
#   A merged pull request completes a DIFF, and the board read it as completing
#   an ISSUE; those coincide only at N=1. Measured on consumer #1: an issue
#   carried four pull requests, one an open draft, read Done for 35 minutes, was
#   reversed by hand, and the inference was made again.
#
#   ARITHMETIC ONLY: N attached pull requests, k open, means not Done. Whether
#   the merged ones did the work is not computable and is not judged. A DRAFT is
#   open, and is named as one. Closed-unmerged is a DECIDED outcome, never a
#   refusal. No pull request at all refuses too: review already requires one, so
#   Done cannot need less.
#
#   COULD-NOT-LOOK NEVER REACHES THIS MODULE. `record derive done-pr` refuses and
#   writes nothing when an attached pull request arrives with no state, so an
#   unread pull request is an absent record here — silence — and never the
#   cheapest route to a pass.
#
#   THE CENSUS CLOSES THE RECORD, as it does for every family in this preset.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/tracker_hygiene.rs
#MUTANT open-state-ignored|s@^\tpull.state == "open"$@\tfalse@|an_open_pull_request_refuses_naming_its_number
#MUTANT draft-not-open|s@^\tpull.state == "draft"$@\tfalse@|the_defect_a_draft_pull_request_refuses_named_as_a_draft
#MUTANT no-pr-licensed|s@^\tentry.attached == "0"$@\tfalse@|no_pull_request_at_all_is_refused
#MUTANT torn-record-passes|s@^\tcount(done_pr_census) != 1$@\tfalse@|a_done_pr_record_without_its_census_is_torn

rules contains "issue ship other"

# EVERY NAME HERE IS PREFIXED `done_pr_`, for the shared package's reason.
done_pr_lines := input.tree.records["done-pr"]

# `issue\t<id>\t<attached pull requests>`.
done_pr_issues contains {"id": columns[1], "attached": columns[2]} if {
	some line in done_pr_lines
	columns := split(line, "\t")
	count(columns) == 3
	columns[0] == "issue"
}

# `pull\t<id>\t<number>\t<draft|open|closed>`.
done_pr_pulls contains {"id": columns[1], "number": columns[2], "state": columns[3]} if {
	some line in done_pr_lines
	columns := split(line, "\t")
	count(columns) == 4
	columns[0] == "pull"
}

done_pr_issue_lines contains line if {
	some line in done_pr_lines
	startswith(line, "issue\t")
}

done_pr_census contains to_number(raw) if {
	some line in done_pr_lines
	startswith(line, "census\tissues=")
	raw := substring(line, count("census\tissues="), -1)
	regex.match(`^[0-9]+$`, raw)
}

done_pr_torn if {
	done_pr_lines
	count(done_pr_census) != 1
}

done_pr_torn if {
	some n in done_pr_census
	n != count(done_pr_issue_lines)
}

# No pull request at all.
violation contains {
	"rule": "issue ship other",
	"verdict": "issue point missing",
	"subjects": [{"artifact": entry.id}],
} if {
	not done_pr_torn
	some entry in done_pr_issues
	entry.attached == "0"
}

# An open pull request, named by its number beside the issue.
violation contains {
	"rule": "issue ship other",
	"verdict": "issue ship early",
	"subjects": [{"artifact": sprintf("%s#%s", [pull.id, pull.number])}],
} if {
	not done_pr_torn
	some pull in done_pr_pulls
	pull.state == "open"
}

# A draft is open, and the pointer says it is a draft: the measured defect was a
# draft nobody noticed, so naming it is the point rather than decoration.
violation contains {
	"rule": "issue ship other",
	"verdict": "issue ship early",
	"subjects": [{"artifact": sprintf("%s#%s:draft", [pull.id, pull.number])}],
} if {
	not done_pr_torn
	some pull in done_pr_pulls
	pull.state == "draft"
}

violation contains {
	"rule": "issue ship other",
	"verdict": "issue list partial",
	"subjects": [{"count": count(done_pr_census)}],
} if {
	done_pr_torn
}

# --- cases -------------------------------------------------------------------

done_pr_tree(lines) := {"tree": {"records": {"done-pr": lines}}}

test_done_pr_every_pull_merged_or_closed_passes if {
	found := violation with input as done_pr_tree([
		"issue\tACME-425\t2",
		"pull\tACME-425\t346\tclosed",
		"pull\tACME-425\t347\tclosed",
		"census\tissues=1",
	])
	count(found) == 0
}

test_done_pr_an_open_pull_refuses_naming_its_number if {
	found := violation with input as done_pr_tree([
		"issue\tACME-1\t1",
		"pull\tACME-1\t500\topen",
		"census\tissues=1",
	])
	{entry.subjects[0].artifact | some entry in found} == {"ACME-1#500"}
}

test_done_pr_a_draft_refuses_named_as_a_draft if {
	found := violation with input as done_pr_tree([
		"issue\tACME-1\t1",
		"pull\tACME-1\t368\tdraft",
		"census\tissues=1",
	])
	{entry.subjects[0].artifact | some entry in found} == {"ACME-1#368:draft"}
}

test_done_pr_no_pull_at_all_refuses if {
	found := violation with input as done_pr_tree(["issue\tACME-1\t0", "census\tissues=1"])
	{entry.verdict | some entry in found} == {"issue point missing"}
}

test_done_pr_a_missing_census_is_torn if {
	found := violation with input as done_pr_tree(["issue\tACME-1\t0"])
	{entry.verdict | some entry in found} == {"issue list partial"}
}

test_done_pr_an_absent_record_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}
