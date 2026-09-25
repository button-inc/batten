# No issue sits Done while no release tag contains its commits (ported off
# `mise-tasks/done-check.sh` under CLOUD-1717; the predicate is CLOUD-192's).
#
# `Done` on this board means RELEASED, and the tracker's GitHub integration keys
# it on the merge. A release cycle sits between those two events, so an issue can
# read Done while shipped in nothing — measured 2026-08-13, CLOUD-499 read Done at
# merge time with `main` 50 commits past the last tag. Landed-but-unreleased is
# In Review, and this module refutes the Done.
#
# REFUTES, NEVER CONFIRMS. Refs come from commit MESSAGES, which cite and defer
# as well as complete, so a ref inside a tag is weak evidence and a ref nowhere
# near one is conclusive. The producer resolves each issue to one of three
# readings, and only `landed` — on `main`, reached by no `v*` tag — refuses.
# `shipped` cannot be refuted, and `unlanded` (no commit names it) is outside
# git's sight and is not judged. An issue carrying several refs is judged by its
# most-released one; half-landed work reaching Done is CLOUD-468's question.
#
# THE SPLIT IS §5's. The reading needs stdin payloads and two `git log` walks,
# and `check` is `read` and cannot spawn, so `[tasks.done-record]` reads and this
# decides. The producer refuses — exit 2, nothing written — where the retired
# program did: unparseable stdin, no `origin/main`, no `v*` tags. The two git
# preconditions fail in opposite directions (false green, false red), which is
# why neither may be inferred from a result.
#
# THE CENSUS CLOSES THE RECORD. `census\tissues=<n>` is written last, with the
# count of `issue` lines above it, so a record missing it or disagreeing with it
# was torn and is refused rather than judged over part of a board.
#
#MUTANT-SUITE crates/batten/tests/it/done.rs
#MUTANT landed-done-passes|s@^\tentry.shipped == "landed"$@\tfalse@|a_done_issue_landed_past_the_last_tag_is_refused
#MUTANT other-columns-judged|s@^\tentry.status == "Done"$@\ttrue@|an_issue_in_another_column_is_not_judged
#MUTANT torn-record-passes|s@^\tcount(census) != 1$@\tfalse@|a_record_without_its_census_is_torn_rather_than_clean

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.done

import rego.v1

rules contains "issue grade other"

# The producer's lines, or nothing. Absent is could-not-look and every rule below
# is silent: the producer writes nothing when it refuses, and a module refusing
# on absence would refuse every checkout nobody piped a board into.
lines := input.tree.records.done

# `issue\t<id>\t<status>\t<shipped|landed|unlanded>`. Tab-separated because a
# status token carries spaces (`In Review`).
entries contains {"id": columns[1], "status": columns[2], "shipped": columns[3]} if {
	some line in lines
	columns := split(line, "\t")
	count(columns) == 4
	columns[0] == "issue"
}

issue_lines contains line if {
	some line in lines
	startswith(line, "issue\t")
}

# Guarded by `whole-number` before `to_number`, which FAULTS in regorus on a
# non-numeric string rather than going undefined.
census contains to_number(raw) if {
	some line in lines
	startswith(line, "census\tissues=")
	raw := substring(line, count("census\tissues="), -1)
	regex.match(data.batten.patterns["whole-number"], raw)
}

torn if {
	lines
	count(census) != 1
}

torn if {
	some n in census
	n != count(issue_lines)
}

violation contains {
	"rule": "issue grade other",
	"verdict": "issue ship ahead",
	"subjects": [{"artifact": entry.id}],
} if {
	not torn
	some entry in entries
	entry.status == "Done"
	entry.shipped == "landed"
}

violation contains {
	"rule": "issue grade other",
	"verdict": "issue read partial",
	"subjects": [{"count": count(census)}],
} if {
	torn
}

# --- cases -------------------------------------------------------------------

tree(lines) := {"tree": {"records": {"done": lines}}}

test_a_landed_done_is_refused if {
	found := violation with input as tree(["issue\tCLOUD-499\tDone\tlanded", "census\tissues=1"])
	{entry.verdict | some entry in found} == {"issue ship ahead"}
}

test_a_shipped_done_and_an_unlanded_done_pass if {
	found := violation with input as tree([
		"issue\tCLOUD-168\tDone\tshipped",
		"issue\tCLOUD-99999\tDone\tunlanded",
		"census\tissues=2",
	])
	count(found) == 0
}

test_another_column_is_not_judged if {
	found := violation with input as tree(["issue\tCLOUD-5\tIn Review\tlanded", "census\tissues=1"])
	count(found) == 0
}

test_a_missing_or_wrong_census_is_torn if {
	missing := violation with input as tree(["issue\tCLOUD-499\tDone\tlanded"])
	{entry.verdict | some entry in missing} == {"issue read partial"}
	wrong := violation with input as tree(["issue\tCLOUD-499\tDone\tlanded", "census\tissues=2"])
	{entry.verdict | some entry in wrong} == {"issue read partial"}
}

test_an_absent_record_says_nothing if {
	found := violation with input as {"tree": {"records": {}}}
	count(found) == 0
}
