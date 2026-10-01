# METADATA
# description: |
#   A citation is a claim that the thing cited exists, and both directions are
#   refused when it does not (CLOUD-826, CLOUD-920, CLOUD-809; the decision halves
#   of the retired `ready-cites-check` and `spec-ref-check`, moved into this
#   preset under CLOUD-1221).
#
#   A READY BLOCK'S CITATIONS AGAINST THE TREE (`board-cites`). A test the
#   obligations clause names must be carried by some file of the consumer's
#   declared corpus — fixtures excluded, because a fixture quoting a citation is
#   not the thing cited. A cited path must exist, OR be marked prospective by
#   the block, beside its own path, OR be refused (CLOUD-920). A marked path an
#   ancestor DELETED is refused anyway: history may REFUTE a marker and is never
#   asked to grant one, and a shallow clone that cannot answer leaves the marker
#   believed. This checks EXISTENCE, never relevance.
#
#   THE TREE'S CLAUSE CITATIONS AGAINST THE PAYLOADS (`board-refs`). Every
#   `<key> §<n>` in the tracked tree must name a clause its issue's Ready block
#   DECLARES. REFUTES, NEVER CONFIRMS: a sparse clause set is not a defect, and a
#   cited issue absent from the piped set is could-not-look, never a pass —
#   an unfetched issue looks exactly like a clean one (CLOUD-189).
#
#   THE ENGINE READS THE TREE AND THE BODIES; THIS DECIDES. Whether a corpus
#   file carries a token, whether a path exists, whether the block marks it and
#   whether history deleted it are facts `batten board check` acquires; which
#   of them is a refusal is here. The reading carries a key, a token or a path,
#   and a clause number — never a line of a body or of a source file.
#
#   A prospective citation is not a refusal, so it is a `board_notes` line.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/board_check.rs
#MUTANT absent-test-passes|s@^\tcited.found == "no"$@\tfalse@|a_citation_that_resolves_only_in_a_fixture_and_nowhere_else_is_refused
#MUTANT marker-not-required|s@^\tabsent.marked == "no"$@\tfalse@|an_unmarked_absent_path_is_still_refused
#MUTANT marker-outranks-history|s@^\tstale.deleted == "yes"$@\tfalse@|a_marker_on_a_deleted_path_is_refused_not_believed
#MUTANT clause-always-present|s@^\tnot board_clause_carried(hit.key, hit.clause)$@\tfalse@|a_citation_naming_a_clause_the_issue_does_not_carry_is_reported_with_its_pointer
#MUTANT unfetched-issue-passes|s@^\tnot unread.key in board_fetched$@\tfalse@|a_cited_issue_absent_from_the_payload_set_is_could_not_look_never_a_silent_pass

rules contains "path point other"

rules contains "source point other"

board_cites_lines := input.tree.records["board-cites"]

board_refs_lines := input.tree.records["board-refs"]

# `test <key> <token> <found>`.
board_cited_tests contains {"key": f[1], "token": f[2], "found": f[3]} if {
	some line in board_cites_lines
	f := split(line, "\t")
	count(f) == 4
	f[0] == "test"
}

# `path <key> <path> <exists> <marked> <deleted: yes|no|unknown>`.
board_cited_paths contains {"key": f[1], "path": f[2], "exists": f[3], "marked": f[4], "deleted": f[5]} if {
	some line in board_cites_lines
	f := split(line, "\t")
	count(f) == 6
	f[0] == "path"
}

violation contains {
	"rule": "path point other",
	"verdict": "path point missing",
	"subjects": [{"artifact": cited.key}, {"artifact": cited.token}, {"artifact": "absent-cited-test"}],
} if {
	some cited in board_cited_tests
	cited.found == "no"
}

violation contains {
	"rule": "path point other",
	"verdict": "path point missing",
	"subjects": [{"artifact": absent.key}, {"artifact": absent.path}, {"artifact": "absent-cited-path"}],
} if {
	some absent in board_cited_paths
	absent.exists == "no"
	absent.marked == "no"
}

violation contains {
	"rule": "path point other",
	"verdict": "path point missing",
	"subjects": [{"artifact": stale.key}, {"artifact": stale.path}, {"artifact": "stale-cited-path"}],
} if {
	some stale in board_cited_paths
	stale.exists == "no"
	stale.marked == "yes"
	stale.deleted == "yes"
}

board_notes contains sprintf("%s %s prospective-cited-path", [planned.key, planned.path]) if {
	some planned in board_cited_paths
	planned.exists == "no"
	planned.marked == "yes"
	planned.deleted != "yes"
}

# `hit <path> <line> <key> <clause>`.
board_hits contains {"at": sprintf("%s:%s", [f[1], f[2]]), "key": f[3], "clause": f[4]} if {
	some line in board_refs_lines
	f := split(line, "\t")
	count(f) == 5
	f[0] == "hit"
}

# `issue <key>` — a cited key whose body the piped set carries.
board_fetched contains f[1] if {
	some line in board_refs_lines
	f := split(line, "\t")
	count(f) == 2
	f[0] == "issue"
}

# `clause <key> <number>` — a clause that body declares.
board_clause_carried(key, clause) if {
	some line in board_refs_lines
	line == concat("\t", ["clause", key, clause])
}

violation contains {
	"rule": "source point other",
	"verdict": "source point unread",
	"subjects": [{"artifact": unread.at}, {"artifact": unread.key}, {"artifact": "unjudgeable-issue"}],
} if {
	some unread in board_hits
	not unread.key in board_fetched
}

violation contains {
	"rule": "source point other",
	"verdict": "source point wrong",
	"subjects": [
		{"artifact": hit.at},
		{"artifact": hit.key},
		{"artifact": concat("", ["§", hit.clause])},
		{"artifact": "absent-issue-clause"},
	],
} if {
	some hit in board_hits
	hit.key in board_fetched
	not board_clause_carried(hit.key, hit.clause)
}

# --- cases -------------------------------------------------------------------

board_cites_tree(lines) := {"tree": {"records": {"board-cites": lines}}}

board_refs_tree(lines) := {"tree": {"records": {"board-refs": lines}}}

board_rendered(found) := {rendered |
	some entry in found
	rendered := concat(" ", [subject.artifact | some subject in entry.subjects])
}

test_board_a_test_no_corpus_file_carries_is_refused if {
	found := violation with input as board_cites_tree(["test\tA-1\ta_case_nobody_wrote\tno"])
	board_rendered(found) == {"A-1 a_case_nobody_wrote absent-cited-test"}
}

test_board_a_test_the_corpus_carries_passes if {
	count(violation) == 0 with input as board_cites_tree(["test\tA-1\ta_case_that_exists\tyes"])
}

test_board_an_unmarked_absent_path_is_refused if {
	found := violation with input as board_cites_tree(["path\tA-1\tsrc/x.rs\tno\tno\tunknown"])
	board_rendered(found) == {"A-1 src/x.rs absent-cited-path"}
}

test_board_a_marked_absent_path_is_prospective_not_refused if {
	tree := board_cites_tree(["path\tA-1\tsrc/x.rs\tno\tyes\tno"])
	count(violation) == 0 with input as tree
	board_notes == {"A-1 src/x.rs prospective-cited-path"} with input as tree
}

test_board_a_marker_on_a_deleted_path_is_refused_not_believed if {
	tree := board_cites_tree(["path\tA-1\tsrc/x.rs\tno\tyes\tyes"])
	board_rendered(violation) == {"A-1 src/x.rs stale-cited-path"} with input as tree
	count(board_notes) == 0 with input as tree
}

test_board_a_shallow_clone_leaves_the_marker_believed if {
	tree := board_cites_tree(["path\tA-1\tsrc/x.rs\tno\tyes\tunknown"])
	count(violation) == 0 with input as tree
	count(board_notes) == 1 with input as tree
}

test_board_an_existing_path_passes if {
	count(violation) == 0 with input as board_cites_tree(["path\tA-1\tsrc/x.rs\tyes\tno\tunknown"])
}

test_board_a_clause_the_issue_does_not_carry_is_refused_with_its_pointer if {
	found := violation with input as board_refs_tree([
		"hit\tsrc/x.rs\t7\tA-1\t4",
		"issue\tA-1",
		"clause\tA-1\t1",
	])
	board_rendered(found) == {"src/x.rs:7 A-1 §4 absent-issue-clause"}
}

test_board_a_clause_the_issue_carries_passes if {
	count(violation) == 0 with input as board_refs_tree([
		"hit\tsrc/x.rs\t7\tA-1\t4",
		"issue\tA-1",
		"clause\tA-1\t4",
	])
}

test_board_an_unfetched_cited_issue_is_a_gap_never_a_pass if {
	found := violation with input as board_refs_tree(["hit\tsrc/x.rs\t7\tA-9\t1"])
	board_rendered(found) == {"src/x.rs:7 A-9 unjudgeable-issue"}
	{entry.verdict | some entry in found} == {"source point unread"}
}
