# METADATA
# description: |
#   The `blockedBy` relation a board carries is a partial order: every row
#   declares its edges, and no row waits on itself through others (CLOUD-175,
#   CLOUD-678; the decision half of the retired `graph-check`, moved into this
#   preset under CLOUD-1221).
#
#   A CYCLE IS A REFUSAL, named with every member in key order. A self-edge is
#   not a cycle — `tsort`'s reading of a pair naming one item twice: it declares
#   the item and orders nothing.
#
#   A ROW CARRYING NO `blockedBy` KEY AT ALL is could-not-look for the set,
#   named once: the caller fetched without relations, and an empty relation and
#   an unfetched one must not be the same bytes. An explicit empty list is data.
#
#   A BLOCKER OUTSIDE THE PIPED SET IS could-not-look AND NEVER A REFUSAL
#   (CLOUD-678): the tracker keeps `blockedBy` after the blocker completes, so an
#   active-only closure carries an edge to a finished ancestor for every landed
#   blocker, and a refusal that fires on correct input trains readers to ignore
#   it.
#
#   THE TRANSITIVE QUESTION IS `graph.reachable`, guarded for the reason
#   `rules/policy-modules.md` gives: the builtin raises on a null graph. The
#   graph here is a comprehension, which is an object even when empty, and
#   every node — a blocker with no edges of its own included — is a key of it,
#   because the builtin never reports a node that is not one.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/board_check.rs
#MUTANT cycle-unseen|s@^\tnode in graph.reachable(board_next, board_next\[node\])$@\tfalse@|a_blocked_by_cycle_is_reported_with_its_members
#MUTANT dangling-blocker-silent|s@^\tcount(board_outside) > 0$@\tfalse@|a_dangling_blocker_is_reported
#MUTANT keyless-set-judged|s@^\tcount(board_keyless) > 0$@\tfalse@|a_set_carrying_no_blocked_by_data_claims_nothing_about_the_graph

board_keyless contains id if {
	some id, row in board_row
	row.edges == "absent"
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": sprintf("unjudgeable-blockedby (%s)", [concat(" ", board_by_num(board_keyless))])},
	],
} if {
	count(board_keyless) > 0
}

board_outside contains edge.to if {
	some edge in board_edges
	not board_row[edge.to]
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": sprintf("dangling-blocker (%s)", [concat(" ", board_by_num(board_outside))])},
	],
} if {
	count(board_outside) > 0
}

board_nodes contains edge.from if {
	some edge in board_edges
}

board_nodes contains edge.to if {
	some edge in board_edges
}

# Each node's successors, self-edges dropped.
board_next := {node: {edge.to |
	some edge in board_edges
	edge.from == node
	edge.to != node
} |
	some node in board_nodes
}

board_cycle contains node if {
	some node in board_nodes
	node in graph.reachable(board_next, board_next[node])
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": sprintf("blockedby-cycle (%s)", [concat(" ", board_by_num(board_cycle))])},
	],
} if {
	count(board_cycle) > 0
}

# --- cases -------------------------------------------------------------------

board_edge_line(from, to, ord) := concat("\t", ["edge", from, to, ord])

test_board_a_two_row_cycle_names_both_in_key_order if {
	found := violation with input as board_graph_tree([
		board_row_line("10", "A-10", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("9", "A-9", "Queue", "other", "no", "0", "set", "-"),
		board_edge_line("A-10", "A-9", "9"),
		board_edge_line("A-9", "A-10", "10"),
	])
	board_pointers(found) == {"graph blockedby-cycle (A-9 A-10)"}
}

test_board_a_self_edge_is_not_a_cycle if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Queue", "other", "no", "0", "set", "-"),
		board_edge_line("A-1", "A-1", "1"),
		board_edge_line("A-2", "A-1", "1"),
	])
	count(found) == 0
}

test_board_a_row_feeding_a_cycle_is_not_a_member if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("3", "A-3", "Queue", "other", "no", "0", "set", "-"),
		board_edge_line("A-1", "A-2", "2"),
		board_edge_line("A-2", "A-1", "1"),
		board_edge_line("A-3", "A-1", "1"),
	])
	board_pointers(found) == {"graph blockedby-cycle (A-1 A-2)"}
}

test_board_a_blocker_outside_the_set_is_one_gap_in_key_order if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_edge_line("A-1", "A-100", "100"),
		board_edge_line("A-1", "A-99", "99"),
	])
	board_pointers(found) == {"graph dangling-blocker (A-99 A-100)"}
	{entry.verdict | some entry in found} == {"issue judge partial"}
}

test_board_a_row_with_no_relation_key_is_a_set_keyed_gap if {
	found := violation with input as board_graph_tree([concat("\t", [
		"row", "1", "A-1", "Queue", "other", "no", "0", "set", "-",
		"absent", "no", "no", "yes",
	])])
	board_pointers(found) == {"graph unjudgeable-blockedby (A-1)"}
}
