# METADATA
# description: |
#   The ready queue claims every row in it is pullable, and the READY FRONTIER
#   is the subset that is (CLOUD-251, CLOUD-375, CLOUD-477, CLOUD-678; the
#   decision half of the retired `graph-check`, moved into this preset under
#   CLOUD-1221).
#
#   A QUEUE ROW IS ON THE FRONTIER iff the one definition of Ready passes its own
#   payload and every blocker in the set is SETTLED. The Ready verdict is the
#   engine's, asked of `crate::ready` and handed over as a fact — this module
#   never re-derives a clause.
#
#   THREE ARMS, THREE PLACES. An unready queue row is a REFUSAL (CLOUD-375 — the
#   queue is lying), and the refinement gate's own pointers ride beside it as
#   notes. A row the gate could not read is could-not-look. An unsettled blocker
#   is a NOTE, because that is scheduling and the row is not claiming otherwise.
#   A blocker outside the set is could-not-look and never a note (CLOUD-678):
#   "excluded" reads exactly like a legitimate block, and an empty frontier reads
#   as "nothing is ready".
#
#   SETTLED IS A TYPE, OR THE LANDED COLUMN BY NAME (CLOUD-477). The reading's
#   `settles` says the blocker's status TYPE is one the consumer declared
#   settling; the landed column settles on top of that because a board where it
#   shares a type with the pulled column would otherwise starve every row behind
#   landed-but-unreleased work. A blocker settled by being RETIRED still admits
#   its dependent, and says so: its premise may have gone with it.
#
#   The frontier and the notes are not refusals, so they are `board_frontier`
#   and `board_notes` rather than `violation`s: the registry holds refusals, and
#   `batten board check` prints these beside them.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/board_check.rs
#MUTANT todo-refusal-dropped|s@^\tboard_ready\[id\].verdict == "unready"$@\tfalse@|a_todo_issue_with_no_ready_block_is_refused
#MUTANT absent-blocker-reads-as-resolved|s@^\tnot board_row\[to\]$@\tfalse@|a_blocker_outside_the_piped_set_is_unjudgeable_not_resolved
#MUTANT settled-type-ignored|s@^board_settled(to) if board_row\[to\].settles == "yes"$@board_settled(to) if false@|a_todo_row_whose_only_blocker_is_canceled_reaches_the_frontier
#MUTANT in-review-loses-its-name-arm|s@^board_settled(to) if board_row\[to\].column == "review"$@board_settled(to) if false@|a_blocker_in_review_still_resolves_since_its_type_is_started
#MUTANT retirement-is-silent|s@^\tcount(board_retired(id)) > 0$@\tfalse@|a_frontier_row_over_a_retired_blocker_says_so
#MUTANT unsettled-blocker-ignored|s@^\tcount(board_blocking(id)) == 0$@\ttrue@|a_todo_issue_blocked_by_unfinished_work_is_off_the_frontier

# `forward <id> <the Ready gate's own pointer line>`.
board_forwarded contains [f[1], f[2]] if {
	some line in board_graph_lines
	f := split(line, "\t")
	count(f) == 3
	f[0] == "forward"
}

board_queue contains id if {
	some id, row in board_row
	row.column == "ready"
}

board_passing contains id if {
	some id in board_queue
	board_ready[id].verdict == "ready"
}

# A queue row the gate could not read, or one the reading carries no verdict
# for at all: neither may reach the frontier, and neither is a refusal.
board_unjudged_block(id) if board_ready[id].verdict == "unjudgeable"

board_unjudged_block(id) if not board_ready[id]

# The row's blockers in the relation's own order, which is lexical.
board_blockers(id) := sort({edge.to |
	some edge in board_edges
	edge.from == id
})

board_settled(to) if board_row[to].settles == "yes"

board_settled(to) if board_row[to].column == "review"

board_unknown(id) := [to |
	some to in board_blockers(id)
	not board_row[to]
]

board_blocking(id) := [to |
	some to in board_blockers(id)
	board_row[to]
	not board_settled(to)
]

board_retired(id) := [to |
	some to in board_blockers(id)
	board_settled(to)
	board_row[to].retires == "yes"
]

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [{"artifact": id}, {"artifact": "todo-not-ready"}],
} if {
	some id in board_queue
	board_ready[id].verdict == "unready"
}

# The refinement gate's own pointers, forwarded as it wrote them.
board_notes contains pointer if {
	some pair in board_forwarded
	pair[0] in board_queue
	board_ready[pair[0]].verdict == "unready"
	pointer := pair[1]
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [{"artifact": id}, {"artifact": "excluded (unjudgeable-ready-block)"}],
} if {
	some id in board_queue
	board_unjudged_block(id)
}

board_frontier contains id if {
	some id in board_passing
	count(board_unknown(id)) == 0
	count(board_blocking(id)) == 0
}

board_notes contains concat(" ", array.concat([id, "frontier-over-retired-blocker"], board_retired(id))) if {
	some id in board_frontier
	count(board_retired(id)) > 0
}

board_notes contains sprintf("%s excluded (blocked-by %s)", [id, concat(" ", board_blocking(id))]) if {
	some id in board_passing
	count(board_unknown(id)) == 0
	count(board_blocking(id)) > 0
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": id},
		{"artifact": sprintf(
			"excluded (unjudgeable-blocker %s)",
			[concat(" ", array.concat(board_unknown(id), board_blocking(id)))],
		)},
	],
} if {
	some id in board_passing
	count(board_unknown(id)) > 0
}

# --- cases -------------------------------------------------------------------

board_settled_row(ord, id, status, settles, retires) := concat("\t", [
	"row", ord, id, status, "other", "no", "0", "set", "-",
	"declared", settles, retires, "yes",
])

test_board_a_ready_row_with_no_blockers_is_on_the_frontier if {
	tree := board_graph_tree([
		board_row_line("1", "A-1", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-1\tready\tminor",
	])
	board_frontier == {"A-1"} with input as tree
	count(violation) == 0 with input as tree
}

test_board_an_unready_queue_row_is_refused_and_its_pointers_forwarded if {
	tree := board_graph_tree([
		board_row_line("1", "A-1", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-1\tunready\t-",
		"forward\tA-1\tA-1:0 no-ready-block",
	])
	board_pointers(violation) == {"A-1 todo-not-ready"} with input as tree
	board_notes == {"A-1:0 no-ready-block"} with input as tree
	count(board_frontier) == 0 with input as tree
}

test_board_an_unreadable_queue_row_is_a_gap if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-1\tunjudgeable\t-",
	])
	board_pointers(found) == {"A-1 excluded (unjudgeable-ready-block)"}
}

test_board_a_settled_blocker_admits_its_dependent if {
	tree := board_graph_tree([
		board_row_line("2", "A-2", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-2\tready\tminor",
		board_settled_row("1", "A-1", "Shipped", "yes", "no"),
		"edge\tA-2\tA-1\t1",
	])
	board_frontier == {"A-2"} with input as tree
	count(board_notes) == 0 with input as tree
}

test_board_a_retired_blocker_admits_its_dependent_and_says_so if {
	tree := board_graph_tree([
		board_row_line("2", "A-2", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-2\tready\tminor",
		board_settled_row("1", "A-1", "Dropped", "yes", "yes"),
		"edge\tA-2\tA-1\t1",
	])
	board_frontier == {"A-2"} with input as tree
	board_notes == {"A-2 frontier-over-retired-blocker A-1"} with input as tree
}

test_board_a_landed_blocker_settles_by_name if {
	tree := board_graph_tree([
		board_row_line("2", "A-2", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-2\tready\tminor",
		board_row_line("1", "A-1", "Landed", "review", "yes", "1", "set", "-"),
		"ready\tA-1\tready\tminor",
		"edge\tA-2\tA-1\t1",
	])
	board_frontier == {"A-2"} with input as tree
}

test_board_an_open_blocker_holds_its_dependent_as_a_note if {
	tree := board_graph_tree([
		board_row_line("2", "A-2", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-2\tready\tminor",
		board_settled_row("1", "A-1", "Backlog", "no", "no"),
		"edge\tA-2\tA-1\t1",
	])
	count(board_frontier) == 0 with input as tree
	board_notes == {"A-2 excluded (blocked-by A-1)"} with input as tree
	count(violation) == 0 with input as tree
}

test_board_a_blocker_outside_the_set_holds_its_dependent_as_a_gap if {
	tree := board_graph_tree([
		board_row_line("2", "A-2", "Queue", "ready", "no", "0", "set", "-"),
		"ready\tA-2\tready\tminor",
		"edge\tA-2\tA-1\t1",
	])
	count(board_frontier) == 0 with input as tree
	"A-2 excluded (unjudgeable-blocker A-1)" in board_pointers(violation) with input as tree
}
