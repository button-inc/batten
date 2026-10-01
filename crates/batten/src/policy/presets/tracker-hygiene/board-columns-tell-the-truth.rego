# METADATA
# description: |
#   A board column is a CLAIM about the work, and this module refuses the four
#   claims a payload set can refute on its own (CLOUD-175, CLOUD-735, CLOUD-771,
#   CLOUD-599; the decision half of the retired `graph-check`, moved into this
#   preset under CLOUD-1221).
#
#   PULLED MEANS SOMEBODY HAS IT: a row in the pulled column with no assignee.
#   LANDED MEANS A PULL REQUEST IS ATTACHED — a deliberate approximation a
#   payload alone can check — unless the row's §6 DECLARES it lands no commit,
#   and a row declaring that while carrying a pull request is refused for the
#   contradiction, so `none` is never the cheapest way past the gate.
#   A STARTED ROW NAMES ITS PHASE: an unparented row in the ready queue, the
#   pulled or the landed column carries a milestone. A CHILD OF A PHASED
#   PARENT carries one of its own — the parent's or a different one declared —
#   and a parent outside the piped set is could-not-look, never a refusal.
#
#   THE MILESTONE CLAIM'S ANTI-VACUITY ARM: a tracker OMITS a null milestone, so
#   per row "none" and "projected away" are the same bytes. The SET tells them
#   apart — if no row anywhere carries the key, the caller projected it away,
#   and the question is could-not-look for the whole set, named once.
#
#   THE READING IS THE ENGINE'S AND THE WORDS ARE ALREADY NORMALISED. The
#   `board-graph` record is written by `batten board check` from the consumer's
#   `[board]` table: a row's column arrives as `ready`, `in-progress`, `review`
#   or `other`, so this module names no tracker's columns (non-negotiable rule
#   1). The raw status rides along only to be NAMED in a pointer.
#
#   TWO CLASSES, AND THEY NEVER COLLAPSE. `issue state wrong` is the board
#   signalling falsely; `issue judge partial` is the piped set too thin to
#   answer. A pointer is two artifacts — the row, or `graph` for a property of
#   the whole set, then the rule the retired gate printed — so a reader greps
#   `^<id> <rule>` exactly as before.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.tracker_hygiene

import rego.v1

#MUTANT-SUITE crates/batten/tests/it/board_check.rs
#MUTANT in-progress-unassigned-passes|s@^\trow.assigned == "no"$@\tfalse@|an_unassigned_in_progress_issue_is_reported
#MUTANT in-review-none-not-exempt|s@^\tnot board_declares_none(id)$@\ttrue@|an_in_review_row_declaring_no_commit_is_exempt_from_in_review_no_pr
#MUTANT declared-none-with-pr-passes|s@^\tboard_declares_none(id)$@\tfalse@|a_row_declaring_no_commit_that_carries_a_pr_is_refused_for_the_contradiction
#MUTANT unphased-row-passes|s@^\tnot board_phased(row)$@\tfalse@|a_todo_issue_with_no_milestone_in_a_set_where_others_carry_one_is_refused
#MUTANT unphased-child-passes|s@^\tnot board_phased(child)$@\tfalse@|a_child_with_no_milestone_under_a_milestoned_parent_is_refused
#MUTANT declared-rephase-refused|s@^\tnot board_phased(child)$@\ttrue@|a_child_carrying_a_different_milestone_is_the_declared_rephase_and_passes
#MUTANT absent-milestone-key-judged|s@^\tanyone.milestone != "absent"$@\ttrue@|a_set_with_the_field_absent_everywhere_is_unjudgeable_not_a_wall_of_violations

rules contains "issue state other"

# EVERY NAME HERE IS PREFIXED `board_`, for the shared package's reason: the
# preset's modules are one package, and a bare `row` would collide.
board_graph_lines := input.tree.records["board-graph"]

# `row <ordinal> <id> <status> <column> <assigned> <prs> <milestone> <parent|->
#  <edges> <settles> <retires> <described>`, tab-separated. ONE PER ID: the
# engine keeps the first payload for a key, so this object has no conflicting
# key to fault on.
board_row[id] := {
	"ord": to_number(f[1]),
	"status": f[3],
	"column": f[4],
	"assigned": f[5],
	"prs": to_number(f[6]),
	"milestone": f[7],
	"parent": f[8],
	"edges": f[9],
	"settles": f[10],
	"retires": f[11],
	"described": f[12],
} if {
	some line in board_graph_lines
	f := split(line, "\t")
	count(f) == 13
	f[0] == "row"
	id := f[2]
}

# `edge <from> <to> <the target's ordinal>`. The ordinal rides on the edge
# because a blocker outside the set has no row to carry one, and a dangling
# report is ordered like every other.
board_edges contains {"from": f[1], "to": f[2], "ord": to_number(f[3])} if {
	some line in board_graph_lines
	f := split(line, "\t")
	count(f) == 4
	f[0] == "edge"
}

# `ready <id> <ready|unready|unjudgeable> <the §6 bump|->` — the one definition
# of Ready's own verdict, asked by the engine and never re-derived here.
board_ready[id] := {"verdict": f[2], "bump": f[3]} if {
	some line in board_graph_lines
	f := split(line, "\t")
	count(f) == 4
	f[0] == "ready"
	id := f[1]
}

# The byte-stable order every pointer list uses: by the key's ordinal, then the
# key itself — `sort -t- -k2,2n`, so a later row never precedes an earlier one
# for being lexically smaller.
board_ord(id) := board_row[id].ord

board_ord(id) := edge.ord if {
	not board_row[id]
	some edge in board_edges
	edge.to == id
}

board_by_num(ids) := [pair[1] | some pair in sort([[board_ord(id), id] | some id in ids])]

board_started_column(column) if column in {"ready", "in-progress", "review"}

board_phased(row) if row.milestone == "set"

board_declares_none(id) if board_ready[id].bump == "none"

# --- pulled means somebody has it ----------------------------------------------

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [{"artifact": id}, {"artifact": "in-progress-unassigned"}],
} if {
	some id, row in board_row
	row.column == "in-progress"
	row.assigned == "no"
}

# --- landed means a pull request is attached ----------------------------------

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [{"artifact": id}, {"artifact": "in-review-no-pr"}],
} if {
	some id, row in board_row
	row.column == "review"
	row.prs == 0
	not board_declares_none(id)
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [{"artifact": id}, {"artifact": "declares-no-commit-with-pr"}],
} if {
	some id, row in board_row
	row.column == "review"
	row.prs != 0
	board_declares_none(id)
}

# --- a started row names its phase ----------------------------------------------

board_started contains id if {
	some id, row in board_row
	board_started_column(row.column)
}

board_milestones_judgeable if count(board_started) == 0

board_milestones_judgeable if {
	some anyone in board_row
	anyone.milestone != "absent"
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": "graph"},
		{"artifact": sprintf("unjudgeable-milestone (%s)", [concat(" ", board_by_num(board_started))])},
	],
} if {
	not board_milestones_judgeable
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [{"artifact": id}, {"artifact": sprintf("unmilestoned (%s)", [row.status])}],
} if {
	board_milestones_judgeable
	some id, row in board_row
	row.parent == "-"
	board_started_column(row.column)
	not board_phased(row)
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue state wrong",
	"subjects": [{"artifact": id}, {"artifact": sprintf("child-unmilestoned (parent %s)", [child.parent])}],
} if {
	board_milestones_judgeable
	some id, child in board_row
	child.parent != "-"
	board_phased(board_row[child.parent])
	not board_phased(child)
}

violation contains {
	"rule": "issue state other",
	"verdict": "issue judge partial",
	"subjects": [
		{"artifact": id},
		{"artifact": sprintf("child-milestone-unjudgeable (parent %s not in the set)", [orphan.parent])},
	],
} if {
	board_milestones_judgeable
	some id, orphan in board_row
	orphan.parent != "-"
	not board_row[orphan.parent]
}

# --- cases -------------------------------------------------------------------

board_graph_tree(lines) := {"tree": {"records": {"board-graph": lines}}}

# A row line, spelled by field so a case reads as the fact it states.
board_row_line(ord, id, status, column, assigned, prs, milestone, parent) := concat("\t", [
	"row", ord, id, status, column, assigned, prs, milestone, parent,
	"declared", "no", "no", "yes",
])

board_pointers(found) := {sprintf("%s %s", [entry.subjects[0].artifact, entry.subjects[1].artifact]) |
	some entry in found
}

test_board_an_unassigned_pulled_row_is_refused if {
	found := violation with input as board_graph_tree([board_row_line("1", "A-1", "Doing", "in-progress", "no", "0", "set", "-")])
	board_pointers(found) == {"A-1 in-progress-unassigned"}
}

test_board_an_assigned_pulled_row_passes if {
	found := violation with input as board_graph_tree([board_row_line("1", "A-1", "Doing", "in-progress", "yes", "0", "set", "-")])
	count(found) == 0
}

test_board_a_landed_row_with_no_pull_request_is_refused if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Landed", "review", "yes", "0", "set", "-"),
		"ready\tA-1\tready\tminor",
	])
	board_pointers(found) == {"A-1 in-review-no-pr"}
}

test_board_a_landed_row_declaring_no_commit_is_exempt if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Landed", "review", "yes", "0", "set", "-"),
		"ready\tA-1\tready\tnone",
	])
	count(found) == 0
}

test_board_declaring_no_commit_beside_a_pull_request_is_refused if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Landed", "review", "yes", "1", "set", "-"),
		"ready\tA-1\tready\tnone",
	])
	board_pointers(found) == {"A-1 declares-no-commit-with-pr"}
}

test_board_an_unphased_started_row_is_refused_where_others_are_phased if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Doing", "in-progress", "yes", "0", "empty", "-"),
	])
	board_pointers(found) == {"A-2 unmilestoned (Doing)"}
}

test_board_a_set_projecting_the_milestone_away_is_one_gap if {
	found := violation with input as board_graph_tree([
		board_row_line("10", "A-10", "Doing", "in-progress", "yes", "0", "absent", "-"),
		board_row_line("9", "A-9", "Doing", "in-progress", "yes", "0", "absent", "-"),
	])
	board_pointers(found) == {"graph unjudgeable-milestone (A-9 A-10)"}
	{entry.verdict | some entry in found} == {"issue judge partial"}
}

test_board_an_unphased_child_of_a_phased_parent_is_refused if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Queue", "other", "no", "0", "empty", "A-1"),
	])
	board_pointers(found) == {"A-2 child-unmilestoned (parent A-1)"}
}

test_board_a_child_rephased_by_declaration_passes if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Doing", "in-progress", "yes", "0", "set", "A-1"),
	])
	count(found) == 0
}

test_board_a_parent_outside_the_set_is_a_gap_not_a_refusal if {
	found := violation with input as board_graph_tree([
		board_row_line("1", "A-1", "Queue", "other", "no", "0", "set", "-"),
		board_row_line("2", "A-2", "Queue", "other", "no", "0", "empty", "A-99"),
	])
	board_pointers(found) == {"A-2 child-milestone-unjudgeable (parent A-99 not in the set)"}
	{entry.verdict | some entry in found} == {"issue judge partial"}
}

test_board_an_absent_reading_says_nothing if {
	count(violation) == 0 with input as {"tree": {"records": {}}}
}
