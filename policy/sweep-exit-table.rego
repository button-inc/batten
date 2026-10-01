# A `[[board.sweep]]` row reads its gate on the gate's OWN exit table
# (CLOUD-843, p6-board review round 3).
#
# THE HAZARD, AND WHY `config lint` CANNOT SEE IT. `batten board sweep` reads a
# row's exit through the row's `refuses` (default `[2]`, the engine's violation);
# every exit it does not classify is could-not-look. The gates a board composes
# do not share one table: an engine verb refuses at 2 and cannot look at 1, and
# the shell corpus a retirement is still draining INVERTS that — 1 refuses, 2
# cannot look. So `refuses` is correct only relative to the table of the program
# the row runs, and that table lives in a DIFFERENT FILE. A mise task that moves
# from a shell body to an engine chain (the `duplicate-close-check` move P7 of
# CLOUD-843 makes) flips its table underneath an unchanged row, and `[1]` then
# reads every could-not-look as a refusal. `config lint` compares two parsed
# configs and never opens the task, so it is structurally blind to the move;
# before this module the obligation to delete the key lived in a comment.
#
# WHAT DECIDES THE TABLE. A row running the engine directly (`run[0] ==
# "batten"`) is on the engine table. A row running `mise run … <task>` is on the
# table of that task's body: engine when EVERY command line of its `run` invokes
# the engine (the `engine-invocation` pattern), corpus when any line does not —
# a shell body mapping its own exits, which is what the corpus is. A row running
# anything else, or a task this manifest does not define inline (a file task),
# abstains: its table is not decidable from a committed document.
#
# BOTH DIRECTIONS ARE REFUSED, because each launders one answer into the other:
#   * engine table, `refuses` naming 1 — could-not-look reads as a refusal;
#   * engine table, `refuses` not naming 2 — a refusal reads as could-not-look;
#   * corpus table, `refuses` naming 2 (the default does) — could-not-look reads
#     as a refusal;
#   * corpus table, `refuses` not naming 1 — a refusal reads as could-not-look.
#
# NO COULD-NOT-LOOK ARM, on purpose. `input.tree.missing` is never populated on
# the tree surface (`policy/module-map.rego`'s header carries the measurement),
# so an unparseable-manifest clause would be unreachable and its mutant a
# survivor that is right. A row whose task is absent from the parsed manifest
# abstains, which is the honest reading of "not decidable here".
#
# THE MANIFEST IS READ INLINE AT EACH USE SITE, for `task-callable`'s reason: a
# top-level binding of `input.tree.documents["mise.toml"]` silences the module,
# because this manifest declares a task named `deny`.
#
#MUTANT-SUITE crates/batten/tests/it/sweep_exit_table.rs
#MUTANT engine-one-admitted|s@^\trefuses_exit(row, 1)$@\tfalse@|an_engine_task_naming_both_exits_is_refused
#MUTANT engine-two-unrequired|s@^\tnot refuses_exit(row, 2)$@\tfalse@|an_engine_verb_whose_refusal_is_unclassified_is_refused
#MUTANT corpus-two-admitted|s@^\trefuses_exit(row, 2)$@\tfalse@|a_shell_task_naming_both_exits_is_refused
#MUTANT corpus-one-unrequired|s@^\tnot refuses_exit(row, 1)$@\tfalse@|a_shell_task_whose_refusal_is_unclassified_is_refused
#MUTANT task-body-unread|s@^\tbody := input.tree.documents\["mise.toml"\].tasks\[task\]$@\tbody := {}@|an_engine_task_read_through_the_corpus_table_is_refused
#MUTANT corpus-arm-unread|s@^\tnot regex.match(data.batten.patterns\["engine-invocation"\], line)$@\tfalse@|a_task_mixing_shell_and_engine_lines_is_the_corpus_table

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.sweep_exit_table

import rego.v1

rules contains "gate table wrong"

# ---------------------------------------------------------------------------
# The rows, and the exits each one classifies as a refusal.
# ---------------------------------------------------------------------------

sweep_row contains row if {
	some row in input.tree.documents["batten.toml"].board.sweep
	is_string(row.name)
	is_array(row.run)
	count(row.run) > 0
}

# The engine's default when the row names none — `SweepGate::refuses`.
refuses(row) := row.refuses if is_array(row.refuses)

refuses(row) := [2] if not is_array(row.refuses)

refuses_exit(row, code) if code in refuses(row)

# ---------------------------------------------------------------------------
# Which table the row's program answers on.
# ---------------------------------------------------------------------------

mise_task(row) := row.run[count(row.run) - 1] if {
	row.run[0] == "mise"
	row.run[1] == "run"
	count(row.run) > 2
	not startswith(row.run[count(row.run) - 1], "-")
}

run_lines(body) := split(body.run, "\n") if is_string(body.run)

# The array's string entries joined and split once, rather than a nested
# iteration over each entry's split: regorus refused to schedule the nested
# comprehension ("statements not scheduled in query"), so the whole rule faulted
# and decided nothing. Joining with the separator it splits on yields the same
# lines in the same order.
#
# The comprehension is bound in the BODY, not written in the head: regorus also
# refused to schedule it as the head expression of this function.
run_lines(body) := lines if {
	is_array(body.run)
	strings := [command | some command in body.run; is_string(command)]
	lines := split(concat("\n", strings), "\n")
}

# A command line: neither blank nor a shell comment.
commands(body) := [trimmed |
	some line in run_lines(body)
	trimmed := trim_space(line)
	trimmed != ""
	not startswith(trimmed, "#")
]

engine_table(row) if row.run[0] == "batten"

engine_table(row) if {
	task := mise_task(row)
	body := input.tree.documents["mise.toml"].tasks[task]
	lines := commands(body)
	count(lines) > 0
	every line in lines {
		regex.match(data.batten.patterns["engine-invocation"], line)
	}
}

corpus_table(row) if {
	task := mise_task(row)
	body := input.tree.documents["mise.toml"].tasks[task]
	some line in commands(body)
	not regex.match(data.batten.patterns["engine-invocation"], line)
}

# ---------------------------------------------------------------------------
# The four launderings.
# ---------------------------------------------------------------------------

wrong contains row.name if {
	some row in sweep_row
	engine_table(row)
	refuses_exit(row, 1)
}

wrong contains row.name if {
	some row in sweep_row
	engine_table(row)
	not refuses_exit(row, 2)
}

wrong contains row.name if {
	some row in sweep_row
	corpus_table(row)
	refuses_exit(row, 2)
}

wrong contains row.name if {
	some row in sweep_row
	corpus_table(row)
	not refuses_exit(row, 1)
}

# ---------------------------------------------------------------------------
# The pointer: the row's `name = "…"` line, within the three lines after its
# `[[board.sweep]]` header — a bare `name = "…"` search would land on any other
# table's field of the same spelling. A set rather than a function, for
# `task-callable`'s reason: an unplaceable line costs the LINE, never the finding.
# ---------------------------------------------------------------------------

row_line contains [row.name, number] if {
	some row in sweep_row
	some index, line in input.tree.lines["batten.toml"]
	trim_space(line) == "[[board.sweep]]"
	some offset in numbers.range(1, 3)
	trim_space(input.tree.lines["batten.toml"][index + offset]) == concat("", ["name = \"", row.name, "\""])
	number := (index + offset) + 1
}

placed(name) if {
	some placement in row_line
	placement[0] == name
}

violation contains {
	"rule": "gate table wrong",
	"verdict": "gate table wrong",
	"subjects": [{"path": "batten.toml", "line": number}, {"artifact": name}],
} if {
	some name in wrong
	some placement in row_line
	placement[0] == name
	number := placement[1]
}

violation contains {
	"rule": "gate table wrong",
	"verdict": "gate table wrong",
	"subjects": [{"path": "batten.toml"}, {"artifact": name}],
} if {
	some name in wrong
	not placed(name)
}

# --- cases -----------------------------------------------------------------

shell_body := "set -uo pipefail\nrc=0\nbatten check --rule 'x y z' || rc=$?\ncase \"$rc\" in 2) exit 1 ;; 0) exit 0 ;; *) exit 2 ;; esac"

engine_body := ["{{vars.batten}} record derive duplicate-close", "{{vars.batten}} check --rule 'issue state other'"]

tree(row, body) := {
	"documents": {
		"batten.toml": {"board": {"sweep": [row]}},
		"mise.toml": {"tasks": {"gate": {"run": body}}},
	},
	"lines": {"batten.toml": ["[[board.sweep]]", concat("", ["name = \"", row.name, "\""])]},
}

# THE P7 MERGE, as the finding named it: the task moved to the engine chain and
# the row kept the corpus `[1]`.
test_an_engine_task_read_through_the_corpus_table_is_refused if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"], "refuses": [1]}, engine_body)}
	found == {{"rule": "gate table wrong", "verdict": "gate table wrong", "subjects": [{"path": "batten.toml", "line": 2}, {"artifact": "g"}]}}
}

# A row naming BOTH exits is the arm the two `not` clauses cannot reach: 2 is
# classified, so only the named 1 is the laundering.
test_an_engine_task_naming_both_exits_is_refused if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"], "refuses": [1, 2]}, engine_body)}
	count(found) == 1
}

test_a_shell_task_naming_both_exits_is_refused if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"], "refuses": [1, 2]}, shell_body)}
	count(found) == 1
}

# The same move with the key deleted is exactly right.
test_an_engine_task_on_the_default_is_clean if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"]}, engine_body)}
	count(found) == 0
}

# The reverse: the key deleted while the task is still a shell body.
test_a_shell_task_read_on_the_engine_default_is_refused if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"]}, shell_body)}
	count(found) == 1
}

# This branch's own row: a shell body read through `[1]`.
test_a_shell_task_read_through_the_corpus_table_is_clean if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"], "refuses": [1]}, shell_body)}
	count(found) == 0
}

test_a_shell_task_whose_refusal_is_unclassified_is_refused if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"], "refuses": [3]}, shell_body)}
	count(found) == 1
}

test_an_engine_verb_whose_refusal_is_unclassified_is_refused if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["batten", "board", "check"], "refuses": [3]}, shell_body)}
	count(found) == 1
}

test_an_engine_verb_on_the_default_is_clean if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["batten", "board", "check"]}, shell_body)}
	count(found) == 0
}

# ONE shell line makes the body the corpus's: its exits are whatever that shell
# maps them to, not the engine's.
test_a_task_mixing_shell_and_engine_lines_is_the_corpus_table if {
	body := ["{{vars.batten}} record derive x", "test -s out || exit 2"]
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "gate"]}, body)}
	count(found) == 1
}

# A row over a program whose table no committed document states abstains.
test_a_row_over_an_undeclared_program_abstains if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["./gate.sh"], "refuses": [7]}, shell_body)}
	count(found) == 0
}

test_a_row_over_a_task_the_manifest_does_not_define_abstains if {
	found := violation with input as {"tree": tree({"name": "g", "run": ["mise", "run", "-q", "file-task"], "refuses": [1]}, engine_body)}
	count(found) == 0
}

# An unplaceable row still refuses, on the path alone.
test_an_unplaced_row_still_refuses if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"board": {"sweep": [{"name": "g", "run": ["mise", "run", "gate"], "refuses": [1]}]}},
			"mise.toml": {"tasks": {"gate": {"run": engine_body}}},
		},
		"lines": {"batten.toml": []},
	}}
	found == {{"rule": "gate table wrong", "verdict": "gate table wrong", "subjects": [{"path": "batten.toml"}, {"artifact": "g"}]}}
}
