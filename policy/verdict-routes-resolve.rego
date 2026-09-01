# Every route a declared verdict offers resolves to something (CLOUD-1050).
#
# The registry's other half. `verdict::validate` decides the SHAPE of a route —
# a `R-` prefix, a kind from the closed set, an override that states a
# precondition, a class that is not an override alone — and it decides all of it
# without a tree, which is why it lives at parse. What it cannot decide is
# whether the route points at anything, because that is a question about THIS
# tree.
#
# WHY THIS IS A MODULE AND NOT A LINE OF RUST. The load-bearing half is a
# `command` route naming a task, and `mise run <task>` is a task RUNNER's
# spelling. Non-negotiable rule 1 keeps the core ignorant of one — the engine
# knows formats, and which file carries which is the consumer's `batten.toml`.
# CLOUD-614 hit exactly this and the tree said so: implementing the sibling
# clause in `crates/batten` was refused by `no_artifact_name_reaches_the_core`.
# So the clause belongs where the runner is known, which is here, and
# `policy/command-task-defined.rego` is the same predicate over `[[rule]]` rows.
#
# WHY IT MATTERS MORE HERE THAN THERE. A `command` ROW naming a missing task
# fails loudly the first time it runs. A ROUTE naming one fails at the worst
# possible moment: a reader has just been refused, has been handed the one thing
# to run, runs it, and is told the task does not exist. That is CLOUD-122's bare
# no with an extra step, and it is the defect CLOUD-680 measured — an override
# hiding among four costumes while the human audited four mechanisms to find the
# one decision.
#
# WHAT IT DOES NOT DECIDE, stated rather than discovered. That the task, once
# run, actually clears the refusal is not checkable here and would be the model
# verdict rule 3 forbids. And a route naming a program on PATH is left alone, for
# `command-task-defined`'s reason: only the `mise run` shape is claimed.
#
# ─── THE `document` ARM WAS WRITTEN, MEASURED AND DROPPED ────────────────────
#
# It refused a `document` route whose target no tracked path matched, and it is
# not decidable from a PARTIAL tree. `command-task-defined`'s marker —
# "`mise.toml` is a parsed document, so this tree uses this runner" — does not
# separate the two populations here: a fixture that copies this repository's
# `batten.toml` AND its `mise.toml` into a scratch directory satisfies it while
# carrying none of the files the routes name. Measured on three cases of
# `tests/prebuilt-lint.bats`, six findings each, against trees whose routes are
# not broken at all.
#
# No honest marker separates them. "Is this the tree that authored the config" is
# the question, and every candidate answer is either consumer-specific (rule 1)
# or satisfied by the fixture too. A gate whose first firing is a false positive
# gets an exception written for it, and the exception is what rots — so the arm
# is absent rather than exempted. What survives is the arm that matters most: a
# `command` route naming a missing task fails at the worst possible moment, and
# it IS decidable, by the marker CLOUD-614 already validated.
#
# The brackets are escaped: unescaped, `[entry.task]` is a sed bracket
# expression and this row could never match the line it names.
#MUTANT route-task-unchecked|s@not defined\[entry.task\]@false@|a_command_route_naming_an_undefined_task_is_refused_over_the_engine
#
#MUTANT-SUITE crates/batten/tests/verdict_registry.rs

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.verdict_routes

import rego.v1

rules contains "verdict-routes-resolve"

# ---------------------------------------------------------------------------
# The routes, flattened out of the registry.
# ---------------------------------------------------------------------------

route_rows contains {
	"verdict": entry.id,
	"route": row.id,
	"kind": row.kind,
	"target": row.target,
} if {
	some entry in input.tree.documents["batten.toml"].verdict
	some row in entry.route
}

# ---------------------------------------------------------------------------
# Tasks this tree defines. The same two sources `command-task-defined` reads,
# and deliberately the same shape: two spellings of "what tasks exist" is the
# drift a shared question does not survive.
# ---------------------------------------------------------------------------

uses_this_runner if input.tree.documents["mise.toml"]

defined contains name if {
	some name, _ in input.tree.documents["mise.toml"].tasks
}

defined contains name if {
	uses_this_runner
	some path in input.tree.tracked
	startswith(path, "mise-tasks/")
	parts := split(path, "/")
	name := parts[count(parts) - 1]
}

defined contains stem if {
	uses_this_runner
	some path in input.tree.tracked
	startswith(path, "mise-tasks/")
	parts := split(path, "/")
	name := parts[count(parts) - 1]
	contains(name, ".")
	stem := split(name, ".")[0]
}

# The task a `mise run` route names, or nothing for any other program. Narrow on
# purpose: `git cherry` is a route and is not this rule's business.
mise_task(command) := task if {
	words := [word | some word in split(command, " "); word != ""]
	words[0] == "mise"
	words[1] == "run"
	rest := [word | some i, word in words; i > 1; not startswith(word, "-")]
	task := rest[0]
}

# ---------------------------------------------------------------------------
# The refusals.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "verdict-routes-resolve",
	"verdict": "V-ROUTE-TASK-UNDEFINED",
	"subjects": [{"artifact": entry.verdict}, {"artifact": entry.route}, {"artifact": entry.task}],
} if {
	# Could-not-look guard, `command-task-defined`'s: with no task namespace
	# there is nothing to judge against, and reporting there makes the rule fire
	# on every tree that merely holds a copy of this config.
	count(defined) > 0
	some row in route_rows
	row.kind == "command"
	task := mise_task(row.target)
	entry := object.union(row, {"task": task})
	not defined[entry.task]
}

# COULD NOT LOOK, NEVER A SILENT PASS. The authority carries the registry, so a
# tree that could not read it has judged no route at all — which must not be
# spelled the same way as a registry whose every route resolves.
violation contains {
	"rule": "verdict-routes-resolve",
	"verdict": "V-AUTHORITY-UNPARSED",
	"subjects": [{"path": path}],
} if {
	some path in input.tree.missing
	endswith(path, "batten.toml")
}

# --- cases ---------------------------------------------------------------

test_a_command_route_naming_an_undefined_task_is_refused if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"verdict": [{
				"id": "V-X",
				"route": [{"id": "R-X", "kind": "command", "target": "mise run absent-task"}],
			}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": ["mise.toml"],
		"missing": [],
	}}
	count(found) == 1
}

test_a_command_route_naming_a_defined_task_is_clean if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"verdict": [{
				"id": "V-X",
				"route": [{"id": "R-X", "kind": "command", "target": "mise run present"}],
			}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": ["mise.toml"],
		"missing": [],
	}}
	count(found) == 0
}

# A ROUTE NAMING A PROGRAM ON PATH IS LEFT ALONE — the shape that never had the
# defect, and refusing it would make the one route spelling that works
# everywhere unwritable.
test_a_program_on_path_is_not_judged if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"verdict": [{
				"id": "V-X",
				"route": [{"id": "R-X", "kind": "command", "target": "git cherry"}],
			}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": ["mise.toml"],
		"missing": [],
	}}
	count(found) == 0
}

# An override route points at neither a task nor a file, so it is judged by
# neither clause. Its `precondition` is `verdict::validate`'s question.
test_an_override_route_is_not_judged_here if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"verdict": [{
				"id": "V-X",
				"route": [{"id": "R-ASK", "kind": "override", "target": ""}],
			}]},
			"mise.toml": {"tasks": {}},
		},
		"tracked": ["batten.toml"],
		"missing": [],
	}}
	count(found) == 0
}

test_an_unreadable_authority_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"tracked": [],
		"missing": ["batten.toml"],
	}}
	count(found) == 1
}

# The anti-vacuity arm: a registry whose every route resolves must be silent, or
# a module that refused nothing would pass every negative case above.
test_a_resolving_registry_is_silent if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"verdict": [{
				"id": "V-X",
				"route": [
					{"id": "R-RUN", "kind": "command", "target": "mise run present"},
					{"id": "R-READ", "kind": "document", "target": "batten.toml"},
				],
			}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": ["batten.toml", "mise.toml"],
		"missing": [],
	}}
	count(found) == 0
}
