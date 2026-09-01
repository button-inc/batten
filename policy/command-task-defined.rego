# A `command` row names a task this tree defines (CLOUD-614).
#
# `mise run <task>` resolves from the working directory, and the working
# directory is the tree being checked. A row naming a task that is not there does
# NOT fail to launch — the runner is on PATH, so it starts, exits non-zero, and
# the engine turns that into a finding AT THE ROW'S OWN SEVERITY.
#
# MEASURED: a scratch tree carrying only a lockfile produced a `deny`-severity
# finding asserting that tree was NTIA-nonconformant, having inspected nothing.
# That is the false red this engine exists to prevent, arriving as a confident
# verdict rather than as an error somebody would notice. The existing rows
# survive on glob luck alone: they select a lockfile and no fixture carries one.
#
# WHY THIS IS A CONSUMER POLICY AND NOT AN ENGINE CHECK. CLOUD-614's Ready block
# put this clause in `config-lint`, which lives in `crates/batten`. Implemented
# there it fails immediately, and the tree says so: `no_artifact_name_reaches_
# the_core` refused the branch, naming `src/lint.rs:221 mise.toml` twice. A task
# RUNNER is a consumer's choice, and non-negotiable rule 1 keeps the core
# ignorant of it — the engine knows formats, and which file carries which is the
# consumer's `batten.toml`. So the clause belongs where the runner is known,
# which is here.
#
# It costs nothing to express: `batten.toml` and the manifest are both parsed
# documents, and the file-task half is `input.tree.tracked`, which the walk
# already yields. Nothing new is read.
#
# THE ROW IS NOT REFUSED FOR SPELLING `mise run`. CLOUD-614 chose the premise
# that a `command` row is a claim about the repository that AUTHORED the config,
# so naming a task is legal; only naming a missing one is a defect.
#
# KNOWN RESIDUAL, from that same decision. A foreign tree defining a task of the
# same name still gets ITS task run: this asserts the task exists, never that it
# is the one the author wrote. Closing that needs a program on PATH, which
# CLOUD-614 declined. It stays a property of the premise — `batten check` is
# supported in the tree that authored its config — and the fixture is what keeps
# that premise honest.
#MUTANT-EXEMPT CLOUD-845|no compiled-binary tier names this module at all, so there is no suite a declared mutation could redden. That is not the `tests/$gate.bats` hole CLOUD-1267 closed — a suite may now be DECLARED — it is that none exists to declare, and what is owed is the tier

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.command_task_defined

import rego.v1

rules contains "command-task-defined"

# Tasks the manifest declares under `[tasks]`.
defined contains name if {
	some name, _ in input.tree.documents["mise.toml"].tasks
}

# FILE TASKS, from the walk the run already did. A task directory entry is a task
# named by its basename, and the runner strips a single extension — `land.sh` is
# `mise run land`. Both spellings are recorded rather than chosen between,
# because a row naming either resolves.
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

# THE MANIFEST IS THE MARKER, and this predicate is what keeps the rule from
# judging a tree that merely HOLDS a copy of this config.
#
# Measured twice, and the second measurement is why the marker is the manifest
# rather than a non-empty namespace. Guarding on "any task found" was not enough:
# a fixture carrying one unrelated task file gave a namespace of exactly that
# file, and the six real `mise run` rows in the copied config then read as naming
# missing tasks — six findings, against a tree whose task namespace is nobody's
# claim. Supplying the real namespace instead was tried and rejected on cost, at
# ~370s per fixture case against ~1.7s.
#
# A tree with no manifest does not use this runner, so a config sitting in it is
# not its authority and its rows are not its claims to answer for. That is
# CLOUD-614's chosen premise applied to the rule itself.
uses_this_runner if input.tree.documents["mise.toml"]

# Every task a `command` row spawns, from either column. `fix` is read for the
# same reason as `check`: `RuleKind::permits` lists both among the `command`
# kind's columns, so a repair is spawned the same way and inherits the same
# failure. Linting one and not the other leaves half the surface unjudged.
spawned contains {"id": row.id, "task": task} if {
	some row in input.tree.documents["batten.toml"].rule
	some column in ["check", "fix"]
	task := mise_task(row[column])
}

# The task a `mise run` command names, or nothing for any other program.
#
# Deliberately narrow: only the exact shape is claimed. A different program, a
# bare runner invocation, or a flag-only one is not this rule's business and is
# left alone rather than guessed at.
mise_task(command) := task if {
	words := [word | some word in split(command, " "); word != ""]
	words[0] == "mise"
	words[1] == "run"
	rest := [word | some i, word in words; i > 1; not startswith(word, "-")]
	task := rest[0]
}

violation contains {
	"rule": "command-task-defined",
	# The row first, then the task it names: the fix is on the row.
	"verdict": "task name undefined",
	"subjects": [{"artifact": row.id}, {"artifact": row.task}],
} if {
	# ONLY WHERE A TASK SOURCE WAS FOUND. Without this guard the rule reproduces
	# the very defect it exists to fix: pointed at a tree with no task source —
	# a fixture that copies `batten.toml` and nothing else — every `mise run` row
	# reads as naming a missing task, and the gate reports a row-per-violation
	# verdict about a tree it could not assess. Measured: seven findings against
	# `tests/prebuilt-lint.bats`, whose first case is named "this repository is
	# clean today". An empty namespace is could-not-look, and the clause below
	# says so ONCE.
	count(defined) > 0
	some row in spawned
	not defined[row.task]
}

# COULD NOT LOOK, NEVER A SILENT PASS. Both documents are declared, so either
# being absent from `documents` means the walk never read it and no row can be
# judged — which must not be spelled the same way as a config whose every task
# resolves.
violation contains {
	"rule": "command-task-defined",
	"verdict": "config parse broken",
	"subjects": [{"path": path}],
} if {
	# THE AUTHORITY ONLY. `mise.toml` is declared as a source and lands in
	# `missing` whenever a tree simply does not have one — which is every fixture
	# that copies this config, and is not-applicable rather than could-not-look
	# (see the decision below). `batten.toml` is different: it carries the rows,
	# so a tree that could not read it cannot have its rows judged at all.
	some path, _ in input.tree.missing
	endswith(path, "batten.toml")
}

# WHY THERE IS NO "NO TASKS FOUND" CLAUSE, decided against and recorded rather
# than omitted by accident.
#
# One was written first and it broke four fixture cases, including the one named
# "this repository is clean today". Those fixtures COPY `batten.toml` into a
# scratch tree without a task namespace, so the rule saw rows to judge and no
# tasks, called it could-not-look, and reported. Supplying the namespace instead
# was tried and rejected on cost: copying the task tree took each case from
# ~1.7s to ~370s, because the walk then covers every task file.
#
# The distinction that survives is between the two absences, and only one of
# them is could-not-look:
#
#   * a manifest that EXISTS and did not parse -- the boundary tried and failed,
#     which is the `input.tree.missing` clause above, and it stays loud;
#   * no task source AT ALL -- this tree does not use the runner, so there is no
#     namespace to be judged against and no question was asked.
#
# The second is not-applicable, and spelling it as a violation makes the rule
# fire on every tree that merely HOLDS a copy of this config. That is the same
# false red CLOUD-614 is about, reproduced by the gate meant to prevent it --
# measured here as seven findings against a fixture, before the guard above.
#
# What it costs is stated rather than hidden: a tree carrying `mise run` rows and
# no runner at all gets no finding. Under CLOUD-614's chosen premise -- a
# `command` row is a claim about the repository that AUTHORED the config -- such
# a tree is not the authority, and the rows are not its claims to answer for.

# --- cases ---------------------------------------------------------------

test_a_row_naming_an_undefined_task_is_refused if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"rule": [{"id": "r", "check": "mise run absent-task"}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": [],
		"missing": {},
	}}
	count(found) == 1
}

test_a_row_naming_a_manifest_task_is_clean if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"rule": [{"id": "r", "check": "mise run present"}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": [],
		"missing": {},
	}}
	count(found) == 0
}

# A FILE TASK COUNTS, and both spellings of it. Missing this would report a false
# red on most of this repository's own rows, which is worse than the silence it
# replaces: a gate whose first firing is a false positive gets switched off.
test_a_file_task_counts_with_and_without_its_extension if {
	every check in ["mise run land", "mise run land.sh"] {
		found := violation with input as {"tree": {
			"documents": {
				"batten.toml": {"rule": [{"id": "r", "check": check}]},
				"mise.toml": {"tasks": {}},
			},
			"tracked": ["mise-tasks/land.sh"],
			"missing": {},
		}}
		count(found) == 0
	}
}

# THE `fix` COLUMN IS THE SAME SURFACE. A repair is spawned the same way, so a
# rule reading only `check` leaves half of it unjudged.
test_a_repair_naming_an_undefined_task_is_refused if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"rule": [{"id": "r", "fix": "mise run absent-task"}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": [],
		"missing": {},
	}}
	count(found) == 1
}

# A PROGRAM ON PATH IS NOT THIS RULE'S BUSINESS — the shape that never had the
# defect. Reporting it would refuse the one `command` row spelling that works
# everywhere.
test_a_program_on_path_is_left_alone if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"rule": [{"id": "r", "check": "hk util check-merge-conflict"}]},
			"mise.toml": {"tasks": {}},
		},
		"tracked": ["mise-tasks/land.sh"],
		"missing": {},
	}}
	count(found) == 0
}

# Flags between `run` and the task must not be read as the task.
test_a_flag_is_not_mistaken_for_the_task if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"rule": [{"id": "r", "check": "mise run --quiet present --precondition"}]},
			"mise.toml": {"tasks": {"present": {}}},
		},
		"tracked": [],
		"missing": {},
	}}
	count(found) == 0
}

# An unreadable AUTHORITY is loud: it carries the rows, so nothing can be judged.
test_an_unreadable_authority_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"tracked": [],
		"missing": {"batten.toml": "absent"},
	}}
	count(found) == 1
}

# AN ABSENT MANIFEST IS NOT-APPLICABLE, and this case is why the clause above is
# narrowed. `mise.toml` is a declared source, so every tree without one puts it
# in `missing` — including every fixture that copies this config. Reporting there
# is CLOUD-614's own false red, measured as a failure of the case named "this
# repository is clean today".
test_an_absent_manifest_is_not_reported if {
	found := violation with input as {"tree": {
		"documents": {"batten.toml": {"rule": [{"id": "r", "check": "mise run anything"}]}},
		"tracked": ["mise-tasks/other.sh"],
		"missing": {"mise.toml": "absent"},
	}}
	count(found) == 0
}

# The vacuity clause: rows to judge and no task source found is could-not-look,
# never consent.
# THE DECISION ABOVE, AS A CASE. A tree with rows to judge and no task source is
# NOT-APPLICABLE, not could-not-look: reporting here makes the rule fire on every
# tree merely holding a copy of this config, which is CLOUD-614's own false red.
# Measured before the guard: seven findings against `tests/prebuilt-lint.bats`.
test_rows_with_no_task_source_at_all_are_not_this_rules_business if {
	found := violation with input as {"tree": {
		"documents": {
			"batten.toml": {"rule": [{"id": "r", "check": "mise run anything"}]},
			"mise.toml": {"tasks": {}},
		},
		"tracked": [],
		"missing": {},
	}}
	count(found) == 0
}
