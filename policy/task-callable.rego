# A workflow step naming a `mise run <task>` resolves to a task this tree
# defines (CLOUD-1833).
#
# THE DEFECT, AND WHY NOTHING SAW IT. A retirement deletes a program; no clause
# asked whether its CALLERS still resolve. Measured on this branch at the moment
# the row was written, five scheduled steps across four workflows named tasks
# that do not exist:
#
#   * `release-assets.yml` ran `mise run attestation-check`, deleted by
#     CLOUD-1717's own earlier commit.
#   * `timeout-drift.yml` ran `mise run timeout-drift`, deleted by the same
#     campaign.
#   * `branch-hygiene.yml`, `land-divergence.yml` and `nonverdict-rate.yml` each
#     ran `mise run batten -- check --rule …`, and there has never been a
#     `[tasks.batten]` at all. That spelling was invented once, copied into three
#     files, and then read back by the next author as an established precedent —
#     which is the more interesting half, because nothing about a wrong caller
#     decays over time. It was wrong on the commit that introduced it.
#
# EVERY ONE IS SILENT, WHICH IS WHAT MAKES THIS A DENY RATHER THAN A REPORT. Each
# of those steps fires on `workflow_run`, `schedule` or `workflow_dispatch`, so
# it reaches no pull request and no reviewer: `ci-local-parity` holds its
# properties over `pull_request` workflows and `land` watches a PR's check-runs.
# A workflow failing on 100% of its invocations is indistinguishable from one
# that has never fired — the composition `release-assets.yml` has now paid for
# three times (CLOUD-258, CLOUD-1777, and this row).
#
# THE THIRD POPULATION OF ONE PREDICATE, AND THAT IS THE DESIGN RATHER THAN
# DUPLICATION. `command-task-defined` asks "does this task exist" of a `[[rule]]`
# row's `check`; `verdict-routes-resolve` asks it of a `[[verdict.route]]`'s
# `target`; this asks it of a workflow step's `run`. Each owns its population,
# and they share the `defined` shape deliberately, for the reason
# `verdict-routes-resolve`'s header already states: two spellings of "what tasks
# exist" is the drift a shared question does not survive.
#
# THE PARSED `run:` SCALAR DECIDES; THE LINES ONLY PLACE THE POINTER. These files
# carry long comments that name tasks in order to explain why they are ABSENT —
# `timeout-drift.yml:7` is one — and a gate that fires on its own documentation
# is a gate people delete. That is `ci-parity`'s rule and it binds here; the line
# index is read afterwards, for a task the parsed reading has already decided on,
# which is rule 4's shape: the finding carries `{path, line}` and never the
# command's text.
#
# AN INTERPOLATED TASK NAME ABSTAINS STRUCTURALLY, AND NO GUARD IS WRITTEN FOR
# IT. `mise run ${{ matrix.task }}` and `mise run "$TASK"` are not decidable from
# a committed document — the name is not in the string — and the shared
# `mise-run-task` pattern requires a lowercase letter where the name begins, so
# neither form matches in the first place. A conjunct excluding them would be
# excluded by the pattern before it ran, which is a surviving mutant rather than
# a safeguard.
#
# THE MANIFEST IS READ INLINE AT EACH USE SITE, NEVER BOUND TO A TOP-LEVEL RULE.
# `ci-cache-declared`'s header carries the measurement: a module holding
# `manifest := input.tree.documents["mise.toml"]` goes ENTIRELY silent — every
# predicate, including one whose body is `true` — because this manifest declares
# a task named `deny` and `data.batten.deny` is the composed set the engine
# reads. `defined` below is a set of STRINGS for that reason, and it is why this
# module can bind one at all.
#
#MUTANT-SUITE crates/batten/tests/it/task_callable.rs
#MUTANT dangling-caller-passes|s@\tnot defined\[task\]@\tfalse@|a_workflow_step_naming_an_undefined_task_is_refused
#MUTANT nested-task-unreachable|s@\tname := replace(rel, "/", ":")@\tname := rel@|a_task_backed_by_a_nested_program_resolves

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, so it reads the tree document
#   and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.task_callable

import rego.v1

rules contains "workflow run unknown"

# ---------------------------------------------------------------------------
# What is being judged, and whether there is anything to judge.
# ---------------------------------------------------------------------------

workflow[path] := doc if {
	some path, doc in input.tree.documents
	is_object(doc.jobs)
}

# The guard `hk-fix-selection` measured the need for: a tree with no workflow
# declaring jobs is answering for nothing here, and an unguarded module reports
# against a fixture that carries a copy of the config and none of its subjects.
governed if count(object.keys(workflow)) > 0

# ---------------------------------------------------------------------------
# Tasks this tree defines. The same two sources `command-task-defined` and
# `verdict-routes-resolve` read, in the same shape.
# ---------------------------------------------------------------------------

uses_this_runner if input.tree.documents["mise.toml"]

defined contains name if {
	some name, _ in input.tree.documents["mise.toml"].tasks
}

# A FILE TASK'S NAME IS ITS PATH UNDER `mise-tasks/` WITH THE SEPARATOR SPELLED
# `:`, AND THE NESTED ARM IS NOT DECORATION. `mise-tasks/render/cli.sh` is
# `mise run render:cli`, which `release-artifacts.yml` calls. A reading that took
# only the last path component would resolve it as `cli`, leave `render:cli`
# undefined, and refuse a caller that works — a false positive on the first run,
# which is the failure mode `verdict-routes-resolve`'s own header says gets an
# exception written for it, and the exception is what rots.
defined contains name if {
	uses_this_runner
	some path in input.tree.tracked
	startswith(path, "mise-tasks/")
	rel := substring(path, count("mise-tasks/"), -1)
	name := replace(rel, "/", ":")
}

# Both spellings, because mise accepts the task with or without the program's
# extension and this repository's callers use the bare stem.
defined contains stem if {
	uses_this_runner
	some path in input.tree.tracked
	startswith(path, "mise-tasks/")
	rel := substring(path, count("mise-tasks/"), -1)
	name := replace(rel, "/", ":")
	contains(name, ".")
	stem := split(name, ".")[0]
}

# ---------------------------------------------------------------------------
# The callers, from the parsed document.
# ---------------------------------------------------------------------------

# A PARTIAL SET RATHER THAN A FUNCTION, for `ci-parity`'s reason: a step runs
# many tasks, and a Rego function binding more than one output faults at
# evaluation rather than returning them.
step_task contains [path, task] if {
	some path, _ in workflow
	some name, _ in workflow[path].jobs
	some step in workflow[path].jobs[name].steps
	some fragment in regex.find_n(data.batten.patterns["mise-run-task"], step.run, -1)
	task := split(fragment, " ")[2]
}

# NOT A FUNCTION, AND THAT IS CORRECTNESS RATHER THAN STYLE — `ci-cache-declared`
# states it at the same shape. A `pointer(path, line_of(path))` spelling makes
# the whole refusal undefined whenever the line index cannot place the subject,
# because Rego propagates undefined through an argument, so a `line_sources` glob
# that drifted would switch the gate off silently. As a set, a line that cannot
# be placed costs the LINE and never the finding.
task_line contains [path, task, number] if {
	some [path, task] in step_task
	some index, line in input.tree.lines[path]
	some fragment in regex.find_n(data.batten.patterns["mise-run-task"], line, -1)
	split(fragment, " ")[2] == task
	number := index + 1
}

placed(path, task) if {
	some placement in task_line
	placement[0] == path
	placement[1] == task
}

# ---------------------------------------------------------------------------
# The refusals.
# ---------------------------------------------------------------------------

violation contains {
	"rule": "workflow run unknown",
	"verdict": "task run unknown",
	"subjects": [{"path": path, "line": number}, {"artifact": task}],
} if {
	governed

	# Could-not-look guard, `command-task-defined`'s: with no task namespace there
	# is nothing to judge against, and reporting there makes the rule fire on
	# every tree that merely holds a copy of this config.
	count(defined) > 0
	some [path, task] in step_task
	not defined[task]
	some placement in task_line
	placement[0] == path
	placement[1] == task
	number := placement[2]
}

# The path-only arm, for a caller the line index could not place.
violation contains {
	"rule": "workflow run unknown",
	"verdict": "task run unknown",
	"subjects": [{"path": path}, {"artifact": task}],
} if {
	governed
	count(defined) > 0
	some [path, task] in step_task
	not defined[task]
	not placed(path, task)
}

# COULD NOT LOOK, NEVER A SILENT PASS. A declared source that would not parse is
# in `input.tree.missing` rather than merely absent from `documents`, and a
# module that iterated only `documents` would report green over a file it never
# read.
#
# TWO CLASSES RATHER THAN ONE, because the two absences are not the same finding
# and a reader acts on them differently. An unreadable manifest makes EVERY task
# read as undefined, so the whole gate abstained; an unreadable workflow leaves
# the rest of the tree judged and only that file's callers unexamined. Collapsing
# them would put a total abstention and a single unread file under one name.
#
# BOTH CLASSES ARE THE ONES `ci-cache-declared` ALREADY RAISES over the same two
# declared sources, and reusing them is the point rather than a shortcut: this
# module reads the same manifest for the same reason, so a reader who has met
# `task resolve missing` once should not have to learn a second name for it.
violation contains {
	"rule": "workflow run unknown",
	"verdict": "workflow read unread",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	endswith(path, ".yml")
}

violation contains {
	"rule": "workflow run unknown",
	"verdict": "task resolve missing",
	"subjects": [{"path": path}],
} if {
	some path, _ in input.tree.missing
	path == "mise.toml"
}

# --- cases -----------------------------------------------------------------

test_a_workflow_step_naming_an_undefined_task_is_refused if {
	found := violation with input as {"tree": {
		"documents": {
			"mise.toml": {"tasks": {"present": {}}},
			".github/workflows/w.yml": {"jobs": {"j": {"steps": [{"run": "mise run absent-task"}]}}},
		},
		"lines": {".github/workflows/w.yml": ["        run: mise run absent-task"]},
		"tracked": ["mise.toml"],
		"missing": {},
	}}
	count(found) == 1
}

test_a_workflow_step_naming_a_defined_task_is_clean if {
	found := violation with input as {"tree": {
		"documents": {
			"mise.toml": {"tasks": {"present": {}}},
			".github/workflows/w.yml": {"jobs": {"j": {"steps": [{"run": "mise run present"}]}}},
		},
		"lines": {".github/workflows/w.yml": ["        run: mise run present"]},
		"tracked": ["mise.toml"],
		"missing": {},
	}}
	count(found) == 0
}

# A task backed by a file program rather than a `[tasks.…]` table resolves.
test_a_task_backed_by_a_program_resolves if {
	found := violation with input as {"tree": {
		"documents": {
			"mise.toml": {"tasks": {}},
			".github/workflows/w.yml": {"jobs": {"j": {"steps": [{"run": "mise run checksums"}]}}},
		},
		"lines": {".github/workflows/w.yml": ["        run: mise run checksums"]},
		"tracked": ["mise.toml", "mise-tasks/checksums.sh"],
		"missing": {},
	}}
	count(found) == 0
}

# THE NESTED ARM'S OWN CASE. `mise-tasks/render/cli.sh` is `mise run render:cli`,
# and a reading that took the last path component alone would refuse it.
test_a_task_backed_by_a_nested_program_resolves if {
	found := violation with input as {"tree": {
		"documents": {
			"mise.toml": {"tasks": {}},
			".github/workflows/w.yml": {"jobs": {"j": {"steps": [{"run": "mise run render:cli"}]}}},
		},
		"lines": {".github/workflows/w.yml": ["        run: mise run render:cli"]},
		"tracked": ["mise.toml", "mise-tasks/render/cli.sh"],
		"missing": {},
	}}
	count(found) == 0
}

# THE PROSE ARM. A comment naming a task in order to explain that it is ABSENT
# must not fire the gate — the parsed `run:` scalar is what decides.
test_a_comment_naming_an_absent_task_is_not_judged if {
	found := violation with input as {"tree": {
		"documents": {
			"mise.toml": {"tasks": {"present": {}}},
			".github/workflows/w.yml": {"jobs": {"j": {"steps": [{"run": "mise run present"}]}}},
		},
		"lines": {".github/workflows/w.yml": [
			"# The commit half is `mise run absent-task`, in the hk gate.",
			"        run: mise run present",
		]},
		"tracked": ["mise.toml"],
		"missing": {},
	}}
	count(found) == 0
}

# AN INTERPOLATED NAME ABSTAINS, and this case is what makes that claim earn
# itself rather than being asserted in the header.
test_an_interpolated_task_name_is_not_judged if {
	found := violation with input as {"tree": {
		"documents": {
			"mise.toml": {"tasks": {"present": {}}},
			".github/workflows/w.yml": {"jobs": {"j": {"steps": [{"run": "mise run ${{ matrix.task }}"}]}}},
		},
		"lines": {".github/workflows/w.yml": ["        run: mise run ${{ matrix.task }}"]},
		"tracked": ["mise.toml"],
		"missing": {},
	}}
	count(found) == 0
}

# A tree with no workflow declaring jobs is answering for nothing.
test_a_tree_with_no_workflow_is_not_judged if {
	found := violation with input as {"tree": {
		"documents": {"mise.toml": {"tasks": {"present": {}}}},
		"lines": {},
		"tracked": ["mise.toml"],
		"missing": {},
	}}
	count(found) == 0
}

test_an_unreadable_manifest_is_loud if {
	found := violation with input as {"tree": {
		"documents": {},
		"lines": {},
		"tracked": [],
		"missing": {"mise.toml": "unparsed"},
	}}
	count(found) == 1
}

# The two could-not-look arms are distinct classes, not one spelled twice — and a
# case counting the findings cannot see that. This one reads the verdicts.
test_the_two_could_not_look_classes_stay_distinct if {
	found := violation with input as {"tree": {
		"documents": {},
		"lines": {},
		"tracked": [],
		"missing": {
			"mise.toml": "unparsed",
			".github/workflows/w.yml": "unparsed",
		},
	}}
	{entry.verdict | some entry in found} == {"task resolve missing", "workflow read unread"}
}

# The other could-not-look arm, reaching the same rule by a second route — which
# is what proves the two classes stay distinct through projection rather than
# collapsing into whichever one the first case happened to spell.
test_an_unreadable_workflow_is_loud if {
	found := violation with input as {"tree": {
		"documents": {"mise.toml": {"tasks": {"present": {}}}},
		"lines": {},
		"tracked": ["mise.toml"],
		"missing": {".github/workflows/w.yml": "unparsed"},
	}}
	count(found) == 1
}

# The anti-vacuity arm: a tree whose every caller resolves must be silent, or a
# module that refused nothing would pass every negative case above.
test_a_tree_whose_callers_resolve_is_silent if {
	found := violation with input as {"tree": {
		"documents": {
			"mise.toml": {"tasks": {"present": {}}},
			".github/workflows/w.yml": {"jobs": {"j": {"steps": [
				{"run": "mise run present"},
				{"run": "mise run checksums && mise run render:cli"},
			]}}},
		},
		"lines": {".github/workflows/w.yml": [
			"        run: mise run present",
			"        run: mise run checksums && mise run render:cli",
		]},
		"tracked": ["mise.toml", "mise-tasks/checksums.sh", "mise-tasks/render/cli.sh"],
		"missing": {},
	}}
	count(found) == 0
}
