#MUTANT-SUITE crates/batten/tests/it/policy_presets.rs
#MUTANT alias-table-emptied|s@^\tsome name, argv in defined$@\tsome name, argv in {}@|every_shipped_preset_passes_its_own_suite
# A task runner's task is reached through the task, not through its program.
#
# The practice is that a project which defines a task has already decided how
# that work is invoked — which program, which arguments, and which environment
# composes around it. Running the task's own program directly reproduces the
# argv and drops everything else, and the failure that produces is the dangerous
# kind: it looks like the failure the caller was investigating.
#
# **This names the TASK, which is the whole affordance.** A guard over the
# program can only say "you reached around something"; this says what to run
# instead, because the mapping it reads is task name -> argv and the refusal
# carries the name. A caller told `opa` was reached loosely has to go and find
# which task wraps it; a caller told the task's name has the remedy in the
# refusal.
#
# THE MAPPING IS A RECEIPT, NOT A PARSE. `input.facts.tasks` is minted OUTSIDE
# the mediated call, at session start, so this path parses no manifest, invokes
# no runner, probes no binary and walks no tree. The receipt's key is recomputed
# from the manifest as it stands, so a record about a manifest that has since
# moved does not answer at all.
#
# **`null` IS COULD-NOT-LOOK AND IT LEAVES THIS SILENT.** A stale, tampered,
# unwritten or oversized receipt makes the whole fact `null`, the set below
# empty, and the predicate unable to hold. That is the only safe direction: a
# refusal on a failure to look would refuse every command in a project whose
# receipt happened to be missing. It is also why the fact is `null` rather than
# an empty table one level down — a guard comparing against an empty table would
# permit every substitution it exists to refuse, and here the two arms are the
# same shape by construction.
#
# NAMES NO TASK, NO PROGRAM AND NO RUNNER, which is what a vendored preset may
# contain (non-negotiable rule 1). Every name in the refusal comes from the
# consumer's own receipt, and a preset that named one would be a single project's
# manifest wearing a practice's clothes.
package batten.mise

import rego.v1

rules contains "task-over-executable"

# The tasks this project's receipt defines, as name -> argv.
#
# A task whose body is not a single command is `null` in the receipt — a
# pipeline, a sequence, a multi-line body — and is skipped here rather than
# guessed at: its first word is not what running it would reach.
defined[name] := argv if {
	tasks := input.facts.tasks
	is_object(tasks)
	some name, argv in tasks
	is_array(argv)
	count(argv) > 0
}

# The program a task would reach, per task.
runs[program] := name if {
	some name, argv in defined
	program := argv[0]
}

# One entry per segment, so a task's program reached in the second half of a
# pipeline is as visible as one in the first.
#
# `mediated` is the BOUNDARY's reading rather than this module's. Deciding it
# here would mean re-implementing the wrapper look-through, the environment
# assignments and every spelling of the runner's own invocation — a second
# authority over an argv the engine already parses.
violation contains {
	"rule": "task-over-executable",
	"verdict": "task reach loose",
	"subjects": [{"artifact": runs[entry.name]}],
} if {
	some entry in input.call.programs
	not entry.mediated
	runs[entry.name]
}

deny contains finding if some finding in violation

# --- cases ---------------------------------------------------------------

test_a_tasks_own_program_reached_directly_is_refused if {
	some finding in violation with input as {
		"facts": {"tasks": {"a-task": ["a-program", "--flag"]}},
		"call": {"programs": [{"name": "a-program", "mediated": false}]},
	}

	finding.rule == "task-over-executable"
}

# The refusal names the TASK, never the program: that is the affordance a guard
# over the program alone cannot give.
test_the_refusal_names_the_task_rather_than_the_program if {
	some finding in violation with input as {
		"facts": {"tasks": {"a-task": ["a-program"]}},
		"call": {"programs": [{"name": "a-program", "mediated": false}]},
	}

	finding.subjects[0].artifact == "a-task"
}

test_a_mediated_call_of_the_same_program_is_allowed if {
	count(violation) == 0 with input as {
		"facts": {"tasks": {"a-task": ["a-program"]}},
		"call": {"programs": [{"name": "a-program", "mediated": true}]},
	}
}

test_a_program_no_task_defines_is_not_judged if {
	count(violation) == 0 with input as {
		"facts": {"tasks": {"a-task": ["a-program"]}},
		"call": {"programs": [{"name": "another-program", "mediated": false}]},
	}
}

# Could-not-look, and the arm that must never read as allow-by-emptiness: the
# whole fact is null, so nothing is judged and nothing is refused.
test_an_unanswerable_receipt_refuses_nothing if {
	count(violation) == 0 with input as {
		"facts": {"tasks": null},
		"call": {"programs": [{"name": "a-program", "mediated": false}]},
	}
}

# A task whose body is not one command is skipped rather than guessed at.
test_a_task_that_is_not_one_command_is_skipped if {
	count(violation) == 0 with input as {
		"facts": {"tasks": {"a-pipeline": null}},
		"call": {"programs": [{"name": "a-program", "mediated": false}]},
	}
}

# Every segment is judged, so the second half of a COMPOUND command is not a
# blind spot — CLOUD-857's measured defect, where a guard anchored on the command
# line denied `git push --force` and allowed `cd /tmp && git push --force`.
#
# The case carries the whole call rather than only the programs, because a suite
# that only ever passed a bare command would be blind to exactly that class. The
# look-through itself is the BOUNDARY's: `programs` is the argv already read, one
# entry per segment, so this module inherits the property rather than
# re-deriving it.
test_a_program_in_the_second_half_of_a_compound_command_is_judged if {
	some finding in violation with input as {
		"facts": {"tasks": {"a-task": ["a-program"]}},
		"call": {
			"command": "cd /tmp && a-program --flag",
			"segments": [
				{"words": ["cd", "/tmp"], "raw": "cd /tmp", "terminator": "&&"},
				{"words": ["a-program", "--flag"], "raw": "a-program --flag", "terminator": null},
			],
			"programs": [
				{"name": "cd", "mediated": false},
				{"name": "a-program", "mediated": false},
			],
		},
	}

	finding.subjects[0].artifact == "a-task"
}
