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

# One entry per segment, so a task's program reached in the second half of a
# pipeline is as visible as one in the first.
#
# `mediated` is the BOUNDARY's reading rather than this module's. Deciding it
# here would mean re-implementing the wrapper look-through, the environment
# assignments and every spelling of the runner's own invocation — a second
# authority over an argv the engine already parses.
#
# THE TASK IS BOUND HERE RATHER THAN THROUGH A PROGRAM -> NAME TABLE, and that
# is a correctness fix and not a style one. The table was written
# `runs[program] := name`, a partial object keyed on the program — so two tasks
# whose bodies begin with the same program are two values under one key, which
# Rego refuses at evaluation with `eval_conflict_error`. Not hypothetical: this
# very repository has 33 tasks starting `cargo` and 3 starting `hk`, so the
# preset would have failed to evaluate at all in the tree that ships it, and a
# preset that cannot evaluate refuses nothing. Every fixture written for it had
# exactly one task, which is the CLOUD-418 class exactly — a gate never shown
# able to fire on the shape it will actually meet.
#
# Binding `name` in the comprehension yields one finding per (call, task) pair
# instead, so several tasks reaching one program each name themselves.
# THE WHOLE ARGV MUST MATCH, NOT JUST THE PROGRAM. Matching the program alone
# is the defect `policy/task-substitution.rego`'s own header records for its
# first life (CLOUD-1222: "compared `words[0] == argv[0]` ... unsound for this
# manifest, where most tasks are a shared tool plus a subcommand"), reintroduced
# here in a preset that ships to every consumer.
#
# Measured live against the shipped binary with the receipt minted:
# `batten doctor session` -- the command AGENTS.md mandates -- was told to run
# `mise run alive`, because a task named `alive` happens to begin with `batten`;
# `actionlint` was told to run `lint:actions`. A refusal naming the wrong remedy
# is worse than no refusal, and `severity = "warn"` bounds that to noise rather
# than making it right.
#
# So the call must reproduce the task's argv, which is what "running the task's
# program directly reproduces the argv" always meant.
#
# AND IT COMPARES `program`, NOT `name`. `name` is the basename, so a task
# spelled with a path -- `./scripts/build.sh`, `node_modules/.bin/eslint` --
# could never match any entry, and the predicate was silently dead for exactly
# those tasks while loading and testing clean. The sibling `weaker_than_program`
# uses `program` for this reason. No task here is path-spelled, so nothing in
# this repository exercised it.
violation contains {
	"rule": "task-over-executable",
	"verdict": "task reach loose",
	"subjects": [{"artifact": name}],
} if {
	some entry in input.call.programs
	not entry.mediated
	some name, argv in defined
	reaches(entry, argv)
}

# Does this call reproduce the task's whole argv -- program, then arguments in
# order at the front of what that program was handed?
reaches(entry, argv) if {
	argv[0] == entry.program
	rest := array.slice(argv, 1, count(argv))
	rest == array.slice(entry.arguments, 0, count(rest))
}

deny contains finding if some finding in violation

# --- cases ---------------------------------------------------------------

test_a_tasks_own_program_reached_directly_is_refused if {
	some finding in violation with input as {
		"facts": {"tasks": {"a-task": ["a-program", "--flag"]}},
		"call": {"programs": [{"name": "a-program", "program": "a-program", "arguments": ["--flag"], "mediated": false}]},
	}

	finding.rule == "task-over-executable"
}

# The refusal names the TASK, never the program: that is the affordance a guard
# over the program alone cannot give.
test_the_refusal_names_the_task_rather_than_the_program if {
	some finding in violation with input as {
		"facts": {"tasks": {"a-task": ["a-program"]}},
		"call": {"programs": [{"name": "a-program", "program": "a-program", "arguments": ["--flag"], "mediated": false}]},
	}

	finding.subjects[0].artifact == "a-task"
}

# TWO TASKS, ONE PROGRAM — the shape every other case in this file lacked.
#
# The program -> name table this module used to build made these two tasks two
# values under the key "a-program", and Rego refuses that with
# `eval_conflict_error` rather than deciding: the preset stopped evaluating and
# therefore refused nothing. This repository has 33 tasks starting `cargo`, so
# the shape is the common one and the single-task fixtures were the unusual one.
test_two_tasks_sharing_a_program_still_decide if {
	findings := violation with input as {
		"facts": {"tasks": {
			"first-task": ["a-program"],
			"second-task": ["a-program"],
		}},
		"call": {"programs": [{"name": "a-program", "program": "a-program", "arguments": [], "mediated": false}]},
	}

	count(findings) == 2

	names := {subject.artifact | some finding in findings; some subject in finding.subjects}
	names == {"first-task", "second-task"}
}

# A call that merely shares the task's PROGRAM is not the task.
#
# The measured defect: `batten doctor session` was told to run `mise run alive`
# because a task named `alive` begins with `batten`. A refusal naming the wrong
# remedy is worse than none, and it is the CLOUD-1222 shape the sibling module's
# header already records -- "most tasks are a shared tool plus a subcommand".
test_a_call_sharing_only_the_program_is_not_the_task if {
	count(violation) == 0 with input as {
		"facts": {"tasks": {"a-task": ["a-program", "sub"]}},
		"call": {"programs": [{
			"name": "a-program",
			"program": "a-program",
			"arguments": ["other"],
			"mediated": false,
		}]},
	}
}

# A task spelled with a PATH is still reachable, which `name` could never match.
test_a_path_spelled_task_is_still_reached if {
	some finding in violation with input as {
		"facts": {"tasks": {"a-task": ["./scripts/build.sh"]}},
		"call": {"programs": [{
			"name": "build.sh",
			"program": "./scripts/build.sh",
			"arguments": [],
			"mediated": false,
		}]},
	}

	finding.subjects[0].artifact == "a-task"
}

test_a_mediated_call_of_the_same_program_is_allowed if {
	count(violation) == 0 with input as {
		"facts": {"tasks": {"a-task": ["a-program"]}},
		"call": {"programs": [{"name": "a-program", "program": "a-program", "arguments": ["--flag"], "mediated": true}]},
	}
}

test_a_program_no_task_defines_is_not_judged if {
	count(violation) == 0 with input as {
		"facts": {"tasks": {"a-task": ["a-program"]}},
		"call": {"programs": [{"name": "another-program", "program": "another-program", "arguments": [], "mediated": false}]},
	}
}

# Could-not-look, and the arm that must never read as allow-by-emptiness: the
# whole fact is null, so nothing is judged and nothing is refused.
test_an_unanswerable_receipt_refuses_nothing if {
	count(violation) == 0 with input as {
		"facts": {"tasks": null},
		"call": {"programs": [{"name": "a-program", "program": "a-program", "arguments": ["--flag"], "mediated": false}]},
	}
}

# A task whose body is not one command is skipped rather than guessed at.
test_a_task_that_is_not_one_command_is_skipped if {
	count(violation) == 0 with input as {
		"facts": {"tasks": {"a-pipeline": null}},
		"call": {"programs": [{"name": "a-program", "program": "a-program", "arguments": ["--flag"], "mediated": false}]},
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
				{"name": "cd", "program": "cd", "arguments": ["/tmp"], "mediated": false},
				{"name": "a-program", "program": "a-program", "arguments": ["--flag"], "mediated": false},
			],
		},
	}

	finding.subjects[0].artifact == "a-task"
}
