# METADATA
# description: |
#   The successor shape for `run-shape-guard`'s `cargo-substitutes-for-a-task`
#   family, and the demonstration CLOUD-856 owes.
#
#   THE FAMILY THAT COULD NOT MOVE. CLOUD-843 called that guard the campaign's
#   free start — "pure string analysis of `command`, which the envelope already
#   carries" — and it was wrong in one term. This family IS the file read: its
#   predicate is "is this argv a weaker form of a task's own", derived from the
#   manifest's task bodies and never restated. `input.call.document` does not
#   exist and must not: a document is unbounded on the mediated path, and parsing
#   one per call would spend the whole invocation budget.
#
#   `input.facts.tasks` is that read moved rather than admitted. The manifest is
#   parsed ONCE at session start and recorded; this path reads a small keyed
#   record whose key is recomputed from the manifest as it stands.
#
#   THE REFUSAL NAMES THE TASK, which is the whole of its value (CLOUD-437): a
#   message that lost the task name in translation is a regression no `policy
#   test` would catch, so the task is a `subjects` entry and the class points at
#   the route that runs it.
#
#   NULL IS A REAL STATE HERE and the guard is not defensive style. The fact is
#   `null` whenever the record is missing, keyed to a manifest that has moved,
#   written at another schema, or past its size cap — and `some .. in null` is a
#   hard evaluation FAULT in Rego rather than a silent miss. It is also the state
#   this module MUST allow in: a guard comparing a call against an empty task
#   table would refuse every command the project runs.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.task_substitution

import rego.v1

rules contains "task-substitution"

# Every declared task whose own argv leads with the program this call runs.
#
# The FIRST word is what identifies the tool a task wraps, and comparing only
# that is deliberate: a task and a call that agree on the tool but differ in
# their flags is exactly the substitution this refuses — a weaker invocation of
# something the project has a stronger spelling for.
substituted contains task if {
	is_object(input.facts.tasks)
	some task, argv in input.facts.tasks

	# A TASK WITH NO SINGLE ARGV IS SKIPPED, not matched. `null` here means the
	# task exists and is a pipeline or a sequence, so there is no word list to
	# compare against — and inventing one would let this refuse a call by naming
	# a command the task never runs.
	is_array(argv)
	some segment in input.call.segments
	segment.words[0] == argv[0]

	# THE TASK'S OWN INVOCATION IS NOT A SUBSTITUTION FOR ITSELF. Without this a
	# repository could not run its own tasks.
	not runs_a_task(segment)
}

# Whether this segment invokes the runner rather than the tool directly.
#
# Anchored on `programs` rather than on the raw first word, because that is the
# EFFECTIVE program the boundary resolved — the argv already read, through
# wrappers and environment assignments (CLOUD-1028). A predicate over
# `segment.words[0]` would miss every mediated spelling of the same call.
runs_a_task(segment) if {
	some program in input.call.programs
	program.mediated == true
	program.program == segment.words[0]
}

violation contains {
	"rule": "task-substitution",
	"verdict": "V-TASK-SUBSTITUTION",
	"subjects": [{"artifact": task}],
} if {
	some task in substituted
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE reads a receipt at all,
# nor that its key goes stale with the manifest — a `with input as` case
# fabricates the very shape the engine may be unable to produce (CLOUD-845,
# CLOUD-857), and here it would fabricate the entire acquisition this row moved.
# `crates/batten/tests/task_receipt.rs` is that tier.

call(command, tasks) := {
	"call": {
		"command": command,
		"segments": [{"words": split(command, " "), "raw": command, "terminator": null, "input-redirect": false}],
		"programs": [{"program": split(command, " ")[0], "mediated": false}],
	},
	"facts": {"tasks": tasks},
}

lint := {"lint": ["cargo", "clippy", "--all-targets"]}

test_a_bare_tool_call_is_refused if {
	some v in violation with input as call("cargo clippy", lint)
	v.verdict == "V-TASK-SUBSTITUTION"
}

# THE REFUSAL CARRIES THE TASK NAME, which is the whole of its value (CLOUD-437).
test_the_refusal_names_the_task if {
	some v in violation with input as call("cargo clippy", lint)
	v.subjects[0].artifact == "lint"
}

test_an_unrelated_program_is_clean if {
	count(violation) == 0 with input as call("git status", lint)
}

# A COMPOUND CALL, and this case is not optional. `policy test` refuses a
# mediated-call module whose every case passes a bare command, because that is
# the shape CLOUD-857 measured: a vendored preset anchored on
# `split(input.call.command, " ")[0]` denied `git push --force` and allowed
# `cd /tmp && git push --force`, with a green suite over it. Anchoring on
# `segments` is what makes the two the same verdict, and this is what shows it.
compound(command, first, second, tasks) := {
	"call": {
		"command": command,
		"segments": [
			{"words": split(first, " "), "raw": first, "terminator": "&&", "input-redirect": false},
			{"words": split(second, " "), "raw": second, "terminator": null, "input-redirect": false},
		],
		"programs": [
			{"program": split(first, " ")[0], "mediated": false},
			{"program": split(second, " ")[0], "mediated": false},
		],
	},
	"facts": {"tasks": tasks},
}

# The compound line is spelled IN THIS RULE rather than composed in the helper,
# because the gate reads the literals a `test_` rule carries — a suite whose
# operator lived one call away would be reported bare-only, correctly: what it
# proves is that the AUTHOR wrote a compound case, not that a helper can join
# two strings.
test_a_tool_call_in_a_later_segment_is_refused if {
	some v in violation with input as compound("cd /tmp && cargo clippy", "cd /tmp", "cargo clippy", lint)
	v.verdict == "V-TASK-SUBSTITUTION"
}

# A task whose body is not a single command carries `null`, and comparing against
# an invented word list would refuse a call by naming a command it never runs.
test_a_task_with_no_single_argv_matches_nothing if {
	count(violation) == 0 with input as call("cargo clippy", {"ship": null})
}

# COULD-NOT-LOOK, and the state this module must ALLOW in rather than merely
# survive: no record, a record about a manifest that has moved, a schema this
# build does not read, one past the size cap. Without the `is_object` guard this
# case does not merely fail — it faults, taking the whole bundle with it.
test_could_not_look_refuses_nothing if {
	count(violation) == 0 with input as call("cargo clippy", null)
}

#MUTANT-EXEMPT CLOUD-931|no `tests/task-substitution.bats` exists and none may be added: `mutant` resolves a gate's suite as `tests/$gate.bats`, and `V-SHELL-RULE-ADDED` refuses adding one, so there is no named case a mutation could turn red. The load-time tier is this file's own `test_` rules and the engine tier is `crates/batten/tests/task_receipt.rs`, neither of which is what the mutation runner drives
