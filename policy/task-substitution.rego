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

# Every declared task this call is a WEAKER SPELLING of.
#
# WEAKER IS A STRICT PREFIX, and that relation is the whole rule (CLOUD-1222).
# This compared `words[0] == argv[0]` for its first life — one word, the
# tool — which is that relation truncated to its first term. Sound for the case it
# was written against (`cargo clippy` against `[tasks.lint]`'s
# `cargo clippy --all-targets`), and unsound for this manifest, where most tasks
# are `cargo run --quiet -p batten -- <verb>` and therefore ALL share
# `argv[0] == "cargo"`. Measured: every command whose first word was `cargo` was
# refused, naming whichever task the set iteration happened to surface, and
# `cargo run -p batten -- capture find …` was refused as a weaker spelling of
# `attribution identity`. That is the command `claim-needs-receipt`'s own remedy
# prescribes, so two gates deadlocked with nothing between them but the hatch.
substituted contains task if {
	is_object(input.facts.tasks)
	some task, argv in input.facts.tasks

	# A TASK WITH NO SINGLE ARGV IS SKIPPED, not matched. `null` here means the
	# task exists and is a pipeline or a sequence, so there is no word list to
	# compare against — and inventing one would let this refuse a call by naming
	# a command the task never runs.
	is_array(argv)

	# ON THE PROGRAM AND ITS OWN ARGV (CLOUD-1382). This iterated
	# `input.call.segments` and compared `segment.words`, whose first element is
	# the first WORD rather than the program — so `time cargo clippy`,
	# `(cargo clippy)` and `{ cargo clippy; }` each diverged at index 0 and
	# matched no task at all. Six such tokens, measured at exit 0 on the
	# `trunk-based` preset that carried the same anchor.
	#
	# `programs` is the argv the engine already read, and reading it here also
	# retires the value join `runs_a_task` used to perform: mediation is a
	# property of THIS entry rather than of whatever segment shared its first
	# word.
	some entry in input.call.programs
	weaker_than_program(entry, argv)

	# THE TASK'S OWN INVOCATION IS NOT A SUBSTITUTION FOR ITSELF. Without this a
	# repository could not run its own tasks. Anchored on `programs` rather than
	# on the raw first word, because that is the EFFECTIVE program the boundary
	# resolved — through wrappers and environment assignments (CLOUD-1028) — so a
	# mediated spelling of the same call is recognised as one.
	entry.mediated != true
}

# THE CALL'S ARGV IS A STRICT PREFIX OF THE TASK'S.
#
# Strict at both ends, and neither bound is defensive style:
#
#   * EQUAL IS NOT WEAKER. A caller spelling the task's own argv exactly has
#     dropped nothing, so the refusal would have no stronger form to name.
#     Whether a bare `cargo` should be routed through mise at all is
#     `no-bare-cargo`'s question, and answering it here would be a second
#     authority over one command.
#   * LONGER IS NOT WEAKER EITHER. `cargo clippy --all-targets --fix` extends the
#     task rather than dropping from it, and refusing it would name a task that
#     does LESS than the call.
#
# What is left is exactly "the task's argv continues past where this call stops",
# which is what `rules/toolchain.md` means by a weaker form — and what
# leaves the genuine one-off it already promises is untouched, untouched.
#
# Spelled as the program plus its `arguments` rather than as one joined list, so
# the two halves are compared where the engine already separates them and no
# array is built to be taken apart again. `program` rather than `name`, because a
# task's argv is the spelling the manifest carries and comparing a basename
# against it would match a different binary reached by the same name.
weaker_than_program(entry, argv) if {
	argv[0] == entry.program
	count(entry.arguments) + 1 < count(argv)
	every index, word in entry.arguments {
		argv[index + 1] == word
	}
}

violation contains {
	"rule": "task-substitution",
	"verdict": "task run loose",
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
		"programs": [{
			"program": split(command, " ")[0],
			"name": split(command, " ")[0],
			"arguments": array.slice(split(command, " "), 1, count(split(command, " "))),
			"mediated": false,
		}],
	},
	"facts": {"tasks": tasks},
}

lint := {"lint": ["cargo", "clippy", "--all-targets"]}

test_a_bare_tool_call_is_refused if {
	some v in violation with input as call("cargo clippy", lint)
	v.verdict == "task run loose"
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
			{
				"program": split(first, " ")[0],
				"name": split(first, " ")[0],
				"arguments": array.slice(split(first, " "), 1, count(split(first, " "))),
				"mediated": false,
			},
			{
				"program": split(second, " ")[0],
				"name": split(second, " ")[0],
				"arguments": array.slice(split(second, " "), 1, count(split(second, " "))),
				"mediated": false,
			},
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
	v.verdict == "task run loose"
}

# THE CASE THAT DISCRIMINATES THE RELATION, and the defect that produced
# CLOUD-1222. Both of these tasks lead with `cargo`, and one of them leads with
# `cargo run --quiet -p batten --` as well, so a predicate comparing the tool —
# or any fixed number of leading words — refuses this call. The argvs diverge at
# the VERB, which is the only place they could, and a call that diverges from
# every task is the genuine one-off `rules/toolchain.md` promises is
# untouched. Fails against the shipped `argv[0]` predicate; that is the point.
verbs := {
	"attribution-identity": ["cargo", "run", "--quiet", "-p", "batten", "--", "attribution", "identity"],
	"lint": ["cargo", "clippy", "--all-targets"],
}

test_a_sibling_verb_under_the_same_runner_is_not_a_substitution if {
	count(violation) == 0 with input as call("cargo run --quiet -p batten -- capture find CLOUD-1 --raw", verbs)
}

# THE MIRROR, without which the case above is satisfied by a rule that refuses
# nothing at all: a genuine weakening of one of those same two tasks still fires.
test_a_genuine_weakening_of_the_same_table_is_still_refused if {
	some v in violation with input as call("cargo clippy", verbs)
	v.subjects[0].artifact == "lint"
}

# EQUAL IS NOT WEAKER. The caller spelled the task's own argv, so nothing was
# dropped and there is no stronger form for the refusal to name. Whether a bare
# `cargo` belongs behind mise at all is `no-bare-cargo`'s question.
test_the_tasks_own_argv_spelled_out_is_not_a_substitution if {
	count(violation) == 0 with input as call("cargo clippy --all-targets", verbs)
}

# AND LONGER IS NOT WEAKER. This extends the task rather than dropping from it,
# so refusing it would name a task that does less than the call.
test_a_call_that_extends_the_task_is_not_a_substitution if {
	count(violation) == 0 with input as call("cargo clippy --all-targets --fix", verbs)
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

# THE GRAMMAR CASE (CLOUD-1382), as the boundary now resolves it: the caller
# wrote `time cargo clippy`, `time` is grammar the walk steps past, and the entry
# names cargo with cargo's own argv — so the weakening is reached where the
# first-word comparison diverged at index 0 and matched nothing.
test_a_grammar_token_does_not_hide_the_tool if {
	some v in violation with input as {
		"call": {
			"command": "time cargo clippy",
			"segments": [{"words": ["time", "cargo", "clippy"], "raw": "time cargo clippy", "terminator": null, "input-redirect": false}],
			"programs": [{"program": "cargo", "name": "cargo", "arguments": ["clippy"], "mediated": false}],
		},
		"facts": {"tasks": lint},
	}
	v.subjects[0].artifact == "lint"
}

# THE MEDIATED SPELLING IS THE TASK ITSELF, and it is read off the entry rather
# than joined back to a segment by its first word — which is what the value join
# this rule used to perform could get wrong the moment the two stopped agreeing.
test_a_mediated_call_is_not_a_substitution_for_its_own_task if {
	count(violation) == 0 with input as {
		"call": {
			"command": "mise x -- cargo clippy",
			"segments": [{"words": ["mise", "x", "--", "cargo", "clippy"], "raw": "mise x -- cargo clippy", "terminator": null, "input-redirect": false}],
			"programs": [{"program": "cargo", "name": "cargo", "arguments": ["clippy"], "mediated": true}],
		},
		"facts": {"tasks": lint},
	}
}

#MUTANT-SUITE crates/batten/tests/it/task_receipt.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.facts.tasks` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT substitution-unread|s@^\tsome task in substituted$@\tsome task in []@|a_session_start_mints_a_receipt_a_call_can_read
