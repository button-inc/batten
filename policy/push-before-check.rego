# CLOUD-2489: a slow local check may not start over committed work no remote holds.
#
# WHAT THE DEFECT WAS, MEASURED. On #1191 an agent committed, then ran the slow
# local checks before pushing, and three times `land` surfaced a failure the push
# would have let it start on. The repo's contract is the opposite order
# (AGENTS.md "PUSH THE IMPERFECT DRAFT"): a draft push starts no CI, so it is
# free, and it is the only thing that survives a container reclaim. A slow check
# run first spends the minutes the reclaim can take.
#
# WHAT IT READS. `input.facts["head-unpushed"]` (`Fact::HeadUnpushed`): a
# rev-walk from HEAD hiding every remote-tracking tip. `true` is committed work
# this clone alone holds. `null` is could-not-look and decides NOTHING: a gate
# that refuses because it could not run its own query is a wall, not a check.
#
# WHAT IT DOES NOT READ, AND WHY. Uncommitted edits are not refused. Edit, then
# test, is the loop that must stay free, and counting dirty paths means hashing the
# tree on every call, which is `GitStatus`'s reason for being off the hook
# (`hook.rs`, the `Fact::GitStatus` arm). The shape refused is the one the defect
# had: committed, unpushed, then checked.
#
# `land` IS NOT A SLOW CHECK HERE. It runs `verify` itself, after its own push,
# so it is the remedy rather than the subject. `verify` alone is gated: it answers
# "would this land" and is worth running only once the draft is safe.
#
#MUTANT-SUITE crates/batten/tests/it/push_before_check.rs
#MUTANT unpushed-ignored|s@^\tinput.facts\["head-unpushed"\] == true$@\tfalse@|an_unpushed_head_refuses_a_slow_check
#MUTANT could-not-look-refuses|s@^\tinput.facts\["head-unpushed"\] == true$@\tinput.facts["head-unpushed"] != false@|a_head_that_could_not_be_read_decides_nothing
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document. The brackets are
#   required: the schema file carries a hyphen, and the dotted form is a parse error.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.push_before_check

import rego.v1

rules contains "check run early"

basename(tok) := b if {
	parts := split(tok, "/")
	b := parts[count(parts) - 1]
}

# The program and its words as one line, so one declared pattern reads it.
spelled(program) := concat(" ", array.concat([basename(program.program)], program.arguments))

slow_check(program) if {
	regex.match(data.batten.patterns["slow-check"], spelled(program))
}

violation contains {
	"rule": "check run early",
	"verdict": "check run early",
} if {
	input.facts["head-unpushed"] == true
	some program in input.call.programs
	slow_check(program)
}

deny contains finding if {
	some finding in violation
}

# --- the module's own tier ---------------------------------------------------

prog(name, arguments) := {
	"program": name,
	"name": name,
	"arguments": arguments,
	"mediated": true,
}

call(unpushed, programs) := {
	"call": {"programs": programs},
	"facts": {"head-unpushed": unpushed},
}

test_an_unpushed_head_refuses_verify if {
	count(violation) == 1 with input as call(true, [prog("mise", ["run", "verify"])])
}

test_an_unpushed_head_refuses_cargo_test if {
	count(violation) == 1 with input as call(true, [prog("/usr/bin/cargo", ["test", "-p", "batten"])])
}

test_a_pushed_head_runs_any_check if {
	count(violation) == 0 with input as call(false, [prog("mise", ["run", "verify"])])
}

test_land_is_the_remedy_not_the_subject if {
	count(violation) == 0 with input as call(true, [prog("mise", ["run", "land"])])
}

test_a_cheap_program_is_not_a_check if {
	count(violation) == 0 with input as call(true, [prog("cargo", ["fmt", "--all"])])
}

# A check in a LATER segment is judged as surely as one alone: every program the
# boundary parsed out of the line is read, so `cargo fmt && cargo test` cannot
# hide the test behind a cheap first word (CLOUD-857's `module-tested-bare-only`).
test_a_later_segment_check_is_refused if {
	count(violation) == 1 with input as {
		"call": {
			"command": "cargo fmt --all && cargo test -p batten",
			"programs": [prog("cargo", ["fmt", "--all"]), prog("cargo", ["test", "-p", "batten"])],
		},
		"facts": {"head-unpushed": true},
	}
}

test_could_not_look_decides_nothing if {
	count(violation) == 0 with input as call(null, [prog("mise", ["run", "verify"])])
}
