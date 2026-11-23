#MUTANT-SUITE crates/batten/tests/it/install_gate.rs
#MUTANT install-gate-open|s@^\tinput.facts\["install-pending"\].state != "ok"$@\tfalse@|a_pending_program_is_held_while_the_setup_task_runs
#
# CLOUD-2840. A session's setup runs as ONE detached task (`batten startup
# --session`), so the agent loop is available at once and the slow, repo-specific
# install happens behind it. A call made before the install finishes may name a
# program that is not there yet: unresolved on PATH, or a shim under the
# environment manager's install root with nothing behind it. Run, it fails as if
# the WORK were wrong, which is the misdiagnosis this refuses.
#
# THE ENGINE DECIDES WHAT IS PENDING; THIS DECIDES WHAT TO SAY. The fact
# `input.facts["install-pending"]` is the setup task's own state from the task
# registry (`running`, `ok`, `failed`, `crashed`) and the call's command-position
# programs that resolve to nothing or under the install root. It is null where no
# setup task is recorded, so a repository that never started one is never judged
# here, and its `pending` is empty once the task said `ok`, so a finished
# install admits everything.
#
# `git status` IS ALWAYS ADMITTED: the one read a session takes to learn where it
# is, and git is never the env manager's to install.

# METADATA
# description: |
#   Hold a call whose program the session's setup task may still be installing.
#   Bound to the MEDIATED-CALL surface: `input.facts["install-pending"]` and
#   `input.call` are that surface's. THIS BLOCK IS YAML AND MUST STAY THE LAST
#   COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.install_gate

import rego.v1

rules contains "tool install pending"

setup := input.facts["install-pending"]

unsettled if {
	is_object(setup)
	input.facts["install-pending"].state != "ok"
}

# The one read admitted throughout.
admitted(program) if {
	some reach in input.call.programs
	reach.program == program
	reach.name == "git"
	reach.subcommand == "status"
}

held contains program if {
	some program in setup.pending
	not admitted(program)
}

violation contains {
	"rule": "tool install pending",
	"verdict": "tool install pending",
	"subjects": array.concat(
		[{"artifact": program} | some program in held],
		[{"artifact": sprintf("%s %s %s", [setup.task, setup.state, setup.pid])}],
	),
} if {
	unsettled
	count(held) > 0
}

# --- the load-time tier ------------------------------------------------------

running := {"state": "running", "task": "session-setup", "pid": "42", "pending": ["cargo"]}

test_a_pending_program_is_held_while_the_task_runs if {
	count(violation) == 1 with input as {"facts": {"install-pending": running}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}
}

# A COMPOUND CALL IS HELD ON THE PROGRAM THE ENGINE FOUND PENDING, whatever
# runs before it (CLOUD-857's class): `cd` resolves and is not named, `cargo`
# is, and the call is held once rather than per segment.
test_a_compound_call_is_held_on_its_pending_program if {
	some v in violation with input as {"facts": {"install-pending": running}, "call": {
		"command": "cd /tmp && cargo build",
		"programs": [{"program": "cd", "name": "cd"}, {"program": "cargo", "name": "cargo"}],
	}}
	{"artifact": "cargo"} in v.subjects
	not {"artifact": "cd"} in v.subjects
}

test_an_ok_task_admits_everything if {
	count(violation) == 0 with input as {"facts": {"install-pending": {"state": "ok", "task": "session-setup", "pid": "42", "pending": []}}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}
}

test_a_failed_install_still_holds_and_says_so if {
	some v in violation with input as {"facts": {"install-pending": object.union(running, {"state": "failed"})}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}
	{"artifact": "session-setup failed 42"} in v.subjects
}

test_git_status_is_admitted_throughout if {
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(running, {"pending": ["git"]})}, "call": {"programs": [{"program": "git", "name": "git", "subcommand": "status"}]}}
}

test_no_setup_task_is_never_judged if {
	count(violation) == 0 with input as {"facts": {"install-pending": null}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}
}
