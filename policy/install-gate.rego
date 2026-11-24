#MUTANT-SUITE crates/batten/tests/it/install_gate.rs
#MUTANT install-gate-open|s@^\tsetup.state == "running"$@\tfalse@|a_pending_program_is_held_while_the_setup_task_runs
#MUTANT install-failed-reads-pending|s@^\tsetup.state == "running"$@\tsetup.state != "ok"@|a_failed_install_is_refused_as_failed
#MUTANT install-failed-open|s@^\tsetup.state in {"failed", "crashed"}$@\tfalse@|a_failed_install_is_refused_as_failed_never_pending
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
# programs that resolve to nothing or, while the task runs, under the install
# root. It is null where no setup task is recorded, so a repository that never
# started one is never judged here, and its `pending` is empty once the task said
# `ok`, so a finished install admits everything.
#
# A SETUP THAT ENDED WITHOUT `ok` IS FAILED, NEVER PENDING (CLOUD-2921). Measured:
# `opa`, by full path, refused as "tool install pending" about 20 hours after the
# setup failed, routed to a watch on a task long gone. After `failed` or
# `crashed` the engine lists only programs that resolve to nothing, and this
# refuses them as `tool install absent`, whose route re-runs the setup.
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

# ONE RULE, TWO VERDICTS: `tool install pending` while the task runs, `tool
# install absent` once it ended without `ok`. A rule raising two classes owes
# an id that is neither (`policy.rs`, the sole-raiser check).
rules contains "tool install held"

setup := input.facts["install-pending"]

# STILL INSTALLING: the one state in which a missing program may yet arrive.
installing if {
	is_object(setup)
	setup.state == "running"
}

# THE INSTALL ENDED WITHOUT `ok` (CLOUD-2921). Nothing more will be installed,
# so a held program is not pending: it is missing because the setup failed or
# died, and the remedy is to run it again, not to wait.
ended if {
	is_object(setup)
	setup.state in {"failed", "crashed"}
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
	"rule": "tool install held",
	"verdict": "tool install pending",
	"subjects": array.concat(
		[{"artifact": program} | some program in held],
		[{"artifact": sprintf("%s %s %s", [setup.task, setup.state, setup.pid])}],
	),
} if {
	installing
	count(held) > 0
}

violation contains {
	"rule": "tool install held",
	"verdict": "tool install absent",
	"subjects": array.concat(
		[{"artifact": program} | some program in held],
		[{"artifact": sprintf("%s %s %s", [setup.task, setup.state, setup.pid])}],
	),
} if {
	ended
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

ended_call(state) := {"facts": {"install-pending": object.union(running, {"state": state})}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}

verdicts(state) := found if {
	found := {v.verdict | some v in violation} with input as ended_call(state)
}

# CLOUD-2921: a setup that ended without `ok` is refused as FAILED, never as
# pending, so the reader re-runs it instead of watching a task that is gone.
test_a_failed_install_is_refused_as_failed if {
	verdicts("failed") == {"tool install absent"}
	some v in violation with input as ended_call("failed")
	{"artifact": "session-setup failed 42"} in v.subjects
}

test_a_crashed_install_is_refused_as_failed if {
	verdicts("crashed") == {"tool install absent"}
}

test_a_running_install_is_pending_not_failed if {
	verdicts("running") == {"tool install pending"}
}

test_git_status_is_admitted_throughout if {
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(running, {"pending": ["git"]})}, "call": {"programs": [{"program": "git", "name": "git", "subcommand": "status"}]}}
}

test_no_setup_task_is_never_judged if {
	count(violation) == 0 with input as {"facts": {"install-pending": null}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}
}
