#MUTANT-SUITE crates/batten/tests/it/install_gate.rs
#MUTANT install-gate-open|s@^\tsetup.state != "ok"$@\tfalse@|a_pending_program_is_held_while_the_setup_task_runs
#MUTANT dispatch-gate-open|s@^\tsetup.state == "undispatched"$@\tfalse@|a_call_before_the_dispatch_is_held_and_a_read_is_not
#
# CLOUD-2840, the owner's design (2026-11-25): "implement install as a 10/100ms
# hook just like every other hook with instructions to agent on how to install as
# background task and gating until agent dispatches the damn install task".
# `SessionStart` spawns nothing; it tells the agent to dispatch ONE install task
# (`batten startup --session`) with its harness's background facility, and this
# module holds the session until it does, then while it installs.
#
# THE ENGINE DECIDES WHAT IS PENDING; THIS DECIDES WHAT TO SAY. The fact
# `input.facts["install-pending"]` is the setup task's state from the task
# registry and the call's command-position programs the install may own. It is
# null where `SessionStart` prepared no setup, so a repository that declares
# none is never judged here.
#
# TWO PHASES.
#
# (a) `undispatched`: setup was prepared and no record exists. Every call is
#     held except the dispatch itself and a read: a read tool, or a command
#     whose every program only reads (the boundary's read-only floor, a batten
#     verb whose declared effect is `read` under house-style §5, `git status`)
#     with no output redirect. The remedy subject is the dispatch command.
#
# (b) a record exists and is not `ok`: a program that does not resolve,
#     resolves under the environment manager's install root, or is the manager
#     itself is held, naming the task's state and pid. `failed` or a dead pid is
#     a refusal naming the failure, with re-dispatch as the remedy. Programs
#     outside the install root (`git`, the shell) are admitted throughout.
#
# The dispatch is admitted in every phase unless the host says it was asked to
# run in the foreground: setup is minutes, and a foreground call holds the turn.

# METADATA
# description: |
#   Hold the session until its one install task is dispatched, then hold a
#   call whose program that task may still be installing. Bound to the
#   MEDIATED-CALL surface: `input.facts["install-pending"]` and `input.call` are
#   that surface's. THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK
#   BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.install_gate

import rego.v1

rules contains "tool install pending"

setup := input.facts["install-pending"]

# The dispatch, unless the host says it runs in the foreground.
dispatching if {
	is_object(setup)
	setup.dispatching == true
	not input.call["run-in-background"] == false
}

undispatched if {
	is_object(setup)
	setup.state == "undispatched"
}

unsettled if {
	is_object(setup)
	setup.state != "undispatched"
	setup.state != "ok"
}

# --- (a) what a session may do before it dispatches --------------------------

reads if input.call.operation == "read"

reads if {
	input.call.operation == "execute"
	count(input.call.programs) > 0
	every program in input.call.programs {
		read_program(program)
	}
	every segment in input.call.segments {
		not segment["output-redirect"]
	}
}

read_program(program) if program["reads-only"] == true

read_program(program) if program["batten-effect"] == "read"

read_program(program) if {
	program.name == "git"
	program.subcommand == "status"
}

violation contains {
	"rule": "tool install pending",
	"verdict": "tool install pending",
	"subjects": [
		{"artifact": sprintf("%s undispatched", [setup.task])},
		{"artifact": setup.dispatch},
	],
} if {
	undispatched
	not dispatching
	not reads
}

# --- (b) what a session may run while the task installs ----------------------

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
		[
			{"artifact": sprintf("%s %s %s", [setup.task, setup.state, setup.pid])},
			{"artifact": setup.dispatch},
		],
	),
} if {
	unsettled
	not dispatching
	count(held) > 0
}

# --- the load-time tier ------------------------------------------------------

running := {"state": "running", "task": "session-setup", "pid": "42", "pending": ["cargo"], "dispatch": "batten startup --session", "dispatching": false}

waiting := {"state": "undispatched", "task": "session-setup", "pid": null, "pending": [], "dispatch": "batten startup --session", "dispatching": false}

cargo_build := {"operation": "execute", "programs": [{"program": "cargo", "name": "cargo", "subcommand": "build"}], "segments": [{"output-redirect": false}]}

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
	{"artifact": "batten startup --session"} in v.subjects
}

test_an_ok_task_admits_everything if {
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(running, {"state": "ok", "pending": []})}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}
}

test_a_failed_install_still_holds_and_says_so if {
	some v in violation with input as {"facts": {"install-pending": object.union(running, {"state": "failed"})}, "call": {"programs": [{"program": "cargo", "name": "cargo"}]}}
	{"artifact": "session-setup failed 42"} in v.subjects
}

test_git_status_is_admitted_throughout if {
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(running, {"pending": ["git"]})}, "call": {"programs": [{"program": "git", "name": "git", "subcommand": "status"}]}}
}

test_no_setup_task_is_never_judged if {
	count(violation) == 0 with input as {"facts": {"install-pending": null}, "call": cargo_build}
}

test_before_the_dispatch_a_mutating_call_is_held_with_the_dispatch if {
	some v in violation with input as {"facts": {"install-pending": waiting}, "call": cargo_build}
	{"artifact": "session-setup undispatched"} in v.subjects
	{"artifact": "batten startup --session"} in v.subjects
}

test_before_the_dispatch_a_write_tool_is_held if {
	count(violation) == 1 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "write", "programs": []}}
}

test_before_the_dispatch_a_read_is_admitted if {
	count(violation) == 0 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "read", "programs": []}}
	count(violation) == 0 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"name": "git", "subcommand": "status"}], "segments": [{"output-redirect": false}]}}
	count(violation) == 0 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"name": "batten", "batten-effect": "read"}], "segments": [{"output-redirect": false}]}}
	count(violation) == 0 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"name": "cat", "reads-only": true}], "segments": [{"output-redirect": false}]}}
}

# A READER THAT WRITES A FILE IS NOT A READ: `cat a > b`.
test_before_the_dispatch_a_redirected_read_is_held if {
	count(violation) == 1 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"name": "cat", "reads-only": true}], "segments": [{"output-redirect": true}]}}
}

test_the_dispatch_is_admitted_in_the_background_only if {
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(waiting, {"dispatching": true})}, "call": object.union(cargo_build, {"run-in-background": true})}
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(running, {"dispatching": true, "pending": ["batten"]})}, "call": {"programs": [{"program": "batten", "name": "batten"}], "run-in-background": true}}
	count(violation) == 1 with input as {"facts": {"install-pending": object.union(waiting, {"dispatching": true})}, "call": object.union(cargo_build, {"run-in-background": false})}
}
