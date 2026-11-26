#MUTANT-SUITE crates/batten/tests/it/install_gate.rs
#MUTANT install-gate-open|s@^\tsetup.state != "ok"$@\tfalse@|a_pending_program_is_held_while_the_setup_task_runs
#MUTANT dispatch-gate-open|s@^\tsetup.state == "undispatched"$@\tfalse@|a_call_before_the_dispatch_is_held_and_a_read_is_not
#MUTANT inline-dispatch-open|s@^\tnot dispatching$@\tfalse@|an_inline_dispatch_is_held_in_every_state
#MUTANT host-dispatch-unread|s@^\tsetup.background == false$@\tfalse@|a_host_without_a_background_facility_dispatches_inline
#MUTANT neutral-read-unread|s@^\tinput.call.operation == "execute"$@\tfalse@|a_host_neutral_read_is_admitted_before_the_dispatch
#MUTANT pending-read-open|s@^\t\tnot pending_name(program.program)$@\t\ttrue@|a_reader_the_install_may_own_is_held_before_the_dispatch
#
# CLOUD-2840, the owner's design (2026-11-25): "implement install as a 10/100ms
# hook just like every other hook with instructions to agent on how to install as
# background task and gating until agent dispatches the damn install task".
# `SessionStart` spawns nothing; it tells the agent to dispatch ONE install task
# (`batten startup --session`), and this module holds the session until it
# does, then while it installs.
#
# THE ENGINE DECIDES WHAT IS PENDING; THIS DECIDES WHAT TO SAY. The fact
# `input.facts["install-pending"]` is the setup task's state from the task
# registry, the call's command-position programs the install may own, and
# whether the host can run the dispatch in the background. It is null where
# `SessionStart` prepared no setup, so a repository that declares none is never
# judged here.
#
# TWO PHASES.
#
# (a) `undispatched`: setup was prepared and no record exists. Every call is
#     held except the dispatch itself and a read: a call whose `operation` is
#     `read`, or a command whose every program only reads (the boundary's
#     read-only floor, or a batten verb whose declared effect is `read` under
#     house-style §5) with no output redirect, and none of which the install
#     may own. Host-neutral, so Cursor's `Shell` and every other host can look.
#     NOT `git`, whatever its subcommand (r5): `-c`, `--config-env` and a
#     `GIT_*` assignment each make git run a program, and telling those apart
#     is the engine-default library's git reading. That library, and its
#     read-only allowlist, join this reading only once the PINNED release
#     carries it (CLOUD-2840 step 14): this module is evaluated by that
#     release, and a call to a function it lacks makes the module unevaluable,
#     so every mediated call is refused. A reader the install may own (a shim
#     under the manager's root, or a name nothing resolves) is held, because
#     running it may run the manager's auto-install before setup. The remedy
#     subject is the dispatch command.
#
# (b) a record exists and is not `ok`: a program that does not resolve,
#     resolves under the environment manager's install root, or is the manager
#     itself is held, naming the task's state and pid. `failed` or a dead pid is
#     a refusal naming the failure, with re-dispatch as the remedy. Programs
#     outside the install root (`git`, the shell) are admitted throughout.
#
# THE DISPATCH, AS THE HOST CAN MAKE IT, IN EVERY STATE (r5). On a host that
# runs a call in the background (`setup.background`), it is admitted as a
# background call and held inline whatever phase setup is in: setup is minutes,
# and a foreground call holds the turn. Claude Code sends an inline call with
# `run_in_background` omitted, so only an explicit `true` is background. On a
# host with no background facility (Cursor, Codex, Gemini, Copilot today), the
# inline dispatch is the only one it can make, so it is admitted: holding it
# would hold that session for good. A fact with no `background` key (an engine
# older than r5) reads as a host that has one, which is what it assumed.

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

# The call IS the dispatch, however it was asked to run.
dispatch_call if {
	is_object(setup)
	setup.dispatching == true
}

# The dispatch, as a background call on a host that has one.
dispatching if {
	dispatch_call
	input.call["run-in-background"] == true
}

# The dispatch on a host with no background facility: inline is all it has.
dispatching if {
	dispatch_call
	setup.background == false
}

# The dispatch run inline where the host could background it: held in every
# state, `ok` included.
inline_dispatch if {
	dispatch_call
	not dispatching
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

# A program the engine found the install may own.
pending_name(name) if {
	some pending in setup.pending
	pending == name
}

# --- (a) what a session may do before it dispatches --------------------------

reads if input.call.operation == "read"

reads if {
	input.call.operation == "execute"
	count(input.call.programs) > 0
	every program in input.call.programs {
		read_program(program)
		not pending_name(program.program)
	}
	every segment in input.call.segments {
		not segment["output-redirect"]
	}
}

read_program(program) if program["reads-only"] == true

read_program(program) if program["batten-effect"] == "read"

violation contains {
	"rule": "tool install pending",
	"verdict": "tool install pending",
	"subjects": [
		{"artifact": sprintf("%s undispatched", [setup.task])},
		{"artifact": setup.dispatch},
	],
} if {
	undispatched
	not dispatch_call
	not reads
}

violation contains {
	"rule": "tool install pending",
	"verdict": "tool install pending",
	"subjects": [
		{"artifact": sprintf("%s inline", [setup.dispatch])},
		{"artifact": sprintf("%s %s", [setup.task, setup.state])},
		{"artifact": setup.dispatch},
	],
} if {
	inline_dispatch
}

# --- (b) what a session may run while the task installs ----------------------

# The one read admitted throughout this phase.
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
	not dispatch_call
	count(held) > 0
}

# --- the load-time tier ------------------------------------------------------

running := {"state": "running", "task": "session-setup", "pid": "42", "pending": ["cargo"], "dispatch": "batten startup --session", "dispatching": false, "background": true}

waiting := {"state": "undispatched", "task": "session-setup", "pid": null, "pending": [], "dispatch": "batten startup --session", "dispatching": false, "background": true}

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

test_git_status_is_admitted_while_the_task_runs if {
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
	count(violation) == 0 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"program": "batten", "name": "batten", "batten-effect": "read"}], "segments": [{"output-redirect": false}]}}
	count(violation) == 0 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"program": "cat", "name": "cat", "reads-only": true}], "segments": [{"output-redirect": false}]}}
}

# GIT IS NO READ BEFORE THE DISPATCH, whatever its subcommand (r5): `-c`,
# `--config-env` and a `GIT_*` assignment make `git status` run a program, and
# the git reading that tells them apart is the library's, which the pinned
# release may not carry.
test_before_the_dispatch_git_is_held if {
	count(violation) == 1 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"program": "git", "name": "git", "subcommand": "status"}], "segments": [{"output-redirect": false}]}}
	count(violation) == 1 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"program": "git", "name": "git", "subcommand": "status", "arguments": ["-c", "core.fsmonitor=./x", "status"]}], "segments": [{"output-redirect": false}]}}
}

# A READER THE INSTALL MAY OWN IS NO READ (r5): a shim under the manager's root
# runs the manager, whose auto-install would run before setup.
test_before_the_dispatch_a_pending_reader_is_held if {
	count(violation) == 1 with input as {"facts": {"install-pending": object.union(waiting, {"pending": ["rg"]})}, "call": {"operation": "execute", "programs": [{"program": "rg", "name": "rg", "reads-only": true}], "segments": [{"output-redirect": false}]}}
}

# A READER THAT WRITES A FILE IS NOT A READ: `cat a > b`.
test_before_the_dispatch_a_redirected_read_is_held if {
	count(violation) == 1 with input as {"facts": {"install-pending": waiting}, "call": {"operation": "execute", "programs": [{"program": "cat", "name": "cat", "reads-only": true}], "segments": [{"output-redirect": true}]}}
}

test_the_dispatch_is_admitted_in_the_background_only if {
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(waiting, {"dispatching": true})}, "call": object.union(cargo_build, {"run-in-background": true})}
	count(violation) == 0 with input as {"facts": {"install-pending": object.union(running, {"dispatching": true, "pending": ["batten"]})}, "call": {"programs": [{"program": "batten", "name": "batten"}], "run-in-background": true}}
	count(violation) == 1 with input as {"facts": {"install-pending": object.union(waiting, {"dispatching": true})}, "call": object.union(cargo_build, {"run-in-background": false})}
	count(violation) == 1 with input as {"facts": {"install-pending": object.union(waiting, {"dispatching": true})}, "call": cargo_build}
}

# A HOST WITH NO BACKGROUND FACILITY DISPATCHES INLINE, and that is admitted
# in every state (r5): it is the only dispatch such a host can make.
test_a_host_without_a_background_facility_dispatches_inline if {
	every state in ["undispatched", "running", "failed", "ok"] {
		count(violation) == 0 with input as {"facts": {"install-pending": object.union(running, {"state": state, "dispatching": true, "background": false, "pending": []})}, "call": {"programs": [{"program": "batten", "name": "batten"}]}}
	}
}

# AN ENGINE OLDER THAN r5 SAYS NOTHING OF THE HOST, and reads as one that can
# background the call, which is what it assumed.
test_a_fact_without_the_host_key_holds_an_inline_dispatch if {
	count(violation) == 1 with input as {"facts": {"install-pending": {"state": "undispatched", "task": "session-setup", "pid": null, "pending": [], "dispatch": "batten startup --session", "dispatching": true}}, "call": cargo_build}
}

# INLINE IS HELD IN EVERY STATE where the host can background it: `batten`
# lives outside every install root, so phase (b) alone never named it, and `ok`
# judges nothing else.
test_an_inline_dispatch_is_held_in_every_state if {
	every state in ["undispatched", "running", "failed", "ok"] {
		some v in violation with input as {"facts": {"install-pending": object.union(running, {"state": state, "dispatching": true, "pending": []})}, "call": {"programs": [{"program": "batten", "name": "batten"}]}}
		{"artifact": "batten startup --session inline"} in v.subjects
		{"artifact": sprintf("session-setup %s", [state])} in v.subjects
	}
}

test_an_inline_dispatch_is_held_once if {
	count(violation) == 1 with input as {"facts": {"install-pending": object.union(waiting, {"dispatching": true})}, "call": cargo_build}
}
