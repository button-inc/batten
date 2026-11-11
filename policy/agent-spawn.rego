#MUTANT-SUITE crates/batten/tests/it/spawn_ceilings.rs
#MUTANT isolation-unread|s@^\tinput.call.arguments.isolation == "worktree"$@\tfalse@|a_worktree_spawn_is_refused
#MUTANT tool-unread|s@^\tinput.call.tool == "EnterWorktree"$@\tfalse@|the_worktree_tool_is_refused
#MUTANT host-unread|s@^\tinput.call.host == "disposable"$@\ttrue@|a_worktree_on_a_machine_is_allowed
#MUTANT add-unread|s@^\tprogram.arguments\[at + 1\] == "add"$@\tfalse@|a_shell_worktree_add_is_refused
# No worktrees in a disposable container; worktrees on a developer's machine
# (CLOUD-1717, narrowed by CLOUD-2026, made host-aware by CLOUD-2709).
#
# MEASURED 2026-09-25: four implementer subagents spawned with
# `isolation: "worktree"` into the one container this repository's sessions run
# in. Each worktree lacked the submodules and `ripsecrets`, each rebuilt
# `target/` from nothing; the disk filled twice, one agent committed
# `--no-verify`, and hours produced zero integrable commits. The cause was the
# WORKTREES — a second checkout per agent — and that is what this refuses, on a
# disposable host:
#   - a spawn asking for worktree isolation;
#   - the host's own worktree tool;
#   - `git worktree add` through the shell, which the first two left open:
#     measured on PR #1276 (2026-11-10), a cloud session added one and built
#     into the main checkout's `target/` during a `land` lap.
#
# ON A DEVELOPER'S MACHINE ALL THREE ARE ADMITTED (CLOUD-2709). There a worktree
# is the practice, not the hazard: the disk and the build cache are the
# developer's, and each line of work gets its own checkout. The kind of machine
# is `input.call.host`, which the engine DETECTS from the harness's own signal
# (`environment::host`) — a committed preset cannot state it, because one commit
# is read by both kinds of machine.
#
# IMPLEMENTER SUBAGENTS ARE ALLOWED (CLOUD-2026). The owner ruled on 2026-09-29
# that in auto mode subagents and workflows never prompt, implementers included,
# and that only sibling-session dispatch is gated. An implementer shares the one
# checkout, and every tool call it makes passes through this same hook.
# METADATA
# description: |
#   Bound to the mediated-call surface: reads `input.call.host`,
#   `input.call.tool`, `input.call.arguments` and `input.call.programs`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.agent_spawn

import rego.v1

rules contains "spawn place wrong"

disposable if {
	input.call.host == "disposable"
}

spawn if input.call.operation == "subagent"

worktree if {
	spawn
	input.call.arguments.isolation == "worktree"
}

worktree if {
	input.call.tool == "EnterWorktree"
}

# `git [<global options>] worktree add …`: the projected argv starts at the
# subcommand's own word, wherever global options left it.
worktree if {
	some program in input.call.programs
	program.name == "git"
	program.subcommand == "worktree"
	some at, word in program.arguments
	word == "worktree"
	program.arguments[at + 1] == "add"
}

violation contains {
	"rule": "spawn place wrong",
	"verdict": "spawn place wrong",
	"subjects": [{"count": 1}],
} if {
	disposable
	worktree
}

# --- the load-time tier ------------------------------------------------------

on(host, call) := {"call": object.union(call, {"host": host})}

worktree_spawn := {
	"operation": "subagent",
	"tool": "Agent",
	"arguments": {"subagent_type": "Explore", "isolation": "worktree"},
	"segments": [],
	"programs": [],
}

git(arguments) := {
	"operation": "execute",
	"tool": "Bash",
	"arguments": {},
	"segments": [],
	"programs": [{"name": "git", "subcommand": "worktree", "arguments": arguments}],
}

test_a_worktree_spawn_is_refused if {
	some _ in violation with input as on("disposable", worktree_spawn)
}

test_a_worktree_on_a_machine_is_allowed if {
	count(violation) == 0 with input as on("machine", worktree_spawn)
	count(violation) == 0 with input as on("machine", git(["worktree", "add", "../wt"]))
}

test_an_implementer_spawn_is_allowed if {
	count(violation) == 0 with input as on("disposable", {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"subagent_type": "general-purpose", "prompt": "port x"},
		"segments": [],
		"programs": [],
	})
}

test_the_worktree_tool_is_refused if {
	some _ in violation with input as on("disposable", {
		"operation": "other",
		"tool": "EnterWorktree",
		"arguments": {},
		"segments": [],
		"programs": [],
	})
}

test_a_shell_worktree_add_is_refused if {
	some _ in violation with input as on("disposable", git(["worktree", "add", "../wt"]))
}

test_listing_worktrees_is_allowed if {
	count(violation) == 0 with input as on("disposable", git(["worktree", "list"]))
}

test_a_read_only_search_is_allowed if {
	count(violation) == 0 with input as on("disposable", {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"subagent_type": "Explore", "prompt": "find x"},
		"segments": [],
		"programs": [],
	})
}

deny contains message if {
	some v in violation
	message := v.verdict
}
