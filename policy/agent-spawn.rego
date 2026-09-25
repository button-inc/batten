#MUTANT-SUITE crates/batten/tests/it/spawn_ceilings.rs
#MUTANT isolation-unread|s@^\tinput.call.arguments.isolation == "worktree"$@\tfalse@|a_worktree_spawn_is_refused
#MUTANT tool-unread|s@^wrong if input.call.tool == "EnterWorktree"$@wrong if false@|the_worktree_tool_is_refused
#MUTANT type-unread|s@^\tnot input.call.arguments.subagent_type in read_only_types$@\tfalse@|an_implementer_spawn_is_refused
#MUTANT allowlist-inverted|s@^\tnot input.call.arguments.subagent_type in read_only_types$@\tinput.call.arguments.subagent_type in read_only_types@|a_read_only_search_spawn_is_allowed
# One checkout, one branch, one implementer (CLOUD-1717).
#
# MEASURED 2026-09-25: four implementer subagents spawned with
# `isolation: "worktree"` into the one container this repository's sessions run
# in. Each worktree lacked the submodules and `ripsecrets`, each rebuilt
# `target/` from nothing; the disk filled twice, one agent committed
# `--no-verify`, and hours produced zero integrable commits. Nothing refused any
# of it: the spawn rows keyed on `Task` while the host's tool is `Agent`, and no
# module could see a spawn's arguments at all.
#
# So this refuses the three shapes, and only these:
#   - a spawn asking for worktree isolation;
#   - the host's own worktree tool;
#   - a spawn of an implementing agent type. Subagents here are read-only
#     search and design (`Explore`, `Plan`, `claude-code-guide`); implementation
#     is serial, by the session, in its one checkout (`mem:workflow/agent-fanout`).
#
# WHAT THIS DOES NOT SEE: an `Explore` agent told to write. Its type cannot write
# through the host's own tools, which is the property the allowlist leans on.
# METADATA
# description: |
#   Bound to the mediated-call surface: reads `input.call.tool` and
#   `input.call.arguments`, the host's tool name and the arguments it was handed.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.agent_spawn

import rego.v1

rules contains "spawn place wrong"

read_only_types := {"Explore", "Plan", "claude-code-guide"}

spawn if input.call.operation == "subagent"

wrong if {
	spawn
	input.call.arguments.isolation == "worktree"
}

wrong if input.call.tool == "EnterWorktree"

wrong if {
	spawn
	not input.call.arguments.subagent_type in read_only_types
}

violation contains {
	"rule": "spawn place wrong",
	"verdict": "spawn place wrong",
	"subjects": [{"count": 1}],
} if {
	wrong
}

test_a_worktree_spawn_is_refused if {
	some _ in violation with input as {"call": {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"subagent_type": "Explore", "isolation": "worktree"},
		"segments": [],
	}}
}

test_an_implementer_spawn_is_refused if {
	some _ in violation with input as {"call": {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"subagent_type": "general-purpose", "prompt": "port x"},
		"segments": [],
	}}
}

test_an_untyped_spawn_is_refused if {
	some _ in violation with input as {"call": {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"prompt": "port x"},
		"segments": [],
	}}
}

test_the_worktree_tool_is_refused if {
	some _ in violation with input as {"call": {
		"operation": "other",
		"tool": "EnterWorktree",
		"arguments": {},
		"segments": [],
	}}
}

test_a_read_only_search_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"subagent_type": "Explore", "prompt": "find x"},
		"segments": [],
	}}
}

test_a_shell_call_is_not_judged if {
	count(violation) == 0 with input as {"call": {
		"operation": "execute",
		"tool": "Bash",
		"arguments": {"command": "git status && git worktree list"},
		"command": "git status && git worktree list",
		"segments": [
			{"words": ["git", "status"], "raw": "git status", "terminator": "&&"},
			{"words": ["git", "worktree", "list"], "raw": "git worktree list", "terminator": null},
		],
	}}
}

deny contains message if {
	some v in violation
	message := v.verdict
}
