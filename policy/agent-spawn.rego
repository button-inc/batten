#MUTANT-SUITE crates/batten/tests/it/spawn_ceilings.rs
#MUTANT isolation-unread|s@^\tinput.call.arguments.isolation == "worktree"$@\tfalse@|a_worktree_spawn_is_refused
#MUTANT tool-unread|s@^wrong if input.call.tool == "EnterWorktree"$@wrong if false@|the_worktree_tool_is_refused
# One checkout, and no worktrees (CLOUD-1717, narrowed by CLOUD-2026).
#
# MEASURED 2026-09-25: four implementer subagents spawned with
# `isolation: "worktree"` into the one container this repository's sessions run
# in. Each worktree lacked the submodules and `ripsecrets`, each rebuilt
# `target/` from nothing; the disk filled twice, one agent committed
# `--no-verify`, and hours produced zero integrable commits. The cause was the
# WORKTREES — a second checkout per agent — and that is what this refuses:
#   - a spawn asking for worktree isolation;
#   - the host's own worktree tool.
#
# IMPLEMENTER SUBAGENTS ARE ALLOWED (CLOUD-2026). The owner ruled on 2026-09-29
# that in auto mode subagents and workflows never prompt, implementers included,
# and that only sibling-session dispatch is gated. An implementer here shares the
# one checkout, and every tool call it makes passes through this same hook, so
# every other deny still applies to its work. The type allowlist this module
# carried refused that, and is gone.
# METADATA
# description: |
#   Bound to the mediated-call surface: reads `input.call.tool` and
#   `input.call.arguments`, the host's tool name and the arguments it was handed.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.agent_spawn

import rego.v1

rules contains "spawn place wrong"

spawn if input.call.operation == "subagent"

wrong if {
	spawn
	input.call.arguments.isolation == "worktree"
}

wrong if input.call.tool == "EnterWorktree"

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

test_an_implementer_spawn_is_allowed if {
	count(violation) == 0 with input as {"call": {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"subagent_type": "general-purpose", "prompt": "port x"},
		"segments": [],
	}}
}

test_an_implementer_in_a_worktree_is_refused if {
	some _ in violation with input as {"call": {
		"operation": "subagent",
		"tool": "Agent",
		"arguments": {"subagent_type": "general-purpose", "isolation": "worktree", "prompt": "port x"},
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
