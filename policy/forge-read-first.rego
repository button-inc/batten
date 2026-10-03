#MUTANT-SUITE crates/batten/tests/it/forge_read_first.rs
#MUTANT forge-call-unselected|s@^\tprogram.name == "gh"$@\tfalse@|a_forge_call_is_handed_its_memory
# A call that reaches the code host is handed the memory documenting this host's
# GitHub access (CLOUD-1470).
#
# MEASURED TWICE, and both are why this exists. 2026-08-31 (CLOUD-1259): an agent
# took an `add_repo` detour the memory itself says is blocked. 2026-09-05: a
# session spent six turns telling the owner the lander could not run — every
# measurement true, the conclusion false — and `mise run land` drove the loop
# first try. The memory opens with exactly that warning, and nothing said to read
# it at the moment it mattered.
#
# A WARN ROW, NEVER A DENY. The call is allowed; the pointer rides it on the
# advisory channel, where the class's one `document` route renders as `read …`.
#
# SELECTED ON THE PROGRAM, never on a segment's first word (CLOUD-1382), so
# `cd /tmp && mise exec -- gh …` resolves to `gh`. `git` is judged on its FIRST
# argument on purpose: `git commit -m push` is not a forge call. `git -C <dir>
# push` is therefore not selected — a stated narrowing, not a miss.
#
# `pre-tool` only, so one call gets one pointer and the batch boundary does not
# repeat it. The tool names are this host's, which is why they live in consumer
# data rather than in the engine.
# METADATA
# description: |
#   Bound to the mediated-call surface: this module is `scope = "mediated_call"`,
#   so it reads `{call, facts}` and NOT the tree document.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.forge_read_first

import rego.v1

rules contains "forge read first"

forge_verbs := {"push", "fetch", "pull", "clone", "ls-remote"}

reached contains program.name if {
	some program in input.call.programs
	program.name == "gh"
}

reached contains program.name if {
	some program in input.call.programs
	program.name == "git"
	program.arguments[0] in forge_verbs
}

reached contains program.name if {
	some program in input.call.programs
	program.name == "mise"
	program.arguments[0] == "run"
	program.arguments[1] == "land"
}

reached contains input.call.tool if startswith(input.call.tool, "mcp__github__")

reached contains input.call.tool if input.call.tool == "mcp__claude-code-remote__add_repo"

violation contains {
	"rule": "forge read first",
	"verdict": "forge read first",
	"subjects": [{"artifact": name}],
} if {
	input.call.event == "pre-tool"
	some name in reached
}

# Every case passes `programs`, and at least one is compound: `batten policy
# test` refuses a mediated-call suite of bare commands (CLOUD-857). These hand the
# predicate a resolution the engine is supposed to produce;
# `crates/batten/tests/it/forge_read_first.rs` is the tier that drives the engine.
test_a_gh_read_is_selected if {
	some _ in violation with input as {"call": {
		"event": "pre-tool",
		"programs": [{"program": "gh", "name": "gh", "arguments": ["pr", "view", "1"], "mediated": false}],
	}}
}

test_gh_through_the_pin_in_a_compound_is_selected if {
	some _ in violation with input as {"call": {
		"event": "pre-tool",
		"command": "cd /tmp && mise exec -- gh api repos/o/r",
		"programs": [
			{"program": "cd", "name": "cd", "arguments": ["/tmp"], "mediated": false},
			{"program": "gh", "name": "gh", "arguments": ["api", "repos/o/r"], "mediated": true},
		],
	}}
}

test_a_git_push_is_selected if {
	some _ in violation with input as {"call": {
		"event": "pre-tool",
		"programs": [{"program": "git", "name": "git", "arguments": ["push", "origin", "HEAD"], "mediated": false}],
	}}
}

test_land_is_selected if {
	some _ in violation with input as {"call": {
		"event": "pre-tool",
		"programs": [{"program": "mise", "name": "mise", "arguments": ["run", "land"], "mediated": false}],
	}}
}

test_a_github_tool_is_selected if {
	some _ in violation with input as {"call": {"event": "pre-tool", "tool": "mcp__github__get_me", "programs": []}}
}

test_add_repo_is_selected if {
	some _ in violation with input as {"call": {
		"event": "pre-tool",
		"tool": "mcp__claude-code-remote__add_repo",
		"programs": [],
	}}
}

test_a_listing_is_not_selected if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool",
		"programs": [{"program": "ls", "name": "ls", "arguments": ["-la"], "mediated": false}],
	}}
}

test_a_local_git_call_is_not_selected if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool",
		"programs": [{"program": "git", "name": "git", "arguments": ["status"], "mediated": false}],
	}}
}

test_a_commit_message_saying_push_is_not_selected if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool",
		"programs": [{"program": "git", "name": "git", "arguments": ["commit", "-m", "push"], "mediated": false}],
	}}
}

test_an_echo_naming_gh_is_not_selected if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool",
		"command": "cd /tmp && echo gh",
		"programs": [
			{"program": "cd", "name": "cd", "arguments": ["/tmp"], "mediated": false},
			{"program": "echo", "name": "echo", "arguments": ["gh"], "mediated": false},
		],
	}}
}

test_a_gh_call_at_stop_is_not_selected if {
	count(violation) == 0 with input as {"call": {
		"event": "stop",
		"programs": [{"program": "gh", "name": "gh", "arguments": ["pr", "view", "1"], "mediated": false}],
	}}
}

deny contains message if {
	some v in violation
	message := v.verdict
}
