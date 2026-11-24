# A write reaching one harness's configuration surface names the harnesses it
# left behind (CLOUD-1636, the neutrality half).
#
# Batten adjudicates for six harnesses, and a repair applied to one harness's
# file reaches that harness alone. Making each harness work is vendor-specific;
# batten behaving the same on all of them is not (`rules/harness-config.md`). A
# change to one harness's config is complete when it is applied to the
# analogous surface on the others, or scoped to one on purpose.
#
# IT REPORTS. A scoped decision is legitimate, and this line is how it gets
# stated rather than defaulted into, so the row is a `warn`.
#
# ITS OWN MODULE for `harness-grant-advisory.rego`'s reason: the boundary speaks
# a bundle's first violation only, so an arm here would be withheld behind the
# vendor route on exactly the writes it exists for.
#
# Answerable from the declared `harness-config-<harness>` family and the call
# alone, so it answers identically in the hook, in CI and in a test.

#MUTANT-SUITE crates/batten/tests/it/harness_config_route.rs
#MUTANT neutrality-predicate-ignores-siblings|s@^\tcount(left) > 0$@\tfalse@|a_settings_write_names_the_harnesses_left_behind

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: it reads `{call, facts}` and never the
#   tree document, so a module reading `input.tree.*` here fails to type check
#   rather than evaluating to undefined (CLOUD-845).
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.harness_config_neutral

rules contains "hook edit partial"

# The harnesses the declared family names.
declared contains substring(id, count("harness-config-"), -1) if {
	some id, _ in data.batten.patterns
	startswith(id, "harness-config-")
}

# The harnesses whose declared surface `path` is.
owners(path) := {substring(id, count("harness-config-"), -1) |
	some id, pattern in data.batten.patterns
	startswith(id, "harness-config-")
	regex.match(pattern, path)
}

# BEHIND A TYPE GUARD: `some x in null` raises rather than abstaining, and
# `write-targets` is `null` on every write-tool call.
write_targets := input.call["write-targets"] if is_array(input.call["write-targets"])

written contains path if {
	input.call.operation == "write"
	path := input.call.writes
	is_string(path)
}

written contains target.path if {
	some target in write_targets
	is_string(target.path)
}

touched contains path if {
	some path in written
	count(owners(path)) > 0
}

reached contains name if {
	some path in touched
	some name in owners(path)
}

violation contains {
	"rule": "hook edit partial",
	"verdict": "hook edit partial",
	"subjects": array.concat(
		[{"path": path} | some path in sort(touched)],
		[{"artifact": name} | some name in sort(left)],
	),
} if {
	count(touched) > 0
	left := declared - reached
	count(left) > 0
}

deny contains verdict if some verdict in {v.verdict | some v in violation}

# --- cases ---------------------------------------------------------------

surfaces := {
	"harness-config-claude-code": `(^|/)\.claude/(settings|settings\.local|launcher-settings)\.json$`,
	"harness-config-cursor": `(^|/)\.cursor/hooks\.json$`,
	"harness-config-gemini-cli": `(^|/)\.gemini/settings\.json$`,
}

test_the_harnesses_left_behind_are_named if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "/home/u/.claude/settings.local.json",
		"write-targets": null,
	}}
		with data.batten.patterns as surfaces
	v.subjects == [
		{"path": "/home/u/.claude/settings.local.json"},
		{"artifact": "cursor"},
		{"artifact": "gemini-cli"},
	]
}

# The compound case `policy test` requires (CLOUD-857): a shell writing two
# harnesses' surfaces leaves only the third behind.
test_a_compound_shell_write_reaching_two_harnesses_names_the_third if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "tee .cursor/hooks.json < a && cp b .gemini/settings.json",
		"writes": null,
		"write-targets": [
			{"path": ".cursor/hooks.json", "program": "tee", "sources": [], "symbolic": false},
			{"path": ".gemini/settings.json", "program": "cp", "sources": ["b"], "symbolic": false},
		],
	}}
		with data.batten.patterns as surfaces
	v.subjects == [
		{"path": ".cursor/hooks.json"},
		{"path": ".gemini/settings.json"},
		{"artifact": "claude-code"},
	]
}

test_a_write_reaching_every_harness_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "command",
		"command": "tee .claude/settings.json .cursor/hooks.json .gemini/settings.json < a",
		"write-targets": [
			{"path": ".claude/settings.json", "program": "tee", "sources": [], "symbolic": false},
			{"path": ".cursor/hooks.json", "program": "tee", "sources": [], "symbolic": false},
			{"path": ".gemini/settings.json", "program": "tee", "sources": [], "symbolic": false},
		],
	}}
		with data.batten.patterns as surfaces
}

test_an_unrelated_write_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": "crates/batten/src/hook.rs",
	}}
		with data.batten.patterns as surfaces
}
