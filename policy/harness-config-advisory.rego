# A write to a harness's configuration surface is told its vendor route, and
# which harnesses it left behind (CLOUD-1636).
#
# THE INSTANCE. `90261809` rewrote `.claude/settings.json`'s permission grant by
# hand on a wrong theory and reverted in `321ef668`. The boundary saw every write
# and said nothing, while two pointers that would have prevented it existed: the
# host's own `update-config` skill, which carries the legal permission-rule
# forms, and `mem:serena-setup`, which names that exact defect. Both were
# feedforward with no trigger; this is the trigger.
#
# THE SECOND HALF IS THE ONE THAT GENERALISES. Batten adjudicates for six
# harnesses and a repair applied to one harness's file reaches one of them. A
# change to one harness's config is incomplete until it is applied to the
# analogous surface on the others or scoped on purpose (`rules/harness-config.md`).
# `hook edit partial` names the harnesses whose declared surface the call did
# not reach. It REPORTS: a scoped decision is legitimate, and the line is how it
# gets stated rather than defaulted into.
#
# WHY `warn`. The vendor route is itself a writer of these files — the skill
# edits `.claude/settings.json` through the same write tool — so a deny here
# would refuse the route it names. The registration case, where a refusal IS
# right, is `policy/harness-config-route.rego`'s, and its deny pre-empts these.
#
# Pure functions of the declared `harness-config-<harness>` family plus the
# call, so they answer identically in the hook, in CI and in a test.

#MUTANT-SUITE crates/batten/tests/it/harness_config_route.rs
#MUTANT config-write-unadjudicated|s@^\t"claude-code" in owners\(path\)$@\tfalse@|a_settings_write_is_told_the_vendor_route
#MUTANT neutrality-predicate-ignores-siblings|s@^\tcount\(left\) > 0$@\tfalse@|a_settings_write_names_the_harnesses_left_behind

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: it reads `{call, facts}` and never the
#   tree document, so a module reading `input.tree.*` here fails to type check
#   rather than evaluating to undefined (CLOUD-845).
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.harness_config_advisory

rules contains "hook edit early"

rules contains "grant edit early"

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

# Every path this call writes by name: a write tool's target, and each shell
# write target. `is_string` is load-bearing: both are `null` off their surface.
written contains path if {
	input.call.operation == "write"
	path := input.call.writes
	is_string(path)
}

written contains target.path if {
	some target in input.call["write-targets"]
	is_string(target.path)
}

# The written surfaces, and the harnesses they belong to.
touched contains path if {
	some path in written
	count(owners(path)) > 0
}

reached contains name if {
	some path in touched
	some name in owners(path)
}

# What a write tool hands its target, both sides of an edit included: a grant
# REMOVED is as much a permission change as one added.
edit_text contains text if {
	some key in ["content", "new_string", "old_string"]
	text := input.call.arguments[key]
	is_string(text)
}

edit_text contains text if {
	some edit in input.call.arguments.edits
	some key in ["new_string", "old_string"]
	text := edit[key]
	is_string(text)
}

violation contains {
	"rule": "hook edit early",
	"verdict": "hook edit early",
	"subjects": [{"path": path}],
} if {
	some path in touched
	"claude-code" in owners(path)
}

violation contains {
	"rule": "grant edit early",
	"verdict": "grant edit early",
	"subjects": [{"path": path}],
} if {
	input.call.operation == "write"
	path := input.call.writes
	is_string(path)
	"claude-code" in owners(path)
	some text in edit_text
	regex.match(data.batten.patterns["harness-permission-rule"], text)
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
	"harness-permission-rule": `"(allow|deny)"\s*:`,
}

test_a_settings_write_is_told_the_vendor_route if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.json",
		"arguments": {"content": "{}"},
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook edit early"
}

test_a_permission_edit_is_told_the_memory if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.json",
		"arguments": {"old_string": "x", "new_string": `"allow": ["Bash(git *)"]`},
	}}
		with data.batten.patterns as surfaces
	v.verdict == "grant edit early"
}

test_a_settings_write_without_a_grant_is_not_told_the_memory if {
	verdicts := {v.verdict | some v in violation} with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.json",
		"arguments": {"content": `{"model": "x"}`},
	}}
		with data.batten.patterns as surfaces
	not "grant edit early" in verdicts
}

test_the_harnesses_left_behind_are_named if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "/home/u/.claude/settings.local.json",
		"arguments": {"content": "{}"},
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook edit partial"
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
		"write-targets": [
			{"path": ".cursor/hooks.json", "program": "tee", "sources": [], "symbolic": false},
			{"path": ".gemini/settings.json", "program": "cp", "sources": ["b"], "symbolic": false},
		],
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook edit partial"
	v.subjects[2] == {"artifact": "claude-code"}
	count(v.subjects) == 3
}

test_another_harnesses_surface_gets_no_vendor_route if {
	verdicts := {v.verdict | some v in violation} with input as {"call": {
		"operation": "write",
		"writes": ".cursor/hooks.json",
		"arguments": {"content": "{}"},
	}}
		with data.batten.patterns as surfaces
	not "hook edit early" in verdicts
}

test_an_unrelated_write_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": "crates/batten/src/hook.rs",
		"arguments": {"content": `"allow": 1`},
	}}
		with data.batten.patterns as surfaces
}

test_a_call_carrying_no_write_is_silent if {
	count(violation) == 0 with input as {"call": {"operation": "command", "write-targets": null}}
		with data.batten.patterns as surfaces
}
