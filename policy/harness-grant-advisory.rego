# A write changing a permission rule list in Claude Code's settings is pointed
# at the memory owning the forms that bind (CLOUD-1636).
#
# THE INSTANCE. `90261809` rewrote `.claude/settings.json`'s permission grant by
# hand on a wrong theory and reverted in `321ef668`. `mem:serena-setup` names
# that exact defect, measured 2026-09-05, and says not to replace an enumeration
# with a broader form; it is read on demand and nothing in the write path routed
# to it. This is the route.
#
# ITS OWN MODULE, NOT AN ARM OF `harness-config-advisory`: the boundary speaks a
# bundle's FIRST violation only (`hook::policy_advisories`), so a second class
# in one module never reaches the writer beside the first.
#
# The surface test restates `harness-config-advisory.rego`'s three-line `owners`
# over the same `[[pattern]]` family: a FUNCTION rule in another package does
# not resolve here (`shell-write-advisory.rego` records the measurement), and
# the family, not the spelling, is the one authority both read.

#MUTANT-SUITE crates/batten/tests/it/harness_config_route.rs
#MUTANT grant-route-unadjudicated|s@^\tregex.match(data.batten.patterns\["harness-permission-rule"\], text)$@\tfalse@|a_written_body_registering_no_hook_is_told_the_vendor_route

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: it reads `{call, facts}` and never the
#   tree document, so a module reading `input.tree.*` here fails to type check
#   rather than evaluating to undefined (CLOUD-845).
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.harness_grant_advisory

rules contains "grant edit early"

claude_code_surface(path) if {
	regex.match(data.batten.patterns["harness-config-claude-code"], path)
}

# BEHIND A TYPE GUARD: `some x in null` raises rather than abstaining.
edits := input.call.arguments.edits if is_array(input.call.arguments.edits)

# Both sides of an edit: a grant REMOVED is as much a permission change as one
# added.
edit_text contains text if {
	some key in ["content", "new_string", "old_string"]
	text := input.call.arguments[key]
	is_string(text)
}

edit_text contains text if {
	some edit in edits
	some key in ["new_string", "old_string"]
	text := edit[key]
	is_string(text)
}

violation contains {
	"rule": "grant edit early",
	"verdict": "grant edit early",
	"subjects": [{"path": path}],
} if {
	input.call.operation == "write"
	path := input.call.writes
	is_string(path)
	claude_code_surface(path)
	some text in edit_text
	regex.match(data.batten.patterns["harness-permission-rule"], text)
}

deny contains verdict if some verdict in {v.verdict | some v in violation}

# --- cases ---------------------------------------------------------------

surfaces := {
	"harness-config-claude-code": `(^|/)\.claude/(settings|settings\.local|launcher-settings)\.json$`,
	"harness-permission-rule": `"(allow|deny)"\s*:`,
}

test_a_permission_edit_is_told_the_memory if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.json",
		"write-targets": null,
		"arguments": {"old_string": "x", "new_string": `"allow": ["Bash(git *)"]`},
	}}
		with data.batten.patterns as surfaces
	v.verdict == "grant edit early"
}

test_a_removed_grant_is_told_the_memory_too if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.local.json",
		"arguments": {"edits": [{"old_string": `"deny": []`, "new_string": ""}]},
	}}
		with data.batten.patterns as surfaces
	v.verdict == "grant edit early"
}

test_a_settings_write_without_a_grant_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.json",
		"arguments": {"content": `{"model": "x"}`},
	}}
		with data.batten.patterns as surfaces
}

test_a_grant_outside_the_surface_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": "crates/batten/src/hook.rs",
		"arguments": {"content": `"allow": 1`},
	}}
		with data.batten.patterns as surfaces
}

# The compound case `policy test` requires (CLOUD-857): a shell call is not a
# write tool, so its command text decides nothing here.
test_a_compound_shell_call_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "command",
		"command": "cd /tmp && echo '\"allow\": []' > .claude/settings.json",
		"writes": null,
	}}
		with data.batten.patterns as surfaces
}
