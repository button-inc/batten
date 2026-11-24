# A write to Claude Code's settings surface is told its vendor route
# (CLOUD-1636).
#
# THE INSTANCE. `90261809` rewrote `.claude/settings.json`'s permission grant by
# hand on a wrong theory and reverted in `321ef668`. The boundary saw every write
# and said nothing, while the host's own `update-config` skill, which carries the
# legal permission-rule forms, existed and was not invoked until after the
# write. This is the trigger that skill never had.
#
# ONE CLASS PER MODULE. The boundary speaks a bundle's FIRST violation only
# (`hook::policy_advisories`), so the permission-forms memory is
# `harness-grant-advisory.rego` and the neutrality half is
# `harness-config-neutral.rego`: an arm here would be withheld behind this one.
#
# CLAUDE CODE ONLY, because it is the one harness with a surveyed vendor route.
# Another harness's surface gets the neutrality line and no vendor pointer: the
# route is unknown, not absent (`rules/harness-config.md`).
#
# WHY `warn`. The vendor route is itself a writer of these files — the skill
# edits `.claude/settings.json` through the same write tool — so a deny here
# would refuse the route it names. The registration case, where a refusal IS
# right, is `policy/harness-config-route.rego`'s, and its deny pre-empts this.

#MUTANT-SUITE crates/batten/tests/it/harness_config_route.rs
#MUTANT config-write-unadjudicated|s@^\tclaude_code_surface(path)$@\tfalse@|a_settings_write_is_told_the_vendor_route

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

claude_code_surface(path) if {
	regex.match(data.batten.patterns["harness-config-claude-code"], path)
}

# BEHIND A TYPE GUARD: `some x in null` raises rather than abstaining, and
# `write-targets` is `null` on every write-tool call, so an unguarded iteration
# faults the module on exactly the calls the other arm judges.
write_targets := input.call["write-targets"] if is_array(input.call["write-targets"])

# Every path this call writes by name: a write tool's target, and each shell
# write target. `is_string` is load-bearing: both are `null` off their surface.
written contains path if {
	input.call.operation == "write"
	path := input.call.writes
	is_string(path)
}

written contains target.path if {
	some target in write_targets
	is_string(target.path)
}

violation contains {
	"rule": "hook edit early",
	"verdict": "hook edit early",
	"subjects": [{"path": path}],
} if {
	some path in written
	claude_code_surface(path)
}

deny contains verdict if some verdict in {v.verdict | some v in violation}

# --- cases ---------------------------------------------------------------

surfaces := {"harness-config-claude-code": `(^|/)\.claude/(settings|settings\.local|launcher-settings)\.json$`}

# `write-targets` SPELLED `null`, as the engine sends it on a write tool: a case
# omitting the key reads undefined and hid the fault the type guard closes.
test_a_settings_write_is_told_the_vendor_route if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.json",
		"write-targets": null,
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook edit early"
}

test_a_home_settings_write_is_told_too if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "/home/u/.claude/settings.local.json",
		"write-targets": null,
	}}
		with data.batten.patterns as surfaces
	v.subjects == [{"path": "/home/u/.claude/settings.local.json"}]
}

# The compound case `policy test` requires (CLOUD-857): the shell write behind a
# `cd` is still a write to the surface.
test_a_compound_shell_write_is_told_too if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "cd /tmp && tee .claude/settings.json < a",
		"writes": null,
		"write-targets": [{"path": ".claude/settings.json", "program": "tee", "sources": [], "symbolic": false}],
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook edit early"
}

test_another_harnesses_surface_gets_no_vendor_route if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": ".cursor/hooks.json",
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

test_a_call_carrying_no_write_is_silent if {
	count(violation) == 0 with input as {"call": {"operation": "command", "write-targets": null}}
		with data.batten.patterns as surfaces
}
