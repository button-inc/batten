#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT destructive-granted|s@^\tgranted_effects(program\["batten-effect"\])$@\tprogram["batten-effect"] != null@|a_destructive_batten_verb_is_not_preapproved
# batten's own lifecycle is never put to the operator (CLOUD-1949).
#
# The measured failure: a session halted, again and again, on a host prompt or
# an auto-mode denial for `batten override spend`, `batten claim check`,
# `batten land replay` — the steps the gates themselves prescribe. A gate that
# names a remedy and a host that then refuses to run it is a dead end the agent
# cannot leave. So a call made only of `batten` verbs whose DECLARED effect is
# read or write is granted, outside plan mode.
#
# NEVER A DESTRUCTIVE VERB, and never a noun: `target prune` and `capture prune`
# are `destructive` and stay the host's to ask about, and a write-bearing noun is
# `unclassified` so it resolves to nothing grantable (CLOUD-170).
#
# WHY NOT `permissions.allow` AS WELL. The committed settings file is the host's
# own authority, and the host already honours it; re-deciding its rule grammar
# here would be a second matcher over one list, and the one place the host
# declines its own allow rule — auto mode dropping a broad interpreter rule — is
# a decision this preset must not reverse.
package batten.claude_code_cloud

import rego.v1

rules contains "call grant now"

preapprove contains "call grant now" if {
	input.call.event == "pre-tool"
	input.call.tool == "Bash"
	not input.call["permission-mode"] == "plan"
	count(input.call.programs) > 0
	every program in input.call.programs {
		lifecycle(program)
	}
	not some_output_redirect(input.call)
}

granted_effects(effect) if {
	effect in {"read", "write"}
}

lifecycle(program) if {
	granted_effects(program["batten-effect"])
}

# `cd` beside a batten verb changes only where it runs.
lifecycle(program) if program.name == "cd"

test_an_override_spend_is_granted if {
	"call grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": "batten override spend --admission x",
		"segments": [{"words": ["batten", "override", "spend", "--admission", "x"]}],
		"programs": [{"name": "batten", "arguments": ["override", "spend", "--admission", "x"], "batten-effect": "write"}],
	}}
}

test_a_prune_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": "batten target prune -y",
		"segments": [{"words": ["batten", "target", "prune", "-y"]}],
		"programs": [{"name": "batten", "arguments": ["target", "prune", "-y"], "batten-effect": "destructive"}],
	}}
}

test_a_batten_verb_beside_a_push_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": "batten claim check && git push",
		"segments": [{"words": ["batten", "claim", "check"]}, {"words": ["git", "push"]}],
		"programs": [
			{"name": "batten", "arguments": ["claim", "check"], "batten-effect": "write"},
			{"name": "git", "arguments": ["push"], "batten-effect": null},
		],
	}}
}

test_plan_mode_grants_no_write if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "plan",
		"command": "batten override spend --admission x",
		"segments": [{"words": ["batten", "override", "spend", "--admission", "x"]}],
		"programs": [{"name": "batten", "arguments": ["override", "spend", "--admission", "x"], "batten-effect": "write"}],
	}}
}
