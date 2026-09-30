#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT unwatch-method-unread|s@^unwatch_method(tool) if regex.match(.*@unwatch_method(tool) if false@|an_unsubscribe_is_preapproved_in_every_mode
# Dropping a PR subscription is never put to the operator.
#
# The owner's ruling, verbatim: "Batten must be always approving unsubscribe pr
# activity you can't be stopping the world to unsubscribe especially since you
# never asked my permission to subscribe in the first place". The harness
# subscribes a session to every PR it opens, unasked; AGENTS.md denies the
# subscription, so the drop is the session UNDOING a change nobody authorised.
# Prompting for the undo — or refusing it in plan mode — halts the session on
# the one call that restores the owner's posture.
#
# EVERY MODE, PLAN MODE INCLUDED. `plan-mode-refuses-writes.rego` reads
# `unwatch_method` and exempts it, so the grant and the exemption are one
# definition and cannot drift apart.
#
# THE METHOD IS THE WHOLE SEGMENT AFTER THE SERVER ALIAS, so the alias decides
# nothing and `subscribe_pr_activity` — which `review watch refused` denies —
# can never match.
#
# Measured 2026-09-28: a hook `allow` clears the Claude Code Remote connector's
# prompt (`get_session` ran with no dialog), which is what makes this grant an
# authority rather than the claim CLOUD-790 found the bash guard's arm to be.
package batten.claude_code_cloud

import rego.v1

rules contains "watch drop now"

preapprove contains "watch drop now" if {
	input.call.event == "pre-tool"
	unwatch_method(input.call.tool)
}

unwatch_method(tool) if regex.match(`^mcp__[^_].*__unsubscribe_pr_activity$`, tool)

test_an_unsubscribe_is_granted_in_every_mode if {
	every mode in ["plan", "auto", "default", "acceptEdits", null] {
		"watch drop now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__unsubscribe_pr_activity", "permission-mode": mode}}
	}
}

test_either_connector_spelling_is_granted if {
	"watch drop now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "mcp__github__unsubscribe_pr_activity"}}
}

# THE SUFFIX HAZARD, from the other side: a subscribe is the one call this must
# never grant.
test_a_subscribe_is_not if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "mcp__Claude_Code_Remote__subscribe_pr_activity"}}
}

test_a_lookalike_is_not if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "mcp__x__unsubscribe_pr_activity_v2"}}
}

# A shell line naming the method is not the method.
test_a_shell_line_naming_the_method_is_not if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "Bash", "command": "echo unsubscribe_pr_activity && true"}}
}
