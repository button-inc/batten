# In auto mode, every call batten allows is granted (CLOUD-2125).
#
# THE MEASURED FAILURE. CLOUD-1949 and CLOUD-2057 each granted one more class of
# call — batten verbs, then git — and left the rest to the host's auto-mode
# classifier. A leased push to the session's own branch, which every batten rule
# allows, came back `[Git Destructive]` because the line also ran `echo`, and the
# git grant requires every program in the line to be git. A list of granted
# classes always has a next class it forgot.
#
# THE OWNER'S RULE, as the predicate: in auto mode the default is ALLOW, and only
# a gate with a rule that denies may refuse. Plan mode keeps its own modules
# (`read-only-is-preapproved`, `plan-mode-refuses-writes`); the remaining modes
# are the host's to prompt in, as the operator chose them.
#
# SOUND FOR THE SAME REASON EVERY OTHER GRANT IS: the engine asks `preapprove`
# only after its own decision came back Allow (`compose` in `lib.rs`, deny
# first), so this grants nothing any rule refused. It adds no judgement; it stops
# discarding the one batten already made.
# Its own package: `preapprove` is a package-wide set, so sharing
# `batten.claude_code_cloud` would put this grant into every sibling module's
# own `test_` cases, which state what THAT module grants.
package batten.claude_code_cloud.auto_mode

import rego.v1

rules contains "mode grant now"

preapprove contains "mode grant now" if {
	input.call.event == "pre-tool"
	input.call["permission-mode"] == "auto"
}

test_an_auto_mode_call_is_granted if {
	"mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
		"command": "git push --force-with-lease=feat:abc origin feat && echo pushed",
	}}
}

test_default_mode_is_left_to_the_host if {
	not "mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": "git push origin feat",
	}}
}

test_plan_mode_is_left_to_its_own_modules if {
	not "mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "plan",
		"command": "git push origin feat",
	}}
}

test_a_post_tool_event_grants_nothing if {
	not "mode grant now" in preapprove with input as {"call": {"event": "post-tool", "tool": "Bash", "permission-mode": "auto"}}
}
