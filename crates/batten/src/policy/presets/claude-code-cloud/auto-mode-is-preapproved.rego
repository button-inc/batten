#MUTANT-SUITE crates/batten/tests/it/permission_events.rs
#MUTANT plan-mode-write-granted|s@^\tinput.call\["permission-mode"\] != "plan"$@\ttrue@|a_write_prompt_in_plan_mode_is_not_granted
#MUTANT dispatch-granted-in-plan|s@^\tinput.call\["permission-mode"\] != "plan"$@\ttrue@|a_dispatch_prompt_in_plan_mode_is_not_granted
#MUTANT grant-auto-only|s@^\tinput.call\["permission-mode"\] != "plan"$@\tinput.call["permission-mode"] == "auto"@|a_prompt_in_default_mode_is_answered_with_allow
#MUTANT auto-grant-pre-tool-only|s@^\tinput.call.event == "permission-denied"$@\tinput.call.event == "pre-tool"@|a_denial_in_auto_is_answered_with_retry_and_counted
#MUTANT prompt-grant-pre-tool-only|s@^granted_event(event) if event in {"pre-tool", "permission-request"}$@granted_event(event) if event == "pre-tool"@|a_prompt_in_auto_is_answered_with_allow_and_counted
#MUTANT denial-needs-the-mode-field|s@^\tnot input.call\["permission-mode"\] == "plan"$@\tis_string(input.call["permission-mode"])@|a_denial_with_no_mode_field_is_still_answered_and_counted
#MUTANT host-decided-granted|s@^\tnot host_decided_call$@\ttrue@|a_destructive_git_call_is_left_to_the_host_in_every_mode
# Every call batten allows is granted, in every permission mode but plan
# (CLOUD-2125; widened by the owner's ruling of 2026-11-23, CLOUD-2768).
#
# THE MEASURED FAILURE. CLOUD-1949 and CLOUD-2057 each granted one more class of
# call — batten verbs, then git — and left the rest to the host's auto-mode
# classifier. A leased push to the session's own branch, which every batten rule
# allows, came back `[Git Destructive]` because the line also ran `echo`, and the
# git grant requires every program in the line to be git. A list of granted
# classes always has a next class it forgot.
#
# THE OWNER'S RULE, as the predicate: the default is ALLOW, and only a gate with
# a rule that denies may refuse. It held in `auto` alone until 2026-11-23, when
# child sessions booted in `default` put each `send_message` to the owner as a
# prompt nothing answered. The ruling widened it to every mode but plan, and to
# the two events the host sends after pre-tool:
#
# - `permission-request`, the prompt the host is about to show: answered allow;
# - `permission-denied`, the auto-mode classifier's denial: answered retry. The
#   host documents it as firing only in auto mode, so it is granted on the event
#   alone, and an envelope with no mode field is answered all the same.
#
# PLAN MODE IS READ-ONLY, so this grants nothing there. A read-only call is
# granted in every mode by `read-only-is-preapproved`, at the prompt as at
# pre-tool, and `plan write refused` denies a write before any grant is asked.
#
# SOUND FOR THE SAME REASON EVERY OTHER GRANT IS: the engine asks `preapprove`
# only after its own decision came back Allow (`compose` in `lib.rs`, deny
# first), so this grants nothing any rule refused. A permission event reaches
# the host only for a call batten allowed at pre-tool, so its grant is the one
# that call already had. It adds no judgement; it stops discarding the one
# batten already made.
#
# A CALL THE HOST DECIDES IS NOT BATTEN'S TO GRANT (CLOUD-2768). Allowed is not
# granted for a git call that discards work with no batten alternative: the git
# preset leaves it to the host on purpose, so this yields wherever
# `git_host.host_decides` holds for any program in the call. That predicate is
# one module shipped in both presets' bundles, so the two grants read one
# judgement. Plan mode is unchanged.
# Its own package: `preapprove` is a package-wide set, so sharing
# `batten.claude_code_cloud` would put this grant into every sibling module's
# own `test_` cases, which state what THAT module grants.
package batten.claude_code_cloud.auto_mode

import data.batten.git_host
import rego.v1

host_decided_call if git_host.call_decided(input.call, object.get(input, ["facts", "pathspec-status"], null))

rules contains "mode grant now"

# The events a mode decides the grant at.
granted_event(event) if event in {"pre-tool", "permission-request"}

# A MODE FIELD IS REQUIRED HERE: the call document projects a missing one as
# `null`, and `null != "plan"` holds, so without the string test a call the
# host named no mode for would be granted.
preapprove contains "mode grant now" if {
	granted_event(input.call.event)
	is_string(input.call["permission-mode"])
	input.call["permission-mode"] != "plan"
	not host_decided_call
}

# The denial: the host sends it only in auto mode, so plan is a guard here, not
# the expected path, and an envelope with no mode field is granted.
preapprove contains "mode grant now" if {
	input.call.event == "permission-denied"
	not input.call["permission-mode"] == "plan"
	not host_decided_call
}

test_an_auto_mode_call_is_granted if {
	"mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "auto",
		"command": "git push --force-with-lease=feat:abc origin feat && echo pushed",
	}}
}

test_a_default_mode_call_is_granted if {
	"mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": "git push origin feat",
	}}
}

test_a_call_with_no_mode_is_not_granted_at_pre_tool if {
	not "mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": null,
		"command": "git push origin feat",
	}}
}

test_a_denial_with_no_mode_is_granted if {
	"mode grant now" in preapprove with input as {"call": {"event": "permission-denied", "tool": "Bash", "permission-mode": null}}
}

test_a_permission_request_in_plan_is_not_granted if {
	not "mode grant now" in preapprove with input as {"call": {
		"event": "permission-request", "tool": "Bash", "permission-mode": "plan",
		"command": "touch made",
	}}
}

test_a_permission_request_in_default_is_granted if {
	"mode grant now" in preapprove with input as {"call": {"event": "permission-request", "tool": "Bash", "permission-mode": "default"}}
}

test_a_permission_request_in_auto_is_granted if {
	"mode grant now" in preapprove with input as {"call": {"event": "permission-request", "tool": "Bash", "permission-mode": "auto"}}
}

test_a_permission_denied_is_granted if {
	"mode grant now" in preapprove with input as {"call": {"event": "permission-denied", "tool": "Bash"}}
}

test_a_hard_reset_is_left_to_the_host if {
	not "mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": "git reset --hard HEAD~1",
		"programs": [{"name": "git", "arguments": ["reset", "--hard", "HEAD~1"], "subcommand": "reset"}],
	}}
}

test_a_denied_forced_clean_is_not_retried if {
	not "mode grant now" in preapprove with input as {"call": {
		"event": "permission-denied", "tool": "Bash", "permission-mode": "auto",
		"programs": [{"name": "git", "arguments": ["clean", "-fdx"], "subcommand": "clean"}],
	}}
}

test_a_soft_reset_is_still_granted if {
	"mode grant now" in preapprove with input as {"call": {
		"event": "pre-tool", "tool": "Bash", "permission-mode": "default",
		"command": "git reset --soft HEAD~1",
		"programs": [{"name": "git", "arguments": ["reset", "--soft", "HEAD~1"], "subcommand": "reset"}],
	}}
}

test_a_post_tool_event_grants_nothing if {
	not "mode grant now" in preapprove with input as {"call": {"event": "post-tool", "tool": "Bash", "permission-mode": "auto"}}
}
