#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT plan-mode-unread|s@^\tinput.call\["permission-mode"\] == "plan"$@\tinput.call["permission-mode"] == "none"@|a_plan_mode_write_is_refused
#MUTANT plan-file-refused|s@^\tnot plan_file_write(input.call)$@\ttrue@|the_plan_file_is_writable_in_plan_mode
#MUTANT unwatch-refused-in-plan|s@^\tnot unwatch_method(input.call.tool)$@\ttrue@|an_unsubscribe_is_preapproved_in_every_mode
# In plan mode, a call either reads or is refused — never prompted (CLOUD-1949).
#
# The owner's ruling, verbatim: "either you're banned from making writes during
# plan mode (desired) or you're always allowed to make a call during plan mode
# (only desired for read only)". The host's plan mode is advisory to the model and
# a prompt to the operator; neither keeps a session honest. This refuses, so a
# write in plan mode ends at the gate with a verdict instead of at a human.
#
# THE CONSEQUENCE, STATED: a Bash call this preset cannot classify — an
# interpreter, a `mise run` — is refused in plan mode. That is the ruling's
# "banned", and a read that needs one is filed as a reader to add, not granted.
#
# Read-only is `read_only` from `read-only-is-preapproved.rego`, one definition
# for both halves, so the set refused here is exactly the complement of the set
# granted there.
package batten.claude_code_cloud

import rego.v1

rules contains "plan write refused"

violation contains {
	"rule": "plan write refused",
	"verdict": "plan write refused",
} if {
	input.call.event == "pre-tool"
	input.call["permission-mode"] == "plan"
	not read_only(input.call)
	not plan_tools(input.call.tool)
	not plan_file_write(input.call)

	# Dropping a PR subscription undoes one the harness made unasked, so it is
	# never refused here. One definition, `unwatch_method` in
	# `unwatch-is-preapproved.rego`, decides both this exemption and the grant.
	not unwatch_method(input.call.tool)
}

# The host's own plan-mode surface: leaving it, asking, and its task list, which
# is session state rather than the tree.
plan_tools(tool) if {
	tool in {"ExitPlanMode", "EnterPlanMode", "AskUserQuestion", "TodoWrite", "TaskCreate", "TaskUpdate"}
}

# The one file plan mode exists to write. Its path is the host's, never a
# repository's.
plan_file_write(call) if {
	call.tool in {"Write", "Edit"}
	regex.match(`/\.claude/plans/[^/]+\.md$`, call.arguments.file_path)
}

deny contains finding if some finding in violation

test_a_plan_mode_edit_is_refused if {
	some v in violation with input as {"call": {
		"event": "pre-tool", "permission-mode": "plan", "tool": "Edit",
		"arguments": {"file_path": "/repo/src/lib.rs"},
	}}
	v.rule == "plan write refused"
}

# A writer later in a list is still a writer: `git status` first does not make
# `git commit` second a read.
test_a_writer_after_a_reader_is_refused if {
	some v in violation with input as {"call": {
		"event": "pre-tool", "permission-mode": "plan", "tool": "Bash",
		"command": "git status && git commit -m x",
		"segments": [{"words": ["git", "status"], "terminator": "&&"}, {"words": ["git", "commit", "-m", "x"]}],
		"programs": [
			{"name": "git", "arguments": ["status"], "reads-only": false},
			{"name": "git", "arguments": ["commit", "-m", "x"], "reads-only": false},
		],
	}}
	v.rule == "plan write refused"
}

test_a_plan_mode_read_is_not if {
	count(violation) == 0 with input as {"call": {"event": "pre-tool", "permission-mode": "plan", "tool": "Read"}}
}

test_the_plan_file_is_not if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool", "permission-mode": "plan", "tool": "Write",
		"arguments": {"file_path": "/root/.claude/plans/a-plan.md"},
	}}
}

test_dropping_a_pr_subscription_is_not if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool", "permission-mode": "plan",
		"tool": "mcp__Claude_Code_Remote__unsubscribe_pr_activity",
	}}
}

test_leaving_plan_mode_is_not if {
	count(violation) == 0 with input as {"call": {"event": "pre-tool", "permission-mode": "plan", "tool": "ExitPlanMode"}}
}

test_outside_plan_mode_nothing_is if {
	count(violation) == 0 with input as {"call": {
		"event": "pre-tool", "permission-mode": "default", "tool": "Edit",
		"arguments": {"file_path": "/repo/src/lib.rs"},
	}}
}
