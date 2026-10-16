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
	# THE PROGRAM THAT WAS NOT A READ, never its arguments (CLOUD-2292): the
	# boundary counts refusals by this pointer, so a read this preset does not
	# yet classify shows up as a program refused again and again.
	"subjects": [{"artifact": refused_subject(input.call)}],
	# Counted by `batten doctor gaps`: the rule asks, so the engine names no class.
	"counted": true,
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

# What a plan-mode refusal names: the first program of a shell call that is not a
# read, or the tool itself for any other call. A function, for the reason
# `read-only-is-preapproved.rego` records: a helper rule keeps a value between
# inputs, and a function has none to keep.
#
# One clause, so the list is built once and a call with no `programs` still
# names its tool rather than leaving the refusal with no subject at all.
refused_subject(call) := array.concat(not_reads(object.get(call, "programs", [])), [call.tool])[0]

# The names of the programs that do not read, in order.
not_reads(programs) := [programs[i].name | programs[i]; not reads(programs[i])]

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

test_the_refusal_names_the_program_that_did_not_read if {
	some v in violation with input as {"call": {
		"event": "pre-tool", "permission-mode": "plan", "tool": "Bash",
		"command": "git status && python3 x.py --secret",
		"segments": [{"words": ["git", "status"], "terminator": "&&"}, {"words": ["python3", "x.py", "--secret"]}],
		"programs": [
			{"name": "git", "arguments": ["status"], "reads-only": false},
			{"name": "python3", "arguments": ["x.py", "--secret"], "reads-only": false},
		],
	}}
	v.subjects == [{"artifact": "python3"}]
}

test_a_refused_tool_names_itself if {
	some v in violation with input as {"call": {
		"event": "pre-tool", "permission-mode": "plan", "tool": "Edit",
		"arguments": {"file_path": "/repo/src/lib.rs"},
	}}
	v.subjects == [{"artifact": "Edit"}]
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
