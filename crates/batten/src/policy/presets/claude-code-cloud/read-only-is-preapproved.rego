#MUTANT-SUITE crates/batten/tests/it/permission_events.rs
#MUTANT plan-mode-reads-refused|s@^read_event(event) if event in {"pre-tool", "permission-request", "permission-denied"}$@read_event(event) if event == "pre-tool"@|a_read_prompt_in_plan_mode_is_granted
# A call that only reads is never put to the operator (CLOUD-1949).
#
# The host halts on a permission prompt, and a halted session is the failure the
# owner ruled out: "allowed calls must be allowed 100% of the time". A read
# cannot change what any gate decides next, so asking about one buys nothing and
# costs the turn. This module says which calls are reads; the engine asks it only
# after every deny in the tree has had its say, so a read some other rule refuses
# stays refused (`compose` in `lib.rs`, deny first).
#
# EVERY FACT HERE IS ONE THE ENGINE ALREADY OWNS. `reads-only` is the boundary's
# `READ_ONLY_PROGRAMS` floor, `batten-effect` is the surface's declared effect,
# and `output-redirect` is the redirect reading the protected-write gate uses. The
# lists below add only what is true of a PROGRAM everywhere — a preset ships to
# every consumer, so it may name no repository (non-negotiable rule 1), and a
# `[[pattern]]` row would be dead in a consumer that declared none, so the one
# regex is inline (`rules/policy-modules.md`).
#
# The ERROR DIRECTION is "not proven read-only": anything this cannot classify is
# left to the host, which prompts — never granted.
package batten.claude_code_cloud

import rego.v1

rules contains "call read now"

# THE TWO PERMISSION EVENTS AS WELL AS PRE-TOOL (CLOUD-2768): a read the host
# is about to put to the person, or that its classifier denied, is the same
# read, in every mode, plan's included, where it is the one grant the owner's
# ruling leaves (plan mode is read-only).
read_event(event) if event in {"pre-tool", "permission-request", "permission-denied"}

preapprove contains "call read now" if {
	read_event(input.call.event)
	read_only(input.call)
}

# THE PREDICATE IS THE LIBRARY'S (CLOUD-2840): one definition every bundle
# carries, so the install gate admits exactly what this preset grants.
read_only(call) if data.batten.library.read_only(call)

some_output_redirect(call) if data.batten.library.some_output_redirect(call)

reads(program) if data.batten.library.reads(program)

# One read/write pair per program, so `batten policy test` covers each form
# without the binary.
program_call(name, arguments) := {"call": {
	"event": "pre-tool",
	"tool": "Bash",
	"command": concat(" ", array.concat([name], arguments)),
	"segments": [{"words": array.concat([name], arguments)}],
	"programs": [{"name": name, "arguments": arguments, "reads-only": false}],
}}

test_flag_checked_reads_are_preapproved if {
	every case in [
		["sort", ["f"]],
		["find", [".", "-name", "x", "-print"]],
		["awk", ["1", "f"]],
		["sed", ["-n", "1,20p", "f"]],
		["gh", ["pr", "view", "1"]],
		["gh", ["api", "repos/a/b"]],
		["curl", ["-sS", "https://example.com"]],
		["read", ["f"]],
	] {
		"call read now" in preapprove with input as program_call(case[0], case[1])
	}
}

test_flag_checked_writes_are_not if {
	every case in [
		["sort", ["-o", "g", "f"]],
		["sort", ["--compress-program=sh", "f"]],
		["find", [".", "-delete"]],
		["awk", ["{print > \"g\"}", "f"]],
		["sed", ["-i", "s/x/y/", "f"]],
		["sed", ["-n", "1w out", "f"]],
		["gh", ["pr", "merge", "1"]],
		["gh", ["co", "list"]],
		["gh", ["api", "-X", "POST", "repos/a/b"]],
		["gh", ["api", "-XPOST", "repos/a/b"]],
		["gh", ["api", "repos/a/b", "-f", "x=y"]],
		["curl", ["-d", "x", "https://example.com"]],
		["curl", ["-o", "out", "https://example.com"]],
	] {
		count(preapprove) == 0 with input as program_call(case[0], case[1])
	}
}

test_git_network_reads_are_preapproved if {
	every case in [
		[[], "fetch", []],
		[[], "fetch", ["origin", "main"]],
		[[], "ls-remote", ["origin"]],
		[[], "remote", ["show", "origin"]],
	] {
		"call read now" in preapprove with input as git_call(case)
	}
}

test_git_network_writes_are_not if {
	every case in [
		[[], "fetch", ["origin", "main:main"]],
		[[], "fetch", ["-u", "origin"]],
		[[], "fetch", ["ext::sh -c x"]],
		[[], "ls-remote", ["-u", "sh", "origin"]],
		[[], "ls-remote", ["--upload-pack=sh", "origin"]],
		[[], "pull", []],
	] {
		count(preapprove) == 0 with input as git_call(case)
	}
}

test_a_skill_is_preapproved if {
	"call read now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "Skill"}}
}

test_a_host_read_is_preapproved if {
	"call read now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "Read"}}
}

test_an_mcp_read_verb_is_preapproved if {
	"call read now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "mcp__Linear__list_issues"}}
}

test_a_noun_first_mcp_list_is_preapproved if {
	"call read now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "mcp__github__actions_list"}}
}

test_an_mcp_write_is_not if {
	count(preapprove) == 0 with input as {"call": {"event": "pre-tool", "tool": "mcp__Linear__save_comment"}}
}

test_a_read_pipeline_is_preapproved if {
	"call read now" in preapprove with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "cd /x && git status | head",
		"segments": [{"words": ["cd", "/x"]}, {"words": ["git", "status"]}, {"words": ["head"]}],
		"programs": [
			{"name": "cd", "arguments": ["/x"], "reads-only": false},
			{"name": "git", "arguments": ["status"], "subcommand": "status", "global-options": [], "reads-only": false},
			{"name": "head", "arguments": [], "reads-only": true},
		],
	}}
}

test_a_redirected_reader_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "echo x > f",
		"segments": [{"words": ["echo", "x", ">", "f"], "redirects": [">", "f"], "output-redirect": true}],
		"programs": [{"name": "echo", "arguments": ["x"], "reads-only": true}],
	}}
}

test_one_writer_in_the_line_spoils_it if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "ls && rm x",
		"segments": [{"words": ["ls"]}, {"words": ["rm", "x"]}],
		"programs": [
			{"name": "ls", "arguments": [], "reads-only": true},
			{"name": "rm", "arguments": ["x"], "reads-only": false},
		],
	}}
}

test_a_batten_mcp_read_is_preapproved if {
	"call read now" in preapprove with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "batten mcp call Linear get_issue '{}'",
		"segments": [{"words": ["batten", "mcp", "call", "Linear", "get_issue", "{}"]}],
		"programs": [{"name": "batten", "arguments": ["mcp", "call", "Linear", "get_issue", "{}"], "reads-only": false}],
	}}
}

test_a_batten_mcp_write_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "batten mcp call Linear save_issue '{}'",
		"segments": [{"words": ["batten", "mcp", "call", "Linear", "save_issue", "{}"]}],
		"programs": [{"name": "batten", "arguments": ["mcp", "call", "Linear", "save_issue", "{}"], "reads-only": false}],
	}}
}

test_the_guide_subagent_is_a_read if {
	"call read now" in preapprove with input as {"call": {
		"event": "pre-tool",
		"tool": "Agent",
		"arguments": {"subagent_type": "claude-code-guide", "prompt": "x"},
	}}
}

test_an_implementer_subagent_is_not_a_read if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Agent",
		"arguments": {"subagent_type": "general-purpose", "prompt": "x"},
	}}
}

test_printenv_and_ps_are_reads if {
	every name in ["printenv", "ps"] {
		"call read now" in preapprove with input as {"call": {
			"event": "pre-tool",
			"tool": "Bash",
			"command": name,
			"segments": [{"words": [name]}],
			"programs": [{"name": name, "arguments": [], "reads-only": false}],
		}}
	}
}

# The projected keys are written by hand, never computed: computing them here
# would be a copy of the engine's parser (CLOUD-2354). One case is
# `[global-options, subcommand, rest]`.
git_call(case) := {"call": {
	"event": "pre-tool",
	"tool": "Bash",
	"command": concat(" ", array.concat(["git"], arguments)),
	"segments": [{"words": array.concat(["git"], arguments)}],
	"programs": [{
		"name": "git", "arguments": arguments, "reads-only": false,
		"subcommand": case[1], "global-options": case[0],
	}],
}} if {
	arguments := array.concat(array.concat(case[0], [case[1]]), case[2])
}

test_git_global_options_come_before_the_verb if {
	every case in [
		[["-C", "/x"], "status", ["--short"]],
		[["--git-dir=/x/.git"], "log", ["-1"]],
		[["--no-pager", "-C", "/x"], "diff", []],
		[[], "stash", ["list"]],
		[[], "branch", ["--show-current"]],
		[[], "branch", []],
		[[], "remote", ["-v"]],
		[[], "config", ["--get", "user.name"]],
	] {
		"call read now" in preapprove with input as git_call(case)
	}
}

test_git_global_options_never_hide_a_writer if {
	every case in [
		[["-C", "/x"], "commit", ["-m", "x"]],
		[["-C", "status"], "commit", []],
		[["-c", "core.pager=sh -c x"], "log", []],
		[["-c", "core.fsmonitor=x"], "status", []],
		[["--exec-path=/x"], "status", []],
		[["--config-env=core.pager=X"], "log", []],
		[[], "stash", []],
		[[], "stash", ["pop"]],
		[[], "branch", ["new-branch"]],
		[[], "branch", ["-D", "old"]],
		[[], "remote", ["add", "o", "u"]],
		[[], "remote", ["-v", "add", "o", "u"]],
		[[], "stash", ["show", "-p", "--output=x"]],
		[[], "stash", ["list", "--output=x"]],
		[[], "config", ["user.name", "x"]],
		[[], "config", ["alias.zz", "--list"]],
		[[], "grep", ["-Osh", "x"]],
		[[], "grep", ["--open-files-in-pager=./x", "y"]],
		[[], "grep", ["-iOsh", "x"]],
		[[], "grep", ["--open=sh", "x"]],
		[["-C", "/x"], "grep", ["--op=sh", "x"]],
		[[], "diff", ["--ext"]],
	] {
		count(preapprove) == 0 with input as git_call(case)
	}
}

test_a_git_writer_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "git commit -m x",
		"segments": [{"words": ["git", "commit", "-m", "x"]}],
		"programs": [{"name": "git", "arguments": ["commit", "-m", "x"], "subcommand": "commit", "global-options": [], "reads-only": false}],
	}}
}
