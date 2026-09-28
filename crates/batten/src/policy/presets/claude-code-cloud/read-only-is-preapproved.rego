#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT redirect-unread|s@^\tnot some_output_redirect(call)$@\ttrue@|a_reader_redirected_into_a_file_is_not_preapproved
#MUTANT mcp-verb-unread|s@^\tmcp_read_verb(call.tool)$@\tstartswith(call.tool, "mcp__")@|an_mcp_write_is_not_preapproved
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

preapprove contains "call read now" if {
	input.call.event == "pre-tool"
	read_only(input.call)
}

# The host's own read tools. Named, because a host tool's effect is the host's
# declaration and there is no argv to read.
read_tools(tool) if {
	tool in {
		"Read", "Grep", "Glob", "LS", "NotebookRead", "ToolSearch", "TaskGet", "TaskList",
		"TaskOutput", "WebSearch", "WebFetch", "ListMcpResourcesTool", "ReadMcpResourceTool",
	}
}

# An MCP method whose verb only reads, by the naming every server this host
# reaches follows: `get_`/`list_`/`search_`/`read_`/`query_`/`fetch_`/`find_`,
# or a trailing `_read`.
mcp_read_verb(tool) if regex.match(`^mcp__[^_].*__((get|list|search|read|query|fetch|find)(_[a-z0-9_]+)?|[a-z0-9_]+_read)$`, tool)

# Programs that leave their operands alone and that the engine's floor does not
# list. Each is admissible for the floor's own reason: its bound is stated. NOT
# here, and deliberately: `sort` (`-o`), `uniq` (an output operand), `sed`
# (`-i`), `awk` (`system`), `find` (`-delete`, `-exec`), `xargs`, and every
# interpreter.
read_programs(name) if {
	name in {
		"cd", "pwd", "true", "false", "test", "[", "which", "type", "date", "jq", "cut",
		"tr", "nl", "tac", "sha256sum", "md5sum", "du", "df", "uname", "id", "whoami",
		"hostname", "tree",
	}
}

# Git subcommands that report and write nothing a reader depends on.
git_reads(verb) if {
	verb in {
		"status", "log", "diff", "show", "rev-parse", "ls-files", "ls-tree", "blame",
		"describe", "cat-file", "merge-base", "rev-list", "shortlog", "grep", "count-objects",
	}
}

# FUNCTIONS, NEVER RULES — not even constant ones — and this was measured rather
# than preferred. A module-level `name := {…}` read as undefined on the hook
# path while every `test_` here passed, so `Read` was never read-only live. The engine evaluates the whole package on every mediated call,
# `test_` rules included, and a helper RULE's value computed under one test's
# `with input as` answered the live call too: `Read` came back not read-only
# while the same document, handed to a test, was. A function has no value to
# keep between two inputs, because the input is its argument.
read_only(call) if {
	read_tools(call.tool)
}

read_only(call) if {
	mcp_read_verb(call.tool)
}

# A subagent the host itself declares read-only.
read_only(call) if {
	call.tool in {"Agent", "Task"}
	call.arguments.subagent_type in {"Explore", "Plan"}
}

read_only(call) if {
	call.tool == "Bash"
	count(call.programs) > 0
	every program in call.programs {
		reads(program)
	}
	not some_output_redirect(call)
}

# GUARDED: `segments` is `null` on a non-shell call, and iterating null faults
# the whole query, which reads as could-not-look for every module here.
some_output_redirect(call) if {
	is_array(call.segments)
	some segment in call.segments
	segment["output-redirect"]
}

# A command the boundary could not segment is not proven anything.
some_output_redirect(call) if {
	not is_array(call.segments)
}

reads(program) if program["reads-only"]

reads(program) if read_programs(program.name)

reads(program) if program["batten-effect"] == "read"

reads(program) if {
	program.name == "git"
	git_reads(program.arguments[0])
	not some_writing_flag(program.arguments)
}

# `--output` writes a file; `-O` hands matches to a pager program.
some_writing_flag(arguments) if {
	some argument in arguments
	startswith(argument, "--output")
}

some_writing_flag(arguments) if {
	some argument in arguments
	argument in {"-O", "--open-files-in-pager", "--ext-diff"}
}

test_a_host_read_is_preapproved if {
	"call read now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "Read"}}
}

test_an_mcp_read_verb_is_preapproved if {
	"call read now" in preapprove with input as {"call": {"event": "pre-tool", "tool": "mcp__Linear__list_issues"}}
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
			{"name": "git", "arguments": ["status"], "reads-only": false},
			{"name": "head", "arguments": [], "reads-only": true},
		],
	}}
}

test_a_redirected_reader_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "echo x > f",
		"segments": [{"words": ["echo", "x", ">", "f"], "output-redirect": true}],
		"programs": [{"name": "echo", "arguments": ["x", ">", "f"], "reads-only": true}],
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

test_a_git_writer_is_not if {
	count(preapprove) == 0 with input as {"call": {
		"event": "pre-tool",
		"tool": "Bash",
		"command": "git commit -m x",
		"segments": [{"words": ["git", "commit", "-m", "x"]}],
		"programs": [{"name": "git", "arguments": ["commit", "-m", "x"], "reads-only": false}],
	}}
}
