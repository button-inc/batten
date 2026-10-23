#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT redirect-unread|s@^\tnot some_output_redirect(call)$@\ttrue@|a_reader_redirected_into_a_file_is_not_preapproved
#MUTANT mcp-verb-unread|s@^\tmcp_read_verb(call.tool)$@\tstartswith(call.tool, "mcp__")@|an_mcp_write_is_not_preapproved
#MUTANT noun-first-list-unread|s@^mcp_read_verb(tool) if regex.match(`^mcp__github__@mcp_read_verb(tool) if regex.match(`^mcp__nothing__@|a_noun_first_mcp_read_is_preapproved
#MUTANT noun-first-read-unread|s@^mcp_read_verb(tool) if regex.match(`^mcp__(github\x7cMiro)__@mcp_read_verb(tool) if regex.match(`^mcp__nothing__@|a_noun_first_mcp_read_is_preapproved
#MUTANT noun-first-unscoped|s@`^mcp__github__\[a-z0-9_\]+_(list@`^mcp__[^_].*__[a-z0-9_]+_(list@|a_write_named_like_a_list_is_not_preapproved
#MUTANT noun-first-read-unscoped|s@`^mcp__(github\x7cMiro)__\[a-z0-9_\]+_read\$`@`^mcp__[^_].*__[a-z0-9_]+_read$`@|a_write_named_like_a_list_is_not_preapproved
#MUTANT mcp-call-unread|s@^\tprogram.name == "batten"$@\tprogram.name == "none"@|a_plan_mode_batten_mcp_read_is_allowed_and_a_write_is_not
#MUTANT guide-not-read|s@"Explore", "Plan", "claude-code-guide"@"Explore", "Plan"@|a_plan_mode_guide_subagent_is_allowed
#MUTANT printenv-not-read|s@"tree", "printenv", "ps",@"tree", "ps",@|a_plan_mode_printenv_is_allowed
#MUTANT ps-not-read|s@"tree", "printenv", "ps",@"tree", "printenv",@|a_plan_mode_ps_is_allowed
#MUTANT git-read-form-writes|s@^\tnot some_writing_flag(verb.rest)$@\ttrue@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT git-pager-cluster-unread|s@^\tcontains(argument, "O")$@\tfalse@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT git-pager-abbreviation-unread|s@^\tsome prefix in {"--output", "--op", "--ext"}$@\tsome prefix in {"--output", "--ext"}@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT git-global-option-unread|s@^\tnot git_option_value(arguments, i)$@\ti == 0@|a_plan_mode_git_with_global_options_is_allowed
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
		# The session's own notification queue (CLOUD-2289). Marking an entry
		# delivered is session state, never the tree.
		"ReadNotifications",
	}
}

# An MCP method whose verb only reads: verb-first `get_`/`list_`/`search_`/
# `read_`/`query_`/`fetch_`/`find_`.
mcp_read_verb(tool) if regex.match(`^mcp__[^_].*__(get|list|search|read|query|fetch|find)(_[a-z0-9_]+)?$`, tool)

# Or noun-first, on the servers measured to name their pure reads that way
# (CLOUD-2519): a trailing `_read` on GitHub (`issue_read`,
# `pull_request_read`) and Miro (`board_preview_read`, `prototype_read`), and a
# trailing `_list` or `_get` on GitHub (`actions_list`, `actions_get`), which
# plan mode refused.
#
# SCOPED TO THE SERVERS MEASURED, NEVER GENERAL. A suffix alone admits a write
# named like a read (`mark_read`, `clear_list`), and no verb list can name every
# such write, so a noun-first read fails closed on every other server.
mcp_read_verb(tool) if regex.match(`^mcp__(github|Miro)__[a-z0-9_]+_read$`, tool)

mcp_read_verb(tool) if regex.match(`^mcp__github__[a-z0-9_]+_(list|get)$`, tool)

# Programs that leave their operands alone and that the engine's floor does not
# list. Each is admissible for the floor's own reason: its bound is stated. NOT
# here, and deliberately: `sort` (`-o`), `uniq` (an output operand), `sed`
# (`-i`), `awk` (`system`), `find` (`-delete`, `-exec`), `xargs`, and every
# interpreter. `printenv` prints variables and takes no operand it could write
# to; `ps` reads `/proc` and has no output-file flag (CLOUD-2367). A wrapped
# form — `env printenv`, `timeout 5 ps` — reaches here as the wrapped program,
# because the boundary looks through those wrappers, so it is a read exactly when
# the program it runs is one. Bare `env` projects no program and stays unproven.
read_programs(name) if {
	name in {
		"cd", "pwd", "true", "false", "test", "[", "which", "type", "date", "jq", "cut",
		"tr", "nl", "tac", "sha256sum", "md5sum", "du", "df", "uname", "id", "whoami",
		"hostname", "tree", "printenv", "ps", "echo", "printf",
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

# A subagent the host itself declares read-only. The bound is the host's own
# tool list for each: `Explore` and `Plan` carry every tool but the writers, and
# `claude-code-guide` carries Glob, Grep, Read, WebFetch and WebSearch
# (CLOUD-2367). A host that gives one of them a writer moves it out of this set.
read_only(call) if {
	call.tool in {"Agent", "Task"}
	call.arguments.subagent_type in {"Explore", "Plan", "claude-code-guide"}
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

# `batten mcp call <server> <method>` is the Bash form of `mcp__<server>__<method>`,
# and reads exactly when the tool form does (CLOUD-2289). The verb's declared
# effect stays unclassified: it writes batten's capture store and spends a
# credential (`surface.rs`, CLOUD-1260). Neither changes anything outside
# batten's own state, and every mediated `mcp__*` read makes the same capture
# write. One regex decides both forms, so they cannot drift.
reads(program) if {
	program.name == "batten"
	array.slice(program.arguments, 0, 2) == ["mcp", "call"]
	mcp_read_verb(sprintf("mcp__%s__%s", [program.arguments[2], program.arguments[3]]))
}

# ONE WRITING-FLAG CHECK FOR EVERY GIT READ (CLOUD-2418): a read form's
# arguments reach git's diff and log parsers too, and `--output` makes git open
# the file itself, which no shell redirect check sees.
reads(program) if {
	program.name == "git"
	verb := git_verb(program.arguments)
	git_read_verb(verb)
	not some_writing_flag(verb.rest)
}

git_read_verb(verb) if git_reads(verb.name)

# Subcommands that read only in some forms: the form is the first argument after
# the subcommand, or, for `branch`, the absence of anything but listing flags.
git_read_verb(verb) if git_reads_as(verb.name, verb.rest)

git_reads_as("stash", rest) if rest[0] in {"list", "show"}

# `-v` alone lists; `git remote -v add …` is still `add`, so `-v` reads only
# as the whole argument list.
git_reads_as("remote", rest) if rest in {[], ["-v"], ["--verbose"]}

# `remote show <name>` asks the remote, which runs its transport and any
# credential helper; `get-url` reads only the config.
git_reads_as("remote", rest) if rest[0] == "get-url"

# The read flag comes FIRST: `git config` stops reading options at the key, so
# `git config user.name --get` sets user.name to `--get`.
git_reads_as("config", rest) if rest[0] in {"--get", "--get-all", "--get-regexp", "--list", "-l"}

git_reads_as("branch", rest) if {
	every argument in rest {
		argument in {"--show-current", "-a", "--all", "-r", "--remotes", "--list", "-l", "-v", "-vv", "--verbose"}
	}
}

# GIT'S GLOBAL OPTIONS COME BEFORE THE SUBCOMMAND, so the subcommand is the first
# word after them, never `arguments[0]` (CLOUD-2418): `git -C /x status` read
# `-C` as its verb and was refused in plan mode.
#
# ONLY OPTIONS THAT CANNOT RUN A PROGRAM ARE SKIPPED, by name. `-c core.pager=…`,
# `-c core.fsmonitor=…`, `--config-env` and `--exec-path` each hand git a program
# to run, so a call carrying one is never a read: its option is not skipped, and
# the word after it is no read verb.
git_verb(arguments) := {"name": word, "rest": array.slice(arguments, i + 1, count(arguments))} if {
	some i, word in arguments
	not startswith(word, "-")
	not git_option_value(arguments, i)
	not some_word_before_is_not_global(arguments, i)
}

some_word_before_is_not_global(arguments, i) if {
	some j, _ in arguments
	j < i
	not git_global_word(arguments, j)
}

# Word `j` is a global option that runs nothing, or the value of `-C`.
git_global_word(arguments, j) if arguments[j] in {
	"-C", "--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs",
	"--no-replace-objects", "--bare",
}

git_global_word(arguments, j) if {
	some prefix in {"--git-dir=", "--work-tree=", "--namespace="}
	startswith(arguments[j], prefix)
}

git_global_word(arguments, j) if git_option_value(arguments, j)

# Word `i` is the separate value of `-C`.
git_option_value(arguments, i) if {
	i > 0
	arguments[i - 1] == "-C"
}

# `--output` writes a file; `-O` hands matches to a pager program and
# `--ext-diff` runs the configured diff program. Every spelling git's option
# parser accepts is the flag: `git grep` takes any unambiguous prefix of
# `--open-files-in-pager` (`--op`, `--open=`), and a short cluster carries `-O`
# anywhere in it (`-iO<pager>` is `-i -O<pager>`).
some_writing_flag(arguments) if {
	some argument in arguments
	some prefix in {"--output", "--op", "--ext"}
	startswith(argument, prefix)
}

some_writing_flag(arguments) if {
	some argument in arguments
	startswith(argument, "-")
	not startswith(argument, "--")
	contains(argument, "O")
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

git_call(arguments) := {"call": {
	"event": "pre-tool",
	"tool": "Bash",
	"command": concat(" ", array.concat(["git"], arguments)),
	"segments": [{"words": array.concat(["git"], arguments)}],
	"programs": [{"name": "git", "arguments": arguments, "reads-only": false}],
}}

test_git_global_options_come_before_the_verb if {
	every arguments in [
		["-C", "/x", "status", "--short"],
		["--git-dir=/x/.git", "log", "-1"],
		["--no-pager", "-C", "/x", "diff"],
		["stash", "list"],
		["branch", "--show-current"],
		["branch"],
		["remote", "-v"],
		["config", "--get", "user.name"],
	] {
		"call read now" in preapprove with input as git_call(arguments)
	}
}

test_git_global_options_never_hide_a_writer if {
	every arguments in [
		["-C", "/x", "commit", "-m", "x"],
		["-C", "status", "commit"],
		["-c", "core.pager=sh -c x", "log"],
		["-c", "core.fsmonitor=x", "status"],
		["--exec-path=/x", "status"],
		["--config-env=core.pager=X", "log"],
		["stash"],
		["stash", "pop"],
		["branch", "new-branch"],
		["branch", "-D", "old"],
		["remote", "add", "o", "u"],
		["remote", "-v", "add", "o", "u"],
		["stash", "show", "-p", "--output=x"],
		["stash", "list", "--output=x"],
		["config", "user.name", "x"],
		["config", "alias.zz", "--list"],
		["grep", "-Osh", "x"],
		["grep", "--open-files-in-pager=./x", "y"],
		["grep", "-iOsh", "x"],
		["grep", "--open=sh", "x"],
		["-C", "/x", "grep", "--op=sh", "x"],
		["diff", "--ext"],
		["remote", "show", "origin"],
	] {
		count(preapprove) == 0 with input as git_call(arguments)
	}
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
