#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT redirect-unread|s@^\tnot some_output_redirect(call)$@\ttrue@|a_reader_redirected_into_a_file_is_not_preapproved
#MUTANT mcp-verb-unread|s@^\tmcp_read_verb(call.tool)$@\tstartswith(call.tool, "mcp__")@|an_mcp_write_is_not_preapproved
#MUTANT noun-first-list-unread|s@^mcp_read_verb(tool) if regex.match(`^mcp__github__@mcp_read_verb(tool) if regex.match(`^mcp__nothing__@|a_noun_first_mcp_read_is_preapproved
#MUTANT noun-first-read-unread|s@^mcp_read_verb(tool) if regex.match(`^mcp__(github__(issue@mcp_read_verb(tool) if regex.match(`^mcp__(nothing__(issue@|a_noun_first_mcp_read_is_preapproved
#MUTANT noun-first-read-any-method|s@`^mcp__(github__(issue\x7cpull_request)\x7cMiro__(board_preview\x7cprototype))_read\$`@`^mcp__(github\x7cMiro)__[a-z0-9_]+_read$`@|a_write_named_like_a_list_is_not_preapproved
#MUTANT noun-first-unscoped|s@`^mcp__github__\[a-z0-9_\]+_(list@`^mcp__[^_].*__[a-z0-9_]+_(list@|a_write_named_like_a_list_is_not_preapproved
#MUTANT noun-first-read-unscoped|s@`^mcp__(github__(issue\x7cpull_request)\x7cMiro__(board_preview\x7cprototype))_read\$`@`^mcp__[^_].*__[a-z0-9_]+_read$`@|a_write_named_like_a_list_is_not_preapproved
#MUTANT mcp-call-unread|s@^\tprogram.name == "batten"$@\tprogram.name == "none"@|a_plan_mode_batten_mcp_read_is_allowed_and_a_write_is_not
#MUTANT guide-not-read|s@"Explore", "Plan", "claude-code-guide"@"Explore", "Plan"@|a_plan_mode_guide_subagent_is_allowed
#MUTANT printenv-not-read|s@"tree", "printenv", "ps",@"tree", "ps",@|a_plan_mode_printenv_is_allowed
#MUTANT ps-not-read|s@"tree", "printenv", "ps",@"tree", "printenv",@|a_plan_mode_ps_is_allowed
#MUTANT git-read-form-writes|s@^\tnot some_writing_flag(verb.rest)$@\ttrue@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT git-pager-cluster-unread|s@^\tcontains(argument, "O")$@\tfalse@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT git-pager-abbreviation-unread|s@^\tsome prefix in {"--output", "--op", "--ext"}$@\tsome prefix in {"--output", "--ext"}@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT git-global-option-unread|s@^git_global_word(globals, j) if git_option_value(globals, j)$@git_global_word(globals, j) if false@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT git-program-global-unread|s@^\tnot some_unsafe_global(program\["global-options"\])$@\ttrue@|a_plan_mode_git_with_global_options_is_allowed
#MUTANT sort-output-unread|s@^\tnot sort_writes(program.arguments)$@\ttrue@|a_plan_mode_sort_read_is_allowed_and_its_writes_are_refused
#MUTANT find-action-unread|s@^\tnot find_acts(program.arguments)$@\ttrue@|a_plan_mode_find_read_is_allowed_and_its_actions_are_refused
#MUTANT awk-redirect-unread|s@^\tnot awk_writes(program.arguments)$@\ttrue@|a_plan_mode_awk_read_is_allowed_and_its_writes_are_refused
#MUTANT sed-script-unread|s@^\tsed_prints_only(sed_scripts(program.arguments))$@\ttrue@|a_plan_mode_sed_print_is_allowed_and_its_writes_are_refused
#MUTANT gh-api-method-unread|s@^\tnot gh_api_writes(program.arguments)$@\ttrue@|a_plan_mode_gh_read_is_allowed_and_its_writes_are_refused
#MUTANT gh-noun-open|s@^\tgh_builtin_noun(program.arguments\[0\])$@\ttrue@|a_plan_mode_gh_read_is_allowed_and_its_writes_are_refused
#MUTANT curl-flag-unread|s@^\tcurl_reads(program.arguments)$@\ttrue@|a_plan_mode_curl_get_is_allowed_and_its_writes_are_refused
#MUTANT git-fetch-refspec-unread|s@^\tnot writes_a_local_ref(rest)$@\ttrue@|a_plan_mode_git_network_read_is_allowed_and_its_writes_are_refused
#MUTANT git-fetch-refused|s@^\t"fetch",$@@|a_plan_mode_git_network_read_is_allowed_and_its_writes_are_refused
#MUTANT git-upload-pack-unread|s@^\tnot git_runs_program(verb.rest)$@\ttrue@|a_plan_mode_git_network_read_is_allowed_and_its_writes_are_refused
#MUTANT read-builtin-refused|s@^\t\t"read",$@@|a_plan_mode_read_loop_is_allowed_and_a_writing_loop_is_refused
#MUTANT skill-refused|s@^\t\t"Skill",$@@|a_plan_mode_skill_is_allowed_and_a_write_tool_is_not
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
		# Loading a skill writes nothing; what it then does is judged call by call
		# (CLOUD-2206).
		"Skill",
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
#
# `_read` NAMES ITS METHODS, because GitHub's own server ends a write in it
# (`mark_all_notifications_read`); `_list` and `_get` end none of its writes.
mcp_read_verb(tool) if regex.match(`^mcp__(github__(issue|pull_request)|Miro__(board_preview|prototype))_read$`, tool)

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
		# The shell builtin writes only a shell variable, so a `while read` loop
		# reads when every program in it does (CLOUD-2206).
		"read",
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
	verb := git_verb(program)
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

# `get-url` reads only the config.
git_reads_as("remote", rest) if rest[0] == "get-url"

# `remote show <name>` asks the remote, which runs its transport and any
# credential helper. So does `fetch`, which the owner admitted (2026-11-08), so
# the transport is no reason to refuse it (CLOUD-2206); a remote that hands git a
# program to run still is.
git_reads_as("remote", rest) if {
	rest[0] == "show"
	every word in array.slice(rest, 1, count(rest)) {
		remote_show_word(word)
	}
}

remote_show_word(word) if word == "-n"

remote_show_word(word) if {
	not startswith(word, "-")
	not contains(word, "::")
}

# THE NETWORK READS (CLOUD-2206): `fetch` writes only `refs/remotes/*` and
# `FETCH_HEAD`, and `ls-remote` writes nothing. Both run the remote's transport,
# so anything that hands git a program to run stays refused.
git_read_verb(verb) if {
	git_network_read(verb.name)
	not git_runs_program(verb.rest)
	git_network_form(verb.name, verb.rest)
}

git_network_read(name) if name in {
	"fetch",
	"ls-remote",
}

# `--upload-pack` in any spelling; a short cluster carrying `u` (`ls-remote -u`
# is `--upload-pack`, `fetch -u` lets fetch write the checked-out branch); and a
# `<transport>::<address>` remote, which runs `git-remote-<transport>`.
git_runs_program(rest) if {
	some word in rest
	startswith(word, "--upload-pack")
}

git_runs_program(rest) if {
	some word in rest
	startswith(word, "-")
	not startswith(word, "--")
	contains(word, "u")
}

git_runs_program(rest) if {
	some word in rest
	contains(word, "::")
}

# A fetch's flags come from a closed list, and a value flag only in its joined
# form, so no value can be read as the remote. A later positional is a refspec,
# and one with `:` writes a local branch.
git_network_form("fetch", rest) if {
	every word in rest {
		git_fetch_word(word)
	}
	not writes_a_local_ref(rest)
}

git_network_form("ls-remote", rest) if is_array(rest)

git_fetch_word(word) if not startswith(word, "-")

git_fetch_word(word) if word in {
	"--all", "--multiple", "-p", "--prune", "-P", "--prune-tags", "-t", "--tags", "-n",
	"--no-tags", "--dry-run", "-q", "--quiet", "-v", "--verbose", "--progress",
	"--no-recurse-submodules",
}

git_fetch_word(word) if {
	some prefix in {"--depth=", "--deepen=", "--shallow-since=", "--filter=", "--jobs="}
	startswith(word, prefix)
}

writes_a_local_ref(rest) if {
	positional := [word | some word in rest; not startswith(word, "-")]
	some refspec in array.slice(positional, 1, count(positional))
	contains(refspec, ":")
}

# The read flag comes FIRST: `git config` stops reading options at the key, so
# `git config user.name --get` sets user.name to `--get`.
git_reads_as("config", rest) if rest[0] in {"--get", "--get-all", "--get-regexp", "--list", "-l"}

git_reads_as("branch", rest) if {
	every argument in rest {
		argument in {"--show-current", "-a", "--all", "-r", "--remotes", "--list", "-l", "-v", "-vv", "--verbose"}
	}
}

# GIT'S GLOBAL OPTIONS COME BEFORE THE SUBCOMMAND, so the verb is the one the
# engine projects past them, never `arguments[0]` (CLOUD-2418), and never a
# copy of git's option table here (CLOUD-2354): `program.subcommand`, with the
# words before it in `program["global-options"]`.
#
# ONLY OPTIONS THAT CANNOT RUN A PROGRAM MAY PRECEDE A READ, by name.
# `-c core.pager=…`, `-c core.fsmonitor=…`, `--config-env` and `--exec-path`
# each hand git a program to run, so a call carrying one is never a read.
git_verb(program) := {
	"name": program.subcommand,
	"rest": array.slice(program.arguments, count(program["global-options"]) + 1, count(program.arguments)),
} if {
	not some_unsafe_global(program["global-options"])
}

some_unsafe_global(globals) if {
	some j, _ in globals
	not git_global_word(globals, j)
}

# Word `j` is a global option that runs nothing, or the value of `-C`.
git_global_word(globals, j) if globals[j] in {
	"-C", "--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs",
	"--no-replace-objects", "--bare",
}

git_global_word(globals, j) if {
	some prefix in {"--git-dir=", "--work-tree=", "--namespace="}
	startswith(globals[j], prefix)
}

git_global_word(globals, j) if git_option_value(globals, j)

# Word `i` is the separate value of `-C`.
git_option_value(globals, i) if {
	i > 0
	globals[i - 1] == "-C"
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

# FLAG-CHECKED READ FORMS (CLOUD-2206). Each program reads unless a flag makes it
# write or run a program: a denylist where the write grammar is closed, an
# allowlist where it is open. Anything outside a check stays "not proven
# read-only".
reads(program) if {
	program.name == "sort"
	not sort_writes(program.arguments)
}

# `-o` in any spelling, and `--compress-program`, which runs a program.
sort_writes(arguments) if {
	some argument in arguments
	some prefix in {"-o", "--output", "--compress-program"}
	startswith(argument, prefix)
}

sort_writes(arguments) if {
	some argument in arguments
	startswith(argument, "-")
	not startswith(argument, "--")
	contains(argument, "o")
}

reads(program) if {
	program.name == "find"
	not find_acts(program.arguments)
}

find_acts(arguments) if {
	some argument in arguments
	argument in {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
}

reads(program) if {
	program.name == "awk"
	not awk_writes(program.arguments)
}

# A program file, an extension, or a script that can redirect, pipe or run a
# command. `$1 > 5` is refused too, which fails closed.
awk_writes(arguments) if {
	some argument in arguments
	regex.match(`^(-[filE]|--(file|include|load|exec))`, argument)
}

awk_writes(arguments) if {
	some argument in arguments
	some marker in {">", "|", "system"}
	contains(argument, marker)
}

reads(program) if {
	program.name == "sed"
	sed_flags_only(program.arguments)
	sed_prints_only(sed_scripts(program.arguments))
}

sed_flags_only(arguments) if {
	every i, word in arguments {
		sed_word(arguments, i, word)
	}
}

sed_word(_, _, word) if not startswith(word, "-")

sed_word(_, _, word) if word in {"-n", "--quiet", "--silent", "-E", "-r", "-e"}

sed_word(arguments, i, _) if {
	i > 0
	arguments[i - 1] == "-e"
}

# Every `-e` value is a script; without one, the first positional is.
sed_scripts(arguments) := [arguments[i + 1] | some i, word in arguments; word == "-e"] if "-e" in arguments

sed_scripts(arguments) := [positional[0]] if {
	not "-e" in arguments
	positional := [word | some word in arguments; not startswith(word, "-")]
	count(positional) > 0
}

# A line address or range followed by `p` or `q`, or `/re/p`. `w`, `W`, `e` and
# `r` are outside the grammar.
sed_prints_only(scripts) if {
	count(scripts) > 0
	every script in scripts {
		regex.match(`^((\d+|\$)(,(\d+|\$))?[pq]|/[^/]*/p)$`, script)
	}
}

# gh's built-in nouns, closed: an alias may bind any other noun to a shell, and
# gh refuses an alias that shadows a built-in. gh takes no flag before the noun,
# so a leading flag fails closed.
reads(program) if {
	program.name == "gh"
	gh_builtin_noun(program.arguments[0])
	program.arguments[1] in {"view", "list", "status", "diff", "checks"}
}

gh_builtin_noun(noun) if noun in {
	"pr", "issue", "release", "repo", "run", "workflow", "gist", "label", "cache",
	"ruleset", "secret", "variable", "org",
}

reads(program) if {
	program.name == "gh"
	program.arguments[0] == "api"
	not gh_api_writes(program.arguments)
}

gh_api_writes(arguments) if {
	some argument in arguments
	argument in {"-f", "-F", "--field", "--raw-field", "--input", "graphql"}
}

gh_api_writes(arguments) if {
	some argument in arguments
	some prefix in {"--field=", "--raw-field=", "--input="}
	startswith(argument, prefix)
}

gh_api_writes(arguments) if {
	some i, argument in arguments
	argument in {"-X", "--method"}
	upper(arguments[i + 1]) != "GET"
}

gh_api_writes(arguments) if {
	some argument in arguments
	startswith(argument, "-X")
	argument != "-X"
	upper(substring(argument, 2, -1)) != "GET"
}

gh_api_writes(arguments) if {
	some argument in arguments
	startswith(argument, "--method=")
	upper(trim_prefix(argument, "--method=")) != "GET"
}

reads(program) if {
	program.name == "curl"
	curl_reads(program.arguments)
}

# Every flag is a GET's: output shaping, headers, timeouts. A body, a method, an
# upload, an output file or a config file is outside the list.
curl_reads(arguments) if {
	every word in arguments {
		curl_word(word)
	}
}

curl_word(word) if not startswith(word, "-")

curl_word(word) if regex.match(`^-[sSfLiIvk]+$`, word)

curl_word(word) if word in {
	"--silent", "--show-error", "--fail", "--fail-with-body", "--location", "--head",
	"--include", "--compressed", "--verbose", "--insecure", "-H", "--header", "-A",
	"--user-agent", "-m", "--max-time", "--connect-timeout", "--retry",
}

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
