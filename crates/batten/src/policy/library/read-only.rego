#MUTANT-SUITE crates/batten/tests/it/preapprove.rs
#MUTANT redirect-unread|s@^\tnot some_output_redirect(call)$@\ttrue@|a_reader_redirected_into_a_file_is_not_preapproved
#MUTANT mcp-verb-unread|s@^\tmcp_read_verb(call.tool)$@\tstartswith(call.tool, "mcp__")@|an_mcp_write_is_not_preapproved
#MUTANT noun-first-list-unread|s@^mcp_read_verb(tool) if regex.match(`^mcp__github__@mcp_read_verb(tool) if regex.match(`^mcp__nothing__@|a_noun_first_mcp_read_is_preapproved
#MUTANT noun-first-read-unread|s@^mcp_read_verb(tool) if regex.match(`^mcp__(github__(issue@mcp_read_verb(tool) if regex.match(`^mcp__(nothing__(issue@|a_noun_first_mcp_read_is_preapproved
#MUTANT noun-first-read-any-method|s@`^mcp__(github__(issue\x7cpull_request)\x7cMiro__(board_preview\x7cprototype))_read\$`@`^mcp__(github\x7cMiro)__[a-z0-9_]+_read$`@|a_write_named_like_a_list_is_not_preapproved
#MUTANT noun-first-unscoped|s@`^mcp__github__\[a-z0-9_\]+_(list@`^mcp__[^_].*__[a-z0-9_]+_(list@|a_write_named_like_a_list_is_not_preapproved
#MUTANT noun-first-read-unscoped|s@`^mcp__(github__(issue\x7cpull_request)\x7cMiro__(board_preview\x7cprototype))_read\$`@`^mcp__[^_].*__[a-z0-9_]+_read$`@|a_write_named_like_a_list_is_not_preapproved
#MUTANT mcp-call-unread|s@^\tprogram.name == "batten"$@\tprogram.name == "none"@|a_plan_mode_batten_mcp_read_beside_another_read_is_allowed
#MUTANT guide-not-read|s@"Explore", "Plan", "claude-code-guide"@"Explore", "Plan"@|a_plan_mode_guide_subagent_is_allowed
#MUTANT printenv-not-read|s@\t\t"printenv", "ps",@\t\t"ps",@|a_plan_mode_printenv_is_allowed
#MUTANT ps-not-read|s@\t\t"printenv", "ps",@\t\t"printenv",@|a_plan_mode_ps_is_allowed
#MUTANT date-set-unread|s@^\tnot date_sets(program.arguments)$@\ttrue@|a_setting_date_hostname_or_tree_output_is_refused
#MUTANT date-operand-unread|s@^\tnot date_value(arguments, i)$@\tfalse@|a_setting_date_hostname_or_tree_output_is_refused
#MUTANT hostname-operand-unread|s@^\t\thostname_query(argument)$@\t\ttrue@|a_setting_date_hostname_or_tree_output_is_refused
#MUTANT tree-output-unread|s@^\tnot tree_writes(program.arguments)$@\ttrue@|a_setting_date_hostname_or_tree_output_is_refused
#MUTANT awk-option-narrowed|s@\[filEWdopD\]@[filE]@|an_awk_option_that_writes_or_runs_is_refused
#MUTANT gh-api-joined-field-unread|s@^\tgh_api_joined_field(argument)$@\tfalse@|a_joined_gh_api_field_is_a_write
#MUTANT long-option-exact|s@^\tstartswith(option, name)$@\toption == name@|an_abbreviated_or_clustered_writing_option_is_refused
#MUTANT date-set-prefix-unread|s@^\tnames_long_option(argument, {"set"})$@\tfalse@|an_abbreviated_or_clustered_writing_option_is_refused
#MUTANT awk-long-option-unread|s@^\tnames_long_option(argument, {"file".*$@\tfalse@|an_abbreviated_or_clustered_writing_option_is_refused
#MUTANT sort-long-option-unread|s@^\tnames_long_option(argument, {"output".*$@\tfalse@|an_abbreviated_or_clustered_writing_option_is_refused
#MUTANT gh-method-cluster-unread|s@^\tgh_method_flag(argument)$@\targument == "-X"@|an_abbreviated_or_clustered_writing_option_is_refused
#MUTANT curl-value-eats-flag-unread|s@^\tnot curl_value_eats_a_flag(arguments)$@\ttrue@|a_curl_flag_consumed_as_a_value_is_not_also_a_flag
#MUTANT git-assignment-unread|s@^\tnot some_live_assignment(call)$@\ttrue@|a_git_variable_assigned_before_the_program_is_not_a_read
#MUTANT curl-scheme-unread|s@^curl_allowed(_, _, word) if regex.match.*$@curl_allowed(_, _, word) if not startswith(word, "-")@|a_curl_read_is_http_only
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
#MUTANT-SUITE crates/batten/tests/it/reach_review.rs
#MUTANT inert-name-widened|s@^\tinert_name(assignment_name(assignment))$@\ttrue@|only_an_inert_assignment_or_a_bare_program_name_is_a_read
#MUTANT pager-value-unread|s@^\tassignment_value(assignment) == "cat"$@\ttrue@|only_an_inert_assignment_or_a_bare_program_name_is_a_read
#MUTANT program-path-unread|s@^\t\tnot spelled_with_a_path(program)$@\t\ttrue@|only_an_inert_assignment_or_a_bare_program_name_is_a_read
#MUTANT awk-directive-unread|s%^\tsome directive in {"@include", "@load"}$%\tsome directive in {"@nothing"}%|an_awk_directive_or_long_debug_is_a_write
#MUTANT awk-debug-unread|s@"pretty-print", "profile", "debug"@"pretty-print", "profile"@|an_awk_directive_or_long_debug_is_a_write
#MUTANT date-cluster-value-unread|s@^\tregex.match(`^-\[uR\]\*\[drf\]$`, arguments\[i - 1\])$@\tfalse@|an_honest_read_the_tip_refused_is_granted
#MUTANT gh-method-rest-ambiguous|s@^\tgh_method_rest(arguments\[i\]) == ""$@\ttrue@|a_gh_method_argument_has_one_reading
#MUTANT reader-name-widened|s@^\tlocal_name(word)$@\ttrue@|a_reader_assigning_a_sensitive_or_subscripted_name_is_a_write
#MUTANT printf-assignment-unread|s@^\tnot printf_local_assignment(program.arguments)$@\tfalse@|a_reader_assigning_a_sensitive_or_subscripted_name_is_a_write
#MUTANT test-lookup-unread|s@^\tword in {"-v", "-R"}$@\tfalse@|a_reader_assigning_a_sensitive_or_subscripted_name_is_a_write
#MUTANT curl-bare-host-guess-unread|s@^\tnot regex.match(`^(?i:(ftp@\tnot regex.match(`^(?i:(nothing@|a_bare_http_host_or_a_system_path_program_is_a_read
#MUTANT system-directory-widened|s@^\tprogram.program == concat("", \[directory, program.name\])$@\ttrue@|a_bare_http_host_or_a_system_path_program_is_a_read
#MUTANT git-upload-pack-unread|s@^\tnot git_runs_program(verb.rest)$@\ttrue@|a_plan_mode_git_network_read_is_allowed_and_its_writes_are_refused
#MUTANT read-builtin-refused|s@^\t\t"read",$@@|a_plan_mode_read_loop_is_allowed_and_a_writing_loop_is_refused
#MUTANT skill-refused|s@^\t\t"Skill",$@@|a_plan_mode_skill_is_allowed_and_a_write_tool_is_not
#
# THE READ-ONLY ALLOWLIST, ONE PREDICATE IN ONE PLACE (CLOUD-2840). Every bundle
# the engine compiles carries this package (`policy::LIBRARY`), whatever presets
# a consumer enables, so a module that asks "does this call only read?" calls
# `data.batten.library.read_only(call)` rather than restating it. The
# `claude-code-cloud` preset grants a read without a prompt on it; the install
# gate admits a read before the session's setup is dispatched on it.
#
# EVERY FACT HERE IS ONE THE ENGINE ALREADY OWNS. `reads-only` is the boundary's
# `READ_ONLY_PROGRAMS` floor, `batten-effect` is the surface's declared effect,
# and `output-redirect` is the redirect reading the protected-write gate uses. The
# lists below add only what is true of a PROGRAM everywhere — it ships to every
# consumer, so it may name no repository (non-negotiable rule 1).
#
# The ERROR DIRECTION is "not proven read-only": anything this cannot classify
# is not a read.
#
# A LIBRARY, NOT A RULE SET: it declares no `rules` and raises no `violation`,
# so it decides nothing on its own.

# METADATA
# description: |
#   The read-only allowlist every bundle carries: `read_only(call)` over a
#   MEDIATED-CALL document, handed in as the argument. THIS BLOCK IS YAML AND
#   MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.library

import rego.v1

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
		"cd", "pwd", "true", "false", "test", "[", "which", "type", "jq", "cut",
		"tr", "nl", "tac", "sha256sum", "md5sum", "du", "df", "uname", "id", "whoami",
		"printenv", "ps", "echo", "printf",
		# The shell builtin writes only a shell variable, so a `while read` loop
		# reads when every program in it does (CLOUD-2206).
		"read",
	}
}

# A GNU LONG OPTION BY ANY PREFIX (CLOUD-2840): `getopt_long` accepts an
# unambiguous abbreviation (`--se=` for `--set`, `--ou=` for `--output`), so the
# full name is one spelling of several. An ambiguous prefix is read as the
# option too, which fails closed.
names_long_option(argument, options) if {
	startswith(argument, "--")
	name := split(trim_prefix(argument, "--"), "=")[0]
	name != ""
	some option in options
	startswith(option, name)
}

# THREE PROGRAMS THAT READ UNLESS AN ARGUMENT SETS SOMETHING (CLOUD-2840), moved
# off the unconditional list above, where their writing forms were admitted.

# `date` prints the clock unless it SETS it: `-s`/`--set`, or an operand that is
# neither a `+FORMAT` nor a flag's value (`date 010100002020` sets the clock).
reads(program) if {
	program.name == "date"
	not date_sets(program.arguments)
}

date_sets(arguments) if {
	some argument in arguments
	regex.match(`^-[uR]*s`, argument)
}

date_sets(arguments) if {
	some argument in arguments
	names_long_option(argument, {"set"})
}

date_sets(arguments) if {
	some i, argument in arguments
	not startswith(argument, "-")
	not startswith(argument, "+")
	not date_value(arguments, i)
}

date_value(arguments, i) if {
	i > 0
	arguments[i - 1] in {"-d", "--date", "-r", "--reference", "-f", "--file"}
}

# A SHORT CLUSTER WHOSE LAST FLAG TAKES THE VALUE (CLOUD-2840 review m7): `-ud
# @0` is `-u -d @0`. Only the switches `-u` and `-R` come before it, so a `-s`
# in the cluster is still read as setting the clock.
date_value(arguments, i) if {
	i > 0
	regex.match(`^-[uR]*[drf]$`, arguments[i - 1])
}

# `hostname` reads with query flags only: an operand, `-F FILE` or `-b` SETS
# the name, so every argument must be a flag that asks.
reads(program) if {
	program.name == "hostname"
	every argument in program.arguments {
		hostname_query(argument)
	}
}

hostname_query(argument) if argument in {
	"-s", "--short", "-f", "--fqdn", "--long", "-i", "--ip-address", "-I",
	"--all-ip-addresses", "-d", "--domain", "-A", "--all-fqdns", "-a", "--alias",
	"-V", "--version", "-h", "--help",
}

# `tree` reads unless `-o FILE` writes its listing or `-R` (with `-H`) writes an
# index file into every directory it walks.
reads(program) if {
	program.name == "tree"
	not tree_writes(program.arguments)
}

tree_writes(arguments) if {
	some argument in arguments
	regex.match(`^(-[a-zA-Z]*[oR]|--output)`, argument)
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
		not spelled_with_a_path(program)
		not assigns_a_live_name(program)
	}
	not some_output_redirect(call)
	not some_live_assignment(call)
}

# A READER THAT ASSIGNS (CLOUD-2840, ca2f8b3e4 review finding 1): `read` and
# `printf -v` set a shell variable, and the next program on the line runs under
# it — `read PATH`, `printf -v HOME …`. And a name with a subscript is evaluated
# as arithmetic, which runs a command substitution: `printf -v 'a[$(id)]' x`,
# `test -v 'a[$(id)]'`. So a name one of these assigns must be a LOWERCASE
# identifier: every variable that makes a shell or program load something
# (`PATH`, `HOME`, `IFS`, `BASH_ENV`, `LD_*`, `PS4`) is uppercase, and no
# subscript is one. `mapfile` and `readarray` are on no list, so stay refused.
local_name(word) if regex.match(`^[a-z_][a-z0-9_]*$`, word)

assigns_a_live_name(program) if {
	program.name == "read"
	some i, word in program.arguments
	not read_word(program.arguments, i, word)
}

# `read`'s switches; `-a` and the value flags only LAST in a cluster, with their
# value the next word. A value never starts with `-`, so a value's flag is never
# itself a value and the left-to-right reading is the only one.
read_word(_, _, word) if regex.match(`^-[ers]+$`, word)

read_word(arguments, i, word) if {
	regex.match(`^-[ers]*[adinNptu]$`, word)
	not startswith(arguments[i + 1], "-")
}

read_word(arguments, i, word) if {
	read_value(arguments, i)
	not startswith(word, "-")
}

read_word(arguments, i, word) if {
	local_name(word)
	not read_value(arguments, i)
}

read_value(arguments, i) if {
	i > 0
	regex.match(`^-[ers]*[dinNptu]$`, arguments[i - 1])
}

# `printf` takes its options before the format: `-v NAME` is the only one, and
# `--` ends them.
assigns_a_live_name(program) if {
	program.name == "printf"
	first := program.arguments[0]
	startswith(first, "-")
	first != "--"
	not printf_local_assignment(program.arguments)
}

printf_local_assignment(arguments) if {
	arguments[0] == "-v"
	local_name(arguments[1])
	not startswith(arguments[2], "-")
}

# `test -v NAME` and `-R NAME` look the name up, subscript and all.
assigns_a_live_name(program) if {
	program.name in {"test", "["}
	some i, word in program.arguments
	word in {"-v", "-R"}
	not regex.match(`^[A-Za-z_][A-Za-z0-9_]*$`, program.arguments[i + 1])
}

# AN ASSIGNMENT BEFORE THE PROGRAM IS A READ'S ONLY IF IT IS INERT (CLOUD-2840
# review M4). `GIT_EXTERNAL_DIFF` and `GIT_PAGER` make git run a program, but so
# do `PATH`, `LD_PRELOAD`, `HOME` (a config file's), `RIPGREP_CONFIG_PATH`,
# `CURL_HOME`, `GH_BROWSER` and their kin for every program here — refusing
# `GIT_*` alone granted all of those. So the list is of the INERT names, which
# set locale, colour, width or a prompt and load nothing: a name outside it is
# not proven a read. A pager is inert only as `cat`, which runs nothing. Each
# `assigns` entry is `NAME=value`, per line and through `env -S`.
some_live_assignment(call) if {
	is_array(call.segments)
	some segment in call.segments
	some assignment in segment.assigns
	not inert_assignment(assignment)
}

inert_assignment(assignment) if {
	inert_name(assignment_name(assignment))
}

inert_assignment(assignment) if {
	assignment_name(assignment) in {"GIT_PAGER", "PAGER"}
	assignment_value(assignment) == "cat"
}

inert_name(name) if name in {"LANG", "LANGUAGE", "TZ", "NO_COLOR", "COLUMNS", "LINES", "TERM", "GIT_TERMINAL_PROMPT"}

inert_name(name) if startswith(name, "LC_")

inert_name(name) if startswith(name, "CLICOLOR")

assignment_name(assignment) := trim_suffix(split(assignment, "=")[0], "+")

assignment_value(assignment) := substring(assignment, indexof(assignment, "=") + 1, -1)

# A PROGRAM SPELLED WITH A PATH IS NOT THE PROGRAM ITS NAME ENDS IN (CLOUD-2840
# review M4): `./ls`, `/tmp/x/ls` and `bin/cat` run whatever sits there, and the
# allowlist above is a list of names `PATH` resolves. `program` is the token as
# written; `name` is its last path component.
spelled_with_a_path(program) if {
	contains(program.program, "/")
	not in_a_system_directory(program)
}

# EXCEPT A SYSTEM DIRECTORY (ca2f8b3e4 review finding 4): `/usr/bin/cat` is the
# file a bare `cat` resolves to through any `PATH` worth trusting, so it is no
# less the program than the name is. Exactly one directory, from a fixed list,
# with no `..`: `/usr/bin/../../tmp/ls` and `/tmp/usr/bin/ls` stay paths.
in_a_system_directory(program) if {
	some directory in {"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/"}
	program.program == concat("", [directory, program.name])
	not contains(program.name, "/")
	program.name != ".."
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
	verb = git_verb(program)
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

# `-o` in any spelling, and `--compress-program`, which runs a program; each
# long option by any prefix (`--ou=`).
sort_writes(arguments) if {
	some argument in arguments
	startswith(argument, "-o")
}

sort_writes(arguments) if {
	some argument in arguments
	names_long_option(argument, {"output", "compress-program"})
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
# command. `$1 > 5` is refused too, which fails closed. `-W` is every
# implementation's extension door (`-W exec`, `-We`), and gawk's `-d`/`-o`/`-p`
# write a dump, a pretty-print or a profile to a file (CLOUD-2840). A flag
# after `-v` or `-F` in one cluster is their value, so it is not read as one.
awk_writes(arguments) if {
	some argument in arguments
	regex.match(`^-[^-vF]*[filEWdopD]`, argument)
}

awk_writes(arguments) if {
	some argument in arguments
	names_long_option(argument, {"file", "include", "load", "exec", "dump-variables", "pretty-print", "profile", "debug"})
}

# A GAWK DIRECTIVE IN THE PROGRAM TEXT loads code as `-i`/`-l` do (CLOUD-2840
# review M6): `@include "inplace"` edits its input files in place, and `@load
# "rwarray"` brings `writea`, which writes one. `--debug` is `-D` spelled long.
awk_writes(arguments) if {
	some argument in arguments
	some directive in {"@include", "@load"}
	contains(argument, directive)
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

# A JOINED FIELD IS A FIELD (CLOUD-2840): `-ftitle=x` sends a body exactly as
# `-f title=x` does, and a body makes the method POST.
gh_api_writes(arguments) if {
	some argument in arguments
	gh_api_joined_field(argument)
}

# A SHORT CLUSTER ENDS AT ITS FIRST VALUE FLAG (CLOUD-2840 review m7): only `-i`
# is a switch, so in `-HX-GitHub-Api-Version:…` the `X` is the header's value.
gh_api_joined_field(argument) if regex.match(`^-i*[fF]`, argument)

gh_api_writes(arguments) if {
	some i, argument in arguments
	argument == "--method"
	upper(arguments[i + 1]) != "GET"
}

# `-X` INSIDE A SHORT CLUSTER (CLOUD-2840): `-iXDELETE` and `-iX DELETE` set the
# method as `-X DELETE` does. The value is the rest of the cluster, else the
# next word; with neither, the call is not proven a read.
gh_api_writes(arguments) if {
	some i, argument in arguments
	gh_method_flag(argument)
	upper(gh_method(arguments, i)) != "GET"
}

gh_api_writes(arguments) if {
	some i, argument in arguments
	gh_method_flag(argument)
	gh_method_rest(argument) == ""
	count(arguments) == i + 1
}

gh_method_flag(argument) if regex.match(`^-i*X`, argument)

# ONE READING PER ARGUMENT (CLOUD-2840 review m9): the rest of the cluster after
# `X`, or the next word only when that rest is empty. Two definitions that could
# both hold gave `-XGETX GET` two methods.
gh_method(arguments, i) := gh_method_rest(arguments[i]) if gh_method_rest(arguments[i]) != ""

gh_method(arguments, i) := arguments[i + 1] if {
	gh_method_rest(arguments[i]) == ""
}

gh_method_rest(argument) := substring(argument, indexof(argument, "X") + 1, -1)

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
# upload, an output file or a config file is outside the list. ONLY AN HTTP(S)
# URL IS AN OPERAND (CLOUD-2840): curl speaks `smtp://`, `mqtt://`, `telnet://`,
# `dict://` and more, where a request sends, and a bare host lets curl guess the
# protocol from its name, so neither is a read.
curl_reads(arguments) if {
	every i, word in arguments {
		curl_allowed(arguments, i, word)
	}
	not curl_value_eats_a_flag(arguments)
}

# A VALUE FLAG NEVER TAKES A FLAG AS ITS VALUE HERE (CLOUD-2840): curl reads
# `-A -A -o` as a user agent of `-A` and then `-o`, so a word after a value flag
# that is itself a flag would be admitted twice over, once as a value and once
# not. Refusing that shape leaves every value owned by exactly one flag, which
# is the left-to-right reading.
curl_value_eats_a_flag(arguments) if {
	some i, word in arguments
	curl_value_flag(word)
	startswith(arguments[i + 1], "-")
}

curl_value_flag(word) if word in {
	"-H", "--header", "-A", "--user-agent", "-m", "--max-time",
	"--connect-timeout", "--retry",
}

curl_allowed(_, _, word) if regex.match(`^(?i:https?)://`, word)

# A BARE HOST IS HTTP (ca2f8b3e4 review finding 4): curl guesses the protocol
# from a scheme-less URL's first label, and only `ftp.`, `dict.`, `ldap.`,
# `imap.`, `smtp.` and `pop3.` guess anything else (`lib/urlapi.c`). A host is
# letters, digits, dots and hyphens; an unexpanded `$URL` is none of those, so
# it stays unproven.
curl_allowed(_, _, word) if {
	regex.match(`^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?(/[^ ]*)?$`, word)
	not regex.match(`^(?i:(ftp|dict|ldap|imap|smtp|pop3)\.)`, word)
}

curl_allowed(_, _, word) if curl_word(word)

curl_allowed(arguments, i, _) if {
	i > 0
	curl_value_flag(arguments[i - 1])
}

curl_word(word) if regex.match(`^-[sSfLiIvk]+$`, word)

curl_word(word) if word in {
	"--silent", "--show-error", "--fail", "--fail-with-body", "--location", "--head",
	"--include", "--compressed", "--verbose", "--insecure", "-H", "--header", "-A",
	"--user-agent", "-m", "--max-time", "--connect-timeout", "--retry",
}
