#MUTANT-SUITE crates/batten/tests/it/tool_install_locked.rs
#MUTANT lockfile-setting-unread|s@^\tmanifest.settings.lockfile == true$@\ttrue@|an_unread_lockfile_is_reported
#MUTANT locked-setting-unread|s@^\tmanifest.settings.locked == true$@\ttrue@|a_lockfile_without_locked_mode_is_reported
#MUTANT parsed-overlay-unread|s@^\tnot truthy_value(value)$@\tfalse@|an_overlay_turning_the_lock_off_is_reported
#MUTANT globbed-overlay-unread|s@^\tnot input.tree.staged\[path\]$@\tfalse@|a_globbed_overlay_turning_the_lock_off_is_reported
#MUTANT env-switch-unread|s@^\tline_off(logical(lines, index, text))$@\tfalse@|a_task_env_turning_the_lock_off_is_reported
#MUTANT writer-widened|s@^\twriter_table(table_of(lines, index))$@\ttrue@|a_task_env_turning_the_lock_off_is_reported
#MUTANT guard-read-as-switch|s@^\tnot exempt(path, text)$@\ttrue@|a_comment_or_pure_read_is_untouched
#MUTANT comment-format-ignored|s@^\tslash_comment_file(path)$@\ttrue@|a_shell_assignment_named_like_prose_is_read
#MUTANT expansion-unread|s@^env_switched_off(text) if expansion_off(text)$@@|a_defaulting_expansion_is_a_switch
#MUTANT parsed-unread|s@^\tleaf_switched_off(pair\[0\], pair\[1\])$@\tfalse@|every_shell_assignment_spelling_is_read
#MUTANT parsed-writer-widened|s@^\tnot parsed_writer(path, pair\[0\])$@\ttrue@|the_declared_writer_may_turn_it_off
#MUTANT env-file-unread|s@^\tnot input.tree.lines\[resolved(path, name)\]$@\tfalse@|an_env_file_is_read_or_refused
#MUTANT truthy-unread|s@^\tnot truthy(value)$@\ttrue@|a_truthy_assignment_is_untouched
#MUTANT scopes-widening-unread|s@^\tscopes_widened(logical(lines, index, text))$@\tfalse@|a_widened_lock_scope_is_reported
#MUTANT directive-read-as-comment|s@^\tnot directive(text)$@\ttrue@|every_route_an_env_reaches_is_read
#MUTANT header-unread|s@^\tregex.match(data.batten.patterns\["toml-table-header"\], text)$@\tfalse@|the_declared_writer_may_turn_it_off
#MUTANT writer-any-task|s@^\tkeys\[1\] == "lock-check"$@\ttrue@|a_colon_or_indented_table_is_its_own_table
#MUTANT append-read-as-on|s@^assigns_off(separator, _) if separator == "+="$@assigns_off(separator, _) if false@|every_shell_assignment_spelling_is_read
#MUTANT comparison-read-as-switch|s@^\tnot separator in {"==", "+="}$@\ttrue@|a_true_prefix_or_comparison_is_untouched
#MUTANT continuation-unjoined|s@^\tsome part in array.slice(lines, index, index + span(lines, index))$@\tsome part in [text]@|every_shell_assignment_spelling_is_read
#MUTANT string-continuation-unjoined|s@replace(value, "\\\\\\n", "")@value@|every_shell_assignment_spelling_is_read
#MUTANT indirect-unread|s@^line_off(text) if indirect_off(text)$@@|every_shell_assignment_spelling_is_read
#MUTANT settings-unread|s@^line_off(text) if settings_off(text)$@@|the_lock_turned_off_without_its_name_is_reported
#MUTANT config-env-unread|s@^unnamed_off(text) if regex.match(data.batten.patterns\["mise-config-env"\], text)$@@|the_lock_turned_off_without_its_name_is_reported
#MUTANT action-config-unread|s@^unnamed_off(text) if regex.match(data.batten.patterns\["mise-action-config"\], text)$@@|the_lock_turned_off_without_its_name_is_reported
#MUTANT config-write-unread|s@^unnamed_off(text) if regex.match(data.batten.patterns\["mise-config-write"\], text)$@@|the_lock_turned_off_without_its_name_is_reported
#MUTANT lock-writer-unread|s@^unnamed_off(text) if regex.match(data.batten.patterns\["mise-lock-writer"\], text)$@@|a_second_lock_writer_is_reported
#MUTANT escaped-name-unread|s@^unnamed_off(text) if regex.match(data.batten.patterns\["mise-name-escaped"\], text)$@@|every_key_spelling_is_read
#MUTANT candidate-narrowed|s@^candidate(text) if contains(lower(text), "mise")$@@|a_task_env_turning_the_lock_off_is_reported
#MUTANT env-array-unread|s@^\tis_number(keys\[count(keys) - 1\])$@\tfalse@|an_env_file_resolves_against_the_config_root
#MUTANT config-root-unread|s@^\t\tunder(config_dir(path), suffix)$@\t\tfalse@|an_env_file_resolves_against_the_config_root
#MUTANT deep-tools-unread|s@^\tcount(node.tools) > 0$@\tfalse@|a_root_without_tools_still_needs_the_lock

# METADATA
# description: |
#   Every mise install reads `mise.lock` and nothing turns that off — CLOUD-2881.
#
#   WHY. With `[settings] lockfile = false`, every install path that did not opt
#   in by env resolved versions and assets through the forges' release APIs:
#   `mise run`'s pre-task install (which never sees a task's `env`), `mise exec`'s
#   auto-install, a by-hand `mise install`. A cloud session's proxy refuses those
#   for any third-party repository, so a cold container's toolchain 403'd before a
#   task body could opt back in. Locked mode installs from the lock's URLs and
#   checksums, calls no API, and never writes the lock. Measured cold on mise
#   2026.9.1: a plain `mise install` and a `mise run` pre-task install each
#   installed all 32 tools with zero api.github.com requests and left `mise.lock`
#   byte-identical.
#
#   THE WAYS BACK TO AN UNLOCKED INSTALL, one predicate each:
#   1. the root manifest's `[settings]` lacking `lockfile = true` and
#      `locked = true` (the staged, parsed node);
#   2. any other mise config file setting `lockfile` or `locked` to anything but
#      true in `[settings]`, `[tool_config]`, or at the top of a `miserc`. EVERY
#      overlay is PARSED, so every TOML spelling is read: a literal name in
#      mise's own config search list (`src/config/mod.rs`) is staged, and a name
#      only a glob reaches (`mise.<env>.toml`, `conf.d/*.toml`) is a document the
#      row's `sources` selects. An overlay that does not parse is one mise
#      refuses to load too;
#   3. an assignment of `MISE_LOCKED` or `MISE_LOCKFILE` to anything but a true
#      value (a `+=` append is never one), or of `MISE_LOCKED_SCOPES` to anything
#      but `project`, outside the one declared lock writer `[tasks.lock-check]` —
#      in a task's `env`, a handler's or startup row's argv, a workflow's or
#      action's `env:`, a file task's `#MISE` directive or `export`, an hk step,
#      a hook script, the harness's settings, an MCP server's env, a shell, bats
#      or direnv file, cargo's `[env]`, `tools/`, or a `.env` — or by a builtin
#      that assigns the name apart from its value (`printf -v`, `read`), or on a
#      line writing `$GITHUB_ENV`. A line a trailing backslash continues is
#      joined first, as the shell joins it. The value ends where the shell word
#      ends, and a `==` comparison is a read. Every TOML source is judged by its
#      PARSE as well as by line, so a quoted key, a joined string and the table a
#      key sits in are TOML's reading; and an env file a config loads (`_.file`,
#      `_.source`, in `[env]` or an `[[env]]` entry, resolved against the
#      config's root) that the row cannot read is refused;
#   4. the lock off with no env name: a `mise settings` write that is not on or
#      an unset, an env pointing mise at another config or none
#      (`MISE_GLOBAL_CONFIG_FILE`, `MISE_CONFIG_FILE`, `MISE_NO_CONFIG`, …),
#      mise-action's `mise_toml` input, a config file written at run time, a
#      `mise lock` outside the writer, and a `MISE_` name spelled through an
#      escape or an interpolation. Each is refused whatever its value.
#
#   EVERY DIRECTORY, NOT ONLY THE ROOT. mise loads its config names in every
#   ancestor of its cwd and a task may run from a subdirectory, so every config
#   name and task dir is matched at any depth, and tools a config below the root
#   declares make the root's settings required (1).
#
#   ONLY TWO THINGS ARE NOT SWITCHES. A whole-line comment, in a format that
#   has one — `#` in TOML, YAML and shell, `//` in pkl and JSON5 — but never a
#   `#!` shebang (`env -S` runs its arguments) and never a `#MISE`, `# [MISE]`
#   or `//MISE` directive, which mise reads. And a pure READ that assigns
#   nothing: `$MISE_LOCKED`, `${MISE_LOCKED}`, `"$MISE_LOCKED"`, a comparison. A
#   defaulting expansion (`${MISE_LOCKED=…}`, `${MISE_LOCKED:=…}`,
#   `${MISE_LOCKED-…}`) is a switch. PROSE IS NOT EXEMPT: two rounds of
#   prose-key and prose-block exemptions each hid a real unlocked install
#   (`title="$(MISE_LOCKED=false mise install)"`, a `'''` block holding `"""`),
#   so prose that must name a switch spells it without the `NAME=value` form,
#   and a refused sentence is the cost this rule accepts over a missed install.
#
#   THE PATHS ARE ONE LIST. `sources` admits exactly the paths the row's
#   `line_sources` names, and `tool_install_locked.rs`'s
#   `every_line_source_is_read` puts a switch in a file under each glob.
#
#   KNOWN LIMITS, each a place a switch can still hide or a line is over-read:
#   - A FILE NO GLOB NAMES is not read: Rust under `crates/` (engine code,
#     judged by its own tests), a Makefile, a Dockerfile, a `package.json`
#     script, an extensionless or `.in` fixture script, and anything outside the
#     tree (the user's own mise config and shell env).
#   - A NAME OR VALUE BUILT AT RUN TIME passes: `"MISE_" + "LOCKED"`, a variable
#     holding the name, `MISE_LOCK""ED` in an `env` argv. A literal pair is
#     read in any argv spelling: `Command::env("MISE_LOCKED", "false")` under
#     `tools/` is refused.
#   - A CONFIG EDITED IN PLACE by a program the line does not name as a write —
#     `sed -i`, `python -c`, `mise use` — passes; a redirect, `tee`, `cp`, `mv`,
#     `install` or `ln` onto a mise config name is refused.
#   - A `mise lock` is read where it runs as a command; a legacy backtick
#     substitution not after an `=` passes, as prose in backticks does.
#   - An empty shell assignment before a word that reads as true
#     (`MISE_LOCKED= 1 cmd`) passes: the value is taken after whitespace, as
#     TOML and YAML need. A continuation is joined to four lines.
#   - Tools declared only in a `.tool-versions` do not require the root's
#     settings; only a TOML config's `[tools]` does.
#   - A `#` LINE INSIDE A MULTI-LINE SHELL STRING is read as a comment — a
#     YAML `run: |` block line, a TOML `run = """` line, and the lines of a
#     parsed TOML string alike. Inside a heredoc or a quoted multi-line shell
#     string that `#` is data, so `# MISE_LOCKED=false` written there into a file
#     that is later sourced passes.
#   - A WRITER'S HEADER TEXT INSIDE A STRING re-attributes the lines after it on
#     the line surface, which takes the last header-shaped line as the table.
#     In the root `mise.toml` the parse judges each string by its real table,
#     so this cannot hide a switch there (a non-writer string spelling
#     `[tasks.lock-check]` is still refused by 3b); it can over-refuse a writer
#     script line that follows other header-shaped text.
#   - A TOML file that does not parse is judged by line only (mise refuses to
#     load it too), and a gitignored or templated env file is refused unread.
#   - The parse is judged to EIGHT levels of nesting (`leaves`, unrolled because
#     the bytecode compiler refuses `walk`); a value deeper than that is judged
#     by its line only.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.toolinstalllocked

import rego.v1

rules contains "lock read loose"

rules contains "tool install unsafe"

manifest := node if {
	node = input.tree.staged["mise.toml"]
	is_object(node)
}

declares_tools if {
	count(manifest.tools) > 0
}

# Tools a config below the root declares install under the root's settings too.
declares_tools if {
	some path, node in parsed_toml
	config_path(path)
	count(node.tools) > 0
}

# --- 1: the root manifest's settings ---------------------------------------------

lockfile_on if {
	manifest.settings.lockfile == true
}

locked_on if {
	manifest.settings.locked == true
}

locked_install if {
	lockfile_on
	locked_on
}

line_of(path, needle) := line if {
	hits := [found |
		some index, text in input.tree.lines[path]
		contains(text, needle)
		found = index + 1
	]
	count(hits) > 0
	line = min(hits)
}

settings_pointer := {"path": "mise.toml", "line": line_of("mise.toml", "[settings]")}

settings_pointer := {"path": "mise.toml"} if not line_of("mise.toml", "[settings]")

violation contains {
	"rule": "lock read loose",
	"verdict": "lock read loose",
	"subjects": [settings_pointer],
} if {
	declares_tools
	not locked_install
}

# --- the paths ---------------------------------------------------------------------

mise_config(path) if regex.match(data.batten.patterns["mise-config-file"], path)

miserc(path) if regex.match(data.batten.patterns["mise-rc-file"], path)

env_source(path) if mise_config(path)

env_source(path) if miserc(path)

env_source(path) if regex.match(data.batten.patterns["mise-task-file"], path)

env_source(path) if regex.match(data.batten.patterns["lock-env-file"], path)

sources[path] := lines if {
	some path, lines in input.tree.lines
	env_source(path)
}

# --- 2: overlay settings, parsed where the name is literal -----------------------

truthy_value(value) if value == true

truthy_value(value) if value == 1

truthy_value(value) if {
	is_string(value)
	regex.match(data.batten.patterns["mise-lock-truthy"], value)
}

parsed_settings(node, path) := {value |
	not miserc(path)
	some table in ["settings", "tool_config"]
	some key in ["lockfile", "locked"]
	value = node[table][key]
} | {value |
	miserc(path)
	some key in ["lockfile", "locked"]
	value = node[key]
}

# Every overlay, parsed: a literal name the row stages, or a name only a glob
# reaches, which the row's `sources` hands in as a document.
overlays[path] := node if {
	some path, node in parsed_toml
	path != "mise.toml"
	config_path(path)
}

config_path(path) if mise_config(path)

config_path(path) if miserc(path)

# Every TOML file the row parses: a literal name it stages, or a name only a
# glob reaches, which its `sources` hands in as a document.
parsed_toml[path] := node if {
	some path, node in input.tree.staged
	is_object(node)
}

parsed_toml[path] := node if {
	some path, node in input.tree.documents
	not input.tree.staged[path]
	is_object(node)
}

violation contains {
	"rule": "lock read loose",
	"verdict": "lock read loose",
	"subjects": [{"path": path}],
} if {
	some path, node in overlays
	some value in parsed_settings(node, path)
	not truthy_value(value)
}

# --- the line surface ------------------------------------------------------------

# A TOML table header: indented or not, every key bare (`lock-check`) or quoted
# (`"lock:refresh"`, `'x'`), inner whitespace, a trailing comment. Never a shell
# test: `[ -n "$x" ]` carries two keys with no dot between them.
table_header(text) if {
	regex.match(data.batten.patterns["toml-table-header"], text)
}

# The table a line sits in, as its key segments with the quotes taken off — so
# `[tasks."lock-check.x"]` is the two keys `tasks` and `lock-check.x`, never the
# writer's sub-table.
table_of(lines, index) := header_keys(lines[header]) if {
	header = max({at |
		some at, text in lines
		at <= index
		table_header(text)
	})
}

header_keys(text) := [concat("", [match[1], match[2], match[3]]) |
	some match in regex.find_all_string_submatch_n(data.batten.patterns["toml-key-segment"], key_path(text), -1)
]

# A header's key path: the table-header pattern's group 1.
key_path(text) := path if {
	some found in regex.find_all_string_submatch_n(data.batten.patterns["toml-table-header"], text, 1)
	path = found[1]
}

writer_table(keys) if {
	count(keys) >= 2
	keys[0] == "tasks"
	keys[1] == "lock-check"
}

# A directive mise reads from a file task's header, whatever comment opens it.
directive(text) if regex.match(data.batten.patterns["mise-task-directive"], text)

# A whole-line comment in the file's own syntax: `//` in pkl and JSON5, `#`
# everywhere else, and never a directive.
slash_comment_file(path) if endswith(path, ".pkl")

slash_comment_file(path) if endswith(path, ".json5")

commented(path, text) if {
	slash_comment_file(path)
	regex.match(data.batten.patterns["comment-slash"], text)
	not directive(text)
}

commented(path, text) if {
	not slash_comment_file(path)
	regex.match(data.batten.patterns["comment-hash"], text)
	not directive(text)
}

exempt(path, text) if commented(path, text)

truthy(value) if regex.match(data.batten.patterns["mise-lock-truthy"], value)

# --- 3: an env off-switch ----------------------------------------------------------

# An assignment of `MISE_LOCKED` or `MISE_LOCKFILE`: the separator is group 1 or
# 2 and the value group 3, which ends where the shell word ends, so
# `MISE_LOCKED=1 mise install` assigns `1`. A `==` comparison is a read; a `+=`
# append is never on, whatever it appends.
assignment_off(text) if {
	some match in regex.find_all_string_submatch_n(data.batten.patterns["mise-lock-env"], text, -1)
	assigns_off(concat("", [match[1], match[2]]), match[3])
}

assigns_off(separator, _) if separator == "+="

assigns_off(separator, value) if {
	not separator in {"==", "+="}
	not truthy(value)
}

# `${MISE_LOCKED=false}`, `${MISE_LOCKED:-}`: an expansion that assigns or
# defaults, whose operand is the value. A bare `${MISE_LOCKED}` has no operator
# and is a read.
expansion_off(text) if {
	some match in regex.find_all_string_submatch_n(data.batten.patterns["mise-lock-expansion"], text, -1)
	not truthy(match[1])
}

env_switched_off(text) if assignment_off(text)

env_switched_off(text) if expansion_off(text)

# A builtin assigning the name with its value elsewhere (`printf -v`, `read`),
# or a line writing `$GITHUB_ENV`: off unless every assignment on it is on.
indirect_off(text) if {
	contains(text, "MISE_LOCK")
	regex.match(data.batten.patterns["mise-lock-indirect"], text)
	not assigned_on(text)
}

assigned_on(text) if {
	count(regex.find_all_string_submatch_n(data.batten.patterns["mise-lock-env"], text, -1)) > 0
	not assignment_off(text)
}

# A `mise settings` write that is not on, or an unset (the default is off).
settings_off(text) if {
	some match in regex.find_all_string_submatch_n(data.batten.patterns["mise-settings-lock"], text, -1)
	not truthy(match[1])
}

settings_off(text) if regex.match(data.batten.patterns["mise-settings-unset"], text)

# THE LOCK OFF WITH NO ENV NAME, refused whatever the value: mise pointed at
# another config (or none), mise-action's inline config, a config file written
# at run time, a second `mise lock`, and a name spelled through an escape.
unnamed_off(text) if regex.match(data.batten.patterns["mise-config-env"], text)

unnamed_off(text) if regex.match(data.batten.patterns["mise-action-config"], text)

unnamed_off(text) if regex.match(data.batten.patterns["mise-config-write"], text)

unnamed_off(text) if regex.match(data.batten.patterns["mise-lock-writer"], text)

unnamed_off(text) if regex.match(data.batten.patterns["mise-name-escaped"], text)

line_off(text) if env_switched_off(text)

line_off(text) if indirect_off(text)

line_off(text) if settings_off(text)

line_off(text) if unnamed_off(text)

# Only a line that names mise, an `.rtx` config or an escape can be one.
candidate(text) if contains(lower(text), "mise")

candidate(text) if contains(text, ".rtx")

candidate(text) if contains(text, "\\")

# A line a trailing backslash continues, joined as the shell joins it (to four
# lines), so `MISE_LOCK\` then `ED=false` is the one word it runs.
logical(_, _, text) := text if not endswith(text, "\\")

logical(lines, index, text) := concat("", [trim_suffix(part, "\\") |
	some part in array.slice(lines, index, index + span(lines, index))
]) if {
	endswith(text, "\\")
}

span(lines, index) := min({end |
	some k in numbers.range(0, 3)
	not continued(lines, index + k)
	end = k + 1
} | {4})

continued(lines, at) if endswith(lines[at], "\\")

declared_writer(path, lines, index) if {
	path == "mise.toml"
	writer_table(table_of(lines, index))
}

line_switch(path, lines, index, text) if {
	candidate(text)
	line_off(logical(lines, index, text))
	not exempt(path, text)
	not declared_writer(path, lines, index)
}

violation contains {
	"rule": "tool install unsafe",
	"verdict": "tool install unsafe",
	"subjects": [{"path": path, "line": index + 1}],
} if {
	some path, lines in sources
	some index, text in lines
	line_switch(path, lines, index, text)
}

# THE SCOPE, TOO. A task's `MISE_LOCKED_SCOPES = "project"` keeps the user's
# global tools out of locked mode inside the task; any other value puts global
# or system tools back under it, or (empty) project tools out of it, and an
# append is never `project`.
scopes_widened(text) if {
	some match in regex.find_all_string_submatch_n(data.batten.patterns["mise-locked-scopes-env"], text, -1)
	scope_off(concat("", [match[1], match[2]]), match[3])
}

scopes_widened(text) if {
	some match in regex.find_all_string_submatch_n(data.batten.patterns["mise-locked-scopes-expansion"], text, -1)
	not regex.match(data.batten.patterns["mise-locked-scopes-project"], match[1])
}

scope_off(separator, _) if separator == "+="

scope_off(separator, value) if {
	not separator in {"==", "+="}
	not regex.match(data.batten.patterns["mise-locked-scopes-project"], value)
}

line_scope(path, lines, index, text) if {
	contains(text, "MISE_LOCKED_SCOPES")
	scopes_widened(logical(lines, index, text))
	not exempt(path, text)
}

violation contains {
	"rule": "tool install unsafe",
	"verdict": "tool install unsafe",
	"subjects": [{"path": path, "line": index + 1}],
} if {
	some path, lines in sources
	some index, text in lines
	line_scope(path, lines, index, text)
}

# A file the line surface already refuses: its parsed finding would only repeat
# that pointer without a line.
line_flagged(path) if {
	some index, text in sources[path]
	line_switch(path, sources[path], index, text)
}

line_flagged(path) if {
	some index, text in sources[path]
	line_scope(path, sources[path], index, text)
}

# --- 3b: TOML judged by its PARSE ---------------------------------------------------
#
# A line cannot see what TOML makes of it: a quoted key (`"MISE_LOCKED" = …`), a
# string a line-ending backslash joins (`MISE_LOCKED\` then `=false`), or which
# table a key really sits in. So every TOML line source is also parsed, and each
# leaf is judged: a switch-named key whose value is not on, and a string whose
# lines carry a switch (its `#` lines are shell comments). Only the writer's own
# keys (`tasks.lock-check.*` in the root manifest) are exempt.
project_value(value) if {
	is_string(value)
	regex.match(data.batten.patterns["mise-locked-scopes-project"], value)
}

parsed_writer(path, key_path) if {
	path == "mise.toml"
	writer_table(key_path)
}

leaf_switched_off(key_path, value) if {
	count(key_path) > 0
	key_path[count(key_path) - 1] in {"MISE_LOCKED", "MISE_LOCKFILE"}
	not truthy_value(value)
}

leaf_switched_off(key_path, value) if {
	count(key_path) > 0
	key_path[count(key_path) - 1] == "MISE_LOCKED_SCOPES"
	not project_value(value)
}

# A string's lines, a backslash-newline joined first as the shell joins it (a
# `'''` string keeps both characters, so the parse cannot).
leaf_switched_off(_, value) if {
	is_string(value)
	some line in split(replace(value, "\\\n", ""), "\n")
	not regex.match(data.batten.patterns["comment-hash"], line)
	candidate(line)
	string_switch(line)
}

string_switch(line) if line_off(line)

string_switch(line) if scopes_widened(line)

# Every [path, value] pair of a parsed node, to LEAVES_DEPTH levels, as a set a
# body iterates with `some pair in`. Unrolled rather than walked: regorus's
# bytecode compiler refuses a `walk` loop (`policy_execution`'s every-load
# case), and Rego has no recursion. Eight levels hold every key this rule
# judges with room over: `tasks.<name>.env.<KEY>` is four, `env._.file[i].path`
# five, a `[[rule.external]]` array element's string five. A deeper value is
# not judged (KNOWN LIMITS).
leaves(node) := ((((((level_1(node) | level_2(node)) | level_3(node)) | level_4(node)) | level_5(node)) | level_6(node)) | level_7(node)) | level_8(node)

collection(value) if is_object(value)

collection(value) if is_array(value)

level_1(node) := {[[key_1_1], value_1_1] |
	some key_1_1, value_1_1 in node
}

level_2(node) := {[[key_2_1, key_2_2], value_2_2] |
	some key_2_1, value_2_1 in node
	collection(value_2_1)
	some key_2_2, value_2_2 in value_2_1
}

level_3(node) := {[[key_3_1, key_3_2, key_3_3], value_3_3] |
	some key_3_1, value_3_1 in node
	collection(value_3_1)
	some key_3_2, value_3_2 in value_3_1
	collection(value_3_2)
	some key_3_3, value_3_3 in value_3_2
}

level_4(node) := {[[key_4_1, key_4_2, key_4_3, key_4_4], value_4_4] |
	some key_4_1, value_4_1 in node
	collection(value_4_1)
	some key_4_2, value_4_2 in value_4_1
	collection(value_4_2)
	some key_4_3, value_4_3 in value_4_2
	collection(value_4_3)
	some key_4_4, value_4_4 in value_4_3
}

level_5(node) := {[[key_5_1, key_5_2, key_5_3, key_5_4, key_5_5], value_5_5] |
	some key_5_1, value_5_1 in node
	collection(value_5_1)
	some key_5_2, value_5_2 in value_5_1
	collection(value_5_2)
	some key_5_3, value_5_3 in value_5_2
	collection(value_5_3)
	some key_5_4, value_5_4 in value_5_3
	collection(value_5_4)
	some key_5_5, value_5_5 in value_5_4
}

level_6(node) := {[[key_6_1, key_6_2, key_6_3, key_6_4, key_6_5, key_6_6], value_6_6] |
	some key_6_1, value_6_1 in node
	collection(value_6_1)
	some key_6_2, value_6_2 in value_6_1
	collection(value_6_2)
	some key_6_3, value_6_3 in value_6_2
	collection(value_6_3)
	some key_6_4, value_6_4 in value_6_3
	collection(value_6_4)
	some key_6_5, value_6_5 in value_6_4
	collection(value_6_5)
	some key_6_6, value_6_6 in value_6_5
}

level_7(node) := {[[key_7_1, key_7_2, key_7_3, key_7_4, key_7_5, key_7_6, key_7_7], value_7_7] |
	some key_7_1, value_7_1 in node
	collection(value_7_1)
	some key_7_2, value_7_2 in value_7_1
	collection(value_7_2)
	some key_7_3, value_7_3 in value_7_2
	collection(value_7_3)
	some key_7_4, value_7_4 in value_7_3
	collection(value_7_4)
	some key_7_5, value_7_5 in value_7_4
	collection(value_7_5)
	some key_7_6, value_7_6 in value_7_5
	collection(value_7_6)
	some key_7_7, value_7_7 in value_7_6
}

level_8(node) := {[[key_8_1, key_8_2, key_8_3, key_8_4, key_8_5, key_8_6, key_8_7, key_8_8], value_8_8] |
	some key_8_1, value_8_1 in node
	collection(value_8_1)
	some key_8_2, value_8_2 in value_8_1
	collection(value_8_2)
	some key_8_3, value_8_3 in value_8_2
	collection(value_8_3)
	some key_8_4, value_8_4 in value_8_3
	collection(value_8_4)
	some key_8_5, value_8_5 in value_8_4
	collection(value_8_5)
	some key_8_6, value_8_6 in value_8_5
	collection(value_8_6)
	some key_8_7, value_8_7 in value_8_6
	collection(value_8_7)
	some key_8_8, value_8_8 in value_8_7
}

parsed_switch(path) if {
	some pair in leaves(parsed_toml[path])
	leaf_switched_off(pair[0], pair[1])
	not parsed_writer(path, pair[0])
}

violation contains {
	"rule": "tool install unsafe",
	"verdict": "tool install unsafe",
	"subjects": [{"path": path}],
} if {
	some path, _ in parsed_toml
	parsed_switch(path)
	not line_flagged(path)
}

# --- 3c: an env file a config loads ---------------------------------------------------
#
# `[env] _.file = ".env"` (or `_.source`, in any env table) loads variables the
# config does not spell, so the file is a route of its own. The row reads every
# `.env` and `.env.*`; one it cannot read — gitignored, templated, outside the
# tree — is refused rather than assumed clean.
env_file_names(value) := ({value | is_string(value)} | {name |
	is_array(value)
	some entry in value
	name = file_name(entry)
}) | {name |
	is_object(value)
	name = value.path
}

file_name(entry) := entry if is_string(entry)

file_name(entry) := entry.path if is_object(entry)

config_dir(path) := concat("/", array.slice(parts, 0, count(parts) - 1)) if {
	parts := split(path, "/")
}

# A config's ROOT, which its relative `_.file` resolves against: the directory
# above `.config/mise/`, `mise/`, `.mise/` (and their `conf.d/`) or `.config/`,
# else the file's own directory. Longest suffix first.
root_suffixes := [".config/mise/conf.d", ".config/mise", "mise/conf.d", ".mise/conf.d", ".config", "mise", ".mise"]

config_root(path) := roots[0] if {
	roots = [above(config_dir(path), suffix) |
		some suffix in root_suffixes
		under(config_dir(path), suffix)
	]
	count(roots) > 0
}

config_root(path) := config_dir(path) if {
	not rooted(config_dir(path))
}

rooted(dir) if {
	some suffix in root_suffixes
	under(dir, suffix)
}

under(dir, suffix) if dir == suffix

under(dir, suffix) if endswith(dir, concat("", ["/", suffix]))

above(dir, suffix) := "" if dir == suffix

above(dir, suffix) := trim_suffix(dir, concat("", ["/", suffix])) if dir != suffix

resolved(path, name) := trim_prefix(name, "./") if config_root(path) == ""

resolved(path, name) := concat("/", [config_root(path), trim_prefix(name, "./")]) if config_root(path) != ""

# `env._.file` / `env._.source`, in an env table or an `[[env]]` entry.
env_file_key(key_path) if {
	count(key_path) >= 3
	key_path[count(key_path) - 1] in {"file", "source"}
	key_path[count(key_path) - 2] == "_"
	env_table(array.slice(key_path, 0, count(key_path) - 2))
}

env_table(keys) if keys[count(keys) - 1] == "env"

env_table(keys) if {
	is_number(keys[count(keys) - 1])
	keys[count(keys) - 2] == "env"
}

env_files contains [path, name] if {
	some path, node in parsed_toml
	config_path(path)
	some pair in leaves(node)
	env_file_key(pair[0])
	some name in env_file_names(pair[1])
}

violation contains {
	"rule": "tool install unsafe",
	"verdict": "tool install unsafe",
	"subjects": [{"path": path}],
} if {
	some [path, name] in env_files
	not input.tree.lines[resolved(path, name)]
}

# --- the load-time tier ------------------------------------------------------------

fixture_patterns := {
	"mise-config-file": `^(?:.+/)?(\.?mise(\.[^/]+)?\.toml|\.rtx(\.local)?\.toml|(mise|\.mise|\.config/mise)/(config|mise)(\.[^/]+)?\.toml|(mise|\.mise|\.config/mise)/conf\.d/[^/]+\.toml|\.config/mise(\.[^/]+)?\.toml)$`,
	"mise-rc-file": `^(?:.+/)?(\.miserc\.toml|\.config/miserc\.toml)$`,
	"mise-task-file": `(?:^|/)(mise-tasks|\.mise-tasks|\.mise/tasks|\.config/mise/tasks|mise/tasks)/`,
	"lock-env-file": `^(batten\.toml|renovate\.json5|(?:.+/)?[^/]+\.(?:pkl|sh|bash|bats)|(?:.+/)?action\.ya?ml|\.github/actions/.+|\.github/workflows/[^/]+\.ya?ml|\.claude/hooks/.+|\.claude/[^/]+\.json|(?:.+/)?\.mcp\.json|tools/.+|(?:.+/)?\.env(?:\..+)?|(?:.+/)?\.envrc|(?:.+/)?\.cargo/config\.toml)$`,
	"toml-table-header": `^\s*\[\[?\s*((?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')(?:\s*\.\s*(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*'))*)\s*\]\]?\s*(?:#.*)?$`,
	"toml-key-segment": `([A-Za-z0-9_-]+)|"((?:[^"\\]|\\.)*)"|'([^']*)'`,
	"comment-hash": `^\s*#([^!]|$)`,
	"comment-slash": `^\s*//`,
	"mise-task-directive": `^(#|//|::)\s*(MISE|\[MISE\]) `,
	"mise-lock-truthy": `^\s*["']?\s*(?i:true|1|yes|on)\s*["']?\s*$`,
	"mise-lock-env": `(?:(?:^|[^${]|(?:^|[^$])\{)MISE_LOCK(?:ED|FILE)[\x60"']?\]?\s*(==|\+=|=|:|,)|\$MISE_LOCK(?:ED|FILE)(=))\s*("[^"]*"|'[^']*'|[^\s,})\]#;&|]*)`,
	"mise-lock-expansion": `\$\x7bMISE_LOCK(?:ED|FILE)(?::?[-=?+])([^}]*)\}`,
	"mise-locked-scopes-expansion": `\$\x7bMISE_LOCKED_SCOPES(?::?[-=?+])([^}]*)\}`,
	"mise-locked-scopes-env": `(?:(?:^|[^${]|(?:^|[^$])\{)MISE_LOCKED_SCOPES[\x60"']?\]?\s*(==|\+=|=|:|,)|\$(?:MISE_LOCKED_SCOPES)(=))\s*("[^"]*"|'[^']*'|[^\s,})\]#;&|]*)`,
	"mise-lock-indirect": `\bprintf\s+(?:-\S+\s+)*-v\s*["']?MISE_LOCK|\b(?:read|mapfile|readarray)\s+(?:-\S+\s+)*(?:\w+\s+)*["']?MISE_LOCK|GITHUB_\x45NV`,
	"mise-settings-lock": `\bmise\s+(?:-\S+\s+)*(?:settings\s+(?:set\s+)?|config\s+set\s+)(?:-\S+\s+)*(?:settings\.)?lock(?:ed|file)(?:\s*=\s*|\s+)(\S*)`,
	"mise-settings-unset": `\bmise\s+(?:-\S+\s+)*settings\s+(?:unset|rm)\s+(?:-\S+\s+)*(?:settings\.)?lock(?:ed|file)\b`,
	"mise-config-env": `(?:^|[^$\x7b\w])\x7b?MISE_(?:GLOBAL_CONFIG_(?:FILE|ROOT)|CONFIG_(?:FILE|DIR)|DEFAULT_CONFIG_FILENAME|OVERRIDE_CONFIG_FILENAMES|SYSTEM_(?:CONFIG_(?:FILE|DIR)|DIR)|ENV_FILE|IGNORED_CONFIG_PATHS|NO_CONFIG|CEILING_PATHS)[\x60"']?\]?\s*(?:\+=|=(?:[^=]|$)|:|,)|\$\x7bMISE_(?:GLOBAL_CONFIG_(?:FILE|ROOT)|CONFIG_(?:FILE|DIR)|DEFAULT_CONFIG_FILENAME|OVERRIDE_CONFIG_FILENAMES|SYSTEM_(?:CONFIG_(?:FILE|DIR)|DIR)|ENV_FILE|IGNORED_CONFIG_PATHS|NO_CONFIG|CEILING_PATHS):?=`,
	"mise-action-config": `^\s*-?\s*["']?mise_toml["']?\s*:`,
	"mise-config-write": `(?:>>?|\btee\s+(?:-\S+\s+)*|\b(?:cp|mv|install|ln)\s+(?:\S+\s+)+)\s*["']?(?:[^\s"'<>|;&]*/)?(?:\.?mise(?:\.[^\s/"'<>|;&]+)?\.toml|\.rtx(?:\.local)?\.toml|\.?miserc\.toml|(?:mise|\.mise|\.config/mise)/(?:config|mise)(?:\.[^\s/"'<>|;&]+)?\.toml|(?:mise|\.mise|\.config/mise)/conf\.d/|\.config/mise(?:\.[^\s/"'<>|;&]+)?\.toml)`,
	"mise-lock-writer": `(?:^|[;&|(\["',:=]|\bthen\b|\bdo\b|\bexec\b|=\s*\x60)\s*(?:command\s+)?mise\s+(?:-\S+\s+)*lock\b`,
	"mise-name-escaped": `MISE_[A-Z_]*\\[xuU0-7(]|\\(?:x|u\x7b?0*|U0*)4[dD]ISE_`,
	"mise-locked-scopes-project": `^\s*["']?\s*project\s*["']?\s*$`,
}

locked_manifest := {"settings": {"lockfile": true, "locked": true}, "tools": {"t": "1.0.0"}}

fixture_staged(staged) := staged if staged["mise.toml"]

fixture_staged(staged) := object.union(staged, {"mise.toml": locked_manifest}) if not staged["mise.toml"]

fixture_input(staged, lines) := fixture_tree(staged, {}, lines)

fixture_tree(staged, documents, lines) := {"tree": {
	"staged": fixture_staged(staged),
	"documents": documents,
	"lines": lines,
	"missing": {},
}}

test_the_locked_settings_are_clean if {
	count(violation) == 0 with input as fixture_input({}, {})
		with data.batten.patterns as fixture_patterns
}

test_each_half_of_the_settings_is_required if {
	some a in violation with input as fixture_input({"mise.toml": {"settings": {"lockfile": true}, "tools": {"t": "1"}}}, {})
		with data.batten.patterns as fixture_patterns
	a.rule == "lock read loose"
	some b in violation with input as fixture_input({"mise.toml": {"settings": {"locked": true}, "tools": {"t": "1"}}}, {})
		with data.batten.patterns as fixture_patterns
	b.rule == "lock read loose"
}

test_a_parsed_overlay_is_read_in_any_spelling if {
	found_seen = violation with input as fixture_input(
		{
			"mise.local.toml": {"settings": {"locked": false}},
			".config/mise/config.toml": {"tool_config": {"locked": 0}},
			".miserc.toml": {"lockfile": false},
			".mise.toml": {"settings": {"lockfile": true, "locked": true}},
		},
		{},
	)
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].path |
		some v in found_seen
		v.rule == "lock read loose"
	}
	found == {"mise.local.toml", ".config/mise/config.toml", ".miserc.toml"}
}

test_a_globbed_overlay_is_parsed if {
	found_seen = violation with input as fixture_tree(
		{},
		{
			"mise.agent.toml": {"settings": {"locked": false}},
			".config/mise/conf.d/a.toml": {"tool_config": {"lockfile": 0}},
			"mise.dev.toml": {"tasks": {"x": {"locked": false}}},
		},
		{},
	)
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].path |
		some v in found_seen
		v.rule == "lock read loose"
	}
	found == {"mise.agent.toml", ".config/mise/conf.d/a.toml"}
}

test_every_env_spelling_is_a_finding if {
	found_seen = violation with input as fixture_input({}, {
		"mise.toml": ["[tasks.build]", "env = { MISE_LOCKED = \" false\" }"],
		"batten.toml": ["run = [\"env\", \"MISE_LOCKFILE=0\", \"mise\"]"],
		".github/workflows/w.yaml": ["  MISE_LOCKED: ${{ inputs.locked }}", "  MISE_LOCKFILE: >-"],
		"mise-tasks/t.sh": ["#MISE env={MISE_LOCKED=\"false\"}", "export MISE_LOCKED=no"],
		".mise/tasks/u": ["# [MISE] env={MISE_LOCKED=\"0\"}"],
		"hk-fix-selection.pkl": ["env { [\"MISE_LOCKED\"] = \"false\" }"],
	})
		with data.batten.patterns as fixture_patterns
	found := {sprintf("%s:%d", [v.subjects[0].path, v.subjects[0].line]) |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {
		"mise.toml:2", "batten.toml:1", ".github/workflows/w.yaml:1",
		".github/workflows/w.yaml:2", "mise-tasks/t.sh:1", "mise-tasks/t.sh:2",
		".mise/tasks/u:1", "hk-fix-selection.pkl:1",
	}
}

test_a_script_block_is_not_prose if {
	found_seen = violation with input as fixture_input({}, {
		"mise.toml": [
			"[tasks.a]", "run = \"\"\"", "MISE_LOCKED=false mise install", "\"\"\"",
			"[tasks.b]", "run = '''", "MISE_LOCKFILE=false mise install", "'''",
		],
		".github/workflows/w.yml": ["  # '''", "  MISE_LOCKED: false"],
	})
		with data.batten.patterns as fixture_patterns
	found := {sprintf("%s:%d", [v.subjects[0].path, v.subjects[0].line]) |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {"mise.toml:3", "mise.toml:7", ".github/workflows/w.yml:2"}
}

test_the_writer_and_truthy_values_are_clean if {
	count(violation) == 0 with input as fixture_input({}, {
		"mise.toml": [
			"[tasks.\"lock-check\"]",
			"env = { MISE_LOCKFILE = \"true\", MISE_LOCKED = \"false\" }",
			"[tasks.lock-check.env]",
			"MISE_LOCKED = \"false\"",
			"[tasks.install]",
			"env = { MISE_LOCKFILE = \"true\", MISE_LOCKED = \"1\" }",
		],
		"batten.toml": ["  \"MISE_LOCKED=1\","],
	})
		with data.batten.patterns as fixture_patterns
}

test_only_the_project_scope_is_not_a_switch if {
	found_seen = violation with input as fixture_input({}, {"mise.toml": [
		"[tasks.a]",
		"env = { MISE_LOCKED_SCOPES = \"project\" }",
		"[tasks.b]",
		"env = { MISE_LOCKED_SCOPES = \"global,project\" }",
		"[tasks.c]",
		"env = { MISE_LOCKED_SCOPES = \"\" }",
	]})
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].line |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {4, 6}
}

test_a_comment_or_pure_read_is_untouched if {
	count(violation) == 0 with input as fixture_input({}, {
		"mise-tasks/t.sh": [`if [ "$MISE_LOCKED" = "false" ]; then`, `  echo "${MISE_LOCKED}" $MISE_LOCKFILE`, `fi`],
		"batten.toml": [`# MISE_LOCKED = "false" in a comment`],
		".github/workflows/w.yml": [`  # MISE_LOCKED: false is refused`],
		"hk.pkl": [`// MISE_LOCKED = "false" in a pkl comment`],
	})
		with data.batten.patterns as fixture_patterns
}

test_prose_is_not_exempt if {
	found_seen = violation with input as fixture_input({}, {
		".github/workflows/w.yml": [`        title="$(MISE_LOCKED=false mise install)"`, `  - name: MISE_LOCKED=false`],
		"mise.toml": [
			`[tasks.a]`,
			`run = """`,
			`summary="$(MISE_LOCKFILE=0 mise install)"`,
			`"""`,
			"title=\"`MISE_LOCKED=false mise install`\"",
			`description = '''a """ inside'''`,
			`run = "MISE_LOCKED=false mise install"`,
			`[tasks.b]`,
			`run = '''`,
			`description = """`,
			`'''`,
			`run = "MISE_LOCKFILE=off mise install"`,
		],
		"renovate.json5": [`  description: "probe", env: { MISE_LOCKED: "false" },`],
		"hk.pkl": [`# MISE_LOCKED = "false" is not a pkl comment`],
	})
		with data.batten.patterns as fixture_patterns
	found := {sprintf("%s:%d", [v.subjects[0].path, v.subjects[0].line]) |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {
		".github/workflows/w.yml:1", ".github/workflows/w.yml:2",
		"mise.toml:3", "mise.toml:5", "mise.toml:7", "mise.toml:12",
		"renovate.json5:1", "hk.pkl:1",
	}
}

test_a_suffixed_name_or_dollar_assignment_is_a_switch if {
	found_seen = violation with input as fixture_input({}, {"mise-tasks/t": [
		`FOO_MISE_LOCKED=false mise install`,
		`$MISE_LOCKED=false`,
		`if [ "$MISE_LOCKED" = "false" ]; then echo; fi`,
	]})
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].line |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {1, 2}
}

test_a_defaulting_expansion_is_a_switch if {
	found_seen = violation with input as fixture_input({}, {"mise-tasks/t": [
		`: "${MISE_LOCKED=false}"`,
		`: "${MISE_LOCKFILE:=0}"`,
		`echo "${MISE_LOCKED-false}"`,
		`echo "${MISE_LOCKED:-}"`,
		`: "${MISE_LOCKED_SCOPES:=global}"`,
		`: "${MISE_LOCKED:=true}"`,
	]})
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].line |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {1, 2, 3, 4, 5}
}

test_a_colon_or_indented_table_is_its_own_table if {
	found_seen = violation with input as fixture_input({}, {"mise.toml": [
		`[tasks.lock-check]`,
		`env = { MISE_LOCKED = "false" }`,
		`[tasks."lock:refresh"]`,
		`env = { MISE_LOCKED = "false" }`,
		`[tasks.lock-check]`,
		`  [tasks.build]`,
		`env = { MISE_LOCKED = "false" }`,
		`[tasks.'lock-check.x']`,
		`env = { MISE_LOCKED = "false" }`,
	]})
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].line |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {4, 7, 9}
}

test_a_shebang_or_shell_assignment_is_read if {
	found_seen = violation with input as fixture_input({}, {
		"mise-tasks/a": [`#!/usr/bin/env -S MISE_LOCKED=false mise exec -- bash`],
		"mise-tasks/b": [`#!/bin/sh`, `name=x MISE_LOCKED=false mise install`],
		".github/workflows/w.yml": [`      run: |`, `        name=x MISE_LOCKFILE=0 mise install`],
	})
		with data.batten.patterns as fixture_patterns
	found := {sprintf("%s:%d", [v.subjects[0].path, v.subjects[0].line]) |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {"mise-tasks/a:1", "mise-tasks/b:2", ".github/workflows/w.yml:2"}
}

test_an_escaped_quote_header_is_its_own_table if {
	found_seen = violation with input as fixture_input({}, {"mise.toml": [
		`[tasks.lock-check]`,
		`env = { MISE_LOCKED = "false" }`,
		`[tasks."probe\"x"]`,
		`env = { MISE_LOCKED = "false" }`,
	]})
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].line |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {4}
}

parsed_manifest(tasks) := object.union(locked_manifest, {"tasks": tasks})

test_the_parse_reads_what_a_line_cannot if {
	found_seen = violation with input as fixture_input(
		{
			"mise.toml": parsed_manifest({
				"x": {"run": "MISE_LOCKED=false mise install"},
				"lock-check": {"env": {"MISE_LOCKED": "false"}},
			}),
			"mise.local.toml": {"env": {"MISE_LOCKFILE": false}},
		},
		{
			"mise.toml": [`[tasks.x]`, `run = """MISE_LOCKED\`, `=false mise install"""`],
			"mise.local.toml": [`[env]`, `"MISE_LOCKFILE" = false`],
		},
	)
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].path |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {"mise.toml", "mise.local.toml"}
}

test_a_writer_header_inside_a_string_hides_nothing if {
	found_seen = violation with input as fixture_input(
		{"mise.toml": parsed_manifest({"x": {"run": "[tasks.lock-check]\nMISE_LOCKED=false mise install\n"}})},
		{"mise.toml": [`[tasks.x]`, `run = """`, `[tasks.lock-check]`, `MISE_LOCKED=false mise install`, `"""`]},
	)
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].path |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {"mise.toml"}
}

test_the_writers_parsed_keys_are_clean if {
	count(violation) == 0 with input as fixture_input(
		{"mise.toml": parsed_manifest({"lock-check": {"env": {"MISE_LOCKED": "false", "MISE_LOCKFILE": "true"}}})},
		{},
	)
		with data.batten.patterns as fixture_patterns
}

test_an_env_file_is_read_or_refused if {
	loads := object.union(locked_manifest, {"env": {"_": {"file": [".env", {"path": "./.env.ci"}]}}})
	unread_seen = violation with input as fixture_input({"mise.toml": loads}, {".env": [`A=1`]})
		with data.batten.patterns as fixture_patterns
	unread := {v.subjects[0].path |
		some v in unread_seen
	}
	unread == {"mise.toml"}
	count(violation) == 0 with input as fixture_input({"mise.toml": loads}, {".env": [`A=1`], ".env.ci": [`B=2`]})
		with data.batten.patterns as fixture_patterns
	switched_seen = violation with input as fixture_input({"mise.toml": loads}, {".env": [`MISE_LOCKED=false`], ".env.ci": [`B=2`]})
		with data.batten.patterns as fixture_patterns
	switched := {sprintf("%s:%d", [v.subjects[0].path, v.subjects[0].line]) |
		some v in switched_seen
	}
	switched == {".env:1"}
}

test_every_new_route_is_read if {
	found_seen = violation with input as fixture_input({}, {
		".claude/hooks/h.sh": [`MISE_LOCKED=false mise install`],
		"tools/t/run.sh": [`MISE_LOCKFILE=0 mise install`],
		"crates/x/mise.toml": [`[env]`, `MISE_LOCKED = "false"`],
		".env.local": [`MISE_LOCKED=no`],
	})
		with data.batten.patterns as fixture_patterns
	found := {v.subjects[0].path |
		some v in found_seen
		v.rule == "tool install unsafe"
	}
	found == {".claude/hooks/h.sh", "tools/t/run.sh", "crates/x/mise.toml", ".env.local"}
}
