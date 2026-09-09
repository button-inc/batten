# METADATA
# description: |
#   No hook registered BY PATH may shell out to a pinned tool — CLOUD-479's own
#   trap, ported from `mise-tasks/hook-pin-check.sh` under CLOUD-843.
#
#   A hook registered through the task runner pays ~203ms of runner startup per
#   call — measured, against 15-19ms for the same script invoked by path, on the
#   one path where an agent cannot background anything. Registering by path is
#   therefore the obvious fix, and it has one non-obvious cost: A BY-PATH
#   INVOCATION DOES NOT GET THE RUNNER'S ENV, so every tool the script assumes is
#   the pinned one resolves to whatever the ambient PATH offers, or to nothing.
#
#   That is not a latency question, it is a correctness one. Every hook here is
#   fail-open by design — an `|| exit 0`, a discarded stderr, an empty read that
#   means "allow" — so a missing parser does not error. It silently allows. A gate
#   that reports a clean session while checking nothing is strictly worse than the
#   203ms it saved, and it is invisible: nothing turns red.
#
#   So the PAIRING is refused: registered by path AND shelling out to a tool the
#   manifest pins. Either invoke it through the runner and pay the startup, or stop
#   depending on the pinned tool — which is what two hooks here already did, moving
#   their payload reads onto the compiled binary that is already on this path.
#
#   ONE EXEMPTION, DECLARED IN THE SCRIPT rather than listed here: a task may carry
#   a `#PIN-OK: <tool>` line stating that it asserts the tool's presence itself.
#   The exemption lives beside the assertion it describes so the two cannot drift
#   apart; a list in this module would be a second authority on a fact the file
#   already states.
#
#   NOT JUDGED: registrations that go through the task runner. They get its env by
#   construction, and this module has nothing to say about them.
#
#   THE SETTINGS FILE IS READ AS TEXT, NOT AS A DOCUMENT, and the reason is the
#   gate's own subject: a rule about depending on a parser must not itself depend
#   on one. The retiring program said so in as many words and reached for text
#   utilities over a JSON tool; reading `input.tree.lines` is that same decision,
#   made by the engine instead of by a subprocess.
#
#   A CALL, NOT A MENTION, and the narrowing is stated because it is a real one.
#   The retired program matched a tool name in COMMAND POSITION with a regex; a
#   module carrying its own regex is refused at load, so the successor tests the
#   same positions as literal prefixes — line start, or after one of the shell's
#   command separators. It is the weakest claim that still catches a call while
#   leaving a paragraph ABOUT a tool alone, and comments are stripped first for
#   the same reason: the prose explaining why a tool was dropped must not read as
#   a dependency on it.
#
#   POINTER, NEVER PAYLOAD (rule 4): a finding names the task and the tool, never
#   a line of either file.
#
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.hook_pin_check

import rego.v1

rules contains "hook-pin-check"

settings_path := ".claude/settings.json"

manifest_path := "mise.toml"

tasks_prefix := "mise-tasks/"

settings_lines := lines if {
	lines := input.tree.lines[settings_path]
}

manifest_lines := lines if {
	lines := input.tree.lines[manifest_path]
}

# --- the pinned set ----------------------------------------------------------
#
# Read from the manifest's `[tools]` table and nothing else, so pinning a tool
# enrols it here with no second edit. A key is either bare or a backend
# coordinate, and it is the LAST path segment that names the executable.
tools_header_index := i if {
	some i, line in manifest_lines
	startswith(line, "[tools]")
}

tools_end := e if {
	after := {j |
		some j, line in manifest_lines
		j > tools_header_index
		startswith(line, "[")
	}
	e := min(after)
}

tools_end := count(manifest_lines) if {
	tools_header_index
	not another_table_follows_tools
}

another_table_follows_tools if {
	some j, line in manifest_lines
	j > tools_header_index
	startswith(line, "[")
}

pinned contains tool if {
	some j, line in manifest_lines
	j > tools_header_index
	j < tools_end
	contains(line, "=")
	key := replace(trim_space(substring(line, 0, indexof(line, "="))), "\"", "")
	key != ""
	segments := split(key, "/")
	tool := segments[count(segments) - 1]
	tool != ""
}

# --- the registrations -------------------------------------------------------
#
# Every registered hook command, taken as the first quoted value after a
# `"command"` key.
# THE COLON IS THE PREDICATE, not punctuation. `"command"` occurs twice on a
# registration line — once as the value of `"type"` and once as the key — so a
# reader that takes the first occurrence reads the literal word `command` as the
# registered program and judges nothing. The retired program required the colon
# for this reason; splitting on the key and keeping only the parts that CONTINUE
# with one is the same requirement, and it finds every occurrence rather than the
# first.
command contains value if {
	some line in settings_lines
	parts := split(line, "\"command\"")
	some k, part in parts
	k > 0
	startswith(trim_space(part), ":")
	spans := regex.find_n(data.batten.patterns["md-quoted-span"], part, 1)
	value := replace(spans[0], "\"", "")
	value != ""
}

# BY PATH is the case this judges: a command naming a file under the tasks
# directory. A registration that goes through the task runner gets its env and is
# not this module's business.
by_path contains task if {
	some value in command
	contains(value, tasks_prefix)
	not contains(value, "mise run")
	after := substring(value, indexof(value, tasks_prefix) + count(tasks_prefix), -1)
	task := split(after, " ")[0]
	task != ""
}

script_lines(task) := lines if {
	lines := input.tree.lines[concat("", [tasks_prefix, task])]
}

# Comments stripped, so the paragraphs explaining why a tool was dropped do not
# read as a dependency on it.
stripped(line) := substring(line, 0, indexof(line, "#")) if {
	contains(line, "#")
}

stripped(line) := line if {
	not contains(line, "#")
}

# A CALL, not a mention: the tool's name in command position.
calls(text, tool) if {
	startswith(trim_space(text), concat("", [tool, " "]))
}

calls(text, tool) if {
	some separator in {";", "&", "|", "(", "$("}
	contains(text, concat("", [separator, tool, " "]))
}

calls(text, tool) if {
	some separator in {";", "&", "|", "(", "$("}
	contains(text, concat("", [separator, " ", tool, " "]))
}

# The declared exemption, read from the RAW lines: it is a comment, and stripping
# comments is what the call test does.
# The tool is named WHOLE, never as a substring: an exemption for one tool must
# not cover another whose name it happens to contain.
exempt(task, tool) if {
	some line in script_lines(task)
	startswith(line, "#PIN-OK:")
	rest := substring(line, count("#PIN-OK:"), -1)
	some named in split(replace(rest, ",", " "), " ")
	trim_space(named) == tool
}

violation contains {
	"rule": "hook-pin-check",
	"verdict": "tool pin missing",
	"subjects": [{"artifact": sprintf("%s %s", [task, tool])}],
} if {
	some task in by_path
	some tool in pinned
	some line in script_lines(task)
	calls(stripped(line), tool)
	not exempt(task, tool)
}

# A MANIFEST PINNING NOTHING is a question this module could not ask, never a
# clean answer: with the pinned set empty every by-path hook passes vacuously,
# which is the shape of a gate that judges nothing while reporting clean.
violation contains {
	"rule": "hook-pin-check",
	"verdict": "pin table missing",
	"subjects": [{"path": manifest_path}],
} if {
	manifest_lines
	count(pinned) == 0
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE resolves three
# different `line_sources` shapes — two literal paths and a glob over the task
# directory — into one map in a single evaluation. A `with input as` block
# fabricates exactly that map (CLOUD-845), and this module's whole judgement is
# the JOIN across the three. `crates/batten/tests/it/hook_pin_check.rs` is that
# tier.

tree(files) := {"tree": {"lines": files}}

manifest := ["[tools]", "zizmor = \"1.0\"", "\"aqua:jqlang/jq\" = \"1.7\"", "[env]", "X = \"1\""]

registered(command_value) := sprintf("      { \"type\": \"command\", \"command\": \"%s\" }", [command_value])

test_a_by_path_hook_calling_a_pinned_tool_is_refused if {
	some v in violation with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["jq -r .x <<<\"$payload\""],
	})
	v.verdict == "tool pin missing"
}

test_a_runner_registration_is_not_this_gates_business if {
	count(violation) == 0 with input as tree({
		".claude/settings.json": [registered("mise run -q mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["jq -r .x <<<\"$payload\""],
	})
}

test_a_mention_in_a_comment_is_not_a_dependency if {
	count(violation) == 0 with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["# this used to call jq and no longer does"],
	})
}

test_the_declared_exemption_is_honoured if {
	count(violation) == 0 with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["#PIN-OK: jq", "jq -r .x <<<\"$payload\""],
	})
}

# The backend coordinate names the executable in its LAST segment.
test_a_backend_coordinate_pins_its_last_segment if {
	some v in violation with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": ["[tools]", "\"aqua:jqlang/jq\" = \"1.7\""],
		"mise-tasks/guard.sh": ["jq -r .x"],
	})
	v.verdict == "tool pin missing"
}

test_a_call_after_a_pipe_is_still_a_call if {
	some v in violation with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["cat file | jq -r .x"],
	})
	v.verdict == "tool pin missing"
}

test_a_manifest_pinning_nothing_is_could_not_look if {
	some v in violation with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": ["[env]", "X = \"1\""],
		"mise-tasks/guard.sh": ["jq -r .x"],
	})
	v.verdict == "pin table missing"
}

# An exemption for a DIFFERENT tool does not cover this one.
test_an_exemption_for_another_tool_does_not_cover_this_one if {
	some v in violation with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["#PIN-OK: zizmor", "jq -r .x"],
	})
	v.verdict == "tool pin missing"
}

# A tool named as a SUBSTRING of another word is not a call to it.
test_a_substring_of_another_word_is_not_a_call if {
	count(violation) == 0 with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["jqx --render file", "cat file | myjq -r .x"],
	})
}

test_a_by_path_hook_calling_nothing_pinned_is_clean if {
	count(violation) == 0 with input as tree({
		".claude/settings.json": [registered("mise-tasks/guard.sh")],
		"mise.toml": manifest,
		"mise-tasks/guard.sh": ["batten hook claude-code"],
	})
}

#MUTANT-SUITE crates/batten/tests/it/hook_pin_check.rs
#MUTANT invocation-shape-unread|s@^\tnot contains(value, "mise run")$@\ttrue@|a_runner_registration_is_not_judged
#MUTANT pinned-call-unread|s@^\tcalls(stripped(line), tool)$@\tfalse@|a_by_path_hook_shelling_out_to_a_pinned_tool_is_refused
#MUTANT empty-pin-table-unpriced|s@^\tcount(pinned) == 0$@\tfalse@|a_manifest_pinning_nothing_is_not_clean
