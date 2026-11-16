# What a call runs that nothing could read, from a file nobody reviewed
# (#1276, CLOUD-2775).
#
# The reach follows the programs a call runs into the text that runs them: a
# shell's script file, and the spawn calls of a Python, Node, Perl or Ruby
# program (`interpreted_reach` in `crates/batten/src/hook.rs`). Where a spawn's
# arguments are not literals, or a script file is present but cannot be read,
# the reach records an `opaque` entry instead of guessing what it runs, with its
# `source` and whether that source is `trusted`: a file the repository tracks
# with no working-tree change. Every other module then judges a call it cannot
# fully see as if the unseen part ran nothing.
#
# THE RULE IS ONE LINE AND THE LINE IS THE POINT. Opaque reach from reviewed
# code (tracked, clean) runs: review is where its spawns were read. Opaque reach
# from anything else is refused: an inline program, an untracked script, or a
# tracked one edited in place, whose spawns no reviewer and no module has seen.
# Measured on #1276: one session ran every commit and landing as `sh
# ship<N>.sh`, a file it wrote itself, and every gate judged `sh <path>`.
#
# A REFUSAL NAMES THE INTERPRETER AND THE SOURCE, never the text (rule 4).
#MUTANT-SUITE crates/batten/tests/it/script_spawn_opaque.rs
#MUTANT opaque-trusted-inverted|s@^\tnot entry.trusted == true$@\tentry.trusted == true@|opaque_reach_from_an_untracked_script_is_refused_and_a_tracked_one_runs

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: `input.call.programs` is the reach.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.script_spawn_opaque

import rego.v1

rules contains "shell reach unread"

# Every opaque entry whose source is not reviewed code.
unread contains entry if {
	some entry in input.call.programs
	entry.opaque == true
	not entry.trusted == true
}

# An inline program has no file to point at: the interpreter is the pointer.
violation contains {
	"rule": "shell reach unread",
	"verdict": "shell reach unread",
	"subjects": [{"artifact": entry.name}],
} if {
	some entry in unread
	entry.source == "-c"
}

violation contains {
	"rule": "shell reach unread",
	"verdict": "shell reach unread",
	"subjects": [{"path": entry.source}, {"artifact": entry.name}],
} if {
	some entry in unread
	entry.source != "-c"
}

# --- the module's own tier ----------------------------------------------------

call(programs) := {"call": {"programs": programs}}

opaque(name, source, trusted) := {
	"program": name,
	"name": name,
	"via": "script",
	"opaque": true,
	"source": source,
	"trusted": trusted,
}

test_an_untracked_scripts_opaque_spawn_is_refused if {
	found := violation with input as call([opaque("python3", "ship.py", false)])
	found == {{
		"rule": "shell reach unread",
		"verdict": "shell reach unread",
		"subjects": [{"path": "ship.py"}, {"artifact": "python3"}],
	}}
}

test_an_inline_programs_opaque_spawn_names_the_interpreter if {
	found := violation with input as call([opaque("node", "-c", false)])
	some finding in found
	finding.subjects == [{"artifact": "node"}]
}

test_reviewed_codes_opaque_spawn_runs if {
	count(violation) == 0 with input as call([opaque("perl", "tools/x.pl", true)])
}

# A compound line, as agents send most commands: the opaque spawn sits behind a
# bare program and is still the call's to refuse.
test_an_opaque_spawn_behind_a_compound_line_is_refused if {
	found := violation with input as {"call": {
		"command": "git status && python3 ship.py",
		"programs": [{"program": "git", "name": "git", "via": null}, opaque("python3", "ship.py", false)],
	}}
	count(found) == 1
}

test_a_call_with_nothing_opaque_runs if {
	count(violation) == 0 with input as call([{"program": "git", "name": "git", "via": null}])
}

# `trusted` absent is not trusted: a reach that could not establish it refuses.
test_an_opaque_entry_with_no_trust_reading_is_refused if {
	count(violation) == 1 with input as call([{"program": "ruby", "name": "ruby", "opaque": true, "source": "x.rb"}])
}
