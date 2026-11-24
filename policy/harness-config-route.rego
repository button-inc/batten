# A hand-made harness hook registration is refused, and the refusal names
# batten's own verb (CLOUD-1636's Amendment, owner ruling 2026-11-24).
#
# THE MEASURED INSTANCE. A cloud container resumed with the harness rooting the
# session outside the checkout, so no batten hook ran for seven hours. The
# agent's repair was `ln -sfn <checkout>/.claude/settings.json
# <root>/.claude/settings.json`, refused by the harness's own classifier, then a
# hand copy. It never ran `batten startup --repair`, and nothing told it to. The
# ruling makes the route a literal refusal rather than a judgement: a link, a
# copy or a written body that registers batten's hook on a harness surface is
# refused, and the line names the verb.
#
# THE SURFACE IS THE CONSUMER'S, THE HARNESS SET IS THE CORE'S. Which paths are
# harness configuration is the `harness-config-<harness>` `[[pattern]]` family in
# `batten.toml` (rule 1); `config_check::harness` refuses a family that leaves a
# harness out. The patterns match a path at any directory, so a surface in the
# tree and one under `$HOME` or a session root are one reading.
#
# THREE SHAPES, ONE CLASS:
#
# * a `ln`, `cp`, `mv` or `install` whose source is a harness surface and whose
#   destination is one — named outright, or a directory the source's basename
#   lands in;
# * a write tool whose body registers batten's hook on a harness surface;
# * a shell write to a harness surface whose command carries such a body.
#
# The vendor route (`policy/harness-config-advisory.rego`) is NEVER this class's
# remedy: a deny pre-empts an advisory on the same call, so a registration's
# line names `batten startup --repair` alone.

#MUTANT-SUITE crates/batten/tests/it/harness_config_route.rs
#MUTANT registration-link-admitted|s@^\ttarget.program in \{"ln", "cp", "mv", "install"\}$@\ttarget.program in {"cp", "mv", "install"}@|a_symlinked_registration_is_refused_naming_the_verb
#MUTANT registration-copy-admitted|s@^\ttarget.program in \{"ln", "cp", "mv", "install"\}$@\ttarget.program in {"ln", "mv", "install"}@|a_copied_registration_is_refused_naming_the_verb
#MUTANT registration-write-routes-to-vendor|s@^\tregex.match\(data.batten.patterns\["harness-hook-registration"\], text\)$@\tfalse@|a_written_registration_is_refused_naming_the_verb
#MUTANT registration-predicate-too-wide|s@^\tsurface\(source\)$@\ttrue@|an_unrelated_link_is_not_refused

# METADATA
# description: |
#   Bound to the MEDIATED-CALL surface: it reads `{call, facts}` and never the
#   tree document, so a module reading `input.tree.*` here fails to type check
#   rather than evaluating to undefined (CLOUD-845).
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-call.schema"]
package batten.harness_config_route

rules contains "hook wire wrong"

# A path some declared harness surface pattern matches.
surface(path) if {
	some id, pattern in data.batten.patterns
	startswith(id, "harness-config-")
	regex.match(pattern, path)
}

# Where a copied source lands: the destination itself when it is a surface, or
# the source's basename under it when the destination is a directory.
lands_on_surface(target, _) if surface(target)

lands_on_surface(target, source) if {
	parts := split(source, "/")
	surface(concat("/", [trim_right(target, "/"), parts[count(parts) - 1]]))
}

# A link or a copy of one harness surface onto another.
registration contains target.path if {
	some target in input.call["write-targets"]
	target.program in {"ln", "cp", "mv", "install"}
	some source in target.sources
	surface(source)
	lands_on_surface(target.path, source)
}

# The text a write tool hands its target: a whole body, or an edit's new side.
written_text contains text if {
	text := input.call.arguments.content
	is_string(text)
}

written_text contains text if {
	text := input.call.arguments.new_string
	is_string(text)
}

written_text contains text if {
	some edit in input.call.arguments.edits
	text := edit.new_string
	is_string(text)
}

# A write tool whose body registers batten's hook on a harness surface.
#
# `is_string` is load-bearing: `writes` is `null` on every non-write call, and
# `regex.match(_, null)` is an evaluation error rather than a false answer.
registration contains path if {
	input.call.operation == "write"
	path := input.call.writes
	is_string(path)
	surface(path)
	some text in written_text
	registers(text)
}

# A shell write to a harness surface whose command carries the registration.
registration contains target.path if {
	some target in input.call["write-targets"]
	surface(target.path)
	registers(input.call.command)
}

registers(text) if {
	regex.match(data.batten.patterns["harness-hook-registration"], text)
}

violation contains {
	"rule": "hook wire wrong",
	"verdict": "hook wire wrong",
	"subjects": [{"path": path}],
} if {
	some path in registration
}

deny contains verdict if some verdict in {v.verdict | some v in violation}

# --- cases ---------------------------------------------------------------
#
# The load-time tier. `crates/batten/tests/it/harness_config_route.rs` is the
# tier proving the ENGINE builds `write-targets`, which no case here can.

surfaces := {
	"harness-config-claude-code": `(^|/)\.claude/(settings|settings\.local|launcher-settings)\.json$`,
	"harness-config-cursor": `(^|/)\.cursor/hooks\.json$`,
	"harness-hook-registration": `"command"\s*:\s*"[^"]*\bbatten\b[^"]*\badjudicate\b`,
}

test_a_link_of_a_surface_onto_a_surface_is_refused if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "ln -sfn /w/.claude/settings.json /root/.claude/settings.json",
		"write-targets": [{
			"path": "/root/.claude/settings.json",
			"program": "ln",
			"sources": ["/w/.claude/settings.json"],
			"symbolic": true,
		}],
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook wire wrong"
}

test_a_copy_into_a_surface_directory_is_refused if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "mkdir -p /root/.claude && cp /w/.claude/settings.json /root/.claude/",
		"write-targets": [{
			"path": "/root/.claude/",
			"program": "cp",
			"sources": ["/w/.claude/settings.json"],
			"symbolic": false,
		}],
	}}
		with data.batten.patterns as surfaces
	v.subjects == [{"path": "/root/.claude/"}]
}

test_a_written_registration_is_refused if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "/root/.claude/settings.json",
		"arguments": {"content": `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "batten adjudicate --harness claude-code"}]}]}}`},
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook wire wrong"
}

test_a_written_body_registering_nothing_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": "/root/.claude/settings.json",
		"arguments": {"content": `{"permissions": {"allow": ["Bash(git status)"]}}`},
	}}
		with data.batten.patterns as surfaces
}

test_an_unrelated_link_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "command",
		"command": "ln -s /w/notes.md /root/.claude/settings.json",
		"write-targets": [{
			"path": "/root/.claude/settings.json",
			"program": "ln",
			"sources": ["/w/notes.md"],
			"symbolic": true,
		}],
	}}
		with data.batten.patterns as surfaces
}

# The compound case `policy test` requires of a mediated module (CLOUD-857):
# the link behind a `cd` is still the link.
test_a_compound_link_is_refused if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "cd /tmp && ln -sfn /w/.cursor/hooks.json /root/.cursor/hooks.json",
		"write-targets": [{
			"path": "/root/.cursor/hooks.json",
			"program": "ln",
			"sources": ["/w/.cursor/hooks.json"],
			"symbolic": true,
		}],
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook wire wrong"
}

test_a_call_carrying_no_write_is_silent if {
	count(violation) == 0 with input as {"call": {"operation": "command", "write-targets": null}}
		with data.batten.patterns as surfaces
}
