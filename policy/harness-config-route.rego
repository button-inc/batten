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
# `batten.toml` (rule 1); `validate_harness_surfaces` refuses a family that leaves a
# harness out. The patterns match a path at any directory, so a surface in the
# tree and one under `$HOME` or a session root are one reading.
#
# DECIDED BY WHAT LANDS, NOT BY HOW THE SOURCE IS SPELLED (the review of #1287).
# The engine places every shell write (`hook::write_targets`): each target
# carries the files it `lands`, at or under it, with the content it receives —
# a copied or linked file's, each file of a copied or linked directory, or what
# a redirect or `tee` takes from `cat`, `git show` or `echo` — through `cd`,
# `$PWD` and a `sh -c` script alike. So the shapes are:
#
# * any shell write whose landed content on a harness surface registers
#   batten's hook (a copy, link, move, redirect or `tee`, of a file or a
#   whole directory);
# * where nothing landing on a surface could be read, a `ln`, `cp`, `mv` or
#   `install` whose source is a harness surface and whose destination is one —
#   named outright, or a directory the source's basename lands in;
# * a write tool whose body ADDS a registration to a harness surface: never
#   one keeping the registration the file already carries (`prior`), so the
#   checkout's own settings keep their hooks through any other edit;
# * a shell write to a harness surface whose command carries such a body.
#
# The vendor route (`policy/harness-config-advisory.rego`) is NEVER this class's
# remedy: a deny pre-empts an advisory on the same call, so a registration's
# line names `batten startup --repair` alone.

#MUTANT-SUITE crates/batten/tests/it/harness_config_route.rs
#MUTANT registration-link-admitted|s@^\ttarget.program in {"ln", "cp", "mv", "install"}$@\ttarget.program in {"cp", "mv", "install"}@|a_symlinked_registration_is_refused_naming_the_verb
#MUTANT registration-copy-admitted|s@^\ttarget.program in {"ln", "cp", "mv", "install"}$@\ttarget.program in {"ln", "mv", "install"}@|a_copied_registration_is_refused_naming_the_verb
#MUTANT registration-write-routes-to-vendor|s@^\tregex.match(data.batten.patterns\["harness-hook-registration"\], text)$@\tfalse@|a_written_registration_is_refused_naming_the_verb
#MUTANT registration-predicate-too-wide|s@^\tsurface(source)$@\ttrue@|an_unrelated_link_is_not_refused
#MUTANT registration-content-unread|s@^\tregisters(land.content)$@\tfalse@|a_copy_by_content_is_refused_naming_the_verb
#MUTANT registration-kept-is-refused|s@^\tnot registered_before$@\ttrue@|the_checkouts_own_settings_keep_their_hooks_through_an_edit
#MUTANT registration-unread-by-spelling|s@^\tcount(read_landings(target)) == 0$@\ttrue@|a_permissions_only_copy_is_not_refused

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

# The shell write targets and an edit list, BEHIND A TYPE GUARD: `some x in null`
# raises an evaluation error rather than abstaining, and `write-targets` is
# `null` on every write-tool call, so an unguarded iteration faults the whole
# module on exactly the calls the other arms judge.
write_targets := input.call["write-targets"] if is_array(input.call["write-targets"])

edits := input.call.arguments.edits if is_array(input.call.arguments.edits)

# What a target lands, as the engine placed it; empty where it placed nothing.
landings(target) := target.lands if is_array(target.lands)

landings(target) := [] if not is_array(target.lands)

# Each file landing on a harness surface whose content was read.
read_landings(target) := [land |
	some land in landings(target)
	surface(land.path)
	is_string(land.content)
]

# A target's sources and destination, as spelled and as placed.
sources(target) := {source | some source in target.sources} | {origin | some origin in object.get(target, "origins", [])}

destinations(target) := {target.path} | {resolved | resolved := target.resolved; is_string(resolved)}

# Any shell write whose landed content on a harness surface registers the hook.
registration contains target.path if {
	some target in write_targets
	some land in read_landings(target)
	registers(land.content)
}

# Where nothing landing on a surface could be read, a link or a copy of one
# harness surface onto another is judged by its spelling.
registration contains target.path if {
	some target in write_targets
	target.program in {"ln", "cp", "mv", "install"}
	count(read_landings(target)) == 0
	some source in sources(target)
	surface(source)
	some destination in destinations(target)
	lands_on_surface(destination, source)
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
	some edit in edits
	text := edit.new_string
	is_string(text)
}

# A write tool whose body ADDS a registration to a harness surface.
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
	not registered_before
}

# The file a write tool writes over already registers the hook: the write keeps
# it, `batten startup --repair` could not make the edit, and the vendor route
# is the one `harness-config-advisory.rego` names.
registered_before if {
	prior := input.call.prior
	is_string(prior)
	registers(prior)
}

# A shell write to a harness surface whose command carries the registration.
registration contains target.path if {
	some target in write_targets
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

# `write-targets` SPELLED `null`, as the engine sends it on a write tool: a case
# omitting the key reads undefined and hid the fault the type guard closes.
test_a_written_registration_is_refused if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "/root/.claude/settings.json",
		"write-targets": null,
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

# --- the review of #1287: decided by what lands ----------------------------

registered := `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "batten adjudicate --harness claude-code"}]}]}}`

# `cat <cs> > <rs>`: the source is spelled nowhere a link arm reads.
test_a_redirect_landing_a_registration_is_refused if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "cat /w/.claude/settings.json > /root/.claude/settings.json",
		"write-targets": [{
			"path": "/root/.claude/settings.json",
			"program": null,
			"sources": [],
			"symbolic": false,
			"resolved": "/root/.claude/settings.json",
			"origins": [],
			"lands": [{"path": "/root/.claude/settings.json", "content": registered}],
		}],
	}}
		with data.batten.patterns as surfaces
	v.subjects == [{"path": "/root/.claude/settings.json"}]
}

# A directory copied whole: the target is no surface, a file landing under it is.
test_a_directory_landing_a_registration_is_refused if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "cp -r /w/.claude /root/",
		"write-targets": [{
			"path": "/root/",
			"program": "cp",
			"sources": ["/w/.claude"],
			"symbolic": false,
			"resolved": "/root/",
			"origins": ["/w/.claude"],
			"lands": [{"path": "/root/.claude/settings.json", "content": registered}],
		}],
	}}
		with data.batten.patterns as surfaces
	v.subjects == [{"path": "/root/"}]
}

# A surface copied whose content was read and registers nothing is no
# registration, whatever its spelling.
test_a_read_copy_registering_nothing_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "command",
		"command": "cp /w/.claude/settings.local.json /root/.claude/settings.local.json",
		"write-targets": [{
			"path": "/root/.claude/settings.local.json",
			"program": "cp",
			"sources": ["/w/.claude/settings.local.json"],
			"symbolic": false,
			"resolved": "/root/.claude/settings.local.json",
			"origins": ["/w/.claude/settings.local.json"],
			"lands": [{"path": "/root/.claude/settings.local.json", "content": `{"permissions": {"allow": ["Bash(git status)"]}}`}],
		}],
	}}
		with data.batten.patterns as surfaces
}

# A relative source whose content could not be read is judged by its placement.
test_an_unread_source_is_judged_by_its_placement if {
	some v in violation with input as {"call": {
		"operation": "command",
		"command": "cd /w/.claude && cp settings.json /root/.claude/settings.json",
		"write-targets": [{
			"path": "/root/.claude/settings.json",
			"program": "cp",
			"sources": ["settings.json"],
			"symbolic": false,
			"resolved": "/root/.claude/settings.json",
			"origins": ["/w/.claude/settings.json"],
			"lands": [{"path": "/root/.claude/settings.json", "content": null}],
		}],
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook wire wrong"
}

test_a_write_keeping_the_files_own_registration_is_silent if {
	count(violation) == 0 with input as {"call": {
		"operation": "write",
		"writes": ".claude/settings.json",
		"write-targets": null,
		"prior": registered,
		"arguments": {"content": concat("", [`{"permissions": {"allow": ["Read"]}, `, substring(registered, 1, -1)])},
	}}
		with data.batten.patterns as surfaces
}

test_a_write_adding_a_registration_over_a_plain_file_is_refused if {
	some v in violation with input as {"call": {
		"operation": "write",
		"writes": "/root/.claude/settings.json",
		"write-targets": null,
		"prior": `{"permissions": {}}`,
		"arguments": {"content": registered},
	}}
		with data.batten.patterns as surfaces
	v.verdict == "hook wire wrong"
}
