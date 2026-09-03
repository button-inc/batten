# METADATA
# description: |
#   The COMMITTED half of `hooks-wiring-check`'s consumer predicate (CLOUD-1160):
#   which of the commands registered beside batten's, on a hook surface this
#   repository tracks, are legitimate HERE.
#
#   The rule is AGENTS.md's own: `PreToolUse` is ONE entry, the engine. CLOUD-312
#   measured the alternative -- six `mise run` launches per Bash call, 1.247s
#   serial to do milliseconds of policy -- so a second program on a hook surface
#   is a second decider over the same call rather than a preference.
#
#   WHY THIS IS A CONSUMER MODULE AND NOT ENGINE SOURCE, which is the question a
#   reader asks first. `batten doctor hooks` already decides the whole DERIVATION
#   half -- batten registered exactly once on every event a harness emits, no
#   matcher, no drift -- with one unit case per finding in
#   `crates/batten/src/doctor.rs`. What it will not do is NAME a sibling, twice
#   over and it says so at both fields: a command line carries a path
#   (non-negotiable rule 4), and whether a hook beside batten's is legitimate is
#   a CONSUMER's judgement (rule 1). Turning that count into a verdict needs the
#   `declared` table below, which is a fact about this repository. So the
#   derivation half needed no porting at all, and the deleted shell was the seam
#   between the two.
#
#   ONE MODULE OVER BOTH SURFACE CLASSES, and the merged half is here rather than
#   in a sibling because there was never a reason to split it. CLOUD-1160 first
#   landed it as two modules on two rows, citing CLOUD-1307 -- an engine defect
#   that does not exist. That row was measured with the RELEASED binary on `PATH`
#   rather than the one built from the tree; the shipping engine runs a rule whose
#   other declared sources resolved, pushing the unacquired id into
#   `input.tree.missing` and continuing. The split cost real coverage: one merged
#   surface watched where the retired shell read four, and no STALE direction over
#   them at all. Both are restored here.
#
#   THE COULD-NOT-LOOK CLAUSE IS WRITABLE SINCE CLOUD-1309. It was absent for one
#   commit because `input.tree.missing` projected NAMES without causes, so a module
#   could not tell "would not parse" from "not there" -- and firing on the second
#   would redden every consumer wiring fewer hosts. The projection carries the
#   cause now, so the clause below asks for `unparsed` and leaves `absent` alone.
#
#   COULD-NOT-LOOK IS ALSO PER SURFACE CLASS, which is what the deleted shell counted
#   with its own `merged_read` variable and what the restored `stale` guards read.
#   A committed row is judged only where a committed surface was read; a merged row
#   only where a merged surface was. A CI runner has no launcher file, so its
#   merged rows are unenforced there rather than reported stale -- the measured
#   verify/CI disagreement that made two rows permanently unlandable before the
#   shell grew that guard.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.harness_wiring

import rego.v1

rules contains "harness-wiring"

# The program every hook registration must resolve to.
#
# A name rather than a full argv: the launcher spells the same registration
# several ways across hosts -- a bare binary, a path, a `mise exec` wrapper --
# and CLOUD-824 records what asking for an exact string bought last time, which
# was a launcher script that resolved the repo root through a second authority
# and allowed every mediated call silently.
mediator := "batten"

# THERE IS NO EXEMPTION TABLE, AND ITS ABSENCE IS THE MECHANISM (CLOUD-1383).
#
# This module used to read `policy/harness-declared.json`: one row per tolerated
# registration naming the issue that owned removing it, with three directions
# watching the table itself -- `unowned` for a row naming no issue, `stale` for a
# row matching nothing wired, `spent` for a row whose issue had CLOSED. All three
# existed to stop a licence becoming permanent. That is a real failure and this
# was the wrong layer to answer it at.
#
# THE TABLE WAS A NEGOTIATION OVER A FACT NOBODY HAD STATED. Batten repairs the
# hook surfaces it owns; whether a repair may REMOVE what it finds beside its own
# registration is not a property of the finding. It is a property of whose home
# directory this is, and with no way to ask, the module had to tolerate siblings
# row by row and then police its own tolerance.
#
# It also drifted from the repair within a day, in the direction that reads
# healthy: `[[hook.handler]] session-wiring` ran `batten wiring reclaim` at every
# session start, REMOVING exactly what the table declared must be present, while
# `wiring reclaim --check` reported nothing to do and `doctor hooks` reported
# everything wired. Two instruments green and this gate refusing (CLOUD-1377).
# Measured 2026-09-02, that cost one session three wrong diagnoses, a hand-write
# into a launcher-owned file, and an escalation asserting the repository was
# structurally broken while `main` had already dropped the rows.
#
# `BATTEN_ENVIRONMENT=disposable` removes the negotiation rather than adjudicating
# it. A container states that its `$HOME` is disposable and the session-start
# repair takes the siblings; a developer machine states nothing, the same walk
# reports them and removes none. Neither needs a row, so a retirement leaves no
# licence behind for the next command with a similar path -- which is the whole of
# what those three directions bought.
#
# What stays is the part that was never the table's: a second decider registered
# beside the mediator is refused, on both surface classes. That rule is AGENTS.md's
# own and CLOUD-312 measured the alternative.

# The committed hook surfaces, one per harness in `Harness::ALL` that has one.
#
# `exit-code` has none and is absent on purpose -- it is the neutral contract,
# envelope in and decision as exit status out. Every one of these is tracked, so
# the rule is live on any checkout; a consumer wiring fewer hosts leaves the rest
# in `input.tree.missing` and they contribute nothing.
committed := {
	".claude/settings.json",
	".cursor/hooks.json",
	".github/hooks/batten.json",
	".gemini/settings.json",
	".codex/hooks.json",
}

# The surfaces a host MERGES its hook config from beyond the committed one
# (CLOUD-525), as the ids `[[rule.external]]` declares.
#
# This is the same set `Harness::merge_surfaces` states in the core, and the
# duplication is deliberate rather than a second authority: the core resolves and
# COUNTS them, this names the commands on them, and only a consumer's module may
# hold the table saying which of those are legitimate here (rule 1).
merged_ids := {
	"harness-settings",
	"harness-settings-local",
	"harness-launcher-settings",
	"harness-gemini-settings",
}

# A wiring document's event map.
#
# `else` rather than one body, because the hosts disagree: Claude Code and Gemini
# merge hooks into a settings file that carries much else, and the other three
# define a hooks-only file. Reading `.hooks` where it exists and the whole
# document where it does not is `WiringFile`'s own Key/Whole split, and a module
# that only read `.hooks` would be silently clean over every hooks-only host.
event_map(doc) := m if {
	m := doc.hooks
} else := doc

# Every command registered on a committed surface, with the file it is in.
#
# EVERY EVENT, not `PreToolUse` alone: CLOUD-777 widened the decision from the
# pre-tool point to every point, in its own words because "the entry point is
# every point". A module iterating one event key would pass a Stop sibling while
# looking correct.
commands contains {"path": path, "command": command} if {
	some path in committed
	some _, entries in event_map(input.tree.documents[path])
	some entry in entries
	some hook in entry.hooks
	command := hook.command
}

# Every command on a MERGED surface, reduced to its BASENAME.
#
# NEVER THE PATH, on either field (CLOUD-525 §5). A merged path is under the
# user's home directory, differs per machine, and emitting one would defeat §6
# byte-stability as well as non-negotiable rule 4 -- which is why the merged half
# reports a count where the committed half reports its file.
merged_commands contains basename(command) if {
	some id in merged_ids
	some _, entries in event_map(input.tree.external[id])
	some entry in entries
	some hook in entry.hooks
	command := hook.command
}

basename(command) := parts[count(parts) - 1] if {
	parts := split(command, "/")
}

# A registration that is not the mediator.
#
# `contains` rather than equality, deliberately: the mediator is invoked directly
# since CLOUD-824, but a consumer may still legitimately reach it through a
# pinned wrapper, and the defect being priced is a SECOND decider beside it
# rather than the spelling of the one that is there.
stray(command) if {
	not contains(command, mediator)
}

# One finding per committed file, pointing at the FILE rather than at the command.
#
# The command is what a reader wants and is exactly what must not travel: it
# carries the host's own `$CLAUDE_PROJECT_DIR` prefix and this consumer's
# directory layout, which non-negotiable rule 4 keeps out of a gate's output --
# and the deleted shell's own merged half already reduced its commands to a
# basename for that reason while its committed half did not. The file is a
# tracked path, so the pointer is honest and opening it shows the entry.
violation contains {
	"rule": "harness-wiring",
	"verdict": "hook wire loose",
	"subjects": [{"path": path}, {"count": count(strays_in(path))}],
} if {
	some path in committed
	count(strays_in(path)) > 0
}

strays_in(path) := {command |
	some entry in commands
	entry.path == path
	command := entry.command
	stray(command)
}

# A COUNT and nothing else, for `merged_commands`' reason: there is no path here
# that may be emitted, and the declared id would only tell a reader which
# home-relative file to open on their own machine.
violation contains {
	"rule": "harness-wiring",
	"verdict": "hook wire duplicate",
	"subjects": [{"count": count(merged_strays)}],
} if {
	count(merged_strays) > 0
}

merged_strays contains command if {
	some command in merged_commands
	stray(command)
}

# The could-not-look clause `.claude/rules/policy-modules.md` requires, and it is
# writable now that `input.tree.missing` carries a CAUSE (CLOUD-1309). Until this
# change the channel was an array of names, so a module could see THAT a declared
# surface was not acquired and never WHY -- and the two states have opposite
# meanings here.
#
# `unparsed` ONLY, and the asymmetry is the whole point. A surface that is ABSENT
# is the ordinary case: four of the five committed files are optional (a consumer
# wiring fewer hosts has no `.cursor/hooks.json`) and every merged surface is
# absent on a CI runner. Firing on absence would redden those for a state nobody
# can fix, which is the measured failure the deleted shell's `merged_read` guard
# existed to prevent. A surface that EXISTS and will not parse is a host reading
# nothing at all, and nobody can tell that from a clean wiring without this.
violation contains {
	"rule": "harness-wiring",
	"verdict": "hook wire unread",
	"subjects": [{"count": count(unreadable)}],
} if {
	count(unreadable) > 0
}

unreadable contains name if {
	some name, cause in input.tree.missing
	cause == "unparsed"
	judged(name)
}

judged(name) if {
	name in committed
}

judged(name) if {
	name in merged_ids
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.documents` for this row at all -- a `with input as` case fabricates
# the very shape the engine may be unable to produce (CLOUD-845, CLOUD-857) --
# which is why `crates/batten/tests/it/harness_wiring.rs` exists over the compiled
# binary. CLOUD-1307 is that class landed and live in this module's own sibling.

wired(pre_tool, stop) := {"tree": {"documents": {".claude/settings.json": {"hooks": {
	"PreToolUse": [{"hooks": [{"command": command} | some command in pre_tool]}],
	"Stop": [{"hooks": [{"command": command} | some command in stop]}],
}}}}}

# A merged surface carrying the commands given, under the launcher's id.
launcher(commands) := {"tree": {"external": {"harness-launcher-settings": {"hooks": {"Stop": [{"hooks": [
{"command": command} |
	some command in commands
]}]}}}}}

# Both surface classes at once.
whole(pre_tool, stop, merged) := object.union(wired(pre_tool, stop), launcher(merged))

verdicts := {v.verdict | some v in violation}

mediates := "batten hook --harness claude-code"

# ANTI-VACUITY, and it is THE REPOSITORY'S OWN STATE: the mediator alone on a
# committed surface produces no finding at all. Without it every case below would
# pass just as well over a module that refuses everything.
test_a_correctly_wired_tree_is_clean if {
	count(violation) == 0 with input as wired({mediates}, {mediates})
}

test_a_sibling_beside_the_mediator_is_refused if {
	some v in violation with input as wired(
		{mediates, "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh"},
		{mediates},
	)
	v.verdict == "hook wire loose"
}

# CLOUD-777 widened the decision from `PreToolUse` to every event, and a module
# iterating one event key would pass this while looking correct.
test_a_stop_sibling_is_refused_too if {
	some v in violation with input as wired(
		{mediates},
		{mediates, "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh"},
	)
	v.verdict == "hook wire loose"
}

test_a_pinned_wrapper_around_the_mediator_is_not_a_second_decider if {
	count(violation) == 0 with input as wired({"mise exec -- batten hook"}, {mediates})
}

# The pointer is the FILE, never the command: the command carries this consumer's
# directory layout and the host's own variable prefix.
test_the_finding_points_at_the_file_and_not_the_command if {
	some v in violation with input as wired({"$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh"}, {mediates})
	v.verdict == "hook wire loose"
	v.subjects[0] == {"path": ".claude/settings.json"}
	every subject in v.subjects {
		not subject.command
	}
}

# --- the merged half -----------------------------------------------------------

# The two launcher-provisioned commands. They were `declared` rows keyed to
# CLOUD-1079 until CLOUD-1383, and they are the reason this module could not
# simply refuse a merged sibling: the launcher rewrites them at every session
# start, so no commit in this repository could clear them and tolerating them was
# the only way the gate stayed green.
#
# THE FACT IS WHAT MOVED, NOT THE SUBJECT. They are refused here like any other
# second decider, and a disposable container's session-start repair removes them
# before this gate reads the surface. A developer machine that is not disposable
# keeps them and is TOLD, which is the difference between a report and a licence.
launcher_hooks := {
	"~/.claude/stop-hook-git-check.sh",
	"~/.claude/session-start-git-identity.sh",
}

test_a_merged_registration_beside_the_mediator_is_refused if {
	some v in violation with input as launcher({mediates, "~/.claude/other-hook.sh"})
	v.verdict == "hook wire duplicate"
}

test_the_launcher_hooks_are_refused_rather_than_declared if {
	vs := verdicts with input as launcher(launcher_hooks)
	"hook wire duplicate" in vs
}

test_the_mediator_alone_on_a_merged_surface_is_clean if {
	vs := verdicts with input as launcher({mediates})
	not "hook wire duplicate" in vs
}

# NEVER A PATH on the merged finding, on either field: a merged path is under
# somebody's home directory and differs per machine, so §6 byte-stability and
# non-negotiable rule 4 both forbid it travelling.
test_the_merged_finding_carries_a_count_and_no_pointer if {
	some v in violation with input as launcher({"/home/someone/.claude/other-hook.sh"})
	v.verdict == "hook wire duplicate"
	every subject in v.subjects {
		not subject.path
	}
}

# ANTI-VACUITY over BOTH classes at once, which the committed-only case cannot
# reach: the mediator alone on each surface, so nothing fires.
test_both_surfaces_wired_correctly_is_clean if {
	count(violation) == 0 with input as whole({mediates}, {mediates}, {mediates})
}

# --- could-not-look, per cause -------------------------------------------------
#
# The two arms CLOUD-1309 made writable, and they must stay a PAIR: the `unparsed`
# case alone passes over a module that fires on any membership, and the `absent`
# case alone passes over one that fires on none.

test_a_surface_that_will_not_parse_is_reported if {
	some v in violation with input as {"tree": {"missing": {".claude/settings.json": "unparsed"}}}
	v.verdict == "hook wire unread"
}

test_a_surface_that_is_merely_absent_is_not_reported if {
	vs := verdicts with input as {"tree": {"missing": {".claude/settings.json": "absent"}}}
	not "hook wire unread" in vs
}

test_a_merged_surface_that_will_not_parse_is_reported_too if {
	some v in violation with input as {"tree": {"missing": {"harness-launcher-settings": "unparsed"}}}
	v.verdict == "hook wire unread"
}

# A path this module does not judge is not its business, whatever its cause.
test_an_undeclared_name_in_the_channel_is_not_this_modules_business if {
	vs := verdicts with input as {"tree": {"missing": {"some/other/file.json": "unparsed"}}}
	not "hook wire unread" in vs
}

# A tree carrying nothing at all decides nothing, which is the shape a fixture repo
# has and the one `cli.rs` reads. It abstains rather than reporting a clean wiring.
test_a_tree_with_no_wiring_surface_is_clean if {
	count(violation) == 0 with input as {"tree": {"documents": {}}}
}

#MUTANT-SUITE crates/batten/tests/it/harness_wiring.rs
#MUTANT stray-unread|s@^\tnot contains(command, mediator)$@\tfalse@|a_committed_sibling_beside_the_mediator_is_refused
