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
#   COULD-NOT-LOOK IS PER SURFACE CLASS, which is what the deleted shell counted
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

# What is wired today that should not be, naming the issue that owns its
# retirement. This is the gate going red on the state it exists to refuse -- one
# that shipped already-green over it would be a gate nothing can fail -- with the
# current registration recorded rather than tolerated silently.
#
# Two rules keep the table from becoming a permanent exemption, and both are
# predicates below rather than prose: a row naming no issue is itself a refusal
# (`unowned`), and a row matching nothing wired is a refusal too (`stale`), so a
# retirement that lands must delete its row rather than leave a licence behind
# for the next command with a similar path.
declared := {
	"mise-tasks/run-shape-guard.sh": "CLOUD-821",
	"stop-hook-git-check.sh": "CLOUD-605",
	"session-start-git-identity.sh": "CLOUD-605",
}

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

# How many merged surfaces were actually READ.
#
# Zero is COULD-NOT-LOOK, not "nothing is registered there": most machines carry
# no launcher file and a CI runner never does. Only `stale` turns on it.
merged_read := count([id |
	some id in merged_ids
	input.tree.external[id]
])

# A registration that is neither the mediator nor declared.
#
# `contains` rather than equality, deliberately: the mediator is invoked directly
# since CLOUD-824, but a consumer may still legitimately reach it through a
# pinned wrapper, and the defect being priced is a SECOND decider beside it
# rather than the spelling of the one that is there.
stray(command) if {
	not contains(command, mediator)
	every pattern, _ in declared {
		not contains(command, pattern)
	}
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

# A declaration with no owner is worse than none: it reads as a decision someone
# made and records nobody to ask.
#
# The key expression is the registry's `ready-issue-key`, never a literal here: a
# tracker's vocabulary is the consumer fact `[[pattern]]` exists to give one home,
# and every other gate that recognises a key reads the same row.
#
# BINDING IT FIRST IS THE COULD-NOT-LOOK ARM. Where no row is supplied the
# expression is undefined, the body does not hold, and no row is called unowned --
# where an undefined regex read as a failed match would call every declared row
# unowned, which is a verdict about the registry dressed as one about the table.
violation contains {
	"rule": "harness-wiring",
	"verdict": "hook declare unnamed",
	"subjects": [{"count": count(unowned)}],
} if {
	count(unowned) > 0
}

unowned contains pattern if {
	some pattern, key in declared
	expression := data.batten.patterns["ready-issue-key"]
	not regex.match(expression, key)
}

# How many committed wiring surfaces were actually READ.
#
# Zero is COULD-NOT-LOOK, not "nothing is wired here". `stale` is the only
# predicate whose verdict turns on it, for the reason recorded there.
committed_read := count([path |
	some path in committed
	input.tree.documents[path]
])

# The other direction: a declared row that matches nothing wired. Without it the
# table only ever grows, and a retirement leaves behind a licence that the next
# command with a similar path inherits silently.
#
# UNENFORCED WHERE NO SURFACE WAS READ, and this guard is the one the deleted
# shell carried as `merged_read` and this module lost when the merged half moved
# out. Measured 2026-09-01: without it, `cli.rs`'s fixture repos -- which carry no
# `.claude/settings.json` at all -- reported `1 harness-wiring`, because a
# declaration matches nothing in a tree where nothing was looked at. That is
# could-not-look rendered as a spent licence, which is the collapse the whole
# `missing` channel exists to prevent.
violation contains {
	"rule": "harness-wiring",
	"verdict": "hook declare stale",
	"subjects": [{"count": count(stale)}],
} if {
	count(stale) > 0
}

stale contains pattern if {
	some pattern, _ in declared
	enforced(pattern)
	not matches_something(pattern)
}

# A COMMITTED row (it carries a `/`) is judged where a committed surface was read;
# a MERGED row (a basename) where a merged surface was. The discriminator is the
# shape the table already uses, so it is one already earning its keep rather than
# a second list to keep in step.
enforced(pattern) if {
	contains(pattern, "/")
	committed_read > 0
}

enforced(pattern) if {
	not contains(pattern, "/")
	merged_read > 0
}

matches_something(pattern) if {
	some entry in commands
	contains(entry.command, pattern)
}

matches_something(pattern) if {
	some command in merged_commands
	contains(command, pattern)
}

# THERE IS NO COULD-NOT-LOOK CLAUSE, AND THAT IS A SURFACE LIMIT RATHER THAN AN
# OMISSION (CLOUD-1308). `.claude/rules/policy-modules.md` requires one and says
# the causes stay distinct so "a policy cannot mistake 'could not parse' for 'not
# there'". The PROJECTION drops that: `input.tree.missing` is an array of NAMES,
# per `schema/policy-input.schema.json`, so a module sees that a declared path was
# not acquired and never why.
#
# That makes the clause unwritable here rather than merely awkward. Four of the
# five surfaces above are optional -- a consumer wiring fewer hosts has no
# `.cursor/hooks.json` -- so a clause firing on membership would redden every such
# consumer for the ordinary case, which is the state nobody can fix that this
# module's merged sibling is careful to leave alone. Measured on the way in: an
# object-shaped clause here type-checked as dead under `opa check` and its
# load-time cases passed anyway, because `with input as` fabricates the object the
# engine does not build.
#
# The engine still records the abstention as `RuleSkipped`, so CLOUD-251's "never
# an empty deny set" holds. What is lost is this module SAYING so, and that is
# CLOUD-1308's to restore by projecting the cause.

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

# Both surface classes at once, which is the only shape that can exercise the
# STALE union: the table declares one committed row and two merged ones, and each
# is judged only where its own surface class was read.
whole(pre_tool, stop, merged) := object.union(wired(pre_tool, stop), launcher(merged))

verdicts := {v.verdict | some v in violation}

mediates := "batten hook --harness claude-code"

guard := "$CLAUDE_PROJECT_DIR/mise-tasks/run-shape-guard.sh"

# ANTI-VACUITY. A correctly wired tree produces no finding at all -- without this
# every case below would pass just as well over a module that refuses everything.
test_a_correctly_wired_tree_is_clean if {
	count(violation) == 0 with input as wired({mediates, guard}, {mediates})
}

test_an_undeclared_sibling_is_refused if {
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
		{mediates, guard},
		{mediates, "$CLAUDE_PROJECT_DIR/mise-tasks/other-guard.sh"},
	)
	v.verdict == "hook wire loose"
}

test_a_pinned_wrapper_around_the_mediator_is_not_a_second_decider if {
	count(violation) == 0 with input as wired({"mise exec -- batten hook", guard}, {mediates})
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

test_a_declaration_matching_nothing_is_stale if {
	some v in violation with input as wired({mediates}, {mediates})
	v.verdict == "hook declare stale"
}

# The guard's own case, and the one whose absence `cli.rs` caught: a tree that
# carries no wiring surface at all has not spent its declaration, it has not been
# looked at.
test_a_tree_with_no_wiring_surface_is_not_stale if {
	vs := verdicts with input as {"tree": {"documents": {}}}
	not "hook declare stale" in vs
}

test_a_declaration_matching_something_is_not_stale if {
	vs := verdicts with input as wired({mediates, guard}, {mediates})
	not "hook declare stale" in vs
}

#MUTANT-SUITE crates/batten/tests/it/harness_wiring.rs
#MUTANT stray-unread|s@^\tnot contains(command, mediator)$@\tfalse@|a_committed_sibling_the_table_does_not_declare_is_refused
#MUTANT stale-unguarded|s@^\tcommitted_read > 0$@\ttrue@|a_tree_with_no_wiring_surface_is_not_stale
#MUTANT stale-never|s@^\tnot matches_something(pattern)$@\tfalse@|a_committed_row_matching_nothing_is_stale
