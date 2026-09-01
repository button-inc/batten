# METADATA
# description: |
#   The MERGED half of `hooks-wiring-check`'s consumer predicate (CLOUD-1160):
#   a registration on a hook surface the host combines in from OUTSIDE this
#   repository, which no in-tree gate can see.
#
#   A SEPARATE MODULE, AND THAT IS CLOUD-1307 RATHER THAN TASTE. The engine binds
#   one module to one rule, and an absent `[[rule.external]]` source skips its
#   whole rule -- measured 2026-09-01 with an unconditional arm, silent with the
#   source absent and firing with it present. So the committed half cannot share
#   a row with an out-of-root file: on every CI runner, and in this container,
#   that file is absent and the committed predicates would go down with it.
#
#   ONE SURFACE, AND THE OTHER THREE ARE BLOCKED ON THE SAME ROW. The deleted
#   shell read four -- `.claude/settings.json`, `.claude/settings.local.json`,
#   `.claude/launcher-settings.json` and `.gemini/settings.json` -- and counted
#   how many it managed to open. One rule can declare all four, and under
#   CLOUD-1307 it is then off unless ALL four exist, which is never. The launcher
#   surface is the one watched here because it is the one that has ever carried a
#   non-batten registration in this repository's measured history (CLOUD-525,
#   2026-08-21: three `Stop` handlers and four on `SessionStart` while every gate
#   read two and three) and the only one present today. The narrowing is recorded
#   on CLOUD-1160 and restored by CLOUD-1307.
#
#   THE STALE DIRECTION IS NOT HERE, for the same reason. A declared row matching
#   nothing is a licence with no subject, and judging that needs the UNION of the
#   surfaces that were read: with one surface in hand, a command registered on the
#   launcher would read as stale to a module that opened the settings file. The
#   committed half keeps its own stale direction, where the subject is a tracked
#   file and always readable.
#
#   COULD-NOT-LOOK IS THE COMMON CASE and is the engine's: an id whose root
#   variable is unset, or whose file is absent, is named in `input.tree.missing`
#   and this rule is skipped, so the module never runs over a fabricated empty
#   document. That is the same posture the shell took by counting surfaces read.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.harness_wiring_merged

import rego.v1

rules contains "harness-wiring-merged"

# The program every hook registration must resolve to.
#
# A name rather than a full argv: the launcher spells the same registration
# several ways across hosts -- a bare binary, a path, a `mise exec` wrapper --
# and CLOUD-824 records what asking for an exact string bought last time, which
# was a launcher script that resolved the repo root through a second authority
# and allowed every mediated call silently.
mediator := "batten"

# What is provisioned onto the launcher's surface today that should not be, each
# naming the issue that owns its retirement.
#
# THESE ARE NOT COMMITTED FILES AND THIS REPOSITORY CANNOT DELETE THEM
# (CLOUD-525). They are launcher-provisioned under `$HOME`; a previous session's
# `batten wiring reclaim` removed them and the launcher rewrote them at the next
# session start, with identical mtimes. Declaring them is the difference between
# a census and a demand: an ADDED launcher hook becomes visible instead of
# silent, and no run goes red on state this repo cannot fix. CLOUD-1079 is the
# owner action that ends the provisioning, and it is outside every repository.
#
# Named by BASENAME, because a merged command is reported without its directory
# (§5) and matched the same way.
declared := {
	"stop-hook-git-check.sh": "CLOUD-605",
	"session-start-git-identity.sh": "CLOUD-605",
}

# The one declared id this module may read. A path no row declares is unreadable
# here, so this is a projection of a declared set rather than the filesystem scan
# house style §5 and non-negotiable rule 1 both refuse.
surface := "harness-launcher-settings"

# A wiring document's event map.
#
# `else` rather than one body: a host that merges hooks into a settings file
# carrying much else keys them under `hooks`, and a hooks-only file is the map.
# A module reading only `.hooks` would be silently clean over the second shape.
event_map(doc) := m if {
	m := doc.hooks
} else := doc

# Every command on the surface, reduced to its BASENAME.
#
# NEVER THE PATH (CLOUD-525 §5). A merged path is under the user's home
# directory, differs per machine, and emitting one would defeat §6 byte-stability
# as well as non-negotiable rule 4.
commands contains basename(command) if {
	some _, entries in event_map(input.tree.external[surface])
	some entry in entries
	some hook in entry.hooks
	command := hook.command
}

basename(command) := parts[count(parts) - 1] if {
	parts := split(command, "/")
}

# A COUNT and nothing else: there is no path here that may be emitted, and the id
# would only tell a reader which home-relative file to open on their own machine.
violation contains {
	"rule": "harness-wiring-merged",
	"verdict": "hook wire duplicate",
	"subjects": [{"count": count(strays)}],
} if {
	count(strays) > 0
}

# `contains` rather than equality, deliberately: the mediator is invoked directly
# since CLOUD-824, but a consumer may still legitimately reach it through a
# pinned wrapper, and the defect being priced is a SECOND decider beside it
# rather than the spelling of the one that is there.
strays contains command if {
	some command in commands
	not contains(command, mediator)
	every pattern, _ in declared {
		not contains(command, pattern)
	}
}

# A declaration with no owner is worse than none: it reads as a decision someone
# made and records nobody to ask.
#
# The key expression is the registry's `ready-issue-key`, never a literal here.
# BINDING IT FIRST IS THE COULD-NOT-LOOK ARM: where no row is supplied the
# expression is undefined, the body does not hold, and no row is called unowned --
# where an undefined regex read as a failed match would call every row unowned.
violation contains {
	"rule": "harness-wiring-merged",
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

# NO COULD-NOT-LOOK CLAUSE HERE EITHER, and here it is unreachable twice over
# (CLOUD-1308). `input.tree.missing` projects NAMES without causes, so a module
# cannot tell "would not parse" from "not there" -- and under CLOUD-1307 an
# unacquired external skips this whole rule before any predicate runs, so the
# channel never reaches this module at all. A clause reading it would be dead by
# construction, which is worse than an absent one because it reads as coverage.

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.external` at all -- a `with input as` case fabricates the very
# shape the engine may be unable to produce (CLOUD-845, CLOUD-857) -- which is
# why `crates/batten/tests/it/harness_wiring.rs` exists over the compiled binary.

wired(cmds) := {"tree": {"external": {"harness-launcher-settings": {"hooks": {"Stop": [{"hooks": [
{"command": command} |
	some command in cmds
]}]}}}}}

verdicts := {v.verdict | some v in violation}

# ANTI-VACUITY: a surface carrying only the mediator and the declared rows is
# clean. Without it every case below would pass over a module that refuses
# everything.
test_a_correctly_provisioned_surface_is_clean if {
	count(violation) == 0 with input as wired({
		"batten hook --harness claude-code",
		"~/.claude/stop-hook-git-check.sh",
		"~/.claude/session-start-git-identity.sh",
	})
}

test_a_second_decider_is_refused if {
	some v in violation with input as wired({
		"batten hook --harness claude-code",
		"~/.claude/some-other-hook.sh",
	})
	v.verdict == "hook wire duplicate"
}

test_a_pinned_wrapper_around_the_mediator_is_not_a_second_decider if {
	count(violation) == 0 with input as wired({"mise exec -- batten hook --harness claude-code"})
}

# The id is the only handle a module has, so asking for another one answers
# nothing -- the negative half of the fact, stated where a reader will meet it.
test_an_undeclared_id_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"external": {"some-other-id": {"hooks": {"Stop": [{"hooks": [{"command": "~/.claude/some-other-hook.sh"}]}]}}}}}
}

# The declaration excuses the command it names and only that one: an excuse is
# worth nothing unless it is narrow.
test_a_declared_command_is_excused_and_an_undeclared_one_is_not if {
	count(violation) == 0 with input as wired({"~/.claude/stop-hook-git-check.sh"})
	some v in violation with input as wired({"~/.claude/some-other-hook.sh"})
	v.verdict == "hook wire duplicate"
}

# NO PATH TRAVELS, on either field. The finding carries a count and nothing else,
# so a reader of the output learns nothing about the layout of somebody's home.
test_the_finding_carries_a_count_and_no_pointer if {
	some v in violation with input as wired({"/home/someone/.claude/some-other-hook.sh"})
	v.verdict == "hook wire duplicate"
	every subject in v.subjects {
		not subject.path
	}
}

#MUTANT-SUITE crates/batten/tests/it/harness_wiring.rs
#MUTANT stray-unread|s@^\tnot contains(command, mediator)$@\tfalse@|a_merged_registration_the_table_does_not_declare_is_refused
