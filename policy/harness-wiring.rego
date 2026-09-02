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

# What is wired today that should not be, naming the issue that owns its
# retirement. This is the gate going red on the state it exists to refuse -- one
# that shipped already-green over it would be a gate nothing can fail -- with the
# current registration recorded rather than tolerated silently.
#
# THREE rules keep the table from becoming a permanent exemption, and all three
# are predicates below rather than prose: a row naming no issue is itself a
# refusal (`unowned`), a row matching nothing wired is a refusal too (`stale`),
# and a row whose issue has CLOSED is a refusal as well (`spent`) -- so a
# retirement that lands must delete its row rather than leave a licence behind
# for the next command with a similar path.
#
# THE THIRD ONE WAS MISSING AND ALL THREE ROWS WERE IN THE STATE IT REFUSES.
# Measured 2026-09-02: `run-shape-guard.sh` named CLOUD-821 (Done 2026-08-28) and
# both merged rows named CLOUD-605 (Done 2026-08-23). `hooks-wiring-check` used to
# hold that direction from a `get_issue` payload a caller piped in; a tree-scoped
# module has no stdin, so CLOUD-1160 retired the predicate with no successor and
# nothing has watched it since. CLOUD-1310's `input.tree.minted` is the successor.
#
# The re-pointed owners are each the issue that owns the REMOVAL rather than the
# one that recorded something about it -- the distinction the CLOUD-605 rows got
# wrong. That issue closed by recording a PRECEDENCE (non-negotiable rule 8), which
# stops the hook's remedy from being followed and cannot remove a program living
# outside this repository.
#
# AND THE FIRST ROW WAS RE-POINTED TWICE, because the first attempt made the same
# mistake one row over. It named CLOUD-1108 as "the open row that owns why this
# guard cannot move yet" -- a blocker that row had already WITHDRAWN. Its
# re-derivation of 2026-08-31 says its own measured instance is discharged: all
# four families have a landed Rego successor (`policy/run-shape.rego` raises three,
# `policy/task-substitution.rego` the fourth), so the file is deletable WHOLE,
# which is the ratchet's one admitted disposition. Citing it here would have
# restated a blocker its own body refutes -- CLOUD-1166's class, which is
# classifying a blocker instead of reading it.
#
# CLOUD-1163 owns the deletion, as its unit 9, and is In Progress. Its own §1 says
# each of its eight units "lands as its own PR with its own ledger arms", and its
# §2 refuses merging two units because that "would manufacture the glue this
# partition exists to avoid" -- so this row points at that unit rather than being
# discharged here.
declared := {
	"mise-tasks/run-shape-guard.sh": "CLOUD-1163",
	"stop-hook-git-check.sh": "CLOUD-1314",
	"session-start-git-identity.sh": "CLOUD-1314",
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

# THE THIRD DIRECTION (CLOUD-1310): a row whose owning issue has CLOSED.
#
# `stale` catches a licence whose SUBJECT is gone. This catches one whose OWNER is
# gone, which is the same permanent exemption arriving by the route `stale` cannot
# see: the command is still wired, so the row matches something, and the issue that
# was going to retire it has shipped. All three rows of this table were in exactly
# that state when this predicate was written, which is why it is here rather than
# in a follow-up.
#
# `input.tree.minted` is a field of a receipt the MEDIATED boundary already wrote
# when somebody read the issue -- the engine fetches nothing and this module cannot
# make it. That is the whole reason this is decidable on the tree surface at all.
violation contains {
	"rule": "harness-wiring",
	"verdict": "hook declare spent",
	"subjects": [{"count": count(spent)}],
} if {
	count(spent) > 0
}

# ABSENT IS COULD-NOT-LOOK, AND HERE IT IS THE ORDINARY STATE. The receipt store
# is under the git directory, is never committed, and is empty on every CI runner
# and every fresh clone -- so a key nobody has read simply does not appear, the
# body does not hold, and the row is not called spent. Reading that absence as
# "the owner is open" would be the false green this fact family exists to refuse,
# and reading it as spent would redden every runner for a state nobody can fix.
#
# Binding the expression FIRST is `unowned`'s could-not-look arm for the same
# reason: an undefined pattern must abstain rather than match nothing, which would
# call every row's owner open.
spent contains pattern if {
	some pattern, key in declared
	expression := data.batten.patterns["closed-issue-status"]
	status := input.tree.minted["issue-status"][key]
	regex.match(expression, status)
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

# --- the merged half -----------------------------------------------------------

merged_declared := {
	"~/.claude/stop-hook-git-check.sh",
	"~/.claude/session-start-git-identity.sh",
}

test_a_merged_registration_the_table_does_not_declare_is_refused if {
	some v in violation with input as launcher({mediates, "~/.claude/other-hook.sh"})
	v.verdict == "hook wire duplicate"
}

test_a_declared_merged_command_is_excused_and_an_undeclared_one_is_not if {
	vs := verdicts with input as launcher(merged_declared)
	not "hook wire duplicate" in vs
	some v in violation with input as launcher({"~/.claude/other-hook.sh"})
	v.verdict == "hook wire duplicate"
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

# THE COULD-NOT-LOOK GUARD, PER SURFACE CLASS. A merged row is unenforced where no
# merged surface was read -- the permanent state of a CI runner -- and is judged
# where one was.
test_a_merged_row_is_unenforced_where_no_merged_surface_was_read if {
	vs := verdicts with input as wired({mediates, guard}, {mediates})
	not "hook declare stale" in vs
}

test_a_merged_row_matching_nothing_is_stale_once_a_surface_was_read if {
	some v in violation with input as launcher({mediates})
	v.verdict == "hook declare stale"
}

# ANTI-VACUITY over BOTH classes at once, which the committed-only case cannot
# reach: every declared row matches on the surface that owns it, so nothing fires.
test_both_surfaces_wired_correctly_is_clean if {
	count(violation) == 0 with input as whole({mediates, guard}, {mediates}, merged_declared)
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

# --- the owner's status (CLOUD-1310) -------------------------------------------
#
# THE THREE CASES MUST STAY A SET. The closed case alone passes over a module that
# fires on any status; the open case alone passes over one that fires on none; and
# without the unread case a module that treats a missing reading as closed looks
# correct here while reddening every CI runner.

# One receipt reading, as the engine projects it: id -> subject -> token.
read(status) := {"tree": {"minted": {"issue-status": {"CLOUD-1314": status}}}}

test_a_row_whose_owner_has_closed_is_spent if {
	some v in violation with input as read("done")
	v.verdict == "hook declare spent"
}

# `canceled` and `duplicate` close a row's owner as surely as `done` does: an
# exemption waiting on work that was abandoned or folded into another issue is
# waiting on nothing.
test_an_abandoned_or_folded_owner_closes_the_row_too if {
	some v in violation with input as read("canceled")
	v.verdict == "hook declare spent"
	some w in violation with input as read("duplicate")
	w.verdict == "hook declare spent"
}

test_a_row_whose_owner_is_open_is_not_spent if {
	vs := verdicts with input as read("in-progress")
	not "hook declare spent" in vs
}

# COULD-NOT-LOOK, and it is the ORDINARY state: the receipt store is per-checkout
# and empty on every runner and every fresh clone. A module reading that absence
# as closed would redden everywhere for a state nobody can fix.
test_a_row_nobody_has_read_the_owner_of_is_not_spent if {
	vs := verdicts with input as {"tree": {"minted": {"issue-status": {}}}}
	not "hook declare spent" in vs
}

# And the whole fact absent, which is what a run declaring no mint produces.
test_no_reading_at_all_is_not_spent if {
	vs := verdicts with input as {"tree": {"documents": {}}}
	not "hook declare spent" in vs
}

#MUTANT-SUITE crates/batten/tests/it/harness_wiring.rs
#MUTANT stray-unread|s@^\tnot contains(command, mediator)$@\tfalse@|a_committed_sibling_the_table_does_not_declare_is_refused
#MUTANT stale-unguarded|s@^\tcommitted_read > 0$@\ttrue@|a_tree_with_no_wiring_surface_is_not_stale
#MUTANT stale-never|s@^\tnot matches_something(pattern)$@\tfalse@|a_committed_row_matching_nothing_is_stale
#MUTANT spent-never|s@^\tregex.match(expression, status)$@\tfalse@|a_row_whose_owner_has_closed_is_spent
