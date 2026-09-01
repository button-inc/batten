# METADATA
# description: |
#   The successor shape for `hooks-wiring-check` (CLOUD-1160), and the
#   demonstration CLOUD-1167 owes: a tree-scoped module deciding over a file that
#   lives OUTSIDE the repository root.
#
#   The predicate is AGENTS.md's own: `PreToolUse` is ONE entry, the engine.
#   CLOUD-312 measured the alternative -- six `mise run` launches per Bash call,
#   1.247s serial to do milliseconds of policy -- so a second registration beside
#   `batten hook` is a defect rather than a preference, and it is invisible to
#   every in-tree gate because the merged wiring the launcher actually reads is
#   assembled under the user's own home directory.
#
#   WHAT MAKES THIS EXPRESSIBLE AT ALL is `input.tree.external`: the row declares
#   ONE id, resolved beneath ONE named environment variable, and this module can
#   read that id and nothing else. A path no row declares is unreadable here, so
#   this is a projection of a declared set rather than the filesystem scan house
#   style §5 and non-negotiable rule 1 both refuse.
#
#   COULD-NOT-LOOK IS THE COMMON CASE and is handled by the engine rather than
#   here: an id whose root variable is unset, or whose file is absent, is named in
#   `input.tree.missing` and the row is skipped, so this module never runs over a
#   fabricated empty document. That is the whole reason the fact keeps `absent`
#   and `root-unset` apart -- a host that has no launcher at all must not read as
#   a host wired correctly.
#
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.harness_wiring

import rego.v1

rules contains "harness-wiring"

# The program every `PreToolUse` registration must resolve to.
#
# A name rather than a full argv: the launcher spells the same registration
# several ways across hosts -- a bare binary, a path, a `mise exec` wrapper --
# and CLOUD-824 records what asking for an exact string bought last time, which
# was a launcher script that resolved the repo root through a second authority
# and allowed every mediated call silently.
mediator := "batten"

# Every `PreToolUse` hook command the launcher's merged wiring declares.
#
# Reaches into the declared file's parsed node and nowhere else. `input.tree` is
# repo-rooted for every other family; this one is the declared id, and the id is
# all a module ever sees -- never the path it resolved to on this machine.
registrations contains command if {
	some entry in input.tree.external["harness-settings"].hooks.PreToolUse
	some hook in entry.hooks
	command := hook.command
}

# A registration that does not reach the engine.
#
# `contains` rather than equality, deliberately: the mediator is invoked directly
# since CLOUD-824, but a consumer may still legitimately reach it through a
# pinned wrapper, and the defect being priced is a SECOND decider beside it
# rather than the spelling of the one that is there.
violation contains {
	"rule": "harness-wiring",
	"verdict": "V-HARNESS-WIRING-SECOND-DECIDER",
	"subjects": [{"count": count(strays)}],
} if {
	count(strays) > 0
}

strays contains command if {
	some command in registrations
	not contains(command, mediator)
}

# --- the load-time tier ------------------------------------------------------
#
# These pin the PREDICATE. They cannot pin that the ENGINE builds
# `input.tree.external` at all -- a `with input as` case fabricates the very
# shape the engine may be unable to produce (CLOUD-845, CLOUD-857) -- which is
# why `crates/batten/tests/external_facts.rs` exists over the compiled binary.

wiring(commands) := {"tree": {"external": {"harness-settings": {"hooks": {"PreToolUse": [{"hooks": [
{"command": command} |
	some command in commands
]}]}}}}}

test_the_engine_alone_is_clean if {
	count(violation) == 0 with input as wiring({"batten hook --harness claude-code"})
}

test_a_second_decider_is_refused if {
	some v in violation with input as wiring({
		"batten hook --harness claude-code",
		"mise run some-other-guard",
	})
	v.verdict == "V-HARNESS-WIRING-SECOND-DECIDER"
}

test_a_pinned_wrapper_around_the_mediator_is_not_a_second_decider if {
	count(violation) == 0 with input as wiring({"mise exec -- batten hook --harness claude-code"})
}

# The id is the only handle a module has, so asking for another one answers
# nothing -- the negative half of the fact, stated where a reader of this module
# will meet it.
test_an_undeclared_id_answers_nothing if {
	count(violation) == 0 with input as {"tree": {"external": {"some-other-id": {"hooks": {"PreToolUse": [{"hooks": [{"command": "mise run some-other-guard"}]}]}}}}}
}

#MUTANT-SUITE crates/batten/tests/external_facts.rs
#MUTANT-OWNER CLOUD-845|the tier this module names drives `input.tree.external` and never installs the module, so no case in it can turn red under a mutation of the predicate
#MUTANT stray-unread|s@^\tcount(strays) > 0$@\tfalse@|a_declared_out_of_root_file_is_read_and_decided_over
