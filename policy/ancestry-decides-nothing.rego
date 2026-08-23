# Merged-ness is decided by patch identity, never by reachability (CLOUD-36).
#
# THE MIGRATION CLOUD-756 ASKS FOR, and the scan it replaces is deleted in the
# same change — `git.rs`'s `no_ancestry_decides_merged_ness`. A module landing
# beside a scan it does not delete is two authorities on one property, which is
# the accretion that row exists to stop.
#
# WHY THIS GUARD, OUT OF THE SEVEN. It is the one this session measured wrong.
# The substring scan fired FOUR times on prose written while implementing
# CLOUD-914 and CLOUD-762 — a doc comment describing the gate, and three parser
# comments naming an example — at no call site at all. Every one was a false
# positive, and each was "fixed" by rewording English until the scanner stopped
# noticing, which is the tell that the instrument was wrong rather than the text.
#
# WHAT CHANGES, STATED IN BOTH DIRECTIONS SO THE TRADE IS LEGIBLE.
#
#   GAINED: position. A token in a comment, in a doc example, or in this rule's
#   own text is not a decision and no longer reads as one. That removes the
#   obfuscation the scan needed — its needles were assembled by `.concat()` "so
#   this test's own source is not a match", a workaround this makes unnecessary.
#
#   LOST: a literal bound to a variable before it is passed. `let t =
#   "..."; query(&repo, &[t])` reaches the call as a name, not a literal, and is
#   invisible here where the scan would have caught the binding. The scan's own
#   comment already conceded smuggling is possible -- "hand-writing a graph walk,
#   which is a different and far more visible change" -- so this narrows an
#   evasion that was never closed, rather than opening one that was.
#
# THE RANGE FORMS STAY LEGAL, unchanged from the scan: selecting which commits to
# hash is allowed, deciding with the result is not.

# METADATA
# description: |
#   Bound to the TREE surface: `scope = "tree"`, reading call sites rather than
#   the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.ancestry

import rego.v1

rules contains "ancestry-decides-nothing"

# The reachability-ANSWER surface, spelled plainly. A Rego string is not Rust
# source, so this file is not its own corpus and needs none of the scan's
# `.concat()` obfuscation -- which is the clearest single symptom of the tier
# change.
reachability_answers := {
	"merge-base",
	"merge_base",
	"is-ancestor",
	"is_ancestor",
	"--contains",
	"--ancestry-path",
}

violation contains {
	"rule": "ancestry-decides-nothing",
	"msg": sprintf(
		"%s:%d passes '%s' in command position; merged-ness is decided by patch identity, never by reachability (CLOUD-36) — a rebased landing is invisible to ancestry",
		[path, site.line, token],
	),
} if {
	some path, sites in input.tree.invocations
	some site in sites
	some argument in site.arguments
	some token in reachability_answers
	contains(argument, token)
}

# A reachability verb in a COMMENT is not a decision, and asserting that is the
# whole point of the migration -- it is the case the retired scan got wrong four
# times in one session. Comments never reach the fact, so the case is spelled as
# an invocation-free file.
test_prose_naming_the_verb_is_not_a_decision if {
	count(violation) == 0 with input as {"tree": {"invocations": {"crates/batten/src/facts.rs": []}}}
}

test_the_verb_in_command_position_is_refused if {
	some v in violation with input as {"tree": {"invocations": {"crates/batten/src/worktree.rs": [{
		"program": "arg",
		"arguments": ["merge-base"],
		"line": 88,
	}]}}}
	v.rule == "ancestry-decides-nothing"
}

test_every_spelling_is_refused if {
	count(violation) == 6 with input as {"tree": {"invocations": {"crates/batten/src/x.rs": [{
		"program": "args",
		"arguments": [
			"merge-base",
			"merge_base",
			"is-ancestor",
			"is_ancestor",
			"--contains",
			"--ancestry-path",
		],
		"line": 3,
	}]}}}
}

# THE ALLOW HALF, and it is load-bearing: a rule that refused every git argument
# would satisfy the denies above and ban the range forms the scan deliberately
# permits. Selecting which commits to hash is allowed.
test_a_range_form_stays_legal if {
	count(violation) == 0 with input as {"tree": {"invocations": {"crates/batten/src/git.rs": [{
		"program": "args",
		"arguments": ["rev-list", "--not", "origin/main..HEAD"],
		"line": 12,
	}]}}}
}

test_an_ordinary_call_is_not_judged if {
	count(violation) == 0 with input as {"tree": {"invocations": {"crates/batten/src/git.rs": [{
		"program": "new",
		"arguments": ["git"],
		"line": 5,
	}]}}}
}

# GIT.RS IS JUDGED TOO, unchanged from the scan: the decision logic lives there,
# so exempting it would gut the gate.
test_this_modules_own_file_is_not_exempt if {
	count(violation) == 1 with input as {"tree": {"invocations": {"crates/batten/src/git.rs": [{
		"program": "arg",
		"arguments": ["--contains"],
		"line": 40,
	}]}}}
}

#MUTANT-EXEMPT CLOUD-931|a policy module has no bats suite for `mutant` to turn red: `batten policy test` is wired to no task, so its six cases cannot be reached by the mutation runner
