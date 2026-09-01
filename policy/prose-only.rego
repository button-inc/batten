# A branch whose whole diff is comments buys a CI matrix that confirms nothing
# (CLOUD-827, ported under CLOUD-1051).
#
# THE ECONOMY IS ALREADY WRITTEN DOWN, which is what makes this an omission
# rather than a new opinion. AGENTS.md: "Local execution — bash, a build, the
# whole test suite — costs nothing... A CI run costs real minutes." `ci.yml`'s
# own header names the two economies it implements — drafts run nothing, and
# `main` is not a trigger. This is the third: a change CI cannot have an opinion
# about should ride the next change that it can.
#
# WHY THIS IS NOT "COMMENTS ARE FREE", which would be wrong here. A comment in
# this repository can change a verdict: `spec-ref-check` resolves `CLOUD-<n> §N`
# citations in tracked files, `rules-drift` holds restated defaults against their
# mechanisms. Every one of those runs in `verify`, locally, for free. That is
# precisely why the economy HOLDS rather than fails: if a comment change breaks
# one, the author learns before a runner is spent.
#
# WHAT THE PORT CHANGED, and it is a repair rather than a move (CLOUD-1051).
# The shell gate classified `git diff --unified=0`'s `+`/`-` lines one at a time,
# which reads a moved block of code as changed lines on both sides and mistakes a
# reflowed comment for code whenever a line straddles a boundary. The engine
# compares REMAINDERS instead — strip every comment and blank line from each side
# and ask whether what is left is byte-identical — so `input.tree["base-delta"]`
# hands this module a decided set and the predicate below is three conjuncts over
# it. `git.rs`'s `code_changed` carries the reasoning for the acquisition half.
#
# THE SECOND CHANGE IS DELETIONS. The shell dropped them wholesale
# (`--diff-filter=d`) because it could not classify a file with no surviving
# lines, and its own header records the cost: a branch deleting a module would
# have read as a comment change if they were admitted. Remainders classify them —
# deleting a module differs, deleting a pure-prose file does not — so the blanket
# exclusion is gone and the case it was protecting against is still refused.
#
# THE `tests/` CONJUNCT IS WHAT MAKES THE GOOD CASE PASS, and it is the difference
# between pricing batching and obstructing doc work. A change that adds or edits a
# test is not prose-only, so a doc rewrite PLUS the gate that enforces it is
# admitted while the follow-up carrying only the prose is not.
#
# COULD-NOT-LOOK IS NOT A REFUSAL. `input.tree["base-delta"]` is `null` when the
# base rev does not resolve, and Rego reads an undefined path as *does not hold*,
# so this module simply says nothing. That is the shell's `exit 0` on an
# unresolvable base, kept: a gate that blocked landing because it failed to
# compute a diff would be a worse defect than the matrix it is trying to save.
#MUTANT-SUITE crates/batten/tests/it/prose_only.rs
# THE CASE IS A DENY-SIDE ONE, and the first spelling of these rows was not.
# Both mutations STOP the rule firing, so a case asserting the branch is
# ADMITTED stays green under them — measured, both survived. A mutation is
# only evidence against the case its own direction can redden.
#MUTANT code-change-unread|s@^\tcount(code_changed) == 0$@\tfalse@|a_branch_whose_whole_diff_is_comment_lines_is_refused
#MUTANT changed-set-unread|s@^\tcount(changed) > 0$@\tfalse@|a_branch_whose_whole_diff_is_comment_lines_is_refused

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads the tree
#   document and never the mediated `{call, facts}` shape.
#   THE BRACKETS ARE NOT STYLE: the schema file carries a hyphen, so the dotted
#   form is a parse error reported as `invalid schema reference` rather than as a
#   missing bind, and an unbound module type checks as `Any`.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`:
#   OPA parses the whole contiguous block that starts the annotation, so prose
#   placed after it reaches the YAML parser and the module fails to load.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.prose_only

import rego.v1

rules contains "prose-only"

# Every path this branch touched, whichever way it moved.
changed := array.concat(
	array.concat(
		object.get(input.tree, ["base-delta", "added"], []),
		object.get(input.tree, ["base-delta", "edited"], []),
	),
	object.get(input.tree, ["base-delta", "deleted"], []),
)

# The paths whose non-comment content moved. The engine decided this; see the
# header for why the classification is acquisition rather than predicate.
code_changed := object.get(input.tree, ["base-delta", "code-changed"], [])

# A changed path under `tests/`. One is enough — the conjunct is about whether
# CI has anything to say, and a single test change means it does.
#
# NOT NAMED `test_touched`, which is what it was called first: `batten policy
# test` collects every rule whose name starts with `test_`, so the helper was
# read as a case, evaluated with no input, and reported as a failure. A helper in
# this corpus may not carry that prefix, and the runner is right to be literal
# about it — a convention it interpreted loosely would let a real case be skipped
# for being misnamed.
touches_a_test if {
	some path in changed
	startswith(path, "tests/")
}

# THE REFUSAL. Three conjuncts, each of which alone would make the gate wrong in
# a different direction: without the first it fires on an empty branch, without
# the second it fires on every change, without the third it blocks the doc
# rewrite that ships with its own test.
violation contains {
	"rule": "prose-only",
	"verdict": "V-PROSE-ONLY-DIFF",
	"subjects": [{"count": count(changed)}],
} if {
	count(changed) > 0
	count(code_changed) == 0
	not touches_a_test
}

# The predicate's own tests. The ALLOW cases are the load-bearing half: a rule
# that fired on everything would satisfy the deny below and gate nothing.

judging(delta) := {"tree": {"base-delta": delta}}

test_a_comment_only_branch_with_no_test_change_is_refused if {
	some v in violation with input as judging({
		"added": [],
		"edited": ["crates/batten/src/git.rs"],
		"deleted": [],
		"code-changed": [],
	})
	v.verdict == "V-PROSE-ONLY-DIFF"
}

# THE CONJUNCT THAT MAKES DOC WORK POSSIBLE. Same diff plus a test, and the gate
# says nothing — which is the difference between pricing batching and obstructing
# the change that documents a gate and ships it.
test_a_comment_change_plus_a_test_change_is_admitted if {
	count(violation) == 0 with input as judging({
		"added": [],
		"edited": ["crates/batten/src/git.rs", "tests/prose-only.bats"],
		"deleted": [],
		"code-changed": [],
	})
}

test_a_code_change_is_not_prose_only if {
	count(violation) == 0 with input as judging({
		"added": [],
		"edited": ["crates/batten/src/git.rs"],
		"deleted": [],
		"code-changed": ["crates/batten/src/git.rs"],
	})
}

# An empty branch has nothing to price, and refusing one would fire on every
# freshly-cut branch before a line is written.
test_an_empty_branch_is_not_a_subject if {
	count(violation) == 0 with input as judging({
		"added": [],
		"edited": [],
		"deleted": [],
		"code-changed": [],
	})
}

# DELETIONS ARE CLASSIFIED NOW, and these two are the pair that shows it. The
# shell could do neither: it dropped every deletion, so both of these read alike.
test_deleting_a_module_is_not_prose_only if {
	count(violation) == 0 with input as judging({
		"added": [],
		"edited": [],
		"deleted": ["crates/batten/src/gone.rs"],
		"code-changed": ["crates/batten/src/gone.rs"],
	})
}

test_deleting_a_pure_prose_file_is_prose_only if {
	some v in violation with input as judging({
		"added": [],
		"edited": [],
		"deleted": ["NOTES.md"],
		"code-changed": [],
	})
	v.verdict == "V-PROSE-ONLY-DIFF"
}

# COULD-NOT-LOOK SAYS NOTHING. An unresolvable base is `null`, and reading it as
# an empty delta would be the vacuous pass — except here the vacuous direction is
# a refusal, which is worse: the branch would be blocked over a question the
# engine could not ask.
test_an_unresolvable_base_is_silent if {
	count(violation) == 0 with input as {"tree": {"base-delta": null}}
}

# The pointer is a COUNT, never the paths (non-negotiable rule 4). A diff is
# content someone has not published yet, and the branch's own file list is
# exactly that.
test_the_finding_carries_a_count_and_no_path if {
	some v in violation with input as judging({
		"added": [],
		"edited": ["a.md", "b.md"],
		"deleted": [],
		"code-changed": [],
	})
	v.subjects == [{"count": 2}]
}
