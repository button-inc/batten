#!/usr/bin/env bats
# subject: mise-tasks/claims-cite-check.sh
# The gate that ships with the "cite it or soften it" rule (AGENTS.md
# non-negotiable 2, rules/scanning.md, CLOUD-1703). The defect it answers is a
# claim promoted from an inference and never checked, which then became
# load-bearing for three further designs; its one mechanical tell was that it
# cited nothing while every neighbouring claim cited a `file:line`.
#
# Driven against fixture trees, because the property under test is what the gate
# does to an UNCITED absolute and the committed tree must never contain one for
# it to find. The committed tree is asserted too, and that row is the regression
# test for the workspace itself.
#
# THE ANTI-VACUITY ROW IS THE DELTA ONE. A gate that reddens the whole tree on
# day one is bypassed and then decides nothing, so "an existing uncited absolute
# the delta does not touch is not a finding" is a property, not an omission —
# and it is the row that fails if the scan is ever widened to the whole file.

setup() {
	load helpers
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/claims-cite-check.sh"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/crates/batten/src"
	cd "$REPO" || return 1
	git init -q .
	git config user.email t@example.com
	git config user.name t
	printf 'fn main() {}\n' >"$REPO/crates/batten/src/lib.rs"
	git add -A
	git commit -qm base
	BASE="$(git rev-parse HEAD)"
}

# Appends to the tracked source and stages it, so the diff against BASE is the
# added lines and nothing else.
added() {
	printf '%s\n' "$1" >>"$REPO/crates/batten/src/lib.rs"
	git add -A
}

@test "the committed workspace has no uncited added absolute" {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no added absolute is uncited"* ]]
}

@test "an added absolute with nothing to look at is refused" {
	# The discriminating row: the exact shape of the claim that started this.
	added '/// A garbage lease is still takeable, so this cannot wedge the fleet.'
	run "$CHECK" "$BASE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"crates/batten/src/lib.rs"* ]]
}

@test "the refusal is a pointer and never the sentence itself" {
	# Rule 4. A gate about unsupported claims that echoed them back would put the
	# claim in one more place than it already was.
	added '/// This cannot happen.'
	run "$CHECK" "$BASE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"This cannot happen"* ]]
}

@test "a CLOUD key in the same block satisfies it" {
	added '/// A garbage lease is unheld and uncontested, so two landers can run
/// under it (CLOUD-1703).'
	run "$CHECK" "$BASE"
	[ "$status" -eq 0 ]
}

@test "a path:line in the same block satisfies it" {
	added '/// `authorises` answers Run on a reading that will not parse, so nothing
/// stops the fleet over it (lease.rs:1260).'
	run "$CHECK" "$BASE"
	[ "$status" -eq 0 ]
}

@test "the citation may be a line apart from the claim" {
	# The unit is the comment BLOCK, because a claim and its citation are
	# routinely a sentence apart and a per-line rule would force a citation into
	# the middle of every sentence that spans two lines.
	added '/// Nothing else reads this.
///
/// The one binder was retired with the shell heartbeat (CLOUD-1703).'
	run "$CHECK" "$BASE"
	[ "$status" -eq 0 ]
}

@test "a machine row is data and owes no citation" {
	# Measured on this gate's own first run, which refused a `//MUTANT` marker for
	# carrying "never" inside its slug. Slugs and paths are not sentences, and the
	# rows are already checked in the shape another gate decides.
	added '//MUTANT progress-never-published|s@a@b@|a_case'
	run "$CHECK" "$BASE"
	[ "$status" -eq 0 ]
}

@test "code that says cannot is a name, not a claim" {
	added 'fn cannot_be_stolen() -> bool { true }'
	run "$CHECK" "$BASE"
	[ "$status" -eq 0 ]
}

@test "an existing uncited absolute the delta does not touch is not a finding" {
	# THE ROW THAT MAKES THE GATE LANDABLE. The tree carries hundreds of correct
	# absolutes written before the rule; a whole-file scan would redden every file
	# any delta happens to touch, which is a gate that must be bypassed to commit.
	printf '%s\n' '/// This cannot happen.' >>"$REPO/crates/batten/src/lib.rs"
	git add -A
	git commit -qm "an absolute from before the rule"
	local before
	before="$(git rev-parse HEAD)"
	added 'fn unrelated() {}'
	run "$CHECK" "$before"
	[ "$status" -eq 0 ]
}
