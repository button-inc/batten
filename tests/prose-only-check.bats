#!/usr/bin/env bats
# subject: mise-tasks/prose-only-check.sh
# CLOUD-827. A branch whose entire diff was two rewritten sentences of `//!` doc
# comment was on its way to a full required matrix against a trunk landing every
# ~16 minutes. What stopped it was a human, which is the wrong mechanism: the
# agent had the rule (AGENTS.md) and every gate it consulted said yes.
#
# Each case builds its own repository, because the predicate reads
# `origin/main...HEAD` and a case that leaned on the checkout would assert about
# whichever branch happened to be current.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/prose-only-check.sh"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	# `git init -b`, not `git branch -f`: forcing the checked-out branch fails, and
	# CI hides it only because the runner still defaults to `master` (CLOUD-282).
	git init -q -b claude/prose-fixture "$REPO"
	cd "$REPO" || return 1
	git config commit.gpgsign false
	git config user.email t@t
	git config user.name t
}

commit() { git add -A && git commit -q -m "$1"; }

# The base every case diffs against. Pointing `origin/main` at the first commit
# makes everything after it "this branch's work".
base() {
	commit "base"
	git update-ref refs/remotes/origin/main HEAD
}

@test "a comment-only diff with no test change is refused" {
	# THE ACCEPTANCE CASE, and the one the first mutation targets: with the
	# predicate stubbed to never refuse, this is the only case that reddens.
	printf 'fn a() {}\n' >src.rs
	base
	printf '// a rewritten sentence\nfn a() {}\n' >src.rs
	commit "docs: reword"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"would confirm nothing"* ]]
	[[ "$output" == *"src.rs"* ]]
}

@test "a comment change plus a test change is admitted — the PR #604 shape" {
	# This prices batching, never doc work. A doc rewrite that also carries the
	# gate enforcing it is exactly the change that SHOULD land.
	printf 'fn a() {}\n' >src.rs
	mkdir -p tests
	printf 'old\n' >tests/t.bats
	base
	printf '// a rewritten sentence\nfn a() {}\n' >src.rs
	printf 'new assertion\n' >tests/t.bats
	commit "docs+test"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"including under tests/"* ]]
}

@test "a comment change plus any code line is admitted" {
	printf 'fn a() {}\n' >src.rs
	base
	printf '// note\nfn a() { let x = 1; }\n' >src.rs
	commit "docs+code"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"non-comment line"* ]]
}

@test "a .md-only diff is refused — the whole file is prose" {
	printf 'one\n' >README.md
	base
	printf 'one\ntwo\n' >README.md
	commit "docs: expand"
	run "$GATE"
	[ "$status" -eq 2 ]
}

@test "an unrecognised extension admits the branch" {
	# The admitting direction is deliberate. Wrong one way this spends someone
	# else's minutes; wrong the other way it blocks correct work, and only the
	# second cannot be recovered by waiting.
	printf 'a: 1\n' >conf.yaml
	base
	printf 'a: 2\n' >conf.yaml
	commit "chore: config"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an empty diff is not judged" {
	printf 'fn a() {}\n' >src.rs
	base
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nothing to price"* ]]
}

@test "no base to diff against is not judged, rather than refused" {
	printf 'fn a() {}\n' >src.rs
	commit "only"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"not judged"* ]]
}

@test "a shell comment counts as prose, and code in the same file does not" {
	printf 'echo hi\n' >t.sh
	base
	printf '# a comment\necho hi\n' >t.sh
	commit "docs: comment"
	run "$GATE"
	[ "$status" -eq 2 ]

	printf '# a comment\necho bye\n' >t.sh
	commit "code too"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a Rust block comment is NOT read as prose" {
	# `/* */` cannot be classified line-by-line without tracking state, and
	# guessing would fail in the refusing direction — so it reads as code.
	printf 'fn a() {}\n' >src.rs
	base
	printf '/* a block */\nfn a() {}\n' >src.rs
	commit "docs: block"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a reflowed comment block with blank lines is still prose" {
	# A blank line inside an otherwise-prose hunk is whitespace, not code.
	# Counting it as code would make every reflowed comment block read as a code
	# change, which is the common case this gate is about.
	printf '// one\nfn a() {}\n' >src.rs
	base
	printf '// one\n\n// two\nfn a() {}\n' >src.rs
	commit "docs: reflow"
	run "$GATE"
	[ "$status" -eq 2 ]
}

@test "a deleted file is not read as a comment change" {
	# A removed file has no surviving lines to classify. Treating it as prose
	# would let a branch that deletes a module read as a doc change.
	printf 'fn a() {}\n' >src.rs
	printf 'fn b() {}\n' >gone.rs
	base
	rm gone.rs
	commit "refactor: drop a module"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the override admits the branch and records which one it admitted" {
	printf 'fn a() {}\n' >src.rs
	base
	printf '// reworded\nfn a() {}\n' >src.rs
	commit "docs: reword"
	BATTEN_PROSE_ONLY_OVERRIDE=1 run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"OVERRIDDEN"* ]]
	[[ "$output" == *"claude/prose-fixture"* ]]
	# The trace is the whole point: a visible decision rather than a silence.
	run cat "$(git rev-parse --git-dir)/batten-receipts/prose-only-overrides.claude/prose-fixture"
	[ "$status" -eq 0 ]
	[[ "$output" == *"OVERRIDDEN"* ]]
}

@test "the refusal names paths and a count, never a line of the diff" {
	# Rule 4. A diff is content someone has not published yet.
	printf 'fn a() {}\n' >src.rs
	base
	printf '// customer detail in the comment\nfn a() {}\n' >src.rs
	commit "docs: reword"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" != *"customer detail"* ]]
	[[ "$output" == *"src.rs"* ]]
}

@test "the remedy names where the content should go, not merely a flag" {
	printf 'fn a() {}\n' >src.rs
	base
	printf '// reworded\nfn a() {}\n' >src.rs
	commit "docs: reword"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"the row that owns it"* ]]
	[[ "$output" == *"BATTEN_PROSE_ONLY_OVERRIDE"* ]]
}
