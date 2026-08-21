#!/usr/bin/env bats
# subject: mise-tasks/pipefail-grep-check
# `producer | grep -q P` under `set -o pipefail` can return FAILURE on a match:
# grep exits at the first hit, a producer still writing dies of SIGPIPE, and
# pipefail promotes 141 to the pipeline's status. The successful case is the one
# that reports failure — and it is a RACE, measured at 2 failures in 300 runs on
# a two-commit range, so it passes review and passes tests.
#
# Two instances landed here before the class was named. `landed-check` reported
# a clean board over three landed issues. `issue-guard` denied `gh pr ready` on
# a branch whose every commit carried `Refs: CLOUD-186`, with a reason asserting
# the opposite of what it had just found — it blocked its own PR.
#
# Both fail toward the verdict nobody checks, which is why a green suite that
# only feeds non-matching input never sees it.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/pipefail-grep-check"
	REPO="$BATS_TEST_TMPDIR/repo-$BATS_TEST_NUMBER"
	mkdir -p "$REPO/mise-tasks"
	cd "$REPO" || return 1
	git init -q .
	git config user.email t@t
	git config user.name t
}

# Writes $1 as a task body and stages it, since the gate reads tracked files.
task() {
	printf '%s\n' "$1" >mise-tasks/t
	git add -A
}

@test "the exact shape that broke issue-guard is flagged" {
	task 'set -euo pipefail
git log --format="%B" origin/main..HEAD | grep -qiE "$ISSUE_RE" && exit 0'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise-tasks/t:2"* ]]
}

@test "the here-string fix passes" {
	task 'set -euo pipefail
log=$(git log --format="%B" origin/main..HEAD || true)
grep -qiE "$ISSUE_RE" <<<"$log" && exit 0'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a flag cluster is judged by its letters, not its spelling" {
	# -qxF and -oq are the same hazard as -q; an enumeration of spellings rots.
	task 'set -euo pipefail
rustup target list --installed | grep -qxF "$target"'
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "--quiet is the same hazard under its long name" {
	task 'set -euo pipefail
producer | grep --quiet PATTERN'
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "-l stops at the first matching file, so it is flagged too" {
	task 'set -euo pipefail
producer | grep -l PATTERN'
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "-m N stops after N matches" {
	task 'set -euo pipefail
producer | grep -m 1 PATTERN'
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "a grep that consumes its whole input is not the hazard" {
	# Without an early exit the producer never takes SIGPIPE, so the pipeline
	# status is honest and the pipe is fine.
	task 'set -euo pipefail
producer | grep -E PATTERN'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an || before grep is not a pipe" {
	# CLOUD-852. The scan was `\|[[:space:]]*grep`, which matches the SECOND bar
	# of `a || grep -q ...` — so a here-string form, the very remedy this gate
	# recommends, was reported as the defect. Measured on `mise-tasks/ready-lint`,
	# whose line pipes nothing.
	task 'set -euo pipefail
[[ "$tok" == *x* ]] || grep -qE PATTERN <<<"$line"'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a real pipe into an early-exiting grep is still caught alongside an ||" {
	# The discriminator: the fix must not have turned the scan off. Same line
	# shape, but a genuine producer pipe.
	task 'set -euo pipefail
[[ "$tok" == *x* ]] || producer | grep -q PATTERN'
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "a file that does not enable pipefail is out of scope" {
	# Without pipefail the pipeline reports grep's status, which is correct.
	task 'set -eu
producer | grep -q PATTERN'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a comment describing the hazard is not the hazard" {
	task 'set -euo pipefail
# Never write `producer | grep -q P` here — pipefail inverts it.
echo ok'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "-q after -- is a pattern, not a flag" {
	task 'set -euo pipefail
producer | grep -- -q'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "output is a pointer — file:line and the fix, never the matched content" {
	task 'set -euo pipefail
producer | grep -q "s3://acct-1234567890/secret"'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"acct-1234567890"* ]]
}

@test "an untracked file is not judged — the gate reads committed bytes" {
	printf 'set -euo pipefail\nproducer | grep -q P\n' >mise-tasks/t
	run "$GATE"
	[ "$status" -eq 0 ]
}
