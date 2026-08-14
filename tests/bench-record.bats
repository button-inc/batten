#!/usr/bin/env bats
# The series writer, exercised against throwaway repositories.
#
# It writes — a git note — so unlike its two siblings it cannot be a pure
# function of stdin. What it CAN be is scoped: every case here builds its own
# repository in $BATS_TEST_TMPDIR, so nothing touches this checkout's notes and
# the suite runs in the gate like any other.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/bench-record"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || return 1
	git init -q -b main .
	git config user.email a@b.c
	git config user.name t
	git commit -q --allow-empty -m "root"
	export BENCH_RUNNER="test-runner"
}

records() {
	cat <<-'EOF'
		path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
		path=hook p50=2.60 p95=3.03 mean=2.64 runs=100
	EOF
}

note_body() {
	git notes --ref=refs/notes/bench show HEAD
}

@test "a measurement on the trunk lands in the notes, keyed to the commit" {
	run bash -c "'$TASK' <<'IN'
$(records)
IN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"appended a wall-clock measurement"* ]]
	run note_body
	[ "$status" -eq 0 ]
	[[ "$output" == *"path=noop p50=2.40"* ]]
	[[ "$output" == *"path=hook p50=2.60"* ]]
}

# The label exists so a later reader can never mistake a wall-clock series for
# the instruction-count one CLOUD-172 originally wanted — valgrind is not in the
# mise registry, so this is the metric everywhere, and the record says so.
@test "the record names its metric and its runner" {
	bash -c "'$TASK' <<'IN'
$(records)
IN"
	run note_body
	[[ "$output" == *"metric=wall-clock"* ]]
	[[ "$output" == *"runner=test-runner"* ]]
}

# The refusal, and the reason: a branch's numbers are not the trunk's, and a
# series mixing them cannot be read at all.
@test "a branch is refused, and nothing is written" {
	git checkout -q -b feature
	run bash -c "'$TASK' <<'IN'
$(records)
IN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not 'main'"* ]]
	run git notes --ref=refs/notes/bench list
	[ -z "$output" ]
}

@test "the trunk's name is configurable, so the refusal is not hardcoded to main" {
	git checkout -q -b trunk
	run bash -c "BENCH_TRUNK=trunk '$TASK' <<'IN'
$(records)
IN"
	[ "$status" -eq 0 ]
}

# Appending, not replacing: a commit sampled twice keeps both readings. Two
# readings of one commit is itself a noise measurement.
@test "a second measurement of the same commit appends rather than overwrites" {
	bash -c "'$TASK' <<'IN'
$(records)
IN"
	bash -c "'$TASK' <<'IN'
path=noop p50=9.99 p95=9.99 mean=9.99 runs=100
IN"
	run note_body
	[[ "$output" == *"p50=2.40"* ]]
	[[ "$output" == *"p50=9.99"* ]]
}

@test "empty stdin is could-not-look, and writes nothing" {
	run bash -c "'$TASK' </dev/null"
	[ "$status" -eq 2 ]
	[[ "$output" == *"stdin is empty"* ]]
	run git notes --ref=refs/notes/bench list
	[ -z "$output" ]
}

@test "a line that is not a record is could-not-look, and writes nothing" {
	run bash -c "'$TASK' <<'IN'
path=noop p50=2.40 p95=2.88 mean=2.44 runs=100
Benchmark 1: target/release/batten --help
IN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"not \`bench\` records"* ]]
	run git notes --ref=refs/notes/bench list
	[ -z "$output" ]
}

# The series is on its own ref, never refs/notes/commits — the default ref is
# what a contributor's own `git notes` writes to, and a series is not a comment.
@test "the series lands on its own ref, leaving the default notes ref alone" {
	bash -c "'$TASK' <<'IN'
$(records)
IN"
	run git notes list
	[ -z "$output" ]
}

@test "output is a pointer — the ref and the commit, never the numbers" {
	run bash -c "'$TASK' <<'IN'
$(records)
IN"
	[[ "$output" != *"p50="* ]]
	[[ "$output" == *"refs/notes/bench"* ]]
}
