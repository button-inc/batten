#!/usr/bin/env bats
# subject: mise-tasks/suite-bench-check.sh mise-tasks/suite-bench.sh

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/suite-bench-check.sh"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT/tests" "$ROOT/bench/suites"
	cd "$ROOT" || return 1
	git init -q .
	git config user.email t@t
	git config user.name t
	export SUITE_BENCH_CORPUS="$ROOT/bench/suites/RESULTS.md"
	export SUITE_BENCH_SUITES="tests"
}

# One corpus row, in the shape `suite-bench` emits.
row() { printf '| %s | 1.0%%%% | `%s` |\n' "$1" "$2"; }

corpus() {
	{
		echo '| seconds | share | suite |'
		echo '| ---: | ---: | --- |'
		for s in "$@"; do row 1.0 "$s"; done
	} >"$SUITE_BENCH_CORPUS"
}

suite() {
	: >"$ROOT/$1"
	git add "$1"
}

@test "a corpus naming exactly the tracked suites passes" {
	suite tests/a.bats
	suite tests/b.bats
	corpus tests/a.bats tests/b.bats
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a suite absent from the corpus is refused" {
	# THE ROT THIS EXISTS FOR: a suite is added, nobody regenerates, and the
	# corpus silently stops covering the tree it claims to describe.
	suite tests/a.bats
	suite tests/b.bats
	corpus tests/a.bats
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"tests/b.bats is tracked but absent"* ]]
}

@test "a corpus row naming no real suite is refused" {
	# The mirror: a suite is deleted and its cost row outlives it, so the corpus
	# carries a figure attached to nothing.
	suite tests/a.bats
	corpus tests/a.bats tests/gone.bats
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"tests/gone.bats"* ]]
}

@test "an untracked suite is not demanded — the corpus describes the tree git carries" {
	suite tests/a.bats
	: >"$ROOT/tests/scratch.bats"
	corpus tests/a.bats
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a missing corpus is could-not-look, not a clean tree" {
	suite tests/a.bats
	rm -f "$SUITE_BENCH_CORPUS"
	run "$GATE"
	[ "$status" -eq 2 ]
}

@test "a corpus with no rows is could-not-look, not an empty suite set" {
	# The anti-vacuity direction: a truncated or half-written corpus must not
	# read as "every suite is recorded" over an empty set.
	suite tests/a.bats
	printf '| seconds | share | suite |\n| ---: | ---: | --- |\n' >"$SUITE_BENCH_CORPUS"
	run "$GATE"
	[ "$status" -eq 2 ]
}

@test "no tracked suite at all is could-not-look" {
	corpus tests/a.bats
	run "$GATE"
	[ "$status" -eq 2 ]
}

@test "output is a pointer — no duration is echoed" {
	# Rule 4, and the specific hazard: a gate that printed the number would be a
	# second authority over the corpus it is judging.
	suite tests/a.bats
	suite tests/b.bats
	corpus tests/a.bats
	run "$GATE"
	[[ "$output" != *"1.0"* ]]
}

# --- the PRODUCER's own refusal (CLOUD-352, found retiring CLOUD-312 row 2) ---
#
# The gate above and `suite-bench --write` are a pair: the gate's refusal names
# that command as the remedy, so a state the remedy cannot reach makes the gate
# read as broken. Measured: a suite retired, `test:bats`'s report still named it,
# `--write` faithfully republished a cost for a file that was gone, and the gate
# refused the file its own message had just asked for.

report() { # a JUnit report in the shape bats' formatter writes
	mkdir -p "$ROOT/target/bats-report"
	{
		echo '<?xml version="1.0" encoding="UTF-8"?>'
		echo '<testsuites>'
		for s in "$@"; do
			printf '<testsuite name="%s" tests="1" time="1.5">\n</testsuite>\n' "$s"
		done
		echo '</testsuites>'
	} >"$ROOT/target/bats-report/report.xml"
	export SUITE_BENCH_REPORT="$ROOT/target/bats-report/report.xml"
}

@test "a report naming a suite the tree does not track is could-not-look" {
	BENCH="$BATS_TEST_DIRNAME/../mise-tasks/suite-bench.sh"
	suite tests/a.bats
	git commit -q -m base
	report a.bats gone.bats
	run "$BENCH"
	[ "$status" -eq 2 ]
	[[ "$output" == *"tests/gone.bats"* ]]
	[[ "$output" == *"does not track"* ]]
}

@test "a report naming only tracked suites derives a corpus" {
	# The anti-vacuity half: the refusal above must not be reachable by every
	# report, or the producer could never run at all.
	BENCH="$BATS_TEST_DIRNAME/../mise-tasks/suite-bench.sh"
	suite tests/a.bats
	git commit -q -m base
	report a.bats
	run "$BENCH"
	[ "$status" -eq 0 ]
	[[ "$output" == *'`tests/a.bats`'* ]]
}
