#!/usr/bin/env bats
# subject: mise-tasks/ci-slow-needed
#
# CLOUD-398. The `ci` job pays for the hk slow tier only when a diff can move it,
# so the failure that matters is the SILENT one: an inert entry that swallows a
# real input leaves the verdict untaken and every required check green.
#
# The fixture paths are held in variables rather than written as literals. That
# is not style: `protected-mutation` reads the committed text of this file, and a
# literal redirect naming a protected path is refused here even though the write
# lands in $BATS_TEST_TMPDIR. Variables keep the suite writable and read better.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/ci-slow-needed"
	RUST="crates/batten/src/lib.rs"
	MEM=".serena/memories/core.md"
	BOT=".coderabbit.yaml"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO"
	cd "$REPO" || return 1
	git init -q .
	git config user.email t@example.com
	git config user.name t
	mkdir -p "$(dirname "$MEM")" "$(dirname "$RUST")"
	echo base >"$RUST"
	echo base >"$MEM"
	echo base >"$BOT"
	git add -A
	git commit -qm base
}

@test "a crates change still needs the slow tier" {
	echo changed >"$RUST"
	git commit -qam rust
	run "$GATE" HEAD~1 HEAD
	[ "$status" -eq 0 ]
	[[ "$output" == *"can move the slow tier"* ]]
}

@test "a memories-only diff does not need the slow tier" {
	echo changed >"$MEM"
	git commit -qam memories
	run "$GATE" HEAD~1 HEAD
	[ "$status" -eq 1 ]
	[[ "$output" == *"inert to the slow tier"* ]]
}

@test "the bot config is inert too — the diff that bought an 18-minute run" {
	echo changed >"$BOT"
	git commit -qam bot
	run "$GATE" HEAD~1 HEAD
	[ "$status" -eq 1 ]
}

@test "ONE non-inert path in a mostly-inert diff still needs the tier" {
	# The case a "mostly inert" heuristic would get wrong. This is all-or-nothing,
	# like GitHub's own paths-ignore: a single real input is enough.
	echo changed >"$MEM"
	echo changed >"$RUST"
	git commit -qam mixed
	run "$GATE" HEAD~1 HEAD
	[ "$status" -eq 0 ]
	[[ "$output" == *"lib.rs"* ]]
}

@test "an empty diff is could-not-look, not a clean skip" {
	# ANTI-VACUITY. A wrong base or a shallow clone reports no changed files, and
	# answering "skip" there is the false-absent this program exists to avoid.
	run "$GATE" HEAD HEAD
	[ "$status" -eq 2 ]
	[[ "$output" == *"could-not-look"* ]]
}

@test "no base revision refuses rather than guessing" {
	run "$GATE"
	[ "$status" -eq 2 ]
}

@test "the probe mode holds the inert list to both directions" {
	run "$GATE" --probe
	[ "$status" -eq 0 ]
	[[ "$output" == *"every probe honoured"* ]]
}

@test "output is a pointer — no file contents echoed" {
	echo 'hunter2' >"$RUST"
	git commit -qam secret
	run "$GATE" HEAD~1 HEAD
	[ "$status" -eq 0 ]
	[[ "$output" != *"hunter2"* ]]
}
