#!/usr/bin/env bats
# CLOUD-424. The per-step receipt's key function is pure, so it gets a decision
# table: identical inputs hit; a changed input file, command, tool version or
# argument misses; and every way a key can fail to compute — an unresolvable
# spec, a deleted input, a tool that will not answer, an unknown step — runs
# the step rather than hitting. Plus the property that makes it safe to ship:
# a corrupted or absent receipt store degrades to running everything, never to
# skipping anything.
#
# The fixture stubs `mise` (the task-body half of the key) and the tool (the
# version half), and BATTEN_STEP_SPECS/BATTEN_STEP_TOOLS override the step
# table — so every component of the key is a lever this suite pulls alone.

setup() {
	SR="$BATS_TEST_DIRNAME/../mise-tasks/step-receipt"
	mkdir -p "$BATS_TEST_TMPDIR/bin" "$BATS_TEST_TMPDIR/repo"
	cat >"$BATS_TEST_TMPDIR/bin/mise" <<-'EOF'
		#!/bin/sh
		echo "{\"run\":[\"${STUB_BODY:-echo body-v1}\"],\"file\":${STUB_FILE:-null},\"shell\":null}"
	EOF
	cat >"$BATS_TEST_TMPDIR/bin/toolv" <<-'EOF'
		#!/bin/sh
		if [ -n "${STUB_TOOL_FAIL:-}" ]; then exit 9; fi
		echo "${STUB_TOOL:-tool-1.0}"
	EOF
	chmod +x "$BATS_TEST_TMPDIR/bin/mise" "$BATS_TEST_TMPDIR/bin/toolv"
	PATH="$BATS_TEST_TMPDIR/bin:$PATH"
	export BATTEN_STEP_SPECS="input.txt"
	export BATTEN_STEP_TOOLS="toolv"
	# The suite itself may be running under CI, where the cache is disabled by
	# design; every case here is about the local posture except the two that
	# say otherwise.
	unset CI BATTEN_STEP_RECEIPT_BYPASS
	cd "$BATS_TEST_TMPDIR/repo" || return 1
	git init -q .
	git config user.email step@test.invalid
	git config user.name step
	echo one >input.txt
	git add input.txt
	git commit -qm init
}

# One full pass: a miss, the run's stand-in, and the record.
pass_once() {
	run "$SR" check mystep
	[ "$status" -eq 1 ]
	run "$SR" record mystep
	[ "$status" -eq 0 ]
}

@test "no receipt: the step runs" {
	run "$SR" check mystep
	[ "$status" -eq 1 ]
	[[ "$output" == *"running the step"* ]]
}

@test "identical inputs, command and tools hit" {
	pass_once
	run "$SR" check mystep
	[ "$status" -eq 0 ]
	[[ "$output" == *"not re-deriving"* ]]
}

@test "a changed input file misses" {
	pass_once
	echo two >input.txt
	git add input.txt
	run "$SR" check mystep
	[ "$status" -eq 1 ]
}

@test "a changed command misses" {
	pass_once
	run env STUB_BODY="echo body-v2" "$SR" check mystep
	[ "$status" -eq 1 ]
}

@test "a changed tool version misses" {
	pass_once
	run env STUB_TOOL="tool-2.0" "$SR" check mystep
	[ "$status" -eq 1 ]
}

@test "a changed argument misses — a receipt for one target must not answer for another" {
	run "$SR" check mystep --arg one
	[ "$status" -eq 1 ]
	run "$SR" record mystep --arg one
	[ "$status" -eq 0 ]
	run "$SR" check mystep --arg one
	[ "$status" -eq 0 ]
	run "$SR" check mystep --arg two
	[ "$status" -eq 1 ]
}

@test "a file task's bytes are key material" {
	echo "body bytes v1" >"$BATS_TEST_TMPDIR/taskfile"
	export STUB_FILE="\"$BATS_TEST_TMPDIR/taskfile\""
	run "$SR" check mystep
	[ "$status" -eq 1 ]
	run "$SR" record mystep
	[ "$status" -eq 0 ]
	run "$SR" check mystep
	[ "$status" -eq 0 ]
	echo "body bytes v2" >"$BATS_TEST_TMPDIR/taskfile"
	run "$SR" check mystep
	[ "$status" -eq 1 ]
}

@test "a tool that cannot answer is no key, and no key runs the step" {
	pass_once
	run env STUB_TOOL_FAIL=1 "$SR" check mystep
	[ "$status" -eq 1 ]
	[[ "$output" == *"no key"* ]]
}

@test "a spec that resolves to nothing runs the step" {
	run env BATTEN_STEP_SPECS="absent-*.txt" "$SR" check mystep
	[ "$status" -eq 1 ]
	[[ "$output" == *"no key"* ]]
}

@test "a deleted input runs the step" {
	pass_once
	rm input.txt
	run "$SR" check mystep
	[ "$status" -eq 1 ]
}

@test "unstaged divergence is no key — the index is what the key hashes, so the worktree must agree with it" {
	pass_once
	echo drift >>input.txt
	run "$SR" check mystep
	[ "$status" -eq 1 ]
	[[ "$output" == *"no key"* ]]
}

@test "an untracked file inside the specs is no key" {
	run env BATTEN_STEP_SPECS="." "$SR" check mystep
	[ "$status" -eq 1 ]
	run env BATTEN_STEP_SPECS="." "$SR" record mystep
	[ "$status" -eq 0 ]
	touch stray
	run env BATTEN_STEP_SPECS="." "$SR" check mystep
	[ "$status" -eq 1 ]
}

@test "an unknown step with no override always runs" {
	unset BATTEN_STEP_SPECS BATTEN_STEP_TOOLS
	run "$SR" check never-declared
	[ "$status" -eq 1 ]
	[[ "$output" == *"no key"* ]]
}

@test "a corrupted receipt store runs everything and records nothing — never skips" {
	pass_once
	rm -rf .git/batten-receipts
	: >.git/batten-receipts
	run "$SR" check mystep
	[ "$status" -eq 1 ]
	run "$SR" record mystep
	[ "$status" -eq 1 ]
}

@test "a record with no paired check refuses" {
	run "$SR" record mystep
	[ "$status" -eq 1 ]
	[[ "$output" == *"no pending key"* ]]
}

@test "inputs changing while the step ran refuse the record — no receipt may attest bytes the run never judged" {
	run "$SR" check mystep
	[ "$status" -eq 1 ]
	echo two >input.txt
	git add input.txt
	run "$SR" record mystep
	[ "$status" -eq 1 ]
	run bash -c 'ls .git/batten-receipts/step.mystep.* 2>/dev/null | wc -l'
	[ "$output" -eq 0 ]
}

@test "under CI the cache neither hits nor records — CI's job is to confirm independently" {
	pass_once
	run env CI=true "$SR" check mystep
	[ "$status" -eq 1 ]
	run env CI=true "$SR" record mystep
	[ "$status" -eq 0 ]
}

@test "the bypass behaves like CI, so a measurement can see the uncached cost" {
	pass_once
	run env BATTEN_STEP_RECEIPT_BYPASS=1 "$SR" check mystep
	[ "$status" -eq 1 ]
}

@test "one receipt per step: a new pass prunes the old key" {
	pass_once
	echo two >input.txt
	git add input.txt
	pass_once
	run bash -c 'find .git/batten-receipts -name "step.mystep.*" | wc -l'
	[ "$output" -eq 1 ]
}

@test "the receipt is pointer-only: a timestamp and a key, never input content" {
	pass_once
	run bash -c 'cat .git/batten-receipts/step.mystep.*'
	[ "$status" -eq 0 ]
	[[ "$output" != *"one"* ]]
	[[ "$output" != *"input.txt"* ]]
	run bash -c 'cat .git/batten-receipts/step.mystep.* | wc -l'
	[ "$output" -eq 1 ]
}
