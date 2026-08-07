#!/usr/bin/env bats
# mise task bodies (`shell = "bash -c"`) do not run under `set -e`: every line
# runs regardless of the previous line's exit status. In a gate that is a silent
# false green — the body reports on state it never refreshed.
#
# tests/linear-check.bats covers the instance inside that script. This covers the
# caller: `verify` invokes linear-check and commit-lint and then writes the
# receipt `ready-guard` honours, so an unguarded call there means `gh pr ready`
# is allowed — and CI minutes spent — on a branch that failed its own pre-flight.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	BODY=$(awk '/^\[tasks\.verify\]/{f=1} f&&/^run = .{3}$/{c=1;next} c&&/^.{3}$/{exit} c' mise.toml)
}

@test "the verify body was found at all — this suite is not passing vacuously" {
	[ -n "$BODY" ]
	[[ "$BODY" == *"linear-check"* ]]
	[[ "$BODY" == *"batten-receipts"* ]]
}

@test "every command verify's verdict depends on is guarded, since the body has no set -e" {
	# A bare `mise run X` line is the defect: its failure would not stop the body.
	local unguarded
	unguarded=$(grep -nE '^[[:space:]]*(BASE_SHA=[^ ]* )?(HEAD_SHA=[^ ]* )?mise run ' <<<"$BODY" || true)
	[ -z "$unguarded" ] || {
		echo "unguarded call in the verify body: $unguarded"
		false
	}
}

@test "verify writes its receipt only after the guarded steps, never before" {
	local guard_line receipt_line
	guard_line=$(grep -n 'linear-check' <<<"$BODY" | head -1 | cut -d: -f1)
	receipt_line=$(grep -n 'batten-receipts' <<<"$BODY" | head -1 | cut -d: -f1)
	[ "$guard_line" -lt "$receipt_line" ]
}

@test "each guard exits non-zero rather than merely warning" {
	# One `exit 1` per guarded step: a guard that prints and continues would
	# still reach the receipt write.
	local guards exits
	guards=$(grep -c 'if ! ' <<<"$BODY")
	exits=$(grep -c 'exit 1' <<<"$BODY")
	[ "$guards" -ge 2 ]
	[ "$exits" -ge "$guards" ]
}

@test "a failing step leaves no receipt — the guard's whole purpose" {
	# Behavioural, not textual: run the body's guard shape with a failing step
	# and assert the receipt line is never reached.
	local receipt="$BATS_TEST_TMPDIR/receipt"
	run bash -c '
		if ! false; then echo "::error:: step failed" >&2; exit 1; fi
		date -u +%FT%TZ >"'"$receipt"'"
		echo "fast-forward-green"
	'
	[ "$status" -eq 1 ]
	[ ! -f "$receipt" ]
	[[ "$output" != *"fast-forward-green"* ]]
}
