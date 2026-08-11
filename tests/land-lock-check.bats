#!/usr/bin/env bats
# land-lock-check: the scheduled half of the landing lease (CLOUD-393).
#
# `land-lock` fails SAFE — an unparseable lease reads as held, so a stray push
# can never free the lock. The cost of that direction is silence: the fleet stops
# landing and nothing says why. This gate is the sensor for exactly that, so the
# cases below are mostly about the two states nothing legitimate can produce.
#
# Both readings are injected (LAND_LOCK_BODY, LAND_LOCK_NOW), so the suite needs
# no remote and no clock — the same lever branch-age-check takes, and for the
# same reason: a gate whose verdict needs the network is a gate nothing tests.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/land-lock-check"
	NOW=1000000
	export LAND_LOCK_NOW="$NOW" LAND_LOCK_TTL=120
}

lease() { printf 'land-lock\nholder: %s\nexpires: %s\nnonce: deadbeef\n' "$1" "$2"; }

@test "an absent lease is healthy — nobody is landing" {
	LAND_LOCK_BODY="" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"absent"* ]]
}

@test "a live lease is healthy and names its holder and remaining time" {
	LAND_LOCK_BODY="$(lease vm-1 $((NOW + 60)))" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"held by vm-1"* ]]
	[[ "$output" == *"60s left"* ]]
}

@test "a RELEASED lease is free, and is reported as a handover rather than an expiry" {
	# The `expires: 0` sentinel. Reading it as an ordinary timestamp would print
	# an age of 56 years, which is how a healthy state comes to look alarming.
	LAND_LOCK_BODY="$(lease vm-1 0)" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"released by vm-1"* ]]
	[[ "$output" != *"ago"* ]]
}

@test "a LAPSED lease is free too — a holder that stopped without releasing" {
	LAND_LOCK_BODY="$(lease vm-1 $((NOW - 30)))" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"free"* ]]
	[[ "$output" == *"lapsed"* ]]
	[[ "$output" == *"30s ago"* ]]
}

@test "a lease expiring exactly now is free — zero seconds left is none" {
	LAND_LOCK_BODY="$(lease vm-1 "$NOW")" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"free"* ]]
}

@test "WEDGED: a horizon beyond one TTL is refused, since nothing legitimate mints one" {
	LAND_LOCK_BODY="$(lease vm-1 $((NOW + 3600)))" run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"WEDGED"* ]]
	[[ "$output" == *"vm-1"* ]]
}

@test "a lease at exactly one TTL is the longest legitimate hold, not wedged" {
	LAND_LOCK_BODY="$(lease vm-1 $((NOW + 120)))" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" != *"WEDGED"* ]]
}

@test "GARBAGE: a ref carrying no lease body is refused" {
	# The shape a stray push leaves. land-lock reads it as held, silently.
	LAND_LOCK_BODY="just some commit message" run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"GARBAGE"* ]]
}

@test "GARBAGE: a non-numeric expiry is a refusal, never a shell error" {
	# Checked before the arithmetic on purpose: `[` on a non-number reports a
	# syntax error, and an error is not a verdict.
	LAND_LOCK_BODY="$(lease vm-1 soon)" run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"GARBAGE"* ]]
	[[ "$output" != *"integer expression"* ]]
}

@test "GARBAGE: a lease with no holder is refused — nobody could ever release it" {
	LAND_LOCK_BODY="$(printf 'land-lock\nexpires: %s\n' $((NOW + 60)))" run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"GARBAGE"* ]]
}

@test "POINTER, NEVER PAYLOAD: no case echoes the lease body" {
	LAND_LOCK_BODY="$(lease vm-1 $((NOW + 60)))" run "$CHECK"
	[[ "$output" != *"nonce"* ]]
	[[ "$output" != *"expires:"* ]]
	LAND_LOCK_BODY="secret-looking garbage" run "$CHECK"
	[[ "$output" != *"secret-looking"* ]]
}

@test "an unreachable remote is exit 2 — could not look is not a verdict" {
	# No LAND_LOCK_BODY, so it takes the live path against a remote that is not
	# there. This must never read as "absent", which is the misread that would
	# report a healthy lease over a broken one.
	unset LAND_LOCK_BODY
	LAND_LOCK_REMOTE="$BATS_TEST_TMPDIR/nope.git" run "$CHECK"
	[ "$status" -eq 2 ]
	[[ "$output" != *"absent"* ]]
}
