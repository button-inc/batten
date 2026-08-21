#!/usr/bin/env bats
# subject: mise-tasks/land-lock-check
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

# --- the successor the lease admits (CLOUD-369) ------------------------------
#
# The lease bounds confirming runs at TWO — the holder plus one branch `reserve`
# admitted — and this gate is what a human runs on a wedged lease. Reporting only
# the holder showed half the occupancy: the one view meant to explain who is
# spending CI could not name the second spender.
#
# `next:` is advisory, exactly like `branch:` and `head:`. It is read for the
# report and never for a verdict, so no case below changes an exit code.

# The same fixture plus a successor. Kept separate from `lease` so every existing
# case keeps asserting the shape it was written for — a body with no `next:` at
# all, which is both the pre-CLOUD-369 lease and the ordinary unreserved one.
lease_with_next() {
	printf 'land-lock\nholder: %s\nexpires: %s\nnext: %s\nnonce: deadbeef\n' "$1" "$2" "$3"
}

@test "CLOUD-369 clause f — a held lease names the successor admitted behind it" {
	LAND_LOCK_BODY="$(lease_with_next vm-1 $((NOW + 60)) feature-y)" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"held by vm-1"* ]]
	[[ "$output" == *"feature-y admitted behind it"* ]]
}

@test "CLOUD-369 clause f — output is BYTE-IDENTICAL when no successor is admitted" {
	# The pair is the point: the addition must be invisible on every lease that
	# carries no `next:`, which is every lease minted before this change and every
	# one nobody has reserved behind.
	LAND_LOCK_BODY="$(lease vm-1 $((NOW + 60)))" run "$CHECK"
	with_field="$output"
	LAND_LOCK_BODY="$(printf 'land-lock\nholder: vm-1\nexpires: %s\nnext: \nnonce: deadbeef\n' "$((NOW + 60))")" run "$CHECK"
	[ "$status" -eq 0 ]
	[ "$output" = "$with_field" ]
}

@test "CLOUD-369 clause f — a RELEASED lease still names who was admitted behind it" {
	# Diagnosis does not stop at the handover: a released lease whose successor is
	# still pushing is exactly the state a human is trying to understand.
	LAND_LOCK_BODY="$(lease_with_next vm-1 0 feature-y)" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"released by vm-1"* ]]
	[[ "$output" == *"feature-y admitted behind it"* ]]
}

@test "CLOUD-369 clause f — a WEDGED lease names the successor too, and still fails" {
	# The successor is reporting, never a verdict: the wedge is still exit 1.
	LAND_LOCK_BODY="$(lease_with_next vm-1 $((NOW + 9999)) feature-y)" run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"WEDGED"* ]]
	[[ "$output" == *"feature-y admitted behind it"* ]]
}

@test "CLOUD-369 clause f — a LAPSED lease names the successor it left behind" {
	LAND_LOCK_BODY="$(lease_with_next vm-1 $((NOW - 30)) feature-y)" run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"lapsed by vm-1"* ]]
	[[ "$output" == *"feature-y admitted behind it"* ]]
}
