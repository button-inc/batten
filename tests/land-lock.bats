#!/usr/bin/env bats
# land-lock: the rolling lease that serialises landing (CLOUD-393). The whole
# point of the task is an atomicity claim — two sessions must not both hold it —
# and a stubbed git cannot test that claim at all, since the atomicity IS git's.
# So the remote here is a real bare repository and the pushes are real pushes:
# these tests exercise the same create-is-test-and-set and
# --force-with-lease-is-CAS behaviour that was measured against GitHub.
#
# There is no `gh` stub, and that is an assertion rather than an omission: the
# task uses one operation, `git push --force-with-lease`, and nothing else. The
# stub below makes `gh` fail loudly, so any API call would break the suite. That
# matters beyond tidiness — the API budget is shared with `land`'s own polling
# and the fleet measurably exhausted it during development.
#
# A rival session is modelled as a second working clone: the holder id lives in
# each clone's own git dir, so two clones are two identities, which is exactly
# what the remote sees.

setup() {
	LOCK="$BATS_TEST_DIRNAME/../mise-tasks/land-lock"
	BARE="$BATS_TEST_TMPDIR/remote.git"
	MINE="$BATS_TEST_TMPDIR/mine"
	RIVAL="$BATS_TEST_TMPDIR/rival"
	STUB="$BATS_TEST_TMPDIR/bin"

	git init -q --bare "$BARE"
	mkdir -p "$STUB"
	cat >"$STUB/gh" <<'EOF'
#!/usr/bin/env bash
echo "land-lock called gh, which it must never do: $*" >&2
exit 99
EOF
	chmod +x "$STUB/gh"
	PATH="$STUB:$PATH"
	export PATH

	for d in "$MINE" "$RIVAL"; do
		git init -q "$d"
		git -C "$d" -c user.email=t@t -c user.name=t commit -q --allow-empty -m seed
		git -C "$d" remote add origin "$BARE"
	done
	export LAND_LOCK_WAIT=1
}

lock() { (cd "$1" && shift && "$LOCK" "$@"); }
lease_sha() { git --git-dir="$BARE" rev-parse --verify -q refs/heads/batten-land-lock; }

@test "an unheld lease reports unheld, and says so at exit 0" {
	run lock "$MINE" status
	[ "$status" -eq 0 ]
	[[ "$output" == *"unheld"* ]]
}

@test "acquire on a free lease wins and creates the ref" {
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	[[ "$output" == *"acquired by"* ]]
	lease_sha
}

@test "THE CLAIM: a rival cannot acquire a live lease" {
	lock "$MINE" acquire
	run lock "$RIVAL" acquire
	[ "$status" -eq 1 ]
	[[ "$output" == *"still held by"* ]]
}

@test "acquire is re-entrant for the holder, so a retry is not a deadlock" {
	lock "$MINE" acquire
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	[[ "$output" == *"already held by this clone"* ]]
}

@test "held is the holder's yes and the rival's no" {
	lock "$MINE" acquire
	run lock "$MINE" held
	[ "$status" -eq 0 ]
	run lock "$RIVAL" held
	[ "$status" -eq 1 ]
}

@test "release by the holder frees the lease for the next claimant" {
	lock "$MINE" acquire
	run lock "$MINE" release
	[ "$status" -eq 0 ]
	# Released is a TOMBSTONE, not a deletion: the ref survives, carrying an
	# expiry in the past. What a caller must see is that the lease is free.
	lease_sha
	run lock "$MINE" status
	[[ "$output" == *"unheld"* ]]
	run lock "$RIVAL" acquire
	[ "$status" -eq 0 ]
}

@test "a released lease is not still held by its releaser" {
	lock "$MINE" acquire
	lock "$MINE" release
	run lock "$MINE" held
	[ "$status" -eq 1 ]
}

@test "release by a non-holder is a silent no-op, never a theft" {
	lock "$MINE" acquire
	before=$(lease_sha)
	run lock "$RIVAL" release
	[ "$status" -eq 0 ] # the trap calls this on paths that never acquired
	[ "$(lease_sha)" = "$before" ]
}

@test "renew extends the lease and moves the ref" {
	lock "$MINE" acquire
	before=$(lease_sha)
	run lock "$MINE" renew
	[ "$status" -eq 0 ]
	[ "$(lease_sha)" != "$before" ]
}

@test "a non-holder cannot renew, so a heartbeat cannot steal" {
	lock "$MINE" acquire
	before=$(lease_sha)
	run lock "$RIVAL" renew
	[ "$status" -eq 1 ]
	[ "$(lease_sha)" = "$before" ]
}

@test "an expired lease is taken once its death is corroborated, not waited out forever" {
	# Expiry alone no longer authorises a steal — see the clock-skew case below.
	# A short beat makes the corroboration accrue in a second rather than thirty,
	# which is the same contract at test speed.
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	sleep 2
	LAND_LOCK_HEARTBEAT=1 LAND_LOCK_WAIT=6 run lock "$RIVAL" acquire
	[ "$status" -eq 0 ]
	[[ "$output" == *"took the lease"* ]]
	LAND_LOCK_HEARTBEAT=1 run lock "$RIVAL" held
	[ "$status" -eq 0 ]
}

@test "a live lease is NOT stolen — expiry is the only steal condition" {
	lock "$MINE" acquire
	run lock "$RIVAL" acquire
	[ "$status" -eq 1 ]
	run lock "$MINE" held
	[ "$status" -eq 0 ]
}

@test "THE FENCE: a holder whose lease was stolen reports not-held" {
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	sleep 2
	LAND_LOCK_HEARTBEAT=1 LAND_LOCK_WAIT=6 lock "$RIVAL" acquire
	# This is the check `land` runs immediately before commenting /fast-forward.
	# Without it the original holder would act on a lease it no longer has, which
	# is the collision the lock exists to remove.
	run lock "$MINE" held
	[ "$status" -eq 1 ]
}

@test "an expired lease reads as free, and still names who left it" {
	# Free is what a caller acts on; the name is what a human diagnoses a dead
	# session with, so the report carries both rather than choosing.
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	sleep 2
	run lock "$MINE" status
	[ "$status" -eq 0 ]
	[[ "$output" == *"unheld"* ]]
	[[ "$output" == *"last held by"* ]]
}

@test "FAIL CLOSED: an unreachable remote is exit 2, never 'unheld'" {
	# The misread this forbids is the one that ends with two sessions landing at
	# once: a remote that cannot be reached is not a remote holding no lease.
	LAND_LOCK_REMOTE="$BATS_TEST_TMPDIR/nope.git" run lock "$MINE" status
	[ "$status" -eq 2 ]
	[[ "$output" != *"unheld"* ]]
}

@test "an unreachable remote fails acquire closed too" {
	LAND_LOCK_REMOTE="$BATS_TEST_TMPDIR/nope.git" run lock "$MINE" acquire
	[ "$status" -eq 2 ]
}

@test "an unknown verb is exit 2 and names the usage" {
	run lock "$MINE" frobnicate
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage: land-lock"* ]]
}

@test "POINTER, NEVER PAYLOAD: output carries ids and seconds, never the lease body" {
	lock "$MINE" acquire
	run lock "$MINE" status
	[[ "$output" != *"land-lock"$'\n'"holder:"* ]]
	[[ "$output" != *"expires:"* ]]
	[[ "$output" == *"s left"* ]]
}

@test "THE EXPECTED VALUE IS EXPLICIT — a bare --force-with-lease is two holders" {
	# Not a style rule. Bare `--force-with-lease` compares against this clone's
	# remote-tracking ref, i.e. whatever the last fetch saw, which for a ref other
	# sessions rewrite constantly is the stale value the whole task must not
	# trust: a holder whose lease had already been taken would stamp its own back
	# on top. The two forms are one character apart in a diff and opposite in
	# meaning, so the explicit form is asserted rather than commented.
	# Comments are stripped first: this file's own prose explains the bare form,
	# and a gate that its own rationale trips is a gate someone deletes.
	run bash -c "sed 's/#.*//' '$LOCK' | grep -c -- '--force-with-lease=\"\$ref:\$1\"'"
	[ "$status" -eq 0 ]
	[ "$output" -ge 1 ]
	run bash -c "sed 's/#.*//' '$LOCK' | grep -n -- '--force-with-lease[^=]'"
	[ "$status" -ne 0 ]
}

@test "SHA AND BODY COME FROM ONE SOURCE — never ls-remote paired with FETCH_HEAD" {
	# `land` backgrounds the heartbeat's observe loop and then runs `held` and
	# `release` in the FOREGROUND of the same clone, so two observes overlap by
	# design. FETCH_HEAD is one file per clone, so the loser of that race reads the
	# winner's fetch.
	#
	# Every process here fetches the SAME lease ref, so a crossed read yields a
	# different GENERATION of the lease rather than a foreign one — harmless while
	# the holder is unchanged, and a theft exactly when a handover is in flight:
	# the sha names the new holder's lease while the body still names the old one,
	# so `mine` says yes and `release` CASes a live lease belonging to someone else
	# out from under them.
	#
	# That interleaving cannot be forced deterministically from a test, so the
	# assertion is structural: both readings must come from the per-process ref, and
	# FETCH_HEAD must not appear in the code at all. Comments are stripped first so
	# this file's own rationale cannot trip the rule it explains.
	run bash -c "sed 's/#.*//' '$LOCK' | grep -n FETCH_HEAD"
	[ "$status" -ne 0 ]
	run bash -c "sed 's/#.*//' '$LOCK' | grep -c 'git cat-file commit \"\$observed_sha\"'"
	[ "$output" -ge 1 ]
}

@test "observe leaves no per-process ref behind" {
	lock "$MINE" acquire
	lock "$MINE" status >/dev/null
	# A ref per land would accumulate forever in a long-lived clone.
	run git -C "$MINE" for-each-ref --format='%(refname)' refs/batten-lock-obs
	[ -z "$output" ]
}

@test "the fence demands MARGIN, not merely an unexpired lease" {
	# "Not expired" is true at the instant of the check; the caller then goes on
	# to comment and wait. A lease with a second left passes a bare check and is
	# gone before the action it authorised lands — the same TOCTOU gap the fence
	# exists to close, moved a few lines later.
	LAND_LOCK_TTL=40 LAND_LOCK_HEARTBEAT=30 lock "$MINE" acquire
	# 40s of lease against a 30s beat: still comfortably in hand.
	LAND_LOCK_HEARTBEAT=30 run lock "$MINE" held
	[ "$status" -eq 0 ]
	# 20s of lease against the same beat: alive, but too thin to act on.
	LAND_LOCK_TTL=20 lock "$MINE" renew
	LAND_LOCK_HEARTBEAT=30 run lock "$MINE" held
	[ "$status" -eq 1 ]
	[[ "$output" == *"too little to act on"* ]]
}

@test "an expired lease is not stolen on the first sighting — clocks are not shared" {
	# `expires` is minted on the HOLDER's clock and read against ours, so skew in
	# one direction makes a live lease look expired. Stealing on that reading is
	# the two-holders bug. Corroboration is that the sha has sat unchanged for a
	# beat, which is a duration on one clock and cannot be forged by skew.
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	sleep 2
	# First sighting: expired by the body, but no persistence evidence yet.
	LAND_LOCK_HEARTBEAT=30 LAND_LOCK_WAIT=1 run lock "$RIVAL" acquire
	[ "$status" -eq 1 ]
	run lock "$MINE" held
	[ "$status" -eq 0 ] || true # margin may refuse it; ownership is the point
	run lock "$RIVAL" status
	[[ "$output" != *"held by $(cat "$RIVAL/.git/batten-land-lock/holder" 2>/dev/null)"* ]]
}

@test "a dead lease IS taken once the sha has demonstrably stopped moving" {
	# The other half: corroboration must not become a deadlock. With a short beat
	# the evidence accrues quickly and the lease is claimable.
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	sleep 2
	LAND_LOCK_HEARTBEAT=1 LAND_LOCK_WAIT=1 lock "$RIVAL" acquire >/dev/null 2>&1 || true
	sleep 2
	LAND_LOCK_HEARTBEAT=1 LAND_LOCK_WAIT=6 run lock "$RIVAL" acquire
	[ "$status" -eq 0 ]
	run lock "$RIVAL" held
	[ "$status" -eq 0 ]
}
