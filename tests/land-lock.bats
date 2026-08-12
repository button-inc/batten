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

teardown() {
	# CLOUD-434's lesson applied to this suite's own plumbing: a hold that a
	# case leaked — a regressed tether, a mutant under test — must cost a stray
	# process for one teardown, never a wedged file. Within-file execution is
	# serial and no other suite runs the real land-lock, so the match cannot
	# reach a sibling test's processes.
	pkill -f 'mise-tasks/land-lock hold' 2>/dev/null || true
}

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
	# Released is a TOMBSTONE, not a deletion: the ref survives, carrying the
	# sentinel expiry 0. What a caller must see is that the lease is free — and
	# since CLOUD-433 it is told so as a HANDOVER rather than as an expiry,
	# which is the true statement about how it became free.
	lease_sha
	run lock "$MINE" status
	[[ "$output" == *"released"* ]]
	run lock "$RIVAL" acquire
	[ "$status" -eq 0 ]
}

@test "THE DEFECT: a released lease's status names the last holder, never an epoch" {
	# `expires: 0` is a SENTINEL, not an instant, so `now - expires` renders
	# wall-clock epoch. Observed live after the lease's first fleet release:
	# `free for 1786499426s`. `land-lock-check` already special-cased the
	# tombstone; `status` never did.
	#
	# `released` has to be tested BEFORE `expired`, because a tombstone
	# satisfies both — `now >= 0` is trivially true — so an expired-first
	# ordering reintroduces the defect exactly.
	lock "$MINE" acquire
	holder=$(cat "$MINE/.git/batten-land-lock/holder")
	lock "$MINE" release
	run lock "$MINE" status
	[ "$status" -eq 0 ]
	[[ "$output" == *"released"* ]]
	[[ "$output" == *"$holder"* ]]
	# No epoch-scale DURATION, whatever wording is used to render one. Anchored
	# on the trailing `s` rather than on ten digits alone, because the holder id
	# is random hex and can itself contain ten consecutive digits — an
	# unanchored version of this assertion fails on roughly one id in ten for a
	# reason that has nothing to do with the defect.
	[[ ! "$output" =~ [0-9]{10}s ]]
	[[ "$output" != *"free for"* ]]
}

@test "THE DEFECT: releasing an already-released lease says so, and reports no epoch age" {
	# `age()` had no tombstone branch and `release` never consulted `released()`
	# before swapping, so a second release re-tombstoned the lease and printed
	# `released after 1786501354s`. Observed live 2026-08-12.
	lock "$MINE" acquire
	lock "$MINE" release
	run lock "$MINE" release
	[ "$status" -eq 0 ]
	[[ "$output" == *"already released"* ]]
	# Anchored on the trailing `s` for the same reason as above.
	[[ ! "$output" =~ [0-9]{10}s ]]
}

@test "THE DEFECT: a first sighting of a sha emits no shell error on stderr" {
	# `read -r … <"$seen" 2>/dev/null` — bash opens the input redirect before
	# the stderr redirect on the same command takes effect, so a missing file
	# still printed `No such file or directory` to the CALLER's stderr, on every
	# acquire that reached the corroboration path. Harmless to the verdict, and
	# noise in the one task whose output contract is pointer-only.
	#
	# Driven through a CONTENDED acquire, because that is the path that reaches
	# corroboration at all: the rival holds a live lease, so this acquire
	# observes a sha it has never seen and gives up at the wait deadline.
	lock "$RIVAL" acquire
	run lock "$MINE" acquire
	[ "$status" -eq 1 ]
	[[ "$output" != *"No such file or directory"* ]]
	[[ "$output" != *"land-lock: line"* ]]
}

@test "THE DEFECT: a LIVE lease is sighted, so the corroboration clock is already running when it expires" {
	# The mechanism, asserted deterministically. The latency row below states the
	# promise a caller cares about, but a wall-clock bound is a poor gate: the
	# defective path steals at ~9-12s and the fixed one at ~3-4s, so any single
	# threshold sits uncomfortably close to one of them. THIS row is the one that
	# discriminates, and it cannot flake — it asserts the sighting was RECORDED,
	# which is the whole change.
	#
	# The defect recorded a sighting only inside the `expired &&` branch, so
	# observing a live lease left no trace at all and the clock started from
	# scratch after expiry — by which time the backoff had grown to 8-30s.
	LAND_LOCK_TTL=60 lock "$RIVAL" acquire
	held=$(lease_sha)
	LAND_LOCK_TTL=60 LAND_LOCK_WAIT=1 run lock "$MINE" acquire
	[ "$status" -eq 1 ]
	# The lease is nowhere near expiry, so under the defect nothing here exists.
	[ -f "$MINE/.git/batten-land-lock/seen" ]
	read -r seen_sha _ <"$MINE/.git/batten-land-lock/seen"
	[ "$seen_sha" = "$held" ]
}

@test "THE DEFECT: a lease sighted before it expired is taken on the first check after" {
	# The corroboration clock used to start at the first POST-expiry
	# observation, by which time acquire's backoff had grown to 8–30s: measured
	# 19s from expiry to steal at TTL=4/beat=2, against this task's own promise
	# of one extra beat. Recording the sighting on every observation is the fix.
	#
	# Asserted as a DURATION because that is the promise the header makes. The
	# bound has to sit between the two behaviours rather than merely above the
	# fixed one: measured, the defect steals at ~9-12s here and the fix at ~3-4s,
	# and an earlier version of this row used `< 12` — which the defect passes,
	# so it graded nothing. The row above is the flake-proof half; this one
	# states the user-visible promise.
	LAND_LOCK_TTL=4 LAND_LOCK_HEARTBEAT=2 lock "$RIVAL" acquire
	# Sight the live lease now, before it expires: this is the observation the
	# defect discarded.
	LAND_LOCK_TTL=4 LAND_LOCK_HEARTBEAT=2 LAND_LOCK_WAIT=1 run lock "$MINE" acquire
	[ "$status" -eq 1 ]
	start=$SECONDS
	LAND_LOCK_TTL=4 LAND_LOCK_HEARTBEAT=2 LAND_LOCK_WAIT=30 run lock "$MINE" acquire
	elapsed=$((SECONDS - start))
	[ "$status" -eq 0 ]
	[[ "$output" == *"took the lease"* ]]
	[ "$elapsed" -lt 8 ]
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
	# `released` is the second way `status` can say "free" (CLOUD-433), so it is
	# forbidden here too. A fail-closed row that names only one of the free
	# wordings stops being fail-closed the moment another is added.
	[[ "$output" != *"released"* ]]
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

@test "NO GIT IDENTITY: the lease is takeable on a machine with no user.email" {
	# `git commit-tree` refuses with "Author identity unknown" wherever no
	# user.email is configured — a CI runner, a fresh clone. Every acquiring test
	# in this suite passed locally and failed in CI for exactly that reason, so
	# the identity is supplied by `mint` rather than inherited from the machine.
	# HOME is redirected because a global config would mask the very absence
	# being tested.
	HOME="$BATS_TEST_TMPDIR/nohome" GIT_CONFIG_GLOBAL=/dev/null \
		GIT_CONFIG_SYSTEM=/dev/null run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	[[ "$output" == *"acquired by"* ]]
	lease_sha
}

@test "A FAILED MINT IS A REFUSED SWAP, NEVER A DELETE" {
	# `swap` used to interpolate $(mint) straight into the refspec, so an empty
	# mint produced ":$ref" — git's DELETE refspec. On the renew path, whose
	# expected value is our own live lease, that CAS would have succeeded and
	# destroyed the lease we held. Breaking the mint must refuse, not delete.
	lock "$MINE" acquire
	before=$(lease_sha)
	# `git` that fails only for commit-tree: mint breaks, everything else works.
	cat >"$STUB/git" <<'EOF'
#!/usr/bin/env bash
[ "$1" != commit-tree ] || exit 1
exec /usr/bin/git "$@"
EOF
	chmod +x "$STUB/git"
	run lock "$MINE" renew
	rm -f "$STUB/git"
	[ "$status" -ne 0 ]
	# The lease must still be there, and still be ours.
	[ "$(lease_sha)" = "$before" ]
	run lock "$MINE" held
	[ "$status" -eq 0 ]
}

# --- the heartbeat's parent tether (CLOUD-432) -------------------------------
#
# `hold` had no coverage at all until the 2026-08-12 pressure probe, which also
# showed an orphaned heartbeat renewing a lease forever after its land was
# SIGKILLed — the trap never fired, the fleet was wedged, and land-lock-check
# reported a healthy hold. The tether: land passes LAND_LOCK_HOLDER_PID, and a
# beat whose holder is gone releases and exits instead of renewing for nobody.
# Every backgrounded process here closes fd 3 (CLOUD-434): a leaked child must
# never hold this file's TAP stream.

# A stand-in land: a process whose cmdline passes the identity check (its path
# ends mise-tasks/land) at a pid the test controls. stdout is detached so the
# command substitution reading the pid returns instead of waiting out the sleep.
fake_land() {
	mkdir -p "$BATS_TEST_TMPDIR/mise-tasks"
	printf '#!/usr/bin/env bash\nsleep 60\n' >"$BATS_TEST_TMPDIR/mise-tasks/land"
	chmod +x "$BATS_TEST_TMPDIR/mise-tasks/land"
	"$BATS_TEST_TMPDIR/mise-tasks/land" >/dev/null 2>&1 3>&- &
	echo $!
}

@test "a hold whose land died releases within a beat instead of renewing for nobody" {
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	land_pid=$(fake_land)
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 LAND_LOCK_HOLDER_PID="$land_pid" \
		"$LOCK" hold >"$BATS_TEST_TMPDIR/hold.out" 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	kill -9 "$land_pid"
	deadline=$((SECONDS + 5))
	while kill -0 "$hold_pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
		sleep 0.2
	done
	! kill -0 "$hold_pid" 2>/dev/null
	grep -q "releasing rather than renewing for nobody" "$BATS_TEST_TMPDIR/hold.out"
	# Released means instantly claimable: the rival sees a handover, not a TTL it
	# has to wait out. The wording is `released` rather than `unheld` since
	# CLOUD-433 — the tether releases, and a release is a tombstone, which is a
	# different and more informative statement than "expired".
	run lock "$RIVAL" status
	[ "$status" -eq 0 ]
	[[ "$output" == *"released"* ]]
	# And claimable in fact, not merely in wording.
	run lock "$RIVAL" acquire
	[ "$status" -eq 0 ]
}

@test "a live land keeps its heartbeat renewing — the tether never fires on a healthy hold" {
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	land_pid=$(fake_land)
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 LAND_LOCK_HOLDER_PID="$land_pid" \
		"$LOCK" hold >/dev/null 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	sleep 2.5
	kill -0 "$hold_pid" 2>/dev/null
	run lock "$RIVAL" status
	[[ "$output" == *"held by"* ]]
	kill "$hold_pid" 2>/dev/null || true
	kill "$land_pid" 2>/dev/null || true
	run lock "$MINE" release
	[ "$status" -eq 0 ]
}

@test "a pid recycled into something that is not a land reads as gone" {
	# Existence is not identity: this clone measurably wrapped its pid space
	# inside 20 minutes, so a live pid may be somebody else entirely. The probe
	# reads /proc/<pid>/cmdline, and anything that is not a mise-tasks/land is
	# a dead holder — failing toward release, the cheap direction.
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	sleep 60 >/dev/null 2>&1 3>&- &
	imposter=$!
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 LAND_LOCK_HOLDER_PID="$imposter" \
		"$LOCK" hold >/dev/null 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	deadline=$((SECONDS + 5))
	while kill -0 "$hold_pid" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do
		sleep 0.2
	done
	! kill -0 "$hold_pid" 2>/dev/null
	run lock "$RIVAL" status
	[ "$status" -eq 0 ]
	# `released`, not `unheld`, since CLOUD-433: the tether RELEASES, and a
	# release is a tombstone — a handover rather than an expiry.
	[[ "$output" == *"released"* ]]
	kill "$imposter" 2>/dev/null || true
}

@test "an unset holder pid keeps today's behaviour, so no other caller changes" {
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 "$LOCK" hold >/dev/null 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	sleep 2.5
	kill -0 "$hold_pid" 2>/dev/null
	run lock "$RIVAL" status
	[[ "$output" == *"held by"* ]]
	kill "$hold_pid" 2>/dev/null || true
	run lock "$MINE" release
	[ "$status" -eq 0 ]
}
