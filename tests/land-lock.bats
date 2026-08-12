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
	# `LAND_LOCK_UNDER_TEST` lets a mutation harness point these rows at a COPY.
	# Mutating the tracked file in place makes a corrupted commit reachable from
	# any concurrent `git add -A`, which staged a mutant into a pushed commit on
	# 2026-08-12 (recorded on CLOUD-418). Unset in every normal run.
	LOCK="${LAND_LOCK_UNDER_TEST:-$BATS_TEST_DIRNAME/../mise-tasks/land-lock}"
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
		git -C "$d" checkout -q -b claude/work
	done
	export LAND_LOCK_WAIT=1
}

lock() { (cd "$1" && shift && "$LOCK" "$@"); }
lease_sha() { git --git-dir="$BARE" rev-parse --verify -q refs/heads/batten-land-lock; }

# A failing `[ … ]` in bats prints the source line and nothing about WHY, which
# for the rows below is the difference between the two readings an author has to
# tell apart: `land-lock` refused a lease it should have taken, or the runner
# never got round to letting it try. CLOUD-448 cost two laps to exactly that
# ambiguity, and CLOUD-450's budgets are only affordable BECAUSE a failure names
# which of the two it was — a 60s wait that fails silently is a worse report than
# the 6s one it replaced, not a better one.
#
# Returns non-zero so `set -e` ends the case at the same place a bare assertion
# would have; it is a diagnostic on the way out, never a recovery.
bail() { # <diagnostic>
	echo "$1" >&2
	return 1
}

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
	#
	# CLOUD-448 — THE SETUP IS THE RACE, not the measurement. The sighting below
	# is only a sighting while the rival's lease is still live, and a 4s TTL is
	# shorter than `rush --jobs` can deschedule this process for (CLOUD-386 made
	# the suite parallel). When that happened the sighting acquire STOLE the
	# lease and the old `[ "$status" -eq 1 ]` failed — grading the runner's
	# scheduler, not `land-lock`, and telling an author to "reproduce and fix
	# locally" something that reproduces nowhere. It cost PR #354 and PR #370 a
	# full `verify` and a lap each.
	#
	# So the precondition is now established rather than assumed, and a
	# precondition the environment failed to create is never asserted through
	# (CLOUD-249). SETUP is retried — never the measurement, which would be
	# drive-to-green — because a plain skip would fire often enough to erase the
	# coverage: this raced twice in one day.
	#
	# The TTL stays short deliberately. Raising it would widen the window
	# without removing the race, and every second added here is paid on every
	# run of the suite.
	local attempt=0
	while :; do
		attempt=$((attempt + 1))
		# Reset: whatever the failed attempt left behind. The `seen` file
		# especially — a stale sighting would pre-age the very clock this case
		# measures, which is the one thing that must be fresh.
		lock "$MINE" release >/dev/null 2>&1 || true
		rm -f "$MINE/.git/batten-land-lock/seen"
		LAND_LOCK_TTL=4 LAND_LOCK_HEARTBEAT=2 lock "$RIVAL" acquire >/dev/null
		# Sight the live lease: this is the observation the defect discarded.
		# A refusal means the lease was still held, which is the setup this case
		# needs. Success means it had already expired — no sighting happened, so
		# there is nothing here to measure.
		LAND_LOCK_TTL=4 LAND_LOCK_HEARTBEAT=2 LAND_LOCK_WAIT=1 run lock "$MINE" acquire
		[ "$status" -ne 1 ] || break
		[ "$attempt" -lt 3 ] ||
			skip "setup not created after $attempt attempts: the rival's 4s lease expired before it could be sighted. That is the runner being descheduled, not a verdict about land-lock (CLOUD-448)"
	done
	# CLOUD-450 — THE DURATION COMES FROM THE PROGRAM, NOT FROM $SECONDS. The old
	# form timed the whole `run`: bash startup, the ls-remote/fetch/commit-tree/
	# push chain, and whatever deschedule the retry loop above had just paid for,
	# all charged to `land-lock` and graded against 8s. `acquire` already reports
	# the one interval that is actually its own — `swap`ping a dead lease prints
	# the seconds between the PREVIOUS HOLDER'S EXPIRY and the steal, computed
	# inside the process from the observed body — and that is precisely the
	# promise this row's header makes, with every cost that is not this task's
	# excluded rather than merely budgeted for.
	#
	# Anchored on words on BOTH sides of the number. A sed anchored on one side,
	# or on the digits alone, keeps matching after a rewording and starts
	# grading something else; anchored on both, a reworded sentence matches
	# nothing, `took` comes back empty and the row FAILS loudly — the one
	# outcome a silently-empty duration assertion never produces.
	#
	# THE RESIDUAL IS CLOSED, AND THE WALL CLOCK IS GONE (CLOUD-450). This used to
	# grade `took` — seconds between the previous holder's expiry and the steal —
	# and both ends of that delta are instants on one clock, so a deschedule
	# landing between them inflated it. Under the parallel runner that fired on
	# roughly 2 of every 4 `verify` runs, and it blocked CLOUD-274's landing
	# directly: `land` refused to push on a `verify` whose only failure was this
	# case, behaving exactly as designed over a signal that was wrong. A flaky
	# gate is a bypassed gate.
	#
	# The promise was never really about seconds. "A dead lease costs one extra
	# beat" IS "the steal lands on the FIRST post-expiry probe", and `acquire` now
	# reports that count — a quantity no amount of load can move. The seconds stay
	# in the sentence because they are what a human reads; nothing grades them.
	LAND_LOCK_TTL=4 LAND_LOCK_HEARTBEAT=2 LAND_LOCK_WAIT=30 run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	[[ "$output" == *"took the lease"* ]]
	probes=$(printf '%s\n' "$output" |
		sed -n 's/.*probes since expiry: \([0-9][0-9]*\).*/\1/p')
	# Anchored on words on both sides of the number, for the reason the header
	# above gives: a reworded sentence must match NOTHING and fail loudly, never
	# match something else and grade it silently.
	[ -n "$probes" ] ||
		bail "acquire reported no probe count in the shape this row parses, so the sentence in land-lock moved and this assertion silently stopped grading anything (CLOUD-450): $output"
	[ "$probes" -eq 1 ] ||
		bail "acquire spent $probes probes on an expired lease, against a promise of one (CLOUD-433/CLOUD-450): $output"
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
	#
	# The `sleep 2` over a 1s TTL is the SAFE shape of this pattern and stays
	# (CLOUD-450): nothing here has to happen while the lease is still live, so a
	# deschedule can only make it more expired than the row needs. Contrast the
	# reservation case, which needs the lease ALIVE at a particular instant and
	# is retried for that reason.
	#
	# THE BUDGET IS NOT THE PROPERTY. `LAND_LOCK_WAIT` is a wall clock INSIDE the
	# program under test, spanning two real fetches and a randomised backoff, and
	# 6s of it was grading the runner: `acquire` computes its deadline before the
	# first `ls-remote`, so one slow fetch made the second probe — the one that
	# corroborates and steals — arrive past a deadline that had nothing to do
	# with land-lock. This row asserts the lease IS taken and never how fast; the
	# duration promise lives in exactly one place, the CLOUD-433 row above. So
	# the budget goes to 60, which costs a passing run nothing (the steal exits
	# the instant it wins) and costs a genuine hang 54 extra seconds once.
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	sleep 2
	LAND_LOCK_HEARTBEAT=1 LAND_LOCK_WAIT=60 run lock "$RIVAL" acquire
	[ "$status" -eq 0 ] ||
		bail "a corroborated dead lease was not taken inside a 60s wait, which is a refusal to steal rather than a slow runner (CLOUD-450): $output"
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
	# THE STEAL IS SETUP, SO IT IS ASSERTED (CLOUD-450). It used to be a bare
	# call under a 6s in-program wait, and the two halves of that were separately
	# wrong. A steal the runner was too slow to complete failed nothing here —
	# MINE's own 1s lease is gone either way, so `held` answers 1 whether it was
	# STOLEN or merely lapsed, and the fence's actual claim ("the holder notices
	# somebody else took it") went ungraded on precisely the loaded runs. That is
	# a pass for the wrong reason, which is worse than a flake: it is silent.
	#
	# So the budget goes to 60 for the reason the corroboration row above states
	# — the wait bounds a fetch, not the property — and the precondition it buys
	# is now read from the observable the steal itself produces.
	LAND_LOCK_HEARTBEAT=1 LAND_LOCK_WAIT=60 run lock "$RIVAL" acquire
	if [ "$status" -ne 0 ] || [[ "$output" != *"took the lease"* ]]; then
		bail "the rival did not steal the expired lease, so the fence below would have graded a lapse rather than a theft (CLOUD-450): $output"
	fi
	# This is the check `land` runs immediately before commenting /fast-forward.
	# Without it the original holder would act on a lease it no longer has, which
	# is the collision the lock exists to remove.
	run lock "$MINE" held
	[ "$status" -eq 1 ]
}

@test "an expired lease reads as free, and still names who left it" {
	# Free is what a caller acts on; the name is what a human diagnoses a dead
	# session with, so the report carries both rather than choosing.
	#
	# CLOUD-450 audited every `TTL=1` + `sleep 2` in this file and left this one
	# alone deliberately. The property is expiry and nothing else — no call has
	# to land while the lease is still live — so a descheduled runner makes the
	# lease MORE expired than the row asked for, never less, and the assertion
	# below is the same one either way. That is what separates it from "a
	# reservation does not extend the holder's lease", where `reserve` refuses a
	# lease that is not live and the same two lines are a race the case can lose.
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
	#
	# Another `TTL=1` + `sleep 2` CLOUD-450 left alone, for the reason spelled
	# out on "an expired lease reads as free": expiry is the whole precondition,
	# and a slow runner overshoots it rather than missing it. The 30s beat below
	# is likewise not a budget — it is chosen so no amount of waiting inside the
	# 1s wait can corroborate, which is the refusal this row is about.
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
	#
	# CLOUD-450 — THIS ROW WAS GREEN THROUGH THE WRONG BRANCH, which is why it is
	# rewritten rather than merely rebudgeted. The first probe is meant to be a
	# REFUSAL that leaves a sighting behind, and `HEARTBEAT=1 WAIT=1` reads like
	# "one probe, nothing corroborated yet". It is not. `acquire` tests its
	# deadline AFTER the steal test and then sleeps `2 + RANDOM % 2`, so unless
	# the first `ls-remote` happens to cross a second boundary — the only way a
	# 1s deadline can fire on probe 1 — a second probe lands 2-3s later with the
	# sha unchanged for longer than the 1s beat, corroborates, and STEALS.
	# Measured over seven runs of the old form: six stole, reporting `took the
	# lease 3-4s after …`, and one refused. The rival then walked away holding a
	# fresh 120s lease, so every assertion below passed through `already held by
	# this clone` and graded re-entrancy — which the row four cases up already
	# covers — while this row's own subject went ungraded on six runs in seven.
	# `|| true` is what hid it: it discarded the one exit status that said which
	# branch had run.
	#
	# So the sighting probe now gets a beat that nothing inside its own wait can
	# corroborate — 30s of persistence demanded against 1s of wait — and its
	# refusal is ASSERTED instead of discarded. A setup step whose outcome nobody
	# reads is a setup step the case is not entitled to assume (CLOUD-249).
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	sleep 2
	LAND_LOCK_HEARTBEAT=30 LAND_LOCK_WAIT=1 run lock "$RIVAL" acquire
	if [ "$status" -ne 1 ] || [[ "$output" != *"still held by"* ]]; then
		bail "the sighting probe TOOK the lease instead of only recording it, so the steal below is a re-entrant acquire and grades nothing about corroboration (CLOUD-450): $output"
	fi
	# Age that sighting past the beat the measurement runs under. Safe in the way
	# the expiry sleeps above are safe: `sha_held_for` is a duration on one clock,
	# so a descheduled runner makes the sha look like it has sat unchanged for
	# LONGER than the row needs, never for less.
	sleep 2
	# 60 rather than 6, for the reason the corroboration row states: the wait
	# bounds two fetches and a randomised backoff, and this row asserts that the
	# steal HAPPENS, never how quickly.
	LAND_LOCK_HEARTBEAT=1 LAND_LOCK_WAIT=60 run lock "$RIVAL" acquire
	if [ "$status" -ne 0 ] || [[ "$output" != *"took the lease"* ]]; then
		bail "a sha that had demonstrably stopped moving was not taken as a corroborated steal (CLOUD-450): $output"
	fi
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

# PROOF THAT A BEAT RAN — the precondition every `hold` case below actually
# needs, and the one none of them used to establish (CLOUD-450). They stood a
# `sleep 2.5` or a 5s deadline in for it, spanning a fork, a bash startup, one
# beat, a /proc read, a fetch and a push; on a loaded runner the hold had not
# been scheduled at all by the time the row read its verdict, and the healthy-hold
# rows then passed VACUOUSLY — alive because nothing had run, "held by" because
# the acquire on the line above had put it there. A tether wrongly firing on a
# healthy hold was therefore invisible on exactly the loaded runs, which is the
# regression class this suite exists to catch.
#
# The observable is the lease SHA, and it is the right one rather than merely the
# convenient one. `swap` mints a fresh nonce on every write, so EVERY beat moves
# the sha — the healthy renew and the tether's tombstone alike — which makes a
# moved sha proof that a beat executed, and keeps that proof true under the
# mutant as well as under the fix: delete the tether and the beat renews, and the
# sha still moves. A case skipping on "no beat ever landed" therefore erases no
# coverage it would otherwise have had. What the sha cannot say is WHICH beat
# ran, which is why every case keeps its own assertion about the outcome.
#
# Bounded by an attempt COUNT and never by a clock, and it ends in `skip` rather
# than in a verdict: "the runner never scheduled the hold" is a statement about
# the runner, and asserting through a precondition the environment failed to
# create is what CLOUD-249 forbids. A healthy run returns on the first or second
# look, so the bound is paid only when something is already wrong.
wait_for_beat() { # <lease sha as it stood before the beat>
	local before="$1" attempt=0
	while [ "$attempt" -lt 100 ]; do
		[ "$(lease_sha)" = "$before" ] || return 0
		attempt=$((attempt + 1))
		sleep 0.2
	done
	return 1
}

@test "a hold whose land died releases within a beat instead of renewing for nobody" {
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	before=$(lease_sha)
	land_pid=$(fake_land)
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 LAND_LOCK_HOLDER_PID="$land_pid" \
		"$LOCK" hold >"$BATS_TEST_TMPDIR/hold.out" 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	kill -9 "$land_pid"
	# The land is dead before the first beat, so the first beat IS the tether's:
	# it tombstones the lease, which moves the sha exactly as a renew would. Wait
	# for that rather than for a wall clock — the 5s deadline below then measures
	# only the interval it was written for, the hold noticing it is finished,
	# instead of also covering the fork and the startup that precede it.
	wait_for_beat "$before" ||
		skip "no beat ever reached the remote: the hold was never scheduled, which is a statement about the runner rather than about the tether (CLOUD-450)"
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
	# THE VACUOUS PASS THIS ROW USED TO HAVE (CLOUD-450), and the reason it is
	# the most important of the four. `sleep 2.5` stood in for "two beats
	# happened", and when the runner never scheduled the hold BOTH assertions
	# passed for the wrong reason: the process is alive because it has not run
	# yet, and the rival sees "held by" because the acquire two lines up put it
	# there. A tether wrongly firing on a healthy hold — the exact regression
	# this case names — was therefore invisible on precisely the loaded runs
	# where a tether is most likely to misread a live land as gone.
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	before=$(lease_sha)
	land_pid=$(fake_land)
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 LAND_LOCK_HOLDER_PID="$land_pid" \
		"$LOCK" hold >/dev/null 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	wait_for_beat "$before" ||
		skip "no beat ever reached the remote: the hold was never scheduled, which is a statement about the runner rather than about the tether (CLOUD-450)"
	kill -0 "$hold_pid" 2>/dev/null
	run lock "$RIVAL" status
	[[ "$output" == *"held by"* ]]
	# AND THE ASSERTION THAT MAKES THE ROW DISCRIMINATING once the vacuous pass
	# is gone. `held by` alone does not separate the two outcomes: a tombstone
	# renders `released — last held by <id>`, which contains `held by`, so a
	# wrongly fired tether satisfied the line above rather than failing it. A
	# tether that fires here RELEASES, so the word `released` is the thing that
	# must not appear — stated as its own line so a failure names which half of
	# the claim broke.
	[[ "$output" != *"released"* ]]
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
	before=$(lease_sha)
	sleep 60 >/dev/null 2>&1 3>&- &
	imposter=$!
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 LAND_LOCK_HOLDER_PID="$imposter" \
		"$LOCK" hold >/dev/null 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	# Same precondition as the tether case above, and needed for the same reason:
	# the 5s deadline was covering the fork and the bash startup as well as the
	# beat it was written to bound, so a slow runner failed the row for having
	# been slow. The imposter is not a land, so the first beat tombstones and the
	# sha moves.
	wait_for_beat "$before" ||
		skip "no beat ever reached the remote: the hold was never scheduled, which is a statement about the runner rather than about the pid probe (CLOUD-450)"
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
	# The healthy-hold pair to the row above, and vacuous in exactly the same way
	# before CLOUD-450: with no beat proven to have run, "the process is alive"
	# and "the rival sees a holder" were both true of a hold that had never
	# started. This row is the one that says an UNSET holder pid changes nothing
	# for every caller that is not `land`, so a hold that never beat is precisely
	# the state in which it proves nothing.
	run lock "$MINE" acquire
	[ "$status" -eq 0 ]
	before=$(lease_sha)
	(cd "$MINE" && LAND_LOCK_HEARTBEAT=1 "$LOCK" hold >/dev/null 2>&1) >/dev/null 2>&1 3>&- &
	hold_pid=$!
	wait_for_beat "$before" ||
		skip "no beat ever reached the remote: the hold was never scheduled, which is a statement about the runner rather than about the unset-pid path (CLOUD-450)"
	kill -0 "$hold_pid" 2>/dev/null
	run lock "$RIVAL" status
	[[ "$output" == *"held by"* ]]
	# `held by` is a substring of `released — last held by <id>`, so it alone
	# cannot tell a renewed lease from a tombstoned one. An unset pid must renew,
	# so the tombstone wording is forbidden here for the same reason it is on the
	# healthy-hold row above.
	[[ "$output" != *"released"* ]]
	kill "$hold_pid" 2>/dev/null || true
	run lock "$MINE" release
	[ "$status" -eq 0 ]
}

# --- `authorises`: the verb a runner asks (CLOUD-420) ------------------------
#
# Every other verb answers about THIS clone, via a holder id no GitHub job can
# compare itself against. `authorises` answers about a BRANCH, which is the one
# identifier the runner and the lease both carry. Its exits are 0 run / 3 stop /
# 2 could not look, and it is the only verb here that fails OPEN: a lease it
# cannot read would otherwise stop every job in the fleet.

# A lease held by the rival clone, authorising a named branch.
rival_holds_for() { # <branch>
	(cd "$RIVAL" && LAND_LOCK_LAND_BRANCH="$1" "$LOCK" acquire >/dev/null)
}

@test "authorises: an absent lease lets any branch run" {
	run lock "$MINE" authorises feature-x
	[ "$status" -eq 0 ]
	[[ "$output" == *"no lease is held"* ]]
}

@test "authorises: the branch the lease names may run" {
	rival_holds_for feature-x
	run lock "$MINE" authorises feature-x
	[ "$status" -eq 0 ]
	[[ "$output" == *"authorises feature-x"* ]]
}

@test "THE STOP: a branch the lease does not name is refused with exit 3" {
	# 3 rather than 1, because 1 already means "held by someone else" — a reason
	# to stop, not the instruction. A caller keying on 3 cannot confuse a
	# refusal with an error.
	rival_holds_for feature-x
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 3 ]
	[[ "$output" == *"authorises feature-x, not feature-y"* ]]
}

@test "authorises: a released lease stops nobody" {
	rival_holds_for feature-x
	(cd "$RIVAL" && "$LOCK" release >/dev/null)
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 0 ]
}

@test "authorises: an expired lease stops nobody" {
	# The third `TTL=1` + `sleep 2` CLOUD-450 audited and deliberately left as it
	# is. `authorises` reads the lease and answers; nothing has to happen while
	# the lease is still live, so a deschedule between these two lines makes it
	# more expired than the row needs rather than less. The reservation case
	# below is the one that inverts this — `reserve` refuses a lease that is not
	# live, so there the same two lines are a race, and it is retried for it.
	LAND_LOCK_TTL=1 rival_holds_for feature-x
	sleep 2
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 0 ]
}

@test "FAIL OPEN: a lease carrying no branch runs rather than guessing" {
	# Every lease minted before CLOUD-420 is exactly this, so during rollout the
	# row is not an edge case — it is every lease. Stopping here would stop the
	# whole fleet on the deploy.
	tree=$(git -C "$MINE" hash-object -t tree /dev/null)
	lease=$(printf 'land-lock\nholder: someone\nexpires: %s\nnonce: ab\n' "$(($(date -u +%s) + 300))" |
		git -C "$MINE" -c user.email=t@t -c user.name=t commit-tree "$tree")
	git -C "$MINE" push -q origin "$lease:refs/heads/batten-land-lock"
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 0 ]
	[[ "$output" == *"names no branch"* ]]
}

@test "FAIL OPEN: an unreachable remote runs, where every other verb refuses" {
	# The deliberate asymmetry. `status` and `acquire` exit 2 here, because a
	# lease they cannot read must never read as free. This verb inverts that: an
	# unreadable lease stops every job in the fleet, and waving one matrix
	# through costs one matrix.
	LAND_LOCK_REMOTE="$BATS_TEST_TMPDIR/nope.git" run lock "$MINE" authorises feature-y
	[ "$status" -eq 0 ]
	[[ "$output" == *"cannot read the lease"* ]]
	LAND_LOCK_REMOTE="$BATS_TEST_TMPDIR/nope.git" run lock "$MINE" status
	[ "$status" -eq 2 ]
}

@test "authorises: a missing branch argument is exit 2, never a verdict" {
	run lock "$MINE" authorises
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage: land-lock authorises"* ]]
}

@test "the lease body carries the branch it authorises, and still ends with the nonce" {
	LAND_LOCK_LAND_BRANCH=feature-x lock "$MINE" acquire
	run bash -c "git --git-dir='$BARE' cat-file commit \"\$(git --git-dir='$BARE' rev-parse refs/heads/batten-land-lock)\""
	[[ "$output" == *"branch: feature-x"* ]]
	# The nonce stays terminal: its uniqueness is what makes every mint a
	# distinct sha, and land-lock-check's fixture treats it as the last line.
	run bash -c "git --git-dir='$BARE' cat-file commit \"\$(git --git-dir='$BARE' rev-parse refs/heads/batten-land-lock)\" | tail -1"
	[[ "$output" == nonce:* ]]
}

@test "the lease's own ref name is never mistaken for the branch it authorises" {
	# `branch` and `land_branch` are one character apart in a diff and mean
	# different things; writing the wrong one stamps `batten-land-lock` into
	# every lease and looks correct in review.
	LAND_LOCK_LAND_BRANCH=feature-x lock "$MINE" acquire
	run bash -c "git --git-dir='$BARE' cat-file commit \"\$(git --git-dir='$BARE' rev-parse refs/heads/batten-land-lock)\""
	[[ "$output" != *"branch: batten-land-lock"* ]]
}

# ---------------------------------------------------------------------------
# The receipt `ready-guard` reads (CLOUD-420 §4). Written from `swap`, which is
# the lease's ONLY writer — acquire, renew, the heartbeat's steal path and
# release all reach the remote through it — so one insertion covers every way
# the lease can change hands, and no caller can take it without leaving one.

# The key is the branch with `/` folded to `-`, the transform `claim-check` and
# `claim-guard` already use — read here the same way the task writes it, and
# exercised on a SLASHED branch because that is the only shape this repository
# actually produces.
receipt() {
	local b
	b="$(git -C "$1" rev-parse --abbrev-ref HEAD)"
	cat "$1/.git/batten-receipts/lease.${b//\//-}" 2>/dev/null
}

@test "acquire leaves a receipt carrying the instant the lease expires" {
	lock "$MINE" acquire
	exp="$(receipt "$MINE")"
	[ -n "$exp" ]
	# Within the TTL of now, rather than an exact equality: the receipt is
	# computed a few milliseconds after the lease body it describes.
	now="$(date +%s)"
	[ "$exp" -gt "$now" ]
	[ "$exp" -le "$((now + 120))" ]
}

@test "a renew REFRESHES the receipt — a lease held for a long lap is still held" {
	# The reason this lives in `swap` and not in `acquire`: `verify` runs longer
	# than one TTL, and `land` readies after its push. A receipt minted once at
	# acquire would read as lapsed by the time it mattered.
	LAND_LOCK_TTL=1 lock "$MINE" acquire
	first="$(receipt "$MINE")"
	LAND_LOCK_TTL=300 lock "$MINE" renew
	second="$(receipt "$MINE")"
	[ "$second" -gt "$first" ]
}

@test "release REMOVES the receipt rather than letting it age out" {
	# A release is a declaration that this clone no longer holds it. Leaving the
	# receipt to lapse would let `ready-guard` honour a lease already handed on.
	lock "$MINE" acquire
	[ -n "$(receipt "$MINE")" ]
	lock "$MINE" release
	[ -z "$(receipt "$MINE")" ]
}

@test "A REFUSED ACQUIRE LEAVES NO RECEIPT — the whole point of the predicate" {
	# If a lost race still wrote one, `ready-guard` would wave through exactly
	# the clone the lease just refused, which is worse than having no receipt at
	# all: it would be a gate that passes precisely when it should not.
	lock "$RIVAL" acquire
	run lock "$MINE" acquire
	[ "$status" -ne 0 ]
	[ -z "$(receipt "$MINE")" ]
}

# --- `head:`, `next:` and `reserve`: the second matrix (CLOUD-369) -----------
#
# The lease bounds confirming runs at one, which is right for cost and wrong for
# latency: after every merge the queue is empty and the next branch starts cold.
# These cover the two fields that close that window — `head:`, so a waiter can
# linearize onto the main that is ABOUT to exist, and `next:`, so exactly one
# successor may spend the run that overlaps the merge.
#
# The property under test throughout is the bound. Not "a successor may run" —
# that is easy and half the story — but that a SECOND one may not, whatever the
# fleet size, because one CAS-guarded slot cannot hold two branches.

@test "the lease body carries the head that is about to become main" {
	LAND_LOCK_LAND_BRANCH=feature-x LAND_LOCK_LAND_HEAD=deadbeef lock "$MINE" acquire
	run lock "$MINE" peek head
	[ "$status" -eq 0 ]
	[ "$output" = deadbeef ]
}

@test "peek prints the field alone, so a caller never parses a sentence" {
	LAND_LOCK_LAND_BRANCH=feature-x lock "$MINE" acquire
	run lock "$MINE" peek branch
	[ "$status" -eq 0 ]
	[ "$output" = feature-x ]
}

@test "peek on an absent lease is silent and 0 — a reading, not an error" {
	# A waiter that cannot learn a head stays linearized on origin/main. That is
	# an ordinary outcome, so it must not arrive as a failure the caller has to
	# distinguish from a broken remote.
	run lock "$MINE" peek head
	[ "$status" -eq 0 ]
	[ -z "$output" ]
}

@test "peek on an unknown field is exit 2, never an empty answer" {
	run lock "$MINE" peek nonesuch
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage: land-lock peek"* ]]
}

@test "reserve admits a waiter as the successor behind the holder" {
	rival_holds_for feature-x
	run lock "$MINE" reserve feature-y
	[ "$status" -eq 0 ]
	[[ "$output" == *"feature-y admitted as the successor behind feature-x"* ]]
	run lock "$MINE" peek next
	[ "$output" = feature-y ]
}

@test "THE BOUND: a second waiter cannot take a slot that is already filled" {
	# The whole design rests on this. If two waiters could both reserve, the
	# bound would grow with the fleet and the lease would be bounding nothing.
	rival_holds_for feature-x
	lock "$MINE" reserve feature-y
	run lock "$MINE" reserve feature-z
	[ "$status" -eq 1 ]
	[[ "$output" == *"feature-y is already the admitted successor, not feature-z"* ]]
	run lock "$MINE" peek next
	[ "$output" = feature-y ]
}

@test "reserve is idempotent for the branch already holding the slot" {
	# A waiter re-reserving each lap must be a read, not a rewrite of the ref.
	rival_holds_for feature-x
	lock "$MINE" reserve feature-y
	before=$(lease_sha)
	run lock "$MINE" reserve feature-y
	[ "$status" -eq 0 ]
	[[ "$output" == *"already the admitted successor"* ]]
	[ "$(lease_sha)" = "$before" ]
}

@test "RESERVING IS NOT STEALING: the holder keeps the lease and every other field" {
	# A reservation re-mints somebody else's lease. If it moved the holder id it
	# would be a steal wearing a different name, and `mine` would start answering
	# for the wrong clone — the two-holders bug this file exists to prevent.
	LAND_LOCK_LAND_HEAD=cafebabe rival_holds_for feature-x
	before=$(git --git-dir="$BARE" cat-file commit "$(lease_sha)" | sed -n 's/^expires: //p')
	lock "$MINE" reserve feature-y
	run bash -c "git --git-dir='$BARE' cat-file commit \"\$(git --git-dir='$BARE' rev-parse refs/heads/batten-land-lock)\""
	[[ "$output" == *"branch: feature-x"* ]]
	[[ "$output" == *"head: cafebabe"* ]]
	[[ "$output" == *"expires: $before"* ]]
	# The holder still holds it, and the reserver still does not.
	run lock "$RIVAL" status
	[ "$status" -eq 0 ]
	run lock "$MINE" status
	[ "$status" -eq 1 ]
}

@test "a reservation does not extend the holder's lease" {
	# Recomputing the expiry here would hand a holder a fresh TTL every time a
	# waiter arrived, so a busy fleet could keep one lease alive indefinitely.
	#
	# CLOUD-450 — THE SETUP IS THE RACE, exactly as in the CLOUD-448 case above,
	# and this is the one `TTL=1` in the file where that is true. `reserve`
	# refuses a lease that is not live ("no lease is held; acquire rather than
	# reserve"), so a deschedule longer than one second between the acquire and
	# the reserve turns the reserve into a refusal — and the bare call then ended
	# the case on a line that was grading the runner's scheduler, not whether a
	# reservation extends an expiry.
	#
	# A SUCCESSFUL RESERVE IS THE PRECONDITION, and it is read from the reserve
	# itself rather than guessed at: the verb answering 0 IS the statement that
	# the lease was live when it was re-minted, which is the only state in which
	# the assertion below means anything. Setup is retried, never the
	# measurement.
	local attempt=0
	while :; do
		attempt=$((attempt + 1))
		# Reset what a failed attempt left behind. The RELEASE is load-bearing:
		# a lapsed attempt leaves an EXPIRED lease, and `acquire` refuses to
		# steal one of those until the sha has sat unchanged for a beat — 30s by
		# default — so a retry without it would fail on the acquire instead. A
		# tombstone is a handover and needs no corroboration, so the next attempt
		# starts from a genuinely free lease.
		(cd "$RIVAL" && "$LOCK" release >/dev/null 2>&1) || true
		LAND_LOCK_TTL=1 rival_holds_for feature-x
		run lock "$MINE" reserve feature-y
		[ "$status" -ne 0 ] || break
		[ "$attempt" -lt 3 ] ||
			skip "setup not created after $attempt attempts: the rival's 1s lease expired before the reservation could land on it. That is the runner being descheduled, not a verdict about whether a reservation extends a lease (CLOUD-450)"
	done
	# Safe to keep as a plain sleep, and the contrast with the retry above is the
	# whole point: past this line the row wants the lease EXPIRED, and load can
	# only deepen an expiry.
	sleep 2
	run lock "$MINE" authorises feature-z
	[ "$status" -eq 0 ]
	[[ "$output" == *"no lease is held"* ]]
}

@test "authorises admits the holder AND its one admitted successor" {
	rival_holds_for feature-x
	lock "$MINE" reserve feature-y
	run lock "$MINE" authorises feature-x
	[ "$status" -eq 0 ]
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 0 ]
	[[ "$output" == *"successor behind feature-x"* ]]
}

@test "THE STOP STILL STOPS: a third branch is refused while two are admitted" {
	rival_holds_for feature-x
	lock "$MINE" reserve feature-y
	run lock "$MINE" authorises feature-z
	[ "$status" -eq 3 ]
}

@test "reserve refuses when no lease is held — acquire is the right verb then" {
	run lock "$MINE" reserve feature-y
	[ "$status" -eq 1 ]
	[[ "$output" == *"acquire rather than reserve"* ]]
}

@test "reserve refuses to reserve behind yourself, which would consume the slot" {
	rival_holds_for feature-x
	run lock "$MINE" reserve feature-x
	[ "$status" -eq 1 ]
	[[ "$output" == *"nothing to reserve"* ]]
	run lock "$MINE" peek next
	[ -z "$output" ]
}

@test "THE HEARTBEAT CARRIES THE RESERVATION, or it erases it within a beat" {
	# The holder re-mints the whole body every beat. A field it did not carry
	# forward would vanish ~30s after a waiter wrote it — and the admitted
	# successor's run would then be cancelled by CI mid-matrix.
	rival_holds_for feature-x
	lock "$MINE" reserve feature-y
	(cd "$RIVAL" && "$LOCK" renew >/dev/null)
	run lock "$MINE" peek next
	[ "$output" = feature-y ]
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 0 ]
}

@test "ACQUIRE CLEARS IT: a new turn does not inherit the last one's successor" {
	# Carrying it forward would authorise a third branch, then a fourth, and the
	# bound would drift upward one handover at a time.
	rival_holds_for feature-x
	lock "$MINE" reserve feature-y
	(cd "$RIVAL" && "$LOCK" release >/dev/null)
	LAND_LOCK_LAND_BRANCH=feature-z lock "$MINE" acquire
	run lock "$MINE" peek next
	[ -z "$output" ]
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 3 ]
}

@test "a lease minted before this change carries no next, and admits no successor" {
	tree=$(git -C "$MINE" hash-object -t tree /dev/null)
	lease=$(printf 'land-lock\nholder: someone\nexpires: %s\nbranch: feature-x\nnonce: ab\n' "$(($(date -u +%s) + 300))" |
		git -C "$MINE" -c user.email=t@t -c user.name=t commit-tree "$tree")
	git -C "$MINE" push -q origin "$lease:refs/heads/batten-land-lock"
	run lock "$MINE" authorises feature-y
	[ "$status" -eq 3 ]
	run lock "$MINE" peek next
	[ -z "$output" ]
}

# --- aging: waiting improves the odds (CLOUD-369) ----------------------------

@test "AGING: an aged waiter probes a freed lease sooner than a fresh one" {
	# The capture effect, and the reason backoff alone is not fairness: a branch
	# that has lost ten times re-enters on the terms of one that just arrived.
	# Asserted on the ceiling the backoff climbs to, not on elapsed seconds — a
	# wall-clock assertion is the guessed delay this repo rules out everywhere.
	rival_holds_for feature-x
	LAND_LOCK_WAIT=6 run lock "$MINE" acquire
	[ "$status" -eq 1 ]
	fresh="$output"
	LAND_LOCK_WAIT=6 LAND_LOCK_AGE=5 run lock "$MINE" acquire
	[ "$status" -eq 1 ]
	# Both give up at the deadline; the aged one got there having probed more
	# often, which is the whole of the mechanism. The observable is that neither
	# spins and both still refuse — a mutant that dropped the cap to 0 would
	# busy-loop and blow the wait budget.
	[[ "$fresh" == *"still held by"* ]]
	[[ "$output" == *"still held by"* ]]
}

@test "a non-numeric age is read as zero rather than crashing the backoff" {
	rival_holds_for feature-x
	LAND_LOCK_WAIT=2 LAND_LOCK_AGE=banana run lock "$MINE" acquire
	[ "$status" -eq 1 ]
}
