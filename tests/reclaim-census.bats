#!/usr/bin/env bats
# reclaim-census: was active work live when a container was replaced? (CLOUD-451)
#
# The question decides whether occupancy is the right lever at all, and it was
# unanswerable when `plan-hold` shipped a deny against every handoff on the
# unmeasured assumption that it is (CLOUD-515). So the rows below are all about
# the ONE distinction the verdict rests on: a loop that CHOSE to stop leaves an
# `x`, a loop the container killed leaves an `h`, and no clock is consulted
# either way — CLOUD-491 measured the last 182s of writes not surviving a
# replacement, so a "how recent is the last beat" reading is stale exactly when
# it is asked.
#
# `BATTEN_BOOT_TIME` is injected throughout. Without it `/proc/stat` is the only
# boot source, no row could vary the boot, and the suite would ship as coverage
# while discriminating nothing (CLOUD-418).

setup() {
	CENSUS="$BATS_TEST_DIRNAME/../mise-tasks/reclaim-census"
	REPO="$BATS_TEST_TMPDIR/clone"
	mkdir -p "$REPO"
	git -C "$REPO" init -q .
	LOG="$REPO/.git/batten-reclaim-log"
	BOOTS="$REPO/.git/batten-boots"
	THIS_BOOT=2000
	PRIOR_BOOT=1000
	export BATTEN_BOOT_TIME="$THIS_BOOT"
}

census() { (cd "$REPO" && run "$CENSUS" "$@"); }
# `run` inside a subshell does not export status/output, so callers use this.
at() { (cd "$REPO" && "$CENSUS" "$@"); }

# --- the verdict table --------------------------------------------------------

@test "an h from a PREVIOUS boot is active work the replacement interrupted" {
	printf 'h 1500 %s\n' "$PRIOR_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 0 ]
	[[ "$output" == *"ACTIVE WORK was live"* ]]
}

@test "an x is a stop on purpose — the container was idle when it was replaced" {
	printf 'h 1400 %s\nx 1500 %s land-stopped\n' "$PRIOR_BOOT" "$PRIOR_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 1 ]
	[[ "$output" == *"stopped on purpose"* ]]
}

@test "an h from THIS boot spanned nothing — it is our own beat" {
	printf 'h 2100 %s\n' "$THIS_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 1 ]
	[[ "$output" == *"from this boot"* ]]
}

@test "no log but a prior boot recorded: the disk is preserved and nothing ran" {
	printf '%s\n' "$PRIOR_BOOT" >"$BOOTS"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 1 ]
	[[ "$output" == *"no work has ever been recorded"* ]]
}

@test "no log and no prior boot is CANNOT LOOK, never a false 'nothing was live'" {
	# A fresh disk destroys the evidence. Answering 1 here would credit occupancy
	# for an idle reading nothing observed — the direction that licenses a
	# mechanism on no evidence, which is what CLOUD-515 removed.
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 2 ]
	[[ "$output" == *"no evidence either way"* ]]
}

@test "an empty log reads as absent rather than as a corrupt record" {
	: >"$LOG"
	printf '%s\n' "$PRIOR_BOOT" >"$BOOTS"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 1 ]
	[[ "$output" == *"no work has ever been recorded"* ]]
}

@test "an unreadable last record is exit 2, never a verdict" {
	printf 'garbage\n' >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 2 ]
	[[ "$output" == *"unreadable"* ]]
}

@test "a record with non-numeric timestamps is exit 2, never a verdict" {
	printf 'h notanepoch %s\n' "$PRIOR_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 2 ]
	[[ "$output" == *"no usable timestamps"* ]]
}

@test "a malformed BATTEN_BOOT_TIME is cannot-look, not a silent /proc fallback" {
	printf 'h 1500 %s\n' "$PRIOR_BOOT" >"$LOG"
	cd "$REPO"
	BATTEN_BOOT_TIME=nonsense run "$CENSUS" report
	[ "$status" -eq 2 ]
}

@test "an unknown verb exits 2 and names the ones that exist" {
	cd "$REPO"
	run "$CENSUS" bogus
	[ "$status" -eq 2 ]
	[[ "$output" == *"unknown mode"* ]]
}

# --- what the recorders actually write ----------------------------------------

@test "note h appends a beat carrying the epoch and the boot, and no reason field" {
	at note h
	run cat "$LOG"
	[ "$status" -eq 0 ]
	# Three fields exactly: a trailing space would be a byte difference between
	# two records that mean the same thing (non-negotiable 5).
	[[ "$output" =~ ^h\ [0-9]+\ 2000$ ]]
}

@test "note x carries its reason, which is what makes the census readable later" {
	at note x land-stopped
	run cat "$LOG"
	[[ "$output" =~ ^x\ [0-9]+\ 2000\ land-stopped$ ]]
}

@test "note refuses a kind that is neither h nor x rather than inventing one" {
	cd "$REPO"
	run "$CENSUS" note q
	[ "$status" -eq 2 ]
}

@test "A SENSOR NEVER KILLS WHAT IT OBSERVES: an unwritable log is still exit 0" {
	# Called from inside land-lock's renewal loop. A census that could abort a
	# landing would be a worse defect than the evidence it fails to collect.
	chmod -w "$REPO/.git"
	cd "$REPO"
	run "$CENSUS" note h
	chmod +w "$REPO/.git"
	[ "$status" -eq 0 ]
}

@test "record-boot is idempotent by the last line, so a resumed session adds nothing" {
	at record-boot
	at record-boot
	run wc -l <"$BOOTS"
	[[ "${output// /}" == "1" ]]
}

@test "record-boot appends when the boot genuinely changed" {
	printf '%s\n' "$PRIOR_BOOT" >"$BOOTS"
	at record-boot
	run cat "$BOOTS"
	[[ "$output" == *"$PRIOR_BOOT"* ]]
	[[ "$output" == *"$THIS_BOOT"* ]]
}

# --- the two rows that are not fixtures, because they are the claim -----------

@test "A KILLED LOOP LEAVES AN h, even though its trap runs" {
	# The whole mechanism in one row. CLOUD-491's finding is that a trap fires on
	# the kill too, so an `x` written from one would report every reclaimed
	# container as an intentional stop — the false negative that hides the event
	# the census exists to catch. Proven with a real SIGKILL, not a fixture.
	cd "$REPO"
	env BATTEN_BOOT_TIME="$PRIOR_BOOT" bash -c '
		trap "exit 0" EXIT TERM
		while :; do "$1" note h; sleep 0.2; done
	' _ "$CENSUS" &
	loop=$!
	sleep 1
	kill -9 "$loop" 2>/dev/null || true
	wait "$loop" 2>/dev/null || true
	run tail -n 1 "$LOG"
	[[ "$output" == h\ * ]]
	# And it is then read as the replacement having interrupted work.
	run "$CENSUS" report
	[ "$status" -eq 0 ]
}

@test "a loop that stops on purpose leaves the matching x" {
	cd "$REPO"
	env BATTEN_BOOT_TIME="$PRIOR_BOOT" bash -c '
		"$1" note h; "$1" note h; "$1" note x land-stopped
	' _ "$CENSUS"
	run tail -n 1 "$LOG"
	[[ "$output" == x\ *land-stopped ]]
	run "$CENSUS" report
	[ "$status" -eq 1 ]
}

# --- the call sites, so the wiring cannot go dead unnoticed -------------------

@test "land-lock's hold loop records a beat and every stop it chooses" {
	LOCK="$BATS_TEST_DIRNAME/../mise-tasks/land-lock"
	run grep -c 'beat_note x' "$LOCK"
	# Four paths where the loop chooses to stop: holder gone, stalled, lease
	# lost, lease lapsed. A new exit added without a record is a silent gap.
	[ "$output" -eq 4 ]
	run grep -c 'beat_note h' "$LOCK"
	[ "$output" -eq 1 ]
}

@test "land records the stop it causes itself, or every clean landing reads as a reclaim" {
	# The commonest stop of all is land killing its own heartbeat on a normal
	# finish; the loop never runs another statement, so its last record stays an
	# `h`. Without this line every successful landing would later read as
	# "the container died under active work".
	run grep -c 'note x land-stopped' "$BATS_TEST_DIRNAME/../mise-tasks/land"
	[ "$output" -eq 1 ]
}
