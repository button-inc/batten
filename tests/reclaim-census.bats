#!/usr/bin/env bats
# subject: mise-tasks/reclaim-census.sh
# reclaim-census: what was in flight when a container was replaced? (CLOUD-451)
#
# The question decides whether occupancy is the right lever at all, and it was
# unanswerable when `plan-hold` shipped a deny against every handoff on the
# unmeasured assumption that it is (CLOUD-515).
#
# THE ROWS BELOW ARE ABOUT TRANSITIONS, not about files, and that is CLOUD-696's
# correction. The first version read the log's newest line and compared it to the
# current boot, so ONE record re-answered forever: measured on a real clone, eight
# boots, seven replacements, records under exactly one of them, and seven
# identical "idle" verdicts from a single observation. A decision rule that counts
# readings would have reached its threshold on the idle side from one event —
# the same "licensed by evidence that was not there" failure CLOUD-515 removed
# `plan-hold` for.
#
# So every verdict row fixtures a BOOTS FILE as well as a log, because a verdict
# without a boundary is not a verdict. `BATTEN_BOOT_TIME` is injected throughout:
# without it `/proc/stat` is the only boot source and no row could discriminate
# (CLOUD-418).

setup() {
	CENSUS="$BATS_TEST_DIRNAME/../mise-tasks/reclaim-census.sh"
	REPO="$BATS_TEST_TMPDIR/clone"
	mkdir -p "$REPO"
	git -C "$REPO" init -q .
	LOG="$REPO/.git/batten-reclaim-log"
	BOOTS="$REPO/.git/batten-boots"
	OLD_BOOT=1000
	PRIOR_BOOT=1500
	THIS_BOOT=2000
	export BATTEN_BOOT_TIME="$THIS_BOOT"
}

# The boundary under judgement: PRIOR_BOOT was replaced by THIS_BOOT.
boundary() { printf '%s\n%s\n' "$PRIOR_BOOT" "$THIS_BOOT" >"$BOOTS"; }
at() { (cd "$REPO" && "$CENSUS" "$@"); }

# --- report: the one boundary that just happened ------------------------------

@test "a landing in flight when the container was replaced" {
	boundary
	printf 'h 1400 %s\n' "$PRIOR_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 0 ]
	[[ "$output" == *"A LANDING WAS IN FLIGHT"* ]]
}

@test "a landing that stopped on purpose means none was in flight" {
	boundary
	printf 'h 1300 %s\nx 1400 %s land-stopped\n' "$PRIOR_BOOT" "$PRIOR_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 1 ]
	[[ "$output" == *"stopped on purpose"* ]]
	# Never the word idle about the CONTAINER — only about landings. The sensor
	# cannot see anything else, and saying otherwise is the overclaim CLOUD-696
	# removed.
	[[ "$output" == *"no landing was in flight"* ]]
}

@test "ABSENCE IS UNOBSERVED, NEVER IDLE — the row the whole correction turns on" {
	# The replaced container recorded nothing. Reporting that as idleness would
	# manufacture evidence out of a coverage gap, and every such reading would
	# count toward a threshold on the side that licenses building a mechanism.
	boundary
	: >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 2 ]
	# Asserted as the phrase, not as an absence of the word: the message says
	# "UNOBSERVED, not idle" on purpose, and a bare `!= *idle*` would fail on the
	# very wording that makes the distinction.
	[[ "$output" == *"UNOBSERVED, not idle"* ]]
}

@test "REGRESSION: a record under an OLDER boot does not answer for this boundary" {
	# The defect itself, as a row. The log's newest line is real but belongs to a
	# container two replacements ago; judging PRIOR_BOOT -> THIS_BOOT from it is
	# what produced seven verdicts from one observation.
	printf '%s\n%s\n%s\n' "$OLD_BOOT" "$PRIOR_BOOT" "$THIS_BOOT" >"$BOOTS"
	printf 'x 900 %s land-stopped\n' "$OLD_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 2 ]
	[[ "$output" == *"UNOBSERVED"* ]]
}

@test "records under THIS boot do not answer for the boundary either" {
	boundary
	printf 'h 2100 %s\n' "$THIS_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 2 ]
	[[ "$output" == *"UNOBSERVED"* ]]
}

@test "no boot predates this one: a fresh disk cannot look" {
	printf '%s\n' "$THIS_BOOT" >"$BOOTS"
	cd "$REPO"
	run "$CENSUS" report
	[ "$status" -eq 2 ]
	[[ "$output" == *"no evidence either way"* ]]
}

@test "a malformed BATTEN_BOOT_TIME is cannot-look, not a silent /proc fallback" {
	boundary
	printf 'h 1400 %s\n' "$PRIOR_BOOT" >"$LOG"
	cd "$REPO"
	BATTEN_BOOT_TIME=nonsense run "$CENSUS" report
	[ "$status" -eq 2 ]
}

@test "an unknown verb exits 2 and names the ones that exist" {
	cd "$REPO"
	run "$CENSUS" bogus
	[ "$status" -eq 2 ]
	[[ "$output" == *"unknown mode"* ]]
	[[ "$output" == *"tally"* ]]
}

# --- tally: counting derived in one pass, so it cannot accumulate duplicates ---

@test "tally classifies every boundary, not just the newest" {
	printf '%s\n%s\n%s\n' "$OLD_BOOT" "$PRIOR_BOOT" "$THIS_BOOT" >"$BOOTS"
	printf 'h 900 %s\n' "$OLD_BOOT" >"$LOG"
	cd "$REPO"
	run "$CENSUS" tally
	[ "$status" -eq 0 ]
	[[ "$output" == *"2 replacement(s)"* ]]
	[[ "$output" == *"1 with a landing in flight"* ]]
	[[ "$output" == *"1 unobserved"* ]]
}

@test "COUNTING IS IDEMPOTENT: repeated reads of one history give one answer" {
	# The property the old reader could not hold. Counting by accumulating
	# session-start lines turned one observation into one per boot.
	printf '%s\n%s\n%s\n' "$OLD_BOOT" "$PRIOR_BOOT" "$THIS_BOOT" >"$BOOTS"
	printf 'x 900 %s land-stopped\n' "$OLD_BOOT" >"$LOG"
	first=$(at tally)
	second=$(at tally)
	[ "$first" = "$second" ]
	[[ "$first" == *"1 idle of landings"* ]]
}

@test "a disk with no replacement has nothing to tally" {
	printf '%s\n' "$THIS_BOOT" >"$BOOTS"
	cd "$REPO"
	run "$CENSUS" tally
	[ "$status" -eq 2 ]
	[[ "$output" == *"no container replacement"* ]]
}

# --- what the recorders write -------------------------------------------------

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
	# CLOUD-491's finding: a trap fires on the kill too, so an `x` written from
	# one would report every reclaimed container as an intentional stop — the
	# false negative that hides the event the census exists to catch. Proven with
	# a real SIGKILL, not a fixture.
	boundary
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
	run "$CENSUS" report
	[ "$status" -eq 0 ]
	[[ "$output" == *"A LANDING WAS IN FLIGHT"* ]]
}

@test "a loop that stops on purpose leaves the matching x" {
	boundary
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

@test "land records the stop it causes itself, or every clean landing reads as a reclaim" {
	# The commonest stop of all is land killing its own heartbeat on a normal
	# finish; the loop never runs another statement, so its last record stays an
	# `h`. Without this line every successful landing would later read as
	# "the container died under active work".
	run grep -c 'note x land-stopped' "$BATS_TEST_DIRNAME/../mise-tasks/land.sh"
	[ "$output" -eq 1 ]
}
