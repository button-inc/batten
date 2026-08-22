#!/usr/bin/env bash
#MISE description="Record whether active work was live when a container was replaced, and read the verdict back — the evidence CLOUD-451 needs before any mechanism"
#
# CLOUD-451. A turn that hands control to a human ends idle, the container is
# reclaimed, and the human's typed approval is destroyed. One mechanism has
# already been built against that and removed: `plan-hold` (CLOUD-515) denied
# every handoff until a backgrounded sleeper occupied the container, on the
# premise that occupancy defers the reclaim. **The premise was never once
# observed**, and the cost was paid on every handoff for seventeen hours.
#
# THIS IS A SENSOR AND NOTHING ELSE. It denies nothing, gates nothing, and
# occupies nothing. Its whole job is to make one question answerable, because
# answering it decides whether a mechanism is worth building at all:
#
#   When a container is replaced, was a LANDING in flight at the time?
#
# **That is narrower than CLOUD-451's question, and the gap is stated rather than
# glossed** (CLOUD-696). This writes only while `land-lock hold` has the lease, so
# it sees landings and nothing else. A container that recorded nothing was not
# necessarily idle — it may simply have had no landing to observe — so absence
# answers `unobserved` (exit 2) and never `idle`. Reporting a coverage gap as
# idleness is evidence manufactured from silence, and it biases toward exactly the
# conclusion that would license a mechanism.
#
# Two events are on record and they point opposite ways. 2026-08-13 06:18:54: a
# container replaced with ZERO tracked tasks after ~14 minutes idle, disk
# preserved. 2026-08-12 ~22:12 (CLOUD-491): a container replaced while four
# tracked tasks were live, one of them a `land` doing network I/O every ten
# seconds. If reclaims only ever hit idle containers, occupancy is the right
# lever. If they kill active work too, occupancy cannot help and CLOUD-451 is not
# this repository's to fix. Nothing has ever separated the two, and each is
# attested exactly once.
#
# **It rides a loop that already exists.** `land-lock hold` beats every 30s for
# exactly as long as a `land` holds the lease — precisely the window "active work
# is in flight" — and already does a network push per beat. One append and one
# `sync -d` there is free by comparison. That is the difference from what was
# deleted: `plan-hold` was a process whose only purpose was to be occupancy; this
# is a record on work that happens anyway. No new process, no new poll, and
# nothing on the path to a human.
#
# **The record is STRUCTURAL, not temporal, and that is CLOUD-491's hard-won
# finding rather than a preference.** Its measurement: every write surviving the
# 2026-08-12 23:45 replacement stopped at 23:42:15 while the container kept
# serving calls until ~23:45 — the last 182 seconds of writes did not survive.
# Snapshot boundary or unflushed page cache cannot be told apart from inside, and
# it does not matter: the tail of any heartbeat is lost exactly when a sensor
# needs it, so `last_beat >= btime - interval` reads minutes stale at the moment
# it is asked. So there is no clock in the predicate. `h` per beat, `x` only
# where something CHOSE to stop, and the verdict is the kind of the last record
# written UNDER THE BOOT BEING JUDGED — not the newest line in the file, which
# belongs to whichever container wrote last. A loop killed by the container going
# down cannot write an `x`, so an `h` in final position under that boot IS the
# evidence.
#
# Usage: reclaim-census note h                — a beat happened
#        reclaim-census note x <reason>       — something chose to stop
#        reclaim-census record-boot           — note this boot, so a later report
#                                               can tell a preserved disk from a
#                                               fresh one
#        reclaim-census report                — the verdict about the ONE
#                                               transition that just happened
#        reclaim-census tally                 — classify every transition this
#                                               disk records, so counting is
#                                               derived rather than accumulated
#        reclaim-census log-path | boot       — accessors, so no caller
#                                               re-derives a path or a btime
#
# Exit codes are house-style §7: 0 the predicate holds, 1 it does not, 2 the
# question could not be asked. `note` and `record-boot` are bookkeeping and
# answer 0 unless they could not look at all.
#
# The two mutations are the two ways this stops discriminating. Collapsing the
# reader's `h`/`x` test leaves only the clock, which the 182s measurement rules
# out. Rewriting the intentional-exit record as a beat makes a loop that stopped
# on purpose indistinguishable from one the container killed — the false positive
# that would license exactly the mechanism this exists to test the need for.
#MUTANT active-discrimination-collapses|s/if \[\[ "$verdict" = "active" \]\]; then/if false; then/|a landing in flight when the container was replaced
#MUTANT terminal-record-collapses|s/^	x) kind=x ;;$/	x) kind=h ;;/|stops on purpose leaves the matching x
set -uo pipefail

# The one authoritative spelling of each path. ABSOLUTE, deliberately: these are
# consumed by a hook whose working directory is the harness's rather than the one
# the record was written from, and a relative answer would have two callers
# resolving the same log to different files — a false reading in the direction
# that matters.
git_dir() {
	local d
	d=$(git rev-parse --absolute-git-dir 2>/dev/null) || return 1
	[[ -n "$d" ]] || return 1
	printf '%s\n' "$d"
}

# `/proc/stat`'s btime is this container's boot time in epoch seconds.
# INJECTABLE because it cannot be faked otherwise, and a suite that cannot vary
# the boot time cannot exercise a single row of the table below — it would ship
# as coverage while discriminating nothing (CLOUD-418).
boot_time() {
	local bt
	# Set at all, not merely non-empty: an override that is present is
	# AUTHORITATIVE, so a malformed one is "cannot look" rather than a silent
	# fall-through to /proc/stat. Falling through would make the override look
	# honoured while the reading came from somewhere else.
	if [[ -n "${BATTEN_BOOT_TIME+set}" ]]; then
		case "$BATTEN_BOOT_TIME" in
		'' | *[!0-9]*) return 1 ;;
		esac
		printf '%s\n' "$BATTEN_BOOT_TIME"
		return 0
	fi
	bt=$(awk '$1 == "btime" { print $2; exit }' /proc/stat 2>/dev/null)
	case "$bt" in
	'' | *[!0-9]*) ;;
	*)
		printf '%s\n' "$bt"
		return 0
		;;
	esac
	# `uptime -s` answers a wall-clock string rather than an epoch; converting it
	# is what makes it a fallback rather than a second format to reason about.
	bt=$(date -u -d "$(uptime -s 2>/dev/null)" +%s 2>/dev/null)
	case "$bt" in
	'' | *[!0-9]*) return 1 ;;
	# Digits, which is the only other thing this can be: fall through to the
	# print. Stated rather than implied — an unhandled value falling out of a
	# validation `case` reads the same whether it was decided or forgotten.
	*) ;;
	esac
	printf '%s\n' "$bt"
}

mode="${1:-report}"

case "$mode" in
log-path)
	d=$(git_dir) || {
		echo "::error:: reclaim-census: not a git repository — no log" >&2
		exit 2
	}
	printf '%s\n' "$d/batten-reclaim-log"
	exit 0
	;;
boot)
	boot=$(boot_time) || {
		echo "::error:: reclaim-census: cannot read this container's boot time" >&2
		exit 2
	}
	printf '%s\n' "$boot"
	exit 0
	;;
note)
	# A SENSOR MUST NEVER KILL WHAT IT OBSERVES. Every failure below is swallowed
	# and answers 0: this is called from inside `land-lock hold`'s renewal loop
	# and from `land`'s cleanup, and a census that could abort a landing would be
	# a far worse defect than the missing evidence it exists to collect.
	kind="${2:-h}"
	case "$kind" in
	h) ;;
	x) kind=x ;;
	*)
		echo "::error:: reclaim-census: note takes h or x, not \"$kind\"" >&2
		exit 2
		;;
	esac
	d=$(git_dir) || exit 0
	boot=$(boot_time) || exit 0
	log="$d/batten-reclaim-log"
	reason="${3:-}"
	# The reason field is omitted rather than emitted empty: a trailing space is a
	# byte difference between two records that mean the same thing, and
	# non-negotiable 5 asks output to be stable rather than nearly so.
	if [[ -n "$reason" ]]; then
		printf '%s %s %s %s\n' "$kind" "$(date -u +%s)" "$boot" "$reason" >>"$log" 2>/dev/null || true
	else
		printf '%s %s %s\n' "$kind" "$(date -u +%s)" "$boot" >>"$log" 2>/dev/null || true
	fi
	# Cannot defeat a snapshot boundary, but it closes the unflushed-cache half of
	# the 182s measurement for one syscall per beat.
	sync -d "$log" 2>/dev/null || true
	exit 0
	;;
record-boot)
	boot=$(boot_time) || {
		echo "::error:: reclaim-census: cannot read this container's boot time — not recording it" >&2
		exit 2
	}
	d=$(git_dir) || {
		echo "::error:: reclaim-census: not a git repository — cannot record this boot" >&2
		exit 2
	}
	boots="$d/batten-boots"
	# Idempotent by the LAST line, not by a search: a session that restarts within
	# one container must not add a second record, and a genuinely earlier boot
	# recurring is not a case that can arise — btime only moves forward.
	last=$(tail -n 1 -- "$boots" 2>/dev/null)
	[[ "$last" = "$boot" ]] || printf '%s\n' "$boot" >>"$boots" 2>/dev/null || true
	exit 0
	;;
report | tally) ;;
*)
	echo "::error:: reclaim-census: unknown mode \"$mode\" (want: report | tally | note | record-boot | log-path | boot)" >&2
	exit 2
	;;
esac

boot=$(boot_time) || {
	echo "::error:: reclaim-census: cannot read this container's boot time — cannot say what the last replacement interrupted" >&2
	exit 2
}
d=$(git_dir) || {
	echo "::error:: reclaim-census: not a git repository — cannot say what the last replacement interrupted" >&2
	exit 2
}
log="$d/batten-reclaim-log"
boots="$d/batten-boots"

# THE READING IS PER TRANSITION, NEVER PER FILE, and that is the correction this
# verb exists in its current form to make (CLOUD-696).
#
# The first version asked "what is the newest line in the log, and is its boot
# different from mine?" — which re-answered from ONE record forever. Measured on
# this clone: eight boots recorded, seven replacements, and log records under
# exactly ONE of them. Every session start after that boot returned the same
# verdict about the same six-boots-ago event, so a decision rule that counts
# readings would have reached its threshold from a single observation, on the
# idle side. That is the shape CLOUD-515 deleted `plan-hold` for — a conclusion
# licensed by evidence that was not there — arriving through the instrument built
# to prevent it.
#
# So a verdict is about ONE boundary: the container recorded immediately before
# this one, and only the records written under THAT boot. Repeated calls about the
# same boundary give the same answer, and `tally` derives the whole history in one
# pass, so counting cannot accumulate duplicates.

# The last record written under one boot, or nothing when that container recorded
# none. `awk` over the whole log rather than `tail`, because the newest line
# overall may belong to a different container entirely — precisely the conflation
# above.
kind_under() {
	awk -v b="$1" '
		($1 == "h" || $1 == "x") && $3 == b { k = $1; e = $2 }
		END { if (k != "") printf "%s %s\n", k, e }
	' "$log" 2>/dev/null
}

# Every recorded boot, oldest first. Malformed lines are dropped rather than
# guessed at: a boots file is append-only and numeric, so anything else is damage.
boot_list() {
	[[ -r "$boots" ]] || return 0
	awk '/^[0-9]+$/ { print }' "$boots" 2>/dev/null
}

# WHAT ABSENCE MEANS, and it is the other half of the correction. A container that
# recorded nothing is UNOBSERVED, never "idle". The sensor only writes while a
# `land` holds the lease, so silence means no landing was running — which is not
# the same claim as the container being idle, and reporting it as idleness is
# evidence manufactured from a gap in coverage. Exit 2, the cannot-look code.
classify() { # classify <boot> -> prints: active|idle|unobserved [epoch]
	local k e
	read -r k e <<<"$(kind_under "$1")"
	case "$k" in
	h) printf 'active %s\n' "$e" ;;
	x) printf 'idle %s\n' "$e" ;;
	*) printf 'unobserved\n' ;;
	esac
}

if [[ "$mode" = tally ]]; then
	prev=
	transitions=0
	active=0
	idle=0
	unobserved=0
	while IFS= read -r b; do
		[[ -n "$b" ]] || continue
		if [[ -n "$prev" ]]; then
			transitions=$((transitions + 1))
			read -r verdict _rest <<<"$(classify "$prev")"
			case "$verdict" in
			active) active=$((active + 1)) ;;
			idle) idle=$((idle + 1)) ;;
			*) unobserved=$((unobserved + 1)) ;;
			esac
		fi
		prev="$b"
	done <<<"$(boot_list)"
	if [[ "$transitions" -eq 0 ]]; then
		echo "::error:: reclaim-census: this disk records no container replacement — nothing to tally" >&2
		exit 2
	fi
	# Pointer-only: four counts. The decision rule reads these rather than
	# accumulating session-start lines, which is what made double counting
	# possible at all.
	echo "reclaim-census: $transitions replacement(s) recorded — $active with a landing in flight, $idle idle of landings, $unobserved unobserved"
	exit 0
fi

# `report`: the one boundary that just happened. The previous container is the
# newest recorded boot that is not this one — which is the second-to-last entry
# once `record-boot` has run, and still correct if it has not.
prev=
while IFS= read -r b; do
	[[ -n "$b" ]] || continue
	[[ "$b" = "$boot" ]] && continue
	prev="$b"
done <<<"$(boot_list)"

if [[ -z "$prev" ]]; then
	# No boot but this one: a fresh disk, where no local evidence can exist.
	# Saying "nothing was live" would be a claim the evidence cannot support.
	echo "::error:: reclaim-census: no boot predates $boot — this container's disk carries no evidence either way" >&2
	exit 2
fi

read -r verdict epoch <<<"$(classify "$prev")"
# The discrimination, and the only place it happens. Mutating it away leaves the
# active case reported as something else, which is the reading that would let a
# reclaim of live work pass as a reclaim of an idle container.
if [[ "$verdict" = "active" ]]; then
	echo "reclaim-census: A LANDING WAS IN FLIGHT when this container replaced the last one (last beat $epoch under boot $prev, now $boot)"
	exit 0
fi
if [[ "$verdict" = "idle" ]]; then
	echo "reclaim-census: the last landing stopped on purpose at $epoch — no landing was in flight when boot $prev was replaced"
	exit 1
fi
echo "::error:: reclaim-census: boot $prev recorded nothing — UNOBSERVED, not idle; this sensor only sees landings and none ran there" >&2
exit 2
