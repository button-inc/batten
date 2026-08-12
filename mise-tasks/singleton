#!/usr/bin/env bash
#MISE description="Refuse to start a task that is already running in this clone, naming the process that holds it"
#
# CLOUD-428. **Measured 2026-08-12, in this repository, by accident.** A session
# running `land` backgrounded ended up with THREE concurrent `land` processes on
# one branch and TWO `land-lock hold` heartbeats, rebasing, pushing and renewing
# the same lease against each other for roughly thirty minutes before a human
# noticed and asked what was running.
#
# Two gaps produced it, and the guardrail belongs here because only one of them
# is fixable here:
#
#   1. Stopping a background task does not reap its tree. The harness's stop
#      kills the wrapper; `mise run land` and its children survive. An agent
#      that stops a run and starts another believes it has one; it has two.
#      That cannot be fixed in this repository, which is exactly why the
#      repository must not depend on it being true.
#   2. **The landing lease is re-entrant per clone, deliberately, so it cannot
#      help.** `land-lock acquire` answers "already held by this clone" rather
#      than blocking, because a retrying `land` must not deadlock against
#      itself, and the holder id is minted once per clone and shared by every
#      process in it. So two `land` processes in one checkout BOTH acquire, and
#      the second heartbeat renews the first's lease. That is not a bug — it is
#      the cost of a trade: the lease serialises landing ACROSS clones and
#      offers exactly nothing WITHIN one. CLOUD-420 is blind to this from the
#      same direction: a second `land` here holds a genuine lease, so a
#      server-side "does this branch hold the lease" says yes to both.
#
# So this is a DIFFERENT lock at a DIFFERENT scope, and `land-lock`'s
# re-entrancy is deliberately left alone.
#
# **The refusal is the point.** Unlike `target-ensure`, which waits, a second
# `land` exits non-zero naming the live pid. Waiting would mean two agents
# intending to land the same branch — a mistake to surface, not to queue.
#
# **The idiom is reused, not reinvented** (CLOUD-220, CLOUD-286): an atomic
# `mkdir` (not `flock(1)`, which is util-linux and absent on macOS), a pid file
# written after winning, stale reclaim by `kill -0` requiring two consecutive
# sightings of the same dead pid, and the rule that an EMPTY pid file means HELD
# — absence of evidence is never "free".
#
# **The caller's trap owns the release.** This process cannot hold anything: it
# exits immediately. It performs the atomic acquire on the CALLER's behalf,
# writing the caller's pid, exactly as `land-lock`'s verbs act for the `land`
# that invoked them. A caller that acquires must `release` from its EXIT trap.
#
# Exit codes follow the one contract: 0 acquired, 1 already running here, 2
# could not look.
set -euo pipefail

usage() {
	echo "::error:: usage: singleton <acquire <task> <pid>|release <task>>" >&2
	exit 2
}

verb="${1:-}"
task="${2:-}"
case "$verb" in
acquire | release) ;;
*) usage ;;
esac
[ -n "$task" ] || usage

git_dir=$(git rev-parse --git-dir 2>/dev/null) || {
	echo "::error:: singleton: not a git repository" >&2
	exit 2
}

state_dir="$git_dir/batten-singleton"
lock="$state_dir/$task"

if [ "$verb" = release ]; then
	# Idempotent, because it runs from an EXIT trap that also fires on paths
	# where the acquire never happened. A trap that can fail masks the real
	# exit code.
	rm -rf "${lock:?}" 2>/dev/null || true
	exit 0
fi

pid="${3:-}"
[ -n "$pid" ] || usage

mkdir -p "$state_dir" 2>/dev/null || {
	echo "::error:: singleton: cannot create $state_dir" >&2
	exit 2
}

# What is the holder doing? Pointer-only, and strictly for the refusal MESSAGE —
# the lock above is the authority, and a missing registry entry never turns a
# refusal into a pass. CLOUD-425 put every long task in that registry, so this
# is its first consumer rather than a second bookkeeping scheme.
# Absence is the COMMON case — the registry is best-effort, and a holder that
# died before registering has no entry — so every failure path here returns
# empty rather than propagating. Without the guard, `sed` on a missing file
# fails, `pipefail` propagates it out of the pipeline, and `set -e` kills the
# refusal before it can be printed: the guard would exit 2 ("could not look")
# on the single most important path it has, refusing a second land.
holder_phase() { # <pid>
	local f="$git_dir/batten-tasks/$1"
	[ -f "$f" ] || return 0
	sed -n 's/^phase: //p' "$f" 2>/dev/null | head -n 1 || true
}

refuse() { # <pid>
	local phase
	phase=$(holder_phase "$1") || phase=
	echo "::error:: singleton: $task is already running in this clone as pid $1${phase:+ (}${phase}${phase:+)}. Stopping a background task does not reap its tree — check \`mise run alive\`, and kill that process rather than starting a second one." >&2
	exit 1
}

# One acquire attempt, plus at most one re-look to satisfy the two-sightings
# rule. `target-ensure` gets its second sighting from the next turn of a wait
# loop; this refuses instead of waiting, so the second look is explicit and
# bounded — the safety property is the same, and the cost is 0.1s in the one
# case where the holder is already dead.
if mkdir "$lock" 2>/dev/null; then
	printf '%s\n' "$pid" >"$lock/pid"
	exit 0
fi

holder="$(cat "$lock/pid" 2>/dev/null || true)"
# An EMPTY pid file is a holder caught between its mkdir and its write, not a
# corpse: absence of evidence is "held", never "free".
[ -n "$holder" ] || refuse "unknown"

# There is deliberately no early `kill -0 && refuse` fast path here. It read as
# a safety property and was not one: with it deleted, a live holder still falls
# through to the refusal at the bottom, so no test could tell the two apart —
# it survived its own mutant. One refusal path is worth more than 0.1s saved on
# the contended path, and a line no test can distinguish is a liability.
#
# First sighting of a dead pid. Look again before reclaiming, so a holder that
# exited cleanly between the read and the check — its own trap already removing
# the directory — is never mistaken for one that died holding, and so a NEW
# holder that took the lock in between is never robbed of it.
#
# The interval is a lever purely so `tests/singleton.bats` can drive that second
# case with a wide margin instead of racing a 0.1s window; nothing sets it in
# production. Same shape as TARGET_LOCK_TIMEOUT and LAND_INTERVAL.
sleep "${SINGLETON_RECHECK:-0.1}"
again="$(cat "$lock/pid" 2>/dev/null || true)"
if [ -n "$again" ] && [ "$again" = "$holder" ] && ! kill -0 "$again" 2>/dev/null; then
	rm -rf "${lock:?}"
	if mkdir "$lock" 2>/dev/null; then
		printf '%s\n' "$pid" >"$lock/pid"
		echo "singleton: reclaimed $task from dead pid $holder"
		exit 0
	fi
fi

# The lock changed under us, or a live holder took it: whoever holds it now is
# real. Re-read rather than reporting the corpse we saw a moment ago.
holder="$(cat "$lock/pid" 2>/dev/null || true)"
refuse "${holder:-unknown}"
