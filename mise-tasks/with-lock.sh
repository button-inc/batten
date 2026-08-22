#!/usr/bin/env bash
#MISE description="Effect: run a command while holding a named directory lock, so concurrent callers queue instead of colliding. Exits with the command's status."
#
# The mutual-exclusion primitive this repo's provisioning tasks share, written
# once. It began inside `target-ensure` (CLOUD-220) and `doctor` needed the same
# thing for its own two writers (CLOUD-201) — a second copy of a lock is a
# second set of subtle edge cases, and the edges here are exactly where the
# defects live, so the body moved out rather than being retyped.
#
# THE PRIMITIVE IS A DIRECTORY, not flock(1). `mkdir` is an atomic
# create-or-fail on every filesystem that matters and costs no binary, where
# `flock` ships with util-linux and simply does not exist on macOS — so the
# refusal that guarded it fired before any other gate on a Mac (CLOUD-286).
#
# THE EXIT STATUS IS THE WRAPPED COMMAND'S. A lock wrapper that reported its own
# success would destroy the verdict of everything it guards — the same defect
# `run-shape-guard` denies at the call site, one level down and invisible there.
# `tests/with-lock.bats` asserts it directly, for a failing command and for a
# signal.
#
# Output is pointer-only: this task prints nothing on the happy path. The
# wrapped command's own output is untouched, so a caller reads its verdict, not
# the lock's narration.
#
# Usage:  with-lock <lockdir> -- <command> [args...]
set -euo pipefail

lock="${1:?usage: with-lock <lockdir> -- <command> [args...]}"
shift
[[ "${1:-}" = "--" ]] || {
	echo "::error:: with-lock: expected \`--\` between the lock path and the command" >&2
	exit 1
}
shift
[[ "$#" -gt 0 ]] || {
	echo "::error:: with-lock: no command to run under $lock" >&2
	exit 1
}

mkdir -p "$(dirname "$lock")"

# Legacy transition. Before CLOUD-286 this same path was a regular FILE that
# flock(1) held, and that file survives on every machine which ever ran doctor.
# `mkdir` against it can never succeed, so waiting for it to become a directory
# is a guaranteed timeout on every existing checkout. The file carries no state
# — the lock was the kernel's, not the bytes' — so drop it. The one hazard is a
# pre-CLOUD-286 holder running concurrently on this machine, which is a single
# upgrade's window; a permanent wedge would be forever.
if [[ -e "$lock" ]] && [[ ! -d "$lock" ]]; then
	rm -f "$lock"
fi

# What the kernel used to do for free — drop the lock when the holder dies — is
# explicit now. The trap covers every ordinary exit including a signal, and a
# holder that took SIGKILL is reclaimed by the stale check in the wait loop, so
# an abandoned lock is a delay measured in one poll rather than in the timeout.
held=no
release() {
	if [[ "$held" = yes ]]; then
		held=no
		rm -rf "${lock:?}"
	fi
}
trap release EXIT
trap 'exit 1' INT TERM

deadline=$((SECONDS + ${WITH_LOCK_TIMEOUT:-${TARGET_LOCK_TIMEOUT:-600}}))
dead_seen=
while ! mkdir "$lock" 2>/dev/null; do
	holder="$(cat "$lock/pid" 2>/dev/null || true)"
	# An EMPTY pid file is a holder caught between its mkdir and its write, not
	# a corpse: absence of evidence is "held", never "free".
	if [[ -n "$holder" ]] && ! kill -0 "$holder" 2>/dev/null; then
		# Two consecutive sightings of the SAME dead pid, so a holder that
		# exited cleanly between the read and the check — its trap already
		# removing the directory — is never mistaken for one that died holding.
		# Residual race: two waiters can reclaim one abandoned lock in the same
		# poll. That costs a collision in the already-abnormal SIGKILL case,
		# where the alternative costs every later run the full timeout.
		if [[ "$dead_seen" = "$holder" ]]; then
			rm -rf "${lock:?}"
			dead_seen=
			continue
		fi
		dead_seen="$holder"
	else
		dead_seen=
	fi
	if [[ "$SECONDS" -ge "$deadline" ]]; then
		# The caller names what the wait was FOR. A lock path is a pointer to a
		# file; "the toolchain lock (aarch64-apple-darwin)" is a pointer to the
		# thing a reader has to reason about, and moving the wait out of the
		# caller must not cost that.
		echo "::error:: with-lock: timed out waiting for ${WITH_LOCK_LABEL:-$lock}" >&2
		exit 1
	fi
	sleep 0.1
done
held=yes
echo "$$" >"$lock/pid"

# `set -e` would exit here on a non-zero command WITHOUT the status reaching the
# line below, so the run is guarded and the code captured — the wrapped verdict
# is the whole product of this task.
rc=0
"$@" || rc=$?
release
exit "$rc"
