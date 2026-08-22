#!/usr/bin/env bash
#MISE description="Gate: measure this branch against its merge base and refuse a regression — the one call `verify` and CI make"
#
# CLOUD-172. `perf-pair` measures, `perf-compare` decides, and this is the one
# name that runs the pair — so a caller wires in ONE task and cannot wire in
# half of it. `mise run ci-local-parity` requires every task a pull_request
# workflow runs to be one `verify` runs, and a single name is what keeps that
# correspondence readable.
#
# REDIRECTED THROUGH A FILE, NEVER PIPED. `perf-pair | perf-compare` would hand
# this task's exit status to the gate alone, so a measurement that failed
# outright would reach `perf-compare` as empty stdin and be reported as its exit
# 2 — the right code for the wrong reason, and one step from a pipeline whose
# producer's failure vanishes entirely. `mise run run-shape-guard` refuses that
# shape in an agent's hands; it is no more correct here.
#
# EXIT CODES PASS THROUGH, and that matters to the caller. `perf-pair` answers 2
# for "could not look" — an unresolvable merge base, a build that failed, a
# missing instrument — and `perf-compare` answers 1 only for a real regression.
# Flattening them would make a shallow clone indistinguishable from a branch
# that made the hook slower, which is the difference `verify` needs in order to
# tell "fix your change" from "fix your checkout".
set -euo pipefail

pair_file="$(mktemp)"
trap 'rm -f "$pair_file"' EXIT

rc=0
mise run perf-pair >"$pair_file" || rc=$?
if [[ "$rc" != 0 ]]; then
	echo "::error:: perf-gate: the paired measurement did not complete (exit $rc), so no comparison was made." >&2
	exit "$rc"
fi

# The skip path prints one human line and no records. That is a pass, not an
# empty measurement: `perf-pair` has already established that the binary cannot
# have changed, and handing an empty stream to `perf-compare` would turn a
# sound skip into a "could not look".
if ! grep -q '^arm=' "$pair_file"; then
	cat "$pair_file"
	echo "perf-gate: nothing to compare — the binary is unchanged on this branch"
	exit 0
fi

mise run perf-compare <"$pair_file"
