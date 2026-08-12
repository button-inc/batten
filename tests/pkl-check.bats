#!/usr/bin/env bats
# CLOUD-406. `hk.pkl:14` amends a pkl PACKAGE uri, so pkl resolves the `hk`
# package over the network on every evaluation — a second dependency beside the
# `hk` binary `mise.lock` pins, and unpinned at runtime. Measured in CI on run
# 31632519615: the fetch failed, hk aborted with exit 134 before reaching a
# single gate, and the `failure` grade then wedged the SHA.
#
# The fix is a cache, and a cache is only a fix if the coupling it breaks is
# real. So this suite measures BOTH directions over the same command:
#
#   cold cache + egress denied -> fails   (the coupling exists)
#   warm cache + egress denied -> exits 0 (the cache is what breaks it)
#
# The first row is the load-bearing one. Without it the second passes on any
# machine that has ever evaluated `hk.pkl` and proves nothing, which is the
# "a new gate is never shown to fail" defect CLOUD-418 landed a discipline
# against. Both directions or neither.
#
# **The suite itself must not need the network**, or it reproduces the very
# defect on a machine that cannot reach github. So the warm row is warmed by
# COPYING the ambient cache, never by downloading, and skips with a diagnostic
# when there is nothing to copy — the "establish the precondition, never retry
# the measurement" shape `tests/land-lock.bats` already uses.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/pkl-check"
	HK="$BATS_TEST_DIRNAME/../hk.pkl"

	# pkl's DEFAULT cache, which is the one that matters: hk evaluates `hk.pkl`
	# internally, so it reads this path and no `--cache-dir` of ours reaches it.
	# The CI cache step keys on exactly this directory.
	AMBIENT="${PKL_TEST_CACHE:-$HOME/.pkl/cache}"

	# Egress denied by pkl's OWN `--http-proxy`, pointed at a port nothing
	# listens on — not by `HTTPS_PROXY`, and not by dropping capabilities.
	#
	# The env-var route was tried first and is a trap worth recording: pkl is a
	# native image and ignored `HTTPS_PROXY`, so the fetch went out over the real
	# network and failed on an unrelated truststore error instead. That reads as
	# a passing anti-vacuity row while measuring nothing about egress. pkl's flag
	# is part of pkl's contract, needs no privileges, and fails closed — if it
	# were ever ignored the fetch would SUCCEED and the cold row below would go
	# green, which is the failure this file is written to notice.
	DENY=(--http-proxy=http://127.0.0.1:1)
}

@test "the coupling is real: a cold cache with egress denied cannot evaluate hk.pkl" {
	run "$CHECK" --cache-dir="$BATS_TEST_TMPDIR/cold" "${DENY[@]}" "$HK"
	[ "$status" -ne 0 ]
	# Pointer-only, and it is what distinguishes "denied" from "failed for some
	# other reason" — the package coordinate, never a fetched byte. A cold
	# evaluation that died on a truststore or a parse error would satisfy the
	# exit code above while proving nothing.
	[[ "$output" == *"github.com/jdx/hk"* ]]
}

@test "a warm cache breaks it: the same command with egress denied evaluates cleanly" {
	[ -d "$AMBIENT/package-2/github.com/jdx/hk" ] ||
		skip "no hk package under $AMBIENT — CLOUD-406: evaluate hk.pkl once on a networked host to warm it, or point PKL_TEST_CACHE at a warm cache"

	cp -a "$AMBIENT" "$BATS_TEST_TMPDIR/warm"
	run "$CHECK" --cache-dir="$BATS_TEST_TMPDIR/warm" "${DENY[@]}" "$HK"
	[ "$status" -eq 0 ]
}

# The cache is provisioning, not evaluation, so nothing in `pkl-check` changed
# for CLOUD-406 — but the task is now covered, and this is the plain case it
# never had: a malformed file fails, which is the whole reason the step exists
# (hk.pkl:381 routes its `pkl` step through here so a broken gate config fails at
# check time rather than when a hook tries to run).
@test "a malformed .pkl file fails" {
	printf 'this is not = pkl {{\n' >"$BATS_TEST_TMPDIR/broken.pkl"
	run "$CHECK" "$BATS_TEST_TMPDIR/broken.pkl"
	[ "$status" -ne 0 ]
}
