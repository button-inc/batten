#!/usr/bin/env bats
# CLOUD-319. The debounce on `auto-release-land`'s automated `/fast-forward`:
# land once `main` has been quiet for 30 minutes, or once the last release is 24h
# old, whichever comes first.
#
# Every reading the task takes is injectable, so this suite needs no stub for
# `gh` and no network — which is also the property that makes the two boundaries
# testable at all. `PATH` is emptied of `gh` in `setup` so a regression that
# reintroduces a live call fails here rather than passing on a runner that
# happens to be authenticated.

setup() {
	DUE="$BATS_TEST_DIRNAME/../mise-tasks/release-due"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	# Any call to `gh` from a fully-injected run is the bug this catches.
	cat >"$STUB/gh" <<-'EOF'
		#!/usr/bin/env bash
		echo "release-due called gh with a fully injected reading: $*" >&2
		exit 97
	EOF
	chmod +x "$STUB/gh"
	PATH="$STUB:$PATH"
	export PATH
	export RELEASE_DUE_NOW="2026-08-11T12:00:00Z"
}

@test "main quiet past the window is due" {
	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:00:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:30:00Z" \
		run "$DUE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"due"* ]]
	[[ "$output" == *"quiet for 60m"* ]]
}

@test "a busy main inside the max wait holds, and says what it is waiting on" {
	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:59:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:30:00Z" \
		run "$DUE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"holding"* ]]
	# Both terms are reported, so a reader can tell which one will fire first.
	[[ "$output" == *"quiet window 30m"* ]]
	[[ "$output" == *"max wait 24h"* ]]
}

@test "a hold carries no ::error:: annotation — it is the ordinary outcome" {
	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:59:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:30:00Z" \
		run "$DUE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"::error::"* ]]
}

@test "the max wait interrupts a main that never goes quiet" {
	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:59:30Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-10T11:00:00Z" \
		run "$DUE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"max wait"* ]]
}

@test "no release yet is due — nothing to wait out" {
	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:59:00Z" \
		RELEASE_DUE_LAST_RELEASE="" \
		run "$DUE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no release exists yet"* ]]
}

# The two boundaries, stated as `>=` in the task. Exercised on both sides at one
# second, because an off-by-one here is a whole extra window of delay and would
# otherwise only show up as "the release was late once".
@test "the quiet window is inclusive at exactly 30 minutes" {
	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:30:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:59:00Z" \
		run "$DUE"
	[ "$status" -eq 0 ]

	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:30:01Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:59:00Z" \
		run "$DUE"
	[ "$status" -eq 1 ]
}

@test "the max wait is inclusive at exactly 24 hours" {
	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:59:59Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-10T12:00:00Z" \
		run "$DUE"
	[ "$status" -eq 0 ]

	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:59:59Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-10T12:00:01Z" \
		run "$DUE"
	[ "$status" -eq 1 ]
}

@test "both windows are honoured from the environment" {
	# A zero quiet window makes every reading due; a huge one makes none due.
	RELEASE_QUIET_MINUTES=0 \
		RELEASE_DUE_LAST_ACTIVITY="2026-08-11T12:00:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:59:00Z" \
		run "$DUE"
	[ "$status" -eq 0 ]

	RELEASE_QUIET_MINUTES=100000 RELEASE_MAX_WAIT_HOURS=100000 \
		RELEASE_DUE_LAST_ACTIVITY="2026-08-01T00:00:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-01T00:00:00Z" \
		run "$DUE"
	[ "$status" -eq 1 ]

	RELEASE_MAX_WAIT_HOURS=0 \
		RELEASE_DUE_LAST_ACTIVITY="2026-08-11T12:00:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T12:00:00Z" \
		run "$DUE"
	[ "$status" -eq 0 ]
}

# Exit 2 is "could not look", and it is distinct from a hold on purpose: the
# workflow fails the run on 2 and reports a hold as a normal skip, so a knob or a
# reading that does not parse must never be able to masquerade as debouncing.
@test "a non-numeric window is exit 2, never a silent fall back to the default" {
	RELEASE_QUIET_MINUTES=half-an-hour \
		RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:00:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:30:00Z" \
		run "$DUE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"RELEASE_QUIET_MINUTES"* ]]

	RELEASE_MAX_WAIT_HOURS=-1 \
		RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:00:00Z" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:30:00Z" \
		run "$DUE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"RELEASE_MAX_WAIT_HOURS"* ]]
}

@test "an unparseable timestamp is exit 2, on either reading" {
	RELEASE_DUE_LAST_ACTIVITY="whenever" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:30:00Z" \
		run "$DUE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"last-commit"* ]]

	RELEASE_DUE_LAST_ACTIVITY="2026-08-11T11:00:00Z" \
		RELEASE_DUE_LAST_RELEASE="whenever" \
		run "$DUE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"last-release"* ]]
}

@test "an empty last-commit reading is could-not-look, not a quiet main" {
	RELEASE_DUE_LAST_ACTIVITY="" \
		RELEASE_DUE_LAST_RELEASE="2026-08-11T11:30:00Z" \
		run "$DUE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no timestamp"* ]]
}
