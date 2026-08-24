#!/usr/bin/env bats
# subject: mise-tasks/release-backfill.sh
# release-backfill's decision table (CLOUD-618).
#
# The sweep that records the 111 tags which shipped before the recording worked.
# Every case runs offline through `$RELEASE_BACKFILL_GH`, the indirection
# `attestation-check` and `sonar-gate` already use — no network, no PATH
# manipulation, and nothing that behaves differently in this sandbox than in CI.
#
# THE STUB IS A LEDGER, not a mock: it appends every argv it is handed to a file,
# so a case can assert the ORDER tags were dispatched in and the COUNT of
# dispatches that happened. Order is the property with an argument behind it — the
# action derives a release's attached issues from the tag's commit range — and a
# stub that only returned canned answers could not check it.

setup() {
	TASK="$BATS_TEST_DIRNAME/../mise-tasks/release-backfill.sh"
	LEDGER="$BATS_TEST_TMPDIR/argv"
	STATE="$BATS_TEST_TMPDIR/state"
	: >"$LEDGER"
	export RELEASE_BACKFILL_GH="$BATS_TEST_TMPDIR/gh"
	# No case may sleep: the poll's interval is a wall clock and the exit condition
	# is what is under test.
	export RELEASE_BACKFILL_POLL_INTERVAL=0
	write_stub
}

# A `gh` that answers the three calls the task makes. `run list` hands back an
# incrementing id so each dispatch looks like a new run — which is the whole of
# what the task waits on — and `run view` reports whatever $STATE says.
#
# `$STATE` holds `<conclusion>` and defaults to success. A case that wants a
# failing run writes into it before invoking the task.
write_stub() {
	echo success >"$STATE"
	cat >"$RELEASE_BACKFILL_GH" <<-EOF
		#!/usr/bin/env bash
		printf '%s\n' "\$*" >>"$LEDGER"
		counter="$BATS_TEST_TMPDIR/counter"
		[ -f "\$counter" ] || echo 100 >"\$counter"
		case "\$1 \$2" in
		"run list")
		  cat "\$counter"
		  ;;
		"workflow run")
		  echo \$(( \$(cat "\$counter") + 1 )) >"\$counter"
		  ;;
		"run view")
		  printf 'completed %s\n' "\$(cat "$STATE")"
		  ;;
		esac
	EOF
	chmod +x "$RELEASE_BACKFILL_GH"
}

# Every `workflow run` argv the task issued, in order, reduced to its tag.
dispatched_tags() {
	sed -n 's/^workflow run .* -f tag=\(.*\)$/\1/p' "$LEDGER" | tr '\n' ' '
}

# --- which tags, and in what order --------------------------------------------

# THE ORDER IS THE POINT. Lexical order puts v0.0.110 before v0.0.78, which is
# the reverse of what the commit-range argument needs, so the sort is `-V` and
# this is the case that would catch it being dropped.
@test "tags are dispatched oldest first, by version and not lexically" {
	RELEASE_BACKFILL_TAGS="v0.0.110 v0.0.78 v0.0.9 v0.1.0" run "$TASK"
	[ "$status" -eq 0 ]
	[ "$(dispatched_tags)" = "v0.0.9 v0.0.78 v0.0.110 v0.1.0 " ]
}

@test "explicit arguments win over the injected list" {
	RELEASE_BACKFILL_TAGS="v0.0.1 v0.0.2" run "$TASK" v0.0.78
	[ "$status" -eq 0 ]
	[ "$(dispatched_tags)" = "v0.0.78 " ]
}

@test "one dispatch per tag, and no more" {
	RELEASE_BACKFILL_TAGS="v0.0.1 v0.0.2 v0.0.3" run "$TASK"
	[ "$status" -eq 0 ]
	[ "$(grep -c '^workflow run' "$LEDGER")" -eq 3 ]
}

# An empty sweep is a refusal, not a clean run of nothing: nothing here can tell
# a repository with no tags from a pattern that matched none, and reporting
# success for the second is how a backfill silently does not happen.
@test "an empty tag list is a refusal" {
	RELEASE_BACKFILL_TAGS=" " run "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no tags to record"* ]]
	[ ! -s "$LEDGER" ]
}

# The whole bad list is named at once rather than the first element of it: the
# workflow's own tag-exists probe would refuse these one round trip later, one
# per run.
@test "an argument that is not a release tag is refused before anything is dispatched" {
	run "$TASK" v0.0.78 not-a-tag also-not
	[ "$status" -eq 2 ]
	[[ "$output" == *"not-a-tag"* ]]
	[[ "$output" == *"also-not"* ]]
	[ ! -s "$LEDGER" ]
}

@test "an unknown flag is a usage error, not a tag" {
	run "$TASK" --nonesuch
	[ "$status" -eq 2 ]
	[[ "$output" == *"usage:"* ]]
}

# --- dry run -------------------------------------------------------------------

@test "a dry run prints the plan and dispatches nothing" {
	RELEASE_BACKFILL_TAGS="v0.0.78 v0.0.9" run "$TASK" --dry-run
	[ "$status" -eq 0 ]
	[[ "$output" == *"would dispatch"* ]]
	[[ "$output" == *"v0.0.9"* ]]
	[[ "$output" == *"v0.0.78"* ]]
	[ ! -s "$LEDGER" ]
}

# The plan is the order the sweep would use, so a dry run is worth reading before
# a real one rather than being a bare list.
@test "a dry run lists the tags in the order it would use" {
	RELEASE_BACKFILL_TAGS="v0.0.110 v0.0.9" run "$TASK" --dry-run
	[ "$status" -eq 0 ]
	plan="$(printf '%s\n' "$output" | sed -n 's/^  \(v.*\)$/\1/p' | tr '\n' ' ')"
	[ "$plan" = "v0.0.9 v0.0.110 " ]
}

# A dry run must not need a forge client at all — it is the one mode an operator
# can use to read the plan before deciding whether to spend anything.
@test "a dry run needs no forge client" {
	RELEASE_BACKFILL_GH="$BATS_TEST_TMPDIR/nonesuch" \
		RELEASE_BACKFILL_TAGS="v0.0.78" run "$TASK" --dry-run
	[ "$status" -eq 0 ]
}

@test "an absent forge client is could-not-look for a real sweep" {
	RELEASE_BACKFILL_GH="$BATS_TEST_TMPDIR/nonesuch" \
		RELEASE_BACKFILL_TAGS="v0.0.78" run "$TASK"
	[ "$status" -eq 2 ]
	[[ "$output" == *"no forge client"* ]]
}

# --- waiting on the run, rather than on the dispatch ---------------------------

# A DISPATCH THAT RETURNS 0 IS NOT A RECORDED RELEASE — it means GitHub accepted
# the request. That is the "green while doing nothing" shape this whole issue is
# about, one layer out, so each tag is waited on and its conclusion read.
@test "each tag's run is viewed, not just dispatched" {
	RELEASE_BACKFILL_TAGS="v0.0.78 v0.0.79" run "$TASK"
	[ "$status" -eq 0 ]
	[ "$(grep -c '^run view' "$LEDGER")" -ge 2 ]
}

# THE RACE THIS AVOIDS, and the reason the newest run id is read BEFORE the
# dispatch: by the time the second tag is dispatched, the FIRST tag's run has
# completed, so a poll that only asked "is the newest run finished" would answer
# yes immediately and attribute the previous run's conclusion to this tag.
@test "a completed previous run is not mistaken for this tag's run" {
	RELEASE_BACKFILL_TAGS="v0.0.78 v0.0.79" run "$TASK"
	[ "$status" -eq 0 ]
	# Two distinct run ids were viewed, one per tag — not the same id twice.
	viewed="$(sed -n 's/^run view \([0-9]*\) .*$/\1/p' "$LEDGER" | sort -u | wc -l)"
	[ "$viewed" -eq 2 ]
}

@test "the summary names how many tags were recorded" {
	RELEASE_BACKFILL_TAGS="v0.0.78 v0.0.79 v0.0.80" run "$TASK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"3 tag(s) recorded"* ]]
}

# --- stopping on the first failure ---------------------------------------------

# CLOUD-750 measured `LINEAR_ACCESS_KEY` refused HTTP 401 under both auth forms.
# If the action refuses it too, every tag fails identically — so pressing on
# would queue 110 more doomed runs and bury the one line that says why.
@test "a failing run stops the sweep" {
	echo failure >"$STATE"
	RELEASE_BACKFILL_TAGS="v0.0.78 v0.0.79 v0.0.80" run "$TASK"
	[ "$status" -eq 1 ]
	[ "$(grep -c '^workflow run' "$LEDGER")" -eq 1 ]
}

# The refusal has to say how far it got, because the remedy is to re-run from
# there — and `sync` being create-or-update is what makes that safe.
@test "the refusal names how many tags were recorded before it" {
	echo failure >"$STATE"
	RELEASE_BACKFILL_TAGS="v0.0.78 v0.0.79" run "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"0 tag(s) recorded"* ]]
	[[ "$output" == *"'failure'"* ]]
}

# A conclusion that is neither success nor failure — `cancelled`, `timed_out`,
# `action_required` — is not a recorded release either. Anything but success
# stops, rather than an enumeration somebody has to keep current.
@test "a cancelled run stops the sweep too" {
	echo cancelled >"$STATE"
	RELEASE_BACKFILL_TAGS="v0.0.78" run "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"'cancelled'"* ]]
}

@test "a refused dispatch stops the sweep" {
	cat >"$RELEASE_BACKFILL_GH" <<-EOF
		#!/usr/bin/env bash
		printf '%s\n' "\$*" >>"$LEDGER"
		case "\$1 \$2" in
		"run list") echo 100 ;;
		"workflow run") exit 1 ;;
		esac
	EOF
	chmod +x "$RELEASE_BACKFILL_GH"
	RELEASE_BACKFILL_TAGS="v0.0.78 v0.0.79" run "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"was refused"* ]]
	[ "$(grep -c '^workflow run' "$LEDGER")" -eq 1 ]
}

# --- the runaway backstop ------------------------------------------------------

# A dispatch GitHub accepted and never scheduled is a platform failure, not a slow
# run. The cap is on the poll COUNT for the reason `LAND_MAX_LAPS` is on the lap
# count: a sweep that hangs forever reports nothing at all.
@test "a run that never appears is bounded, not an infinite poll" {
	cat >"$RELEASE_BACKFILL_GH" <<-EOF
		#!/usr/bin/env bash
		printf '%s\n' "\$*" >>"$LEDGER"
		case "\$1 \$2" in
		"run list") echo 100 ;;
		"workflow run") ;;
		"run view") printf 'completed success\n' ;;
		esac
	EOF
	chmod +x "$RELEASE_BACKFILL_GH"
	RELEASE_BACKFILL_MAX_POLLS=3 RELEASE_BACKFILL_TAGS="v0.0.78" run timeout 30 "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"never appeared"* ]]
}

@test "a run that never finishes is bounded too" {
	cat >"$RELEASE_BACKFILL_GH" <<-EOF
		#!/usr/bin/env bash
		printf '%s\n' "\$*" >>"$LEDGER"
		counter="$BATS_TEST_TMPDIR/counter"
		[ -f "\$counter" ] || echo 100 >"\$counter"
		case "\$1 \$2" in
		"run list") cat "\$counter" ;;
		"workflow run") echo \$(( \$(cat "\$counter") + 1 )) >"\$counter" ;;
		"run view") printf 'in_progress \n' ;;
		esac
	EOF
	chmod +x "$RELEASE_BACKFILL_GH"
	RELEASE_BACKFILL_MAX_POLLS=3 RELEASE_BACKFILL_TAGS="v0.0.78" run timeout 30 "$TASK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"did not finish"* ]]
}
