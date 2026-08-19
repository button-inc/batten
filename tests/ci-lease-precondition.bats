#!/usr/bin/env bats
# ci-lease-precondition: the runner's half of the landing lease (CLOUD-420).
#
# Two questions, asked in order, and the first is the one the lease itself cannot
# answer: does this head's own `land` take the lease at all? A clone running
# tooling that predates CLOUD-393 takes no lease, so the ref reads ABSENT and the
# lease table would authorise it — which is how four matrices ran beside three
# orderly handoffs on 2026-08-12.
#
# Everything here is driven through a stubbed `gh`: the script's only inputs are
# two reads from trunk and one POST, so a stub that scripts those three covers
# every row without a remote, a runner, or a clock. `git` is real — the throwaway
# repo it builds is local and instant, and stubbing it would test the stub.
#
# THE PROPERTY THAT OUTRANKS EVERY ROW: this never exits non-zero. A job that
# reds before its cancellation lands makes the RUN conclude `failure` rather than
# `cancelled`, `final` runs under `!cancelled()` and fails, and `land` re-drafts
# the PR — the fleet-wide re-drafting the whole design exists to avoid, arriving
# through its own remedy. Every case asserts status 0, including the failures.

setup() {
	PRECOND="$BATS_TEST_DIRNAME/../mise-tasks/ci-lease-precondition"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH

	# HERMETIC, AND THAT IS NOT HOUSEKEEPING. Every variable below has an ambient
	# `GITHUB_*` fallback in the script under test, and CI sets those while a
	# developer box does not — so a case that reaches "unset" by unsetting only
	# the `LEASE_*` name passes locally and behaves differently under Actions.
	# That is a verify/CI disagreement by construction, which is the single thing
	# the gate exists to rule out. Measured: `no run id means there is nothing to
	# cancel` went green locally and red in CI, where it had fallen through to
	# GITHUB_RUN_ID and asked to cancel the very run it was executing in.
	unset GITHUB_REPOSITORY GITHUB_HEAD_REF GITHUB_RUN_ID GITHUB_SERVER_URL GITHUB_SHA

	# Defaults describing a healthy, current, unblocked head. Each case moves
	# exactly one of them, so a failure names the row rather than the fixture.
	head_land 'mise run land-lock acquire'
	land_lock_exits 0
	export GH_REPO=button-inc/batten
	export LEASE_HEAD_REF=feature-x
	export LEASE_HEAD_SHA=cafebabe
	export LEASE_RUN_ID=12345
	export RUNNER_TEMP="$BATS_TEST_TMPDIR/runner"
	# The production wait is a backstop on a cancellation that never arrives; a
	# suite that paid it would spend 45s per stop row to observe nothing.
	export LEASE_CANCEL_WAIT=0
	export GH_TOKEN=ghs-not-a-real-token
	mkdir -p "$RUNNER_TEMP"
	stub_gh
}

# What `contents/mise-tasks/land?ref=<head sha>` returns.
head_land() { printf '%s\n' "$1" >"$BATS_TEST_TMPDIR/head-land"; }

# The `land-lock` this fetches from trunk IS a stub — which is the whole trick
# here. `authorises` has its own exhaustive suite in tests/land-lock.bats; what
# this file tests is how the precondition reacts to each of its answers, so the
# answer is scripted rather than provoked.
land_lock_exits() {
	cat >"$BATS_TEST_TMPDIR/land-lock" <<EOF
#!/usr/bin/env bash
echo "land-lock stub: \$*"
exit $1
EOF
}

stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
t="$BATS_TEST_TMPDIR"
url=""
for a in "\$@"; do case "\$a" in repos/*) url="\$a"; break ;; esac; done
case "\$url" in
  */cancel)
    [ ! -e "\$t/cancel-refused" ] || exit 1
    echo "\$url" >>"\$t/cancels" ;;
  *contents/mise-tasks/land-lock*)
    [ ! -e "\$t/land-lock-unreadable" ] || exit 1
    cat "\$t/land-lock" ;;
  *contents/mise-tasks/land*)
    [ ! -e "\$t/head-land-unreadable" ] || exit 1
    cat "\$t/head-land" ;;
  *) exit 1 ;;
esac
EOF
	chmod +x "$STUB/gh"
}

cancels() { cat "$BATS_TEST_TMPDIR/cancels" 2>/dev/null || true; }

@test "a current head with a free lease runs, and cancels nothing" {
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[ -z "$(cancels)" ]
}

@test "a lease that authorises another branch STOPS this run — the acceptance case" {
	# `land-lock authorises` exits 3 for exactly this. The precondition's job is
	# to turn that into a cancelled run rather than a red one.
	land_lock_exits 3
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$(cancels)" == *"/actions/runs/12345/cancel"* ]]
	[[ "$output" == *"not authorised"* ]]
}

@test "THE STALENESS ROW: a head whose land does not take the lease is stopped" {
	# The hole the lease table cannot see. This head takes no lease, so the ref
	# reads absent and every row below would wave it through.
	head_land 'echo landing without a lease'
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$(cancels)" == *"/cancel"* ]]
}

@test "the staleness refusal names the remedy, not merely the refusal" {
	head_land 'echo landing without a lease'
	run "$PRECOND"
	[[ "$output" == *"git rebase origin/main"* ]]
	[[ "$output" == *"mise run land"* ]]
}

@test "a stale head is stopped WITHOUT consulting the lease — it cannot be judged by it" {
	# Ordering matters, not just the verdict: a lease that authorises this very
	# branch must not rescue tooling that cannot honour it.
	head_land 'echo landing without a lease'
	land_lock_exits 0
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$(cancels)" == *"/cancel"* ]]
}

@test "the head sha is read from LEASE_HEAD_SHA, and its absence is said out loud" {
	# GITHUB_SHA on a pull_request event is the MERGE commit, which carries
	# trunk's `land` whenever the head did not touch it — so falling back to it
	# would pass every stale head silently and look implemented.
	head_land 'echo landing without a lease'
	unset LEASE_HEAD_SHA
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"not judging this head's age"* ]]
	[ -z "$(cancels)" ]
}

@test "FAIL OPEN: an unreadable head land is not judged" {
	touch "$BATS_TEST_TMPDIR/head-land-unreadable"
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[ -z "$(cancels)" ]
}

@test "FAIL OPEN: an unreadable land-lock runs rather than stopping the fleet" {
	touch "$BATS_TEST_TMPDIR/land-lock-unreadable"
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"running rather than stopping the fleet"* ]]
	[ -z "$(cancels)" ]
}

@test "FAIL OPEN: an answer that is neither run nor stop runs" {
	# `authorises` fails open by contract, so a 1 or a 2 arriving here means this
	# script is holding it wrong. One matrix beats a stopped fleet either way.
	land_lock_exits 2
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"neither run nor stop"* ]]
	[ -z "$(cancels)" ]
}

@test "CLOUD-420: A WORKSPACE THAT CANNOT BE BUILT STILL EXITS 0" {
	# THE UNTESTED LINE. `set -euo pipefail` became `set -uo pipefail` to keep the
	# header's promise — "AND IT NEVER EXITS NON-ZERO" — and nothing exercised the
	# case that promise exists for. Eighteen cases covered `gh` and fetch failures;
	# every one of them still handed the script a working `RUNNER_TEMP`.
	#
	# The whole setup chain is unguarded: the `RUNNER_TEMP` fallback, `mkdir -p`,
	# the redirect that writes land-lock, `chmod +x`, `git init`, `remote add` and
	# `config --local`. With `-e` restored the first of them ends the script
	# non-zero, the job reds before its cancellation lands, the RUN concludes
	# `failure` rather than `cancelled`, `final` fails its needs assertion, and
	# `land` re-drafts the PR — the fleet-wide re-drafting this design exists to
	# avoid, arriving through its own remedy.
	#
	# A FILE where a directory must be. `mkdir -p "$file/batten-lease.$$"` cannot
	# succeed, and every later step inherits the failure.
	: >"$BATS_TEST_TMPDIR/not-a-dir"
	export RUNNER_TEMP="$BATS_TEST_TMPDIR/not-a-dir"
	# The lease says STOP, so this row cannot pass by never reaching the workspace:
	# it is the expensive path, the one that builds the clone and consults the lock.
	land_lock_exits 3
	run "$PRECOND"
	[ "$status" -eq 0 ]
}

@test "CLOUD-420: a broken workspace is not reported as land-lock's answer" {
	# The fail-open above is reached BY ACCIDENT — a cd/exec failure falls into the
	# `*)` arm, whose message says `land-lock answered <rc>, which is neither run
	# nor stop`. That attributes a workspace failure to a predicate that was never
	# consulted, and it is the line a human reads when the fleet misbehaves.
	: >"$BATS_TEST_TMPDIR/not-a-dir"
	export RUNNER_TEMP="$BATS_TEST_TMPDIR/not-a-dir"
	land_lock_exits 3
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"workspace"* ]]
	[[ "$output" != *"land-lock answered"* ]]
}

@test "FAIL OPEN: a refused cancellation runs rather than reddening" {
	land_lock_exits 3
	touch "$BATS_TEST_TMPDIR/cancel-refused"
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$output" == *"cancellation was refused"* ]]
}

@test "FAIL OPEN: no run id means there is nothing to cancel" {
	land_lock_exits 3
	unset LEASE_RUN_ID
	run "$PRECOND"
	[ "$status" -eq 0 ]
	[ -z "$(cancels)" ]
}

@test "FAIL OPEN: no repository and no head ref each run" {
	unset GH_REPO
	run "$PRECOND"
	[ "$status" -eq 0 ]
	GH_REPO=button-inc/batten
	export GH_REPO
	unset LEASE_HEAD_REF
	run "$PRECOND"
	[ "$status" -eq 0 ]
}

@test "the branch under judgement is the one passed to land-lock" {
	# The stub echoes its arguments. A precondition that asked about the wrong
	# branch would authorise every run and look correct in review.
	run "$PRECOND"
	[[ "$output" == *"authorises feature-x"* ]]
}

@test "the token never reaches the log, on any path" {
	# Non-negotiable 4, and the reason the credential goes in an http header
	# rather than a userinfo URL: land-lock prints its remote when it cannot
	# reach it.
	land_lock_exits 3
	run "$PRECOND"
	[[ "$output" != *"ghs-not-a-real-token"* ]]
	head_land 'echo landing without a lease'
	run "$PRECOND"
	[[ "$output" != *"ghs-not-a-real-token"* ]]
}

@test "a branch that lands through /fast-forward is not judged, in either row" {
	# `auto-bot-land.yml` and `auto-release-land.yml` fire on
	# `workflow_run: completed`, which a CANCELLED run satisfies — they then find
	# the checks not green and stop, and nothing retries. Cancelling those runs
	# would defer a matrix to the next rebase rather than save one, and add a
	# stall to a landing path that is unattended by design.
	land_lock_exits 3
	head_land 'echo landing without a lease'
	for ref in renovate/cargo release-plz-2026-08-12; do
		LEASE_HEAD_REF="$ref" run "$PRECOND"
		[ "$status" -eq 0 ]
		[[ "$output" == *"lands through /fast-forward"* ]]
	done
	[ -z "$(cancels)" ]
}

@test "the retired bot's prefix is judged like any other branch (CLOUD-660)" {
	# The arm moved rather than being added: Dependabot is retired, so a
	# `dependabot/*` head is now somebody's ordinary branch and gets the ordinary
	# answer. An exemption left behind for a bot that no longer runs is an
	# unauthorised matrix nobody would ever look at.
	land_lock_exits 3
	head_land 'echo landing without a lease'
	LEASE_HEAD_REF=dependabot/cargo/serde-1.0.2 run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$(cancels)" == *"/cancel"* ]]
}

@test "the exemption is a prefix on the landing path, not a substring anywhere in the ref" {
	# `feature/release-plz-notes` is somebody's branch, not the release PR's.
	land_lock_exits 3
	LEASE_HEAD_REF=feature/release-plz-notes run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$(cancels)" == *"/cancel"* ]]
}

@test "the ambient Actions run id is the fallback, and it is the run this is standing in" {
	# The fallback the scrub in `setup` exists to keep out of the other cases —
	# pinned here rather than merely avoided, because it is real behaviour: inside
	# a job, GITHUB_RUN_ID names exactly the run a stop is meant to cancel, so a
	# workflow that forgot to pass LEASE_RUN_ID still stops correctly.
	land_lock_exits 3
	unset LEASE_RUN_ID
	GITHUB_RUN_ID=987654 run "$PRECOND"
	[ "$status" -eq 0 ]
	[[ "$(cancels)" == *"/actions/runs/987654/cancel"* ]]
}

# The runner only treats a line as a workflow command when it begins with `::`
# after leading whitespace is trimmed (actions/runner, ActionCommand.TryParseV2,
# which is line-anchored). `say()` prefixes `lease-precondition: `, so a token
# routed through it lands at column 20 and is read as ordinary output.
#
# That matters more here than anywhere else in the repo: a stopped run is a
# CANCELLED run whose `final` is red with no failed step of its own, so the
# annotation is the only surface that says the lease declined it and that the
# remedy is one rebase. Both stop paths are pinned, and every occurrence is
# checked rather than the first — a second token behind a prefix is the same
# defect with a passing test.
assert_annotations_are_annotations() {
	local line bad=""
	while IFS= read -r line; do
		case "$line" in
		*"::error::"*) [[ "$line" == "::error::"* ]] || bad="$line" ;;
		esac
	done <<<"$output"
	[ -z "$bad" ]
}

@test "the lease refusal is a real annotation, not a log line the runner ignores" {
	land_lock_exits 3
	run "$PRECOND"
	[[ "$output" == *"::error::"* ]]
	assert_annotations_are_annotations
}

@test "the staleness remedy is a real annotation too — it is the actionable one" {
	head_land 'echo landing without a lease'
	run "$PRECOND"
	[[ "$output" == *"::error::"* ]]
	[[ "$output" == *"git rebase origin/main"* ]]
	assert_annotations_are_annotations
}
