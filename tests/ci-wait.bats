#!/usr/bin/env bats
# subject: mise-tasks/ci-wait
# ci-wait's reading of a check-run set, exercised through a stub `gh` so the
# cases that matter — an all-skipped set, a red set, a conditional 304 — are
# reproducible without waiting on real CI.
#
# $CI_REQUIRED_CHECKS is deliberately NOT set here. It arrives from mise.toml
# [env] via `mise run test:bats`, so these cases run against the real roster
# rather than a copy of it that could disagree with the one landing uses. The
# check names below are that roster's; `ci-local-parity` is what keeps it
# matching the workflows.

setup() {
	# tests/helpers.bash: `sed_i` / `run_timeout`, standing in for GNU
	# tools a stock macOS does not ship (CLOUD-282).
	load helpers
	WAIT="$BATS_TEST_DIRNAME/../mise-tasks/ci-wait"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH SHA=deadbeef CI_WAIT_INTERVAL=1
}

# Writes a fake `gh` that replays canned HTTP responses, one per call, and
# records the argv of each call — the request itself is a contract too, and
# `per_page` living in it is what keeps a busy SHA from being read one page deep
# (CLOUD-337).
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
n=\$(cat "$BATS_TEST_TMPDIR/calls" 2>/dev/null || echo 0)
echo \$((n + 1)) >"$BATS_TEST_TMPDIR/calls"
printf '%s\n' "\$*" >>"$BATS_TEST_TMPDIR/args"
cat "$BATS_TEST_TMPDIR/resp.\$((n + 1))" 2>/dev/null || cat "$BATS_TEST_TMPDIR/resp.last"
EOF
	chmod +x "$STUB/gh"
	rm -f "$BATS_TEST_TMPDIR/calls" "$BATS_TEST_TMPDIR/args"
}

response() {
	local file="$1" etag="$2" runs="$3"
	{
		printf 'HTTP/2.0 200 OK\n'
		printf 'ETag: %s\n\n' "$etag"
		printf '%s\n' "$runs"
	} >"$BATS_TEST_TMPDIR/$file"
}

# A whole response body carrying the seven roster names for which ABSENCE is not
# a legitimate reading (CLOUD-337) — $CI_REQUIRED_CHECKS minus
# $CI_ABSENT_OK_CHECKS — all green, with any rows the case names appended after
# them. Every response meant to END the poll has to carry them: `checks-green`
# answers "no run at all" over a reading that omits one, and here that does not
# read as a failed assertion but as a HANG, since the poll is unbounded and only
# the case's own `run_timeout` stops it.
# DERIVED FROM THE ROSTER, never hand-listed, and the difference is a hang.
#
# These cases read the real `$CI_REQUIRED_CHECKS` on purpose (see the header), so
# a hand-written green set is a SECOND copy of the roster that drifts the moment
# a required check is added. Adding `perf` (CLOUD-172) is what proved it: the
# fixture answered green for every name it knew, `ci-wait` correctly kept waiting
# for the one it did not, and the suite HUNG rather than failed — twice, for the
# better part of an hour each time, because a poll with no answer is exactly what
# this task is built to do and it cannot tell "the roster grew" from "the run is
# still going".
#
# Deriving it means the green set is green BY CONSTRUCTION for whatever the
# roster says today. Absent-ok names are excluded deliberately: `zizmor` and the
# `action*` jobs are path-filtered and mint no run at all on most PRs, so a
# fixture that reported them would assert a shape the real API never produces.
green_body() {
	local rows='' name
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		rows+="${rows:+,}{\"status\":\"completed\",\"conclusion\":\"success\",\"name\":\"$name\"}"
	done < <(tr ',' '\n' <<<"${CI_REQUIRED_CHECKS:?the suite runs under mise, which supplies the roster}" |
		grep -vxF -f <(tr ',' '\n' <<<"${CI_ABSENT_OK_CHECKS:-}") || true)
	# Anti-vacuity: an empty set would make every one of these cases pass by
	# asserting nothing, which is the false green the task itself exists to stop.
	[ -n "$rows" ] || {
		echo "green_body derived an empty check set from CI_REQUIRED_CHECKS" >&2
		return 1
	}
	if [ "$#" -gt 0 ]; then
		printf '{"check_runs":[%s,%s]}' "$rows" "$*"
	else
		printf '{"check_runs":[%s]}' "$rows"
	fi
}

@test "green set exits 0 and prints each conclusion" {
	stub_gh
	response resp.last 'W/"a"' "$(green_body)"
	run "$WAIT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"success"*"ci"* ]]
}

@test "the check-runs request asks for a full page, not the default 30 (CLOUD-337)" {
	# The request is part of the predicate. This endpoint returns a check-run
	# per EVENT per name (CLOUD-436), so a nine-name roster over a PR that has
	# been readied, re-drafted and re-readied, plus the third parties, clears 30
	# rows without anything unusual happening — and nothing here fetches page 2.
	# Under the CLOUD-337 predicate a truncated name reads as absent and stalls
	# the poll; before it, it read as green. `checks-green`, `sonar-gate` and
	# `auto-bot-land.yml` had asked for 100 all along, so this reader was
	# the sole divergence.
	stub_gh
	response resp.last 'W/"a"' "$(green_body)"
	run "$WAIT"
	[ "$status" -eq 0 ]
	[[ "$(cat "$BATS_TEST_TMPDIR/args")" == *"check-runs?per_page=100"* ]]
}

@test "a failing check exits 1" {
	# The reading is deliberately a bare `ci failure` with the other six
	# mandatory names absent, which makes this the poll-level statement of
	# CLOUD-337's ordering: a real failure outranks a name that has not
	# registered, so `ci-wait` exits 1 here rather than holding the poll open for
	# stragglers on a tree already known to be red — which is what re-drafts the
	# PR and stops the next push buying another runner. Do not "fix" it by
	# swapping in `green_body`; that is the one edit that would silently retire
	# the assertion.
	stub_gh
	response resp.last 'W/"a"' '{"check_runs":[{"status":"completed","conclusion":"failure","name":"ci"}]}'
	run "$WAIT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not green"* ]]
}

@test "an all-skipped set is not green, and the poll continues" {
	# The draft-era runs look terminal and unfailed. Treating them as an answer
	# would clear a PR whose CI never ran.
	stub_gh
	response resp.1 'W/"a"' '{"check_runs":[{"status":"completed","conclusion":"skipped","name":"ci"}]}'
	response resp.last 'W/"b"' "$(green_body)"
	run run_timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 2 ]
}

@test "a draft-era skip set with third-party successes is not green" {
	# The set that landed #261 (CLOUD-327), byte-for-byte in shape: every check
	# that judges this repository is a draft-era `skipped`, and the two
	# workflows that are not draft-gated graded on their own. The old predicate
	# counted those two and reported "all checks terminal and green".
	stub_gh
	response resp.1 'W/"a"' '{"check_runs":[
          {"status":"completed","conclusion":"success","name":"SonarCloud Code Analysis"},
          {"status":"completed","conclusion":"success","name":"release-plz"},
          {"status":"completed","conclusion":"skipped","name":"commit-lint"},
          {"status":"completed","conclusion":"skipped","name":"cross"},
          {"status":"completed","conclusion":"skipped","name":"ci"},
          {"status":"completed","conclusion":"skipped","name":"final"},
          {"status":"completed","conclusion":"skipped","name":"darwin-link (aarch64-apple-darwin)"}]}'
	response resp.last 'W/"b"' "$(green_body)"
	run run_timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 2 ]
	# And it says what it is waiting on, as a pointer rather than a log.
	[[ "$output" == *"required check(s) with no verdict"* ]]
	[[ "$output" == *"ci skipped"* ]]
}

@test "a cancelled set holds the poll open instead of reporting red" {
	# CLOUD-363, through the poll rather than the predicate: the supersession
	# that cancelled #293's landing run made `ci-wait` exit 1, `land` re-draft,
	# and the branch wedge. The poll must outlive the cancellation, because
	# `land`'s next lap re-fires the ready and the fresh run supersedes these
	# check-runs by name.
	stub_gh
	response resp.1 'W/"a"' '{"check_runs":[
          {"status":"completed","conclusion":"failure","name":"final"},
          {"status":"completed","conclusion":"cancelled","name":"ci"},
          {"status":"completed","conclusion":"cancelled","name":"cross"}]}'
	response resp.last 'W/"b"' "$(green_body)"
	# `run_timeout`, not a bare `timeout`: macOS ships no coreutils `timeout` at
	# all, and this was the one call site in this suite still naming it directly
	# (CLOUD-282) — a failure on a missing binary, not on a flag.
	run run_timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 2 ]
	[[ "$output" == *"ci cancelled"* ]]
}

@test "a third-party check gets no veto over landing" {
	# Branch protection enforces the required set, so a failure outside it must
	# not hold `main`. The mirror of the case above: same scoping, other sign.
	stub_gh
	response resp.last 'W/"a"' "$(green_body '
          {"status":"completed","conclusion":"failure","name":"SonarCloud Code Analysis"},
          {"status":"completed","conclusion":"skipped","name":"release-plz"}')"
	run "$WAIT"
	[ "$status" -eq 0 ]
}

@test "a required check still pending holds the poll open" {
	# A third-party check that has already graded must not make the set look
	# terminal while ours is still running.
	stub_gh
	response resp.1 'W/"a"' '{"check_runs":[
          {"status":"completed","conclusion":"success","name":"SonarCloud Code Analysis"},
          {"status":"in_progress","conclusion":null,"name":"ci"}]}'
	response resp.last 'W/"b"' "$(green_body)"
	run run_timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 2 ]
}

@test "every poll pushes a tick, so a blocked loop is distinguishable from a waiting one" {
	# CLOUD-499. This loop is the only thing in a landing that iterates faster
	# than the lease heartbeat, and it used to push nothing at all — `land` sets
	# the phase `ci-wait(lap N)` once and it stays frozen for the whole matrix,
	# so a heartbeat reading only the phase could not tell a healthy wait from a
	# wedged `gh`. The tick is what makes "the loop went round" observable.
	#
	# Run inside a scratch repository: the registry is keyed to the git dir, and
	# a suite writing entries for fake pids into the real one would leave
	# headstones in the clone under test.
	repo="$BATS_TEST_TMPDIR/repo"
	git init -q "$repo"
	stub_gh
	response resp.1 'W/"a"' '{"check_runs":[{"status":"in_progress","conclusion":null,"name":"ci"}]}'
	response resp.last 'W/"b"' "$(green_body)"
	reg="$BATS_TEST_DIRNAME/../mise-tasks/task-registry"
	(cd "$repo" && "$reg" register land 4242 "ci-wait(lap 1)")
	run bash -c "cd '$repo' && BATTEN_TASK_PID=4242 '$WAIT'"
	[ "$status" -eq 0 ]
	entry="$repo/.git/batten-tasks/4242"
	# One tick per poll, counted rather than sampled: the tick IS the poll
	# counter, so the two must agree exactly or a poll went unrecorded.
	[ "$(sed -n 's/^tick: //p' "$entry")" = "$(cat "$BATS_TEST_TMPDIR/calls")" ]
	# And the world-moved signal is recorded too, which is the other half: a
	# tick that rose while this stayed put is the livelock a hang detector
	# cannot see.
	[ -n "$(sed -n 's/^sig: //p' "$entry")" ]
}

@test "a required check that failed is red, and named" {
	stub_gh
	response resp.last 'W/"a"' '{"check_runs":[
          {"status":"completed","conclusion":"success","name":"ci"},
          {"status":"completed","conclusion":"failure","name":"cross"}]}'
	run "$WAIT"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not green"* ]]
	[[ "$output" == *"cross failure"* ]]
}

@test "an unset required set is fatal rather than an empty one" {
	# An empty set makes every check unrequired, which is the false green this
	# task exists to stop — so it must not be reachable by forgetting a variable.
	stub_gh
	response resp.last 'W/"a"' '{"check_runs":[{"status":"completed","conclusion":"skipped","name":"ci"}]}'
	run env -u CI_REQUIRED_CHECKS "$WAIT"
	[ "$status" -ne 0 ]
	[[ "$output" == *"CI_REQUIRED_CHECKS is unset"* ]]
}

@test "a 304 keeps the previous reading instead of clearing it" {
	# A conditional request that finds no change has no body. Re-parsing that as
	# an empty check set would restart the wait on every unchanged poll.
	stub_gh
	response resp.1 'W/"a"' '{"check_runs":[{"status":"in_progress","conclusion":null,"name":"ci"}]}'
	printf 'HTTP/2.0 304 Not Modified\nETag: W/"a"\n\n' >"$BATS_TEST_TMPDIR/resp.2"
	response resp.last 'W/"b"' "$(green_body)"
	run run_timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 3 ]
}

@test "a server-requested poll floor is honoured over a shorter interval" {
	stub_gh
	{
		printf 'HTTP/2.0 200 OK\nETag: W/"a"\nX-Poll-Interval: 2\n\n'
		printf '%s\n' "$(green_body)"
	} >"$BATS_TEST_TMPDIR/resp.last"
	run "$WAIT"
	[ "$status" -eq 0 ]
}
