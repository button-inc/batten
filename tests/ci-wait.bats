#!/usr/bin/env bats
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
	WAIT="$BATS_TEST_DIRNAME/../mise-tasks/ci-wait"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	export PATH SHA=deadbeef CI_WAIT_INTERVAL=1
}

# Writes a fake `gh` that replays canned HTTP responses, one per call.
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
n=\$(cat "$BATS_TEST_TMPDIR/calls" 2>/dev/null || echo 0)
echo \$((n + 1)) >"$BATS_TEST_TMPDIR/calls"
cat "$BATS_TEST_TMPDIR/resp.\$((n + 1))" 2>/dev/null || cat "$BATS_TEST_TMPDIR/resp.last"
EOF
	chmod +x "$STUB/gh"
	rm -f "$BATS_TEST_TMPDIR/calls"
}

response() {
	local file="$1" etag="$2" runs="$3"
	{
		printf 'HTTP/2.0 200 OK\n'
		printf 'ETag: %s\n\n' "$etag"
		printf '%s\n' "$runs"
	} >"$BATS_TEST_TMPDIR/$file"
}

@test "green set exits 0 and prints each conclusion" {
	stub_gh
	response resp.last 'W/"a"' '{"check_runs":[{"status":"completed","conclusion":"success","name":"ci"}]}'
	run "$WAIT"
	[ "$status" -eq 0 ]
	[[ "$output" == *"success"*"ci"* ]]
}

@test "a failing check exits 1" {
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
	response resp.last 'W/"b"' '{"check_runs":[{"status":"completed","conclusion":"success","name":"ci"}]}'
	run timeout 20 "$WAIT"
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
	response resp.last 'W/"b"' '{"check_runs":[
          {"status":"completed","conclusion":"success","name":"ci"}]}'
	run timeout 20 "$WAIT"
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
	response resp.last 'W/"b"' '{"check_runs":[
          {"status":"completed","conclusion":"success","name":"ci"}]}'
	run timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 2 ]
	[[ "$output" == *"ci cancelled"* ]]
}

@test "a third-party check gets no veto over landing" {
	# Branch protection enforces the required set, so a failure outside it must
	# not hold `main`. The mirror of the case above: same scoping, other sign.
	stub_gh
	response resp.last 'W/"a"' '{"check_runs":[
          {"status":"completed","conclusion":"failure","name":"SonarCloud Code Analysis"},
          {"status":"completed","conclusion":"skipped","name":"release-plz"},
          {"status":"completed","conclusion":"success","name":"ci"}]}'
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
	response resp.last 'W/"b"' '{"check_runs":[
          {"status":"completed","conclusion":"success","name":"ci"}]}'
	run timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 2 ]
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
	response resp.last 'W/"b"' '{"check_runs":[{"status":"completed","conclusion":"success","name":"ci"}]}'
	run timeout 20 "$WAIT"
	[ "$status" -eq 0 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -ge 3 ]
}

@test "a server-requested poll floor is honoured over a shorter interval" {
	stub_gh
	{
		printf 'HTTP/2.0 200 OK\nETag: W/"a"\nX-Poll-Interval: 2\n\n'
		printf '%s\n' '{"check_runs":[{"status":"completed","conclusion":"success","name":"ci"}]}'
	} >"$BATS_TEST_TMPDIR/resp.last"
	run "$WAIT"
	[ "$status" -eq 0 ]
}
