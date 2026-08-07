#!/usr/bin/env bats
# ci-wait's reading of a check-run set, exercised through a stub `gh` so the
# cases that matter — an all-skipped set, a red set, a conditional 304 — are
# reproducible without waiting on real CI.

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
