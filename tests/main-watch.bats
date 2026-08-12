#!/usr/bin/env bats
# The second half of a landing lap's wait (CLOUD-240): "is this SHA still
# landable", raced against `ci-wait`'s "is this SHA green".
#
# The stub answers with real HTTP framing — status line, headers, blank line,
# body — because that framing is what the task parses. A stub that handed back
# only the body would leave the 304 path, which is the whole reason a second
# poller is affordable, untested.

setup() {
	# tests/helpers.bash: `sed_i` / `run_timeout`, standing in for GNU
	# tools a stock macOS does not ship (CLOUD-282).
	load helpers
	WATCH="$BATS_TEST_DIRNAME/../mise-tasks/main-watch"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	# A FRACTION, because the poll interval is scaffolding here and not the
	# property (CLOUD-390). Five cases each burned ~3s waiting out whole-second
	# cycles — ~15s of the suite — to observe behaviour that is about WHICH
	# answer wins, never about how long a cycle takes. `main-watch` passes this
	# straight to `sleep`, which takes fractions, and `tests/target-ensure.bats`
	# already relies on that. Every assertion below is unchanged: a case that
	# stopped exercising its race would be worse than a slow one.
	export PATH MAIN_WATCH_INTERVAL=0.2
	: >"$BATS_TEST_TMPDIR/requests"
	stub_gh
}

# The Nth call answers with the Nth response file, the last one sticking. Every
# invocation records its own arguments, which is how the conditional request is
# asserted rather than assumed.
stub_gh() {
	cat >"$STUB/gh" <<-EOF
		#!/usr/bin/env bash
		printf '%s\n' "\$*" >>"$BATS_TEST_TMPDIR/requests"
		n=\$(cat "$BATS_TEST_TMPDIR/calls" 2>/dev/null || echo 0)
		n=\$((n + 1))
		echo "\$n" >"$BATS_TEST_TMPDIR/calls"
		cat "$BATS_TEST_TMPDIR/resp.\$n" 2>/dev/null || cat "$BATS_TEST_TMPDIR/resp.last"
	EOF
	chmod +x "$STUB/gh"
	rm -f "$BATS_TEST_TMPDIR/calls"
}

# A 200 carrying a ref object, with an ETag the next request should echo back.
ref_response() {
	local file="$1" sha="$2" etag="${3:-\"abc\"}" extra="${4:-}"
	{
		echo "HTTP/2.0 200 OK"
		echo "ETag: $etag"
		[ -z "$extra" ] || echo "$extra"
		echo
		printf '{"ref":"refs/heads/main","object":{"sha":"%s","type":"commit"}}' "$sha"
	} >"$BATS_TEST_TMPDIR/$file"
}

# 304 Not Modified: no body, no rate-limit charge. The reading stands.
not_modified() {
	{
		echo "HTTP/2.0 304 Not Modified"
		echo "ETag: \"abc\""
		echo
	} >"$BATS_TEST_TMPDIR/$1"
}

@test "main having moved exits 0 and points at both ends" {
	ref_response resp.last bbbbbbbbbbbbbbbb
	run "$WATCH" aaaaaaaaaaaaaaaa
	[ "$status" -eq 0 ]
	[[ "$output" == *"main moved aaaaaaaa -> bbbbbbbb"* ]]
}

@test "main standing still blocks, because losing the race is the normal case" {
	# A wall-clock cap here would turn a quiet main into a spurious lap, and a
	# spurious lap costs a whole CI run. The caller races this against a wait
	# that always terminates, so blocking forever is the correct behaviour.
	#
	# SIGKILL rather than the default TERM: bash defers a trapped signal until
	# the running `sleep` returns, so a TERM would make every blocking case here
	# cost a full poll interval to end.
	ref_response resp.last aaaaaaaaaaaaaaaa
	run run_timeout -s KILL 3 "$WATCH" aaaaaaaaaaaaaaaa
	[ "$status" -eq 137 ] || {
		echo "expected the watch to still be blocking, exited $status"
		return 1
	}
	[[ "$output" != *"moved"* ]]
}

@test "the second request is conditional on the first response's ETag" {
	# This is what makes a second poller affordable at all: GitHub answers 304
	# with no body and no rate-limit charge, so a quiet main costs nothing. An
	# unconditional poll would double the request cost of every lap to usually
	# learn nothing.
	ref_response resp.1 aaaaaaaaaaaaaaaa '"etag-one"'
	not_modified resp.2
	ref_response resp.last aaaaaaaaaaaaaaaa '"etag-one"'
	run run_timeout -s KILL 3 "$WATCH" aaaaaaaaaaaaaaaa
	[[ "$(sed -n '1p' "$BATS_TEST_TMPDIR/requests")" != *"If-None-Match"* ]]
	[[ "$(sed -n '2p' "$BATS_TEST_TMPDIR/requests")" == *"If-None-Match: \"etag-one\""* ]]
}

@test "a 304 is not read as a change, however many arrive" {
	# The 304 body is empty. Parsing it as a ref would yield an empty sha, and
	# an empty sha is not equal to the base — a naive comparison would report
	# movement on every unchanged poll and lap forever.
	ref_response resp.1 aaaaaaaaaaaaaaaa
	not_modified resp.last
	run run_timeout -s KILL 3 "$WATCH" aaaaaaaaaaaaaaaa
	[ "$status" -eq 137 ]
	[[ "$output" != *"moved"* ]]
}

@test "movement after a run of 304s is still caught" {
	ref_response resp.1 aaaaaaaaaaaaaaaa
	not_modified resp.2
	not_modified resp.3
	ref_response resp.last cccccccccccccccc
	run run_timeout -s KILL 8 "$WATCH" aaaaaaaaaaaaaaaa
	[ "$status" -eq 0 ]
	[[ "$output" == *"-> cccccccc"* ]]
}

@test "a server-sent poll interval is honoured as a floor" {
	# X-Poll-Interval is the server asking for a floor, and it wins over the
	# configured interval. Asserted by the watch outliving a window it would
	# have finished several polls inside.
	ref_response resp.1 aaaaaaaaaaaaaaaa '"abc"' "X-Poll-Interval: 9"
	ref_response resp.last dddddddddddddddd
	run run_timeout -s KILL 3 "$WATCH" aaaaaaaaaaaaaaaa
	[ "$status" -eq 137 ]
	[ "$(cat "$BATS_TEST_TMPDIR/calls")" -eq 1 ]
}

@test "a transient gh failure costs one poll, not the landing" {
	# `set -e` is off on purpose: this runs for as long as a CI run does, and a
	# single failed request must not abandon the lap.
	printf 'boom' >"$BATS_TEST_TMPDIR/resp.1"
	ref_response resp.last eeeeeeeeeeeeeeee
	run run_timeout -s KILL 8 "$WATCH" aaaaaaaaaaaaaaaa
	[ "$status" -eq 0 ]
	[[ "$output" == *"-> eeeeeeee"* ]]
}

@test "no base to compare against is a refusal, not a silent block" {
	# Outside a repository there is no `origin/main` to fall back to, so the
	# base really is empty — and an empty base compares unequal to every sha,
	# which would report movement on the first poll and lap forever.
	cd "$BATS_TEST_TMPDIR"
	run "$WATCH" ""
	[ "$status" -eq 1 ]
	[[ "$output" == *"no base SHA"* ]]
}
