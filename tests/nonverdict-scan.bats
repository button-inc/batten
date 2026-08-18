#!/usr/bin/env bats
# CLOUD-484. The measuring half: which recent required-check failures never reached
# a verdict. `gh` is stubbed with canned HTTP responses, the `tests/ci-wait.bats`
# idiom, because two of the properties under test are about the REQUEST (was
# `If-None-Match` actually sent) and about a response with no body at all (does a
# 304 keep the previous reading, or read as an empty window).

setup() {
	SCAN="$BATS_TEST_DIRNAME/../mise-tasks/nonverdict-scan"
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	# Its own cache per case: the store persists between runs by design, so a
	# shared one would let one case's ETags decide another's verdict.
	BATTEN_NONVERDICT_CACHE="$BATS_TEST_TMPDIR/cache"
	# The roster is normally supplied by mise.toml [env]. Set explicitly here so a
	# case's expectations do not move when the real roster gains a check.
	CI_REQUIRED_CHECKS="ci,cross,msrv,final"
	export PATH BATTEN_NONVERDICT_CACHE CI_REQUIRED_CHECKS
}

# A `gh` that routes on the endpoint and replays a numbered response per endpoint
# kind, recording every argv so a case can assert what was actually requested.
# Unquoted heredoc: stub-local vars are escaped, test-side paths interpolate.
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$BATS_TEST_TMPDIR/args"
kind=runs
for a in "\$@"; do
	case "\$a" in
	*/jobs*) kind=jobs ;;
	esac
done
n=\$(cat "$BATS_TEST_TMPDIR/n.\$kind" 2>/dev/null || echo 0)
n=\$((n + 1))
echo "\$n" >"$BATS_TEST_TMPDIR/n.\$kind"
file="$BATS_TEST_TMPDIR/\$kind.\$n"
[ -f "\$file" ] || file="$BATS_TEST_TMPDIR/\$kind.last"
cat "\$file"
# A non-2xx makes the real gh exit non-zero, a 304 included. The scan must
# tolerate that rather than aborting, so the stub reproduces it.
head -n1 "\$file" | grep -q ' 2[0-9][0-9] ' || exit 1
EOF
	chmod +x "$STUB/gh"
	rm -f "$BATS_TEST_TMPDIR/args" "$BATS_TEST_TMPDIR"/n.*
}

# `response <file> <etag> <json>` — a 200 carrying a body.
response() {
	{
		printf 'HTTP/2.0 200 OK\n'
		printf 'ETag: %s\n\n' "$2"
		printf '%s\n' "$3"
	} >"$BATS_TEST_TMPDIR/$1"
}

# `not_modified <file> <etag>` — a 304, which carries no body at all.
not_modified() {
	{
		printf 'HTTP/2.0 304 Not Modified\n'
		printf 'ETag: %s\n\n' "$2"
	} >"$BATS_TEST_TMPDIR/$1"
}

# The step name a toolchain-install failure really carries. Declared once, with
# the FULL pin: `attribution-check` exempts a pinned coordinate and refuses a bare
# vendor mention in prose, and the full sha is what the API actually returns.
TOOLCHAIN_STEP='Run jdx/mise-action@7e36c90d9ab29c415a2384db3006f3ec8a8cc654'

runs_list() { printf '{"workflow_runs":[{"id":%s,"conclusion":"failure"}]}' "$1"; }

# One failed job with one failed step.
jobs_body() {
	printf '{"jobs":[{"name":"%s","conclusion":"failure","steps":[{"number":1,"name":"%s","conclusion":"failure"}]}]}' "$1" "$2"
}

@test "THE ACCEPTANCE CASE: a job that died before any mise step is a non-verdict failure" {
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 900)"
	response jobs.last 'W/"j1"' "$(jobs_body msrv "$TOOLCHAIN_STEP")"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nonverdict"*"run=900"*"job=msrv"* ]]
	[[ "$output" == *"nonverdict=1"* ]]
	[[ "$output" == *"verdict=0"* ]]
}

@test "a job that failed IN a mise step rendered a verdict and is not counted" {
	# The other direction. A classifier that fires on everything is as silent a
	# failure as one that never fires.
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 901)"
	response jobs.last 'W/"j1"' "$(jobs_body ci 'Run mise run test:bats')"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"verdict"*"run=901"* ]]
	[[ "$output" == *"nonverdict=0"* ]]
	[[ "$output" == *"verdict=1"* ]]
}

@test "a job that failed in a mise EXEC step rendered a verdict too" {
	# THE SECOND SPELLING, and the case whose absence cost four Windows jobs in
	# one lap. `windows` runs `mise exec -- cargo test --workspace` rather than a
	# task, for the Git Bash reason its own comment measures — so seven
	# reproducibly failing tests classified as a provisioning transient, and
	# `land` re-ran the job until its budget stopped it while reporting that the
	# provisioning path was broken.
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 905)"
	response jobs.last 'W/"j1"' "$(jobs_body windows 'Run mise exec -- cargo test --workspace')"
	# The roster gains the job under test rather than the case borrowing a name
	# already in it: which job it is decides nothing here, but a case whose
	# subject is filtered out before the predicate runs would pass on nothing.
	CI_REQUIRED_CHECKS="ci,cross,msrv,windows,final" run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"verdict"*"run=905"*"job=windows"* ]]
	[[ "$output" == *"nonverdict=0"* ]]
	[[ "$output" == *"verdict=1"* ]]
}

@test "THE FAN-IN IS EXCLUDED: final's needs-assertion is not a non-verdict failure" {
	# Measured on run 31637881076: `final` failed at `Assert all required jobs
	# passed`, a bare run: step. Counted naively it would fire on every genuinely
	# red branch, because its failure is manufactured by its siblings.
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 902)"
	response jobs.last 'W/"j1"' "$(jobs_body final 'Assert all required jobs passed')"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"nonverdict=0"* ]]
	[[ "$output" == *"failed_jobs=0"* ]]
}

@test "A JOB OUTSIDE THE ROSTER IS EXCLUDED: a declining merge bot is not a failure here" {
	# Measured: the first version counted 22 `fast-forward` jobs failing at
	# `Run sequoia-pgp/fast-forward@…` — the bot refusing a branch that is no
	# longer a descendant, which is the landing loop working as designed.
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 903)"
	response jobs.last 'W/"j1"' "$(jobs_body fast-forward 'Run sequoia-pgp/fast-forward@ea7628b')"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"failed_jobs=0"* ]]
	[[ "$output" != *"fast-forward"* ]]
}

@test "the conditional request is actually sent once an ETag is stored" {
	# The whole rate-limit argument rests on this header reaching the server; a
	# cache that stores an ETag and never sends it costs the same as no cache.
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 904)"
	response jobs.last 'W/"j1"' "$(jobs_body ci 'Run mise run ci')"
	run "$SCAN"
	[ "$status" -eq 0 ]
	run "$SCAN"
	[ "$status" -eq 0 ]
	grep -q 'If-None-Match: W/"r1"' "$BATS_TEST_TMPDIR/args"
}

@test "A 304 KEEPS THE PREVIOUS READING rather than reading as an empty window" {
	# mem:github-rest-etiquette: re-parsing an empty 304 body yields nothing, which
	# for this scan would silently become "no failures" — a false green whose only
	# symptom is that the number stopped moving.
	stub_gh
	response runs.1 'W/"r1"' "$(runs_list 905)"
	response jobs.1 'W/"j1"' "$(jobs_body msrv "$TOOLCHAIN_STEP")"
	not_modified runs.2 'W/"r1"'
	not_modified jobs.2 'W/"j1"'
	run "$SCAN"
	[ "$status" -eq 0 ]
	first="$output"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[ "$output" = "$first" ]
	[[ "$output" == *"nonverdict=1"* ]]
}

@test "a 304 with no cached body is unreadable, never an empty window" {
	# The cache is the only thing that makes a 304 answerable. Without it the
	# honest report is that the window could not be read.
	stub_gh
	not_modified runs.last 'W/"r1"'
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"unreadable=1"* ]]
	[[ "$output" == *"runs=0"* ]]
}

@test "an unreadable jobs read is counted, not silently dropped" {
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 906)"
	printf 'HTTP/2.0 500 Internal Server Error\n\n' >"$BATS_TEST_TMPDIR/jobs.last"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"unreadable=1"* ]]
}

@test "an empty roster is unreadable rather than a count over every job" {
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 907)"
	response jobs.last 'W/"j1"' "$(jobs_body msrv "$TOOLCHAIN_STEP")"
	CI_REQUIRED_CHECKS="" run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"unreadable=1"* ]]
}

@test "a summary line is always emitted, even when nothing failed" {
	# ANTI-VACUITY, and the bug that produced this case: the first version aborted
	# silently under `set -e` when a response carried no ETag, printing neither
	# records nor a summary — indistinguishable from a clean empty window.
	stub_gh
	response runs.last 'W/"r1"' '{"workflow_runs":[]}'
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"window"*"runs=0"* ]]
}

@test "POINTER, NEVER PAYLOAD: records carry coordinates, and no log is fetched" {
	stub_gh
	response runs.last 'W/"r1"' "$(runs_list 908)"
	response jobs.last 'W/"j1"' "$(jobs_body msrv "$TOOLCHAIN_STEP")"
	run "$SCAN"
	[ "$status" -eq 0 ]
	# No call asked for a log; the step name is the whole diagnosis.
	! grep -q 'logs' "$BATS_TEST_TMPDIR/args"
}
