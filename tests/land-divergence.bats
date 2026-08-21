#!/usr/bin/env bats
# subject: mise-tasks/land-divergence.sh
# CLOUD-492. The measuring half. `gh` is stubbed with canned HTTP responses, the
# `tests/ci-wait.bats` idiom, because the properties under test are about the
# REQUEST (was `If-None-Match` actually sent), about a response with no body at
# all (does a 304 keep the previous reading), and about a response that is honest
# about being a prefix (does `total_count` catch the API's 1000-item cap).

setup() {
	SCAN="$BATS_TEST_DIRNAME/../mise-tasks/land-divergence.sh"
	ASSERT="$BATS_TEST_DIRNAME/../mise-tasks/land-divergence-assert.sh"
	ROOT="$BATS_TEST_DIRNAME/.."
	STUB="$BATS_TEST_TMPDIR/bin"
	mkdir -p "$STUB"
	PATH="$STUB:$PATH"
	# Its own cache per case: the ETag store persists within a clone by design, so
	# a shared one would let one case's cached body decide another's verdict.
	BATTEN_DIVERGENCE_CACHE="$BATS_TEST_TMPDIR/cache"
	BATTEN_DIVERGENCE_SINCE="2026-08-12T00:00:00Z"
	export PATH BATTEN_DIVERGENCE_CACHE BATTEN_DIVERGENCE_SINCE
}

# A `gh` that routes on the endpoint and replays a numbered response per endpoint
# kind, recording every argv so a case can assert what was actually requested.
# Unquoted heredoc: stub-local vars are escaped, test-side paths interpolate.
stub_gh() {
	cat >"$STUB/gh" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$BATS_TEST_TMPDIR/args"
kind=ci
for a in "\$@"; do
	case "\$a" in
	*fast-forward.yml*) kind=ff ;;
	*/pulls*) kind=pulls ;;
	*/jobs*) kind=jobs ;;
	esac
done
n=\$(cat "$BATS_TEST_TMPDIR/n.\$kind" 2>/dev/null || echo 0)
n=\$((n + 1))
printf '%s' "\$n" >"$BATS_TEST_TMPDIR/n.\$kind"
f="$BATS_TEST_TMPDIR/resp.\$kind.\$n"
[ -f "\$f" ] || f="$BATS_TEST_TMPDIR/resp.\$kind.1"
head -n1 "\$f" | grep -q ' 2' || { cat "\$f"; exit 1; }
cat "\$f"
EOF
	chmod +x "$STUB/gh"
}

# `ok <file> <etag> <json>` — a 200 with a body.
ok() {
	{
		printf 'HTTP/2.0 200 OK\n'
		[ -n "$2" ] && printf 'ETag: %s\n' "$2"
		printf '\n%s\n' "$3"
	} >"$1"
}

# `not_modified <file> <etag>` — a 304, which carries no body at all.
not_modified() {
	{
		printf 'HTTP/2.0 304 Not Modified\n'
		printf 'ETag: %s\n' "$2"
		printf '\n'
	} >"$1"
}

# One CI run, shaped as the runs endpoint returns it.
ci_payload() { # $1 = total_count, $2 = conclusion, $3 = branch
	printf '{"total_count":%s,"workflow_runs":[{"id":1,"head_branch":"%s","conclusion":"%s","created_at":"2026-08-12T01:00:00Z","run_started_at":"2026-08-12T01:00:00Z","updated_at":"2026-08-12T01:05:00Z","run_attempt":1}]}' \
		"$1" "$3" "$2"
}

pulls_payload() { # $1 = branch
	printf '[{"number":1,"merged_at":"2026-08-12T02:00:00Z","head":{"ref":"%s"}}]' "$1"
}

# One job of a run, as the per-run jobs endpoint returns it. `created` is when the
# leg was queued and `started` when a runner picked it up; the gap between them is
# the whole measurement (CLOUD-501).
jobs_payload() { # $1 = created, $2 = started, $3 = name
	printf '{"total_count":1,"jobs":[{"id":7,"name":"%s","created_at":"%s","started_at":"%s","conclusion":"success"}]}' \
		"$3" "$1" "$2"
}

prime() { # the happy path every case starts from
	stub_gh
	ok "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"' "$(ci_payload 1 success feat)"
	ok "$BATS_TEST_TMPDIR/resp.ff.1" 'W/"f1"' '{"total_count":0,"workflow_runs":[]}'
	ok "$BATS_TEST_TMPDIR/resp.pulls.1" 'W/"p1"' "$(pulls_payload feat)"
	# The jobs endpoint is read once per graded run. Without a default here every
	# existing case would fall through to the `ci` canned response, because the
	# stub's unmatched-URL branch is `kind=ci`.
	ok "$BATS_TEST_TMPDIR/resp.jobs.1" 'W/"j1"' \
		"$(jobs_payload 2026-08-12T01:00:00Z 2026-08-12T01:00:00Z ci)"
}

@test "a linear window measures one graded run against one landing" {
	prime
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"landings=1"* ]]
	[[ "$output" == *"graded=1"* ]]
	[[ "$output" == *"unreadable=0"* ]]
}

@test "the conditional request actually sends If-None-Match once an ETag is cached" {
	# mem:github-rest-etiquette: a 304 does not count against the primary rate
	# limit, and that is what makes a daily walk affordable. Asserted on the
	# REQUEST, because a cache nobody sends is not a cache.
	prime
	run "$SCAN"
	[ "$status" -eq 0 ]
	rm -f "$BATS_TEST_TMPDIR"/n.ci "$BATS_TEST_TMPDIR"/n.ff "$BATS_TEST_TMPDIR"/n.pulls "$BATS_TEST_TMPDIR"/n.jobs
	run "$SCAN"
	[ "$status" -eq 0 ]
	grep -q 'If-None-Match: W/"c1"' "$BATS_TEST_TMPDIR/args"
}

@test "A 304 KEEPS THE PREVIOUS READING rather than reading as an empty window" {
	# Re-parsing an empty 304 body yields nothing, which reads as "no runs" — a
	# perfect score off a response that carried no data. The failure then shows up
	# only as unexplained quiet, which is why this is asserted rather than assumed.
	prime
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"graded=1"* ]]

	rm -f "$BATS_TEST_TMPDIR"/n.ci "$BATS_TEST_TMPDIR"/n.ff "$BATS_TEST_TMPDIR"/n.pulls "$BATS_TEST_TMPDIR"/n.jobs
	not_modified "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"'
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"graded=1"* ]]
	[[ "$output" == *"unreadable=0"* ]]
}

@test "a 304 with no cached body is unreadable, never an empty window" {
	stub_gh
	not_modified "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"'
	ok "$BATS_TEST_TMPDIR/resp.ff.1" 'W/"f1"' '{"total_count":0,"workflow_runs":[]}'
	ok "$BATS_TEST_TMPDIR/resp.pulls.1" 'W/"p1"' "$(pulls_payload feat)"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"unreadable=1"* ]]
}

@test "TRUNCATION IS CAUGHT BY total_count, not by running out of pages" {
	# The measured defect, and the reason this property exists. The runs endpoint
	# hard-caps pagination at 1000 items while still reporting the true
	# total_count: measured on fast-forward.yml, total_count 1446, page 10 full,
	# page 11 EMPTY. A walk that stops when a page comes back short collects a
	# prefix and looks exactly like a clean finish — it reported ff_refused=0 over
	# a window carrying 598 refusals.
	prime
	ok "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"' "$(ci_payload 1446 success feat)"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"unreadable=1"* ]]
	[[ "$output" == *"read 1 of 1446"* ]]
}

@test "a truncated window makes the decider refuse, rather than judge a prefix" {
	# The two halves together: the measurer reports the prefix honestly and the
	# decider turns that into `could not look`, never a pass.
	prime
	ok "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"' "$(ci_payload 1446 success feat)"
	"$SCAN" >"$BATS_TEST_TMPDIR/records" 2>/dev/null
	run "$ASSERT" <"$BATS_TEST_TMPDIR/records"
	[ "$status" -eq 2 ]
}

@test "runs after a PR merged are not attributed to it" {
	# A branch name is reused, and a landing's denominator must not collect the
	# runs of its next life. Bounded by merged_at, so this run is out of scope.
	prime
	ok "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"' \
		'{"total_count":1,"workflow_runs":[{"id":9,"head_branch":"feat","conclusion":"failure","created_at":"2026-08-12T09:00:00Z","run_started_at":"2026-08-12T09:00:00Z","updated_at":"2026-08-12T09:05:00Z","run_attempt":1}]}'
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"graded=0"* ]]
}

@test "a draft-era skipped run is not counted as graded" {
	# CI does not run on drafts; the run object still exists and concluded
	# `skipped`. It spent no matrix, so counting it would inflate every ratio.
	prime
	ok "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"' "$(ci_payload 1 skipped feat)"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"graded=0"* ]]
}

@test "an unreadable run list reports rather than claiming a clean window" {
	stub_gh
	printf 'HTTP/2.0 500 Server Error\n\n' >"$BATS_TEST_TMPDIR/resp.ci.1"
	ok "$BATS_TEST_TMPDIR/resp.ff.1" 'W/"f1"' '{"total_count":0,"workflow_runs":[]}'
	ok "$BATS_TEST_TMPDIR/resp.pulls.1" 'W/"p1"' "$(pulls_payload feat)"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"unreadable=1"* ]]
}

# --- a property of the world must not red a branch ----------------------------

@test "neither half is in the hk gate" {
	# Non-negotiable: this measures the world, not the commit. A gate step that
	# reaches the network on the landing path is what CLOUD-410 cost.
	run grep -c 'land-divergence' "$ROOT/hk.pkl"
	[ "$output" = "0" ]
}

@test "neither half is in verify" {
	run bash -c "awk '/^\[tasks.verify\]/{p=1;next} /^\[/{p=0} p' '$ROOT/mise.toml' | grep -c land-divergence"
	[ "$output" = "0" ]
}

@test "the scheduled workflow declares a concurrency group, like every other" {
	# ci-local-parity property 8 requires it; asserted here too so the workflow
	# this task ships with cannot be the one that breaks the gate it landed after.
	run grep -c '^concurrency:' "$ROOT/.github/workflows/land-divergence.yml"
	[ "$output" = "1" ]
}

# --- CLOUD-501: the queue delay, attributed per JOB ----------------------------

@test "A JOB THAT WAITED REPORTS ITS GAP, where the run's own figure cannot" {
	# The measured defect. A run's `created_at` -> `run_started_at` is the FIRST
	# job's start, so a matrix leg that waited behind its siblings contributes
	# nothing to it — and telling a wide matrix from a saturated pool is exactly
	# what the diagnosis needs.
	prime
	ok "$BATS_TEST_TMPDIR/resp.jobs.1" 'W/"j1"' \
		"$(jobs_payload 2026-08-12T01:00:00Z 2026-08-12T01:04:00Z ci-linux)"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"queue_job_p90=240"* ]]
	[[ "$output" == *"job"*"job=ci-linux"*"queue=240"* ]]
}

@test "a job that started immediately reports zero and earns no record" {
	# The other direction, and the anti-noise rule the `pr` records already use: a
	# zero-wait leg is the ideal and says nothing a reader needs.
	prime
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"queue_job_p90=0"* ]]
	[[ "$output" != *"job"$'\t'"run="* ]]
}

@test "A RUN WHOSE JOBS CANNOT BE READ IS UNREADABLE, NEVER A ZERO WAIT" {
	# Dropping it would report a p90 over the legs that happened to answer, which
	# is the partial-coverage false green this whole sensor exists to refuse — and
	# the decider turns `unreadable` into `could not look` rather than a pass.
	prime
	printf 'HTTP/2.0 500 Server Error\n\n' >"$BATS_TEST_TMPDIR/resp.jobs.1"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"unreadable=1"* ]]
}

@test "the per-job read is bounded to graded runs, so a skipped run costs no request" {
	# `job_queue` is one request per run, which cuts against the ETag-stability
	# argument in the header — so the bound is asserted rather than described.
	prime
	ok "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"' "$(ci_payload 1 skipped feat)"
	run "$SCAN"
	[ "$status" -eq 0 ]
	run grep -c '/jobs' "$BATS_TEST_TMPDIR/args"
	[ "$output" = "0" ]
}

@test "the job record is pointer-only — a run id, a job name and seconds" {
	# Non-negotiable 4. A jobs payload carries step detail and log urls; none of it
	# reaches the record.
	prime
	ok "$BATS_TEST_TMPDIR/resp.jobs.1" 'W/"j1"' \
		"$(jobs_payload 2026-08-12T01:00:00Z 2026-08-12T01:00:30Z ci-linux)"
	run "$SCAN"
	[ "$status" -eq 0 ]
	[[ "$output" != *"conclusion"* ]]
	[[ "$output" != *"total_count"* ]]
}
