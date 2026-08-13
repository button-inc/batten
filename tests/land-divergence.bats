#!/usr/bin/env bats
# CLOUD-492. The measuring half. `gh` is stubbed with canned HTTP responses, the
# `tests/ci-wait.bats` idiom, because the properties under test are about the
# REQUEST (was `If-None-Match` actually sent), about a response with no body at
# all (does a 304 keep the previous reading), and about a response that is honest
# about being a prefix (does `total_count` catch the API's 1000-item cap).

setup() {
	SCAN="$BATS_TEST_DIRNAME/../mise-tasks/land-divergence"
	ASSERT="$BATS_TEST_DIRNAME/../mise-tasks/land-divergence-assert"
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

prime() { # the happy path every case starts from
	stub_gh
	ok "$BATS_TEST_TMPDIR/resp.ci.1" 'W/"c1"' "$(ci_payload 1 success feat)"
	ok "$BATS_TEST_TMPDIR/resp.ff.1" 'W/"f1"' '{"total_count":0,"workflow_runs":[]}'
	ok "$BATS_TEST_TMPDIR/resp.pulls.1" 'W/"p1"' "$(pulls_payload feat)"
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
	rm -f "$BATS_TEST_TMPDIR/n.ci" "$BATS_TEST_TMPDIR/n.ff" "$BATS_TEST_TMPDIR/n.pulls"
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

	rm -f "$BATS_TEST_TMPDIR/n.ci" "$BATS_TEST_TMPDIR/n.ff" "$BATS_TEST_TMPDIR/n.pulls"
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
