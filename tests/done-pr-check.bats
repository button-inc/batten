#!/usr/bin/env bats
# subject: mise-tasks/done-pr-check.sh
# done-pr-check: an issue may become Done only if none of its own pull requests is
# still open (CLOUD-468).
#
# The motivating incident is the regression fixture at the bottom. CLOUD-420
# carried four PRs, one of them an open draft, and read Done for 35 minutes
# before a human reversed it — then the same inference was made independently by
# a session reading the same board. A merged PR completes a DIFF; the board read
# it as completing an ISSUE, and those coincide only at N=1.
#
# Pure function of stdin, like `claim-check` and `graph-check`: no network, no
# credential, so these rows run unconditionally in the gate rather than needing
# live board data.

setup() {
	# `DONE_UNDER_TEST` lets the mutation harness point these rows at a COPY.
	# Mutating the tracked file in place makes a corrupted commit reachable from
	# any concurrent `git add -A` — which staged a mutant into a pushed commit
	# on 2026-08-12 (recorded on CLOUD-418). Unset in every normal run.
	DONE="${DONE_UNDER_TEST:-$BATS_TEST_DIRNAME/../mise-tasks/done-pr-check.sh}"
}

# One issue, given its attachment numbers and the PR states the caller fetched.
payload() { # <json>
	printf '%s' "$1"
}

pr_url() { # <n>
	printf 'https://github.com/button-inc/batten/pull/%s' "$1"
}

@test "every attached PR merged: Done is licensed" {
	run "$DONE" <<EOF
[{"id":"CLOUD-425",
  "attachments":[{"url":"$(pr_url 346)","title":"t"}],
  "pulls":[{"number":346,"state":"closed","merged":true,"draft":false}]}]
EOF
	[ "$status" -eq 0 ]
}

@test "an OPEN pull request refuses, and the refusal names its number" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"$(pr_url 500)","title":"t"}],
  "pulls":[{"number":500,"state":"open","merged":false,"draft":false}]}]
EOF
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 open-pr (#500)"* ]]
}

@test "THE DEFECT: a DRAFT pull request refuses, and is named as a draft" {
	# The sharper case, and the one that actually happened: a draft is invisible
	# in most PR listings, so #368 went unnoticed while CLOUD-420 read Done.
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"$(pr_url 368)","title":"t"}],
  "pulls":[{"number":368,"state":"open","merged":false,"draft":true}]}]
EOF
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 open-pr (#368, draft)"* ]]
}

@test "one open PR among several merged still refuses — N=1 is the only safe case" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"$(pr_url 1)"},{"url":"$(pr_url 2)"},{"url":"$(pr_url 3)"}],
  "pulls":[{"number":1,"state":"closed","merged":true,"draft":false},
           {"number":2,"state":"closed","merged":true,"draft":false},
           {"number":3,"state":"open","merged":false,"draft":false}]}]
EOF
	[ "$status" -eq 1 ]
	[[ "$output" == *"#3"* ]]
}

@test "a closed-unmerged PR does NOT refuse — a decided outcome is not work in flight" {
	# Deliberate. Refusing on an abandoned or superseded PR would block Done
	# forever with no action that could clear it, which is the shape of a gate
	# that gets bypassed rather than satisfied.
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"$(pr_url 10)"},{"url":"$(pr_url 11)"}],
  "pulls":[{"number":10,"state":"closed","merged":false,"draft":false},
           {"number":11,"state":"closed","merged":true,"draft":false}]}]
EOF
	[ "$status" -eq 0 ]
}

@test "no pull request at all is refused — In Review already requires one" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1","attachments":[],"pulls":[]}]
EOF
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-1 no-pr"* ]]
}

@test "a non-PR attachment is ignored, not counted as a pull request" {
	# The filter is claim-check's, matched on URL shape rather than on a title a
	# human wrote. A Linear document or a Sonar link must not read as a PR.
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"https://linear.app/buttoninc/document/x","title":"spec"},
                 {"url":"$(pr_url 7)"}],
  "pulls":[{"number":7,"state":"closed","merged":true,"draft":false}]}]
EOF
	[ "$status" -eq 0 ]
}

@test "a PR-shaped URL on another host is not a PR — the filter is GitHub-anchored" {
	# Found by mutation: widening the filter to `pull/[0-9]+` survived every
	# other row, because the number capture requires a LEADING slash and so
	# already rejects `how-to-pull/123`. The host restriction is the half only
	# this row exercises, and without it a forge link would read as a blocker.
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"https://gitlab.com/acme/x/pull/999"},{"url":"$(pr_url 7)"}],
  "pulls":[{"number":7,"state":"closed","merged":true,"draft":false}]}]
EOF
	[ "$status" -eq 0 ]
}

@test "an attachment whose URL only mentions pull is not a PR" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"https://example.com/how-to-pull/123"},{"url":"$(pr_url 7)"}],
  "pulls":[{"number":7,"state":"closed","merged":true,"draft":false}]}]
EOF
	[ "$status" -eq 0 ]
}

@test "COULD NOT LOOK: an attached PR with no state supplied is exit 2, never a licence" {
	# The whole defect is a Done granted over a PR nobody checked, so an absent
	# state must not be the cheapest route to that same outcome.
	run "$DONE" <<EOF
[{"id":"CLOUD-1","attachments":[{"url":"$(pr_url 42)"}],"pulls":[]}]
EOF
	[ "$status" -eq 2 ]
	[[ "$output" == *"#42"* ]]
	[[ "$output" == *"no state"* ]]
}

@test "a missing pulls key is could-not-look too, not an empty set of blockers" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1","attachments":[{"url":"$(pr_url 42)"}]}]
EOF
	[ "$status" -eq 2 ]
}

@test "several issues are each judged, and one bad issue refuses the batch" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1","attachments":[{"url":"$(pr_url 1)"}],
  "pulls":[{"number":1,"state":"closed","merged":true,"draft":false}]},
 {"id":"CLOUD-2","attachments":[{"url":"$(pr_url 2)"}],
  "pulls":[{"number":2,"state":"open","merged":false,"draft":false}]}]
EOF
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-2 open-pr (#2)"* ]]
	[[ "$output" != *"CLOUD-1 open-pr"* ]]
}

@test "a duplicate attachment for one PR is counted once" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1","attachments":[{"url":"$(pr_url 9)"},{"url":"$(pr_url 9)"}],
  "pulls":[{"number":9,"state":"open","merged":false,"draft":false}]}]
EOF
	[ "$status" -eq 1 ]
	[ "$(grep -c 'open-pr' <<<"$output")" -eq 1 ]
}

@test "empty stdin is exit 2, distinct from a licensed issue" {
	run "$DONE" </dev/null
	[ "$status" -eq 2 ]
}

@test "unparseable stdin is exit 2" {
	run "$DONE" <<<'not json'
	[ "$status" -eq 2 ]
}

@test "a payload with no id is exit 2, never a pass" {
	run "$DONE" <<<'[{"attachments":[]}]'
	[ "$status" -eq 2 ]
}

@test "a concatenated payload stream is accepted, like claim-check's" {
	run "$DONE" <<EOF
{"id":"CLOUD-1","attachments":[{"url":"$(pr_url 1)"}],
 "pulls":[{"number":1,"state":"closed","merged":true,"draft":false}]}
{"id":"CLOUD-2","attachments":[{"url":"$(pr_url 2)"}],
 "pulls":[{"number":2,"state":"closed","merged":true,"draft":false}]}
EOF
	[ "$status" -eq 0 ]
}

@test "THE PROPERTY: output is a pointer — an id, a rule and a number, never a title" {
	run "$DONE" <<EOF
[{"id":"CLOUD-1",
  "attachments":[{"url":"$(pr_url 500)","title":"a distinctive title no gate may echo"}],
  "pulls":[{"number":500,"state":"open","merged":false,"draft":false,
            "title":"another distinctive title"}]}]
EOF
	[ "$status" -eq 1 ]
	[[ "$output" != *"distinctive title"* ]]
}

@test "THE REGRESSION: CLOUD-420's real shape refuses, naming the draft nobody noticed" {
	# Four attachments, three merged, one open draft — the exact payload behind
	# the Done at 07:17 that a human reversed at 07:52. This row is why the
	# incident cannot recur silently.
	run "$DONE" <<EOF
[{"id":"CLOUD-420",
  "attachments":[{"url":"$(pr_url 362)"},{"url":"$(pr_url 363)"},
                 {"url":"$(pr_url 366)"},{"url":"$(pr_url 368)"}],
  "pulls":[{"number":362,"state":"closed","merged":true,"draft":false},
           {"number":363,"state":"closed","merged":true,"draft":false},
           {"number":366,"state":"closed","merged":true,"draft":false},
           {"number":368,"state":"open","merged":false,"draft":true}]}]
EOF
	[ "$status" -eq 1 ]
	[[ "$output" == *"CLOUD-420 open-pr (#368, draft)"* ]]
}
