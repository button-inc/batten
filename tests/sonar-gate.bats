#!/usr/bin/env bats
# The external analyzer's verdict on a SHA (CLOUD-441), exercised through the
# injected reading so every case runs offline — no `gh`, no stub, no network.
#
# The name under test is injected too. Pinning the vendor string into every case
# would make a rename a diff across the whole file rather than one line in the
# task, and the task is where the name belongs.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/sonar-gate"
	export SHA=deadbeef
	export SONAR_CHECK_NAME="SonarCloud Code Analysis"
}

# TSV: status, conclusion, name, started_at, id — the shape `checks-green`
# already uses, so a caller holding one reading can feed either gate.
runs() { printf '%s\n' "$@"; }

@test "a green analysis passes" {
	SONAR_GATE_RUNS="$(runs "completed	success	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"green"* ]]
}

@test "a failed analysis is red, and named" {
	SONAR_GATE_RUNS="$(runs "completed	failure	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"SonarCloud Code Analysis is failure"* ]]
}

@test "a neutral conclusion passes — the analyzer graded and did not object" {
	SONAR_GATE_RUNS="$(runs "completed	neutral	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 0 ]
}

@test "timed_out is red like any other non-success conclusion" {
	SONAR_GATE_RUNS="$(runs "completed	timed_out	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 1 ]
}

@test "ABSENT IS NOT A VETO — an analyzer with no opinion cannot wedge a PR" {
	# The `zizmor` posture. An analyzer that declines to grade produces no
	# check-run at all, and failing on that would block every PR it skips.
	SONAR_GATE_RUNS="$(runs "completed	success	ci")" run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"absent is not a verdict"* ]]
}

@test "an empty reading is absent, and takes no network to say so" {
	SONAR_GATE_RUNS="" run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a pending analysis is not an answer" {
	SONAR_GATE_RUNS="$(runs "in_progress	-	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 3 ]
	[[ "$output" == *"not an answer yet"* ]]
}

@test "a skipped analysis is not an answer either" {
	# Distinct from absent: a run exists and carries no verdict, which is the
	# draft-era state a later push replaces.
	SONAR_GATE_RUNS="$(runs "completed	skipped	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 3 ]
}

@test "a cancelled analysis is not an answer either — it judged nothing" {
	# CLOUD-363, in the THIRD reader of check-run conclusions. This file's header
	# claims "same shape and same rules as checks-green, deliberately"; it carried
	# the pre-CLOUD-363 rank, so `cancelled` fell through to the catch-all and
	# reported red.
	#
	# Worse here than in the original defect: this gate runs inside `final`, and
	# `final` IS in the required roster while the analyzer deliberately is not. So
	# a cancelled analysis reds `final`, `checks-green` sees an independent
	# `final failure` with nothing in its no-verdict bucket, and the guard
	# CLOUD-363 added cannot fire on a run it cannot see — `land` re-drafts a
	# healthy PR.
	SONAR_GATE_RUNS="$(runs "completed	cancelled	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 3 ]
	[[ "$output" == *"cancelled"* ]]
	[[ "$output" != *"::error::"* ]]
}

@test "another check's failure is none of this gate's business" {
	# This gate judges exactly one name. `final`'s `needs:` assertion is what
	# judges our own jobs, and two authorities for one fact is the CLOUD-351
	# defect.
	SONAR_GATE_RUNS="$(runs \
		"completed	failure	ci" \
		"completed	success	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 0 ]
}

# --- one name, one answer: the latest run (CLOUD-436) ------------------------

@test "a skip superseded by a success passes — the residue does not veto" {
	SONAR_GATE_RUNS="$(runs \
		"completed	skipped	SonarCloud Code Analysis	2026-08-12T03:18:10Z	1" \
		"completed	success	SonarCloud Code Analysis	2026-08-12T03:20:16Z	2")" run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a success superseded by a FAILURE is red" {
	SONAR_GATE_RUNS="$(runs \
		"completed	success	SonarCloud Code Analysis	2026-08-12T03:00:00Z	1" \
		"completed	failure	SonarCloud Code Analysis	2026-08-12T03:05:00Z	2")" run "$GATE"
	[ "$status" -eq 1 ]
}

@test "a success superseded by a re-run in flight is not an answer yet" {
	SONAR_GATE_RUNS="$(runs \
		"completed	success	SonarCloud Code Analysis	2026-08-12T03:00:00Z	1" \
		"in_progress	-	SonarCloud Code Analysis	2026-08-12T03:05:00Z	2")" run "$GATE"
	[ "$status" -eq 3 ]
}

@test "the id breaks a tie between two runs started in the same second" {
	SONAR_GATE_RUNS="$(runs \
		"completed	success	SonarCloud Code Analysis	2026-08-12T03:00:00Z	10" \
		"completed	failure	SonarCloud Code Analysis	2026-08-12T03:00:00Z	11")" run "$GATE"
	[ "$status" -eq 1 ]
}

@test "a reading with no ordering key fails closed — the least conclusive wins" {
	# Two runs that cannot be ordered must never read greener than their union.
	SONAR_GATE_RUNS="$(runs \
		"completed	failure	SonarCloud Code Analysis" \
		"completed	success	SonarCloud Code Analysis")" run "$GATE"
	[ "$status" -eq 1 ]
}

# --- output contract ---------------------------------------------------------

@test "output is a pointer — a conclusion and a name, never the analysis" {
	SONAR_GATE_RUNS="$(runs "completed	failure	SonarCloud Code Analysis")" run "$GATE"
	[[ "$output" == *"failure	SonarCloud Code Analysis"* ]]
	# The finding itself lives on the check-run's details page. Nothing about
	# what the analyzer objected to may cross this channel (non-negotiable
	# rule 4).
	[[ "$output" != *"vulnerabilit"* ]]
	[[ "$output" != *"code smell"* ]]
}

@test "the verdict is byte-identical across two runs on identical input" {
	SONAR_GATE_RUNS="$(runs "completed	success	SonarCloud Code Analysis")" run "$GATE"
	first="$output"
	SONAR_GATE_RUNS="$(runs "completed	success	SonarCloud Code Analysis")" run "$GATE"
	[ "$output" = "$first" ]
}

# --- the fetch, and the one distinction that matters in it -------------------
#
# These are the only cases that exercise the network path, through a stub `gh`
# rather than a real one. They exist because a 404 and a dead network are the
# same exit code to a naive reader, and conflating them made `verify` fail on
# every rebase — measured on this change's own first landing lap.

stub_gh() {
	# $1 = exit code, $2 = stderr text
	cat >"$BATS_TEST_TMPDIR/gh" <<EOF
#!/usr/bin/env bash
echo "$2" >&2
exit $1
EOF
	chmod +x "$BATS_TEST_TMPDIR/gh"
	echo "$BATS_TEST_TMPDIR/gh"
}

@test "a SHA the remote has never seen is NO ANSWER YET, not a failed reading" {
	# The rebase case: `land` mints a new commit every lap and `verify` judges it
	# before the push. Exit 3 is what lets `verify` pass there; exit 2 failed it.
	gh="$(stub_gh 1 'gh: Not Found (HTTP 404)')"
	SONAR_GATE_GH="$gh" REPO=o/r run "$GATE"
	[ "$status" -eq 3 ]
	[[ "$output" == *"not pushed yet"* ]]
}

@test "any other fetch failure is COULD NOT LOOK — a reading we cannot take is not a pass" {
	gh="$(stub_gh 1 'gh: connection refused')"
	SONAR_GATE_GH="$gh" REPO=o/r run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"could not read the check-runs"* ]]
}

@test "an auth failure is could not look too, never a pass" {
	gh="$(stub_gh 1 'gh: Bad credentials (HTTP 401)')"
	SONAR_GATE_GH="$gh" REPO=o/r run "$GATE"
	[ "$status" -eq 2 ]
}

@test "a successful fetch returning nothing is absent — the SHA exists and has no analysis" {
	cat >"$BATS_TEST_TMPDIR/gh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
	chmod +x "$BATS_TEST_TMPDIR/gh"
	SONAR_GATE_GH="$BATS_TEST_TMPDIR/gh" REPO=o/r run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"absent is not a verdict"* ]]
}

@test "an AUTHENTICATED unpushed SHA is no answer yet — 422, not 404" {
	# The real signal, and the one the first fix missed. A private repo answers
	# 404 to a stranger and 422 to a member, so a classifier matching only 404
	# passes when run without a token and fails under `mise`, which supplies one.
	# Measured on f0f2b7b: `{"message":"No commit found for SHA: ...","status":"422"}`.
	gh="$(stub_gh 1 'gh: No commit found for SHA: f0f2b7b (HTTP 422)')"
	SONAR_GATE_GH="$gh" REPO=o/r run "$GATE"
	[ "$status" -eq 3 ]
	[[ "$output" == *"not pushed yet"* ]]
}

@test "a 422 that is NOT a missing commit stays could-not-look" {
	# The code alone does not mean "not pushed" — 422 is GitHub's generic
	# validation refusal. Matching the code without the message would read a real
	# API refusal as a benign local state.
	gh="$(stub_gh 1 'gh: Validation Failed (HTTP 422)')"
	SONAR_GATE_GH="$gh" REPO=o/r run "$GATE"
	[ "$status" -eq 2 ]
}
