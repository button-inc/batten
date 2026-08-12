#!/usr/bin/env bats
# The one definition of "is this SHA green" (CLOUD-346), exercised through the
# injected reading so every case runs offline — no `gh`, no stub, no network.
#
# $CI_REQUIRED_CHECKS is deliberately NOT set here. It arrives from mise.toml
# [env] via `mise run test:bats`, so these cases run against the real roster
# rather than a copy of it that could disagree with the one landing uses. The
# check names below are that roster's; `ci-local-parity` is what keeps it
# matching the workflows.

setup() {
	GREEN="$BATS_TEST_DIRNAME/../mise-tasks/checks-green"
	export SHA=deadbeef
}

# A reading is TSV: status, conclusion, name, started_at, id — the shape
# `ci-wait` already holds after its conditional poll, and the shape the task
# fetches for itself. The last two order a name's runs (CLOUD-436); the cases
# that predate them are deliberately left three-field, since answering a
# reading with no ordering key exactly as before is itself a property.
runs() { printf '%s\n' "$@"; }

@test "a graded, all-success required set is green" {
	CHECKS_GREEN_RUNS="$(runs "completed	success	ci")" run "$GREEN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"success"*"ci"* ]]
	[[ "$output" == *"every required check terminal and green"* ]]
}

@test "an all-skipped required set is not an answer" {
	# The draft-era runs look terminal and unfailed. Treating them as an answer
	# would clear a PR whose CI never ran — and with the release PR now a draft
	# by default, this is the state on every refresh, not a corner case.
	CHECKS_GREEN_RUNS="$(runs "completed	skipped	ci")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"required check(s) skipped"* ]]
	[[ "$output" == *"ci"* ]]
}

@test "third-party successes do not make a draft-era skip set an answer" {
	# The set that landed #261 (CLOUD-327): every check that judges this
	# repository is a draft-era `skipped`, and the two workflows that are not
	# draft-gated graded on their own.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	SonarCloud Code Analysis" \
		"completed	success	release-plz" \
		"completed	skipped	commit-lint" \
		"completed	skipped	cross" \
		"completed	skipped	ci" \
		"completed	skipped	final" \
		"completed	skipped	darwin-link (aarch64-apple-darwin)")" run "$GREEN"
	[ "$status" -eq 3 ]
}

@test "a required check still pending is not an answer" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	SonarCloud Code Analysis" \
		"in_progress	-	ci")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"still running"* ]]
}

@test "an empty reading is not an answer, and takes no network to say so" {
	# Explicitly empty means "this SHA carries no check-run yet" — a real state,
	# and one that must not fall through to a fetch.
	CHECKS_GREEN_RUNS="" run "$GREEN"
	[ "$status" -eq 3 ]
}

@test "a required check that failed is red, and named" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci" \
		"completed	failure	cross")" run "$GREEN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"not green"* ]]
	[[ "$output" == *"cross failure"* ]]
}

@test "a third-party check gets neither a vote nor a veto" {
	# Branch protection enforces the required set, so a failure outside it must
	# not hold `main`.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	failure	SonarCloud Code Analysis" \
		"completed	skipped	release-plz" \
		"completed	success	ci")" run "$GREEN"
	[ "$status" -eq 0 ]
}

@test "an absent path-filtered check is not a skipped one" {
	# `zizmor` produces no check-run at all on a PR touching no workflow.
	# Requiring every required name to be PRESENT would hang the ordinary PR.
	CHECKS_GREEN_RUNS="$(runs "completed	success	ci")" run "$GREEN"
	[ "$status" -eq 0 ]
}

@test "an unset required set is fatal rather than an empty one" {
	# An empty set makes every check unrequired, which is the false green this
	# task exists to stop — so it must not be reachable by forgetting a variable.
	CHECKS_GREEN_RUNS="$(runs "completed	skipped	ci")" run env -u CI_REQUIRED_CHECKS "$GREEN"
	[ "$status" -eq 2 ]
	[[ "$output" == *"CI_REQUIRED_CHECKS is unset"* ]]
}

# --- one name, one answer: the latest run (CLOUD-436) ------------------------
#
# A SHA accumulates a check-run per event, and a draft-created PR mints a whole
# skipped set from its `opened` event that never goes away. These cases fix
# which of a name's runs speaks for it.

@test "a skip superseded by a success is green — the residue does not veto the verdict" {
	# #342 and #345: readied without a push, the graded set landed beside the
	# draft-era skips on the same SHA, and the union read it as no answer. The
	# poll ran unbounded over a head whose every required check was green.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	skipped	ci	2026-08-12T03:18:10Z	93999182343" \
		"completed	success	ci	2026-08-12T03:20:16Z	93999484435")" run "$GREEN"
	[ "$status" -eq 0 ]
	[[ "$output" == *"every required check terminal and green"* ]]
	# The summary is the judged view, so it cannot contradict the verdict.
	[[ "$output" != *"skipped"* ]]
}

@test "a skip superseded by a FAILURE is red — the case that made this urgent" {
	# #343: the poll could not see a completed failure, so the red that
	# re-drafts the PR never fired and the lap spent its wait learning nothing.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	skipped	ci	2026-08-12T02:50:00Z	1" \
		"completed	failure	ci	2026-08-12T02:55:00Z	2")" run "$GREEN"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ci failure"* ]]
}

@test "a success superseded by a skip is NOT an answer — the draft economy survives" {
	# The other direction, and the reason this is latest-per-name rather than
	# best-per-name: re-drafting a PR mints a fresh skip, and that skip is the
	# current state of the name. Answering green from a superseded success is
	# exactly the false green CLOUD-247/327 exist to stop.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci	2026-08-12T01:00:00Z	1" \
		"completed	skipped	ci	2026-08-12T02:00:00Z	2")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"required check(s) skipped"* ]]
}

@test "the id breaks a tie between two runs started in the same second" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci	2026-08-12T03:00:00Z	10" \
		"completed	skipped	ci	2026-08-12T03:00:00Z	11")" run "$GREEN"
	[ "$status" -eq 3 ]
}

@test "a pending re-run supersedes a completed one — the answer is not in yet" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	success	ci	2026-08-12T03:00:00Z	1" \
		"in_progress	-	ci	2026-08-12T03:05:00Z	2")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"still running"* ]]
}

@test "each name is judged on its own latest, never one name's run against another's" {
	CHECKS_GREEN_RUNS="$(runs \
		"completed	skipped	ci	2026-08-12T03:00:00Z	1" \
		"completed	success	ci	2026-08-12T03:10:00Z	2" \
		"completed	success	cross	2026-08-12T03:01:00Z	3" \
		"completed	skipped	commit-lint	2026-08-12T03:11:00Z	4")" run "$GREEN"
	[ "$status" -eq 3 ]
	[[ "$output" == *"commit-lint"* ]]
	[[ "$output" != *"skipped: ci"* ]]
}

@test "a reading with no ordering key answers as the union did — fail closed" {
	# The legacy three-field shape. Two runs of one name cannot be ordered, so
	# the least conclusive wins: this must never become green by accident.
	CHECKS_GREEN_RUNS="$(runs \
		"completed	skipped	ci" \
		"completed	success	ci")" run "$GREEN"
	[ "$status" -eq 3 ]
}
