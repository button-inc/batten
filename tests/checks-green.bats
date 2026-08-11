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

# A reading is TSV: status, conclusion, name — the shape `ci-wait` already holds
# after its conditional poll, and the shape the task fetches for itself.
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
