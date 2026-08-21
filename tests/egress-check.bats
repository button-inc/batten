#!/usr/bin/env bats
# subject: mise-tasks/egress-check
# The pure decision behind the container preflight (CLOUD-261): given the ambient
# proxy environment, can mise's own release resolver reach api.github.com?
#
# Both inputs are ARGUMENTS, never reads of the live environment, which is the
# whole reason this is a separate program — the combinations that matter cannot
# be produced by running the suite on any one machine. Same split as
# doctor-check, and the same payoff: the verdict is testable without a proxy.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/egress-check"
}

@test "the check is executable" {
	[ -x "$CHECK" ]
}

@test "no proxy is ok — the ordinary machine has nothing to fence" {
	run "$CHECK" "" ""
	[ "$status" -eq 0 ]
	[ "$output" = ok ]
}

@test "no proxy is ok even with an unrelated NO_PROXY" {
	# NO_PROXY carrying other hosts says nothing when no proxy is in play; a
	# verdict of unfenced here would fire on every developer machine that has
	# ever exported it.
	run "$CHECK" "" "localhost,127.0.0.1,.internal"
	[ "$status" -eq 0 ]
	[ "$output" = ok ]
}

@test "a proxy with api.github.com fenced is ok" {
	run "$CHECK" "http://proxy:8080" "api.github.com,objects.githubusercontent.com"
	[ "$status" -eq 0 ]
	[ "$output" = ok ]
}

@test "a proxy without the fence is unfenced — the measured broken container" {
	# The exact shape that made `mise install` die naming cargo-zigbuild.
	run "$CHECK" "http://proxy:8080" "localhost,127.0.0.1"
	[ "$status" -eq 0 ]
	[ "$output" = unfenced ]
}

@test "a proxy with an empty NO_PROXY is unfenced" {
	run "$CHECK" "http://proxy:8080" ""
	[ "$status" -eq 0 ]
	[ "$output" = unfenced ]
}

@test "wildcard and dot-prefixed NO_PROXY forms are honoured" {
	# NO_PROXY has no single normative syntax; entries appear bare, dot-prefixed
	# and wildcard-prefixed across tools. A false "ok" hides the diagnosis a
	# session needs, a false "unfenced" only asks a human to look — so the match
	# is deliberately generous in the direction that costs least.
	run "$CHECK" "http://proxy:8080" "*.api.github.com"
	[ "$output" = ok ]
	run "$CHECK" "http://proxy:8080" ".api.github.com"
	[ "$output" = ok ]
}

@test "a malformed call is exit 2, distinct from any verdict" {
	# 2 is "I could not read the input", never "the environment is bad" — a
	# caller passing the wrong thing must not look like a broken container.
	run "$CHECK"
	[ "$status" -eq 2 ]
	run "$CHECK" only-one
	[ "$status" -eq 2 ]
	run "$CHECK" a b c
	[ "$status" -eq 2 ]
}

@test "it never reads the live environment" {
	# The property that keeps it testable: an ambient proxy must not leak into a
	# verdict about the arguments. Called with the "no proxy" pair while the
	# environment says otherwise, it must still answer ok.
	run env HTTPS_PROXY=http://proxy:8080 NO_PROXY="" "$CHECK" "" ""
	[ "$output" = ok ]
}

@test "it makes no network call" {
	# A preflight that hangs is worse than the failure it detects, so the
	# decision half must be pure. No probing binary is referenced at all.
	run bash -c "grep -vE '^[[:space:]]*#' '$CHECK' | grep -cE 'curl|wget|gh |ping' || true"
	[ "$output" -eq 0 ]
}
