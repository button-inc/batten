#!/usr/bin/env bats
# The landing-path/clock split for zizmor (CLOUD-410), asserted over the task
# definitions themselves.
#
# There is no script here to test — zizmor is a pinned tool and the whole change
# is WHICH INVOCATION runs WHERE. That is exactly the part that reverts silently:
# dropping `--offline` restores a green-looking gate whose verdict depends on
# api.github.com, and nothing else in the tree would notice until a rate limit
# stopped a landing again. So the split is pinned as text, the same way
# `hk-version` and `mise-pin-agreement` pin agreements no runtime check reaches.
#
# The measurement behind it: two laps of one `land` run over an unchanged tree —
# `No findings to report`, then `403 Forbidden` on
# `/advisories?affects=actions%2Fcheckout%40v7.0.1`, reported to the operator as
# "verify failed … reproduce and fix locally".
#
# The landing-path task is receipt-gated (CLOUD-424) and so carries a multi-line
# body, while the scheduled one is a bare invocation. Both readers below extract
# the `zizmor` INVOCATION rather than the body, so a later change to the receipt
# wrapper cannot break these cases and, more importantly, cannot hide the flag
# they exist to watch.

setup() {
	MANIFEST="$BATS_TEST_DIRNAME/../mise.toml"
	# The zizmor invocation inside a named task block, whether the body is an
	# inline scalar or a `'''` block.
	zizmor_invocation() {
		awk -v want="[tasks.$1]" '
			$0 == want { intask = 1; next }
			intask && /^\[/ { exit }
			# Comments in these blocks discuss the flag at length, and matching
			# one would make every case below pass on prose alone — the vacuous
			# read this suite exists to prevent.
			/^[[:space:]]*#/ { next }
			intask && /zizmor[[:space:]]+--/ {
				sub(/^[[:space:]]*/, "")
				sub(/^run = /, "")
				sub(/^if ! /, "")
				gsub(/"/, "")
				sub(/;.*$/, "")
				sub(/[[:space:]]*$/, "")
				print
				exit
			}
		' "$MANIFEST"
	}
	# `verify:gated`, not `verify` — CLOUD-407 moved the gate set there when
	# `verify` became a dependency-free mapper over the exit-code contract. The
	# property this suite asserts is unchanged and so is where it is decided: the
	# dependency closure of `mise run verify` is what drags a task onto the
	# landing path, and `verify:gated` is now the link that carries it.
	verify_depends() {
		awk '/^\[tasks\."verify:gated"\]/ { intask = 1; next }
		     intask && /^\[/ { exit }
		     intask && /^depends = / { print; exit }' "$MANIFEST"
	}
}

@test "the landing-path invocation is offline" {
	# The property. A gate on the landing path decides a question about THIS
	# COMMIT, and whether an action has an advisory today is not one.
	run zizmor_invocation zizmor
	[ "$status" -eq 0 ]
	[[ "$output" == *"zizmor "* ]]
	[[ "$output" == *"--offline"* ]]
}

@test "the scheduled invocation is not offline, or it would check nothing" {
	# The mirror. An advisory sweep that cannot reach the network answers
	# nothing while reporting success — the vacuous pass this repo keeps
	# paying for.
	run zizmor_invocation zizmor-advisories
	[ "$status" -eq 0 ]
	[[ "$output" == *"zizmor "* ]]
	[[ "$output" != *"--offline"* ]]
}

@test "the two audit the same targets at the same severity" {
	# Only the network reach may differ. A split that also narrowed the target
	# set or relaxed the severity would be a coverage cut wearing a bug fix's
	# clothes.
	local on off
	off=$(zizmor_invocation zizmor)
	on=$(zizmor_invocation zizmor-advisories)
	[ -n "$off" ]
	[ -n "$on" ]
	[[ "${off/--offline /}" == "$on" ]]
}

@test "verify depends on the offline one and never on the scheduled one" {
	# `ci-local-parity` requires every task CI runs to be one `verify` runs, so
	# adding the online audit to `verify` would drag it back onto the landing
	# path through CI — the coupling this split exists to remove.
	run verify_depends
	[ "$status" -eq 0 ]
	[[ "$output" == *'"zizmor"'* ]]
	[[ "$output" != *"zizmor-advisories"* ]]
}
