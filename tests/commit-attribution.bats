#!/usr/bin/env bats
# subject: hk.pkl mise.toml
# The WIRING of the attribution gate (CLOUD-274). The predicate itself is tested
# in Rust over the compiled binary (`crates/batten/tests/attribution.rs`); this
# suite asserts only that something actually invokes it, and that the policy is
# data rather than code.
#
# Why the wiring needs its own assertions: CLOUD-435 removed six `PreToolUse`
# guards from `.claude/settings.json` and **every one of their suites stayed
# green**, because each drove its task by path and read no settings file. Before
# that, CLOUD-216 found `attribution-check` fully implemented, fully tested, and
# wired to nothing. A gate's suite that never asserts its call site measures only
# itself.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

@test "the commit-time seam is wired: hk.pkl's commit-msg hook runs the gate" {
	# Asserted on the step block rather than a bare grep: the surrounding comment
	# names the task too, and a comment is not a call site.
	run awk '/^      \["commit-attribution"\] \{$/ { found = 1; next }
	         found && /mise run commit-attribution-msg/ { print "wired"; exit }
	         found && /^      \}$/ { exit }' hk.pkl
	[ "$status" -eq 0 ]
	[ "$output" = "wired" ]
}

@test "the range seam is wired: commit-lint depends on the gate" {
	# This dependency is what gives the gate both seams — `verify` and CI's
	# commit-lint job each already run `mise run commit-lint` with BASE_SHA and
	# HEAD_SHA exported — without adding a task name to a workflow, which
	# `ci-local-parity` would then require `verify` to run too.
	run awk '/^\[tasks\.commit-lint\]$/ { found = 1; next }
	         found && /^depends = .*commit-attribution/ { print "wired"; exit }
	         found && /^\[/ { exit }' mise.toml
	[ "$status" -eq 0 ]
	[ "$output" = "wired" ]
}

@test "the fixer is wired: session-start runs it, so a clone is compliant before it commits" {
	run grep -c 'step attribution-identity mise run attribution-identity' .claude/hooks/session-start.sh
	[ "$output" = "1" ]
}

@test "both tasks resolve to the engine, not to a second implementation" {
	# The policy has exactly one evaluator. A shell task that re-implemented any
	# part of the predicate would be the second authority this issue moved the
	# rule into `batten.toml` to avoid.
	for task in commit-attribution commit-attribution-msg attribution-identity; do
		run awk -v task="[tasks.$task]" '$0 == task { found = 1; next }
		         found && /^run = .*batten -- attribution/ { print "engine"; exit }
		         found && /^\[/ { exit }' mise.toml
		[ "$status" -eq 0 ]
		[ "$output" = "engine" ]
	done
}

@test "the policy is data: no configured pattern appears anywhere under crates/" {
	# CLOUD-274's third acceptance bullet, and non-negotiable rule 1 extended from
	# consumers to vendors.
	#
	# THE PREDICATE IS THE CONFIGURED PATTERNS, NOT THE VENDOR'S NAME, and the
	# difference is load-bearing. `crates/batten/src/hook.rs` names `claude-code`
	# across ten files as a HARNESS IDENTIFIER — the host x capability table
	# CLOUD-45 built, where naming a supported host is how the engine addresses
	# it. That is a coordinate, the same exemption `attribution-check` draws for a
	# tool pin, and a bare name grep would fail on it forever and get this gate
	# switched off. What rule 1 forbids is an attribution POLICY literal compiled
	# in; that is what these patterns are.
	local pattern
	while IFS= read -r pattern; do
		[ -n "$pattern" ] || continue
		run git grep -nE -- "$pattern" -- crates/
		[ "$status" -ne 0 ]
		[ -z "$output" ]
	done < <(
		taplo get -f batten.toml 'attribution.identity_deny'
		taplo get -f batten.toml 'attribution.trailer_deny'
		taplo get -f batten.toml 'attribution.body_deny'
	)
}

@test "the accountable identity is config too, and not compiled in" {
	local name
	name=$(taplo get -f batten.toml 'attribution.identity.name')
	[ -n "$name" ]
	run git grep -Fn -- "$name" -- crates/
	[ "$status" -ne 0 ]
}

@test "this repo's posture is silent: the allow-set is empty" {
	# The decision record's §2.2 chose silent-with-records for Button repos, and
	# the emptiness of this list IS that decision — not an unfinished config. A
	# change here is a change of posture and should fail this case, loudly.
	run taplo get -f batten.toml 'attribution.trailer_allow'
	[ "$status" -eq 0 ]
	[ -z "$(printf '%s' "$output" | tr -d '[:space:]')" ]
}
