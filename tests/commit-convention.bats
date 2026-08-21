#!/usr/bin/env bats
# subject: batten.toml mise.toml
# The WIRING of the commit-subject gate (CLOUD-701). The predicate is tested in
# Rust over the compiled binary (`crates/batten/tests/commit.rs`); this suite
# asserts only that something invokes it, and that the pattern moved rather than
# being copied.
#
# Why the wiring needs its own assertions: CLOUD-435 removed six `PreToolUse`
# guards and every one of their suites stayed green, because each drove its task
# by path and read no settings file. Before that, CLOUD-216 found a task fully
# implemented, fully tested, and wired to nothing.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

@test "the variable is gone: no CONVENTIONAL_RE survives in mise.toml" {
	# THE ASSERTION THAT KEEPS THIS DONE. A cleanup with no gate is one refactor
	# from being undone, and the failure would be silent — a re-added variable
	# read by a re-added grep passes every other check in this repo.
	run grep -c 'CONVENTIONAL_RE' mise.toml
	[ "$output" = "0" ]
}

@test "the pattern lives in batten.toml, and exactly once" {
	run bash -c "grep -c '^subject_pattern = ' batten.toml"
	[ "$output" = "1" ]
}

@test "the range seam is wired: commit-lint depends on the gate" {
	# This dependency is what gives the gate both seams — `verify` and CI's
	# commit-lint job each already run `mise run commit-lint` with BASE_SHA and
	# HEAD_SHA exported — without adding a task name to a workflow, which
	# `ci-local-parity` would then require `verify` to run too.
	run awk '/^\[tasks\.commit-lint\]$/ { found = 1; next }
	         found && /^depends = .*commit-check/ { print "wired"; exit }
	         found && /^\[/ { exit }' mise.toml
	[ "$status" -eq 0 ]
	[ "$output" = "wired" ]
}

@test "the commit-time seam is wired: hk.pkl's commit-msg hook runs commit-msg" {
	run awk '/^      \["conventional-commit"\] \{$/ { found = 1; next }
	         found && /mise run commit-msg/ { print "wired"; exit }
	         found && /^      \}$/ { exit }' hk.pkl
	[ "$status" -eq 0 ]
	[ "$output" = "wired" ]
}

@test "both tasks resolve to the engine, not to a second implementation" {
	# The convention has exactly one evaluator. A shell task re-implementing the
	# match would be the second authority this issue moved the pattern to
	# batten.toml to avoid — and it is how the variable got there originally.
	for task in commit-check commit-msg; do
		run awk -v task="[tasks.$task]" '$0 == task { found = 1; next }
		         found && /^run = .*batten -- commit check/ { print "engine"; exit }
		         found && /^\[/ { exit }' mise.toml
		[ "$status" -eq 0 ]
		[ "$output" = "engine" ]
	done
}

@test "no task greps a subject pattern of its own" {
	# The shape that would reintroduce the defect without naming the variable:
	# a task inlining the regex rather than reading the config.
	run grep -rlE "grep -Eq .*(feat\|fix|fix\|feat)" mise.toml mise-tasks/
	[ "$status" -ne 0 ]
	[ -z "$output" ]
}

@test "this repo's own history satisfies its committed convention" {
	# Consumer #1, end to end: the pattern in batten.toml is the one this
	# repository's commits actually follow, so the move changed where the rule
	# lives and not which commits it admits.
	local base
	base=$(git rev-parse HEAD~1 2>/dev/null) || skip "no parent commit to range over"
	run env BASE_SHA="$base" HEAD_SHA="$(git rev-parse HEAD)" \
		cargo run --quiet -p batten -- commit check "$base..$(git rev-parse HEAD)"
	[ "$status" -eq 0 ]
}
