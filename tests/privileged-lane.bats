#!/usr/bin/env bats
# subject: policy/privileged-lane.rego
#
# The negative-control suite for the tree-scoped privileged-lane gate (CLOUD-931).
#
# WHY THIS EXISTS AT ALL. `policy/privileged-lane.rego` is a live `deny` row over
# this repository's own privileged CI lanes, and until this file it had no test
# outside itself: no bats suite, no Rust test, and an entry in no mutation set.
# Its nine `test_` rules are `with input as` assertions, and CLOUD-845 established
# that those are insufficient evidence on their own — a module can fabricate a
# shape the engine never produces, pass its own suite green, and gate nothing.
#
# So every case here goes in through `batten check`, the same door `verify` and
# the hk gate come through, and reads the verdict a caller would read. The two
# tiers are complementary rather than redundant: the module's own rules pin the
# PREDICATE, this file pins that the ENGINE builds the input the predicate reads.
#
# The case that only this tier can make is `an_unparseable_workflow_denies`.
# `input.tree.missing` is populated by the engine when a declared source will not
# parse; a `with input as` test hands itself that key and proves nothing about
# whether anything ever fills it.
#
# The fixture is a throwaway git repository carrying ONE row and a copy of the
# module under test, so the predicate is exercised in isolation from this
# repository's other rules, and `mise run mutant` reaches it: the copy is taken
# from the suite's own tree, which under `mutant` is the mutated one.

setup() {
	load helpers

	# The same resolution chain `tests/run-shape.bats` uses, and for the reason
	# measured there: there is no release build when `test:bats` runs in CI, and a
	# shorter chain aborts setup before the skip can fire — turning "no binary
	# here" into a wall of red over a gate that was never exercised.
	BIN=""
	for candidate in \
		"${BATTEN_BIN:-}" \
		"$BATS_TEST_DIRNAME/../target/release/batten" \
		"$BATS_TEST_DIRNAME/../target/debug/batten"; do
		[ -n "$candidate" ] && [ -x "$candidate" ] || continue
		BIN="$candidate"
		break
	done
	[ -n "$BIN" ] || BIN="$(command -v batten || true)"
	[ -n "$BIN" ] || skip "no batten binary to drive"

	MODULE="$BATS_TEST_DIRNAME/../policy/privileged-lane.rego"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/policy" "$REPO/.github/workflows"
	cp "$MODULE" "$REPO/policy/privileged-lane.rego"
	{
		echo "version = 1"
		echo
		echo "[[rule]]"
		echo 'id = "privileged-lane-tests-origin"'
		echo 'kind = "policy"'
		echo 'scope = "tree"'
		echo 'sources = [".github/workflows/*.yml"]'
		echo 'module = "policy/privileged-lane.rego"'
		echo 'severity = "deny"'
	} >"$REPO/batten.toml"
	# No global or system config: a contributor's own git settings must not be able
	# to change a verdict here (CLOUD-282).
	GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main "$REPO"
}

# Write one workflow into the fixture. Each case supplies its own, so a case
# names exactly the shape it is about.
workflow() { # workflow <name> <body>
	printf '%s\n' "$2" >"$REPO/.github/workflows/$1"
}

check() {
	(cd "$REPO" && "$BIN" check)
}

# The exit contract, asserted by NAME rather than by integer (`.claude/rules/rust.md`):
# 2 is the policy verdict, 0 is clean. The shell tasks' inverted convention must
# not be carried in — a case asserting 1 here would be asserting "unreadable
# input" while meaning "violation", and it would pass.
assert_denied() {
	[ "$status" -eq 2 ] || {
		echo "expected the policy verdict (2), got $status: $output" >&2
		return 1
	}
	[[ "$output" == *privileged-lane-tests-origin* ]] || {
		echo "the finding does not name the rule: $output" >&2
		return 1
	}
}

assert_clean() {
	[ "$status" -eq 0 ] || {
		echo "expected a clean tree (0), got $status: $output" >&2
		return 1
	}
}

@test "a bot lane selecting by branch prefix is denied" {
	# The defect CLOUD-867 was filed for: the head is chosen by a string the PR
	# author picks. Driven through the engine rather than through `policy test`.
	workflow auto-bot-land.yml 'on:
  workflow_run:
    workflows: [ci]
jobs:
  land:
    permissions:
      contents: write
    if: startsWith(github.event.workflow_run.head_branch, ${{ '"'"'renovate/'"'"' }})
    steps:
      - run: echo land'
	run check
	assert_denied
}

@test "the same lane testing the head origin is clean" {
	# The discriminating half. Same trigger, same grant, same job — only the origin
	# test is added, so a gate that denied both would be proving nothing.
	workflow auto-bot-land.yml 'on:
  workflow_run:
    workflows: [ci]
jobs:
  land:
    permissions:
      contents: write
    if: github.event.workflow_run.head_repository.full_name == github.repository
    steps:
      - run: echo land'
	run check
	assert_clean
}

@test "a scheduled writer that resolves no outside head is not a subject" {
	# THE FALSE POSITIVE THE THIRD CONJUNCT EXISTS FOR, and the mutation this
	# suite declares is aimed at exactly it: `perf.yml` is scheduled, holds
	# contents:write to push its own series, and selects no outside head. A gate
	# whose first firing is a false positive gets an exception written for it, and
	# the exception is what rots.
	workflow perf.yml 'on:
  schedule:
    - cron: "0 0 * * *"
  workflow_dispatch:
jobs:
  measure:
    permissions:
      contents: write
    steps:
      - run: git push origin refs/notes/perf'
	run check
	assert_clean
}

@test "an outsider-reachable writer that resolves no outside head is not a subject" {
	# THE CASE THAT ACTUALLY DISCRIMINATES THE THIRD CONJUNCT, and it exists
	# because the module's own stated rationale for that conjunct is wrong.
	#
	# `privileged-lane.rego` says: "Drop the third and `perf.yml` is a finding: it
	# is scheduled, it holds `contents: write`, and it resolves no outside head at
	# all." Measured — the real `perf.yml` triggers are `schedule` and
	# `workflow_dispatch`, and NEITHER is in `outsider_reachable`'s list. So
	# `perf.yml` is excluded by the FIRST conjunct and dropping the third changes
	# nothing about it. The module's `test_a_scheduled_writer_with_no_outside_head_is_not_a_subject`
	# has the same hole: its input is not outsider-reachable either, so it passes
	# with the third conjunct deleted.
	#
	# This is what a discriminating input looks like: outsider-reachable
	# (`issue_comment`), holds `contents: write`, and resolves no outside head —
	# no `pull_request`/`workflow_run` trigger and no `/pulls` anywhere. Clean
	# today; a finding the moment the third conjunct stops being asked. That is
	# what makes it the case the declared mutation names.
	workflow triage.yml 'on:
  issue_comment:
    types: [created]
jobs:
  label:
    permissions:
      contents: write
    steps:
      - run: echo "labelling from a comment"'
	run check
	assert_clean
}

@test "a read-only lane is not a subject" {
	workflow ci.yml 'on:
  pull_request:
jobs:
  gate:
    permissions:
      contents: read
    steps:
      - run: echo test'
	run check
	assert_clean
}

# THE CASE THIS SUITE DELIBERATELY DOES NOT CARRY, and the reason is a finding
# rather than an omission (CLOUD-1049).
#
# The module's first clause says an unparseable workflow lands in
# `input.tree.missing` and denies, so that "could not read it" never reads as
# "clean". Written as a case here, that is RED: a genuinely invalid workflow —
# `yaml.safe_load` raises `ParserError` on it — produces exit 0, no finding, and
# no cause, even under `--strictness strict`. The same fixture with a parseable
# workflow that fails the predicate denies at 2, so the row is live and selected;
# it is the unparseable path specifically that vanishes.
#
# It is not shipped red, and it is not shipped asserting the current behaviour
# either — that would bake the defect in as the contract and go green forever.
# CLOUD-1049 owns it and names this file as where the case belongs once the
# engine honours what the module already documents.
#
# This is also the clearest evidence for why this tier exists at all: the
# module's own `test_an_unparseable_workflow_denies_rather_than_passing` is
# GREEN, because `with input as` hands itself the populated `missing` the engine
# never builds (CLOUD-845).
