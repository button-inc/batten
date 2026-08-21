#!/usr/bin/env bats
# subject: hk.pkl
# CLOUD-224. Which steps a change SELECTS, asserted as data.
#
# `batten-check` and `macos-link-check` carried no glob, so they ran on every
# commit whatever it touched — and `batten-check` is `cargo run`, so a docs-only
# commit paid a debug build (9.47s cold, 133-141ms warm). Giving them a glob is
# the fix; the risk a glob introduces is the opposite failure, a step that
# silently stops running for a change it should judge.
#
# `hk check --plan` prints the plan WITHOUT running a step, so selection is
# readable as JSON rather than inferred from a timing — which is the only form
# the negative case can be asserted in at all. A timing proves nothing: a step
# can be fast because it was skipped or because its inputs were cached, and
# those are the two cases that must not be confused.
#
# These run against the repository's own hk.pkl, which is the artifact under
# test. Nothing here executes a gate.

setup() {
	REPO="$BATS_TEST_DIRNAME/.."
	PLAN="$BATS_TEST_TMPDIR/plan.json"
}

# The status hk assigns one step for a change touching exactly these files.
# `--plan` runs nothing, so this is free and has no side effect on the tree.
status_of() {
	local step=$1
	shift
	# hk has no --cd, and it resolves hk.pkl from the working directory, so the
	# subshell is what pins which config is under test rather than whatever
	# directory bats happened to start in.
	(cd "$REPO" && hk check --plan --json "$@") >"$PLAN" 2>/dev/null
	jq -r --arg s "$step" '.steps[] | select(.name == $s) | .status' <"$PLAN"
}

# --- batten-check: the expensive one --------------------------------------

@test "every path selects batten-check once a rule globs the whole tree" {
	# SUPERSEDES "a Markdown file that is not an input does not select
	# batten-check", which asserted `skipped` for README.md on the premise that
	# it "carries no rule glob and is in no budget". CLOUD-59's `no-secrets` row
	# globs `**`, so that premise is simply false now: a credential can be in
	# README.md, and narrowing the rule would be choosing which files are
	# allowed to carry one.
	#
	# The case is kept rather than deleted, inverted rather than weakened,
	# because the property it guards is still worth pinning — it just moved. The
	# question is no longer "does the glob exclude this path" but "is the glob
	# still total", and a narrowing that reintroduced a skip would fail here.
	#
	# What kept CLOUD-224's economy is now the TIER, not the glob:
	# `batten-check` is `slow`-profile, so a docs-only commit still pays nothing
	# locally. `hook-profile-check` is the gate on that, and it is what would go
	# red if the tier were removed.
	[ "$(status_of batten-check README.md)" = "included" ]
}

@test "AGENTS.md DOES select batten-check — a budget file is an input" {
	# The trap in the obvious reading of "a Markdown-only change cannot change
	# this verdict". `[budget.instructions] files = ["AGENTS.md"]`, and a declared
	# budget is a gate under `check`, not only under `policy budget` (CLOUD-50).
	# Globbing this step on non-Markdown alone would have switched the gate off
	# for the most-edited Markdown file in the repo.
	[ "$(status_of batten-check AGENTS.md)" = "included" ]
}

@test "the engine selects batten-check" {
	[ "$(status_of batten-check crates/batten/src/lib.rs)" = "included" ]
}

@test "the config authority selects batten-check" {
	[ "$(status_of batten-check batten.toml)" = "included" ]
}

@test "a dependency change selects batten-check" {
	# The pairing `cargo run` exists to judge: the gate runs the working tree's
	# engine, so a change to what that engine is built from must run it. A glob
	# tight enough to skip here is the false green the gate model exists for.
	[ "$(status_of batten-check Cargo.lock)" = "included" ]
	[ "$(status_of batten-check Cargo.toml)" = "included" ]
}

@test "every non-crates path a batten.toml rule globs selects batten-check" {
	# mise.toml (no-source-built-tool), workflows (no-cargo-install-in-ci),
	# tests/*.bats (bats-tests-not-deleted). These are the ones the issue's
	# proposed glob would have dropped.
	[ "$(status_of batten-check mise.toml)" = "included" ]
	[ "$(status_of batten-check .github/workflows/ci.yml)" = "included" ]
	[ "$(status_of batten-check tests/lock-complete.bats)" = "included" ]
}

@test "the embedded budget path selects batten-check" {
	[ "$(status_of batten-check .serena/project.yml)" = "included" ]
}

# --- macos-link-check: globbed on the manifests ----------------------------

@test "a manifest change selects macos-link-check, a doc change does not" {
	# Its predicate is `cargo metadata --filter-platform` over the resolved
	# graph, so the manifests are exactly its inputs.
	[ "$(status_of macos-link-check Cargo.lock)" = "included" ]
	[ "$(status_of macos-link-check README.md)" = "skipped" ]
}

# --- no-docs-tree: deliberately still unconditional ------------------------

# --- the two tiers: profile-based selection (CLOUD-509) --------------------

# The status hk assigns one step for a whole-tree run at a given profile. This
# is the profile axis, where `status_of` above is the changed-files axis — a
# step can be selected by its glob and still excluded by its profile, and the
# split is only correct if both are asserted.
status_at_profile() {
	local step=$1 profile=$2
	(cd "$REPO" && hk check --all --plan --json --profile "$profile") >"$PLAN" 2>/dev/null
	jq -r --arg s "$step" '.steps[] | select(.name == $s) | .status' <"$PLAN"
}

status_default() {
	local step=$1
	(cd "$REPO" && hk check --all --plan --json) >"$PLAN" 2>/dev/null
	jq -r --arg s "$step" '.steps[] | select(.name == $s) | .status' <"$PLAN"
}

@test "every slow-tier step is skipped when the profile is off" {
	# The pre-commit economy. `.claude/hooks/git-hook` passes exactly this flag,
	# so this is the selection a commit actually gets.
	for step in cargo-clippy test test:bats batten-check token-bench-check sbom-check; do
		[ "$(status_at_profile "$step" '!slow')" = "skipped" ]
	done
}

@test "every slow-tier step still runs under check, which is what CI drives" {
	# THE ONE THAT MATTERS. `mise run ci` -> `hk check --all` uses this mapping,
	# so a step missing here is a step CI has silently stopped running — the
	# false green the whole split has to be incapable of.
	for step in cargo-clippy test test:bats batten-check token-bench-check sbom-check; do
		[ "$(status_default "$step")" = "included" ]
	done
}

@test "an unprofiled step is selected in both tiers" {
	# The control. Without this, a run that excluded EVERYTHING would satisfy the
	# skipped-assertion above and look like a working split.
	[ "$(status_at_profile no-docs-tree '!slow')" = "included" ]
	[ "$(status_default no-docs-tree)" = "included" ]
}

@test "the profile skip is reported as profile_exclude, not as a filter miss" {
	# The two are different failures and only one is intended: `filter_match`
	# would mean the step's glob stopped matching, which is a selection bug
	# wearing the same status. The JSON kind is snake_case `profile_exclude` —
	# NOT the kebab-case `profile-not-enabled` that names the same condition in
	# hk's `display_skip_reasons` setting.
	(cd "$REPO" && hk check --all --plan --json --profile '!slow') >"$PLAN" 2>/dev/null
	run jq -r '.steps[] | select(.name == "test:bats") | .reasons[] | .kind' "$PLAN"
	[[ "$output" == *"profile_exclude"* ]]
}

@test "no-docs-tree keeps no glob, so it runs on a change it does not read" {
	# Not an oversight and not a candidate for the same treatment: its input is
	# the whole INDEX — any tracked docs/ path, including one an earlier commit
	# left behind — so a glob would let a violation persist unreported on every
	# commit that did not touch it. ~95ms is what makes that affordable.
	[ "$(status_of no-docs-tree README.md)" = "included" ]
}
