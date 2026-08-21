#!/usr/bin/env bats
# subject: mise-tasks/hook-profile-check
# CLOUD-509. The decision table for `hook-profile-check`.
#
# The gate reads two `hk check --plan --json` documents — the full plan and the
# one the pre-commit hook gets — and judges the relationship between them. Past
# the argument handling it is a pure function of those two documents, so every
# case here supplies them as fixtures and `hk` is never invoked. That is what
# makes the failing cases expressible at all: there is no way to ask a real hk
# for a plan in which the slow tier has silently vanished from `check`.
#
# One case (the last) does run against the repository's own config, because the
# claim "this repo is correctly wired today" is the one thing a fixture cannot
# make checkable.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/hook-profile-check"
	FULL="$BATS_TEST_TMPDIR/full.json"
	FAST="$BATS_TEST_TMPDIR/fast.json"
}

# A plan document from a list of `name@status[@reasonkind]` specs. Written as a
# builder rather than as inline heredocs so a case reads as its decision table
# row and not as JSON.
#
# `@` and not `:` as the separator: real step names contain colons (`test:bats`
# is the pole of the whole gate), and a `:`-split builder silently parsed that
# name as `test` with status `bats` — four cases passing over a step that did
# not exist. The separator has to be a character the keys cannot contain.
plan_with() {
	local dest=$1
	shift
	local steps="" spec name status kind
	for spec in "$@"; do
		name=${spec%%@*}
		status=${spec#*@}
		kind=""
		if [[ "$status" == *@* ]]; then
			kind=${status#*@}
			status=${status%%@*}
		fi
		[ -z "$steps" ] || steps+=","
		steps+="{\"name\":\"$name\",\"status\":\"$status\",\"reasons\":[{\"kind\":\"${kind:-filter_match}\",\"detail\":\"x\"}]}"
	done
	printf '{"hook":"check","runType":"check","steps":[%s]}\n' "$steps" >"$dest"
}

# --- the happy path ---------------------------------------------------------

@test "a correctly wired split passes" {
	plan_with "$FULL" test:bats@included cargo-clippy@included no-docs-tree@included
	plan_with "$FAST" test:bats@skipped@profile_exclude cargo-clippy@skipped@profile_exclude no-docs-tree@included
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 0 ]
	[[ "$output" == *"2 step(s) in the slow tier"* ]]
}

# --- the false green this gate exists for -----------------------------------

@test "a slow step missing from the check plan is a violation" {
	# THE ONE THAT MATTERS. This is what deleting the config-level `profiles`
	# line produces: the tier is still declared, so it is skipped at pre-commit,
	# but `check` — and therefore `mise run ci`, `verify` and CI — skips it too.
	# Nothing else in the toolchain would say so.
	plan_with "$FULL" test:bats@skipped@profile_exclude no-docs-tree@included
	plan_with "$FAST" test:bats@skipped@profile_exclude no-docs-tree@included
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 1 ]
	[[ "$output" == *"profiled-step-not-in-check"* ]]
	[[ "$output" == *"test:bats"* ]]
}

@test "every slow step missing from check is reported, not just the first" {
	# fail_fast is false for the hk gate; a gate that stopped at the first would
	# make a reader fix one line per run.
	plan_with "$FULL" test:bats@skipped@profile_exclude cargo-clippy@skipped@profile_exclude
	plan_with "$FAST" test:bats@skipped@profile_exclude cargo-clippy@skipped@profile_exclude
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 1 ]
	[[ "$output" == *"2 problem(s)"* ]]
}

@test "a tier member cannot also be included in the same no-profile plan" {
	# Not a rule — a property of the derivation, pinned so nobody re-adds the
	# rule that used to be here. The tier is derived FROM this plan's exclusions,
	# so "in the tier and still included here" is unrepresentable. An earlier
	# draft asserted it anyway and the branch was unreachable; a step included in
	# the no-profile plan is simply not a tier member, and the run is judged on
	# whatever else is.
	plan_with "$FULL" test:bats@included cargo-clippy@included
	plan_with "$FAST" test:bats@skipped@profile_exclude cargo-clippy@included
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 step(s) in the slow tier"* ]]
}

# --- anti-vacuity -----------------------------------------------------------

@test "no slow tier at all is could-not-look, never a pass" {
	# Every assertion this gate makes is universally quantified over the tier, so
	# an empty tier satisfies all of them. A gate that cannot find its subject
	# has verified nothing.
	plan_with "$FULL" no-docs-tree@included shellcheck@included
	plan_with "$FAST" no-docs-tree@included shellcheck@included
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 2 ]
	[[ "$output" == *"does not exist"* ]]
}

@test "a step skipped for a non-profile reason is not read as the slow tier" {
	# `filter_match` means the glob did not match — a different condition wearing
	# the same status. Counting it would invent a tier member and then report it
	# missing from check.
	plan_with "$FULL" no-docs-tree@included
	plan_with "$FAST" no-docs-tree@skipped@filter_match
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 2 ]
	[[ "$output" == *"does not exist"* ]]
}

# --- could-not-look ---------------------------------------------------------

@test "a plan with no steps is exit 2" {
	printf '{"hook":"check","steps":[]}\n' >"$FULL"
	plan_with "$FAST" test:bats@skipped@profile_exclude
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 2 ]
}

@test "unparseable JSON is exit 2, not a verdict" {
	printf 'not json at all\n' >"$FULL"
	plan_with "$FAST" test:bats@skipped@profile_exclude
	run "$GATE" "$FULL" "$FAST"
	[ "$status" -eq 2 ]
}

@test "a missing plan file is exit 2" {
	plan_with "$FAST" test:bats@skipped@profile_exclude
	run "$GATE" "$BATS_TEST_TMPDIR/absent.json" "$FAST"
	[ "$status" -eq 2 ]
}

@test "one argument is a usage error, not a half-judged run" {
	plan_with "$FULL" test:bats@included
	run "$GATE" "$FULL"
	[ "$status" -eq 2 ]
	[[ "$output" == *"exactly two"* ]]
}

# --- the self-referential case ----------------------------------------------

@test "this repository's own two-tier gate is correctly wired today" {
	# The claim made checkable rather than asserted. It fails the day someone
	# removes the config-level profile or a step's declaration — which is the
	# whole mechanism.
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"still selected by"* ]]
}
