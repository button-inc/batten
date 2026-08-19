#!/usr/bin/env bats
# release-tracking-check's decision table (CLOUD-618).
#
# Every case below is a shape that leaves the release job GREEN while a tagged
# push fails to reach Linear, which is what makes them worth a gate at all — a
# dropped `complete` produces a release stuck in the wrong stage, a shallow
# checkout produces a release with no issues attached, and neither reports
# anything. The suite drives a synthetic workflow rather than the real one for
# all but the first case: mutating the committed file in place would make the
# fixtures depend on its line numbers, and CLOUD-614's class is exactly that.
#
# The first case is the tie to reality — the gate must pass the workflow this
# change ships, or the table below is a decision procedure for nothing.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/release-tracking-check"
	WORKFLOW="$BATS_TEST_TMPDIR/release-plz.yml"
	clean_workflow >"$WORKFLOW"
	export BATTEN_RELEASE_WORKFLOW="$WORKFLOW"
}

# The shape the gate is written against, reduced to the nodes it judges. Quoted
# heredoc: every `${{ }}`, `$(…)` and `$GITHUB_OUTPUT` here is workflow syntax
# and must reach the file unexpanded.
clean_workflow() {
	cat <<-'EOF'
		name: release-plz
		on:
		  push:
		    branches: [main]
		jobs:
		  release-plz:
		    runs-on: ubuntu-latest
		    steps:
		      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
		        with:
		          fetch-depth: 0
		      - name: Resolve the release tag this push shipped
		        id: release-tag
		        run: echo "tag=$(git tag --points-at HEAD | grep -E '^v[0-9]' | head -n1)" >>"$GITHUB_OUTPUT"
		      - name: Release tracking requires its credential
		        if: steps.release-tag.outputs.tag != ''
		        env:
		          LINEAR_ACCESS_KEY: ${{ secrets.LINEAR_ACCESS_KEY }}
		        run: |
		          if [ -z "$LINEAR_ACCESS_KEY" ]; then
		            echo "::error:: LINEAR_ACCESS_KEY is empty" >&2
		            exit 1
		          fi
		      - name: Record the release in Linear
		        if: steps.release-tag.outputs.tag != ''
		        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
		        with:
		          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
		          command: sync
		          version: ${{ steps.release-tag.outputs.tag }}
		      - name: Complete the Linear release
		        if: steps.release-tag.outputs.tag != ''
		        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
		        with:
		          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
		          command: complete
		          version: ${{ steps.release-tag.outputs.tag }}
	EOF
}

# Delete one step by its `- name:`, from that line to the line before the next
# step at the same indent. Whole-step deletion is what a dropped invocation
# actually looks like in a diff.
drop_step() { # drop_step <name>
	awk -v want="      - name: $1" '
		$0 == want { dropping = 1; next }
		dropping && /^      - / { dropping = 0 }
		!dropping { print }
	' "$WORKFLOW" >"$WORKFLOW.new"
	mv "$WORKFLOW.new" "$WORKFLOW"
}

# Rewrite one line matching a pattern. `sed -i` is deliberately avoided: GNU and
# BSD disagree about its suffix argument (see tests/helpers.bash).
replace_line() { # replace_line <extended-regex> <replacement-line>
	awk -v pat="$1" -v repl="$2" '$0 ~ pat { print repl; next } { print }' \
		"$WORKFLOW" >"$WORKFLOW.new"
	mv "$WORKFLOW.new" "$WORKFLOW"
}

@test "the workflow this change ships passes" {
	run env BATTEN_RELEASE_WORKFLOW="$BATS_TEST_DIRNAME/../.github/workflows/release-plz.yml" "$GATE"
	[ "$status" -eq 0 ]
}

@test "the clean fixture passes" {
	run "$GATE"
	[ "$status" -eq 0 ]
}

# THE REGRESSION THIS SUITE EXISTS FOR AS MUCH AS THE TABLE BELOW. The row is
# `deny` + `scope = "tree"`, so the check runs on every gate invocation —
# including a `batten hook` mediated call, whose CWD is the caller's, not this
# tree's root. Reading the workflow relative to that CWD made the gate answer
# "could not look" from anywhere else, and a deny row that cannot look denies:
# CI refused an unrelated `gh pr ready` under this rule's name instead of the
# receipt row's, failing `the_committed_policy_gates_ready_on_receipts_rather_
# than_banning_it`. Asserted from a subdirectory, which is the shape a hook's
# CWD actually takes.
@test "the committed workflow is judged from any directory in the tree" {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run env -u BATTEN_RELEASE_WORKFLOW sh -c "cd crates && exec '$GATE'"
	[ "$status" -eq 0 ]
}

@test "a dropped sync invocation is a violation" {
	drop_step "Record the release in Linear"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-sync-missing"* ]]
	[[ "$output" != *"release-tracking-complete-missing"* ]]
}

# The one the pipeline's `type: scheduled` makes load-bearing: `sync` alone
# leaves the release started, and it never reaches Released.
@test "a dropped complete invocation is a violation" {
	drop_step "Complete the Linear release"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-complete-missing"* ]]
	[[ "$output" != *"release-tracking-sync-missing"* ]]
}

@test "the floating @v0 ref upstream publishes is a violation" {
	replace_line "uses: linear/linear-release-action@" \
		"        uses: linear/linear-release-action@v0"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-unpinned"* ]]
}

# A SHA with no trailing version comment is invisible to the bot's
# `github-actions` ecosystem, so the pin never gets proposed for update.
@test "a SHA pin without its version comment is a violation" {
	replace_line "uses: linear/linear-release-action@" \
		"        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-unpinned"* ]]
}

@test "an absent fetch-depth is a violation" {
	awk '!/fetch-depth:/' "$WORKFLOW" >"$WORKFLOW.new"
	mv "$WORKFLOW.new" "$WORKFLOW"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-shallow-checkout"* ]]
}

# A bounded depth carries no more of the tag's commit range than a shallow one,
# so it attaches nothing for the same reason and just as quietly.
@test "a non-zero fetch-depth is a violation" {
	replace_line "fetch-depth:" "          fetch-depth: 1"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-shallow-checkout"* ]]
}

@test "a literal version instead of the resolved tag output is a violation" {
	replace_line "version: " "          version: v0.0.77"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-version-unbound"* ]]
}

# An output reference to a step nobody declares expands to the empty string at
# run time — the action is then handed no version at all, silently.
@test "a version bound to an undeclared step is a violation" {
	replace_line "version: " "          version: \${{ steps.nonesuch.outputs.tag }}"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-version-unbound"* ]]
}

@test "a dropped credential precondition is a violation" {
	drop_step "Release tracking requires its credential"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-precondition-missing"* ]]
}

# §1's "computed in exactly one place" needs the place to exist; without it the
# bound-version check passes vacuously.
@test "a dropped tag-resolution step is a violation" {
	drop_step "Resolve the release tag this push shipped"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-tag-source-missing"* ]]
}

# Could-not-look is exit 2, never a verdict. Permission bits are deliberately not
# used to produce it: the suite runs as root in CI's container, where a mode-000
# file is still readable and the case would silently test nothing.
@test "an absent workflow is could-not-look, not a violation" {
	run env BATTEN_RELEASE_WORKFLOW="$BATS_TEST_TMPDIR/nonesuch.yml" "$GATE"
	[ "$status" -eq 2 ]
}

@test "a directory where the workflow should be is could-not-look" {
	mkdir -p "$BATS_TEST_TMPDIR/dir.yml"
	run env BATTEN_RELEASE_WORKFLOW="$BATS_TEST_TMPDIR/dir.yml" "$GATE"
	[ "$status" -eq 2 ]
}

# Non-negotiable rule 4. The gate reads a file carrying a secret REFERENCE on
# every invocation line, so a finding that quoted its context would put the
# expression in every CI log that ever fails this check.
@test "findings are pointers, never workflow text" {
	drop_step "Record the release in Linear"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"access_key"* ]]
	[[ "$output" != *"LINEAR_ACCESS_KEY"* ]]
	[[ "$output" != *"secrets."* ]]
	[[ "$output" == *"$WORKFLOW:0 release-tracking-sync-missing"* ]]
}

# Byte-stable output: the same tree must produce the same bytes, or a diff of two
# runs is unreadable and the finding list cannot be compared across commits.
@test "output is sorted and stable across runs" {
	drop_step "Record the release in Linear"
	drop_step "Complete the Linear release"
	run "$GATE"
	[ "$status" -eq 1 ]
	first="$output"
	run "$GATE"
	[ "$output" = "$first" ]
	# complete-missing sorts before sync-missing; the report is sorted, not
	# emission-ordered, and emission order is the reverse here. Only the pointer
	# lines are read — the summary line above them carries the task's own name,
	# which a looser match would collect as if it were a finding.
	pointers="$(printf '%s\n' "$output" | sed -n 's/^.*:[0-9][0-9]* \(release-tracking-[a-z-]*\)$/\1/p' | tr '\n' ' ')"
	[ "$pointers" = "release-tracking-complete-missing release-tracking-sync-missing " ]
}
