#!/usr/bin/env bats
# subject: mise-tasks/release-tracking-check.sh .github/workflows/release-plz.yml .github/workflows/linear-release-backfill.yml
# release-tracking-check's decision table (CLOUD-618).
#
# Every case below is a shape that leaves a job GREEN while a shipped tag fails to
# reach Linear, which is what makes them worth a gate at all — a dropped
# `complete` produces a release stuck in the wrong stage, a shallow checkout
# produces a release with no issues attached, and neither reports anything. The
# suite drives synthetic workflows rather than the real ones for all but the tie
# cases: mutating a committed file in place would make the fixtures depend on its
# line numbers, and CLOUD-614's class is exactly that.
#
# TWO SUBJECTS, TWO FIXTURES. The gate judges the release path (`push` profile,
# tag resolved from git) and the backfill path (`dispatch` profile, tag named by
# an operator) in one run, so each is driven separately and the other stays clean —
# a mutation must produce ONE finding, not a pair whose second half comes from the
# fixture that was not being tested.
#
# The tie cases are the ones that keep this honest: the gate must pass the two
# workflows this change ships, or the table below is a decision procedure for
# nothing.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/release-tracking-check.sh"
	WORKFLOW="$BATS_TEST_TMPDIR/release-plz.yml"
	BACKFILL="$BATS_TEST_TMPDIR/linear-release-backfill.yml"
	clean_workflow >"$WORKFLOW"
	clean_backfill >"$BACKFILL"
	export BATTEN_RELEASE_WORKFLOW="$WORKFLOW"
	export BATTEN_BACKFILL_WORKFLOW="$BACKFILL"
}

# The release path, reduced to the nodes the gate judges. Quoted heredoc: every
# `${{ }}`, `$(…)` and `$GITHUB_OUTPUT` here is workflow syntax and must reach the
# file unexpanded.
#
# TWO JOBS, and the first one is not decoration. It mirrors `release-plz.yml`'s
# own shape — a cache-warm job whose checkout comes FIRST and carries no
# `fetch-depth` — because that is what made the file-global depth probe both pass
# for the wrong reason and point its finding at the wrong checkout. A one-job
# fixture cannot express the case that caught it.
clean_workflow() {
	cat <<-'EOF'
		name: release-plz
		on:
		  push:
		    branches: [main]
		jobs:
		  cache-warm:
		    runs-on: ubuntu-latest
		    steps:
		      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
		        with:
		          persist-credentials: false
		  release-plz:
		    runs-on: ubuntu-latest
		    steps:
		      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
		        with:
		          fetch-depth: 0
		      - run: mise run release
		      - name: Refresh tags after release-plz pushed one
		        run: git fetch --force --tags origin
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

# The backfill path. Same shapes, one difference: the version is bound to a
# declared `workflow_dispatch` input rather than to a step output, and the
# tag-exists probe stands in for the resolver a dispatch does not have.
clean_backfill() {
	cat <<-'EOF'
		name: linear-release-backfill
		on:
		  workflow_dispatch:
		    inputs:
		      tag:
		        description: Release tag to record in Linear
		        required: true
		        type: string
		jobs:
		  linear-release-backfill:
		    runs-on: ubuntu-latest
		    steps:
		      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
		        with:
		          ref: ${{ inputs.tag }}
		          fetch-depth: 0
		          persist-credentials: false
		      - name: The tag must exist in this checkout
		        env:
		          TAG: ${{ inputs.tag }}
		        run: |
		          if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
		            echo "::error:: no such tag" >&2
		            exit 1
		          fi
		      - name: Release tracking requires its credential
		        env:
		          LINEAR_ACCESS_KEY: ${{ secrets.LINEAR_ACCESS_KEY }}
		        run: |
		          if [ -z "$LINEAR_ACCESS_KEY" ]; then
		            echo "::error:: LINEAR_ACCESS_KEY is empty" >&2
		            exit 1
		          fi
		      - name: Record the release in Linear
		        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
		        with:
		          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
		          command: sync
		          version: ${{ inputs.tag }}
		      - name: Complete the Linear release
		        uses: linear/linear-release-action@17b8c24f8ceb2b98cabaf1965ff83c55dd596fac # v0.15.1
		        with:
		          access_key: ${{ secrets.LINEAR_ACCESS_KEY }}
		          command: complete
		          version: ${{ inputs.tag }}
	EOF
}

# Delete one step by its `- name:`, from that line to the line before the next
# step at the same indent. Whole-step deletion is what a dropped invocation
# actually looks like in a diff. The file defaults to the release-path fixture, so
# every pre-existing caller reads unchanged.
drop_step() { # drop_step <name> [file]
	local file="${2:-$WORKFLOW}"
	awk -v want="      - name: $1" '
		$0 == want { dropping = 1; next }
		dropping && /^      - / { dropping = 0 }
		!dropping { print }
	' "$file" >"$file.new"
	mv "$file.new" "$file"
}

# Rewrite one line matching a pattern. `sed -i` is deliberately avoided: GNU and
# BSD disagree about its suffix argument (see tests/helpers.bash).
replace_line() { # replace_line <extended-regex> <replacement-line> [file]
	local file="${3:-$WORKFLOW}"
	awk -v pat="$1" -v repl="$2" '$0 ~ pat { print repl; next } { print }' \
		"$file" >"$file.new"
	mv "$file.new" "$file"
}

drop_lines() { # drop_lines <extended-regex> [file]
	local file="${2:-$WORKFLOW}"
	awk -v pat="$1" '$0 ~ pat { next } { print }' "$file" >"$file.new"
	mv "$file.new" "$file"
}

# --- the ties to reality ------------------------------------------------------

@test "the workflow this change ships passes" {
	run env BATTEN_RELEASE_WORKFLOW="$BATS_TEST_DIRNAME/../.github/workflows/release-plz.yml" "$GATE"
	[ "$status" -eq 0 ]
}

@test "the backfill workflow this change ships passes" {
	run env BATTEN_BACKFILL_WORKFLOW="$BATS_TEST_DIRNAME/../.github/workflows/linear-release-backfill.yml" "$GATE"
	[ "$status" -eq 0 ]
}

@test "the clean fixture passes" {
	run "$GATE"
	[ "$status" -eq 0 ]
}

# Both subjects are named in the summary, so a reader can tell a run that judged
# one from a run that judged both. A gate that silently stopped judging the
# backfill path would otherwise look exactly like a clean one.
@test "the summary names both subjects" {
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"$WORKFLOW"* ]]
	[[ "$output" == *"$BACKFILL"* ]]
	[[ "$output" == *"(push path)"* ]]
	[[ "$output" == *"(dispatch path)"* ]]
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
	run env -u BATTEN_RELEASE_WORKFLOW -u BATTEN_BACKFILL_WORKFLOW sh -c "cd crates && exec '$GATE'"
	[ "$status" -eq 0 ]
}

# --- shapes both profiles hold ------------------------------------------------

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

@test "a dropped sync invocation on the backfill path is a violation" {
	drop_step "Record the release in Linear" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:0 release-tracking-sync-missing"* ]]
	[[ "$output" != *"$WORKFLOW:0 release-tracking-sync-missing"* ]]
}

@test "a dropped complete invocation on the backfill path is a violation" {
	drop_step "Complete the Linear release" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:0 release-tracking-complete-missing"* ]]
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

@test "an unpinned ref on the backfill path is a violation" {
	replace_line "uses: linear/linear-release-action@" \
		"        uses: linear/linear-release-action@v0" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-unpinned"* ]]
}

@test "a dropped credential precondition is a violation" {
	drop_step "Release tracking requires its credential"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-precondition-missing"* ]]
}

@test "a dropped credential precondition on the backfill path is a violation" {
	drop_step "Release tracking requires its credential" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:0 release-tracking-precondition-missing"* ]]
}

# --- the checkout, judged per job ---------------------------------------------

@test "an absent fetch-depth is a violation" {
	drop_lines "fetch-depth:"
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

# THE TIGHTENING, and the case the file-global probe passed. `fetch-depth: 0`
# anywhere in the document used to satisfy the rule, so a release job that lost
# it read as clean while some other job happened to carry one — and the finding's
# pointer named the FIRST checkout in the file, which in `release-plz.yml` belongs
# to a cache-warm job three jobs away. The depth is asserted on the checkout of
# each job that actually invokes the action.
@test "fetch-depth 0 on a job that does not invoke the action is not enough" {
	drop_lines "fetch-depth:"
	# Give it to the cache-warm job instead: the first checkout in the file, and
	# the one that never reads a commit range.
	awk '
		/persist-credentials: false/ && !done { print "          fetch-depth: 0"; done = 1 }
		{ print }
	' "$WORKFLOW" >"$WORKFLOW.new"
	mv "$WORKFLOW.new" "$WORKFLOW"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-shallow-checkout"* ]]
}

@test "an absent fetch-depth on the backfill path is a violation" {
	drop_lines "fetch-depth:" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:"*"release-tracking-shallow-checkout"* ]]
}

# --- the version binding, per profile -----------------------------------------

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

# The dispatch profile's own binding. A step-output reference is wrong HERE for
# the mirror-image reason a literal is wrong on the release path: a dispatch has
# no resolver step, so the expression names nothing.
@test "a step-output version on the backfill path is a violation" {
	replace_line "version: " "          version: \${{ steps.release-tag.outputs.tag }}" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:"*"release-tracking-version-unbound"* ]]
}

@test "a literal version on the backfill path is a violation" {
	replace_line "version: " "          version: v0.0.78" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:"*"release-tracking-version-unbound"* ]]
}

# The name is read back out and required to be DECLARED, which is the half a
# looser regex drops: `inputs.nonesuch` is valid workflow syntax that expands to
# the empty string, so the action is handed no version and the run stays green.
@test "a version bound to an undeclared input is a violation" {
	replace_line "version: " "          version: \${{ inputs.nonesuch }}" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:"*"release-tracking-version-unbound"* ]]
}

# A step's `with: tag:` is not an input declaration. Deleting the real one while
# leaving that spelling in the file is what a whole-file grep would have accepted.
@test "an input declared nowhere but passed as a step key is not a declaration" {
	drop_lines "^      tag:$" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:"*"release-tracking-version-unbound"* ]]
}

# The declaration is found by measured indent rather than a hard-coded column, so
# a differently indented but perfectly valid workflow still reads as declaring it.
@test "a deeper but valid input indentation still declares the input" {
	awk '
		/^on:$/ { print; print "    workflow_dispatch:"; print "      inputs:"; print "        tag:"; print "          required: true"; skip = 1; next }
		skip && /^  workflow_dispatch:$/ { next }
		skip && /^    inputs:$/ { next }
		skip && /^      tag:$/ { next }
		skip && /^        (description|required|type):/ { next }
		{ skip = 0; print }
	' "$BACKFILL" >"$BACKFILL.new"
	mv "$BACKFILL.new" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# --- the release path's tag source and its refresh ----------------------------

# §1's "computed in exactly one place" needs the place to exist; without it the
# bound-version check passes vacuously.
@test "a dropped tag-resolution step is a violation" {
	drop_step "Resolve the release tag this push shipped"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-tag-source-missing"* ]]
}

# With no resolver there is no ordering question, so the refresh rule must stay
# silent — one cause, one finding. Reporting both would send a reader to fix a
# step's position relative to a step that does not exist.
@test "a dropped tag-resolution step does not also report the refresh" {
	drop_step "Resolve the release tag this push shipped"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"release-tracking-tag-refresh-missing"* ]]
}

# THE DEFECT THIS CHANGE EXISTS FOR. `release-plz release` creates and pushes the
# tag from its own temporary clone, so the resolver reads a ref set that predates
# the tag — `fetch-depth: 0` does not help, because the tag was not there to
# fetch. Measured at `v0.0.110`, run 32665754952: tag created 20:53:13Z, resolver
# answered empty at 20:54:21Z, three steps skipped, 32 releases unrecorded.
@test "a dropped tag refresh is a violation" {
	drop_step "Refresh tags after release-plz pushed one"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-tag-refresh-missing"* ]]
}

# PRESENCE IS NOT ENOUGH, and this is the case a presence-only rule would pass
# while the workflow stayed exactly as broken: a refresh after the resolver
# updates a ref set nothing reads again.
@test "a tag refresh after the resolver is a violation" {
	drop_step "Refresh tags after release-plz pushed one"
	awk '
		{ print }
		/run: echo "tag=\$\(git tag --points-at HEAD/ {
			print "      - name: Refresh tags too late"
			print "        run: git fetch --force --tags origin"
		}
	' "$WORKFLOW" >"$WORKFLOW.new"
	mv "$WORKFLOW.new" "$WORKFLOW"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-tag-refresh-missing"* ]]
}

# A `git fetch` that does not carry `--tags` fetches branches and leaves the tag
# the resolver is looking for exactly as absent as before.
@test "a fetch without --tags is not a refresh" {
	replace_line "run: git fetch --force --tags origin" "        run: git fetch origin main"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-tag-refresh-missing"* ]]
}

# COMMENTS ARE NOT CODE, and this is the case that caught the gate itself. The
# comments this change added to `release-plz.yml` explain the measurement by
# quoting `git tag --points-at HEAD`, and the first run of the new probe matched
# one of them 29 lines above the real resolver — then compared the refresh's
# position against that line and reported a correctly ordered workflow as broken.
# CLOUD-843's substring-versus-command-position finding, arriving inside a gate.
@test "a comment quoting the resolver is not the resolver" {
	awk '
		/^      - run: mise run release$/ {
			print "      # `git tag --points-at HEAD` is what the resolver below runs."
		}
		{ print }
	' "$WORKFLOW" >"$WORKFLOW.new"
	mv "$WORKFLOW.new" "$WORKFLOW"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# The mirror image: a comment must not SATISFY a rule either. A workflow whose
# only `git fetch --tags` is prose about one has no refresh at all.
@test "a comment quoting the refresh does not satisfy the refresh rule" {
	drop_step "Refresh tags after release-plz pushed one"
	awk '
		/^      - run: mise run release$/ {
			print "      # run: git fetch --force --tags origin"
		}
		{ print }
	' "$WORKFLOW" >"$WORKFLOW.new"
	mv "$WORKFLOW.new" "$WORKFLOW"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-tag-refresh-missing"* ]]
}

# --- the backfill path's tag probe --------------------------------------------

# A TYPO MUST NOT MINT A RELEASE RECORD. The release path cannot make this
# mistake — its tag comes from git, so it either exists or is empty — but the
# backfill's version is typed by a human, and `sync` would create a release for a
# version that never shipped, green and unreported.
@test "a dropped tag-exists probe on the backfill path is a violation" {
	drop_step "The tag must exist in this checkout" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:0 release-tracking-tag-unverified"* ]]
}

# The probe is the backfill's own obligation, and the release path must not be
# held to it — it has no operator-supplied tag to verify.
@test "the release path is not asked for a tag-exists probe" {
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"release-tracking-tag-unverified"* ]]
}

# --- the checkout must sit on the version the invocation names ----------------

# THE DEFECT THE FIRST REAL DISPATCH SHIPPED (CLOUD-1026), and the case that
# would have caught it. `version:` names the release OBJECT; the commit range the
# action attaches issues from comes from the checkout's HEAD. `fetch-depth: 0`
# supplies the history and says nothing about where in it HEAD sits — so this is
# the shape that ran green, reached Released, and recorded `main`'s tip with ONE
# attached issue where the tag shipped EIGHTEEN.
@test "a backfill checkout with no ref is a violation" {
	drop_lines "ref: " "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$BACKFILL:"*"release-tracking-ref-unbound"* ]]
}

# Depth is not the same assertion, and this is what says so: a fixture that keeps
# `fetch-depth: 0` and loses only the `ref:` must still fail. Otherwise the depth
# rule reads as covering both and the gate goes back to certifying the defect.
@test "fetch-depth 0 does not stand in for a bound ref" {
	drop_lines "ref: " "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"$BACKFILL:"*"release-tracking-shallow-checkout"* ]]
	[[ "$output" == *"$BACKFILL:"*"release-tracking-ref-unbound"* ]]
}

# A literal branch is the actual pre-fix behaviour written down — `actions/checkout`
# defaults to the default branch, so naming one explicitly is the same record.
@test "a backfill checkout pinned to a branch is a violation" {
	replace_line "ref: " "          ref: main" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-ref-unbound"* ]]
}

# The name is read back out here too: a ref bound to an input nobody declares
# expands to the empty string, which is `actions/checkout`'s default — the
# defect again, wearing an expression.
@test "a backfill checkout bound to an undeclared input is a violation" {
	replace_line "ref: " "          ref: \${{ inputs.nonesuch }}" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"release-tracking-ref-unbound"* ]]
}

# Asked of the dispatch profile ONLY. The release path resolves its tag from
# `git tag --points-at HEAD`, so its HEAD and its version agree by construction,
# and demanding a `ref:` there would refuse the correct workflow.
@test "the release path is not asked for a bound ref" {
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"release-tracking-ref-unbound"* ]]
}

# --- could-not-look -----------------------------------------------------------

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

# EITHER subject being unreadable is could-not-look. A pass earned on the strength
# of the one file that could be read is the false green this contract refuses —
# and the backfill path is the one a reader is least likely to notice missing.
@test "an absent backfill workflow is could-not-look, not a violation" {
	run env BATTEN_BACKFILL_WORKFLOW="$BATS_TEST_TMPDIR/nonesuch.yml" "$GATE"
	[ "$status" -eq 2 ]
}

@test "an unreadable backfill workflow is not a clean release path" {
	run env BATTEN_BACKFILL_WORKFLOW="$BATS_TEST_TMPDIR/nonesuch.yml" "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" != *"(push path)"* ]]
}

# --- the output contract ------------------------------------------------------

# Non-negotiable rule 4. The gate reads files carrying a secret REFERENCE on every
# invocation line, so a finding that quoted its context would put the expression
# in every CI log that ever fails this check.
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

# Findings from both subjects sort together into one list, so a run that fails on
# both paths is still one readable, comparable report rather than two.
@test "findings from both subjects sort into one list" {
	drop_step "Complete the Linear release"
	drop_step "Complete the Linear release" "$BACKFILL"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"2 finding(s)"* ]]
	[[ "$output" == *"$WORKFLOW:0 release-tracking-complete-missing"* ]]
	[[ "$output" == *"$BACKFILL:0 release-tracking-complete-missing"* ]]
}

# A failing run must not also announce that a workflow "records and completes a
# Linear release" — the summary is held until the verdict is known, because the
# two sentences together are the ones a reader quotes back as a contradiction.
@test "a failing run prints no success summary" {
	drop_step "Complete the Linear release"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" != *"records and completes"* ]]
}
