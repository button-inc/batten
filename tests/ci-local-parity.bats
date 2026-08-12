#!/usr/bin/env bats
# The gate that keeps CI a confirmation rather than a discovery (CLOUD-240).
#
# Each case is a fixture workflow directory plus a fixture manifest, so the
# predicate is exercised over text the gate has never seen — and the last case
# runs it over this repo's real workflows, which is the only assertion that can
# catch the gate drifting away from what it guards.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/ci-local-parity"
	WF="$BATS_TEST_TMPDIR/workflows"
	MANIFEST="$BATS_TEST_TMPDIR/mise.toml"
	RELEASE_PLZ="$BATS_TEST_TMPDIR/release-plz.toml"
	mkdir -p "$WF"
	export PARITY_WORKFLOWS="$WF" PARITY_MANIFEST="$MANIFEST" PARITY_RELEASE_PLZ="$RELEASE_PLZ"
	printf '[workspace]\npr_draft = true\n' >"$RELEASE_PLZ"
	cat >"$MANIFEST" <<-'EOF'
		CI_REQUIRED_CHECKS = "ci"

		[tasks.ci]
		run = "hk check --all"

		[tasks.verify]
		depends = ["ci", "cross-check"]
		run = '''
		mise run linear-check
		'''

		[tasks.other]
		run = "true"
	EOF
}

# A minimal well-formed PR workflow. Arguments override the pieces a case is
# about, so each fixture differs from a passing one in exactly one way.
workflow() {
	local name="$1" guard="${2:-    if: \${{ github.event.pull_request.draft == false }}}" \
		conc="${3:-cancel-in-progress: true}" task="${4:-ci}" \
		lease="${5:-      - name: Landing lease precondition
        run: ':'}"
	cat >"$WF/$name.yml" <<-EOF
		name: $name

		on:
		  pull_request:
		    types: [opened, synchronize]

		concurrency:
		  group: $name-\${{ github.ref }}
		  $conc

		jobs:
		  $name:
		    name: $name
		$guard
		    runs-on: ubuntu-latest
		    steps:
		$lease
		      - run: mise run $task
	EOF
}

# A minimal scheduled workflow — the population properties 8 and 9 exist for,
# and the one the `pull_request` filter skips entirely. `conc=no` drops the
# concurrency block, which is the only thing most of these cases vary.
scheduled() {
	local name="$1" cron="$2" conc="${3:-yes}"
	{
		printf 'name: %s\n\non:\n  schedule:\n    - cron: "%s"\n  workflow_dispatch:\n\n' "$name" "$cron"
		if [ "$conc" = yes ]; then
			printf 'concurrency:\n  group: %s\n  cancel-in-progress: false\n\n' "$name"
		fi
		printf 'jobs:\n  %s:\n    name: %s\n    runs-on: ubuntu-latest\n    steps:\n      - run: mise run ci\n' "$name" "$name"
	} >"$WF/$name.yml"
}

@test "a draft-gated, self-superseding workflow running a verify task passes" {
	workflow ci
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 pull_request workflow(s)"* ]]
}

@test "a job with no draft guard is refused, and named" {
	# Draft means \"still being verified locally\" — and it is the lever a red run
	# pulls, since `land` re-drafts to stop the spend. One ungated job defeats
	# both, which is exactly what zizmor.yml did.
	workflow ci "    # no guard here"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"job 'ci' runs on a draft PR"* ]]
	[[ "$output" == *"draft == false"* ]]
}

@test "a workflow that does not supersede its own runs is refused" {
	# A lap rebases and pushes; without this the superseded SHA's run is paid
	# out in full for a verdict nobody reads.
	workflow ci "    if: \${{ github.event.pull_request.draft == false }}" "cancel-in-progress: false"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"never supersedes its own runs"* ]]
}

@test "a task CI runs that verify does not is refused" {
	# The whole promise: CI confirms what was already proved. A task only CI
	# runs makes it the place a failure is discovered, at a runner's cost.
	workflow ci "    if: \${{ github.event.pull_request.draft == false }}" "cancel-in-progress: true" other
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise run other"* ]]
	[[ "$output" == *"verify\` does not"* ]]
}

@test "a task named only in a comment is not read as spend" {
	# These files carry long comments that name tasks to explain why they are
	# ABSENT. A gate that fires on its own documentation is a gate people
	# delete, so only `run:` steps count.
	workflow ci
	printf '      # see also mise run other, which is deliberately not here\n' >>"$WF/ci.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a multi-line run block is read too" {
	workflow ci
	cat >>"$WF/ci.yml" <<-'EOF'
		      - run: |
		          mise run other
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise run other"* ]]
}

@test "a workflow not triggered by pull_request is out of scope for the landing-path properties" {
	# A scheduled or release workflow is not on the landing path, so properties
	# 1-7 do not apply to it — `mise run other` here is a task `verify` does not
	# run, and that is deliberately not a finding.
	#
	# Properties 8 and 9 DO apply, which is the correction: this fixture used to
	# carry no concurrency group and passed, because the only concurrency
	# question was guarded on `pull_request`. That scoping is what left eleven
	# real workflows unjudged, so the group is now required here too.
	workflow ci
	cat >"$WF/nightly.yml" <<-'EOF'
		name: nightly

		on:
		  schedule:
		    - cron: "0 6 * * 1"

		concurrency:
		  group: nightly
		  cancel-in-progress: false

		jobs:
		  nightly:
		    runs-on: ubuntu-latest
		    steps:
		      - run: mise run other
	EOF
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 pull_request workflow(s)"* ]]
}

@test "a pull_request job missing from CI_REQUIRED_CHECKS is refused" {
	# The rot this sensor exists for. A job added and not listed is silently
	# unrequired, which is CLOUD-327 itself: `ci-wait` reports green on a SHA
	# where that job never graded.
	workflow ci
	workflow cross
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"job 'cross' runs on pull_request but is missing from CI_REQUIRED_CHECKS"* ]]
}

@test "a required name matching no job is refused" {
	# The other direction, and it fails differently: `ci-wait` waits forever for
	# a run nothing will ever create.
	workflow ci
	sed -i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci,gone"/' "$MANIFEST"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"names 'gone', which is no job"* ]]
}

@test "a matrix leg matches on its base name" {
	# A check-run's name carries the leg in parentheses and no committed text
	# can expand the template, so the comparison is over the base name.
	workflow ci
	sed -i 's/^    name: ci$/    name: ci (${{ matrix.target }})/' "$WF/ci.yml"
	sed -i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci (aarch64-apple-darwin)"/' "$MANIFEST"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a manifest with no required set at all is a failure, not a pass" {
	# An empty required set makes every check unrequired — the false green
	# stated as a default rather than a bug.
	workflow ci
	sed -i '/^CI_REQUIRED_CHECKS = /d' "$MANIFEST"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no CI_REQUIRED_CHECKS"* ]]
}

@test "finding no pull_request workflow at all is a failure, not a pass" {
	# A gate that passes vacuously when pointed at the wrong path reports the
	# landing path as covered when nothing was read.
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no pull_request-triggered workflow"* ]]
}

@test "a release config that does not open the release PR as a draft is refused" {
	# CLOUD-346. A ready release PR is refreshed on every push to `main`, and
	# each refresh buys a full matrix over a version bump. Property 1 gates every
	# job on the draft flag; this gates the flag being set at all.
	workflow ci
	printf '[workspace]\npublish = false\n' >"$RELEASE_PLZ"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pr_draft = true"* ]]
}

@test "a release config set to something other than true is refused" {
	# The key present and false is the same defect as the key absent, so the
	# gate matches the value rather than the name.
	workflow ci
	printf '[workspace]\npr_draft = false\n' >"$RELEASE_PLZ"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"pr_draft = true"* ]]
}

@test "a missing release config is a failure, not a pass" {
	workflow ci
	rm -f "$RELEASE_PLZ"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nothing declares whether the release PR is a draft"* ]]
}

# A fan-in job over two legs. `$1` is the body of its assert step, which is the
# only thing the two cases below differ in.
fanin() {
	workflow ci
	workflow cross "    if: \${{ github.event.pull_request.draft == false }}" "cancel-in-progress: true" "cross-check"
	sed -i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci,cross,final"/' "$MANIFEST"
	cat >"$WF/final.yml" <<-EOF
		name: final

		on:
		  pull_request:
		    types: [opened, synchronize]

		concurrency:
		  group: final-\${{ github.ref }}
		  cancel-in-progress: true

		jobs:
		  final:
		    name: final
		    if: \${{ always() && github.event.pull_request.draft == false }}
		    needs: [ci, cross]
		    runs-on: ubuntu-latest
		    steps:
		      - run: $1
	EOF
}

@test "a fan-in that enumerates only some of its needs is refused, and the omission named" {
	# The defect itself: `final` waited on four jobs and asserted three, so a red
	# `msrv` left green the one check branch protection requires (CLOUD-351).
	fanin '[ "${{ needs.ci.result }}" = "success" ]'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"job 'final' waits on 'cross' but never asserts it"* ]]
}

@test "a fan-in asserting over needs.* passes, and stays passing when a leg is added" {
	# The fix has to be the SET, not a longer enumeration: a list that happens to
	# be complete today is the same defect one job later. So the second half of
	# this case adds a dependency without touching the assertion.
	fanin "[ \"\${{ contains(needs.*.result, 'failure') }}\" = \"false\" ]"
	run "$GATE"
	[ "$status" -eq 0 ]

	workflow msrv "    if: \${{ github.event.pull_request.draft == false }}" "cancel-in-progress: true" "ci"
	sed -i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci,cross,final,msrv"/' "$MANIFEST"
	sed -i 's/^    needs: \[ci, cross\]$/    needs: [ci, cross, msrv]/' "$WF/final.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "this repository's real workflows pass" {
	# The assertion that catches the gate drifting from what it guards.
	unset PARITY_WORKFLOWS PARITY_MANIFEST PARITY_RELEASE_PLZ
	cd "$BATS_TEST_DIRNAME/.."
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a job that starts without asking the landing lease is refused, and named" {
	# CLOUD-420. The lease serialises landing, but it was enforced only inside
	# `mise-tasks/land` — so anything else pushing to a ready PR bought a full
	# matrix without ever touching the lock. Four concurrent matrices ran that
	# way on 2026-08-12 while the lease changed hands three times, every holder
	# honouring it.
	workflow ci "" "" ci "      - run: echo starting work"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"job 'ci' starts without asking whether the landing lease"* ]]
	[[ "$output" == *"Landing lease precondition"* ]]
}

@test "the precondition must be FIRST — a job that asks after installing has already spent" {
	# Most of what asking saves is the toolchain install and the build behind it.
	# A precondition placed after them is a precondition in name only, and it
	# would read as present to any check that merely greps the job.
	workflow ci "" "" ci "      - uses: actions/checkout@v7
      - name: Landing lease precondition
        run: ':'"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"job 'ci' starts without asking"* ]]
}

@test "a fan-in is exempt, because it cannot start before its dependencies" {
	# Exempt for a reason rather than by name: `needs:` is what makes a job
	# unable to spend a runner ahead of the cancellation, so `needs:` is what
	# the gate reads. `final` carries a checkout, so "has no checkout" — the
	# rule this replaced — would have demanded a precondition it cannot use.
	workflow ci
	# Property 5 would otherwise flag the new job as unrequired, which would
	# pass this case for the wrong reason.
	sed -i 's/^CI_REQUIRED_CHECKS = "ci"$/CI_REQUIRED_CHECKS = "ci,final"/' "$MANIFEST"
	cat >>"$WF/ci.yml" <<-'EOF'
		  final:
		    name: final
		    if: ${{ always() && github.event.pull_request.draft == false }}
		    needs: [ci]
		    runs-on: ubuntu-latest
		    steps:
		      - run: echo "${{ needs.*.result }}"
	EOF
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the success line reports the lease gate, so a silent skip is visible" {
	workflow ci
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"lease-gated before they spend"* ]]
}

# --- property 8: every workflow declares a concurrency group ------------------
#
# The arm that property 2 could not reach. Property 2 is guarded on
# `pull_request`, so a scheduled or `issue_comment` workflow was never asked the
# question at all — which is how eleven of them ended up with no group.

@test "a scheduled workflow with no concurrency group is refused, and named" {
	workflow ci
	scheduled nightly "0 5 * * *" no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nightly.yml declares no concurrency group"* ]]
}

@test "a scheduled workflow that declares one passes, with cancel-in-progress false" {
	# The two arms are not one. A scheduled run must NOT be cancelled by its own
	# next tick, so `false` is correct here — while property 2 still demands
	# `true` of a pull_request workflow. A gate collapsing them is wrong for one.
	workflow ci
	scheduled nightly "0 5 * * *"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the concurrency property judges every workflow, not only the pull_request ones" {
	# The regression that matters: if this check ever moves below the
	# `pull_request` filter it silently stops seeing the population it exists
	# for, and every case above still passes.
	workflow ci
	scheduled nightly "0 5 * * *" no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"all 2 workflow(s)"* ]] || [[ "$output" == *"nightly.yml"* ]]
}

@test "the success line reports how many workflows were judged for concurrency" {
	workflow ci
	scheduled nightly "0 5 * * *"
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"all 2 workflow(s) declare a concurrency group"* ]]
}

# --- property 9: no two schedules collide -------------------------------------

@test "two workflows sharing a cron expression are refused, and both named" {
	workflow ci
	scheduled alpha "0 7 * * 1"
	scheduled beta "0 7 * * 1"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'cron "0 7 * * 1" is declared by more than one workflow'* ]]
	[[ "$output" == *"alpha.yml"* ]]
	[[ "$output" == *"beta.yml"* ]]
}

@test "a staggered pair passes" {
	workflow ci
	scheduled alpha "0 7 * * 1"
	scheduled beta "15 7 * * 1"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an every-30-minutes schedule beside a weekly slot is not a collision" {
	# The false positive this property is deliberately shaped to avoid.
	# `auto-release-land` runs `*/30 * * * *`, which genuinely fires at the same
	# minute as every `:00` and `:30` weekly slot — so a firing-time comparison
	# would flag it forever, on a workflow doing nothing wrong. Literal equality
	# is the predicate, and this is the case that pins it.
	workflow ci
	scheduled alpha "0 7 * * 1"
	scheduled beta "*/30 * * * *"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a cron named only in a comment is not read as a schedule" {
	# These headers explain their slot in prose, often quoting a neighbour's
	# expression. A gate firing on its own documentation is a gate people delete.
	workflow ci
	scheduled alpha "0 7 * * 1"
	scheduled beta "15 7 * * 1"
	printf '# neighbours the 0 7 * * 1 slot\n#     - cron: "0 7 * * 1"\n' >>"$WF/beta.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an empty workflow directory is refused rather than silently green" {
	# Properties 8 and 9 judge every workflow, so they need their own
	# did-I-look-at-anything guard: reusing the pull_request counter would report
	# a wrong reason, and reporting nothing would be a false green over an empty
	# or mistyped path.
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no workflow found under"* ]]
}

# --- property 10: a workflow_run trigger filters where filtering is free -------

# A `workflow_run` workflow. `branches=no` drops the trigger-level filter;
# `cond=no` drops the job's head_branch condition, which is what the property is
# keyed to.
triggered() {
	local name="$1" branches="${2:-yes}" cond="${3:-yes}"
	{
		printf 'name: %s\n\non:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\n' "$name"
		if [ "$branches" = yes ]; then
			printf '    branches: ["dependabot/**"]\n'
		fi
		printf '\nconcurrency:\n  group: %s\n  cancel-in-progress: false\n\njobs:\n  %s:\n    name: %s\n' "$name" "$name" "$name"
		if [ "$cond" = yes ]; then
			printf "    if: startsWith(github.event.workflow_run.head_branch, 'dependabot/')\n"
		fi
		printf '    runs-on: ubuntu-latest\n    steps:\n      - run: mise run ci\n'
	} >"$WF/$name.yml"
}

@test "a workflow_run job filtering on head_branch with no trigger filter is refused" {
	# The measured defect: 1131 runs in 25 hours, 1131 skipped, because a job
	# `if:` is evaluated after the run already exists.
	workflow ci
	triggered autoland no yes
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"autoland.yml filters on workflow_run.head_branch"* ]]
	[[ "$output" == *"no branches: filter"* ]]
}

@test "the same workflow with a trigger-level branches filter passes" {
	workflow ci
	triggered autoland yes yes
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a workflow_run workflow with no branch condition at all is not asked for a filter" {
	# The property is keyed to the job's declared intent. Without that it could
	# not tell a deliberately repository-wide trigger from one that meant to be
	# narrow and expressed it in the wrong place — and it would demand a filter
	# of a workflow that legitimately wants every completion.
	workflow ci
	triggered autoland no no
	run "$GATE"
	[ "$status" -eq 0 ]
}
