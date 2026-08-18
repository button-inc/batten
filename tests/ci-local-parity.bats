#!/usr/bin/env bats
# The gate that keeps CI a confirmation rather than a discovery (CLOUD-240).
#
# Each case is a fixture workflow directory plus a fixture manifest, so the
# predicate is exercised over text the gate has never seen — and the last case
# runs it over this repo's real workflows, which is the only assertion that can
# catch the gate drifting away from what it guards.

setup() {
	# tests/helpers.bash: `sed_i` / `run_timeout`, standing in for GNU
	# tools a stock macOS does not ship (CLOUD-282).
	load helpers
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/ci-local-parity"
	WF="$BATS_TEST_TMPDIR/workflows"
	MANIFEST="$BATS_TEST_TMPDIR/mise.toml"
	RELEASE_PLZ="$BATS_TEST_TMPDIR/release-plz.toml"
	DEPENDABOT="$BATS_TEST_TMPDIR/dependabot.yml"
	RENOVATE="$BATS_TEST_TMPDIR/renovate.json5"
	mkdir -p "$WF"
	export PARITY_WORKFLOWS="$WF" PARITY_MANIFEST="$MANIFEST" PARITY_RELEASE_PLZ="$RELEASE_PLZ" \
		PARITY_DEPENDABOT="$DEPENDABOT" PARITY_RENOVATE="$RENOVATE"
	printf '[workspace]\npr_draft = true\n' >"$RELEASE_PLZ"
	# The passing fixture, written by default for the same reason `pr_draft = true`
	# is: every case unrelated to property 12 must satisfy it, so only its own cases
	# overwrite this.
	dependabot cargo yes yes
	# Same, for property 13.
	renovate
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
        run: ':'}" \
		types="${6:-[opened, synchronize, reopened, ready_for_review]}"
	cat >"$WF/$name.yml" <<-EOF
		name: $name

		on:
		  pull_request:
		    types: $types

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

@test "a required check whose workflow cannot see ready_for_review is refused" {
	# CLOUD-503. Omitting `ready_for_review` defaults the trigger to
	# `[opened, synchronize, reopened]`. Every job is draft-gated, so the draft
	# `opened` run is a `skipped` — and `land` readies before pushing, with
	# nothing to push whenever HEAD is already on the remote. No event remains
	# that could supersede the skip, `checks-green` refuses to read it as an
	# answer, and the lease is held while the poll never ends.
	workflow ci "    if: \${{ github.event.pull_request.draft == false }}" \
		"cancel-in-progress: true" ci "      - name: Landing lease precondition
        run: ':'" "[opened, synchronize, reopened]"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"omits \`ready_for_review\`"* ]]
}

@test "a workflow producing no required check may omit ready_for_review" {
	# The other direction, and the reason the property is scoped rather than
	# demanded of every pull_request workflow: nothing waits on `other`, so a
	# skip nothing can supersede costs nobody a poll. A gate that asserted more
	# than the failure needs would refuse this file for no reason.
	printf 'CI_REQUIRED_CHECKS = "elsewhere"\n\n[tasks.ci]\nrun = "hk check --all"\n\n[tasks.verify]\ndepends = ["ci"]\n\n[tasks.elsewhere]\nrun = "true"\n' >"$MANIFEST"
	workflow ci "    if: \${{ github.event.pull_request.draft == false }}" \
		"cancel-in-progress: true" ci "      - name: Landing lease precondition
        run: ':'" "[opened, synchronize, reopened]"
	run "$GATE"
	[[ "$output" != *"ready_for_review"* ]]
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
	sed_i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci,gone"/' "$MANIFEST"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"names 'gone', which is no job"* ]]
}

@test "a matrix leg matches on its base name" {
	# A check-run's name carries the leg in parentheses and no committed text
	# can expand the template, so the comparison is over the base name.
	workflow ci
	sed_i 's/^    name: ci$/    name: ci (${{ matrix.target }})/' "$WF/ci.yml"
	sed_i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci (aarch64-apple-darwin)"/' "$MANIFEST"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a manifest with no required set at all is a failure, not a pass" {
	# An empty required set makes every check unrequired — the false green
	# stated as a default rather than a bug.
	workflow ci
	sed_i '/^CI_REQUIRED_CHECKS = /d' "$MANIFEST"
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
	sed_i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci,cross,final"/' "$MANIFEST"
	cat >"$WF/final.yml" <<-EOF
		name: final

		on:
		  pull_request:
		    types: [opened, synchronize, reopened, ready_for_review]

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
	sed_i 's/^CI_REQUIRED_CHECKS = .*/CI_REQUIRED_CHECKS = "ci,cross,final,msrv"/' "$MANIFEST"
	sed_i 's/^    needs: \[ci, cross\]$/    needs: [ci, cross, msrv]/' "$WF/final.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# --- property 11: an unquoted '#' must not swallow an interpolation ----------
#
# CLOUD-507. `run-name: fast-forward #${{ … }}` parses to the bare string
# `fast-forward`, so the key never reaches GitHub and `land`'s verdict filter can
# never match. Legal YAML, so actionlint and zizmor both pass it.
#
# The three passing rows are not padding. The obvious predicate — raw `${{` count
# versus the count surviving a parse — is 75% false positives on this repo's own
# corpus, and a gate that noisy gets switched off. Each row below is one of those
# false positives.

@test "an unquoted # that swallows an interpolation is refused, and named" {
	workflow ci
	printf 'run-name: build #%s\n' '${{ github.event.issue.number }}' >>"$WF/ci.yml"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"unquoted '#'"* ]]
	[[ "$output" == *"ci.yml:"* ]]
	# Pointer-only: the repair, never the line's text — a value can name a secret.
	[[ "$output" != *"github.event.issue.number"* ]]
}

@test "the same value quoted passes — the repair must not be refused" {
	workflow ci
	printf 'run-name: "build #%s"\n' '${{ github.event.issue.number }}' >>"$WF/ci.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a whole-line comment mentioning an interpolation passes" {
	workflow ci
	printf '# a note about %s expansion in a run block\n' '${{ }}' >>"$WF/ci.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a trailing comment with no interpolation after it passes" {
	workflow ci
	printf 'run-name: build # an ordinary trailing comment\n' >>"$WF/ci.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "this repository's real workflows pass" {
	# The assertion that catches the gate drifting from what it guards.
	unset PARITY_WORKFLOWS PARITY_MANIFEST PARITY_RELEASE_PLZ PARITY_DEPENDABOT PARITY_RENOVATE
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

# --- property 12: every dependabot ecosystem bounds its re-proposals ----------

# Two `updates` entries, because the property is per-entry and a whole-file grep
# passes a file where one carries both keys and the other carries none. Each
# argument toggles the keys on the entry of that name: `yes`/`no`, or `wrong` for
# the key present with a value that is not the fix.
dependabot() {
	local first="${1:-cargo}" rebase="${2:-yes}" limit="${3:-yes}"
	local second_rebase="${4:-yes}" second_limit="${5:-yes}"
	# `none` drops the second entry entirely — the shape a handover leaves behind,
	# which property 14 reads and property 12 must stay silent about.
	local second="${6:-github-actions}"
	{
		printf 'version: 2\nupdates:\n'
		printf '  - package-ecosystem: %s\n    directory: "/"\n' "$first"
		case "$rebase" in
		yes) printf '    rebase-strategy: disabled\n' ;;
		wrong) printf '    rebase-strategy: auto\n' ;;
		esac
		case "$limit" in
		yes) printf '    open-pull-requests-limit: 1\n' ;;
		# `zero` is the security-only shim CLOUD-658 leaves behind: property 12
		# still sees the key, property 14 must not see a version-update lane.
		zero) printf '    open-pull-requests-limit: 0\n' ;;
		esac
		printf '    # a comment inside the entry, as the real file carries\n'
		printf '    ignore:\n      - dependency-name: ignore\n        versions: [">= 0.4.30"]\n'
		if [ "$second" != none ]; then
			printf '\n  - package-ecosystem: %s\n    directory: "/"\n' "$second"
			case "$second_rebase" in
			yes) printf '    rebase-strategy: disabled\n' ;;
			wrong) printf '    rebase-strategy: auto\n' ;;
			esac
			[ "$second_limit" = yes ] && printf '    open-pull-requests-limit: 1\n'
			printf '    schedule:\n      interval: weekly\n'
		fi
	} >"$DEPENDABOT"
	return 0
}

@test "a dependabot entry declaring neither key is refused, and named" {
	workflow ci
	dependabot cargo no no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cargo entry does not declare \`rebase-strategy: disabled\`"* ]]
	[[ "$output" == *"cargo entry does not declare \`open-pull-requests-limit"* ]]
}

@test "rebase-strategy present with a value that is not disabled is the same defect" {
	# Property 4's reasoning: the key set to anything but the fix is the key absent.
	workflow ci
	dependabot cargo wrong yes
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cargo entry does not declare \`rebase-strategy: disabled\`"* ]]
}

@test "one compliant entry does not cover a second that is not" {
	# The case a whole-file grep passes: the keys exist in the file, on one entry.
	workflow ci
	dependabot cargo yes yes no no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"github-actions entry does not declare"* ]]
	[[ "$output" != *"cargo entry does not declare"* ]]
}

@test "a missing dependabot config is a failure, not a pass" {
	workflow ci
	rm -f "$DEPENDABOT"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nothing bounds how often the bot re-proposes a head"* ]]
}

@test "both entries declaring both keys pass" {
	workflow ci
	dependabot cargo yes yes yes yes
	run "$GATE"
	[ "$status" -eq 0 ]
}

# --- property 13: the Renovate config keeps its four CI-cost keys -------------

# A minimal well-formed Renovate config. Each argument toggles one of the four
# keys: `yes`, `no`, or `wrong` for the key present with a value that is not the
# fix. `$schema` is always written, because its `https://` is the thing the
# comment strip must not mistake for a comment.
renovate() {
	local draft="${1:-yes}" rebase="${2:-yes}" limit="${3:-yes}" age="${4:-yes}"
	local managers="${5:-\"mise\"}"
	{
		printf '// the lane for mise.toml [tools], which no other bot can read\n{\n'
		printf '  $schema: "https://docs.renovatebot.com/renovate-schema.json",\n'
		printf '  enabledManagers: [%s],\n' "$managers"
		case "$draft" in
		yes) printf '  draftPR: true,\n' ;;
		wrong) printf '  draftPR: false,\n' ;;
		esac
		case "$rebase" in
		yes) printf '  rebaseWhen: "never",\n' ;;
		wrong) printf '  rebaseWhen: "behind-base-branch",\n' ;;
		esac
		case "$limit" in
		yes) printf '  prConcurrentLimit: 1,\n' ;;
		wrong) printf '  prConcurrentLimit: 0,\n' ;;
		esac
		case "$age" in
		yes) printf '  minimumReleaseAge: "7 days",\n' ;;
		wrong) printf '  minimumReleaseAge: "",\n' ;;
		esac
		printf '}\n'
	} >"$RENOVATE"
	return 0
}

@test "a renovate config carrying all four keys passes" {
	workflow ci
	renovate
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "each of the four keys missing is refused, and named" {
	# One case per direction, as property 4's cases are written: the four keys are
	# the whole CI-cost mechanism, so each must red on its own rather than the set
	# being checked as a lump.
	workflow ci

	renovate no yes yes yes
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `draftPR`'* ]]

	renovate yes no yes yes
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `rebaseWhen`'* ]]

	renovate yes yes no yes
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `prConcurrentLimit`'* ]]

	renovate yes yes yes no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `minimumReleaseAge`'* ]]
}

@test "a key present with a value that is not the fix is the same defect" {
	# `prConcurrentLimit: 0` is the sharp one: Renovate reads 0 as UNLIMITED, so
	# the bound and its own negation differ by a single character, and a gate
	# matching the key alone would pass the config that removed the bound.
	workflow ci
	renovate wrong wrong wrong wrong
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `draftPR`'* ]]
	[[ "$output" == *'does not declare `rebaseWhen`'* ]]
	[[ "$output" == *'does not declare `prConcurrentLimit`'* ]]
	[[ "$output" == *'does not declare `minimumReleaseAge`'* ]]
}

@test "a key named only in a comment does not satisfy the property" {
	# That file argues for each of its keys at length. A gate a comment can
	# satisfy is a gate satisfied by deleting the key the comment explains.
	workflow ci
	renovate no yes yes yes
	sed_i 's|^  enabledManagers.*$|  // draftPR: true,|' "$RENOVATE"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `draftPR`'* ]]
}

@test "a missing renovate config is a failure, not a pass" {
	workflow ci
	rm -f "$RENOVATE"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"nothing bounds what the Renovate lane spends"* ]]
}

# --- property 14: exactly one bot per ecosystem both can serve ----------------

@test "an ecosystem in the renovate config only passes — that is the handover's landing state" {
	workflow ci
	dependabot cargo yes yes yes yes none
	renovate yes yes yes yes '"mise", "github-actions"'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an ecosystem declared in both configs is refused, and named" {
	# Two bots proposing the same updates doubles the lane and every PR it opens.
	workflow ci
	renovate yes yes yes yes '"mise", "github-actions"'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"github-actions runs version updates in BOTH"* ]]
	[[ "$output" != *"cargo runs version updates in BOTH"* ]]
}

@test "an ecosystem declared in neither config is refused, and named" {
	# The direction with no other symptom: removed from one config and never added
	# to the other, the ecosystem is unmaintained and nothing anywhere is red.
	workflow ci
	dependabot cargo yes yes yes yes none
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"github-actions runs version updates in NEITHER"* ]]
}

@test "a manager list broken across lines reads the same as one on a single line" {
	# A formatter's choice must not change a verdict.
	workflow ci
	dependabot cargo yes yes yes yes none
	renovate
	sed_i 's|^  enabledManagers.*$|  enabledManagers: [\n    "mise",\n    "github-actions",\n  ],|' "$RENOVATE"
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a dependabot entry at open-pull-requests-limit: 0 is a security shim, not a second lane" {
	# CLOUD-658's landing state: `cargo` version updates belong to Renovate, and
	# the Dependabot entry survives only to give a SECURITY PR a subject
	# commit-lint accepts. Reading that shim as a second updater would refuse the
	# correct tree.
	workflow ci
	dependabot cargo yes zero yes yes none
	renovate yes yes yes yes '"mise", "cargo", "github-actions"'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the shim raising its limit is a second version-update lane, and is refused" {
	# The direction that matters: nothing else would go red, and `cargo` would
	# quietly be proposed by two bots at once.
	workflow ci
	dependabot cargo yes yes yes yes none
	renovate yes yes yes yes '"mise", "cargo", "github-actions"'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cargo runs version updates in BOTH"* ]]
}

@test "a dependabot entry with no limit at all counts as a lane — fail closed" {
	# The missing key is already property 12's refusal; counting it here too fails
	# in the safe direction rather than exempting an entry nobody bounded.
	workflow ci
	dependabot cargo yes no yes yes none
	renovate yes yes yes yes '"mise", "cargo", "github-actions"'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cargo runs version updates in BOTH"* ]]
}

@test "an ecosystem left only as a shim, and owned by neither bot, is refused" {
	# A shim is not coverage: if Renovate never gained the manager, silencing the
	# Dependabot entry leaves the ecosystem unmaintained with nothing else red.
	workflow ci
	dependabot cargo yes zero yes yes none
	renovate yes yes yes yes '"mise", "github-actions"'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"cargo runs version updates in NEITHER"* ]]
}

@test "mise is not judged by property 14 — no dependabot ecosystem can read that file" {
	# It can never be double-covered, and its absence from dependabot.yml is
	# CLOUD-655's whole subject rather than a drift this property could catch.
	workflow ci
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"mise runs version updates in NEITHER"* ]]
}

# --- property 11: reading check status means deciding through checks-green ----

# A workflow that lands a SHA. `endpoint=no` drops the check-runs read, which is
# what the property is keyed to; `predicate=no` drops the `checks-green` call.
lander() {
	local name="$1" endpoint="${2:-yes}" predicate="${3:-yes}"
	{
		printf 'name: %s\n\non:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\n' "$name"
		printf '\nconcurrency:\n  group: %s\n  cancel-in-progress: false\n\njobs:\n  %s:\n    name: %s\n' "$name" "$name" "$name"
		printf '    runs-on: ubuntu-latest\n    steps:\n'
		if [ "$endpoint" = yes ]; then
			printf '      - run: gh api "repos/$REPO/commits/$SHA/check-runs?per_page=100"\n'
		fi
		if [ "$predicate" = yes ]; then
			printf '      - run: mise run checks-green\n'
		fi
		printf '      - run: mise run ci\n'
	} >"$WF/$name.yml"
}

@test "a workflow reading check-runs without checks-green is refused" {
	# CLOUD-391. The hand-rolled copy counts a wholly skipped set as green, which
	# is CLOUD-327's false green with a second author.
	workflow ci
	lander autoland yes no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"autoland.yml reads the check-runs endpoint"* ]]
	[[ "$output" == *"checks-green"* ]]
}

@test "the same workflow deciding through checks-green passes" {
	workflow ci
	lander autoland yes yes
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a workflow that never reads check status is not asked for the predicate" {
	# Keyed to the endpoint, so a workflow with no verdict to reach is not asked
	# to call a gate that would have nothing to judge.
	workflow ci
	lander autoland no no
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the endpoint named only in a comment does not demand the predicate" {
	# Both auto-landers explain this very property in prose, quoting the jq they
	# replaced. A gate firing on its own explanation is unfixable except by
	# deleting the explanation.
	workflow ci
	lander autoland no no
	printf '# the old copy read repos/x/commits/y/check-runs and called it green\n' >>"$WF/autoland.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# --- property 3's scope: a job on an OS this machine cannot be ---------------
#
# CLOUD-394. Property 3's premise is its own header's — "a free local run would
# have caught it" — and that is false for a job running on an OS the agent is
# not. Applied there it stops being a parity check and becomes a prohibition on
# cross-OS CI, which is what blocked CLOUD-113's Windows test job: it satisfied
# every other property and could not be committed at all.
#
# A PR workflow whose single job runs `mise run <task>` on the given runner.
# `task` defaults to one `verify` does not run, which is the whole question.
on_runner() {
	local name="$1" runner="$2" task="${3:-other}"
	{
		printf 'name: %s\n\non:\n  pull_request:\n    types: [opened, synchronize, reopened, ready_for_review]\n' "$name"
		printf '\nconcurrency:\n  group: %s-${{ github.ref }}\n  cancel-in-progress: true\n\njobs:\n  %s:\n    name: %s\n' "$name" "$name" "$name"
		printf '    if: ${{ github.event.pull_request.draft == false }}\n'
		if [ -n "$runner" ]; then
			printf '    runs-on: %s\n' "$runner"
		fi
		printf '    steps:\n      - name: Landing lease precondition\n        run: %s\n      - run: mise run %s\n' "':'" "$task"
	} >"$WF/$name.yml"
}

@test "a Windows job may run a task verify does not — there is no local Windows to have caught it" {
	on_runner ci windows-latest
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a macOS job is exempt on the same reasoning" {
	on_runner ci macos-latest
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the identical step on a Linux runner is still refused" {
	# The case that would regress silently: exempting too broadly switches the
	# property off for the jobs it exists to judge, and nothing goes red.
	on_runner ci ubuntu-latest
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"which \`mise run verify\` does not"* ]]
}

@test "a job declaring no runs-on is judged, not exempted" {
	on_runner ci ""
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"which \`mise run verify\` does not"* ]]
}

@test "an unclassified runner label is judged — the exemption is foreign labels, not non-Linux ones" {
	# The direction that makes this fail closed. An allowlist of `ubuntu-*` would
	# exempt `self-hosted` and a matrix expression too, silently.
	on_runner ci self-hosted
	run "$GATE"
	[ "$status" -eq 1 ]

	on_runner ci '${{ matrix.os }}'
	run "$GATE"
	[ "$status" -eq 1 ]
}

@test "a Windows job running a task verify DOES run is still fine" {
	# The exemption removes a refusal; it must not invent an acceptance rule of
	# its own, nor stop the other five properties applying to the same job.
	on_runner ci windows-latest ci
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the exemption is per job, so a Linux job beside a Windows one is still judged" {
	on_runner win windows-latest
	on_runner ci ubuntu-latest
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ci.yml"* ]]
	[[ "$output" != *"win.yml runs"* ]]
}
