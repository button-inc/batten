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
		conc="${3:-cancel-in-progress: true}" task="${4:-ci}"
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
		      - run: mise run $task
	EOF
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

@test "a workflow not triggered by pull_request is out of scope" {
	# A scheduled or release workflow is not on the landing path, so none of
	# the three properties apply to it.
	workflow ci
	cat >"$WF/nightly.yml" <<-'EOF'
		name: nightly

		on:
		  schedule:
		    - cron: "0 6 * * 1"

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

@test "this repository's real workflows pass" {
	# The assertion that catches the gate drifting from what it guards.
	unset PARITY_WORKFLOWS PARITY_MANIFEST PARITY_RELEASE_PLZ
	cd "$BATS_TEST_DIRNAME/.."
	run "$GATE"
	[ "$status" -eq 0 ]
}
