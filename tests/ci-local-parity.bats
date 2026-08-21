#!/usr/bin/env bats
# subject: mise-tasks/ci-local-parity
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
	# No `dependabot.yml` is written: since CLOUD-660 property 12 asserts that file
	# is ABSENT, so the passing fixture for it is the empty directory it already
	# has. Its own cases write one to watch the refusal.
	#
	# The Renovate config IS written by default, for the same reason `pr_draft =
	# true` is: every case unrelated to property 13 must satisfy it. The lander is
	# written for the same reason again: property 15 judges every fixture directory,
	# and a case about draft guards must not also have to be a case about landers.
	renovate
	bot_lander
	# Property 16's subject, written by default for the reason the Renovate config
	# and the lander are: that property refuses a tree with NO foreign-runner cargo
	# job — "could not look", never clean — so every case unrelated to it must
	# satisfy it. Its own cases delete the file or move the spelling.
	foreign_runner
	# The task side of the same property, pinned rather than read from the real
	# `mise tasks info`: a fixture that reached into this repository's own manifest
	# would compare a fixture workflow against the committed task and fail for a
	# reason no case wrote.
	export PARITY_TASK_CARGO="cargo test --workspace"
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

@test "a foreign-runner job that runs nothing is not a second spelling" {
	# CLOUD-840. The refusal says a drifted job "goes green on work it no longer
	# covers", which presupposes it covers work. `--no-run` builds the test
	# binaries and executes none, so there is no verdict to be wrong — that is
	# `release-plz.yml`'s cache-warm job, which compiles on a Windows runner
	# purely to fill the base-branch cache.
	#
	# `workflow ci` first: without a pull_request workflow the gate refuses on a
	# different property entirely, and the row would assert nothing about this
	# one. The sibling below was passing exactly that way until this was fixed.
	workflow ci
	cat >"$WF/warm.yml" <<-'EOF'
		name: warm

		on:
		  workflow_dispatch:

		concurrency:
		  group: warm
		  cancel-in-progress: false

		jobs:
		  cache-warm-windows:
		    runs-on: windows-latest
		    timeout-minutes: 30 # budget: grandfathered measured=2026-08-21
		    steps:
		      - run: mise exec -- cargo nextest run --no-run --workspace
	EOF
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a cache-warm compile with no cache-hit guard is refused" {
	# CLOUD-840. The exemption property 16 grants a `--no-run` job is also what
	# makes it easy to leave running for nothing. Measured 2026-08-21: the two
	# `v0-rust-windows-…` entries in the repository carried the SAME key across
	# five merges, because the key follows the toolchain and the dependency set
	# rather than workspace source — and `rust-cache` skips saving when the key
	# already exists. So every cycle after the first compiled for ~145s and wrote
	# nothing, at ~6.4 billed minutes on a 2x runner.
	workflow ci
	cat >"$WF/warm.yml" <<-'EOF'
		name: warm

		on:
		  workflow_dispatch:

		concurrency:
		  group: warm
		  cancel-in-progress: false

		jobs:
		  cache-warm-windows:
		    runs-on: windows-latest
		    timeout-minutes: 30 # budget: grandfathered measured=2026-08-21
		    steps:
		      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
		        id: rust-cache
		      - run: mise exec -- cargo nextest run --no-run --workspace
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"does not guard that step"* ]]
}

@test "a guard naming a step id that does not exist is refused" {
	# THE ROT THAT WOULD OTHERWISE BE SILENT. If the action stops emitting
	# `cache-hit` the expression is empty, the guard holds, and the compile runs —
	# wasteful but visible in the bill. If the `id:` is renamed or dropped while
	# the `if:` keeps naming it, the expression is ALSO empty and the job quietly
	# goes back to compiling every time. Same symptom, no signal, so the gate has
	# to read both halves rather than just the guard.
	workflow ci
	cat >"$WF/warm.yml" <<-'EOF'
		name: warm

		on:
		  workflow_dispatch:

		concurrency:
		  group: warm
		  cancel-in-progress: false

		jobs:
		  cache-warm-windows:
		    runs-on: windows-latest
		    timeout-minutes: 30 # budget: grandfathered measured=2026-08-21
		    steps:
		      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
		        id: renamed-since
		      - run: mise exec -- cargo nextest run --no-run --workspace
		        if: steps.rust-cache.outputs.cache-hit != 'true'
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no step in that file declares"* ]]
}

@test "a guarded cache-warm compile passes" {
	# The positive direction, so the two rows above are shown to discriminate
	# rather than to refuse everything with `--no-run` in it.
	workflow ci
	cat >"$WF/warm.yml" <<-'EOF'
		name: warm

		on:
		  workflow_dispatch:

		concurrency:
		  group: warm
		  cancel-in-progress: false

		jobs:
		  cache-warm-windows:
		    runs-on: windows-latest
		    timeout-minutes: 30 # budget: grandfathered measured=2026-08-21
		    steps:
		      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
		        id: rust-cache
		      - run: mise exec -- cargo nextest run --no-run --workspace
		        if: steps.rust-cache.outputs.cache-hit != 'true'
	EOF
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "the no-run exemption cannot be used to escape the property" {
	# THE ROW THAT MAKES THE EXEMPTION SAFE. If the real foreign job gained
	# `--no-run` it would stop being compared — and it also stops counting as the
	# subject, so the tree refuses rather than silently ceasing to test there.
	# Without this, `--no-run` would be a documented way to switch the property
	# off, which is worse than not having it.
	rm -f "$WF/foreign.yml"
	workflow ci
	cat >"$WF/warm.yml" <<-'EOF'
		name: warm

		on:
		  workflow_dispatch:

		concurrency:
		  group: warm
		  cancel-in-progress: false

		jobs:
		  cache-warm-windows:
		    runs-on: windows-latest
		    timeout-minutes: 30 # budget: grandfathered measured=2026-08-21
		    steps:
		      - run: mise exec -- cargo nextest run --no-run --workspace
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"second-spelling property has no subject"* ]]
}

@test "this repository's real workflows pass" {
	# The assertion that catches the gate drifting from what it guards.
	#
	# `PARITY_TASK_CARGO` belongs in this list and was missed when property 16
	# landed (CLOUD-662), which made this case assert against a FIXTURE rather
	# than the tree: `setup` exports `cargo test --workspace`, so the real
	# `rust.yml` was compared to a string no file contains. It passed only while
	# the tree happened to agree with the fixture, and went red the moment
	# CLOUD-813 changed the real command to `cargo nextest run` — the case
	# reporting drift in the tree when the drift was in its own environment.
	# Every override this suite sets must be unset here or this row is fiction.
	unset PARITY_WORKFLOWS PARITY_MANIFEST PARITY_RELEASE_PLZ PARITY_DEPENDABOT PARITY_RENOVATE \
		PARITY_TASK_CARGO
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
	# Four: the PR workflow, the scheduled one, the bot lander `setup` writes so
	# property 15 is satisfied everywhere it is not the subject, and the
	# foreign-runner workflow it writes for property 16's benefit for the same
	# reason. This line editing when a default fixture is added is the count
	# assertion working.
	[[ "$output" == *"all 4 workflow(s) declare a concurrency group"* ]]
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
	rm -f "$WF"/*.yml
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

# A minimal bot lander: a `workflow_run` workflow whose TRIGGER names both live
# bot prefixes, which is what property 15 asks for. Written by `setup` like the
# Renovate fixture, so property 15's own cases are the only ones that have to
# think about it — they delete or narrow it.
foreign_runner() {
	# Deliberately NOT a `pull_request` workflow. Property 16 scans every
	# workflow for a foreign-runner cargo invocation, so a `workflow_dispatch`
	# fixture exercises it exactly as a PR one would — and it stays out of scope
	# for the landing-path properties, which is the same reason `bot_lander` is
	# `workflow_run`. A case about a second spelling must not also have to be a
	# case about draft guards and required-check rosters.
	cat >"$WF/foreign.yml" <<-'EOF'
		name: foreign

		on:
		  workflow_dispatch:

		concurrency:
		  group: foreign
		  cancel-in-progress: false

		jobs:
		  windows:
		    runs-on: windows-latest
		    timeout-minutes: 30 # budget: grandfathered measured=2026-08-19
		    steps:
		      - run: mise exec -- cargo test --workspace
	EOF
	return 0
}

bot_lander() {
	cat >"$WF/bot-lander.yml" <<-'EOF'
		name: bot-lander

		on:
		  workflow_run:
		    workflows: [ci]
		    types: [completed]
		    branches: ["renovate/**", "release-plz-**"]

		concurrency:
		  group: bot-lander
		  cancel-in-progress: false

		jobs:
		  land:
		    if: github.event.workflow_run.conclusion == 'success'
		    runs-on: ubuntu-latest
		    timeout-minutes: 3 # budget: grandfathered measured=2026-08-19
		    steps:
		      - run: ':'
	EOF
	return 0
}

# --- property 12: the dependabot config is absent, and stays absent -----------

@test "no dependabot config is the passing state — the bot is retired (CLOUD-660)" {
	workflow ci
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a dependabot config that comes back is refused, and named" {
	# The inversion's whole point: a re-added file puts a second bot on ecosystems
	# Renovate already owns, and nothing else in the tree would go red about it.
	workflow ci
	printf 'version: 2\nupdates:\n  - package-ecosystem: cargo\n    directory: "/"\n' >"$DEPENDABOT"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Dependabot is retired"* ]]
}

@test "an empty dependabot config is still a config — presence is the predicate" {
	# There is no shape of that file this tree wants. A gate reading its contents
	# would let an empty one back in, and the next commit fills it.
	workflow ci
	: >"$DEPENDABOT"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"Dependabot is retired"* ]]
}

# --- property 13: the Renovate config keeps its five CI-cost-and-coverage keys -

# A minimal well-formed Renovate config. Each argument toggles one of the keys:
# `yes`, `no`, or `wrong` for the key present with a value that is not the fix.
# `$schema` is always written, because its `https://` is the thing the comment
# strip must not mistake for a comment.
renovate() {
	local draft="${1:-yes}" rebase="${2:-yes}" limit="${3:-yes}" age="${4:-yes}"
	local managers="${5:-\"mise\", \"cargo\", \"github-actions\"}" type="${6:-rules}"
	local alerts="${7:-yes}"
	{
		printf '// the lane for mise.toml [tools], which no other bot can read\n{\n'
		printf '  $schema: "https://docs.renovatebot.com/renovate-schema.json",\n'
		printf '  enabledManagers: [%s],\n' "$managers"
		case "$draft" in
		yes) printf '  draftPR: true,\n' ;;
		wrong) printf '  draftPR: false,\n' ;;
		esac
		# `wrong` is `"never"` on purpose: it is the value this key USED to be
		# asserted at, so the case that would silently revert CLOUD-692 is the one
		# the suite pins (#503 sat BEHIND main under exactly that config).
		case "$rebase" in
		yes) printf '  rebaseWhen: "behind-base-branch",\n' ;;
		wrong) printf '  rebaseWhen: "never",\n' ;;
		esac
		case "$limit" in
		yes) printf '  prConcurrentLimit: 1,\n' ;;
		wrong) printf '  prConcurrentLimit: 0,\n' ;;
		esac
		case "$age" in
		yes) printf '  minimumReleaseAge: "7 days",\n' ;;
		wrong) printf '  minimumReleaseAge: "",\n' ;;
		esac
		case "$alerts" in
		yes) printf '  vulnerabilityAlerts: {\n    enabled: true,\n    minimumReleaseAge: null,\n  },\n' ;;
		esac
		# `rules` puts the commit type where it survives a preset's catch-all;
		# `toplevel` is the spelling that silently does nothing; `no` omits it.
		case "$type" in
		toplevel) printf '  semanticCommitType: "ci",\n' ;;
		esac
		printf '  packageRules: [\n'
		case "$type" in
		rules) printf '    { matchManagers: ["mise"], semanticCommitType: "ci" },\n' ;;
		esac
		printf '    { matchManagers: ["mise"], groupName: "tools" },\n'
		printf '  ],\n}\n'
	} >"$RENOVATE"
	return 0
}

@test "a renovate config carrying all five keys passes" {
	workflow ci
	renovate
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "each of the five keys missing is refused, and named" {
	# One case per direction, as property 4's cases are written: the keys are the
	# whole cost-and-coverage mechanism, so each must red on its own rather than
	# the set being checked as a lump.
	workflow ci

	renovate no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `draftPR`'* ]]

	renovate yes no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `rebaseWhen`'* ]]

	renovate yes yes no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `prConcurrentLimit`'* ]]

	renovate yes yes yes no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `minimumReleaseAge`'* ]]

	renovate yes yes yes yes '"mise", "cargo", "github-actions"' rules no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'declares no `vulnerabilityAlerts`'* ]]
}

@test "REVERTING rebaseWhen TO never IS REFUSED, because that is the regression (CLOUD-692)" {
	# The key whose asserted VALUE changed. `never` reads as the cautious choice
	# and is the one that stranded #503: with `draftPR: true` a rebase is free,
	# and a head nobody rebases goes BEHIND main where no fast-forward exists.
	workflow ci
	renovate yes wrong
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'does not declare `rebaseWhen`'* ]]
	[[ "$output" == *"BEHIND main"* ]]
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
	renovate no
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

# --- property 14: every ecosystem this repo maintains is served by the one bot -

@test "all three ecosystems named in the one config passes" {
	workflow ci
	renovate
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "an ecosystem missing from enabledManagers is refused, and named" {
	# The direction with no other symptom: nothing proposes updates for it, and
	# nothing anywhere goes red about an ecosystem standing still.
	workflow ci
	renovate yes yes yes yes '"mise", "cargo"'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"github-actions is not in"* ]]
	[[ "$output" != *"cargo is not in"* ]]
}

@test "mise IS judged now — the one bot can read that file, so its absence is a drift" {
	# It was exempt only because no Dependabot ecosystem could serve it, which
	# made "covered by neither" undetectable rather than acceptable (CLOUD-655).
	workflow ci
	renovate yes yes yes yes '"cargo", "github-actions"'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"mise is not in"* ]]
}

@test "a manager list broken across lines reads the same as one on a single line" {
	# A formatter's choice must not change a verdict.
	workflow ci
	renovate
	sed_i 's|^  enabledManagers.*$|  enabledManagers: [\n    "mise",\n    "cargo",\n    "github-actions",\n  ],|' "$RENOVATE"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# --- property 15: a lander per live bot branch prefix -------------------------

@test "a bot prefix with no workflow scoped to it is refused, and named" {
	# CLOUD-692 measured twice: two ecosystems were handed to a bot and no lander
	# moved with them, so #493 needed a human and #503 reproduced it 84 seconds
	# after #493 landed. Nothing else in the tree is red while a lane proposes and
	# never lands.
	workflow ci
	rm -f "$WF/bot-lander.yml"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"runs a bot on \`renovate/**\`"* ]]
	[[ "$output" == *"runs a bot on \`release-plz-**\`"* ]]
}

@test "a trigger-level branches filter is what satisfies it" {
	workflow ci
	bot_lander
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "A JOB CONDITION IS NOT A SCOPE, which is property 10's finding reused" {
	# A job `if:` is evaluated after the run exists: 1131 runs in 25 hours, 1131
	# of them skipped (CLOUD-493). A lander scoped only in its `if:` is not scoped.
	workflow ci
	sed_i 's|^    branches: \["renovate/\*\*", "release-plz-\*\*"\]$|    branches: ["release-plz-**"]|' "$WF/bot-lander.yml"
	sed_i "s|^    if: .*|    if: startsWith(github.event.workflow_run.head_branch, 'renovate/')|" "$WF/bot-lander.yml"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"runs a bot on \`renovate/**\`"* ]]
}

@test "the prefix is read from the config that owns it, not assumed" {
	# `branchPrefix` moves the heads the bot opens; a lander still watching the
	# default prefix watches nothing.
	workflow ci
	sed_i 's|^  enabledManagers|  branchPrefix: "bot-updates/",\n  enabledManagers|' "$RENOVATE"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"runs a bot on \`bot-updates/**\`"* ]]
}

@test "a lane whose config is absent is not asked for a watcher" {
	# The property refuses a missing WATCHER, never a missing lane: no
	# `release-plz.toml` means no release PRs exist to land. Property 4 refuses the
	# missing file for its own reason, which is why this asserts what property 15
	# does NOT say rather than an exit code it does not own.
	workflow ci
	rm -f "$RELEASE_PLZ"
	sed_i 's|^    branches: \["renovate/\*\*", "release-plz-\*\*"\]$|    branches: ["renovate/**"]|' "$WF/bot-lander.yml"
	run "$GATE"
	[[ "$output" != *"runs a bot on \`release-plz-**\`"* ]]
	[[ "$output" != *"runs a bot on \`renovate/**\`"* ]]
}

# --- property 16: a declared trigger can reach a job --------------------------

@test "a trigger no job condition admits is refused, and named" {
	# Measured on this repo's own bot lander: `workflow_dispatch` was added so the
	# lane could be exercised without waiting on a late cron, the job `if:` still
	# admitted only `schedule` and `workflow_run`, and the dispatched run SKIPPED.
	# The trigger existed and did nothing, which the run list cannot show.
	workflow ci
	cat >"$WF/lander2.yml" <<-'EOF'
		name: lander2

		on:
		  schedule:
		    - cron: "7 * * * *"
		  workflow_dispatch:

		concurrency:
		  group: lander2
		  cancel-in-progress: false

		jobs:
		  land:
		    if: github.event_name == 'schedule'
		    runs-on: ubuntu-latest
		    timeout-minutes: 3 # budget: grandfathered measured=2026-08-20
		    steps:
		      - run: ':'
	EOF
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"declares the \`workflow_dispatch\` trigger and no job condition admits it"* ]]
	[[ "$output" != *"declares the \`schedule\` trigger"* ]]
}

@test "the same workflow admitting both triggers passes" {
	workflow ci
	cat >"$WF/lander2.yml" <<-'EOF'
		name: lander2

		on:
		  schedule:
		    - cron: "7 * * * *"
		  workflow_dispatch:

		concurrency:
		  group: lander2
		  cancel-in-progress: false

		jobs:
		  land:
		    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
		    runs-on: ubuntu-latest
		    timeout-minutes: 3 # budget: grandfathered measured=2026-08-20
		    steps:
		      - run: ':'
	EOF
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "workflow_run is admitted by reading its payload, not only by naming the event" {
	# `github.event.workflow_run.*` is populated under that event alone, so a
	# condition reading it is discriminating on the event by another spelling.
	workflow ci
	run "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" != *"declares the \`workflow_run\` trigger"* ]]
}

@test "a job condition that mentions no event admits everything, so nothing is judged" {
	# The narrowing that keeps this a text gate rather than an expression
	# evaluator: a job with no `event_name` mention answers for every trigger.
	workflow ci
	cat >"$WF/lander2.yml" <<-'EOF'
		name: lander2

		on:
		  schedule:
		    - cron: "7 * * * *"
		  workflow_dispatch:

		concurrency:
		  group: lander2
		  cancel-in-progress: false

		jobs:
		  land:
		    runs-on: ubuntu-latest
		    timeout-minutes: 3 # budget: grandfathered measured=2026-08-20
		    steps:
		      - run: ':'
	EOF
	run "$GATE"
	[ "$status" -eq 0 ]
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

# --- property 13, fifth key: the commit type must outrank the preset ---------
#
# CLOUD-676. `extends: ["config:recommended"]` expands to include
# `:semanticPrefixFixDepsChoreOthers`, whose first rule is the catch-all
# `{ matchPackageNames: ["*"], semanticCommitType: "chore" }`. packageRules
# outrank top-level config, so a top-level `semanticCommitType` is set and then
# immediately overwritten — measured on the lane's first run, where every subject
# came out `chore(deps)` while the config said `ci` and every other key in it was
# demonstrably in effect.

@test "a commit type inside packageRules passes" {
	workflow ci
	renovate yes yes yes yes '"mise", "cargo", "github-actions"' rules
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "no commit type anywhere is refused" {
	# Without one, the lane's subjects carry no Conventional type at all and
	# commit-lint refuses every PR it opens — they could never land.
	workflow ci
	renovate yes yes yes yes '"mise", "cargo", "github-actions"' no
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'sets no `semanticCommitType` inside `packageRules`'* ]]
}

@test "THE MEASURED DEFECT: a top-level commit type is refused, because a preset outranks it" {
	# The case this property exists for. The key is present, spelled correctly,
	# and does nothing — which is why asserting mere presence would have passed
	# the exact config that failed.
	workflow ci
	renovate yes yes yes yes '"mise", "cargo", "github-actions"' toplevel
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'sets no `semanticCommitType` inside `packageRules`'* ]]
	[[ "$output" == *"outranked"* ]]
}

@test "a config with no packageRules at all is refused, and says why" {
	workflow ci
	renovate
	sed_i '/packageRules/,$d' "$RENOVATE"
	printf '}\n' >>"$RENOVATE"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *'declares no `packageRules`'* ]]
}

# --- property 16: the foreign runner's second spelling (CLOUD-662) ------------
#
# Property 3 asks "does CI run what verify runs", and CLOUD-394 gave foreign
# runners an exemption from it — correctly, since there is no local Windows. The
# `windows` job then landed inside that exemption running `mise exec -- cargo
# test --workspace` rather than the task, for a measured Git Bash / MSYS PATH
# reason that still stands. What nothing owned was the consequence: the job's
# command is a second spelling of `[tasks."test:cargo"]`'s body, and the
# exemption is per JOB rather than per property, so property 3 cannot see it
# drift.

@test "a foreign-runner command matching the task passes" {
	# `workflow ci` because the landing-path properties need a pull_request
	# workflow to exist at all; the foreign runner `setup` writes is deliberately
	# not one.
	workflow ci
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "a task that gained a flag the foreign runner did not is refused, and names both" {
	# THE DISCRIMINATING ROW. Every Linux leg follows the task; the Windows leg
	# keeps running the old command and goes green on work it no longer covers.
	# Nothing else in this repository would notice.
	PARITY_TASK_CARGO="cargo test --workspace --all-features" run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"foreign.yml"* ]]
	[[ "$output" == *"mise.toml"* ]]
	[[ "$output" == *"CLOUD-662"* ]]
	# Pointer-only: the two locations and that they differ, never the commands.
	[[ "$output" != *"--all-features"* ]]
}

@test "a foreign runner whose command drifted from the task is refused the same way" {
	# The other side of the same drift: the job changes and the task does not.
	sed_i 's|mise exec -- cargo test --workspace|mise exec -- cargo test --workspace --no-fail-fast|' "$WF/foreign.yml"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"foreign.yml"* ]]
}

@test "a tree with no foreign-runner cargo job is refused, not passed" {
	# ANTI-VACUITY, and the reason this property is written at all. With the
	# subject gone there is nothing to compare, and a gate that reported clean
	# would be answering a question it never asked.
	rm -f "$WF/foreign.yml"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"no subject"* ]]
	[[ "$output" == *"could-not-look, not clean"* ]]
}

@test "a task yielding no cargo invocation is refused, not passed" {
	# The same refusal from the other input: if the task's body stops carrying a
	# cargo line, the comparison has no left-hand side.
	PARITY_TASK_CARGO="" run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"yielded no"* ]]
	[[ "$output" == *"could-not-look, not clean"* ]]
}

# --- CLOUD-853: the comment-triggered merge path, unjudged until it merged ----
#
# Both properties sit ABOVE the `pull_request` filter in the gate, and that
# placement is the finding as much as the rules are: an `issue_comment` workflow
# never reaches that filter, so `fast-forward.yml` — the one workflow that moves
# `main` — was exempt from every property this suite enforces while reading as
# covered. Measured on PR #624, 2026-08-21: merged 42 seconds after opening, as
# a draft, with no CI run of any kind.
#
# The fixture is a minimal comment-triggered lander rather than a copy of the
# real file, for the reason the header states: the predicate is exercised over
# text the gate has never seen.
comment_lander() {
	cat >"$WF/ff.yml" <<-EOF
		name: ff

		on:
		  issue_comment:
		    types: [created]

		concurrency:
		  group: ff-\${{ github.event.issue.number }}
		  cancel-in-progress: false

		jobs:
		  ff:
		    if: >-
		      github.event.issue.pull_request &&
		      $1(github.event.comment.body, '/fast-forward')
		    runs-on: ubuntu-latest
		    timeout-minutes: 5 # budget: grandfathered measured=2026-08-10
		    steps:
		      - run: '$2'
		      - uses: some/lander@v1
		        with:
		          merge: true
	EOF
}

@test "an anchored comment trigger that also reads draft state passes" {
	workflow ci
	comment_lander startsWith 'gh api repos/o/r/pulls/1 --jq .draft'
	run "$GATE"
	[ "$status" -eq 0 ]
}

@test "CLOUD-853: an UNANCHORED comment trigger is refused, because prose naming the token fires it" {
	# THE DISCRIMINATING ROW for defect 1, and the one that is red against the
	# workflow as it stood on 2026-08-21. `contains` is a substring test, so a
	# comment merely discussing the trigger invokes it — which is how #624
	# merged itself out of a sentence about where a review gate should sit.
	workflow ci
	comment_lander contains 'gh api repos/o/r/pulls/1 --jq .draft'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ff.yml"* ]]
	[[ "$output" == *"unanchored"* ]]
	[[ "$output" == *"startsWith"* ]]
	[[ "$output" == *"CLOUD-853"* ]]
}

@test "CLOUD-853: a comment-triggered merge that never reads draft state is refused" {
	# THE DISCRIMINATING ROW for defect 2. A draft head grades no checks, and the
	# branch ruleset admits that empty set as satisfying "required checks green"
	# — measured on #624, not assumed. So delegating the draft question to the
	# ruleset is the same as not asking it. CLOUD-327/334/335/336 each fixed this
	# absent-is-not-green reading inside `ci-wait`, which is `land` deciding not
	# to ask; none of them constrained the push.
	workflow ci
	comment_lander startsWith ':'
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"ff.yml"* ]]
	[[ "$output" == *"draft"* ]]
	[[ "$output" == *"CLOUD-853"* ]]
}

@test "a comment-triggered workflow that does NOT merge is not asked the draft question" {
	# ANTI-VACUITY for property 13's scope. The rule is about a merge path, so a
	# comment-triggered workflow that merges nothing must pass without a draft
	# read — otherwise the property is really "every issue_comment workflow",
	# which would refuse shapes it has no argument against.
	workflow ci
	comment_lander startsWith ':'
	sed_i 's/          merge: true/          merge: false/' "$WF/ff.yml"
	run "$GATE"
	[ "$status" -eq 0 ]
}
