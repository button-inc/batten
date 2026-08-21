#!/usr/bin/env bats
# subject: mise-tasks/report-only-check.sh
# CLOUD-582. `coverage` and `scorecard` are reports, not gates, and until this
# gate existed the only thing keeping them off the landing path was that nobody
# had added them to it — a decision held by a comment, which is feedforward with
# no sensor.
#
# The two ways onto that path are independent and fail for the same reason, so
# both are exercised: `[tasks.verify]` (what an agent runs before readying) and
# a `pull_request` workflow (what CI spends a runner on per push).

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/report-only-check.sh"
	MANIFEST="$BATS_TEST_TMPDIR/mise.toml"
	WORKFLOWS="$BATS_TEST_TMPDIR/workflows"
	mkdir -p "$WORKFLOWS"
	export REPORT_ONLY_MANIFEST="$MANIFEST"
	export REPORT_ONLY_WORKFLOWS="$WORKFLOWS"
	export REPORT_ONLY_TASKS="coverage scorecard"
}

# A `[tasks.verify]` block whose depends list is exactly the arguments.
verify_with() {
	local deps=""
	local d
	for d in "$@"; do deps="$deps\"$d\", "; done
	printf '[tasks.verify]\ndepends = [%s]\nrun = """\necho hi\n"""\n\n[tasks.other]\n' "${deps%, }" >"$MANIFEST"
}

workflow() {
	printf 'on:\n%s\njobs:\n  x:\n    steps:\n      - run: %s\n' "$2" "$3" >"$WORKFLOWS/$1"
}

@test "the repo's real manifest and workflows are clean today" {
	run env -u REPORT_ONLY_MANIFEST -u REPORT_ONLY_WORKFLOWS -u REPORT_ONLY_TASKS "$GATE"
	[ "$status" -eq 0 ]
	[[ "$output" == *"off the landing path"* ]]
}

@test "a report named in [tasks.verify] is refused" {
	verify_with tree-clean ci scorecard
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"scorecard"* ]]
	[[ "$output" == *"[tasks.verify] names it"* ]]
}

@test "a report run by a pull_request workflow is refused" {
	verify_with tree-clean ci
	workflow "pr.yml" "  pull_request:" "mise run coverage"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"coverage"* ]]
	[[ "$output" == *"pr.yml"* ]]
}

@test "a report run by a SCHEDULED workflow is the point, not a violation" {
	verify_with tree-clean ci
	workflow "weekly.yml" "  schedule:\n    - cron: \"0 9 * * 1\"" "mise run scorecard"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# The substring hazard. A name glued into a longer identifier is not a run of
# the task, and treating it as one is how a gate becomes noise and gets
# switched off.
@test "a longer identifier merely containing the name does not fire" {
	printf '[tasks.verify]\ndepends = ["ci"]\nrun = """\necho "$coverage_out_dir"\n"""\n\n[tasks.other]\n' >"$MANIFEST"
	run "$GATE"
	[ "$status" -eq 0 ]
}

# The other side of that boundary, and it is a real fire rather than a tolerated
# false positive: `verify` naming the report's own output path means `verify` is
# producing the report, which is the thing being refused.
@test "the report's output path in verify's body does fire" {
	printf '[tasks.verify]\ndepends = ["ci"]\nrun = """\nmkdir -p target/coverage\n"""\n\n[tasks.other]\n' >"$MANIFEST"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"coverage"* ]]
}

@test "both routes are reported together, not one at a time" {
	verify_with tree-clean scorecard
	workflow "pr.yml" "  pull_request:" "mise run coverage"
	run "$GATE"
	[ "$status" -eq 1 ]
	[[ "$output" == *"2 violation(s)"* ]]
}

@test "a manifest with no [tasks.verify] cannot be judged, and says so" {
	printf '[tasks.other]\n' >"$MANIFEST"
	run "$GATE"
	[ "$status" -eq 2 ]
	[[ "$output" == *"nothing to judge"* ]]
}

@test "a missing manifest is exit 2, never a pass" {
	export REPORT_ONLY_MANIFEST="$BATS_TEST_TMPDIR/absent.toml"
	run "$GATE"
	[ "$status" -eq 2 ]
}
