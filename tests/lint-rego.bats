#!/usr/bin/env bats
# subject: mise.toml
# CLOUD-930. `.rego` was the one config format with no formatter, and the campaign
# CLOUD-843 owns migrates ~80 gates onto it — so this gate's value scales with the
# campaign rather than with the nine modules in tree when it was written.
#
# What this suite pins is not "opa fmt works". It pins the two properties that
# were WRONG on the first attempt and would fail silently if they regressed, plus
# the fixture hazard the row's §7 demands be tested rather than argued:
#
#   1. the file list comes from `git ls-files`, piped straight into xargs. Wrapping
#      it in a command substitution strips the NUL bytes `-z` emits and collapses
#      the whole list into one concatenated path — measured on the first run, and
#      it presents as a "no such file or directory" red rather than as a gate that
#      selected nothing.
#   2. the check does not pass `--fail`. It short-circuits on the first differing
#      file, so a corpus with two unformatted modules reported one — measured, both
#      before and after.
#
# The red/green demonstration (CLOUD-418) was made on the real corpus rather than
# a fixture, because the corpus supplied it: `sibling-resolves.rego` and
# `privileged-lane.rego` were both unformatted on `main`, the gate named both and
# exited 1, and it exits 0 after `fmt:rego`. Both reformats landed with the gate.

setup() {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	CHECK=$(awk '/^\[tasks\."lint:rego"\]/{f=1} f&&/^run = .{3}$/{c=1;next} c&&/^'"'''"'$/{exit} c' mise.toml)
	FIX=$(awk '/^\[tasks\."fmt:rego"\]/{f=1} f&&/^run = .{3}$/{c=1;next} c&&/^'"'''"'$/{exit} c' mise.toml)
}

@test "both task bodies were found at all — this suite is not passing vacuously" {
	[ -n "$CHECK" ]
	[ -n "$FIX" ]
	[[ "$CHECK" == *"opa fmt"* ]]
	[[ "$FIX" == *"opa fmt"* ]]
}

@test "THE FIXTURE HAZARD: an unparseable .rego outside git's index is never judged" {
	# `lint:toml`'s reason, on this format: the suites write deliberately broken
	# fixtures under `target/`, and a gate that fails on its own test data is a
	# gate someone switches off. Unparseable rather than merely misformatted,
	# because that is the case a tree walk could not survive quietly — `opa fmt`
	# errors on it, so a walking gate would red rather than reformat.
	local fixture="target/tmp/lint-rego-fixture"
	mkdir -p "$fixture"
	printf 'this is not = = rego\n' >"$fixture/broken.rego"
	run mise run lint:rego
	rm -rf "$fixture"
	[ "$status" -eq 0 ]
	[[ "$output" != *"broken.rego"* ]]
}

@test "the selection is git's index, piped — never a command substitution over -z" {
	# The NUL-stripping bug. `files=$(git ls-files -z ...)` is the shape that
	# looks equivalent and is not; bash drops the NULs, so every path arrives as
	# one argument. Asserted over both bodies, since the fixer selecting a wider
	# set than the checker would repair a fixture the suite wrote to be broken.
	local body
	for body in "$CHECK" "$FIX"; do
		[[ "$body" == *"git ls-files -z '*.rego'"* ]]
		[[ "$body" == *"| xargs -0 -r"* ]]
		# No `$(` on any line that reads the index.
		! grep -qE '\$\(\s*git ls-files' <<<"$body"
	done
}

@test "the check reports every unformatted file, so it does not pass --fail" {
	[[ "$CHECK" != *"--fail"* ]]
	[[ "$CHECK" == *"opa fmt -l"* ]]
}

@test "the fixer writes in place and the checker never does" {
	[[ "$FIX" == *"opa fmt -w"* ]]
	[[ "$CHECK" != *"-w"* ]]
}

@test "a clean corpus passes, and says so rather than passing silently" {
	run mise run lint:rego
	[ "$status" -eq 0 ]
	[[ "$output" == *"every tracked Rego module is formatted"* ]]
}
