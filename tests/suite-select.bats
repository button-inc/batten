#!/usr/bin/env bats
# subject: mise-tasks/suite-select.sh
#
# The probes ARE the deliverable here, not the selector (CLOUD-886 §7).
#
# A selection that is too WIDE costs money and shows up in the bill. A selection
# that is too NARROW has no symptom at all: the suites do not run, the count
# matches whatever was selected, and a regression lands green. So the
# narrow-selection probe is the one that must be shown able to fail, because it is
# the direction nothing else would ever notice.

setup() {
	load helpers

	SELECT="$BATS_TEST_DIRNAME/../mise-tasks/suite-select.sh"

	# A whole repository, because the selector reads `# subject:` headers out of
	# tracked files and a diff out of git. A fixture with mocked-out git would be
	# testing a different program.
	FIX="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$FIX/mise-tasks" "$FIX/tests"

	# THE TOKEN IS ASSEMBLED, NEVER WRITTEN LITERALLY, and this cost a real
	# debugging detour worth recording. bats preprocesses its own suite file by
	# rewriting every line that STARTS with the case keyword — and it does not
	# care that the line is inside a quoted heredoc. So a fixture written with the
	# keyword at column zero arrives already rewritten into
	# `bats_test_function ...`, the counter finds zero cases, and the failure looks
	# like a bug in the selector rather than in the fixture that feeds it.
	local case="@te"'st'
	fixture_suite() { # fixture_suite <path> <subject> <case-name>...
		local path="$1" subject="$2" name
		shift 2
		{
			echo "#!/usr/bin/env bats"
			echo "# subject: $subject"
			echo
			for name in "$@"; do
				echo "$case \"$name\" { [ 1 -eq 1 ]; }"
			done
		} >"$FIX/$path"
	}

	fixture_suite tests/alpha.bats mise-tasks/alpha "alpha does its thing" "alpha does its other thing"
	fixture_suite tests/alpha-lock.bats mise-tasks/alpha-lock "the lease is held"
	fixture_suite tests/gamma.bats mise.toml "the gate runs"
	cat >"$FIX/tests/helpers.bash" <<'HELP'
# sourced widely
HELP
	printf 'land\n' >"$FIX/mise-tasks/alpha"
	printf 'lock\n' >"$FIX/mise-tasks/alpha-lock"
	printf 'version = 1\n' >"$FIX/mise.toml"
	printf 'orphan\n' >"$FIX/mise-tasks/orphan-gate"

	(
		cd "$FIX" || exit 1
		GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git init -q -b main .
		git config user.email t@example.com
		git config user.name t
		git add -A
		git commit -qm base
		# The trunk this compares against. A branch off it is what a real run sees.
		git branch -f trunk main
	)
}

select_with() { # select_with <changed-path>...
	local path
	for path in "$@"; do
		printf 'a change\n' >>"$FIX/$path"
	done
	(cd "$FIX" && BASE_SHA=trunk "$SELECT" 2>/dev/null)
}

reason_for() { # reason_for <changed-path>...
	local path
	for path in "$@"; do
		printf 'a change\n' >>"$FIX/$path"
	done
	(cd "$FIX" && BASE_SHA=trunk "$SELECT" 2>&1 >/dev/null)
}

# --- the narrow direction: the one with no symptom -------------------------

@test "THE PROBE: a change to one program selects that program's suite and no others" {
	# CLOUD-886's measured case, in miniature. On the real tree this is
	# tests/alpha.bats at 141.5s instead of 1,188s.
	run select_with mise-tasks/alpha
	[ "$status" -eq 0 ]
	[ "$output" = "tests/alpha.bats" ]
}

@test "a subject match is a whole field, not a substring" {
	# `mise-tasks/alpha` must not select `land-lock`'s suite. A substring test
	# would, and it would be invisible: the run is WIDER than needed, so nothing
	# fails — it just quietly costs more, which is the failure this whole row is
	# about, one level down.
	run select_with mise-tasks/alpha
	[ "$status" -eq 0 ]
	[[ "$output" != *"land-lock"* ]]
}

@test "a changed suite selects itself" {
	run select_with tests/alpha-lock.bats
	[ "$status" -eq 0 ]
	[ "$output" = "tests/alpha-lock.bats" ]
}

@test "two changed programs select both suites, sorted" {
	run select_with mise-tasks/alpha mise-tasks/alpha-lock
	[ "$status" -eq 0 ]
	[ "$output" = "tests/alpha-lock.bats
tests/alpha.bats" ]
}

# --- the wide direction, and every reason it is taken ---------------------

@test "a shared input runs everything" {
	# `mise.toml` defines the tasks every suite invokes. Subject-intersection
	# alone would select only the one suite naming it and skip the rest, which is
	# strictly worse than running all of them.
	run select_with mise.toml
	[ "$status" -eq 0 ]
	[[ "$output" == *"tests/alpha.bats"* ]]
	[[ "$output" == *"tests/alpha-lock.bats"* ]]
	[[ "$output" == *"tests/gamma.bats"* ]]
}

@test "the helpers file runs everything, because it is sourced widely" {
	run select_with tests/helpers.bash
	[ "$status" -eq 0 ]
	[[ "$output" == *"tests/alpha.bats"* ]]
	[[ "$output" == *"tests/gamma.bats"* ]]
}

@test "a path outside the reasonable set runs everything" {
	# A crate source can move any suite that drives the binary, and this selector
	# knows nothing about which. Could-not-look widens.
	mkdir -p "$FIX/crates/batten/src"
	run select_with crates/batten/src/lib.rs
	[ "$status" -eq 0 ]
	[[ "$output" == *"tests/alpha.bats"* ]]
	[[ "$output" == *"tests/gamma.bats"* ]]
}

@test "a program no suite declares runs everything" {
	# A header that rotted, or a program nothing covers. Either way this cannot
	# say which suites it moves — and reading that as "no suites" would be the
	# narrow failure with no symptom.
	run select_with mise-tasks/orphan-gate
	[ "$status" -eq 0 ]
	[[ "$output" == *"tests/alpha.bats"* ]]
	[[ "$output" == *"tests/gamma.bats"* ]]
}

@test "an unresolvable base runs everything rather than guessing" {
	printf 'a change\n' >>"$FIX/mise-tasks/alpha"
	run bash -c "cd '$FIX' && BASE_SHA=refs/heads/nonexistent '$SELECT' 2>/dev/null"
	[ "$status" -eq 0 ]
	[[ "$output" == *"tests/gamma.bats"* ]]
}

@test "every wide run says why, as a pointer" {
	# A wide run with no stated cause is indistinguishable from a selector that is
	# not working. The reason names the path and the class; it never carries a
	# diff or a case name (rule 4).
	run reason_for mise.toml
	[[ "$output" == *"running every suite"* ]]
	[[ "$output" == *"mise.toml"* ]]
	[[ "$output" != *"a change"* ]]
}

# --- the anti-vacuity assertion moves with the selection -----------------

@test "the case count of a narrow selection is the selected suites' own" {
	# CLOUD-386's `ran == expected` exists to catch "a suite that got faster by
	# running fewer tests", which is exactly what selection does on purpose. So
	# `expected` has to be computed from the SELECTED set by the same map that
	# chose it — an expected derived from a second list would be the defect
	# wearing the fix's clothes. Asserted here as the property test:bats depends
	# on: the selected suites carry a countable, non-total number of cases.
	run select_with mise-tasks/alpha
	[ "$status" -eq 0 ]
	# COUNTED FROM TRACKED CONTENT, and that is not incidental: writing this
	# against the working copy failed, because bats preprocesses a `.bats` file it
	# is handed — `@test` becomes `bats_test_function` — and a fixture suite can be
	# rewritten under the counter. `test:bats` computes `expected` BEFORE bats
	# runs, so it is safe there either way; here the INDEX is read (`--cached`)
	# because that is the one copy a preprocessor cannot have touched.
	local expected
	expected=$(cd "$FIX" && git grep --cached -c '^@test ' -- $output | awk -F: '{s+=$NF} END{print s+0}')
	[ "$expected" -eq 2 ]

	# And the total is strictly larger, so a count taken over everything would
	# not have discriminated.
	local total
	total=$(cd "$FIX" && git grep --cached -c '^@test ' -- 'tests/*.bats' | awk -F: '{s+=$NF} END{print s+0}')
	[ "$total" -gt "$expected" ]
}
