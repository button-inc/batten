#!/usr/bin/env bats
# The gate that ships with the license-table release precondition (CLOUD-325).
#
# The precondition was prose for the table's whole life and nothing failed while
# three of five rows were unresolved. These cases pin the two directions that
# matter: an open row must fail, and a resolved table must pass — plus the
# vacuous case, where a table the parser cannot find would otherwise satisfy
# every per-row assertion by having no rows to check.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/license-table-check"
	cd "$BATS_TEST_DIRNAME/.." || return 1
}

# A table with the same shape as the real one, so a fixture exercises the parser
# rather than a simplified stand-in.
write_table() {
	# $1 = destination, $2 = license cell, $3 = compatibility cell
	cat >"$1" <<EOF
## License compatibility of adopted tools

Preamble prose that is not a row.

| Tool       | Role                      | License           | Compatible with Apache-2.0 |
| ---------- | ------------------------- | ----------------- | -------------------------- |
| cargo-deny | dependency severity model | Apache-2.0 OR MIT | ✅                         |
| sample     | a role                    | $2 | $3 |

Trailing prose.
EOF
}

@test "the repo as it stands passes" {
	run "$CHECK"
	[ "$status" -eq 0 ]
}

@test "the gate is wired: hk.pkl declares a step that runs this task" {
	# Asserted on the step block, not a bare grep: the surrounding comment names
	# the task too, and a comment is not a call site. A suite that passes while
	# nothing invokes the task measures only itself.
	run awk '/^  \["license-table-check"\] \{$/ { found = 1; next }
	         found && /mise run license-table-check/ { print "wired"; exit }
	         found && /^  \}$/ { exit }' hk.pkl
	[ "$status" -eq 0 ]
	[ "$output" = "wired" ]
}

@test "an unresolved license fails, and names the tool" {
	write_table "$BATS_TEST_TMPDIR/t.md" "_to confirm_" "_to confirm_"
	run "$CHECK" "$BATS_TEST_TMPDIR/t.md"
	[ "$status" -ne 0 ]
	[[ "$output" == *"sample"* ]]
}

@test "a resolved license with an unresolved verdict still fails" {
	# The two columns are separate claims: knowing the license does not settle
	# whether it is compatible with ours.
	write_table "$BATS_TEST_TMPDIR/t.md" "MIT" "_to confirm_"
	run "$CHECK" "$BATS_TEST_TMPDIR/t.md"
	[ "$status" -ne 0 ]
}

@test "a verdict outside the closed set fails rather than passing" {
	# "Some other marker" is how an unresolved row slips past a check that only
	# looks for the literal placeholder.
	write_table "$BATS_TEST_TMPDIR/t.md" "MIT" "probably?"
	run "$CHECK" "$BATS_TEST_TMPDIR/t.md"
	[ "$status" -ne 0 ]
}

@test "a fully resolved fixture passes" {
	write_table "$BATS_TEST_TMPDIR/t.md" "MIT" "✅"
	run "$CHECK" "$BATS_TEST_TMPDIR/t.md"
	[ "$status" -eq 0 ]
}

@test "an explicit incompatible verdict is resolved, and passes" {
	# The gate judges whether the question was answered, not which answer it got.
	# Recording a tool as incompatible is a resolved row.
	write_table "$BATS_TEST_TMPDIR/t.md" "SSPL-1.0" "❌"
	run "$CHECK" "$BATS_TEST_TMPDIR/t.md"
	[ "$status" -eq 0 ]
}

@test "a table with no rows is a failure, not a vacuous pass" {
	printf '# No table here\n\nJust prose.\n' >"$BATS_TEST_TMPDIR/t.md"
	run "$CHECK" "$BATS_TEST_TMPDIR/t.md"
	[ "$status" -ne 0 ]
	[[ "$output" == *"no license rows"* ]]
}

@test "an unreadable file is exit 1 — could not look is not a verdict" {
	run "$CHECK" "$BATS_TEST_TMPDIR/does-not-exist.md"
	[ "$status" -eq 1 ]
}

@test "output is a pointer — it names the tool and the cell, never the table body" {
	write_table "$BATS_TEST_TMPDIR/t.md" "_to confirm_" "_to confirm_"
	run "$CHECK" "$BATS_TEST_TMPDIR/t.md"
	[[ "$output" != *"Preamble prose"* ]]
	[[ "$output" != *"Trailing prose"* ]]
}
