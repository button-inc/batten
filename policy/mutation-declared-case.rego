# A declared mutation names a case its suite actually has (CLOUD-1355).
#
# THE DEFECT, MEASURED. `mise run mutant` reports `names-no-case` when a
# mutation's declared case selects nothing, and that sweep runs ONLY from
# `.github/workflows/mutant.yml` on a `schedule` -- not in `verify`, not in the
# `hk` gate, not on any `pull_request`. So a declaration could name a case that
# never existed and nothing a contributor runs would say so. Measured
# 2026-09-02: the nightly had been red since its first recorded run, on two such
# rows, and `policy/harness-wiring.rego`'s named the LOAD-TIME tier's `test_`
# rule where its own `#MUTANT-SUITE` resolves the COMPILED one.
#
# The sweep is nightly because it STAGES A TREE and RUNS A SUITE per mutation.
# Asking whether a declaration RESOLVES costs neither: the declaring file's rows
# and the suite's case titles are both lines this engine already acquires. That
# is the whole argument for a second reader rather than a wider sweep -- one
# question is expensive and one is free, and only the free one can be asked
# every time.
#
# `mise run mutant` still owns APPLYING a mutation and deciding whether the case
# it names can actually fail. This owns only whether the case exists.
#
# WHAT IT DELIBERATELY DOES NOT JUDGE, because judging it would make this a
# second authority over `mutate.rs`'s mapping. A file carrying `#MUTANT` rows
# and NO `#MUTANT-SUITE` gets the runner's default, and that default is derived
# from the gate's name rather than from the file's path -- a task name carries
# no extension, a preset is a directory, and a module's stem is not its gate.
# Re-deriving it here would put two spellings of one mapping in the tree, which
# is the defect the `[[pattern]]` registry exists to make unwritable one layer
# over. So a declaration reaches this rule only when its own file names the
# suite, and the sweep stays the authority for the rest.
#
# The live instance that leaves uncaught is named rather than glossed over:
# `mise-tasks/graph-check.sh`'s `receipt-carries-no-ids` declares no suite, and
# both its declaration and the bats title it has drifted from are in files
# `shell-retirement` admits only retiring whole. It stays blocked on that
# retirement, which is CLOUD-843's queue.
#
# POINTER-ONLY (non-negotiable rule 4). The finding carries the declaring file
# and the suite path, never the case body and never the mutation's `sed`
# program -- which is the one field here that is arbitrary text.
#MUTANT-SUITE crates/batten/tests/it/mutation_declared_case.rs
#MUTANT unresolved-case-unread|s@^\tnot resolves(entry)$@\tfalse@|a_declaration_naming_a_case_its_suite_lacks_is_refused
#MUTANT every-declaration-reported|s@^\tnot resolves(entry)$@\ttrue@|a_declaration_whose_case_its_suite_has_is_silent

# METADATA
# description: |
#   Bound to the TREE surface: this row is `scope = "tree"`, so it reads
#   `input.tree` and never the mediated call.
#   THIS BLOCK IS YAML AND MUST STAY THE LAST COMMENT BLOCK BEFORE `package`.
# schemas:
#   - input: schema["policy-input.schema"]
package batten.mutation_declared_case

import rego.v1

rules contains "marker name undefined"

# The declared documents, or nothing. ABSENT IS NOT EMPTY: a run acquiring no
# lines has no key here, Rego reads that as *does not hold*, and this module is
# silent rather than reporting every declaration as unresolvable.
lines := input.tree.lines

# The suite a file declares, and UNDEFINED where it declares none.
#
# That undefinedness is the scope narrowing above, expressed structurally rather
# than as a filter somebody can delete: a declaration in a file with no
# `#MUTANT-SUITE` never binds `entry.suite`, so it never reaches the violation.
#
# PER ROW, THE NEAREST ABOVE (CLOUD-2193, as `mutate.rs` judges it): a file may
# declare several suites, and a row above every one keeps the first. One suite
# per file was a function with several outputs on such a file, which faults.
suite_headers(path) := [[j, trim_space(substring(line, count(opener) + count("MUTANT-SUITE "), -1))] |
	some j, line in lines[path]
	some opener in openers
	startswith(line, concat("", [opener, "MUTANT-SUITE "]))
]

# THE OPENERS `mutate.rs`'s `OPENERS` honours, at column zero (#1276). A file
# whose comments are `//` (`hk.pkl`, `hk-fix-selection.pkl`) declares its rows
# with that opener, and reading `#` alone left every one of them unjudged.
# Neither opener is a prefix of the other, so one line matches at most one.
openers := ["#", "//"]

suite_above(path, i) if {
	some header in suite_headers(path)
	header[0] < i
}

declared_suite(path, i) := suite if {
	above := [header | some header in suite_headers(path); header[0] < i]
	count(above) > 0
	suite = above[count(above) - 1][1]
}

declared_suite(path, i) := suite if {
	not suite_above(path, i)
	headers = suite_headers(path)
	count(headers) > 0
	suite = headers[0][1]
}

# Every declaration whose file names a suite, as `{path, suite, case}`.
#
# THE TRAILING SPACE IN THE MARKER IS LOAD-BEARING: `#MUTANT-SUITE`,
# `#MUTANT-OWNER` and `#MUTANT-EXEMPT` all start with `#MUTANT` and none starts
# with `#MUTANT `, so the row marker selects rows and nothing else.
#
# THREE FIELDS, AND ONLY THE THIRD IS READ. The slug and the `sed` program are
# the sweep's business; a module deriving anything from them would be a second
# authority over a format the runner already owns.
declaration contains entry if {
	some path, file_lines in lines
	some i, line in file_lines
	some opener in openers
	startswith(line, concat("", [opener, "MUTANT "]))
	fields := split(line, "|")
	count(fields) == 3
	entry := {
		"path": path,
		"suite": declared_suite(path, i),
		"case": fields[2],
	}
}

# The case as its suite spells it: a qualified `module::case` is a nextest
# filter the sweep selects by its whole path, and the suite holds only the
# last segment.
spelled(entry) := parts[count(parts) - 1] if parts := split(entry.case, "::")

# How a case is spelled in the suite that holds it.
#
# Two suite kinds, and the extension is what tells them apart -- the same axis
# `mutate.rs`'s own `Suite::declared` turns on, so a third kind arriving there
# arrives here as an unmatched extension and this rule goes silent rather than
# refusing something it cannot read.
needle(entry) := sprintf("@test \"%v\"", [entry.case]) if {
	endswith(entry.suite, ".bats")
}

needle(entry) := sprintf("fn %v(", [spelled(entry)]) if {
	endswith(entry.suite, ".rs")
}

# COULD-NOT-LOOK, and it is the ORDINARY state for a suite outside the declared
# document set. A rule reading an unacquired suite as "the case is missing"
# would report a verdict about this run's `line_sources` as a verdict about the
# declaration.
suite_read(entry) if {
	_ = lines[entry.suite]
}

# Whether the declared suite carries a line spelling the declared case.
resolves(entry) if {
	some line in lines[entry.suite]
	contains(line, needle(entry))
}

# OR WHETHER THE MODULE ITSELF DECLARES IT (CLOUD-2255, taught here in CLOUD-2341).
# The sweep judges a `.rego` row by a `test_<case>` rule in the mutated module
# BEFORE it looks at any suite (`mutate.rs`'s `declares_own_case`), so a row
# naming one is resolved wherever its file's `#MUTANT-SUITE` points. Spelled as
# that function spells it — a line opening `test_<case> `.
#
# ONLY UNDER `policy/`, because the runner judges by module only a REGISTERED
# row's module (`lib.rs`'s `policy_case` answers `None` otherwise, and the row
# falls back to its suite), and every `policy/*.rego` is a registered row while
# a preset under `crates/batten/src/policy/presets/` is loaded another way.
# Without the prefix a preset row naming its own `test_` rule would read as
# resolved here and as `names-no-case` in the sweep (code review of CLOUD-2341).
#MUTANT own-case-unread|s@^\tstartswith(line, sprintf("test_%v ", \[entry.case\]))$@\tfalse@|a_declaration_naming_its_own_modules_case_is_silent
#MUTANT own-case-unregistered|s@^\tstartswith(entry.path, "policy/")$@\ttrue@|a_presets_own_case_is_still_judged_by_its_suite
resolves(entry) if {
	startswith(entry.path, "policy/")
	endswith(entry.path, ".rego")
	some line in lines[entry.path]
	startswith(line, sprintf("test_%v ", [entry.case]))
}

# A declaration whose suite was read and does not carry its case.
#
# ONE FINDING PER DECLARATION, so a reviewer sees which promise is unresolvable
# rather than a count to reconstruct. The declaring file leads, because that is
# what a reader opens to fix it; the suite follows as the place the case was
# looked for.
violation contains {
	"rule": "marker name undefined",
	"verdict": "marker name undefined",
	"subjects": [{"path": entry.path}, {"path": entry.suite}],
} if {
	some entry in declaration
	suite_read(entry)
	not resolves(entry)
}

# The predicate's own tests. The SILENT cases carry the weight: every
# could-not-look above is a pass-side property, and a rule firing on every
# declaration would satisfy the deny while deciding nothing.

tree(lines_by_file) := {"tree": {"lines": lines_by_file}}

rust_suite := {
	"policy/a.rego": [
		"#MUTANT-SUITE crates/batten/tests/it/a.rs",
		"#MUTANT slug|s@a@b@|a_case_that_exists",
	],
	"crates/batten/tests/it/a.rs": ["fn a_case_that_exists() {"],
}

test_a_declaration_whose_suite_carries_its_case_is_silent if {
	count(violation) == 0 with input as tree(rust_suite)
}

# THE NEAREST SUITE ABOVE, as the sweep judges it (`mutate.rs`, CLOUD-2193). A
# file declaring two suites made the one-suite-per-file function fault, so the
# interpreter answered could-not-look and the gate decided nothing; bytecode
# evaluated it and refused correct rows (#1276: `lock-complete.rego`,
# `mise.toml`). A row above every declaration keeps the first.
test_a_row_is_judged_under_the_suite_above_it if {
	count(violation) == 0 with input as tree({
		"policy/a.rego": [
			"#MUTANT-SUITE crates/batten/tests/it/first.rs",
			"#MUTANT one|s@a@b@|in_first",
			"#MUTANT-SUITE crates/batten/tests/it/second.rs",
			"#MUTANT two|s@a@b@|in_second",
		],
		"crates/batten/tests/it/first.rs": ["fn in_first() {"],
		"crates/batten/tests/it/second.rs": ["fn in_second() {"],
	})
}

test_a_row_under_the_second_suite_is_not_read_against_the_first if {
	some v in violation with input as tree({
		"policy/a.rego": [
			"#MUTANT-SUITE crates/batten/tests/it/first.rs",
			"#MUTANT-SUITE crates/batten/tests/it/second.rs",
			"#MUTANT two|s@a@b@|in_first",
		],
		"crates/batten/tests/it/first.rs": ["fn in_first() {"],
		"crates/batten/tests/it/second.rs": ["fn in_second() {"],
	})
	v.subjects[1].path == "crates/batten/tests/it/second.rs"
}

# A QUALIFIED CASE is a nextest filter the sweep selects by its whole path
# (`land_divergence::a_case`), so the suite spells it by its last segment.
test_a_qualified_case_resolves_by_its_last_segment if {
	count(violation) == 0 with input as tree({
		"policy/a.rego": [
			"#MUTANT-SUITE crates/batten/tests/it/a.rs",
			"#MUTANT slug|s@a@b@|a::a_case_that_exists",
		],
		"crates/batten/tests/it/a.rs": ["fn a_case_that_exists() {"],
	})
}

test_a_declaration_naming_a_case_the_suite_lacks_is_refused if {
	some v in violation with input as tree({
		"policy/a.rego": [
			"#MUTANT-SUITE crates/batten/tests/it/a.rs",
			"#MUTANT slug|s@a@b@|a_case_nobody_wrote",
		],
		"crates/batten/tests/it/a.rs": ["fn a_case_that_exists() {"],
	})
	v.verdict == "marker name undefined"
}

# The bats spelling, which is a different needle and not a second copy of the
# case above: a `.rs` suite matched by the `@test` needle would pass vacuously.
test_a_bats_suite_is_matched_on_its_own_spelling if {
	count(violation) == 0 with input as tree({
		"mise-tasks/a.sh": [
			"#MUTANT-SUITE tests/a.bats",
			"#MUTANT slug|s@a@b@|a case that exists",
		],
		"tests/a.bats": ["@test \"a case that exists\" {"],
	})
}

test_a_bats_declaration_naming_a_missing_title_is_refused if {
	some v in violation with input as tree({
		"mise-tasks/a.sh": [
			"#MUTANT-SUITE tests/a.bats",
			"#MUTANT slug|s@a@b@|a case nobody wrote",
		],
		"tests/a.bats": ["@test \"a case that exists\" {"],
	})
	v.verdict == "marker name undefined"
}

# THE SCOPE NARROWING, asserted rather than described: a file declaring no
# suite contributes no declaration, so the default mapping stays the sweep's.
test_a_declaration_whose_file_names_no_suite_is_not_judged if {
	count(violation) == 0 with input as tree({"mise-tasks/a.sh": ["#MUTANT slug|s@a@b@|a case nobody wrote"]})
}

# COULD-NOT-LOOK: a suite outside this run's declared documents.
test_a_suite_this_run_did_not_read_is_not_judged if {
	count(violation) == 0 with input as tree({"policy/a.rego": [
		"#MUTANT-SUITE crates/batten/tests/it/a.rs",
		"#MUTANT slug|s@a@b@|a_case_nobody_wrote",
	]})
}

# THE `//` OPENER: a row and its suite declared with it are judged exactly as
# the `#` spelling is.
test_a_slash_opened_declaration_naming_a_missing_case_is_refused if {
	some v in violation with input as tree({
		"hk.pkl": [
			"//MUTANT-SUITE crates/batten/tests/it/a.rs",
			"//MUTANT slug|s@a@b@|a_case_nobody_wrote",
		],
		"crates/batten/tests/it/a.rs": ["fn a_case_that_exists() {"],
	})
	v.subjects[0].path == "hk.pkl"
}

# The other markers are not rows, and a rule reading them as rows would find
# two fields where it wanted three and either refuse or, worse, judge the
# owner's prose as a case name.
test_the_sibling_markers_are_not_read_as_rows if {
	count(violation) == 0 with input as tree({
		"policy/a.rego": [
			"#MUTANT-SUITE crates/batten/tests/it/a.rs",
			"#MUTANT-OWNER CLOUD-1|the tier this names drives the fact",
			"#MUTANT-EXEMPT CLOUD-2|no suite can redden this",
		],
		"crates/batten/tests/it/a.rs": ["fn a_case_that_exists() {"],
	})
}

# ANTI-VACUITY over the whole set: a run that acquired nothing is silent, and
# without this the silent cases above are all satisfied by a rule that never
# fires at all.
test_the_deny_arm_is_reachable_at_all if {
	count(violation) == 1 with input as tree({
		"policy/a.rego": [
			"#MUTANT-SUITE crates/batten/tests/it/a.rs",
			"#MUTANT slug|s@a@b@|a_case_nobody_wrote",
		],
		"crates/batten/tests/it/a.rs": ["fn a_case_that_exists() {"],
	})
}
