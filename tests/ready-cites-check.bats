#!/usr/bin/env bats
# subject: mise-tasks/ready-cites-check
# CLOUD-826's decision table: a Ready block's citations against the tree.
#
# The two CLOUD-740 fixtures are FETCHED, not invented — `tests/fixtures/
# ready-cites-check/` holds the row's own body and its own superseded block, as
# the tracker returned them. That matters for the vacuity case below, which is
# only red because the real tree really does carry a fixture quoting the citation.

setup() {
	GATE="$BATS_TEST_DIRNAME/../mise-tasks/ready-cites-check"
	REPO="$BATS_TEST_DIRNAME/.."
	FIX="$BATS_TEST_DIRNAME/fixtures/ready-cites-check"
	# THE SUITE MUST NOT SATISFY ITS OWN CITATIONS. The two cases below run against
	# the REAL tree, and this file is a tracked file under `tests/` — so a citation
	# token written here whole would be resolved BY the assertion that says it does
	# not resolve, which is the vacuity the gate exists to refuse, occurring inside
	# the suite that tests for it. Each token is assembled from halves instead, so
	# no line of this file matches one.
	SNAPSHOT_CITE="a_snapshot_captures_a_dirty_tree""_and_nothing_else"
	WORKTREE_CITE="the_worktree_listing_reads""_gits_own_attributes"
}

# A synthetic corpus: a real git repo, so `git ls-files` has something to answer
# with, and nothing of this repository's own text can satisfy a citation.
synthetic() {
	ROOT="$BATS_TEST_TMPDIR/root"
	mkdir -p "$ROOT/crates/batten/src" "$ROOT/tests/fixtures/quoted"
	printf 'fn a_real_test_that_exists_here() {}\n' >"$ROOT/crates/batten/src/git.rs"
	printf 'a note quoting `only_in_a_fixture_and_nowhere_else` and nothing more\n' \
		>"$ROOT/tests/fixtures/quoted/CLOUD-999.md"
	git -C "$ROOT" init -q
	git -C "$ROOT" add -A
	git -C "$ROOT" -c user.email=t@example.invalid -c user.name=t commit -qm init
}

# Writes a payload whose live Ready block carries $1 as its §7 body.
block7() {
	PAYLOAD="$BATS_TEST_TMPDIR/p.json"
	local d
	d=$(printf '**Why**\nSomething needs doing.\n\n**Refinement — Ready**\n\n* **Source of truth (§1).** One artifact.\n* **Test obligation (§7).** %s\n* **Blockers (§8).** None.\n' "$1")
	jq -nc --arg d "$d" '{id: "CLOUD-999", description: $d}' >"$PAYLOAD"
}

at_root() { run env READY_CITES_ROOT="$ROOT" "$GATE" <"$PAYLOAD"; }

# --- the discriminating case, on the real board and the real tree -------------
#
# CLOUD-740's SUPERSEDED §7 demands two tests CLOUD-780 deleted. One is absent
# everywhere; the other resolves ONLY in `tests/fixtures/board-diff-overlap/
# CLOUD-740.md`, a copy of the row's own prose. Both must be named.

@test "CLOUD-740's superseded §7 names two tests the tree does not carry" {
	run bash -c "'$GATE' <'$FIX/CLOUD-740-superseded.json'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$WORKTREE_CITE absent-cited-test"* ]]
	[[ "$output" == *"$SNAPSHOT_CITE absent-cited-test"* ]]
}

@test "a citation resolving only under tests/fixtures is refused" {
	# The vacuity guard, isolated. The snapshot citation has exactly one match in
	# this repository, and it is a fixture QUOTING the citation. A gate that resolved a citation against a quotation of the citation
	# would be CLOUD-418's shape occurring inside the gate written to prevent it.
	run bash -c "git grep -lF '$SNAPSHOT_CITE' -- crates tests"
	[ "$status" -eq 0 ]
	# EVERY match is under `tests/fixtures/` — the excluded region. The count is not
	# pinned, because this row's own fetched payloads live there too and quoting the
	# citation is what a fetched payload does; what must hold is that nothing
	# OUTSIDE the exclusion carries it, which is the whole of the vacuity claim.
	[[ "$output" == *"tests/fixtures/board-diff-overlap/CLOUD-740.md"* ]]
	while IFS= read -r match; do
		[[ "$match" == tests/fixtures/* ]]
	done <<<"$output"
	run bash -c "'$GATE' <'$FIX/CLOUD-740-superseded.json'"
	[ "$status" -eq 1 ]
	[[ "$output" == *"$SNAPSHOT_CITE"* ]]
}

@test "a body with a superseded block and a live one is judged on the live one" {
	# CLOUD-740's whole body, as the tracker returns it. The stale citations are in
	# the superseded block and carry no obligation; the live block's do resolve.
	# `ready-lint` takes the FIRST opener and this takes the LAST, which is the one
	# place the two gates deliberately differ.
	run bash -c "'$GATE' <'$FIX/CLOUD-740-live.json'"
	[ "$status" -eq 0 ]
}

# --- the synthetic decision table --------------------------------------------

@test "a §7 citing a test that exists passes" {
	synthetic
	block7 'The case `a_real_test_that_exists_here` still holds.'
	at_root
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 of 1 citation(s) resolve"* ]]
}

@test "a §7 citing no candidate passes and reports zero resolved" {
	# Vacuity is legitimate — a §7 naming no test symbol is a perfectly good §7 —
	# so the guard is visibility rather than refusal: a `0` is legible, not silent.
	synthetic
	block7 'End-to-end over the compiled binary, shown able to fail.'
	at_root
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 of 0 citation(s) resolve"* ]]
}

@test "a one-underscore API name is not a citation" {
	# The false-positive guard, and the case that must fail if the threshold is
	# wrong: `check_ignore`, `stash_create` and `update_ref` are API names, not the
	# repository's test-naming shape. A looser rule would refuse an honest §7.
	synthetic
	block7 'The `check_ignore` and `update_ref` paths keep their behaviour.'
	at_root
	[ "$status" -eq 0 ]
	[[ "$output" == *"0 of 0 citation(s) resolve"* ]]
}

@test "a cited path that does not exist is refused" {
	synthetic
	block7 'Cases live in `tests/no_such_suite.bats`.'
	at_root
	[ "$status" -eq 1 ]
	[[ "$output" == *"tests/no_such_suite.bats absent-cited-path"* ]]
}

@test "a cited path that exists passes" {
	synthetic
	block7 'The subject is `crates/batten/src/git.rs`.'
	at_root
	[ "$status" -eq 0 ]
	[[ "$output" == *"1 of 1 citation(s) resolve"* ]]
}

@test "a test name cited outside §7 is not judged" {
	# The span is bounded on purpose: a greedier one would sweep later sections and
	# read an unrelated backticked symbol as a test obligation.
	synthetic
	PAYLOAD="$BATS_TEST_TMPDIR/p.json"
	local d
	d=$(printf '**Refinement — Ready**\n\n* **Source of truth (§1).** One artifact.\n* **Test obligation (§7).** Nothing named.\n* **Blockers (§8).** None. See `a_name_that_is_absent_entirely` for context.\n')
	jq -nc --arg d "$d" '{id: "CLOUD-999", description: $d}' >"$PAYLOAD"
	at_root
	[ "$status" -eq 0 ]
}

@test "the report carries no line of the block and no line of a source file" {
	# Pointer-only per non-negotiable rule 4: the key, the clause, the token, a
	# count. An issue body can carry customer detail and a source line can carry a
	# secret; this gate reads both.
	synthetic
	block7 'ACME-12345 is the account. The case `a_name_that_is_absent_entirely` holds.'
	at_root
	[ "$status" -eq 1 ]
	[[ "$output" != *"ACME-12345"* ]]
	[[ "$output" != *"is the account"* ]]
	[[ "$output" != *"fn a_real_test_that_exists_here"* ]]
}

@test "the report is byte-stable across runs" {
	synthetic
	block7 'The cases `a_name_that_is_absent_entirely` and `another_name_absent_as_well` hold.'
	at_root
	local first="$output"
	at_root
	[ "$output" = "$first" ]
}

# --- could not look ----------------------------------------------------------

@test "empty stdin is exit 2, never a verdict" {
	synthetic
	run bash -c "env READY_CITES_ROOT='$ROOT' '$GATE' </dev/null"
	[ "$status" -eq 2 ]
}

@test "stdin that is not a payload is exit 2" {
	synthetic
	printf 'not json' >"$BATS_TEST_TMPDIR/junk"
	run bash -c "env READY_CITES_ROOT='$ROOT' '$GATE' <'$BATS_TEST_TMPDIR/junk'"
	[ "$status" -eq 2 ]
}

@test "a root that is not a repository is exit 2, never a pass" {
	# A gate that cannot resolve the tree must refuse rather than report clean —
	# an empty corpus would make every citation resolve nothing, or nothing at all.
	block7 'The case `a_real_test_that_exists_here` still holds.'
	mkdir -p "$BATS_TEST_TMPDIR/bare"
	run bash -c "env READY_CITES_ROOT='$BATS_TEST_TMPDIR/bare' '$GATE' <'$PAYLOAD'"
	[ "$status" -eq 2 ]
}

@test "a body with no Ready block is not this gate's business" {
	# `ready-lint` already reports `no-ready-block`; a second gate reporting the
	# same fact would be a second authority over one question.
	synthetic
	PAYLOAD="$BATS_TEST_TMPDIR/p.json"
	jq -nc '{id: "CLOUD-999", description: "Just a description."}' >"$PAYLOAD"
	at_root
	[ "$status" -eq 0 ]
}
