#!/usr/bin/env bats
# subject: mise-tasks/no-doctests
# The gate that ships with the nextest swap (AGENTS.md non-negotiable 2,
# CLOUD-813). `[tasks."test:cargo"]` runs `cargo nextest run`, which does not
# execute doctests. That was safe to land only because the class is empty here —
# `cargo test --doc --workspace` reported `0 passed; 0 failed` on 2026-08-21 —
# and an empty class is a measurement, not an invariant.
#
# The failure it exists to catch is silent and is the worst shape a test can
# take: a doc example that never runs, which a reader trusts precisely because it
# is executable. Nothing else in the tree would go red.
#
# Driven against fixture trees rather than the real crate, so the suite can hold
# a fence the committed tree must never contain. The committed tree is asserted
# too — that row is the regression test for the workspace itself.

setup() {
	load helpers
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/no-doctests"
	REPO="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$REPO/crates/x/src"
	cd "$REPO" || return 1
	git init -q .
	git config user.email t@example.com
	git config user.name t
}

# Writes lib.rs, tracks it, and answers from the fixture root.
fixture() {
	printf '%s\n' "$1" >"$REPO/crates/x/src/lib.rs"
	git -C "$REPO" add -A
}

@test "the committed workspace carries no runnable doctest" {
	cd "$BATS_TEST_DIRNAME/.." || return 1
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"no runnable doctest fence"* ]]
}

@test "an unattributed fence in a doc comment is refused" {
	# The discriminating row: this is the shape that compiles and runs under
	# `cargo test` and is skipped entirely by nextest.
	fixture '/// Example
/// ```
/// let a = 1;
/// ```
pub fn f() {}'
	run "$CHECK" crates
	[ "$status" -eq 1 ]
	[[ "$output" == *"crates/x/src/lib.rs:2"* ]]
	[[ "$output" == *"info=(none)"* ]]
}

@test "the refusal is a pointer, never the example" {
	# Non-negotiable 4: a doc example can carry anything its author wrote.
	fixture '/// Example
/// ```
/// let the_secret = "hunter2";
/// ```
pub fn f() {}'
	run "$CHECK" crates
	[ "$status" -eq 1 ]
	[[ "$output" != *"hunter2"* ]]
}

@test "a text fence is not a doctest" {
	# Both fences in the committed crate are `text`, which is why the class is
	# empty; a gate that flagged them would be unusable and would get bypassed.
	fixture '//! ```text
//! deny-stop  <=>  at-risk work
//! ```
pub fn f() {}'
	run "$CHECK" crates
	[ "$status" -eq 0 ]
}

@test "ignore, compile_fail and no_run are all non-running" {
	# `no_run` compiles but does not execute, so nextest skipping it costs
	# nothing — the gate is about EXECUTION, not compilation.
	fixture '/// ```ignore
/// one
/// ```
/// ```compile_fail
/// two
/// ```
/// ```no_run
/// three
/// ```
pub fn f() {}'
	run "$CHECK" crates
	[ "$status" -eq 0 ]
}

@test "a closing fence is not read as an unattributed opening one" {
	# THE PARSE THAT MATTERS: a closing fence carries no info string, so a
	# scanner that did not track open/closed would report every `text` block as
	# runnable — and a gate with false positives gets bypassed, which enforces
	# nothing.
	fixture '/// ```text
/// one
/// ```
pub fn f() {}'
	run "$CHECK" crates
	[ "$status" -eq 0 ]
}

@test "a fence outside a doc comment is not a doctest" {
	# A fence in an ordinary `//` comment is prose. rustdoc never sees it.
	fixture '// ```
// let a = 1;
// ```
pub fn f() {}'
	run "$CHECK" crates
	[ "$status" -eq 0 ]
}

@test "a root with no tracked .rs file is could-not-look, not clean" {
	# The anti-vacuity term. A scan matching nothing would report "no runnable
	# doctest" over nothing, which is the reads-as-coverage defect CLOUD-418
	# names — and it is exactly what a moved crate directory would produce.
	git -C "$REPO" rm -q --cached -r . 2>/dev/null || true
	run "$CHECK" crates
	[ "$status" -eq 2 ]
	[[ "$output" == *"could-not-look"* ]]
}

@test "a missing root is could-not-look, not clean" {
	run "$CHECK" nope
	[ "$status" -eq 2 ]
	[[ "$output" == *"could-not-look"* ]]
}
