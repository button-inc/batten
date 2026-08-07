#!/usr/bin/env bats
# The gate that ships with `doctor` (AGENTS.md non-negotiable 2). The decision
# under test is the one that cost a session: a rustup target whose FILES are on
# disk while rustup does not consider it installed — the state that turns the
# supposedly-idempotent `rustup target add` into a hard "detected conflict".
#
# Driven against fixture directories rather than a real toolchain, so the suite
# can construct each residue shape (dir only, manifest only, components entry
# only) that a partial install can leave. Every one of them collides with the
# next `add`, so every one of them must read as stale.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/doctor-check"
	RUSTLIB="$BATS_TEST_TMPDIR/rustlib"
	TARGET="aarch64-apple-darwin"
	mkdir -p "$RUSTLIB"
	printf 'rust-std-x86_64-unknown-linux-gnu\n' >"$RUSTLIB/components"
}

# --- ok: rustup has it, which is the only thing that makes a target usable -----

@test "installed target with full residue is ok" {
	mkdir -p "$RUSTLIB/$TARGET/lib"
	touch "$RUSTLIB/manifest-rust-std-$TARGET"
	printf 'rust-std-%s\n' "$TARGET" >>"$RUSTLIB/components"
	run "$CHECK" "$RUSTLIB" "$TARGET" yes
	[ "$status" -eq 0 ]
	[ "$output" = "ok" ]
}

@test "installed target is ok even with no residue on disk" {
	# rustup's answer is the truth; the files are what lie.
	run "$CHECK" "$RUSTLIB" "$TARGET" yes
	[ "$status" -eq 0 ]
	[ "$output" = "ok" ]
}

# --- missing: a plain add works ----------------------------------------------

@test "absent target with no residue is missing" {
	run "$CHECK" "$RUSTLIB" "$TARGET" no
	[ "$status" -eq 0 ]
	[ "$output" = "missing" ]
}

@test "another target's residue does not make this one stale" {
	mkdir -p "$RUSTLIB/x86_64-pc-windows-gnu/lib"
	touch "$RUSTLIB/manifest-rust-std-x86_64-pc-windows-gnu"
	run "$CHECK" "$RUSTLIB" "$TARGET" no
	[ "$status" -eq 0 ]
	[ "$output" = "missing" ]
}

# --- stale: every residue shape that collides with `rustup target add` --------

@test "target dir without rustup knowing is stale" {
	mkdir -p "$RUSTLIB/$TARGET/lib"
	touch "$RUSTLIB/$TARGET/lib/libaddr2line-ca30e0d5b6ed0ca3.rlib"
	run "$CHECK" "$RUSTLIB" "$TARGET" no
	[ "$status" -eq 0 ]
	[ "$output" = "stale" ]
}

@test "leftover per-component manifest is stale" {
	# The second conflict of the live failure: purging the lib dir alone left
	# this behind, and the next add died on the manifest instead.
	touch "$RUSTLIB/manifest-rust-std-$TARGET"
	run "$CHECK" "$RUSTLIB" "$TARGET" no
	[ "$status" -eq 0 ]
	[ "$output" = "stale" ]
}

@test "components entry alone is stale" {
	printf 'rust-std-%s\n' "$TARGET" >>"$RUSTLIB/components"
	run "$CHECK" "$RUSTLIB" "$TARGET" no
	[ "$status" -eq 0 ]
	[ "$output" = "stale" ]
}

@test "components entry matches whole lines only" {
	# A substring match would read rust-std-aarch64-apple-darwin-sim as residue
	# for aarch64-apple-darwin and purge a target nobody asked about.
	printf 'rust-std-%s-sim\n' "$TARGET" >>"$RUSTLIB/components"
	run "$CHECK" "$RUSTLIB" "$TARGET" no
	[ "$status" -eq 0 ]
	[ "$output" = "missing" ]
}

# --- DOCTOR_TARGETS: which targets doctor is responsible for ------------------
#
# Driven against the real `doctor` rather than doctor-check, because the thing
# under test is the parameter expansion, not the verdict. Safe to run for real:
# with no targets there is no rustup work to do, and the submodule half is
# idempotent.

@test "an empty DOCTOR_TARGETS asks for no rust targets at all" {
	# `-` and not `:-`. CI's `ci` job runs test:bats, which needs the submodule
	# half and none of the rustup half — cross-check and darwin-link are their
	# own jobs. With `:-` an empty value would silently take the default pair
	# and download two std libs that job never uses.
	DOCTOR_TARGETS="" run "$BATS_TEST_DIRNAME/../mise-tasks/doctor"
	[ "$status" -eq 0 ]
	[[ "$output" == *"bats submodule checked out"* ]]
	[[ "$output" != *"rust target"* ]]
}

@test "an unset DOCTOR_TARGETS still takes the default pair" {
	# The local lifecycle depends on this default; only an explicit empty value
	# opts out.
	run env -u DOCTOR_TARGETS "$BATS_TEST_DIRNAME/../mise-tasks/doctor"
	[[ "$output" == *"x86_64-pc-windows-gnu"* ]]
	[[ "$output" == *"aarch64-apple-darwin"* ]]
}

# --- usage --------------------------------------------------------------------

@test "rejects a missing installed argument" {
	run "$CHECK" "$RUSTLIB" "$TARGET"
	[ "$status" -eq 2 ]
}

@test "rejects a non-boolean installed argument" {
	run "$CHECK" "$RUSTLIB" "$TARGET" maybe
	[ "$status" -eq 2 ]
}
