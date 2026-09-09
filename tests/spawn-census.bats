#!/usr/bin/env bats
# subject: clippy.toml
# The spawn census, shown able to fail (CLOUD-743 §7, CLOUD-418).
#
# `crates/batten/tests/spawn_census.rs` holds the gate's SHAPE — the level in the
# manifest, the entry in `clippy.toml`, a verdict on every annotation. What it
# cannot hold is that clippy behaves as the design claims, because the crate it
# runs over is green by construction: every assertion there passes over a tree
# where the gate does nothing at all.
#
# So this file drives real clippy over a throwaway crate and makes each arm go
# red on purpose. The clauses of the row, one case each:
#
#   (a) a new spawn with no annotation is refused;
#   (b) a STALE annotation over a deleted spawn is refused, which is what
#       `#[expect]` buys over `#[allow]` and the direction a count table is blind
#       to;
#   (c) a bare `Command` import that is NOT std's needs no annotation — the
#       discriminator, and the reason this gate is clippy and not a string scan;
#   (d) at `warn`, an invocation that omits `-D warnings` reports CLEAN over an
#       unannotated spawn. That is CLOUD-822's measurement reproduced, and it is
#       why the level lives in `[workspace.lints.clippy]` rather than being left
#       for a flag to promote.
#
# A throwaway crate with NO dependencies, for the reason `tests/mutant.bats`
# records for its own: the subject is the MECHANISM, not any real module's
# coverage, and running against the live tree would make the verdict a function
# of whichever file someone edited last. It also keeps the case offline — cargo
# fetches nothing for a crate that declares nothing.
#
# Case (c) stands in for `clap::Command` with a locally-declared type rather than
# clap itself. Name resolution is what is being asserted, and a local `Command`
# exercises it identically while costing no dependency; the REAL `surface.rs`
# sites are held by `spawn_census.rs`'s `claps_command_needs_no_annotation`,
# which reads that file directly.

setup() {
	# The PINNED toolchain, resolved once from the repository that pins it. The
	# toy crate lives outside this tree, so a bare `cargo` there would resolve to
	# whatever is ambient — which is the exact defect `no-bare-cargo` refuses, and
	# the exact defect this suite is about.
	CARGO=$(cd "$BATS_TEST_DIRNAME/.." && mise which cargo)
	[ -x "$CARGO" ] || skip "no pinned cargo to drive clippy with"

	CRATE="$BATS_TEST_TMPDIR/toy"
	mkdir -p "$CRATE/src"
	cat >"$CRATE/clippy.toml" <<-'EOF'
		disallowed-types = [
		  { path = "std::process::Command", reason = "a spawn is an inventory row" },
		]
	EOF
	manifest deny
	# Out of the workspace's own target dir, or every case contends on the lock
	# `hk.pkl` deliberately serialises.
	export CARGO_TARGET_DIR="$BATS_TEST_TMPDIR/target"
}

# The toy manifest, with BOTH halves of the census at level `$1`.
#
# Two lints, because `#[expect]` is two arms and each needs its own severity:
# `disallowed_types` refuses a new spawn, and `unfulfilled_lint_expectations`
# refuses a stale annotation over a spawn that is gone. The second is
# warn-by-default, which is what the case below measured — so the workspace
# denies it explicitly rather than leaning on `-D warnings`.
manifest() {
	cat >"$CRATE/Cargo.toml" <<-EOF
		[package]
		name = "toy"
		version = "0.0.0"
		edition = "2021"

		[lints.rust]
		unfulfilled_lint_expectations = "$1"

		[lints.clippy]
		disallowed_types = "$1"
	EOF
}

# Drive clippy over the toy crate, deliberately WITHOUT `-D warnings`: the level
# under test is the manifest's, and adding the flag here would answer a question
# nobody is asking (case (d) is precisely about the flag being absent).
toy_clippy() {
	(cd "$CRATE" && "$CARGO" clippy --quiet 2>&1)
}

@test "a new spawn with no annotation is refused" {
	cat >"$CRATE/src/lib.rs" <<-'EOF'
		pub fn spawn() {
		    let _ = std::process::Command::new("true").status();
		}
	EOF
	run toy_clippy
	[ "$status" -ne 0 ]
	[[ "$output" == *"disallowed type"* ]]
	[[ "$output" == *"std::process::Command"* ]]
}

@test "an annotated spawn passes" {
	# The other side of (a): the annotation is what clears it, so the refusal
	# above is about the missing verdict rather than about the file.
	cat >"$CRATE/src/lib.rs" <<-'EOF'
		#[expect(clippy::disallowed_types, reason = "stays: the toy case")]
		pub fn spawn() {
		    let _ = std::process::Command::new("true").status();
		}
	EOF
	run toy_clippy
	[ "$status" -eq 0 ]
}

@test "a stale annotation over a deleted spawn is refused" {
	# WHY `expect` AND NOT `allow`, as a decision rather than a claim. The spawn is
	# gone and the annotation was left behind; under `#[allow]` this is silent
	# forever, and the census accumulates rows describing code that is not there.
	# A count table catches additions only — this is the other direction.
	#
	# MEASURED HERE, AND IT CHANGED THE MANIFEST. `unfulfilled_lint_expectations`
	# is warn-by-default, so at first writing this case exited 0: the whole
	# second direction rested on `mise run lint:clippy`'s `-D warnings`, which is
	# the same half-a-gate CLOUD-822 found and the same one §2 refuses. The lint
	# now carries `deny` in `[workspace.lints.rust]` for exactly the reason
	# `disallowed_types` does.
	cat >"$CRATE/src/lib.rs" <<-'EOF'
		#[expect(clippy::disallowed_types, reason = "stays: the spawn this described is gone")]
		pub fn spawn() {}
	EOF
	run toy_clippy
	[ "$status" -ne 0 ]
	[[ "$output" == *"unfulfilled"* ]]
}

@test "an allow in place of an expect goes quiet, which is why expect is the shape" {
	# The same source as the case above, with one word changed. It PASSES — and
	# that pass is the measurement behind the choice, not an accident this suite
	# tolerates. `spawn_census.rs::every_annotation_is_an_expect_carrying_a_verdict`
	# is what keeps the word from being changed in the real tree.
	cat >"$CRATE/src/lib.rs" <<-'EOF'
		#[allow(clippy::disallowed_types, reason = "stays: the spawn this described is gone")]
		pub fn spawn() {}
	EOF
	run toy_clippy
	[ "$status" -eq 0 ]
}

@test "a bare Command import that is not std's needs no annotation" {
	# THE DISCRIMINATOR. `surface.rs` imports clap's `Command` bare, so the token
	# names two types in one crate; a text scan counted 14 sites and a syntax-only
	# matcher counts 11, because neither resolves names. clippy matches the fully
	# resolved path, so this file is green with no annotation anywhere in it — and a
	# gate
	# that demanded one here would have reproduced the defect it exists to fix.
	cat >"$CRATE/src/lib.rs" <<-'EOF'
		mod other {
		    #[derive(Debug)]
		    pub struct Command;
		    impl Command {
		        #[must_use]
		        pub fn new(_name: &str) -> Self {
		            Self
		        }
		    }
		}

		use other::Command;

		#[must_use]
		pub fn build() -> Command {
		    Command::new("check")
		}
	EOF
	run toy_clippy
	[ "$status" -eq 0 ]
}

@test "at warn the gate reports clean, and at deny the same source is refused" {
	# CLOUD-822's measurement, reproduced as the argument for where the level
	# lives. The escape `no-bare-cargo`'s own refusal text recommends omits
	# `-D warnings`; under it a lint left at `warn` reports clean over an
	# unannotated spawn, and the agent then quotes the clean run as verification.
	#
	# A gate whose verdict depends on which sanctioned invocation ran is not a
	# gate — so the workspace sets `deny` in the manifest, and
	# `spawn_census.rs::the_lint_is_denied_in_the_manifest_itself` goes red if
	# anyone relaxes it.
	manifest warn
	cat >"$CRATE/src/lib.rs" <<-'EOF'
		pub fn spawn() {
		    let _ = std::process::Command::new("true").status();
		}
	EOF
	run toy_clippy
	[ "$status" -eq 0 ]
	# The refusal is IN THE OUTPUT and not in the status, which is precisely the
	# reading that makes a `warn` gate quotable as verification.
	[[ "$output" == *"disallowed type"* ]]

	# The same bytes at `deny`, with no flag added — which is what makes the pass
	# above a statement about the LEVEL rather than about clippy having missed it.
	manifest deny
	run toy_clippy
	[ "$status" -ne 0 ]
}
