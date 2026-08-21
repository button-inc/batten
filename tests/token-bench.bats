#!/usr/bin/env bats
# subject: mise-tasks/token-bench mise-tasks/token-bench-check
# bench-check's decision table (CLOUD-119): does the committed benchmark table
# still reproduce, and does every published figure state its method?
#
# The gate re-runs the harness, which builds the binary under test, so a fixture
# cannot be a bare directory — it needs a real workspace. Each fixture is a
# scratch root that symlinks the manifest and sources of the real repo and holds
# its *own* copy of `bench/`, which is the only thing a test mutates.
# CARGO_TARGET_DIR points back at the real target dir so the fixture compiles
# nothing the suite has not already built.

setup() {
	CHECK="$BATS_TEST_DIRNAME/../mise-tasks/token-bench-check"
	BENCH="$BATS_TEST_DIRNAME/../mise-tasks/token-bench"
	REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
	ROOT="$BATS_TEST_TMPDIR/repo"
	mkdir -p "$ROOT"
	for entry in Cargo.toml Cargo.lock crates rustfmt.toml; do
		ln -s "$REPO/$entry" "$ROOT/$entry"
	done
	cp -R "$REPO/bench" "$ROOT/bench"
	export TOKEN_BENCH_ROOT="$ROOT"
	export CARGO_TARGET_DIR="$REPO/target"
}

@test "a committed table that reproduces exits 0" {
	run "$CHECK"
	[ "$status" -eq 0 ]
	[[ "$output" == *"the committed results table reproduces"* ]]
}

@test "an edited figure is reported as drift with a pointer" {
	# The defect this catches: a published number nothing re-derives. Editing a
	# byte count by hand is the cheapest way to make the story better, and it must
	# be the loudest to fail.
	sed -i 's/| baseline | 1 | [0-9]*/| baseline | 1 | 999999/' "$ROOT/bench/tokens/RESULTS.md"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"bench/tokens/RESULTS.md:0 token-bench-drift"* ]]
}

@test "a figure with no method line is refused" {
	# The honesty gate's whole point: a number without its workload, baseline, run
	# count and method is exactly the unmethodical claim this benchmark exists to
	# beat, so it must not survive the gate even when it is arithmetically right.
	sed -i '/^\*\*Method\.\*\* measured;/d' "$ROOT/bench/tokens/RESULTS.md"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"token-bench-unmethodical (no method or run count)"* ]]
}

@test "a figure with no baseline is refused" {
	sed -i '/^\*\*Baseline\*\*/d' "$ROOT/bench/tokens/RESULTS.md"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"token-bench-unmethodical (no baseline)"* ]]
}

@test "a not-measured capability with no stated reason is refused" {
	# A gap that is stated is a finding; a gap that is silent is a claim of
	# coverage nobody made on purpose.
	#
	# The section is APPENDED rather than made by stripping a reason off an
	# existing one: every committed workload carries a figure since CLOUD-121
	# landed the handle verbs, so a test that edited the published table would
	# have quietly stopped exercising this rule the moment the last "not measured"
	# row got its number. The honesty pass runs before the regeneration diff, so a
	# hand-written section is judged on its own.
	cat >>"$ROOT/bench/tokens/RESULTS.md" <<-'EOF'

		### silent-gap — a capability nobody scoped

		**Question.** Does an unexplained omission survive the gate?

		**not measured**
	EOF
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"token-bench-unmethodical (no figure and no stated reason)"* ]]
}

@test "a not-measured capability WITH a reason passes, so the rule is not just a ban" {
	# The other half, and what keeps the rule from reading as "never say not
	# measured": a stated gap is the honest answer the issue asks for, and the
	# gate must accept one. Without this the suite would pass just as happily if
	# the check refused every `not measured` line outright.
	cat >>"$ROOT/bench/tokens/workloads.toml" <<-'EOF'

		[[workload]]
		id = "stated-gap"
		capability = "suite fixture"
		fixture = "scan-pointer"
		question = "Is a gap with a reason accepted?"
		runs = 1
		not_measured = "a reason the suite supplies, so the accepting path is exercised"
	EOF
	run env TOKEN_BENCH_OUT="$ROOT/bench/tokens/RESULTS.md" "$BENCH"
	[ "$status" -eq 0 ]
	run "$CHECK"
	[ "$status" -eq 0 ]
	grep -q "a reason the suite supplies" "$ROOT/bench/tokens/RESULTS.md"
}

@test "a missing table is a violation, never a quiet pass" {
	rm -f "$ROOT/bench/tokens/RESULTS.md"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" == *"bench/tokens/RESULTS.md:0 token-bench-missing"* ]]
}

@test "the drift report is pointer-only — no fixture bytes echoed" {
	# The same rule 4 posture the engine holds: the remedy is one command, so the
	# diff body adds nothing and a benchmark fixture is the last place to start
	# echoing captured output from.
	sed -i 's/| baseline | 1 | [0-9]*/| baseline | 1 | 999999/' "$ROOT/bench/tokens/RESULTS.md"
	run "$CHECK"
	[ "$status" -eq 1 ]
	[[ "$output" != *"unwrap_or_else"* ]]
	[[ "$output" != *"Compiling"* ]]
}

@test "a fixture file missing its .in suffix is an error, not a silent skip" {
	# Inertness is load-bearing: a fixture carries shapes this repository's own
	# gates refuse, and the suffix is what keeps them out of the walked tree. A
	# stray un-suffixed file would be copied under a name nothing expects.
	touch "$ROOT/bench/tokens/fixtures/scan-pointer/stray.rs"
	run "$BENCH"
	[ "$status" -eq 1 ]
	[[ "$output" == *"missing the .in suffix"* ]]
}

@test "an arm that is not byte-stable reports not measured rather than an average" {
	# Averaging a non-deterministic tool is how a figure arrives that nothing
	# supports — and byte-stability is precisely the property the cross-session
	# cache claim rests on, so losing it loses the mechanism, not just precision.
	cat >>"$ROOT/bench/tokens/workloads.toml" <<'EOF'

[[workload]]
id = "unstable-probe"
capability = "suite fixture"
fixture = "scan-pointer"
question = "Does the harness refuse to average a non-deterministic arm?"
runs = 3
baseline = ["echo $$"]
baseline_model = "A command whose output differs every run."
batten = ["$BATTEN check"]
batten_model = "Byte-stable, so the refusal must come from the baseline alone."
EOF
	run env TOKEN_BENCH_OUT="$BATS_TEST_TMPDIR/out.md" "$BENCH"
	[ "$status" -eq 0 ]
	grep -q "not byte-identical across 3 runs" "$BATS_TEST_TMPDIR/out.md"
	grep -q "baseline byte-stable: no" "$BATS_TEST_TMPDIR/out.md"
}

@test "the harness refuses to run without its declared method" {
	# The method and the workloads are inputs, never defaults the program supplies.
	# A harness that fell back to a built-in price would be re-deriving nothing.
	rm -f "$ROOT/bench/tokens/method.toml"
	run "$BENCH"
	[ "$status" -eq 1 ]
	[[ "$output" == *"bench/tokens/method.toml is missing"* ]]
}
